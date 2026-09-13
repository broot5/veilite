use crate::{Column, Header, PageSource, ReaderError, TextEncoding, Value};
use crate::{
    btree::{Cursor, Kind},
    record,
    schema::{self, Affinity, Layout},
};
use std::{num::NonZeroU32, sync::Arc};

/// A row from sqlite_schema, including objects whose SQL cannot be executed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaObject {
    /// SQLite object kind: table, index, view, or trigger.
    pub kind: String,
    /// Object name.
    pub name: String,
    /// Associated table name.
    pub table_name: String,
    /// Root page, or zero for an object without its own B-tree.
    pub root_page: u32,
    /// Original CREATE statement; implicit indexes have no SQL text.
    pub sql: Option<String>,
}

/// Schema and row reader over a logical page source, independent of file I/O.
///
/// Opening validates page 1. Table and index reads are lazy and do not perform
/// database-wide integrity checking. The source's page count defines the
/// snapshot even when page 1 contains an older header count.
pub struct Reader<S> {
    source: S,
    header: Header,
}

impl<S: PageSource> Reader<S> {
    /// Opens an immutable logical snapshot, validating source metadata and page 1.
    pub fn open(source: S) -> Result<Self, ReaderError<S::Error>> {
        let size = source.page_size();
        let count = source.page_count();
        if !(512..=65536).contains(&size)
            || !size.is_power_of_two()
            || count == 0
            || count == u32::MAX
        {
            return Err(ReaderError::InvalidFormat("invalid page-source metadata"));
        }
        let mut page = vec![0; size];
        source
            .read_page_into(NonZeroU32::MIN, &mut page)
            .map_err(ReaderError::Source)?;
        let mut bytes = [0; 100];
        bytes.copy_from_slice(&page[..100]);
        let header = Header::snapshot(
            &bytes,
            u32::try_from(size).map_err(|_| ReaderError::InvalidFormat("page size overflow"))?,
            count,
        )?;
        Ok(Self { source, header })
    }

    /// Validated header metadata with the source's logical snapshot count.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Reads schema entries without parsing their CREATE statements.
    ///
    /// Unsupported tables, views, and triggers do not block schema enumeration.
    /// Malformed schema records or unreadable schema pages do return an error.
    pub fn schema(&self) -> Result<Vec<SchemaObject>, ReaderError<S::Error>> {
        let mut objects = Vec::new();
        for record in Cursor::new(&self.source, 1, Kind::Table, self.header.usable_size()) {
            let values = record::decode(&record?.payload, self.header.text_encoding())?;
            let [kind, name, table_name, root_page, sql] = values.as_slice() else {
                return Err(ReaderError::InvalidFormat(
                    "invalid sqlite_schema column count",
                ));
            };
            let kind = schema_text(kind)?;
            if !["table", "index", "view", "trigger"].contains(&kind.as_str()) {
                return Err(ReaderError::InvalidFormat("unknown schema object type"));
            }
            let root_page = match root_page {
                Value::Integer(n) => u32::try_from(*n)
                    .map_err(|_| ReaderError::InvalidFormat("invalid schema root page"))?,
                _ => return Err(ReaderError::InvalidFormat("invalid schema root page type")),
            };
            if root_page > self.source.page_count() {
                return Err(ReaderError::PageOutOfRange(root_page));
            }
            let sql = if matches!(sql, Value::Null) {
                None
            } else {
                Some(schema_text(sql)?)
            };
            objects.push(SchemaObject {
                kind,
                name: schema_text(name)?,
                table_name: schema_text(table_name)?,
                root_page,
                sql,
            });
        }
        Ok(objects)
    }

    fn find(&self, kind: &str, name: &str) -> Result<SchemaObject, ReaderError<S::Error>> {
        let mut found = None;
        for object in self.schema()? {
            if object.kind == kind
                && object.name.eq_ignore_ascii_case(name)
                && found.replace(object).is_some()
            {
                return Err(ReaderError::InvalidFormat("duplicate schema name"));
            }
        }
        found.ok_or_else(|| ReaderError::NotFound(name.to_owned()))
    }

    /// Opens a table by name. Unsupported DDL affects only this operation.
    pub fn table(&self, name: &str) -> Result<Table<'_, S>, ReaderError<S::Error>> {
        let object = if name.eq_ignore_ascii_case("sqlite_schema")
            || name.eq_ignore_ascii_case("sqlite_master")
        {
            SchemaObject { kind: "table".into(), name: "sqlite_schema".into(), table_name: "sqlite_schema".into(), root_page: 1,
                sql: Some("CREATE TABLE sqlite_schema(type TEXT,name TEXT,tbl_name TEXT,rootpage INTEGER,sql TEXT)".into()) }
        } else {
            self.find("table", name)?
        };
        if object.root_page == 0 {
            return Err(ReaderError::Unsupported("virtual table rows"));
        }
        let sql = object
            .sql
            .as_deref()
            .ok_or(ReaderError::InvalidFormat("table has no CREATE statement"))?;
        let layout =
            schema::parse(sql, self.header.text_encoding()).map_err(ReaderError::Unsupported)?;
        Ok(Table {
            reader: self,
            name: object.name,
            root: object.root_page,
            layout,
        })
    }

    /// Opens an index for stored-entry traversal, without executing collations.
    pub fn index(&self, name: &str) -> Result<Index<'_, S>, ReaderError<S::Error>> {
        let object = self.find("index", name)?;
        if object.root_page == 0 {
            return Err(ReaderError::InvalidFormat("index has no root page"));
        }
        Ok(Index {
            reader: self,
            object,
        })
    }
}

fn schema_text<E>(value: &Value) -> Result<String, ReaderError<E>> {
    match value {
        Value::Text(text) => text
            .to_string()
            .map_err(|_| ReaderError::InvalidFormat("invalid schema text encoding")),
        _ => Err(ReaderError::InvalidFormat("invalid schema text value")),
    }
}

/// A table with parsed column metadata, borrowing its reader.
pub struct Table<'a, S> {
    reader: &'a Reader<S>,
    name: String,
    root: u32,
    layout: Layout,
}
impl<S: PageSource> Table<'_, S> {
    /// Table name from the schema.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Columns in declaration order.
    pub fn columns(&self) -> &[Column] {
        &self.layout.columns
    }
    /// Whether rows use an index B-tree and have no rowid.
    pub fn without_rowid(&self) -> bool {
        self.layout.without_rowid
    }
    /// Iterates rows in stored B-tree order. Stops permanently after an error.
    pub fn rows(&self) -> Rows<'_, S> {
        Rows {
            cursor: Cursor::new(
                &self.reader.source,
                self.root,
                if self.layout.without_rowid {
                    Kind::Index
                } else {
                    Kind::Table
                },
                self.reader.header.usable_size(),
            ),
            columns: Arc::clone(&self.layout.columns),
            storage: &self.layout.storage,
            alias: self.layout.alias,
            encoding: self.reader.header.text_encoding(),
            failed: false,
        }
    }
}

/// An owned row in declared column order. Successful earlier rows are not revoked
/// if a later read fails; a failing row never returns partially assembled values.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    columns: Arc<[Column]>,
    values: Vec<Value>,
    rowid: Option<i64>,
}
impl Row {
    /// Values in column declaration order.
    pub fn values(&self) -> &[Value] {
        &self.values
    }
    /// Finds a declared column by SQLite's ASCII case-insensitive naming rule.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
            .and_then(|i| self.values.get(i))
    }
    /// Separate B-tree rowid; absent for WITHOUT ROWID tables.
    pub fn rowid(&self) -> Option<i64> {
        self.rowid
    }
}

/// Fallible streaming row iterator; each row owns its values.
pub struct Rows<'a, S: PageSource> {
    cursor: Cursor<'a, S>,
    columns: Arc<[Column]>,
    storage: &'a [usize],
    alias: Option<usize>,
    encoding: TextEncoding,
    failed: bool,
}
impl<S: PageSource> Rows<'_, S> {
    fn row(&self, record: crate::btree::Record) -> Result<Row, ReaderError<S::Error>> {
        let stored = record::decode(&record.payload, self.encoding)?;
        if stored.len() > self.storage.len() {
            return Err(ReaderError::InvalidFormat(
                "record has more values than declared columns",
            ));
        }
        let stored_len = stored.len();
        let mut values = vec![Value::Null; self.columns.len()];
        // Repeated WITHOUT ROWID key slots may map to the same column. Fill
        // missing slots first so an already stored value always takes precedence.
        for &column in &self.storage[stored_len..] {
            values[column] = self.columns[column]
                .missing_value()
                .map_err(ReaderError::InvalidFormat)?;
        }
        for (position, value) in stored.into_iter().enumerate() {
            values[self.storage[position]] = value;
        }
        if let Some(alias) = self.alias {
            values[alias] = Value::Integer(
                record
                    .rowid
                    .ok_or(ReaderError::InvalidFormat("rowid alias without rowid"))?,
            );
        }
        for (column, value) in self.columns.iter().zip(&mut values) {
            if column.affinity == Affinity::Real
                && let Value::Integer(n) = value
            {
                *value = Value::Real(*n as f64);
            }
        }
        Ok(Row {
            columns: Arc::clone(&self.columns),
            values,
            rowid: record.rowid,
        })
    }
}
impl<S: PageSource> Iterator for Rows<'_, S> {
    type Item = Result<Row, ReaderError<S::Error>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = self.cursor.next()?.and_then(|record| self.row(record));
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}
impl<S: PageSource> std::iter::FusedIterator for Rows<'_, S> {}

/// Index metadata and access to its stored records.
pub struct Index<'a, S> {
    reader: &'a Reader<S>,
    object: SchemaObject,
}
impl<S: PageSource> Index<'_, S> {
    /// Schema entry, including the index's table and root page.
    pub fn schema_object(&self) -> &SchemaObject {
        &self.object
    }
    /// Iterates complete stored keys, including interior-page keys and row locators.
    /// Values stay in index storage order; no key comparisons or SQL expressions run.
    pub fn entries(&self) -> IndexEntries<'_, S> {
        IndexEntries {
            cursor: Cursor::new(
                &self.reader.source,
                self.object.root_page,
                Kind::Index,
                self.reader.header.usable_size(),
            ),
            encoding: self.reader.header.text_encoding(),
            failed: false,
        }
    }
}

/// Fallible iterator over stored index entries. Stops permanently after an error.
pub struct IndexEntries<'a, S: PageSource> {
    cursor: Cursor<'a, S>,
    encoding: TextEncoding,
    failed: bool,
}
impl<S: PageSource> Iterator for IndexEntries<'_, S> {
    type Item = Result<Vec<Value>, ReaderError<S::Error>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let result = self
            .cursor
            .next()?
            .and_then(|r| record::decode(&r.payload, self.encoding));
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}
impl<S: PageSource> std::iter::FusedIterator for IndexEntries<'_, S> {}
