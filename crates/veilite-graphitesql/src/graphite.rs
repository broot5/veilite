use std::error::Error as StdError;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use graphitesql::vfs::{File, OpenFlags, Vfs};
use graphitesql::{
    Connection as GraphiteConnection, Error as GraphiteError, QueryResult as GraphiteQueryResult,
    Value as GraphiteValue,
};
use thiserror::Error;
use zeroize::Zeroizing;

use veilite_core::{CipherConfig, DecryptError, FileSource, ReaderError, SqlCipherReader};

#[cfg(test)]
use crate::companion::companion_path;
use crate::{CompanionError, check_companion_files};

const WAL_SUFFIX: &str = "-wal";
const JOURNAL_SUFFIX: &str = "-journal";
const READ_ONLY_ERROR: &str = "database is read-only";
const WAL_ERROR: &str = "SQLCipher WAL files are unsupported";
const JOURNAL_ERROR: &str = "SQLCipher rollback journals are unsupported";

#[derive(Debug, Error)]
pub enum GraphiteAdapterError {
    #[error("database path is not valid UTF-8: {path:?}")]
    NonUtf8Path { path: PathBuf },
    #[error(transparent)]
    Companion(#[from] CompanionError),
    #[error("GraphiteSQL failed to open the database: {source}")]
    Open {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    #[error("GraphiteSQL query failed: {source}")]
    Query {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}

pub struct ReadOnlyConnection {
    inner: GraphiteConnection,
}

impl ReadOnlyConnection {
    pub fn query(&self, sql: &str) -> Result<QueryResult, GraphiteAdapterError> {
        self.inner
            .query(sql)
            .map(convert_query_result)
            .map_err(|source| GraphiteAdapterError::Query {
                source: Box::new(source),
            })
    }
}

struct SqlCipherFile {
    reader: SqlCipherReader<FileSource>,
}

impl File for SqlCipherFile {
    fn read_exact_at(&self, output: &mut [u8], offset: u64) -> graphitesql::Result<()> {
        self.reader
            .read_exact_at(offset, output)
            .map_err(map_reader_error)
    }

    fn write_all_at(&mut self, _contents: &[u8], _offset: u64) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn truncate(&mut self, _size: u64) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn sync(&mut self) -> graphitesql::Result<()> {
        Ok(())
    }

    fn size(&self) -> graphitesql::Result<u64> {
        Ok(self.reader.file_size())
    }
}

struct SqlCipherVfs {
    main_path: PathBuf,
    main_path_utf8: String,
    config: CipherConfig,
    passphrase: Zeroizing<Vec<u8>>,
}

impl SqlCipherVfs {
    fn new(
        path: impl AsRef<Path>,
        config: CipherConfig,
        passphrase: &[u8],
    ) -> Result<Self, GraphiteAdapterError> {
        let main_path = path.as_ref().to_path_buf();
        let main_path_utf8 = main_path
            .to_str()
            .ok_or_else(|| GraphiteAdapterError::NonUtf8Path {
                path: main_path.clone(),
            })?
            .to_owned();

        Ok(Self {
            main_path,
            main_path_utf8,
            config,
            passphrase: Zeroizing::new(passphrase.to_vec()),
        })
    }
}

impl Vfs for SqlCipherVfs {
    fn open(&self, path: &str, flags: OpenFlags) -> graphitesql::Result<Box<dyn File>> {
        if flags != OpenFlags::READ_ONLY {
            return Err(read_only_error());
        }
        if path != self.main_path_utf8 {
            if path == companion_path_string(&self.main_path_utf8, WAL_SUFFIX) {
                return Err(GraphiteError::Unsupported(WAL_ERROR));
            }
            if path == companion_path_string(&self.main_path_utf8, JOURNAL_SUFFIX) {
                return Err(GraphiteError::Unsupported(JOURNAL_ERROR));
            }
            return Err(GraphiteError::CantOpen(path.to_owned()));
        }

        // Callers may invoke `Vfs::open` directly without going through
        // `open_readonly`, so check for companion files before opening the main
        // database.
        check_companion_files(&self.main_path).map_err(map_companion_to_graphite)?;
        let source = FileSource::open(&self.main_path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => GraphiteError::CantOpen(path.to_owned()),
            _ => GraphiteError::Io(error.to_string()),
        })?;
        let reader = SqlCipherReader::open(source, self.config, self.passphrase.as_slice())
            .map_err(map_reader_error)?;

        Ok(Box::new(SqlCipherFile { reader }))
    }

    fn delete(&self, _path: &str) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn exists(&self, path: &str) -> graphitesql::Result<bool> {
        match fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(GraphiteError::Io(error.to_string())),
        }
    }
}

pub fn open_readonly(
    path: impl AsRef<Path>,
    config: CipherConfig,
    passphrase: &[u8],
) -> Result<ReadOnlyConnection, GraphiteAdapterError> {
    let vfs = SqlCipherVfs::new(path, config, passphrase)?;
    check_companion_files(&vfs.main_path)?;
    let inner =
        GraphiteConnection::open_readonly_vfs(&vfs, &vfs.main_path_utf8).map_err(|source| {
            GraphiteAdapterError::Open {
                source: Box::new(source),
            }
        })?;
    Ok(ReadOnlyConnection { inner })
}

fn convert_query_result(result: GraphiteQueryResult) -> QueryResult {
    QueryResult {
        columns: result.columns,
        rows: result
            .rows
            .into_iter()
            .map(|row| row.into_iter().map(convert_value).collect())
            .collect(),
    }
}

fn convert_value(value: GraphiteValue) -> Value {
    match value {
        GraphiteValue::Null => Value::Null,
        GraphiteValue::Integer(value) => Value::Integer(value),
        GraphiteValue::Real(value) => Value::Real(value),
        GraphiteValue::Text(value) => Value::Text(value.into_bytes()),
        GraphiteValue::Blob(value) => Value::Blob(value),
    }
}

fn read_only_error() -> GraphiteError {
    GraphiteError::Error(READ_ONLY_ERROR.to_owned())
}

fn map_companion_to_graphite(error: CompanionError) -> GraphiteError {
    match error {
        CompanionError::UnsupportedWal { .. } => GraphiteError::Unsupported(WAL_ERROR),
        CompanionError::UnsupportedJournal { .. } => GraphiteError::Unsupported(JOURNAL_ERROR),
        io_error @ CompanionError::Io { .. } => GraphiteError::Io(io_error.to_string()),
    }
}

fn companion_path_string(path: &str, suffix: &str) -> String {
    let mut companion = String::with_capacity(path.len() + suffix.len());
    companion.push_str(path);
    companion.push_str(suffix);
    companion
}

fn map_reader_error(error: ReaderError<io::Error>) -> GraphiteError {
    match error {
        ReaderError::Source(source) => GraphiteError::Io(source.to_string()),
        empty_passphrase @ ReaderError::Decrypt(DecryptError::EmptyPassphrase) => {
            GraphiteError::Error(empty_passphrase.to_string())
        }
        other => GraphiteError::Corrupt(other.to_string()),
    }
}

#[cfg(test)]
mod tests;
