use crate::{Text, TextEncoding, Value};

type Result<T> = std::result::Result<T, &'static str>;

/// Column metadata in declaration order.
#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub(crate) name: String,
    pub(crate) declared_type: String,
    kind: ColumnKind,
    pub(crate) primary_key: Option<usize>,
    pub(crate) not_null: bool,
    pub(crate) affinity: Affinity,
    collation: String,
}

impl Column {
    /// Whether this column contains the stored result of a generated expression.
    /// The reader returns that result without evaluating the expression.
    pub fn is_stored_generated(&self) -> bool {
        matches!(self.kind, ColumnKind::StoredGenerated)
    }

    /// Declared column name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Declared type, with whitespace normalized by the schema parser.
    pub fn declared_type(&self) -> &str {
        &self.declared_type
    }
    /// Constant default after applying column affinity, or no DEFAULT clause.
    pub fn default_value(&self) -> Option<&Value> {
        match &self.kind {
            ColumnKind::Ordinary { default } => default.as_ref(),
            ColumnKind::StoredGenerated => None,
        }
    }
    pub(crate) fn missing_value(&self) -> Result<Value> {
        match &self.kind {
            ColumnKind::Ordinary { default } => Ok(default.clone().unwrap_or(Value::Null)),
            ColumnKind::StoredGenerated => Err("missing STORED generated value"),
        }
    }

    /// One-based position in the primary key, if any.
    pub fn primary_key_position(&self) -> Option<usize> {
        self.primary_key
    }
    /// NOT NULL metadata, including implicit WITHOUT ROWID and STRICT keys.
    /// As in SQLite's table_info, a rowid alias need not report NOT NULL.
    pub fn not_null(&self) -> bool {
        self.not_null
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ColumnKind {
    Ordinary { default: Option<Value> },
    StoredGenerated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Affinity {
    Integer,
    Text,
    Blob,
    Real,
    Numeric,
}

pub(crate) struct Layout {
    pub columns: std::sync::Arc<[Column]>,
    pub storage: Vec<usize>,
    pub alias: Option<usize>,
    pub without_rowid: bool,
}

#[derive(Debug)]
enum Token {
    Word(String, bool),
    String(String),
    Number(String),
    Blob(Vec<u8>),
    Symbol(char),
}
impl Token {
    fn kw(&self, expected: &str) -> bool {
        matches!(self, Self::Word(word, false) if word.eq_ignore_ascii_case(expected))
    }
    fn symbol(&self, expected: char) -> bool {
        matches!(self, Self::Symbol(c) if *c == expected)
    }
    fn name(&self) -> Option<&str> {
        match self {
            Self::Word(s, _) | Self::String(s) => Some(s),
            _ => None,
        }
    }
    fn spelling(&self) -> String {
        match self {
            Self::Word(s, _) | Self::String(s) | Self::Number(s) => s.clone(),
            Self::Symbol(c) => c.to_string(),
            Self::Blob(_) => String::new(),
        }
    }
}

fn lex(sql: &str) -> Result<Vec<Token>> {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut tokens = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"--") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i..].starts_with(b"/*") {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            if i == b.len() {
                return Err("unterminated SQL comment");
            }
            i += 2;
            continue;
        }
        let blob = matches!(b[i], b'x' | b'X') && b.get(i + 1) == Some(&b'\'');
        if blob {
            i += 1;
        }
        if matches!(b[i], b'\'' | b'"' | b'`' | b'[') {
            let quote = b[i];
            let end = if quote == b'[' { b']' } else { quote };
            i += 1;
            let mut value = Vec::new();
            loop {
                if i == b.len() {
                    return Err("unterminated quoted SQL token");
                }
                if b[i] == end {
                    i += 1;
                    if quote != b'[' && b.get(i) == Some(&end) {
                        value.push(end);
                        i += 1;
                    } else {
                        break;
                    }
                } else {
                    value.push(b[i]);
                    i += 1;
                }
            }
            let value = String::from_utf8(value).map_err(|_| "invalid SQL text")?;
            tokens.push(if blob {
                if value.len() % 2 != 0 {
                    return Err("invalid blob literal");
                }
                let mut out = Vec::new();
                for pair in value.as_bytes().chunks_exact(2) {
                    let high = (pair[0] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    let low = (pair[1] as char)
                        .to_digit(16)
                        .ok_or("invalid blob literal")?;
                    out.push((high * 16 + low) as u8);
                }
                Token::Blob(out)
            } else if quote == b'\'' {
                Token::String(value)
            } else {
                Token::Word(value, true)
            });
            continue;
        }
        if b[i].is_ascii_digit() || (b[i] == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let start = i;
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric()
                    || matches!(b[i], b'.' | b'_')
                    || (matches!(b[i], b'+' | b'-') && matches!(b[i - 1], b'e' | b'E')))
            {
                i += 1;
            }
            tokens.push(Token::Number(sql[start..i].into()));
            continue;
        }
        if b[i].is_ascii_alphabetic() || b[i] == b'_' || b[i] >= 128 {
            let start = i;
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'$') || b[i] >= 128)
            {
                i += 1;
            }
            tokens.push(Token::Word(sql[start..i].into(), false));
            continue;
        }
        if !b[i].is_ascii() {
            return Err("invalid SQL token");
        }
        tokens.push(Token::Symbol(b[i] as char));
        i += 1;
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
}
impl<'a> Parser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, at: 0 }
    }
    fn eat(&mut self, keyword: &str) -> bool {
        if self.tokens.get(self.at).is_some_and(|t| t.kw(keyword)) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn require(&mut self, keyword: &str) -> Result<()> {
        if self.eat(keyword) {
            Ok(())
        } else {
            Err("unsupported CREATE TABLE grammar")
        }
    }
    fn symbol(&mut self, symbol: char) -> bool {
        if self.tokens.get(self.at).is_some_and(|t| t.symbol(symbol)) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn name(&mut self) -> Result<String> {
        let name = self
            .tokens
            .get(self.at)
            .and_then(Token::name)
            .ok_or("expected SQL identifier")?
            .to_owned();
        self.at += 1;
        Ok(name)
    }
    fn group(&mut self) -> Result<&'a [Token]> {
        if !self.symbol('(') {
            return Err("expected parenthesized SQL group");
        }
        let start = self.at;
        let mut depth = 1;
        while let Some(token) = self.tokens.get(self.at) {
            self.at += 1;
            if token.symbol('(') {
                depth += 1;
            }
            if token.symbol(')') {
                depth -= 1;
                if depth == 0 {
                    return Ok(&self.tokens[start..self.at - 1]);
                }
            }
        }
        Err("unclosed SQL group")
    }
    fn conflict(&mut self) -> Result<()> {
        if self.eat("ON") {
            self.require("CONFLICT")?;
            if !["ROLLBACK", "ABORT", "FAIL", "IGNORE", "REPLACE"]
                .iter()
                .any(|s| self.eat(s))
            {
                return Err("unsupported ON CONFLICT clause");
            }
        }
        Ok(())
    }
    fn references(&mut self) -> Result<()> {
        self.name()?;
        if self.tokens.get(self.at).is_some_and(|t| t.symbol('(')) {
            names(self.group()?)?;
        }
        loop {
            if self.eat("ON") {
                if !self.eat("DELETE") && !self.eat("UPDATE") {
                    return Err("unsupported foreign key action");
                }
                if self.eat("SET") {
                    if !self.eat("NULL") && !self.eat("DEFAULT") {
                        return Err("unsupported foreign key action");
                    }
                } else if self.eat("NO") {
                    self.require("ACTION")?;
                } else if !self.eat("CASCADE") && !self.eat("RESTRICT") {
                    return Err("unsupported foreign key action");
                }
            } else if self.eat("MATCH") {
                self.name()?;
            } else {
                break;
            }
        }
        if self.tokens.get(self.at).is_some_and(|t| t.kw("NOT"))
            && self
                .tokens
                .get(self.at + 1)
                .is_some_and(|t| t.kw("DEFERRABLE"))
        {
            self.at += 1;
        }
        if self.eat("DEFERRABLE")
            && self.eat("INITIALLY")
            && !self.eat("DEFERRED")
            && !self.eat("IMMEDIATE")
        {
            return Err("unsupported foreign key deferral");
        }
        Ok(())
    }
}

fn split(tokens: &[Token]) -> Result<Vec<&[Token]>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate() {
        if token.symbol('(') {
            depth += 1;
        }
        if token.symbol(')') {
            depth = depth.checked_sub(1).ok_or("unmatched SQL parenthesis")?;
        }
        if depth == 0 && token.symbol(',') {
            if start == i {
                return Err("empty SQL definition");
            }
            parts.push(&tokens[start..i]);
            start = i + 1;
        }
    }
    if depth != 0 || start == tokens.len() {
        return Err("invalid SQL definition list");
    }
    parts.push(&tokens[start..]);
    Ok(parts)
}

struct KeyTerm {
    name: String,
    collation: Option<String>,
}

fn keys(tokens: &[Token]) -> Result<Vec<KeyTerm>> {
    split(tokens)?
        .into_iter()
        .map(|part| {
            let mut p = Parser::new(part);
            let name = p.name()?;
            let collation = if p.eat("COLLATE") {
                Some(p.name()?)
            } else {
                None
            };
            p.eat("ASC");
            p.eat("DESC");
            if p.at != part.len() {
                return Err("indexed expressions are unsupported in table constraints");
            }
            Ok(KeyTerm { name, collation })
        })
        .collect()
}

fn names(tokens: &[Token]) -> Result<Vec<String>> {
    Ok(keys(tokens)?.into_iter().map(|key| key.name).collect())
}

fn constraint(t: &Token) -> bool {
    [
        "CONSTRAINT",
        "PRIMARY",
        "NOT",
        "NULL",
        "UNIQUE",
        "CHECK",
        "DEFAULT",
        "COLLATE",
        "REFERENCES",
        "GENERATED",
        "AS",
    ]
    .iter()
    .any(|s| t.kw(s))
}

pub(crate) fn parse(sql: &str, encoding: TextEncoding) -> Result<Layout> {
    parse_table(sql, encoding)?.resolve_layout()
}

struct InlinePrimaryKey {
    descending: bool,
}

struct ParsedTable {
    columns: Vec<Column>,
    key: Option<Vec<KeyTerm>>,
    inline_desc: Option<usize>,
    without_rowid: bool,
    strict: bool,
}

fn parse_table(sql: &str, encoding: TextEncoding) -> Result<ParsedTable> {
    let tokens = lex(sql)?;
    let mut p = Parser::new(&tokens);
    p.require("CREATE")?;
    p.eat("TEMP");
    p.eat("TEMPORARY");
    p.require("TABLE")?;
    if p.eat("IF") {
        p.require("NOT")?;
        p.require("EXISTS")?;
    }
    p.name()?;
    if p.symbol('.') {
        p.name()?;
    }
    let definitions = split(p.group()?)?;
    let mut without_rowid = false;
    let mut strict = false;
    while p.at < tokens.len() && !p.symbol(';') {
        if p.eat("WITHOUT") {
            p.require("ROWID")?;
            if without_rowid {
                return Err("duplicate table option");
            }
            without_rowid = true;
        } else if p.eat("STRICT") {
            if strict {
                return Err("duplicate table option");
            }
            strict = true;
        } else {
            return Err("unsupported table option");
        }
        if !p.symbol(',') {
            break;
        }
    }
    p.symbol(';');
    if p.at != tokens.len() {
        return Err("trailing CREATE TABLE tokens");
    }
    let mut columns = Vec::new();
    let mut key: Option<Vec<KeyTerm>> = None;
    let mut inline_desc = None;
    for definition in definitions {
        let mut p = Parser::new(definition);
        if p.eat("CONSTRAINT") {
            p.name()?;
        }
        if p.eat("PRIMARY") {
            p.require("KEY")?;
            if key.replace(keys(p.group()?)?).is_some() {
                return Err("multiple primary keys");
            }
            p.conflict()?;
        } else if p.eat("UNIQUE") {
            names(p.group()?)?;
            p.conflict()?;
        } else if p.eat("CHECK") {
            p.group()?;
        } else if p.eat("FOREIGN") {
            p.require("KEY")?;
            names(p.group()?)?;
            p.require("REFERENCES")?;
            p.references()?;
        } else {
            if p.at != 0 {
                return Err("unsupported named table constraint");
            }
            let (column, primary_key) = parse_column(&mut p, strict, encoding)?;
            if columns
                .iter()
                .any(|c: &Column| c.name.eq_ignore_ascii_case(&column.name))
            {
                return Err("duplicate column name");
            }
            if let Some(primary_key) = primary_key {
                if key
                    .replace(vec![KeyTerm {
                        name: column.name.clone(),
                        collation: None,
                    }])
                    .is_some()
                {
                    return Err("multiple primary keys");
                }
                if primary_key.descending {
                    inline_desc = Some(columns.len());
                }
            }
            columns.push(column);
        }
        if p.at != definition.len() {
            return Err("unsupported table constraint suffix");
        }
    }
    Ok(ParsedTable {
        columns,
        key,
        inline_desc,
        without_rowid,
        strict,
    })
}

fn parse_column(
    p: &mut Parser<'_>,
    strict: bool,
    encoding: TextEncoding,
) -> Result<(Column, Option<InlinePrimaryKey>)> {
    let definition = p.tokens;
    let mut primary_key = None;
    let name = p.name()?;
    let start = p.at;
    while let Some(t) = definition.get(p.at) {
        if constraint(t) {
            break;
        }
        if t.symbol('(') {
            p.group()?;
        } else if t.name().is_some() {
            p.at += 1;
        } else {
            return Err("unsupported declared type");
        }
    }
    let declared_type = definition[start..p.at]
        .iter()
        .map(Token::spelling)
        .collect::<Vec<_>>()
        .join(" ");
    let affinity = affinity(&declared_type, strict)?;
    let mut column = Column {
        name,
        declared_type,
        kind: ColumnKind::Ordinary { default: None },
        primary_key: None,
        not_null: false,
        affinity,
        collation: "BINARY".into(),
    };
    while p.at < definition.len() {
        if p.eat("CONSTRAINT") {
            p.name()?;
        }
        if p.eat("PRIMARY") {
            p.require("KEY")?;
            p.eat("ASC");
            let descending = p.eat("DESC");
            if primary_key
                .replace(InlinePrimaryKey { descending })
                .is_some()
            {
                return Err("multiple primary keys");
            }
            p.conflict()?;
            p.eat("AUTOINCREMENT");
        } else if p.eat("NOT") {
            p.require("NULL")?;
            column.not_null = true;
            p.conflict()?;
        } else if p.eat("NULL") || p.eat("UNIQUE") {
            p.conflict()?;
        } else if p.eat("CHECK") {
            p.group()?;
        } else if p.eat("COLLATE") {
            column.collation = p.name()?;
        } else if p.eat("REFERENCES") {
            p.references()?;
        } else if p.eat("DEFAULT") {
            let value = if p.tokens.get(p.at).is_some_and(|t| t.symbol('(')) {
                constant(p.group()?, affinity, encoding)?
            } else {
                let start = p.at;
                if p.symbol('+') || p.symbol('-') { /* numeric sign */ }
                if p.at >= definition.len() {
                    return Err("missing DEFAULT value");
                }
                p.at += 1;
                constant(&definition[start..p.at], affinity, encoding)?
            };
            match &mut column.kind {
                ColumnKind::Ordinary { default } => {
                    *default = Some(crate::defaults::coerce(value, affinity, encoding)?);
                }
                ColumnKind::StoredGenerated => return Err("generated column with DEFAULT"),
            }
        } else if p
            .tokens
            .get(p.at)
            .is_some_and(|t| t.kw("GENERATED") || t.kw("AS"))
        {
            if column.is_stored_generated() {
                return Err("duplicate generated column clause");
            }
            if p.eat("GENERATED") {
                p.require("ALWAYS")?;
            }
            p.require("AS")?;
            if p.group()?.is_empty() {
                return Err("empty generated expression");
            }
            // Omitted storage kind means VIRTUAL in SQLite.
            if !p.eat("STORED") {
                return Err("VIRTUAL generated columns");
            }
            if column.default_value().is_some() {
                return Err("generated column with DEFAULT");
            }
            column.kind = ColumnKind::StoredGenerated;
        } else {
            return Err("unsupported column constraint");
        }
    }
    Ok((column, primary_key))
}

impl ParsedTable {
    fn resolve_layout(self) -> Result<Layout> {
        let Self {
            mut columns,
            key,
            inline_desc,
            without_rowid,
            strict,
        } = self;
        if columns.is_empty() || columns.iter().all(|c| c.is_stored_generated()) {
            return Err("table has no ordinary columns");
        }
        let mut storage = Vec::new();
        let declared_key_count = key.as_ref().map_or(0, Vec::len);
        if let Some(key) = key {
            let mut stored_keys: Vec<(usize, String)> = Vec::new();
            for (position, term) in key.iter().enumerate() {
                let index = columns
                    .iter()
                    .position(|c| c.name.eq_ignore_ascii_case(&term.name))
                    .ok_or("unknown primary key column")?;
                if columns[index].is_stored_generated() {
                    return Err("generated column in primary key");
                }
                let collation = term
                    .collation
                    .as_ref()
                    .unwrap_or(&columns[index].collation)
                    .clone();
                if without_rowid
                    && stored_keys
                        .iter()
                        .any(|(i, c)| *i == index && c.eq_ignore_ascii_case(&collation))
                {
                    continue;
                }
                let ordinal = if without_rowid {
                    stored_keys.len() + 1
                } else {
                    position + 1
                };
                columns[index].primary_key.get_or_insert(ordinal);
                if without_rowid {
                    columns[index].not_null = true;
                    storage.push(index);
                    stored_keys.push((index, collation));
                }
            }
        }
        if without_rowid && storage.is_empty() {
            return Err("WITHOUT ROWID requires a primary key");
        }
        let alias = if !without_rowid && declared_key_count == 1 {
            columns.iter().enumerate().find_map(|(index, column)| {
                (column.primary_key.is_some()
                    && column.declared_type.eq_ignore_ascii_case("INTEGER")
                    && inline_desc != Some(index))
                .then_some(index)
            })
        } else {
            None
        };
        if strict {
            for (index, column) in columns.iter_mut().enumerate() {
                if column.primary_key.is_some() && Some(index) != alias {
                    column.not_null = true;
                }
            }
        }
        for index in 0..columns.len() {
            if !storage.contains(&index) {
                storage.push(index);
            }
        }
        Ok(Layout {
            columns: columns.into(),
            storage,
            alias,
            without_rowid,
        })
    }
}

fn affinity(name: &str, strict: bool) -> Result<Affinity> {
    let name = name.to_ascii_uppercase();
    if strict && !["INT", "INTEGER", "REAL", "TEXT", "BLOB", "ANY"].contains(&name.as_str()) {
        return Err("unsupported STRICT column type");
    }
    Ok(if strict && name == "ANY" {
        Affinity::Blob
    } else if name.contains("INT") {
        Affinity::Integer
    } else if name.contains("CHAR") || name.contains("CLOB") || name.contains("TEXT") {
        Affinity::Text
    } else if name.is_empty() || name.contains("BLOB") {
        Affinity::Blob
    } else if name.contains("REAL") || name.contains("FLOA") || name.contains("DOUB") {
        Affinity::Real
    } else {
        Affinity::Numeric
    })
}

fn constant(mut tokens: &[Token], affinity: Affinity, encoding: TextEncoding) -> Result<Value> {
    while tokens.first().is_some_and(|t| t.symbol('(')) {
        let mut p = Parser::new(tokens);
        let inner = p.group()?;
        if p.at != tokens.len() {
            return Err("expression DEFAULT is unsupported");
        }
        tokens = inner;
    }
    match tokens {
        [Token::String(s)] => Ok(Value::Text(Text::encode(s, encoding))),
        [Token::Blob(b)] => Ok(Value::Blob(b.clone())),
        [token] if token.kw("NULL") => Ok(Value::Null),
        [token] if token.kw("TRUE") => Ok(Value::Integer(1)),
        [token] if token.kw("FALSE") => Ok(Value::Integer(0)),
        [Token::Number(n)] => crate::defaults::number_literal(n, affinity, encoding),
        [Token::Symbol(sign), Token::Number(n)] if matches!(sign, '+' | '-') => {
            crate::defaults::number_literal(&format!("{sign}{n}"), affinity, encoding)
        }
        _ => Err("expression DEFAULT is unsupported"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_stored_generated_declarations() {
        for definition in [
            "a, b AS () STORED",
            "a, b AS (a+1) STORED DEFAULT 0",
            "a, b DEFAULT 0 AS (a+1) STORED",
            "a, b AS (a+1) STORED PRIMARY KEY",
            "a, b AS (a+1) STORED, PRIMARY KEY(b)",
            "a, b AS (a+1) STORED AS (a+2) STORED",
            "a AS (1) STORED",
        ] {
            assert!(
                parse(&format!("CREATE TABLE t({definition})"), TextEncoding::Utf8).is_err(),
                "{definition}"
            );
        }
    }

    #[test]
    fn malformed_numeric_separators_do_not_become_valid_defaults() {
        for literal in [
            "1__0", "1_", "1_.0", "1._0", "1_e2", "1e_2", "0x_FF", "0xFF_",
        ] {
            let sql = format!("CREATE TABLE t(value NUMERIC DEFAULT {literal})");
            assert!(parse(&sql, TextEncoding::Utf8).is_err(), "{literal}");
        }
    }
}
