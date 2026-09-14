# sqlite-reader

Read SQLite database snapshots directly in Rust, without a SQLite runtime.
Provides schema, table, and index access. Requires Rust 1.89 or newer.

## Usage

Add the crate from a local checkout, adjusting the path to your project:

```toml
[dependencies]
sqlite-reader = { path = "../veilite/crates/sqlite-reader" }
```

```no_run
use sqlite_reader::{Database, FileSource, Reader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::open(FileSource::open("snapshot.db")?)?;
    let reader = Reader::open(database)?;
    let table = reader.table("people")?;

    for row in table.rows() {
        let row = row?;
        println!("{:?}", row.get("name"));
    }
    Ok(())
}
```

Use `SliceSource` for in-memory database bytes or implement `PageSource` for a
custom source. `schema()` lists schema objects, `table(name)` exposes columns
and rows, and `index(name)` iterates stored index entries.

Rows expose values in column declaration order through `values()`, named access
through `get(name)`, and a separate `rowid()`. Text preserves its original bytes
and encoding; `Text::to_string()` performs checked Unicode conversion.

## Supported databases

- Schema format 4, UTF-8/UTF-16LE/UTF-16BE, and page sizes from 512 to 65,536 bytes.
- Rowid, `WITHOUT ROWID`, and `STRICT` tables, including STORED generated columns.
- NULL, integers, real numbers, text, blobs, and overflow values.
- Rowid aliases, column-order restoration, and constant defaults for trailing
  columns absent from older records.

Tables containing VIRTUAL generated columns or expression defaults are rejected
when opened. Other supported tables and schema enumeration remain available.
Numeric default conversion follows SQLite 3.53.4; floating-point results can
vary slightly across SQLite versions or builds.

## Limits

Supply a complete main database after checkpoint and clean close, and keep it
unchanged while reading. The library does not acquire locks or read/recover WAL
and journal files. Empty, uninitialized database files are unsupported.

SQL execution, writes, view evaluation, virtual-table rows, and index key/range
lookup are not provided. Generated expressions and constraints are not evaluated.

Opening checks the header and file layout; further errors can occur while
reading. Row and index iterators stop after their first error. Validation is not
a full database integrity check. Large records and visited-page tracking can
consume memory proportional to the data being read.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
