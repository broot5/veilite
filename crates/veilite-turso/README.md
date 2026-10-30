# veilite-turso

Read immutable SQLCipher snapshots using Turso's Rust SQL engine and Veilite's
authenticated page decryption. No C SQLite, C SQLCipher, or OpenSSL is needed.

```rust,no_run
use std::num::NonZeroUsize;
use veilite_core::CipherPreset;
use veilite_turso::{open_readonly, turso};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let conn = open_readonly("encrypted.db", CipherPreset::SqlCipher3.into(), b"passphrase")?;
    let mut statement = conn.prepare("SELECT name FROM people WHERE id = ?1")?;
    statement.bind_at(NonZeroUsize::MIN, turso::Value::from_i64(1))?;
    statement.run_with_row_callback(|row| {
        let name: String = row.get(0)?;
        println!("{name}");
        Ok(())
    })?;
    Ok(())
}
```

Use `veilite-core` for cipher configuration and the re-exported `turso` module
for connection, statement, value, and error types. Reuse connections and
prepared statements for repeated queries.

## Requirements

- An explicit SQLCipher 3, SQLCipher 4, or complete custom configuration.
- A checkpointed main snapshot or consistent DB/WAL pair. Keep files and
  directory entries unchanged throughout use; live snapshots are not acquired.
- UTF-8 paths and database text, and a schema supported by `turso_core = 0.8.3`.
  STORED generated columns are unsupported.

## WAL snapshots

`open_readonly` rejects WAL. Use `open_readonly_with_wal(path, config, passphrase)`
for a DB/WAL pair. A regular `-wal` must exist beside the canonical main path;
a WAL beside a symlink alias must resolve to the same file. Rollback journals
are always rejected.

Turso selects the last valid commit. Invalid or incomplete tails may be ignored;
empty or short WAL files may yield main-only state. Page HMAC and I/O errors
fail without falling back to an older commit.

For page traversal, call `snapshot::WalInput::open(path)`, then
`input.snapshot(config, passphrase)` and `visit_pages(callback)`. This
consumes the snapshot and authenticates all selected pages, including unused
pages, under the same schema restrictions as queries. Standalone exports must
set page 1 bytes 18 and 19 to 1; the CLI handles this automatically.

## Behavior

Opening authenticates main page 1; other pages are authenticated on read.
Open-time authentication errors preserve `DecryptError`; query failures use
Turso errors. Row and page callbacks may receive valid data before a later
failure. Authentication does not audit WAL history or prove logical integrity,
completeness, or freshness.

Inputs are read-only and `query_only` is enabled. Use trusted SQL: native
connections can change settings and access other databases through `ATTACH`.
Derived keys are zeroized on drop; plaintext caches and results may not be.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
