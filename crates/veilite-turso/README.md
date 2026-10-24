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
- A complete, checkpointed, immutable main database with a UTF-8 path and
  UTF-8 text encoding. Keep the file unchanged while the connection is open.
- A schema supported by `turso_core = 0.8.3`. STORED generated columns prevent
  opening the database in this version.

WAL and rollback-journal companions are rejected. The adapter does not acquire
a snapshot from a live database.

## Behavior

Opening authenticates the first page; other pages are authenticated as they
are read. This does not verify the entire database. Open-time authentication
errors preserve `DecryptError`; query-time failures use Turso's error types.
Streaming callbacks may receive valid earlier rows before a later read fails.

The encrypted main file is read-only and `query_only` is enabled. Use trusted
SQL: the native connection can change settings and access other databases
through operations such as `ATTACH`.

Derived keys are zeroized on drop. Turso's plaintext caches and query results
are not guaranteed to be zeroized when released.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
