# Veilite

Veilite provides libraries and a CLI for reading immutable SQLCipher database
snapshots.

All components are implemented in Rust without C SQLCipher, C SQLite, or
OpenSSL. Rust 1.89 or newer is required.

## Components

- `sqlite-source` provides shared byte and page source interfaces. See its
  [README](crates/sqlite-source/README.md).
- `veilite-turso` runs SQL queries over encrypted snapshots using Turso. See its
  [README](crates/veilite-turso/README.md).
- `veilite-core` provides authenticated random-access page reads and
  AES-256-CBC decryption.
- `veilite` is the command-line interface for inspecting, verifying, and
  exporting snapshots.

## Compatibility

Veilite supports the default SQLCipher 3 and 4 profiles. Custom configurations
can select the page size, KDF iteration count, PBKDF2-HMAC algorithm, and page
HMAC algorithm. The profile or complete custom configuration must be supplied
explicitly; it is not auto-detected.

Input must be an immutable main database snapshot created after all transactions
have completed and the originating application has checkpointed and cleanly
closed the database. Removing existing `-wal` or `-journal` files does not
produce a valid snapshot.

Live databases, writes to encrypted databases, database creation, rekeying,
SQLCipher 1 or 2 presets, raw keys, disabled page HMACs, and plaintext headers
are not supported.

## CLI

```console
git clone https://github.com/broot5/veilite.git
cd veilite
cargo install --locked --path crates/veilite-cli
```

Choose a preset with `--preset 3` or `--preset 4`:

```console
# Show snapshot metadata without requesting a passphrase
veilite inspect --preset 4 encrypted.db

# Authenticate every page
veilite verify --preset 4 encrypted.db

# Export a plaintext SQLite image
veilite export --preset 4 encrypted.db plaintext.db
```

For a custom configuration, supply all four cipher parameters explicitly:

```console
veilite verify --custom \
  --page-size 2048 \
  --kdf-iterations 100000 \
  --kdf-algorithm sha256 \
  --hmac-algorithm sha256 \
  encrypted.db
```

`verify` and `export` prompt for a passphrase. Use
`--passphrase-file FILE` to read it from the first line of a file. `inspect`
reports sibling `-wal` and `-journal` files; the other commands reject them.

`export` does not overwrite an existing destination. Run `veilite help` or
`veilite <command> --help` for the full CLI reference.

`verify` authenticates every physical page present in the file; it does not
establish SQLite logical integrity or prove that the snapshot is complete or
current. Removing whole pages from the end may not be detected by authentication
of the remaining pages.

## Libraries

### `veilite-core`

```rust
use std::num::NonZeroU32;
use veilite_core::{CipherConfig, CipherPreset, FileSource, SqlCipherReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = FileSource::open("encrypted.db")?;
    let config = CipherConfig::from(CipherPreset::SqlCipher4);
    let reader = SqlCipherReader::open(source, config, b"example passphrase")?;
    let mut page = vec![0; reader.page_size()];

    reader.read_page_into(NonZeroU32::MIN, &mut page)?;
    Ok(())
}
```

Opening a reader derives keys but does not authenticate the entire database.
Pages are authenticated as they are read; use `veilite verify` for a full
check.

### `veilite-turso`

Use `veilite_turso::open_readonly(path, config, passphrase)` to obtain a native
Turso connection. See the [binding and query example](crates/veilite-turso/README.md).

The pinned Turso engine requires UTF-8 database text and does not support STORED
generated columns. These restrictions apply to SQL queries through
`veilite-turso`; core page reading and the CLI do not use the SQL engine.
Use trusted SQL with the native connection. Read-only protection covers the
encrypted main file; the connection is not a sandbox for other file access.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Contributions are dual-licensed on
the same terms unless explicitly stated otherwise.

Veilite is not affiliated with or endorsed by Zetetic, LLC. SQLCipher is a
registered trademark of Zetetic, LLC.
