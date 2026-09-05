# Veilite

Veilite provides libraries and a CLI for reading immutable SQLCipher database
snapshots.

All components are implemented in Rust without C SQLCipher, C SQLite, or
OpenSSL. Rust 1.89 or newer is required.

## Components

- `veilite-core` provides authenticated random-access page reads and
  AES-256-CBC decryption.
- `veilite-graphitesql` runs read-only SQL queries through
  [GraphiteSQL](https://github.com/KarpelesLab/graphitesql).
- `veilite` is the command-line interface for inspecting, verifying, exporting,
  and querying snapshots.

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

# Run a read-only query
veilite query --preset 4 encrypted.db 'SELECT id, title FROM notes ORDER BY id'
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

`verify`, `export`, and `query` prompt for a passphrase. Use
`--passphrase-file FILE` to read it from the first line of a file. `inspect`
reports sibling `-wal` and `-journal` files; the other commands reject them.

`export` does not overwrite an existing destination. Query output is
human-readable and is not a stable machine-readable format. Run `veilite help`
or `veilite <command> --help` for the full CLI reference.

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

### `veilite-graphitesql`

```rust
use veilite_graphitesql::{CipherPreset, open_readonly};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = open_readonly(
        "encrypted.db",
        CipherPreset::SqlCipher4.into(),
        b"example passphrase",
    )?;
    let result = connection.query("SELECT id, title FROM notes ORDER BY id")?;

    println!("{result:#?}");
    Ok(())
}
```

`open_readonly` returns a native `graphitesql::Connection` for use with
GraphiteSQL's API. The adapter rejects sibling `-wal` and `-journal` files and
protects the encrypted main file from writes through its VFS. Other file access,
such as `ATTACH`, follows GraphiteSQL's behavior. Keep the source snapshot
unchanged while the connection is open.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Contributions are dual-licensed on
the same terms unless explicitly stated otherwise.

Veilite is not affiliated with or endorsed by Zetetic, LLC. SQLCipher is a
registered trademark of Zetetic, LLC.
