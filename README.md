# Veilite

Veilite is a pure Rust library and CLI for reading immutable
SQLCipher database snapshots. It authenticates and decrypts pages, exports
plaintext SQLite images, and runs read-only queries through
[GraphiteSQL](https://github.com/KarpelesLab/graphitesql).

## Compatibility

Veilite supports the default SQLCipher 3 and 4 profiles, along with custom
page size, KDF, and page HMAC settings. Profiles must be selected explicitly;
they are not auto-detected.

Input must be an immutable main database snapshot created after all transactions
have completed and the originating application has checkpointed and cleanly
closed the database. Removing existing `-wal` or `-journal` files does not
produce a valid snapshot.

Live databases, writes, database creation, rekeying, SQLCipher 1 or 2 presets,
raw keys, disabled page HMACs, and plaintext headers are not supported.

## Install

```console
git clone https://github.com/broot5/veilite.git
cd veilite
cargo install --locked --path crates/veilite-cli
```

## CLI

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

Use `--custom` with a page size, KDF iteration count, KDF algorithm, and HMAC
algorithm to supply a complete custom configuration.

`verify`, `export`, and `query` prompt for a passphrase unless
`--passphrase-file` is provided. Run `veilite help` or
`veilite <command> --help` for the full CLI reference.

## Library

Use `veilite-core` for authenticated page access and `veilite-graphitesql` for
read-only SQL queries:

```rust
use std::num::NonZeroU32;
use veilite_core::{CipherConfig, CipherPreset, FileSource, SqlCipherReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = FileSource::open("encrypted.db")?;
    let config = CipherConfig::from(CipherPreset::SqlCipher4);
    let reader = SqlCipherReader::open(source, config, b"example passphrase")?;
    let mut page = vec![0; reader.page_size()];

    reader.read_page_into(NonZeroU32::new(1).unwrap(), &mut page)?;
    Ok(())
}
```

Opening a reader derives keys but does not authenticate the entire database.
Pages are authenticated as they are read; use `veilite verify` for a full
check.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Contributions are dual-licensed on
the same terms unless explicitly stated otherwise.

Veilite is not affiliated with or endorsed by Zetetic, LLC. SQLCipher is a
registered trademark of Zetetic, LLC.
