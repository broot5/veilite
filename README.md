# Veilite

Veilite provides libraries and a CLI for reading immutable SQLCipher database
snapshots.

All components are implemented in Rust without C SQLCipher, C SQLite, or
OpenSSL. Rust 1.89 or newer is required.

## Components

- `veilite-turso` queries encrypted snapshots, including WAL, using Turso. See its [README](crates/veilite-turso/README.md).
- `veilite-core` provides authenticated random-access page reads and
  AES-256-CBC decryption.
- `veilite` is the command-line interface for inspecting, verifying, and
  exporting snapshots.

## Compatibility

Veilite supports the default SQLCipher 3 and 4 profiles. Custom configurations
can select the page size, KDF iteration count, PBKDF2-HMAC algorithm, and page
HMAC algorithm. The profile or complete custom configuration must be supplied
explicitly; it is not auto-detected.

Input must be immutable: a checkpointed, cleanly closed main database, or a
consistent main database and sibling `-wal` in explicit WAL mode. Copying files
while a writer is active or removing companions does not ensure a valid snapshot.

WAL mode reads Turso's last valid commit. Invalid or incomplete tails may be
ignored; empty or short WAL files may yield main-only state. Authentication
and I/O errors fail the operation.

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

# Read a consistent, immutable encrypted.db + encrypted.db-wal pair
veilite verify --wal --preset 4 encrypted.db
veilite export --wal --preset 4 encrypted.db plaintext.db
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

`verify` and `export` prompt for a passphrase, or read the first line of
`--passphrase-file FILE`. `inspect` reports WAL and journal companions.
Other commands reject WAL unless `--wal` is supplied; rollback journals are
always rejected. WAL must be a regular file beside the canonical main path,
with no conflicting WAL beside a symlink alias.

`verify` authenticates every main-file page, or every selected snapshot page
with `--wal`, including unused pages. It does not audit WAL history or prove
logical integrity, completeness, or freshness.

`export` creates a standalone plaintext SQLite image without overwriting an
existing destination. Run `veilite <command> --help` for all options.

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

Use `veilite_turso::open_readonly` for a main-only snapshot or
`open_readonly_with_wal` for a DB/WAL pair. Both return a native Turso connection;
`snapshot::WalInput` provides WAL snapshot page traversal. See the
[usage and requirements](crates/veilite-turso/README.md).

Turso queries and CLI `--wal` require UTF-8 paths and database text, and do not
support STORED generated columns. Use trusted SQL: read-only input protection
is not a sandbox for other file access.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option. Contributions are dual-licensed on
the same terms unless explicitly stated otherwise.

Veilite is not affiliated with or endorsed by Zetetic, LLC. SQLCipher is a
registered trademark of Zetetic, LLC.
