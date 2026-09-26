# sqlite-source

Byte and page source interfaces for immutable SQLite snapshots in Rust.
Requires Rust 1.89 or newer.

## Usage

Add the crate from a local checkout, adjusting the path to your project:

```toml
[dependencies]
sqlite-source = { path = "../veilite/crates/sqlite-source" }
```

```rust
use sqlite_source::{ReadAt, SliceSource};

fn main() -> Result<(), std::io::Error> {
    let source = SliceSource::new(b"snapshot");
    let mut bytes = [0; 4];
    source.read_exact_at(0, &mut bytes)?;
    assert_eq!(&bytes, b"snap");
    Ok(())
}
```

Use `FileSource::open(path)` for files or implement `ReadAt` for a custom byte
source. Implement `PageSource` to supply complete SQLite pages.

## Support

- `ReadAt`: byte reads at absolute offsets, independent of a shared file cursor.
- `FileSource`: file reads on Unix and Windows.
- `SliceSource`: reads from an immutable byte slice.
- `PageSource`: one-based page reads with snapshot page size and count.

## Limits

Source contents and length must remain unchanged while in use. This crate does
not acquire locks, parse SQLite structures, or decrypt pages.

`PageSource` implementations must include reserved bytes, reject invalid page
numbers and buffer lengths, and clear the output on failure. Encrypted sources
must authenticate pages before returning plaintext.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
