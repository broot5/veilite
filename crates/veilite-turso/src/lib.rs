//! SQL queries over immutable SQLCipher main database snapshots.
//!
//! [`open_readonly`] authenticates page 1 before opening Turso, including when
//! the file already has a cached database in this process. Subsequent pages are
//! authenticated on demand. It returns Turso's native connection and query API.
//!
//! Only UTF-8 databases supported by the pinned Turso engine can be queried.
//! WAL, rollback journals, live databases, and writes to the encrypted main
//! database are unsupported. SQL must be trusted: the native connection is
//! not a sandbox for SQL that accesses other files (for example, `ATTACH`).
//!
//! ```no_run
//! use std::num::NonZeroUsize;
//! use veilite_turso::{open_readonly, turso};
//! use veilite_core::CipherPreset;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let conn = open_readonly("encrypted.db", CipherPreset::SqlCipher3.into(), b"passphrase")?;
//! let mut stmt = conn.prepare("SELECT name FROM people WHERE id = ?1")?;
//! stmt.bind_at(NonZeroUsize::MIN, turso::Value::from_i64(1))?;
//! stmt.run_with_row_callback(|row| {
//!     let name: String = row.get(0)?;
//!     println!("{name}");
//!     Ok(())
//! })?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod codec;

use std::{io, num::NonZeroU32, path::Path, sync::Arc};
use thiserror::Error;
use veilite_core::{CipherConfig, DecryptError, FileSource, PageDecryptor, ReadAt, ReaderError};
use zeroize::Zeroizing;

/// The pinned Turso engine, re-exported for query, value, and error types.
pub use turso_core as turso;

/// Failure to open an immutable encrypted database.
#[derive(Debug, Error)]
pub enum OpenError {
    /// Filesystem inspection or opening failed.
    #[error("database filesystem access failed: {0}")]
    Io(#[from] io::Error),
    /// Turso requires UTF-8 paths.
    #[error("database path is not valid UTF-8")]
    NonUtf8Path,
    /// A WAL or rollback journal exists beside the supplied or resolved path.
    #[error("unsupported database companion: {0:?}")]
    Companion(std::path::PathBuf),
    /// The physical source length is invalid for the supplied configuration.
    #[error(transparent)]
    Source(#[from] ReaderError<io::Error>),
    /// Key derivation or first-page authentication/header validation failed.
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    /// Turso rejected the schema, header, or connection.
    #[error("Turso failed to open the database: {0}")]
    Turso(#[from] turso::LimboError),
}

/// Opens a read-only SQL connection to a complete, immutable SQLCipher snapshot.
///
/// Supply an explicit, validated configuration. The caller must ensure that the
/// main file and its directory entries remain unchanged for the connection's
/// lifetime. Companion checks are preflight checks, not snapshot acquisition.
/// Passphrase bytes are borrowed only during key derivation; derived keys are
/// zeroized when the last owning pager/statement releases them.
///
/// The encrypted main file is opened read-only, and `query_only` is enabled.
/// The returned native connection can change connection settings and access
/// other databases; use trusted SQL. Turso owns plaintext page caches and query
/// values, whose memory is not guaranteed to be zeroized on release.
///
/// # Errors
///
/// Returns [`OpenError`] for companion files, invalid lengths, authentication
/// failure, unsupported encoding/schema, and I/O or engine failures. Later
/// query-time codec failures are reported by Turso as `PageCodecError` with a
/// page index; Turso does not preserve the original [`DecryptError`].
pub fn open_readonly(
    path: impl AsRef<Path>,
    config: CipherConfig,
    passphrase: &[u8],
) -> Result<Arc<turso::Connection>, OpenError> {
    if passphrase.is_empty() {
        return Err(DecryptError::EmptyPassphrase.into());
    }
    let path = path.as_ref();
    check_companions(path)?;
    let resolved = path.canonicalize()?;
    check_companions(&resolved)?;
    let path = resolved.to_str().ok_or(OpenError::NonUtf8Path)?;
    let source = FileSource::open(&resolved)?;
    let size = source.len()?;
    let page_size = config.page_size();
    let page_size_u64 = page_size as u64;
    let invalid = if size == 0 {
        Some(ReaderError::EmptyFile)
    } else if size < page_size_u64 {
        Some(ReaderError::FileTooSmall {
            file_size: size,
            page_size,
        })
    } else if !size.is_multiple_of(page_size_u64) {
        Some(ReaderError::InvalidFileSize {
            file_size: size,
            page_size,
        })
    } else {
        None
    };
    if let Some(error) = invalid {
        return Err(OpenError::Source(error));
    }
    let count = size / page_size_u64;
    let page_count = u32::try_from(count)
        .map_err(|_| OpenError::Source(ReaderError::TooManyPages { page_count: count }))?;
    let mut salt = [0; 16];
    source.read_exact_at(0, &mut salt)?;
    let decoder = PageDecryptor::new(config, passphrase, &salt)?;

    // Always authenticate with this caller's key, before Turso can reuse any
    // schema or database state from its process-wide file registry.
    let mut first_page = Zeroizing::new(vec![0; page_size]);
    source.read_exact_at(0, &mut first_page)?;
    decoder.decrypt_page_in_place(NonZeroU32::MIN, &mut first_page)?;
    drop(first_page);

    let codec: Arc<dyn turso::PageCodec> = Arc::new(codec::SqlCipherCodec::new(
        decoder, config, salt, page_count,
    ));
    let io = Arc::new(turso::PlatformIO::new()?);
    let options = turso::OpenOptions::new(Arc::new(turso::SqliteDialect))
        .flags(turso::OpenFlags::ReadOnly)
        .page_codec(Some(codec.clone()));
    let database = turso::Database::open(io, path, options)?;
    let connection = database.connect_with_page_codec(codec)?;
    connection.set_query_only(true);
    Ok(connection)
}

fn check_companions(path: &Path) -> Result<(), OpenError> {
    for suffix in ["-wal", "-journal"] {
        let mut companion = path.as_os_str().to_owned();
        companion.push(suffix);
        let companion = std::path::PathBuf::from(companion);
        // Also reject dangling symlinks rather than treating them as absent.
        match companion.symlink_metadata() {
            Ok(_) => return Err(OpenError::Companion(companion)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
