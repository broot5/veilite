//! SQL queries and page traversal over immutable SQLCipher snapshots.
//!
//! [`open_readonly`] authenticates page 1 before opening Turso, including when
//! the file already has a cached database in this process. Subsequent pages are
//! authenticated on demand. It returns Turso's native connection and query API.
//!
//! Only UTF-8 databases supported by the pinned Turso engine can be queried.
//! [`open_readonly_with_wal`] explicitly accepts a consistent immutable DB/WAL
//! pair. [`snapshot`] provides authenticated traversal of the selected image.
//! Rollback journals, live databases, and encrypted writes are unsupported.
//! SQL must be trusted: the native connection is
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
pub mod snapshot;

use std::{io, path::Path, sync::Arc};
use thiserror::Error;
use veilite_core::{CipherConfig, DecryptError, ReaderError};

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
    /// A WAL path is ambiguous or does not refer to a regular file.
    #[error("invalid WAL snapshot input: {0}")]
    WalInput(String),
    /// The selected snapshot size cannot be represented by the input pages.
    #[error("invalid snapshot page count {count}; input can contain at most {maximum} pages")]
    SnapshotSize {
        /// Page count reported by the engine.
        count: i64,
        /// Conservative bound from main-file pages and complete WAL frames.
        maximum: u32,
    },
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
    snapshot::open_main(path.as_ref(), config, passphrase)
}

/// Opens an immutable main database and its required sibling `-wal` for SQL queries.
///
/// The caller must supply a consistent, unchanging DB/WAL pair. Turso selects
/// the last valid commit; an incomplete or checksum-invalid tail may be ignored.
/// Page authentication and I/O errors fail the operation, without retrying an
/// earlier commit. This does not acquire a snapshot from a live database.
///
/// The same schema, trusted-SQL and plaintext-cache limitations as
/// [`open_readonly`] apply. Rollback journals are rejected. WAL is resolved
/// beside the canonical main path; conflicting companions beside a symlink
/// alias are rejected. The main file and WAL are opened read-only.
///
/// # Errors
///
/// Returns [`OpenError`] on invalid inputs, authentication or engine failures.
/// Subsequent query errors use Turso's error types.
pub fn open_readonly_with_wal(
    path: impl AsRef<Path>,
    config: CipherConfig,
    passphrase: &[u8],
) -> Result<Arc<turso::Connection>, OpenError> {
    snapshot::WalInput::open(path)?
        .connect(config, passphrase)
        .map(|(connection, _)| connection)
}
