use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub(super) const WAL_SUFFIX: &str = "-wal";
pub(super) const JOURNAL_SUFFIX: &str = "-journal";

/// Error returned while enforcing the immutable main-database policy.
#[derive(Debug, Error)]
pub enum CompanionError {
    /// A sibling write-ahead log is present.
    #[error("SQLCipher WAL companion file is unsupported: {path:?}")]
    UnsupportedWal {
        /// Detected `-wal` path.
        path: PathBuf,
    },
    /// A sibling rollback journal is present.
    #[error("SQLCipher rollback journal companion file is unsupported: {path:?}")]
    UnsupportedJournal {
        /// Detected `-journal` path.
        path: PathBuf,
    },
    /// A companion path could not be inspected.
    #[error("failed to inspect companion path {path:?}: {source}")]
    Io {
        /// Companion path being inspected.
        path: PathBuf,
        /// Filesystem error returned while inspecting the path.
        #[source]
        source: io::Error,
    },
}

/// Rejects a main database path when an unsupported WAL or journal exists.
///
/// This function only performs a preflight check. Callers must still ensure the
/// database remains an immutable snapshot throughout its use.
pub fn check_companion_files(path: impl AsRef<Path>) -> Result<(), CompanionError> {
    let path = path.as_ref();
    let wal_path = companion_path(path, WAL_SUFFIX);
    if path_exists(&wal_path)? {
        return Err(CompanionError::UnsupportedWal { path: wal_path });
    }

    let journal_path = companion_path(path, JOURNAL_SUFFIX);
    if path_exists(&journal_path)? {
        return Err(CompanionError::UnsupportedJournal { path: journal_path });
    }

    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, CompanionError> {
    path.try_exists().map_err(|source| CompanionError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Constructs a sibling companion path by appending `suffix`.
pub(super) fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    companion.into()
}
