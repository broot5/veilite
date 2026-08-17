use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

const WAL_SUFFIX: &str = "-wal";
const JOURNAL_SUFFIX: &str = "-journal";

#[derive(Debug, Error)]
pub enum CompanionError {
    #[error("SQLCipher WAL companion file is unsupported: {path:?}")]
    UnsupportedWal { path: PathBuf },
    #[error("SQLCipher rollback journal companion file is unsupported: {path:?}")]
    UnsupportedJournal { path: PathBuf },
    #[error("failed to inspect companion path {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

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
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(CompanionError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub(crate) fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    companion.into()
}
