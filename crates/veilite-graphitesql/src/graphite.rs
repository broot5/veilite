use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use graphitesql::vfs::{File, OpenFlags, Vfs};
use graphitesql::{Connection as GraphiteConnection, Error as GraphiteError};
use thiserror::Error;
use zeroize::Zeroizing;

use veilite_core::{CipherConfig, DecryptError, FileSource, ReaderError, SqlCipherReader};

use crate::companion::{JOURNAL_SUFFIX, WAL_SUFFIX, companion_path};
use crate::{CompanionError, check_companion_files};

const READ_ONLY_ERROR: &str = "database is read-only";
const WAL_ERROR: &str = "SQLCipher WAL files are unsupported";
const JOURNAL_ERROR: &str = "SQLCipher rollback journals are unsupported";

/// Error returned while opening through the GraphiteSQL adapter.
#[derive(Debug, Error)]
pub enum GraphiteAdapterError {
    /// GraphiteSQL cannot represent the database path as UTF-8.
    #[error("database path is not valid UTF-8: {path:?}")]
    NonUtf8Path {
        /// Rejected database path.
        path: PathBuf,
    },
    /// The immutable snapshot companion-file policy was not satisfied.
    #[error(transparent)]
    Companion(#[from] CompanionError),
    /// GraphiteSQL failed while opening the database.
    #[error("GraphiteSQL failed to open the database: {source}")]
    Open {
        /// Original GraphiteSQL error.
        #[source]
        source: GraphiteError,
    },
}

struct SqlCipherFile {
    reader: SqlCipherReader<FileSource>,
}

impl File for SqlCipherFile {
    fn read_exact_at(&self, output: &mut [u8], offset: u64) -> graphitesql::Result<()> {
        self.reader
            .read_exact_at(offset, output)
            .map_err(map_reader_error)
    }

    fn write_all_at(&mut self, _contents: &[u8], _offset: u64) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn truncate(&mut self, _size: u64) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn sync(&mut self) -> graphitesql::Result<()> {
        Ok(())
    }

    fn size(&self) -> graphitesql::Result<u64> {
        Ok(self.reader.file_size())
    }
}

struct SqlCipherVfs {
    main_path: PathBuf,
    main_path_utf8: String,
    config: CipherConfig,
    passphrase: Zeroizing<Vec<u8>>,
}

impl SqlCipherVfs {
    fn new(
        path: impl AsRef<Path>,
        config: CipherConfig,
        passphrase: &[u8],
    ) -> Result<Self, GraphiteAdapterError> {
        let main_path = path.as_ref().to_path_buf();
        let main_path_utf8 = main_path
            .to_str()
            .ok_or_else(|| GraphiteAdapterError::NonUtf8Path {
                path: main_path.clone(),
            })?
            .to_owned();

        Ok(Self {
            main_path,
            main_path_utf8,
            config,
            passphrase: Zeroizing::new(passphrase.to_vec()),
        })
    }
}

impl Vfs for SqlCipherVfs {
    fn open(&self, path: &str, flags: OpenFlags) -> graphitesql::Result<Box<dyn File>> {
        if flags != OpenFlags::READ_ONLY {
            return Err(read_only_error());
        }
        if path != self.main_path_utf8 {
            if OsStr::new(path) == companion_path(&self.main_path, WAL_SUFFIX).as_os_str() {
                return Err(GraphiteError::Unsupported(WAL_ERROR));
            }
            if OsStr::new(path) == companion_path(&self.main_path, JOURNAL_SUFFIX).as_os_str() {
                return Err(GraphiteError::Unsupported(JOURNAL_ERROR));
            }
            return Err(GraphiteError::CantOpen(path.to_owned()));
        }

        check_companion_files(&self.main_path).map_err(map_companion_to_graphite)?;
        let source = FileSource::open(&self.main_path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => GraphiteError::CantOpen(path.to_owned()),
            _ => GraphiteError::Io(error.to_string()),
        })?;
        let reader = SqlCipherReader::open(source, self.config, self.passphrase.as_slice())
            .map_err(map_reader_error)?;

        Ok(Box::new(SqlCipherFile { reader }))
    }

    fn delete(&self, _path: &str) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn exists(&self, path: &str) -> graphitesql::Result<bool> {
        Path::new(path)
            .try_exists()
            .map_err(|error| GraphiteError::Io(error.to_string()))
    }
}

/// Opens an immutable encrypted main database through a read-only GraphiteSQL VFS.
///
/// The path must be valid UTF-8, and sibling `-wal` and `-journal` files are
/// rejected before the main database is opened. The caller must ensure the
/// source remains unchanged for the connection's lifetime.
///
/// Returns the native GraphiteSQL connection. Read-only protection applies to
/// the encrypted main file through this VFS, not to the entire connection:
/// GraphiteSQL can create or write other databases through `ATTACH` and use
/// temporary tables. Operations outside this VFS are the caller's responsibility.
/// In GraphiteSQL 0.1.6, `ATTACH` can create and attach a file before returning
/// a read-only error during main-database autocommit; errors do not guarantee
/// absence of side effects outside this VFS.
pub fn open_readonly(
    path: impl AsRef<Path>,
    config: CipherConfig,
    passphrase: &[u8],
) -> Result<GraphiteConnection, GraphiteAdapterError> {
    let vfs = SqlCipherVfs::new(path, config, passphrase)?;
    check_companion_files(&vfs.main_path)?;
    GraphiteConnection::open_readonly_vfs(&vfs, &vfs.main_path_utf8)
        .map_err(|source| GraphiteAdapterError::Open { source })
}

fn read_only_error() -> GraphiteError {
    GraphiteError::Error(READ_ONLY_ERROR.to_owned())
}

fn map_companion_to_graphite(error: CompanionError) -> GraphiteError {
    match error {
        CompanionError::UnsupportedWal { .. } => GraphiteError::Unsupported(WAL_ERROR),
        CompanionError::UnsupportedJournal { .. } => GraphiteError::Unsupported(JOURNAL_ERROR),
        io_error @ CompanionError::Io { .. } => GraphiteError::Io(io_error.to_string()),
    }
}

fn map_reader_error(error: ReaderError<io::Error>) -> GraphiteError {
    match error {
        ReaderError::Source(source) => GraphiteError::Io(source.to_string()),
        empty_passphrase @ ReaderError::Decrypt(DecryptError::EmptyPassphrase) => {
            GraphiteError::Error(empty_passphrase.to_string())
        }
        other => GraphiteError::Corrupt(other.to_string()),
    }
}

#[cfg(test)]
mod tests;
