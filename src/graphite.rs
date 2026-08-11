use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use graphitesql::vfs::{File, OpenFlags, Vfs};
use graphitesql::{Connection, Error as GraphiteError};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{CompatibilityProfile, DecryptError, FileSource, ReaderError, SqlCipherReader};

const WAL_SUFFIX: &str = "-wal";
const JOURNAL_SUFFIX: &str = "-journal";
const READ_ONLY_ERROR: &str = "database is read-only";
const WAL_ERROR: &str = "SQLCipher WAL files are unsupported";
const JOURNAL_ERROR: &str = "SQLCipher rollback journals are unsupported";

#[derive(Debug, Error)]
pub enum GraphiteAdapterError {
    #[error("database path is not valid UTF-8: {path:?}")]
    NonUtf8Path { path: PathBuf },
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
    #[error("GraphiteSQL failed to open the database: {0}")]
    Graphite(#[from] GraphiteError),
}

impl GraphiteAdapterError {
    fn into_graphite(self) -> GraphiteError {
        match self {
            Self::UnsupportedWal { .. } => GraphiteError::Unsupported(WAL_ERROR),
            Self::UnsupportedJournal { .. } => GraphiteError::Unsupported(JOURNAL_ERROR),
            io_error @ Self::Io { .. } => GraphiteError::Io(io_error.to_string()),
            path_error @ Self::NonUtf8Path { .. } => {
                GraphiteError::CantOpen(path_error.to_string())
            }
            Self::Graphite(source) => source,
        }
    }
}

pub struct SqlCipherFile {
    reader: SqlCipherReader<FileSource>,
}

impl SqlCipherFile {
    #[must_use]
    pub fn new(reader: SqlCipherReader<FileSource>) -> Self {
        Self { reader }
    }
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

pub struct SqlCipherVfs {
    main_path: PathBuf,
    main_path_utf8: String,
    profile: CompatibilityProfile,
    passphrase: Zeroizing<Vec<u8>>,
}

impl SqlCipherVfs {
    pub fn new(
        path: impl AsRef<Path>,
        profile: CompatibilityProfile,
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
            profile,
            passphrase: Zeroizing::new(passphrase.to_vec()),
        })
    }

    pub fn open_readonly(&self) -> Result<Connection, GraphiteAdapterError> {
        check_companion_files(&self.main_path)?;
        Connection::open_readonly_vfs(self, &self.main_path_utf8).map_err(Into::into)
    }
}

impl Vfs for SqlCipherVfs {
    fn open(&self, path: &str, flags: OpenFlags) -> graphitesql::Result<Box<dyn File>> {
        if flags != OpenFlags::READ_ONLY {
            return Err(read_only_error());
        }
        if path != self.main_path_utf8 {
            if path == companion_path_string(&self.main_path_utf8, WAL_SUFFIX) {
                return Err(GraphiteError::Unsupported(WAL_ERROR));
            }
            if path == companion_path_string(&self.main_path_utf8, JOURNAL_SUFFIX) {
                return Err(GraphiteError::Unsupported(JOURNAL_ERROR));
            }
            return Err(GraphiteError::CantOpen(path.to_owned()));
        }

        // Callers may invoke `Vfs::open` directly without going through
        // `open_readonly`, so check for companion files before opening the main
        // database.
        check_companion_files(&self.main_path).map_err(GraphiteAdapterError::into_graphite)?;
        let source = FileSource::open(&self.main_path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => GraphiteError::CantOpen(path.to_owned()),
            _ => GraphiteError::Io(error.to_string()),
        })?;
        let reader = SqlCipherReader::open(source, self.profile, self.passphrase.as_slice())
            .map_err(map_reader_error)?;

        Ok(Box::new(SqlCipherFile::new(reader)))
    }

    fn delete(&self, _path: &str) -> graphitesql::Result<()> {
        Err(read_only_error())
    }

    fn exists(&self, path: &str) -> graphitesql::Result<bool> {
        match fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(GraphiteError::Io(error.to_string())),
        }
    }
}

pub fn open_readonly(
    path: impl AsRef<Path>,
    profile: CompatibilityProfile,
    passphrase: &[u8],
) -> Result<Connection, GraphiteAdapterError> {
    SqlCipherVfs::new(path, profile, passphrase)?.open_readonly()
}

fn read_only_error() -> GraphiteError {
    GraphiteError::Error(READ_ONLY_ERROR.to_owned())
}

fn check_companion_files(path: &Path) -> Result<(), GraphiteAdapterError> {
    let wal_path = companion_path(path, WAL_SUFFIX);
    if path_exists(&wal_path)? {
        return Err(GraphiteAdapterError::UnsupportedWal { path: wal_path });
    }

    let journal_path = companion_path(path, JOURNAL_SUFFIX);
    if path_exists(&journal_path)? {
        return Err(GraphiteAdapterError::UnsupportedJournal { path: journal_path });
    }

    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, GraphiteAdapterError> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(GraphiteAdapterError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut companion = path.as_os_str().to_os_string();
    companion.push(suffix);
    companion.into()
}

fn companion_path_string(path: &str, suffix: &str) -> String {
    let mut companion = String::with_capacity(path.len() + suffix.len());
    companion.push_str(path);
    companion.push_str(suffix);
    companion
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
