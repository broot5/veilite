//! Authenticated page traversal of immutable SQLCipher DB/WAL snapshots.
//!
//! Turso selects the last valid commit, including when a trailing transaction
//! is incomplete or has invalid WAL checksums. Traversal authenticates every
//! page in that selected image, not every historical WAL frame, and does not
//! prove logical integrity, completeness or freshness. Input acquisition and
//! immutability are the caller's responsibility.
//!
//! The pinned engine's UTF-8 and schema restrictions apply to this path too.
//! Engine-owned plaintext caches are not guaranteed to be zeroized.
//!
//! ```no_run
//! use veilite_core::CipherPreset;
//! use veilite_turso::snapshot::WalInput;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let input = WalInput::open("encrypted.db")?;
//! let snapshot = input.snapshot(CipherPreset::SqlCipher4.into(), b"passphrase")?;
//! println!("selected {} pages", snapshot.page_count());
//! snapshot.visit_pages(|_number, _page| Ok(()))?;
//! # Ok(())
//! # }
//! ```

use std::{
    fs, io,
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::Arc,
};

use thiserror::Error;
use veilite_core::{CipherConfig, DecryptError, FileSource, PageDecryptor, ReadAt, ReaderError};
use zeroize::Zeroizing;

use crate::{OpenError, codec, turso};

/// A preflight-checked, canonical main path and its sibling WAL.
///
/// Construction does not derive keys or authenticate pages. Both files and
/// their directory entries must remain unchanged from construction until all
/// connections and snapshots using this input have been released.
pub struct WalInput {
    path: PathBuf,
    wal_size: u64,
}

impl WalInput {
    /// Checks the input before a caller requests a passphrase.
    ///
    /// Requires regular main and WAL files. Rejects rollback journals at the
    /// supplied and canonical paths, including dangling links. The WAL lives
    /// beside the canonical main path. A WAL beside an alias must resolve to
    /// that same WAL path, otherwise the pair is ambiguous and is rejected.
    /// Empty and short WAL files are permitted; the engine may select main-only
    /// state. A missing WAL is an error rather than an implicit main-only open.
    ///
    /// # Errors
    /// Returns [`OpenError`] for filesystem, companion or path failures.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let path = path.as_ref();
        reject_journal(path)?;
        let resolved = path.canonicalize()?;
        reject_journal(&resolved)?;
        if !fs::metadata(&resolved)?.is_file() {
            return Err(OpenError::WalInput(
                "main database is not a regular file".into(),
            ));
        }
        let wal = companion(&resolved, "-wal");
        let metadata = fs::metadata(&wal).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to inspect WAL {wal:?}: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(OpenError::WalInput(format!(
                "WAL is not a regular file: {wal:?}"
            )));
        }
        let alias_wal = companion(path, "-wal");
        match alias_wal.symlink_metadata() {
            Ok(_) => {
                if alias_wal.canonicalize()? != wal.canonicalize()? {
                    return Err(OpenError::WalInput(format!(
                        "conflicting WAL beside input alias: {alias_wal:?}"
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if resolved.to_str().is_none() {
            return Err(OpenError::NonUtf8Path);
        }
        Ok(Self {
            path: resolved,
            wal_size: metadata.len(),
        })
    }

    /// Opens the selected committed image for authenticated page traversal.
    ///
    /// Holds a dedicated read transaction. No SQL connection or mutable pager
    /// is exposed, so callers cannot change the selected state while visiting.
    /// Pages are authenticated when read; opening alone is not full verification.
    ///
    /// # Errors
    /// Returns [`OpenError`] on authentication, schema, I/O or size failures.
    pub fn snapshot(
        self,
        config: CipherConfig,
        passphrase: &[u8],
    ) -> Result<WalSnapshot, OpenError> {
        let (connection, maximum) = self.connect(config, passphrase)?;
        connection.execute("BEGIN")?;
        // The SQL read establishes the engine's read mark and uses the same
        // database-size semantics as native queries, including after VACUUM.
        let mut count = 0_i64;
        connection
            .prepare("PRAGMA page_count")?
            .run_with_row_callback(|row| {
                count = row.get(0)?;
                Ok(())
            })?;
        let page_count = u32::try_from(count)
            .ok()
            .filter(|&n| n > 0 && n <= maximum)
            .ok_or(OpenError::SnapshotSize { count, maximum })?;
        Ok(WalSnapshot {
            connection,
            page_count,
            page_size: config.page_size(),
        })
    }

    pub(crate) fn connect(
        self,
        config: CipherConfig,
        passphrase: &[u8],
    ) -> Result<(Arc<turso::Connection>, u32), OpenError> {
        // This is only a conservative physical bound, not a second WAL parser.
        // Every additional logical page needs at least one complete WAL frame.
        let frames = self.wal_size.saturating_sub(32) / (config.page_size() as u64 + 24);
        let frames = u32::try_from(frames).unwrap_or(u32::MAX);
        open_connection(&self.path, config, passphrase, Some(frames))
    }
}

/// A private read transaction over one selected DB/WAL image.
pub struct WalSnapshot {
    connection: Arc<turso::Connection>,
    page_count: u32,
    page_size: usize,
}

/// Failure while reading or delivering authenticated snapshot pages.
#[derive(Debug, Error)]
pub enum VisitError {
    /// The engine failed to read or authenticate a selected page.
    #[error("snapshot page read failed: {0}")]
    Read(#[from] turso::LimboError),
    /// The caller's page callback failed.
    #[error("snapshot page callback failed: {0}")]
    Callback(#[source] io::Error),
    /// An engine page did not have the configured size.
    #[error("invalid snapshot page length: expected {expected}, got {actual}")]
    PageLength {
        /// Configured page size.
        expected: usize,
        /// Length returned by the engine.
        actual: usize,
    },
}

impl WalSnapshot {
    /// Number of pages in the selected committed image.
    #[must_use]
    pub const fn page_count(&self) -> u32 {
        self.page_count
    }

    /// Physical size of each authenticated plaintext page, including reserve.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    /// Authenticates and visits pages 1 through [`Self::page_count`] in order.
    ///
    /// Consumes the snapshot and releases its read transaction on success or
    /// error. The callback receives a borrowed plaintext page with zeroed cipher
    /// reserve. Header journal-mode bytes are preserved; a standalone export
    /// should set page 1 bytes 18 and 19 to 1 in its output copy.
    ///
    /// A failure stops traversal without delivering the failed page. Earlier
    /// callbacks cannot be undone; output cleanup is the caller's responsibility.
    /// Success authenticates the selected image, not obsolete or ignored frames.
    ///
    /// # Errors
    /// Returns [`VisitError`] on page I/O/authentication or callback failure.
    pub fn visit_pages(
        self,
        mut visit: impl FnMut(NonZeroU32, &[u8]) -> io::Result<()>,
    ) -> Result<(), VisitError> {
        let pager = self.connection.get_pager();
        for number in 1..=self.page_count {
            let page_no = NonZeroU32::new(number)
                .ok_or_else(|| turso::LimboError::InvalidArgument("snapshot page zero".into()))?;
            // Bypass the SQL cache: verify/export must also authenticate unused
            // pages, and should not fill the query cache with the full image.
            let (page, completion) =
                pager.read_page_no_cache(i64::from(number), None, false, None)?;
            pager.io.wait_for_completion(completion)?;
            let contents = page.get_contents();
            let bytes = contents.as_ptr();
            if bytes.len() != self.page_size {
                return Err(VisitError::PageLength {
                    expected: self.page_size,
                    actual: bytes.len(),
                });
            }
            visit(page_no, bytes).map_err(VisitError::Callback)?;
        }
        Ok(())
    }
}

impl Drop for WalSnapshot {
    fn drop(&mut self) {
        let _ = self.connection.execute("ROLLBACK");
    }
}

fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn reject_journal(path: &Path) -> Result<(), OpenError> {
    let journal = companion(path, "-journal");
    match journal.symlink_metadata() {
        Ok(_) => Err(OpenError::Companion(journal)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn open_main(
    path: &Path,
    config: CipherConfig,
    passphrase: &[u8],
) -> Result<Arc<turso::Connection>, OpenError> {
    if passphrase.is_empty() {
        return Err(DecryptError::EmptyPassphrase.into());
    }
    check_companions(path)?;
    let resolved = path.canonicalize()?;
    check_companions(&resolved)?;
    open_connection(&resolved, config, passphrase, None).map(|(connection, _)| connection)
}

fn open_connection(
    resolved: &Path,
    config: CipherConfig,
    passphrase: &[u8],
    wal_pages: Option<u32>,
) -> Result<(Arc<turso::Connection>, u32), OpenError> {
    if passphrase.is_empty() {
        return Err(DecryptError::EmptyPassphrase.into());
    }
    let path = resolved.to_str().ok_or(OpenError::NonUtf8Path)?;
    let source = FileSource::open(resolved)?;
    let size = source.len()?;
    let page_size = config.page_size();
    let page_size_u64 = page_size as u64;
    if size == 0 {
        return Err(ReaderError::EmptyFile.into());
    }
    if size < page_size_u64 {
        return Err(ReaderError::FileTooSmall {
            file_size: size,
            page_size,
        }
        .into());
    }
    if !size.is_multiple_of(page_size_u64) {
        return Err(ReaderError::InvalidFileSize {
            file_size: size,
            page_size,
        }
        .into());
    }
    let count = size / page_size_u64;
    let page_count = u32::try_from(count)
        .map_err(|_| OpenError::Source(ReaderError::TooManyPages { page_count: count }))?;
    let mut first_page = Zeroizing::new(vec![0; page_size]);
    source.read_exact_at(0, &mut first_page)?;
    let mut salt = [0; 16];
    salt.copy_from_slice(&first_page[..16]);
    let decoder = PageDecryptor::new(config, passphrase, &salt)?;

    // Always authenticate with this caller's key, before Turso can reuse any
    // schema or database state from its process-wide file registry.
    decoder.decrypt_page_in_place(NonZeroU32::MIN, &mut first_page)?;
    drop(first_page);

    let codec: Arc<dyn turso::PageCodec> = Arc::new(codec::SqlCipherCodec::new(
        decoder,
        config,
        salt,
        page_count,
        wal_pages,
        wal_pages.map(|_| path),
    ));
    let io = Arc::new(turso::PlatformIO::new()?);
    let options = turso::OpenOptions::new(Arc::new(turso::SqliteDialect))
        .flags(turso::OpenFlags::ReadOnly)
        .page_codec(Some(codec.clone()));
    let database = turso::Database::open(io, path, options)?;
    let connection = database.connect_with_page_codec(codec)?;
    connection.set_query_only(true);
    Ok((
        connection,
        page_count.saturating_add(wal_pages.unwrap_or(0)),
    ))
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
