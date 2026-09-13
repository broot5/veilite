#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod btree;
mod decimal;
mod defaults;
mod header;
mod reader;
mod record;
mod schema;
mod source;

pub use reader::{Index, IndexEntries, Reader, Row, Rows, SchemaObject, Table};
pub use record::{Text, TextError, Value};
pub use schema::Column;

use std::num::NonZeroU32;
use thiserror::Error;

pub use header::{Header, TextEncoding};
pub use source::{FileSource, ReadAt, SliceSource};

/// Failure to read or validate a snapshot.
#[derive(Debug, Error)]
pub enum ReaderError<E> {
    /// The underlying source failed; its original error is preserved.
    #[error("source read failed: {0}")]
    Source(#[source] E),
    /// A malformed header or physical file layout.
    #[error("invalid SQLite database: {0}")]
    InvalidFormat(&'static str),
    /// A recognized feature outside the supported format scope.
    #[error("unsupported SQLite feature: {0}")]
    Unsupported(&'static str),
    /// Page number is outside the logical database.
    #[error("page {0} is outside the database")]
    PageOutOfRange(u32),
    /// The output must contain exactly one page.
    #[error("output length must equal the page size")]
    InvalidOutputLength,
    /// No schema object of the requested kind and name exists.
    #[error("schema object not found: {0}")]
    NotFound(String),
    /// An allocation needed to read a record could not be satisfied.
    #[error("record allocation failed")]
    Allocation,
}

/// An immutable, logical SQLite snapshot with one-based page numbers.
///
/// Metadata and bytes must remain stable. Implementations read exactly one
/// complete page independently of any shared file cursor. They reject wrong
/// output lengths and pages outside `1..=page_count()`, and clear output on
/// failure. Encrypted sources must authenticate before returning plaintext.
/// Page count describes the selected snapshot, not a WAL's frame count.
pub trait PageSource {
    /// Error returned by page reads.
    type Error;
    /// Physical page size in bytes, including any reserved tail.
    fn page_size(&self) -> usize;
    /// Number of pages in the logical snapshot.
    fn page_count(&self) -> u32;
    /// Reads a complete page, including reserved bytes.
    fn read_page_into(&self, page: NonZeroU32, output: &mut [u8]) -> Result<(), Self::Error>;
}

/// A validated header and page source for a plaintext SQLite main database.
///
/// Opening checks the header and physical file length, not B-trees or records.
/// Callers must ensure no WAL or journal is needed to complete the snapshot.
pub struct Database<R> {
    source: R,
    header: Header,
}

impl<R: ReadAt> Database<R> {
    /// Opens a complete immutable plaintext snapshot.
    ///
    /// Zero-byte files and headers with uninitialized schema/encoding fields
    /// are rejected. WAL-mode header flags alone do not imply a WAL is needed;
    /// ensuring a complete checkpointed image is the caller's responsibility.
    pub fn open(source: R) -> Result<Self, ReaderError<R::Error>> {
        let length = source.len().map_err(ReaderError::Source)?;
        if length < 100 {
            return Err(ReaderError::InvalidFormat(
                "file is shorter than the header",
            ));
        }
        let mut bytes = [0; 100];
        source
            .read_exact_at(0, &mut bytes)
            .map_err(ReaderError::Source)?;
        let header = Header::parse(&bytes, length)?;
        Ok(Self { source, header })
    }

    /// Returns validated database metadata.
    pub fn header(&self) -> &Header {
        &self.header
    }
}

impl<R: ReadAt> PageSource for Database<R> {
    type Error = ReaderError<R::Error>;

    fn page_size(&self) -> usize {
        self.header.page_size()
    }

    fn page_count(&self) -> u32 {
        self.header.page_count()
    }

    fn read_page_into(&self, page: NonZeroU32, output: &mut [u8]) -> Result<(), Self::Error> {
        output.fill(0);
        if output.len() != self.page_size() {
            return Err(ReaderError::InvalidOutputLength);
        }
        if page.get() > self.page_count() {
            return Err(ReaderError::PageOutOfRange(page.get()));
        }
        // Both operands are bounded by the validated SQLite format limits.
        let offset = u64::from(page.get() - 1) * u64::from(self.header.page_size);
        if let Err(error) = self.source.read_exact_at(offset, output) {
            output.fill(0);
            return Err(ReaderError::Source(error));
        }
        Ok(())
    }
}
