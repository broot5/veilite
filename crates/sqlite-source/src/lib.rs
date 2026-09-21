#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod source;

pub use source::{FileSource, ReadAt, SliceSource};

use std::num::NonZeroU32;

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
