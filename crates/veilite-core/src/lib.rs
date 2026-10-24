//! Authenticated, random-access reading of selected SQLCipher on-disk formats.
//!
//! The crate supports the SQLCipher 3 and 4 default on-disk presets and a
//! bounded set of complete custom configurations. It reads immutable main
//! database snapshots; transaction companions, concurrent mutation, writes,
//! and automatic configuration detection are outside its scope.
//!
//! [`SqlCipherReader::open`] derives keys but authenticates pages lazily. A page
//! is decrypted only after its stored HMAC has been verified.
//!
//! [`ReadAt`], [`FileSource`], and [`SliceSource`] supply immutable input bytes.
//! [`PageDecryptor`] supports storage-engine adapters such as `veilite-turso`.
//! Provide a checkpointed snapshot that needs no WAL or journal.
//!
//! ```no_run
//! use std::num::NonZeroU32;
//! use veilite_core::{CipherPreset, FileSource, SqlCipherReader};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let source = FileSource::open("encrypted.db")?;
//! let pages = SqlCipherReader::open(source, CipherPreset::SqlCipher4.into(), b"passphrase")?;
//! let mut page = vec![0; pages.page_size()];
//! pages.read_page_into(NonZeroU32::new(1).unwrap(), &mut page)?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod config;
mod decryptor;
mod reader;
mod source;

pub use config::{CipherConfig, CipherConfigError, CipherPreset, HashAlgorithm};
pub use decryptor::{DecryptError, PageDecryptor};
pub use reader::{ReaderError, SqlCipherReader};
pub use source::{FileSource, ReadAt, SliceSource};
