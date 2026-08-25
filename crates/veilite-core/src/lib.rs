//! Authenticated, random-access reading of selected SQLCipher on-disk formats.
//!
//! The crate supports the SQLCipher 3 and 4 default on-disk presets and a
//! bounded set of complete custom configurations. It reads immutable main
//! database snapshots; transaction companions, concurrent mutation, writes,
//! and automatic configuration detection are outside its scope.
//!
//! [`SqlCipherReader::open`] derives keys but authenticates pages lazily. A page
//! is decrypted only after its stored HMAC has been verified.

#![warn(missing_docs)]

mod config;
mod decryptor;
mod reader;
mod source;

pub use config::{CipherConfig, CipherConfigError, CipherPreset, HashAlgorithm};
pub use decryptor::DecryptError;
pub use reader::{ReaderError, SqlCipherReader};
pub use source::{FileSource, ReadAt, SliceSource};
