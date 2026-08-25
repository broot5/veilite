//! Read-only GraphiteSQL access to immutable SQLCipher main database snapshots.
//!
//! This crate adapts [`veilite_core::SqlCipherReader`] to GraphiteSQL while
//! rejecting writes and unsupported `-wal` and `-journal` companions.

#![warn(missing_docs)]

mod companion;
mod graphite;

pub use companion::{CompanionError, check_companion_files};
pub use graphite::{GraphiteAdapterError, QueryResult, ReadOnlyConnection, Value, open_readonly};
