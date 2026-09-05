//! Read-only GraphiteSQL access to immutable SQLCipher main database snapshots.
//!
//! This crate adapts [`veilite_core::SqlCipherReader`] to GraphiteSQL while
//! rejecting writes through its VFS and unsupported `-wal` and `-journal` companions.
//!
//! [`open_readonly`] returns a native [`graphitesql::Connection`]. Only the
//! encrypted main file accessed through the adapter VFS is protected from
//! writes. Attached databases and temporary tables follow GraphiteSQL semantics;
//! this adapter does not restrict filesystem access outside its VFS.
//!
//! Results, values, bindings and query errors are GraphiteSQL types, tied to the
//! adapter's pinned
//! engine version. [`graphitesql`] re-exports that exact dependency; [`Params`]
//! is an upstream type re-exported from its internal module.
//!
//! Results are fully materialized. Text preserves raw bytes: use
//! [`graphitesql::Text::as_bytes`] for exact access, since its `as_str` method
//! returns an empty string for invalid UTF-8.

#![warn(missing_docs)]

mod companion;
mod graphite;

pub use companion::{CompanionError, check_companion_files};
pub use graphite::{GraphiteAdapterError, open_readonly};

/// The exact GraphiteSQL dependency used by this adapter.
pub use graphitesql;
/// GraphiteSQL bindings, re-exported from its internal module for convenience.
pub use graphitesql::exec::eval::Params;
pub use graphitesql::{QueryResult, Value};
