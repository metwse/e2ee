//! `e2ee-provider` unifies the function interfaces of different cryptographic
//! libraries into a single abstraction.
//!
//! It also provides fallback mechanisms: if one provider does not support a
//! particular function, another available provider will be used.

#![forbid(unsafe_code, unused_must_use)]
#![warn(clippy::all, clippy::cargo, missing_docs)]
#![no_std]
// Enable documentation for all features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

/// Elliptic Curve
pub mod ec;

/// Key provider interface.
pub mod key;

/// Error reporting.
mod error;

pub use error::Error;

/// Internal `sync` module aliases the `Arc` implementation to allow
/// replacement of it in one centrral location.
mod sync {
    pub(crate) type Arc<T> = alloc::sync::Arc<T>;
}
