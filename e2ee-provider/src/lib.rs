//! `e2ee-provider` unifies the function interfaces of different cryptographic
//! libraries into a single abstraction.

#![forbid(unsafe_code, unused_must_use)]
#![warn(clippy::all, clippy::cargo, missing_docs)]
#![no_std]
// Enable documentation for all features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

/// Key provider interface.
pub mod key;

/// Hash provider interface.
pub mod digest;

/// HMAC-based key derivation interface.
pub mod hkdf;

/// Provider interface.
pub mod provider;

/// Error reporting.
mod error;

pub use error::Error;
pub use key::KeyProvider;
pub use provider::{HashProvider, HkdfProvider};

/// Cryptographic functions used by e2ee.
pub struct CryptoProvider {
    /// HMAC-based key derivation.
    pub hkdf: &'static dyn HkdfProvider,
    /// Hash functions.
    pub hash: &'static dyn HashProvider,
    /// Key provider.
    pub key: &'static dyn KeyProvider,
}
