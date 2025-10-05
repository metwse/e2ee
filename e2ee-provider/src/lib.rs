//! `e2ee-provider` standardizes the function interfaces of different
//! cryptographic libraries into a single abstraction.

#![forbid(unsafe_code, unused_must_use)]
#![warn(clippy::all, clippy::cargo, missing_docs)]
#![no_std]
// Enable documentation for all features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

/// Digest (hash) provider interface.
pub mod digest;

/// HMAC-based key derivation funciton (HKDF) interface.
pub mod hkdf;

/// Elliptic curve cryptography.
pub mod ec;

/// General provider interface.
pub mod provider;

/// Error reporting.
mod error;

/// `CryptoProvider` implementation using aws-lc-rs.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs;

pub use error::Error;
pub use provider::{HashProvider, HkdfProvider};

/// Cryptographic functions used by e2ee.
pub struct CryptoProvider {
    /// HKDF (HMAC-based key derivation).
    pub hkdf: &'static dyn HkdfProvider,
    /// Hashing functions.
    pub hash: &'static dyn HashProvider,
    // /// Key provider.
    // pub key: &'static dyn KeyProvider,
}
