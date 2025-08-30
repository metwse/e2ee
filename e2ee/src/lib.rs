//! # e2ee - end-to-end encryption framework
//! e2ee provides highly configurable tools for establishing secure
//! communication tunnels between pairs.

#![forbid(unsafe_code, unused_must_use)]
#![warn(clippy::all, clippy::cargo, missing_docs)]
#![no_std]
// Enable documentation for all features on docs.rs.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

/// Extended Triple Diffie-Hellman, as described by
/// [Signal](https://signal.org/docs/specifications/x3dh/x3dh.pdf).
pub mod x3dh;

/// Error reporting.
pub mod error;

/// Double Ratchet, as described by
/// [Signal](https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf).
pub mod doubleratchet;

/// Crypto provider interface.
pub mod crypto;

/// Internal `sync` module aliases the `Arc` implementation to allow
/// replacement of it in one centrral location.
mod sync {
    pub(crate) type Arc<T> = alloc::sync::Arc<T>;
}
