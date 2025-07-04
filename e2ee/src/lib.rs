//! # e2ee
//! `e2ee` is a transport-agnostic end-to-end encryption framework that
//! provides highly configurable tools for establishing secure communication
//! tunnels between pairs.
//!
//! The library currently supports two key agreement protocols:
//! - [`x3dh`] — Triple Diffie-Hellman handshake, inspired by the
//!   Signal Protocol.
//! - `ca` — Certificate-based authentication via trusted certificate
//!   authorities.
//!
//! Depending on your transport layer, `e2ee` lets you choose between:
//! - Ordered encryption streams,
//! - AEAD-based framed encryption,
//! - Or unordered datagram encryption.
//!
//! Sessions can be serialized and resumed, making `e2ee` suitable for both
//! connectionless protocols (like UDP) and stream-oriented ones (like TCP).
//!
//! The API is designed to be minimal, modular, and memory-safe — with full
//! control over identity, trust, and encryption policy.

#![forbid(unsafe_code, unused_must_use)]
#![warn(clippy::all, clippy::cargo, missing_docs)]
#![deny(
    elided_lifetimes_in_paths,
    missing_docs,
    trivial_numeric_casts,
    while_true,
    unreachable_pub,
    unused_qualifications
)]
// Enable documentation for all features on docs.rs.
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![no_std]
extern crate alloc;

/// Extended Triple Diffie-Hellman, as described by
/// [Signal](https://signal.org/docs/specifications/x3dh/x3dh.pdf).
pub mod x3dh;

/// Crypto provider interface.
pub mod crypto;
