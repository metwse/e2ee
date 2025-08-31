use crate::error::Unspecified;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Available HKDF algorithms.
#[non_exhaustive]
pub enum Algorithm {
    /// HKDF using HMAC-SHA-256.
    Sha256,
    /// HKDF using HMAC-SHA-384.
    Sha384,
    /// HKDF using HMAC-SHA-512.
    Sha512,
}

/// `HKDF` implementation required by e2ee.
///
/// See [RFC 5869](https://www.ietf.org/rfc/rfc5869.txt) for the terminology
/// used in this definition.
pub trait Provider: Send + Sync {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero
    /// bytes.
    fn extract(
        &self,
        algorithm: Algorithm,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn Expander>;

    /// Whether or not the HKDF algorithm is supported.
    fn is_algorithm_supported(&self, algorithm: Algorithm) -> bool;
}

/// Implementation of `HKDF-Expand` with an implicitly stored and immutable
/// `PRK`.
pub trait Expander: Send + Sync {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where `L` is `output.len()`
    ///
    /// Returns Err("output length error") if `L` is larger than `255*HashLen`.
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<Okm, Unspecified>;
}

/// Key derived using `HKDF`.
pub struct Okm {
    pub(crate) buf: Vec<u8>,
}

impl Drop for Okm {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for Okm {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}
