use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Supported HKDF algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HKDF with HMAC-SHA-256.
    Sha256 = 1496,
    /// HKDF with HMAC-SHA-384.
    Sha384 = 1497,
    /// HKDF with HMAC-SHA-512.
    Sha512 = 1498,
}

impl TryFrom<u32> for Algorithm {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1496 => Ok(Self::Sha256),
            1497 => Ok(Self::Sha384),
            1498 => Ok(Self::Sha512),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// A HKDF implementation.
pub trait Hkdf {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// Returns an [`Expander`] that can be used to derive keying material.
    fn extract(&self, salt: &[u8], secret: &[u8]) -> Box<dyn Expander>;
}


/// Implementation of `HKDF-Expand` using an internally stored pseudorandom key
/// (PRK).
pub trait Expander {
    /// `HKDF-Expand(PRK, info, L)` where L is output.len()
    ///
    /// Returns [`Error::Unspecified`] if L is larger than `255*HashLen`.
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<Okm, Error>;
}

/// Output keying material (OKM).
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
