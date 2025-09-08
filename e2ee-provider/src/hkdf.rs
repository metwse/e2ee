use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Available HKDF algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HKDF using HMAC-SHA-256.
    Sha256 = 1496,
    /// HKDF using HMAC-SHA-384.
    Sha384 = 1497,
    /// HKDF using HMAC-SHA-512.
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
    fn extract(&self, salt: &[u8], secret: &[u8]) -> Box<dyn Expander>;
}

/// Implementation of `HKDF-Expand` with an implicitly stored pseudo random
/// key.
pub trait Expander {
    /// `HKDF-Expand(PRK, info, L)`
    /// Where L is output.len()
    /// Returns [`Error::Unspecified`] if L is larger than `255*HashLen`.
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<Okm, Error>;
}

/// Output keying material.
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
