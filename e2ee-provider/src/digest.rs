use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Supported hash algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA3-224, as specified in FIPS 202.
    Sha3_224 = 1096,
    /// SHA3-256, as specified in FIPS 202.
    Sha3_256 = 1097,
    /// SHA3-384, as specified in FIPS 202.
    Sha3_384 = 1098,
    /// SHA3-512, as specified in FIPS 202.
    Sha3_512 = 1099,
    /// SHA-224, as specified in FIPS 180-4.
    Sha224 = 675,
    /// SHA-256, as specified in FIPS 180-4.
    Sha256 = 672,
    /// SHA-384, as specified in FIPS 180-4.
    Sha384 = 673,
    /// SHA-512, as specified in FIPS 180-4.
    Sha512 = 674,
}

impl TryFrom<u32> for Algorithm {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1096 => Ok(Self::Sha3_224),
            1097 => Ok(Self::Sha3_256),
            1098 => Ok(Self::Sha3_384),
            1099 => Ok(Self::Sha3_512),
            675 => Ok(Self::Sha224),
            672 => Ok(Self::Sha256),
            673 => Ok(Self::Sha384),
            674 => Ok(Self::Sha512),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// A cryptographic hash function.
pub trait Hash {
    /// Starts an incremental hash computation.
    fn start(&self) -> Box<dyn Context>;

    /// Returns output length of the hash function.
    fn output_len(&self) -> usize;

    /// Computes and returns the digest of the given data.
    fn hash(&self, data: &[u8]) -> Output;

    /// Returns the digest of data.
    fn algorithm(&self) -> Algorithm;
}

/// Incremental hash computation context.
pub trait Context {
    /// Adds data to the current hash computation.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the computation and returns the resulting digest.
    fn finish(self: Box<Self>) -> Output;

    /// Algorithm used in this hash computation.
    fn algorithm(&self) -> Algorithm;
}

/// The output (digest) of a hash function.
pub struct Output {
    pub(crate) buf: Vec<u8>,
}

impl Drop for Output {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}
