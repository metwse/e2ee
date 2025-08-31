use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Hash functions.
#[non_exhaustive]
pub enum Algorithm {
    /// SHA3-256 as specified in FIPS 202.
    Sha3_256,
    /// SHA3-384 as specified in FIPS 202.
    Sha3_384,
    /// SHA3-512 as specified in FIPS 202.
    Sha3_512,
    /// SHA-224 as specified in FIPS 180-4.
    Sha224,
    /// SHA-256 as specified in FIPS 180-4.
    Sha256,
    /// SHA-384 as specified in FIPS 180-4.
    Sha384,
    /// SHA-512 as specified in FIPS 180-4.
    Sha512,
}

/// Describes a cryptographic hash functions.
pub trait Provider: Send + Sync {
    /// Start an incremental hash computation.
    fn start(&self, algorithm: Algorithm) -> Box<dyn Context>;

    /// Start an incremental hash computation.
    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Output;

    /// Whether the hash function is supported by the provider.
    fn is_function_supported(&self) -> bool;
}

/// Incrementally computed hash.
pub trait Context: Send + Sync {
    /// Add data to the computation.
    fn update(&mut self, data: &[u8]);

    /// Terminate and finish the computation, returning the resulting output.
    fn finish(self: Box<Self>) -> Output;
}

/// Output of hash function.
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
