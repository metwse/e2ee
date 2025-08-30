use crate::sync::Arc;
use alloc::{boxed::Box, vec::Vec};

/// Cryptographic functions used by e2ee.
pub struct CryptoProvider {
    /// List of supported key exchange algorithms.
    pub kx: Vec<&'static dyn KeyExchangeAlgorithm>,
    /// How to complete HKDF with the suite's hash function.
    pub hkdf_provider: Vec<&'static dyn Hkdf>,
    /// For loading private SigningKeys from PrivateKeyDer.
    pub key_provider: &'static dyn KeyProvider,
}

impl CryptoProvider {
    /// Sets this insance of `CryptoProvider` as the default for this process.
    pub fn install_default(self) -> Result<(), Arc<Self>> {
        static_default::install_default(self)
    }

    /// Returns the default `CryptoProvider` for this process.
    ///
    /// Returns `None` if no default has been set.
    pub fn get_default() -> Option<&'static Arc<Self>> {
        static_default::get_default()
    }
}

/// `DH` implementation for key derivation.
pub trait KeyExchangeAlgorithm: Send + Sync {
    /// Returns shared secret output from an Diffie-Hellman key exchange
    /// function involving the key pairs.
    fn agree(&self, my_private_key: &[u8], peer_public_key: &[u8])
        -> Result<Vec<u8>, &'static str>;

    /// DH key exchange using ephemeral private key.
    fn agree_ephemeral(
        &self,
        my_private_key: Vec<u8>,
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, &'static str>;
}

/// `HKDF` implementation required by e2ee.
///
/// See [RFC 5869](https://www.ietf.org/rfc/rfc5869.txt) for the terminology
/// used in this definition.
pub trait Hkdf: Send + Sync {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero
    /// bytes.
    fn extract(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander>;
}

/// Implementation of `HKDF-Expand` with an implicitly stored and immutable
/// `PRK`.
pub trait HkdfExpander: Send + Sync {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where `L` is `output.len()`
    ///
    /// Returns Err("output length error") if `L` is larger than `255*HashLen`.
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), &'static str>;
}

/// Mechanism for loading private keys.
pub trait KeyProvider: Send + Sync {}

mod static_default {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    #[cfg(not(feature = "std"))]
    use once_cell::race::OnceBox;

    #[cfg(feature = "std")]
    use std::sync::OnceLock;

    use super::CryptoProvider;
    use crate::sync::Arc;

    #[cfg(not(feature = "std"))]
    pub(crate) fn install_default(
        default_provider: CryptoProvider,
    ) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER
            .set(Box::new(Arc::new(default_provider)))
            .map_err(|e| *e)
    }

    #[cfg(feature = "std")]
    pub(crate) fn install_default(
        default_provider: CryptoProvider,
    ) -> Result<(), Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.set(Arc::new(default_provider))
    }

    pub(crate) fn get_default() -> Option<&'static Arc<CryptoProvider>> {
        PROCESS_DEFAULT_PROVIDER.get()
    }

    #[cfg(feature = "std")]
    static PROCESS_DEFAULT_PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

    #[cfg(not(feature = "std"))]
    static PROCESS_DEFAULT_PROVIDER: OnceBox<Arc<CryptoProvider>> = OnceBox::new();
}
