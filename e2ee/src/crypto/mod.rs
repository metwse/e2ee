use crate::sync::Arc;
use alloc::vec::Vec;

/// Key formats used in e2ee.
mod keys;

/// Cryptographic algorithms interface.
mod algorithms;

#[doc(inline)]
pub use keys::*;

#[doc(inline)]
pub use algorithms::*;

/// Cryptographic functions used by e2ee.
pub struct CryptoProvider {
    /// List of supported key exchange algorithms.
    pub kx: Vec<&'static dyn KeyExchangeAlgorithm>,
    /// How to complete HKDF with the suite's hash function.
    pub hkdf_provider: Vec<&'static dyn Hkdf>,
    /// For loading keys from `der` format.
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
