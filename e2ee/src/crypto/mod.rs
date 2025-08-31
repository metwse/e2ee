use crate::sync::Arc;

/// HMAC-based key derivation interface.
pub mod hkdf;

/// Key interface used in e2ee.
pub mod key;

/// Hashing interface.
pub mod hash;

/// aws-lc-rs based `CryptoProvider`.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs;

/// Cryptographic functions used by e2ee.
pub struct CryptoProvider {
    /// HMAC-based key derivation.
    pub hkdf: &'static dyn hkdf::Provider,
    /// Hash functions.
    pub hash: &'static dyn hash::Provider,
    /// For loading keys from `der` format.
    pub key: &'static dyn key::Provider,
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
