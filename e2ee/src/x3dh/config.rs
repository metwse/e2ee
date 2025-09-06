use super::ConfigBuilder;
use crate::{
    crypto::{CryptoProvider, hash, hkdf, key},
    sync::Arc,
};
use alloc::vec::Vec;

/// `x3dh` peer configuration.
pub struct Config {
    /// List of supported curves, ordered by preference.
    pub curve: Vec<key::Algorithm>,
    /// List of supported key derivation functions, ordered by preference.
    pub hkdf: Vec<hkdf::Algorithm>,
    /// List of supported hash functions, ordered by preference.
    pub hash: Vec<hash::Algorithm>,

    pub(crate) _provider: Arc<CryptoProvider>,
}

impl Config {
    /// Create a builder for a client configuration with the process-default
    /// [`CryptoProvider`].
    pub fn builder() -> ConfigBuilder {
        Self::builder_with_provider(
            CryptoProvider::get_default_or_install_from_crate_features().clone(),
        )
    }

    /// Create a builder for a client configuration with a specific
    /// [`CryptoProvider`].
    pub fn builder_with_provider(provider: Arc<CryptoProvider>) -> ConfigBuilder {
        ConfigBuilder {
            curve: None,
            hash: None,
            hkdf: None,
            provider,
        }
    }
}
