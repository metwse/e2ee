use crate::crypto::{CryptoProvider, hash, hkdf, key};
use crate::sync::Arc;
use alloc::vec::Vec;

use super::Config;

/// A builder for [`x3dh::Config`].
///
/// [`x3dh::Config`]: crate::x3dh::Config
pub struct ConfigBuilder {
    pub(crate) curve: Option<Vec<key::Algorithm>>,
    pub(crate) hkdf: Option<Vec<hkdf::Algorithm>>,
    pub(crate) hash: Option<Vec<hash::Algorithm>>,

    pub(crate) provider: Arc<CryptoProvider>,
}

impl ConfigBuilder {
    /// Specifies which curve algorithms are supported by the peer.
    pub fn with_curve(mut self, curve: Vec<key::Algorithm>) -> Self {
        for c in curve.iter() {
            if !self.provider.key.is_curve_supported(*c) {
                panic!("{c:?} is not supported by the provider.");
            }
        }

        self.curve = Some(curve);
        self
    }

    /// Specifies which key derivation algorithms are supported by the peer.
    pub fn with_hkdf(mut self, hkdf: Vec<hkdf::Algorithm>) -> Self {
        for c in hkdf.iter() {
            if !self.provider.hkdf.is_algorithm_supported(*c) {
                panic!("{c:?} is not supported by the provider.");
            }
        }

        self.hkdf = Some(hkdf);
        self
    }

    /// Specifies which key derivation algorithms are supported by the peer.
    pub fn with_hash(mut self, hash: Vec<hash::Algorithm>) -> Self {
        for c in hash.iter() {
            if !self.provider.hash.is_function_supported(*c) {
                panic!("{c:?} is not supported by the provider.");
            }
        }

        self.hash = Some(hash);
        self
    }

    /// Sets algorithms with safe defaults.
    pub fn with_recommended_algorithms(self) -> Self {
        self.with_hkdf(alloc::vec![
            hkdf::Algorithm::Sha256,
            hkdf::Algorithm::Sha512,
            hkdf::Algorithm::Sha384
        ])
        .with_curve(alloc::vec![
            key::Algorithm::EcP521,
            key::Algorithm::EcP384,
            key::Algorithm::EcP384
        ])
        .with_hash(alloc::vec![
            hash::Algorithm::Sha256,
            hash::Algorithm::Sha512,
            hash::Algorithm::Sha224,
            hash::Algorithm::Sha384,
            hash::Algorithm::Sha3_256,
            hash::Algorithm::Sha3_512,
            hash::Algorithm::Sha3_384,
        ])
    }

    /// Finish builder to peer config.
    pub fn build(self) -> Arc<Config> {
        Arc::new(Config {
            curve: self.curve.expect("No curve algorithm has been specified."),
            hkdf: self
                .hkdf
                .expect("No key derivation function has been specified."),
            hash: self.hash.expect("No key hash funciton has been specified."),
            _provider: self.provider,
        })
    }
}
