use alloc::{boxed::Box, vec::Vec};

mod builder;
mod config;

pub use builder::ConfigBuilder;
pub use config::Config;

use crate::crypto::key::PrivateKey;

/// X3DH peer.
pub struct Peer {
    /// Peer's identity key, used for prekey signing and mutual authentication.
    pub identitiy_key: Box<dyn PrivateKey>,
    /// Storage for peer's prekeys.
    pub key_storage: Option<Box<dyn KeyStorage>>,
}

/// Key storage for peer's prekeys and one-time prekeys.
pub trait KeyStorage {
    /// Store prekeys encoded in value against key, overwrites any existing
    /// value against key. Returns `true` if the value was stored.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool;

    /// Find a value with the given key. Returns it, `None` if it does not
    /// exists.
    fn get(&self, key: &[u8]) -> Option<u8>;

    /// Find a value with the given key. Returns it and delete it from storage,
    /// `None` if it does not exists.
    fn take(&self, key: &[u8]) -> Option<u8>;
}
