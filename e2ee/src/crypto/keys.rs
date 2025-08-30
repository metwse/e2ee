use crate::error::Unspecified;
use alloc::boxed::Box;

/// A public key can be used for key agreement or digital signature
/// verification.
pub trait PublicKey {
    /// Used to standartize key agreement material accross different
    /// [`CryptoProvider`]s.
    ///
    /// [`CryptoProvider`]: super::CryptoProvider
    fn as_der(&self) -> &[u8];
}

/// A private key for key agreement and signing key generation. The signature
/// of [`agree`] allows [`PrivateKey`] to be used for more than one key
/// agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// Converts private key into der.
    fn as_der(&self) -> &[u8];

    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Unspecified>;
}

/// An ephemeral private key for use (only) with ephemeral key agreement. The
/// signature of [`agree_ephemeral`] allows [`EphemeralPrivateKey`] to be used for only one
/// key agreement.
///
/// [`agree_ephemeral`]: super::KeyExchangeAlgorithm::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// DH key agreement with ephemeral key.
    fn agree(self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Unspecified>;
}

/// Result of DH key exchange.
pub struct SharedSecret {}

/// Mechanism for loading/generating keys.
pub trait KeyProvider: Send + Sync {
    /// Loads private key from binary.
    fn load_private_key(&self, key_der: &[u8]) -> Box<dyn PrivateKey>;

    /// Loads public key from binary.
    fn load_public_key(&self, key_der: &[u8]) -> Box<dyn PublicKey>;

    /// Generates an ephemeral private key.
    fn generate_ephemeral_private_key(&self) -> Box<dyn EphemeralPrivateKey>;
}
