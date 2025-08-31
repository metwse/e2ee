use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use core::any::Any;
use zeroize::Zeroize;

/// Available key curve algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    /// ECDH using the NSA Suite B P-256 (secp256r1) curve.
    EcdhP256,
    /// ECDH using the NSA Suite B P-384 (secp384r1) curve.
    EcdhP384,
    /// ECDH using the NSA Suite B P-521 (secp521r1) curve.
    EcdhP521,
    /// X25519 (ECDH using Curve25519) as described in RFC 7748.
    X25519,
}

/// Mechanism for loading/generating keys.
pub trait Provider: Send + Sync {
    /// Loads private key from binary.
    fn load_private_key(
        &self,
        algorithm: Algorithm,
        key_der: &[u8],
    ) -> Result<Box<dyn PrivateKey>, Error>;

    /// Loads public key from binary.
    fn load_public_key(
        &self,
        algorithm: Algorithm,
        key_der: Vec<u8>,
    ) -> Result<Box<dyn PublicKey>, Error>;

    /// Generates an ephemeral private key.
    fn generate_ephemeral_private_key(
        &self,
        algorithm: Algorithm,
    ) -> Result<Box<dyn EphemeralPrivateKey>, Error>;

    /// Whether or not the curve algorithm is supported.
    fn is_curve_supported(&self, algorithm: Algorithm) -> bool;
}

/// A public key can be used for key agreement or digital signature
/// verification.
pub trait PublicKey: Any {
    /// The algorithm for the public key.
    fn algorithm(&self) -> Algorithm;

    /// Used to standartize key agreement material across different
    /// [`CryptoProvider`]s.
    ///
    /// [`CryptoProvider`]: super::CryptoProvider
    fn as_der(&self) -> Result<Vec<u8>, Error>;
}

/// A private key for key agreement and signing key generation. The signature
/// of [`agree`] allows [`PrivateKey`] to be used for more than one key
/// agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error>;

    /// Computes public key of the private key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// The algorithm for the private key.
    fn algorithm(&self) -> Algorithm;

    /// Converts private key into der.
    fn as_der(&self) -> Result<Vec<u8>, Error>;
}

/// An ephemeral private key for use (only) with ephemeral key agreement. The
/// signature of [`agree_ephemeral`] allows [`EphemeralPrivateKey`] to be used for only one
/// key agreement.
///
/// [`agree_ephemeral`]: EphemeralPrivateKey::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// DH key agreement with ephemeral key.
    fn agree_ephemeral(
        self: Box<Self>,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// The algorithm for the ephemeral private key.
    fn algorithm(&self) -> Algorithm;
}

/// Key derived using `HKDF`.
pub struct SharedSecret {
    pub(crate) buf: Vec<u8>,
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}
