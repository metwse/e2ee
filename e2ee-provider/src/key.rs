use crate::{Error, digest::Hash};
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Available elliptic curves.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NSA Suite B P-256 curve
    /// Also known as: prime256v1, secp256r1, prime256v1
    P256 = 415,
    /// NSA Suite B P-384 curve
    /// Also known as: secp384r1, ansip384r1
    P384 = 715,
    /// NSA Suite B P-521 curve
    /// Also known as: secp521r1, ansip521r1
    P521 = 716,
    /// curve25519 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve25519 = 1034,
    /// curve448 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve448 = 1035,
}

impl TryFrom<u32> for Curve {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            415 => Ok(Curve::P256),
            715 => Ok(Curve::P384),
            716 => Ok(Curve::P521),
            1034 | 1087 => Ok(Curve::Curve25519),
            1035 | 1088 => Ok(Curve::Curve448),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// Mechanism for loading or generating keys.
pub trait KeyProvider {
    /// Loads private key from binary.
    fn load_private_key(
        &self,
        algorithm: Curve,
        key_der: &[u8],
    ) -> Result<Box<dyn PrivateKey>, Error>;

    /// Loads public key from binary.
    fn load_public_key(
        &self,
        algorithm: Curve,
        key_der: &[u8],
    ) -> Result<Box<dyn PublicKey>, Error>;

    /// Generates an ephemeral private key.
    fn generate_ephemeral_private_key(
        &self,
        algorithm: Curve,
    ) -> Result<Box<dyn EphemeralPrivateKey>, Error>;

    /// Whether or not the curve algorithm is supported.
    fn is_curve_supported(&self, algorithm: Curve) -> bool;
}

/// A private key for key agreement and signing key generation. The signature
/// of [`agree`] allows [`PrivateKey`] to be used for more than one key agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Signs `message` using the selected digest function.
    fn sign(&self, message: &[u8], digest: Box<dyn Hash>) -> Result<Vec<u8>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key only for key agreement. The signature of [`agree_ephemeral`]
/// allows [`EphemeralPrivateKey`] to be used for more than one key agreement.
///
/// [`agree_ephemeral`]: EphemeralPrivateKey::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// DH key agreement.
    fn agree_ephemeral(
        self: Box<Self>,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key can be used for key agreement or digital signature
/// verification.
pub trait PublicKey {
    /// Verify the `signature` signature of `message`.
    fn sign(&self, message: &[u8], digest: i32) -> Result<Vec<u8>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// Result of a key agreement.
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
