use super::{
    Curve,
    encoding::{PrivateKeySerializer, PublicKeySerializer},
};
use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Supported key agreement functions.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDH using the [`P256`] curve.
    ///
    /// [`P256`]: Curve::P256
    EcdhP256 = 714,
    /// ECDH using the [`P384`] curve.
    ///
    /// [`P384`]: Curve::P384
    EcdhP384 = 715,
    /// ECDH using the [`P521`] curve.
    ///
    /// [`P521`]: Curve::P521
    EcdhP521 = 716,
    /// X25519 (ECDH using [`Curve25519`]).
    ///
    /// [`Curve25519`]: Curve::Curve25519
    X25519 = 1034,
    /// X448 (ECDH using [`Curve448`]).
    ///
    /// [`Curve448`]: Curve::Curve448
    X448 = 1035,
}

impl Algorithm {
    /// Elliptic curve associated with the algorithm.
    pub fn curve(&self) -> Curve {
        match self {
            Self::EcdhP256 => Curve::P256,
            Self::EcdhP384 => Curve::P384,
            Self::EcdhP521 => Curve::P521,
            Self::X25519 => Curve::Curve25519,
            Self::X448 => Curve::Curve448,
        }
    }
}

impl TryFrom<i32> for Algorithm {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            714 => Ok(Self::EcdhP256),
            715 => Ok(Self::EcdhP384),
            716 => Ok(Self::EcdhP521),
            1034 => Ok(Self::X25519),
            1035 => Ok(Self::X448),
            _ => Err(Error::UnsupportedAgreementAlgorithm),
        }
    }
}

/// A private key for key agreement.
///
/// The signature of [`agree`] allows a [`PrivateKey`] to be used for
/// multiple key agreements.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// Performs a Diffie-Hellman (DH) key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error>;

    /// Computes public key of the private key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKeySerializer>, Error>;

    /// Returns the algorithm associated with this key.
    fn algorithm(&self) -> Algorithm;

    /// Interface for serializing the key into binary formats.
    fn to_serializer(self: Box<Self>) -> Box<dyn PrivateKeySerializer>;
}

/// An ephemeral private key for key agreement.
///
/// The signature of [`agree_ephemeral`] allows an [`EphemeralPrivateKey`]
/// to be used for multiple key agreements.
///
/// [`agree_ephemeral`]: EphemeralPrivateKey::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// Performs a Diffie-Hellman (DH) key agreement.
    fn agree_ephemeral(
        self: Box<Self>,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKeySerializer>, Error>;

    /// Returns the algorithm associated with this key.
    fn algorithm(&self) -> Algorithm;
}

/// A public key for key agreement.
pub trait PublicKey {
    /// Kind of the public key we have.
    fn algorithm(&self) -> Algorithm;

    /// Interface for serializing the key into binary formats.
    fn to_serializer(self: Box<Self>) -> Box<dyn PublicKeySerializer>;
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
