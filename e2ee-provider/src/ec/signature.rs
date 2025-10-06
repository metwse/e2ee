use super::{
    Curve,
    encoding::{PrivateKeySerializer, PublicKeySerializer},
};
use crate::Error;
use alloc::{boxed::Box, vec::Vec};

/// Supported signature algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ASN.1 DER-encoded ECDSA signatures using the [`P256`] curve and
    /// [`Sha256`].
    ///
    /// [`P256`]: Curve::P256
    /// [`Sha256`]: crate::digest::Algorithm::Sha256
    EcdsaP256Sha256Asn1 = 1113,
    /// Fixed-length (PKCS#11 style) ECDSA signatures using the [`P256`] curve
    /// and [`Sha256`].
    ///
    /// [`P256`]: Curve::P256
    /// [`Sha256`]: crate::digest::Algorithm::Sha256
    EcdsaP256Sha256Fixed = -1113,
    /// ASN.1 DER-encoded ECDSA signatures using the [`P384`] curve and
    /// [`Sha384`].
    ///
    /// [`P384`]: Curve::P384
    /// [`Sha384`]: crate::digest::Algorithm::Sha384
    EcdsaP384Sha384Asn1 = 1114,
    /// Fixed-length (PKCS#11 style) ECDSA signatures using the [`P384`] curve
    /// and [`Sha384`].
    ///
    /// [`P384`]: Curve::P384
    /// [`Sha384`]: crate::digest::Algorithm::Sha384
    EcdsaP384Sha384Fixed = -1114,
    /// Verification of [`Curve25519`] signatures.
    ///
    /// [`Curve25519`]: Curve::Curve25519
    Ed25519 = 1087,
    /// Verification of [`Curve448`] signatures.
    ///
    /// [`Curve448`]: Curve::Curve448
    Ed448 = 1088,
}

impl Algorithm {
    /// Elliptic curve associated with the algorithm.
    pub fn curve(&self) -> Curve {
        match self {
            Self::EcdsaP256Sha256Asn1 | Self::EcdsaP256Sha256Fixed => Curve::P256,
            Self::EcdsaP384Sha384Asn1 | Self::EcdsaP384Sha384Fixed => Curve::P384,
            Self::Ed25519 => Curve::Curve25519,
            Self::Ed448 => Curve::Curve448,
        }
    }
}

impl TryFrom<i32> for Algorithm {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1113 => Ok(Self::EcdsaP256Sha256Asn1),
            -1113 => Ok(Self::EcdsaP256Sha256Fixed),
            1114 => Ok(Self::EcdsaP384Sha384Asn1),
            -1114 => Ok(Self::EcdsaP384Sha384Fixed),
            1087 => Ok(Self::Ed25519),
            1088 => Ok(Self::Ed448),
            _ => Err(Error::UnsupportedSignatureAlgorithm),
        }
    }
}

/// A private key used for digital signatures.
pub trait SigningKey {
    /// Signs given `message` using the selected digest function.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Computes public key of the signing key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKeySerializer>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Algorithm;

    /// Interface for serializing the key into binary formats.
    fn to_serializer(self: Box<Self>) -> Box<dyn PrivateKeySerializer>;
}

/// A public key for verifying digital signatures.
pub trait VerifyingKey {
    /// Verifies the signature of the given `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Algorithm;

    /// Interface for serializing the key into binary formats.
    fn to_serializer(self: Box<Self>) -> Box<dyn PublicKeySerializer>;
}
