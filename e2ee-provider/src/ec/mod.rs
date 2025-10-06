use crate::Error;
use alloc::boxed::Box;
use encoding::{PrivateKeyBin, PrivateKeyDer, PublicKeyBin, PublicKeyDer};

/// Elliptic curve key agreement interface.
pub mod agreement;

/// Elliptic curve digital signature algorithms.
pub mod signature;

/// Public and private key encoding formats.
pub mod encoding;

/// Supported elliptic curves.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256 curve (NSA Suite B).
    ///
    /// Also known as: prime256v1, secp256r1, prime256v1
    P256 = 415,
    /// NIST P-384 curve (NSA Suite B).
    ///
    /// Also known as: secp384r1, ansip384r1
    P384 = 715,
    /// NIST P-521 curve (NSA Suite B).
    ///
    /// Also known as: secp521r1, ansip521r1
    P521 = 716,
    /// Curve25519 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve25519 = 1034,
    /// Curve448 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve448 = 1035,
}

impl TryFrom<i32> for Curve {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            415 => Ok(Self::P256),
            715 => Ok(Self::P384),
            716 => Ok(Self::P521),
            1034 => Ok(Self::Curve25519),
            1035 => Ok(Self::Curve448),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// Mechanism for loading or generating keys.
pub trait KeyProvider {
    /// Loads a private (agreement) key from DER.
    fn load_private_key_der(
        algorithm: agreement::Algorithm,
        der: PrivateKeyDer,
    ) -> Result<Box<dyn agreement::PrivateKey>, Error>;

    /// Loads a private (agreement) key from big-endian bytes.
    fn load_private_key_bin(
        algorithm: agreement::Algorithm,
        der: PrivateKeyBin,
    ) -> Result<Box<dyn agreement::PrivateKey>, Error>;

    /// Loads a public (agreement) key from DER.
    fn load_public_key_der(
        algorithm: agreement::Algorithm,
        der: PublicKeyDer,
    ) -> Result<Box<dyn agreement::PublicKey>, Error>;

    /// Loads a private (agreement) key from big-endian bytes.
    fn load_public_key_bin(
        algorithm: agreement::Algorithm,
        der: PublicKeyBin,
    ) -> Result<Box<dyn agreement::PublicKey>, Error>;

    /// Generates a new ephemeral private key.
    fn generate_ephemeral_private_key(
        algorithm: agreement::Algorithm,
    ) -> Result<Box<dyn agreement::EphemeralPrivateKey>, Error>;

    /// Loads an elliptic curve signing key from DER.
    fn load_signing_key_der(
        algorithm: signature::Algorithm,
        der: PrivateKeyDer,
    ) -> Result<Box<dyn signature::SigningKey>, Error>;

    /// Loads an elliptic curve signing key from raw bytes.
    fn load_signing_key_bin(
        algorithm: signature::Algorithm,
        der: PrivateKeyDer,
    ) -> Result<Box<dyn signature::SigningKey>, Error>;

    /// Loads an elliptic curve verifying key from DER.
    fn load_verifying_key_der(
        algorithm: signature::Algorithm,
        der: PublicKeyDer,
    ) -> Result<Box<dyn signature::VerifyingKey>, Error>;

    /// Loads an elliptic curve signing key from raw bytes.
    fn load_verifying_key_bin(
        algorithm: signature::Algorithm,
        der: PublicKeyBin,
    ) -> Result<Box<dyn signature::VerifyingKey>, Error>;
}
