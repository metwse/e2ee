use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

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

/// Serialized private key bytes.
#[derive(Clone)]
pub enum PrivateKeyBytes {
    /// PKCS #8 v1 private key in DER format, defined in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V1KeyDer(Vec<u8>),
    /// PKCS #8 v2 private key in DER format, defined in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V2KeyDer(Vec<u8>),
    /// Elliptic curve private key structure in DER format, defined in
    /// [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
    EcPrivateKeyDer(Vec<u8>),
    /// Curve25519 seed encoded as a big-endian fixed-length integer.
    Curve25519Seed(Vec<u8>),
}

/// Serialized public key bytes.
#[derive(Clone)]
pub enum PublicKeyBytes {
    /// Internet X.509 public key as defined in
    /// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
    X509KeyDer(Vec<u8>),
    /// Elliptic curve public key structure in DER format, defined in
    /// [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
    EcPublicKeyDer(Vec<u8>),
}

/// Mechanism for loading or generating keys.
pub trait KeyProvider {
    /// Loads a private (agreement) key from raw bytes.
    fn load_private_key(&self, key_bytes: PrivateKeyBytes) -> Result<Box<dyn PrivateKey>, Error>;

    /// Loads a signing key from raw bytes.
    fn load_signing_key(&self, key_bytes: PrivateKeyBytes) -> Result<Box<dyn SigningKey>, Error>;

    /// Loads a public (agreement) key from raw bytes.
    fn load_public_key(&self, key_bytes: PublicKeyBytes) -> Result<Box<dyn PublicKey>, Error>;

    /// Loads a verifying key from raw bytes.
    fn load_verifying_key(&self, key_bytes: PublicKeyBytes)
    -> Result<Box<dyn VerifyingKey>, Error>;

    /// Generates a new ephemeral private key.
    fn generate_ephemeral_private_key(
        &self,
        algorithm: Curve,
    ) -> Result<Box<dyn EphemeralPrivateKey>, Error>;

    /// Whether or not the curve algorithm is supported.
    fn is_curve_supported(&self, algorithm: Curve) -> bool;
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
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Serializes the private key into bytes.
    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes;

    /// Returns the curve associated with this key.
    fn algorithm(&self) -> Curve;
}

/// A private key used for digital signatures.
pub trait SigningKey {
    /// Computes public key of the signing key.
    fn compute_public_key(&self) -> Result<Box<dyn VerifyingKey>, Error>;

    /// Signs given `message` using the selected digest function.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Serializes underlying private key into bytes.
    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key capable of both signing and key agreement.
pub trait IdentityPrivateKey: PrivateKey + SigningKey {}

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
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key for key agreement.
pub trait PublicKey {
    /// Serializes the public key into bytes.
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key for verifying digital signatures.
pub trait VerifyingKey {
    /// Verifies the signature of the given `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;

    /// Serializes the public key into bytes.
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key capable of both signing and key agreement.
pub trait IdentityPublicKey: PublicKey + VerifyingKey {}

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

impl Drop for PrivateKeyBytes {
    fn drop(&mut self) {
        match self {
            Self::Pkcs8V1KeyDer(key)
            | Self::Pkcs8V2KeyDer(key)
            | Self::EcPrivateKeyDer(key)
            | Self::Curve25519Seed(key) => key.zeroize(),
        }
    }
}

impl AsRef<[u8]> for PrivateKeyBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Pkcs8V1KeyDer(key)
            | Self::Pkcs8V2KeyDer(key)
            | Self::EcPrivateKeyDer(key)
            | Self::Curve25519Seed(key) => key,
        }
    }
}

impl Drop for PublicKeyBytes {
    fn drop(&mut self) {
        match self {
            Self::X509KeyDer(key) | Self::EcPublicKeyDer(key) => key.zeroize(),
        }
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X509KeyDer(key) | Self::EcPublicKeyDer(key) => key,
        }
    }
}
