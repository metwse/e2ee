use crate::Error;
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

/// Serialized private key DER.
pub enum PrivateKeyDer {
    /// PKCS #8 private key der v1 as described in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V1Key(Vec<u8>),
    /// PKCS #8 private key der v2 as described in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V2Key(Vec<u8>),
    /// Elliptic curve private key structure as described in
    /// [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
    EcPrivateKey(Vec<u8>),
}

/// Serialized public key DER.
#[derive(Clone)]
pub enum PublicKeyDer {
    /// Internet X.509 public key as described in
    /// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
    X509Key(Vec<u8>),
    /// Elliptic curve public key structure as described in
    /// [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
    EcPublicKey(Vec<u8>),
}

/// Mechanism for loading or generating keys.
pub trait KeyProvider {
    /// Loads private key from binary.
    fn load_private_key(&self, key_der: PrivateKeyDer) -> Result<Box<dyn PrivateKey>, Error>;

    /// Loads signing key from binary.
    fn load_signing_key(&self, key_der: PrivateKeyDer) -> Result<Box<dyn SingingKey>, Error>;

    /// Loads identity (signature + agreement) private key from binary.
    fn load_identity_private_key(
        &self,
        key_der: PrivateKeyDer,
    ) -> Result<Box<dyn IdentityPrivateKey>, Error>;

    /// Loads public key from binary.
    fn load_public_key(&self, key_der: PublicKeyDer) -> Result<Box<dyn PublicKey>, Error>;

    /// Loads signature verification public key from binary.
    fn load_verifying_key(&self, key_der: PublicKeyDer) -> Result<Box<dyn VerifyingKey>, Error>;

    /// Loads identity (signature + agreement) private key from binary.
    fn load_identity_public_key(
        &self,
        key_der: PrivateKeyDer,
    ) -> Result<Box<dyn IdentityPublicKey>, Error>;

    /// Generates an ephemeral private key.
    fn generate_ephemeral_private_key(
        &self,
        algorithm: Curve,
    ) -> Result<Box<dyn EphemeralPrivateKey>, Error>;

    /// Whether or not the curve algorithm is supported.
    fn is_curve_supported(&self, algorithm: Curve) -> bool;
}

/// A private key for key agreement. The signature of [`agree`] allows
/// [`PrivateKey`] to be used for more than one key agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error>;

    /// Computes public key of the private key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Serializes underlying private key as DER.
    fn as_der(&self) -> &PrivateKeyDer;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key for digital signatures.
pub trait SingingKey {
    /// Computes public key of the signing key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Signs `message` using the selected digest function.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Serializes underlying private key as DER.
    fn as_der(&self) -> &PrivateKeyDer;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key capable of both signing: and key agreement.
pub trait IdentityPrivateKey: PrivateKey + SingingKey {}

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

/// A public key can be used for key agreement.
pub trait PublicKey {
    /// Serializes underlying public key as DER.
    fn as_der(&self) -> &PublicKeyDer;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key can be used for key agreement.
pub trait VerifyingKey {
    /// Verifies signature of the message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;

    /// Serializes underlying public key as DER.
    fn as_der(&self) -> &PublicKeyDer;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key capable of both signing: and key agreement.
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

impl Drop for PrivateKeyDer {
    fn drop(&mut self) {
        match self {
            Self::Pkcs8V1Key(key) | Self::Pkcs8V2Key(key) | Self::EcPrivateKey(key) => {
                key.zeroize()
            }
        }
    }
}

impl AsRef<[u8]> for PrivateKeyDer {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Pkcs8V1Key(key) | Self::Pkcs8V2Key(key) | Self::EcPrivateKey(key) => key,
        }
    }
}

impl Drop for PublicKeyDer {
    fn drop(&mut self) {
        match self {
            Self::X509Key(key) | Self::EcPublicKey(key) => key.zeroize(),
        }
    }
}

impl AsRef<[u8]> for PublicKeyDer {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::X509Key(key) | Self::EcPublicKey(key) => key,
        }
    }
}
