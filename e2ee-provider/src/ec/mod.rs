use crate::Error;
use alloc::vec::Vec;
use zeroize::Zeroize;

/// Elliptic curve key agreement interface.
pub mod agreement;

/// Elliptic curve digital signature algorithms.
pub mod signature;

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

/// Serialized private key bytes.
#[derive(Clone)]
pub enum PrivateKeyDer {
    /// PKCS #8 v1 private key in DER format, defined in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V1Key(Vec<u8>),
    /// PKCS #8 v2 private key in DER format, defined in
    /// [RFC 5208](https://datatracker.ietf.org/doc/html/rfc5208).
    Pkcs8V2Key(Vec<u8>),
    /// Elliptic curve private key structure in DER format, defined in
    /// [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
    EcPrivateKey(Vec<u8>),
}

/// Serialized public key bytes.
#[derive(Clone)]
pub enum PublicKeyDer {
    /// Internet X.509 public key as defined in
    /// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
    X509Key(Vec<u8>),
    /// Elliptic curve public key structure in DER format, defined in
    /// [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
    EcPublicKey(Vec<u8>),
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
