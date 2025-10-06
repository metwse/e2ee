use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

/// Serialized private key DER.
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

/// Serialized public key DER.
#[derive(Clone)]
pub enum PublicKeyDer {
    /// Internet X.509 public key as defined in
    /// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
    X509Key(Vec<u8>),
    /// Elliptic curve public key structure in DER format, defined in
    /// [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
    EcPublicKey(Vec<u8>),
}

/// Serialized private key bytes.
#[derive(Clone)]
pub enum PrivateKeyBin {
    /// Seed of a twisted Edwards curve encoded as a big-endian fixed-length
    /// integer.
    EdEcSeed(Vec<u8>),
    /// Elliptic curve private key encoded as a big-endian fixed-length
    /// integer.
    Ec(Vec<u8>),
}

/// Serialized public key bytes.
#[derive(Clone)]
pub enum PublicKeyBin {
    /// Compressed big-endian integer representing elliptic curve.
    Compressed(Vec<u8>),
    /// Big-endian integer representing elliptic curve.
    Uncompreessed(Vec<u8>),
}

/// Methods for serializing private keys into DER or binary formats.
pub trait PrivateKeySerializer {
    /// Serializes the private key into PKCS#8 v1 DER format.
    fn to_pkcs8v1_der(self: Box<Self>) -> Result<PrivateKeyDer, Error>;

    /// Serializes the private key into PKCS#8 v2 DER format.
    fn to_pkcs8v2_der(self: Box<Self>) -> Result<PrivateKeyDer, Error>;

    /// Serializes the private key into elliptic curve private key structure,
    /// defined in [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
    fn to_rfc_5915_private_key_der(self: Box<Self>) -> Result<PrivateKeyDer, Error>;

    /// Exposes the seed encoded as a big-endian fixed-length integer.
    ///
    /// Only X25519 and X448 are supported.
    fn to_ed_ec_be_bytes(self: Box<Self>) -> Result<PrivateKeyBin, Error>;

    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// X25519 and X448 are not supported.
    fn to_ec_be_bytes(self: Box<Self>) -> Result<PrivateKeyBin, Error>;
}

/// Methods for serializing public keys into DER or binary formats.
pub trait PublicKeySerializer {
    /// Serializes the key into Internet X.509 Public Key format.
    fn to_x509_der(self: Box<Self>) -> Result<PublicKeyDer, Error>;

    /// Serializes the public key into elliptic curve public key structure,
    /// defined in [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
    fn to_rfc_5915_private_key_der(self: Box<Self>) -> Result<PublicKeyDer, Error>;

    /// Serializes the key into a big-endian format.
    fn to_be_bytes(self: Box<Self>) -> Result<PublicKeyBin, Error>;

    /// Serializes the key into a compressed big-endian format.
    fn to_compressed_be_bytes(self: Box<Self>) -> Result<PublicKeyBin, Error>;
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

impl Drop for PrivateKeyBin {
    fn drop(&mut self) {
        match self {
            Self::Ec(bytes) | Self::EdEcSeed(bytes) => bytes.zeroize(),
        }
    }
}

impl AsRef<[u8]> for PrivateKeyBin {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Ec(bytes) | Self::EdEcSeed(bytes) => bytes,
        }
    }
}

impl Drop for PublicKeyBin {
    fn drop(&mut self) {
        match self {
            Self::Compressed(bytes) | Self::Uncompreessed(bytes) => bytes.zeroize(),
        }
    }
}

impl AsRef<[u8]> for PublicKeyBin {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Compressed(bytes) | Self::Uncompreessed(bytes) => bytes,
        }
    }
}
