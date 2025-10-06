use crate::{
    Error,
    ec::encoding::{PublicKeyBin, PublicKeyDer, PublicKeySerializer},
};
use alloc::borrow::ToOwned;
use aws_lc_rs::encoding::AsDer;

/// Curve25519 digital signature algorithm using aws-lc-rs.
pub mod ed25519;

/// Elliptic curve digital signature algorithm using aws-lc-rs.
pub mod ecdsa;

//  /// X25519 key agreement using aws-lc-rs.
//  pub mod x25519;

//  /// ECDH key agreement using aws-lc-rs.
//  pub mod ecdh;

struct VerifyingKeySerializer<T> {
    key: T,
}

impl<T> PublicKeySerializer for VerifyingKeySerializer<T>
where
    T: AsDer<aws_lc_rs::encoding::PublicKeyX509Der<'static>> + AsRef<[u8]>,
{
    fn as_x509_der(&self) -> Result<PublicKeyDer, Error> {
        Ok(PublicKeyDer::X509Key(
            self.key.as_der()?.as_ref().to_owned(),
        ))
    }

    fn as_rfc_5915_public_key_der(&self) -> Result<PublicKeyDer, Error> {
        Err(Error::UnsupportedEncoding)
    }

    fn as_be_bytes(&self) -> Result<PublicKeyBin, Error> {
        Ok(PublicKeyBin::Uncompreessed(self.key.as_ref().to_vec()))
    }

    fn as_compressed_be_bytes(&self) -> Result<PublicKeyBin, Error> {
        Err(Error::UnsupportedEncoding)
    }
}
