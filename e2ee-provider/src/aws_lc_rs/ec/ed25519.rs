use super::VerifyingKeySerializer;
use crate::{
    Error,
    ec::{
        encoding::{PrivateKeyBin, PrivateKeyDer, PrivateKeySerializer, PublicKeySerializer},
        signature::{Algorithm, SigningKey, VerifyingKey},
    },
};
use alloc::{boxed::Box, vec::Vec};
use aws_lc_rs::{
    encoding::AsBigEndian,
    signature::{self, KeyPair},
};

/// Signing key for [`Ed25519`] digital signature algorithm.
///
/// [`Ed25519`]: Algorithm::Ed25519
pub struct Ed25519SigningKey {
    key: signature::Ed25519KeyPair,
}

impl SigningKey for Ed25519SigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.try_sign(message)?.as_ref().to_vec())
    }

    fn compute_public_key(&self) -> Result<Box<dyn PublicKeySerializer>, Error> {
        Ok(Box::new(VerifyingKeySerializer {
            key: self.key.public_key().clone(),
        }))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn to_serializer(self: Box<Self>) -> Box<dyn PrivateKeySerializer> {
        Box::new(Ed25519SigningKeySerializer { key: self.key })
    }
}

/// [`Ed25519`] digital signature algorithm verification key.
///
/// [`Ed25519`]: Algorithm::Ed25519
pub struct Ed25519VerifyingKey {
    key: signature::ParsedPublicKey,
}

impl VerifyingKey for Ed25519VerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.key.verify_sig(message, signature).is_ok()
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn to_serializer(self: Box<Self>) -> Box<dyn PublicKeySerializer> {
        Box::new(VerifyingKeySerializer { key: self.key })
    }
}

struct Ed25519SigningKeySerializer {
    key: signature::Ed25519KeyPair,
}

impl PrivateKeySerializer for Ed25519SigningKeySerializer {
    fn as_pkcs8v1_der(&self) -> Result<PrivateKeyDer, Error> {
        Ok(PrivateKeyDer::Pkcs8V1Key(
            self.key.to_pkcs8v1()?.as_ref().to_vec(),
        ))
    }

    fn as_pkcs8v2_der(&self) -> Result<PrivateKeyDer, Error> {
        Ok(PrivateKeyDer::Pkcs8V1Key(
            self.key.to_pkcs8()?.as_ref().to_vec(),
        ))
    }

    fn as_rfc_5915_private_key_der(&self) -> Result<PrivateKeyDer, Error> {
        Err(Error::UnsupportedEncoding)
    }

    fn as_ec_be_bytes(&self) -> Result<PrivateKeyBin, Error> {
        Err(Error::UnsupportedEncoding)
    }

    fn as_ed_ec_be_bytes(&self) -> Result<PrivateKeyBin, Error> {
        Ok(PrivateKeyBin::EdEcSeed(
            self.key.seed()?.as_be_bytes()?.as_ref().to_vec(),
        ))
    }
}
