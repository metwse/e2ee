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
    encoding::{self, AsBigEndian, AsDer},
    rand,
    signature::{self, KeyPair},
};

/// Digital signature algorithm using NSA Suite B elliptic curves.
pub struct EcdsaSigningKey {
    pub(super) key: signature::EcdsaKeyPair,
    pub(super) algorithm: Algorithm,
}

impl SigningKey for EcdsaSigningKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .key
            .sign(&rand::SystemRandom::new(), message)?
            .as_ref()
            .to_vec())
    }

    fn compute_public_key(&self) -> Result<Box<dyn PublicKeySerializer>, Error> {
        Ok(Box::new(VerifyingKeySerializer {
            key: self.key.public_key().clone(),
        }))
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn to_serializer(self: Box<Self>) -> Box<dyn PrivateKeySerializer> {
        Box::new(EcdsaSigningKeySerializer { key: self.key })
    }
}

/// Digital signature verification for NSA Suite B elliptic curves.
pub struct EcdsaVerifyingKey {
    pub(super) key: signature::ParsedPublicKey,
    pub(super) algorithm: Algorithm,
}

impl VerifyingKey for EcdsaVerifyingKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.key.verify_sig(message, signature).is_ok()
    }

    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn to_serializer(self: Box<Self>) -> Box<dyn PublicKeySerializer> {
        Box::new(VerifyingKeySerializer {
            key: self.key.clone(),
        })
    }
}

struct EcdsaSigningKeySerializer {
    key: signature::EcdsaKeyPair,
}

impl PrivateKeySerializer for EcdsaSigningKeySerializer {
    fn as_pkcs8v1_der(&self) -> Result<PrivateKeyDer, Error> {
        Ok(PrivateKeyDer::Pkcs8V1Key(
            self.key.to_pkcs8v1()?.as_ref().to_vec(),
        ))
    }

    fn as_pkcs8v2_der(&self) -> Result<PrivateKeyDer, Error> {
        Err(Error::UnsupportedEncoding)
    }

    fn as_rfc_5915_private_key_der(&self) -> Result<PrivateKeyDer, Error> {
        Ok(PrivateKeyDer::EcPrivateKey(
            AsDer::<encoding::EcPrivateKeyRfc5915Der<'static>>::as_der(&self.key.private_key())?
                .as_ref()
                .to_vec(),
        ))
    }

    fn as_ec_be_bytes(&self) -> Result<PrivateKeyBin, Error> {
        Ok(PrivateKeyBin::Ec(
            AsBigEndian::<encoding::EcPrivateKeyBin<'static>>::as_be_bytes(
                &self.key.private_key(),
            )?
            .as_ref()
            .to_vec(),
        ))
    }

    fn as_ed_ec_be_bytes(&self) -> Result<PrivateKeyBin, Error> {
        Err(Error::UnsupportedEncoding)
    }
}
