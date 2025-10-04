use crate::{Error, key::*};
use alloc::{boxed::Box, vec::Vec};
use aws_lc_rs::{
    encoding::{AsDer, EcPrivateKeyRfc5915Der, PublicKeyX509Der},
    signature::{self, KeyPair},
};

/// Digital signature algorithm using Curve25519.
pub struct EcdsaPrivateKey {
    key: signature::EcdsaKeyPair,
}

/// Curve25519 for key signature verification.
pub struct EcdsaPublicKey {
    key: signature::ParsedPublicKey,
}

impl SigningKey for EcdsaPrivateKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .key
            .sign(&aws_lc_rs::rand::SystemRandom::new(), message)?
            .as_ref()
            .to_vec())
    }

    fn compute_public_key(&self) -> Result<Box<dyn VerifyingKey>, Error> {
        Ok(Box::new(EcdsaPublicKey {
            key: signature::ParsedPublicKey::new(&signature::ED25519, self.key.public_key())?,
        }))
    }

    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes {
        let der =
            AsDer::<EcPrivateKeyRfc5915Der>::as_der(&self.key.private_key()).expect("unreachable");

        PrivateKeyBytes::EcPrivateKeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl VerifyingKey for EcdsaPublicKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.key.verify_sig(message, signature).is_ok()
    }

    fn to_bytes(self: Box<Self>) -> PublicKeyBytes {
        let der = AsDer::<PublicKeyX509Der>::as_der(&self.key).expect("unreachable");

        PublicKeyBytes::X509KeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}
