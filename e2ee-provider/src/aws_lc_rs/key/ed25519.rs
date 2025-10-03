use crate::{key::*, Error};
use alloc::{boxed::Box, vec::Vec};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V2Der, PublicKeyX509Der},
    signature::{self, KeyPair},
};

/// Digital signature algorithm using Curve25519.
pub struct Ed25519PrivateKey {
    key: signature::Ed25519KeyPair,
}

/// Curve25519 for key signature verification.
pub struct Ed25519PublicKey {
    key: signature::ParsedPublicKey,
}

impl SigningKey for Ed25519PrivateKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.try_sign(message)?.as_ref().to_vec())
    }

    fn compute_public_key(&self) -> Result<Box<dyn VerifyingKey>, Error> {
        Ok(Box::new(Ed25519PublicKey {
            key: signature::ParsedPublicKey::new(&signature::ED25519, self.key.public_key())?,
        }))
    }

    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes {
        let der = AsDer::<Pkcs8V2Der>::as_der(&self.key).expect("unreachable");

        PrivateKeyBytes::Pkcs8V2KeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl VerifyingKey for Ed25519PublicKey {
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
