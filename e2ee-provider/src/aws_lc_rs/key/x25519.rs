use super::AwsLcRs;
use crate::{Error, key::*};
use alloc::{borrow::ToOwned, boxed::Box};
use aws_lc_rs::{
    agreement,
    encoding::{AsBigEndian, AsDer, Curve25519SeedBin, PublicKeyX509Der},
};
use core::any::Any;

/// Key agreement using Curve25519.
pub struct X25519PrivateKey {
    key: agreement::PrivateKey,
}

/// Possibly malformed Curve25519 public key.
pub struct X25519PublicKey {
    bytes: PublicKeyBytes,
}

/// Parsed Curve25519 for key agreement.
pub struct SerializedX25519PublicKey {
    key: agreement::UnparsedPublicKey<agreement::PublicKey>,
}

impl PrivateKey for X25519PrivateKey {
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error> {
        if let Some(serialized_public_key) =
            (&peer_public_key as &dyn Any).downcast_ref::<SerializedX25519PublicKey>()
        {
            return agreement::agree(
                &self.key,
                &serialized_public_key.key,
                Error::Unspecified,
                |okm| {
                    Ok(SharedSecret {
                        buf: okm.to_owned(),
                    })
                },
            );
        }

        let public_key_reloaded = if (&peer_public_key as &dyn Any).is::<X25519PublicKey>() {
            peer_public_key
        } else {
            let public_key = AwsLcRs.load_public_key(peer_public_key.to_bytes())?;

            if public_key.algorithm() != Curve::Curve25519 {
                return Err(Error::KeyRejected);
            }

            public_key
        };

        let peer_public_key = (&public_key_reloaded as &dyn Any)
            .downcast_ref::<X25519PublicKey>()
            .expect("unreachable");

        agreement::agree(
            &self.key,
            agreement::UnparsedPublicKey::new(&agreement::X25519, &peer_public_key.bytes),
            Error::Unspecified,
            |okm| {
                Ok(SharedSecret {
                    buf: okm.to_owned(),
                })
            },
        )
    }

    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(SerializedX25519PublicKey {
            key: agreement::UnparsedPublicKey::new(
                self.key.algorithm(),
                self.key.compute_public_key()?,
            ),
        }))
    }

    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes {
        let be_bytes =
            AsBigEndian::<Curve25519SeedBin<'static>>::as_be_bytes(&self.key).expect("unreachable");

        PrivateKeyBytes::Curve25519Seed((*be_bytes).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl PublicKey for X25519PublicKey {
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes {
        self.bytes
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl PublicKey for SerializedX25519PublicKey {
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes {
        let der = AsDer::<PublicKeyX509Der>::as_der(self.key.bytes()).expect("unreachable");

        PublicKeyBytes::X509KeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}
