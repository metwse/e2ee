use super::AwsLcRs;
use crate::{Error, key::*};
use alloc::{borrow::ToOwned, boxed::Box};
use aws_lc_rs::{
    agreement,
    encoding::{AsBigEndian, AsDer, Curve25519SeedBin, PublicKeyX509Der},
};
use core::any::Any;

/// Key agreement using Curve25519.
pub struct X25519PrivateKey(agreement::PrivateKey);

/// Possibly malformed Curve25519 public key.
pub struct X25519PublicKey(agreement::UnparsedPublicKey<PublicKeyBytes>);

/// Parsed Curve25519 for key agreement.
pub struct SerializedX25519PublicKey(agreement::UnparsedPublicKey<agreement::PublicKey>);

impl PrivateKey for X25519PrivateKey {
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error> {
        if let Some(serialized_public_key) =
            (&peer_public_key as &dyn Any).downcast_ref::<SerializedX25519PublicKey>()
        {
            return agreement::agree(
                &self.0,
                &serialized_public_key.0,
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

        if let Some(public_key) =
            (&public_key_reloaded as &dyn Any).downcast_ref::<X25519PublicKey>()
        {
            agreement::agree(&self.0, &public_key.0, Error::Unspecified, |okm| {
                Ok(SharedSecret {
                    buf: okm.to_owned(),
                })
            })
        } else {
            unreachable!()
        }
    }

    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(SerializedX25519PublicKey(
            agreement::UnparsedPublicKey::new(self.0.algorithm(), self.0.compute_public_key()?),
        )))
    }

    fn to_bytes(&self) -> PrivateKeyBytes {
        if let Ok(buf) = AsBigEndian::<Curve25519SeedBin<'static>>::as_be_bytes(&self.0) {
            PrivateKeyBytes::Curve25519Seed((*buf).as_ref().to_vec())
        } else {
            unreachable!()
        }
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl PublicKey for X25519PublicKey {
    fn to_bytes(&self) -> PublicKeyBytes {
        self.0.bytes().clone()
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}

impl PublicKey for SerializedX25519PublicKey {
    fn to_bytes(&self) -> PublicKeyBytes {
        if let Ok(buf) = AsDer::<PublicKeyX509Der>::as_der(self.0.bytes()) {
            PublicKeyBytes::X509KeyDer((*buf).as_ref().to_vec())
        } else {
            unreachable!()
        }
    }

    fn algorithm(&self) -> Curve {
        Curve::Curve25519
    }
}
