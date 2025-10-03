use super::AwsLcRs;
use crate::{Error, key::*};
use alloc::{borrow::ToOwned, boxed::Box};
use aws_lc_rs::{
    agreement,
    encoding::{AsDer, EcPrivateKeyRfc5915Der, PublicKeyX509Der},
};
use core::any::Any;

/// Key agreement using ECDH.
pub struct EcdhPrivateKey {
    key: agreement::PrivateKey,
    algorithm: Curve,
}

/// Possibly malformed ECDH public key.
pub struct EcdhPublicKey {
    bytes: PublicKeyBytes,
    algorithm: Curve,
}

/// Parsed ECDH public key for key agreement.
pub struct SerializedEcdhPublicKey {
    key: agreement::UnparsedPublicKey<agreement::PublicKey>,
    algorithm: Curve,
}

macro_rules! map_algorithm {
    ($curve:expr) => {
        match $curve {
            Curve::P256 => &agreement::ECDH_P256,
            Curve::P384 => &agreement::ECDH_P384,
            Curve::P521 => &agreement::ECDH_P521,
            Curve::Curve448 => unreachable!(),
            Curve::Curve25519 => unreachable!(),
        }
    };
}

impl PrivateKey for EcdhPrivateKey {
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Error> {
        if let Some(serialized_public_key) =
            (&peer_public_key as &dyn Any).downcast_ref::<SerializedEcdhPublicKey>()
        {
            if self.algorithm != serialized_public_key.algorithm {
                return Err(Error::KeyRejected);
            }

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

        let public_key_reloaded = if (&peer_public_key as &dyn Any).is::<EcdhPublicKey>() {
            peer_public_key
        } else {
            let public_key = AwsLcRs.load_public_key(peer_public_key.to_bytes())?;

            if public_key.algorithm() != self.algorithm {
                return Err(Error::KeyRejected);
            }

            public_key
        };

        let peer_public_key = (&public_key_reloaded as &dyn Any)
            .downcast_ref::<EcdhPublicKey>()
            .expect("unreachable");

        agreement::agree(
            &self.key,
            &agreement::UnparsedPublicKey::new(
                map_algorithm!(self.algorithm),
                &peer_public_key.bytes,
            ),
            Error::Unspecified,
            |okm| {
                Ok(SharedSecret {
                    buf: okm.to_owned(),
                })
            },
        )
    }

    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(SerializedEcdhPublicKey {
            key: agreement::UnparsedPublicKey::new(
                self.key.algorithm(),
                self.key.compute_public_key()?,
            ),
            algorithm: self.algorithm,
        }))
    }

    fn to_bytes(self: Box<Self>) -> PrivateKeyBytes {
        let der = AsDer::<EcPrivateKeyRfc5915Der<'static>>::as_der(&self.key).expect("unreachable");

        PrivateKeyBytes::EcPrivateKeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        self.algorithm
    }
}

impl PublicKey for EcdhPublicKey {
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes {
        self.bytes
    }

    fn algorithm(&self) -> Curve {
        self.algorithm
    }
}

impl PublicKey for SerializedEcdhPublicKey {
    fn to_bytes(self: Box<Self>) -> PublicKeyBytes {
        let der = AsDer::<PublicKeyX509Der>::as_der(self.key.bytes()).expect("unreachable");

        PublicKeyBytes::X509KeyDer((*der).as_ref().to_vec())
    }

    fn algorithm(&self) -> Curve {
        self.algorithm
    }
}
