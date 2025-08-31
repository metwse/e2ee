use super::{super::key, AwsLcRs};
use crate::Error;
use alloc::{boxed::Box, vec::Vec};
use aws_lc_rs::{
    agreement::{self, UnparsedPublicKey},
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rand,
};
use core::any::Any;

macro_rules! map {
    ($algorithm:expr) => {
        match $algorithm {
            key::Algorithm::EcdhP256 => &agreement::ECDH_P256,
            key::Algorithm::EcdhP384 => &agreement::ECDH_P384,
            key::Algorithm::EcdhP521 => &agreement::ECDH_P521,
            _ => return Err(Error::UnsupportedAlgorithm),
        }
    };
}

fn is_curve_supported(algorithm: key::Algorithm) -> bool {
    matches!(
        algorithm,
        key::Algorithm::EcdhP256 | key::Algorithm::EcdhP384 | key::Algorithm::EcdhP521
    )
}

impl key::Provider for AwsLcRs {
    fn load_private_key(
        &self,
        algorithm: key::Algorithm,
        key_der: &[u8],
    ) -> Result<Box<dyn key::PrivateKey>, Error> {
        Ok(Box::new(PrivateKey {
            algorithm,
            key: agreement::PrivateKey::from_private_key_der(map!(algorithm), key_der)?,
        }))
    }

    fn load_public_key(
        &self,
        algorithm: key::Algorithm,
        key_der: Vec<u8>,
    ) -> Result<Box<dyn key::PublicKey>, Error> {
        Ok(Box::new(PublicKey::Vec {
            key: agreement::UnparsedPublicKey::new(map!(algorithm), key_der),
            algorithm,
        }))
    }

    fn generate_ephemeral_private_key(
        &self,
        algorithm: key::Algorithm,
    ) -> Result<Box<dyn key::EphemeralPrivateKey>, Error> {
        Ok(Box::new(EphemeralPrivateKey {
            algorithm,
            key: agreement::EphemeralPrivateKey::generate(
                map!(algorithm),
                &rand::SystemRandom::new(),
            )?,
        }))
    }

    fn is_curve_supported(&self, algorithm: key::Algorithm) -> bool {
        is_curve_supported(algorithm)
    }
}

macro_rules! agreement {
    ($privk:expr, $pubk:expr, $fn:ident) => {
        match $pubk {
            PublicKey::Vec { key, .. } => {
                agreement::$fn($privk, &key, Error::Unspecified, |k| Ok(k.to_vec()))?
            }
            PublicKey::Parsed { key, .. } => {
                agreement::$fn($privk, &key, Error::Unspecified, |k| Ok(k.to_vec()))?
            }
        }
    };
}

struct PrivateKey {
    algorithm: key::Algorithm,
    key: agreement::PrivateKey,
}

impl key::PrivateKey for PrivateKey {
    fn agree(&self, peer_public_key: Box<dyn key::PublicKey>) -> Result<key::SharedSecret, Error> {
        let buf = match (&peer_public_key as &dyn Any).downcast_ref::<PublicKey>() {
            Some(pk) => agreement!(&self.key, pk, agree),
            None => {
                let alg = peer_public_key.algorithm();
                if !is_curve_supported(alg) {
                    return Err(Error::UnsupportedAlgorithm);
                }
                agreement::agree(
                    &self.key,
                    &UnparsedPublicKey::new(map!(alg), peer_public_key.as_der()?),
                    Error::Unspecified,
                    |k| Ok(k.to_vec()),
                )?
            }
        };

        Ok(key::SharedSecret { buf })
    }

    fn compute_public_key(&self) -> Result<Box<dyn key::PublicKey>, Error> {
        Ok(Box::new(PublicKey::Parsed {
            algorithm: self.algorithm,
            key: UnparsedPublicKey::new(map!(self.algorithm()), self.key.compute_public_key()?),
        }))
    }

    fn as_der(&self) -> Result<Vec<u8>, Error> {
        let der: Pkcs8V1Der<'static> = self.key.as_der()?;

        Ok(der.as_ref().to_vec())
    }

    fn algorithm(&self) -> key::Algorithm {
        self.algorithm
    }
}

struct EphemeralPrivateKey {
    algorithm: key::Algorithm,
    key: agreement::EphemeralPrivateKey,
}

impl key::EphemeralPrivateKey for EphemeralPrivateKey {
    fn agree_ephemeral(
        self: Box<Self>,
        peer_public_key: Box<dyn key::PublicKey>,
    ) -> Result<key::SharedSecret, Error> {
        let buf = match (&peer_public_key as &dyn Any).downcast_ref::<PublicKey>() {
            Some(pk) => agreement!(self.key, pk, agree_ephemeral),
            None => {
                let alg = peer_public_key.algorithm();
                if !is_curve_supported(alg) {
                    return Err(Error::UnsupportedAlgorithm);
                }
                agreement::agree_ephemeral(
                    self.key,
                    &UnparsedPublicKey::new(map!(alg), peer_public_key.as_der()?),
                    Error::Unspecified,
                    |k| Ok(k.to_vec()),
                )?
            }
        };

        Ok(key::SharedSecret { buf })
    }

    fn compute_public_key(&self) -> Result<Box<dyn key::PublicKey>, Error> {
        Ok(Box::new(PublicKey::Parsed {
            algorithm: self.algorithm(),
            key: UnparsedPublicKey::new(map!(self.algorithm()), self.key.compute_public_key()?),
        }))
    }

    fn algorithm(&self) -> key::Algorithm {
        self.algorithm
    }
}

enum PublicKey {
    Vec {
        key: agreement::UnparsedPublicKey<Vec<u8>>,
        algorithm: key::Algorithm,
    },
    Parsed {
        key: agreement::UnparsedPublicKey<agreement::PublicKey>,
        algorithm: key::Algorithm,
    },
}

impl key::PublicKey for PublicKey {
    fn as_der(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            Self::Vec { key, .. } => key.bytes().clone(),
            Self::Parsed { key, .. } => {
                let public_key = key.bytes();

                let der: PublicKeyX509Der = public_key.as_der()?;

                der.as_ref().to_vec()
            }
        })
    }

    fn algorithm(&self) -> key::Algorithm {
        match self {
            Self::Vec { algorithm, .. } => *algorithm,
            Self::Parsed { algorithm, .. } => *algorithm,
        }
    }
}
