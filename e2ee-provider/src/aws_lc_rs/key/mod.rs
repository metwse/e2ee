use super::AwsLcRs;
use crate::{Error, KeyProvider, key::*};
use alloc::boxed::Box;

/// X25519 key agreement using aws-lc-rs.
pub mod x25519;

/// ECDH key agreement using aws-lc-rs.
pub mod ecdh;

/// Curve25519 signature algorithm using aws-lc-rs .
pub mod ed25519;

/// Elliptic curve digital signature algorithm using aws-lc-rs .
pub mod ecdsa;

impl KeyProvider for AwsLcRs {
    fn load_private_key(&self, _key_bytes: PrivateKeyBytes) -> Result<Box<dyn PrivateKey>, Error> {
        todo!()
    }

    fn load_signing_key(&self, _key_bytes: PrivateKeyBytes) -> Result<Box<dyn SigningKey>, Error> {
        todo!()
    }

    fn load_identity_private_key(
        &self,
        _key_bytes: PrivateKeyBytes,
    ) -> Result<Box<dyn IdentityPrivateKey>, Error> {
        todo!()
    }

    fn load_public_key(&self, _key_bytes: PublicKeyBytes) -> Result<Box<dyn PublicKey>, Error> {
        todo!()
    }

    fn load_verifying_key(
        &self,
        _key_bytes: PublicKeyBytes,
    ) -> Result<Box<dyn VerifyingKey>, Error> {
        todo!()
    }

    fn load_identity_public_key(
        &self,
        _key_bytes: PublicKeyBytes,
    ) -> Result<Box<dyn IdentityPublicKey>, Error> {
        todo!()
    }

    fn generate_ephemeral_private_key(
        &self,
        _algorithm: Curve,
    ) -> Result<Box<dyn EphemeralPrivateKey>, Error> {
        todo!()
    }

    fn is_curve_supported(&self, _algorithm: Curve) -> bool {
        todo!()
    }
}
