use super::AwsLcRs;
use crate::{Error, KeyProvider, key::*};
use alloc::boxed::Box;

/// DH key agreement using aws-lc-rs.
pub mod agreement;

/// Cryptographic signature verification.
pub mod signature;

impl KeyProvider for AwsLcRs {
    fn load_private_key(&self, _key_bytes: PrivateKeyBytes) -> Result<Box<dyn PrivateKey>, Error> {
        todo!()
    }

    fn load_signing_key(&self, _key_bytes: PrivateKeyBytes) -> Result<Box<dyn SingingKey>, Error> {
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
