use super::AwsLcRs;
use crate::{
    Error, HashProvider, HkdfProvider, KeyProvider,
    hkdf::{self, Hkdf},
    key::{Curve, EphemeralPrivateKey, PrivateKey, PrivateKeyDer, PublicKey, PublicKeyDer},
    provider::Provider,
};

impl HashProvider for AwsLcRs {}

impl Provider<hkdf::Algorithm, &'static dyn Hkdf> for AwsLcRs {
    fn get(&self, _algorithm: hkdf::Algorithm) -> Option<&'static dyn Hkdf> {
        todo!()
    }

    fn supported_algorithms(&self) -> &'static [hkdf::Algorithm] {
        todo!()
    }

    fn is_algorithm_supported(&self, _algorithm: hkdf::Algorithm) -> bool {
        todo!()
    }
}

impl HkdfProvider for AwsLcRs {}

impl KeyProvider for AwsLcRs {
    fn load_public_key(
        &self,
        _key_der: PublicKeyDer,
    ) -> Result<alloc::boxed::Box<dyn PublicKey>, Error> {
        todo!()
    }

    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer,
    ) -> Result<alloc::boxed::Box<dyn PrivateKey>, Error> {
        todo!()
    }

    fn is_curve_supported(&self, _algorithm: Curve) -> bool {
        todo!()
    }

    fn generate_ephemeral_private_key(
        &self,
        _algorithm: crate::key::Curve,
    ) -> Result<alloc::boxed::Box<dyn EphemeralPrivateKey>, Error> {
        todo!()
    }
}
