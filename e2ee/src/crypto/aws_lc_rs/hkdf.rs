use super::{
    super::{algorithms::HkdfAlgorithm, HkdfExpander, HkdfProvider},
    AwsLcRs,
};
use crate::error::Unspecified;
use alloc::boxed::Box;
use aws_lc_rs::hkdf;

impl HkdfProvider for AwsLcRs {
    fn extract(
        &self,
        algorithm: HkdfAlgorithm,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(
            ZERO_SALT[match algorithm {
                HkdfAlgorithm::Sha256 => 0,
                HkdfAlgorithm::Sha384 => 1,
                HkdfAlgorithm::Sha512 => 2,
            }],
        );

        let salt = hkdf::Salt::new(
            match algorithm {
                HkdfAlgorithm::Sha256 => hkdf::HKDF_SHA256,
                HkdfAlgorithm::Sha384 => hkdf::HKDF_SHA384,
                HkdfAlgorithm::Sha512 => hkdf::HKDF_SHA512,
            },
            salt,
        );
        let pseudo_random_key = salt.extract(secret);

        Box::new(Prk { pseudo_random_key })
    }

    fn is_supported(&self, algorithm: HkdfAlgorithm) -> bool {
        match algorithm {
            HkdfAlgorithm::Sha256 => true,
            HkdfAlgorithm::Sha384 => true,
            HkdfAlgorithm::Sha512 => true,
        }
    }
}

/// Salts with `HashLen` bits of zero.
static ZERO_SALT: &[&[u8]; 3] = &[&[0; 32], &[0; 48], &[0; 64]];

/// A usize wrapper that implements `KeyType`
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

struct Prk {
    pseudo_random_key: hkdf::Prk,
}

impl HkdfExpander for Prk {
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<(), Unspecified> {
        self.pseudo_random_key
            .expand(info, Len(len))
            .map_err(|_| Unspecified)?;

        todo!()
    }
}
