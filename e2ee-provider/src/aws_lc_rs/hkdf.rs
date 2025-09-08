use super::AwsLcRs;
use crate::{
    Error,
    hkdf::{Algorithm, Expander, Hkdf, Okm},
    provider::Provider,
};
use alloc::boxed::Box;
use aws_lc_rs::hkdf;

impl Provider<Algorithm, &'static dyn Hkdf> for AwsLcRs {
    fn get(&self, algorithm: Algorithm) -> Option<&'static dyn Hkdf> {
        match algorithm {
            Algorithm::Sha256 => Some(&HkdfSha256),
            Algorithm::Sha384 => Some(&HkdfSha384),
            Algorithm::Sha512 => Some(&HkdfSha512),
        }
    }

    fn supported_algorithms(&self) -> &'static [Algorithm] {
        &[Algorithm::Sha256, Algorithm::Sha384, Algorithm::Sha512]
    }

    fn is_algorithm_supported(&self, _algorithm: Algorithm) -> bool {
        true
    }
}

/// usize wrapper for aws-lc-rs's [`hkdf::KeyType`]
struct Keylen(usize);

impl hkdf::KeyType for Keylen {
    fn len(&self) -> usize {
        self.0
    }
}

macro_rules! impl_hkdf_functions {
    ($($alg:ident),*) => {
        $(paste::paste! {
            #[doc = "HMAC-key derivation using " $alg "."]
            pub struct [<Hkdf $alg>];

            #[doc = "HKDF " $alg " expander."]
            struct [<Hkdf $alg Expander>] {
                prk: hkdf::Prk
            }

            impl Hkdf for [<Hkdf $alg>] {
                fn extract(&self, salt: &[u8], secret: &[u8]) -> Box<dyn Expander> {
                    Box::new([<Hkdf $alg Expander>] {
                        prk: hkdf::Salt::new(hkdf::[<HKDF_ $alg:upper>], salt).extract(secret)
                    })
                }
            }

            impl Expander for [<Hkdf $alg Expander>] {
                fn expand(&self, info: &[&[u8]], len: usize) -> Result<Okm, Error> {
                    let mut okm = Okm { buf: alloc::vec![0; len] };

                    self.prk.expand(info, Keylen(len))?.fill(&mut okm.buf)?;

                    Ok(okm)
                }
            }
        })*
    };
}

impl_hkdf_functions!(Sha256, Sha384, Sha512);
