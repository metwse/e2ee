use super::AwsLcRs;
use crate::{
    digest::{Algorithm, Context, Hash, Output},
    provider::Provider,
};
use alloc::boxed::Box;
use aws_lc_rs::digest::{
    self, SHA224_OUTPUT_LEN, SHA256_OUTPUT_LEN, SHA384_OUTPUT_LEN, SHA512_OUTPUT_LEN,
};

static SHA3_256_OUTPUT_LEN: usize = SHA256_OUTPUT_LEN;
static SHA3_384_OUTPUT_LEN: usize = SHA384_OUTPUT_LEN;
static SHA3_512_OUTPUT_LEN: usize = SHA512_OUTPUT_LEN;

impl Provider<Algorithm, &'static dyn Hash> for AwsLcRs {
    fn get(&self, algorithm: Algorithm) -> Option<&'static dyn Hash> {
        match algorithm {
            Algorithm::Sha224 => Some(&Sha224Digest),
            Algorithm::Sha256 => Some(&Sha256Digest),
            Algorithm::Sha384 => Some(&Sha384Digest),
            Algorithm::Sha512 => Some(&Sha512Digest),
            Algorithm::Sha3_224 => None,
            Algorithm::Sha3_256 => Some(&Sha3_256Digest),
            Algorithm::Sha3_384 => Some(&Sha3_384Digest),
            Algorithm::Sha3_512 => Some(&Sha3_512Digest),
        }
    }

    fn supported_algorithms(&self) -> &'static [Algorithm] {
        &[
            Algorithm::Sha224,
            Algorithm::Sha256,
            Algorithm::Sha384,
            Algorithm::Sha512,
            Algorithm::Sha3_256,
            Algorithm::Sha3_384,
            Algorithm::Sha3_512,
        ]
    }

    fn is_algorithm_supported(&self, algorithm: Algorithm) -> bool {
        self.get(algorithm).is_some()
    }
}

macro_rules! impl_hash_functions {
    ($($alg:ident),*) => {
        $(
            paste::paste! {
                #[doc = "Hash digest using " $alg "."]
                pub struct [<$alg Digest>];

                #[doc = "Incremental " $alg " hash computation."]
                struct [<$alg Context>] {
                    ctx: digest::Context
                }

                impl Hash for [<$alg Digest>] {
                    fn hash(&self, data: &[u8]) -> Output {
                        Output {
                            buf: digest::digest(&digest::[<$alg:upper>], data)
                                .as_ref().into(),
                        }
                    }

                    fn start(&self) -> Box<dyn Context> {
                        Box::new([<$alg Context>] {
                            ctx: digest::Context::new(&digest::[<$alg:upper>])
                        })
                    }

                    fn output_len(&self) -> usize {
                        [<$alg:upper _OUTPUT_LEN>]
                    }

                    fn algorithm(&self) -> Algorithm {
                        Algorithm::$alg
                    }
                }

                impl Context for [<$alg Context>] {
                    fn update(&mut self, data: &[u8]) {
                        self.ctx.update(data);
                    }

                    fn finish(self: Box<Self>) -> Output {
                        Output {
                            buf: self.ctx.finish().as_ref().into()
                        }
                    }

                    fn algorithm(&self) -> Algorithm {
                        Algorithm::$alg
                    }
                }
            }
        )*
    };
}

impl_hash_functions!(Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512);
