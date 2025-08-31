use super::{super::hash::*, AwsLcRs};
use crate::Error;
use alloc::boxed::Box;
use aws_lc_rs::digest;

macro_rules! map {
    ($algorithm:expr) => {
        match $algorithm {
            Algorithm::Sha224 => &digest::SHA224,
            Algorithm::Sha256 => &digest::SHA256,
            Algorithm::Sha384 => &digest::SHA384,
            Algorithm::Sha512 => &digest::SHA512,
            Algorithm::Sha3_256 => &digest::SHA3_256,
            Algorithm::Sha3_384 => &digest::SHA3_384,
            Algorithm::Sha3_512 => &digest::SHA3_512,
        }
    };
}

impl Provider for AwsLcRs {
    fn start(&self, algorithm: Algorithm) -> Result<Box<dyn Context>, Error> {
        Ok(Box::new(HashContext {
            context: digest::Context::new(map!(algorithm)),
        }))
    }

    fn hash(&self, algorithm: Algorithm, data: &[u8]) -> Result<Output, Error> {
        let alg = map!(algorithm);

        Ok(Output {
            buf: digest::digest(alg, data).as_ref().to_vec(),
        })
    }

    fn is_function_supported(&self, algorithm: Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::Sha224
                | Algorithm::Sha256
                | Algorithm::Sha384
                | Algorithm::Sha512
                | Algorithm::Sha3_256
                | Algorithm::Sha3_384
                | Algorithm::Sha3_512
        )
    }
}

/// Incremental hash computing.
struct HashContext {
    context: digest::Context,
}

impl Context for HashContext {
    fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    fn finish(self: Box<Self>) -> Output {
        Output {
            buf: self.context.finish().as_ref().to_vec(),
        }
    }
}
