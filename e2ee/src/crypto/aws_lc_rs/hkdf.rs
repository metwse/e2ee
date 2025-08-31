use super::{super::hkdf::*, AwsLcRs};
use crate::error::Unspecified;
use alloc::boxed::Box;
use aws_lc_rs::hkdf;

impl Provider for AwsLcRs {
    fn extract(
        &self,
        algorithm: Algorithm,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn Expander> {
        let salt = salt.unwrap_or(
            ZERO_SALT[match algorithm {
                Algorithm::Sha256 => 0,
                Algorithm::Sha384 => 1,
                Algorithm::Sha512 => 2,
            }],
        );

        let salt = hkdf::Salt::new(
            match algorithm {
                Algorithm::Sha256 => aws_lc_rs::hkdf::HKDF_SHA256,
                Algorithm::Sha384 => aws_lc_rs::hkdf::HKDF_SHA384,
                Algorithm::Sha512 => aws_lc_rs::hkdf::HKDF_SHA512,
            },
            salt,
        );
        let pseudo_random_key = salt.extract(secret);

        Box::new(Prk { pseudo_random_key })
    }

    fn is_algorithm_supported(&self, algorithm: Algorithm) -> bool {
        match algorithm {
            Algorithm::Sha256 => true,
            Algorithm::Sha384 => true,
            Algorithm::Sha512 => true,
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

impl Expander for Prk {
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<Okm, Unspecified> {
        let okm = self
            .pseudo_random_key
            .expand(info, Len(len))
            .map_err(|_| Unspecified)?;

        let mut buf = alloc::vec![0; len];
        okm.fill(&mut buf).map_err(|_| Unspecified)?;

        Ok(Okm { buf })
    }
}

#[test]
#[cfg(test)]
fn test() -> Result<(), crate::error::Unspecified> {
    let provider = AwsLcRs;

    struct TestCase {
        ikm: &'static str,
        salt: &'static str,
        info: &'static str,
        len: usize,
        output: &'static str,
    }

    let test_cases = [
        TestCase {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            len: 42,
            output: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        TestCase {
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            len: 82,
            output: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        TestCase {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "",
            info: "",
            len: 42,
            output: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ];

    for test_case in test_cases {
        let expander = provider.extract(
            Algorithm::Sha256,
            Some(&hex::decode(test_case.salt).unwrap()),
            &hex::decode(test_case.ikm).unwrap(),
        );

        let okm = expander.expand(&[&hex::decode(test_case.info).unwrap()], test_case.len)?;

        assert_eq!(okm.buf, hex::decode(test_case.output).unwrap());
    }

    Ok(())
}
