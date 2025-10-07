use crate::{
    Error,
    aws_lc_rs::{AwsLcRs, ec::ed25519::Ed25519VerifyingKey},
    ec::{
        KeyProvider, agreement,
        encoding::{PrivateKeyBin, PrivateKeyDer, PublicKeyBin, PublicKeyDer},
        signature,
    },
};
use alloc::boxed::Box;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, ED25519, VerificationAlgorithm,
};

use super::{
    ecdsa::{EcdsaSigningKey, EcdsaVerifyingKey},
    ed25519::Ed25519SigningKey,
};

impl KeyProvider for AwsLcRs {
    fn load_private_key_der(
        _algorithm: agreement::Algorithm,
        _der: &PrivateKeyDer,
    ) -> Result<Box<dyn agreement::PrivateKey>, Error> {
        todo!()
    }

    fn load_private_key_bin(
        _algorithm: agreement::Algorithm,
        _bin: &PrivateKeyBin,
    ) -> Result<Box<dyn agreement::PrivateKey>, Error> {
        todo!()
    }

    fn load_public_key_der(
        _algorithm: agreement::Algorithm,
        _der: &PublicKeyDer,
    ) -> Result<Box<dyn agreement::PublicKey>, Error> {
        todo!()
    }

    fn load_public_key_bin(
        _algorithm: agreement::Algorithm,
        _bin: &PublicKeyBin,
    ) -> Result<Box<dyn agreement::PublicKey>, Error> {
        todo!()
    }

    fn generate_ephemeral_private_key(
        _algorithm: agreement::Algorithm,
    ) -> Result<Box<dyn agreement::EphemeralPrivateKey>, Error> {
        todo!()
    }

    fn load_signing_key_der(
        algorithm: signature::Algorithm,
        der: &PrivateKeyDer,
    ) -> Result<Box<dyn signature::SigningKey>, Error> {
        match algorithm {
            signature::Algorithm::Ed448 => return Err(Error::UnsupportedSignatureAlgorithm),
            signature::Algorithm::Ed25519 => {
                return Ok(Box::new(Ed25519SigningKey {
                    key: match der {
                        PrivateKeyDer::Pkcs8V1Key(key) => {
                            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(key)?
                        }
                        _ => return Err(Error::UnsupportedEncoding),
                    },
                }));
            }
            _ => {}
        };

        let aws_lc_rs_alg = match algorithm {
            signature::Algorithm::EcdsaP256Sha256Asn1 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            signature::Algorithm::EcdsaP256Sha256Fixed => &ECDSA_P256_SHA256_FIXED_SIGNING,
            signature::Algorithm::EcdsaP384Sha384Asn1 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            signature::Algorithm::EcdsaP384Sha384Fixed => &ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => unreachable!(),
        };

        Ok(Box::new(EcdsaSigningKey {
            key: match der {
                PrivateKeyDer::Pkcs8V1Key(key) => {
                    aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(aws_lc_rs_alg, key)?
                }
                PrivateKeyDer::EcPrivateKey(key) => {
                    aws_lc_rs::signature::EcdsaKeyPair::from_private_key_der(aws_lc_rs_alg, key)?
                }
                _ => return Err(Error::UnsupportedEncoding),
            },
            algorithm,
        }))
    }

    fn load_signing_key_bin(
        algorithm: signature::Algorithm,
        bin: &PrivateKeyBin,
    ) -> Result<Box<dyn signature::SigningKey>, Error> {
        match algorithm {
            signature::Algorithm::Ed448 => return Err(Error::UnsupportedSignatureAlgorithm),
            signature::Algorithm::Ed25519 => {
                return Ok(Box::new(Ed25519SigningKey {
                    key: match bin {
                        PrivateKeyBin::EdEcSeed(seed) => {
                            aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(seed)?
                        }
                        _ => return Err(Error::UnsupportedEncoding),
                    },
                }));
            }
            _ => {}
        };

        let _be_bytes = match bin {
            PrivateKeyBin::Ec(be_bytes) => be_bytes,
            _ => return Err(Error::UnsupportedEncoding),
        };

        todo!("implement loading signing keys from big-endian bytes")
    }

    fn load_verifying_key_der(
        algorithm: signature::Algorithm,
        der: &PublicKeyDer,
    ) -> Result<Box<dyn signature::VerifyingKey>, Error> {
        let der = match der {
            PublicKeyDer::X509Key(der) | PublicKeyDer::EcPublicKey(der) => der,
        };

        load_verifying_key(algorithm, der)
    }

    fn load_verifying_key_bin(
        algorithm: signature::Algorithm,
        bin: &PublicKeyBin,
    ) -> Result<Box<dyn signature::VerifyingKey>, Error> {
        let bytes = match bin {
            PublicKeyBin::Compressed(bytes) | PublicKeyBin::Uncompreessed(bytes) => bytes,
        };

        load_verifying_key(algorithm, bytes)
    }
}

fn load_verifying_key(
    algorithm: signature::Algorithm,
    bytes: &[u8],
) -> Result<Box<dyn signature::VerifyingKey>, Error> {
    if matches!(algorithm, signature::Algorithm::Ed448) {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }

    let aws_lc_rs_alg: &dyn VerificationAlgorithm = match algorithm {
        signature::Algorithm::Ed448 => unreachable!(),
        signature::Algorithm::Ed25519 => &ED25519,
        signature::Algorithm::EcdsaP256Sha256Asn1 => &ECDSA_P256_SHA256_ASN1,
        signature::Algorithm::EcdsaP256Sha256Fixed => &ECDSA_P256_SHA256_FIXED,
        signature::Algorithm::EcdsaP384Sha384Asn1 => &ECDSA_P384_SHA384_ASN1,
        signature::Algorithm::EcdsaP384Sha384Fixed => &ECDSA_P384_SHA384_FIXED,
    };

    let public_key = aws_lc_rs::signature::ParsedPublicKey::new(aws_lc_rs_alg, bytes)?;

    if matches!(algorithm, signature::Algorithm::Ed25519) {
        Ok(Box::new(Ed25519VerifyingKey { key: public_key }))
    } else {
        Ok(Box::new(EcdsaVerifyingKey {
            key: public_key,
            algorithm,
        }))
    }
}
