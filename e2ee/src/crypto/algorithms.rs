use super::keys::*;
use crate::error::Unspecified;
use alloc::boxed::Box;

/// `DH` implementation for key derivation.
pub trait KeyExchangeAlgorithm: Send + Sync {
    /// Returns shared secret output from an Diffie-Hellman key exchange
    /// function involving the key pairs.
    fn agree(
        &self,
        my_private_key: Box<dyn PrivateKey>,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, &'static str>;

    /// DH key exchange using ephemeral private key.
    fn agree_ephemeral(
        &self,
        my_private_key: Box<dyn EphemeralPrivateKey>,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, &'static str>;
}

/// `HKDF` implementation required by e2ee.
///
/// See [RFC 5869](https://www.ietf.org/rfc/rfc5869.txt) for the terminology
/// used in this definition.
pub trait Hkdf: Send + Sync {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero
    /// bytes.
    fn extract(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander>;
}

/// Implementation of `HKDF-Expand` with an implicitly stored and immutable
/// `PRK`.
pub trait HkdfExpander: Send + Sync {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where `L` is `output.len()`
    ///
    /// Returns Err("output length error") if `L` is larger than `255*HashLen`.
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), Unspecified>;
}
