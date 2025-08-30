use super::{
    algorithms::{CurveAlgorithm, HkdfAlgorithm},
    keys::{EphemeralPrivateKey, PrivateKey, PublicKey},
};
use crate::error::Unspecified;
use alloc::boxed::Box;

/// Mechanism for loading/generating keys.
pub trait KeyProvider: Send + Sync {
    /// Loads private key from binary.
    fn load_private_key(&self, key_der: &[u8]) -> Box<dyn PrivateKey>;

    /// Loads public key from binary.
    fn load_public_key(&self, key_der: &[u8]) -> Box<dyn PublicKey>;

    /// Generates an ephemeral private key.
    fn generate_ephemeral_private_key(&self) -> Box<dyn EphemeralPrivateKey>;

    /// Whether or not the curve algorithm is supported.
    fn is_curve_supported(&self, algorithm: CurveAlgorithm) -> bool;
}

/// `HKDF` implementation required by e2ee.
///
/// See [RFC 5869](https://www.ietf.org/rfc/rfc5869.txt) for the terminology
/// used in this definition.
pub trait HkdfProvider: Send + Sync {
    /// `HKDF-Extract(salt, secret)`
    ///
    /// A `salt` of `None` should be treated as a sequence of `HashLen` zero
    /// bytes.
    fn extract(
        &self,
        algorithm: HkdfAlgorithm,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn HkdfExpander>;

    /// Whether or not the HKDF algorithm is supported.
    fn is_supported(&self, algorithm: HkdfAlgorithm) -> bool;
}

/// Implementation of `HKDF-Expand` with an implicitly stored and immutable
/// `PRK`.
pub trait HkdfExpander: Send + Sync {
    /// `HKDF-Expand(PRK, info, L)` into a slice.
    ///
    /// Where `L` is `output.len()`
    ///
    /// Returns Err("output length error") if `L` is larger than `255*HashLen`.
    fn expand(&self, info: &[&[u8]], len: usize) -> Result<(), Unspecified>;
}
