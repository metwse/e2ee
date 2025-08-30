use super::algorithms::CurveAlgorithm;
use crate::error::Unspecified;
use alloc::boxed::Box;

/// A public key can be used for key agreement or digital signature
/// verification.
pub trait PublicKey {
    /// Used to standartize key agreement material across different
    /// [`CryptoProvider`]s.
    ///
    /// [`CryptoProvider`]: super::CryptoProvider
    fn as_der(&self) -> &[u8];

    /// The algorithm for the public key.
    fn algorithm(&self) -> CurveAlgorithm;
}

/// A private key for key agreement and signing key generation. The signature
/// of [`agree`] allows [`PrivateKey`] to be used for more than one key
/// agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// Converts private key into der.
    fn as_der(&self) -> &[u8];

    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>) -> Result<SharedSecret, Unspecified>;

    /// The algorithm for the private key.
    fn algorithm(&self) -> CurveAlgorithm;
}

/// An ephemeral private key for use (only) with ephemeral key agreement. The
/// signature of [`agree_ephemeral`] allows [`EphemeralPrivateKey`] to be used for only one
/// key agreement.
///
/// [`agree_ephemeral`]: EphemeralPrivateKey::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// DH key agreement with ephemeral key.
    fn agree_ephemeral(
        self,
        peer_public_key: Box<dyn PublicKey>,
    ) -> Result<SharedSecret, Unspecified>;

    /// The algorithm for the ephemeral private key.
    fn algorithm(&self) -> CurveAlgorithm;
}

/// Result of DH key exchange.
pub struct SharedSecret {}
