use alloc::{boxed::Box, vec::Vec};
use zeroize::Zeroize;

use crate::{Error, ec::Curve};

/// A private key for key agreement and signing key generation. The signature
/// of [`agree`] allows [`PrivateKey`] to be used for more than one key agreement.
///
/// [`agree`]: PrivateKey::agree
pub trait PrivateKey {
    /// DH key agreement.
    fn agree(&self, peer_public_key: Box<dyn PublicKey>, kdf: i32) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Signs `message` using the selected digest function.
    fn sign(&self, message: &[u8], digest: i32) -> Result<Vec<u8>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A private key only for key agreement. The signature of [`agree_ephemeral`]
/// allows [`EphemeralPrivateKey`] to be used for more than one key agreement.
///
/// [`agree_ephemeral`]: EphemeralPrivateKey::agree_ephemeral
pub trait EphemeralPrivateKey {
    /// DH key agreement.
    fn agree_ephemeral(
        self: Box<Self>,
        peer_public_key: Box<dyn PublicKey>,
        kdf: i32,
    ) -> Result<SharedSecret, Error>;

    /// Computes public key of the ephemeral key.
    fn compute_public_key(&self) -> Result<Box<dyn PublicKey>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// A public key can be used for key agreement or digital signature
/// verification.
pub trait PublicKey {
    /// Verify the `signature` signature of `message`.
    fn sign(&self, message: &[u8], digest: i32) -> Result<Vec<u8>, Error>;

    /// Kind of the private key we have.
    fn algorithm(&self) -> Curve;
}

/// Result of a key agreement.
pub struct SharedSecret {
    pub(crate) buf: Vec<u8>,
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}
