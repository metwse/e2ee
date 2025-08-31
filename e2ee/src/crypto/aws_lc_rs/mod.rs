use super::CryptoProvider;

/// A `CryptoProvider` unit type backed by aws-lc-rs.
pub struct AwsLcRs;

mod hkdf;

mod hash;

mod key;

/// A `CryptoProvider` backed by aws-lc-rs.
pub fn default_provider() -> &'static CryptoProvider {
    todo!()
}
