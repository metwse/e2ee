use super::CryptoProvider;

/// A `CryptoProvider` backed by aws-lc-rs.
pub struct AwsLcRs;

mod hkdf;

/// A `CryptoProvider` backed by aws-lc-rs.
pub fn default_provider() -> &'static CryptoProvider {
    todo!()
}
