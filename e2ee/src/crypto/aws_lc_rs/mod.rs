use super::CryptoProvider;

/// A `CryptoProvider` unit type backed by aws-lc-rs.
pub struct AwsLcRs;

mod hkdf;

mod hash;

mod key;

static PROVIDER: AwsLcRs = AwsLcRs;

/// A `CryptoProvider` backed by aws-lc-rs.
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        hkdf: &PROVIDER,
        hash: &PROVIDER,
        key: &PROVIDER,
    }
}
