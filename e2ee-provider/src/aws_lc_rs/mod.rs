/// aws-lc-rs hash implementations.
pub mod digest;

/// aws-lc-rs HMAC-key derivation implementations.
pub mod hkdf;

// /// aws-lc-rs key provider.
// pub mod key;

/// Unit type implementing cryptographic providers required by e2ee.
pub struct AwsLcRs;

use crate::{HashProvider, HkdfProvider};

impl HashProvider for AwsLcRs {}

impl HkdfProvider for AwsLcRs {}
