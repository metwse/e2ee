/// Error reporting.
#[derive(Debug)]
pub enum Error {
    /// An error with absolutely no details.
    ///
    /// This type used usually by `aws-lc-rs`. If the spesific reasons for a
    /// failure are obvious or are not useful to know, or providing more
    /// details about the error is dangereous due to side channel attacks.
    Unspecified,
    /// The key could not marshal to the format.
    UnsupportedEncoding,
    /// The key agreement algorithm is not supported by the provider.
    UnsupportedAgreementAlgorithm,
    /// The digital signature algorithm is not supported by the provider.
    UnsupportedSignatureAlgorithm,
    /// The digest function is not supported by the provider.
    UnsupportedDigestFunction,
    /// The key derivation function is not supported by the provider.
    UnsupportedHkdf,
    /// The elliptic curve is not supported by the provider.
    UnsupportedCurve,
    /// An error parsing or validating a key.
    KeyRejected,
}

#[cfg(feature = "aws_lc_rs")]
impl From<aws_lc_rs::error::Unspecified> for Error {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

#[cfg(feature = "aws_lc_rs")]
impl From<aws_lc_rs::error::KeyRejected> for Error {
    fn from(_: aws_lc_rs::error::KeyRejected) -> Self {
        Self::KeyRejected
    }
}
