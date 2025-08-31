/// Error reporting.
#[derive(Debug)]
pub enum Error {
    /// An error with absolutely no details.
    ///
    /// This type used if the spesific reasons for a failure are obvious or are not
    /// useful to know, or providing more details about the error is dangereous due
    /// to side channel attacks.
    Unspecified,
    /// The algorithm is not supported by the provider.
    UnsupportedAlgorithm,
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
