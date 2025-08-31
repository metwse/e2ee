/// An error with absolutely no details.
///
/// This type used if the spesific reasons for a failure are obvious or are not
/// useful to know, or providing more details about the error is dangereous due
/// to side channel attacks.
#[derive(Debug)]
pub struct Unspecified;
