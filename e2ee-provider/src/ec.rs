use crate::Error;

/// Available elliptic curves.
pub enum Curve {
    /// NSA Suite B P-256 curve
    /// Also known as: prime256v1, secp256r1, prime256v1
    P256 = 415,
    /// NSA Suite B P-384 curve
    /// Also known as: secp384r1, ansip384r1
    P384 = 715,
    /// NSA Suite B P-521 curve
    /// Also known as: secp521r1, ansip521r1
    P521 = 716,
    /// curve25519 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve25519 = 1034,
    /// curve448 as described by
    /// [RFC7748](https://datatracker.ietf.org/doc/html/rfc7748).
    Curve448 = 1035,
}

impl TryFrom<u32> for Curve {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            415 => Ok(Curve::P256),
            715 => Ok(Curve::P384),
            716 => Ok(Curve::P521),
            1034 | 1087 => Ok(Curve::Curve25519),
            1035 | 1088 => Ok(Curve::Curve448),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}
