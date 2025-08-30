/// Available key agreement algorithms.
#[non_exhaustive]
pub enum CurveAlgorithm {
    /// ECDH using the NSA Suite B P-256 (secp256r1) curve.
    EcdhP256,
    /// ECDH using the NSA Suite B P-384 (secp384r1) curve.
    EcdhP384,
    /// ECDH using the NSA Suite B P-521 (secp521r1) curve.
    EcdhP521,
    /// X25519 (ECDH using Curve25519) as described in RFC 7748.
    X25519,
}

/// Available HKDF algorithms.
#[non_exhaustive]
pub enum HkdfAlgorithm {
    /// HKDF using HMAC-SHA-256.
    Sha256,
    /// HKDF using HMAC-SHA-384.
    Sha384,
    /// HKDF using HMAC-SHA-512.
    Sha512,
}
