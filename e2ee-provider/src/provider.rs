use crate::{digest, hkdf};

/// A provider that maps algorithms to their corresponding cryptographic
/// handlers.
///
/// Enables querying cryptographic functions by algorithm and exposes the full
/// list of supported algorithms in order of preference.
pub trait Provider<A, T> {
    /// Returns the cryptographic handler for the specified algorithm.
    fn get(&self, algorithm: A) -> Option<T>;

    /// Returns all supported algorithms.
    fn supported_algorithms(&self) -> &'static [A];

    /// Wheter the given algorithm is supported.
    fn is_algorithm_supported(&self, algorithm: A) -> bool;
}

/// Provides hash functions required by e2ee.
pub trait HashProvider: Provider<digest::Algorithm, &'static dyn digest::Hash> {}

/// Provides key derivation functions required by e2ee.
pub trait HkdfProvider: Provider<hkdf::Algorithm, &'static dyn hkdf::Hkdf> {}
