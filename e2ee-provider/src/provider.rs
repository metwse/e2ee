use crate::{digest, hkdf};
use alloc::{boxed::Box, vec::Vec};

/// A provider that maps algorithms to cryptographic handlers.
///
/// Allows querying a cryptographic function by algorithm and exposes the full
/// list of supported algorithms in order of preference.
pub trait Provider<A, T> {
    /// Returns the cryptographic handler for the given algorithm.
    fn get(&self, algorithm: A) -> Option<T>;

    /// Returns all supported algorithms in preference order.
    fn supported_algorithms(&self) -> Vec<A>;

    /// Wheter or not the algorithm is supported.
    fn is_algorithm_supported(&self, algorithm: A) -> bool;
}

/// Provides hash functions required by e2ee.
pub trait HashProvider: Provider<digest::Algorithm, Box<dyn digest::Hash>> {}

/// Provides key derivation functions required by e2ee.
pub trait HkdfProvider: Provider<hkdf::Algorithm, Box<dyn hkdf::Hkdf>> {}
