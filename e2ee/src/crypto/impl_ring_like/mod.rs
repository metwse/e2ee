use alloc::vec::Vec;


/// SHA256 secure-hashing algorithm.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Vec::from(ring_like::digest::digest(&ring_like::digest::SHA256, data).as_ref())
}

#[test]
fn test_sha256() {
    assert_eq!(
        sha256(&[65, 66, 67]),
        b"\xb5\xd4\x04\x5c\x3f\x46\x6f\xa9\x1f\xe2\xcc\x6a\xbe\x79\x23\x2a\x1a\x57\xcd\xf1\x04\xf7\xa2\x6e\x71\x6e\x0a\x1e\x27\x89\xdf\x78"
    );
}
