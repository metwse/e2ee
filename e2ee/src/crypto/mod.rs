/// `ring` based CryptoProvider.
#[cfg(feature = "ring")]
pub mod ring {
    use ring as ring_like;
    include!("impl_ring_like/impl.rs");
}

/// `aws-lc-rs` based CryptoProvider.
#[cfg(feature = "aws_lc_rs")]
pub mod aws_lc_rs {
    use aws_lc_rs as ring_like;
    include!("impl_ring_like/impl.rs");
}
