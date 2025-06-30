use crate::tunnel::Tunnel;

/// Represents a local cryptographic peer for establishing secure tunnels.
pub struct Peer {}

/// Public configuration of a remote peer used during handshake.
pub struct PeerConfig {}

/// Key bundle used for `3xdh` (Triple Diffie-Hellman) key agreement.
pub struct PeerPreKeyBundle {}

/// Signed ephemeral key along with its certificate chain.
pub struct PeerCertificateChain {}

impl Peer {
    /// Performs a handshake using the `3xdh` key agreement protocol.
    pub fn handshake_3xdh(_key_bundle: PeerPreKeyBundle) -> Tunnel {
        todo!()
    }

    /// Performs a handshake using a certificate authority–based trust model.
    pub fn handshake_ca(_peer_key_chain: PeerCertificateChain) -> Tunnel {
        todo!()
    }
}
