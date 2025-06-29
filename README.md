# e2ee
Embryonic Rust library.

`e2ee` is a transport-agnostic, end-to-end encryption framework written.
It provides building blocks for establishing secure, authenticated
communication between peers — independent of the underlying network
layer (TCP, UDP, etc.).

## Goals
- Cryptographic peer abstraction
- Secure handshake with identity/authentication
- Replay and reorder protection (optional)
- Customizable key agreement & encryption suites
- Serializable sessions (store & resume later)
- Forward secrecy & rekeying
- Minimal dependencies, zero unsafe
