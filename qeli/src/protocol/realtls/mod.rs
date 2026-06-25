//! `realtls` — a hand-rolled, byte-grade browser TLS 1.3 stack for true REALITY
//! (Ось 1, см. `docs/DESIGN-remaining.md`). Unlike `protocol::tls` (fake-TLS: a
//! browser-*ish* ClientHello followed by the qeli protocol), `realtls` emits a
//! Chrome-exact ClientHello and (M2.2+) carries the tunnel inside a genuine
//! TLS 1.3 session.
//!
//! Milestones:
//! - **M2.1** `clienthello` — Chrome-grade ClientHello + JA4 (this file's submodule).
//! - M2.2 `keyschedule`/`record` — HKDF key schedule + AEAD record layer.
//! - M2.3 `client` — client handshake state machine.
//!
//! The REALITY authenticator is unchanged from M1: the 32-byte token from
//! [`crate::crypto::reality::seal_session_id`] is placed in the TLS
//! `legacy_session_id`, and the ephemeral X25519 public key is the `key_share`.

pub mod client;
pub mod clienthello;
pub mod ffi;
#[cfg(target_os = "android")]
pub mod jni;
pub mod keyschedule;
pub mod record;
pub mod registry;
pub mod sansio;
// Server-side TLS 1.3 termination — the only `rustls`/`ring` user in realtls.
// Gated so the client-only router build (no `server` feature) excludes `ring`
// (no MIPS backend). Client submodules above are hand-rolled and stay portable.
// (Tests in ffi/sansio/stream reference this; they run with default features.)
#[cfg(feature = "server")]
pub mod server;
pub mod stream;
