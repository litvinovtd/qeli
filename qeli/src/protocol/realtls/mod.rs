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
// The FFI hands `registry` handles to the caller as pointers, so its packed u64 only
// round-trips where a pointer is 64 bits wide (see registry.rs). Compile it only there.
// The GUI clients that consume the cdylib — Windows, macOS, Android arm64/x86_64, iOS —
// are all 64-bit, so they are unaffected; the 32-bit ROUTER builds (mipsel Keenetic,
// armv7 OpenWrt) never call the FFI at all and previously only compiled it by accident.
// Without this gate the guard inside registry.rs fails those builds outright, which is
// how mipsel/armv7 stopped building in 0.7.12 despite shipping in every release before.
#[cfg(target_pointer_width = "64")]
pub mod ffi;
#[cfg(all(target_os = "android", target_pointer_width = "64"))]
pub mod jni;
pub mod keyschedule;
pub mod record;
#[cfg(target_pointer_width = "64")]
pub mod registry;
pub mod sansio;
// Server-side TLS 1.3 termination — the only `rustls`/`ring` user in realtls.
// Gated so the client-only router build (no `server` feature) excludes `ring`
// (no MIPS backend). Client submodules above are hand-rolled and stay portable.
// (Tests in ffi/sansio/stream reference this; they run with default features.)
#[cfg(feature = "server")]
pub mod server;
pub mod stream;
