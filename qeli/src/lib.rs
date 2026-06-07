//! qeli library crate.
//!
//! The modules live here (rather than in `main.rs`) so the realtls core can be
//! built as a `cdylib` for Android/Windows via [`protocol::realtls::ffi`]. The
//! server/client/TUN/web modules are Linux-only; the cross-platform pieces
//! (config, crypto, protocol — including the realtls FFI) build everywhere.

pub mod config;
pub mod crypto;
pub mod protocol;
// Transport-trait scaffolding for the planned TCP/UDP unification (ROADMAP P1#2);
// not yet wired into handler.rs/udp_handler.rs. Linux-only (uses libc socket
// options); the cross-platform realtls FFI doesn't need it.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod transport;

#[cfg(target_os = "linux")]
pub mod client;
#[cfg(target_os = "linux")]
pub mod server;
#[cfg(target_os = "linux")]
pub mod tun;
#[cfg(target_os = "linux")]
pub mod web;
