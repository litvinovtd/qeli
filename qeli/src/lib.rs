//! qeli library crate.
//!
//! The modules live here (rather than in `main.rs`) so the realtls core can be
//! built as a `cdylib` for Android/Windows via [`protocol::realtls::ffi`]. The
//! server/client/TUN/web modules are Linux-only; the cross-platform pieces
//! (config, crypto, protocol — including the realtls FFI) build everywhere.

pub mod config;
pub mod crypto;
pub mod protocol;
// Cross-platform helpers (atomic file writes etc.); builds everywhere, including
// the realtls FFI cdylib for Android/Windows/macOS.
pub mod util;
// Transport-trait scaffolding for the planned TCP/UDP unification (ROADMAP P1#2);
// not yet fully wired, but the client already uses `transport::tcp::set_tcp_keepalive`,
// so it builds in both the client-only and the full daemon builds. `ring`-free, so
// it cross-compiles to mipsel/aarch64.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod transport;

// `client`/`tun` build under feature = "client"; `server`/`web` under
// feature = "server". Default features enable both, so a normal build is
// unchanged. A router (Keenetic) build uses `--no-default-features --features
// client-bin` to drop the server/web stack (and its MIPS-incompatible `ring`).
#[cfg(all(target_os = "linux", feature = "client"))]
pub mod client;
#[cfg(all(target_os = "linux", feature = "server"))]
pub mod server;
#[cfg(all(target_os = "linux", feature = "client"))]
pub mod tun;
#[cfg(all(target_os = "linux", feature = "server"))]
pub mod web;
