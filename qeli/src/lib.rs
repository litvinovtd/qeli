//! qeli library crate.
//!
//! The modules live here (rather than in `main.rs`) so the realtls core can be
//! built as a `cdylib` for Android/Windows via [`protocol::realtls::ffi`]. The
//! server/client/TUN/web modules are Linux-only; the cross-platform pieces
//! (config, crypto, protocol — including the realtls FFI) build everywhere.

pub mod config;
pub mod crypto;
pub mod protocol;
// Cross-platform whole-client lifecycle and platform-plan boundary. The current Linux
// client is migrated onto this incrementally; keeping the module platform-neutral lets
// every GUI client consume the same state machine through its optional C ABI.
pub mod transport_core;
// Cross-platform helpers (atomic file writes etc.); builds everywhere, including
// the realtls FFI cdylib for Android/Windows/macOS.
pub mod util;
// Linux daemon socket-option helpers and transport constants. The cross-platform client
// carrier itself lives in `transport_core`; these helpers remain for the Linux server/CLI
// path. `ring`-free, so they cross-compile to mipsel/aarch64.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod transport;

// Lifecycle hooks (post_up/post_down) + the file-trust guard; used by both the
// client and the server, Linux-only.
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub mod hooks;

// Opt-in packet timeline (`QELI_TRACE`). Gated like `hooks`: it instruments the
// client/server data planes and pulls in tokio's signal handling, neither of which
// belongs in the realtls cdylib.
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub mod trace;

// `client`/`tun` build under feature = "client"; `server`/`web` under
// feature = "server". Default features enable both, so a normal build is
// unchanged. A router (Keenetic) build uses `--no-default-features --features
// client-bin` to drop the server/web stack (and its MIPS-incompatible `ring`).
#[cfg(any(
    all(target_os = "linux", feature = "client"),
    all(
        any(
            target_os = "android",
            target_os = "windows",
            target_os = "macos",
            target_os = "ios"
        ),
        feature = "transport-core-ffi"
    )
))]
pub mod client;
#[cfg(all(target_os = "linux", feature = "server"))]
pub mod server;
#[cfg(all(target_os = "linux", feature = "client"))]
pub mod tun;
#[cfg(all(target_os = "linux", feature = "server"))]
pub mod web;
