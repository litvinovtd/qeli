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
#[cfg(all(target_os = "linux", any(feature = "server", feature = "client")))]
pub mod logging;
pub mod util;

// Resolver wire/cache/upstream code has no Linux dependencies. Compile it in host tests
// too; GUI native release libraries keep it excluded and Linux owns the socket lifecycle.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/dns/resolver.rs"]
mod dns_resolver;

// Preflight parsing and fail-open policy are portable; Linux retains the server entry point.
#[cfg(all(test, not(all(target_os = "linux", feature = "server"))))]
#[allow(dead_code)] // Host tests inject observations rather than invoking the host's `ip`.
#[path = "server/preflight.rs"]
mod server_preflight;

// Gateway rollback is tested against isolated firewall and sysctl models.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)] // Host tests inject probe results instead of invoking the host's ip.
#[path = "client/gateway.rs"]
mod client_gateway;

// Run route transaction fault injection on the host without invoking host networking.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)]
#[path = "client/route.rs"]
mod client_route;

// Exercise the real firewall command boundary with isolated child processes on the host.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)]
#[path = "client/killswitch.rs"]
mod client_killswitch;

// Exercise the same client reservation coordinator with an isolated host backend.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)]
#[path = "client/network_lease.rs"]
mod client_network_lease;

// Joined network transaction ownership is exercised without host mutations.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[path = "client/network_task.rs"]
mod client_network_task;

// Identity-file parsers have portable bounded-reader regressions.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)]
#[path = "client/identity_files.rs"]
mod client_identity_files;

// TOFU request ownership is portable; host tests use injected verification.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[path = "client/identity_worker.rs"]
mod client_identity_worker;

// Diagnostics queue ownership is portable; tests do not mutate host networking.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[path = "client/status_writer.rs"]
mod client_status_writer;

// TUN admission tests replace interface queries and waiting; no real device operations.
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
#[allow(dead_code)]
#[path = "client/tun_recovery.rs"]
mod client_tun_recovery;

// Linux ioctl opening policy can be tested without loading a platform TUN backend.
#[cfg(all(
    test,
    not(all(target_os = "linux", any(feature = "client", feature = "server")))
))]
#[path = "tun/open.rs"]
mod tun_open;

// A live fd pins the namespace shared by route and standalone firewall owners.
#[cfg(all(target_os = "linux", any(test, feature = "client", feature = "server")))]
mod network_namespace;

// Link identity queried in the calling network namespace, shared by client/server.
#[cfg(all(target_os = "linux", any(test, feature = "client", feature = "server")))]
mod network_interface;

// One default-route parser for client exit and managed server uplink selection.
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
mod network_default_route;

// Shared interpretation of firewall rule/chain checks; no platform commands in this module.
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
mod firewall_check;

// Firewall cleanup algorithms are tested with command results, without host mutations.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/nat/cleanup.rs"]
mod nat_cleanup;

// Retain exact generic NAT/routing rules across failed cleanup attempts.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/nat/owned_rules.rs"]
mod nat_owned_rules;

#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[cfg_attr(test, allow(dead_code))]
#[path = "server/nat/firewall_journal.rs"]
mod nat_firewall_journal;

// IPv6 sysctl rollback keeps partial acquisitions visible until release succeeds.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/nat/ipv6_sysctl.rs"]
mod nat_ipv6_sysctl;

// Exact DNS firewall ownership survives failed cleanup within the running worker.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/nat/dns_input.rs"]
mod nat_dns_input;

// Process-only shutdown budget, independent of the async executor.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/shutdown_budget.rs"]
mod server_shutdown_budget;

// Share final worker error/exit policy with portable host regression tests.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/shutdown.rs"]
mod server_shutdown;

#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/teardown.rs"]
mod profile_teardown;

// Profile ownership is platform-neutral and exercised without privileged network setup.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/tasks.rs"]
mod profile_tasks;

// Delivery admission/lifetime is tested without making external HTTP requests.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/notify_tasks.rs"]
mod notify_tasks;

#[cfg(all(test, feature = "server", not(target_os = "linux")))]
#[allow(dead_code)] // Host tests exercise helpers; server entry points run only on Linux.
#[path = "server/notify.rs"]
mod server_notify;

// A blocking config transaction retains its lock even when its async caller is cancelled.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/config_transaction.rs"]
mod config_transaction;

// Control protocol bounds are shared by the Unix server and its CLI client.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/control_io.rs"]
mod control_io;

// Process ownership/retry logic is tested with isolated child processes on the host.
#[cfg(any(test, all(target_os = "linux", feature = "server")))]
#[path = "server/supervisor.rs"]
mod server_supervisor;

#[cfg(test)]
#[path = "server/dns/test_support.rs"]
mod dns_test_support;

// Compile the actual listeners in host tests too; Linux already includes them via server.
#[cfg(all(test, not(all(target_os = "linux", feature = "server"))))]
#[path = "server/dns.rs"]
mod dns_listeners;

// Accounting uses portable counters and atomic file writes; exercise it on the host too.
#[cfg(all(test, not(all(target_os = "linux", feature = "server"))))]
#[path = "server/usage.rs"]
mod server_usage;

#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod state_storage;

// One cross-process ownership journal for every Linux component that changes host-wide
// forwarding sysctls. The full daemon can run server profiles and panel-managed outbound
// clients at the same time, so separate server/client snapshots would race on teardown.
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[path = "client/sysctl.rs"]
pub(crate) mod sysctl;

// Linux daemon socket-option helpers and transport constants. The cross-platform client
// carrier itself lives in `transport_core`; these helpers remain for the Linux server/CLI
// path. `ring`-free, so they cross-compile to mipsel/aarch64.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod transport;

// Exercise bounded hook process I/O with real host child fixtures. Linux clients and
// servers use this same runner; native GUI release libraries do not include it.
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
#[path = "hooks/process.rs"]
mod hook_process;

// Synchronous Linux network setup/rollback commands share the owned process runner.
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
mod system_command;

#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
#[cfg_attr(not(any(test, feature = "client")), allow(dead_code))]
mod operation_budget;

// Headless credential I/O, shutdown ordering and cleanup policy have portable host tests.
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod client_cleanup;
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod client_tasks;
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod credential_file;
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod dns_lease;
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod dns_legacy;
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
mod secret_buffer;

// The notification INI loader uses the same bounded snapshot on every platform.
// Linux additionally binds command authorization to that exact descriptor.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod config_source;

// Lifecycle hooks (post_up/post_down); used by both the client and server, Linux-only.
// Command trust is supplied by config_source above.
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub mod hooks;

// Opt-in packet timeline (`QELI_TRACE`). Gated like `hooks`: it instruments the
// client/server data planes and pulls in tokio's signal handling, neither of which
// belongs in the realtls cdylib.
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub mod trace;

// `client` builds under feature = "client"; `server`/`web` under feature = "server".
// Linux TUN is shared by either feature. Default features enable both, so a normal build is
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
// `tun::tap` contains the platform-neutral Ethernet framing helpers consumed by the
// fd-backed Android/macOS core. The actual TUN device implementation remains Linux-only
// inside `tun::iface`.
#[cfg(any(
    all(target_os = "linux", any(feature = "client", feature = "server")),
    all(
        any(target_os = "android", target_os = "macos"),
        feature = "transport-core-ffi"
    )
))]
pub mod tun;
#[cfg(all(target_os = "linux", feature = "server"))]
pub mod web;
