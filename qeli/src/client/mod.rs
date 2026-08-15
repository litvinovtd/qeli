#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod killswitch;
#[cfg(target_os = "linux")]
pub mod route;

use crate::crypto::{
    derive_keys, derive_keys_bound, derive_keys_hybrid, derive_keys_hybrid_bound,
    handshake_transcript_hash, Keypair,
};
use crate::protocol::{
    generate_connection_id, pick_random_sni, read_record, read_record_into, read_tls_record,
    unwrap_quic, unwrap_quic_payload, wrap_quic_long, wrap_quic_short, wrap_quic_short_into,
    FakeTlsHandshake, Framing, Obfuscator, PacketCodec,
};
#[cfg(target_os = "linux")]
use crate::trace;
#[cfg(not(target_os = "linux"))]
mod trace {
    pub(crate) enum Dir {
        Tx,
        Rx,
    }

    #[inline]
    pub(crate) fn record(_direction: Dir, _label: &str, _bytes: usize, _stream: u8) {}
}
use crate::transport_core::buffer_pool::PooledBuffer;
#[cfg(target_os = "linux")]
use crate::transport_core::linux_tun::LinuxTunPumpStop;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
use crate::transport_core::linux_tun::{
    LinuxTunPump, LinuxTunPumpConfig, TapHeaders, TunFraming, TunPacket, TunWriter,
};
#[cfg(target_os = "ios")]
use crate::transport_core::packet_tun::TunWriter;
#[cfg(target_os = "ios")]
type TunPacket = PooledBuffer;
#[cfg(target_os = "linux")]
use crate::transport_core::network::is_full_tunnel;
use crate::transport_core::network::{build_network_plan, server_push_log_lines, HandshakeNetwork};
use crate::transport_core::session::{
    authenticate_tcp, build_client_auth_plaintext, build_udp_client_hello_flight, effective_mtu,
    parse_auth_ok, static_es, verify_server_identity, AuthOk, UdpClientHelloFlight,
};
use crate::transport_core::udp_buffer::{
    InternalDrop, UdpBufferController, UdpBufferPolicy, AUTO_MAX_RECV_BYTES,
};
#[cfg(target_os = "windows")]
use crate::transport_core::wintun::{TunPacket, TunWriter, WindowsTunPump};
#[cfg(target_os = "linux")]
use crate::transport_core::{platform_capability, ClientCore, ClientState, CoreOptions, EventKind};
#[cfg(all(test, target_os = "linux"))]
use crate::transport_core::{NetworkDns, NetworkRoute};
use crate::transport_core::{NetworkPlan, RuntimeCounters};

/// How many extra copies of the path-MTU report the UDP data plane emits after the first
/// (#13/#5). The frame is never acknowledged — the server answers no control frame — so a
/// single lost datagram would otherwise cost the whole session's downlink narrowing. Three
/// copies, spread over the first ~10 s of idle ticks, survive both an isolated drop and a short
/// burst; the server simply stores the latest value, and the copies all carry the same one, so the duplicates are a no-op.
/// TCP needs none of this — it retransmits for us.
const MTU_REPORT_RESENDS: u8 = 3;

/// The current tunnel address plan is IPv4-only. Android's TUN can still surface IPv6
/// packets while the OS is withdrawing routes or probing connectivity; sending them to
/// the server only produces source-guard drops and can starve useful traffic in a burst.
#[inline]
fn is_supported_inner_packet(packet: &[u8]) -> bool {
    packet.len() >= 20 && (packet[0] >> 4) == 4
}

/// The address the data-plane socket is ACTUALLY connected to.
///
/// The bypass route used to be installed for `config.server.address` — the hostname —
/// which `ip route get` and `ip route add` each resolved AGAIN, independently of the
/// resolution `TcpStream::connect` had already done. Against round-robin DNS (or any
/// GSLB) those three lookups can return different addresses, so the /32 that is supposed
/// to keep the encrypted path on the physical link could be pinned to an address the
/// tunnel is not using — while the address it IS using fell under the full-tunnel halves
/// and got routed into the tunnel we are building. Record what the socket actually
/// connected to and pin that.
#[cfg(target_os = "linux")]
static CONNECTED_PEER: std::sync::Mutex<Option<std::net::IpAddr>> = std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
fn note_connected_peer(ip: std::net::IpAddr) {
    if let Ok(mut g) = CONNECTED_PEER.lock() {
        *g = Some(ip);
    }
}

/// The peer address to pin, as a literal; falls back to the configured address when the
/// socket never reported one (should not happen after a successful connect).
#[cfg(target_os = "linux")]
fn pin_target(config: &crate::config::client::ClientConfig) -> String {
    CONNECTED_PEER
        .lock()
        .ok()
        .and_then(|g| *g)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| config.server.address.clone())
}
#[cfg(target_os = "linux")]
use crate::transport::tcp::set_tcp_keepalive;
#[cfg(target_os = "linux")]
use crate::tun::iface::TunInterface;
#[cfg(target_os = "linux")]
use crate::tun::{generate_mac, is_tap_mode, tap_interface_name};
use rand::prelude::*;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
// `portable_atomic::AtomicU64` so the data-plane byte counters compile on 32-bit
// mipsel routers (no native 64-bit atomics); native instruction on aarch64/x86_64.
use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(target_os = "linux")]
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub(crate) type IdentityFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'static>>;
pub(crate) type IdentityVerifier = Arc<dyn Fn([u8; 32]) -> IdentityFuture + Send + Sync + 'static>;

#[cfg(target_os = "linux")]
fn cleanup_routing_features(
    kill_switch: bool,
    gateway_nat: bool,
    exit_node: bool,
    tun_if: &str,
    lan_subnet: &str,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Keep the kill-switch in place until forwarding/NAT state has been removed. This
    // preserves fail-closed egress throughout teardown instead of opening the host first.
    if exit_node {
        if let Err(error) = gateway::disengage_exit(tun_if) {
            errors.push(error.to_string());
        }
    }
    if gateway_nat {
        if let Err(error) = gateway::disengage(tun_if, lan_subnet) {
            errors.push(error.to_string());
        }
    }
    if kill_switch {
        if let Err(error) = killswitch::disengage(tun_if) {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("host firewall cleanup failed: {}", errors.join("; "))
    }
}

/// The packet/session code is platform-neutral. This is the deliberately small boundary
/// retained by Linux and Android: identity persistence/trust, NetworkPlan execution and
/// ownership of the already-created TUN descriptors.
pub(crate) trait ClientPlatform {
    fn next_generation(&mut self) -> u64;
    fn device_id(&self) -> anyhow::Result<[u8; crate::protocol::DEVICE_ID_LEN]>;
    fn identity_verifier(&self, config: &crate::config::client::ClientConfig) -> IdentityVerifier;
    fn prepare_tunnel(
        &mut self,
        config: &crate::config::client::ClientConfig,
        plan: NetworkPlan,
        network: &HandshakeNetwork<'_>,
    ) -> anyhow::Result<TunnelSetup>;
    fn fallback_dns_servers(&self) -> &[String];
    fn cancel_token(&self) -> Arc<AtomicBool>;
    fn counters(&self) -> Arc<RuntimeCounters>;
}

/// In-process Linux adapter for the same lifecycle contract exported over the C ABI.
/// It deliberately polls the bounded event queue instead of reaching around it: this is
/// the first real adapter that freezes the semantics other clients will consume.
#[cfg(target_os = "linux")]
struct LinuxCoreAdapter {
    core: ClientCore,
    next_plan_generation: u64,
    cancel: Arc<AtomicBool>,
    counters: Arc<RuntimeCounters>,
    diagnostics: ClientStatusReporter,
}

/// Sanitized state exported by a Linux client process for the server panel. This is a
/// deliberately separate contract from logs: consumers no longer infer connection state,
/// negotiated MTU or DNS by matching English log messages. Credentials, identity keys and
/// session material are never copied into this structure.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientStatusReporter {
    path: Option<Arc<std::path::PathBuf>>,
    state: Arc<std::sync::Mutex<ClientDiagnosticState>>,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientDiagnosticState {
    profile: String,
    state: String,
    generation: u64,
    reconnects: u64,
    retry_in_secs: Option<u64>,
    last_error: Option<String>,
    plan: Option<serde_json::Value>,
}

#[cfg(target_os = "linux")]
impl ClientStatusReporter {
    fn from_env() -> Self {
        let path = std::env::var("QELI_CLIENT_STATUS")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .map(Arc::new);
        let profile =
            std::env::var("QELI_CLIENT_PROFILE").unwrap_or_else(|_| "standalone".to_string());
        Self {
            path,
            state: Arc::new(std::sync::Mutex::new(ClientDiagnosticState {
                profile,
                state: "created".to_string(),
                generation: 0,
                reconnects: 0,
                retry_in_secs: None,
                last_error: None,
                plan: None,
            })),
        }
    }

    fn state_name(state: ClientState) -> &'static str {
        match state {
            ClientState::Created => "created",
            ClientState::Connecting => "connecting",
            ClientState::AwaitingNetwork => "awaiting_network",
            ClientState::Running => "running",
            ClientState::Stopping => "stopping",
            ClientState::Stopped => "stopped",
            ClientState::Failed => "failed",
        }
    }

    fn clean_error(message: &str) -> String {
        message
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(1024)
            .collect::<String>()
            .trim()
            .to_string()
    }

    fn update_state(&self, state: ClientState, reconnects: u64) {
        if let Ok(mut current) = self.state.lock() {
            current.state = Self::state_name(state).to_string();
            current.reconnects = reconnects;
            current.retry_in_secs = None;
            if state == ClientState::Running {
                current.last_error = None;
            }
        }
    }

    fn update_plan(&self, plan: &NetworkPlan) {
        if let Ok(mut current) = self.state.lock() {
            current.generation = plan.generation;
            current.plan = serde_json::to_value(plan).ok();
        }
    }

    fn update_fault(&self, message: &str) {
        if let Ok(mut current) = self.state.lock() {
            current.last_error = Some(Self::clean_error(message));
        }
    }

    fn retrying(&self, error: Option<&anyhow::Error>, attempt: u64, delay_secs: u64) {
        if let Ok(mut current) = self.state.lock() {
            current.state = "retrying".to_string();
            current.reconnects = attempt;
            current.retry_in_secs = Some(delay_secs);
            if let Some(error) = error {
                current.last_error = Some(Self::clean_error(&error.to_string()));
            }
        }
    }

    fn terminal(&self, error: Option<&anyhow::Error>) {
        if let Ok(mut current) = self.state.lock() {
            current.state = if error.is_some() { "failed" } else { "stopped" }.to_string();
            current.retry_in_secs = None;
            if let Some(error) = error {
                current.last_error = Some(Self::clean_error(&error.to_string()));
            }
        }
    }

    fn publish(&self, counters: &RuntimeCounters) {
        let Some(path) = self.path.as_deref() else {
            return;
        };
        let current = match self.state.lock() {
            Ok(current) => current.clone(),
            Err(_) => return,
        };
        let udp = counters.udp.snapshot();
        let updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        let body = serde_json::json!({
            "schema": 1,
            "profile": current.profile,
            "state": current.state,
            "updated_at_ms": updated_at_ms,
            "generation": current.generation,
            "reconnects": current.reconnects,
            "retry_in_secs": current.retry_in_secs,
            "last_error": current.last_error,
            "plan": current.plan,
            "stats": {
                "tx_packets": counters.tx_packets.load(portable_atomic::Ordering::Relaxed),
                "tx_bytes": counters.tx_bytes.load(portable_atomic::Ordering::Relaxed),
                "rx_packets": counters.rx_packets.load(portable_atomic::Ordering::Relaxed),
                "rx_bytes": counters.rx_bytes.load(portable_atomic::Ordering::Relaxed),
                "udp_kernel_drops": udp.kernel_drops,
                "udp_internal_drops": udp.internal_drops,
                "udp_drops_pool_exhausted": udp.pool_exhausted_drops,
                "udp_drops_queue_full": udp.queue_full_drops,
                "udp_drops_oversize": udp.oversize_drops,
                "udp_drops_unsupported": udp.unsupported_drops,
                "udp_drops_tun_write": udp.tun_write_drops,
                "udp_buffer_grows": udp.grow_events,
                "udp_recv_buffer_bytes": udp.granted_recv_bytes,
            },
        });
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(encoded) = serde_json::to_vec(&body) {
            if let Err(error) = crate::util::write_atomic_private(path, &encoded) {
                log::debug!(
                    "cannot publish client diagnostics {}: {error}",
                    path.display()
                );
            }
        }
    }

    fn start_sampler(&self, counters: Arc<RuntimeCounters>) {
        if self.path.is_none() {
            return;
        }
        let reporter = self.clone();
        tokio::spawn(async move {
            loop {
                reporter.publish(&counters);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
}

#[cfg(target_os = "linux")]
impl LinuxCoreAdapter {
    fn new(config_text: &str) -> anyhow::Result<(Self, crate::config::client::ClientConfig)> {
        let mut core = ClientCore::new(
            config_text,
            CoreOptions {
                platform_capabilities: platform_capability::SYSTEM_PLAN,
                ..CoreOptions::default()
            },
        )?;
        let config = core.config().clone();
        while core.poll_event().is_some() {}
        let counters = Arc::new(RuntimeCounters::default());
        let diagnostics = ClientStatusReporter::from_env();
        diagnostics.publish(&counters);
        Ok((
            Self {
                core,
                next_plan_generation: 1,
                cancel: Arc::new(AtomicBool::new(false)),
                counters,
                diagnostics,
            },
            config,
        ))
    }

    fn begin_connection(&mut self, reconnect: bool) -> anyhow::Result<()> {
        if !matches!(
            self.core.state(),
            ClientState::Created | ClientState::Stopped
        ) {
            self.core.stop()?;
            self.drain_events(None)?;
        }
        if reconnect {
            self.core.record_reconnect();
        }
        self.core.start()?;
        self.drain_events(None).map(|_| ())
    }

    fn finish_connection(&mut self) -> anyhow::Result<()> {
        self.core.stop()?;
        self.drain_events(None).map(|_| ())
    }

    fn next_generation(&mut self) -> u64 {
        let generation = self.next_plan_generation;
        self.next_plan_generation = self.next_plan_generation.saturating_add(1);
        generation
    }

    fn apply_network_plan<T>(
        &mut self,
        plan: NetworkPlan,
        apply: impl FnOnce(&NetworkPlan) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let generation = plan.generation;
        self.core.publish_network_plan(plan)?;
        let executable = self.drain_events(Some(generation))?.ok_or_else(|| {
            anyhow::anyhow!("core emitted no network plan for generation {generation}")
        })?;

        match apply(&executable) {
            Ok(value) => {
                self.core.ack_network_plan(generation, true, None)?;
                self.drain_events(None)?;
                Ok(value)
            }
            Err(error) => {
                let reason = error.to_string();
                self.core
                    .ack_network_plan(generation, false, Some(&reason))?;
                self.drain_events(None)?;
                Err(error)
            }
        }
    }

    fn drain_events(&mut self, wanted_plan: Option<u64>) -> anyhow::Result<Option<NetworkPlan>> {
        let mut found = None;
        while let Some(event) = self.core.poll_event() {
            match event.kind {
                EventKind::StateChanged => {
                    log::debug!("transport core state: {:?}", event.state);
                    self.diagnostics
                        .update_state(event.state, self.core.stats().reconnects);
                    self.diagnostics.publish(&self.counters);
                }
                EventKind::NetworkPlan => {
                    let plan = event
                        .plan
                        .ok_or_else(|| anyhow::anyhow!("network-plan event has no payload"))?;
                    self.diagnostics.update_plan(&plan);
                    self.diagnostics.publish(&self.counters);
                    if wanted_plan == Some(plan.generation) {
                        found = Some(plan);
                    }
                }
                EventKind::Error => {
                    if let Some(fault) = event.fault {
                        log::warn!("transport core error {:?}: {}", fault.code, fault.message);
                        self.diagnostics.update_fault(&fault.message);
                        self.diagnostics.publish(&self.counters);
                    }
                }
                EventKind::SocketProtect => {
                    return Err(anyhow::anyhow!(
                        "unexpected socket-protect event: Linux does not advertise that capability"
                    ));
                }
                EventKind::ServerIdentity => {
                    return Err(anyhow::anyhow!(
                        "unexpected server-identity event: Linux verifies trust in-process"
                    ));
                }
            }
        }
        Ok(found)
    }
}

#[cfg(target_os = "linux")]
impl ClientPlatform for LinuxCoreAdapter {
    fn next_generation(&mut self) -> u64 {
        LinuxCoreAdapter::next_generation(self)
    }

    fn device_id(&self) -> anyhow::Result<[u8; crate::protocol::DEVICE_ID_LEN]> {
        Ok(device_id())
    }

    fn identity_verifier(&self, config: &crate::config::client::ClientConfig) -> IdentityVerifier {
        let expected = config.auth.server_public_key.clone();
        let server_id = format!("{}:{}", config.server.address, config.server.port);
        let allow_tofu = config.auth.allow_unpinned_tofu;
        Arc::new(move |received| {
            let expected = expected.clone();
            let server_id = server_id.clone();
            Box::pin(async move { verify_server_key(&received, &expected, &server_id, allow_tofu) })
        })
    }

    fn prepare_tunnel(
        &mut self,
        config: &crate::config::client::ClientConfig,
        plan: NetworkPlan,
        network: &HandshakeNetwork<'_>,
    ) -> anyhow::Result<TunnelSetup> {
        self.apply_network_plan(plan, |plan| setup_tunnel(config, plan, network))
    }

    fn fallback_dns_servers(&self) -> &[String] {
        &[]
    }

    fn cancel_token(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    fn counters(&self) -> Arc<RuntimeCounters> {
        self.counters.clone()
    }
}

/// Set by a data-plane loop when IT chose to end the session — today only resume-from-suspend,
/// which ends a perfectly good session on purpose so the socket and NAT mapping are rebuilt on
/// the network the machine woke up on.
///
/// The retry loop must tell that apart from a failure: the backoff only clears after a 30 s
/// "stable" session, so a laptop that suspends sooner than that used to climb 1→2→4→…→60 s and
/// spend longer waiting out a penalty than carrying traffic. Same defect fixed in the Android
/// and desktop clients; this is the CLI's share of it.
///
/// A process-wide flag rather than a richer `Ok` type deliberately: [`run_client`] is the single
/// retry loop in the process, and the alternative — threading an exit reason out of both
/// data-plane functions — is a far wider edit for the same information.
///
/// Not gated on the CLI's own target: the two data-plane loops that SET it are shared with the
/// mobile cores, so a `linux`-only definition compiles on the gate host and nowhere else.
static DELIBERATE_CYCLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
pub async fn run_client(config_path: &str) -> anyhow::Result<()> {
    // SIGUSR1 dumps the packet trace, when one is armed (no-op otherwise).
    tokio::spawn(trace::watch());

    let config_content = std::fs::read_to_string(config_path)?;
    // STRICT: a misspelled key name and an unreadable value both used to fail open here —
    // only `check-config` reported them, while the real start substituted defaults in silence.
    // See `config::parse_client_config_strict`. (Audit 2026-08-01, §4/§5.)
    let (mut core_adapter, config) = LinuxCoreAdapter::new(&config_content)?;
    core_adapter
        .diagnostics
        .start_sampler(core_adapter.counters.clone());
    // Warn when a config holding a cleartext password is readable by other local accounts.
    //
    // Nothing on the LOAD path ever looked at the file mode. `pass = <vpn password>` and a
    // pinned `key` sit in this file verbatim, and the ordinary way to create it is to paste a
    // `qeli://` link into an editor under the default umask — which yields 0644. The client
    // then started without a word, and any local user could read the credential. Permissions
    // are narrowed on WRITE (`write_atomic_private`), so this only ever bit hand-made files —
    // i.e. the common case. The only existing mode check, `hooks::config_is_trusted`, looks
    // at WRITABILITY and runs only when hooks are configured.
    //
    // A warning rather than a refusal: an operator with a 0644 config and no better option
    // should still be able to bring the tunnel up, and OpenSSH's precedent (refuse) applies
    // to keys the daemon can regenerate, not to a user's only way in. (Audit 2026-08-04.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let has_secret = config
            .auth
            .password
            .as_deref()
            .is_some_and(|p| !p.is_empty());
        if has_secret {
            if let Ok(md) = std::fs::metadata(config_path) {
                let mode = md.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    log::warn!(
                        "config '{config_path}' is mode {mode:o} — it contains the VPN password \
                         in cleartext and every local account can read it. `chmod 600 \
                         {config_path}`."
                    );
                }
            }
        }
    }
    let password = zeroize::Zeroizing::new(if let Some(ref pw) = config.auth.password {
        pw.clone()
    } else if let Some(ref pw_file) = config.auth.password_file {
        std::fs::read_to_string(pw_file)?.trim().to_string()
    } else if let Some(ref pw_cmd) = config.auth.password_command {
        // SECURITY: password_command runs `sh -c` as us (typically root). Honour it
        // ONLY from a trusted (not group/world-writable) config file, exactly like
        // post_up/post_down below — otherwise anyone who can write the config gets code
        // execution. Fail closed (the user explicitly asked to source the password this
        // way, so a refusal must be loud, not a silent skip). The panel never persists
        // this field; see web/api/client.rs::persist.
        crate::hooks::config_is_trusted(config_path)
            .map_err(|why| anyhow::anyhow!("refusing to run auth.password_command — {why}"))?;
        let output = std::process::Command::new("sh")
            .args(["-c", pw_cmd])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "auth.password_command failed with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        String::from_utf8(output.stdout)?.trim().to_string()
    } else {
        return Err(anyhow::anyhow!(
            "auth.password, auth.password_file or auth.password_command required"
        ));
    });
    // Bound the EFFECTIVE credential, not just the inline one.
    //
    // `config.validate()` above already checked `pass`, but it ran before this block — the
    // file and command sources produce their secret only now, so a long token from either
    // walked straight past the bound that exists for it. These are the sources most likely to
    // carry one: nobody types a 1 KB password, a secret manager emits one without blinking.
    // (Audit 2026-08-02, §2 of the follow-up.)
    let pw_source = if config.auth.password.is_some() {
        "pass"
    } else if config.auth.password_file.is_some() {
        "password_file"
    } else {
        "password_command"
    };
    config.check_credential_size(&password, pw_source)?;

    // Repair any DNS state left behind by a previous run that died without
    // restoring (SIGKILL / power loss / panic). Must run before we touch DNS.
    dns::recover_stale()?;

    // Whether to run the firewall kill-switch for this config (enabled + full-tunnel).
    let ks_on = killswitch::should_engage(&config.routing);

    // Gateway/router NAT + lifecycle hooks (Linux). Resolve the tun interface name
    // once — both the kill-switch and the gateway NAT key their rules on it.
    let gw_on = gateway::should_engage(&config.routing);
    // Exit-node: this client is an internet EXIT for OTHER tunnel clients (mirror of
    // gateway_nat — masquerade tun-forwarded traffic out the physical WAN). Independent of
    // gw_on: exit uses its own engage/disengage, so both can be off, one on, or (unusually)
    // both.
    let exit_on = config.routing.exit_node;
    let tun_if = tap_interface_name(&config.tun.name, &config.tun.device_type);
    let lan_subnet = config.routing.lan_subnet.clone();
    // post_up/post_down are honoured ONLY from a trusted (not group/world-writable)
    // config file: a hook runs as us (root). SECURITY: the panel/API never writes
    // these fields, so a panel compromise can't become RCE — see hooks.rs.
    let (post_up, post_down) =
        if config.routing.post_up.is_empty() && config.routing.post_down.is_empty() {
            (String::new(), String::new())
        } else {
            match crate::hooks::config_is_trusted(config_path) {
                Ok(()) => (
                    config.routing.post_up.clone(),
                    config.routing.post_down.clone(),
                ),
                Err(why) => {
                    log::error!("Ignoring post_up/post_down — {why}");
                    (String::new(), String::new())
                }
            }
        };

    // Env passed to hooks (wg-quick-style context).
    let hook_env: Vec<(&str, String)> = vec![
        ("QELI_TUN", tun_if.clone()),
        ("QELI_SERVER", config.server.address.clone()),
        ("QELI_SERVER_PORT", config.server.port.to_string()),
        ("QELI_LAN_SUBNET", lan_subnet.clone()),
    ];

    // Graceful shutdown: on SIGINT/SIGTERM restore DNS (and clear the kill-switch)
    // before exiting, so a `systemctl stop` or Ctrl-C never strands the system on
    // the tunnel resolver or behind a closed firewall. Last line of defence on top
    // of the per-connection restore in the data-plane loops below.
    let (sig_tun, sig_lan, sig_post_down) = (tun_if.clone(), lan_subnet.clone(), post_down.clone());
    // The hook environment has to reach THIS path too.
    //
    // post_down is invoked from three places; the two orderly exits passed `&hook_env`, and
    // the signal handler — `systemctl stop` and Ctrl-C, i.e. the way the client actually
    // stops in practice — passed `&[]`. So the paired hooks operators are told to write,
    // `post_up = iptables -I FORWARD -i "$QELI_TUN" -j ACCEPT` /
    // `post_down = iptables -D FORWARD -i "$QELI_TUN" -j ACCEPT`, ran their teardown as
    // `iptables -D FORWARD -i "" -j ACCEPT`: it fails, `hooks::run` only warns on a non-zero
    // exit, and the rule that opens forwarding stays in the firewall after the VPN is gone.
    // (Audit 2026-08-04.)
    let sig_hook_env = hook_env.clone();
    // Also needed below: `process::exit` runs no destructors, so `TunGuard` — which owns
    // removing the device and the routes — never fires on this path. Everything it would
    // have done has to be done explicitly here.
    let sig_server = config.server.address.clone();
    let sig_exclude = config.routing.exclude.clone();
    let sig_owns_device = !config.tun.attach_existing;
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = async {
                match term.as_mut() {
                    Some(t) => { let _ = t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
        log::info!(
            "Shutdown signal received — restoring DNS{}{}{} and exiting",
            if ks_on { " + clearing kill-switch" } else { "" },
            if gw_on { " + clearing gateway-NAT" } else { "" },
            if exit_on { " + clearing exit-node" } else { "" }
        );
        // Name our own interface so a sibling client's resolvectl config is not
        // reverted along with ours. (Audit 2026-07-27, R7.)
        let mut cleanup_failed = false;
        if let Err(error) = dns::restore_dns_for(&sig_tun) {
            cleanup_failed = true;
            log::error!("shutdown DNS cleanup failed: {error}");
        }
        if let Err(error) = cleanup_routing_features(ks_on, gw_on, exit_on, &sig_tun, &sig_lan) {
            cleanup_failed = true;
            log::error!("shutdown firewall cleanup failed: {error}");
        }
        // Routes and the device: `TunGuard::drop` handles these on every normal exit, but
        // `process::exit` below skips destructors entirely, so a Ctrl-C used to leave the
        // physical server-bypass /32, the exclude bypasses, the full-tunnel halves and the
        // IPv6 blackholes installed — plus the interface itself — on a host that now has
        // no VPN. Do it explicitly; both calls are idempotent.
        if sig_owns_device {
            if let Err(error) = cleanup_owned_tun(&sig_tun, &sig_server, &sig_exclude) {
                cleanup_failed = true;
                log::error!("shutdown network cleanup failed: {error}");
            }
        }
        crate::hooks::run("post_down", &sig_post_down, &sig_hook_env).await;
        std::process::exit(if cleanup_failed { 1 } else { 0 });
    });

    // Engage the kill-switch BEFORE the first connect, so even the first attempt
    // and every reconnect window is leak-proof. It stays up across reconnects and
    // is torn down only on a clean stop. If the user asked for it but it can't be
    // installed (no iptables / unresolvable server), refuse to run unprotected.
    if ks_on {
        killswitch::engage(
            &config.server.address,
            config.server.port,
            &tun_if,
            config.routing.allow_ipv6_leak,
            gw_on,
        )?;
    }
    // Gateway/router NAT: program ip_forward + MASQUERADE out the tun so a LAN
    // behind this client reaches the internet through the tunnel. Idempotent;
    // stays up across reconnects (rules are by interface name), removed on stop.
    if gw_on {
        // masquerade only for gateway_nat (internet egress); `forward` alone = pure L3
        // routing, no NAT (#13).
        if let Err(error) = gateway::engage(&tun_if, &lan_subnet, config.routing.gateway_nat) {
            // `engage` may already have changed sysctls or installed an earlier
            // rule before a later verification failed. Roll back its partial work
            // and everything successfully installed before it.
            let cleanup = cleanup_routing_features(ks_on, true, false, &tun_if, &lan_subnet);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(anyhow::anyhow!(
                    "{error}; rollback after gateway setup failure also failed: {cleanup}"
                )),
            };
        }
    }
    // Exit-node: forward + MASQUERADE tunnel traffic out the physical WAN, so other tunnel
    // clients reach the internet under this host's IP. Like the gateway NAT it installs by
    // interface name before the first connect, stays up across reconnects, and is removed on
    // a clean stop. Refuse to run if requested but not installable (no iptables / no WAN).
    if exit_on {
        if let Err(error) = gateway::engage_exit(&tun_if) {
            let cleanup = cleanup_routing_features(ks_on, gw_on, true, &tun_if, &lan_subnet);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(anyhow::anyhow!(
                    "{error}; rollback after exit-node setup failure also failed: {cleanup}"
                )),
            };
        }
    }
    // Run post_up after the firewall is in place.
    crate::hooks::run("post_up", &post_up, &hook_env).await;

    let mut retry_count = 0u64;

    loop {
        if let Err(error) = core_adapter.begin_connection(retry_count > 0) {
            let cleanup = cleanup_routing_features(ks_on, gw_on, exit_on, &tun_if, &lan_subnet);
            crate::hooks::run("post_down", &post_down, &hook_env).await;
            let error = match cleanup {
                Ok(()) => error,
                Err(cleanup) => anyhow::anyhow!("{error}; teardown also failed: {cleanup}"),
            };
            core_adapter.diagnostics.terminal(Some(&error));
            core_adapter.diagnostics.publish(&core_adapter.counters);
            return Err(error);
        }
        let started = std::time::Instant::now();
        let result = if config.server.protocol == "udp" {
            connect_and_run_udp(&config, &password, &mut core_adapter).await
        } else {
            connect_and_run_tcp(&config, &password, &mut core_adapter).await
        };
        if let Err(error) = core_adapter.finish_connection() {
            log::error!("transport core teardown error: {error}");
        }
        let ran = started.elapsed();

        let deliberate = DELIBERATE_CYCLE.swap(false, std::sync::atomic::Ordering::AcqRel);
        match &result {
            Ok(_) => {
                log::info!("Connection closed, reconnecting...");
                // Reset the backoff ONLY when the session was STABLE (ran a while):
                // only *consecutive* connect/auth failures should escalate the delay
                // (a flapping cell / Wi-Fi↔LTE link shouldn't crawl to max_delay). But
                // a server that accepts auth then INSTANTLY drops must keep escalating,
                // or we'd hot-loop at the floor delay with a full teardown each cycle.
                if deliberate || ran >= Duration::from_secs(30) {
                    retry_count = 0;
                }
            }
            Err(e) => log::error!("Connection error: {}", e),
        }

        if !config.server.reconnect.enabled {
            // Clean exit (reconnect disabled): lift the kill-switch / gateway NAT so
            // the host isn't left firewalled or NAT'ing after the client returns.
            let cleanup = cleanup_routing_features(ks_on, gw_on, exit_on, &tun_if, &lan_subnet);
            crate::hooks::run("post_down", &post_down, &hook_env).await;
            let result = match (result, cleanup) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error),
                (Ok(()), Err(cleanup)) => Err(cleanup),
                (Err(error), Err(cleanup)) => {
                    Err(anyhow::anyhow!("{error}; teardown also failed: {cleanup}"))
                }
            };
            core_adapter.diagnostics.terminal(result.as_ref().err());
            core_adapter.diagnostics.publish(&core_adapter.counters);
            return result;
        }

        let max_retries = config.server.reconnect.max_retries;
        if max_retries >= 0 && retry_count >= max_retries as u64 {
            let cleanup = cleanup_routing_features(ks_on, gw_on, exit_on, &tun_if, &lan_subnet);
            crate::hooks::run("post_down", &post_down, &hook_env).await;
            let error = match cleanup {
                Ok(()) => anyhow::anyhow!("max retries ({}) reached", max_retries),
                Err(cleanup) => anyhow::anyhow!(
                    "max retries ({}) reached; teardown also failed: {}",
                    max_retries,
                    cleanup
                ),
            };
            core_adapter.diagnostics.terminal(Some(&error));
            core_adapter.diagnostics.publish(&core_adapter.counters);
            return Err(error);
        }

        // Exponential backoff from the base delay. Compute BEFORE incrementing so the
        // first retry uses the configured base (retry_count 0 → base * 2^0), not
        // double it (the previous off-by-one skipped the base step).
        let multiplier = 1u64
            .checked_shl(retry_count as u32)
            .unwrap_or(u64::MAX)
            .min(100);
        let delay = std::cmp::min(
            config
                .server
                .reconnect
                .base_delay_secs
                .saturating_mul(multiplier),
            config.server.reconnect.max_delay_secs,
        );
        retry_count += 1;

        // Re-resolve the server so a rotated (DDNS / round-robin) address is allowed
        // through the kill-switch before the next attempt — otherwise a stale
        // allow-list would block every reconnect (add-only, no leak window).
        if ks_on {
            if let Err(error) =
                killswitch::refresh_server_ips(&config.server.address, config.server.port, &tun_if)
            {
                log::error!("kill-switch address refresh failed: {error}");
            }
        }

        log::info!("Reconnecting in {}s (attempt {})...", delay, retry_count);
        core_adapter
            .diagnostics
            .retrying(result.as_ref().err(), retry_count, delay);
        core_adapter.diagnostics.publish(&core_adapter.counters);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

/// A factory that opens one more connection of the SAME concrete stream type, for
/// stream bonding (multipath). Cloneable + callable from the data-plane to ramp
/// streams. Every TCP wire mode installs a concrete connector; UDP has its own
/// transport path and never reaches this type.
pub(crate) type StreamConnector<S> = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<S>> + Send>>
        + Send
        + Sync,
>;

/// Divide the remaining dial deadline across every untried A record. A dead first address
/// can consume only its fair share; addresses that fail quickly donate their unused time to
/// the remaining candidates. No fixed per-address timeout is baked into the transport.
#[cfg(any(target_os = "linux", test))]
fn per_candidate_connect_budget(remaining: Duration, candidates_left: usize) -> Duration {
    if candidates_left <= 1 {
        remaining
    } else {
        remaining / u32::try_from(candidates_left).unwrap_or(u32::MAX)
    }
}

#[cfg(target_os = "linux")]
async fn connect_tcp_candidates(
    host: &str,
    port: u16,
    total: Duration,
    label: &str,
) -> anyhow::Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + total;
    let resolved = match tokio::time::timeout(total, tokio::net::lookup_host((host, port))).await {
        Ok(result) => result.map_err(|error| {
            anyhow::anyhow!("{label} DNS lookup for {host}:{port} failed: {error}")
        })?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "{label} DNS lookup for {host}:{port} timed out after {}s",
                total.as_secs()
            ));
        }
    };
    let mut seen = std::collections::HashSet::new();
    let candidates: Vec<std::net::SocketAddr> = resolved
        .filter(|address| address.is_ipv4())
        .filter(|address| seen.insert(*address))
        .collect();
    if candidates.is_empty() {
        return Err(anyhow::anyhow!(
            "{label} DNS lookup for {host}:{port} returned no IPv4 address"
        ));
    }

    let mut failures = Vec::with_capacity(candidates.len());
    for (index, address) in candidates.iter().copied().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let slice = per_candidate_connect_budget(remaining, candidates.len() - index);
        match tokio::time::timeout(slice, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => {
                note_connected_peer(address.ip());
                if index > 0 {
                    log::info!("{label} connected through fallback carrier {address}");
                }
                return Ok(stream);
            }
            Ok(Err(error)) => failures.push(format!("{address}: {error}")),
            Err(_) => failures.push(format!(
                "{address}: timed out after {} ms",
                slice.as_millis()
            )),
        }
    }
    Err(anyhow::anyhow!(
        "{label} could not connect to any IPv4 address for {host}:{port} within {}s ({})",
        total.as_secs(),
        failures.join("; ")
    ))
}

/// Open ONE reality-tls connection (TCP + browser-grade TLS 1.3 carrying the
/// REALITY token). Reusable for the primary connection and each bonded stream —
/// every call uses a fresh ephemeral + freshly sealed session_id.
#[cfg(target_os = "linux")]
async fn connect_reality(
    config: &crate::config::client::ClientConfig,
) -> anyhow::Result<crate::protocol::realtls::stream::RealTlsStream<TcpStream>> {
    // Bound connect + the TLS 1.3 handshake (reads) by connection_timeout_secs: a server
    // that accepts TCP then stalls the TLS handshake would otherwise hang here forever.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let mut stream = connect_tcp_candidates(
        &config.server.address,
        config.server.port,
        to,
        "reality-tls TCP",
    )
    .await?;
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;
    // SNI precedence mirrors the inner handshake.
    let server_name: String = match config.obfuscation.sni.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => {
            crate::protocol::pick_random_sni().to_string()
        }
        _ => config.server.address.clone(),
    };
    // Seal the REALITY token into the real ClientHello's session_id with a fresh
    // ephemeral. Requires a pinned server key + short_id, else the server can't
    // recognise us and would proxy us to the real site.
    let eph = crate::crypto::Keypair::generate();
    let session_id = match (
        config
            .obfuscation
            .reality_short_id
            .as_deref()
            .filter(|s| !s.is_empty()),
        config
            .auth
            .server_public_key
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(crate::crypto::parse_pubkey_hex),
    ) {
        (Some(sid_hex), Some(pk)) => {
            let reality_pub = crate::crypto::PublicKey::from_bytes(&pk);
            let short_id = crate::crypto::reality::short_id_from_hex(sid_hex);
            crate::crypto::reality::seal_session_id(&reality_pub, &eph, &short_id)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "reality-tls requires obfuscation.reality_short_id and auth.server_public_key"
            ))
        }
    };
    let est = match tokio::time::timeout(
        to,
        crate::protocol::realtls::client::client_handshake(
            &mut stream,
            eph,
            session_id,
            &server_name,
        ),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "reality-tls handshake timed out after {}s",
                to.as_secs()
            ))
        }
    };
    Ok(crate::protocol::realtls::stream::RealTlsStream::new(
        stream, est,
    ))
}

/// Open ONE obfs connection (TCP + ChaCha20 stream obfuscation with its own nonce
/// exchange). Reusable for the primary connection and each bonded stream.
#[cfg(target_os = "linux")]
async fn connect_obfs(
    config: &crate::config::client::ClientConfig,
) -> anyhow::Result<crate::protocol::obfs::ObfsStream<TcpStream>> {
    // Bound connect + the obfs nonce-exchange handshake (reads) by
    // connection_timeout_secs: a server that accepts TCP then stalls the obfs handshake
    // would otherwise hang here forever (the reads are unbounded `.await`s), and no
    // reconnect would fire. Covers both the primary and each bonded stream.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    match tokio::time::timeout(to, async {
        let stream =
            connect_tcp_candidates(&config.server.address, config.server.port, to, "obfs TCP")
                .await?;
        stream.set_nodelay(config.performance.tcp_nodelay)?;
        set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;
        let key = crate::protocol::obfs::derive_obfs_key(&config.obfuscation.obfs_key);
        let fronting = config.obfuscation.fronting == "websocket";
        let awg = crate::protocol::obfs::AwgParams {
            enabled: config.obfuscation.awg.enabled,
            jc: config.obfuscation.awg.jc,
            jmin: config.obfuscation.awg.jmin,
            jmax: config.obfuscation.awg.jmax,
        };
        // Same precedence as the fake-TLS SNI: an explicit `obfuscation.sni` wins, else
        // the connect hostname, else `None` (a random decoy) when dialling a bare IP —
        // so the cleartext `Host:` header agrees with where the packets are actually
        // going instead of naming an unrelated CDN. (Audit 2026-07-27, E2.)
        let ws_host: Option<&str> = match config.obfuscation.sni.as_deref() {
            Some(s) if !s.is_empty() => Some(s),
            _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => None,
            _ => Some(config.server.address.as_str()),
        };
        anyhow::Ok(
            crate::protocol::obfs::ObfsStream::connect_with_host(
                stream, &key, fronting, awg, ws_host,
            )
            .await?,
        )
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!(
            "obfs connect/handshake timed out after {}s",
            to.as_secs()
        )),
    }
}

/// Open ONE bare-TCP connection for the `fake-tls` / `plain` wire modes — the TLS
/// mimicry (fake-tls) or raw framing (plain) is applied by the qeli handshake, not
/// the transport. Reusable for the primary connection and each bonded stream.
#[cfg(target_os = "linux")]
async fn connect_bare_tcp(
    config: &crate::config::client::ClientConfig,
) -> anyhow::Result<TcpStream> {
    // Bound the connect by connection_timeout_secs rather than the (much longer, ~75s)
    // OS SYN timeout, so a never-accepting server fails over to a reconnect promptly. No
    // handshake reads here — the qeli handshake (bounded in run_tcp_tunnel) does those.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let stream =
        connect_tcp_candidates(&config.server.address, config.server.port, to, "TCP").await?;
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
async fn connect_and_run_tcp(
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut LinuxCoreAdapter,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.server.address, config.server.port);
    log::info!(
        "Connecting to {} (TCP) as user '{}'",
        addr,
        config.auth.username
    );

    if config.obfuscation.mode == "obfs" {
        if config.obfuscation.obfs_key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "obfs wire mode requires a non-empty obfuscation.obfs_key \
                 (an empty key is publicly derivable → no DPI resistance)"
            ));
        }
        log::info!("Wire mode: obfs (ChaCha20 stream obfuscation)");
        let first = connect_obfs(config).await?;
        // Connector clones the config so it outlives this scope and can be called
        // by the data-plane to open bonded streams (fixed open / adaptive ramp).
        let cfg = std::sync::Arc::new(config.clone());
        let connector: StreamConnector<_> = std::sync::Arc::new(move || {
            let cfg = cfg.clone();
            Box::pin(async move { connect_obfs(&cfg).await })
        });
        run_tcp_tunnel(first, connector, config, password, core).await
    } else if config.obfuscation.mode == "reality-tls" {
        log::info!("Wire mode: reality-tls (real TLS 1.3 carrying the tunnel)");
        let first = connect_reality(config).await?;
        // Connector clones the config so it outlives this scope and can be called
        // by the data-plane (fixed open / adaptive ramp).
        let cfg = std::sync::Arc::new(config.clone());
        let connector: StreamConnector<_> = std::sync::Arc::new(move || {
            let cfg = cfg.clone();
            Box::pin(async move { connect_reality(&cfg).await })
        });
        run_tcp_tunnel(first, connector, config, password, core).await
    } else {
        // fake-tls / plain: bare TCP transport; the qeli handshake applies the
        // fake-TLS mimicry or the raw framing. Both support stream bonding.
        log::info!("Wire mode: {} (TCP)", config.obfuscation.mode);
        let first = connect_bare_tcp(config).await?;
        let cfg = std::sync::Arc::new(config.clone());
        let connector: StreamConnector<_> = std::sync::Arc::new(move || {
            let cfg = cfg.clone();
            Box::pin(async move { connect_bare_tcp(&cfg).await })
        });
        run_tcp_tunnel(first, connector, config, password, core).await
    }
}

/// Immutable per-stream pump config (data-phase obfuscation + liveness), cheaply
/// cloned into every bonded stream's tasks.
#[derive(Clone)]
struct StreamPump {
    framing: Framing,
    heartbeat_enabled: bool,
    heartbeat_interval: Duration,
    idle_timeout: Duration,
    hb_data: u16,
    hb_jitter: u64,
    padding_enabled: bool,
    padding_min: u16,
    padding_max: u16,
    padding_randomize: bool,
    padding_prob: f64,
    norm_enabled: bool,
    norm_sizes: Vec<u16>,
    /// Flow-shaping (DPI-AUDIT 6.1/6.2): client->server idle cover, mirror of the
    /// server's. When enabled it replaces this stream's fixed heartbeat.
    shaping: crate::protocol::ShapingConfig,
    /// reality-tls only: run the receive side as a 2-stage pipeline so the outer
    /// TLS AES-GCM (done in `read_record`) and the inner qeli ChaCha
    /// (`decrypt_packet`) overlap across cores instead of running serially in one
    /// task. Off for every other mode (no heavy outer AEAD → a pipeline hop would
    /// only add latency).
    pipeline_rx: bool,
}

/// Plaintext queued for one TCP stream. TUN packets retain their reusable backing
/// allocation until encryption finishes; small control frames keep ordinary owned storage.
enum ClientUplink {
    Tun(TunPacket),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for ClientUplink {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Tun(packet) => packet,
            Self::Owned(packet) => packet,
        }
    }
}

/// Spawn one bonded stream's reader (decrypt → TUN-writer) and writer/heartbeat
/// tasks (outgoing plaintext → encrypt → socket). Returns the outgoing channel
/// the distributor feeds. `live` counts streams still up; this stream's death
/// (reader or writer) decrements it and fires `dead_tx` ONLY when it was the LAST
/// one — so losing one bonded stream degrades to the rest instead of tearing the
/// whole tunnel down (the server keeps the session alive while ≥1 stream remains).
#[allow(clippy::too_many_arguments)]
fn spawn_stream<R, W>(
    mut read_half: R,
    mut write_half: W,
    rx_codec: PacketCodec,
    tx_codec: PacketCodec,
    tun_write_tx: TunWriter,
    dead_tx: mpsc::Sender<()>,
    total_tx: Arc<AtomicU64>,
    total_rx: Arc<AtomicU64>,
    runtime: Arc<RuntimeCounters>,
    live: Arc<std::sync::atomic::AtomicUsize>,
    // Every task this stream spawns is registered here so the teardown can abort them.
    // Without it the caller had no handle at all: a reader parked in `read_record` on a
    // half-open connection outlived its connection generation, retaining its socket,
    // codecs and outbound channel. The shared TUN pump can now stop despite sender
    // clones, but the obsolete stream tasks still must not survive a reconnect.
    tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    cfg: StreamPump,
) -> mpsc::Sender<ClientUplink>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, mut out_rx) = mpsc::channel::<ClientUplink>(4096);
    let base = tokio::time::Instant::now();
    let last_rx = Arc::new(AtomicU64::new(0));
    // This stream counts itself as live; its first dying task (reader/writer)
    // decrements and, only if it was the last, signals a full-tunnel teardown.
    live.fetch_add(1, Ordering::AcqRel);
    let stream_dead = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Reader: socket → decrypt → TUN writer.
    //
    // For reality-tls (`cfg.pipeline_rx`) the receive side pays TWO AEAD layers
    // per packet: the outer TLS AES-GCM (performed inside `read_record`'s
    // `RealTlsStream`) and the inner qeli ChaCha20-Poly1305 (`decrypt_packet`).
    // Running them serially in one task pins both to one core. Instead we split
    // them into a 2-stage pipeline: this task reads + outer-decrypts + frames one
    // inner record and hands it to a second task that does the inner decrypt and
    // TUN write. A bounded FIFO between them preserves record order (both stages
    // stay single-threaded, so the outer TLS record sequence and the inner replay
    // window each still advance strictly in order). Every other mode keeps the
    // inline path — its `read_record` is cheap framing, so a pipeline hop would
    // only add latency.
    {
        let rx = rx_codec;
        let tun_write_tx = tun_write_tx.clone();
        let dead_tx = dead_tx.clone();
        let last_rx = last_rx.clone();
        let framing = cfg.framing;
        let stream_dead = stream_dead.clone();
        let live = live.clone();
        let total_rx = total_rx.clone();
        let runtime = runtime.clone();
        let record_pool = tun_write_tx.clone();

        // Where the reader sends each framed record. `Inline` decrypts in this
        // task (all non-reality modes, unchanged behaviour); `Pipe` forwards the
        // outer-decrypted record to the inner-decrypt task. Exactly one of these
        // exists per stream (never in a collection), so the size gap between the
        // codec-carrying `Inline` and the tiny `Pipe` is irrelevant — boxing the
        // codec would only add an indirection to the common inline path.
        #[allow(clippy::large_enum_variant)]
        enum RxSink {
            Inline { rx: PacketCodec, tun: TunWriter },
            Pipe(mpsc::Sender<PooledBuffer>),
        }

        let mut sink = if cfg.pipeline_rx {
            let (rec_tx, mut rec_rx) = mpsc::channel::<PooledBuffer>(1024);
            let mut inner_rx_codec = rx;
            let inner_tun = tun_write_tx;
            let inner_total_rx = total_rx.clone();
            let inner_runtime = runtime.clone();
            // Stage B: inner ChaCha decrypt → TUN. Ends when the reader drops
            // `rec_tx`. Never blocks (the TUN send is drop-on-full), so it always
            // drains the FIFO — the reader's backpressure send can therefore
            // always make progress (no deadlock).
            let __h = tokio::spawn(async move {
                while let Some(mut record) = rec_rx.recv().await {
                    match inner_rx_codec.decrypt_packet_in_place(record.as_vec_mut()) {
                        Ok(()) if !record.is_empty() => {
                            inner_total_rx.fetch_add(record.len() as u64, Ordering::Relaxed);
                            inner_runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
                            inner_runtime
                                .rx_bytes
                                .fetch_add(record.len() as u64, Ordering::Relaxed);
                            trace::record(trace::Dir::Rx, "client.tcp", record.len(), 0);
                            match inner_tun.try_send(record) {
                                Ok(()) => {}
                                Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                            }
                        }
                        Ok(()) => {}
                        Err(e) => log::debug!("Decrypt error: {}", e),
                    }
                }
            });
            crate::util::lock_or_recover(&tasks, "client::tasks").push(__h);
            RxSink::Pipe(rec_tx)
        } else {
            RxSink::Inline {
                rx,
                tun: tun_write_tx,
            }
        };

        // Stage A: socket read (+ outer decrypt/framing for reality-tls) → sink.
        let __h = tokio::spawn(async move {
            loop {
                let mut record = match record_pool.acquire().await {
                    Some(record) => record,
                    None => break,
                };
                match read_record_into(&mut read_half, framing, record.as_vec_mut()).await {
                    Ok(()) => {
                        last_rx.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                        match &mut sink {
                            RxSink::Inline { rx, tun } => {
                                match rx.decrypt_packet_in_place(record.as_vec_mut()) {
                                    Ok(()) if !record.is_empty() => {
                                        total_rx.fetch_add(record.len() as u64, Ordering::Relaxed);
                                        runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
                                        runtime
                                            .rx_bytes
                                            .fetch_add(record.len() as u64, Ordering::Relaxed);
                                        trace::record(
                                            trace::Dir::Rx,
                                            "client.tcp",
                                            record.len(),
                                            0,
                                        );
                                        match tun.try_send(record) {
                                            Ok(()) => {}
                                            Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                                            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                                break
                                            }
                                        }
                                    }
                                    Ok(()) => {}
                                    Err(e) => log::debug!("Decrypt error: {}", e),
                                }
                            }
                            // Hand the outer-decrypted record to the inner-decrypt
                            // task. `.send().await` applies backpressure rather than
                            // dropping — there is no `select!` in this loop, so a
                            // blocked send never cancels a partial `read_record`. A
                            // closed receiver means that task is gone → stop.
                            RxSink::Pipe(rec_tx) => {
                                if rec_tx.send(record).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Distinguish a clean close/EOF from a framing desync (the
                        // under-load PacketTooLarge / short-record case) so the latter is
                        // visible in logs — the reconnect path is the same either way.
                        match e {
                            crate::protocol::packet::PacketError::ConnectionClosed => {
                                log::debug!("Bonded stream read closed (clean)")
                            }
                            other => log::warn!(
                                "Bonded stream framing desync ({:?}) — reconnecting",
                                other
                            ),
                        }
                        break;
                    }
                }
            }
            // Stream lost (read side): tear down the whole tunnel only if this was
            // the last live stream; otherwise the tunnel keeps running on the rest.
            // Dropping `sink` here (its `Pipe` sender, if any) ends the inner task.
            if !stream_dead.swap(true, Ordering::AcqRel) {
                if live.fetch_sub(1, Ordering::AcqRel) <= 1 {
                    let _ = dead_tx.try_send(());
                } else {
                    log::info!(
                        "Bonded stream lost; {} stream(s) remain",
                        live.load(Ordering::Relaxed)
                    );
                }
            }
        });
        crate::util::lock_or_recover(&tasks, "client::tasks").push(__h);
    }

    // Writer + heartbeat: outgoing plaintext → encrypt → socket.
    {
        let mut tx = tx_codec;
        let dead_tx = dead_tx.clone();
        let stream_dead = stream_dead.clone();
        let live = live.clone();
        let __h = tokio::spawn(async move {
            let mut hb_tick = tokio::time::interval(cfg.heartbeat_interval);
            hb_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut idle_tick = tokio::time::interval(Duration::from_secs(5));
            idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_tick_wall = std::time::SystemTime::now();
            let mut last_tick_inst = tokio::time::Instant::now();
            let hb_ms = cfg.heartbeat_interval.as_millis() as u64;
            let idle_ms = cfg.idle_timeout.as_millis() as u64;
            let mut last_tx_ms: u64 = 0;
            // Flow-shaping: when enabled, idle cover at exponential (non-periodic)
            // gaps REPLACES the fixed heartbeat (client->server direction). Never
            // hold a `ThreadRng` across `.await` (it is `!Send`) — fresh per call.
            let mut shaper =
                crate::protocol::Shaper::new(cfg.shaping.clone(), std::time::Instant::now());
            let shaping_on = shaper.enabled();
            let heartbeat_enabled = cfg.heartbeat_enabled && !shaping_on;
            let rx_dead_ms = crate::protocol::liveness_deadline(
                heartbeat_enabled,
                cfg.heartbeat_interval,
                Duration::from_millis(cfg.hb_jitter),
                shaping_on,
                Duration::from_millis(cfg.shaping.idle_gap_max_ms),
            )
            .map(|deadline| u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX));
            let mut cover_deadline =
                tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());
            // One real record may have to stay intact while stealth pacing emits cover
            // records first, hence two connection-owned buffers. Both are allocated once
            // and reused by `encrypt_packet_into`; neither crosses to another task.
            let wire_capacity = crate::protocol::packet::TLS_RECORD_HEADER
                + crate::protocol::packet::MAX_RECORD_SIZE;
            let mut wire_record = Vec::with_capacity(wire_capacity);
            let mut cover_record = Vec::with_capacity(wire_capacity);
            let mut normalized_packet = Vec::with_capacity(1400);
            let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
            loop {
                tokio::select! {
                    biased;

                    Some(pt) = out_rx.recv() => {
                        // Normalize, pad and encrypt in a sub-scope so the (non-Send) RNG
                        // inside Obfuscator is dropped before the write .await. A pooled TUN
                        // buffer is borrowed directly; normalization, padding and wire records
                        // each use connection-owned storage for the lifetime of this writer.
                        let encrypted_data_len = {
                            let mut obf = Obfuscator::new();
                            let normalized = if cfg.norm_enabled && !cfg.norm_sizes.is_empty() {
                                // Same ceiling this block already uses for the pad cap
                                // below. A stream has no datagram to overflow, so this
                                // bounds the record rather than the path.
                                obf.normalize_packet_length_into(
                                    pt.as_ref(),
                                    &cfg.norm_sizes,
                                    1400,
                                    &mut normalized_packet,
                                );
                                Some(normalized_packet.as_slice())
                            } else {
                                None
                            };
                            let data = normalized.unwrap_or_else(|| pt.as_ref());
                            let pad_cap = {
                                let b = data.len().saturating_add(60);
                                (cfg.padding_max as usize).min(1400usize.saturating_sub(b)) as u16
                            };
                            obf.generate_padding_opts_into(
                                cfg.padding_enabled, cfg.padding_min, pad_cap,
                                cfg.padding_randomize, cfg.padding_prob, &mut padding,
                            );
                            tx.encrypt_packet_into(data, &padding, &mut wire_record)
                                .ok()
                                .map(|()| data.len())
                        };
                        // Return a pooled TUN allocation before pacing or socket I/O awaits.
                        drop(pt);
                        if let Some(data_len) = encrypted_data_len {
                            total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                            // Stealth: pace the uplink to stealth_rate; fill the gap
                            // with jittered small cover (size mix + non-metronome
                            // timing) instead of one smooth sleep.
                            let d = shaper.stealth_pace(wire_record.len(), std::time::Instant::now());
                            if shaper.stealth() && !d.is_zero() {
                                let mut remaining = d;
                                while remaining > Duration::from_millis(6) {
                                    let csize = shaper.next_size(&mut rand::rng());
                                    let cover_ready = if shaper.try_spend(csize, std::time::Instant::now()) {
                                        let mut obf = Obfuscator::new();
                                        obf.generate_padding_into(
                                            csize as u16,
                                            csize as u16,
                                            &mut padding,
                                        );
                                        tx.encrypt_packet_into(&[], &padding, &mut cover_record).is_ok()
                                    } else { false };
                                    if cover_ready
                                        && write_half.write_all(&cover_record).await.is_err()
                                    {
                                        break;
                                    }
                                    let step = Duration::from_millis(rand::rng().random_range(4..=18));
                                    let s = step.min(remaining);
                                    tokio::time::sleep(s).await;
                                    remaining = remaining.saturating_sub(s);
                                }
                            } else if !d.is_zero() {
                                tokio::time::sleep(d).await;
                            }
                            last_tx_ms = base.elapsed().as_millis() as u64;
                            if write_half.write_all(&wire_record).await.is_err() { break; }
                        }
                    }

                    _ = hb_tick.tick(), if heartbeat_enabled => {
                        let since = base.elapsed().as_millis() as u64 - last_tx_ms;
                        if since < hb_ms { continue; }
                        // The beat already fires on a fixed-interval tick and this sleep is
                        // ADDED to it, so a symmetric ±jitter is impossible by construction.
                        // Drawing from [0, 2*jitter) and saturating_sub'ing jitter (the old
                        // shape) put >50% of the mass at exactly 0 — mean ≈ jitter/4, i.e.
                        // much weaker aperiodicity than intended — and `jitter * 2` could
                        // overflow into an empty RNG range. Draw the delay directly instead.
                        let jitter = if cfg.hb_jitter > 0 {
                            let mut rng = rand::rng();
                            Duration::from_millis(rng.random_range(0..=cfg.hb_jitter))
                        } else { Duration::ZERO };
                        tokio::time::sleep(jitter).await;
                        let hb_ready = {
                            let mut obf = Obfuscator::new();
                            // saturating: hb_data is u16 and may be server-pushed.
                            obf.generate_padding_into(
                                cfg.hb_data,
                                cfg.hb_data.saturating_add(32),
                                &mut padding,
                            );
                            tx.encrypt_packet_into(&[], &padding, &mut cover_record).is_ok()
                        };
                        if hb_ready && write_half.write_all(&cover_record).await.is_err() {
                            break;
                        }
                        last_tx_ms = base.elapsed().as_millis() as u64;
                    }

                    _ = tokio::time::sleep_until(cover_deadline), if shaping_on => {
                        let now_ms = base.elapsed().as_millis() as u64;
                        // Fill genuine idle; in STEALTH run cover under load too so
                        // small cover mixes into the rate-capped stream (size tell).
                        if shaper.stealth() || now_ms.saturating_sub(last_tx_ms) >= 50 {
                            let size = shaper.next_size(&mut rand::rng());
                            if shaper.try_spend(size, std::time::Instant::now()) {
                                let cover_ready = {
                                    let mut obf = Obfuscator::new();
                                    obf.generate_padding_into(
                                        size as u16,
                                        size as u16,
                                        &mut padding,
                                    );
                                    tx.encrypt_packet_into(&[], &padding, &mut cover_record).is_ok()
                                };
                                if cover_ready {
                                    if write_half.write_all(&cover_record).await.is_err() { break; }
                                    last_tx_ms = base.elapsed().as_millis() as u64;
                                }
                            }
                        }
                        cover_deadline = tokio::time::Instant::now()
                            + shaper.next_gap(&mut rand::rng());
                    }

                    _ = idle_tick.tick() => {
                        // Propagate a read-side death (e.g. decrypt desync while the
                        // socket write side still looks alive) so this writer exits too.
                        if stream_dead.load(Ordering::Relaxed) { break; }
                        // `tokio::Instant` may freeze while a laptop sleeps whereas wall
                        // time keeps advancing. Cycle a half-open TCP carrier promptly on
                        // resume instead of waiting for the OS retransmit timeout.
                        let wall_gap = last_tick_wall.elapsed().unwrap_or_default();
                        last_tick_wall = std::time::SystemTime::now();
                        let tick_gap = last_tick_inst.elapsed();
                        last_tick_inst = tokio::time::Instant::now();
                        if wall_gap.saturating_sub(tick_gap) > Duration::from_secs(10) {
                            log::warn!(
                                "TCP: resumed from suspend (~{}s) — reconnecting",
                                wall_gap.as_secs()
                            );
                            // Our decision, not a fault: don't let it escalate the backoff.
                            DELIBERATE_CYCLE.store(true, std::sync::atomic::Ordering::Release);
                            break;
                        }
                        let now = base.elapsed().as_millis() as u64;
                        // An RX deadline is meaningful only when the peer promises
                        // inbound liveness traffic. With heartbeat and shaping disabled a
                        // healthy TCP tunnel may legitimately be silent for hours.
                        if let Some(rx_dead) = rx_dead_ms {
                            if now.saturating_sub(last_rx.load(Ordering::Relaxed)) > rx_dead {
                                break;
                            }
                        }
                        if idle_ms > 0 && now.saturating_sub(last_tx_ms) > idle_ms { break; }
                    }

                    else => break,
                }
            }
            // Stream lost (write side): tear down the whole tunnel only if this was
            // the last live stream; otherwise keep running on the remaining streams.
            if !stream_dead.swap(true, Ordering::AcqRel) {
                if live.fetch_sub(1, Ordering::AcqRel) <= 1 {
                    let _ = dead_tx.try_send(());
                } else {
                    log::info!(
                        "Bonded stream lost; {} stream(s) remain",
                        live.load(Ordering::Relaxed)
                    );
                }
            }
        });
        crate::util::lock_or_recover(&tasks, "client::tasks").push(__h);
    }

    out_tx
}

pub(crate) async fn run_tcp_tunnel<S>(
    mut stream: S,
    connector: StreamConnector<S>,
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut dyn ClientPlatform,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + crate::protocol::obfs::SplitStream,
{
    // Bound the qeli handshake by connection_timeout_secs. The reads inside
    // tcp_handshake are otherwise unbounded `.await`s, so a server that completes the
    // TCP/TLS connect and then goes silent would pin the client here forever — the
    // outer reconnect loop never re-runs because this future never returns. The timeout
    // wraps ONLY the handshake phase; once it returns, the data plane runs untimed.
    let hs_to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let client_device_id = core.device_id()?;
    let identity_verifier = core.identity_verifier(config);
    let (client_rx, client_tx, ok) = match tokio::time::timeout(
        hs_to,
        tcp_handshake(
            &mut stream,
            config,
            password,
            &client_device_id,
            identity_verifier.clone(),
        ),
    )
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "TCP handshake timed out after {}s (server accepted the connection but did \
                     not complete the qeli handshake)",
                hs_to.as_secs()
            ))
        }
    };
    let AuthOk {
        client_ip: client_ip_str,
        server_ip,
        prefix,
        mtu: pushed_mtu,
        dns_ip,
        dns_port,
        routes_json,
        pushed_obf,
        session_token,
        max_streams,
        adaptive,
    } = ok;
    // Multipath plan: the primary connection is stream #0; secondaries JOIN with
    // `session_token` (opened below — fixed fan-out, or adaptive ramp when `adaptive`).
    if max_streams > 1 {
        log::info!(
            "Multipath: server allows up to {} bonded streams (adaptive={}), token {}…",
            max_streams,
            adaptive,
            session_token.chars().take(8).collect::<String>()
        );
    }

    // Effective obfuscation = client config, with the data-phase params
    // (padding / heartbeat / traffic-normalization) overridden by whatever the
    // server pushed, so the two ends always agree without the client carrying
    // them in its config.
    let mut eff_obf = config.obfuscation.clone();
    if let Some(po) = pushed_obf.as_ref() {
        eff_obf.padding = po.padding.clone();
        eff_obf.heartbeat = po.heartbeat.clone();
        eff_obf.traffic_normalization = po.traffic_normalization.clone();
        eff_obf.traffic_shaping = po.traffic_shaping.clone();
    }

    // Bound once: the TUN is brought up with it, and it is reported to the server below so
    // the server's downlink respects it too (#13).
    let tun_mtu = effective_mtu(config.tun.mtu, pushed_mtu);
    let fallback_dns_servers = core.fallback_dns_servers().to_vec();
    let network = HandshakeNetwork {
        client_ip: &client_ip_str,
        prefix,
        tunnel_gateway: &server_ip,
        dns_ip: &dns_ip,
        dns_port: &dns_port,
        routes_json: &routes_json,
        mtu: tun_mtu,
        fallback_dns_servers: &fallback_dns_servers,
    };
    let mut plan = build_network_plan(config, core.next_generation(), &network)?;
    plan.max_streams = max_streams;
    plan.adaptive = adaptive;
    plan.data_plane = crate::transport_core::NetworkDataPlaneFacts::from_obfuscation(&eff_obf);
    plan.connection_log = server_push_log_lines(
        config,
        &plan,
        pushed_mtu,
        &dns_ip,
        &dns_port,
        &routes_json,
        pushed_obf.as_ref(),
    );
    for line in &plan.connection_log {
        log::info!("{line}");
    }
    let tunnel = core.prepare_tunnel(config, plan, &network)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let reader_fd = tunnel.reader_fd;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let writer_fd = tunnel.writer_fd;
    #[cfg(target_os = "linux")]
    let tun_name = tunnel.if_name;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let is_tap = tunnel.is_tap;
    #[cfg(target_os = "macos")]
    let is_tap = false;
    #[cfg(target_os = "linux")]
    let server_addr = pin_target(config);
    #[cfg(target_os = "linux")]
    let tunnel_tun = tunnel.tun;
    #[cfg(target_os = "linux")]
    let tap_mac = if is_tap { generate_mac() } else { [0u8; 6] };
    #[cfg(not(target_os = "linux"))]
    let tap_mac = [0u8; 6];
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let gateway_mac: [u8; 6] = if is_tap {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
    } else {
        [0u8; 6]
    };

    log::info!(
        "Client TAP MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        tap_mac[0],
        tap_mac[1],
        tap_mac[2],
        tap_mac[3],
        tap_mac[4],
        tap_mac[5]
    );

    let hb_config = &eff_obf.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let padding_min = eff_obf.padding.min_bytes;
    let padding_max = eff_obf.padding.max_bytes;
    let padding_enabled = eff_obf.padding.enabled;
    let padding_randomize = eff_obf.padding.randomize;
    let padding_prob = eff_obf.padding.probability;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let tun_buf_size = config
        .performance
        .tun_buffer_size
        .saturating_add(if cfg!(target_os = "macos") { 4 } else { 0 });
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;
    // Needed before the pump: the TUN writer thread owns the only place where an
    // `EAGAIN`/`ENOBUFS` drop is observable.
    let runtime_counters = core.counters();

    // Everything below can bail out through `?`, which would skip the teardown at the
    // end of this function; from here on the guard covers that (see `TunGuard`).
    #[cfg(target_os = "linux")]
    let mut tun_guard = TunGuard::new(
        tun_name.clone(),
        !config.tun.attach_existing,
        server_addr.clone(),
        config.routing.exclude.clone(),
    );
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let mut tun_pump = LinuxTunPump::start(
        reader_fd,
        writer_fd,
        LinuxTunPumpConfig {
            buffer_size: tun_buf_size,
            downlink_record_bytes: downlink_record_budget(tun_mtu, padding_max, norm_sizes),
            write_drops: Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
            framing: if cfg!(target_os = "macos") {
                TunFraming::Utun
            } else if is_tap {
                TunFraming::Tap(TapHeaders {
                    client_mac: tap_mac,
                    gateway_mac,
                })
            } else {
                TunFraming::Raw
            },
        },
    )?;
    #[cfg(target_os = "windows")]
    let mut tun_pump = match tunnel.windows_tun {
        WindowsTunSetup::Ring(adapter_name) => WindowsTunPump::open(
            &adapter_name,
            downlink_record_budget(tun_mtu, padding_max, norm_sizes),
            Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
        )?,
        WindowsTunSetup::Packet(packet_tun) => WindowsTunPump::packet(packet_tun),
    };
    #[cfg(target_os = "ios")]
    let mut tun_pump = tunnel.packet_tun;
    #[cfg(target_os = "linux")]
    tun_guard.attach_pump(tun_pump.stop_handle());
    let tun_write_tx = tun_pump.sender_to_tun();
    let cancel = core.cancel_token();
    // Keep one timer across select iterations. Recreating `sleep(100ms)` inside the loop
    // lets continuous packet readiness cancel it forever and can starve stop/reconnect.
    let mut cancel_tick = tokio::time::interval(Duration::from_millis(100));
    cancel_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cancel_tick.tick().await;

    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        30000
    });
    let idle_timeout = Duration::from_secs(config.performance.idle_timeout_secs);

    // Split the socket: a dedicated reader task makes record reads
    // cancellation-safe. `read_tls_record` loses a partially-read header if its
    // future is dropped, which `tokio::select!` does whenever another branch
    // fires — under bidirectional load that desynced the framing (PacketTooLarge
    // / connection drop). The writer stays in the select loop (writes inside a
    // branch body run to completion and are never cancelled).
    let (primary_r, primary_w) = stream.split_io();
    // Records on the wire are TLS-dressed for every mode except `plain`, which
    // uses bare length-prefixed framing (matching the codecs from the handshake).
    let framing = if config.obfuscation.mode == "plain" {
        Framing::Raw
    } else {
        Framing::Tls
    };

    // Any bonded stream fatal-erroring fires this → the whole tunnel reconnects
    // (P1: simplest correct behaviour; a finer policy can keep the session alive
    // on a single stream loss later).
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);
    // Live outgoing channels — one per active stream; the distributor round-robins
    // across them. The adaptive ramp task grows this Vec at runtime.
    // Handles for every task the bonded streams spawn, so the teardown can stop them.
    let stream_tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let outs: Arc<std::sync::Mutex<Vec<mpsc::Sender<ClientUplink>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // Bytes encrypted+sent across all streams (uplink half of the adaptive probe).
    let total_tx = Arc::new(AtomicU64::new(0));
    // Bytes decrypted+delivered to TUN across all streams (downlink half). Without
    // this the adaptive ramp is blind to download-only load and never grows past
    // one stream.
    let total_rx = Arc::new(AtomicU64::new(0));
    // Count of streams still up. A stream's death tears the tunnel down only when
    // this reaches 0 (losing one bonded stream just degrades to the rest).
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let pump = StreamPump {
        framing,
        heartbeat_enabled,
        heartbeat_interval,
        idle_timeout,
        hb_data: hb_config.data_size_bytes,
        hb_jitter: hb_config.jitter_ms,
        padding_enabled,
        padding_min,
        padding_max,
        padding_randomize,
        padding_prob,
        norm_enabled: eff_obf.traffic_normalization.enabled,
        norm_sizes: norm_sizes.clone(),
        shaping: eff_obf.traffic_shaping.to_shaping(),
        // Only reality-tls pays a second (outer TLS AES-GCM) AEAD on the read
        // side; pipeline its two decrypt layers across cores. Other modes decrypt
        // inline (unchanged path).
        pipeline_rx: config.obfuscation.mode == "reality-tls",
    };

    // Stream #0 = the primary (already authenticated) connection.
    crate::util::lock_or_recover(&outs, "client::outs").push(spawn_stream(
        primary_r,
        primary_w,
        client_rx,
        client_tx,
        tun_write_tx.clone(),
        dead_tx.clone(),
        total_tx.clone(),
        total_rx.clone(),
        runtime_counters.clone(),
        live.clone(),
        stream_tasks.clone(),
        pump.clone(),
    ));

    // Report our tunnel MTU (#13). The stream writer takes plaintext and encrypts it, so the
    // control frame goes out the same authenticated path as a packet — no special casing, and
    // padding/normalization on top are harmless because the frame carries its own length.
    // Matters on TCP too: the server sizes its downlink from the profile's `tun.mtu`, and a
    // packet larger than our TUN's MTU is dropped when we write it, transport regardless.
    if let Ok(mtu) = u16::try_from(tun_mtu.max(0)) {
        let frame = crate::protocol::ctrl::mtu_report(mtu);
        let sender = crate::util::lock_or_recover(&outs, "client::outs")
            .first()
            .cloned();
        if let Some(s) = sender {
            match s.try_send(ClientUplink::Owned(frame)) {
                Ok(()) => log::debug!("reported tunnel MTU {mtu} to the server"),
                Err(e) => log::debug!("could not report tunnel MTU: {e}"),
            }
        }
    }

    // Tell the server which build we are, so the operator's `list-clients` and the panel can
    // show it. Same authenticated path and the same fire-and-forget contract as the MTU
    // report above: an older server discards the frame as a malformed packet, and nothing
    // here waits for or depends on a reply.
    if let Some(frame) = crate::protocol::ctrl::this_build() {
        let sender = crate::util::lock_or_recover(&outs, "client::outs")
            .first()
            .cloned();
        if let Some(s) = sender {
            if let Err(e) = s.try_send(ClientUplink::Owned(frame)) {
                log::debug!("could not report client version: {e}");
            }
        }
    }

    // Stream-bonding plan. `max_streams` is the server's hard ceiling.
    let target = if max_streams > 1 {
        max_streams as usize
    } else {
        1
    };
    let token_bytes = hex_to_bytes(&session_token);
    let bonding = target > 1 && !token_bytes.is_empty();
    // The adaptive ramp decides the desired width; a separate maintainer restores
    // that width after individual bonded streams die. Fixed mode wants the full
    // configured width from the start (including retrying initial JOIN failures).
    let desired_streams = Arc::new(std::sync::atomic::AtomicUsize::new(
        if bonding && !adaptive { target } else { 1 },
    ));
    let next_join_index = Arc::new(std::sync::atomic::AtomicUsize::new(target.max(1)));
    let join_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Handle of the adaptive ramp task (if any) so teardown can abort it. Otherwise it
    // keeps opening bonded streams for an obsolete connection generation.
    let mut ramp_handle: Option<tokio::task::JoinHandle<()>> = None;

    if bonding && !adaptive {
        // FIXED: open the remaining streams now.
        for idx in 1..target {
            match connector().await {
                Ok(mut s) => {
                    // Bound the JOIN handshake too (parity with the primary): a stalled
                    // JOIN would otherwise hang this bonded-stream task forever, holding a
                    // tun_write_tx clone. It only degrades bonding (the primary survives).
                    let join = match tokio::time::timeout(
                        Duration::from_secs(config.server.connection_timeout_secs.max(1)),
                        tcp_join_handshake(
                            &mut s,
                            config,
                            &token_bytes,
                            idx as u8,
                            identity_verifier.clone(),
                        ),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_) => Err(anyhow::anyhow!("JOIN handshake timed out")),
                    };
                    match join {
                        Ok((rx, tx)) => {
                            let (r, w) = s.split_io();
                            crate::util::lock_or_recover(&outs, "client::outs").push(spawn_stream(
                                r,
                                w,
                                rx,
                                tx,
                                tun_write_tx.clone(),
                                dead_tx.clone(),
                                total_tx.clone(),
                                total_rx.clone(),
                                runtime_counters.clone(),
                                live.clone(),
                                stream_tasks.clone(),
                                pump.clone(),
                            ));
                        }
                        Err(e) => log::warn!("bonded stream #{} JOIN failed: {}", idx, e),
                    }
                }
                Err(e) => log::warn!("bonded stream #{} connect failed: {}", idx, e),
            }
        }
        log::info!(
            "Multipath: {} bonded stream(s) active (fixed)",
            crate::util::lock_or_recover(&outs, "client::outs").len()
        );
    } else if bonding && adaptive {
        // ADAPTIVE: ramp from 1 stream up based on measured throughput.
        let outs_r = outs.clone();
        let stream_tasks_r = stream_tasks.clone();
        let total_r = total_tx.clone();
        let total_rx_r = total_rx.clone();
        let tww = tun_write_tx.clone();
        let dead_r = dead_tx.clone();
        let pump_r = pump.clone();
        let conn_r = connector.clone();
        let cfg_r = std::sync::Arc::new(config.clone());
        let token_r = token_bytes.clone();
        let live_r = live.clone();
        let runtime_r = runtime_counters.clone();
        let identity_r = identity_verifier.clone();
        let desired_r = desired_streams.clone();
        let joining_r = join_in_flight.clone();
        ramp_handle = Some(tokio::spawn(async move {
            let mut last_bytes = 0u64;
            let mut best_rate = 0u64;
            let mut grace = 0u32;
            let mut idx = 1u8;
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let cur = crate::util::lock_or_recover(&outs_r, "client::outs_r").len();
                if cur >= target {
                    break;
                }
                let now_bytes =
                    total_r.load(Ordering::Relaxed) + total_rx_r.load(Ordering::Relaxed);
                let rate = now_bytes.saturating_sub(last_bytes) / 3; // bytes/s (up+down)
                last_bytes = now_bytes;
                let under_load = rate > 250_000; // >~2 Mbps — only ramp under demand
                let improving = rate > best_rate + best_rate / 10; // >10% over best
                if rate > best_rate {
                    best_rate = rate;
                }
                if !under_load {
                    continue;
                }
                if cur > 1 && !improving {
                    if grace > 0 {
                        // A stream was just added; let it fill for one more window
                        // before declaring a plateau (otherwise the ramp caps at 2).
                        grace -= 1;
                        continue;
                    }
                    log::info!("Multipath adaptive: plateau at {} stream(s)", cur);
                    break;
                }
                if joining_r
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                match conn_r().await {
                    // Bound the adaptive JOIN handshake as well (see the fixed path); flatten
                    // the timeout Elapsed into an Err so the existing match arms stay put.
                    Ok(mut s) => match tokio::time::timeout(
                        Duration::from_secs(cfg_r.server.connection_timeout_secs.max(1)),
                        tcp_join_handshake(&mut s, &cfg_r, &token_r, idx, identity_r.clone()),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("JOIN handshake timed out")))
                    {
                        Ok((rx, tx)) => {
                            let (r, w) = s.split_io();
                            crate::util::lock_or_recover(&outs_r, "client::outs_r").push(
                                spawn_stream(
                                    r,
                                    w,
                                    rx,
                                    tx,
                                    tww.clone(),
                                    dead_r.clone(),
                                    total_r.clone(),
                                    total_rx_r.clone(),
                                    runtime_r.clone(),
                                    live_r.clone(),
                                    stream_tasks_r.clone(),
                                    pump_r.clone(),
                                ),
                            );
                            idx = idx.wrapping_add(1);
                            desired_r.store(cur + 1, Ordering::Release);
                            grace = 1;
                            log::info!(
                                "Multipath adaptive: ramped to {} stream(s) ({} KB/s)",
                                cur + 1,
                                rate / 1000
                            );
                        }
                        Err(e) => log::warn!("adaptive JOIN failed: {}", e),
                    },
                    Err(e) => log::warn!("adaptive connect failed: {}", e),
                }
                joining_r.store(false, Ordering::Release);
            }
        }));
    }

    // Restore lost members of an established bond. Previously a dead secondary
    // merely reduced `live`; once the ramp task had ended nothing ever recreated
    // it, so a long-lived multipath session silently degraded to one stream.
    let maintenance_handle = if bonding {
        let outs_m = outs.clone();
        let stream_tasks_m = stream_tasks.clone();
        let total_m = total_tx.clone();
        let total_rx_m = total_rx.clone();
        let tww_m = tun_write_tx.clone();
        let dead_m = dead_tx.clone();
        let pump_m = pump.clone();
        let conn_m = connector.clone();
        let cfg_m = std::sync::Arc::new(config.clone());
        let token_m = token_bytes.clone();
        let live_m = live.clone();
        let desired_m = desired_streams.clone();
        let next_m = next_join_index.clone();
        let joining_m = join_in_flight.clone();
        let runtime_m = runtime_counters.clone();
        let identity_m = identity_verifier.clone();
        Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let desired = desired_m.load(Ordering::Acquire).min(target);
                if live_m.load(Ordering::Acquire) >= desired {
                    continue;
                }
                if joining_m
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }
                let raw_index = next_m.fetch_add(1, Ordering::AcqRel);
                if raw_index > u8::MAX as usize {
                    // JOIN derives per-stream state from the u8 index. Never wrap and
                    // reuse it in one session; reconnect to obtain a fresh session key.
                    log::warn!("Multipath JOIN index exhausted — reconnecting tunnel");
                    let _ = dead_m.try_send(());
                    joining_m.store(false, Ordering::Release);
                    break;
                }
                let joined = match conn_m().await {
                    Ok(mut stream) => tokio::time::timeout(
                        Duration::from_secs(cfg_m.server.connection_timeout_secs.max(1)),
                        tcp_join_handshake(
                            &mut stream,
                            &cfg_m,
                            &token_m,
                            raw_index as u8,
                            identity_m.clone(),
                        ),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("JOIN handshake timed out")))
                    .map(|(rx, tx)| (stream, rx, tx)),
                    Err(error) => Err(error),
                };
                match joined {
                    Ok((stream, rx, tx)) => {
                        let (reader, writer) = stream.split_io();
                        crate::util::lock_or_recover(&outs_m, "client::outs_m").push(spawn_stream(
                            reader,
                            writer,
                            rx,
                            tx,
                            tww_m.clone(),
                            dead_m.clone(),
                            total_m.clone(),
                            total_rx_m.clone(),
                            runtime_m.clone(),
                            live_m.clone(),
                            stream_tasks_m.clone(),
                            pump_m.clone(),
                        ));
                        log::info!(
                            "Multipath: restored bond to {}/{} live stream(s)",
                            live_m.load(Ordering::Acquire),
                            desired
                        );
                    }
                    Err(error) => log::warn!("Multipath replacement JOIN failed: {error}"),
                }
                joining_m.store(false, Ordering::Release);
            }
        }))
    } else {
        None
    };

    // Distributor: FLOW-PIN TUN packets across the live bonded streams (by inner
    // 5-tuple) so each connection stays in order. Each stream's tasks own
    // encrypt/heartbeat/idle; a dead stream fires dead_rx.
    let mut unsupported_inner_drops = 0u64;
    loop {
        tokio::select! {
            biased;

            _ = dead_rx.recv() => { break; }

            _ = cancel_tick.tick() => {
                if cancel.load(Ordering::Acquire) { break; }
            }

            packet = tun_pump.recv_from_tun() => {
                let Some(ip_packet) = packet else {
                    log::warn!("TCP: TUN reader stopped — reconnecting");
                    break;
                };
                if !is_supported_inner_packet(ip_packet.as_ref()) {
                    unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                    if unsupported_inner_drops.is_power_of_two() {
                        log::debug!(
                            "TCP client dropped unsupported non-IPv4 inner packet (total {})",
                            unsupported_inner_drops
                        );
                    }
                    continue;
                }
                trace::record(trace::Dir::Tx, "client.tcp", ip_packet.len(), 0);
                runtime_counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                runtime_counters
                    .tx_bytes
                    .fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
                // Pin by flow hash, lazily dropping any dead stream (closed channel)
                // and re-pinning onto a live one. When the last stream is gone the
                // per-stream death handler has already fired `dead_rx`.
                let mut g = crate::util::lock_or_recover(&outs, "client::outs");
                let h = crate::protocol::flow_hash(ip_packet.as_ref());
                let mut pkt = ClientUplink::Tun(ip_packet);
                while !g.is_empty() {
                    let i = (h % g.len() as u64) as usize;
                    match g[i].try_send(pkt) {
                        Ok(()) => break,
                        // Backpressure on the pinned stream: drop (inner TCP retransmits).
                        Err(mpsc::error::TrySendError::Full(_)) => break,
                        // Dead stream: remove it and re-pin (hash modulo the new len).
                        Err(mpsc::error::TrySendError::Closed(v)) => {
                            pkt = v;
                            g.remove(i);
                        }
                    }
                }
            }

            else => break,
        }
    }

    // Stop the adaptive ramp task first: it loops indefinitely trying to add bonded
    // streams and must not create sockets for an obsolete connection generation.
    if let Some(h) = ramp_handle {
        h.abort();
    }
    if let Some(h) = maintenance_handle {
        h.abort();
    }
    // Same reasoning for the per-stream tasks. A reader can sit in `read_record` on a
    // half-open socket forever; abort cancels it at that await point before the shared
    // TUN backend releases this generation's descriptors.
    for h in crate::util::lock_or_recover(&stream_tasks, "client::stream_tasks").drain(..) {
        h.abort();
    }
    #[cfg(target_os = "linux")]
    let dns_cleanup_error = dns::restore_dns_for(&tun_name).err();
    drop(tun_write_tx);
    tun_pump.shutdown().await;
    // Closes the TUN fd: `TunInterface` holds it as a `File`. (Do NOT also close the raw
    // number — that would be a double close, and the freed number can already have been
    // handed to another thread's socket.)
    #[cfg(target_os = "linux")]
    drop(tunnel_tun);
    // Attach mode: the interface + routes belong to an external owner — leave them
    // (we only borrowed the fd). Otherwise remove the device + routes we created.
    #[cfg(target_os = "linux")]
    let tun_cleanup_error = if !config.tun.attach_existing {
        cleanup_owned_tun(&tun_name, &server_addr, &config.routing.exclude).err()
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    match (dns_cleanup_error, tun_cleanup_error) {
        (None, None) => {}
        (Some(dns), None) => return Err(anyhow::anyhow!("DNS cleanup failed: {dns}")),
        (None, Some(tun)) => return Err(tun),
        (Some(dns), Some(tun)) => {
            return Err(anyhow::anyhow!("DNS cleanup failed: {dns}; {tun}"));
        }
    }
    #[cfg(target_os = "linux")]
    tun_guard.disarm(); // graceful teardown done — nothing left for `Drop` to repeat
    log::info!("Client disconnected");
    Ok(())
}

/// Load (or first-time generate + persist) this client's stable device id. Stored
/// at a fixed state path; an unwritable host falls back to a per-run random id
/// (still works — just not stable across restarts there).
#[cfg(target_os = "linux")]
fn device_id() -> [u8; crate::protocol::DEVICE_ID_LEN] {
    // `QELI_DEVICE_ID_FILE` overrides the path (lets several instances on one host —
    // or tests — keep distinct device ids).
    let path = std::env::var("QELI_DEVICE_ID_FILE")
        .unwrap_or_else(|_| "/var/lib/qeli/device-id".to_string());
    device_id_at(&path)
}

#[cfg(target_os = "linux")]
fn device_id_at(path: &str) -> [u8; crate::protocol::DEVICE_ID_LEN] {
    let read_valid = || {
        let bytes = std::fs::read(path).ok()?;
        let id: [u8; crate::protocol::DEVICE_ID_LEN] = bytes
            .get(..crate::protocol::DEVICE_ID_LEN)?
            .try_into()
            .ok()?;
        (id != [0u8; crate::protocol::DEVICE_ID_LEN]).then_some(id)
    };
    if let Some(id) = read_valid() {
        return id;
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Serialize first creation across processes, then re-read after taking the
    // lock in case another client won the race while we were waiting.
    let lock = match crate::util::FileLock::acquire(path) {
        Ok(lock) => Some(lock),
        Err(error) => {
            log::warn!("device id will be per-run because '{path}' cannot be locked: {error}");
            None
        }
    };
    if lock.is_some() {
        if let Some(id) = read_valid() {
            return id;
        }
    }

    use rand::prelude::*;
    let mut id = [0u8; crate::protocol::DEVICE_ID_LEN];
    rand::rng().fill_bytes(&mut id);
    if lock.is_some() {
        if let Err(error) = crate::util::write_atomic_private(path, &id) {
            log::warn!("device id could not be persisted at '{path}': {error}");
        }
    }
    id
}

async fn tcp_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    password: &str,
    client_device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<(PacketCodec, PacketCodec, AuthOk)> {
    authenticate_tcp(
        stream,
        config,
        password,
        client_device_id,
        move |received| identity_verifier(received),
    )
    .await
}

/// Inner qeli handshake for a SECONDARY bonded connection (stream bonding): the
/// SAME fake-TLS KE + server-identity verify as the primary, but presents the
/// per-session JOIN token instead of credentials. Returns the stream's own
/// codecs. Only used for reality-tls/fake-tls inner (the modes that wire bonding).
async fn tcp_join_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    token: &[u8],
    stream_index: u8,
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<(PacketCodec, PacketCodec)> {
    let client_kp = Keypair::generate();

    // `plain` wire mode: no TLS mimicry — raw X25519 exchange + raw-framed records,
    // then present the JOIN token instead of credentials. Mirrors the plain branch
    // of `tcp_handshake`.
    if config.obfuscation.mode == "plain" {
        stream.write_all(client_kp.public().as_bytes()).await?;
        let mut sp = [0u8; 32];
        stream
            .read_exact(&mut sp)
            .await
            .map_err(|e| anyhow::anyhow!("JOIN(plain): read server key: {}", e))?;
        let server_pub = crate::crypto::PublicKey::from_bytes(&sp);
        let transcript_hash = handshake_transcript_hash(&[client_kp.public().as_bytes(), &sp]);
        let shared = client_kp
            .derive_shared_checked(&server_pub)
            .ok_or_else(|| anyhow::anyhow!("JOIN(plain): rejected low-order server key"))?;
        let (server_to_client, client_to_server) = match static_es(config, &client_kp)? {
            Some(es) => derive_keys_bound(&shared.0, &es),
            None => derive_keys(&shared.0),
        };
        let mut client_rx = PacketCodec::new_raw(server_to_client);
        let mut client_tx = PacketCodec::new_raw(client_to_server);
        let auth_proof_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|e| anyhow::anyhow!("JOIN(plain): auth proof: {}", e))?;
        let auth_proof_msg = client_rx.decrypt_packet(&auth_proof_record)?;
        let server_static_pub_bytes = verify_server_identity(
            &auth_proof_msg,
            &client_kp,
            &shared.0,
            &transcript_hash,
            &config.auth.server_public_key,
        )?;
        identity_verifier(server_static_pub_bytes).await?;
        let mut join = Vec::with_capacity(crate::protocol::JOIN_MAGIC.len() + token.len() + 1);
        join.extend_from_slice(crate::protocol::JOIN_MAGIC.as_slice());
        join.extend_from_slice(token);
        join.push(stream_index);
        let join_packet = client_tx.encrypt_packet(&join, &[])?;
        stream.write_all(&join_packet).await?;
        let ack_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|e| anyhow::anyhow!("JOIN(plain): ack: {}", e))?;
        let ack = client_rx.decrypt_packet(&ack_record)?;
        if ack != b"JOINOK" {
            return Err(anyhow::anyhow!("JOIN(plain) rejected by server"));
        }
        log::info!("Bonded stream #{} joined (plain)", stream_index);
        return Ok((client_rx, client_tx));
    }

    let server_name: &str = match config.obfuscation.sni.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => pick_random_sni(),
        _ => &config.server.address,
    };
    let reality_sid: Option<[u8; 32]> = match (
        config
            .obfuscation
            .reality_short_id
            .as_deref()
            .filter(|s| !s.is_empty()),
        config
            .auth
            .server_public_key
            .as_deref()
            .filter(|s| !s.is_empty())
            .and_then(crate::crypto::parse_pubkey_hex),
    ) {
        (Some(sid_hex), Some(pk)) => {
            let reality_pub = crate::crypto::PublicKey::from_bytes(&pk);
            let short_id = crate::crypto::reality::short_id_from_hex(sid_hex);
            Some(crate::crypto::reality::seal_session_id(
                &reality_pub,
                &client_kp,
                &short_id,
            ))
        }
        _ => None,
    };
    let (client_hello, mlkem_dk) = FakeTlsHandshake::build_client_hello_pq(
        client_kp.public(),
        server_name,
        0,
        reality_sid.as_ref(),
    );
    stream.write_all(&client_hello).await?;
    let server_hello_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: ServerHello: {}", e))?;
    let (mlkem_ct, server_x25519) =
        FakeTlsHandshake::parse_server_hello_pq(&server_hello_record)
            .ok_or_else(|| anyhow::anyhow!("JOIN: parse hybrid ServerHello"))?;
    let server_pub = crate::crypto::PublicKey::from_bytes(&server_x25519);
    let ccs = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: ChangeCipherSpec: {}", e))?;
    if ccs.first() != Some(&0x14) {
        anyhow::bail!("JOIN: expected ChangeCipherSpec before the encrypted handshake flight");
    }
    let cert_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: Certificate: {}", e))?;
    let finished_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: Finished: {}", e))?;
    let _nst = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: NewSessionTicket: {}", e))?;
    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("JOIN: rejected low-order server key"))?;
    let mlkem_ss = crate::crypto::mlkem::mlkem768_decapsulate(&mlkem_dk, &mlkem_ct)
        .ok_or_else(|| anyhow::anyhow!("JOIN: ML-KEM decapsulation failed"))?;
    let mlkem_shared: [u8; 32] = mlkem_ss
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("JOIN: ML-KEM shared secret not 32 bytes"))?;
    let (server_to_client, client_to_server) = match static_es(config, &client_kp)? {
        Some(es) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, &es),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };
    let mut client_rx = PacketCodec::new(server_to_client);
    let mut client_tx = PacketCodec::new(client_to_server);
    let transcript_hash = handshake_transcript_hash(&[
        &client_hello,
        &server_hello_record,
        &cert_record,
        &finished_record,
    ]);
    let auth_proof_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: auth proof: {}", e))?;
    let auth_proof_msg = client_rx.decrypt_packet(&auth_proof_record)?;
    let server_static_pub_bytes = verify_server_identity(
        &auth_proof_msg,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &config.auth.server_public_key,
    )?;
    identity_verifier(server_static_pub_bytes).await?;

    // Present the session JOIN token (instead of credentials).
    let mut join = Vec::with_capacity(crate::protocol::JOIN_MAGIC.len() + token.len() + 1);
    join.extend_from_slice(crate::protocol::JOIN_MAGIC.as_slice());
    join.extend_from_slice(token);
    join.push(stream_index);
    let join_packet = client_tx.encrypt_packet(&join, &[])?;
    stream.write_all(&join_packet).await?;

    let ack_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: ack: {}", e))?;
    let ack = client_rx.decrypt_packet(&ack_record)?;
    if ack != b"JOINOK" {
        return Err(anyhow::anyhow!("JOIN rejected by server"));
    }
    log::info!("Bonded stream #{} joined", stream_index);
    Ok((client_rx, client_tx))
}

/// Decode a lowercase-hex string to bytes (for the session token).
fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

#[cfg(target_os = "windows")]
pub(crate) enum WindowsTunSetup {
    Ring(String),
    Packet(crate::transport_core::packet_tun::PacketTunPump),
}

pub(crate) struct TunnelSetup {
    #[cfg(target_os = "linux")]
    tun: TunInterface,
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    reader_fd: OwnedFd,
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    writer_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    if_name: String,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    is_tap: bool,
    #[cfg(target_os = "windows")]
    windows_tun: WindowsTunSetup,
    #[cfg(target_os = "ios")]
    packet_tun: crate::transport_core::packet_tun::PacketTunPump,
}

impl TunnelSetup {
    #[cfg(any(target_os = "android", target_os = "macos"))]
    pub(crate) fn external(reader_fd: OwnedFd, writer_fd: OwnedFd) -> Self {
        Self {
            reader_fd,
            writer_fd,
            #[cfg(target_os = "android")]
            is_tap: false,
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn wintun(adapter_name: String) -> Self {
        Self {
            windows_tun: WindowsTunSetup::Ring(adapter_name),
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn packet(packet_tun: crate::transport_core::packet_tun::PacketTunPump) -> Self {
        Self {
            windows_tun: WindowsTunSetup::Packet(packet_tun),
        }
    }

    #[cfg(target_os = "ios")]
    pub(crate) fn packet(packet_tun: crate::transport_core::packet_tun::PacketTunPump) -> Self {
        Self { packet_tun }
    }
}

/// Unconditional TUN teardown, for the paths the graceful one cannot reach.
///
/// The cleanup at the end of `run_tcp_tunnel` / `connect_and_run_udp` runs only when
/// the data plane exits NORMALLY. Every `?` in those functions — the uplink dying when
/// a modem is power-cycled, say — returns early and skips the route/DNS/device teardown.
/// The shared TUN pump releases its `OwnedFd` workers on `Drop`, but it deliberately does
/// not own these platform resources.
///
/// This guard carries the platform parts that must happen no matter how we leave: request
/// pump cancellation before touching the device, restore the resolver, and remove the
/// interface and routes we installed. The normal path `disarm()`s it after the fuller
/// graceful sequence, whose `.await`s are impossible in `Drop`.
#[cfg(target_os = "linux")]
struct TunGuard {
    if_name: String,
    stop: Option<LinuxTunPumpStop>,
    /// Attach mode borrows an externally-owned device: pump packets, never tear down.
    owns_device: bool,
    server_addr: String,
    exclude: Vec<String>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl TunGuard {
    fn new(if_name: String, owns_device: bool, server_addr: String, exclude: Vec<String>) -> Self {
        Self {
            if_name,
            stop: None,
            owns_device,
            server_addr,
            exclude,
            armed: true,
        }
    }

    fn attach_pump(&mut self, stop: LinuxTunPumpStop) {
        self.stop = Some(stop);
    }

    /// Called once the graceful teardown has run, so `Drop` does not repeat it.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

/// Remove every host resource owned by a non-attach client generation. Attempt both halves
/// even when one fails: routes on the physical interface can survive a failed TUN deletion,
/// while deleting the interface does not prove that independently installed bypass routes
/// were removed.
#[cfg(target_os = "linux")]
fn cleanup_owned_tun(if_name: &str, server_addr: &str, exclude: &[String]) -> anyhow::Result<()> {
    let route_error = route::cleanup_routes(if_name, server_addr, exclude).err();
    let tun_error = TunInterface::delete(if_name).err();
    match (route_error, tun_error) {
        (None, None) => Ok(()),
        (Some(routes), None) => Err(anyhow::anyhow!("route cleanup failed: {routes}")),
        (None, Some(tun)) => Err(anyhow::anyhow!("TUN deletion failed: {tun}")),
        (Some(routes), Some(tun)) => Err(anyhow::anyhow!(
            "route cleanup failed: {routes}; TUN deletion failed: {tun}"
        )),
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        log::warn!(
            "connection ended on an error path — releasing TUN {}",
            self.if_name
        );
        // Ask both workers to stop before deleting the device. The descriptors are not
        // closed here directly: their OwnedFd values live in the workers and closing a
        // raw number concurrently with read/write could target a subsequently reused fd.
        if let Some(stop) = &self.stop {
            stop.request_stop();
        }
        if let Err(error) = dns::restore_dns_for(&self.if_name) {
            log::error!("TUN guard DNS cleanup failed: {error}");
        }
        if self.owns_device {
            if let Err(error) = cleanup_owned_tun(&self.if_name, &self.server_addr, &self.exclude) {
                log::error!("TUN guard cleanup failed: {error}");
            }
        }
    }
}

/// PIDs holding an open `/dev/net/tun` fd attached to `if_name`.
///
/// A tun fd's `/proc/<pid>/fdinfo/<fd>` carries an `iff:` line naming the device it is
/// attached to — the only reliable way to tell who owns an interface. Needs root (the
/// client already requires it for TUN); entries we cannot read are skipped, so the
/// result is "who we can PROVE holds it", which is why the caller treats an empty
/// answer as "not ours" rather than "free to take".
#[cfg(target_os = "linux")]
fn tun_fd_holders(if_name: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for proc in procs.flatten() {
        let Some(pid) = proc
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue; // not a pid entry
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else {
            continue; // process vanished mid-scan, or not inspectable
        };
        for fd in fds.flatten() {
            // Cheap filter first: only a /dev/net/tun fd can be attached to a device,
            // and a readlink is far cheaper than reading every fdinfo in the system.
            if std::fs::read_link(fd.path())
                .map(|t| t != std::path::Path::new("/dev/net/tun"))
                .unwrap_or(true)
            {
                continue;
            }
            let Some(fd_num) = fd.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(info) = std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", pid, fd_num))
            else {
                continue;
            };
            if info.lines().any(|l| {
                l.strip_prefix("iff:")
                    .map(|v| v.trim() == if_name)
                    .unwrap_or(false)
            }) {
                pids.push(pid);
                break; // one attached fd is enough to call this pid a holder
            }
        }
    }
    pids
}

/// Decide what to do about an interface that is already present when we are about to
/// create one, and reclaim it when it is provably our own leftover.
///
/// This used to be an unconditional error, reasoning that our device is non-persistent
/// and so cannot outlive us. That misses the case it most needs to handle: an in-process
/// reconnect after the data plane exited on an error path, where a leaked reader thread
/// in THIS process still holds the fd. The device is then very much alive, and refusing
/// it means every later reconnect fails identically — forever.
///
/// The ownership test follows from non-persistence:
///   * not a tuntap device -> someone else's (ethernet/WireGuard/…) -> refuse
///   * held by another pid -> another app, or a second qeli -> refuse
///   * held by nobody -> only a PERSISTENT device survives with no fd, and ours never
///     are, so it was created by someone else -> refuse
///   * held only by us -> our own leftover -> reclaim
#[cfg(target_os = "linux")]
fn reclaim_stale_tun(if_name: &str) -> anyhow::Result<()> {
    let advice = "Set 'dev=<name>' in [qeli] to use a different interface name (or \
                  'dev_attach=true' to attach to an externally-owned interface).";
    // Only tuntap devices expose tun_flags, so its absence settles the question.
    if !std::path::Path::new(&format!("/sys/class/net/{}/tun_flags", if_name)).exists() {
        anyhow::bail!(
            "interface '{}' already exists and is not a TUN/TAP device — refusing to touch \
             it. {}",
            if_name,
            advice
        );
    }
    let me = std::process::id();
    let holders = tun_fd_holders(if_name);
    let foreign: Vec<u32> = holders.iter().copied().filter(|&p| p != me).collect();
    if !foreign.is_empty() {
        anyhow::bail!(
            "interface '{}' already exists and is held by another process (pid {:?}) — \
             refusing to take it over. {}",
            if_name,
            foreign,
            advice
        );
    }
    if holders.is_empty() {
        anyhow::bail!(
            "interface '{}' already exists with no process attached, so it is a persistent \
             device someone else created (ours never are) — refusing to delete it. {}",
            if_name,
            advice
        );
    }

    // Held only by us: a previous connection in this process leaked it.
    log::warn!(
        "interface '{}' is left over from a previous connection in this process — reclaiming it",
        if_name
    );
    // Best effort only: `ip tuntap del` fails with EINVAL while a queue is still attached,
    // which is precisely the state we are in — the previous reader has not let go yet. It
    // is the LAST fd closing that removes a non-persistent device, so this is a nudge (and
    // clears the persist flag in the odd case one got set), not the mechanism.
    if let Err(e) = TunInterface::delete(if_name) {
        log::debug!(
            "reclaiming '{}': still attached ({}) — waiting for the previous reader to \
             close its fd",
            if_name,
            e
        );
    }

    // The device goes away once its last fd closes, which the teardown guard guarantees by
    // stopping that reader — so wait for it instead of racing it. Attaching while it still
    // holds a queue would be worse than failing: the kernel would split arriving packets
    // between the live reader and the dead one, silently blackholing half the tunnel.
    // Blocking here is safe: what we wait on are plain threads, not tasks.
    let sysfs = format!("/sys/class/net/{}", if_name);
    for _ in 0..120 {
        if !std::path::Path::new(&sysfs).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    anyhow::bail!(
        "interface '{}' is still held open after reclaiming it (a previous reader thread has \
         not exited) — not attaching, as sharing the device would blackhole traffic. {}",
        if_name,
        advice
    )
}

/// Set `IP_MTU_DISCOVER` on the raw UDP fd (Linux). `PROBE` sets DF and ignores the
/// kernel's cached PMTU (so we can probe freely); `DO` keeps DF for the data plane;
/// `DONT` allows fragmentation (the behaviour we restore if probing can't complete).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_pmtudisc(fd: std::os::unix::io::RawFd, mode: libc::c_int) -> bool {
    let v: libc::c_int = mode;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_pmtudisc(socket.as_raw_fd(), libc::IP_PMTUDISC_PROBE)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_pmtudisc(
        socket.as_raw_fd(),
        if success {
            libc::IP_PMTUDISC_DO
        } else {
            libc::IP_PMTUDISC_DONT
        },
    );
}

/// Darwin exposes a boolean DF control rather than Linux's three-state PMTU policy. Probes
/// still get the property we need: an oversized datagram fails locally instead of fragmenting.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_dont_fragment(fd: std::os::unix::io::RawFd, enabled: bool) -> bool {
    const IP_DONTFRAG: libc::c_int = 28;
    let value: libc::c_int = i32::from(enabled);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_DONTFRAG,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_dont_fragment(socket.as_raw_fd(), true)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_dont_fragment(socket.as_raw_fd(), success);
}

/// Winsock's IP_DONTFRAGMENT option (14) is a BOOL on an IPv4 UDP socket. Keeping this tiny
/// declaration local avoids adding a Windows-only dependency to router/server builds.
#[cfg(target_os = "windows")]
fn set_dont_fragment(socket: std::os::windows::io::RawSocket, enabled: bool) -> bool {
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(
            socket: usize,
            level: i32,
            option_name: i32,
            option_value: *const i8,
            option_length: i32,
        ) -> i32;
    }
    const IPPROTO_IP: i32 = 0;
    const IP_DONTFRAGMENT: i32 = 14;
    let value: i32 = i32::from(enabled);
    unsafe {
        setsockopt(
            socket as usize,
            IPPROTO_IP,
            IP_DONTFRAGMENT,
            &value as *const i32 as *const i8,
            std::mem::size_of::<i32>() as i32,
        ) == 0
    }
}

#[cfg(target_os = "windows")]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_dont_fragment(socket.as_raw_socket(), true)
}

#[cfg(target_os = "windows")]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_dont_fragment(socket.as_raw_socket(), success);
}

/// Active path-MTU discovery on a UDP transport (Linux). Sends DF-marked probe
/// datagrams from `ceiling` down a small ladder; each probe's wire size equals a
/// full data packet of the candidate tunnel MTU, so the largest one the server
/// echoes is a size that traverses the path unfragmented. Returns that MTU, or
/// `None` (→ caller keeps the pushed/effective MTU) on any failure — probing is
/// purely additive and never makes connectivity worse (DF is dropped again on miss).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
async fn probe_udp_mtu(
    socket: &crate::protocol::obfs::ObfsUdp,
    quic_enabled: bool,
    connection_id: &[u8; 4],
    quic_pn: &mut u32,
    ceiling: i32,
) -> Option<i32> {
    use crate::protocol::udp_frag::{is_mtu_probe_ack, mtu_probe_datagram, parse_mtu_probe};
    use std::time::Duration;
    // qeli UDP record overhead (nonce+counter+tag+padlen+framing) + a small margin, so
    // a probe that fits certifies a real full-MTU data packet also fits.
    const REC_OVERHEAD: usize = 48;
    if !begin_mtu_probe(socket) {
        return None;
    }
    // How many bytes of the PATH a probe for tunnel-MTU `m` occupies beyond `m` itself:
    // our record overhead, the obfs seal, the QUIC short header, and the UDP + IP headers.
    //
    // This is the difference the ladder used to ignore. `m` is an INNER (tunnel) MTU, but
    // the rungs were the IPv6 minimum PATH mtu — so the lowest rung, 1280, actually asked
    // the path for ~1280 + overhead bytes. On a path whose real MTU is 1280 every rung
    // therefore failed, the probe reported nothing, and the caller fell back to the pushed
    // MTU (typically 1400) with fragmentation re-enabled: the exact outcome probing exists
    // to avoid. Derive the floor from the overhead actually in play instead of hard-coding
    // a number that silently means something else. (Audit 2026-07-29, #12.)
    let outer_overhead = REC_OVERHEAD
        + socket.seal_overhead()
        + if quic_enabled {
            crate::protocol::quic::QUIC_SHORT_HEADER_MIN
        } else {
            0
        }
        + 8 // UDP header
        + if socket.peer_is_ipv6() { 40 } else { 20 };
    let ladder = mtu_probe_ladder(ceiling, outer_overhead);

    let mut buf = vec![0u8; 2048];
    // Randomize the probe-id sequence per connection. A fixed start (0x4D54 "MT") + a
    // predictable +1 per rung let an off-path attacker forge a probe-ACK and pin the client
    // to a too-large MTU (a DoS on fake-tls-UDP-without-obfs, where the probe rides in the
    // clear). A random 16-bit start means the attacker must also guess the id.
    let mut probe_id: u16 = rand::rng().random();

    // One rung: send up to twice, accept only an ACK echoing this id AND this size.
    //
    // Requiring the echoed SIZE as well as the id is what stops a stale or forged ACK for a
    // different rung from pinning the client to an MTU the path cannot carry.
    macro_rules! try_mtu {
        ($m:expr) => {{
            let m: i32 = $m;
            probe_id = probe_id.wrapping_add(1);
            let probe_size = (m as usize + REC_OVERHEAD) as u16;
            match mtu_probe_datagram(probe_id, m as usize + REC_OVERHEAD) {
                None => false,
                Some(probe) => {
                    let pkt = if quic_enabled {
                        let w = wrap_quic_short(&probe, connection_id, *quic_pn);
                        *quic_pn = quic_pn.wrapping_add(1);
                        w
                    } else {
                        probe
                    };
                    let mut ok = false;
                    for _ in 0..2u8 {
                        // EMSGSIZE = the local link is smaller than this probe → size fails.
                        if socket.send(&pkt).await.is_err() {
                            break;
                        }
                        match tokio::time::timeout(
                            Duration::from_millis(220),
                            socket.recv(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                let payload = if quic_enabled {
                                    unwrap_quic(&buf[..n])
                                        .map(|p| p.payload)
                                        .unwrap_or_default()
                                } else {
                                    buf[..n].to_vec()
                                };
                                if is_mtu_probe_ack(&payload)
                                    && parse_mtu_probe(&payload) == Some((probe_id, probe_size))
                                {
                                    ok = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    ok
                }
            }
        }};
    }

    // Coarse pass: walk the rungs high to low and keep the first that answers, remembering the
    // lowest rung that did NOT — that pair brackets the path's real MTU.
    let mut found: Option<i32> = None;
    let mut failed_above: Option<i32> = None;
    for m in ladder {
        if try_mtu!(m) {
            found = Some(m);
            break;
        }
        failed_above = Some(m);
    }

    // Refinement: the coarse pass certifies the best rung that FITS, which is not the path's
    // maximum. With rungs at 9000 and 6000 a 8999-byte path was pinned to 6000 and threw away
    // a third of every frame — the ladder can only ever land on one of its own numbers, so no
    // amount of adding rungs fixes this in general, it just moves the loss around.
    //
    // Binary-search the open interval between the rung that answered and the lowest one that
    // did not. Each step is one probe, so the cost is bounded by the iteration cap rather than
    // by the size of the gap, and the invariant is simple: `lo` has always been proven to work,
    // so a refinement that finds nothing better still returns the coarse result. STEP is the
    // point of diminishing returns — chasing the last few dozen bytes is not worth a round
    // trip, and stopping on it also bounds the loop for a huge gap. (Audit 2026-08-01, §8.)
    if let (Some(lo0), Some(hi0)) = (found, failed_above) {
        let (mut lo, mut hi) = (lo0, hi0);
        for _ in 0..MTU_REFINE_MAX_PROBES {
            let Some(mid) = mtu_refine_step(lo, hi) else {
                break;
            };
            if try_mtu!(mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        if lo > lo0 {
            log::debug!("path-MTU probe: refined {lo0} -> {lo} (upper bound {hi0})");
        }
        found = Some(lo);
    }
    // Keep DF for the data plane on success (packets ≤ the discovered MTU never
    // fragment); restore fragmentation-allowed on a miss so behaviour is unchanged.
    finish_mtu_probe(socket, found.is_some());
    found
}

/// Stop refining once the bracket is this narrow. Chasing the last few dozen bytes is not
/// worth a round trip, and the threshold also bounds the loop for a very wide gap.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) const MTU_REFINE_STEP: i32 = 256;

/// Hard cap on refinement probes, so a pathological bracket cannot stretch the handshake.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) const MTU_REFINE_MAX_PROBES: u8 = 5;

/// Next size to try between a rung known to WORK (`lo`) and one known to FAIL (`hi`), or
/// `None` when the bracket is narrow enough to stop.
///
/// Split out of the probe loop so the search itself is testable without a socket: the loop
/// contributes only "send and wait", and everything that decides *which* size to ask about
/// lives here.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) fn mtu_refine_step(lo: i32, hi: i32) -> Option<i32> {
    if hi - lo <= MTU_REFINE_STEP {
        return None;
    }
    Some(lo + (hi - lo) / 2)
}

/// Rungs of the path-MTU ladder, in TUNNEL (inner) MTU units, highest first.
///
/// `outer_overhead` is everything a probe for tunnel-MTU `m` adds on the wire: our record
/// overhead, the obfs seal, the QUIC header and the UDP + IP headers. The floor is the
/// largest tunnel MTU whose datagram still fits the IPv6 minimum path of 1280 — which is the
/// whole point: rungs are inner MTUs, 1280 is an outer PATH mtu, and using it directly as
/// the lowest rung meant asking a 1280-byte path for 1280 + overhead bytes. Every rung then
/// failed on exactly the narrow paths probing exists for.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
fn mtu_probe_ladder(ceiling: i32, outer_overhead: usize) -> Vec<i32> {
    const PATH_FLOOR: i32 = 1280; // IPv6 minimum path MTU — the narrowest path we must serve
    let floor = (PATH_FLOOR - outer_overhead as i32).clamp(576, ceiling);
    // The jumbo rungs (12000..1500) exist because the ceiling stopped being an Ethernet number.
    // While it was 1500 the next rung down was 1360 and the gap was 140 bytes; once the ceiling
    // became 16638 the same ladder went straight from 16638 to 1360, so a path that carries
    // 9000 — an ordinary jumbo LAN, which is exactly who configures a large MTU — was certified
    // at 1360 and lost ~85% of its frame. These rungs cost nothing on a normal path: they are
    // all above a 1500 ceiling and the filter below drops them.
    //
    // The set is a COMPROMISE, not an exact answer: probing fixed rungs certifies the best rung
    // that FITS, not the path's real maximum, so a 7000-byte path lands on 6000. Closing that
    // needs a binary search between the highest failing rung and the best passing one — worth
    // doing, and deliberately not smuggled in here, since it changes the probe's control flow
    // in all four ports. (Audit 2026-08-01, §8.)
    let mut ladder: Vec<i32> = [
        ceiling, 12000, 9000, 6000, 4000, 2500, 2000, 1500, 1360, 1320, 1280, 1200, floor,
    ]
    .into_iter()
    .filter(|&m| (floor..=ceiling).contains(&m))
    .collect();
    ladder.sort_unstable_by(|a, b| b.cmp(a));
    ladder.dedup();
    ladder
}

#[cfg(test)]
mod mtu_ladder_tests {
    use super::mtu_probe_ladder;

    /// The narrowest rung must be reachable over a 1280-byte path once the probe's own
    /// framing is counted; otherwise a path at the IPv6 minimum certifies nothing and the
    /// caller falls back to the pushed MTU with fragmentation switched back on.
    #[test]
    fn the_lowest_rung_fits_the_ipv6_minimum_path() {
        // Worst case in this codebase: obfs seal (13) + QUIC short header (9) + UDP (8)
        // + IPv6 (40) + record overhead (48).
        for overhead in [48 + 8 + 20, 48 + 13 + 9 + 8 + 40] {
            let ladder = mtu_probe_ladder(1400, overhead);
            let lowest = *ladder.last().expect("ladder must not be empty");
            assert!(
                lowest + overhead as i32 <= 1280,
                "lowest rung {lowest} + overhead {overhead} exceeds the 1280 path floor"
            );
            // Still ordered high→low, and every rung is inside the ceiling.
            assert!(
                ladder.windows(2).all(|w| w[0] > w[1]),
                "ladder must descend: {ladder:?}"
            );
            assert!(ladder.iter().all(|&m| m <= 1400));
        }
    }

    #[test]
    fn a_low_ceiling_collapses_to_a_single_rung_and_never_inverts() {
        // A server that pushes a small MTU must not produce an empty or inverted ladder.
        let ladder = mtu_probe_ladder(1000, 48 + 13 + 9 + 8 + 40);
        assert!(!ladder.is_empty());
        assert!(ladder.iter().all(|&m| m <= 1000));
    }

    /// A jumbo ceiling must not fall straight to 1360.
    ///
    /// The ladder was written when the ceiling was an Ethernet-sized number, so the rung below
    /// it was 1360 and the gap was 140 bytes. Raising the ceiling to 16638 turned that same gap
    /// into 15278: a path carrying 9000 — an ordinary jumbo LAN, and precisely the setup where
    /// someone configures a large MTU — probed 16638, failed, and was certified at 1360.
    /// (Audit 2026-08-01, §8.)
    #[test]
    fn a_jumbo_ceiling_has_rungs_between_it_and_1360() {
        let overhead = 48 + 13 + 9 + 8 + 40;
        let ladder = mtu_probe_ladder(16638, overhead);
        let jumbo: Vec<i32> = ladder
            .iter()
            .copied()
            .filter(|&m| (1360..16638).contains(&m))
            .collect();
        assert!(
            jumbo.len() >= 3,
            "a jumbo ceiling needs intermediate rungs, got {ladder:?}"
        );
        // The specific case that regressed: a 9000-byte path must certify near 9000, not 1360.
        let best_under_9000 = ladder
            .iter()
            .copied()
            .find(|&m| m + overhead as i32 <= 9000)
            .expect("some rung must fit a 9000-byte path");
        assert!(
            best_under_9000 >= 4000,
            "a 9000-byte path certified at {best_under_9000}, wasting most of the frame"
        );
        assert!(
            ladder.windows(2).all(|w| w[0] > w[1]),
            "ladder must descend: {ladder:?}"
        );
    }

    /// Refinement finds the path's real MTU, not just the best rung that fits.
    ///
    /// The ladder can only ever land on one of its own numbers, so adding rungs moves the loss
    /// around instead of removing it: with rungs at 9000 and 6000 an 8999-byte path was pinned
    /// to 6000 and threw away a third of every frame. This drives the same search the probe
    /// loop runs, against a simulated path, and asserts it converges from below.
    /// (Audit 2026-08-01, §8.)
    #[test]
    fn refinement_converges_on_the_real_path_mtu() {
        use super::{mtu_refine_step, MTU_REFINE_MAX_PROBES, MTU_REFINE_STEP};

        // `real` is what the path actually carries; a probe succeeds iff it fits.
        fn search(mut lo: i32, mut hi: i32, real: i32) -> (i32, u8) {
            let mut probes = 0u8;
            for _ in 0..MTU_REFINE_MAX_PROBES {
                let Some(mid) = mtu_refine_step(lo, hi) else {
                    break;
                };
                probes += 1;
                if mid <= real {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            (lo, probes)
        }

        for (lo0, hi0, real) in [(6000, 9000, 8999), (4000, 6000, 5500), (1500, 2500, 2000)] {
            let (got, probes) = search(lo0, hi0, real);
            assert!(
                got <= real,
                "must never certify above the path: {got} > {real}"
            );
            assert!(
                real - got <= MTU_REFINE_STEP,
                "left {} bytes on the table (lo0={lo0} hi0={hi0} real={real} got={got})",
                real - got
            );
            assert!(
                got > lo0,
                "refinement must beat the coarse rung {lo0}, got {got}"
            );
            assert!(probes <= MTU_REFINE_MAX_PROBES, "probe budget exceeded");
        }

        // A path that carries barely more than the rung must not be made WORSE, and must not
        // burn probes on a gap that is already narrow.
        assert_eq!(
            mtu_refine_step(6000, 6200),
            None,
            "a narrow bracket stops immediately"
        );
        let (got, probes) = search(6000, 9000, 6001);
        assert_eq!(got, 6000, "a path at the rung stays at the rung");
        assert!(probes <= MTU_REFINE_MAX_PROBES);
    }

    /// ...and a normal 1500-class path must be probed exactly as before, so the jumbo rungs
    /// cost no extra round-trips for the common case.
    #[test]
    fn a_normal_ceiling_gains_no_extra_rungs() {
        let overhead = 48 + 13 + 9 + 8 + 40;
        assert_eq!(
            mtu_probe_ladder(1400, overhead),
            vec![1400, 1360, 1320, 1280, 1200, 1280 - overhead as i32]
        );
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
)))]
async fn probe_udp_mtu(
    _socket: &crate::protocol::obfs::ObfsUdp,
    _quic_enabled: bool,
    _connection_id: &[u8; 4],
    _quic_pn: &mut u32,
    _ceiling: i32,
) -> Option<i32> {
    None // no kernel DF control off Linux → keep the pushed/effective MTU
}

#[cfg(target_os = "linux")]
fn setup_tunnel(
    config: &crate::config::client::ClientConfig,
    plan: &NetworkPlan,
    network: &HandshakeNetwork<'_>,
) -> anyhow::Result<TunnelSetup> {
    let client_ip = plan.tunnel_address.as_str();
    let netmask = prefix_to_netmask(plan.prefix_len);
    let server_ip = plan.tunnel_gateway.as_str();
    let dns_ip = network.dns_ip;
    let dns_port = network.dns_port;
    let routes_json = network.routes_json;
    let mtu = i32::from(plan.mtu);
    let is_tap = is_tap_mode(&config.tun.device_type);
    let if_name = tap_interface_name(&config.tun.name, &config.tun.device_type);
    let attach = config.tun.attach_existing;
    let dev_label = if is_tap { "TAP" } else { "TUN" };
    log::info!("TUN MTU: {}", mtu);

    let exists = std::path::Path::new(&format!("/sys/class/net/{}", if_name)).exists();
    if attach {
        // Attach to a PRE-EXISTING, externally-owned interface; we only open it for
        // packet IO. If it's not there yet, error out and let the reconnect loop retry
        // until the owner creates it.
        if !exists {
            anyhow::bail!(
                "dev_attach is set but interface '{}' does not exist yet — waiting for its \
                 owner to create it (the reconnect loop will retry).",
                if_name
            );
        }
        log::info!("Attaching to existing {} interface {}", dev_label, if_name);
    } else {
        // An interface that already exists is usually someone else's, and clobbering it
        // would be destructive — but it can also be OUR OWN leftover from a connection
        // that died on an error path, in which case refusing would wedge every reconnect
        // from here on. Only that provably-ours case is reclaimed; everything else still
        // errors out and tells the operator to pick a distinct name via `dev=`.
        if exists {
            reclaim_stale_tun(&if_name)?;
        }
        log::info!("Creating {} interface {}", dev_label, if_name);
    }

    // `TUNSETIFF` creates the device when absent and ATTACHES to it when it already
    // exists — so the same call serves both the create and the (attach) path.
    let tun_res = if is_tap {
        TunInterface::create_tap(&if_name, mtu)
    } else {
        TunInterface::create(&if_name, mtu)
    };
    let tun = tun_res.map_err(|e| {
        anyhow::anyhow!(
            "failed to {} {} interface '{}': {} — is it already in use by another app? \
             Set 'dev=<name>' in [qeli] to use a different interface name.",
            if attach { "attach to" } else { "create" },
            dev_label,
            if_name,
            e
        )
    })?;
    if attach {
        // The interface owner sets L3 (address + link up) — some managers only route
        // through an interface they configured themselves, so if qeli sets the address
        // the owner never treats it as connected. We only pump packets, and export the
        // server-assigned IP via `QELI_TUNIP_FILE` so the owner can apply it.
        if let Ok(path) = std::env::var("QELI_TUNIP_FILE") {
            if !path.is_empty() {
                if let Err(e) = crate::util::write_atomic(&path, client_ip.as_bytes()) {
                    log::warn!("could not write tun IP to {}: {}", path, e);
                }
            }
        }
        log::info!(
            "Attached {}; L3 (address {}) left to its owner",
            if_name,
            client_ip
        );
    } else {
        TunInterface::set_address(&if_name, client_ip, plan.prefix_len)?;
        TunInterface::set_up(&if_name, mtu)?;
        log::info!("{} {} is up (IP: {})", dev_label, if_name, client_ip);
    }
    // NOW that the interface exists, apply the per-interface sysctl the gateway-NAT /
    // exit-node paths need. They run before the connect loop, so their own attempt at
    // this happened while /proc/sys/net/ipv4/conf/<tun>/ did not exist yet and silently
    // did nothing. (Audit 2026-07-27, R1.)
    if config.routing.gateway_nat || config.routing.forward || config.routing.exit_node {
        crate::client::gateway::apply_tun_rp_filter(&if_name);
    }
    tun.set_nonblocking()?;

    // Own the dups through the rest of this function. They used to be bare `i32`s, and
    // everything below can still fail: a `?` from `setup_routes` or the DNS setup left
    // both of them open with nothing to close them. The device is non-persistent, so it
    // then survived on those two fds — and `reclaim_stale_tun` could not recover it
    // either, because the holder it found was OUR OWN pid and the fds were never going
    // to be released, so every later reconnect timed out waiting and bailed. `OwnedFd`
    // closes them on any early return; ownership passes to the caller only on success.
    // F_DUPFD_CLOEXEC, not dup(2).
    //
    // POSIX says dup(2) CLEARS FD_CLOEXEC on the new descriptor. The original /dev/net/tun
    // fd is opened by std, which sets O_CLOEXEC — and both dups threw that away. After this
    // point the client keeps spawning children: `ip` (routes), `resolvectl` (DNS),
    // `iptables`/`ip6tables` (kill-switch refresh on EVERY reconnect), and above all
    // `hooks::run("post_down", …)`, which is `/bin/sh -c <operator string>`. Each inherited
    // a live, readable TUN descriptor: `exec 9<&<N>` in a hook script reads the user's raw
    // pre-encryption IP traffic, straight past the tunnel's cryptography. A dumber failure
    // is just as real — a hook that leaves a background child keeps a dup alive, the
    // interface never goes away, and every later reconnect fails.
    //
    // `F_DUPFD_CLOEXEC` (POSIX.1-2008) duplicates AND sets close-on-exec atomically, so
    // there is no window where a concurrent fork could inherit it either.
    // (Audit 2026-08-04.)
    let (owned_reader, owned_writer) = unsafe {
        use std::os::fd::{FromRawFd, OwnedFd};
        let r = libc::fcntl(tun.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
        if r < 0 {
            return Err(anyhow::anyhow!("failed to dup TUN fd (reader)"));
        }
        let r = OwnedFd::from_raw_fd(r);
        let w = libc::fcntl(tun.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0);
        if w < 0 {
            // `r` drops here and closes itself.
            return Err(anyhow::anyhow!("failed to dup TUN fd (writer)"));
        }
        (r, OwnedFd::from_raw_fd(w))
    };

    // Attach mode: routing belongs to the interface owner — don't install our own.
    if !attach {
        // Roll back on failure. `setup_routes` journals each route into `CREATED_ROUTES`
        // as it installs it and can still bail afterwards — on the `include` overlap
        // check, or on the FIB verification of the two default halves. `TunGuard`, the
        // only thing that calls `cleanup_routes` on an error path, is constructed by the
        // CALLER after `setup_tunnel` returns, so a failure here propagated with the
        // journal full and nothing to drain it: the process exited leaving the server
        // bypass route and, in full-tunnel, the IPv6 blackholes (`::/1`, `8000::/1`) on
        // the host. No VPN, and no IPv6 either, fixable only by hand.
        // (Audit 2026-07-27, B1.)
        let route_result =
            route::setup_routes(&config.routing, server_ip, &if_name, &pin_target(config))
                .and_then(|()| {
                    route::apply_local_networks(&config.routing, routes_json, &if_name, server_ip)
                });
        if let Err(e) = route_result {
            if let Err(ce) = route::cleanup_routes(&if_name, server_ip, &config.routing.exclude) {
                log::warn!("route rollback after a failed setup also failed: {ce}");
            }
            return Err(e);
        }
    }
    // On a full-tunnel host with dns=off, all traffic is routed through the tunnel but the
    // system resolver is left untouched — on a normal host (unlike a router with its own
    // local resolver) that can leak DNS to the physical network's resolver. Make it visible.
    if is_full_tunnel(config) && config.leaves_resolver_alone() {
        log::warn!(
            "full-tunnel + dns=off/system: qeli does not manage the host resolver, so DNS queries may \
             go to the physical network's resolver. Prefer dns=tunnel unless this host already \
             has a trusted local resolver (e.g. a router)."
        );
    }
    // DNS is part of the generation-scoped platform plan. Do not acknowledge Running when
    // a requested resolver could not be installed: that would make the new lifecycle lie
    // and, in full-tunnel mode, can expose or break name resolution. Operators whose
    // environment intentionally owns DNS can set `dns = off` and receive an empty DNS plan.
    // Tunnel subnet, so a server-pushed resolver can be checked for reachability through
    // the tunnel instead of being written into the host resolver on trust.
    let tun_net = match (
        client_ip.parse::<std::net::Ipv4Addr>(),
        netmask.parse::<std::net::Ipv4Addr>(),
    ) {
        (Ok(a), Ok(m)) => Some((a, m)),
        _ => None,
    };
    let dns_result = dns::setup_dns_for_interface(
        &config.dns,
        dns_ip,
        dns_port,
        &if_name,
        tun_net,
        is_full_tunnel(config),
    );
    if plan.dns_servers.is_empty() {
        if let Err(e) = dns_result {
            log::warn!(
                "DNS was omitted from the network plan ({e}) — keeping the host resolver unchanged. \
                 Configure dns_servers, let the server push a reachable resolver, or set `dns = off` \
                 when the platform manages DNS itself."
            );
        }
    } else if let Err(e) = dns_result {
        let dns_cleanup_error = dns::restore_dns_for(&if_name).err();
        if !attach {
            if let Err(ce) = route::cleanup_routes(&if_name, server_ip, &config.routing.exclude) {
                log::warn!("route rollback after DNS setup failure also failed: {ce}");
            }
        }
        return Err(match dns_cleanup_error {
            Some(cleanup) => anyhow::anyhow!(
                "DNS network-plan step failed: {e}; DNS rollback also failed: {cleanup}. Set `dns = off` only when the platform manages DNS itself"
            ),
            None => anyhow::anyhow!(
                "DNS network-plan step failed: {e}. Set `dns = off` only when the platform manages DNS itself"
            ),
        });
    }

    // Past every fallible platform step — move the RAII descriptors to the caller, which
    // immediately hands them to the shared TUN backend. No raw integer ownership escapes.
    Ok(TunnelSetup {
        tun,
        reader_fd: owned_reader,
        writer_fd: owned_writer,
        if_name,
        is_tap,
    })
}

#[cfg(target_os = "linux")]
async fn connect_and_run_udp(
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut LinuxCoreAdapter,
) -> anyhow::Result<()> {
    if config.obfuscation.mode == "plain" {
        return Err(anyhow::anyhow!(
            "plain (raw) wire mode is TCP-only; set server.protocol = tcp"
        ));
    }
    let addr = format!("{}:{}", config.server.address, config.server.port);
    log::info!(
        "Connecting to {} (UDP) as user '{}'",
        addr,
        config.auth.username
    );

    if config.obfuscation.mode == "obfs" && config.obfuscation.obfs_key.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "obfs wire mode requires a non-empty obfuscation.obfs_key \
             (an empty key is publicly derivable → no DPI resistance)"
        ));
    }
    let raw_socket = UdpSocket::bind("0.0.0.0:0").await?;
    // The shared UDP path below applies the socket policy before its first handshake packet,
    // so Linux and every native client use one controller and one set of counters.
    raw_socket.connect(&addr).await?;
    if let Ok(p) = raw_socket.peer_addr() {
        note_connected_peer(p.ip());
    }
    run_udp_tunnel(raw_socket, config, password, core).await
}

pub(crate) async fn run_udp_tunnel(
    raw_socket: UdpSocket,
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut dyn ClientPlatform,
) -> anyhow::Result<()> {
    if config.obfuscation.mode == "plain" {
        return Err(anyhow::anyhow!(
            "plain (raw) wire mode is TCP-only; set server.protocol = tcp"
        ));
    }
    if config.obfuscation.mode == "obfs" && config.obfuscation.obfs_key.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "obfs wire mode requires a non-empty obfuscation.obfs_key"
        ));
    }
    let runtime_counters = core.counters();
    let mut udp_buffer = UdpBufferController::configure(
        &raw_socket,
        UdpBufferPolicy {
            send_bytes: config.performance.send_buffer_size,
            receive_bytes: config.performance.recv_buffer_size,
            automatic_receive: config.performance.recv_buffer_auto,
            max_receive_bytes: AUTO_MAX_RECV_BYTES,
        },
        runtime_counters.udp.clone(),
        "client UDP",
    );
    let client_device_id = core.device_id()?;
    let identity_verifier = core.identity_verifier(config);
    // `obfs` wire mode: transparently XOR every datagram (ObfsUdp). None = fake-tls.
    let obfs_key = if config.obfuscation.mode == "obfs" && !config.obfuscation.obfs_key.is_empty() {
        Some(crate::protocol::obfs::derive_obfs_key(
            &config.obfuscation.obfs_key,
        ))
    } else {
        None
    };
    let socket = crate::protocol::obfs::ObfsUdp::new(raw_socket, obfs_key);

    let quic_enabled = config.obfuscation.quic.enabled;
    let connection_id = if quic_enabled {
        generate_connection_id()
    } else {
        [0u8; 4]
    };
    let mut quic_pn = 0u32;

    // The UDP ClientHello carries the ML-KEM-768 encapsulation key (~1.4 KB total)
    // and the ServerHello the ML-KEM ciphertext + cert (~2 KB); both exceed the path
    // MTU and would be IP-fragmented, which mobile / CGNAT networks drop (breaking UDP
    // on LTE). We fragment them ourselves so no datagram needs IP fragmentation.
    // `pad_to_min` still enforces the anti-amplification floor; see build_client_hello.
    let UdpClientHelloFlight {
        client_keypair: client_kp,
        mlkem_decapsulation_key: mlkem_dk,
        client_hello,
        fragments: ch_frags,
    } = build_udp_client_hello_flight(config)?;
    let n_frags = ch_frags.len();

    // AWG junk (AmneziaWG-style Jc) on UDP: before the ClientHello, emit `jc` throwaway
    // decoy datagrams of random size — a polymorphic start that blurs the size/count
    // fingerprint of the first packets. Sent ONCE (not on retransmit); each rides the
    // same obfs-XOR / QUIC mask as the handshake so it blends, and the server drops it
    // cheaply BEFORE its new-session rate limiter (so it never counts against it).
    let awg = crate::protocol::obfs::AwgParams {
        enabled: config.obfuscation.awg.enabled,
        jc: config.obfuscation.awg.jc,
        jmin: config.obfuscation.awg.jmin,
        jmax: config.obfuscation.awg.jmax,
    };
    let awg_jc = awg.effective_jc();
    if awg_jc > 0 {
        let (jmin, jmax) = awg.clamp_window();
        for _ in 0..awg_jc {
            let len = if jmin >= jmax {
                jmin
            } else {
                rand::rng().random_range(jmin..=jmax)
            } as usize;
            // Cap at MAX_CHUNK so a junk datagram never needs IP fragmentation on a
            // low-MTU (LTE/CGNAT) path — same reason the real fragments cap there.
            let len = len.clamp(1, crate::protocol::udp_frag::MAX_CHUNK);
            let junk = crate::protocol::udp_frag::junk_datagram(len);
            let send_data = if quic_enabled {
                let pn = quic_pn;
                quic_pn += 1;
                // 0x00 = Initial, not 0x02 = Handshake. `wrap_quic_long` always writes a
                // Token Length field, which ONLY an Initial has (RFC 9000 §17.2.2): a
                // QUIC-aware middlebox reading a Handshake packet expects the Length varint
                // right after the SCID, hit the stray zero byte, read Length = 0 and dropped
                // the datagram as malformed. The sequence was impossible anyway — a
                // Handshake packet cannot precede any Initial. The server's classifier
                // (`looks_like_quic_initial`) accepts this Initial and the one historical
                // qeli Handshake spelling, so rolling upgrades remain compatible.
                // (Audit 2026-07-27, E4.)
                wrap_quic_long(&junk, &connection_id, pn)
            } else {
                junk
            };
            socket.send(&send_data).await?;
        }
        log::info!(
            "UDP: Sent {} AWG junk datagram(s) before ClientHello",
            awg_jc
        );
    }

    let mut recv_buf = vec![0u8; 65535];
    let timeout = Duration::from_secs(config.server.connection_timeout_secs);
    // Drive the whole UDP handshake off a single hs_deadline with per-leg
    // retransmission instead of one fire-and-forget send + a full-timeout wait. On a
    // lossy / CGNAT path a single dropped handshake datagram would otherwise stall the
    // attempt for the entire connect timeout before the outer reconnect loop retries
    // from scratch — the "stuck channel that won't come back up after a server restart
    // / path flap" symptom (reproduced cause: the server never receives a complete
    // ClientHello). Both the ClientHello (below) and the auth credentials (further
    // down) are re-sent on a jittered ~HS_RETRANSMIT_INTERVAL tick until answered or
    // hs_deadline: the server's Reassembler dedups duplicate ClientHello fragments,
    // continuation fragments aren't re-charged by the new-session rate limiter, and a
    // resent auth packet is replay-dropped if it's a duplicate.
    //
    // The reverse direction is repaired by the SAME retransmits. The server caches its
    // ServerHello and its AuthOK and re-emits on a byte-identical request — the AuthOK up
    // to a small per-session cap — so a dropped reply costs about one RTT rather than the
    // whole connect timeout. That is why the resends above must be identical bytes: the
    // server matches on them. Only once the cap is spent does this fall through to
    // hs_deadline and a fresh-port reconnect. (This used to say the server ignores
    // handshake resends once it has the session; it has re-emitted since 0.7.14 — see
    // `UdpClient::server_hello` / `auth_ok`.) Jitter avoids fleet-wide phase-locking and a
    // fixed DPI cadence. A legacy single-datagram ServerHello (no fragment magic) is
    // accepted.
    const HS_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(1000);
    let hs_deadline = tokio::time::Instant::now() + timeout;
    let mut sh_re = crate::protocol::udp_frag::Reassembler::new();
    let mut ch_sends = 0u32;
    let raw_response = 'hs: loop {
        // (Re)send all ClientHello fragments. QUIC packet numbers keep advancing so a
        // retransmit is never mistaken for a replay of an earlier packet.
        for frag in &ch_frags {
            let send_data = if quic_enabled {
                let pn = quic_pn;
                quic_pn += 1;
                // Initial — see the compatibility note on the junk path above.
                wrap_quic_long(frag, &connection_id, pn)
            } else {
                frag.clone()
            };
            socket.send(&send_data).await?;
        }
        ch_sends += 1;
        if ch_sends == 1 {
            log::info!(
                "UDP: Sent ClientHello ({} fragment{}){}",
                n_frags,
                if n_frags == 1 { "" } else { "s" },
                if quic_enabled { " (QUIC)" } else { "" }
            );
        } else {
            log::debug!("UDP: Retransmitted ClientHello (send #{})", ch_sends);
        }

        // Wait for ServerHello fragments until the next retransmit tick (or the
        // overall deadline); a per-round timeout loops back to retransmit.
        loop {
            let now = tokio::time::Instant::now();
            if now >= hs_deadline {
                return Err(anyhow::anyhow!(
                    "UDP: no ServerHello after {} ClientHello send(s) in {}s",
                    ch_sends,
                    timeout.as_secs()
                ));
            }
            // Jitter the cadence so a fleet reconnecting after a shared outage does
            // not phase-lock on exact 1.000s ticks, and to blur the on-wire cadence.
            let jitter = Duration::from_millis(rand::rng().random_range(0..250));
            let round = (HS_RETRANSMIT_INTERVAL + jitter).min(hs_deadline - now);
            let n = match tokio::time::timeout(round, socket.recv(&mut recv_buf)).await {
                Err(_) => break, // round elapsed — retransmit ClientHello
                Ok(res) => res?,
            };
            let payload = if quic_enabled {
                unwrap_quic(&recv_buf[..n])
                    .map_err(|e| anyhow::anyhow!("UDP: failed to parse QUIC header: {:?}", e))?
                    .payload
            } else {
                recv_buf[..n].to_vec()
            };
            if crate::protocol::udp_frag::is_fragment(&payload) {
                match sh_re.push(&payload) {
                    Ok(Some(full)) => break 'hs full,
                    Ok(None) => continue,
                    Err(e) => return Err(anyhow::anyhow!("UDP: bad ServerHello fragment: {}", e)),
                }
            } else {
                break 'hs payload;
            }
        }
    };
    log::info!(
        "UDP: Received server response ({} bytes)",
        raw_response.len()
    );

    let data = &raw_response;

    if data.len() < 5 {
        return Err(anyhow::anyhow!("UDP: server response too short"));
    }

    let mut offset = 0usize;

    if offset + 5 > data.len() {
        return Err(anyhow::anyhow!("UDP: truncated ServerHello"));
    }
    let sh_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
    if offset + 5 + sh_len > data.len() {
        return Err(anyhow::anyhow!("UDP: truncated ServerHello record"));
    }
    let server_hello = data[offset..offset + 5 + sh_len].to_vec();
    offset += 5 + sh_len;

    let (mlkem_ct, server_x25519) = FakeTlsHandshake::parse_server_hello_pq(&server_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to parse hybrid ServerHello"))?;
    let server_pub = crate::crypto::PublicKey::from_bytes(&server_x25519);

    // Every following handshake component is length-prefixed. Validate the complete
    // record before advancing: accepting a header whose declared body lay past the
    // datagram used to push `offset` beyond `data`, perform the expensive PQ key schedule,
    // and only then fail (or wait for a non-existent split proof).
    let record_end = |start: usize, name: &str| -> anyhow::Result<usize> {
        let header = data
            .get(start..)
            .and_then(|tail| tail.get(..5))
            .ok_or_else(|| anyhow::anyhow!("UDP: truncated {name} record header"))?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let end = start
            .checked_add(5 + length)
            .ok_or_else(|| anyhow::anyhow!("UDP: {name} record length overflow"))?;
        if end > data.len() {
            return Err(anyhow::anyhow!("UDP: truncated {name} record"));
        }
        Ok(end)
    };

    if data.get(offset) != Some(&0x14) {
        anyhow::bail!("UDP: expected ChangeCipherSpec after ServerHello");
    }
    offset = record_end(offset, "ChangeCipherSpec")?;

    // Capture Certificate and Finished records for the handshake transcript. The
    // server now emits both as application_data (0x17) records, matching real TLS 1.3
    // (everything after ServerHello is encrypted); match that type when splitting the
    // concatenated UDP flight. Kept in lockstep with tls.rs build_certificate/finished.
    if data.get(offset) != Some(&0x17) {
        anyhow::bail!("UDP: expected encrypted Certificate record");
    }
    let end = record_end(offset, "Certificate")?;
    let cert_record = data[offset..end].to_vec();
    offset = end;

    if data.get(offset) != Some(&0x17) {
        anyhow::bail!("UDP: expected encrypted Finished record");
    }
    let end = record_end(offset, "Finished")?;
    let finished_record = data[offset..end].to_vec();
    offset = end;

    // NewSessionTicket. The server ALWAYS emits exactly one NST here, now as an
    // application_data (0x17) record — matching real TLS 1.3, in lockstep with
    // tls.rs build_new_session_ticket. Consume it POSITIONALLY by its own length;
    // do NOT peek the type to tell the NST from the auth-proof (both are 0x17 now).
    // The very next record (read below) is always the auth-proof.
    if data.get(offset) != Some(&0x17) {
        anyhow::bail!("UDP: expected encrypted NewSessionTicket record");
    }
    offset = record_end(offset, "NewSessionTicket")?;

    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
    // Hybrid PQ: decapsulate the server's ML-KEM ciphertext and fold both secrets
    // into the tunnel keys (UDP is always a fake-tls-family mode).
    let mlkem_ss = crate::crypto::mlkem::mlkem768_decapsulate(&mlkem_dk, &mlkem_ct)
        .ok_or_else(|| anyhow::anyhow!("UDP: ML-KEM decapsulation failed"))?;
    let mlkem_shared: [u8; 32] = mlkem_ss
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("UDP: ML-KEM shared secret not 32 bytes"))?;
    let (server_to_client, client_to_server) = match static_es(config, &client_kp)? {
        Some(es) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, &es),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };
    let mut client_rx = PacketCodec::new(server_to_client);
    let mut client_tx = PacketCodec::new(client_to_server);

    // Same transcript the server bound the proof to. Order must match
    // server/udp_handler.rs: ClientHello, ServerHello, Cert, Finished.
    let transcript_hash =
        handshake_transcript_hash(&[&client_hello, &server_hello, &cert_record, &finished_record]);

    log::info!("UDP: Handshake derived keys");

    let auth_proof_msg = if offset >= data.len() {
        // Bound this (rare, legacy split-proof) recv by the remaining handshake budget
        // so a stalled peer fails fast to a fresh-port reconnect, not a second timeout.
        let n2 = tokio::time::timeout(
            hs_deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .max(Duration::from_secs(2)),
            socket.recv(&mut recv_buf),
        )
        .await??;
        let auth_raw = if quic_enabled {
            let quic_pkt = unwrap_quic(&recv_buf[..n2])
                .map_err(|e| anyhow::anyhow!("UDP: failed to parse QUIC auth response: {:?}", e))?;
            quic_pkt.payload
        } else {
            recv_buf[..n2].to_vec()
        };
        client_rx.decrypt_packet(&auth_raw)?
    } else {
        let auth_record = data
            .get(offset..)
            .ok_or_else(|| anyhow::anyhow!("UDP: malformed handshake record framing"))?
            .to_vec();
        client_rx.decrypt_packet(&auth_record)?
    };

    let server_static_pub_bytes = verify_server_identity(
        &auth_proof_msg,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &config.auth.server_public_key,
    )?;
    identity_verifier(server_static_pub_bytes).await?;

    log::info!("UDP: Server identity verified");

    let auth_plain = build_client_auth_plaintext(
        config,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &client_device_id,
        password,
    );
    // The inner encrypted auth packet is fixed; only the QUIC wrapper's packet number
    // changes per (re)send. Resending identical inner bytes is safe: a duplicate that
    // reaches the server is replay-dropped, while a resend after loss is processed as
    // the real auth.
    let auth_packet = client_tx.encrypt_packet(&auth_plain, &[])?;

    // Retransmit the auth credentials on the same jittered timer as the ClientHello,
    // bounded by hs_deadline, so a dropped auth datagram (client->server) recovers in
    // ~1-2s instead of stalling the full connect timeout.
    //
    // A dropped AuthOK (server->client) is repaired by the SAME retransmit: the server
    // caches it and re-emits on a byte-identical AUTH, up to a small per-session cap. That
    // is why resending identical inner bytes matters — the server matches on them. Only
    // once the cap is spent does this fall through to the deadline and a fresh-port
    // reconnect, which redoes the whole handshake cleanly. (This used to say the server
    // never re-emits; it has since 0.7.14 — see `UdpClient::auth_ok`.)
    let mut auth_sends = 0u32;
    // Reassembly state for a FRAGMENTED AuthOK. A server whose pushed-route list puts the
    // AuthOK over the fragment budget splits it rather than emitting one oversized datagram
    // that an LTE/CGNAT path silently eats (see `udp_frag::MSG_AUTH_OK`); below the budget it
    // still arrives as the single datagram it always was, and this stays untouched.
    //
    // Scoped to this loop because this is the only place an AuthOK is expected — not because
    // the check would be unsafe elsewhere. A real record can never be mistaken for a
    // fragment in either framing (see `udp_frag::MSG_AUTH_OK`).
    let mut auth_ok_frags = crate::protocol::udp_frag::Reassembler::new();
    let mut auth_ok_frag_seen = false;
    let auth_response = 'auth: loop {
        let wire = if quic_enabled {
            quic_pn += 1;
            wrap_quic_short(&auth_packet, &connection_id, quic_pn - 1)
        } else {
            auth_packet.clone()
        };
        socket.send(&wire).await?;
        auth_sends += 1;
        if auth_sends == 1 {
            log::info!("UDP: Sent auth credentials");
        } else {
            log::debug!("UDP: Retransmitted auth credentials (send #{})", auth_sends);
        }

        loop {
            let now = tokio::time::Instant::now();
            if now >= hs_deadline {
                return Err(anyhow::anyhow!(
                    "UDP: no AuthOK after {} auth send(s) in {}s",
                    auth_sends,
                    timeout.as_secs()
                ));
            }
            let jitter = Duration::from_millis(rand::rng().random_range(0..250));
            let round = (HS_RETRANSMIT_INTERVAL + jitter).min(hs_deadline - now);
            let n3 = match tokio::time::timeout(round, socket.recv(&mut recv_buf)).await {
                Err(_) => break, // round elapsed — retransmit auth
                Ok(res) => res?,
            };
            let raw = if quic_enabled {
                match unwrap_quic(&recv_buf[..n3]) {
                    Ok(p) => p.payload,
                    Err(_) => continue, // not our QUIC framing — ignore, keep waiting
                }
            } else {
                recv_buf[..n3].to_vec()
            };
            // A fragmented AuthOK: collect the pieces, then decrypt the reassembled record.
            // Checked BEFORE decrypt because a lone fragment is not a valid AEAD record and
            // would otherwise be discarded as a stray datagram, one per fragment, forever.
            if crate::protocol::udp_frag::is_auth_ok_fragment(&raw) {
                if !auth_ok_frag_seen {
                    auth_ok_frag_seen = true;
                    log::debug!("UDP: AuthOK is arriving fragmented (large pushed-route set)");
                }
                match auth_ok_frags.push(&raw) {
                    Ok(Some(record)) => match client_rx.decrypt_packet(&record) {
                        Ok(resp) => break 'auth resp,
                        // Reassembled but undecryptable: fragments from a stale attempt got
                        // mixed with this one. Start over rather than staying wedged on a
                        // reassembler that can never complete correctly.
                        Err(e) => {
                            log::debug!(
                                "UDP: reassembled AuthOK failed to decrypt ({e}) — resetting"
                            );
                            auth_ok_frags = crate::protocol::udp_frag::Reassembler::new();
                            continue;
                        }
                    },
                    Ok(None) => continue, // more fragments needed
                    Err(e) => {
                        // Malformed or inconsistent — drop the partial and keep waiting, the
                        // same way a stray datagram is ignored below.
                        log::debug!("UDP: bad AuthOK fragment ({e}) — resetting reassembly");
                        auth_ok_frags = crate::protocol::udp_frag::Reassembler::new();
                        continue;
                    }
                }
            }
            match client_rx.decrypt_packet(&raw) {
                // A record that decrypts is not automatically the AuthOK. Server cover and
                // heartbeat traffic carries an EMPTY payload and is encrypted with these very
                // keys, so it decrypts perfectly and used to be accepted here — then failed the
                // `OK:` parse a few lines down and killed the connect. The server no longer
                // emits either before the AuthOK, but an older one still does, and "empty is
                // not an answer" is true regardless of who is on the other end.
                // (Audit 2026-08-03, P1.)
                Ok(resp) if !resp.is_empty() => break 'auth resp,
                Ok(_) => continue,  // server cover/beacon — keep waiting
                Err(_) => continue, // stray datagram — keep waiting
            }
        }
    };
    let response_str = String::from_utf8(auth_response)?;

    let ok = parse_auth_ok(&response_str)?;
    let client_ip = ok.client_ip;
    let server_ip = ok.server_ip;
    let prefix = ok.prefix;
    let pushed_mtu = ok.mtu;
    let dns_ip = ok.dns_ip;
    let dns_port = ok.dns_port;
    let routes_json_udp = ok.routes_json;
    let max_streams_udp = ok.max_streams;
    let adaptive_udp = ok.adaptive;

    let mut eff_obf = config.obfuscation.clone();
    let pushed_obf = ok.pushed_obf;
    if let Some(po) = pushed_obf.as_ref() {
        eff_obf.padding = po.padding.clone();
        eff_obf.heartbeat = po.heartbeat.clone();
        eff_obf.traffic_normalization = po.traffic_normalization.clone();
        eff_obf.traffic_shaping = po.traffic_shaping.clone();
    }

    log::info!("UDP: Auth OK, assigned IP: {}", client_ip);
    // The complete push journal is attached below after path-MTU probing, so every
    // platform sees both the server ceiling and the final selected MTU.

    // Auto MTU on UDP: when `mtu = 0` and probing is on, actively discover the path
    // MTU (DF probes from the pushed ceiling down) before bringing the TUN up — so a
    // narrow LTE/CGNAT path is measured, not guessed. Otherwise adopt the pushed MTU.
    // The socket is idle here (handshake done, data plane not started), so the probe
    // has it to itself. Falls back to the pushed/effective MTU on any miss.
    let base_mtu = effective_mtu(config.tun.mtu, pushed_mtu);
    let tun_mtu = if config.tun.mtu == 0 && config.tun.mtu_probe {
        match probe_udp_mtu(
            &socket,
            quic_enabled,
            &connection_id,
            &mut quic_pn,
            base_mtu,
        )
        .await
        {
            Some(m) => {
                log::info!(
                    "UDP path-MTU probe: tunnel MTU {} (ceiling {})",
                    m,
                    base_mtu
                );
                m
            }
            None => {
                log::info!("UDP path-MTU probe: no result — using MTU {}", base_mtu);
                base_mtu
            }
        }
    } else {
        base_mtu
    };
    let fallback_dns_servers = core.fallback_dns_servers().to_vec();
    let network = HandshakeNetwork {
        client_ip: &client_ip,
        prefix,
        tunnel_gateway: &server_ip,
        dns_ip: &dns_ip,
        dns_port: &dns_port,
        routes_json: &routes_json_udp,
        mtu: tun_mtu,
        fallback_dns_servers: &fallback_dns_servers,
    };
    let mut plan = build_network_plan(config, core.next_generation(), &network)?;
    plan.max_streams = max_streams_udp;
    plan.adaptive = adaptive_udp;
    plan.data_plane = crate::transport_core::NetworkDataPlaneFacts::from_obfuscation(&eff_obf);
    plan.connection_log = server_push_log_lines(
        config,
        &plan,
        pushed_mtu,
        &dns_ip,
        &dns_port,
        &routes_json_udp,
        pushed_obf.as_ref(),
    );
    for line in &plan.connection_log {
        log::info!("{line}");
    }
    let tun_setup = core.prepare_tunnel(config, plan, &network)?;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let reader_fd = tun_setup.reader_fd;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let writer_fd = tun_setup.writer_fd;
    #[cfg(target_os = "linux")]
    let tun_name = tun_setup.if_name;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let is_tap = tun_setup.is_tap;
    #[cfg(target_os = "macos")]
    let is_tap = false;
    #[cfg(target_os = "linux")]
    let server_addr = pin_target(config);
    #[cfg(target_os = "linux")]
    let tunnel_tun = tun_setup.tun;
    #[cfg(target_os = "linux")]
    let tap_mac = if is_tap { generate_mac() } else { [0u8; 6] };
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let tap_mac = [0u8; 6];
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let gateway_mac: [u8; 6] = if is_tap {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
    } else {
        [0u8; 6]
    };

    log::info!("UDP: Starting tunnel");

    let hb_config = &eff_obf.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let padding_min = eff_obf.padding.min_bytes;
    let padding_max = eff_obf.padding.max_bytes;
    let padding_enabled = eff_obf.padding.enabled;
    let padding_randomize = eff_obf.padding.randomize;
    let padding_prob = eff_obf.padding.probability;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let tun_buf_size = config
        .performance
        .tun_buffer_size
        .saturating_add(if cfg!(target_os = "macos") { 4 } else { 0 });
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;

    // Everything below can bail out through `?`, which would skip the teardown at the
    // end of this function; from here on the guard covers that (see `TunGuard`).
    #[cfg(target_os = "linux")]
    let mut tun_guard = TunGuard::new(
        tun_name.clone(),
        !config.tun.attach_existing,
        server_addr.clone(),
        config.routing.exclude.clone(),
    );
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let mut tun_pump = LinuxTunPump::start(
        reader_fd,
        writer_fd,
        LinuxTunPumpConfig {
            buffer_size: tun_buf_size,
            downlink_record_bytes: downlink_record_budget(tun_mtu, padding_max, norm_sizes),
            write_drops: Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
            framing: if cfg!(target_os = "macos") {
                TunFraming::Utun
            } else if is_tap {
                TunFraming::Tap(TapHeaders {
                    client_mac: tap_mac,
                    gateway_mac,
                })
            } else {
                TunFraming::Raw
            },
        },
    )?;
    #[cfg(target_os = "windows")]
    let mut tun_pump = match tun_setup.windows_tun {
        WindowsTunSetup::Ring(adapter_name) => WindowsTunPump::open(
            &adapter_name,
            downlink_record_budget(tun_mtu, padding_max, norm_sizes),
            Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
        )?,
        WindowsTunSetup::Packet(packet_tun) => WindowsTunPump::packet(packet_tun),
    };
    #[cfg(target_os = "ios")]
    let mut tun_pump = tun_setup.packet_tun;
    #[cfg(target_os = "linux")]
    tun_guard.attach_pump(tun_pump.stop_handle());
    let tun_write_tx = tun_pump.sender_to_tun();
    let cancel = core.cancel_token();
    // Persistent for the same reason as the TCP cancellation tick: high packet rates must
    // never postpone teardown by continually resetting a newly-created sleep future.
    let mut cancel_tick = tokio::time::interval(Duration::from_millis(100));
    cancel_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cancel_tick.tick().await;

    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        30000
    });
    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut idle_check = tokio::time::interval(Duration::from_secs(5));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut udp_buffer_tick = tokio::time::interval(Duration::from_secs(1));
    udp_buffer_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_activity = tokio::time::Instant::now();
    // Last datagram RECEIVED from the server (RX-only) — for dead-link detection,
    // independent of our own heartbeats. (UDP has no connection state, so this is
    // the only way to notice a vanished server.)
    let mut last_rx_inst = tokio::time::Instant::now();
    let idle_timeout = Duration::from_secs(config.performance.idle_timeout_secs);
    let socket = Arc::new(socket);

    // Flow-shaping (client->server idle cover): mirror of the TCP path; replaces
    // the fixed heartbeat when enabled. `last_tx_inst` tracks our OWN last send so
    // inbound server cover (which bumps last_activity) doesn't suppress our uplink
    // cover. Never hold a ThreadRng across `.await` — fresh temporary per call.
    let mut shaper = crate::protocol::Shaper::new(
        {
            // Stealth is TCP-only (UDP stealth craters throughput — see bench);
            // UDP keeps Phase-1 idle cover.
            let mut sh = eff_obf.traffic_shaping.to_shaping();
            sh.stealth = false;
            sh
        },
        std::time::Instant::now(),
    );
    let shaping_on = shaper.enabled();
    let heartbeat_enabled = heartbeat_enabled && !shaping_on;
    let rx_dead = crate::protocol::liveness_deadline(
        heartbeat_enabled,
        heartbeat_interval,
        Duration::from_millis(hb_config.jitter_ms),
        shaping_on,
        Duration::from_millis(eff_obf.traffic_shaping.idle_gap_max_ms),
    );
    let mut last_tx_inst = tokio::time::Instant::now();
    let mut cover_deadline = tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());
    // Suspend/resume baseline: each idle tick compares wall-clock elapsed to monotonic
    // elapsed. A large positive difference = the host slept (Instant freezes during sleep
    // on macOS/Windows) while the wall clock kept running ⇒ the session + NAT are gone.
    let mut last_tick_wall = std::time::SystemTime::now();
    let mut last_tick_inst = tokio::time::Instant::now();
    // The UDP loop is sequential, so it can retain its record/envelope allocations for the
    // whole connection. A separate cover record is required because stealth pacing may send
    // cover while the real record is waiting; the QUIC envelope can be reused for both.
    let wire_capacity =
        crate::protocol::packet::TLS_RECORD_HEADER + crate::protocol::packet::MAX_RECORD_SIZE;
    let mut wire_record = Vec::with_capacity(wire_capacity);
    let mut cover_record = Vec::with_capacity(wire_capacity);
    let mut quic_record =
        Vec::with_capacity(wire_capacity + crate::protocol::quic::QUIC_SHORT_HEADER_MIN);
    let mut normalized_packet = Vec::with_capacity(tun_mtu.max(0) as usize);
    let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
    let mut oversize_tun_drops: u64 = 0;

    // Tell the server the MTU we actually settled on (#13). It sized its own downlink from
    // the profile's `tun.mtu`, which is the path up to ITS tun — it cannot see that our leg
    // is narrower, so without this every large packet it forwards is dropped downstream with
    // no signal to anyone. Sent as an in-tunnel control frame, so it is authenticated by the
    // session AEAD rather than spoofable like a bare datagram. Fire-and-forget: the server
    // ignores a value that is not narrower than its own, an older server discards the frame
    // as a malformed packet, and nothing here waits for a reply.
    //
    // Being unacknowledged is exactly the problem on UDP: one lost datagram would leave the
    // server on `path_mtu = 0` for the WHOLE session, on the transport where the report matters
    // most. The frame is idempotent — the server simply stores the latest value, and the copies all carry the same one — so it
    // is simply re-sent on the next few idle ticks below, which costs a few bytes and removes
    // the single point of loss. (Audit 2026-07-30, #5.)
    let mtu_report_value = u16::try_from(tun_mtu.max(0)).ok();
    let mut mtu_resends: u8 = 0;
    if let Some(mtu) = mtu_report_value {
        let frame = crate::protocol::ctrl::mtu_report(mtu);
        if client_tx
            .encrypt_packet_into(&frame, &[], &mut cover_record)
            .is_ok()
        {
            let send_data: &[u8] = if quic_enabled {
                quic_pn += 1;
                wrap_quic_short_into(&cover_record, &connection_id, quic_pn - 1, &mut quic_record);
                &quic_record
            } else {
                &cover_record
            };
            match socket.send(send_data).await {
                Ok(_) => {
                    log::debug!("reported tunnel MTU {mtu} to the server");
                    mtu_resends = MTU_REPORT_RESENDS;
                }
                Err(e) => log::debug!("could not report tunnel MTU: {e}"),
            }
        }
    }

    // Tell the server which build we are, so the operator's `list-clients` and the panel can
    // show it. Same authenticated path and the same fire-and-forget contract as the MTU
    // report above: an older server discards the frame as a malformed packet, and nothing
    // here waits for or depends on a reply.
    if let Some(frame) = crate::protocol::ctrl::this_build() {
        if client_tx
            .encrypt_packet_into(&frame, &[], &mut cover_record)
            .is_ok()
        {
            let send_data: &[u8] = if quic_enabled {
                quic_pn += 1;
                wrap_quic_short_into(&cover_record, &connection_id, quic_pn - 1, &mut quic_record);
                &quic_record
            } else {
                &cover_record
            };
            if let Err(e) = socket.send(send_data).await {
                log::debug!("could not report client version: {e}");
            }
        }
    }

    let mut unsupported_inner_drops = 0u64;
    loop {
        tokio::select! {
            _ = cancel_tick.tick() => {
                if cancel.load(Ordering::Acquire) { break; }
            }

            _ = udp_buffer_tick.tick() => {
                udp_buffer.tick(socket.raw_socket());
            }

            packet = tun_pump.recv_from_tun() => {
                let Some(ip_packet) = packet else {
                    log::warn!("UDP: TUN reader stopped — reconnecting");
                    break;
                };
                if !is_supported_inner_packet(ip_packet.as_ref()) {
                    unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                    udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                    if unsupported_inner_drops.is_power_of_two() {
                        log::debug!(
                            "UDP client dropped unsupported non-IPv4 inner packet (total {})",
                            unsupported_inner_drops
                        );
                    }
                    continue;
                }
                let mtu = tun_mtu.max(0) as usize;
                if mtu != 0 && ip_packet.len() > mtu {
                    oversize_tun_drops = oversize_tun_drops.saturating_add(1);
                    udp_buffer.note_internal_drop(InternalDrop::Oversize);
                    if oversize_tun_drops.is_power_of_two() {
                        log::warn!(
                            "UDP client dropped inner packet larger than tunnel MTU: {} > {} bytes (total {})",
                            ip_packet.len(), mtu, oversize_tun_drops
                        );
                    }
                    continue;
                }
                trace::record(trace::Dir::Tx, "client.udp", ip_packet.len(), 0);
                runtime_counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                runtime_counters
                    .tx_bytes
                    .fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
                last_activity = tokio::time::Instant::now();
                last_tx_inst = last_activity;
                let encrypted = {
                    let mut obf = Obfuscator::new();
                    let normalized = if eff_obf.traffic_normalization.enabled && !norm_sizes.is_empty() {
                        // Bounded by the SAME mtu the pad cap below uses: normalization that
                        // rounds past it re-creates the oversized DF datagram the probe just
                        // ruled out, and the pad cap cannot undo it (it only trims padding).
                        obf.normalize_packet_length_into(
                            ip_packet.as_ref(),
                            norm_sizes,
                            mtu,
                            &mut normalized_packet,
                        );
                        Some(normalized_packet.as_slice())
                    } else {
                        None
                    };
                    let data_with_route = normalized.unwrap_or_else(|| ip_packet.as_ref());
                    // Clamp padding so the whole record (data + padding) stays within the
                    // DISCOVERED/pushed tunnel MTU. The path-MTU probe certifies that a
                    // datagram of `tun_mtu + REC_OVERHEAD(48)` fits, and the real record adds
                    // only 43 (header+nonce+counter+padlen+tag) + the QUIC/obfs wrappers — so
                    // keeping data+padding <= tun_mtu leaves margin for all of it. Mirrors the
                    // C#/Kotlin `EncryptCapped(pkt, effectiveMtu)`. The old code used a literal
                    // 1400 (ignoring a smaller probed MTU on LTE/CGNAT — full-size padded
                    // uplink packets were then silently dropped with EMSGSIZE under DF) and a
                    // `+60` overhead that under-counted obfs+quic (65) by 5 bytes.
                    let pad_cap =
                        (padding_max as usize).min(mtu.saturating_sub(data_with_route.len())) as u16;
                    obf.generate_padding_opts_into(
                        padding_enabled,
                        padding_min,
                        pad_cap,
                        padding_randomize,
                        padding_prob,
                        &mut padding,
                    );
                    client_tx
                        .encrypt_packet_into(data_with_route, &padding, &mut wire_record)
                        .is_ok()
                };
                // Encryption has copied the plaintext into its wire record; return the TUN
                // allocation before any pacing or socket-send await below.
                drop(ip_packet);
                if encrypted {
                    // Stealth: pace the uplink to stealth_rate; fill the gap with
                    // jittered small cover (size mix + non-metronome). Cover datagrams
                    // take their own QUIC pns FIRST so the real packet's pn stays the
                    // largest (monotonic on the wire).
                    let d = shaper.stealth_pace(wire_record.len(), std::time::Instant::now());
                    if shaper.stealth() && !d.is_zero() {
                        let mut remaining = d;
                        while remaining > Duration::from_millis(6) {
                            // Cap cover size to the probed tunnel MTU: with DF armed after a
                            // successful probe, an oversized cover datagram is dropped with
                            // EMSGSIZE (send error swallowed), so the DPI cover silently never
                            // goes out. Mirrors the data path and C#/Kotlin's EncryptCapped.
                            let csize =
                                shaper.next_size(&mut rand::rng()).min(tun_mtu.max(0) as usize);
                            if shaper.try_spend(csize, std::time::Instant::now()) {
                                let cover_ready = {
                                    let mut obf = Obfuscator::new();
                                    obf.generate_padding_into(
                                        csize as u16,
                                        csize as u16,
                                        &mut padding,
                                    );
                                    client_tx
                                        .encrypt_packet_into(&[], &padding, &mut cover_record)
                                        .is_ok()
                                };
                                if cover_ready {
                                    let send_data: &[u8] = if quic_enabled {
                                        quic_pn += 1;
                                        wrap_quic_short_into(
                                            &cover_record,
                                            &connection_id,
                                            quic_pn - 1,
                                            &mut quic_record,
                                        );
                                        &quic_record
                                    } else { &cover_record };
                                    let _ = socket.send(send_data).await;
                                }
                            }
                            let step = Duration::from_millis(rand::rng().random_range(4..=18));
                            let s = step.min(remaining);
                            tokio::time::sleep(s).await;
                            remaining = remaining.saturating_sub(s);
                        }
                    } else if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                    let send_data: &[u8] = if quic_enabled {
                        quic_pn += 1;
                        wrap_quic_short_into(
                            &wire_record,
                            &connection_id,
                            quic_pn - 1,
                            &mut quic_record,
                        );
                        &quic_record
                    } else {
                        &wire_record
                    };
                    if let Err(error) = socket.send(send_data).await {
                        log::warn!("UDP carrier send failed: {error}");
                        break;
                    }
                }
            }

            result = socket.recv(&mut recv_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(_) => break,
                };
                udp_buffer.note_receive(n);
                // Unlike TCP, UDP must not await a pool slot here: doing so would stall this
                // select loop's heartbeat and dead-link timers. Congestion already uses
                // drop-on-full semantics at the TUN queue, so drop the datagram when every
                // bounded record allocation is still in flight.
                let mut record = match tun_write_tx.try_acquire() {
                    Some(record) => record,
                    None => {
                        log::trace!("downlink record pool exhausted — dropping inbound datagram");
                        udp_buffer.note_internal_drop(InternalDrop::PoolExhausted);
                        continue;
                    }
                };
                let payload = if quic_enabled {
                    match unwrap_quic_payload(&recv_buf[..n]) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    }
                } else {
                    &recv_buf[..n]
                };
                // A crafted oversized datagram must not make a pooled Vec grow beyond the
                // fixed per-slot budget before PacketCodec gets to reject its length field.
                if payload.len() > wire_capacity {
                    continue;
                }
                record.as_vec_mut().extend_from_slice(payload);
                match client_rx.decrypt_packet_in_place(record.as_vec_mut()) {
                    Ok(()) => {
                        // Only authenticated records prove that the peer/session is alive.
                        // Updating this before QUIC parsing + AEAD let malformed or spoofed
                        // carrier datagrams suppress reconnect indefinitely.
                        last_activity = tokio::time::Instant::now();
                        last_rx_inst = last_activity;
                        if !record.is_empty() {
                            runtime_counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                            runtime_counters
                                .rx_bytes
                                .fetch_add(record.len() as u64, Ordering::Relaxed);
                            // Non-blocking: a blocking send() here would stall the
                            // entire select! loop (heartbeat, RX-liveness, reads)
                            // whenever the TUN writer falls behind. Drop on a full
                            // queue — correct congestion behaviour.
                            trace::record(trace::Dir::Rx, "client.udp", record.len(), 0);
                            match tun_write_tx.try_send(record) {
                                Ok(()) => {}
                                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                    log::trace!("TUN write queue full — dropping inbound datagram");
                                    udp_buffer.note_internal_drop(InternalDrop::QueueFull);
                                }
                                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                            }
                        }
                    }
                    Err(e) => log::debug!("UDP decrypt error: {}", e),
                }
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                // Idle-gate on OUR last send (last_tx_inst), NOT last_activity (which
                // also counts RX): a download-only client (receiving, not sending) would
                // otherwise skip its keepalive, and the server — which reaps on
                // client->server silence — would drop it mid-download. Gating on TX still
                // skips the keepalive while real upload traffic is flowing.
                if last_tx_inst.elapsed() < heartbeat_interval {
                    continue;
                }
                // Same shape as the TCP path: the delay is drawn directly and uniformly
                // (the old [0, 2*jitter) minus jitter put >50% of the mass at exactly 0
                // and could overflow `jitter * 2` into an empty range).
                let jitter = if hb_config.jitter_ms > 0 {
                    let mut rng = rand::rng();
                    Duration::from_millis(rng.random_range(0..=hb_config.jitter_ms))
                } else {
                    Duration::ZERO
                };
                tokio::time::sleep(jitter).await;

                let heartbeat_ready = {
                    let mut obf = Obfuscator::new();
                    // Cap the (server-pushable) heartbeat size to the probed MTU so a large
                    // data_size_bytes can't make a DF-marked keepalive overflow the path and
                    // get dropped (which would make the server reap the idle client).
                    let hb_cap = tun_mtu.max(0) as usize;
                    let hb_lo = (hb_config.data_size_bytes as usize).min(hb_cap) as u16;
                    let hb_hi = ((hb_config.data_size_bytes as usize).saturating_add(32))
                        .min(hb_cap) as u16;
                    obf.generate_padding_into(hb_lo, hb_hi, &mut padding);
                    client_tx
                        .encrypt_packet_into(&[], &padding, &mut cover_record)
                        .is_ok()
                };
                if heartbeat_ready {
                    let send_data: &[u8] = if quic_enabled {
                        quic_pn += 1;
                        wrap_quic_short_into(
                            &cover_record,
                            &connection_id,
                            quic_pn - 1,
                            &mut quic_record,
                        );
                        &quic_record
                    } else {
                        &cover_record
                    };
                    let _ = socket.send(send_data).await;
                }
                last_activity = tokio::time::Instant::now();
                last_tx_inst = last_activity;
            }

            _ = tokio::time::sleep_until(cover_deadline), if shaping_on => {
                // Fill genuine idle on OUR send side (last_tx_inst); in STEALTH run
                // cover under load too so small cover mixes into the rate-capped stream.
                if shaper.stealth() || last_tx_inst.elapsed() >= Duration::from_millis(50) {
                    // Cap idle-cover size to the probed MTU (see the stealth-cover branch).
                    let size = shaper.next_size(&mut rand::rng()).min(tun_mtu.max(0) as usize);
                    if shaper.try_spend(size, std::time::Instant::now()) {
                        let cover_ready = {
                            let mut obf = Obfuscator::new();
                            obf.generate_padding_into(
                                size as u16,
                                size as u16,
                                &mut padding,
                            );
                            client_tx
                                .encrypt_packet_into(&[], &padding, &mut cover_record)
                                .is_ok()
                        };
                        if cover_ready {
                            let send_data: &[u8] = if quic_enabled {
                                quic_pn += 1;
                                wrap_quic_short_into(
                                    &cover_record,
                                    &connection_id,
                                    quic_pn - 1,
                                    &mut quic_record,
                                );
                                &quic_record
                            } else {
                                &cover_record
                            };
                            let _ = socket.send(send_data).await;
                            last_tx_inst = tokio::time::Instant::now();
                        }
                    }
                }
                cover_deadline = tokio::time::Instant::now()
                    + shaper.next_gap(&mut rand::rng());
            }

            _ = idle_check.tick() => {
                // Re-send the unacknowledged MTU report (#5). `idle_check` fires immediately on
                // its first tick, so the copies land at roughly 0 s, 5 s and 10 s: the first
                // covers an isolated drop, the later ones a short burst of loss that would take
                // out back-to-back datagrams. The server keeps the narrowest value it has seen,
                // so duplicates are a no-op there.
                if mtu_resends > 0 {
                    mtu_resends -= 1;
                    if let Some(mtu) = mtu_report_value {
                        let frame = crate::protocol::ctrl::mtu_report(mtu);
                        if client_tx
                            .encrypt_packet_into(&frame, &[], &mut cover_record)
                            .is_ok()
                        {
                            let send_data: &[u8] = if quic_enabled {
                                quic_pn += 1;
                                wrap_quic_short_into(
                                    &cover_record,
                                    &connection_id,
                                    quic_pn - 1,
                                    &mut quic_record,
                                );
                                &quic_record
                            } else {
                                &cover_record
                            };
                            let _ = socket.send(send_data).await;
                        }
                    }
                }
                // Suspend/resume: wall clock advanced far more than the monotonic clock
                // since the last tick ⇒ the host was asleep (Instant froze). The RX window
                // can't see the pre-suspend silence and the session + NAT are gone — cycle now.
                let wall_gap = last_tick_wall.elapsed().unwrap_or_default();
                last_tick_wall = std::time::SystemTime::now();
                let tick_gap = last_tick_inst.elapsed();
                last_tick_inst = tokio::time::Instant::now();
                if wall_gap.saturating_sub(tick_gap) > Duration::from_secs(10) {
                    log::warn!("UDP: resumed from suspend (~{}s) — reconnecting", wall_gap.as_secs());
                    // Our decision, not a fault: don't let it escalate the backoff.
                    DELIBERATE_CYCLE.store(true, std::sync::atomic::Ordering::Release);
                    break;
                }
                // RX-liveness is valid only when the peer promises authenticated heartbeat
                // or shaping cover. Ordinary UDP uplink is allowed to be one-way and has no
                // transport ACK, so it must never be treated as proof that downlink is due.
                if let Some(deadline) = rx_dead {
                    if last_rx_inst.elapsed() > deadline {
                        log::warn!(
                            "UDP: no authenticated data from server for >{}s — reconnecting",
                            deadline.as_secs()
                        );
                        break;
                    }
                }
                if idle_timeout.as_secs() > 0 && last_activity.elapsed() > idle_timeout {
                    log::debug!("Idle timeout reached");
                    break;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    let dns_cleanup_error = dns::restore_dns_for(&tun_name).err();
    drop(tun_write_tx);
    tun_pump.shutdown().await;
    // Closes the TUN fd: `TunInterface` holds it as a `File`. (Do NOT also close the raw
    // number — that would be a double close, and the freed number can already have been
    // handed to another thread's socket.)
    #[cfg(target_os = "linux")]
    drop(tunnel_tun);
    // Attach mode: the interface + routes belong to an external owner — leave them.
    #[cfg(target_os = "linux")]
    let tun_cleanup_error = if !config.tun.attach_existing {
        cleanup_owned_tun(&tun_name, &server_addr, &config.routing.exclude).err()
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    match (dns_cleanup_error, tun_cleanup_error) {
        (None, None) => {}
        (Some(dns), None) => return Err(anyhow::anyhow!("DNS cleanup failed: {dns}")),
        (None, Some(tun)) => return Err(tun),
        (Some(dns), Some(tun)) => {
            return Err(anyhow::anyhow!("DNS cleanup failed: {dns}; {tun}"));
        }
    }
    #[cfg(target_os = "linux")]
    tun_guard.disarm(); // graceful teardown done — nothing left for `Drop` to repeat
    log::info!("UDP client disconnected");
    Ok(())
}

/// Bytes to reserve per pooled downlink buffer: the largest wire record this session can
/// legitimately receive.
///
/// One record carries one inner packet (at most the tunnel MTU), plus the AEAD/counter/pad-len
/// and record header, plus whatever the peer's obfuscation adds — random padding up to
/// `padding_max`, and size normalisation, which rounds a record UP to one of its configured
/// sizes and can therefore exceed the MTU on a small-MTU tunnel.
///
/// Deliberately an estimate, not a guarantee: the pool pre-reserves this much but the buffer is
/// a plain `Vec`, so a larger record simply grows it once. Under-estimating costs one
/// reallocation; over-estimating costs slots, which is the mistake that made the pool 251
/// buffers deep while the packets were a tenth of the reserved size.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "windows"
))]
fn downlink_record_budget(tun_mtu: i32, padding_max: u16, norm_sizes: &[u16]) -> usize {
    let mtu = tun_mtu.max(0) as usize;
    let normalized = norm_sizes.iter().copied().max().unwrap_or(0) as usize;
    mtu.max(normalized)
        .saturating_add(padding_max as usize)
        .saturating_add(crate::protocol::packet::TLS_RECORD_HEADER)
        // nonce + tag + counter + pad-len, i.e. everything encrypt_packet adds around the
        // plaintext; taken with headroom rather than as an exact sum so a future field does
        // not silently start costing a reallocation per packet.
        .saturating_add(128)
}

/// Convert a CIDR prefix length (e.g. 24) to a dotted IPv4 netmask (e.g.
/// "255.255.255.0"). Out-of-range values fall back to /24 so a malformed push
/// can never produce an unusable mask.
#[cfg(target_os = "linux")]
fn prefix_to_netmask(prefix: u8) -> String {
    let p = if (1..=32).contains(&prefix) {
        prefix
    } else {
        24
    };
    let mask: u32 = if p == 32 { u32::MAX } else { !0u32 << (32 - p) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

/// Verify the server static public key.
/// * `pinned_hex` Some — the received bytes must match exactly (explicit pin).
/// * `pinned_hex` None — trust-on-first-use *with persistence*: the key is pinned
///   in a `known_hosts` store on first sight (keyed by `server_id` = host:port) and
///   verified against it on every later connection, so a later key change aborts as
///   a probable MITM (instead of the old behaviour of warning and accepting any key
///   every time).
#[cfg(target_os = "linux")]
fn verify_server_key(
    received: &[u8],
    pinned_hex: &Option<String>,
    server_id: &str,
    allow_unpinned: bool,
) -> anyhow::Result<()> {
    let received_hex: String = received.iter().map(|b| format!("{:02x}", b)).collect();
    match pinned_hex {
        Some(expected) => {
            let expected_clean = expected.replace([':', '-', ' '], "").to_lowercase();
            if received_hex != expected_clean {
                return Err(anyhow::anyhow!(
                    "SERVER KEY MISMATCH — possible MITM attack!\n  Expected: {}\n  Received: {}",
                    expected_clean,
                    received_hex
                ));
            }
            log::debug!("Server public key verified: {}", received_hex);
            Ok(())
        }
        None => trust_on_first_use(server_id, &received_hex, allow_unpinned),
    }
}

/// Path of the TOFU trust store (SSH-`known_hosts`-style). Override with
/// `QELI_KNOWN_HOSTS` (tests, or routers with a different writable path).
#[cfg(target_os = "linux")]
fn known_hosts_path() -> String {
    std::env::var("QELI_KNOWN_HOSTS").unwrap_or_else(|_| "/var/lib/qeli/known_hosts".to_string())
}

/// Trust-on-first-use with persistence. Pins the server's static key on first
/// sight (recorded under `server_id`), then verifies every later connection
/// against it — a changed key aborts as a probable MITM. An unwritable store fails
/// closed unless the explicit `allow_unpinned_tofu` escape hatch is enabled; a
/// readable existing pin is always enforced.
#[cfg(target_os = "linux")]
fn trust_on_first_use(
    server_id: &str,
    received_hex: &str,
    allow_unpinned: bool,
) -> anyhow::Result<()> {
    trust_on_first_use_at(&known_hosts_path(), server_id, received_hex, allow_unpinned)
}

/// Path-injectable core of [`trust_on_first_use`] — unit-testable without touching
/// the real `/var/lib/qeli/known_hosts`.
#[cfg(target_os = "linux")]
fn trust_on_first_use_at(
    path: &str,
    server_id: &str,
    received_hex: &str,
    allow_unpinned: bool,
) -> anyhow::Result<()> {
    let check_existing = || -> Option<anyhow::Result<()>> {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((id, key)) = line.split_once(char::is_whitespace) {
                    if id == server_id {
                        let pinned = key.trim().to_lowercase();
                        if pinned == received_hex {
                            log::debug!("Server key matches the known_hosts pin for {}", server_id);
                            return Some(Ok(()));
                        }
                        return Some(Err(anyhow::anyhow!(
                            "SERVER KEY MISMATCH for {} — possible MITM attack!\n  Pinned:   {}\n  \
                             Received: {}\n  If you deliberately rotated the server key, remove the \
                             '{}' line from {} (or set auth.server_public_key) and reconnect.",
                            server_id,
                            pinned,
                            received_hex,
                            server_id,
                            path
                        )));
                    }
                }
            }
        }
        None
    };
    if let Some(result) = check_existing() {
        return result;
    }

    // First sighting: serialize the read/decision/append across processes. The second read
    // under the sidecar lock is the important one — another client may have pinned a key
    // between our optimistic read above and acquiring the lock.
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _lock = match crate::util::FileLock::acquire(path) {
        Ok(lock) => lock,
        Err(error) => {
            if !allow_unpinned {
                return Err(anyhow::anyhow!(
                    "cannot lock the known_hosts store {} for {} ({}). Refusing to make an \
                     unserialized first-trust decision; fix the path or set \
                     allow_unpinned_tofu = true to accept the risk.",
                    path,
                    server_id,
                    error
                ));
            }
            log::warn!(
                "could not lock the TOFU store {} for {} ({}) — continuing UNPINNED by \
                 explicit allow_unpinned_tofu",
                path,
                server_id,
                error
            );
            return Ok(());
        }
    };
    if let Some(result) = check_existing() {
        return result;
    }

    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    // Create known_hosts with 0600 from the start — no world-readable umask window
    // between create and the set_permissions below (which only re-tightens re-opens).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            // The result used to be discarded, and the "pinned" message printed anyway —
            // so on a full or read-only disk the operator was told the key was recorded
            // when nothing had been written, and the NEXT connection would happily TOFU
            // a different key. Treat a failed write exactly like a failed open.
            if let Err(e) =
                writeln!(f, "{} {}", server_id, received_hex).and_then(|()| f.sync_all())
            {
                if !allow_unpinned {
                    return Err(anyhow::anyhow!(
                        "cannot pin server key for {} — writing to the known_hosts store {}                          failed ({}). Refusing to continue unpinned; fix the path or set                          allow_unpinned_tofu = true to accept the risk.",
                        server_id,
                        path,
                        e
                    ));
                }
                log::warn!(
                    "could not record the TOFU pin for {} in {} ({}) — continuing UNPINNED, so                      a future key change will NOT be detected",
                    server_id,
                    path,
                    e
                );
                return Ok(());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            log::warn!(
                "Pinned server key for {} on first use (TOFU) → recorded in {}. A future key \
                 change will now abort as a possible MITM. Pin explicitly with \
                 auth.server_public_key to verify out-of-band.",
                server_id,
                path
            );
            Ok(())
        }
        Err(e) => {
            if !allow_unpinned {
                return Err(anyhow::anyhow!(
                    "cannot pin server key for {} — the known_hosts store {} is unwritable ({}). \
                     Refusing to connect unpinned (fail closed) to avoid a first-connect MITM \
                     window. Fix: set auth.server_public_key to pin explicitly (recommended), \
                     point QELI_KNOWN_HOSTS at a writable path, or set \
                     allow_unpinned_tofu = true to accept the risk.",
                    server_id,
                    path,
                    e
                ));
            }
            log::warn!(
                "⚠ Could not record server key in {} ({}). MITM protection NOT pinned this run \
                 (allow_unpinned_tofu = true); set key in [qeli] to pin explicitly. \
                 Server key: {}",
                path,
                e,
                received_hex
            );
            Ok(())
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lifecycle_adapter_tests {
    use super::*;

    const CONFIG: &str = "[qeli]\nserver = 127.0.0.1:443\nproto = tcp\nuser = test\npass = secret\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nmode = fake-tls\n";

    fn plan(generation: u64) -> NetworkPlan {
        NetworkPlan {
            generation,
            tunnel_address: "10.20.0.2".into(),
            prefix_len: 24,
            mtu: 1400,
            tunnel_gateway: "10.20.0.1".into(),
            carrier_address: None,
            routes: vec![NetworkRoute {
                cidr: "192.0.2.0/24".into(),
                gateway: "10.20.0.1".into(),
                metric: 100,
            }],
            pushed_routes: vec!["192.0.2.0/24".into()],
            dns_servers: vec![NetworkDns {
                address: "10.20.0.1".into(),
                port: 53,
            }],
            full_tunnel: false,
            kill_switch: false,
            max_streams: 1,
            adaptive: false,
            data_plane: Default::default(),
            connection_log: Vec::new(),
        }
    }

    #[test]
    fn linux_adapter_enters_running_only_after_platform_apply() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        assert_eq!(adapter.core.state(), ClientState::Connecting);

        let generation = adapter.next_generation();
        let result = adapter
            .apply_network_plan(plan(generation), |event_plan| {
                assert_eq!(event_plan.generation, generation);
                assert_eq!(event_plan.routes[0].gateway, "10.20.0.1");
                Ok(42)
            })
            .unwrap();

        assert_eq!(result, 42);
        assert_eq!(adapter.core.state(), ClientState::Running);
    }

    #[test]
    fn linux_adapter_rejects_a_partial_platform_plan() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        let generation = adapter.next_generation();
        let error = adapter
            .apply_network_plan::<()>(plan(generation), |_| {
                Err(anyhow::anyhow!("route installation failed"))
            })
            .unwrap_err();

        assert!(error.to_string().contains("route installation failed"));
        assert_eq!(adapter.core.state(), ClientState::Failed);
    }
}

#[cfg(test)]
mod obf_push_tests {
    use super::*;
    use crate::config::PushedObf;

    #[test]
    fn ipv4_only_dataplane_rejects_ipv6_and_truncated_packets() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45;
        assert!(is_supported_inner_packet(&ipv4));

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        assert!(!is_supported_inner_packet(&ipv6));
        assert!(!is_supported_inner_packet(&ipv4[..19]));
        assert!(!is_supported_inner_packet(&[]));
    }

    #[test]
    fn multi_a_budget_is_shared_across_remaining_candidates() {
        let total = Duration::from_secs(30);
        assert_eq!(
            per_candidate_connect_budget(total, 3),
            Duration::from_secs(10)
        );
        assert_eq!(
            per_candidate_connect_budget(total, 2),
            Duration::from_secs(15)
        );
        assert_eq!(per_candidate_connect_budget(total, 1), total);
        assert_eq!(per_candidate_connect_budget(total, 0), total);
    }

    #[test]
    fn rx_liveness_uses_the_actual_promised_cadence() {
        assert_eq!(
            crate::protocol::liveness_deadline(
                true,
                Duration::from_secs(15),
                Duration::from_secs(2),
                false,
                Duration::ZERO,
            ),
            Some(Duration::from_secs(51)),
        );
        assert_eq!(
            crate::protocol::liveness_deadline(
                false,
                Duration::from_secs(15),
                Duration::ZERO,
                true,
                Duration::from_secs(120),
            ),
            Some(Duration::from_secs(363)),
        );
        assert_eq!(
            crate::protocol::liveness_deadline(
                false,
                Duration::from_secs(15),
                Duration::ZERO,
                false,
                Duration::from_secs(120),
            ),
            None,
        );
    }

    /// The keyed `OK:{json}` payload round-trips through parse_auth_ok: every
    /// field is looked up by key, so routes (JSON, full of `:`) and the inline
    /// obfuscation object both survive intact regardless of order.
    #[test]
    fn parse_auth_ok_extracts_keyed_fields() {
        let mut obf = PushedObf::default();
        obf.padding.min_bytes = 99;
        obf.padding.max_bytes = 777;
        obf.heartbeat.interval_ms = 4242;
        obf.traffic_normalization.enabled = true;
        obf.traffic_normalization.round_sizes = vec![10, 20, 30];
        let obf_json = serde_json::to_string(&obf).unwrap();

        let msg = format!(
            r#"OK:{{"client_ip":"10.9.0.5","server_ip":"10.9.0.1","dns":"10.9.0.1","dns_port":53,"routes":[{{"cidr":"10.20.0.0/16","gateway":"10.9.0.1"}}],"obfuscation":{}}}"#,
            obf_json
        );

        let ok = parse_auth_ok(&msg).expect("parses");
        assert_eq!(ok.client_ip, "10.9.0.5");
        assert_eq!(ok.dns_ip, "10.9.0.1");
        assert_eq!(ok.dns_port, "53");
        assert!(
            ok.routes_json.contains("10.20.0.0/16"),
            "routes survive: {}",
            ok.routes_json
        );
        let po = ok.pushed_obf.expect("obf present");
        assert_eq!(po.padding.min_bytes, 99);
        assert_eq!(po.padding.max_bytes, 777);
        assert_eq!(po.heartbeat.interval_ms, 4242);
        assert!(po.traffic_normalization.enabled);
        assert_eq!(po.traffic_normalization.round_sizes, vec![10, 20, 30]);
    }

    #[test]
    fn parse_auth_ok_rejects_non_ok_and_malformed() {
        assert!(parse_auth_ok("ERR: bad credentials").is_err()); // not an OK frame
        assert!(parse_auth_ok("OK:not json").is_err()); // malformed JSON
        assert!(parse_auth_ok(r#"OK:{"server_ip":"x"}"#).is_err()); // missing client_ip
    }

    /// The two addresses must be parsed as IPv4, not merely non-empty.
    ///
    /// They were the last fields the client took from the server on trust, while every
    /// other pushed value (DNS, CIDRs, gateways) is validated. `client_ip` is handed to
    /// `ip addr add` and `server_ip` becomes the default-route gateway.
    /// (Audit 2026-07-27, C5.)
    #[test]
    fn parse_auth_ok_validates_pushed_addresses() {
        // Non-address client_ip.
        for bad in [
            "not-an-ip",
            "-1.2.3.4",
            "10.0.0.1 metric 0",
            "1.2.3.4/24",
            "::1",
        ] {
            let msg = format!(r#"OK:{{"client_ip":"{bad}","server_ip":"10.0.0.1"}}"#);
            assert!(
                parse_auth_ok(&msg).is_err(),
                "client_ip {bad:?} must be rejected"
            );
        }
        // Non-address server_ip.
        for bad in ["-6", "10.0.0.1 via x", "gateway"] {
            let msg = format!(r#"OK:{{"client_ip":"10.9.0.2","server_ip":"{bad}"}}"#);
            assert!(
                parse_auth_ok(&msg).is_err(),
                "server_ip {bad:?} must be rejected"
            );
        }
        // An ABSENT server_ip stays acceptable — an older server omits it.
        let ok = parse_auth_ok(r#"OK:{"client_ip":"10.9.0.2"}"#).expect("absent server_ip is ok");
        assert_eq!(ok.client_ip, "10.9.0.2");
        assert_eq!(ok.server_ip, "");
        // And the well-formed pair still parses.
        let ok = parse_auth_ok(r#"OK:{"client_ip":"10.9.0.2","server_ip":"10.9.0.1"}"#)
            .expect("valid pair parses");
        assert_eq!(ok.server_ip, "10.9.0.1");
    }

    #[test]
    fn parse_auth_ok_reads_pushed_mtu() {
        let ok = parse_auth_ok(r#"OK:{"client_ip":"10.9.0.5","mtu":1380}"#).expect("parses");
        assert_eq!(ok.mtu, 1380);
        // absent (older server) => 0, meaning "not pushed"
        let ok2 = parse_auth_ok(r#"OK:{"client_ip":"10.9.0.5"}"#).expect("parses");
        assert_eq!(ok2.mtu, 0);
        // out-of-range values are ignored (treated as not pushed)
        let ok3 = parse_auth_ok(r#"OK:{"client_ip":"10.9.0.5","mtu":50}"#).expect("parses");
        assert_eq!(ok3.mtu, 0);
    }

    #[test]
    fn effective_mtu_precedence() {
        assert_eq!(effective_mtu(1280, 1400), 1280); // explicit client override wins
        assert_eq!(effective_mtu(0, 1400), 1400); // else adopt server-pushed
        assert_eq!(
            effective_mtu(0, 0),
            crate::config::client::MTU_AUTO_FALLBACK
        ); // else fallback
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn prefix_to_netmask_known_values() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(23), "255.255.254.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
        // out-of-range falls back to /24 (never an unusable mask)
        assert_eq!(prefix_to_netmask(0), "255.255.255.0");
        assert_eq!(prefix_to_netmask(33), "255.255.255.0");
    }

    #[test]
    fn parse_auth_ok_reads_prefix_with_default() {
        // explicit prefix is honoured
        let with = r#"OK:{"client_ip":"10.9.0.5","prefix":23,"server_ip":"10.9.0.1"}"#;
        assert_eq!(parse_auth_ok(with).unwrap().prefix, 23);
        // missing prefix → default /24 (older server)
        let without = r#"OK:{"client_ip":"10.9.0.5","server_ip":"10.9.0.1"}"#;
        assert_eq!(parse_auth_ok(without).unwrap().prefix, 24);
        // out-of-range prefix → default /24
        let bad = r#"OK:{"client_ip":"10.9.0.5","prefix":99}"#;
        assert_eq!(parse_auth_ok(bad).unwrap().prefix, 24);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tofu_tests {
    use super::trust_on_first_use_at;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qeli-known-hosts-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn pins_on_first_use_then_accepts_same_key() {
        let p = tmp("pin");
        let path = p.to_str().unwrap();
        let key = "aa".repeat(32);
        // First sight records and accepts; the same key later is accepted from store.
        assert!(trust_on_first_use_at(path, "vpn.example.com:443", &key, false).is_ok());
        assert!(trust_on_first_use_at(path, "vpn.example.com:443", &key, false).is_ok());
        cleanup(path);
    }

    #[test]
    fn unwritable_store_fails_closed_unless_opted_in() {
        // A directory path can be neither read as a file nor opened for append on
        // any platform, so the first-sight write fails deterministically.
        let dir = tmp("directory");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let key = "cc".repeat(32);
        // Default (fail closed): unpinned + unwritable store => abort.
        assert!(trust_on_first_use_at(path, "h:443", &key, false).is_err());
        // Opt-in escape hatch: accept-any-key TOFU is allowed.
        assert!(trust_on_first_use_at(path, "h:443", &key, true).is_ok());
        cleanup(path);
        let _ = std::fs::remove_dir(path);
    }

    #[test]
    fn rejects_changed_key_as_mitm() {
        let p = tmp("mitm");
        let path = p.to_str().unwrap();
        assert!(trust_on_first_use_at(path, "h:443", &"aa".repeat(32), false).is_ok());
        let err = trust_on_first_use_at(path, "h:443", &"bb".repeat(32), false).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
        cleanup(path);
    }

    #[test]
    fn distinct_servers_are_independent() {
        let p = tmp("multi");
        let path = p.to_str().unwrap();
        assert!(trust_on_first_use_at(path, "a:443", &"11".repeat(32), false).is_ok());
        assert!(trust_on_first_use_at(path, "b:443", &"22".repeat(32), false).is_ok());
        assert!(trust_on_first_use_at(path, "a:443", &"11".repeat(32), false).is_ok());
        assert!(trust_on_first_use_at(path, "a:443", &"22".repeat(32), false).is_err());
        cleanup(path);
    }

    #[test]
    fn concurrent_first_use_commits_exactly_one_key() {
        let p = tmp("race");
        let path = p.to_str().unwrap().to_string();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for key in ["aa".repeat(32), "bb".repeat(32)] {
            let path = path.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                trust_on_first_use_at(&path, "h:443", &key, false)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("TOFU worker must not panic"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let content = std::fs::read_to_string(&path).expect("winning pin must be durable");
        assert_eq!(
            content
                .lines()
                .filter(|line| line.starts_with("h:443 "))
                .count(),
            1
        );
        cleanup(&path);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod device_id_tests {
    use super::device_id_at;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "qeli-device-id-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn generates_persists_and_reloads() {
        let p = tmp("stable");
        let path = p.to_str().unwrap();
        let id = device_id_at(path);
        assert_ne!(id, [0u8; crate::protocol::DEVICE_ID_LEN]);
        assert_eq!(device_id_at(path), id, "id must be stable across restarts");
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    /// An all-zero id file must not become the device identity: every client with
    /// such a (zero-filled/corrupted) file would alias onto ONE device key and
    /// supersede each other's sessions. It is treated as corrupt and replaced.
    #[test]
    fn all_zero_file_is_regenerated() {
        let p = tmp("zero");
        let path = p.to_str().unwrap();
        std::fs::write(path, [0u8; crate::protocol::DEVICE_ID_LEN]).unwrap();
        let id = device_id_at(path);
        assert_ne!(id, [0u8; crate::protocol::DEVICE_ID_LEN]);
        // The bad file is overwritten, so the regenerated id is stable from now on.
        assert_eq!(std::fs::read(path).unwrap(), id);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.lock"));
    }

    #[test]
    fn concurrent_first_use_publishes_one_device_id() {
        let path = tmp("race");
        let path_text = path.to_string_lossy().into_owned();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path_text.clone();
                std::thread::spawn(move || device_id_at(&path))
            })
            .collect();
        let ids: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(ids.iter().all(|id| id == &ids[0]));
        assert_eq!(std::fs::read(&path).unwrap(), ids[0]);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }
}
