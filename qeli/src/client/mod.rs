#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
mod identity_files;
#[cfg(target_os = "linux")]
mod identity_worker;
#[cfg(all(test, target_os = "linux"))]
use identity_files::{device_id_at, trust_on_first_use_at};
#[cfg(target_os = "linux")]
pub mod killswitch;
#[cfg(target_os = "linux")]
mod network_lease;
#[cfg(target_os = "linux")]
mod network_task;
#[cfg(target_os = "linux")]
mod plan_publication;
#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
mod roaming_linux;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
mod status_writer;
#[cfg(target_os = "linux")]
mod tun_recovery;

use crate::crypto::{
    derive_data_frag_key, derive_keys, derive_keys_bound, derive_keys_hybrid,
    derive_keys_hybrid_bound, handshake_transcript_hash, Keypair,
};
#[cfg(feature = "experimental-roaming")]
use crate::crypto::{derive_session_material_hybrid, derive_session_material_hybrid_bound};
use crate::protocol::{
    generate_connection_id, read_record, read_record_into, read_tls_record, unwrap_quic,
    wrap_quic_long, wrap_quic_short, FakeTlsHandshake, Framing, Obfuscator, PacketCodec,
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
use crate::transport_core::buffer_pool::{BufferPool, PooledBuffer};
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
use crate::transport_core::client_downlink::DownlinkDrop;
use crate::transport_core::client_uplink::{UplinkCounters, UplinkDrop};
#[cfg(target_os = "linux")]
use crate::transport_core::network::is_full_tunnel;
use crate::transport_core::network::{build_network_plan, server_push_log_lines, HandshakeNetwork};
#[cfg(feature = "experimental-roaming")]
use crate::transport_core::path::PathCommandFailure;
use crate::transport_core::path::PreparedPathCandidate;
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
use crate::transport_core::path::{PathCommand, PathCommandAction, PathCommandOutcome};
use crate::transport_core::session::{
    authenticate_tcp, build_client_auth_plaintext, build_udp_client_hello_flight, effective_mtu,
    parse_auth_ok, static_es, verify_server_identity, AuthOk, TcpAuthentication,
    UdpClientHelloFlight,
};
use crate::transport_core::udp_buffer::{
    InternalDrop, UdpBufferController, UdpBufferPolicy, AUTO_MAX_RECV_BYTES,
};
#[cfg(target_os = "windows")]
use crate::transport_core::wintun::{TunPacket, TunWriter, WindowsTunPump};
#[cfg(any(target_os = "linux", feature = "experimental-roaming"))]
use crate::transport_core::ClientCore;
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
use crate::transport_core::ClientEvent;
#[cfg(target_os = "linux")]
use crate::transport_core::{platform_capability, ClientState, CoreOptions, EventKind};
#[cfg(all(test, target_os = "linux"))]
use crate::transport_core::{NetworkDns, NetworkRoute};
use crate::transport_core::{NetworkPlan, RuntimeCounters};

/// How many extra copies of the inner-MTU and certified UDP-budget reports the UDP data plane
/// emits after the first (#13/#5). Neither frame is acknowledged, so a single lost datagram
/// would otherwise affect the whole session's downlink sizing. Three copies, spread over the
/// first ~10 s of idle ticks, survive both an isolated drop and a short burst. Both updates are
/// idempotent and all copies carry the same values, so duplicates are harmless.
/// TCP needs none of this — it retransmits for us.
const UDP_CONTROL_REPORT_RESENDS: u8 = 3;
/// PacketCodec framing/nonce/counter/tag/padding-trailer plus probe safety margin. This is
/// used only to translate the existing inner-MTU-shaped probe into the independently tracked
/// UDP payload budget that the probe actually certified.
const UDP_RECORD_PROBE_OVERHEAD: usize = crate::protocol::udp_frag::UDP_RECORD_PROBE_OVERHEAD;
/// Confirmation catches same-endpoint PMTU shrink; discovery remains sparse.
const UDP_MTU_REPROBE_INTERVAL: Duration = crate::protocol::pmtu::CONFIRM_INTERVAL;
const UDP_MTU_REPROBE_TICK: Duration = crate::protocol::pmtu::TICK;
#[cfg(test)]
const UDP_MTU_REPROBE_REPLY_TIMEOUT: Duration = crate::protocol::pmtu::INITIAL_TIMEOUT;
#[cfg(test)]
const UDP_MTU_REPROBE_SENDS: u8 = 2;
/// Kept equal to the server's experimental grace. The attempt itself is bounded by the
/// remaining budget; expiry falls back to the ordinary full reconnect and NetworkPlan cycle.
const TCP_RESUME_GRACE: Duration = Duration::from_secs(30);
const TCP_RESUME_MAINTENANCE_TICK: Duration = Duration::from_secs(1);
/// A platform PathUpdate may need a short DNS/debounce step after the last carrier disappears.
/// Give its exact-path handover priority over the generic hard-resume dialer; otherwise both can
/// replace slot 0 back-to-back. The ordinary resume remains the bounded fallback when no candidate
/// materializes promptly.
#[cfg(feature = "experimental-roaming")]
const TCP_HANDOVER_PREPARE_GRACE: Duration = Duration::from_secs(1);
#[cfg(feature = "experimental-roaming")]
const TCP_CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_millis(750);
#[cfg(feature = "experimental-roaming")]
const TCP_HANDOVER_POLL: Duration = Duration::from_millis(100);
#[cfg(feature = "experimental-roaming")]
const PATH_ACK_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Default)]
struct LiveUdpMtuProbe {
    search: crate::protocol::pmtu::ProbeSearch,
    path_epoch: u64,
    budget_revision: u64,
    confirmation: bool,
}

impl LiveUdpMtuProbe {
    fn start(&mut self, candidates: impl IntoIterator<Item = i32>) {
        let mut candidates = candidates
            .into_iter()
            .filter_map(|value| usize::try_from(value).ok());
        if self.confirmation {
            if let Some(current) = candidates.next() {
                self.search
                    .start_confirmation(current, candidates.next().unwrap_or(current));
            } else {
                self.search.clear();
            }
        } else {
            self.search.start_discovery(candidates);
        }
    }

    fn is_active(&self) -> bool {
        self.search.is_active()
    }

    fn clear(&mut self) {
        self.search.clear();
    }

    fn next_send(&mut self, now: tokio::time::Instant) -> Option<(u128, i32)> {
        let challenge = self.search.next_send(now)?;
        Some((challenge.token, i32::try_from(challenge.budget).ok()?))
    }

    fn matches(&self, token: u128, size: u16, epoch: u64, revision: u64) -> bool {
        self.path_epoch == epoch
            && self.budget_revision == revision
            && self.search.challenge.is_some_and(|challenge| {
                challenge.token == token
                    && challenge.budget + UDP_RECORD_PROBE_OVERHEAD == usize::from(size)
            })
    }

    fn acknowledge(&mut self, token: u128, probe_payload_size: u16) -> Option<i32> {
        let candidate = usize::from(probe_payload_size).checked_sub(UDP_RECORD_PROBE_OVERHEAD)?;
        self.search
            .acknowledge(token, candidate, tokio::time::Instant::now())
            .and_then(|value| i32::try_from(value).ok())
    }
}

fn udp_payload_budget_for_probe(probe_mtu: i32, seal_overhead: usize, wrapper_len: usize) -> usize {
    (probe_mtu.max(0) as usize)
        .saturating_add(UDP_RECORD_PROBE_OVERHEAD)
        .saturating_add(seal_overhead)
        .saturating_add(wrapper_len)
}

/// Accept only packets belonging to the address families negotiated atomically in the
/// authenticated NetworkPlan. Packets from a disabled family must not leak into a profile
/// merely because the host TUN briefly retains an old route during reconfiguration.
#[inline]
fn is_supported_inner_packet(
    packet: &[u8],
    family_mode: crate::transport_core::NetworkFamilyMode,
) -> bool {
    let Ok(meta) = crate::protocol::ip::parse_ip_packet(packet) else {
        return false;
    };
    matches!(
        (family_mode, meta.version),
        (
            crate::transport_core::NetworkFamilyMode::Ipv4,
            crate::protocol::ip::IpVersion::V4
        ) | (
            crate::transport_core::NetworkFamilyMode::Ipv6,
            crate::protocol::ip::IpVersion::V6
        ) | (crate::transport_core::NetworkFamilyMode::Dual, _)
    )
}

#[cfg(target_os = "linux")]
fn tap_gateway_facts(
    addresses: &[crate::transport_core::NetworkAddress],
) -> (
    Option<std::net::Ipv4Addr>,
    u8,
    Option<std::net::Ipv6Addr>,
    u8,
) {
    let mut ipv4 = None;
    let mut ipv4_prefix_len = 0;
    let mut ipv6 = None;
    let mut ipv6_prefix_len = 0;
    for address in addresses {
        match address.family {
            crate::transport_core::NetworkAddressFamily::Ipv4 if ipv4.is_none() => {
                ipv4 = address
                    .gateway
                    .as_deref()
                    .and_then(|value| value.parse().ok());
                ipv4_prefix_len = address.on_link_prefix_len;
            }
            crate::transport_core::NetworkAddressFamily::Ipv6 if ipv6.is_none() => {
                ipv6 = address
                    .gateway
                    .as_deref()
                    .and_then(|value| value.parse().ok());
                ipv6_prefix_len = address.on_link_prefix_len;
            }
            _ => {}
        }
    }
    (ipv4, ipv4_prefix_len, ipv6, ipv6_prefix_len)
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
#[derive(Default)]
struct CarrierCandidateState {
    /// Exact addresses currently admitted to bypass routes and later bonded streams. Once pinned,
    /// this remains restricted to the authenticated connected/committed endpoint.
    addresses: Vec<std::net::IpAddr>,
    /// Generation-scoped DNS results retained only to prepare an authenticated roaming candidate.
    roaming_discovery_addresses: Vec<std::net::IpAddr>,
    /// Once the host routes are committed, bonded streams must stay within this set.
    /// Re-resolving to an unpinned address after full-tunnel capture would route the
    /// encrypted carrier into qeli itself.
    pinned: bool,
    /// Rotate the first candidate between top-level reconnect generations. UDP
    /// `connect()` alone cannot prove reachability, so an address that black-holes the
    /// authenticated first flight must not be selected forever just because DNS order
    /// is stable.
    rotation: usize,
}

#[cfg(target_os = "linux")]
impl CarrierCandidateState {
    fn reset(&mut self, rotation: usize) {
        self.addresses.clear();
        self.roaming_discovery_addresses.clear();
        self.pinned = false;
        self.rotation = rotation;
    }

    fn note_resolved(&mut self, candidates: impl IntoIterator<Item = std::net::IpAddr>) {
        if self.pinned {
            return;
        }
        self.addresses.clear();
        self.roaming_discovery_addresses.clear();
        for address in candidates {
            let address = crate::transport_core::carrier::canonical_carrier_ip(address);
            if !self.addresses.contains(&address) {
                self.addresses.push(address);
                self.roaming_discovery_addresses.push(address);
            }
        }
    }

    fn pin_authenticated(&mut self, addresses: &[std::net::IpAddr]) {
        if self.roaming_discovery_addresses.is_empty() {
            self.roaming_discovery_addresses.extend(
                addresses
                    .iter()
                    .copied()
                    .map(crate::transport_core::carrier::canonical_carrier_ip),
            );
        }
        self.addresses = addresses
            .iter()
            .copied()
            .map(crate::transport_core::carrier::canonical_carrier_ip)
            .collect();
        self.pinned = true;
    }

    #[cfg(any(feature = "experimental-roaming", test))]
    fn roaming_discovery(&self) -> Vec<std::net::IpAddr> {
        self.roaming_discovery_addresses.clone()
    }
}

#[cfg(target_os = "linux")]
static CARRIER_CANDIDATES: std::sync::Mutex<CarrierCandidateState> =
    std::sync::Mutex::new(CarrierCandidateState {
        addresses: Vec::new(),
        roaming_discovery_addresses: Vec::new(),
        pinned: false,
        rotation: 0,
    });

#[cfg(target_os = "linux")]
fn note_connected_peer(ip: std::net::IpAddr) {
    let ip = crate::transport_core::carrier::canonical_carrier_ip(ip);
    if let Ok(mut g) = CONNECTED_PEER.lock() {
        *g = Some(ip);
    }
}

#[cfg(target_os = "linux")]
fn reset_carrier_candidates(rotation: usize) {
    if let Ok(mut state) = CARRIER_CANDIDATES.lock() {
        state.reset(rotation);
    }
    if let Ok(mut peer) = CONNECTED_PEER.lock() {
        *peer = None;
    }
}

#[cfg(target_os = "linux")]
fn rotate_carrier_candidates<T>(candidates: &mut [T]) {
    if candidates.is_empty() {
        return;
    }
    let rotation = CARRIER_CANDIDATES
        .lock()
        .map(|state| state.rotation)
        .unwrap_or(0)
        % candidates.len();
    candidates.rotate_left(rotation);
}

#[cfg(target_os = "linux")]
fn note_carrier_candidates(candidates: impl IntoIterator<Item = std::net::IpAddr>) {
    if let Ok(mut state) = CARRIER_CANDIDATES.lock() {
        state.note_resolved(candidates);
    }
}

#[cfg(target_os = "linux")]
fn select_carrier_pin_targets(
    mut candidates: Vec<std::net::IpAddr>,
    connected_peer: Option<std::net::IpAddr>,
    literal_server: Option<std::net::IpAddr>,
) -> Vec<std::net::IpAddr> {
    // A completed connect is stronger evidence than DNS resolution. Pinning every resolved
    // address here both leaks stale DNS choices into the host FIB and lets a later bonded
    // stream select an endpoint that was never authenticated. A new endpoint is admitted only
    // through a prepared roaming transaction, whose candidate socket proves reachability first.
    if let Some(peer) = connected_peer {
        return vec![crate::transport_core::carrier::canonical_carrier_ip(peer)];
    }
    if candidates.is_empty() {
        if let Some(literal) = literal_server {
            candidates.push(crate::transport_core::carrier::canonical_carrier_ip(
                literal,
            ));
        }
    }
    candidates
}

#[cfg(target_os = "linux")]
fn carrier_pin_targets(config: &crate::config::client::ClientConfig) -> Vec<std::net::IpAddr> {
    let candidates = CARRIER_CANDIDATES
        .lock()
        .map(|state| state.addresses.clone())
        .unwrap_or_default();
    let connected_peer = CONNECTED_PEER.lock().ok().and_then(|peer| *peer);
    let literal_server = config.server.address.parse::<std::net::IpAddr>().ok();
    select_carrier_pin_targets(candidates, connected_peer, literal_server)
}

#[cfg(target_os = "linux")]
fn mark_carrier_candidates_pinned(addresses: &[std::net::IpAddr]) {
    if let Ok(mut state) = CARRIER_CANDIDATES.lock() {
        state.pin_authenticated(addresses);
    }
}

#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
fn carrier_candidate_ips() -> Vec<std::net::IpAddr> {
    crate::util::lock_or_recover(&CARRIER_CANDIDATES, "client::carrier_candidates")
        .roaming_discovery()
}

#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
fn active_carrier_ips() -> Vec<std::net::IpAddr> {
    let state = crate::util::lock_or_recover(&CARRIER_CANDIDATES, "client::active_carriers");
    if state.pinned {
        state.addresses.clone()
    } else {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn pinned_carrier_socket_addresses(port: u16) -> Option<Vec<std::net::SocketAddr>> {
    CARRIER_CANDIDATES.lock().ok().and_then(|state| {
        state.pinned.then(|| {
            state
                .addresses
                .iter()
                .copied()
                .map(|address| std::net::SocketAddr::new(address, port))
                .collect()
        })
    })
}

#[cfg(all(test, target_os = "linux"))]
mod carrier_pin_tests {
    use super::{select_carrier_pin_targets, CarrierCandidateState};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn authenticated_peer_excludes_unconnected_dns_candidates() {
        let dead = IpAddr::V4(Ipv4Addr::new(10, 10, 9, 9));
        let connected = IpAddr::V4(Ipv4Addr::new(10, 10, 2, 2));
        assert_eq!(
            select_carrier_pin_targets(vec![dead, connected], Some(connected), None),
            vec![connected]
        );
    }

    #[test]
    fn unresolved_connect_fallback_keeps_literal_server() {
        let literal = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(
            select_carrier_pin_targets(Vec::new(), None, Some(literal)),
            vec![literal]
        );
    }

    #[test]
    fn roaming_discovery_survives_exact_active_pinning() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10));
        let mut state = CarrierCandidateState::default();
        state.note_resolved([ipv4, ipv6, ipv4]);
        state.pin_authenticated(&[ipv4]);

        assert_eq!(
            state.addresses,
            vec![ipv4],
            "bypass and bonded carriers remain restricted to the authenticated peer"
        );
        assert_eq!(
            state.roaming_discovery(),
            vec![ipv4, ipv6],
            "the other family remains available only for an authenticated path transaction"
        );
        assert!(state.pinned);
    }
}

#[cfg(target_os = "linux")]
use crate::transport::tcp::set_tcp_keepalive;
#[cfg(target_os = "linux")]
use crate::tun::iface::{DeviceType, TunInterface};
#[cfg(target_os = "linux")]
use crate::tun::{is_tap_mode, mac_from_ip};
use rand::prelude::*;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
// `portable_atomic::AtomicU64` so the data-plane byte counters compile on 32-bit
// mipsel routers (no native 64-bit atomics); native instruction on aarch64/x86_64.
use crate::protocol::stream_io::WriteAllFlush;
use crate::transport_core::tcp_carrier_metrics::{CarrierMetrics, CloseGuard, InFlight, Ticket};
use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

pub(crate) type IdentityFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'static>>;
pub(crate) type IdentityVerifier = Arc<dyn Fn([u8; 32]) -> IdentityFuture + Send + Sync + 'static>;
#[cfg(target_os = "linux")]
pub(crate) struct PendingLifecycleHook {
    command: String,
    environment: Vec<(String, String)>,
    positional_arguments: Vec<String>,
    context_json: String,
}
#[cfg(not(target_os = "linux"))]
pub(crate) struct PendingLifecycleHook;

/// Stable, secret-free process-lifecycle snapshot supplied to Linux client hooks.
///
/// The connection can rebuild its TUN several times while the outer client process remains
/// alive. `post_up` consumes the first committed snapshot; this value is refreshed after every
/// later committed NetworkPlan so the eventual `post_down` sees the latest generation.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct ClientHookContext {
    profile: String,
    config_path: String,
    if_name: String,
    if_index: String,
    device_type: String,
    tun_reused: bool,
    server_host: String,
    server_port: u16,
    protocol: String,
    wire_mode: String,
    fronting: String,
    roaming_policy: String,
    configured_carrier_local_address: String,
    carrier_if_name: String,
    carrier_if_index: String,
    carrier_gateway: String,
    carrier_local_address: String,
    route_local: bool,
    gateway_nat: bool,
    forward: bool,
    exit_node: bool,
    allow_ipv4_leak: bool,
    allow_ipv6_leak: bool,
    lan_subnet: String,
    lan_subnet_ipv6: String,
    include: Vec<String>,
    exclude: Vec<String>,
    plan: Option<NetworkPlan>,
}

#[cfg(target_os = "linux")]
fn hook_bool(value: bool) -> String {
    value.to_string()
}

#[cfg(target_os = "linux")]
fn hook_if_index(if_name: &str) -> String {
    crate::network_interface::index(if_name)
        .ok()
        .flatten()
        .map(|value| value.to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn hook_address_cidr(address: &crate::transport_core::NetworkAddress) -> String {
    format!("{}/{}", address.address, address.prefix_len)
}

#[cfg(target_os = "linux")]
fn hook_address_subnet(address: &crate::transport_core::NetworkAddress) -> String {
    address
        .address
        .parse::<std::net::IpAddr>()
        .ok()
        .and_then(|value| ipnet::IpNet::new(value, address.on_link_prefix_len).ok())
        .map(|network| network.trunc().to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn hook_family_name(family: crate::transport_core::NetworkAddressFamily) -> &'static str {
    match family {
        crate::transport_core::NetworkAddressFamily::Ipv4 => "ipv4",
        crate::transport_core::NetworkAddressFamily::Ipv6 => "ipv6",
    }
}

#[cfg(target_os = "linux")]
fn hook_family_mode(mode: crate::transport_core::NetworkFamilyMode) -> &'static str {
    match mode {
        crate::transport_core::NetworkFamilyMode::Ipv4 => "ipv4",
        crate::transport_core::NetworkFamilyMode::Dual => "dual",
        crate::transport_core::NetworkFamilyMode::Ipv6 => "ipv6",
    }
}

#[cfg(target_os = "linux")]
fn hook_recordizer_mode(plan: Option<&NetworkPlan>) -> String {
    plan.and_then(|plan| plan.data_plane.recordizer_mode)
        .map(|mode| match mode {
            crate::transport_core::NetworkRecordizerMode::LegacyPacketPerRecord => {
                "legacy_packet_per_record"
            }
            crate::transport_core::NetworkRecordizerMode::PacketMuxV1 => "packet_mux_v1",
        })
        .unwrap_or("")
        .to_string()
}

#[cfg(target_os = "linux")]
fn hook_roaming_mode(plan: Option<&NetworkPlan>) -> String {
    plan.and_then(|plan| plan.data_plane.roaming_mode)
        .map(|mode| match mode {
            crate::transport_core::NetworkRoamingMode::Reconnect => "reconnect",
            crate::transport_core::NetworkRoamingMode::UdpRoamV1 => "udp_roam_v1",
            crate::transport_core::NetworkRoamingMode::TcpResumeV2 => "tcp_resume_v2",
            crate::transport_core::NetworkRoamingMode::TcpHandoverV2 => "tcp_handover_v2",
        })
        .unwrap_or("")
        .to_string()
}

#[cfg(target_os = "linux")]
impl ClientHookContext {
    fn new(config: &crate::config::client::ClientConfig, config_path: &str) -> Self {
        let canonical_path = std::fs::canonicalize(config_path)
            .unwrap_or_else(|_| std::path::PathBuf::from(config_path));
        let profile = canonical_path
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("default")
            .to_string();
        Self {
            profile,
            config_path: canonical_path.to_string_lossy().into_owned(),
            if_name: config.tun.name.clone(),
            if_index: hook_if_index(&config.tun.name),
            device_type: config.tun.device_type.to_ascii_lowercase(),
            tun_reused: config.tun.attach_existing,
            server_host: config.server.address.clone(),
            server_port: config.server.port,
            protocol: config.server.protocol.clone(),
            wire_mode: config.obfuscation.mode.clone(),
            fronting: config.obfuscation.fronting.clone(),
            roaming_policy: config.roaming.to_string(),
            configured_carrier_local_address: config
                .server
                .local_address
                .clone()
                .unwrap_or_default(),
            carrier_if_name: String::new(),
            carrier_if_index: String::new(),
            carrier_gateway: String::new(),
            carrier_local_address: String::new(),
            route_local: config.routing.route_local_networks,
            gateway_nat: config.routing.gateway_nat,
            forward: config.routing.forward,
            exit_node: config.routing.exit_node,
            allow_ipv4_leak: config.routing.allow_ipv4_leak,
            allow_ipv6_leak: config.routing.allow_ipv6_leak,
            lan_subnet: config.routing.lan_subnet.clone(),
            lan_subnet_ipv6: config.routing.lan_subnet_ipv6.clone(),
            include: config.routing.include.clone(),
            exclude: config.routing.exclude.clone(),
            plan: None,
        }
    }

    fn refresh(&mut self, plan: &NetworkPlan, if_name: &str) {
        self.if_name = if_name.to_string();
        self.if_index = hook_if_index(if_name);
        self.carrier_if_name.clear();
        self.carrier_if_index.clear();
        self.carrier_gateway.clear();
        self.carrier_local_address = self.configured_carrier_local_address.clone();

        if let Some(carrier) = plan
            .carrier_address
            .as_deref()
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        {
            let requested_source = self
                .configured_carrier_local_address
                .parse::<std::net::IpAddr>()
                .ok();
            if let Some(path) = route::hook_physical_path_for(carrier, if_name, requested_source) {
                self.carrier_if_index = hook_if_index(&path.device);
                self.carrier_if_name = path.device;
                self.carrier_gateway = path.gateway.unwrap_or_default();
                if let Some(source) = path.source {
                    self.carrier_local_address = source;
                }
            }
        }
        self.plan = Some(plan.clone());
    }

    fn primary_gateway(&self) -> String {
        let Some(plan) = self.plan.as_ref() else {
            return String::new();
        };
        plan.addresses
            .iter()
            .find(|address| {
                address.family == crate::transport_core::NetworkAddressFamily::Ipv4
                    && address.gateway.is_some()
            })
            .or_else(|| {
                plan.addresses
                    .iter()
                    .find(|address| address.gateway.is_some())
            })
            .and_then(|address| address.gateway.clone())
            .unwrap_or_else(|| plan.tunnel_gateway.clone())
    }

    fn invocation(
        &self,
        command: String,
        event: &str,
        reason: &str,
        error_code: &str,
        error_message: &str,
        session_duration_seconds: u64,
    ) -> PendingLifecycleHook {
        let plan = self.plan.as_ref();
        let primary_gateway = self.primary_gateway();
        let server_endpoint = crate::util::join_host_port(&self.server_host, self.server_port);
        let carrier_address = plan
            .and_then(|plan| plan.carrier_address.clone())
            .unwrap_or_default();
        let carrier_endpoint = if carrier_address.is_empty() {
            String::new()
        } else {
            crate::util::join_host_port(&carrier_address, self.server_port)
        };
        let ipv4 = plan.and_then(|plan| {
            plan.addresses
                .iter()
                .find(|address| address.family == crate::transport_core::NetworkAddressFamily::Ipv4)
        });
        let ipv6 = plan.and_then(|plan| {
            plan.addresses
                .iter()
                .find(|address| address.family == crate::transport_core::NetworkAddressFamily::Ipv6)
        });
        let value = |address: Option<&crate::transport_core::NetworkAddress>| {
            address
                .map(|address| address.address.clone())
                .unwrap_or_default()
        };
        let prefix = |address: Option<&crate::transport_core::NetworkAddress>| {
            address
                .map(|address| address.prefix_len.to_string())
                .unwrap_or_default()
        };
        let on_link_prefix = |address: Option<&crate::transport_core::NetworkAddress>| {
            address
                .map(|address| address.on_link_prefix_len.to_string())
                .unwrap_or_default()
        };
        let gateway = |address: Option<&crate::transport_core::NetworkAddress>| {
            address
                .and_then(|address| address.gateway.clone())
                .unwrap_or_default()
        };
        let cidr = |address: Option<&crate::transport_core::NetworkAddress>| {
            address.map(hook_address_cidr).unwrap_or_default()
        };
        let subnet = |address: Option<&crate::transport_core::NetworkAddress>| {
            address.map(hook_address_subnet).unwrap_or_default()
        };

        let mut environment = vec![
            ("QELI_HOOK_API".into(), "1".into()),
            ("QELI_EVENT".into(), event.into()),
            ("QELI_PROFILE".into(), self.profile.clone()),
            ("QELI_PROFILE_NAME".into(), self.profile.clone()),
            ("QELI_CONFIG_PATH".into(), self.config_path.clone()),
            ("QELI_PID".into(), std::process::id().to_string()),
            ("QELI_PLAN_AVAILABLE".into(), hook_bool(plan.is_some())),
            (
                "QELI_PLAN_GENERATION".into(),
                plan.map(|plan| plan.generation.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_FAMILY_MODE".into(),
                plan.map(|plan| hook_family_mode(plan.family_mode).to_string())
                    .unwrap_or_default(),
            ),
            ("QELI_TUN".into(), self.if_name.clone()),
            ("QELI_IFNAME".into(), self.if_name.clone()),
            ("QELI_IFINDEX".into(), self.if_index.clone()),
            ("QELI_DEVICE_TYPE".into(), self.device_type.clone()),
            ("QELI_TUN_MODE".into(), self.device_type.clone()),
            ("QELI_TUN_REUSED".into(), hook_bool(self.tun_reused)),
            (
                "QELI_MTU".into(),
                plan.map(|plan| plan.mtu.to_string()).unwrap_or_default(),
            ),
            (
                "QELI_TUNNEL_ADDRESS".into(),
                plan.map(|plan| plan.tunnel_address.clone())
                    .unwrap_or_default(),
            ),
            (
                "QELI_PREFIX_LEN".into(),
                plan.map(|plan| plan.prefix_len.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_TUNNEL_GATEWAY".into(),
                plan.map(|plan| plan.tunnel_gateway.clone())
                    .unwrap_or_default(),
            ),
            ("QELI_GATEWAY".into(), primary_gateway.clone()),
            ("QELI_IPV4_ADDRESS".into(), value(ipv4)),
            ("QELI_IPV4_PREFIX".into(), prefix(ipv4)),
            ("QELI_IPV4_PREFIX_LEN".into(), prefix(ipv4)),
            ("QELI_IPV4_ON_LINK_PREFIX_LEN".into(), on_link_prefix(ipv4)),
            ("QELI_IPV4_CIDR".into(), cidr(ipv4)),
            ("QELI_IPV4_SUBNET".into(), subnet(ipv4)),
            ("QELI_IPV4_GATEWAY".into(), gateway(ipv4)),
            ("QELI_IPV6_ADDRESS".into(), value(ipv6)),
            ("QELI_IPV6_PREFIX".into(), prefix(ipv6)),
            ("QELI_IPV6_PREFIX_LEN".into(), prefix(ipv6)),
            ("QELI_IPV6_ON_LINK_PREFIX_LEN".into(), on_link_prefix(ipv6)),
            ("QELI_IPV6_CIDR".into(), cidr(ipv6)),
            ("QELI_IPV6_SUBNET".into(), subnet(ipv6)),
            ("QELI_IPV6_GATEWAY".into(), gateway(ipv6)),
            ("QELI_SERVER".into(), self.server_host.clone()),
            ("QELI_SERVER_HOST".into(), self.server_host.clone()),
            ("QELI_SERVER_PORT".into(), self.server_port.to_string()),
            ("QELI_SERVER_ENDPOINT".into(), server_endpoint),
            ("QELI_CARRIER_ADDRESS".into(), carrier_address),
            ("QELI_CARRIER_ENDPOINT".into(), carrier_endpoint),
            (
                "QELI_CARRIER_LOCAL_ADDRESS".into(),
                self.carrier_local_address.clone(),
            ),
            ("QELI_CARRIER_IFNAME".into(), self.carrier_if_name.clone()),
            ("QELI_CARRIER_IFINDEX".into(), self.carrier_if_index.clone()),
            ("QELI_CARRIER_GATEWAY".into(), self.carrier_gateway.clone()),
            ("QELI_PROTOCOL".into(), self.protocol.clone()),
            ("QELI_WIRE_MODE".into(), self.wire_mode.clone()),
            ("QELI_FRONTING".into(), self.fronting.clone()),
            (
                "QELI_ROUTING_MODE".into(),
                plan.map(|plan| if plan.full_tunnel { "full" } else { "split" })
                    .unwrap_or("")
                    .to_string(),
            ),
            (
                "QELI_FULL_TUNNEL".into(),
                hook_bool(plan.is_some_and(|plan| plan.full_tunnel)),
            ),
            (
                "QELI_KILL_SWITCH".into(),
                hook_bool(plan.is_some_and(|plan| plan.kill_switch)),
            ),
            ("QELI_ROUTE_LOCAL".into(), hook_bool(self.route_local)),
            ("QELI_GATEWAY_NAT".into(), hook_bool(self.gateway_nat)),
            ("QELI_FORWARD".into(), hook_bool(self.forward)),
            ("QELI_EXIT_NODE".into(), hook_bool(self.exit_node)),
            (
                "QELI_ALLOW_IPV4_LEAK".into(),
                hook_bool(self.allow_ipv4_leak),
            ),
            (
                "QELI_ALLOW_IPV6_LEAK".into(),
                hook_bool(self.allow_ipv6_leak),
            ),
            ("QELI_LAN_SUBNET".into(), self.lan_subnet.clone()),
            ("QELI_LAN_SUBNET_IPV6".into(), self.lan_subnet_ipv6.clone()),
            (
                "QELI_ADDRESS_COUNT".into(),
                plan.map(|plan| plan.addresses.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "QELI_DNS_COUNT".into(),
                plan.map(|plan| plan.dns_servers.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "QELI_ROUTE_COUNT".into(),
                plan.map(|plan| plan.routes.len()).unwrap_or(0).to_string(),
            ),
            (
                "QELI_PUSHED_ROUTE_COUNT".into(),
                plan.map(|plan| plan.pushed_routes.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            ("QELI_INCLUDE_COUNT".into(), self.include.len().to_string()),
            ("QELI_EXCLUDE_COUNT".into(), self.exclude.len().to_string()),
            (
                "QELI_MAX_STREAMS".into(),
                plan.map(|plan| plan.max_streams.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_ADAPTIVE".into(),
                hook_bool(plan.is_some_and(|plan| plan.adaptive)),
            ),
            ("QELI_ROAMING_POLICY".into(), self.roaming_policy.clone()),
            ("QELI_ROAMING_MODE".into(), hook_roaming_mode(plan)),
            ("QELI_RECORDIZER_MODE".into(), hook_recordizer_mode(plan)),
            (
                "QELI_RECORDIZER_POLICY".into(),
                plan.and_then(|plan| plan.data_plane.recordizer_policy.clone())
                    .unwrap_or_default(),
            ),
            (
                "QELI_PADDING_ENABLED".into(),
                hook_bool(plan.is_some_and(|plan| plan.data_plane.padding_enabled)),
            ),
            (
                "QELI_PADDING_MIN".into(),
                plan.map(|plan| plan.data_plane.padding_min.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_PADDING_MAX".into(),
                plan.map(|plan| plan.data_plane.padding_max.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_NORMALIZATION_MAX".into(),
                plan.map(|plan| plan.data_plane.normalization_max.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_HEARTBEAT_ENABLED".into(),
                hook_bool(plan.is_some_and(|plan| plan.data_plane.heartbeat_enabled)),
            ),
            (
                "QELI_HEARTBEAT_INTERVAL_MS".into(),
                plan.map(|plan| plan.data_plane.heartbeat_interval_ms.to_string())
                    .unwrap_or_default(),
            ),
            (
                "QELI_SHAPING_ENABLED".into(),
                hook_bool(plan.is_some_and(|plan| plan.data_plane.shaping_enabled)),
            ),
            ("QELI_REASON".into(), reason.into()),
            ("QELI_STOP_REASON".into(), reason.into()),
            ("QELI_ERROR_CODE".into(), error_code.into()),
            ("QELI_ERROR_MESSAGE".into(), error_message.into()),
            (
                "QELI_SESSION_DURATION_SECONDS".into(),
                session_duration_seconds.to_string(),
            ),
        ];

        if let Some(plan) = plan {
            for (index, address) in plan.addresses.iter().enumerate() {
                let base = format!("QELI_ADDRESS_{index}");
                environment.push((
                    format!("{base}_FAMILY"),
                    hook_family_name(address.family).into(),
                ));
                environment.push((format!("{base}_ADDRESS"), address.address.clone()));
                environment.push((format!("{base}_PREFIX_LEN"), address.prefix_len.to_string()));
                environment.push((
                    format!("{base}_ON_LINK_PREFIX_LEN"),
                    address.on_link_prefix_len.to_string(),
                ));
                environment.push((
                    format!("{base}_GATEWAY"),
                    address.gateway.clone().unwrap_or_default(),
                ));
                environment.push((format!("{base}_CIDR"), hook_address_cidr(address)));
                environment.push((format!("{base}_SUBNET"), hook_address_subnet(address)));
            }
            for (index, dns) in plan.dns_servers.iter().enumerate() {
                let base = format!("QELI_DNS_{index}");
                environment.push((
                    base.clone(),
                    crate::util::join_host_port(&dns.address, dns.port),
                ));
                environment.push((format!("{base}_ADDRESS"), dns.address.clone()));
                environment.push((format!("{base}_PORT"), dns.port.to_string()));
            }
            for (index, route) in plan.routes.iter().enumerate() {
                let base = format!("QELI_ROUTE_{index}");
                environment.push((format!("{base}_CIDR"), route.cidr.clone()));
                environment.push((format!("{base}_GATEWAY"), route.gateway.clone()));
                environment.push((format!("{base}_METRIC"), route.metric.to_string()));
            }
            for (index, route) in plan.pushed_routes.iter().enumerate() {
                environment.push((format!("QELI_PUSHED_ROUTE_{index}"), route.clone()));
            }
        }
        for (index, route) in self.include.iter().enumerate() {
            environment.push((format!("QELI_INCLUDE_{index}"), route.clone()));
        }
        for (index, route) in self.exclude.iter().enumerate() {
            environment.push((format!("QELI_EXCLUDE_{index}"), route.clone()));
        }

        let context_json = serde_json::to_string_pretty(&serde_json::json!({
            "hook_api": 1,
            "event": event,
            "profile": self.profile,
            "config_path": self.config_path,
            "process_id": std::process::id(),
            "interface": {
                "name": self.if_name,
                "index": self.if_index,
                "device_type": self.device_type,
                "reused": self.tun_reused,
            },
            "server": {
                "configured_host": self.server_host,
                "port": self.server_port,
                "endpoint": crate::util::join_host_port(&self.server_host, self.server_port),
                "protocol": self.protocol,
                "wire_mode": self.wire_mode,
                "fronting": self.fronting,
            },
            "carrier": {
                "address": plan.and_then(|plan| plan.carrier_address.as_deref()),
                "interface": self.carrier_if_name,
                "interface_index": self.carrier_if_index,
                "local_address": self.carrier_local_address,
                "gateway": self.carrier_gateway,
            },
            "routing": {
                "route_local": self.route_local,
                "gateway_nat": self.gateway_nat,
                "forward": self.forward,
                "exit_node": self.exit_node,
                "allow_ipv4_leak": self.allow_ipv4_leak,
                "allow_ipv6_leak": self.allow_ipv6_leak,
                "lan_subnet": self.lan_subnet,
                "lan_subnet_ipv6": self.lan_subnet_ipv6,
                "include": self.include,
                "exclude": self.exclude,
            },
            "lifecycle": {
                "reason": reason,
                "error_code": error_code,
                "error_message": error_message,
                "session_duration_seconds": session_duration_seconds,
            },
            "network_plan": plan,
        }))
        .unwrap_or_else(|error| {
            log::warn!("could not serialize client hook context: {error}");
            String::new()
        });

        PendingLifecycleHook {
            command,
            environment,
            positional_arguments: vec![self.if_name.clone(), primary_gateway],
            context_json,
        }
    }
}

/// Observe the exit uplink independently of the VPN carrier. The connection task
/// group joins this worker before its NetworkPlan owner or TUN is cleaned up.
#[cfg(target_os = "linux")]
fn spawn_exit_wan_monitor(tun_if: String, tasks: &crate::transport_core::tasks::Spawner) {
    tasks.spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // The authenticated plan installed the initial rules.
        let mut last_refreshed = None;
        let cancel = Arc::new(AtomicBool::new(false));
        loop {
            tick.tick().await;
            let name = tun_if.clone();
            let snapshot = network_task::run(cancel.clone(), move || {
                gateway::exit_wan_snapshot_if_active(&name)
            })
            .await;
            let snapshot = match snapshot {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    log::warn!("exit-node WAN observation failed: {error}");
                    continue;
                }
            };
            if snapshot == last_refreshed {
                continue;
            }
            if snapshot.is_none() {
                last_refreshed = None;
                continue;
            }
            let name = tun_if.clone();
            match network_task::run(cancel.clone(), move || {
                gateway::refresh_exit_paths_if_active(&name)
            })
            .await
            {
                Ok(()) => last_refreshed = snapshot,
                Err(error) => log::warn!("exit-node WAN refresh failed; will retry: {error}"),
            }
        }
    });
}

#[cfg(target_os = "linux")]
async fn cleanup_routing_features(
    failures: &crate::client_cleanup::Failures,
    checks: impl Into<crate::client_cleanup::Checks>,
    kill_switch: bool,
    gateway_enabled: bool,
    exit_node: bool,
    tun_if: &str,
) -> anyhow::Result<()> {
    let checks = checks.into();
    let until = failures.cleanup_deadline();
    let tun_if = tun_if.to_owned();
    network_task::run(Arc::new(AtomicBool::new(false)), move || {
        let _budget = crate::operation_budget::Scope::enter(until);
        crate::client_cleanup::routing(
            checks,
            kill_switch,
            || {
                if gateway_enabled || exit_node {
                    gateway::disengage_plan(&tun_if)
                } else {
                    Ok(())
                }
            },
            || killswitch::disengage(&tun_if),
        )
    })
    .await
}

/// The packet/session code is platform-neutral. This is the deliberately small boundary
/// retained by Linux and Android: identity persistence/trust, NetworkPlan execution and
/// ownership of the already-created TUN descriptors.
#[cfg(feature = "experimental-roaming")]
pub(crate) type PathAckFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'static>>;

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, thiserror::Error)]
enum PathAckFailure {
    #[error("{action} rejected: {reason}")]
    Rejected {
        action: &'static str,
        reason: String,
    },
    #[error("{action} left platform network state unknown: {reason}")]
    PlatformStateUnknown {
        action: &'static str,
        reason: String,
    },
    #[error("{action} acknowledgement was cancelled")]
    Cancelled { action: &'static str },
}

#[cfg(feature = "experimental-roaming")]
fn path_ack_is_explicit_rejection(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<PathAckFailure>(),
        Some(PathAckFailure::Rejected { .. })
    )
}

#[cfg(feature = "experimental-roaming")]
fn path_ack_future(
    receiver: tokio::sync::oneshot::Receiver<Result<(), PathCommandFailure>>,
    action: &'static str,
) -> PathAckFuture {
    Box::pin(async move {
        match receiver.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(PathCommandFailure::Rejected(reason))) => {
                Err(PathAckFailure::Rejected { action, reason }.into())
            }
            Ok(Err(PathCommandFailure::PlatformStateUnknown(reason))) => {
                Err(PathAckFailure::PlatformStateUnknown { action, reason }.into())
            }
            Err(_) => Err(PathAckFailure::Cancelled { action }.into()),
        }
    })
}

/// Shared transport-side client of the generation-scoped PathUpdate state machine.
///
/// Platform adapters still execute the emitted OS command, but they do not reimplement
/// candidate lookup, phase validation, ACK correlation or cancellation semantics.
#[cfg(feature = "experimental-roaming")]
#[derive(Clone)]
pub(crate) struct CorePathController {
    core: Arc<std::sync::Mutex<ClientCore>>,
}

#[cfg(feature = "experimental-roaming")]
impl CorePathController {
    pub(crate) fn new(core: Arc<std::sync::Mutex<ClientCore>>) -> Self {
        Self { core }
    }

    fn with_core<T>(&self, action: impl FnOnce(&mut ClientCore) -> T) -> T {
        let mut core = crate::util::lock_or_recover(&self.core, "client::core_path_controller");
        action(&mut core)
    }

    pub(crate) fn prepared_candidate(&self) -> Option<PreparedPathCandidate> {
        self.with_core(|core| core.prepared_path_candidate())
    }

    pub(crate) fn candidate_is_current(&self, candidate: &PreparedPathCandidate) -> bool {
        self.with_core(|core| {
            core.path_candidate_is_current(candidate.update.generation, candidate.candidate_id)
        })
    }

    pub(crate) fn bind_candidate_socket(
        &self,
        candidate: &PreparedPathCandidate,
        socket_fd: i64,
    ) -> anyhow::Result<PathAckFuture> {
        let (_, receiver) = self.with_core(|core| {
            core.request_candidate_socket_binding(
                candidate.update.generation,
                candidate.candidate_id,
                socket_fd,
            )
        })?;
        Ok(path_ack_future(receiver, "BIND_SOCKET"))
    }

    pub(crate) fn commit_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
    ) -> anyhow::Result<PathAckFuture> {
        let (_, receiver) = self.with_core(|core| {
            core.candidate_path_validated(candidate.update.generation, candidate.candidate_id)
        })?;
        Ok(path_ack_future(receiver, "COMMIT_PATH"))
    }

    pub(crate) fn abort_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
        reason: &str,
    ) -> anyhow::Result<PathAckFuture> {
        let (_, receiver) = self.with_core(|core| {
            core.abort_candidate_path(candidate.update.generation, candidate.candidate_id, reason)
        })?;
        Ok(path_ack_future(receiver, "ABORT_PATH"))
    }
}

/// Linux OS executor for the shared PathUpdate transaction. It owns only prepared route facts;
/// phase/order/idempotency and every ACK waiter remain in `ClientCore`/`CorePathController`.
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
fn linux_path_command_outcome(execution: &anyhow::Result<()>) -> PathCommandOutcome {
    match execution {
        Ok(()) => PathCommandOutcome::Accepted,
        Err(error)
            if error
                .downcast_ref::<route::RouteCommitStateUnknown>()
                .is_some() =>
        {
            PathCommandOutcome::PlatformStateUnknown
        }
        Err(_) => PathCommandOutcome::Rejected,
    }
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
// MIPS has no native AtomicU64; preserve the lease width with the shared fallback.
static NEXT_ROAM_RPF_LEASE: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(1);

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
struct CandidateRpfLease {
    scope: String,
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
impl Drop for CandidateRpfLease {
    fn drop(&mut self) {
        if let Err(error) = crate::sysctl::release_scope(&self.scope) {
            log::error!("could not restore roaming candidate rp_filter: {error}");
        }
    }
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
struct PreparedLinuxPath {
    routes: route::LinuxPreparedPathRoutes,
    // Held only while the old /32 carrier bypass can make the new path asymmetric.
    _rpf: Option<CandidateRpfLease>,
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
pub(crate) struct LinuxPathController {
    core: Arc<std::sync::Mutex<ClientCore>>,
    shared: CorePathController,
    tunnel_interface: String,
    prepared_routes: std::sync::Mutex<Option<PreparedLinuxPath>>,
    route_owner: std::sync::Mutex<Option<route::RouteScope>>,
    same_network_nat_failure_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
    dispatch_lock: std::sync::Mutex<()>,
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
impl LinuxPathController {
    fn new(core: Arc<std::sync::Mutex<ClientCore>>, tunnel_interface: String) -> Self {
        Self {
            shared: CorePathController::new(core.clone()),
            core,
            tunnel_interface,
            prepared_routes: std::sync::Mutex::new(None),
            route_owner: std::sync::Mutex::new(None),
            same_network_nat_failure_tx: std::sync::Mutex::new(None),
            dispatch_lock: std::sync::Mutex::new(()),
        }
    }

    fn with_core<T>(&self, action: impl FnOnce(&mut ClientCore) -> T) -> T {
        let mut core = crate::util::lock_or_recover(&self.core, "client::linux_path_core");
        action(&mut core)
    }

    fn install_same_network_nat_failure_trigger(&self, sender: tokio::sync::mpsc::Sender<()>) {
        *crate::util::lock_or_recover(
            &self.same_network_nat_failure_tx,
            "client::linux_nat_failure_trigger",
        ) = Some(sender);
    }

    fn command_candidate(command: &PathCommand) -> PreparedPathCandidate {
        PreparedPathCandidate {
            candidate_id: command.candidate_id,
            update: command.path.clone(),
        }
    }

    fn execute_command(&self, command: &PathCommand) -> anyhow::Result<()> {
        match command.action {
            PathCommandAction::PreparePath => {
                let candidate = Self::command_candidate(command);
                let owner = crate::util::lock_or_recover(&self.route_owner, "client::route_owner")
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Linux path has no managed route owner"))?
                    .upgrade()?;
                let prepared = route::prepare_candidate_path_routes(&candidate, &owner)?;
                let mut current = crate::util::lock_or_recover(
                    &self.prepared_routes,
                    "client::linux_prepared_routes",
                );
                if current.as_ref().is_some_and(|active| {
                    active.routes.generation != command.generation
                        || active.routes.candidate_id != command.candidate_id
                }) {
                    anyhow::bail!("Linux path executor already owns another prepared candidate");
                }
                // The old carrier's /32 remains pinned until COMMIT. Strict IPv4
                // reverse-path filtering drops replies on a different candidate interface
                // before the candidate can authenticate. Loose mode still checks source
                // reachability; this lease restores the value on COMMIT or ABORT.
                let rpf = if let Some(route) =
                    prepared.routes.iter().find(|route| route.remote.is_ipv4())
                {
                    let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", route.interface);
                    let all = std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
                        .map(|value| value.trim().to_string());
                    let interface =
                        std::fs::read_to_string(&path).map(|value| value.trim().to_string());
                    // Avoid a conflicting lease when the gateway already disabled filtering.
                    let already_compatible = matches!(all.as_deref(), Ok("2"))
                        || matches!((all.as_deref(), interface.as_deref()), (Ok("0"), Ok("0")));
                    if already_compatible {
                        None
                    } else {
                        let id = NEXT_ROAM_RPF_LEASE
                            .fetch_update(
                                std::sync::atomic::Ordering::Relaxed,
                                std::sync::atomic::Ordering::Relaxed,
                                |id| id.checked_add(1),
                            )
                            .map_err(|_| {
                                anyhow::anyhow!("roaming rp_filter lease counter exhausted")
                            })?;
                        let scope = format!("roam-rpf-{id:016x}");
                        crate::sysctl::acquire_checked(&path, "2", &scope)
                            .map_err(|error| anyhow::anyhow!(
                                "cannot relax reverse-path filtering for roaming candidate {}: {error}",
                                route.interface
                            ))?;
                        Some(CandidateRpfLease { scope })
                    }
                } else {
                    None
                };
                *current = Some(PreparedLinuxPath {
                    routes: prepared,
                    _rpf: rpf,
                });
                Ok(())
            }
            PathCommandAction::BindSocket => {
                {
                    let current = crate::util::lock_or_recover(
                        &self.prepared_routes,
                        "client::linux_prepared_routes",
                    );
                    let prepared = current.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("BIND_SOCKET has no prepared Linux route projection")
                    })?;
                    if prepared.routes.generation != command.generation
                        || prepared.routes.candidate_id != command.candidate_id
                    {
                        anyhow::bail!("BIND_SOCKET does not match the prepared Linux candidate");
                    }
                }
                let socket_fd = command
                    .socket_fd
                    .ok_or_else(|| anyhow::anyhow!("BIND_SOCKET omitted the candidate fd"))?;
                crate::transport_core::carrier::bind_linux_candidate_socket(
                    i32::try_from(socket_fd).map_err(|_| {
                        anyhow::anyhow!("candidate socket handle is outside the Unix fd range")
                    })?,
                    &Self::command_candidate(command),
                )
            }
            PathCommandAction::CommitPath => {
                let mut current = crate::util::lock_or_recover(
                    &self.prepared_routes,
                    "client::linux_prepared_routes",
                );
                let prepared = current.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("COMMIT_PATH has no prepared Linux route projection")
                })?;
                if prepared.routes.generation != command.generation
                    || prepared.routes.candidate_id != command.candidate_id
                {
                    anyhow::bail!("COMMIT_PATH does not match the prepared Linux candidate");
                }
                let address = command
                    .path
                    .compatible_resolved_addresses()
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        anyhow::anyhow!("COMMIT_PATH has no compatible carrier address")
                    })?;
                let previous_carriers = active_carrier_ips();
                // Exit-node forwarding is WAN-dependent, unlike the qeli carrier itself.
                // Refresh each active inner family's current default uplink before publishing
                // the authenticated carrier route; those interfaces may differ from the
                // carrier and from each other. Failure leaves the previous route active and
                // makes the core enqueue ABORT/reconnect.
                prepared.routes.commit_with(&previous_carriers, || {
                    gateway::refresh_exit_paths_if_active(&self.tunnel_interface)
                })?;
                mark_carrier_candidates_pinned(&[address]);
                note_connected_peer(address);
                *current = None;
                Ok(())
            }
            PathCommandAction::AbortPath => {
                let mut current = crate::util::lock_or_recover(
                    &self.prepared_routes,
                    "client::linux_prepared_routes",
                );
                if current.as_ref().is_some_and(|prepared| {
                    prepared.routes.generation != command.generation
                        || prepared.routes.candidate_id != command.candidate_id
                }) {
                    anyhow::bail!("ABORT_PATH does not match the prepared Linux candidate");
                }
                *current = None;
                Ok(())
            }
        }
    }

    /// Consume and ACK one exact command. A rejection makes `ClientCore` enqueue ABORT; execute
    /// that rollback before returning so no temporary Linux state can outlive the failed call.
    fn dispatch_event(
        &self,
        event: ClientEvent,
        expected_action: PathCommandAction,
        expected_candidate: u64,
    ) -> anyhow::Result<Option<String>> {
        if event.kind != EventKind::PathCommand {
            anyhow::bail!(
                "Linux path dispatcher received unrelated {:?} event {}",
                event.kind,
                event.sequence
            );
        }
        let command = event
            .path_command
            .ok_or_else(|| anyhow::anyhow!("PathCommand event has no command payload"))?;
        if command.action != expected_action || command.candidate_id != expected_candidate {
            anyhow::bail!(
                "Linux path dispatcher expected {:?}/{} but received {:?}/{}",
                expected_action,
                expected_candidate,
                command.action,
                command.candidate_id
            );
        }

        let execution = self.execute_command(&command);
        let rejection = execution.as_ref().err().map(ToString::to_string);
        let outcome = linux_path_command_outcome(&execution);
        self.with_core(|core| {
            core.ack_path_command(
                command.generation,
                command.candidate_id,
                event.sequence,
                outcome,
                rejection.as_deref(),
            )
        })?;

        if outcome == PathCommandOutcome::Rejected
            && expected_action != PathCommandAction::AbortPath
        {
            self.dispatch_pending(PathCommandAction::AbortPath, expected_candidate)?;
        }
        Ok(rejection)
    }

    fn dispatch_pending(
        &self,
        expected_action: PathCommandAction,
        expected_candidate: u64,
    ) -> anyhow::Result<Option<String>> {
        let event = self
            .with_core(|core| core.poll_path_event())
            .ok_or_else(|| anyhow::anyhow!("Linux path command queue is empty"))?;
        self.dispatch_event(event, expected_action, expected_candidate)
    }

    fn submit_path_update(&self, update_json: &str) -> anyhow::Result<u64> {
        // Emitting and consuming a command is one ordered in-process platform transaction.
        // Without this lock a concurrent detector could steal a BIND/COMMIT event between the
        // core mutation and dispatch, or execute ABORT against an OS command still in flight.
        let _dispatch =
            crate::util::lock_or_recover(&self.dispatch_lock, "client::linux_path_dispatch");
        let candidate_id = self.with_core(|core| core.submit_path_update(update_json))?;
        let Some(event) = self.with_core(|core| core.poll_path_event()) else {
            // Idempotent observations and updates queued behind COMMIT/ABORT have no immediate
            // platform work. The terminal ACK will publish the queued PREPARE event.
            return Ok(candidate_id);
        };
        let command = event
            .path_command
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PathCommand event has no command payload"))?;
        let action = command.action;
        let queued_candidate = command.candidate_id;
        if action == PathCommandAction::AbortPath && queued_candidate != candidate_id {
            self.dispatch_event(event, PathCommandAction::AbortPath, queued_candidate)?;
            log::info!(
                "Linux roaming rolled back superseded candidate {} before preparing {}",
                queued_candidate,
                candidate_id
            );
            if let Some(reason) =
                self.dispatch_pending(PathCommandAction::PreparePath, candidate_id)?
            {
                anyhow::bail!("PREPARE_PATH rejected: {reason}");
            }
            return Ok(candidate_id);
        }
        if let Some(reason) =
            self.dispatch_event(event, PathCommandAction::PreparePath, candidate_id)?
        {
            anyhow::bail!("PREPARE_PATH rejected: {reason}");
        }
        Ok(candidate_id)
    }
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
impl PathController for LinuxPathController {
    fn prepared_candidate(&self) -> Option<PreparedPathCandidate> {
        self.shared.prepared_candidate()
    }

    fn candidate_is_current(&self, candidate: &PreparedPathCandidate) -> bool {
        self.shared.candidate_is_current(candidate)
    }

    fn can_request_same_network_nat_rebind(&self) -> bool {
        crate::util::lock_or_recover(
            &self.same_network_nat_failure_tx,
            "client::linux_nat_failure_trigger",
        )
        .is_some()
    }

    fn request_same_network_nat_rebind(&self) -> anyhow::Result<()> {
        let sender = crate::util::lock_or_recover(
            &self.same_network_nat_failure_tx,
            "client::linux_nat_failure_trigger",
        )
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Linux roaming observer is unavailable"))?;
        match sender.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                anyhow::bail!("Linux roaming observer has stopped")
            }
        }
    }

    fn bind_candidate_socket(
        &self,
        candidate: &PreparedPathCandidate,
        socket_fd: i64,
    ) -> anyhow::Result<PathAckFuture> {
        let _dispatch =
            crate::util::lock_or_recover(&self.dispatch_lock, "client::linux_path_dispatch");
        let result = self.shared.bind_candidate_socket(candidate, socket_fd)?;
        self.dispatch_pending(PathCommandAction::BindSocket, candidate.candidate_id)?;
        Ok(result)
    }

    fn commit_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
    ) -> anyhow::Result<PathAckFuture> {
        let _dispatch =
            crate::util::lock_or_recover(&self.dispatch_lock, "client::linux_path_dispatch");
        let result = self.shared.commit_candidate_path(candidate)?;
        self.dispatch_pending(PathCommandAction::CommitPath, candidate.candidate_id)?;
        Ok(result)
    }

    fn abort_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
        reason: &str,
    ) -> anyhow::Result<PathAckFuture> {
        let _dispatch =
            crate::util::lock_or_recover(&self.dispatch_lock, "client::linux_path_dispatch");
        let result = self.shared.abort_candidate_path(candidate, reason)?;
        self.dispatch_pending(PathCommandAction::AbortPath, candidate.candidate_id)?;
        Ok(result)
    }
}

/// Transport-facing half of one platform PathUpdate transaction. The platform owns temporary
/// routes and exact-network binding; the transport owns the candidate socket and authenticated
/// proof. Production adapters expose this only together with the complete ROAMING_PATH bits.
#[cfg(feature = "experimental-roaming")]
pub(crate) trait PathController: Send + Sync {
    fn prepared_candidate(&self) -> Option<PreparedPathCandidate>;
    fn candidate_is_current(&self, candidate: &PreparedPathCandidate) -> bool;
    /// Whether the platform can emit a fresh PathUpdate for the unchanged physical path. The
    /// common UDP actor owns liveness/retry policy; adapters only refresh platform-owned facts.
    fn can_request_same_network_nat_rebind(&self) -> bool {
        false
    }
    fn request_same_network_nat_rebind(&self) -> anyhow::Result<()> {
        anyhow::bail!("same-network NAT recovery is unavailable on this platform")
    }
    // Native FFI and Linux connectors consume BIND_SOCKET while opening the candidate; the
    // Capability masking keeps adapters without this exact binding contract on reconnect.
    #[cfg_attr(not(feature = "transport-core-ffi"), allow(dead_code))]
    fn bind_candidate_socket(
        &self,
        candidate: &PreparedPathCandidate,
        socket_fd: i64,
    ) -> anyhow::Result<PathAckFuture>;
    fn commit_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
    ) -> anyhow::Result<PathAckFuture>;
    fn abort_candidate_path(
        &self,
        candidate: &PreparedPathCandidate,
        reason: &str,
    ) -> anyhow::Result<PathAckFuture>;
}

pub(crate) trait ClientPlatform {
    fn next_generation(&mut self) -> u64;
    fn platform_capabilities(&self) -> u64;
    #[cfg(feature = "experimental-roaming")]
    fn path_controller(&self) -> Option<Arc<dyn PathController>> {
        None
    }
    #[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
    fn linux_path_controller(&self) -> Option<Arc<LinuxPathController>> {
        None
    }
    fn device_id(&self) -> anyhow::Result<[u8; crate::protocol::DEVICE_ID_LEN]>;
    fn identity_verifier(&self, config: &crate::config::client::ClientConfig) -> IdentityVerifier;
    fn prepare_tunnel<'a>(
        &'a mut self,
        config: &'a crate::config::client::ClientConfig,
        plan: NetworkPlan,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TunnelSetup>> + 'a>>;
    fn fallback_dns_servers(&self) -> &[String];
    fn cancel_token(&self) -> Arc<AtomicBool>;
    fn counters(&self) -> Arc<RuntimeCounters>;
    fn management_event(
        &mut self,
        event: &crate::protocol::control_v2::ManagementEvent,
    ) -> anyhow::Result<()> {
        match event {
            crate::protocol::control_v2::ManagementEvent::Notice(notice) => {
                log::warn!("server notice: {}", notice.message)
            }
            crate::protocol::control_v2::ManagementEvent::Kick(kick) => {
                log::error!("server terminated the session: {}", kick.message)
            }
        }
        Ok(())
    }
    /// Consume the client `post_up` hook after the first successfully applied NetworkPlan.
    /// Non-Linux adapters and later reconnect generations have no pending hook.
    fn take_post_up(&mut self) -> Option<PendingLifecycleHook> {
        None
    }
}

async fn run_pending_post_up(core: &mut dyn ClientPlatform) {
    let Some(hook) = core.take_post_up() else {
        return;
    };
    #[cfg(target_os = "linux")]
    crate::hooks::run_with_context(
        "post_up",
        &hook.command,
        &hook.environment,
        &hook.positional_arguments,
        (!hook.context_json.is_empty()).then_some(hook.context_json.as_str()),
    )
    .await;
    #[cfg(not(target_os = "linux"))]
    let _ = hook;
}

#[cfg(target_os = "linux")]
async fn run_client_post_down(
    core: &LinuxCoreAdapter,
    command: &str,
    reason: &str,
    error_code: &str,
    error_message: &str,
) {
    let Some(hook) = core.post_down_invocation(command, reason, error_code, error_message) else {
        return;
    };
    crate::hooks::run_with_context(
        "post_down",
        &hook.command,
        &hook.environment,
        &hook.positional_arguments,
        (!hook.context_json.is_empty()).then_some(hook.context_json.as_str()),
    )
    .await;
}

/// In-process Linux adapter for the same lifecycle contract exported over the C ABI.
/// It deliberately polls the bounded event queue instead of reaching around it: this is
/// the first real adapter that freezes the semantics other clients will consume.
#[cfg(target_os = "linux")]
struct LinuxCoreAdapter {
    /// Shared with the transport-facing path controller. The mutex protects only bounded core
    /// state transitions; Linux route/socket work always runs after releasing this lock.
    core: Arc<std::sync::Mutex<ClientCore>>,
    next_plan_generation: u64,
    cancel: Arc<AtomicBool>,
    counters: Arc<RuntimeCounters>,
    diagnostics: ClientStatusReporter,
    device_identity: Option<[u8; crate::protocol::DEVICE_ID_LEN]>,
    identity_verifier: Option<identity_worker::Verifier>,
    identity_worker: Option<identity_worker::Worker>,
    diagnostic_writer: Option<status_writer::Writer<serde_json::Value>>,
    cleanup_failures: crate::client_cleanup::Failures,
    post_up: Option<String>,
    hook_context: Option<ClientHookContext>,
    connected_since: Option<std::time::Instant>,
    attempt_connected_since: Option<std::time::Instant>,
    #[cfg(feature = "experimental-roaming")]
    path_controller: Arc<LinuxPathController>,
}

/// Sanitized state exported by a Linux client process for the server panel. This is a
/// deliberately separate contract from logs: consumers no longer infer connection state,
/// negotiated MTU or DNS by matching English log messages. Credentials, identity keys and
/// session material are never copied into this structure.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct ClientStatusReporter {
    sender: Option<status_writer::Sender<serde_json::Value>>,
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
    fn from_env() -> (Self, Option<status_writer::Writer<serde_json::Value>>) {
        let path = std::env::var("QELI_CLIENT_STATUS")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from);
        let profile =
            std::env::var("QELI_CLIENT_PROFILE").unwrap_or_else(|_| "standalone".to_string());
        let (sender, writer) = match path {
            Some(path) => match status_writer::Writer::start(move |body: serde_json::Value| {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(encoded) = serde_json::to_vec(&body) {
                    if let Err(error) = crate::util::write_atomic_private(&path, &encoded) {
                        log::debug!(
                            "cannot publish client diagnostics {}: {error}",
                            path.display()
                        );
                    }
                }
            }) {
                Ok((sender, writer)) => (Some(sender), Some(writer)),
                Err(error) => {
                    log::warn!("cannot start client diagnostics writer: {error}");
                    (None, None)
                }
            },
            None => (None, None),
        };
        (
            Self {
                sender,
                state: Arc::new(std::sync::Mutex::new(ClientDiagnosticState {
                    profile,
                    state: "created".to_string(),
                    generation: 0,
                    reconnects: 0,
                    retry_in_secs: None,
                    last_error: None,
                    plan: None,
                })),
            },
            writer,
        )
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
        let Some(sender) = &self.sender else {
            return;
        };
        let current = match self.state.lock() {
            Ok(current) => current,
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
                "udp_receive_queue": udp.receive_queue,
                "udp_data_fragmentation": udp.path,
                "tcp_uplink_drops": counters.tcp_uplink.snapshot(),
                "tcp_downlink_drops": counters.tcp_downlink.snapshot(),
                "tcp_carriers": serde_json::from_slice::<serde_json::Value>(
                    &counters.tcp_carriers.diagnostics_json()).ok(),
            },
        });
        // Keep the state lock until enqueue: an older sampled state must never be
        // submitted after a newer event. The worker performs all file I/O unlocked.
        sender.submit(body);
    }

    fn start_sampler(
        &self,
        counters: Arc<RuntimeCounters>,
        tasks: &mut crate::client_tasks::Owner,
    ) {
        if self.sender.is_none() {
            return;
        }
        let reporter = self.clone();
        tasks.spawn(async move {
            loop {
                reporter.publish(&counters);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
}

#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
fn linux_roaming_path_supported(config: &crate::config::client::ClientConfig) -> bool {
    use crate::config::client::ClientRoamingPolicy;

    let transport_supported = matches!(config.server.protocol.as_str(), "tcp" | "udp");
    // Explicit source settings are operator pins, not a path the observer may replace.
    config.roaming != ClientRoamingPolicy::Off
        && !config.tun.attach_existing
        && transport_supported
        && config.server.local_address.is_none()
        && config.server.local_port == 0
}

#[cfg(target_os = "linux")]
impl LinuxCoreAdapter {
    /// All startup file work and capability probes run on the admitted worker.
    fn load_startup(
        config_path: &str,
    ) -> anyhow::Result<(
        Self,
        crate::config::client::ClientConfig,
        crate::config_source::CommandTrust,
    )> {
        let (snapshot, mode) = crate::config_source::load_client(config_path)?;
        let (contents, trust) = snapshot.into_parts();
        let (mut adapter, config) = Self::new(&contents)?;
        adapter.hook_context = Some(ClientHookContext::new(&config, config_path));
        if config
            .auth
            .password
            .as_deref()
            .is_some_and(|p| !p.is_empty())
            && mode & 0o077 != 0
        {
            log::warn!("config '{config_path}' is mode {mode:o} — it contains the VPN password in cleartext and other local accounts can read it. chmod 600 {config_path}");
        }
        Ok((adapter, config, trust))
    }

    async fn load_device_identity(
        &mut self,
        path: String,
        stop: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<bool> {
        if self.device_identity.is_some() {
            return Ok(true);
        }
        let loaded = network_task::prepared(
            async move { Ok(move || Ok(identity_files::device_id_at(&path))) },
            stop,
        )
        .await?;
        self.device_identity = loaded;
        Ok(loaded.is_some())
    }

    fn with_core<T>(&self, action: impl FnOnce(&mut ClientCore) -> T) -> T {
        let mut core = crate::util::lock_or_recover(&self.core, "client::linux_core");
        action(&mut core)
    }

    fn new(config_text: &str) -> anyhow::Result<(Self, crate::config::client::ClientConfig)> {
        let preview = crate::config::parse_client_config_strict(config_text)?;
        let mut platform_capabilities = platform_capability::SYSTEM_PLAN
            | platform_capability::IPV6_TUN
            | platform_capability::IPV6_ROUTES
            | platform_capability::IPV6_DNS
            | platform_capability::MANAGEMENT_EVENTS;
        #[cfg(feature = "experimental-roaming")]
        if linux_roaming_path_supported(&preview) {
            platform_capabilities |= platform_capability::ROAMING_PATH;
        }
        if killswitch::ipv6_available() {
            platform_capabilities |= platform_capability::IPV6_KILL_SWITCH;
        }
        if gateway::should_engage(&preview.routing) && !gateway::ipv6_available() {
            // A router client must not accept an IPv6 lease it cannot forward for its LAN.
            // `auto` will negotiate IPv4; `required` will fail with the missing platform
            // capability before any address or route is touched.
            platform_capabilities &= !(platform_capability::IPV6_TUN
                | platform_capability::IPV6_ROUTES
                | platform_capability::IPV6_DNS);
        }
        let mut core = ClientCore::new(
            config_text,
            CoreOptions {
                platform_capabilities,
                ..CoreOptions::default()
            },
        )?;
        let config = core.config().clone();
        while core.poll_event().is_some() {}
        let core = Arc::new(std::sync::Mutex::new(core));
        #[cfg(feature = "experimental-roaming")]
        let path_controller = Arc::new(LinuxPathController::new(
            core.clone(),
            config.tun.name.clone(),
        ));
        let counters = Arc::new(RuntimeCounters::default());
        let (identity_verifier, identity_worker) = if config.auth.server_public_key.is_none() {
            let path = known_hosts_path();
            let server_id = crate::transport_core::server_identity::endpoint_id(
                &config.server.protocol,
                &config.server.address,
                config.server.port,
            );
            let allow_unpinned = config.auth.allow_unpinned_tofu;
            let (verifier, worker) = identity_worker::Worker::start(move |received| {
                let hex: String = received.iter().map(|b| format!("{b:02x}")).collect();
                identity_files::trust_on_first_use_at(&path, &server_id, &hex, allow_unpinned)
            })?;
            (Some(verifier), Some(worker))
        } else {
            (None, None)
        };
        let (diagnostics, diagnostic_writer) = ClientStatusReporter::from_env();
        diagnostics.publish(&counters);
        Ok((
            Self {
                core,
                next_plan_generation: 1,
                cancel: Arc::new(AtomicBool::new(false)),
                counters,
                diagnostics,
                device_identity: None,
                identity_verifier,
                identity_worker,
                diagnostic_writer,
                cleanup_failures: crate::client_cleanup::Failures::default(),
                post_up: None,
                hook_context: None,
                connected_since: None,
                attempt_connected_since: None,
                #[cfg(feature = "experimental-roaming")]
                path_controller,
            },
            config,
        ))
    }

    fn begin_connection(&mut self, reconnect: bool) -> anyhow::Result<()> {
        if !matches!(
            self.with_core(|core| core.state()),
            ClientState::Created | ClientState::Stopped
        ) {
            self.with_core(|core| core.stop())?;
            self.drain_events(None)?;
        }
        self.attempt_connected_since = None;
        if reconnect {
            self.with_core(ClientCore::record_reconnect);
        }
        self.with_core(|core| core.start())?;
        self.drain_events(None).map(|_| ())
    }

    fn finish_connection(&mut self) -> anyhow::Result<()> {
        self.with_core(|core| core.stop())?;
        self.drain_events(None).map(|_| ())
    }

    fn next_generation(&mut self) -> u64 {
        let generation = self.next_plan_generation;
        self.next_plan_generation = self.next_plan_generation.saturating_add(1);
        generation
    }

    fn configure_hooks(&mut self, post_up: String) {
        self.post_up = (!post_up.trim().is_empty()).then_some(post_up);
    }

    fn post_down_invocation(
        &self,
        command: &str,
        reason: &str,
        error_code: &str,
        error_message: &str,
    ) -> Option<PendingLifecycleHook> {
        if command.trim().is_empty() {
            return None;
        }
        let duration = self
            .connected_since
            .map(|started| started.elapsed().as_secs())
            .unwrap_or(0);
        self.hook_context.as_ref().map(|context| {
            context.invocation(
                command.to_string(),
                "post_down",
                reason,
                error_code,
                error_message,
                duration,
            )
        })
    }

    async fn apply_network_plan<T: Send + 'static>(
        &mut self,
        plan: NetworkPlan,
        apply: impl FnOnce(&NetworkPlan) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let generation = plan.generation;
        self.with_core(|core| core.publish_network_plan(plan))?;
        let executable = self.drain_events(Some(generation))?.ok_or_else(|| {
            anyhow::anyhow!("core emitted no network plan for generation {generation}")
        })?;

        match network_task::run(self.cancel.clone(), move || apply(&executable)).await {
            Ok(value) => {
                let acknowledged = if self.cancel.load(Ordering::Acquire) {
                    Err(anyhow::anyhow!(
                        "client stopped before NetworkPlan acknowledgement"
                    ))
                } else {
                    self.with_core(|core| core.ack_network_plan(generation, true, None))
                        .map_err(anyhow::Error::from)
                        .and_then(|()| self.drain_events(None).map(|_| ()))
                };
                if let Err(error) = acknowledged {
                    // The unapplied ACK never strips ownership from a completed platform result.
                    // Join its rollback before returning to the outer network-lease owner.
                    let rollback = network_task::run(Arc::new(AtomicBool::new(false)), move || {
                        drop(value);
                        Ok(())
                    })
                    .await;
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback) => {
                            error.context(format!("network rollback also failed: {rollback}"))
                        }
                    });
                }
                Ok(value)
            }
            Err(error) => {
                let reason = error.to_string();
                self.with_core(|core| core.ack_network_plan(generation, false, Some(&reason)))?;
                self.drain_events(None)?;
                Err(error)
            }
        }
    }

    fn drain_events(&mut self, wanted_plan: Option<u64>) -> anyhow::Result<Option<NetworkPlan>> {
        let mut found = None;
        while let Some(event) = self.with_core(|core| core.poll_event()) {
            match event.kind {
                EventKind::StateChanged => {
                    log::debug!("transport core state: {:?}", event.state);
                    if event.state == ClientState::Running {
                        self.attempt_connected_since
                            .get_or_insert_with(std::time::Instant::now);
                    }
                    let reconnects = self.with_core(|core| core.stats().reconnects);
                    self.diagnostics.update_state(event.state, reconnects);
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
                EventKind::PathCommand => {
                    return Err(anyhow::anyhow!(
                        "unexpected path command: this Linux adapter does not advertise roaming"
                    ));
                }
                EventKind::PathRefresh => {
                    return Err(anyhow::anyhow!(
                        "unexpected path refresh: this Linux adapter owns NAT recovery in-process"
                    ));
                }
                EventKind::Notice | EventKind::Kick => {
                    let management = event
                        .management
                        .ok_or_else(|| anyhow::anyhow!("management event has no typed payload"))?;
                    <Self as ClientPlatform>::management_event(self, &management)?;
                    if let crate::protocol::control_v2::ManagementEvent::Kick(kick) = management {
                        return Err(ServerKickError {
                            message: kick.message,
                            reconnect_allowed: kick.reconnect_allowed,
                        }
                        .into());
                    }
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

    fn platform_capabilities(&self) -> u64 {
        self.with_core(|core| core.platform_capabilities())
    }

    #[cfg(feature = "experimental-roaming")]
    fn path_controller(&self) -> Option<Arc<dyn PathController>> {
        let required = crate::transport_core::platform_capability::ROAMING_PATH;
        if self.platform_capabilities() & required == required {
            Some(self.path_controller.clone())
        } else {
            None
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn linux_path_controller(&self) -> Option<Arc<LinuxPathController>> {
        let required = crate::transport_core::platform_capability::ROAMING_PATH;
        if self.platform_capabilities() & required == required {
            Some(self.path_controller.clone())
        } else {
            None
        }
    }

    fn device_id(&self) -> anyhow::Result<[u8; crate::protocol::DEVICE_ID_LEN]> {
        self.device_identity
            .ok_or_else(|| anyhow::anyhow!("client device identity was not initialized"))
    }

    fn identity_verifier(&self, config: &crate::config::client::ClientConfig) -> IdentityVerifier {
        let expected = config.auth.server_public_key.clone();
        let verifier = self.identity_verifier.clone();
        let cancel = self.cancel.clone();
        let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
        Arc::new(move |received| {
            let expected = expected.clone();
            let verifier = verifier.clone();
            let cancel = cancel.clone();
            Box::pin(async move {
                if let Some(expected) = expected {
                    return verify_pinned_key(&received, &expected);
                }
                let verifier =
                    verifier.ok_or_else(|| anyhow::anyhow!("TOFU worker is unavailable"))?;
                tokio::time::timeout(timeout, verifier.verify(received, cancel))
                    .await
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "server identity verification timed out after {}s",
                            timeout.as_secs()
                        )
                    })?
            })
        })
    }

    fn prepare_tunnel<'a>(
        &'a mut self,
        config: &'a crate::config::client::ClientConfig,
        plan: NetworkPlan,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TunnelSetup>> + 'a>>
    {
        Box::pin(async move {
            let mut hook_context = self.hook_context.clone();
            let cleanup_failures = self.cleanup_failures.clone();
            let owned_config = config.clone();
            let (tunnel, hook_context) = self
                .apply_network_plan(plan, move |plan| {
                    let tunnel = setup_tunnel(&owned_config, plan, cleanup_failures)?;
                    if let Some(context) = hook_context.as_mut() {
                        context.refresh(plan, &tunnel.if_name);
                    }
                    Ok((tunnel, hook_context))
                })
                .await?;
            #[cfg(feature = "experimental-roaming")]
            {
                *crate::util::lock_or_recover(
                    &self.path_controller.prepared_routes,
                    "client::linux_prepared_routes",
                ) = None;
                *crate::util::lock_or_recover(
                    &self.path_controller.route_owner,
                    "client::route_owner",
                ) = (!config.tun.attach_existing).then(|| tunnel.guard.routes.scope());
            }
            self.hook_context = hook_context;
            self.connected_since
                .get_or_insert_with(std::time::Instant::now);
            Ok(tunnel)
        })
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

    fn take_post_up(&mut self) -> Option<PendingLifecycleHook> {
        let command = self.post_up.take()?;
        let duration = self
            .connected_since
            .map(|started| started.elapsed().as_secs())
            .unwrap_or(0);
        self.hook_context
            .as_ref()
            .map(|context| context.invocation(command, "post_up", "connected", "", "", duration))
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

#[derive(Debug, thiserror::Error)]
#[error("server terminated the session: {message}")]
struct ServerKickError {
    message: String,
    reconnect_allowed: bool,
}

// A received terminal policy must outlive socket EOF and platform-event delivery errors.
fn management_result(
    event: crate::protocol::control_v2::ManagementEvent,
    delivered: anyhow::Result<()>,
) -> anyhow::Result<()> {
    if let crate::protocol::control_v2::ManagementEvent::Kick(kick) = event {
        if delivered.is_err() {
            log::warn!("Could not publish terminal management event to the platform");
        }
        Err(ServerKickError {
            message: kick.message,
            reconnect_allowed: kick.reconnect_allowed,
        }
        .into())
    } else {
        delivered
    }
}

fn apply_server_management(
    core: &mut dyn ClientPlatform,
    event: crate::protocol::control_v2::ManagementEvent,
) -> anyhow::Result<()> {
    let delivered = core.management_event(&event);
    management_result(event, delivered)
}

enum TcpLifecycleEvent {
    Management(Option<crate::protocol::control_v2::ManagementEvent>),
    Disconnected,
}

async fn next_tcp_lifecycle_event(
    management: &mut tokio::sync::watch::Receiver<
        Option<crate::protocol::control_v2::ManagementEvent>,
    >,
    dead: &mut mpsc::Receiver<()>,
) -> TcpLifecycleEvent {
    tokio::select! {
        biased;
        changed = management.changed() => {
            if changed.is_err() {
                TcpLifecycleEvent::Disconnected
            } else {
                TcpLifecycleEvent::Management(management.borrow_and_update().clone())
            }
        }
        _ = dead.recv() => TcpLifecycleEvent::Disconnected,
    }
}

fn finish_pending_management(
    core: &mut dyn ClientPlatform,
    receiver: &tokio::sync::watch::Receiver<Option<crate::protocol::control_v2::ManagementEvent>>,
    result: anyhow::Result<()>,
) -> anyhow::Result<()> {
    if result
        .as_ref()
        .is_err_and(|error| error.downcast_ref::<ServerKickError>().is_some())
    {
        return result;
    }
    // Producers have been joined: this snapshot cannot be replaced during teardown.
    let event = receiver.borrow().clone();
    if let Some(event @ crate::protocol::control_v2::ManagementEvent::Kick(_)) = event {
        apply_server_management(core, event)
    } else {
        result
    }
}

#[cfg(test)]
mod terminal_cleanup_tests {
    use super::ServerKickError;

    #[test]
    fn terminal_kick_survives_dns_and_route_cleanup_failure() {
        let kick = ServerKickError {
            message: "profile disabled".to_string(),
            reconnect_allowed: false,
        };
        let cleanup = crate::client_cleanup::with_cleanup_error(
            Err(anyhow::anyhow!("DNS revert failed")),
            Err(anyhow::anyhow!("route delete failed")),
        );
        let error =
            crate::client_cleanup::with_cleanup_error(Err(kick.into()), cleanup).unwrap_err();
        let kick = error
            .downcast_ref::<ServerKickError>()
            .expect("terminal policy must survive cleanup");
        assert!(!kick.reconnect_allowed);
        let message = error.to_string();
        assert!(message.contains("profile disabled"));
        assert!(message.contains("DNS revert failed"));
        assert!(message.contains("route delete failed"));
    }
}

#[cfg(test)]
mod terminal_lifecycle_tests {
    use super::*;
    use crate::protocol::control_v2::{Kick, KickReason, ManagementEvent};

    fn kick() -> ManagementEvent {
        ManagementEvent::Kick(Kick {
            reason: KickReason::Administrative,
            message: "Session replaced".into(),
            reconnect_allowed: false,
        })
    }

    #[tokio::test]
    async fn received_kick_wins_when_eof_is_also_ready() {
        let (sender, mut receiver) = tokio::sync::watch::channel(None);
        let (dead_tx, mut dead_rx) = mpsc::channel(1);
        sender.send(Some(kick())).unwrap();
        dead_tx.send(()).await.unwrap();
        let TcpLifecycleEvent::Management(Some(event)) =
            next_tcp_lifecycle_event(&mut receiver, &mut dead_rx).await
        else {
            panic!("EOF discarded a received terminal policy")
        };
        let error = management_result(event, Ok(())).unwrap_err();
        assert!(
            !error
                .downcast_ref::<ServerKickError>()
                .unwrap()
                .reconnect_allowed
        );
        assert!(matches!(
            next_tcp_lifecycle_event(&mut receiver, &mut dead_rx).await,
            TcpLifecycleEvent::Disconnected
        ));
    }

    #[tokio::test]
    async fn ordinary_eof_does_not_invent_a_terminal_policy() {
        let (_sender, mut receiver) = tokio::sync::watch::channel(None);
        let (dead_tx, mut dead_rx) = mpsc::channel(1);
        dead_tx.send(()).await.unwrap();
        assert!(matches!(
            next_tcp_lifecycle_event(&mut receiver, &mut dead_rx).await,
            TcpLifecycleEvent::Disconnected
        ));
    }

    #[test]
    fn platform_delivery_failure_cannot_enable_reconnect_after_kick() {
        let error =
            management_result(kick(), Err(anyhow::anyhow!("event queue full"))).unwrap_err();
        assert!(
            !error
                .downcast_ref::<ServerKickError>()
                .unwrap()
                .reconnect_allowed
        );
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ManagementConsume {
    consumed: bool,
    ack_message_id: Option<u32>,
}

fn queue_client_management_ack(
    sender: &mpsc::Sender<ClientTerminalControl>,
    message_id: u32,
) -> bool {
    let (written, _receipt) = tokio::sync::oneshot::channel();
    sender
        .try_send(ClientTerminalControl {
            packet: crate::protocol::control_v2::ack(message_id),
            written,
        })
        .is_ok()
}

fn consume_authenticated_management(
    bytes: &[u8],
    negotiated: bool,
    reassembler: &std::sync::Mutex<crate::protocol::control_v2::Reassembler>,
    sender: &tokio::sync::watch::Sender<Option<crate::protocol::control_v2::ManagementEvent>>,
    terminal_sender: Option<&mpsc::Sender<ClientTerminalControl>>,
) -> ManagementConsume {
    if !crate::protocol::control_v2::is_control_v2(bytes) {
        return ManagementConsume::default();
    }
    if !negotiated {
        log::warn!("dropping unnegotiated server CONTROL_V2 management frame");
        return ManagementConsume {
            consumed: true,
            ack_message_id: None,
        };
    }
    let mut requested_ack = None;
    let outcome = crate::protocol::control_v2::decode(bytes).and_then(|frame| {
        requested_ack = (frame.flags & crate::protocol::control_v2::FLAG_ACK_REQUIRED != 0)
            .then_some(frame.message_id);
        crate::util::lock_or_recover(reassembler, "client::management_reassembler")
            .push_management(std::time::Instant::now(), frame)
    });
    let mut ack_message_id = None;
    match outcome {
        Ok(crate::protocol::control_v2::ReassemblyOutcome::Complete(message)) => {
            match crate::protocol::control_v2::decode_management(&message) {
                Ok(Some(event)) => {
                    ack_message_id = requested_ack;
                    // Queue the ACK before publishing a terminal KICK. The supervisor may tear
                    // this generation down as soon as it observes the watch value.
                    if let (Some(message_id), Some(terminal_sender)) =
                        (ack_message_id, terminal_sender)
                    {
                        let _ = queue_client_management_ack(terminal_sender, message_id);
                        ack_message_id = None;
                    }
                    sender.send_if_modified(|pending| {
                        // A bounded watch slot deliberately coalesces advisory notices, but a
                        // terminal KICK must never be overwritten by a later NOTICE arriving on
                        // another bonded stream before the supervisor observes it.
                        if matches!(
                            &event,
                            crate::protocol::control_v2::ManagementEvent::Notice(_)
                        ) && matches!(
                            pending.as_ref(),
                            Some(crate::protocol::control_v2::ManagementEvent::Kick(_))
                        ) {
                            return false;
                        }
                        *pending = Some(event.clone());
                        true
                    });
                }
                Ok(None) => log::debug!(
                    "ignoring unsupported server CONTROL_V2 type 0x{:02x}",
                    message.message_type
                ),
                Err(error) => log::warn!("rejecting invalid server management message: {error}"),
            }
        }
        Ok(crate::protocol::control_v2::ReassemblyOutcome::Duplicate) => {
            // A duplicate valid KICK is a retransmission after a possibly lost ACK.
            ack_message_id = requested_ack;
        }
        Ok(crate::protocol::control_v2::ReassemblyOutcome::Pending) => {}
        Err(error) => log::warn!("rejecting malformed server CONTROL_V2 frame: {error}"),
    }
    if let (Some(message_id), Some(terminal_sender)) = (ack_message_id, terminal_sender) {
        // Repeated UDP KICKs must be ACKed repeatedly: the first ACK may be the datagram lost.
        let _ = queue_client_management_ack(terminal_sender, message_id);
        ack_message_id = None;
    }
    ManagementConsume {
        consumed: true,
        ack_message_id,
    }
}

/// A stop signal must interrupt even a day-long configured backoff. The atomic flag
/// handles cancellation before registration; Notify handles it while the timer is pending.
#[cfg(any(target_os = "linux", test))]
async fn wait_for_reconnect(delay: Duration, shutdown: &AtomicBool, wakeup: &tokio::sync::Notify) {
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    tokio::select! {
        _ = wakeup.notified() => {},
        _ = tokio::time::sleep(delay) => {},
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_shutdown(shutdown: &AtomicBool, wakeup: &tokio::sync::Notify) {
    if !shutdown.load(Ordering::Acquire) {
        wakeup.notified().await;
    }
}

/// Run one Linux client per process, including startup and terminal cleanup.
/// Concurrent calls fail before reading config or registering signal handlers.
/// Dropping this future before completion requires a process restart, because Drop
/// cannot join every nested transport task. Signal-driven stop waits for cleanup.
/// Use separate processes for independent clients; shared transport-core adapters
/// are not governed by this Linux runtime entry point.
#[cfg(target_os = "linux")]
pub async fn run_client(config_path: &str) -> anyhow::Result<()> {
    let mut client_tasks = crate::client_tasks::Owner::acquire()?;
    reset_carrier_candidates(0);
    DELIBERATE_CYCLE.store(false, Ordering::Release);
    let mut final_report = None;
    let mut result = run_client_inner(config_path, &mut client_tasks, &mut final_report).await;
    if let Some(report) = final_report.as_mut() {
        if let Some(worker) = report.identity_worker.as_mut() {
            result = crate::client_cleanup::with_cleanup_error(result, worker.finish().await);
        }
    }
    client_tasks.finish().await;
    if let Some(mut report) = final_report {
        report.reporter.terminal(result.as_ref().err());
        report.reporter.publish(&report.counters);
        if let Some(writer) = report.writer.as_mut() {
            if let Err(error) = writer.finish().await {
                // Diagnostics remain best effort; their failure cannot change the
                // transport result or cause a reconnect after successful cleanup.
                log::warn!("cannot finish client diagnostics: {error}");
            }
        }
    }
    client_tasks.complete();
    result
}

#[cfg(target_os = "linux")]
struct ClientFinalReport {
    reporter: ClientStatusReporter,
    counters: Arc<RuntimeCounters>,
    writer: Option<status_writer::Writer<serde_json::Value>>,
    identity_worker: Option<identity_worker::Worker>,
}

#[cfg(target_os = "linux")]
async fn run_client_inner(
    config_path: &str,
    client_tasks: &mut crate::client_tasks::Owner,
    final_report: &mut Option<ClientFinalReport>,
) -> anyhow::Result<()> {
    // SIGUSR1 dumps the packet trace, when one is armed (no-op otherwise).
    client_tasks.spawn(trace::watch());

    // Register before config open/read or any worker/credential command. The token
    // survives adapter creation and is shared by startup, carriers and backoff.
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let signal_cancel = shutdown_requested.clone();
    let shutdown_wakeup = Arc::new(tokio::sync::Notify::new());
    let signal_wakeup = shutdown_wakeup.clone();
    client_tasks.spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = term.recv() => {},
        }
        log::info!("Shutdown signal received — stopping the client cleanly");
        signal_cancel.store(true, Ordering::Release);
        signal_wakeup.notify_one();
    });
    // Keep the reservation alive until every network owner has been dropped.
    let _network_lease;
    let startup_path = config_path.to_string();
    let loaded = network_task::prepared(
        async move { Ok(move || LinuxCoreAdapter::load_startup(&startup_path)) },
        wait_for_shutdown(&shutdown_requested, &shutdown_wakeup),
    )
    .await?;
    let Some((mut core_adapter, config, config_command_trust)) = loaded else {
        return Ok(());
    };
    core_adapter.cancel = shutdown_requested.clone();
    // Transfer worker ownership even if stop arrived during loading: the outer
    // wrapper joins them asynchronously and publishes the final outcome.
    *final_report = Some(ClientFinalReport {
        reporter: core_adapter.diagnostics.clone(),
        counters: core_adapter.counters.clone(),
        writer: core_adapter.diagnostic_writer.take(),
        identity_worker: core_adapter.identity_worker.take(),
    });
    if shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }
    core_adapter
        .diagnostics
        .start_sampler(core_adapter.counters.clone(), client_tasks);
    let password = if let Some(ref pw) = config.auth.password {
        zeroize::Zeroizing::new(pw.clone())
    } else if let Some(ref pw_file) = config.auth.password_file {
        let stop = async {
            if !shutdown_requested.load(Ordering::Acquire) {
                shutdown_wakeup.notified().await;
            }
        };
        match crate::credential_file::password(pw_file, stop).await {
            Ok(password) => password,
            Err(crate::credential_file::FileError::Cancelled) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    } else if let Some(ref pw_cmd) = config.auth.password_command {
        // SECURITY: password_command runs `sh -c` as us (typically root). Honour it
        // ONLY from a trusted (not group/world-writable) config file, exactly like
        // post_up/post_down below — otherwise anyone who can write the config gets code
        // execution. Fail closed (the user explicitly asked to source the password this
        // way, so a refusal must be loud, not a silent skip). The panel never persists
        // this field; see web/api/client.rs::persist.
        config_command_trust
            .check()
            .map_err(|why| anyhow::anyhow!("refusing to run auth.password_command — {why}"))?;
        let stop = async {
            if !shutdown_requested.load(Ordering::Acquire) {
                shutdown_wakeup.notified().await;
            }
        };
        match crate::hook_process::secret::password(pw_cmd, stop).await {
            Ok(password) => password,
            Err(crate::hook_process::secret::SecretError::Cancelled) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    } else {
        return Err(anyhow::anyhow!(
            "auth.password, auth.password_file or auth.password_command required"
        ));
    };
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

    if shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }

    // Initialize once, before the first carrier/handshake timeout exists. Even a
    // nonpersistent fallback must stay stable across reconnects within this run.
    // Stop awaits an admitted write; no background identity mutation outlives startup.
    let identity_path = std::env::var("QELI_DEVICE_ID_FILE")
        .unwrap_or_else(|_| "/var/lib/qeli/device-id".to_string());
    if !core_adapter
        .load_device_identity(
            identity_path,
            wait_for_shutdown(&shutdown_requested, &shutdown_wakeup),
        )
        .await?
        || shutdown_requested.load(Ordering::Acquire)
    {
        return Ok(());
    }

    // Reserve the configured TUN for every client, including gateway/exit without
    // a kill-switch. Protected clients additionally claim the namespace-wide policy.
    // Both guards survive reconnect and all terminal cleanup/post_down paths.
    let ks_on = killswitch::should_engage(&config.routing);
    let recovery_tun = config.tun.name.clone();
    let attach_existing = config.tun.attach_existing;
    let recovered = network_task::prepared(
        async move {
            Ok(move || {
                // The same worker owns admission and all recovery, including blocking
                // journal locks/I/O. Once admitted, stop must join its actual outcome.
                let lease = network_lease::acquire(&recovery_tun, ks_on)?;
                if !attach_existing {
                    // Physical routes outlive the TUN fd. Repair them before resolving
                    // or dialing the server; attached interfaces retain their routes.
                    route::recover_stale(&recovery_tun)?;
                }
                // Only retire eligible stale markers; never revert a live resolver
                // from a durable marker alone. Preserve ambiguous state for recovery.
                dns::recover_stale()?;
                Ok(lease)
            })
        },
        wait_for_shutdown(&shutdown_requested, &shutdown_wakeup),
    )
    .await?;
    let Some(lease) = recovered else {
        return Ok(());
    };
    _network_lease = lease;
    // A stop during admitted recovery still observes its errors, but successful
    // recovery must not proceed to hooks, firewall preparation or a new connection.
    if shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }

    // Gateway/router NAT + lifecycle hooks (Linux). Resolve the tun interface name
    // once — both the kill-switch and the gateway NAT key their rules on it.
    let gw_on = gateway::should_engage(&config.routing);
    // Exit-node: this client is an internet EXIT for OTHER tunnel clients (mirror of
    // gateway_nat — masquerade tun-forwarded traffic out the physical WAN). Independent of
    // gw_on: exit uses its own engage/disengage. Validation rejects combining it
    // with gateway/forward on the same TUN because their egress policies conflict.
    let exit_on = config.routing.exit_node;
    let tun_if = config.tun.name.clone();
    // Config validation already rejects exit_node + every full-tunnel spelling. Its own
    // internet must remain on the physical WAN so forwarded traffic has an egress path.

    // post_up/post_down are honoured ONLY from a trusted (not group/world-writable)
    // config file: a hook runs as us (root). SECURITY: the panel/API never writes
    // these fields, so a panel compromise can't become RCE — see hooks.rs.
    let (post_up, post_down) =
        if config.routing.post_up.is_empty() && config.routing.post_down.is_empty() {
            (String::new(), String::new())
        } else {
            match config_command_trust.check() {
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

    // Build a secret-free hook context before the first dial. It starts with configured
    // values, then each committed authenticated NetworkPlan refreshes the actual interface,
    // address, gateway, DNS, route, data-plane and physical-carrier facts. `post_up` consumes
    // the first committed snapshot; `post_down` receives the latest one.
    core_adapter.configure_hooks(post_up.clone());

    // Engage the kill-switch BEFORE the first connect, so even the first attempt
    // and every reconnect window is leak-proof. It stays up across reconnects and
    // is torn down only on a clean stop. If the user asked for it but it can't be
    // installed (no iptables / unresolvable server), refuse to run unprotected.
    if ks_on {
        let applied = network_task::prepared(
            killswitch::prepare_engage(
                &config.server.address,
                config.server.port,
                &tun_if,
                config.routing.allow_ipv4_leak,
                config.routing.allow_ipv6_leak,
                gw_on,
            ),
            wait_for_shutdown(&shutdown_requested, &shutdown_wakeup),
        )
        .await?;
        if applied.is_none() {
            return Ok(()); // Only read-only preparation was cancelled.
        }
    }
    // Gateway and exit-node firewalling are installed by `setup_tunnel` only after the
    // authenticated NetworkPlan identifies the active families. This keeps an IPv6-only
    // router independent from IPv4 iptables/sysctls (and vice versa). `post_up` is consumed
    // immediately afterwards by the data-plane setup, once on the first successful plan.

    let mut retry_count = 0i64;
    let mut carrier_generation = 0usize;

    loop {
        core_adapter.cleanup_failures.start_attempt();
        let started = std::time::Instant::now();
        // Re-resolve the server so a rotated (DDNS / round-robin) address is allowed
        // through the kill-switch before the next attempt — otherwise a stale
        // allow-list would block every reconnect. Verify the barrier before retrying.
        if ks_on && !shutdown_requested.load(Ordering::Acquire) {
            let refresh = network_task::prepared(
                killswitch::prepare_refresh(&config.server.address, config.server.port, &tun_if),
                wait_for_shutdown(&shutdown_requested, &shutdown_wakeup),
            )
            .await;
            if let Err(error) = refresh {
                let message = format!("kill-switch verification/address refresh failed: {error}");
                log::error!("{message}; stopping reconnect and retaining protection");
                let cleanup = cleanup_routing_features(
                    &core_adapter.cleanup_failures,
                    crate::client_cleanup::Checks {
                        core: Ok(()),
                        network: Err(anyhow::anyhow!("{message}")),
                    },
                    ks_on,
                    gw_on,
                    exit_on,
                    &tun_if,
                )
                .await;
                run_client_post_down(
                    &core_adapter,
                    &post_down,
                    "kill_switch_failed",
                    "kill_switch",
                    &message,
                )
                .await;
                return crate::client_cleanup::with_cleanup_error(
                    Err(error.context(message)),
                    cleanup,
                );
            }
        }

        let mut start_failed = false;
        let result = if shutdown_requested.load(Ordering::Acquire) {
            // Backoff was interrupted. Reuse the ordinary teardown below without dialing.
            Ok(())
        } else {
            match core_adapter.begin_connection(carrier_generation > 0) {
                Err(error) => {
                    start_failed = true;
                    let message = format!("transport core startup failed: {error}");
                    Err(error.context(message))
                }
                Ok(()) => {
                    // Carrier generations rotate independently of the unstable-attempt budget.
                    reset_carrier_candidates(carrier_generation);
                    carrier_generation = carrier_generation.saturating_add(1);
                    if config.server.protocol == "udp" {
                        connect_and_run_udp(&config, &password, &mut core_adapter).await
                    } else {
                        connect_and_run_tcp(&config, &password, &mut core_adapter).await
                    }
                }
            }
        };
        // Transport task groups have stopped all handshake waiters. Retain the
        // namespace lease and egress protection while admitted TOFU work finishes.
        let identity_outcome = if let Some(verifier) = &core_adapter.identity_verifier {
            verifier.drain().await
        } else {
            Ok(())
        };
        let connected_ms = core_adapter
            .attempt_connected_since
            .map(|started| i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX));
        let core_stop = core_adapter.finish_connection().map_err(|error| {
            let message = format!("transport core teardown failed: {error}");
            error.context(message)
        });
        let checks = crate::client_cleanup::Checks {
            core: core_stop,
            network: core_adapter.cleanup_failures.result(),
        };
        let failure_reason = checks.failure_reason();
        if start_failed || failure_reason.is_some() {
            // Cleanup faults outrank signal-success and reconnect. This includes failures
            // reported by Drop guards before the connection future returned.
            let (reason, error_code) =
                failure_reason.unwrap_or(("core_start_failed", "core_start"));
            let cleanup = cleanup_routing_features(
                &core_adapter.cleanup_failures,
                checks,
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
            )
            .await;
            let result = crate::client_cleanup::with_cleanup_error(result, identity_outcome);
            let terminal = crate::client_cleanup::with_cleanup_error(result, cleanup);
            let message = terminal
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default();
            run_client_post_down(&core_adapter, &post_down, reason, error_code, &message).await;
            return terminal;
        }

        if let Err(error) = identity_outcome {
            // A late disk/trust error must not become signal-success or be hidden
            // by reconnect after the handshake's timeout discarded its receiver.
            let message = match &result {
                Err(connection) => format!("{error:#}; connection ended: {connection:#}"),
                Ok(()) => format!("{error:#}"),
            };
            let cleanup = cleanup_routing_features(
                &core_adapter.cleanup_failures,
                Ok(()),
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
            )
            .await;
            run_client_post_down(
                &core_adapter,
                &post_down,
                "identity_failed",
                "identity",
                &message,
            )
            .await;
            return crate::client_cleanup::with_cleanup_error(Err(error.context(message)), cleanup);
        }

        if let Err(error) = &result {
            if error
                .downcast_ref::<ServerKickError>()
                .is_some_and(|kick| !kick.reconnect_allowed)
            {
                let cleanup = cleanup_routing_features(
                    &core_adapter.cleanup_failures,
                    Ok(()),
                    ks_on,
                    gw_on,
                    exit_on,
                    &tun_if,
                )
                .await;
                run_client_post_down(
                    &core_adapter,
                    &post_down,
                    "server_kick",
                    "server_kick",
                    &error.to_string(),
                )
                .await;
                let terminal = match cleanup {
                    Ok(()) => anyhow::anyhow!("{error}"),
                    Err(cleanup) => anyhow::anyhow!("{error}; teardown also failed: {cleanup}"),
                };
                return Err(terminal);
            }
        }

        if shutdown_requested.load(Ordering::Acquire) {
            let cleanup = cleanup_routing_features(
                &core_adapter.cleanup_failures,
                Ok(()),
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
            )
            .await;
            let transport_error = result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default();
            run_client_post_down(
                &core_adapter,
                &post_down,
                "shutdown_signal",
                "shutdown",
                &transport_error,
            )
            .await;
            let result = cleanup
                .map_err(|error| anyhow::anyhow!("shutdown network cleanup failed: {error}"));
            return result;
        }

        let deliberate = DELIBERATE_CYCLE.swap(false, std::sync::atomic::Ordering::AcqRel);
        match &result {
            Ok(_) => log::info!("Connection closed"),
            Err(e) => log::error!("Connection error: {}", e),
        }
        retry_count = crate::config::policy::reconnect_next_attempt(
            retry_count,
            connected_ms.is_some(),
            deliberate,
            connected_ms.unwrap_or(0),
        );
        let max_retries = config.server.reconnect.max_retries;
        let stop_reason = crate::config::policy::reconnect_stop_reason(
            config.server.reconnect.enabled,
            i64::from(max_retries),
            retry_count,
        );

        if stop_reason == Some("disabled") {
            // Clean exit (reconnect disabled): lift the kill-switch / gateway NAT so
            // the host isn't left firewalled or NAT'ing after the client returns.
            let cleanup = cleanup_routing_features(
                &core_adapter.cleanup_failures,
                Ok(()),
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
            )
            .await;
            let (error_code, error_message) = match result.as_ref() {
                Ok(()) => ("", String::new()),
                Err(error) => ("transport_error", error.to_string()),
            };
            run_client_post_down(
                &core_adapter,
                &post_down,
                "reconnect_disabled",
                error_code,
                &error_message,
            )
            .await;
            let result = match (result, cleanup) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) => Err(error),
                (Ok(()), Err(cleanup)) => Err(cleanup),
                (Err(error), Err(cleanup)) => {
                    Err(anyhow::anyhow!("{error}; teardown also failed: {cleanup}"))
                }
            };
            return result;
        }

        if stop_reason == Some("retry_limit") {
            let cleanup = cleanup_routing_features(
                &core_adapter.cleanup_failures,
                Ok(()),
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
            )
            .await;
            let transport_error = result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("max retries ({max_retries}) reached"));
            run_client_post_down(
                &core_adapter,
                &post_down,
                "max_retries",
                "max_retries",
                &transport_error,
            )
            .await;
            let error = match cleanup {
                Ok(()) => anyhow::anyhow!("max retries ({}) reached", max_retries),
                Err(cleanup) => anyhow::anyhow!(
                    "max retries ({}) reached; teardown also failed: {}",
                    max_retries,
                    cleanup
                ),
            };
            return Err(error);
        }

        let delay_ms = crate::config::policy::reconnect_delay(
            retry_count,
            i64::try_from(config.server.reconnect.base_delay_secs.saturating_mul(1000))
                .unwrap_or(i64::MAX),
            i64::try_from(config.server.reconnect.max_delay_secs.saturating_mul(1000))
                .unwrap_or(i64::MAX),
            i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
            None,
            None,
        );
        let delay = Duration::from_millis(delay_ms as u64);

        let retry_in_secs =
            u64::try_from(delay.as_millis().saturating_add(999) / 1000).unwrap_or(u64::MAX);
        log::info!(
            "Reconnecting in {:.3}s (attempt {})...",
            delay.as_secs_f64(),
            retry_count
        );
        core_adapter.diagnostics.retrying(
            result.as_ref().err(),
            carrier_generation as u64,
            retry_in_secs,
        );
        core_adapter.diagnostics.publish(&core_adapter.counters);
        wait_for_reconnect(delay, &shutdown_requested, &shutdown_wakeup).await;
    }
}

#[cfg(test)]
mod management_event_tests {
    use super::{consume_authenticated_management, ClientTerminalControl};
    use crate::protocol::control_v2::{
        Frame, Kick, KickReason, ManagementEvent, Notice, NoticeKind, NoticeSeverity, Reassembler,
        FLAG_ACK, FLAG_ACK_REQUIRED, TYPE_ACK, TYPE_KICK,
    };

    #[test]
    fn terminal_kick_cannot_be_overwritten_by_a_later_notice() {
        let reassembler = std::sync::Mutex::new(Reassembler::new());
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let kick = ManagementEvent::Kick(Kick {
            reason: KickReason::Administrative,
            message: "Session stopped".to_string(),
            reconnect_allowed: false,
        });
        let notice = ManagementEvent::Notice(Notice {
            kind: NoticeKind::Administrative,
            severity: NoticeSeverity::Info,
            message: "Maintenance scheduled".to_string(),
            value: None,
            deadline_unix: None,
        });

        let kick_frame = crate::protocol::control_v2::management_frames(&kick, 1)
            .unwrap()
            .pop()
            .unwrap();
        let notice_frame = crate::protocol::control_v2::management_frames(&notice, 2)
            .unwrap()
            .pop()
            .unwrap();
        let kick_result =
            consume_authenticated_management(&kick_frame, true, &reassembler, &sender, None);
        assert!(kick_result.consumed);
        assert_eq!(kick_result.ack_message_id, Some(1));
        let notice_result =
            consume_authenticated_management(&notice_frame, true, &reassembler, &sender, None);
        assert!(notice_result.consumed);
        assert_eq!(notice_result.ack_message_id, None);
        let repeated_kick =
            consume_authenticated_management(&kick_frame, true, &reassembler, &sender, None);
        assert!(repeated_kick.consumed);
        assert_eq!(repeated_kick.ack_message_id, Some(1));
        assert!(matches!(
            receiver.borrow().as_ref(),
            Some(ManagementEvent::Kick(Kick {
                reconnect_allowed: false,
                ..
            }))
        ));
    }

    #[test]
    fn partial_kick_retransmission_is_not_a_message_receipt() {
        let reassembler = std::sync::Mutex::new(Reassembler::new());
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let kick = ManagementEvent::Kick(Kick {
            reason: KickReason::Administrative,
            message: "Session stopped".to_string(),
            reconnect_allowed: false,
        });
        let wire = crate::protocol::control_v2::management_frames(&kick, 31)
            .unwrap()
            .remove(0);
        let frame = crate::protocol::control_v2::decode(&wire).unwrap();
        let cut = frame.payload.len() / 2;
        let first = Frame {
            part_count: 2,
            payload: &frame.payload[..cut],
            ..frame
        }
        .encode()
        .unwrap();
        let last = Frame {
            part_index: 1,
            part_count: 2,
            payload: &frame.payload[cut..],
            ..frame
        }
        .encode()
        .unwrap();
        for _ in 0..2 {
            let result =
                consume_authenticated_management(&first, true, &reassembler, &sender, None);
            assert_eq!(result.ack_message_id, None);
            assert!(receiver.borrow().is_none());
        }
        assert_eq!(
            consume_authenticated_management(&last, true, &reassembler, &sender, None)
                .ack_message_id,
            Some(31)
        );
        assert_eq!(receiver.borrow().as_ref(), Some(&kick));
        assert_eq!(
            consume_authenticated_management(&first, true, &reassembler, &sender, None)
                .ack_message_id,
            Some(31)
        );
    }

    #[test]
    fn completed_notice_id_does_not_ack_a_conflicting_kick() {
        let reassembler = std::sync::Mutex::new(Reassembler::new());
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let notice = ManagementEvent::Notice(Notice {
            kind: NoticeKind::Administrative,
            severity: NoticeSeverity::Info,
            message: "Maintenance".to_string(),
            value: None,
            deadline_unix: None,
        });
        let wire = crate::protocol::control_v2::management_frames(&notice, 32)
            .unwrap()
            .remove(0);
        consume_authenticated_management(&wire, true, &reassembler, &sender, None);
        let bad = Frame {
            message_type: TYPE_KICK,
            flags: FLAG_ACK_REQUIRED,
            message_id: 32,
            part_index: 0,
            part_count: 1,
            payload: b"{}",
        }
        .encode()
        .unwrap();
        assert_eq!(
            consume_authenticated_management(&bad, true, &reassembler, &sender, None)
                .ack_message_id,
            None
        );
        assert_eq!(receiver.borrow().as_ref(), Some(&notice));
    }

    #[test]
    fn valid_kick_queues_exact_ack_but_invalid_payload_is_never_acknowledged() {
        let reassembler = std::sync::Mutex::new(Reassembler::new());
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let (terminal_sender, mut terminal_receiver) =
            tokio::sync::mpsc::channel::<ClientTerminalControl>(1);
        let kick = ManagementEvent::Kick(Kick {
            reason: KickReason::QuotaExceeded,
            message: "Quota exceeded".to_string(),
            reconnect_allowed: false,
        });
        let kick_frame = crate::protocol::control_v2::management_frames(&kick, 17)
            .unwrap()
            .pop()
            .unwrap();
        let result = consume_authenticated_management(
            &kick_frame,
            true,
            &reassembler,
            &sender,
            Some(&terminal_sender),
        );
        assert!(result.consumed);
        assert_eq!(result.ack_message_id, None);
        let queued = terminal_receiver.try_recv().unwrap();
        let ack = crate::protocol::control_v2::decode(&queued.packet).unwrap();
        assert_eq!(ack.message_type, TYPE_ACK);
        assert_eq!(ack.flags, FLAG_ACK);
        assert_eq!(ack.message_id, 17);
        assert!(matches!(
            receiver.borrow().as_ref(),
            Some(ManagementEvent::Kick(_))
        ));

        let malformed = Frame {
            message_type: TYPE_KICK,
            flags: FLAG_ACK_REQUIRED,
            message_id: 18,
            part_index: 0,
            part_count: 1,
            payload: b"{}",
        }
        .encode()
        .unwrap();
        for _ in 0..2 {
            let malformed_result = consume_authenticated_management(
                &malformed,
                true,
                &reassembler,
                &sender,
                Some(&terminal_sender),
            );
            assert!(malformed_result.consumed);
            assert_eq!(malformed_result.ack_message_id, None);
            assert!(terminal_receiver.try_recv().is_err());
        }
    }
}

#[cfg(test)]
mod reconnect_jitter_tests {
    #[tokio::test]
    async fn shutdown_interrupts_a_pending_long_reconnect_delay() {
        let shutdown = super::AtomicBool::new(false);
        let wakeup = tokio::sync::Notify::new();
        let wait =
            super::wait_for_reconnect(std::time::Duration::from_secs(86_400), &shutdown, &wakeup);
        tokio::pin!(wait);
        tokio::select! {
            biased;
            _ = &mut wait => panic!("retry delay ended before cancellation"),
            _ = tokio::task::yield_now() => {},
        }
        shutdown.store(true, super::Ordering::Release);
        wakeup.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .expect("shutdown must wake the pending retry timer");
    }

    #[tokio::test]
    async fn shutdown_before_reconnect_wait_does_not_require_a_notification() {
        let shutdown = super::AtomicBool::new(true);
        let wakeup = tokio::sync::Notify::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::wait_for_reconnect(std::time::Duration::from_secs(86_400), &shutdown, &wakeup),
        )
        .await
        .expect("a stopped client must not start another retry timer");
    }

    use crate::config::policy::reconnect_jitter;
    use std::time::Duration;

    #[test]
    fn reconnect_jitter_stays_within_eighty_to_one_hundred_percent() {
        let scheduled = Duration::from_secs(60);
        for _ in 0..256 {
            let delay = Duration::from_millis(reconnect_jitter(60_000, None) as u64);
            assert!(delay >= Duration::from_secs(48));
            assert!(delay <= scheduled);
        }
    }
}

/// Optional requirements for one additional TCP carrier. Ordinary bonding and hard-resume
/// callers use the default request; a roaming handover supplies the exact prepared path.
#[derive(Clone, Default)]
pub(crate) struct StreamConnectRequest {
    #[cfg(feature = "experimental-roaming")]
    // Read by the transport-core FFI native connector. Other connectors accept the common
    // request shape but ignore candidate metadata until their platform stage is enabled.
    #[cfg_attr(not(feature = "transport-core-ffi"), allow(dead_code))]
    pub path_candidate: Option<PreparedPathCandidate>,
}

#[cfg(feature = "experimental-roaming")]
impl StreamConnectRequest {
    fn for_path(candidate: PreparedPathCandidate) -> Self {
        Self {
            path_candidate: Some(candidate),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
struct LinuxStreamConnectContext {
    #[cfg(feature = "experimental-roaming")]
    request: StreamConnectRequest,
    #[cfg(feature = "experimental-roaming")]
    path_controller: Option<Arc<dyn PathController>>,
}

/// A factory that opens one more connection of the SAME concrete stream type, for
/// stream bonding (multipath). Cloneable + callable from the data-plane to ramp
/// streams. Every TCP wire mode installs a concrete connector; UDP has its own
/// transport path and never reaches this type.
pub(crate) type StreamConnector<S> = std::sync::Arc<
    dyn Fn(
            StreamConnectRequest,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<S>> + Send>>
        + Send
        + Sync,
>;

/// Divide the remaining dial deadline across every untried A/AAAA record. A dead first address
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

/// `lport` can identify the primary carrier to a firewall, but two simultaneous TCP
/// connections to the same server cannot share the same local/remote four-tuple. Bonded
/// members therefore keep the requested local address (egress choice) while taking an
/// ephemeral port, matching the shared desktop carrier contract.
#[cfg(any(target_os = "linux", test))]
fn tcp_carrier_bind_address(
    local_ip: Option<std::net::IpAddr>,
    local_port: u16,
    primary: bool,
    remote: std::net::SocketAddr,
) -> Option<std::net::SocketAddr> {
    if local_ip.is_none() && (!primary || local_port == 0) {
        return None;
    }
    let address = local_ip.unwrap_or_else(|| {
        if remote.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        }
    });
    Some(std::net::SocketAddr::new(
        address,
        if primary { local_port } else { 0 },
    ))
}

#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
async fn connect_tcp_path_candidate(
    config: &crate::config::client::ClientConfig,
    total: Duration,
    label: &str,
    candidate: &PreparedPathCandidate,
    path_controller: &dyn PathController,
) -> anyhow::Result<TcpStream> {
    let deadline = tokio::time::Instant::now() + total;
    // The core accepts one BIND_SOCKET for one prepared candidate. Use the first validated,
    // family-compatible address exactly as native adapters do; another address needs a fresh
    // PathUpdate/candidate rather than silently binding a different fd outside the transaction.
    let remote_ip = candidate
        .update
        .compatible_resolved_addresses()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("candidate path has no compatible carrier address"))?;
    let remote = std::net::SocketAddr::new(remote_ip, config.server.port);
    let socket = crate::transport_core::carrier::open_candidate_for(config, remote_ip)?;
    let binding = path_controller.bind_candidate_socket(
        candidate,
        crate::transport_core::carrier::candidate_socket_handle(&socket)?,
    )?;
    tokio::time::timeout(total.min(PATH_ACK_TIMEOUT), binding)
        .await
        .map_err(|_| anyhow::anyhow!("BIND_SOCKET acknowledgement timed out"))??;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        anyhow::bail!("{label} candidate connect deadline expired after BIND_SOCKET");
    }
    match crate::transport_core::carrier::connect_to(socket, config, remote, remaining).await? {
        crate::transport_core::carrier::ConnectedCarrier::Tcp(stream) => {
            log::info!(
                "{label} connected candidate {} through {}",
                candidate.candidate_id,
                remote
            );
            Ok(stream)
        }
        crate::transport_core::carrier::ConnectedCarrier::Udp(_) => {
            anyhow::bail!("{label} candidate unexpectedly produced a UDP carrier")
        }
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
pub(crate) async fn connect_udp_path_candidate(
    config: &crate::config::client::ClientConfig,
    total: Duration,
    candidate: &PreparedPathCandidate,
    path_controller: &dyn PathController,
) -> anyhow::Result<UdpSocket> {
    let deadline = tokio::time::Instant::now() + total;
    // PREPARE_PATH supplied addresses resolved through this exact physical network. Like TCP,
    // one candidate owns one BIND_SOCKET transaction, so do not silently try a second address
    // with an fd the platform already bound to the first network generation.
    let remote_ip = candidate
        .update
        .compatible_resolved_addresses()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("candidate path has no compatible carrier address"))?;
    let remote = std::net::SocketAddr::new(remote_ip, config.server.port);
    let socket = crate::transport_core::carrier::open_candidate_for(config, remote_ip)?;
    let binding = path_controller.bind_candidate_socket(
        candidate,
        crate::transport_core::carrier::candidate_socket_handle(&socket)?,
    )?;
    tokio::time::timeout(total.min(PATH_ACK_TIMEOUT), binding)
        .await
        .map_err(|_| anyhow::anyhow!("BIND_SOCKET acknowledgement timed out"))??;
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        anyhow::bail!("UDP candidate connect deadline expired after BIND_SOCKET");
    }
    match crate::transport_core::carrier::connect_to(socket, config, remote, remaining).await? {
        crate::transport_core::carrier::ConnectedCarrier::Udp(socket) => {
            log::info!(
                "UDP connected candidate {} through {}",
                candidate.candidate_id,
                remote
            );
            Ok(socket)
        }
        crate::transport_core::carrier::ConnectedCarrier::Tcp(_) => {
            anyhow::bail!("UDP candidate unexpectedly produced a TCP carrier")
        }
    }
}

#[cfg(target_os = "linux")]
async fn connect_tcp_candidates(
    config: &crate::config::client::ClientConfig,
    total: Duration,
    label: &str,
    primary: bool,
    context: &LinuxStreamConnectContext,
) -> anyhow::Result<TcpStream> {
    #[cfg(feature = "experimental-roaming")]
    if let Some(candidate) = context.request.path_candidate.as_ref() {
        let path_controller = context
            .path_controller
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("candidate TCP connect has no Linux path controller"))?;
        return connect_tcp_path_candidate(config, total, label, candidate, path_controller).await;
    }
    #[cfg(not(feature = "experimental-roaming"))]
    let _ = context;
    let host = config.server.address.as_str();
    let port = config.server.port;
    let local_ip = config
        .server
        .local_address
        .as_deref()
        .map(str::parse::<std::net::IpAddr>)
        .transpose()
        .map_err(|_| anyhow::anyhow!("invalid local carrier address"))?
        .map(crate::transport_core::carrier::canonical_carrier_ip);
    let deadline = tokio::time::Instant::now() + total;
    let pinned = pinned_carrier_socket_addresses(port);
    let using_pinned_generation = pinned.is_some();
    let mut candidates: Vec<std::net::SocketAddr> = if let Some(pinned) = pinned {
        // The host routes were computed from this exact set before full-tunnel
        // capture. Do not perform a later DNS lookup for a bonded stream: a newly
        // published A/AAAA record has no safe physical route in this generation.
        pinned
    } else {
        let resolved = crate::transport_core::resolver::lookup(host, port, deadline)
            .await
            .map_err(|error| {
                anyhow::anyhow!("{label} DNS lookup for {host}:{port} failed: {error}")
            })?;
        let mut seen = std::collections::HashSet::new();
        resolved
            .into_iter()
            .map(|address| {
                std::net::SocketAddr::new(
                    crate::transport_core::carrier::canonical_carrier_ip(address.ip()),
                    address.port(),
                )
            })
            .filter(|address| seen.insert(*address))
            .collect()
    };
    if let Some(local) = local_ip {
        candidates.retain(|address| local.is_ipv4() == address.is_ipv4());
    }
    if candidates.is_empty() {
        return Err(anyhow::anyhow!(
            "{label} DNS lookup for {host}:{port} returned no address compatible with the configured local carrier"
        ));
    }
    if !using_pinned_generation {
        rotate_carrier_candidates(&mut candidates);
    }
    note_carrier_candidates(candidates.iter().map(|address| address.ip()));

    let mut failures = Vec::with_capacity(candidates.len());
    for (index, address) in candidates.iter().copied().enumerate() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let slice = per_candidate_connect_budget(remaining, candidates.len() - index);
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        };
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) => {
                failures.push(format!("{address}: socket creation failed: {error}"));
                continue;
            }
        };
        if let Some(bind) =
            tcp_carrier_bind_address(local_ip, config.server.local_port, primary, address)
        {
            if let Err(error) = socket.bind(bind) {
                failures.push(format!("{address}: bind {bind} failed: {error}"));
                continue;
            }
        }
        match tokio::time::timeout(slice, socket.connect(address)).await {
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
        "{label} could not connect to any IPv4 or IPv6 address for {host}:{port} within {}s ({})",
        total.as_secs(),
        failures.join("; ")
    ))
}

#[cfg(all(test, target_os = "linux", feature = "experimental-roaming"))]
mod linux_candidate_dialer_tests {
    use super::*;
    use crate::transport_core::path::{
        PathResolution, PathUpdate, PathUpdateFlags, PathUpdateReason,
    };

    #[test]
    fn rollback_incomplete_is_not_classified_as_reversible_rejection() {
        let accepted = Ok(());
        assert_eq!(
            linux_path_command_outcome(&accepted),
            PathCommandOutcome::Accepted
        );
        let rejected = Err(anyhow::anyhow!("route was not changed"));
        assert_eq!(
            linux_path_command_outcome(&rejected),
            PathCommandOutcome::Rejected
        );
        let unsafe_result = Err(route::RouteCommitStateUnknown::new(
            "route commit and rollback both failed",
        )
        .into());
        assert_eq!(
            linux_path_command_outcome(&unsafe_result),
            PathCommandOutcome::PlatformStateUnknown
        );
    }

    struct RecordingPathController {
        bound: Arc<AtomicBool>,
    }

    impl PathController for RecordingPathController {
        fn prepared_candidate(&self) -> Option<PreparedPathCandidate> {
            None
        }

        fn candidate_is_current(&self, _candidate: &PreparedPathCandidate) -> bool {
            true
        }

        fn bind_candidate_socket(
            &self,
            _candidate: &PreparedPathCandidate,
            socket_fd: i64,
        ) -> anyhow::Result<PathAckFuture> {
            assert!(socket_fd >= 0);
            self.bound.store(true, Ordering::Release);
            Ok(Box::pin(async { Ok(()) }))
        }

        fn commit_candidate_path(
            &self,
            _candidate: &PreparedPathCandidate,
        ) -> anyhow::Result<PathAckFuture> {
            unreachable!("the dialer does not commit a candidate")
        }

        fn abort_candidate_path(
            &self,
            _candidate: &PreparedPathCandidate,
            _reason: &str,
        ) -> anyhow::Result<PathAckFuture> {
            unreachable!("the dialer does not abort a candidate")
        }
    }

    #[tokio::test]
    async fn candidate_dial_uses_path_address_and_acks_binding_before_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = crate::config::parse_client_config_strict(&format!(
            "[qeli]\nserver = 198.51.100.99:{port}\nproto = tcp\nuser = test\npass = secret\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nmode = fake-tls\n"
        ))
        .unwrap();
        let candidate = PreparedPathCandidate {
            candidate_id: 9,
            update: PathUpdate {
                generation: 7,
                update_id: 3,
                platform_path_id: "test-loopback".into(),
                reason: PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: Some(1),
                local_addresses: vec!["127.0.0.1".into()],
                resolved_addresses: vec![PathResolution {
                    address: "127.0.0.1".into(),
                    ttl_secs: 10,
                }],
                flags: PathUpdateFlags::default(),
            },
        };
        let bound = Arc::new(AtomicBool::new(false));
        let controller = RecordingPathController {
            bound: bound.clone(),
        };
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream = connect_tcp_path_candidate(
            &config,
            Duration::from_secs(2),
            "test TCP",
            &candidate,
            &controller,
        )
        .await
        .unwrap();
        assert!(bound.load(Ordering::Acquire));
        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn udp_candidate_dial_uses_the_same_bound_path_contract() {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();
        let config = crate::config::parse_client_config_strict(&format!(
            "[qeli]\nserver = 198.51.100.99:{port}\nproto = udp\nuser = test\npass = secret\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nmode = fake-tls\n"
        ))
        .unwrap();
        let candidate = PreparedPathCandidate {
            candidate_id: 10,
            update: PathUpdate {
                generation: 7,
                update_id: 4,
                platform_path_id: "test-udp-loopback".into(),
                reason: PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: Some(1),
                local_addresses: vec!["127.0.0.1".into()],
                resolved_addresses: vec![PathResolution {
                    address: "127.0.0.1".into(),
                    ttl_secs: 10,
                }],
                flags: PathUpdateFlags::default(),
            },
        };
        let bound = Arc::new(AtomicBool::new(false));
        let controller = RecordingPathController {
            bound: bound.clone(),
        };

        let socket =
            connect_udp_path_candidate(&config, Duration::from_secs(2), &candidate, &controller)
                .await
                .unwrap();
        assert!(bound.load(Ordering::Acquire));
        assert_eq!(
            socket.peer_addr().unwrap().ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        socket.send(b"candidate").await.unwrap();
        let mut payload = [0u8; 32];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut payload))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&payload[..length], b"candidate");
    }
}

/// Open ONE reality-tls connection (TCP + browser-grade TLS 1.3 carrying the
/// REALITY token). Reusable for the primary connection and each bonded stream —
/// every call uses a fresh ephemeral + freshly sealed session_id.
#[cfg(target_os = "linux")]
async fn connect_reality(
    config: &crate::config::client::ClientConfig,
    primary: bool,
    context: LinuxStreamConnectContext,
    tasks: &crate::transport_core::tasks::Spawner,
) -> anyhow::Result<crate::protocol::h2_carrier::Carrier> {
    // Bound connect + the TLS 1.3 handshake (reads) by connection_timeout_secs: a server
    // that accepts TCP then stalls the TLS handshake would otherwise hang here forever.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let mut stream =
        connect_tcp_candidates(config, to, "reality-tls TCP", primary, &context).await?;
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;
    // SNI precedence mirrors the inner handshake.
    let server_name = config.effective_reality_sni().to_string();
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
    let handshake = async {
        if !config.obfuscation.reality_split.is_empty()
            && config.obfuscation.reality_split != "none"
        {
            log::info!(
                "REALITY-TLS ClientHello split={} delay={}ms compact={}",
                config.obfuscation.reality_split,
                config.obfuscation.reality_split_delay_ms,
                config.obfuscation.reality_compact
            );
            crate::protocol::realtls::client::client_handshake_evasive(
                &mut stream,
                eph,
                session_id,
                &server_name,
                config.obfuscation.reality_compact,
                &config.obfuscation.reality_split,
                config.obfuscation.reality_split_delay_ms,
            )
            .await
        } else if config.obfuscation.reality_compact {
            log::info!(
                "REALITY-TLS compact ClientHello enabled (X25519-only, single-segment target)"
            );
            crate::protocol::realtls::client::client_handshake_compact(
                &mut stream,
                eph,
                session_id,
                &server_name,
            )
            .await
        } else {
            crate::protocol::realtls::client::client_handshake(
                &mut stream,
                eph,
                session_id,
                &server_name,
            )
            .await
        }
    };
    let est = match tokio::time::timeout(to, handshake).await {
        Ok(Ok(established)) => established,
        Ok(Err(error)) => {
            return Err(anyhow::anyhow!(
                "reality-tls handshake failed: {error}; if the server bridged to the decoy, verify the pinned server key, short_id, and that client/server clocks differ by no more than ±120 seconds"
            ));
        }
        Err(_) => {
            return Err(anyhow::anyhow!(
                "reality-tls handshake timed out after {}s; verify reachability and, if the server bridged to the decoy, the pinned key, short_id and ±120-second clock window",
                to.as_secs()
            ))
        }
    };
    let tls = crate::protocol::realtls::stream::RealTlsStream::new(stream, est);
    let h2 = tokio::time::timeout(
        to,
        crate::protocol::h2_carrier::connect_owned(tls, &server_name, tasks),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "reality-tls HTTP/2 carrier timed out after {}s",
            to.as_secs()
        )
    })?
    .map_err(|error| anyhow::anyhow!("reality-tls HTTP/2 carrier failed: {error}"))?;
    log::info!("REALITY-TLS carrier: genuine HTTP/2 stream");
    Ok(h2)
}

/// Open ONE obfs connection (TCP + ChaCha20 stream obfuscation with its own nonce
/// exchange). Reusable for the primary connection and each bonded stream.
#[cfg(target_os = "linux")]
async fn connect_obfs(
    config: &crate::config::client::ClientConfig,
    primary: bool,
    context: LinuxStreamConnectContext,
) -> anyhow::Result<crate::protocol::obfs::ObfsStream<TcpStream>> {
    // Bound connect + the obfs nonce-exchange handshake (reads) by
    // connection_timeout_secs: a server that accepts TCP then stalls the obfs handshake
    // would otherwise hang here forever (the reads are unbounded `.await`s), and no
    // reconnect would fire. Covers both the primary and each bonded stream.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    match tokio::time::timeout(to, async {
        let stream = connect_tcp_candidates(config, to, "obfs TCP", primary, &context).await?;
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
        // Always send the configured front or the actual connect host. In particular,
        // a bare IP stays that IP instead of rotating unrelated CDN names.
        let ws_host = config.effective_fronting_host();
        anyhow::Ok(
            crate::protocol::obfs::ObfsStream::connect_with_host(
                stream,
                &key,
                fronting,
                awg,
                Some(&ws_host),
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
    primary: bool,
    context: LinuxStreamConnectContext,
) -> anyhow::Result<TcpStream> {
    // Bound the connect by connection_timeout_secs rather than the (much longer, ~75s)
    // OS SYN timeout, so a never-accepting server fails over to a reconnect promptly. No
    // handshake reads here — the qeli handshake (bounded in run_tcp_tunnel) does those.
    let to = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let stream = connect_tcp_candidates(config, to, "TCP", primary, &context).await?;
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;
    Ok(stream)
}

// This cancellation boundary owns only initial carrier sockets/handshake work. It
// never drops an in-progress NetworkPlan mutation; the TCP task owner still joins
// H2 drivers/bridges after an interrupted initial connection.
#[cfg(any(target_os = "linux", test))]
async fn connect_before_tunnel<T>(
    cancel: Arc<AtomicBool>,
    connect: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::select! {
        biased;
        _ = async {
            while !cancel.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        } => anyhow::bail!("client stopped during initial carrier connection"),
        result = connect => result,
    }
}

#[cfg(test)]
mod carrier_cancel_tests;

#[cfg(target_os = "linux")]
async fn connect_and_run_tcp(
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut LinuxCoreAdapter,
) -> anyhow::Result<()> {
    let mut tasks = crate::transport_core::tasks::TaskGroup::default();
    let result = tasks
        .spawner()
        .scope(connect_and_run_tcp_owned(
            config, password, core, &mut tasks,
        ))
        .await;
    // Also cover errors before the data loop exists, including a pending H2 response.
    tasks.finish().await;
    result
}

#[cfg(target_os = "linux")]
async fn connect_and_run_tcp_owned(
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut LinuxCoreAdapter,
    tasks: &mut crate::transport_core::tasks::TaskGroup,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.server.address, config.server.port);
    log::info!(
        "Connecting to {} (TCP) as user '{}'",
        addr,
        crate::util::log_identity(&config.auth.username)
    );
    #[cfg(feature = "experimental-roaming")]
    let path_controller = core.path_controller();

    if config.obfuscation.mode == "obfs" {
        if config.obfuscation.obfs_key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "obfs wire mode requires a non-empty obfuscation.obfs_key \
                 (an empty key is publicly derivable → no DPI resistance)"
            ));
        }
        log::info!("Wire mode: obfs (ChaCha20 stream obfuscation)");
        let first = connect_before_tunnel(
            core.cancel_token(),
            connect_obfs(config, true, LinuxStreamConnectContext::default()),
        )
        .await?;
        // Connector clones the config so it outlives this scope and can be called
        // by the data-plane to open bonded streams (fixed open / adaptive ramp).
        let cfg = std::sync::Arc::new(config.clone());
        #[cfg(feature = "experimental-roaming")]
        let controller = path_controller.clone();
        let connector: StreamConnector<_> = std::sync::Arc::new(move |request| {
            let cfg = cfg.clone();
            #[cfg(not(feature = "experimental-roaming"))]
            let _ = request;
            let context = LinuxStreamConnectContext {
                #[cfg(feature = "experimental-roaming")]
                request,
                #[cfg(feature = "experimental-roaming")]
                path_controller: controller.clone(),
            };
            Box::pin(async move { connect_obfs(&cfg, false, context).await })
        });
        run_tcp_tunnel(first, connector, config, password, core, tasks).await
    } else if config.obfuscation.mode == "reality-tls" {
        log::info!("Wire mode: reality-tls (real TLS 1.3 carrying the tunnel)");
        let carrier_tasks = tasks.spawner();
        let first = connect_before_tunnel(
            core.cancel_token(),
            connect_reality(
                config,
                true,
                LinuxStreamConnectContext::default(),
                &carrier_tasks,
            ),
        )
        .await?;
        // Connector clones the config so it outlives this scope and can be called
        // by the data-plane (fixed open / adaptive ramp).
        let cfg = std::sync::Arc::new(config.clone());
        #[cfg(feature = "experimental-roaming")]
        let controller = path_controller.clone();
        let connector: StreamConnector<_> = std::sync::Arc::new(move |request| {
            let cfg = cfg.clone();
            #[cfg(not(feature = "experimental-roaming"))]
            let _ = request;
            let context = LinuxStreamConnectContext {
                #[cfg(feature = "experimental-roaming")]
                request,
                #[cfg(feature = "experimental-roaming")]
                path_controller: controller.clone(),
            };
            let carrier_tasks = carrier_tasks.clone();
            Box::pin(async move { connect_reality(&cfg, false, context, &carrier_tasks).await })
        });
        run_tcp_tunnel(first, connector, config, password, core, tasks).await
    } else {
        // fake-tls / plain: bare TCP transport; the qeli handshake applies the
        // fake-TLS mimicry or the raw framing. Both support stream bonding.
        log::info!("Wire mode: {} (TCP)", config.obfuscation.mode);
        let first = connect_before_tunnel(
            core.cancel_token(),
            connect_bare_tcp(config, true, LinuxStreamConnectContext::default()),
        )
        .await?;
        let cfg = std::sync::Arc::new(config.clone());
        #[cfg(feature = "experimental-roaming")]
        let controller = path_controller.clone();
        let connector: StreamConnector<_> = std::sync::Arc::new(move |request| {
            let cfg = cfg.clone();
            #[cfg(not(feature = "experimental-roaming"))]
            let _ = request;
            let context = LinuxStreamConnectContext {
                #[cfg(feature = "experimental-roaming")]
                request,
                #[cfg(feature = "experimental-roaming")]
                path_controller: controller.clone(),
            };
            Box::pin(async move { connect_bare_tcp(&cfg, false, context).await })
        });
        run_tcp_tunnel(first, connector, config, password, core, tasks).await
    }
}

/// Immutable per-stream pump config (data-phase obfuscation + liveness), cheaply
/// cloned into every bonded stream's tasks.
#[derive(Clone)]
struct StreamPump {
    framing: Framing,
    /// Authenticated address-family contract for both TUN directions.  Uplink validation alone
    /// is insufficient: a stale or incompatible peer must not inject an opposite-family packet
    /// into a platform adapter whose routes deliberately keep that family outside the tunnel.
    family_mode: crate::transport_core::NetworkFamilyMode,
    heartbeat_enabled: bool,
    heartbeat_interval: Duration,
    idle_timeout: Duration,
    /// Effective authenticated TUN MTU. TCP normalization and padding must obey the same
    /// inner-record budget as UDP even though the outer TCP stream handles segmentation.
    tun_mtu: usize,
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
    /// Effective PACKET_MUX_V1 configuration; absent for every legacy peer.
    recordizer: Option<crate::protocol::recordizer::RuntimeConfig>,

    /// Aggregate client→server cover budget shared by every bonded stream.
    cover_budget: crate::protocol::SharedCoverBudget,
    uplink_queue_capacity: usize,
    /// reality-tls only: run the receive side as a 2-stage pipeline so the outer
    /// TLS AES-GCM (done in `read_record`) and the inner qeli ChaCha
    /// (`decrypt_packet`) overlap across cores instead of running serially in one
    /// task. Off for every other mode (no heavy outer AEAD → a pipeline hop would
    /// only add latency).
    pipeline_rx: bool,
    management_v1: bool,
    management_reassembler: Arc<std::sync::Mutex<crate::protocol::control_v2::Reassembler>>,
    management_tx: tokio::sync::watch::Sender<Option<crate::protocol::control_v2::ManagementEvent>>,
}

/// Plaintext queued for one TCP stream. TUN packets retain their reusable backing
/// allocation until encryption finishes; small control frames keep ordinary owned storage.
const CLIENT_BONDED_UPLINK_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// Keep slot metadata bounded even when an authenticated peer advertises a tiny MTU.
const CLIENT_BONDED_UPLINK_MIN_SLOT_BYTES: usize = 2 * 1024;

/// Packet storage follows the already accepted wire contract. Legacy AEAD records cannot
/// carry more than MAX_TUNNEL_MTU; the mux can fragment packets up to its negotiated bound.
/// The shared byte budget and other-carrier/resume-candidate queue reserves stay unchanged.
fn bonded_uplink_pool_layout(
    recordizer: Option<&crate::protocol::recordizer::RuntimeConfig>,
) -> (usize, usize) {
    let packet_bound = recordizer.map_or(crate::protocol::packet::MAX_TUNNEL_MTU, |mux| {
        mux.max_packet_bytes
    });
    let slot_bytes = packet_bound.clamp(CLIENT_BONDED_UPLINK_MIN_SLOT_BYTES, u16::MAX as usize);
    (CLIENT_BONDED_UPLINK_BUFFER_BYTES / slot_bytes, slot_bytes)
}

enum ClientUplink {
    Tun(TunPacket),
    Bonded(PooledBuffer),
    Owned(Vec<u8>),
}

struct QueuedUplink {
    packet: ClientUplink,
    ticket: Option<Ticket>,
}

impl AsRef<[u8]> for QueuedUplink {
    fn as_ref(&self) -> &[u8] {
        self.packet.as_ref()
    }
}

struct ClientTerminalControl {
    packet: Vec<u8>,
    written: tokio::sync::oneshot::Sender<()>,
}

#[derive(Clone)]
struct ClientStreamSender {
    logical_slot_id: u32,
    sender: mpsc::Sender<QueuedUplink>,
    terminal_sender: mpsc::Sender<ClientTerminalControl>,
    metrics: Option<Arc<CarrierMetrics>>,
}

impl ClientStreamSender {
    fn try_send(
        &self,
        packet: ClientUplink,
    ) -> Result<(), mpsc::error::TrySendError<ClientUplink>> {
        // Reserve before admission: a failed try_send is not an accepted packet,
        // and a fast writer cannot finish a ticket before its counters exist.
        match self.sender.try_reserve() {
            Ok(permit) => {
                let ticket = self
                    .metrics
                    .as_ref()
                    .map(|row| row.admit(packet.as_ref().len()));
                permit.send(QueuedUplink { packet, ticket });
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(())) => {
                if let Some(row) = &self.metrics {
                    row.queue_full(packet.as_ref().len());
                }
                Err(mpsc::error::TrySendError::Full(packet))
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                Err(mpsc::error::TrySendError::Closed(packet))
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    #[cfg(feature = "experimental-roaming")]
    fn try_send_terminal_control(
        &self,
        packet: Vec<u8>,
    ) -> Result<tokio::sync::oneshot::Receiver<()>, mpsc::error::TrySendError<ClientTerminalControl>>
    {
        let (written, receipt) = tokio::sync::oneshot::channel();
        self.terminal_sender
            .try_send(ClientTerminalControl { packet, written })?;
        Ok(receipt)
    }
}

/// Pick the writer for an inner flow.
///
/// A resume-capable peer assigns stable logical slot ids. Hashing modulo the current Vec length
/// would remap otherwise healthy flows whenever one carrier disappears or is restored. Hash over
/// the negotiated width instead, then walk clockwise through the surviving slot ids. Legacy peers
/// retain the historical modulo-current-width scheduler.
fn select_tcp_stream_index(
    streams: &[ClientStreamSender],
    flow_hash: u64,
    stable_width: Option<u32>,
) -> Option<usize> {
    if streams.is_empty() {
        return None;
    }
    let Some(width) = stable_width.map(|width| width.max(1)) else {
        return Some((flow_hash % streams.len() as u64) as usize);
    };
    let desired = (flow_hash % u64::from(width)) as u32;
    streams
        .iter()
        .enumerate()
        .min_by_key(|(_, stream)| {
            let slot = stream.logical_slot_id % width;
            (slot + width - desired) % width
        })
        .map(|(index, _)| index)
}

fn prepare_bonded_uplink(
    bytes: &[u8],
    pool: &BufferPool,
    counters: &UplinkCounters,
) -> Option<PooledBuffer> {
    let Some(mut packet) = pool.try_acquire() else {
        counters.note(UplinkDrop::PoolExhausted);
        return None;
    };
    if bytes.len() > packet.capacity() {
        counters.note(UplinkDrop::Oversize);
        return None;
    }
    packet.as_vec_mut().extend_from_slice(bytes);
    Some(packet)
}

fn queue_tcp_uplink(
    streams: &mut Vec<ClientStreamSender>,
    mut packet: ClientUplink,
    flow: u64,
    stable_width: Option<u32>,
    counters: &UplinkCounters,
) {
    while let Some(index) = select_tcp_stream_index(streams, flow, stable_width) {
        match streams[index].try_send(packet) {
            Ok(()) => return,
            // Preserve flow pinning: a full live queue drops once, without rerouting.
            Err(mpsc::error::TrySendError::Full(_)) => {
                counters.note(UplinkDrop::QueueFull);
                return;
            }
            Err(mpsc::error::TrySendError::Closed(value)) => {
                packet = value;
                streams.remove(index);
            }
        }
    }
    counters.note(UplinkDrop::NoCarrier);
}

#[cfg(test)]
mod tcp_uplink_tests {
    use super::*;

    fn stream(slot: u32) -> (ClientStreamSender, mpsc::Receiver<QueuedUplink>) {
        let (sender, receiver) = mpsc::channel(1);
        let (terminal_sender, _terminal_receiver) = mpsc::channel(1);
        (
            ClientStreamSender {
                logical_slot_id: slot,
                sender,
                terminal_sender,
                metrics: None,
            },
            receiver,
        )
    }

    #[test]
    fn bonded_packet_contract_preserves_bounds_and_byte_budget() {
        let config = crate::config::RecordizerConfig::default();
        for packet_bound in [64, 1464, 9064, u16::MAX as usize, u16::MAX as usize + 1] {
            let mux = crate::protocol::recordizer::RuntimeConfig::from_config(
                &config,
                crate::protocol::packet::MAX_TUNNEL_MTU,
                packet_bound,
            )
            .unwrap();
            let (count, slot) = bonded_uplink_pool_layout(Some(&mux));
            assert!(slot >= packet_bound.min(u16::MAX as usize));
            assert!(slot >= CLIENT_BONDED_UPLINK_MIN_SLOT_BYTES);
            assert!(count <= 2048);
            assert!(count * slot <= CLIENT_BONDED_UPLINK_BUFFER_BYTES);
        }
        let (count, slot) = bonded_uplink_pool_layout(None);
        assert_eq!(slot, crate::protocol::packet::MAX_TUNNEL_MTU);
        assert!(count * slot <= CLIENT_BONDED_UPLINK_BUFFER_BYTES);
    }

    #[test]
    fn bonded_reader_burst_keeps_pinned_data_and_ack_packets_without_drops() {
        let mux = crate::protocol::recordizer::RuntimeConfig::from_config(
            &crate::config::RecordizerConfig::default(),
            crate::protocol::packet::MAX_TUNNEL_MTU,
            1464,
        )
        .unwrap();
        let (count, slot) = bonded_uplink_pool_layout(Some(&mux));
        let pool = BufferPool::new(count, slot).unwrap();
        let capacity = crate::transport_core::buffer_pool::bonded_queue_capacity(count, 2);
        let (sender, mut receiver) = mpsc::channel(capacity);
        let (terminal_sender, _terminal_receiver) = mpsc::channel(1);
        let mut streams = vec![ClientStreamSender {
            logical_slot_id: 0,
            sender,
            terminal_sender,
            metrics: None,
        }];
        let counters = UplinkCounters::default();
        // Two 64-packet reader bursts collide on one pinned carrier before it drains.
        // Include small ACK-sized packets instead of requiring bulk-payload-only fairness.
        for index in 0..128 {
            let bytes = vec![index as u8; if index % 2 == 0 { 1400 } else { 40 }];
            let packet = prepare_bonded_uplink(&bytes, &pool, &counters).unwrap();
            queue_tcp_uplink(
                &mut streams,
                ClientUplink::Bonded(packet),
                0,
                Some(2),
                &counters,
            );
        }
        assert_eq!(counters.snapshot().total, 0);
        for index in 0..128 {
            let packet = receiver.try_recv().unwrap();
            assert_eq!(packet.as_ref()[0], index as u8);
            assert_eq!(
                packet.as_ref().len(),
                if index % 2 == 0 { 1400 } else { 40 }
            );
        }
        assert!(receiver.try_recv().is_err());
        // A stalled pinned carrier still cannot take the whole shared pool.
        for _ in 0..capacity {
            let packet = prepare_bonded_uplink(b"stalled", &pool, &counters).unwrap();
            streams[0]
                .try_send(ClientUplink::Bonded(packet))
                .ok()
                .unwrap();
        }
        assert!(pool.try_acquire().is_some());
        assert!(capacity * 3 < count);
    }

    #[test]
    fn pool_refusal_and_oversize_are_distinct_and_release_the_slot() {
        let pool = BufferPool::new(1, 64).unwrap();
        let counters = UplinkCounters::default();
        let held = pool.try_acquire().unwrap();
        assert!(prepare_bonded_uplink(b"data", &pool, &counters).is_none());
        drop(held);
        assert!(prepare_bonded_uplink(&[0; 65], &pool, &counters).is_none());
        let accepted = prepare_bonded_uplink(b"data", &pool, &counters).unwrap();
        assert_eq!(accepted.as_ref(), b"data");
        let snapshot = counters.snapshot();
        assert_eq!(
            (snapshot.total, snapshot.pool_exhausted, snapshot.oversize),
            (2, 1, 1)
        );
    }

    #[test]
    fn full_pinned_queue_drops_once_and_releases_buffer_without_repinning() {
        let (pinned, mut pinned_rx) = stream(0);
        let (other, mut other_rx) = stream(1);
        pinned
            .try_send(ClientUplink::Owned(b"held".to_vec()))
            .ok()
            .unwrap();
        let mut streams = vec![pinned, other];
        let counters = UplinkCounters::default();
        let pool = BufferPool::new(1, 64).unwrap();
        let packet = prepare_bonded_uplink(b"discard", &pool, &counters).unwrap();
        queue_tcp_uplink(
            &mut streams,
            ClientUplink::Bonded(packet),
            0,
            Some(2),
            &counters,
        );
        assert!(matches!(
            other_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(pinned_rx.try_recv().is_ok());
        assert!(pool.try_acquire().is_some());
        assert_eq!(
            (counters.snapshot().total, counters.snapshot().queue_full),
            (1, 1)
        );
        assert_eq!(streams.len(), 2);
    }

    #[test]
    fn closed_carrier_retries_a_live_slot_without_counting_a_packet_drop() {
        for stable_width in [None, Some(2)] {
            let (closed, closed_rx) = stream(0);
            drop(closed_rx);
            let (live, mut live_rx) = stream(1);
            let mut streams = vec![closed, live];
            let counters = UplinkCounters::default();
            queue_tcp_uplink(
                &mut streams,
                ClientUplink::Owned(b"delivered".to_vec()),
                0,
                stable_width,
                &counters,
            );
            let ClientUplink::Owned(packet) = live_rx.try_recv().unwrap().packet else {
                panic!("wrong packet");
            };
            assert_eq!(packet, b"delivered");
            assert_eq!(counters.snapshot().total, 0);
            assert_eq!(streams.len(), 1);
        }
    }

    #[test]
    fn missing_or_all_closed_carriers_count_one_drop_per_packet() {
        let counters = UplinkCounters::default();
        queue_tcp_uplink(
            &mut vec![],
            ClientUplink::Owned(vec![1]),
            0,
            None,
            &counters,
        );
        let (first, first_rx) = stream(0);
        drop(first_rx);
        let (second, second_rx) = stream(1);
        drop(second_rx);
        let mut streams = vec![first, second];
        queue_tcp_uplink(
            &mut streams,
            ClientUplink::Owned(vec![2]),
            0,
            Some(2),
            &counters,
        );
        assert!(streams.is_empty());
        assert_eq!(
            (counters.snapshot().total, counters.snapshot().no_carrier),
            (2, 2)
        );
    }
}

#[cfg(feature = "experimental-roaming")]
async fn send_tcp_close_session(outs: &Arc<std::sync::Mutex<Vec<ClientStreamSender>>>) {
    let senders = crate::util::lock_or_recover(outs, "client::outs").clone();
    let frame = crate::protocol::control_v2::close_session(rand::random());
    let deadline = tokio::time::Instant::now() + TCP_CLOSE_NOTIFY_TIMEOUT;
    for sender in senders {
        if sender.is_closed() {
            continue;
        }
        match sender.try_send_terminal_control(frame.clone()) {
            Ok(receipt) => {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, receipt).await {
                    Ok(Ok(())) => {
                        log::info!(
                            "sent orderly CLOSE_SESSION on TCP stream slot {}",
                            sender.logical_slot_id
                        );
                        return;
                    }
                    Ok(Err(_)) => log::debug!(
                        "TCP stream slot {} closed before CLOSE_SESSION was written",
                        sender.logical_slot_id
                    ),
                    Err(_) => log::debug!(
                        "timed out writing CLOSE_SESSION on TCP stream slot {}",
                        sender.logical_slot_id
                    ),
                }
            }
            Err(error) => log::debug!(
                "could not queue CLOSE_SESSION on TCP stream slot {}: {}",
                sender.logical_slot_id,
                error
            ),
        }
    }
    log::debug!("no live TCP stream accepted the best-effort CLOSE_SESSION");
}

/// Original-session material shared by authenticated hard resume and the future
/// PathUpdate-driven make-before-break transaction.
#[derive(Clone)]
struct TcpResumeContext {
    #[cfg(feature = "experimental-roaming")]
    session_locator: [u8; crate::protocol::roaming::SESSION_LOCATOR_LEN],
    #[cfg(feature = "experimental-roaming")]
    resume_secret: Arc<zeroize::Zeroizing<[u8; 32]>>,
    #[cfg(feature = "experimental-roaming")]
    next_epoch: Arc<AtomicU64>,
}

#[cfg(feature = "experimental-roaming")]
impl TcpResumeContext {
    fn next_epoch(&self) -> anyhow::Result<u64> {
        let previous = self
            .next_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("TCP resume epoch exhausted"))?;
        previous
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("TCP resume epoch exhausted"))
    }
}

#[cfg(feature = "experimental-roaming")]
fn decode_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut decoded = [0u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(decoded)
}

#[cfg(all(test, feature = "experimental-roaming"))]
mod tcp_resume_client_tests {
    use super::{
        decode_hex_array, mark_tcp_slot_started, mark_tcp_slot_stopped, path_ack_future,
        path_ack_is_explicit_rejection, publish_tcp_path_handover, select_tcp_stream_index,
        should_defer_tcp_resume_for_handover, tcp_handover_failure_action, ClientStreamSender,
        PathCommandFailure, TcpActiveSlots, TcpHandoverCommitPhase, TcpHandoverFailureAction,
        TcpResumeContext, TcpSecondaryAttach, PATH_ACK_TIMEOUT, TCP_HANDOVER_PREPARE_GRACE,
    };
    use portable_atomic::AtomicU64;
    use std::{sync::Arc, time::Duration};

    #[test]
    fn resume_attach_binds_original_secret_transcript_epoch_and_slot() {
        let secret = [0x5a; 32];
        let context = TcpResumeContext {
            session_locator: [0x33; crate::protocol::roaming::SESSION_LOCATOR_LEN],
            resume_secret: Arc::new(zeroize::Zeroizing::new(secret)),
            next_epoch: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(context.next_epoch().unwrap(), 1);
        let epoch = context.next_epoch().unwrap();
        assert_eq!(epoch, 2);
        let transcript = [0xa7; 32];
        let encoded = TcpSecondaryAttach::Resume {
            context: &context,
            resume_epoch: epoch,
            logical_slot_id: 3,
            handover: false,
        }
        .first_message(transcript);
        let join = crate::protocol::roaming::TcpResumeJoin::decode(&encoded).unwrap();
        assert!(join.verify(&secret));
        assert!(join.matches_transcript(&transcript));
        assert_eq!(join.input().resume_epoch(), 2);
        assert_eq!(join.input().logical_slot_id(), 3);
        assert!(!join.input().is_handover());

        let handover = TcpSecondaryAttach::Resume {
            context: &context,
            resume_epoch: context.next_epoch().unwrap(),
            logical_slot_id: 3,
            handover: true,
        }
        .first_message(transcript);
        let handover = crate::protocol::roaming::TcpResumeJoin::decode(&handover).unwrap();
        assert!(handover.verify(&secret));
        assert!(handover.input().is_handover());
    }

    #[test]
    fn overlapping_handover_carriers_keep_the_logical_slot_active_until_both_stop() {
        let active: TcpActiveSlots =
            Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        mark_tcp_slot_started(&active, 3);
        mark_tcp_slot_started(&active, 3);
        mark_tcp_slot_stopped(&active, 3);
        assert_eq!(
            crate::util::lock_or_recover(&active, "test::active_slots")
                .get(&3)
                .copied(),
            Some(1)
        );
        mark_tcp_slot_stopped(&active, 3);
        assert!(!crate::util::lock_or_recover(&active, "test::active_slots").contains_key(&3));
    }

    #[test]
    fn path_handover_retires_every_old_bonded_sender_before_publishing_slot_zero() {
        let (old_zero, old_zero_rx) = tokio::sync::mpsc::channel(1);
        let (old_one, old_one_rx) = tokio::sync::mpsc::channel(1);
        let (old_two, old_two_rx) = tokio::sync::mpsc::channel(1);
        let (new_zero, _new_zero_rx) = tokio::sync::mpsc::channel(1);
        let (terminal_sender, _terminal_receiver) = tokio::sync::mpsc::channel(1);
        let mut outputs = vec![
            ClientStreamSender {
                logical_slot_id: 0,
                sender: old_zero,
                terminal_sender: terminal_sender.clone(),
                metrics: None,
            },
            ClientStreamSender {
                logical_slot_id: 1,
                sender: old_one,
                terminal_sender: terminal_sender.clone(),
                metrics: None,
            },
            ClientStreamSender {
                logical_slot_id: 2,
                sender: old_two,
                terminal_sender: terminal_sender.clone(),
                metrics: None,
            },
        ];
        let retired = publish_tcp_path_handover(
            &mut outputs,
            ClientStreamSender {
                logical_slot_id: 0,
                sender: new_zero,
                terminal_sender,
                metrics: None,
            },
        );
        assert_eq!(retired, 3);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].logical_slot_id, 0);
        assert!(old_zero_rx.is_closed() && old_one_rx.is_closed() && old_two_rx.is_closed());
    }

    #[test]
    fn resume_scheduler_keeps_healthy_logical_slots_stable_when_a_carrier_changes() {
        let (terminal_sender, _terminal_receiver) = tokio::sync::mpsc::channel(1);
        let sender = |logical_slot_id| {
            let (sender, _receiver) = tokio::sync::mpsc::channel(1);
            ClientStreamSender {
                logical_slot_id,
                sender,
                terminal_sender: terminal_sender.clone(),
                metrics: None,
            }
        };
        let mut outputs = vec![sender(0), sender(1), sender(2), sender(3)];
        let selected_slot = |outputs: &[ClientStreamSender], hash| {
            let index = select_tcp_stream_index(outputs, hash, Some(4)).unwrap();
            outputs[index].logical_slot_id
        };

        assert_eq!(selected_slot(&outputs, 2), 2);
        outputs.retain(|entry| entry.logical_slot_id != 1);
        assert_eq!(selected_slot(&outputs, 2), 2);
        assert_eq!(selected_slot(&outputs, 1), 2);
        outputs.push(sender(1));
        outputs.sort_unstable_by_key(|entry| entry.logical_slot_id);
        assert_eq!(selected_slot(&outputs, 2), 2);
        assert_eq!(selected_slot(&outputs, 1), 1);
    }

    #[test]
    fn exact_path_handover_preempts_generic_hard_resume_only_while_useful() {
        let just_orphaned = Some(TCP_HANDOVER_PREPARE_GRACE / 2);
        let grace_expired = Some(TCP_HANDOVER_PREPARE_GRACE);

        assert!(should_defer_tcp_resume_for_handover(
            true,
            false,
            just_orphaned
        ));
        assert!(should_defer_tcp_resume_for_handover(true, true, None));
        assert!(should_defer_tcp_resume_for_handover(
            true,
            true,
            grace_expired
        ));
        assert!(!should_defer_tcp_resume_for_handover(
            true,
            false,
            grace_expired
        ));
        assert!(!should_defer_tcp_resume_for_handover(
            false,
            true,
            just_orphaned
        ));
    }

    #[test]
    fn post_platform_commit_failure_is_terminal_and_server_wait_has_margin() {
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::Reversible, false),
            TcpHandoverFailureAction::RollbackCandidate
        );
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::CommitIssued, true),
            TcpHandoverFailureAction::RollbackCandidate,
            "only an explicit platform rejection is safely reversible after issuance"
        );
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::CommitIssued, false),
            TcpHandoverFailureAction::ReconnectGeneration
        );
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::PlatformCommitted, true),
            TcpHandoverFailureAction::ReconnectGeneration
        );
        let server_wait =
            Duration::from_secs(crate::protocol::roaming::TCP_RESUME_SERVER_COMMIT_TIMEOUT_SECS);
        assert!(server_wait >= PATH_ACK_TIMEOUT + Duration::from_secs(10));
    }

    #[tokio::test]
    async fn late_platform_commit_ack_is_uncertain_and_forces_reconnect() {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let timed_out = tokio::time::timeout(
            Duration::from_millis(1),
            path_ack_future(receiver, "COMMIT_PATH"),
        )
        .await;
        assert!(timed_out.is_err());
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::CommitIssued, false),
            TcpHandoverFailureAction::ReconnectGeneration
        );
        assert!(sender.send(Ok(())).is_err(), "late ACK lost its receiver");

        let (sender, receiver) = tokio::sync::oneshot::channel();
        sender
            .send(Err(PathCommandFailure::Rejected("route rejected".into())))
            .unwrap();
        let rejection = path_ack_future(receiver, "COMMIT_PATH").await.unwrap_err();
        assert!(path_ack_is_explicit_rejection(&rejection));
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::CommitIssued, true),
            TcpHandoverFailureAction::RollbackCandidate
        );

        let (sender, receiver) = tokio::sync::oneshot::channel();
        sender
            .send(Err(PathCommandFailure::PlatformStateUnknown(
                "route rollback failed".into(),
            )))
            .unwrap();
        let uncertain = path_ack_future(receiver, "COMMIT_PATH").await.unwrap_err();
        assert!(!path_ack_is_explicit_rejection(&uncertain));
        assert_eq!(
            tcp_handover_failure_action(TcpHandoverCommitPhase::CommitIssued, false),
            TcpHandoverFailureAction::ReconnectGeneration
        );
    }

    #[test]
    fn session_locator_hex_is_strict() {
        let expected = [0xabu8; crate::protocol::roaming::SESSION_LOCATOR_LEN];
        assert_eq!(
            decode_hex_array::<{ crate::protocol::roaming::SESSION_LOCATOR_LEN }>(
                &"ab".repeat(crate::protocol::roaming::SESSION_LOCATOR_LEN)
            ),
            Some(expected)
        );
        assert!(decode_hex_array::<16>("ab").is_none());
        assert!(decode_hex_array::<16>(&"zz".repeat(16)).is_none());
    }
}

impl AsRef<[u8]> for ClientUplink {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Tun(packet) => packet,
            Self::Bonded(packet) => packet,
            Self::Owned(packet) => packet,
        }
    }
}

/// Encrypt, pace and write one already-recordized plaintext. Keeping this in one
/// helper guarantees that legacy packets and PACKET_MUX_V1 envelopes use exactly
/// the same padding/shaping path.
fn encrypt_client_payload(
    tx: &mut PacketCodec,
    data: &[u8],
    payload_budget: usize,
    cfg: &StreamPump,
    wire_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
) -> bool {
    {
        let mut obf = Obfuscator::new();
        let normalization_padding = if cfg.norm_enabled && !cfg.norm_sizes.is_empty() {
            Obfuscator::normalization_padding_len(data.len(), &cfg.norm_sizes, payload_budget)
        } else {
            0
        };
        let base = data
            .len()
            .saturating_add(normalization_padding)
            .saturating_add(60);
        let pad_cap = (cfg.padding_max as usize).min(payload_budget.saturating_sub(base)) as u16;
        obf.generate_padding_opts_into(
            cfg.padding_enabled,
            cfg.padding_min,
            pad_cap,
            cfg.padding_randomize,
            cfg.padding_prob,
            padding,
        );
        if cfg.norm_enabled && !cfg.norm_sizes.is_empty() {
            obf.append_normalization_padding_into(
                data.len(),
                &cfg.norm_sizes,
                payload_budget,
                padding,
            );
        }
        tx.encrypt_packet_into(data, padding, wire_record).is_ok()
    }
}

async fn write_client_wire_record<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    tx: &mut PacketCodec,
    shaper: &mut crate::protocol::Shaper,
    wire_record: &[u8],
    cover_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
) -> bool {
    let delay = shaper.stealth_pace(wire_record.len(), std::time::Instant::now());
    if shaper.stealth() && !delay.is_zero() {
        let pacing = crate::protocol::shaper::StealthPacing::new(delay);
        while let Some(step) = pacing.next_step() {
            let size = shaper.next_size(&mut rand::rng());
            let cover_ready = if step.cover && shaper.try_spend(size, std::time::Instant::now()) {
                let mut obf = Obfuscator::new();
                obf.generate_padding_into(size as u16, size as u16, padding);
                tx.encrypt_packet_into(&[], padding, cover_record).is_ok()
            } else {
                false
            };
            if cover_ready && write_half.write_all_flush(cover_record).await.is_err() {
                return false;
            }
            tokio::time::sleep_until(step.resume_at).await;
        }
    } else if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    write_half.write_all_flush(wire_record).await.is_ok()
}

/// Deliver one authenticated plaintext record. With PACKET_MUX_V1 it may yield
/// zero, one or several inner packets; legacy records retain their pooled buffer.
struct ClientTcpRxMetrics<'a> {
    last_rx: &'a AtomicU64,
    base: tokio::time::Instant,
    total_rx: &'a AtomicU64,
    runtime: &'a RuntimeCounters,
    unsupported_drops: &'a mut u64,
}

#[derive(Clone, Copy)]
struct ClientManagementRx<'a> {
    negotiated: bool,
    reassembler: &'a std::sync::Mutex<crate::protocol::control_v2::Reassembler>,
    sender: &'a tokio::sync::watch::Sender<Option<crate::protocol::control_v2::ManagementEvent>>,
    terminal_sender: &'a mpsc::Sender<ClientTerminalControl>,
}

fn deliver_client_tcp_plaintext(
    record: PooledBuffer,
    mux: &mut Option<crate::protocol::recordizer::Reassembler>,
    tun: &TunWriter,
    family_mode: crate::transport_core::NetworkFamilyMode,
    management: ClientManagementRx<'_>,
    metrics: ClientTcpRxMetrics<'_>,
) -> bool {
    metrics
        .last_rx
        .store(metrics.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    if record.is_empty() {
        return true;
    }
    // Terminal management bypasses the recordizer's morphology queue. Consume that direct,
    // authenticated record before asking the mux decoder to interpret it as PACKET_MUX_V1.
    // Recordized NOTICE/legacy management is still handled inside the decoded packet loop.
    if consume_authenticated_management(
        record.as_ref(),
        management.negotiated,
        management.reassembler,
        management.sender,
        Some(management.terminal_sender),
    )
    .consumed
    {
        return true;
    }

    if let Some(mux) = mux.as_mut() {
        let packets = match mux.decode(record.as_ref()) {
            Ok(packets) => packets,
            Err(error) => {
                log::debug!("TCP recordizer decode error: {error}");
                return true;
            }
        };
        drop(record);
        for bytes in packets {
            if consume_authenticated_management(
                &bytes,
                management.negotiated,
                management.reassembler,
                management.sender,
                Some(management.terminal_sender),
            )
            .consumed
            {
                continue;
            }
            if !is_supported_inner_packet(&bytes, family_mode) {
                *metrics.unsupported_drops = metrics.unsupported_drops.saturating_add(1);
                if metrics.unsupported_drops.is_power_of_two() {
                    log::debug!(
                        "TCP client dropped invalid or non-negotiated-family downlink packet (total {})",
                        metrics.unsupported_drops
                    );
                }
                continue;
            }
            let Some(mut packet) = tun.try_acquire() else {
                metrics
                    .runtime
                    .tcp_downlink
                    .note(DownlinkDrop::PoolExhausted);
                continue;
            };
            packet.as_vec_mut().extend_from_slice(&bytes);
            metrics
                .total_rx
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            metrics.runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
            metrics
                .runtime
                .rx_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            trace::record(trace::Dir::Rx, "client.tcp", bytes.len(), 0);
            match tun.try_send(packet) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    metrics.runtime.tcp_downlink.note(DownlinkDrop::QueueFull);
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    metrics
                        .runtime
                        .tcp_downlink
                        .note(DownlinkDrop::Disconnected);
                    return false;
                }
            }
        }
        return true;
    }

    if !is_supported_inner_packet(record.as_ref(), family_mode) {
        *metrics.unsupported_drops = metrics.unsupported_drops.saturating_add(1);
        if metrics.unsupported_drops.is_power_of_two() {
            log::debug!(
                "TCP client dropped invalid or non-negotiated-family downlink packet (total {})",
                metrics.unsupported_drops
            );
        }
        return true;
    }
    metrics
        .total_rx
        .fetch_add(record.len() as u64, Ordering::Relaxed);
    metrics.runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
    metrics
        .runtime
        .rx_bytes
        .fetch_add(record.len() as u64, Ordering::Relaxed);
    trace::record(trace::Dir::Rx, "client.tcp", record.len(), 0);
    match tun.try_send(record) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            metrics.runtime.tcp_downlink.note(DownlinkDrop::QueueFull);
            true
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            metrics
                .runtime
                .tcp_downlink
                .note(DownlinkDrop::Disconnected);
            false
        }
    }
}

#[cfg(test)]
mod tcp_downlink_tests {
    use super::*;
    use crate::protocol::recordizer::{Reassembler, Recordizer, RuntimeConfig};

    fn packet() -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        bytes
    }

    fn deliver(
        bytes: &[u8],
        muxed: bool,
        tun: &TunWriter,
        records: &BufferPool,
        counters: &RuntimeCounters,
    ) -> bool {
        let runtime =
            RuntimeConfig::from_config(&crate::config::RecordizerConfig::default(), 512, 128)
                .unwrap();
        let mut mux = muxed.then(|| Reassembler::new(runtime.clone()));
        let payload = if muxed {
            let mut encoder = Recordizer::new(runtime);
            let mut ready = encoder.push(bytes, std::time::Instant::now()).unwrap();
            ready.extend(encoder.flush());
            assert_eq!(ready.len(), 1);
            ready.remove(0)
        } else {
            bytes.to_vec()
        };
        let mut record = records.try_acquire().unwrap();
        record.as_vec_mut().extend_from_slice(&payload);
        let reassembler = std::sync::Mutex::new(crate::protocol::control_v2::Reassembler::new());
        let (sender, _) = tokio::sync::watch::channel(None);
        let (terminal_sender, _) = mpsc::channel(1);
        let last_rx = AtomicU64::new(0);
        let total_rx = AtomicU64::new(0);
        let mut unsupported = 0;
        deliver_client_tcp_plaintext(
            record,
            &mut mux,
            tun,
            crate::transport_core::NetworkFamilyMode::Ipv4,
            ClientManagementRx {
                negotiated: false,
                reassembler: &reassembler,
                sender: &sender,
                terminal_sender: &terminal_sender,
            },
            ClientTcpRxMetrics {
                last_rx: &last_rx,
                base: tokio::time::Instant::now(),
                total_rx: &total_rx,
                runtime: counters,
                unsupported_drops: &mut unsupported,
            },
        )
    }

    #[test]
    fn raw_and_mux_full_queue_count_once_continue_and_return_buffers() {
        for muxed in [false, true] {
            let pool = BufferPool::new(2, 512).unwrap();
            let records = BufferPool::new(2, 512).unwrap();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            let tun = TunWriter::from_parts(sender, pool.clone());
            let counters = RuntimeCounters::default();
            assert!(deliver(&packet(), muxed, &tun, &records, &counters));
            assert!(deliver(&packet(), muxed, &tun, &records, &counters));
            assert_eq!(
                (
                    counters.tcp_downlink.snapshot().total,
                    counters.tcp_downlink.snapshot().queue_full
                ),
                (1, 1)
            );
            assert_eq!(counters.rx_packets.load(Ordering::Relaxed), 2);
            assert_eq!(counters.tcp_uplink.snapshot().total, 0);
            let queued = receiver.try_recv().unwrap();
            assert_eq!(queued.as_ref(), packet());
            drop(queued);
            let first = pool.try_acquire().unwrap();
            let second = pool.try_acquire().unwrap();
            assert!(pool.try_acquire().is_none());
            drop((first, second));
            let first = records.try_acquire().unwrap();
            let second = records.try_acquire().unwrap();
            assert!(records.try_acquire().is_none());
            drop((first, second));
        }
    }

    #[test]
    fn raw_and_mux_disconnected_queue_count_once_stop_and_return_buffers() {
        for muxed in [false, true] {
            let pool = BufferPool::new(1, 512).unwrap();
            let records = BufferPool::new(1, 512).unwrap();
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            drop(receiver);
            let tun = TunWriter::from_parts(sender, pool.clone());
            let counters = RuntimeCounters::default();
            assert!(!deliver(&packet(), muxed, &tun, &records, &counters));
            assert_eq!(
                (
                    counters.tcp_downlink.snapshot().total,
                    counters.tcp_downlink.snapshot().disconnected
                ),
                (1, 1)
            );
            assert!(pool.try_acquire().is_some());
            assert!(records.try_acquire().is_some());
        }
    }

    #[test]
    fn mux_pool_refusal_counts_one_packet_then_recovers_without_rx_overcount() {
        let pool = BufferPool::new(1, 512).unwrap();
        let records = BufferPool::new(1, 512).unwrap();
        let held = pool.try_acquire().unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let tun = TunWriter::from_parts(sender, pool.clone());
        let counters = RuntimeCounters::default();
        assert!(deliver(&packet(), true, &tun, &records, &counters));
        assert_eq!(
            (
                counters.tcp_downlink.snapshot().total,
                counters.tcp_downlink.snapshot().pool_exhausted
            ),
            (1, 1)
        );
        assert_eq!(counters.rx_packets.load(Ordering::Relaxed), 0);
        assert!(receiver.try_recv().is_err());
        assert!(records.try_acquire().is_some());
        drop(held);
        assert!(deliver(&packet(), true, &tun, &records, &counters));
        assert_eq!(receiver.try_recv().unwrap().as_ref(), packet());
        assert_eq!(counters.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.tcp_downlink.snapshot().total, 1);
    }

    #[test]
    fn empty_and_unsupported_plaintext_are_not_tun_handoff_losses() {
        let pool = BufferPool::new(1, 512).unwrap();
        let records = BufferPool::new(1, 512).unwrap();
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        let tun = TunWriter::from_parts(sender, pool.clone());
        let counters = RuntimeCounters::default();
        assert!(deliver(&[], false, &tun, &records, &counters));
        for muxed in [false, true] {
            assert!(deliver(&[0], muxed, &tun, &records, &counters));
        }
        assert_eq!(counters.tcp_downlink.snapshot().total, 0);
        assert_eq!(counters.rx_packets.load(Ordering::Relaxed), 0);
        assert!(pool.try_acquire().is_some());
        assert!(records.try_acquire().is_some());
    }
}

type TcpActiveSlots = Arc<std::sync::Mutex<std::collections::BTreeMap<u32, usize>>>;
type TcpStreamTasks = crate::transport_core::tasks::Spawner;

#[cfg(feature = "experimental-roaming")]
fn publish_tcp_path_handover(
    outputs: &mut Vec<ClientStreamSender>,
    replacement: ClientStreamSender,
) -> usize {
    // A platform path transaction moves the complete bonded carrier set, not only stable slot 0.
    // Keeping secondary writers bound to the old interface makes their flow-pinned queues accept
    // packets into black-holed TCP sockets after that interface disappears. Retire every old
    // sender immediately; the stable-slot maintainer rebuilds the desired fixed/adaptive width
    // through the newly committed platform route while slot 0 keeps the inner tunnel alive.
    let retired = outputs.len();
    outputs.clear();
    debug_assert_eq!(replacement.logical_slot_id, 0);
    outputs.push(replacement);
    retired
}

fn mark_tcp_slot_started(active_slots: &TcpActiveSlots, logical_slot_id: u32) {
    let mut active = crate::util::lock_or_recover(active_slots, "client::active_slots");
    let count = active.entry(logical_slot_id).or_insert(0);
    *count = count.saturating_add(1);
}

fn mark_tcp_slot_stopped(active_slots: &TcpActiveSlots, logical_slot_id: u32) {
    let mut active = crate::util::lock_or_recover(active_slots, "client::active_slots");
    let remove = if let Some(count) = active.get_mut(&logical_slot_id) {
        *count = count.saturating_sub(1);
        *count == 0
    } else {
        log::error!("TCP active-slot counter underflow for slot {logical_slot_id}");
        false
    };
    if remove {
        active.remove(&logical_slot_id);
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpHandoverCommitPhase {
    Reversible,
    CommitIssued,
    PlatformCommitted,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpHandoverFailureAction {
    RollbackCandidate,
    ReconnectGeneration,
}

#[cfg(feature = "experimental-roaming")]
fn tcp_handover_failure_action(
    commit_phase: TcpHandoverCommitPhase,
    explicit_platform_rejection: bool,
) -> TcpHandoverFailureAction {
    if commit_phase == TcpHandoverCommitPhase::Reversible
        || (commit_phase == TcpHandoverCommitPhase::CommitIssued && explicit_platform_rejection)
    {
        TcpHandoverFailureAction::RollbackCandidate
    } else {
        TcpHandoverFailureAction::ReconnectGeneration
    }
}

#[cfg(feature = "experimental-roaming")]
fn should_defer_tcp_resume_for_handover(
    handover_enabled: bool,
    candidate_prepared: bool,
    orphaned_for: Option<Duration>,
) -> bool {
    handover_enabled
        && (candidate_prepared
            || orphaned_for.is_some_and(|elapsed| elapsed < TCP_HANDOVER_PREPARE_GRACE))
}

fn mark_tcp_stream_stopped(
    logical_slot_id: u32,
    stream_dead: &std::sync::atomic::AtomicBool,
    live: &std::sync::atomic::AtomicUsize,
    dead_tx: &mpsc::Sender<()>,
    active_slots: Option<&TcpActiveSlots>,
    last_live_lost_at: Option<&Arc<std::sync::Mutex<Option<tokio::time::Instant>>>>,
) {
    if stream_dead.swap(true, Ordering::AcqRel) {
        return;
    }
    if let Some(active_slots) = active_slots {
        mark_tcp_slot_stopped(active_slots, logical_slot_id);
    }
    let previous = live.fetch_sub(1, Ordering::AcqRel);
    let remaining = previous.saturating_sub(1);
    if previous == 0 {
        log::error!("TCP live-stream counter underflow for slot {logical_slot_id}");
        live.store(0, Ordering::Release);
    }
    if remaining == 0 {
        if let Some(last_live_lost_at) = last_live_lost_at {
            let mut lost_at =
                crate::util::lock_or_recover(last_live_lost_at, "client::last_live_lost_at");
            lost_at.get_or_insert_with(tokio::time::Instant::now);
            log::info!(
                "TCP stream slot {logical_slot_id} lost; preserving TUN during resume grace"
            );
        } else {
            let _ = dead_tx.try_send(());
        }
    } else {
        log::info!("Bonded stream slot {logical_slot_id} lost; {remaining} stream(s) remain");
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
    write_half: W,
    rx_codec: PacketCodec,
    tx_codec: PacketCodec,
    tun_write_tx: TunWriter,
    dead_tx: mpsc::Sender<()>,
    total_tx: Arc<AtomicU64>,
    total_rx: Arc<AtomicU64>,
    runtime: Arc<RuntimeCounters>,
    live: Arc<std::sync::atomic::AtomicUsize>,
    logical_slot_id: u32,
    active_slots: Option<TcpActiveSlots>,
    last_live_lost_at: Option<Arc<std::sync::Mutex<Option<tokio::time::Instant>>>>,
    // The generation owns reader, writer and optional decrypt pipeline through shutdown.
    tasks: TcpStreamTasks,
    cfg: StreamPump,
) -> ClientStreamSender
where
    R: AsyncRead + Unpin + Send + 'static,
    W: crate::protocol::obfs::CarrierWriteControl + Unpin + Send + 'static,
{
    let progress = write_half.write_progress();
    let mut write_half = crate::protocol::stream_io::StallGuard::observing(write_half, progress);
    let write_progress = write_half.progress();
    let carrier_metrics = runtime
        .tcp_carriers
        .register(logical_slot_id, write_progress.clone());
    let (out_tx, mut out_rx) = mpsc::channel::<QueuedUplink>(cfg.uplink_queue_capacity);
    let (terminal_tx, mut terminal_rx) = mpsc::channel::<ClientTerminalControl>(4);
    let stream_sender = ClientStreamSender {
        logical_slot_id,
        sender: out_tx,
        terminal_sender: terminal_tx.clone(),
        metrics: Some(carrier_metrics.clone()),
    };
    let base = tokio::time::Instant::now();
    let last_rx = Arc::new(AtomicU64::new(0));
    // The reader owns the live-count transition after draining received records.
    // A stopped writer requests reader shutdown without racing queued terminal policy.
    let previous_live = live.fetch_add(1, Ordering::AcqRel);
    if let Some(active_slots) = &active_slots {
        mark_tcp_slot_started(active_slots, logical_slot_id);
    }
    if previous_live == 0 {
        if let Some(last_live_lost_at) = &last_live_lost_at {
            *crate::util::lock_or_recover(last_live_lost_at, "client::last_live_lost_at") = None;
        }
    }
    let stream_dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (stream_stop_tx, _) = tokio::sync::watch::channel(false);
    let (writer_stopped_tx, writer_stopped_rx) = tokio::sync::oneshot::channel();

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
        let family_mode = cfg.family_mode;
        let stream_dead = stream_dead.clone();
        let live = live.clone();
        let active_slots = active_slots.clone();
        let last_live_lost_at = last_live_lost_at.clone();
        let stream_stop_tx = stream_stop_tx.clone();
        let mut stream_stop_rx = stream_stop_tx.subscribe();
        let total_rx = total_rx.clone();
        let runtime = runtime.clone();
        let record_pool = tun_write_tx.clone();
        let recordizer_config = cfg.recordizer.clone();
        let management_v1 = cfg.management_v1;
        let management_reassembler = cfg.management_reassembler.clone();
        let management_tx = cfg.management_tx.clone();
        let management_terminal_tx = terminal_tx.clone();

        // Where the reader sends each framed record. `Inline` decrypts in this
        // task (all non-reality modes, unchanged behaviour); `Pipe` forwards the
        // outer-decrypted record to the inner-decrypt task. Exactly one of these
        // exists per stream (never in a collection), so the size gap between the
        // codec-carrying `Inline` and the tiny `Pipe` is irrelevant — boxing the
        // codec would only add an indirection to the common inline path.
        #[allow(clippy::large_enum_variant)]
        enum RxSink {
            Inline {
                rx: PacketCodec,
                tun: TunWriter,
                mux: Option<crate::protocol::recordizer::Reassembler>,
            },
            Pipe(mpsc::Sender<PooledBuffer>),
        }

        let mut pipeline_drained = None;
        let mut sink = if cfg.pipeline_rx {
            let (rec_tx, mut rec_rx) = mpsc::channel::<PooledBuffer>(1024);
            let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
            pipeline_drained = Some(drained_rx);
            let mut inner_rx_codec = rx;
            let inner_tun = tun_write_tx;
            let inner_total_rx = total_rx.clone();
            let inner_runtime = runtime.clone();
            let inner_last_rx = last_rx.clone();
            let mut inner_mux = recordizer_config
                .clone()
                .map(crate::protocol::recordizer::Reassembler::new);
            let inner_management_reassembler = management_reassembler.clone();
            let inner_management_tx = management_tx.clone();
            let inner_management_terminal_tx = management_terminal_tx.clone();
            // Stage B: inner ChaCha decrypt → TUN. Ends when the reader drops
            // `rec_tx`. Never blocks (the TUN send is drop-on-full), so it always
            // drains the FIFO — the reader's backpressure send can therefore
            // always make progress (no deadlock).
            tasks.spawn(async move {
                let mut unsupported_downlink_drops = 0u64;
                while let Some(mut record) = rec_rx.recv().await {
                    match inner_rx_codec.decrypt_packet_in_place(record.as_vec_mut()) {
                        Ok(()) => {
                            if !deliver_client_tcp_plaintext(
                                record,
                                &mut inner_mux,
                                &inner_tun,
                                family_mode,
                                ClientManagementRx {
                                    negotiated: management_v1,
                                    reassembler: &inner_management_reassembler,
                                    sender: &inner_management_tx,
                                    terminal_sender: &inner_management_terminal_tx,
                                },
                                ClientTcpRxMetrics {
                                    last_rx: &inner_last_rx,
                                    base,
                                    total_rx: &inner_total_rx,
                                    runtime: &inner_runtime,
                                    unsupported_drops: &mut unsupported_downlink_drops,
                                },
                            ) {
                                break;
                            }
                        }
                        Err(e) => log::debug!("Decrypt error: {}", e),
                    }
                }
                let _ = drained_tx.send(());
            });
            RxSink::Pipe(rec_tx)
        } else {
            RxSink::Inline {
                rx,
                tun: tun_write_tx,
                mux: recordizer_config.map(crate::protocol::recordizer::Reassembler::new),
            }
        };

        // Stage A: socket read (+ outer decrypt/framing for reality-tls) → sink.
        tasks.spawn(async move {
            let mut unsupported_downlink_drops = 0u64;
            loop {
                let acquired = tokio::select! {
                    biased;
                    _ = stream_stop_rx.changed() => break,
                    record = record_pool.acquire() => record,
                };
                let mut record = match acquired {
                    Some(record) => record,
                    None => break,
                };
                let read = tokio::select! {
                    biased;
                    _ = stream_stop_rx.changed() => break,
                    result = read_record_into(&mut read_half, framing, record.as_vec_mut()) => result,
                };
                match read {
                    Ok(()) => {
                        match &mut sink {
                            RxSink::Inline { rx, tun, mux } => {
                                match rx.decrypt_packet_in_place(record.as_vec_mut()) {
                                    Ok(()) => {
                                        if !deliver_client_tcp_plaintext(
                                            record,
                                            mux,
                                            tun,
                                            family_mode,
                                            ClientManagementRx {
                                                negotiated: management_v1,
                                                reassembler: &management_reassembler,
                                                sender: &management_tx,
                                                terminal_sender: &management_terminal_tx,
                                            },
                                            ClientTcpRxMetrics {
                                                last_rx: &last_rx,
                                                base,
                                                total_rx: &total_rx,
                                                runtime: &runtime,
                                                unsupported_drops: &mut unsupported_downlink_drops,
                                            },
                                        ) {
                                            break;
                                        }
                                    }
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
            // Close the bounded FIFO and join its finite, non-blocking decrypt drain
            // before EOF can tear down the actor. Otherwise a final KICK can be aborted
            // while still queued. Generation cancellation still aborts both tasks.
            drop(sink);
            if let Some(drained) = pipeline_drained {
                let _ = drained.await;
            }
            let _ = stream_stop_tx.send(true);
            // A replacement must not reuse this logical slot while its old
            // writer still owns a socket or a partially serialized record.
            if writer_stopped_rx.await.is_err() {
                log::warn!("TCP writer ended without completion; stopping connection generation");
                let _ = dead_tx.try_send(());
                return;
            }
            mark_tcp_stream_stopped(
                logical_slot_id,
                &stream_dead,
                &live,
                &dead_tx,
                active_slots.as_ref(),
                last_live_lost_at.as_ref(),
            );
        });
    }

    // Writer + heartbeat: outgoing plaintext → encrypt → socket.
    {
        let mut tx = tx_codec;
        let stream_stop_tx = stream_stop_tx.clone();
        let mut stream_stop_rx = stream_stop_tx.subscribe();
        let diagnostics_close = CloseGuard(carrier_metrics.clone());
        tasks.spawn(async move {
            let _diagnostics_close = diagnostics_close;
            let idle_ms = cfg.idle_timeout.as_millis() as u64;
            let mut last_tx_ms: u64 = 0;
            // Flow-shaping: when enabled, idle cover at exponential (non-periodic)
            // gaps REPLACES the fixed heartbeat (client->server direction). Never
            // hold a `ThreadRng` across `.await` (it is `!Send`) — fresh per call.
            let mut shaper =
                crate::protocol::Shaper::new(cfg.shaping.clone(), std::time::Instant::now())
                    .with_shared_budget(cfg.cover_budget.clone());
            let shaping_on = shaper.enabled();
            let heartbeat_enabled = cfg.heartbeat_enabled && !shaping_on;
            let mut heartbeat_deadline = tokio::time::Instant::now()
                + crate::protocol::randomized_heartbeat_delay(
                    cfg.heartbeat_interval,
                    Duration::from_millis(cfg.hb_jitter),
                );
            let rx_dead_ms = crate::protocol::liveness_deadline(
                heartbeat_enabled,
                cfg.heartbeat_interval,
                Duration::from_millis(cfg.hb_jitter),
                shaping_on,
                Duration::from_millis(cfg.shaping.idle_gap_max_ms),
            )
            .map(|deadline| u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX));
            // Supervise the entire pump, including blocked writes and pacing.
            let health = async move {
                let mut tick = tokio::time::interval(Duration::from_secs(5));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut wall = std::time::SystemTime::now();
                let mut instant = tokio::time::Instant::now();
                let mut previous_progress = write_progress.snapshot();
                let mut last_write_ms = 0;
                loop {
                    tick.tick().await;
                    if stream_dead.load(Ordering::Relaxed) { break; }
                    let wall_gap = wall.elapsed().unwrap_or_default();
                    let tick_gap = instant.elapsed();
                    wall = std::time::SystemTime::now();
                    instant = tokio::time::Instant::now();
                    if wall_gap.saturating_sub(tick_gap) > Duration::from_secs(10) {
                        log::warn!("TCP: resumed from suspend (~{}s) — reconnecting", wall_gap.as_secs());
                        DELIBERATE_CYCLE.store(true, std::sync::atomic::Ordering::Release);
                        break;
                    }
                    let now = base.elapsed().as_millis() as u64;
                    let current_progress = write_progress.snapshot();
                    if current_progress != previous_progress {
                        last_write_ms = now;
                        previous_progress = current_progress;
                    }
                    let received = last_rx.load(Ordering::Relaxed);
                    // Silence is valid unless the peer promises liveness traffic.
                    if rx_dead_ms.is_some_and(|deadline| now.saturating_sub(received) > deadline) {
                        log::info!("TCP carrier closed: inbound liveness deadline expired");
                        break;
                    }
                    if idle_ms > 0 && now.saturating_sub(last_write_ms.max(received)) > idle_ms {
                        break;
                    }
                }
            };
            {
            let pump = async move {
            let mut cover_deadline =
                tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());
            // One real record may have to stay intact while stealth pacing emits cover
            // records first, hence two connection-owned buffers. Both are allocated once
            // and reused by `encrypt_packet_into`; neither crosses to another task.
            let wire_capacity = crate::protocol::packet::TLS_RECORD_HEADER
                + crate::protocol::packet::MAX_RECORD_SIZE;
            let mut wire_record = Vec::with_capacity(wire_capacity);
            let mut cover_record = Vec::with_capacity(wire_capacity);
            let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
            let mut recordizer = cfg
                .recordizer
                .clone()
                .map(crate::protocol::recordizer::Recordizer::new);
            let ledger_capacity = cfg.recordizer.as_ref()
                .map_or(1, crate::protocol::recordizer::pending_packet_capacity);
            let mut in_flight = InFlight::new(carrier_metrics, ledger_capacity);
            'writer: loop {
                let mux_deadline = recordizer
                    .as_ref()
                    .and_then(|mux| mux.deadline())
                    .map(tokio::time::Instant::from_std)
                    .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
                tokio::select! {
                    biased;

                    control = std::future::poll_fn(|cx| crate::protocol::obfs::CarrierWriteControl::poll_control(&mut write_half,cx)) => {
                        if control.is_err() {break;}
                    }

                    terminal = terminal_rx.recv() => {
                        let Some(terminal) = terminal else { break };
                        let data_len = terminal.packet.len();
                        let delivered = encrypt_client_payload(
                            &mut tx,
                            &terminal.packet,
                            crate::protocol::packet::MAX_TUNNEL_MTU,
                            &cfg,
                            &mut wire_record,
                            &mut padding,
                        ) && write_client_wire_record(
                            &mut write_half,
                            &mut tx,
                            &mut shaper,
                            &wire_record,
                            &mut cover_record,
                            &mut padding,
                        )
                        .await;
                        if delivered {
                            total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                            last_tx_ms = base.elapsed().as_millis() as u64;
                            heartbeat_deadline = tokio::time::Instant::now()
                                + crate::protocol::randomized_heartbeat_delay(
                                    cfg.heartbeat_interval,
                                    Duration::from_millis(cfg.hb_jitter),
                                );
                            let _ = terminal.written.send(());
                            continue;
                        }
                        break 'writer;
                    }

                    pt = out_rx.recv() => {
                        let Some(pt) = pt else { break };
                        let opportunistic = cfg.recordizer.as_ref().is_some_and(|mux| mux.opportunistic);
                        let mut packets = Vec::new();
                        if opportunistic {
                            while packets.len() + 1 < crate::transport_core::udp_batch::MAX_BATCH {
                                match out_rx.try_recv() {
                                    Ok(packet) => {
                                        if packets.is_empty() { packets.reserve_exact(crate::transport_core::udp_batch::MAX_BATCH - 1); }
                                        packets.push(packet);
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        let batch_len = packets.len() + 1;
                        for (batch_index, pt) in std::iter::once(pt).chain(packets).enumerate() {
                        let QueuedUplink { packet: pt, ticket } = pt;
                        if let Some(ticket) = ticket { in_flight.push(ticket); }
                        let data_len = pt.as_ref().len();
                        if let Some(mux) = recordizer.as_mut() {
                            let ready = mux.push(pt.as_ref(), std::time::Instant::now());
                            drop(pt);
                            let mut payloads = match ready {
                                Ok(payloads) => {
                                    total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                                    payloads
                                }
                                Err(error) => {
                                    // A rejected push can have mutated pending mux
                                    // state; stop claiming exact completion thereafter.
                                    in_flight.invalidate();
                                    log::debug!("TCP recordizer dropped a packet: {error}");
                                    if opportunistic { break 'writer; }
                                    continue;
                                }
                            };
                            if batch_index + 1 == batch_len {
                                if let Some(payload) = mux.finish_ready_batch() { payloads.push(payload); }
                            }
                            for payload in payloads {
                                let payload_bytes = crate::protocol::recordizer::encoded_payload_len(&payload);
                                if payload_bytes.is_none() { in_flight.invalidate(); }
                                if !encrypt_client_payload(
                                    &mut tx,
                                    &payload,
                                    crate::protocol::packet::MAX_TUNNEL_MTU,
                                    &cfg,
                                    &mut wire_record,
                                    &mut padding,
                                ) {
                                    if let Some(bytes) = payload_bytes { in_flight.finish_bytes(bytes, false); }
                                    continue;
                                }
                                if !write_client_wire_record(
                                    &mut write_half,
                                    &mut tx,
                                    &mut shaper,
                                    &wire_record,
                                    &mut cover_record,
                                    &mut padding,
                                ).await {
                                    break 'writer;
                                }
                                if let Some(bytes) = payload_bytes { in_flight.finish_bytes(bytes, true); }
                                last_tx_ms = base.elapsed().as_millis() as u64;
                                heartbeat_deadline = tokio::time::Instant::now()
                                    + crate::protocol::randomized_heartbeat_delay(
                                        cfg.heartbeat_interval,
                                        Duration::from_millis(cfg.hb_jitter),
                                    );
                            }
                        } else {
                            let encrypted = encrypt_client_payload(
                                &mut tx,
                                pt.as_ref(),
                                cfg.tun_mtu,
                                &cfg,
                                &mut wire_record,
                                &mut padding,
                            );
                            drop(pt);
                            if encrypted {
                                total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                                if !write_client_wire_record(
                                    &mut write_half,
                                    &mut tx,
                                    &mut shaper,
                                    &wire_record,
                                    &mut cover_record,
                                    &mut padding,
                                ).await {
                                    break 'writer;
                                }
                                in_flight.finish_bytes(data_len, true);
                                last_tx_ms = base.elapsed().as_millis() as u64;
                                heartbeat_deadline = tokio::time::Instant::now()
                                    + crate::protocol::randomized_heartbeat_delay(
                                        cfg.heartbeat_interval,
                                        Duration::from_millis(cfg.hb_jitter),
                                    );
                            } else {
                                in_flight.finish_bytes(data_len, false);
                            }
                        }
                    }

                        }
                    _ = tokio::time::sleep_until(mux_deadline),
                        if recordizer.as_ref().is_some_and(|mux| mux.is_pending()) =>
                    {
                        if let Some(payload) = recordizer
                            .as_mut()
                            .and_then(|mux| mux.flush_due(std::time::Instant::now()))
                        {
                            let payload_bytes = crate::protocol::recordizer::encoded_payload_len(&payload);
                            if payload_bytes.is_none() { in_flight.invalidate(); }
                            let encrypted = encrypt_client_payload(
                                &mut tx,
                                &payload,
                                crate::protocol::packet::MAX_TUNNEL_MTU,
                                &cfg,
                                &mut wire_record,
                                &mut padding,
                            );
                            if encrypted && !write_client_wire_record(
                                &mut write_half,
                                &mut tx,
                                &mut shaper,
                                &wire_record,
                                &mut cover_record,
                                &mut padding,
                            ).await {
                                break;
                            }
                            if let Some(bytes) = payload_bytes { in_flight.finish_bytes(bytes, encrypted); }
                            last_tx_ms = base.elapsed().as_millis() as u64;
                            heartbeat_deadline = tokio::time::Instant::now()
                                + crate::protocol::randomized_heartbeat_delay(
                                    cfg.heartbeat_interval,
                                    Duration::from_millis(cfg.hb_jitter),
                                );
                        }
                    }

                    _ = tokio::time::sleep_until(heartbeat_deadline), if heartbeat_enabled => {
                        let hb_ready = {
                            let mut obf = Obfuscator::new();
                            obf.generate_padding_into(
                                cfg.hb_data,
                                cfg.hb_data.saturating_add(32),
                                &mut padding,
                            );
                            tx.encrypt_packet_into(&[], &padding, &mut cover_record).is_ok()
                        };
                        if hb_ready && write_half.write_all_flush(&cover_record).await.is_err() {
                            break;
                        }
                        last_tx_ms = base.elapsed().as_millis() as u64;
                        heartbeat_deadline = tokio::time::Instant::now()
                            + crate::protocol::randomized_heartbeat_delay(
                                cfg.heartbeat_interval,
                                Duration::from_millis(cfg.hb_jitter),
                            );
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
                                    if write_half.write_all_flush(&cover_record).await.is_err() { break; }
                                    last_tx_ms = base.elapsed().as_millis() as u64;
                                }
                            }
                        }
                        cover_deadline = tokio::time::Instant::now()
                            + shaper.next_gap(&mut rand::rng());
                    }

                    else => break,
                }
            }
            };
            tokio::select! {
                biased;
                _ = stream_stop_rx.wait_for(|stopped| *stopped) => {},
                _ = health => {},
                _ = pump => {},
            }
            } // Drop the writer and any partial record before stopping its reader.
            // The reader reports loss after processing all already-received records.
            // Wake it even when it is waiting for a recycled TUN buffer.
            let _ = stream_stop_tx.send(true);
            let _ = writer_stopped_tx.send(());
        });
    }

    stream_sender
}

pub(crate) async fn run_tcp_tunnel<S>(
    mut stream: S,
    connector: StreamConnector<S>,
    config: &crate::config::client::ClientConfig,
    password: &str,
    core: &mut dyn ClientPlatform,
    connection_tasks: &mut crate::transport_core::tasks::TaskGroup,
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
    let platform_capabilities = core.platform_capabilities();
    let identity_verifier = core.identity_verifier(config);
    let handshake = match tokio::time::timeout(
        hs_to,
        tcp_handshake(
            &mut stream,
            config,
            password,
            &client_device_id,
            platform_capabilities,
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
    let server_capabilities = handshake.server_capabilities;
    #[cfg(feature = "experimental-roaming")]
    let client_capabilities = handshake.client_capabilities;
    #[cfg(not(feature = "experimental-roaming"))]
    let client_capabilities = None;
    #[cfg(feature = "experimental-roaming")]
    let tcp_control_v2 = client_capabilities.is_some_and(|client| {
        client.core_bits & crate::protocol::capabilities::client_capability::CONTROL_V2 != 0
    }) && server_capabilities.is_some_and(|server| {
        server.contains(crate::protocol::capabilities::server_capability::CONTROL_V2)
    });
    let management_v1 = crate::protocol::capabilities::management_v1_negotiated(
        server_capabilities,
        client_capabilities,
    );
    #[cfg(feature = "experimental-roaming")]
    let resume_secret = handshake.resume_secret;
    let client_rx = handshake.client_rx;
    let client_tx = handshake.client_tx;
    let ok = handshake.auth;
    let AuthOk {
        family_mode,
        addresses,
        client_ip: client_ip_str,
        server_ip,
        prefix,
        mtu: pushed_mtu,
        dns_ip,
        dns_port,
        dns_servers,
        routes_json,
        pushed_obf,
        session_token,
        max_streams,
        adaptive,
        udp_roaming_session_id: _,
    } = ok;
    #[cfg(feature = "experimental-roaming")]
    let tcp_resume: Option<Arc<TcpResumeContext>> = if client_capabilities.is_some_and(|client| {
        client.core_bits & crate::protocol::capabilities::client_capability::TCP_RESUME_V2 != 0
    }) && server_capabilities.is_some_and(
        |server| server.contains(crate::protocol::capabilities::server_capability::TCP_RESUME_V2),
    ) {
        let session_locator =
            decode_hex_array::<{ crate::protocol::roaming::SESSION_LOCATOR_LEN }>(&session_token)
                .ok_or_else(|| {
                anyhow::anyhow!(
                    "server negotiated TCP_RESUME_V2 but returned an invalid session locator"
                )
            })?;
        log::info!("TCP hard-resume negotiated; preserving NetworkPlan during carrier loss");
        Some(Arc::new(TcpResumeContext {
            session_locator,
            resume_secret: Arc::new(resume_secret),
            next_epoch: Arc::new(AtomicU64::new(0)),
        }))
    } else {
        None
    };
    #[cfg(not(feature = "experimental-roaming"))]
    let tcp_resume: Option<Arc<TcpResumeContext>> = {
        let _ = server_capabilities;
        None
    };
    #[cfg(feature = "experimental-roaming")]
    let path_controller = core.path_controller();
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let linux_path_controller = core.linux_path_controller();
    #[cfg(feature = "experimental-roaming")]
    let tcp_handover_enabled = path_controller.is_some()
        && client_capabilities.is_some_and(|client| {
            client.core_bits & crate::protocol::capabilities::client_capability::TCP_HANDOVER_V2
                != 0
        })
        && tcp_resume.is_some()
        && server_capabilities.is_some_and(|server| {
            server.contains(crate::protocol::capabilities::server_capability::TCP_HANDOVER_V2)
        })
        && platform_capabilities & crate::transport_core::platform_capability::ROAMING_PATH
            == crate::transport_core::platform_capability::ROAMING_PATH;
    #[cfg(feature = "experimental-roaming")]
    if tcp_handover_enabled {
        log::info!(
            "TCP make-before-break negotiated; prepared PathUpdate candidates may replace slot 0"
        );
    } else if path_controller.is_some() {
        log::info!(
            "platform path transactions are available, but this server session requires full reconnect fallback"
        );
    }
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
        family_mode,
        addresses: &addresses,
        client_ip: &client_ip_str,
        prefix,
        tunnel_gateway: &server_ip,
        dns_ip: &dns_ip,
        dns_port: &dns_port,
        dns_servers: &dns_servers,
        routes_json: &routes_json,
        mtu: tun_mtu,
        fallback_dns_servers: &fallback_dns_servers,
    };
    let validated_tun_mtu = usize::try_from(tun_mtu)
        .map_err(|_| anyhow::anyhow!("authenticated TUN MTU is negative"))?;
    let recordizer = pushed_obf
        .as_ref()
        .and_then(|pushed| pushed.recordizer.as_ref())
        .map(|config| {
            crate::protocol::recordizer::RuntimeConfig::from_config(
                config,
                crate::protocol::packet::MAX_TUNNEL_MTU,
                validated_tun_mtu.saturating_add(64),
            )
        })
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid negotiated recordizer: {error}"))?;
    // Stream-bonding plan. `max_streams` is the server's hard ceiling.
    let target = if max_streams > 1 {
        max_streams as usize
    } else {
        1
    };
    // TCP_RESUME_V2 gives both peers the same stable logical-slot namespace. Keep that fixed
    // width for flow placement even while the live carrier set temporarily shrinks or grows.
    let stable_stream_width = tcp_resume
        .as_ref()
        .map(|_| u32::try_from(target).unwrap_or(u32::MAX).max(1));
    let token_bytes = hex_to_bytes(&session_token);
    let bonding = target > 1 && !token_bytes.is_empty();
    // Snapshot bonded packets into one fixed pool before queuing them. Queues must
    // release TUN buffers (and FIFO Wintun ring reservations) even when one writer
    // is blocked. One 4 MiB budget serves all streams; there is no fallback allocation.
    let bonded_uplink_pool = if bonding {
        let (buffer_count, slot_bytes) = bonded_uplink_pool_layout(recordizer.as_ref());
        Some(crate::transport_core::buffer_pool::BufferPool::new(
            buffer_count,
            slot_bytes,
        )?)
    } else {
        None
    };
    let uplink_queue_capacity = bonded_uplink_pool.as_ref().map_or(4096, |pool| {
        crate::transport_core::buffer_pool::bonded_queue_capacity(pool.buffer_count(), max_streams)
    });

    let mut plan = build_network_plan(config, core.next_generation(), &network)?;
    #[cfg(target_os = "linux")]
    {
        // Linux owns the socket and therefore knows the literal peer selected by DNS. Export
        // that authoritative value in the NetworkPlan used by hooks instead of forcing scripts
        // to resolve the configured hostname again (which can select another GSLB address).
        plan.carrier_address = CONNECTED_PEER
            .lock()
            .ok()
            .and_then(|peer| *peer)
            .map(|peer| peer.to_string());
    }
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_generation = plan.generation;
    plan.max_streams = max_streams;
    plan.adaptive = adaptive;
    plan.data_plane = crate::transport_core::NetworkDataPlaneFacts::from_obfuscation(&eff_obf);
    // Genuine HTTP/2/TCP provides its own liveness and the runtime intentionally suppresses
    // qeli's periodic heartbeat on Reality-TLS. Keep the exported NetworkPlan/hook fact equal
    // to what the data plane will actually do rather than merely echoing the pushed setting.
    if config.obfuscation.mode == "reality-tls" {
        plan.data_plane.heartbeat_enabled = false;
    }
    #[cfg(feature = "experimental-roaming")]
    let negotiated_roaming_mode = if tcp_handover_enabled {
        crate::transport_core::NetworkRoamingMode::TcpHandoverV2
    } else if tcp_resume.is_some() {
        crate::transport_core::NetworkRoamingMode::TcpResumeV2
    } else {
        crate::transport_core::NetworkRoamingMode::Reconnect
    };
    #[cfg(not(feature = "experimental-roaming"))]
    let negotiated_roaming_mode = crate::transport_core::NetworkRoamingMode::Reconnect;
    plan.data_plane.set_negotiated_modes(
        pushed_obf
            .as_ref()
            .and_then(|obfuscation| obfuscation.recordizer.as_ref()),
        negotiated_roaming_mode,
        config.roaming,
    );
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
    let negotiated_family_mode = plan.family_mode;
    #[cfg(target_os = "linux")]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        tap_gateway_facts(&plan.addresses);
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        (None, 0, None, 0);
    // Validate data-plane parameters before acquiring platform resources or invoking hooks.
    let tunnel = core.prepare_tunnel(config, plan).await?;
    run_pending_post_up(core).await;
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
    let tap_mac = tunnel.tap_mac;
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
    // HTTP/2/TCP already carries liveness. A fixed qeli heartbeat produced a highly
    // classifiable periodic beacon, so the maximum-stealth REALITY path omits it.
    let heartbeat_enabled =
        hb_config.enabled && hb_config.interval_ms > 0 && config.obfuscation.mode != "reality-tls";
    let padding_min = eff_obf.padding.min_bytes;
    let padding_max = eff_obf.padding.max_bytes;
    let padding_enabled = eff_obf.padding.enabled;
    let padding_randomize = eff_obf.padding.randomize;
    let padding_prob = eff_obf.padding.probability;
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let tun_buf_size = {
        let configured = config
            .performance
            .tun_buffer_size
            .saturating_add(if cfg!(target_os = "macos") { 4 } else { 0 });
        let actual = tun_read_buffer_size(
            config.performance.tun_buffer_size,
            tun_mtu,
            is_tap,
            cfg!(target_os = "macos"),
        );
        if actual > configured {
            log::warn!(
                "TUN read buffer expanded from {} to {} bytes for negotiated MTU {} ({})",
                configured,
                actual,
                tun_mtu,
                if is_tap {
                    "tap"
                } else if cfg!(target_os = "macos") {
                    "utun"
                } else {
                    "tun"
                }
            );
        }
        actual
    };
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;
    // Needed before the pump: the TUN writer thread owns the only place where an
    // `EAGAIN`/`ENOBUFS` drop is observable.
    let runtime_counters = core.counters();

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let pump_config = LinuxTunPumpConfig {
        buffer_size: tun_buf_size,
        downlink_record_bytes: downlink_record_budget(tun_mtu, padding_max, norm_sizes),
        write_drops: Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
        framing: if cfg!(target_os = "macos") {
            TunFraming::Utun
        } else if is_tap {
            TunFraming::Tap(TapHeaders {
                client_mac: tap_mac,
                gateway_mac,
                gateway_ipv4: tap_gateway_ipv4,
                ipv4_prefix_len: tap_ipv4_prefix_len,
                gateway_ipv6: tap_gateway_ipv6,
                ipv6_prefix_len: tap_ipv6_prefix_len,
            })
        } else {
            TunFraming::Raw
        },
    };
    #[cfg(target_os = "linux")]
    let (tun_guard, mut tun_pump) =
        start_linux_tun_pump(tunnel.guard, reader_fd, writer_fd, pump_config, None).await?;
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let mut tun_pump = LinuxTunPump::start(reader_fd, writer_fd, pump_config)?;
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
    stream.set_opportunistic_batching(recordizer.as_ref().is_some_and(|mux| mux.opportunistic));
    let (primary_r, primary_w) = stream.split_io();
    // Plain mode uses raw records directly. Current reality-tls uses the same
    // private raw framing inside genuine HTTP/2; legacy camouflage modes retain
    // their TLS-dressed inner records.
    let framing = if matches!(config.obfuscation.mode.as_str(), "plain" | "reality-tls") {
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
    // The caller creates this owner before connect, so H2 drivers/bridges already belong
    // to it. Stream tasks, producers and Linux path workers share the same teardown.
    let stream_tasks = connection_tasks.spawner();
    let outs: Arc<std::sync::Mutex<Vec<ClientStreamSender>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let active_slots = tcp_resume.as_ref().map(|_| {
        Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<
            u32,
            usize,
        >::new()))
    });
    let last_live_lost_at = tcp_resume
        .as_ref()
        .map(|_| Arc::new(std::sync::Mutex::new(None::<tokio::time::Instant>)));
    // Bytes encrypted+sent across all streams (uplink half of the adaptive probe).
    let total_tx = Arc::new(AtomicU64::new(0));
    // Bytes decrypted+delivered to TUN across all streams (downlink half). Without
    // this the adaptive ramp is blind to download-only load and never grows past
    // one stream.
    let total_rx = Arc::new(AtomicU64::new(0));
    // Count of streams still up. A stream's death tears the tunnel down only when
    // this reaches 0 (losing one bonded stream just degrades to the rest).
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let shaping = eff_obf.traffic_shaping.to_shaping();
    let cover_budget = crate::protocol::Shaper::shared_budget(&shaping, std::time::Instant::now());
    if recordizer.is_some() {
        log::info!("Packet recordizer: PACKET_MUX_V1 active on TCP");
        log::info!(
            "Recordizer batching: {} on TCP",
            if recordizer.as_ref().is_some_and(|mux| mux.opportunistic) {
                "opportunistic"
            } else {
                "timed"
            }
        );
    }

    let (management_tx, mut management_rx) = tokio::sync::watch::channel(None);
    let management_reassembler = Arc::new(std::sync::Mutex::new(
        crate::protocol::control_v2::Reassembler::new(),
    ));
    let pump = StreamPump {
        framing,
        family_mode: negotiated_family_mode,
        heartbeat_enabled,
        heartbeat_interval,
        idle_timeout,
        tun_mtu: validated_tun_mtu,
        hb_data: hb_config.data_size_bytes,
        hb_jitter: hb_config.jitter_ms,
        padding_enabled,
        padding_min,
        padding_max,
        padding_randomize,
        padding_prob,
        norm_enabled: eff_obf.traffic_normalization.enabled,
        norm_sizes: norm_sizes.clone(),
        shaping,
        recordizer,
        cover_budget,
        uplink_queue_capacity,
        // Only reality-tls pays a second (outer TLS AES-GCM) AEAD on the read
        // side; pipeline its two decrypt layers across cores. Other modes decrypt
        // inline (unchanged path).
        pipeline_rx: config.obfuscation.mode == "reality-tls",
        management_v1,
        management_reassembler,
        management_tx,
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
        0,
        active_slots.clone(),
        last_live_lost_at.clone(),
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

    // The adaptive ramp decides the desired width; a separate maintainer restores
    // that width after individual bonded streams die. Fixed mode wants the full
    // configured width from the start (including retrying initial JOIN failures).
    let desired_streams = Arc::new(std::sync::atomic::AtomicUsize::new(
        if bonding && !adaptive { target } else { 1 },
    ));
    let next_join_index = Arc::new(std::sync::atomic::AtomicUsize::new(target.max(1)));
    let join_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));

    if bonding && !adaptive {
        // FIXED: open the remaining streams now.
        for idx in 1..target {
            match connector(StreamConnectRequest::default()).await {
                Ok(mut s) => {
                    // Bound the JOIN handshake too (parity with the primary): a stalled
                    // JOIN would otherwise hang this bonded-stream task forever, holding a
                    // tun_write_tx clone. It only degrades bonding (the primary survives).
                    let join = match tokio::time::timeout(
                        Duration::from_secs(config.server.connection_timeout_secs.max(1)),
                        tcp_attach_handshake(
                            &mut s,
                            config,
                            &token_bytes,
                            idx as u32,
                            tcp_resume.as_deref(),
                            false,
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
                            s.set_opportunistic_batching(
                                pump.recordizer
                                    .as_ref()
                                    .is_some_and(|mux| mux.opportunistic),
                            );
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
                                idx as u32,
                                active_slots.clone(),
                                last_live_lost_at.clone(),
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
        let resume_r = tcp_resume.clone();
        let active_slots_r = active_slots.clone();
        let last_live_lost_at_r = last_live_lost_at.clone();
        stream_tasks.spawn(async move {
            let mut last_bytes = 0u64;
            let mut best_rate = 0u64;
            let mut grace = 0u32;
            let mut idx = 1u32;
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let cur = live_r.load(Ordering::Acquire);
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
                match conn_r(StreamConnectRequest::default()).await {
                    // Bound the adaptive JOIN handshake as well (see the fixed path); flatten
                    // the timeout Elapsed into an Err so the existing match arms stay put.
                    Ok(mut s) => match tokio::time::timeout(
                        Duration::from_secs(cfg_r.server.connection_timeout_secs.max(1)),
                        tcp_attach_handshake(
                            &mut s,
                            &cfg_r,
                            &token_r,
                            idx,
                            resume_r.as_deref(),
                            false,
                            identity_r.clone(),
                        ),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("JOIN handshake timed out")))
                    {
                        Ok((rx, tx)) => {
                            s.set_opportunistic_batching(
                                pump_r
                                    .recordizer
                                    .as_ref()
                                    .is_some_and(|mux| mux.opportunistic),
                            );
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
                                    idx,
                                    active_slots_r.clone(),
                                    last_live_lost_at_r.clone(),
                                    stream_tasks_r.clone(),
                                    pump_r.clone(),
                                ),
                            );
                            idx = idx.saturating_add(1);
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
        });
    }

    // Restore lost members of an established bond. Previously a dead secondary
    // merely reduced `live`; once the ramp task had ended nothing ever recreated
    // it, so a long-lived multipath session silently degraded to one stream.
    if bonding || tcp_resume.is_some() {
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
        let resume_m = tcp_resume.clone();
        let active_slots_m = active_slots.clone();
        let last_live_lost_at_m = last_live_lost_at.clone();
        #[cfg(feature = "experimental-roaming")]
        let path_controller_m = path_controller.clone();
        #[cfg(feature = "experimental-roaming")]
        let handover_enabled_m = tcp_handover_enabled;
        stream_tasks.spawn(async move {
            let mut tick = tokio::time::interval(TCP_RESUME_MAINTENANCE_TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let orphaned_at = last_live_lost_at_m.as_ref().and_then(|lost_at| {
                    *crate::util::lock_or_recover(lost_at, "client::last_live_lost_at")
                });
                #[cfg(feature = "experimental-roaming")]
                {
                    let candidate_prepared = path_controller_m
                        .as_ref()
                        .and_then(|controller| controller.prepared_candidate())
                        .is_some();
                    if should_defer_tcp_resume_for_handover(
                        handover_enabled_m,
                        candidate_prepared,
                        orphaned_at.map(|lost_at| lost_at.elapsed()),
                    ) {
                        continue;
                    }
                }
                if orphaned_at.is_some_and(|lost_at| lost_at.elapsed() >= TCP_RESUME_GRACE) {
                    log::warn!("TCP resume grace expired; falling back to full reconnect");
                    let _ = dead_m.try_send(());
                    break;
                }
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
                let logical_slot_id = if resume_m.is_some() {
                    let Some(active_slots) = active_slots_m.as_ref() else {
                        joining_m.store(false, Ordering::Release);
                        continue;
                    };
                    let active = crate::util::lock_or_recover(active_slots, "client::active_slots");
                    let missing = (0..u32::try_from(desired).unwrap_or(u32::MAX))
                        .find(|slot| !active.contains_key(slot));
                    drop(active);
                    let Some(missing) = missing else {
                        joining_m.store(false, Ordering::Release);
                        continue;
                    };
                    missing
                } else {
                    let raw_index = next_m.fetch_add(1, Ordering::AcqRel);
                    if raw_index > u8::MAX as usize {
                        // Legacy JOIN derives state from a u8 index. Never wrap and reuse it.
                        log::warn!("Multipath JOIN index exhausted — reconnecting tunnel");
                        let _ = dead_m.try_send(());
                        joining_m.store(false, Ordering::Release);
                        break;
                    }
                    raw_index as u32
                };

                let attempt = async {
                    let mut stream = conn_m(StreamConnectRequest::default()).await?;
                    let (rx, tx) = tokio::time::timeout(
                        Duration::from_secs(cfg_m.server.connection_timeout_secs.max(1)),
                        tcp_attach_handshake(
                            &mut stream,
                            &cfg_m,
                            &token_m,
                            logical_slot_id,
                            resume_m.as_deref(),
                            false,
                            identity_m.clone(),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("TCP attach handshake timed out"))??;
                    Ok::<_, anyhow::Error>((stream, rx, tx))
                };
                let joined = if let Some(lost_at) = orphaned_at {
                    let remaining = TCP_RESUME_GRACE.saturating_sub(lost_at.elapsed());
                    if remaining.is_zero() {
                        Err(anyhow::anyhow!("TCP resume grace expired"))
                    } else {
                        tokio::time::timeout(remaining, attempt)
                            .await
                            .map_err(|_| anyhow::anyhow!("TCP resume grace expired"))
                            .and_then(|result| result)
                    }
                } else {
                    attempt.await
                };

                match joined {
                    Ok((mut stream, rx, tx)) => {
                        stream.set_opportunistic_batching(
                            pump_m
                                .recordizer
                                .as_ref()
                                .is_some_and(|mux| mux.opportunistic),
                        );
                        let (reader, writer) = stream.split_io();
                        let replacement = spawn_stream(
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
                            logical_slot_id,
                            active_slots_m.clone(),
                            last_live_lost_at_m.clone(),
                            stream_tasks_m.clone(),
                            pump_m.clone(),
                        );
                        let mut outputs = crate::util::lock_or_recover(&outs_m, "client::outs_m");
                        // Drop an obsolete writer for the same stable slot before publishing
                        // the replacement. Other closed slots are cheap to purge here too.
                        outputs.retain(|entry| {
                            entry.logical_slot_id != logical_slot_id && !entry.is_closed()
                        });
                        outputs.push(replacement);
                        outputs.sort_unstable_by_key(|entry| entry.logical_slot_id);
                        log::info!(
                            "TCP stream slot {} resumed; {}/{} stream(s) active",
                            logical_slot_id,
                            live_m.load(Ordering::Acquire),
                            desired
                        );
                    }
                    Err(error) => {
                        log::warn!(
                            "TCP stream slot {} resume/attach attempt failed: {}",
                            logical_slot_id,
                            error
                        );
                    }
                }
                joining_m.store(false, Ordering::Release);
                if last_live_lost_at_m.as_ref().is_some_and(|lost_at| {
                    crate::util::lock_or_recover(lost_at, "client::last_live_lost_at")
                        .is_some_and(|at| at.elapsed() >= TCP_RESUME_GRACE)
                }) {
                    let _ = dead_m.try_send(());
                    break;
                }
            }
        });
    }

    #[cfg(feature = "experimental-roaming")]
    if let Some(path_controller) = path_controller {
        let handover_enabled = tcp_handover_enabled;
        let outs_h = outs.clone();
        let stream_tasks_h = stream_tasks.clone();
        let total_h = total_tx.clone();
        let total_rx_h = total_rx.clone();
        let tww_h = tun_write_tx.clone();
        let dead_h = dead_tx.clone();
        let pump_h = pump.clone();
        let conn_h = connector.clone();
        let cfg_h = std::sync::Arc::new(config.clone());
        let token_h = token_bytes.clone();
        let live_h = live.clone();
        let joining_h = join_in_flight.clone();
        let runtime_h = runtime_counters.clone();
        let identity_h = identity_verifier.clone();
        let resume_h = tcp_resume.clone();
        let active_slots_h = active_slots.clone();
        let last_live_lost_at_h = last_live_lost_at.clone();
        stream_tasks.spawn(async move {
            let mut tick = tokio::time::interval(TCP_HANDOVER_POLL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(candidate) = path_controller.prepared_candidate() else {
                    continue;
                };
                if !handover_enabled {
                    match path_controller
                        .abort_candidate_path(&candidate, "peer did not negotiate TCP_HANDOVER_V2")
                    {
                        Ok(rollback) => {
                            match tokio::time::timeout(PATH_ACK_TIMEOUT, rollback).await {
                                Ok(Ok(())) => log::info!(
                                    "rolled back candidate {} before full reconnect fallback",
                                    candidate.candidate_id
                                ),
                                Ok(Err(error)) => log::warn!(
                                    "candidate {} rollback failed before reconnect: {}",
                                    candidate.candidate_id,
                                    error
                                ),
                                Err(_) => log::warn!(
                                    "candidate {} rollback timed out before reconnect",
                                    candidate.candidate_id
                                ),
                            }
                        }
                        Err(error) => log::warn!(
                            "could not start candidate {} rollback: {}",
                            candidate.candidate_id,
                            error
                        ),
                    }
                    let _ = dead_h.try_send(());
                    break;
                }
                if joining_h
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }

                let mut commit_phase = TcpHandoverCommitPhase::Reversible;
                let attempt = async {
                    let resume = resume_h.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("handover requires negotiated TCP resume")
                    })?;
                    let mut stream =
                        conn_h(StreamConnectRequest::for_path(candidate.clone())).await?;
                    let pending = tokio::time::timeout(
                        Duration::from_secs(cfg_h.server.connection_timeout_secs.max(1)),
                        tcp_prepare_attach_handshake(
                            &mut stream,
                            &cfg_h,
                            &token_h,
                            0,
                            Some(resume),
                            true,
                            identity_h.clone(),
                        ),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("TCP handover JOIN timed out"))??;
                    let commit = path_controller.commit_candidate_path(&candidate)?;
                    // The candidate can be superseded between JOIN proof and this call. An
                    // immediate stale/error result means COMMIT_PATH never crossed the ABI and
                    // remains safely reversible; only an accepted command creates ambiguity.
                    commit_phase = TcpHandoverCommitPhase::CommitIssued;
                    match tokio::time::timeout(PATH_ACK_TIMEOUT, commit).await {
                        Ok(Ok(())) => {
                            commit_phase = TcpHandoverCommitPhase::PlatformCommitted;
                        }
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {
                            return Err(anyhow::anyhow!(
                                "COMMIT_PATH acknowledgement timed out"
                            ));
                        }
                    }
                    let (rx, tx) = tokio::time::timeout(
                        Duration::from_secs(cfg_h.server.connection_timeout_secs.max(1)),
                        finish_tcp_secondary_handshake(&mut stream, pending),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("TCP handover peer commit timed out"))??;
                    Ok::<_, anyhow::Error>((stream, rx, tx))
                }
                .await;

                match attempt {
                    Ok((mut stream, rx, tx)) => {
                        stream.set_opportunistic_batching(pump_h.recordizer.as_ref().is_some_and(|mux| mux.opportunistic));
                        let (reader, writer) = stream.split_io();
                        let replacement = spawn_stream(
                            reader,
                            writer,
                            rx,
                            tx,
                            tww_h.clone(),
                            dead_h.clone(),
                            total_h.clone(),
                            total_rx_h.clone(),
                            runtime_h.clone(),
                            live_h.clone(),
                            0,
                            active_slots_h.clone(),
                            last_live_lost_at_h.clone(),
                            stream_tasks_h.clone(),
                            pump_h.clone(),
                        );
                        let mut outputs = crate::util::lock_or_recover(&outs_h, "client::outs_h");
                        let retired = publish_tcp_path_handover(&mut outputs, replacement);
                        log::info!(
                            "TCP path handover retired {} previous carrier(s); stable slot 0 is live on the committed path",
                            retired
                        );
                        log::info!(
                            "TCP make-before-break committed candidate {} ({}) into stable slot 0",
                            candidate.candidate_id,
                            candidate.update.platform_path_id
                        );
                    }
                    Err(error) => {
                        let explicit_platform_rejection =
                            path_ack_is_explicit_rejection(&error);
                        if tcp_handover_failure_action(commit_phase, explicit_platform_rejection)
                            == TcpHandoverFailureAction::ReconnectGeneration
                        {
                            log::error!(
                                "TCP handover candidate {} failed after COMMIT_PATH was issued without a safe rollback outcome; terminating this generation for immediate reconnect: {}",
                                candidate.candidate_id,
                                error
                            );
                            let _ = dead_h.try_send(());
                            joining_h.store(false, Ordering::Release);
                            break;
                        }
                        // Before COMMIT_PATH issuance, or after an explicit platform rejection,
                        // the candidate is still reversible and the
                        // platform must remove every prepared route/filter/socket binding.
                        let reason = format!("TCP handover failed: {error}");
                        match path_controller.abort_candidate_path(&candidate, &reason) {
                            Ok(rollback) => {
                                match tokio::time::timeout(PATH_ACK_TIMEOUT, rollback).await {
                                    Ok(Ok(())) => log::debug!(
                                        "candidate {} rollback completed",
                                        candidate.candidate_id
                                    ),
                                    Ok(Err(abort_error)) => log::warn!(
                                        "candidate {} rollback failed: {}",
                                        candidate.candidate_id,
                                        abort_error
                                    ),
                                    Err(_) => log::warn!(
                                        "candidate {} rollback acknowledgement timed out",
                                        candidate.candidate_id
                                    ),
                                }
                            }
                            Err(abort_error) => log::debug!(
                                "candidate {} rollback was already resolved or superseded: {}",
                                candidate.candidate_id,
                                abort_error
                            ),
                        }
                        log::warn!(
                            "TCP make-before-break candidate {} ({}) failed: {}",
                            candidate.candidate_id,
                            candidate.update.platform_path_id,
                            error
                        );
                    }
                }
                joining_h.store(false, Ordering::Release);
            }
        });
    }

    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    if let Some(path_controller) = linux_path_controller {
        stream_tasks.spawn(roaming_linux::run(
            path_controller,
            tun_name.clone(),
            path_generation,
            stream_tasks.clone(),
        ));
    }

    #[cfg(target_os = "linux")]
    if config.routing.exit_node {
        spawn_exit_wan_monitor(tun_name.clone(), &stream_tasks);
    }

    // Distributor: FLOW-PIN TUN packets across the live bonded streams (by inner
    // 5-tuple) so each connection stays in order. Each stream's tasks own
    // encrypt/heartbeat/idle; a dead stream fires dead_rx.
    let mut unsupported_inner_drops = 0u64;
    let mut result = Ok(());
    loop {
        tokio::select! {
            biased;

            event = next_tcp_lifecycle_event(&mut management_rx, &mut dead_rx) => {
                match event {
                    TcpLifecycleEvent::Disconnected => break,
                    TcpLifecycleEvent::Management(Some(event)) => {
                        if let Err(error) = apply_server_management(core, event) {
                            result = Err(error);
                            break;
                        }
                    }
                    TcpLifecycleEvent::Management(None) => {}
                }
            }

            _ = cancel_tick.tick() => {
                if cancel.load(Ordering::Acquire) { break; }
            }

            packet = tun_pump.recv_from_tun() => {
                let Some(ip_packet) = packet else {
                    log::warn!("TCP: TUN reader stopped — reconnecting");
                    break;
                };
                if !is_supported_inner_packet(ip_packet.as_ref(), negotiated_family_mode) {
                    unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                    if unsupported_inner_drops.is_power_of_two() {
                        log::debug!(
                            "TCP client dropped invalid or non-negotiated-family inner packet (total {})",
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
                // and re-pinning onto a live one. Resume-capable sessions hash over the
                // negotiated stable slot namespace, so losing/restoring another carrier does
                // not reorder healthy flows. Legacy sessions retain modulo-live-width.
                let mut g = crate::util::lock_or_recover(&outs, "client::outs");
                let h = crate::protocol::flow_hash(ip_packet.as_ref());
                let pkt = if let Some(pool) = &bonded_uplink_pool {
                    let Some(packet) = prepare_bonded_uplink(ip_packet.as_ref(), pool, &runtime_counters.tcp_uplink) else {
                        continue;
                    };
                    drop(ip_packet);
                    ClientUplink::Bonded(packet)
                } else {
                    ClientUplink::Tun(ip_packet)
                };
                queue_tcp_uplink(&mut g, pkt, h, stable_stream_width, &runtime_counters.tcp_uplink);
            }

            else => break,
        }
    }

    // Only an intentional application shutdown is terminal. A carrier failure must retain the
    // server session so hard resume can reuse the existing NetworkPlan and TUN.
    #[cfg(feature = "experimental-roaming")]
    if cancel.load(Ordering::Acquire) && tcp_control_v2 {
        send_tcp_close_session(&outs).await;
    }

    // Seal admission before aborting producers and streams together. Await every task
    // (including Linux path workers) before restoring DNS or releasing the TUN.
    connection_tasks.finish().await;
    let result = finish_pending_management(core, &management_rx, result);
    let pump_shutdown = async move {
        drop(tun_write_tx);
        tun_pump.shutdown().await;
    };
    #[cfg(target_os = "linux")]
    let result =
        crate::client_cleanup::with_cleanup_error(result, tun_guard.shutdown(pump_shutdown).await);
    #[cfg(not(target_os = "linux"))]
    pump_shutdown.await;
    if result.is_ok() {
        log::info!("Client disconnected");
    }
    result
}

async fn tcp_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    password: &str,
    client_device_id: &[u8; crate::protocol::DEVICE_ID_LEN],
    platform_capabilities: u64,
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<TcpAuthentication> {
    let result = authenticate_tcp(
        stream,
        config,
        password,
        client_device_id,
        platform_capabilities,
        move |received| identity_verifier(received),
    )
    .await;
    result.map_err(|error| {
        if config.obfuscation.mode == "reality-tls" {
            anyhow::anyhow!(
                "REALITY authentication failed: {error}; verify the pinned server key, short_id, and that client/server clocks differ by no more than ±120 seconds"
            )
        } else {
            error
        }
    })
}

#[derive(Clone, Copy)]
enum TcpSecondaryAttach<'a> {
    Legacy {
        token: &'a [u8],
        stream_index: u8,
    },
    #[cfg(feature = "experimental-roaming")]
    Resume {
        context: &'a TcpResumeContext,
        resume_epoch: u64,
        logical_slot_id: u32,
        handover: bool,
    },
}

struct TcpSecondaryHandshake {
    rx: PacketCodec,
    tx: PacketCodec,
    framing: Framing,
    resume_pending: bool,
}

impl TcpSecondaryAttach<'_> {
    fn logical_slot_id(self) -> u32 {
        match self {
            Self::Legacy { stream_index, .. } => u32::from(stream_index),
            #[cfg(feature = "experimental-roaming")]
            Self::Resume {
                logical_slot_id, ..
            } => logical_slot_id,
        }
    }

    fn first_message(self, _transcript_hash: [u8; 32]) -> Vec<u8> {
        match self {
            Self::Legacy {
                token,
                stream_index,
            } => {
                let mut join =
                    Vec::with_capacity(crate::protocol::JOIN_MAGIC.len() + token.len() + 1);
                join.extend_from_slice(crate::protocol::JOIN_MAGIC.as_slice());
                join.extend_from_slice(token);
                join.push(stream_index);
                join
            }
            #[cfg(feature = "experimental-roaming")]
            Self::Resume {
                context,
                resume_epoch,
                logical_slot_id,
                handover,
            } => crate::protocol::roaming::TcpResumeJoin::new(
                crate::protocol::roaming::ResumeProofInput::new(
                    _transcript_hash,
                    context.session_locator,
                    resume_epoch,
                    logical_slot_id,
                    handover,
                ),
                context.resume_secret.as_ref(),
            )
            .encode()
            .to_vec(),
        }
    }
}

async fn tcp_prepare_attach_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    token: &[u8],
    logical_slot_id: u32,
    resume: Option<&TcpResumeContext>,
    handover: bool,
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<TcpSecondaryHandshake> {
    #[cfg(feature = "experimental-roaming")]
    if let Some(context) = resume {
        let resume_epoch = context.next_epoch()?;
        return tcp_secondary_handshake(
            stream,
            config,
            TcpSecondaryAttach::Resume {
                context,
                resume_epoch,
                logical_slot_id,
                handover,
            },
            identity_verifier,
        )
        .await;
    }
    #[cfg(not(feature = "experimental-roaming"))]
    let _ = (resume, handover);
    let stream_index = u8::try_from(logical_slot_id)
        .map_err(|_| anyhow::anyhow!("legacy TCP JOIN stream index exhausted"))?;
    tcp_secondary_handshake(
        stream,
        config,
        TcpSecondaryAttach::Legacy {
            token,
            stream_index,
        },
        identity_verifier,
    )
    .await
}

async fn tcp_attach_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    token: &[u8],
    logical_slot_id: u32,
    resume: Option<&TcpResumeContext>,
    handover: bool,
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<(PacketCodec, PacketCodec)> {
    let pending = tcp_prepare_attach_handshake(
        stream,
        config,
        token,
        logical_slot_id,
        resume,
        handover,
        identity_verifier,
    )
    .await?;
    finish_tcp_secondary_handshake(stream, pending).await
}

async fn finish_tcp_secondary_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    mut pending: TcpSecondaryHandshake,
) -> anyhow::Result<(PacketCodec, PacketCodec)> {
    if !pending.resume_pending {
        return Ok((pending.rx, pending.tx));
    }
    let commit = pending
        .tx
        .encrypt_packet(crate::protocol::roaming::TCP_RESUME_COMMIT, &[])?;
    stream.write_all_flush(&commit).await?;
    let ack_record = read_record(stream, pending.framing)
        .await
        .map_err(|error| anyhow::anyhow!("TCP resume commit acknowledgement: {error}"))?;
    let ack = pending.rx.decrypt_packet(&ack_record)?;
    if ack != crate::protocol::roaming::TCP_RESUME_COMMIT_ACK {
        anyhow::bail!("TCP resume commit rejected by server");
    }
    Ok((pending.rx, pending.tx))
}

/// Inner qeli handshake for a SECONDARY bonded connection (stream bonding): the
/// same key exchange and server-identity verification as the primary, but with
/// an authenticated resume proof (or the legacy JOIN token when not negotiated)
/// instead of credentials. Returns fresh, per-carrier data-plane codecs.
async fn tcp_secondary_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    attach: TcpSecondaryAttach<'_>,
    identity_verifier: IdentityVerifier,
) -> anyhow::Result<TcpSecondaryHandshake> {
    let client_kp = Keypair::generate();
    #[cfg(feature = "experimental-roaming")]
    let resume_pending = matches!(attach, TcpSecondaryAttach::Resume { .. });
    #[cfg(not(feature = "experimental-roaming"))]
    let resume_pending = false;

    // Plain uses raw framing directly; current reality-tls uses it privately
    // inside genuine HTTP/2. Both perform the raw X25519 exchange, then present
    // the JOIN token instead of credentials, mirroring the corresponding primary
    // handshake branch.
    if matches!(config.obfuscation.mode.as_str(), "plain" | "reality-tls") {
        stream
            .write_all_flush(client_kp.public().as_bytes())
            .await?;
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
        let join = attach.first_message(transcript_hash);
        let join_packet = client_tx.encrypt_packet(&join, &[])?;
        stream.write_all_flush(&join_packet).await?;
        let ack_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|e| anyhow::anyhow!("JOIN(plain): ack: {}", e))?;
        let ack = client_rx.decrypt_packet(&ack_record)?;
        if ack != crate::protocol::roaming::TCP_RESUME_PREPARED_ACK {
            return Err(anyhow::anyhow!("JOIN(plain) rejected by server"));
        }
        log::info!(
            "TCP stream slot {} attached (plain)",
            attach.logical_slot_id()
        );
        return Ok(TcpSecondaryHandshake {
            rx: client_rx,
            tx: client_tx,
            framing: Framing::Raw,
            resume_pending,
        });
    }

    let server_name = config.effective_fake_tls_sni();
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
    stream.write_all_flush(&client_hello).await?;
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

    // Present an authenticated resume proof, or the legacy token for an old session.
    let join = attach.first_message(transcript_hash);
    let join_packet = client_tx.encrypt_packet(&join, &[])?;
    stream.write_all_flush(&join_packet).await?;

    let ack_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("JOIN: ack: {}", e))?;
    let ack = client_rx.decrypt_packet(&ack_record)?;
    if ack != crate::protocol::roaming::TCP_RESUME_PREPARED_ACK {
        return Err(anyhow::anyhow!("JOIN rejected by server"));
    }
    log::info!("TCP stream slot {} attached", attach.logical_slot_id());
    Ok(TcpSecondaryHandshake {
        rx: client_rx,
        tx: client_tx,
        framing: Framing::Tls,
        resume_pending,
    })
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
    guard: TunGuard,
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    reader_fd: OwnedFd,
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    writer_fd: OwnedFd,
    #[cfg(target_os = "linux")]
    if_name: String,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    is_tap: bool,
    #[cfg(target_os = "linux")]
    tap_mac: [u8; 6],
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

/// Start packet workers with the platform guard on an owning network worker. A
/// partial pump failure joins its threads before guard rollback. Keep ordinary pump
/// errors distinct from worker/context/panic failures that make cleanup uncertain.
/// UDP supplies its runtime for raw input; TCP retains its established reader worker.
#[cfg(target_os = "linux")]
async fn start_linux_tun_pump(
    mut guard: TunGuard,
    reader_fd: OwnedFd,
    writer_fd: OwnedFd,
    config: LinuxTunPumpConfig,
    runtime: Option<tokio::runtime::Handle>,
) -> anyhow::Result<(TunGuard, LinuxTunPump)> {
    let failures = guard.failures.clone();
    let started = network_task::run(Arc::new(AtomicBool::new(false)), move || {
        let created = match runtime {
            Some(runtime) => LinuxTunPump::start_pollable(reader_fd, writer_fd, config, runtime),
            None => LinuxTunPump::start(reader_fd, writer_fd, config),
        };
        let pump = match created {
            Ok(pump) => pump,
            Err(error) => {
                let message = format!("TUN packet pump startup failed: {error}");
                return Ok(Err(anyhow::Error::new(error).context(message)));
            }
        };
        guard.attach_pump(pump.stop_handle());
        // A rejected result must drop/join the pump before releasing the original TUN.
        // Tuple fields drop in order; successful adoption unpacks them without an await.
        Ok(Ok((pump, guard)))
    })
    .await;
    let (pump, guard) =
        failures.observe(crate::client_cleanup::Resource::Transaction, started)??;
    Ok((guard, pump))
}

/// Fallback platform cleanup when a joined graceful teardown cannot be reached.
/// Normal data-plane exits await shutdown; pump-start failure drops this guard on
/// the startup worker. Unwinding or abandoning earlier futures may still use Drop
/// on the caller. The pump owns duplicate descriptors, not DNS/routes/forwarding.
///
/// The guard requests pump stop before restoring network resources and keeps the
/// original TUN descriptor alive throughout cleanup. TunnelSetup owns it before
/// core ACK, the startup worker then transfers it with the pump, and successful
/// graceful cleanup disarms it. Failures remain sticky even after a later retry.
#[cfg(target_os = "linux")]
struct TunGuard {
    // A field stays alive throughout Drop, including retries after failed graceful cleanup.
    // Closing this owned File releases only this queue; never reopen a name for deletion.
    _tun: std::sync::Arc<TunInterface>,
    dns: Option<dns::DnsLease>,
    failures: crate::client_cleanup::Failures,
    if_name: String,
    stop: Option<LinuxTunPumpStop>,
    /// Attach mode borrows an externally-owned device: pump packets, never tear down.
    owns_device: bool,
    routes: route::RouteOwner,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl TunGuard {
    fn new(
        tun: std::sync::Arc<TunInterface>,
        dns: Option<dns::DnsLease>,
        if_name: String,
        owns_device: bool,
        routes: route::RouteOwner,
        failures: crate::client_cleanup::Failures,
    ) -> Self {
        Self {
            _tun: tun,
            dns,
            failures,
            if_name,
            stop: None,
            owns_device,
            routes,
            armed: true,
        }
    }

    async fn shutdown(
        self,
        pump_shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        let failures = self.failures.clone();
        let until = failures.cleanup_deadline();
        let result = network_task::teardown(
            self,
            move |guard| {
                let budget = crate::operation_budget::Scope::enter(until);
                (budget, guard.restore_dns())
            },
            pump_shutdown,
            |guard, (_budget, dns_cleanup)| {
                let dns_cleanup =
                    dns_cleanup.map_err(|error| anyhow::anyhow!("DNS cleanup failed: {error}"));
                let routes_cleanup = if guard.owns_device {
                    cleanup_owned_routes(&guard.routes, &guard._tun, &guard.failures)
                } else {
                    Ok(())
                };
                let cleanup =
                    crate::client_cleanup::with_cleanup_error(dns_cleanup, routes_cleanup);
                let cleanup =
                    crate::client_cleanup::with_cleanup_error(cleanup, guard.restore_router());
                if cleanup.is_ok() {
                    guard.disarm();
                }
                cleanup
            },
        )
        .await;
        // Thread creation/context errors and panics are cleanup failures too. Keeping
        // them sticky prevents reconnect or release of the kill-switch after uncertainty.
        failures.observe(crate::client_cleanup::Resource::Transaction, result)?
    }

    fn restore_dns(&mut self) -> anyhow::Result<()> {
        let result = self
            .dns
            .as_mut()
            .map_or(Ok(()), |lease| lease.restore(&self._tun));
        self.failures
            .observe(crate::client_cleanup::Resource::Dns, result)
    }

    fn restore_router(&self) -> anyhow::Result<()> {
        self.failures.observe(
            crate::client_cleanup::Resource::Forwarding,
            gateway::disengage_owned(&self.routes),
        )
    }

    fn attach_pump(&mut self, stop: LinuxTunPumpStop) {
        self.stop = Some(stop);
    }

    /// Called once the graceful teardown has run, so `Drop` does not repeat it.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

/// Remove owned routes while TunGuard retains the original queue descriptor. Physical
/// bypass routes require explicit cleanup even though the kernel retires TUN routes when
/// the last descriptor closes. Cleanup errors remain sticky and retryable.
#[cfg(target_os = "linux")]
fn cleanup_owned_routes(
    routes: &route::RouteOwner,
    tun: &TunInterface,
    failures: &crate::client_cleanup::Failures,
) -> anyhow::Result<()> {
    failures.observe(
        crate::client_cleanup::Resource::Routes,
        route::cleanup_routes_for_tun(routes, tun),
    )
}

#[cfg(target_os = "linux")]
impl Drop for TunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _budget = crate::operation_budget::Scope::enter(self.failures.cleanup_deadline());
        log::warn!(
            "connection ended on an error path — releasing TUN {}",
            self.if_name
        );
        // Ask both workers to stop before releasing our descriptor. Worker descriptors are not
        // closed here directly: their OwnedFd values live in the workers and closing a
        // raw number concurrently with read/write could target a subsequently reused fd.
        if let Some(stop) = &self.stop {
            stop.request_stop();
        }
        if let Err(error) = self.restore_dns() {
            log::error!("TUN guard DNS cleanup failed: {error}");
        }
        if let Err(error) = self.restore_router() {
            log::error!("TUN guard router cleanup failed: {error}");
        }
        if self.owns_device {
            if let Err(error) = cleanup_owned_routes(&self.routes, &self._tun, &self.failures) {
                log::error!("TUN guard cleanup failed: {error}");
            }
        }
    }
}

/// Set the family-matched `IP*_MTU_DISCOVER` option. `PROBE` sets DF and ignores the
/// kernel's cached PMTU (so we can probe freely); `DO` keeps DF for the data plane;
/// `DONT` allows fragmentation (the behaviour we restore if probing can't complete).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_pmtudisc(socket: &crate::protocol::obfs::ObfsUdp, mode: libc::c_int) -> bool {
    // Linux uapi: IPV6_MTU_DISCOVER has the same modes as IP_MTU_DISCOVER. libc does not
    // expose the IPv6 constant on every Android architecture supported by qeli, so keep the
    // stable uapi value local instead of making those targets fail to compile.
    const IPV6_MTU_DISCOVER: libc::c_int = 23;
    let (level, option) = if socket.peer_is_ipv6() {
        (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    let v: libc::c_int = mode;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_pmtudisc(socket, crate::protocol::data_frag::ACTIVE_PMTUDISC_MODE)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_pmtudisc(
        socket,
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
fn set_dont_fragment(socket: &crate::protocol::obfs::ObfsUdp, enabled: bool) -> bool {
    const IP_DONTFRAG: libc::c_int = 28;
    const IPV6_DONTFRAG: libc::c_int = 62;
    let (level, option) = if socket.peer_is_ipv6() {
        (libc::IPPROTO_IPV6, IPV6_DONTFRAG)
    } else {
        (libc::IPPROTO_IP, IP_DONTFRAG)
    };
    let value: libc::c_int = i32::from(enabled);
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_dont_fragment(socket, true)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_dont_fragment(socket, success);
}

/// Winsock uses option 14 for both `IP_DONTFRAGMENT` and `IPV6_DONTFRAG`; the protocol level
/// must still match the connected peer family. Keeping this tiny declaration local avoids
/// adding a Windows-only dependency to router/server builds.
#[cfg(target_os = "windows")]
fn set_dont_fragment(socket: &crate::protocol::obfs::ObfsUdp, enabled: bool) -> bool {
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
    const IPPROTO_IPV6: i32 = 41;
    const DONT_FRAGMENT: i32 = 14;
    let level = if socket.peer_is_ipv6() {
        IPPROTO_IPV6
    } else {
        IPPROTO_IP
    };
    let value: i32 = i32::from(enabled);
    unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            DONT_FRAGMENT,
            &value as *const i32 as *const i8,
            std::mem::size_of::<i32>() as i32,
        ) == 0
    }
}

#[cfg(target_os = "windows")]
fn begin_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp) -> bool {
    set_dont_fragment(socket, true)
}

#[cfg(target_os = "windows")]
fn finish_mtu_probe(socket: &crate::protocol::obfs::ObfsUdp, success: bool) {
    let _ = set_dont_fragment(socket, success);
}

/// Active path-MTU discovery on a UDP transport. Sends DF-marked probe datagrams from
/// `ceiling` down a small ladder; each rung is expressed in inner-packet units but the actual
/// datagram includes every active outer wrapper. Returns the largest certified rung. The
/// caller converts it into a complete outer UDP-payload budget; only a legacy peer without
/// DATA_FRAG also uses it to lower an IPv4 TUN MTU. `None` keeps the pushed/effective inner
/// MTU and selects the conservative DATA_FRAG budget (or legacy IP-fragmentation fallback).
// The probe owns the session's codecs, framing counter, and management-control state while it
// is the sole UDP receiver during startup. Keeping those dependencies explicit prevents hidden
// shared state and is safer than wrapping the mutable references solely to satisfy this lint.
#[allow(clippy::too_many_arguments)]
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
async fn probe_udp_mtu(
    socket: &crate::protocol::obfs::ObfsUdp,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    quic_pn: &mut u32,
    client_rx: &mut PacketCodec,
    client_tx: &mut PacketCodec,
    management_v1: bool,
    management_reassembler: &std::sync::Mutex<crate::protocol::control_v2::Reassembler>,
    management_sender: &tokio::sync::watch::Sender<
        Option<crate::protocol::control_v2::ManagementEvent>,
    >,
    ceiling: i32,
    keep_df_after_success: bool,
) -> anyhow::Result<Option<i32>> {
    use crate::protocol::udp_frag::{mtu_probe_v2_datagram, parse_mtu_probe_v2_ack};
    use std::time::Duration;
    if !begin_mtu_probe(socket) {
        return Ok(None);
    }
    // How many bytes of the PATH a probe for tunnel-MTU `m` occupies beyond `m` itself:
    // our record overhead, the obfs seal, the QUIC short header, and the UDP + IP headers.
    //
    // This is the difference the ladder used to ignore. `m` is an INNER-shaped value, but
    // the rungs were the IPv6 minimum PATH MTU — so the lowest rung, 1280, actually asked
    // the path for ~1280 + overhead bytes. On a real 1280-byte path every rung therefore
    // failed. Before DATA_FRAG that forced the caller back to the oversized pushed MTU with
    // IP fragmentation; now it would unnecessarily retain the conservative fragment budget.
    // Derive the floor from the overhead actually in play instead of hard-coding a number
    // that silently means something else. (Audit 2026-07-29, #12.)
    let outer_overhead = UDP_RECORD_PROBE_OVERHEAD
        + socket.seal_overhead()
        + framing.wrapper_len()
        + 8 // UDP header
        + if socket.peer_is_ipv6() { 40 } else { 20 };
    let ladder = mtu_probe_ladder(ceiling, outer_overhead, socket.peer_is_ipv6());

    let mut buf = vec![0u8; 2048];
    let mut terminal_wire_record = Vec::new();
    let mut terminal_carrier_record = Vec::new();
    // Every challenge gets an independent 128-bit token. A random start followed by a
    // predictable increment would let one observed response predict later rungs.

    // One rung: send up to twice, accept only an ACK echoing this token AND this size.
    //
    // Requiring the echoed SIZE as well as the id is what stops a stale or forged ACK for a
    // different rung from pinning the client to an MTU the path cannot carry.
    macro_rules! try_mtu {
        ($m:expr) => {{
            let m: i32 = $m;
            let probe_token: u128 = rand::rng().random();
            let probe_size = (m as usize + UDP_RECORD_PROBE_OVERHEAD) as u16;
            match mtu_probe_v2_datagram(probe_token, m as usize + UDP_RECORD_PROBE_OVERHEAD) {
                None => false,
                Some(probe) => {
                    let mut wrapped = Vec::new();
                    let pkt = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                        framing,
                        &probe,
                        quic_pn,
                        &mut wrapped,
                    );
                    let mut ok = false;
                    for _ in 0..2u8 {
                        // EMSGSIZE = the local link is smaller than this probe → size fails.
                        if socket.send(&pkt).await.is_err() {
                            break;
                        }
                        // Cover, heartbeat, a delayed ACK for an older rung, or any other
                        // service datagram may already be queued on this socket. Keep reading
                        // inside ONE fixed deadline instead of spending the whole attempt on
                        // whichever datagram happened to arrive first.
                        let deadline = tokio::time::Instant::now() + Duration::from_millis(220);
                        loop {
                            match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
                                Ok(Ok(n)) if n > 0 => {
                                    let payload = framing.unwrap(&buf[..n]).unwrap_or_default();
                                    if parse_mtu_probe_v2_ack(payload)
                                        == Some((probe_token, probe_size))
                                    {
                                        ok = true;
                                        break;
                                    }
                                    // KICK is terminal even while startup PMTU owns the UDP
                                    // receive socket. Previously this loop discarded every
                                    // authenticated non-PMTU datagram, so the server could close
                                    // the session while the client missed the reason and retried.
                                    if crate::protocol::udp_frag::is_fragment(payload) {
                                        continue;
                                    }
                                    let mut management_record = payload.to_vec();
                                    if client_rx
                                        .decrypt_packet_in_place(&mut management_record)
                                        .is_err()
                                    {
                                        continue;
                                    }
                                    let management = consume_authenticated_management(
                                        &management_record,
                                        management_v1,
                                        management_reassembler,
                                        management_sender,
                                        None,
                                    );
                                    if let Some(message_id) = management.ack_message_id {
                                        let _ = send_client_udp_terminal_control(
                                            &crate::protocol::control_v2::ack(message_id),
                                            client_tx,
                                            socket,
                                            framing,
                                            quic_pn,
                                            &mut terminal_wire_record,
                                            &mut terminal_carrier_record,
                                        )
                                        .await;
                                    }
                                    if management.consumed {
                                        if let Some(
                                            crate::protocol::control_v2::ManagementEvent::Kick(
                                                kick,
                                            ),
                                        ) = management_sender.borrow().clone()
                                        {
                                            finish_mtu_probe(socket, false);
                                            return Err(ServerKickError {
                                                message: kick.message,
                                                reconnect_allowed: kick.reconnect_allowed,
                                            }
                                            .into());
                                        }
                                    }
                                }
                                Ok(Ok(_)) => continue,
                                _ => break,
                            }
                        }
                        if ok {
                            break;
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
    // so a refinement that finds nothing better still returns the coarse result. Stop at a
    // one-byte bracket; the fixed probe cap bounds work even for jumbo paths (#69).
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

    // Keep two independent confirmations after the search converges. The V2 128-bit token makes
    // blind source-spoofed ACKs infeasible; repeated confirmation additionally protects the
    // widening decision from stale/reordered carrier frames. If confirmation is lost or blocked,
    // fail closed to the conservative DATA_FRAG budget (or legacy IP-fragmentation fallback).
    if let Some(candidate) = found {
        if !try_mtu!(candidate) || !try_mtu!(candidate) {
            log::warn!(
                "path-MTU probe: final candidate {candidate} did not pass independent confirmation"
            );
            found = None;
        }
    }
    // DATA_FRAG_V1 keeps every outer datagram inside the certified budget, so retaining DF
    // prevents accidental IP fragmentation. A legacy peer cannot split an encrypted record:
    // restore fragmentation even after a successful probe or an IPv6-minimum inner packet
    // (1280 bytes plus framing) can still exceed the outer path and fail with EMSGSIZE.
    finish_mtu_probe(socket, found.is_some() && keep_df_after_success);
    Ok(found)
}

/// Select the inner MTU after a successful UDP path probe.
///
/// With DATA_FRAG_V1 the inner interface and the outer datagram budget are independent. For a
/// legacy peer an automatic IPv4 TUN can use the certified record size to avoid oversized
/// sends. An explicit inner MTU always wins; legacy sockets retain IP fragmentation. IPv6
/// interfaces may not advertise less than 1280, so automatic dual/IPv6 sessions keep that floor.
fn udp_inner_mtu_after_probe(
    base_mtu: i32,
    probed_mtu: i32,
    data_frag_enabled: bool,
    family_mode: crate::transport_core::NetworkFamilyMode,
    explicit_inner_mtu: bool,
) -> i32 {
    if explicit_inner_mtu || data_frag_enabled {
        return base_mtu;
    }
    match family_mode {
        crate::transport_core::NetworkFamilyMode::Ipv4 => probed_mtu.min(base_mtu),
        crate::transport_core::NetworkFamilyMode::Ipv6
        | crate::transport_core::NetworkFamilyMode::Dual => probed_mtu.max(1280).min(base_mtu),
    }
}

/// Certify the largest working byte instead of leaving a 256-byte gap (#69).
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) const MTU_REFINE_STEP: i32 = 1;

/// Hard cap on refinement probes, so a pathological bracket cannot stretch the handshake.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
pub(crate) const MTU_REFINE_MAX_PROBES: u8 = 16;

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
/// overhead, the obfs seal, the QUIC header and the UDP + IP headers. IPv6 keeps its mandated
/// 1280-byte path floor. IPv4 has no equivalent 1280 requirement, so its ladder descends to
/// Qeli's supported inner minimum (576); otherwise a valid 900/1000/1200-byte IPv4 path
/// certifies nothing. A legacy peer then falls back to IP fragmentation, while DATA_FRAG stays
/// unnecessarily pinned to its conservative floor instead of using the wider working budget.
#[cfg(any(
    test,
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
fn mtu_probe_ladder(ceiling: i32, outer_overhead: usize, peer_is_ipv6: bool) -> Vec<i32> {
    let floor = if peer_is_ipv6 {
        (1280 - outer_overhead as i32).max(crate::config::server::MTU_MIN as i32)
    } else {
        crate::config::server::MTU_MIN as i32
    }
    .clamp(crate::config::server::MTU_MIN as i32, ceiling);
    crate::protocol::udp_frag::mtu_probe_ladder(ceiling, floor)
}

#[cfg(test)]
mod mtu_ladder_tests {
    use super::{mtu_probe_ladder, udp_inner_mtu_after_probe};
    use crate::transport_core::NetworkFamilyMode;

    /// The narrowest rung must be reachable over a 1280-byte path once the probe's own
    /// framing is counted; otherwise a valid IPv6-minimum path certifies no wider DATA_FRAG
    /// budget (and a legacy peer falls back to outer IP fragmentation).
    #[test]
    fn the_lowest_rung_fits_the_ipv6_minimum_path() {
        // Worst case in this codebase: obfs seal (13) + QUIC short header (9) + UDP (8)
        // + IPv6 (40) + record overhead (48).
        for overhead in [48 + 8 + 20, 48 + 13 + 9 + 8 + 40] {
            let ladder = mtu_probe_ladder(1400, overhead, true);
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
    fn ipv4_ladder_can_certify_a_path_below_1280() {
        let overhead = 48 + 8 + 20;
        let ladder = mtu_probe_ladder(1400, overhead, false);
        assert_eq!(ladder.last().copied(), Some(576));
        assert!(
            ladder.iter().any(|&m| m + overhead as i32 <= 1000),
            "an IPv4 path below 1280 must have a certifiable rung: {ladder:?}"
        );
    }

    #[test]
    fn live_ipv4_reprobe_does_not_collapse_from_1200_to_the_floor() {
        // Roaming CID (13) + UDP/IP (28) + the probe record allowance (48). On a 1280-byte
        // carrier, candidate 1200 is nine bytes too large, while 1100 is the first rung that
        // fits. Without the intermediate IPv4 rungs the live state machine fell straight to
        // 576 and needlessly pinned both directions to a 637-byte UDP payload budget.
        let overhead = 13 + 8 + 20 + 48;
        let ladder = mtu_probe_ladder(1400, overhead, false);
        let highest_fitting = ladder
            .iter()
            .copied()
            .find(|candidate| candidate + overhead as i32 <= 1280)
            .expect("the IPv4 floor fits");
        assert_eq!(highest_fitting, 1100);
        assert!(ladder.windows(2).all(|pair| pair[0] > pair[1]));
    }

    #[test]
    fn a_low_ceiling_collapses_to_a_single_rung_and_never_inverts() {
        // A server that pushes a small MTU must not produce an empty or inverted ladder.
        let ladder = mtu_probe_ladder(1000, 48 + 13 + 9 + 8 + 40, true);
        assert!(!ladder.is_empty());
        assert!(ladder.iter().all(|&m| m <= 1000));
    }

    /// A jumbo ceiling must not fall straight to 1360.
    ///
    /// The ladder was written when the ceiling was an Ethernet-sized number, so the rung below
    /// it was 1360 and the gap was 140 bytes. Raising to the record-format ceiling made that
    /// gap enormous: a path carrying 9000 — an ordinary jumbo LAN, and precisely the setup
    /// where someone configures a large MTU — could fail the ceiling probe and be certified
    /// at only 1360.
    /// (Audit 2026-08-01, §8.)
    #[test]
    fn a_jumbo_ceiling_has_rungs_between_it_and_1360() {
        let overhead = 48 + 13 + 9 + 8 + 40;
        let ceiling = crate::protocol::packet::MAX_TUNNEL_MTU as i32;
        let ladder = mtu_probe_ladder(ceiling, overhead, true);
        let jumbo: Vec<i32> = ladder
            .iter()
            .copied()
            .filter(|&m| (1360..ceiling).contains(&m))
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

        // Even the old sub-256-byte blind spot is refined to the largest working byte.
        assert_eq!(
            mtu_refine_step(6000, 6200),
            Some(6100),
            "a narrow bracket still needs refinement"
        );
        let (got, probes) = search(6000, 9000, 6001);
        assert_eq!(got, 6001, "the last working byte is retained");
        assert!(probes <= MTU_REFINE_MAX_PROBES);
    }

    /// ...and a normal 1500-class path must be probed exactly as before, so the jumbo rungs
    /// cost no extra round-trips for the common case.
    #[test]
    fn a_normal_ceiling_gains_no_extra_rungs() {
        let overhead = 48 + 13 + 9 + 8 + 40;
        assert_eq!(
            mtu_probe_ladder(1400, overhead, true),
            vec![1400, 1360, 1320, 1280, 1200, 1280 - overhead as i32]
        );
    }

    #[test]
    fn negotiated_record_fragmentation_keeps_inner_and_outer_mtu_independent() {
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, true, NetworkFamilyMode::Dual, false),
            1400
        );
    }

    #[test]
    fn legacy_udp_peer_uses_probe_without_breaking_ipv6_minimum_mtu() {
        assert_eq!(
            udp_inner_mtu_after_probe(1365, 1403, false, NetworkFamilyMode::Ipv4, false),
            1365,
            "a wider outer path must never raise the server-pushed inner MTU"
        );
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, false, NetworkFamilyMode::Ipv4, false),
            1160
        );
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, false, NetworkFamilyMode::Ipv6, false),
            1280
        );
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1320, false, NetworkFamilyMode::Dual, false),
            1320
        );
    }

    #[test]
    fn explicit_inner_mtu_is_preserved_after_a_smaller_probe() {
        for family in [
            NetworkFamilyMode::Ipv4,
            NetworkFamilyMode::Ipv6,
            NetworkFamilyMode::Dual,
        ] {
            for data_frag in [false, true] {
                for (configured, probed) in [(1400, 1160), (9000, 1400), (1280, 576)] {
                    assert_eq!(
                        udp_inner_mtu_after_probe(configured, probed, data_frag, family, true),
                        configured,
                        "an explicit inner MTU must not become the probed outer-path size"
                    );
                }
            }
        }
    }

    #[test]
    fn live_probe_requires_three_independent_exact_echoes() {
        use super::{LiveUdpMtuProbe, UDP_RECORD_PROBE_OVERHEAD};

        let mut probe = LiveUdpMtuProbe::default();
        probe.start([1400]);
        for confirmation in 0..3 {
            let (id, candidate) = probe
                .next_send(tokio::time::Instant::now())
                .expect("fresh challenge must send immediately");
            assert_eq!(candidate, 1400);
            let size = (candidate as usize + UDP_RECORD_PROBE_OVERHEAD) as u16;
            assert_eq!(
                probe.acknowledge(id.wrapping_add(1), size),
                None,
                "wrong token must not advance confirmation"
            );
            let result = probe.acknowledge(id, size);
            if confirmation < 2 {
                assert_eq!(result, None);
                assert!(probe.is_active());
            } else {
                assert_eq!(result, Some(1400));
                assert!(!probe.is_active());
            }
        }
    }

    #[test]
    fn live_probe_descends_after_two_unanswered_sends() {
        use super::{LiveUdpMtuProbe, UDP_MTU_REPROBE_REPLY_TIMEOUT, UDP_MTU_REPROBE_SENDS};

        let mut probe = LiveUdpMtuProbe::default();
        probe.start([1500, 1400]);
        let start = tokio::time::Instant::now();
        for send in 0..UDP_MTU_REPROBE_SENDS {
            let (_, candidate) = probe
                .next_send(start + UDP_MTU_REPROBE_REPLY_TIMEOUT * u32::from(send))
                .expect("retry must be emitted");
            assert_eq!(candidate, 1500);
        }
        let (_, next_candidate) = probe
            .next_send(start + UDP_MTU_REPROBE_REPLY_TIMEOUT * u32::from(UDP_MTU_REPROBE_SENDS))
            .expect("lower rung must start after timeout");
        assert_eq!(next_candidate, 1400);
    }

    #[test]
    fn probe_budget_accounts_for_all_udp_payload_wrappers() {
        use super::udp_payload_budget_for_probe;

        assert_eq!(udp_payload_budget_for_probe(1400, 13, 0), 1461);
        assert_eq!(
            udp_payload_budget_for_probe(1400, 13, crate::protocol::quic::QUIC_SHORT_HEADER_MIN),
            1461 + crate::protocol::quic::QUIC_SHORT_HEADER_MIN
        );
    }

    #[tokio::test]
    async fn pppoe_probe_uses_exact_outer_budget_with_small_inner_mtu() {
        use crate::protocol::obfs::ObfsUdp;
        use crate::protocol::udp_frag::{mtu_probe_v2_ack_datagram, parse_mtu_probe_v2_request};
        use crate::transport_core::udp_client_framing::UdpClientFraming;
        let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        a.connect(b.local_addr().unwrap()).await.unwrap();
        b.connect(a.local_addr().unwrap()).await.unwrap();
        let key = Some(crate::protocol::obfs::derive_obfs_key(
            "issue69-pmtu-fixture",
        ));
        let client = ObfsUdp::new(a, key);
        let peer = ObfsUdp::new(b, key);
        let responder = tokio::spawn(async move {
            let mut bytes = [0u8; 2048];
            loop {
                let n = peer.recv(&mut bytes).await.unwrap();
                if n + 13 + 28 <= 1492 {
                    if let Some((token, size)) = parse_mtu_probe_v2_request(&bytes[..n]) {
                        peer.send(&mtu_probe_v2_ack_datagram(token, size))
                            .await
                            .unwrap();
                    }
                }
            }
        });
        let mut rx = crate::protocol::PacketCodec::new([1; 32]);
        let mut tx = crate::protocol::PacketCodec::new([2; 32]);
        let mut pn = 0;
        let management = std::sync::Mutex::new(crate::protocol::control_v2::Reassembler::new());
        let (sender, _receiver) = tokio::sync::watch::channel(None);
        let ceiling = crate::protocol::pmtu::probe_ceiling(1365, 48 + 13 + 28, None);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(12),
            super::probe_udp_mtu(
                &client,
                UdpClientFraming::legacy(false, [0; 4]),
                &mut pn,
                &mut rx,
                &mut tx,
                false,
                &management,
                &sender,
                ceiling,
                true,
            ),
        )
        .await;
        responder.abort();
        let _ = responder.await;
        let certified = result
            .expect("bounded probe")
            .unwrap()
            .expect("path certified");
        assert_eq!(certified, 1403);
        assert_eq!(
            super::udp_payload_budget_for_probe(certified, 13, 0) + 28,
            1492
        );
        assert_eq!(
            super::udp_inner_mtu_after_probe(
                1365,
                certified,
                true,
                crate::transport_core::NetworkFamilyMode::Ipv4,
                false
            ),
            1365
        );
    }

    #[test]
    fn live_probe_echo_is_bound_to_path_and_budget_revision() {
        let mut probe = super::LiveUdpMtuProbe {
            path_epoch: 7,
            budget_revision: 4,
            ..Default::default()
        };
        probe.start([1400]);
        let (token, _) = probe.next_send(tokio::time::Instant::now()).unwrap();
        let size = (1400 + super::UDP_RECORD_PROBE_OVERHEAD) as u16;
        assert!(probe.matches(token, size, 7, 4));
        assert!(!probe.matches(token, size, 8, 4));
        assert!(!probe.matches(token, size, 7, 5));
        probe.clear();
        probe.start([500]);
        probe.next_send(tokio::time::Instant::now()).unwrap();
        assert!(!probe.matches(token, size, 7, 4));
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
)))]
async fn probe_udp_mtu(
    _socket: &crate::protocol::obfs::ObfsUdp,
    _framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    _quic_pn: &mut u32,
    _client_rx: &mut PacketCodec,
    _client_tx: &mut PacketCodec,
    _management_v1: bool,
    _management_reassembler: &std::sync::Mutex<crate::protocol::control_v2::Reassembler>,
    _management_sender: &tokio::sync::watch::Sender<
        Option<crate::protocol::control_v2::ManagementEvent>,
    >,
    _ceiling: i32,
    _keep_df_after_success: bool,
) -> anyhow::Result<Option<i32>> {
    Ok(None) // no kernel DF control off Linux → keep the pushed/effective MTU
}

#[cfg(target_os = "linux")]
struct NetworkPlanApplyGuard<'a> {
    // The rollback must finish before the original queue can be closed.
    _tun: &'a TunInterface,
    failures: crate::client_cleanup::Failures,
    if_name: String,
    owns_device: bool,
    routes: route::RouteOwner,
    platform_state_touched: bool,
    routes_started: bool,
    dns: Option<dns::DnsLease>,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl<'a> NetworkPlanApplyGuard<'a> {
    fn new(
        tun: &'a TunInterface,
        if_name: &str,
        owns_device: bool,
        routes: route::RouteOwner,
        failures: crate::client_cleanup::Failures,
    ) -> Self {
        Self {
            _tun: tun,
            failures,
            if_name: if_name.to_string(),
            owns_device,
            routes,
            platform_state_touched: false,
            routes_started: false,
            dns: None,
            armed: true,
        }
    }

    fn touch_platform_state(&mut self) {
        self.platform_state_touched = true;
    }

    fn start_routes(&mut self) {
        self.routes_started = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetworkPlanApplyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _budget = crate::operation_budget::Scope::enter(self.failures.cleanup_deadline());
        log::warn!(
            "Linux NetworkPlan failed before commit — rolling back platform state for {}",
            self.if_name
        );
        if let Some(lease) = self.dns.as_mut() {
            if let Err(error) = self.failures.observe(
                crate::client_cleanup::Resource::Dns,
                lease.restore(self._tun),
            ) {
                log::warn!("DNS rollback after NetworkPlan failure also failed: {error}");
            }
        }
        if self.routes_started && self.owns_device {
            if let Err(error) = self.failures.observe(
                crate::client_cleanup::Resource::Routes,
                route::cleanup_routes_for_tun(&self.routes, self._tun),
            ) {
                log::warn!("route rollback after NetworkPlan failure also failed: {error}");
            }
        }
        if self.platform_state_touched {
            // A rejected reconnect generation must not leave old router permits active
            // while there is no acknowledged TUN plan. Both teardown functions are
            // idempotent and remove their IPv4 and IPv6 family halves independently.
            if let Err(error) = self.failures.observe(
                crate::client_cleanup::Resource::Forwarding,
                gateway::disengage_owned(&self.routes),
            ) {
                log::warn!("router rollback after NetworkPlan failure also failed: {error}");
            }
        }
    }
}

/// Inspect gateway ownership through the same bounded file loader and strict INI
/// service used at Linux startup. This command performs no platform/network work.
#[cfg(all(target_os = "linux", feature = "client-bin"))]
pub fn inspect_gateway_owner(config_path: &std::path::Path) -> anyhow::Result<&'static str> {
    inspect_gateway_owner_with_router_expectation(config_path, None)
}

/// Router wrappers can require the configured TUN and L3 owner without parsing INI.
/// This checks one file snapshot before launch; it does not pin later reloads.
#[cfg(all(target_os = "linux", feature = "client-bin"))]
pub fn inspect_gateway_owner_with_router_expectation(
    config_path: &std::path::Path,
    expected: Option<(&str, bool)>,
) -> anyhow::Result<&'static str> {
    let (snapshot, _) = crate::config_source::load_client(config_path)?;
    let (contents, _) = snapshot.into_parts();
    let config = crate::config::parse_client_config_strict(&contents)?;
    if let Some((device, attach)) = expected {
        anyhow::ensure!(
            config.tun.name == device,
            "router template TUN does not match configured dev"
        );
        anyhow::ensure!(
            config.tun.device_type == "tun",
            "router template requires device_type=tun"
        );
        anyhow::ensure!(
            config.tun.attach_existing == attach,
            "router template attachment mode does not match configured dev_attach"
        );
        anyhow::ensure!(
            !attach
                || !(config.routing.gateway_nat
                    || config.routing.forward
                    || config.routing.exit_node),
            "attached router interface requires gateway_nat/forward/exit_node disabled"
        );
    }
    Ok(
        if config.routing.gateway_nat || config.routing.forward || config.routing.exit_node {
            "core"
        } else {
            "legacy"
        },
    )
}

#[cfg(target_os = "linux")]
fn network_plan_state(plan: &NetworkPlan) -> String {
    // First line remains compatible with the original attach-mode contract. Named
    // family lines let interface owners and legacy router wrappers consume the exact
    // authenticated family set without guessing from `ipv6=auto`. Generation
    // also distinguishes reauthentication with the same addresses within an adapter.
    let mut state = format!("{}\n", plan.tunnel_address);
    for address in &plan.addresses {
        let family = match address.family {
            crate::transport_core::NetworkAddressFamily::Ipv4 => "ipv4",
            crate::transport_core::NetworkAddressFamily::Ipv6 => "ipv6",
        };
        state.push_str(&format!(
            "{family}={}/{}\n",
            address.address, address.prefix_len
        ));
    }
    state.push_str(&format!("mtu={}\n", plan.mtu));
    state.push_str(&format!("generation={}\n", plan.generation));
    state
}

#[cfg(target_os = "linux")]
fn publish_network_plan_state(plan: &NetworkPlan) -> anyhow::Result<()> {
    let Ok(path) = std::env::var("QELI_TUNIP_FILE") else {
        return Ok(());
    };
    if path.is_empty() {
        return Ok(());
    }
    let state = network_plan_state(plan);
    let _publication = plan_publication::PublicationLock::acquire(std::path::Path::new(&path))
        .map_err(|error| {
            anyhow::anyhow!("could not acquire network-plan publication lock: {error}")
        })?;
    crate::util::write_atomic(&path, state.as_bytes()).map_err(|error| {
        anyhow::anyhow!(
            "could not publish authenticated network plan to QELI_TUNIP_FILE '{path}': {error}"
        )
    })
}

#[cfg(target_os = "linux")]
fn setup_tunnel(
    config: &crate::config::client::ClientConfig,
    plan: &NetworkPlan,
    cleanup_failures: crate::client_cleanup::Failures,
) -> anyhow::Result<TunnelSetup> {
    let until =
        crate::operation_budget::limit(std::time::Instant::now() + crate::operation_budget::LIMIT);
    let _budget = crate::operation_budget::Scope::enter(until);
    crate::operation_budget::check()?;
    let client_ip = plan.tunnel_address.as_str();
    let mtu = i32::from(plan.mtu);
    let is_tap = is_tap_mode(&config.tun.device_type);
    let if_name = config.tun.name.clone();
    let attach = config.tun.attach_existing;
    let dev_label = if is_tap { "TAP" } else { "TUN" };
    let planned_tap_mac = if is_tap && !attach {
        let address = plan
            .addresses
            .first()
            .ok_or_else(|| anyhow::anyhow!("TAP network plan contains no assigned address"))?
            .address
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("TAP network plan contains an invalid address"))?;
        mac_from_ip(address)
    } else {
        [0u8; 6]
    };
    log::info!("TUN MTU: {}", mtu);

    let route_owner = if attach {
        route::RouteOwner::new(&if_name, plan.generation)?
    } else {
        route::RouteOwner::new_persistent(&if_name, plan.generation)?
    };
    tun_recovery::prepare(&if_name, attach)?;
    log::info!(
        "{} {} interface {}",
        if attach {
            "Attaching to existing"
        } else {
            "Creating"
        },
        dev_label,
        if_name
    );

    // Attach mode must mirror the existing device's IFF_MULTI_QUEUE flag. Opening a
    // multi-queue TUN/TAP without it fails with EINVAL, while adding it to a single-queue
    // device is equally invalid. The attach helper also verifies TUN vs TAP and IFF_NO_PI.
    let device_type = if is_tap {
        DeviceType::Tap
    } else {
        DeviceType::Tun
    };
    crate::operation_budget::check()?;
    let tun_res = if attach {
        TunInterface::attach(&if_name, mtu, device_type)
    } else if is_tap {
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
    let tun = std::sync::Arc::new(tun);
    let router_enabled =
        config.routing.gateway_nat || config.routing.forward || config.routing.exit_node;
    if !attach || router_enabled {
        route_owner.bind_tun(&tun)?;
    }
    // Cover partial setup with a local transaction. A completed TunGuard is transferred
    // into TunnelSetup before returning, so a failed core ACK cannot leave a gap.
    // This transaction covers address/up, gateway and exit
    // firewall state, descriptor duplication, routes, DNS, and the final TAP MAC read.
    // The external interface in attach mode is borrowed and is therefore never deleted.
    let mut plan_guard = NetworkPlanApplyGuard::new(
        &tun,
        &if_name,
        !attach,
        route_owner.clone(),
        cleanup_failures.clone(),
    );
    // An owned exit interface must not receive forwarded traffic before its
    // fail-closed FORWARD rules are installed, even if host forwarding is already on.
    let bring_up = || -> anyhow::Result<()> {
        route_owner.verify_plan()?;
        TunInterface::set_up(&if_name, mtu)?;
        log::info!(
            "{} {} is up (addresses: {})",
            dev_label,
            if_name,
            plan.addresses
                .iter()
                .map(|address| format!("{}/{}", address.address, address.prefix_len))
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(())
    };
    if attach {
        // The interface owner sets L3 (address + link up) — some managers only route
        // through an interface they configured themselves, so if qeli sets the address
        // the owner never treats it as connected. We only pump packets; the committed
        // authenticated plan is exported at the end of this transaction.
        log::info!(
            "Attached {}; L3 (address {}) left to its owner",
            if_name,
            client_ip
        );
    } else {
        // Local Linux adapter policy, deliberately not supplied by the server or
        // a share link. Apply before link-up and only to the device we created;
        // the transaction guard releases it if setup fails.
        if let Some(queue_len) = config.tun.owned_linux_tx_queue_len() {
            route_owner.verify_plan()?;
            TunInterface::set_queue_len_strict(&if_name, queue_len).map_err(|error| {
                anyhow::anyhow!(
                    "failed to set client TUN TX queue length on '{}': {}",
                    if_name,
                    error
                )
            })?;
            log::info!("Client TUN TX queue length: {} packets", queue_len);
        }
        if is_tap {
            route_owner.verify_plan()?;
            TunInterface::set_mac(&if_name, planned_tap_mac)?;
        }
        for address in &plan.addresses {
            route_owner.verify_plan()?;
            TunInterface::set_address(&if_name, &address.address, address.prefix_len)?;
        }
        if !config.routing.exit_node {
            bring_up()?;
        }
    }
    // Now that the interface exists, apply only the firewall/sysctl families present in
    // the authenticated plan. An IPv6-only router must not depend on IPv4 iptables or
    // net.ipv4.ip_forward, and an IPv4-only router must not require ip6tables.
    let has_ipv4 = plan
        .addresses
        .iter()
        .any(|address| address.family == crate::transport_core::NetworkAddressFamily::Ipv4);
    let has_ipv6 = plan
        .addresses
        .iter()
        .any(|address| address.family == crate::transport_core::NetworkAddressFamily::Ipv6);
    if config.routing.exit_node && !has_ipv4 && !has_ipv6 {
        anyhow::bail!("exit-node requires an authenticated IPv4 or IPv6 TUN address");
    }
    if router_enabled {
        gateway::bind_owner(&route_owner)?;
        plan_guard.touch_platform_state();
    }
    if router_enabled && has_ipv4 {
        crate::client::gateway::apply_tun_rp_filter(&if_name)?;
    }
    if config.routing.gateway_nat || config.routing.forward {
        if has_ipv4 {
            // `gateway_nat` masquerades; `forward` alone is pure L3 routing (#13).
            crate::client::gateway::engage(
                &if_name,
                &config.routing.lan_subnet,
                config.routing.gateway_nat,
            )?;
        }
        if has_ipv6 {
            crate::client::gateway::engage_ipv6(
                &if_name,
                &config.routing.lan_subnet_ipv6,
                config.routing.gateway_nat,
            )?;
        }
    }
    if config.routing.exit_node {
        if has_ipv4 {
            crate::client::gateway::engage_exit(&if_name)?;
        }
        if has_ipv6 {
            crate::client::gateway::engage_exit_ipv6(&if_name)?;
        }
    }
    if config.routing.exit_node && !attach {
        bring_up()?;
    }
    tun.set_nonblocking()?;

    // Own the dups through the rest of this function. They used to be bare `i32`s, and
    // everything below can still fail: a `?` from `setup_routes` or the DNS setup left
    // both of them open with nothing to close them. The device is non-persistent, so it
    // then survived on those two fds. Waiting for the non-persistent device could never
    // succeed because those descriptors were not going to be released. `OwnedFd`
    // closes them on any early return; ownership passes to the caller only on success.
    // F_DUPFD_CLOEXEC, not dup(2).
    //
    // POSIX says dup(2) CLEARS FD_CLOEXEC on the new descriptor. The original /dev/net/tun
    // fd is opened by std, which sets O_CLOEXEC — and both dups threw that away. After this
    // point the client keeps spawning children: `ip` (routes), `busctl` (DNS),
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
        plan_guard.start_routes();
        let carrier_targets = carrier_pin_targets(config);
        let carrier_local_address = config
            .server
            .local_address
            .as_deref()
            .map(str::parse::<std::net::IpAddr>)
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid local carrier address"))?
            .map(crate::transport_core::carrier::canonical_carrier_ip);
        route::setup_network_plan_routes(
            &route_owner,
            &config.routing,
            plan,
            &carrier_targets,
            carrier_local_address,
            is_tap,
        )?;
        // From this point bonded TCP streams must use only addresses for which the
        // generation just installed a physical bypass.
        mark_carrier_candidates_pinned(&carrier_targets);
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
    dns::setup_network_plan_dns(&config.dns, &plan.dns_servers, &tun, &mut plan_guard.dns)
        .map_err(|error| anyhow::anyhow!("DNS network-plan step failed: {error}. Set `dns = off` only when the platform manages DNS itself"))?;

    // Past every fallible platform step — move the RAII descriptors to the caller, which
    // immediately hands them to the shared TUN backend. No raw integer ownership escapes.
    let tap_mac = if !is_tap {
        [0u8; 6]
    } else if attach {
        read_interface_mac(&if_name)?
    } else {
        planned_tap_mac
    };
    // Publish only after every fallible host-network step succeeded. A router wrapper
    // must never enable forwarding/NAT based on an authenticated plan that was rolled
    // back before becoming the active generation.
    if !attach || router_enabled {
        route_owner.verify_plan()?;
    }
    crate::operation_budget::check()?;
    publish_network_plan_state(plan)?;
    let dns = plan_guard.dns.take();
    plan_guard.disarm();
    drop(plan_guard);
    let guard = TunGuard::new(
        tun,
        dns,
        if_name.clone(),
        !attach,
        route_owner,
        cleanup_failures,
    );
    Ok(TunnelSetup {
        guard,
        reader_fd: owned_reader,
        writer_fd: owned_writer,
        if_name,
        is_tap,
        tap_mac,
    })
}

#[cfg(target_os = "linux")]
fn read_interface_mac(ifname: &str) -> anyhow::Result<[u8; 6]> {
    let (_, mac) = crate::network_interface::ethernet(ifname)?;
    Ok(mac)
}

#[cfg(target_os = "linux")]
async fn connect_udp_candidates(
    config: &crate::config::client::ClientConfig,
    total: Duration,
) -> anyhow::Result<UdpSocket> {
    let host = config.server.address.as_str();
    let port = config.server.port;
    let resolved =
        crate::transport_core::resolver::lookup(host, port, tokio::time::Instant::now() + total)
            .await
            .map_err(|error| anyhow::anyhow!("UDP DNS lookup for {host}:{port} failed: {error}"))?;
    let mut seen = std::collections::HashSet::new();
    let mut candidates: Vec<std::net::SocketAddr> = resolved
        .into_iter()
        .map(|address| {
            std::net::SocketAddr::new(
                crate::transport_core::carrier::canonical_carrier_ip(address.ip()),
                address.port(),
            )
        })
        .filter(|address| seen.insert(*address))
        .collect();
    if candidates.is_empty() {
        anyhow::bail!("UDP server {host}:{port} resolved to no IPv4 or IPv6 address");
    }

    let local_ip = config
        .server
        .local_address
        .as_deref()
        .map(str::parse::<std::net::IpAddr>)
        .transpose()
        .map_err(|_| anyhow::anyhow!("invalid local carrier address"))?
        .map(crate::transport_core::carrier::canonical_carrier_ip);
    if let Some(local) = local_ip {
        candidates.retain(|address| local.is_ipv4() == address.is_ipv4());
    }
    if candidates.is_empty() {
        anyhow::bail!(
            "UDP server {host}:{port} has no address compatible with the configured local carrier"
        );
    }
    rotate_carrier_candidates(&mut candidates);
    note_carrier_candidates(candidates.iter().map(|address| address.ip()));
    let mut failures = Vec::with_capacity(candidates.len());
    for address in candidates {
        let bind_ip = local_ip.unwrap_or_else(|| {
            if address.is_ipv4() {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            }
        });
        let bind = std::net::SocketAddr::new(bind_ip, config.server.local_port);
        let socket = match UdpSocket::bind(bind).await {
            Ok(socket) => socket,
            Err(error) => {
                failures.push(format!("{address}: bind {bind} failed: {error}"));
                continue;
            }
        };
        match socket.connect(address).await {
            Ok(()) => {
                note_connected_peer(address.ip());
                return Ok(socket);
            }
            Err(error) => failures.push(format!("{address}: {error}")),
        }
    }
    anyhow::bail!(
        "UDP could not connect to any IPv4 or IPv6 address for {host}:{port} ({})",
        failures.join("; ")
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientUdpPayloadSendOutcome {
    Sent,
    EncodeFailed,
    CarrierFailed,
}

async fn flush_client_udp_datagrams(
    datagrams: &mut Vec<Vec<u8>>,
    socket: &crate::protocol::obfs::ObfsUdp,
    scratch: &mut crate::transport_core::udp_batch::BatchScratch,
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < datagrams.len() {
        let chunk: Vec<&[u8]> = datagrams[offset..]
            .iter()
            .take(crate::transport_core::udp_batch::MAX_BATCH)
            .map(|datagram| datagram.as_slice())
            .collect();
        match socket.send_batch(&chunk, scratch).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "UDP socket accepted no datagram from a writable batch",
                ));
            }
            Ok(sent) => offset += sent,
            Err(error) => return Err(error),
        }
    }
    datagrams.clear();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_client_udp_payloads(
    payloads: &[Vec<u8>],
    client_tx: &mut PacketCodec,
    obfuscation: &crate::config::client::ClientObfuscationConfig,
    payload_budget: usize,
    data_record_budget: usize,
    data_frag_enabled: bool,
    tx_data_frag_key: &[u8; 32],
    tx_record_id: &mut u64,
    socket: &crate::protocol::obfs::ObfsUdp,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    quic_pn: &mut u32,
    wire_record: &mut Vec<u8>,
    quic_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
    send_scratch: &mut crate::transport_core::udp_batch::BatchScratch,
    path_counters: &crate::transport_core::udp_buffer::UdpPathCounters,
) -> ClientUdpPayloadSendOutcome {
    let mut datagrams = Vec::with_capacity(crate::transport_core::udp_batch::MAX_BATCH);
    for payload in payloads {
        let mut obf = Obfuscator::new();
        let normalization_padding = if obfuscation.traffic_normalization.enabled
            && !obfuscation.traffic_normalization.round_sizes.is_empty()
        {
            Obfuscator::normalization_padding_len(
                payload.len(),
                &obfuscation.traffic_normalization.round_sizes,
                payload_budget,
            )
        } else {
            0
        };
        let pad_cap = (obfuscation.padding.max_bytes as usize)
            .min(payload_budget.saturating_sub(payload.len().saturating_add(normalization_padding)))
            as u16;
        obf.generate_padding_opts_into(
            obfuscation.padding.enabled,
            obfuscation.padding.min_bytes,
            pad_cap,
            obfuscation.padding.randomize,
            obfuscation.padding.probability,
            padding,
        );
        if obfuscation.traffic_normalization.enabled
            && !obfuscation.traffic_normalization.round_sizes.is_empty()
        {
            obf.append_normalization_padding_into(
                payload.len(),
                &obfuscation.traffic_normalization.round_sizes,
                payload_budget,
                padding,
            );
        }
        if client_tx
            .encrypt_packet_into(payload, padding, wire_record)
            .is_err()
        {
            if flush_client_udp_datagrams(&mut datagrams, socket, send_scratch)
                .await
                .is_err()
            {
                return ClientUdpPayloadSendOutcome::CarrierFailed;
            }
            return ClientUdpPayloadSendOutcome::EncodeFailed;
        }

        if data_frag_enabled && wire_record.len() > data_record_budget {
            let record_id = *tx_record_id;
            *tx_record_id = tx_record_id.wrapping_add(1);
            let fragments = match crate::protocol::data_frag::fragment_record(
                wire_record,
                tx_data_frag_key,
                record_id,
                data_record_budget - crate::protocol::data_frag::HEADER_LEN,
            ) {
                Ok(fragments) => fragments,
                Err(error) => {
                    log::warn!("UDP data fragmentation failed: {error}");
                    if flush_client_udp_datagrams(&mut datagrams, socket, send_scratch)
                        .await
                        .is_err()
                    {
                        return ClientUdpPayloadSendOutcome::CarrierFailed;
                    }
                    return ClientUdpPayloadSendOutcome::EncodeFailed;
                }
            };
            path_counters.note_fragmentation(fragments.len());
            for fragment in fragments {
                let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                    framing,
                    &fragment,
                    quic_pn,
                    quic_record,
                );
                datagrams.push(send_data.to_vec());
                if datagrams.len() == crate::transport_core::udp_batch::MAX_BATCH
                    && flush_client_udp_datagrams(&mut datagrams, socket, send_scratch)
                        .await
                        .is_err()
                {
                    log::warn!("UDP carrier fragment batch send failed");
                    return ClientUdpPayloadSendOutcome::CarrierFailed;
                }
            }
        } else {
            let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                framing,
                wire_record,
                quic_pn,
                quic_record,
            );
            datagrams.push(send_data.to_vec());
            if datagrams.len() == crate::transport_core::udp_batch::MAX_BATCH
                && flush_client_udp_datagrams(&mut datagrams, socket, send_scratch)
                    .await
                    .is_err()
            {
                log::warn!("UDP carrier batch send failed");
                return ClientUdpPayloadSendOutcome::CarrierFailed;
            }
        }
    }
    if let Err(error) = flush_client_udp_datagrams(&mut datagrams, socket, send_scratch).await {
        log::warn!("UDP carrier batch send failed: {error}");
        return ClientUdpPayloadSendOutcome::CarrierFailed;
    }
    ClientUdpPayloadSendOutcome::Sent
}
fn prepare_client_udp_control_payloads(
    frame: &[u8],
    recordizer: Option<&mut crate::protocol::recordizer::Recordizer>,
) -> Result<Vec<Vec<u8>>, crate::protocol::recordizer::RecordizerError> {
    let Some(recordizer) = recordizer else {
        return Ok(vec![frame.to_vec()]);
    };
    let mut payloads = recordizer.push(frame, std::time::Instant::now())?;
    // Control metadata must not wait behind the morphology delay. Flushing here also
    // preserves any ready payload returned by push(), which is required when max_packets
    // is one or when a fragmented control frame fills the current record.
    if let Some(payload) = recordizer.flush() {
        payloads.push(payload);
    }
    Ok(payloads)
}

async fn send_client_udp_terminal_control(
    frame: &[u8],
    client_tx: &mut PacketCodec,
    socket: &crate::protocol::obfs::ObfsUdp,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    quic_pn: &mut u32,
    wire_record: &mut Vec<u8>,
    carrier_record: &mut Vec<u8>,
) -> bool {
    wire_record.clear();
    if client_tx
        .encrypt_packet_into(frame, &[], wire_record)
        .is_err()
    {
        return false;
    }
    let packet = crate::transport_core::udp_client_framing::wrap_next_udp_record(
        framing,
        wire_record,
        quic_pn,
        carrier_record,
    );
    match socket.send(packet).await {
        Ok(_) => true,
        Err(error) => {
            log::debug!("could not send UDP terminal control: {error}");
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_client_udp_control_frame(
    frame: &[u8],
    recordizer: Option<&mut crate::protocol::recordizer::Recordizer>,
    client_tx: &mut PacketCodec,
    obfuscation: &crate::config::client::ClientObfuscationConfig,
    payload_budget: usize,
    data_record_budget: usize,
    data_frag_enabled: bool,
    tx_data_frag_key: &[u8; 32],
    tx_record_id: &mut u64,
    socket: &crate::protocol::obfs::ObfsUdp,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    quic_pn: &mut u32,
    wire_record: &mut Vec<u8>,
    quic_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
    send_scratch: &mut crate::transport_core::udp_batch::BatchScratch,
    path_counters: &crate::transport_core::udp_buffer::UdpPathCounters,
) -> Result<bool, crate::protocol::recordizer::RecordizerError> {
    let payloads = prepare_client_udp_control_payloads(frame, recordizer)?;
    Ok(send_client_udp_payloads(
        &payloads,
        client_tx,
        obfuscation,
        payload_budget,
        data_record_budget,
        data_frag_enabled,
        tx_data_frag_key,
        tx_record_id,
        socket,
        framing,
        quic_pn,
        wire_record,
        quic_record,
        padding,
        send_scratch,
        path_counters,
    )
    .await
        == ClientUdpPayloadSendOutcome::Sent)
}

#[cfg(test)]
mod udp_control_recordizer_tests {
    use super::prepare_client_udp_control_payloads;
    use crate::protocol::recordizer::{Reassembler, Recordizer, RuntimeConfig};
    use std::time::Duration;

    fn config() -> RuntimeConfig {
        RuntimeConfig {
            opportunistic: false,
            delay_min: Duration::from_millis(25),
            delay_max: Duration::from_millis(25),
            max_packets: 1,
            max_queue_bytes: 512,
            max_payload_bytes: 512,
            small_min_ratio: 1.0,
            small_max_ratio: 1.0,
            full_probability: 1.0,
            fragment_enabled: true,
            reassembly_timeout: Duration::from_secs(3),
            max_inflight_packets: 8,
            max_reassembly_bytes: 64 * 1024,
            max_fragments_per_packet: 64,
            max_packet_bytes: 16 * 1024,
        }
    }

    #[test]
    fn udp_client_info_uses_the_negotiated_recordizer_envelope() {
        let frame = crate::protocol::ctrl::client_info("0.8.0", "android").unwrap();
        assert_eq!(
            prepare_client_udp_control_payloads(&frame, None).unwrap(),
            vec![frame.clone()]
        );

        let runtime = config();
        let mut sender = Recordizer::new(runtime.clone());
        let payloads = prepare_client_udp_control_payloads(&frame, Some(&mut sender)).unwrap();
        assert!(!sender.is_pending());

        let mut receiver = Reassembler::new(runtime);
        let restored: Vec<Vec<u8>> = payloads
            .iter()
            .flat_map(|payload| receiver.decode(payload).unwrap())
            .collect();
        assert_eq!(restored, vec![frame]);
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientUdpReceivePath {
    Active,
    Candidate,
    Draining,
    Stale,
}

#[cfg(feature = "experimental-roaming")]
fn classify_client_udp_receive_path(
    active_epoch: u64,
    candidate_epoch: Option<u64>,
    draining_epoch: Option<u64>,
    received_epoch: u64,
) -> ClientUdpReceivePath {
    if received_epoch == active_epoch {
        ClientUdpReceivePath::Active
    } else if candidate_epoch == Some(received_epoch) {
        ClientUdpReceivePath::Candidate
    } else if draining_epoch == Some(received_epoch) {
        ClientUdpReceivePath::Draining
    } else {
        ClientUdpReceivePath::Stale
    }
}

#[cfg(all(test, feature = "experimental-roaming", any(unix, windows)))]
mod udp_receive_path_tests {
    use super::{
        classify_client_udp_receive_path, ClientUdpEarlyDataQueue, ClientUdpReceivePath,
        ClientUdpReceivedDatagram, UDP_EARLY_CANDIDATE_MAX_BYTES,
    };
    use bytes::BytesMut;

    fn received(
        path_epoch: u64,
        wire: &[u8],
        authenticated_plaintext: Option<Vec<u8>>,
    ) -> ClientUdpReceivedDatagram {
        let (recycler, _receiver) = tokio::sync::mpsc::channel(1);
        let mut bytes = BytesMut::with_capacity(wire.len());
        bytes.extend_from_slice(wire);
        ClientUdpReceivedDatagram {
            path_epoch,
            datagram: crate::transport_core::udp_receive::PooledUdpDatagram::new(bytes, recycler),
            authenticated_plaintext,
        }
    }

    #[test]
    fn candidate_becomes_active_only_after_epoch_publication() {
        assert_eq!(
            classify_client_udp_receive_path(0, Some(1), None, 1),
            ClientUdpReceivePath::Candidate
        );
        assert_eq!(
            classify_client_udp_receive_path(1, None, Some(0), 1),
            ClientUdpReceivePath::Active
        );
        assert_eq!(
            classify_client_udp_receive_path(1, None, Some(0), 0),
            ClientUdpReceivePath::Draining
        );
        assert_eq!(
            classify_client_udp_receive_path(1, None, None, 0),
            ClientUdpReceivePath::Stale
        );
    }

    #[test]
    fn candidate_data_is_bounded_epoch_scoped_and_published_in_order() {
        let mut queue = ClientUdpEarlyDataQueue::default();
        queue.begin(7);

        assert!(queue.push(received(7, b"wire-data", Some(b"plain-data".to_vec()))));
        assert!(queue.push(received(7, b"wire-fragment", None)));
        assert!(!queue.push(received(8, b"wrong-epoch", None)));

        let mut committed = queue.take_committed(7).unwrap();
        let first = committed.pop_front().unwrap();
        assert_eq!(first.path_epoch, 7);
        assert_eq!(
            first.authenticated_plaintext.as_deref(),
            Some(b"plain-data".as_slice())
        );
        assert_eq!(&*committed.pop_front().unwrap().datagram, b"wire-fragment");
        assert!(committed.is_empty());
        assert!(queue.take_committed(7).is_none());

        queue.begin(9);
        assert!(!queue.push(received(
            9,
            b"x",
            Some(vec![0; UDP_EARLY_CANDIDATE_MAX_BYTES]),
        )));
        assert!(queue.take_committed(9).unwrap().is_empty());
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
struct UdpClientDrainingPath {
    epoch: u64,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    expires_at: tokio::time::Instant,
    receive_task: crate::transport_core::tasks::TaskHandle,
}

/// One pooled datagram tagged by the path epoch of the socket that received it. The tag is local
/// actor metadata, never wire input. It lets a future commit reject already-queued old-path traffic
/// and accept datagrams queued by the candidate pump only after that epoch becomes active. The
/// immediately previous pump may remain receive-only for one bounded DATA_FRAG reassembly window.
struct ClientUdpReceivedDatagram {
    path_epoch: u64,
    datagram: crate::transport_core::udp_receive::PooledUdpDatagram,
    /// Candidate DATA is authenticated before PATH_COMMIT can be recognized. Retain that
    /// plaintext exactly once so commit can publish it without replaying the AEAD counter.
    #[cfg_attr(not(feature = "experimental-roaming"), allow(dead_code))]
    authenticated_plaintext: Option<Vec<u8>>,
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
const UDP_EARLY_CANDIDATE_MAX_ITEMS: usize = 128;
#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
const UDP_EARLY_CANDIDATE_MAX_BYTES: usize = 512 * 1024;

/// Bounded reorder window for candidate DATA/DATA_FRAG that arrives before PATH_COMMIT.
/// Holding the pooled datagram also bounds socket-pool ownership; the byte cap includes both
/// wire bytes and cached authenticated plaintext.
#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
#[derive(Default)]
struct ClientUdpEarlyDataQueue {
    epoch: Option<u64>,
    retained_bytes: usize,
    items: std::collections::VecDeque<ClientUdpReceivedDatagram>,
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
impl ClientUdpEarlyDataQueue {
    fn begin(&mut self, epoch: u64) {
        self.clear();
        self.epoch = Some(epoch);
    }

    fn push(&mut self, item: ClientUdpReceivedDatagram) -> bool {
        let retained = item.datagram.len().saturating_add(
            item.authenticated_plaintext
                .as_ref()
                .map(Vec::len)
                .unwrap_or(0),
        );
        let Some(next_bytes) = self.retained_bytes.checked_add(retained) else {
            return false;
        };
        if self.epoch != Some(item.path_epoch)
            || self.items.len() >= UDP_EARLY_CANDIDATE_MAX_ITEMS
            || next_bytes > UDP_EARLY_CANDIDATE_MAX_BYTES
        {
            return false;
        }
        self.retained_bytes = next_bytes;
        self.items.push_back(item);
        true
    }

    fn take_committed(
        &mut self,
        epoch: u64,
    ) -> Option<std::collections::VecDeque<ClientUdpReceivedDatagram>> {
        if self.epoch != Some(epoch) {
            return None;
        }
        self.epoch = None;
        self.retained_bytes = 0;
        Some(std::mem::take(&mut self.items))
    }

    fn clear(&mut self) {
        self.epoch = None;
        self.retained_bytes = 0;
        self.items.clear();
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
#[allow(clippy::too_many_arguments)]
fn deliver_buffered_udp_plaintext(
    plaintext: Vec<u8>,
    recordizer: &mut Option<crate::protocol::recordizer::Reassembler>,
    tun_write_tx: &TunWriter,
    family_mode: crate::transport_core::NetworkFamilyMode,
    runtime: &RuntimeCounters,
    udp_buffer: &UdpBufferController,
    unsupported_inner_drops: &mut u64,
) -> bool {
    if let Some(reassembler) = recordizer.as_mut() {
        if plaintext.is_empty() {
            return true;
        }
        let mut first_packet = None;
        let mut extra_packets = Vec::new();
        let mut pool_exhausted_drops = 0_u64;
        let mut oversize_drops = 0_u64;
        let decode_result = reassembler.decode_with(&plaintext, |bytes| {
            let Some(mut packet) = tun_write_tx.try_acquire() else {
                pool_exhausted_drops = pool_exhausted_drops.saturating_add(1);
                return;
            };
            if bytes.len() > packet.capacity() {
                oversize_drops = oversize_drops.saturating_add(1);
                return;
            }
            packet.as_vec_mut().extend_from_slice(bytes);
            if first_packet.is_none() {
                first_packet = Some(packet);
            } else {
                extra_packets.push(packet);
            }
        });
        if let Err(error) = decode_result {
            log::debug!("buffered UDP recordizer decode error: {error}");
            return true;
        }
        for _ in 0..pool_exhausted_drops {
            udp_buffer.note_internal_drop(InternalDrop::PoolExhausted);
        }
        for _ in 0..oversize_drops {
            udp_buffer.note_internal_drop(InternalDrop::Oversize);
        }
        for packet in first_packet.into_iter().chain(extra_packets) {
            if !is_supported_inner_packet(packet.as_ref(), family_mode) {
                *unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                if unsupported_inner_drops.is_power_of_two() {
                    log::debug!(
                        "UDP client dropped invalid buffered mux packet (total {})",
                        unsupported_inner_drops
                    );
                }
                continue;
            }
            runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
            runtime
                .rx_bytes
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            trace::record(trace::Dir::Rx, "client.udp", packet.len(), 0);
            match tun_write_tx.try_send(packet) {
                Ok(()) => {}
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    udp_buffer.note_internal_drop(InternalDrop::QueueFull);
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
            }
        }
        return true;
    }

    if plaintext.is_empty() {
        return true;
    }
    if !is_supported_inner_packet(&plaintext, family_mode) {
        *unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
        udp_buffer.note_internal_drop(InternalDrop::Unsupported);
        if unsupported_inner_drops.is_power_of_two() {
            log::debug!(
                "UDP client dropped invalid buffered inner packet (total {})",
                unsupported_inner_drops
            );
        }
        return true;
    }
    let Some(mut packet) = tun_write_tx.try_acquire() else {
        udp_buffer.note_internal_drop(InternalDrop::PoolExhausted);
        return true;
    };
    if plaintext.len() > packet.capacity() {
        udp_buffer.note_internal_drop(InternalDrop::Oversize);
        return true;
    }
    packet.as_vec_mut().extend_from_slice(&plaintext);
    runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
    runtime
        .rx_bytes
        .fetch_add(packet.len() as u64, Ordering::Relaxed);
    trace::record(trace::Dir::Rx, "client.udp", packet.len(), 0);
    match tun_write_tx.try_send(packet) {
        Ok(()) => true,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            udp_buffer.note_internal_drop(InternalDrop::QueueFull);
            true
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
    }
}

impl std::ops::Deref for ClientUdpReceivedDatagram {
    type Target = crate::transport_core::udp_receive::PooledUdpDatagram;

    fn deref(&self) -> &Self::Target {
        &self.datagram
    }
}

/// Start one socket-owned receive pump with its own bounded recycler. A roaming candidate can run
/// this before commit without borrowing the active path's pool; after commit the actor may retain
/// this handle and abort the old one, while every queued datagram remains ordinary pooled storage.
fn spawn_client_udp_receive_pump(
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
    path_epoch: u64,
    received_tx: mpsc::Sender<
        crate::transport_core::receive_queue::QueuedBatch<ClientUdpReceivedDatagram>,
    >,
    tasks: &crate::transport_core::tasks::Spawner,
    receive_queue: Arc<crate::transport_core::receive_queue::ReceiveQueue>,
) -> crate::transport_core::tasks::TaskHandle {
    let receive_slots = crate::transport_core::udp_receive::UDP_RECEIVE_QUEUE_PACKETS + 1;
    let (receive_recycler, mut recycled_receivers) = mpsc::channel(receive_slots);
    for _ in 0..receive_slots {
        receive_recycler
            .try_send(bytes::BytesMut::with_capacity(
                crate::transport_core::udp_receive::MAX_UDP_PACKET_SIZE,
            ))
            .expect("fresh UDP receive recycler has exact advertised capacity");
    }
    tasks.spawn_owned(async move {
        // One syscall per datagram was a measured UDP data-plane cost: at MTU 1400 a
        // 500 Mbit/s stream is ~45 000 `recvfrom` per second, and an `strace` of a live run
        // matched datagrams to calls almost exactly. The TCP transport never paid it — one
        // `read` returns many records. Repeated same-window old/new lab A/B found no stable
        // goodput or process-CPU change. A syscall trace nevertheless confirmed successful
        // receive batches averaging 3.55 datagrams on server upload ingress and 4.46 on client
        // download ingress. This is verified syscall batching, not a claim that it closes the
        // UDP/TCP throughput gap by itself.
        let mut scratch = crate::transport_core::udp_batch::BatchScratch::new(
            crate::transport_core::udp_batch::MAX_BATCH,
        );
        let mut slots: Vec<bytes::BytesMut> =
            Vec::with_capacity(crate::transport_core::udp_batch::MAX_BATCH);
        loop {
            // Wait only for the FIRST buffer. Taking whatever else the recycler already holds
            // keeps the batch opportunistic: it is never padded out by waiting, so batching
            // removes syscalls without adding a millisecond of latency.
            while slots.len() < crate::transport_core::udp_batch::MAX_BATCH {
                if slots.is_empty() {
                    match recycled_receivers.recv().await {
                        Some(buffer) => slots.push(buffer),
                        None => return,
                    }
                } else if let Ok(buffer) = recycled_receivers.try_recv() {
                    slots.push(buffer);
                } else {
                    break;
                }
            }
            for slot in slots.iter_mut() {
                slot.clear();
            }

            let received = match socket.recv_batch(&mut slots, None, &mut scratch).await {
                Ok(received) => received,
                Err(error) => {
                    log::debug!("UDP receive pump stopped: {error}");
                    return;
                }
            };

            let received_at = std::time::Instant::now();
            // Hand the whole batch over once. Per-datagram channel sends were the second
            // per-packet cost after the syscall, and the consumer drains this exactly like
            // the early-data queue it already keeps.
            let mut batch = Vec::with_capacity(received);
            for slot in slots.drain(..received) {
                if slot.is_empty() {
                    // Malformed obfs frame (or a zero-length datagram): recycle, do not
                    // forward — same outcome the single-datagram path gave for `Ok(0)`.
                    if receive_recycler.send(slot).await.is_err() {
                        return;
                    }
                    continue;
                }
                batch.push(ClientUdpReceivedDatagram {
                    path_epoch,
                    datagram: crate::transport_core::udp_receive::PooledUdpDatagram::new(
                        slot,
                        receive_recycler.clone(),
                    ),
                    authenticated_plaintext: None,
                });
            }
            if !batch.is_empty() {
                let bytes = batch.iter().map(|packet| packet.len()).sum();
                let batch = receive_queue.batch(batch, bytes, received_at).await;
                if received_tx.send(batch).await.is_err() {
                    return;
                }
            }
        }
    })
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
fn begin_udp_carrier_failure_recovery(
    recovery: &mut crate::transport_core::udp_roaming_client::UdpClientNatRecoveryPolicy,
    roaming: &crate::transport_core::udp_roaming_client::UdpClientRoaming,
    path_controller: &dyn PathController,
    candidate_in_flight: bool,
    detail: &str,
) -> bool {
    let active_epoch = roaming.active_epoch();
    match recovery.on_carrier_failure(
        active_epoch,
        candidate_in_flight,
        path_controller.can_request_same_network_nat_rebind(),
        std::time::Instant::now(),
    ) {
        crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::WaitForPath => {
            log::warn!(
                "UDP active carrier failed ({detail}); preserving generation for a replacement path at epoch {active_epoch}"
            );
            true
        }
        crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::RequestSameNetworkPath => {
            match path_controller.request_same_network_nat_rebind() {
                Ok(()) => log::warn!(
                    "UDP active carrier failed ({detail}); requested an immediate replacement path at epoch {active_epoch}"
                ),
                Err(error) => log::warn!(
                    "UDP active carrier failed ({detail}); path refresh request failed ({error}), waiting for the platform observer at epoch {active_epoch}"
                ),
            }
            // A platform network callback or Linux sampler may still deliver a candidate even
            // when the explicit refresh event failed. The policy owns the bounded timeout.
            true
        }
        crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::Reconnect => {
            log::warn!(
                "UDP replacement-path grace expired after carrier failure ({detail}); reconnecting"
            );
            false
        }
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
struct UdpClientLiveCandidate {
    prepared: PreparedPathCandidate,
    epoch: u64,
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
    receive_task: crate::transport_core::tasks::TaskHandle,
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
impl UdpClientLiveCandidate {
    fn new(
        prepared: PreparedPathCandidate,
        epoch: u64,
        socket: Arc<crate::protocol::obfs::ObfsUdp>,
        receive_task: crate::transport_core::tasks::TaskHandle,
    ) -> Self {
        Self {
            prepared,
            epoch,
            socket,
            receive_task,
        }
    }

    fn prepared(&self) -> &PreparedPathCandidate {
        &self.prepared
    }

    fn into_active(
        self,
    ) -> (
        PreparedPathCandidate,
        Arc<crate::protocol::obfs::ObfsUdp>,
        crate::transport_core::tasks::TaskHandle,
    ) {
        (self.prepared, self.socket, self.receive_task)
    }

    async fn stop(mut self) {
        self.receive_task.finish().await;
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
async fn send_udp_path_transmit(
    socket: &crate::protocol::obfs::ObfsUdp,
    client_tx: &mut PacketCodec,
    packet_number: &mut u32,
    transmit: &crate::transport_core::udp_roaming_client::UdpClientPathTransmit,
) -> anyhow::Result<()> {
    let wire = crate::transport_core::udp_roaming_client::encrypt_path_transmit(
        client_tx,
        *packet_number,
        transmit,
    )?;
    *packet_number = packet_number.wrapping_add(1);
    socket.send(&wire).await?;
    Ok(())
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
async fn abort_udp_platform_candidate(
    path_controller: &dyn PathController,
    candidate: &PreparedPathCandidate,
    reason: &str,
) {
    let rollback = match path_controller.abort_candidate_path(candidate, reason) {
        Ok(rollback) => rollback,
        Err(error) => {
            log::debug!(
                "UDP candidate {} rollback was already resolved: {}",
                candidate.candidate_id,
                error
            );
            return;
        }
    };
    match tokio::time::timeout(PATH_ACK_TIMEOUT, rollback).await {
        Ok(Ok(())) => log::info!(
            "UDP candidate {} rollback completed",
            candidate.candidate_id
        ),
        Ok(Err(error)) => log::warn!(
            "UDP candidate {} rollback failed: {}",
            candidate.candidate_id,
            error
        ),
        Err(_) => log::warn!(
            "UDP candidate {} rollback acknowledgement timed out",
            candidate.candidate_id
        ),
    }
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
    let addr = crate::util::join_host_port(&config.server.address, config.server.port);
    log::info!(
        "Connecting to {} (UDP) as user '{}'",
        addr,
        crate::util::log_identity(&config.auth.username)
    );

    if config.obfuscation.mode == "obfs" && config.obfuscation.obfs_key.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "obfs wire mode requires a non-empty obfuscation.obfs_key \
             (an empty key is publicly derivable → no DPI resistance)"
        ));
    }
    let raw_socket = connect_before_tunnel(
        core.cancel_token(),
        connect_udp_candidates(
            config,
            Duration::from_secs(config.server.connection_timeout_secs.max(1)),
        ),
    )
    .await?;
    // The shared UDP path below applies the socket policy before its first handshake packet,
    // so Linux and every native client use one controller and one set of counters.
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
    if quic_enabled {
        log::warn!(
            "UDP quic-shape compatibility masking is enabled; it is not a real QUIC/HTTP/3 \
             state machine and is not the maximum-stealth profile. Use TCP reality-tls \
             for hostile DPI."
        );
    }
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
    let static_shared = static_es(config, &client_kp)?;
    #[cfg(feature = "experimental-roaming")]
    let udp_session_material = match &static_shared {
        Some(es) => derive_session_material_hybrid_bound(&shared.0, &mlkem_shared, es),
        None => derive_session_material_hybrid(&shared.0, &mlkem_shared),
    };
    #[cfg(feature = "experimental-roaming")]
    let (server_to_client, client_to_server) = udp_session_material.data_keys();
    #[cfg(not(feature = "experimental-roaming"))]
    let (server_to_client, client_to_server) = match static_shared {
        Some(es) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, &es),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };
    let rx_data_frag_key = derive_data_frag_key(&server_to_client);
    let tx_data_frag_key = derive_data_frag_key(&client_to_server);
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

    let (_, server_capabilities) =
        crate::protocol::capabilities::split_server_capabilities(&auth_proof_msg)?;
    let negotiated_capabilities = crate::protocol::capabilities::negotiate_client_capabilities(
        config,
        server_capabilities,
        core.platform_capabilities(),
    )?;
    let data_frag_enabled = server_capabilities.is_some_and(|server| {
        server.contains(crate::protocol::capabilities::server_capability::UDP_DATA_FRAG_V1)
    }) && negotiated_capabilities.is_some_and(|client| {
        client.core_bits & crate::protocol::capabilities::client_capability::UDP_DATA_FRAG_V1 != 0
    });
    let management_v1 = crate::protocol::capabilities::management_v1_negotiated(
        server_capabilities,
        negotiated_capabilities,
    );
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
        server_capabilities,
        core.platform_capabilities(),
    )?;
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

    let AuthOk {
        family_mode,
        addresses,
        client_ip,
        server_ip,
        prefix,
        mtu: pushed_mtu,
        dns_ip,
        dns_port,
        dns_servers,
        routes_json: routes_json_udp,
        pushed_obf,
        session_token: _,
        max_streams: max_streams_udp,
        adaptive: adaptive_udp,
        udp_roaming_session_id: _udp_roaming_session_id,
    } = parse_auth_ok(&response_str)?;
    #[cfg(feature = "experimental-roaming")]
    let udp_roaming_session_id = if crate::protocol::capabilities::udp_roaming_negotiated(
        server_capabilities,
        negotiated_capabilities,
    ) {
        Some(_udp_roaming_session_id.ok_or_else(|| {
            anyhow::anyhow!("server negotiated UDP_ROAM_V1 but omitted its session id")
        })?)
    } else {
        None
    };
    #[cfg(feature = "experimental-roaming")]
    let mut udp_roaming = udp_roaming_session_id
        .map(|session_id| {
            crate::transport_core::udp_roaming_client::UdpClientRoaming::new(
                session_id,
                *udp_session_material.client_to_server_cid_secret(),
                *udp_session_material.server_to_client_cid_secret(),
            )
        })
        .transpose()?;
    #[cfg_attr(
        not(all(feature = "experimental-roaming", any(unix, windows))),
        allow(unused_mut)
    )]
    let mut udp_framing = {
        #[cfg(feature = "experimental-roaming")]
        {
            match udp_roaming.as_ref() {
                Some(roaming) => {
                    crate::transport_core::udp_client_framing::UdpClientFraming::roaming(
                        *roaming.active_transmit_cid(),
                        *roaming.active_receive_cid(),
                    )
                }
                None => crate::transport_core::udp_client_framing::UdpClientFraming::legacy(
                    quic_enabled,
                    connection_id,
                ),
            }
        }
        #[cfg(not(feature = "experimental-roaming"))]
        {
            crate::transport_core::udp_client_framing::UdpClientFraming::legacy(
                quic_enabled,
                connection_id,
            )
        }
    };
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let path_controller = core.path_controller();
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let linux_path_controller = core.linux_path_controller();
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let udp_handover_enabled = udp_roaming.is_some()
        && path_controller.is_some()
        && core.platform_capabilities() & crate::transport_core::platform_capability::ROAMING_PATH
            == crate::transport_core::platform_capability::ROAMING_PATH;
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    if udp_handover_enabled {
        log::info!(
            "UDP make-before-break negotiated; prepared PathUpdate candidates may migrate this session"
        );
    }
    #[cfg(not(all(feature = "experimental-roaming", any(unix, windows))))]
    let udp_handover_enabled = false;

    let mut eff_obf = config.obfuscation.clone();
    if let Some(po) = pushed_obf.as_ref() {
        eff_obf.padding = po.padding.clone();
        eff_obf.heartbeat = po.heartbeat.clone();
        eff_obf.traffic_normalization = po.traffic_normalization.clone();
        eff_obf.traffic_shaping = po.traffic_shaping.clone();
    }

    log::info!("UDP: Auth OK, assigned IP: {}", client_ip);
    // The complete push journal is attached below after path-MTU probing, so every
    // platform sees both the server ceiling and the final selected MTU.

    // Discover the outer UDP path whenever probing is enabled, independently of an
    // explicit inner TUN MTU. DATA_FRAG keeps the selected inner MTU while records fit
    // the certified outer budget; legacy sockets retain IP-fragmentation compatibility.
    // The client data plane is not running yet, but the server may already emit cover or a
    // heartbeat after AuthOK. The probe receive loop ignores unrelated datagrams until each
    // fixed deadline. Falls back to the pushed/effective MTU on any miss.
    let management_reassembler =
        std::sync::Mutex::new(crate::protocol::control_v2::Reassembler::new());
    let (management_tx, mut management_rx) = tokio::sync::watch::channel(None);
    let base_mtu = effective_mtu(config.tun.mtu, pushed_mtu);
    let probe_ceiling = crate::protocol::pmtu::probe_ceiling(
        base_mtu,
        UDP_RECORD_PROBE_OVERHEAD
            + socket.seal_overhead()
            + udp_framing.wrapper_len()
            + 8
            + if socket.peer_is_ipv6() { 40 } else { 20 },
        crate::protocol::pmtu::socket_path_mtu(socket.raw_socket(), socket.peer_is_ipv6()),
    );
    let mut uplink_udp_payload_budget =
        crate::protocol::data_frag::conservative_udp_payload_budget(socket.peer_is_ipv6());
    let mut keep_df_after_live_probe = false;
    let mut initial_probe_confirmed = false;
    let tun_mtu = if config.tun.mtu_probe {
        match probe_udp_mtu(
            &socket,
            udp_framing,
            &mut quic_pn,
            &mut client_rx,
            &mut client_tx,
            management_v1,
            &management_reassembler,
            &management_tx,
            probe_ceiling,
            data_frag_enabled,
        )
        .await?
        {
            Some(m) => {
                keep_df_after_live_probe = data_frag_enabled;
                initial_probe_confirmed = true;
                // The probe sent `m + record-overhead`, then QUIC/obfs wrapped it. Record
                // the UDP payload size it actually certified separately from inner MTU.
                uplink_udp_payload_budget = udp_payload_budget_for_probe(
                    m,
                    socket.seal_overhead(),
                    udp_framing.wrapper_len(),
                );
                // Inner and outer MTU stay independent when DATA_FRAG_V1 was negotiated.
                // Preserve an explicit inner MTU. For legacy peers only auto IPv4 may
                // shrink; auto IPv6 keeps its 1280 floor. The probe restored outer IP
                // fragmentation for legacy compatibility in either case.
                let inner_mtu = udp_inner_mtu_after_probe(
                    base_mtu,
                    m,
                    data_frag_enabled,
                    family_mode,
                    config.tun.mtu > 0,
                );
                log::info!(
                    "UDP path probe: inner MTU {}, uplink UDP payload budget {} (probe rung {}, DATA_FRAG_V1={})",
                    inner_mtu,
                    uplink_udp_payload_budget,
                    m,
                    data_frag_enabled
                );
                inner_mtu
            }
            None => {
                log::info!(
                    "UDP path probe: no result — using inner MTU {} and conservative {}-byte UDP payload budget",
                    base_mtu,
                    uplink_udp_payload_budget
                );
                base_mtu
            }
        }
    } else {
        log::info!(
            "UDP path probe disabled: using inner MTU {} and conservative {}-byte UDP payload budget",
            base_mtu,
            uplink_udp_payload_budget
        );
        base_mtu
    };
    runtime_counters.udp.path.set(
        tun_mtu as u32,
        uplink_udp_payload_budget,
        data_frag_enabled,
        if initial_probe_confirmed {
            "probe"
        } else {
            "fallback"
        },
        if initial_probe_confirmed {
            None
        } else {
            Some(if config.tun.mtu_probe {
                "probe_unconfirmed"
            } else {
                "probe_disabled"
            })
        },
    );
    log::info!(
        "UDP path diagnostics: {}",
        serde_json::to_string(&runtime_counters.udp.path.snapshot())
            .expect("path diagnostics serialize")
    );
    let fallback_dns_servers = core.fallback_dns_servers().to_vec();
    let network = HandshakeNetwork {
        family_mode,
        addresses: &addresses,
        client_ip: &client_ip,
        prefix,
        tunnel_gateway: &server_ip,
        dns_ip: &dns_ip,
        dns_port: &dns_port,
        dns_servers: &dns_servers,
        routes_json: &routes_json_udp,
        mtu: tun_mtu,
        fallback_dns_servers: &fallback_dns_servers,
    };
    let mut plan = build_network_plan(config, core.next_generation(), &network)?;
    #[cfg(target_os = "linux")]
    {
        plan.carrier_address = CONNECTED_PEER
            .lock()
            .ok()
            .and_then(|peer| *peer)
            .map(|peer| peer.to_string());
    }
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_generation = plan.generation;
    plan.max_streams = max_streams_udp;
    plan.adaptive = adaptive_udp;
    plan.data_plane = crate::transport_core::NetworkDataPlaneFacts::from_obfuscation(&eff_obf);
    #[cfg(feature = "experimental-roaming")]
    let negotiated_roaming_mode = if udp_roaming_session_id.is_some() {
        crate::transport_core::NetworkRoamingMode::UdpRoamV1
    } else {
        crate::transport_core::NetworkRoamingMode::Reconnect
    };
    #[cfg(not(feature = "experimental-roaming"))]
    let negotiated_roaming_mode = crate::transport_core::NetworkRoamingMode::Reconnect;
    plan.data_plane.set_negotiated_modes(
        pushed_obf
            .as_ref()
            .and_then(|obfuscation| obfuscation.recordizer.as_ref()),
        negotiated_roaming_mode,
        config.roaming,
    );
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
    let negotiated_family_mode = plan.family_mode;
    #[cfg(target_os = "linux")]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        tap_gateway_facts(&plan.addresses);
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        (None, 0, None, 0);
    // Reject unusable authenticated budgets before platform mutation and post_up.
    let mut data_record_budget =
        crate::protocol::data_frag::unfragmented_record_budget_with_wrapper(
            uplink_udp_payload_budget,
            socket.seal_overhead(),
            udp_framing.wrapper_len(),
        )?;
    let mut mux_payload_budget = client_tx
        .max_data_for_record_budget(data_record_budget)
        .map_err(|error| anyhow::anyhow!("UDP recordizer budget is invalid: {error}"))?;
    let udp_recordizer_config = pushed_obf
        .as_ref()
        .and_then(|pushed| pushed.recordizer.as_ref())
        .cloned();
    let udp_recordizer_runtime = udp_recordizer_config
        .as_ref()
        .map(|config| {
            crate::protocol::recordizer::RuntimeConfig::from_config(
                config,
                mux_payload_budget,
                crate::protocol::packet::MAX_TUNNEL_MTU,
            )
        })
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid negotiated UDP recordizer: {error}"))?;
    let mut max_empty_record_padding = client_tx
        .max_padding_for_record_budget(0, data_record_budget)
        .map_err(|error| {
            anyhow::anyhow!("UDP record budget cannot carry control traffic: {error}")
        })?;
    let tun_setup = core.prepare_tunnel(config, plan).await?;
    run_pending_post_up(core).await;
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
    let tap_mac = tun_setup.tap_mac;
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
    let tun_buf_size = {
        let configured = config
            .performance
            .tun_buffer_size
            .saturating_add(if cfg!(target_os = "macos") { 4 } else { 0 });
        let actual = tun_read_buffer_size(
            config.performance.tun_buffer_size,
            tun_mtu,
            is_tap,
            cfg!(target_os = "macos"),
        );
        if actual > configured {
            log::warn!(
                "TUN read buffer expanded from {} to {} bytes for negotiated MTU {} ({})",
                configured,
                actual,
                tun_mtu,
                if is_tap {
                    "tap"
                } else if cfg!(target_os = "macos") {
                    "utun"
                } else {
                    "tun"
                }
            );
        }
        actual
    };
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let pump_config = LinuxTunPumpConfig {
        buffer_size: tun_buf_size,
        downlink_record_bytes: downlink_record_budget(tun_mtu, padding_max, norm_sizes),
        write_drops: Some(runtime_counters.udp.sink(InternalDrop::TunWrite)),
        framing: if cfg!(target_os = "macos") {
            TunFraming::Utun
        } else if is_tap {
            TunFraming::Tap(TapHeaders {
                client_mac: tap_mac,
                gateway_mac,
                gateway_ipv4: tap_gateway_ipv4,
                ipv4_prefix_len: tap_ipv4_prefix_len,
                gateway_ipv6: tap_gateway_ipv6,
                ipv6_prefix_len: tap_ipv6_prefix_len,
            })
        } else {
            TunFraming::Raw
        },
    };
    #[cfg(target_os = "linux")]
    let (tun_guard, mut tun_pump) = start_linux_tun_pump(
        tun_setup.guard,
        reader_fd,
        writer_fd,
        pump_config,
        Some(tokio::runtime::Handle::current()),
    )
    .await?;
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let mut tun_pump = LinuxTunPump::start(reader_fd, writer_fd, pump_config)?;
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
    #[cfg_attr(
        not(all(feature = "experimental-roaming", any(unix, windows))),
        allow(unused_mut)
    )]
    let mut socket = Arc::new(socket);

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
    let mut heartbeat_deadline = tokio::time::Instant::now()
        + crate::protocol::randomized_heartbeat_delay(
            heartbeat_interval,
            Duration::from_millis(hb_config.jitter_ms),
        );
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
    let mut quic_record = Vec::with_capacity(wire_capacity + udp_framing.wrapper_len());
    let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
    let mut oversize_tun_drops: u64 = 0;
    let mut udp_tx_recordizer = udp_recordizer_runtime
        .clone()
        .map(crate::protocol::recordizer::Recordizer::new);
    let mut udp_rx_recordizer =
        udp_recordizer_runtime.map(crate::protocol::recordizer::Reassembler::new);
    if udp_tx_recordizer.is_some() {
        log::info!("Packet recordizer: PACKET_MUX_V1 active on UDP");
        log::info!(
            "Recordizer batching: {} on UDP",
            if udp_recordizer_config
                .as_ref()
                .is_some_and(|mux| mux.batch.mode == "opportunistic")
            {
                "opportunistic"
            } else {
                "timed"
            }
        );
    }
    let mut tx_record_id: u64 = rand::random();
    let mut data_reassembler = crate::protocol::data_frag::DataReassembler::new();

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
    // DATA_FRAG decouples inner MTU from outer datagram size. Report the independently
    // certified uplink UDP payload budget as a distinct authenticated frame. A current server
    // treats it only as the ceiling for its own reverse DF probe and widens downlink after that
    // direction answers; an older server skips the unknown type.
    // An authenticated report also opts into server reverse confirmation. Keep it
    // absent when probing is explicitly disabled, including at the family base.
    let mut udp_payload_budget_report_value = (data_frag_enabled && config.tun.mtu_probe)
        .then(|| u16::try_from(uplink_udp_payload_budget).ok())
        .flatten();
    let client_info_frame = crate::protocol::ctrl::this_build();
    let mut udp_send_scratch = crate::transport_core::udp_batch::BatchScratch::new(
        crate::transport_core::udp_batch::MAX_BATCH,
    );
    macro_rules! send_udp_control {
        ($frame:expr) => {
            send_client_udp_control_frame(
                $frame,
                udp_tx_recordizer.as_mut(),
                &mut client_tx,
                &eff_obf,
                mux_payload_budget,
                data_record_budget,
                data_frag_enabled,
                &tx_data_frag_key,
                &mut tx_record_id,
                &socket,
                udp_framing,
                &mut quic_pn,
                &mut wire_record,
                &mut quic_record,
                &mut padding,
                &mut udp_send_scratch,
                &runtime_counters.udp.path,
            )
            .await
        };
    }

    // Arm retries from intent, not from the result of the first local send. A transient
    // socket loss must not leave the server without the path limits or the client build.
    let mut control_report_resends = if mtu_report_value.is_some()
        || udp_payload_budget_report_value.is_some()
        || client_info_frame.is_some()
    {
        UDP_CONTROL_REPORT_RESENDS
    } else {
        0
    };
    if let Some(budget) = udp_payload_budget_report_value {
        let frame = crate::protocol::ctrl::udp_payload_budget_report(budget);
        match send_udp_control!(&frame) {
            Ok(true) => log::debug!("reported UDP payload budget {budget} to the server"),
            Ok(false) => log::debug!("could not report UDP payload budget"),
            Err(error) => {
                log::debug!("could not recordize UDP payload budget report: {error}")
            }
        }
    }
    if let Some(mtu) = mtu_report_value {
        let frame = crate::protocol::ctrl::mtu_report(mtu);
        match send_udp_control!(&frame) {
            Ok(true) => log::debug!("reported tunnel MTU {mtu} to the server"),
            Ok(false) => log::debug!("could not report tunnel MTU"),
            Err(error) => log::debug!("could not recordize UDP MTU report: {error}"),
        }
    }

    // Tell the server which common-core build and platform we are. This uses the same
    // authenticated and negotiated PACKET_MUX path as ordinary data; sending a bare control
    // frame while the peer expects a recordizer envelope makes the server reject it.
    if let Some(frame) = client_info_frame.as_ref() {
        match send_udp_control!(frame) {
            Ok(true) => log::debug!("reported client version to the server"),
            Ok(false) => log::debug!("could not report client version"),
            Err(error) => log::debug!("could not recordize client version: {error}"),
        }
    }

    // Live PMTU adjustment is available only when DATA_FRAG decouples the TUN MTU from the
    // carrier datagram size. A legacy peer would require rebuilding the interface/routes.
    let mut last_path_diagnostic = std::time::Instant::now();
    let mut previous_path_diagnostic = runtime_counters.udp.path.snapshot();
    let live_mtu_reprobe_enabled = data_frag_enabled && config.tun.mtu_probe;
    let mut live_mtu_probe = LiveUdpMtuProbe::default();
    let mut udp_budget_revision = 0u64;
    let mut next_mtu_growth = tokio::time::Instant::now() + crate::protocol::pmtu::GROW_INTERVAL;
    let mut last_pmtu_data_activity = tokio::time::Instant::now();
    let mut live_mtu_due = tokio::time::interval(UDP_MTU_REPROBE_INTERVAL);
    live_mtu_due.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume interval's immediate first tick: startup probing just ran above.
    live_mtu_due.tick().await;
    live_mtu_due.reset_after(
        UDP_MTU_REPROBE_INTERVAL + Duration::from_millis(u64::from(rand::random::<u16>() % 1000)),
    );
    let mut live_mtu_tick = tokio::time::interval(UDP_MTU_REPROBE_TICK);
    live_mtu_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    live_mtu_tick.tick().await;

    // Handshake reception is complete. From here one dedicated reader keeps recvmsg moving
    // while this task performs decrypt/reassembly/TUN work. The bounded FIFO preserves packet
    // order and does not touch DATA_FRAG or either PMTU state machine.
    drop(recv_buf);
    // A channel slot is one variable-size batch, so dividing the old packet capacity by the
    // maximum batch size would collapse the common short-batch queue to four datagrams. Keep the
    // original message depth. This cannot create 128 full batches: each receive pump owns only
    // UDP_RECEIVE_QUEUE_PACKETS + 1 reusable datagram buffers, and that fixed recycler remains
    // the actual memory/datagram bound.
    let (received_tx, mut received_rx) =
        mpsc::channel(crate::transport_core::udp_receive::UDP_RECEIVE_QUEUE_PACKETS);
    let receive_queue = crate::transport_core::receive_queue::ReceiveQueue::new(
        runtime_counters.udp.receive_queue.clone(),
        "client UDP",
    );
    // Drained one datagram at a time by the receive arm below, exactly like the early-data
    // queue beside it: the arm's body is unchanged and still handles a single datagram.
    let mut pending_batch = std::collections::VecDeque::<ClientUdpReceivedDatagram>::new();
    let mut connection_tasks = crate::transport_core::tasks::TaskGroup::default();
    let tasks = connection_tasks.spawner();
    let mut udp_receive_task = spawn_client_udp_receive_pump(
        socket.clone(),
        0,
        received_tx.clone(),
        &tasks,
        receive_queue.clone(),
    );
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    if udp_handover_enabled {
        if let Some(path_controller) = linux_path_controller {
            tasks.spawn(roaming_linux::run(
                path_controller,
                tun_name.clone(),
                path_generation,
                tasks.clone(),
            ));
        }
    }
    let (_candidate_connect_tx, mut candidate_connect_rx) =
        mpsc::channel::<(PreparedPathCandidate, anyhow::Result<UdpSocket>)>(1);
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut candidate_connect_task: Option<crate::transport_core::tasks::TaskHandle> = None;
    let mut candidate_tick = tokio::time::interval(Duration::from_millis(100));
    candidate_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    candidate_tick.tick().await;
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let candidate_config = Arc::new(config.clone());
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut live_udp_candidate: Option<UdpClientLiveCandidate> = None;
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut draining_udp_path: Option<UdpClientDrainingPath> = None;
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut same_network_nat_recovery =
        crate::transport_core::udp_roaming_client::UdpClientNatRecoveryPolicy::default();
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut early_candidate_data = ClientUdpEarlyDataQueue::default();
    let mut committed_early_data = std::collections::VecDeque::<ClientUdpReceivedDatagram>::new();

    #[cfg(target_os = "linux")]
    if config.routing.exit_node {
        spawn_exit_wan_monitor(tun_name.clone(), &tasks);
    }

    let mut unsupported_inner_drops = 0u64;
    let mut result = Ok(());
    'udp: loop {
        let mux_deadline = udp_tx_recordizer
            .as_ref()
            .and_then(|mux| mux.deadline())
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            changed = management_rx.changed() => {
                if changed.is_err() { break; }
                let event = management_rx.borrow_and_update().clone();
                if let Some(event) = event {
                    if let Err(error) = apply_server_management(core, event) {
                        result = Err(error);
                        break;
                    }
                }
            }

            _ = cancel_tick.tick() => {
                if cancel.load(Ordering::Acquire) { break; }
            }

            _ = udp_buffer_tick.tick() => {
                if last_path_diagnostic.elapsed() >= Duration::from_secs(10) {
                    let current = runtime_counters.udp.path.snapshot();
                    if current != previous_path_diagnostic {
                        log::debug!("UDP path diagnostics: {}", serde_json::to_string(&current).expect("path diagnostics serialize"));
                        previous_path_diagnostic = current;
                    }
                    last_path_diagnostic = std::time::Instant::now();
                }
                udp_buffer.tick(socket.raw_socket());
            }

            _ = candidate_tick.tick(), if udp_handover_enabled => {
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                {
                let drain_expired = draining_udp_path
                    .as_ref()
                    .is_some_and(|draining| tokio::time::Instant::now() > draining.expires_at);
                if drain_expired {
                    let mut draining = draining_udp_path
                        .take()
                        .expect("expired UDP receive drain was present");
                    draining.receive_task.finish().await;
                    log::debug!(
                        "UDP receive drain expired for path epoch {}",
                        draining.epoch
                    );
                }
                let superseded = live_udp_candidate.as_ref().and_then(|candidate| {
                    (!path_controller
                        .as_deref()
                        .expect("enabled UDP handover retains path controller")
                        .candidate_is_current(candidate.prepared()))
                    .then_some(candidate.prepared().candidate_id)
                });
                if let Some(candidate_id) = superseded {
                    let candidate = live_udp_candidate
                        .take()
                        .expect("superseded candidate was present");
                    udp_roaming
                        .as_mut()
                        .expect("negotiated UDP handover retains roaming state")
                        .abort_candidate(candidate_id);
                    candidate.stop().await;
                    log::info!(
                        "UDP candidate {} superseded before validation completed",
                        candidate_id
                    );
                }
                if live_udp_candidate.is_some() {
                    let retry = udp_roaming
                        .as_mut()
                        .expect("negotiated UDP handover retains roaming state")
                        .retransmit_due(std::time::Instant::now());
                    match retry {
                        Ok(Some(transmit)) => {
                            let candidate_socket = live_udp_candidate
                                .as_ref()
                                .expect("candidate checked above")
                                .socket
                                .clone();
                            if let Err(error) = send_udp_path_transmit(
                                &candidate_socket,
                                &mut client_tx,
                                &mut quic_pn,
                                &transmit,
                            )
                            .await
                            {
                                let reason = format!("UDP candidate retransmit failed: {error}");
                                let candidate = live_udp_candidate
                                    .take()
                                    .expect("candidate checked above");
                                let prepared = candidate.prepared().clone();
                                udp_roaming
                                    .as_mut()
                                    .expect("negotiated UDP handover retains roaming state")
                                    .abort_candidate(prepared.candidate_id);
                                candidate.stop().await;
                                abort_udp_platform_candidate(
                                    path_controller
                                        .as_deref()
                                        .expect("enabled UDP handover retains path controller"),
                                    &prepared,
                                    &reason,
                                )
                                .await;
                                log::warn!(
                                    "UDP path candidate {} failed: {}",
                                    prepared.candidate_id,
                                    error
                                );
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let reason = format!("UDP candidate validation expired: {error}");
                            let candidate = live_udp_candidate
                                .take()
                                .expect("state candidate has a live socket candidate");
                            let prepared = candidate.prepared().clone();
                            udp_roaming
                                .as_mut()
                                .expect("negotiated UDP handover retains roaming state")
                                .abort_candidate(prepared.candidate_id);
                            candidate.stop().await;
                            abort_udp_platform_candidate(
                                path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller"),
                                &prepared,
                                &reason,
                            )
                            .await;
                            log::warn!(
                                "UDP path candidate {} expired: {}",
                                prepared.candidate_id,
                                error
                            );
                        }
                    }
                } else if candidate_connect_task.is_none() {
                    let path_controller = path_controller
                        .as_ref()
                        .expect("enabled UDP handover retains path controller");
                    if let Some(candidate) = path_controller.prepared_candidate() {
                        let config = candidate_config.clone();
                        let controller = path_controller.clone();
                        let outcome_tx = _candidate_connect_tx.clone();
                        candidate_connect_task = Some(tasks.spawn_owned(async move {
                            let timeout = Duration::from_secs(
                                config.server.connection_timeout_secs.max(1),
                            );
                            let result = connect_udp_path_candidate(
                                &config,
                                timeout,
                                &candidate,
                                controller.as_ref(),
                            )
                            .await;
                            let _ = outcome_tx.send((candidate, result)).await;
                        }));
                    }
                }
                if live_udp_candidate.is_none() {
                    early_candidate_data.clear();
                }
                }
            }

            connected = candidate_connect_rx.recv(), if udp_handover_enabled => {
                let _ = &connected;
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                {
                let Some((prepared, result)) = connected else { continue; };
                if let Some(mut task) = candidate_connect_task.take() {
                    task.finish().await;
                }
                let raw_candidate = match result {
                    Ok(socket) => socket,
                    Err(error) => {
                        let reason = format!("UDP candidate connect failed: {error}");
                        abort_udp_platform_candidate(
                            path_controller
                                .as_deref()
                                .expect("enabled UDP handover retains path controller"),
                            &prepared,
                            &reason,
                        )
                        .await;
                        log::warn!(
                            "UDP path candidate {} connect failed: {}",
                            prepared.candidate_id,
                            error
                        );
                        continue;
                    }
                };
                if !path_controller
                    .as_deref()
                    .expect("enabled UDP handover retains path controller")
                    .candidate_is_current(&prepared)
                {
                    log::info!(
                        "UDP candidate {} superseded while its socket was connecting",
                        prepared.candidate_id
                    );
                    drop(raw_candidate);
                    continue;
                }
                // Apply the same socket policy before PATH_INIT. The temporary controller may
                // drop after setsockopt; a fresh controller owns periodic tuning after COMMIT.
                let _ = UdpBufferController::configure(
                    &raw_candidate,
                    UdpBufferPolicy {
                        send_bytes: config.performance.send_buffer_size,
                        receive_bytes: config.performance.recv_buffer_size,
                        automatic_receive: config.performance.recv_buffer_auto,
                        max_receive_bytes: AUTO_MAX_RECV_BYTES,
                    },
                    runtime_counters.udp.clone(),
                    "client UDP candidate",
                );
                let candidate_socket = Arc::new(crate::protocol::obfs::ObfsUdp::new(
                    raw_candidate,
                    obfs_key,
                ));
                let transmit = match udp_roaming
                    .as_mut()
                    .expect("negotiated UDP handover retains roaming state")
                    .begin_candidate(prepared.candidate_id, rand::random(), std::time::Instant::now())
                {
                    Ok(transmit) => transmit,
                    Err(error) => {
                        let reason = format!("UDP candidate state rejected BIND: {error}");
                        abort_udp_platform_candidate(
                            path_controller
                                .as_deref()
                                .expect("enabled UDP handover retains path controller"),
                            &prepared,
                            &reason,
                        )
                        .await;
                        continue;
                    }
                };
                let epoch = udp_roaming
                    .as_ref()
                    .and_then(|roaming| roaming.candidate_epoch())
                    .expect("begin_candidate publishes its epoch");
                early_candidate_data.begin(epoch);
                let receive_task = spawn_client_udp_receive_pump(
                    candidate_socket.clone(),
                    epoch,
                    received_tx.clone(),
                    &tasks,
                    receive_queue.clone(),
                );
                live_udp_candidate = Some(UdpClientLiveCandidate::new(
                    prepared.clone(),
                    epoch,
                    candidate_socket.clone(),
                    receive_task,
                ));
                if let Err(error) = send_udp_path_transmit(
                    &candidate_socket,
                    &mut client_tx,
                    &mut quic_pn,
                    &transmit,
                )
                .await
                {
                    let reason = format!("UDP PATH_INIT send failed: {error}");
                    udp_roaming
                        .as_mut()
                        .expect("negotiated UDP handover retains roaming state")
                        .abort_candidate(prepared.candidate_id);
                    if let Some(candidate) = live_udp_candidate.take() {
                        candidate.stop().await;
                    }
                    abort_udp_platform_candidate(
                        path_controller
                            .as_deref()
                            .expect("enabled UDP handover retains path controller"),
                        &prepared,
                        &reason,
                    )
                    .await;
                } else {
                    log::info!(
                        "UDP PATH_INIT sent for candidate {} ({}) at epoch {}",
                        prepared.candidate_id,
                        prepared.update.platform_path_id,
                        epoch
                    );
                }
                }
            }
            _ = tokio::time::sleep_until(mux_deadline),
                if udp_tx_recordizer.as_ref().is_some_and(|mux| mux.is_pending()) =>
            {
                if let Some(payload) = udp_tx_recordizer
                    .as_mut()
                    .and_then(|mux| mux.flush_due(std::time::Instant::now()))
                {
                    let send_outcome = send_client_udp_payloads(
                        std::slice::from_ref(&payload),
                        &mut client_tx,
                        &eff_obf,
                        mux_payload_budget,
                        data_record_budget,
                        data_frag_enabled,
                        &tx_data_frag_key,
                        &mut tx_record_id,
                        &socket,
                        udp_framing,
                        &mut quic_pn,
                        &mut wire_record,
                        &mut quic_record,
                        &mut padding,
                        &mut udp_send_scratch,
                        &runtime_counters.udp.path,
                    )
                    .await;
                    match send_outcome {
                        ClientUdpPayloadSendOutcome::Sent => {}
                        ClientUdpPayloadSendOutcome::EncodeFailed => break 'udp,
                        ClientUdpPayloadSendOutcome::CarrierFailed => {
                            #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                            if udp_handover_enabled {
                                let path_controller = path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller");
                                let candidate_in_flight = live_udp_candidate.is_some()
                                    || candidate_connect_task.is_some()
                                    || path_controller.prepared_candidate().is_some();
                                if begin_udp_carrier_failure_recovery(
                                    &mut same_network_nat_recovery,
                                    udp_roaming
                                        .as_ref()
                                        .expect("enabled UDP handover retains roaming state"),
                                    path_controller,
                                    candidate_in_flight,
                                    "recordizer flush send",
                                ) {
                                    continue 'udp;
                                }
                            }
                            break 'udp;
                        }
                    }
                    last_activity = tokio::time::Instant::now();
                    last_tx_inst = last_activity;
                    heartbeat_deadline = tokio::time::Instant::now()
                        + crate::protocol::randomized_heartbeat_delay(
                            heartbeat_interval,
                            Duration::from_millis(hb_config.jitter_ms),
                        );
                }
            }

            _ = live_mtu_due.tick(), if live_mtu_reprobe_enabled => {
                // A long growth ladder must not postpone confirmation of the working size.
                if live_mtu_probe.is_active() && live_mtu_probe.confirmation {
                    continue;
                }
                if live_mtu_probe.is_active() {
                    live_mtu_probe.clear();
                    finish_mtu_probe(&socket, keep_df_after_live_probe);
                }
                // Do not keep idle phones awake solely for PMTU. The first user packet after
                // idle resets this timer below, so stale confirmation is checked promptly.
                if last_pmtu_data_activity.elapsed() > Duration::from_secs(30) {
                    continue;
                }
                let wrapper = socket.seal_overhead() + udp_framing.wrapper_len();
                let now = tokio::time::Instant::now();
                let mut grow = now >= next_mtu_growth;
                let mut candidates: Vec<i32> = if grow {
                    next_mtu_growth = now + crate::protocol::pmtu::GROW_INTERVAL;
                    let outer_overhead = UDP_RECORD_PROBE_OVERHEAD + wrapper + 8
                        + if socket.peer_is_ipv6() { 40 } else { 20 };
                    let ceiling = crate::protocol::pmtu::probe_ceiling(
                        base_mtu, outer_overhead,
                        crate::protocol::pmtu::socket_path_mtu(socket.raw_socket(), socket.peer_is_ipv6()),
                    );
                    mtu_probe_ladder(ceiling, outer_overhead, socket.peer_is_ipv6())
                        .into_iter()
                        .filter(|candidate| udp_payload_budget_for_probe(*candidate, socket.seal_overhead(), udp_framing.wrapper_len()) > uplink_udp_payload_budget)
                        .collect()
                } else {
                    crate::protocol::pmtu::confirmation_budgets(
                        uplink_udp_payload_budget,
                        crate::protocol::data_frag::conservative_udp_payload_budget(socket.peer_is_ipv6()),
                    ).into_iter().filter_map(|budget| {
                        budget.checked_sub(wrapper + UDP_RECORD_PROBE_OVERHEAD)
                            .and_then(|value| i32::try_from(value).ok())
                    }).collect()
                };
                if grow && !candidates.is_empty() {
                    // The current certified size closes the bottom of the growth bracket.
                    if let Some(current) = uplink_udp_payload_budget.checked_sub(wrapper + UDP_RECORD_PROBE_OVERHEAD)
                        .and_then(|value| i32::try_from(value).ok())
                    {
                        candidates.push(current);
                    }
                }
                if candidates.is_empty() {
                    // Reaching the ceiling must not skip this confirmation window.
                    grow = false;
                    candidates = crate::protocol::pmtu::confirmation_budgets(
                        uplink_udp_payload_budget,
                        crate::protocol::data_frag::conservative_udp_payload_budget(socket.peer_is_ipv6()),
                    ).into_iter().filter_map(|budget| {
                        budget.checked_sub(wrapper + UDP_RECORD_PROBE_OVERHEAD)
                            .and_then(|value| i32::try_from(value).ok())
                    }).collect();
                }
                if !candidates.is_empty() && begin_mtu_probe(&socket) {
                    #[cfg(feature = "experimental-roaming")]
                    let active_path_epoch = udp_roaming.as_ref().map(|state| state.active_epoch()).unwrap_or(0);
                    #[cfg(not(feature = "experimental-roaming"))]
                    let active_path_epoch = 0;
                    live_mtu_probe.path_epoch = active_path_epoch;
                    live_mtu_probe.budget_revision = udp_budget_revision;
                    live_mtu_probe.confirmation = !grow;
                    live_mtu_probe.start(candidates);
                }
            }

            _ = live_mtu_tick.tick(), if live_mtu_reprobe_enabled && live_mtu_probe.is_active() => {
                if let Some((probe_token, candidate)) =
                    live_mtu_probe.next_send(tokio::time::Instant::now())
                {
                    if let Some(probe) = crate::protocol::udp_frag::mtu_probe_v2_datagram(
                        probe_token,
                        candidate.max(0) as usize + UDP_RECORD_PROBE_OVERHEAD,
                    ) {
                        let send_data =
                            crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                udp_framing,
                                &probe,
                                &mut quic_pn,
                                &mut quic_record,
                            );
                        if let Err(error) = socket.send(send_data).await {
                            log::trace!("UDP live PMTU probe send failed: {error}");
                        }
                    }
                }
                if !live_mtu_probe.is_active() {
                    // No size was confirmed. This is not evidence of an MTU-only failure;
                    // preserve the budget and let ordinary path liveness recover an outage.
                    finish_mtu_probe(&socket, keep_df_after_live_probe);
                    log::debug!(
                        "UDP live PMTU search unconfirmed; keeping {}-byte budget",
                        uplink_udp_payload_budget,
                    );
                }
            }

            packet = tun_pump.recv_from_tun() => {
                if last_pmtu_data_activity.elapsed() > Duration::from_secs(30) {
                    live_mtu_due.reset_immediately();
                }
                last_pmtu_data_activity = tokio::time::Instant::now();
                let Some(ip_packet) = packet else {
                    log::warn!("UDP: TUN reader stopped — reconnecting");
                    break;
                };
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                if udp_handover_enabled {
                    let active_epoch = udp_roaming
                        .as_ref()
                        .expect("enabled UDP handover retains roaming state")
                        .active_epoch();
                    let now = std::time::Instant::now();
                    if same_network_nat_recovery.recovery_pending(active_epoch, now) {
                        // The old carrier is known dead. Bound memory/CPU by dropping current
                        // uplink while PATH_INIT/COMMIT establishes the replacement socket.
                        continue;
                    }
                    if same_network_nat_recovery.recovery_expired(active_epoch, now) {
                        log::warn!("UDP replacement-path grace expired; reconnecting");
                        break;
                    }
                }
                if !is_supported_inner_packet(ip_packet.as_ref(), negotiated_family_mode) {
                    unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                    udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                    if unsupported_inner_drops.is_power_of_two() {
                        log::debug!(
                            "UDP client dropped invalid or non-negotiated-family inner packet (total {})",
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
                heartbeat_deadline = tokio::time::Instant::now()
                    + crate::protocol::randomized_heartbeat_delay(
                        heartbeat_interval,
                        Duration::from_millis(hb_config.jitter_ms),
                    );
                if let Some(mux) = udp_tx_recordizer.as_mut() {
                    let mut payloads = match mux.push(
                        ip_packet.as_ref(),
                        std::time::Instant::now(),
                    ) {
                        Ok(payloads) => payloads,
                        Err(error) => {
                            log::debug!("client UDP recordizer dropped a packet: {error}");
                            continue;
                        }
                    };
                    drop(ip_packet);
                    // The first packet was awaited by select. Drain only packets immediately
                    // available from the TUN backend, bounded to one socket batch. This adds no
                    // coalescing timer and keeps cancellation/roaming latency bounded, while
                    // giving sendmmsg real work instead of one record at a time.
                    let mut drained_packets = 1usize;
                    let mut tun_disconnected = false;
                    while drained_packets < crate::transport_core::udp_batch::MAX_BATCH {
                        let next_packet = match tun_pump.try_recv_from_tun() {
                            Ok(packet) => packet,
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                tun_disconnected = true;
                                break;
                            }
                        };
                        drained_packets += 1;
                        if !is_supported_inner_packet(
                            next_packet.as_ref(),
                            negotiated_family_mode,
                        ) {
                            unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                            udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                            if unsupported_inner_drops.is_power_of_two() {
                                log::debug!(
                                    "UDP client dropped invalid or non-negotiated-family inner packet (total {})",
                                    unsupported_inner_drops
                                );
                            }
                            continue;
                        }
                        if mtu != 0 && next_packet.len() > mtu {
                            oversize_tun_drops = oversize_tun_drops.saturating_add(1);
                            udp_buffer.note_internal_drop(InternalDrop::Oversize);
                            if oversize_tun_drops.is_power_of_two() {
                                log::warn!(
                                    "UDP client dropped inner packet larger than tunnel MTU: {} > {} bytes (total {})",
                                    next_packet.len(), mtu, oversize_tun_drops
                                );
                            }
                            continue;
                        }
                        trace::record(trace::Dir::Tx, "client.udp", next_packet.len(), 0);
                        runtime_counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                        runtime_counters
                            .tx_bytes
                            .fetch_add(next_packet.len() as u64, Ordering::Relaxed);
                        last_activity = tokio::time::Instant::now();
                        last_tx_inst = last_activity;
                        heartbeat_deadline = tokio::time::Instant::now()
                            + crate::protocol::randomized_heartbeat_delay(
                                heartbeat_interval,
                                Duration::from_millis(hb_config.jitter_ms),
                            );
                        match mux.push(next_packet.as_ref(), std::time::Instant::now()) {
                            Ok(ready) => payloads.extend(ready),
                            Err(error) => {
                                log::debug!("client UDP recordizer dropped a packet: {error}");
                            }
                        }
                    }
                    if let Some(payload) = mux.finish_ready_batch() { payloads.push(payload); }
                    let send_outcome = send_client_udp_payloads(
                        &payloads,
                        &mut client_tx,
                        &eff_obf,
                        mux_payload_budget,
                        data_record_budget,
                        data_frag_enabled,
                        &tx_data_frag_key,
                        &mut tx_record_id,
                        &socket,
                        udp_framing,
                        &mut quic_pn,
                        &mut wire_record,
                        &mut quic_record,
                        &mut padding,
                        &mut udp_send_scratch,
                        &runtime_counters.udp.path,
                    )
                    .await;
                    match send_outcome {
                        ClientUdpPayloadSendOutcome::Sent => {}
                        ClientUdpPayloadSendOutcome::EncodeFailed => break 'udp,
                        ClientUdpPayloadSendOutcome::CarrierFailed => {
                            #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                            if udp_handover_enabled {
                                let path_controller = path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller");
                                let candidate_in_flight = live_udp_candidate.is_some()
                                    || candidate_connect_task.is_some()
                                    || path_controller.prepared_candidate().is_some();
                                if begin_udp_carrier_failure_recovery(
                                    &mut same_network_nat_recovery,
                                    udp_roaming
                                        .as_ref()
                                        .expect("enabled UDP handover retains roaming state"),
                                    path_controller,
                                    candidate_in_flight,
                                    "recordizer data send",
                                ) {
                                    continue 'udp;
                                }
                            }
                            break 'udp;
                        }
                    }
                    if tun_disconnected {
                        log::warn!("UDP: TUN reader stopped — reconnecting");
                        break 'udp;
                    }
                    continue;
                }
                let encrypted = {
                    let mut obf = Obfuscator::new();
                    let normalization_padding = if eff_obf.traffic_normalization.enabled
                        && !norm_sizes.is_empty()
                    {
                        Obfuscator::normalization_padding_len(ip_packet.len(), norm_sizes, mtu)
                    } else {
                        0
                    };
                    // Clamp padding so the whole record (data + padding) stays within the
                    // DISCOVERED/pushed tunnel MTU. The path-MTU probe certifies that a
                    // datagram of `tun_mtu + REC_OVERHEAD(48)` fits, and the real record adds
                    // only 43 (header+nonce+counter+padlen+tag) + the QUIC/obfs wrappers — so
                    // keeping data+padding <= tun_mtu leaves margin for all of it. Mirrors the
                    // C#/Kotlin `EncryptCapped(pkt, effectiveMtu)`. The old code used a literal
                    // 1400 (ignoring a smaller probed MTU on LTE/CGNAT — full-size padded
                    // uplink packets were then silently dropped with EMSGSIZE under DF) and a
                    // `+60` overhead that under-counted obfs+quic (65) by 5 bytes.
                    let pad_cap = (padding_max as usize).min(
                        mtu.saturating_sub(ip_packet.len().saturating_add(normalization_padding)),
                    ) as u16;
                    obf.generate_padding_opts_into(
                        padding_enabled,
                        padding_min,
                        pad_cap,
                        padding_randomize,
                        padding_prob,
                        &mut padding,
                    );
                    if eff_obf.traffic_normalization.enabled && !norm_sizes.is_empty() {
                        obf.append_normalization_padding_into(
                            ip_packet.len(),
                            norm_sizes,
                            mtu,
                            &mut padding,
                        );
                    }
                    client_tx
                        .encrypt_packet_into(ip_packet.as_ref(), &padding, &mut wire_record)
                        .is_ok()
                };
                // Encryption has copied the plaintext into its wire record; return the TUN
                // allocation before any socket-send await below.
                drop(ip_packet);
                if encrypted {
                    if data_frag_enabled && wire_record.len() > data_record_budget {
                        let record_id = tx_record_id;
                        tx_record_id = tx_record_id.wrapping_add(1);
                        let fragments = match crate::protocol::data_frag::fragment_record(
                            &wire_record,
                            &tx_data_frag_key,
                            record_id,
                            data_record_budget - crate::protocol::data_frag::HEADER_LEN,
                        ) {
                            Ok(fragments) => fragments,
                            Err(error) => {
                                log::warn!("UDP data fragmentation failed: {error}");
                                break;
                            }
                        };
                        runtime_counters.udp.path.note_fragmentation(fragments.len());
                        // Fragments of one record are the only uplink datagrams already
                        // available as a group — the pacing/shaping loop emits every other
                        // packet as it arrives. Send them in one `sendmmsg`; a short write is
                        // normal there, so the remainder is retried rather than assumed sent.
                        let mut send_failed = None;
                        let mut wire: Vec<Vec<u8>> = Vec::with_capacity(fragments.len());
                        for fragment in fragments {
                            wire.push(
                                crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                    udp_framing,
                                    &fragment,
                                    &mut quic_pn,
                                    &mut quic_record,
                                )
                                .to_vec(),
                            );
                        }
                        let mut offset = 0;
                        while offset < wire.len() {
                            let chunk: Vec<&[u8]> = wire[offset..]
                                .iter()
                                .map(|datagram| datagram.as_slice())
                                .collect();
                            match socket.send_batch(&chunk, &mut udp_send_scratch).await {
                                Ok(0) => {
                                    send_failed = Some(std::io::Error::new(
                                        std::io::ErrorKind::WriteZero,
                                        "UDP socket accepted no fragment of the record",
                                    ));
                                    break;
                                }
                                Ok(sent) => offset += sent,
                                Err(error) => {
                                    send_failed = Some(error);
                                    break;
                                }
                            }
                        }
                        if let Some(error) = send_failed {
                            log::warn!("UDP carrier fragment send failed: {error}");
                            #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                            if udp_handover_enabled {
                                let path_controller = path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller");
                                let candidate_in_flight = live_udp_candidate.is_some()
                                    || candidate_connect_task.is_some()
                                    || path_controller.prepared_candidate().is_some();
                                if begin_udp_carrier_failure_recovery(
                                    &mut same_network_nat_recovery,
                                    udp_roaming
                                        .as_ref()
                                        .expect("enabled UDP handover retains roaming state"),
                                    path_controller,
                                    candidate_in_flight,
                                    "fragment send",
                                ) {
                                    continue 'udp;
                                }
                            }
                            break;
                        }
                    } else {
                        let send_data =
                            crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                udp_framing,
                                &wire_record,
                                &mut quic_pn,
                                &mut quic_record,
                            );
                        if let Err(error) = socket.send(send_data).await {
                            log::warn!("UDP carrier send failed: {error}");
                            #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                            if udp_handover_enabled {
                                let path_controller = path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller");
                                let candidate_in_flight = live_udp_candidate.is_some()
                                    || candidate_connect_task.is_some()
                                    || path_controller.prepared_candidate().is_some();
                                if begin_udp_carrier_failure_recovery(
                                    &mut same_network_nat_recovery,
                                    udp_roaming
                                        .as_ref()
                                        .expect("enabled UDP handover retains roaming state"),
                                    path_controller,
                                    candidate_in_flight,
                                    "data send",
                                ) {
                                    continue 'udp;
                                }
                            }
                            break;
                        }
                    }
                }
            }

            received = async {
                if let Some(buffered) = committed_early_data.pop_front() {
                    Some(buffered)
                } else if let Some(next) = pending_batch.pop_front() {
                    Some(next)
                } else {
                    match received_rx.recv().await {
                        Some(batch) => {
                            pending_batch.extend(batch.into_inner());
                            pending_batch.pop_front()
                        }
                        None => None,
                    }
                }
            } => {
                #[cfg_attr(
                    not(feature = "experimental-roaming"),
                    allow(unused_mut)
                )]
                let Some(mut recv_buf) = received else {
                    break;
                };
                #[cfg(feature = "experimental-roaming")]
                let active_path_epoch = udp_roaming
                    .as_ref()
                    .map(|roaming| roaming.active_epoch())
                    .unwrap_or(0);
                #[cfg(not(feature = "experimental-roaming"))]
                let active_path_epoch = 0;

                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                let draining_path_epoch = draining_udp_path.as_ref().and_then(|draining| {
                    (tokio::time::Instant::now() <= draining.expires_at).then_some(draining.epoch)
                });
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                let receive_path = classify_client_udp_receive_path(
                    active_path_epoch,
                    live_udp_candidate
                        .as_ref()
                        .map(|candidate| candidate.epoch),
                    draining_path_epoch,
                    recv_buf.path_epoch,
                );
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                if receive_path == ClientUdpReceivePath::Candidate {
                    let candidate_matches = live_udp_candidate.as_ref().is_some_and(|candidate| {
                        candidate.epoch == recv_buf.path_epoch
                            && path_controller
                                .as_deref()
                                .expect("candidate receive retains path controller")
                                .candidate_is_current(candidate.prepared())
                            && udp_roaming.as_ref().is_some_and(|roaming| {
                                roaming.candidate_epoch() == Some(candidate.epoch)
                                    && roaming.candidate_id()
                                        == Some(candidate.prepared().candidate_id)
                            })
                    });
                    if !candidate_matches {
                        continue;
                    }
                    let n = recv_buf.len();
                    let (candidate_header, candidate_payload) =
                        match crate::protocol::roaming::decode_udp_short(&recv_buf[..n]) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                log::debug!("UDP candidate outer header rejected: {error}");
                                continue;
                            }
                        };
                    let candidate_cid_matches = udp_roaming.as_ref().is_some_and(|roaming| {
                        roaming.candidate_receive_cid()
                            == Some(candidate_header.destination_cid())
                    });
                    if !candidate_cid_matches {
                        continue;
                    }
                    if crate::protocol::data_frag::is_data_fragment(candidate_payload) {
                        if !data_frag_enabled {
                            continue;
                        }
                        if !early_candidate_data.push(recv_buf) {
                            log::error!(
                                "UDP candidate DATA_FRAG reorder window exceeded; reconnecting"
                            );
                            break 'udp;
                        }
                        continue;
                    }
                    let packet = match crate::transport_core::udp_roaming_client::decrypt_authenticated_packet(
                        &mut client_rx,
                        &recv_buf[..n],
                    ) {
                        Ok(packet) => packet,
                        Err(error) => {
                            log::debug!("UDP candidate wire/decrypt rejected: {error}");
                            continue;
                        }
                    };
                    let control = match crate::transport_core::udp_roaming_client::decode_authenticated_path_control(&packet) {
                        Ok(Some(control)) => control,
                        Ok(None) => {
                            recv_buf.authenticated_plaintext = Some(packet.into_plaintext());
                            if !early_candidate_data.push(recv_buf) {
                                log::error!(
                                    "UDP candidate DATA reorder window exceeded; reconnecting"
                                );
                                break 'udp;
                            }
                            // Publish only after the authenticated PATH_COMMIT and platform
                            // COMMIT_PATH have made this candidate the active path.
                            continue;
                        }
                        Err(error) => {
                            log::debug!("UDP candidate control rejected: {error}");
                            continue;
                        }
                    };
                    let action = match udp_roaming
                        .as_mut()
                        .expect("candidate packet retains roaming state")
                        .accept_authenticated_control(
                            packet.destination_cid(),
                            control.message_id(),
                            control.control(),
                            std::time::Instant::now(),
                        )
                    {
                        Ok(action) => action,
                        Err(error) => {
                            log::debug!("UDP candidate state rejected control: {error}");
                            let candidate_id = live_udp_candidate
                                .as_ref()
                                .expect("candidate receive retains live socket")
                                .prepared()
                                .candidate_id;
                            let state_still_matches = udp_roaming
                                .as_ref()
                                .and_then(|roaming| roaming.candidate_id())
                                == Some(candidate_id);
                            if !state_still_matches {
                                let candidate = live_udp_candidate
                                    .take()
                                    .expect("candidate receive retains live socket");
                                let prepared = candidate.prepared().clone();
                                candidate.stop().await;
                                let reason = format!("UDP candidate state expired: {error}");
                                abort_udp_platform_candidate(
                                    path_controller
                                        .as_deref()
                                        .expect("candidate receive retains path controller"),
                                    &prepared,
                                    &reason,
                                )
                                .await;
                            }
                            continue;
                        }
                    };
                    match action {
                        crate::transport_core::udp_roaming_client::UdpClientPathAction::Transmit(transmit) => {
                            let candidate_socket = live_udp_candidate
                                .as_ref()
                                .expect("candidate action retains live socket")
                                .socket
                                .clone();
                            if let Err(error) = send_udp_path_transmit(
                                &candidate_socket,
                                &mut client_tx,
                                &mut quic_pn,
                                &transmit,
                            )
                            .await
                            {
                                let reason = format!("UDP PATH_RESPONSE send failed: {error}");
                                let candidate = live_udp_candidate
                                    .take()
                                    .expect("candidate action retains live socket");
                                let prepared = candidate.prepared().clone();
                                udp_roaming
                                    .as_mut()
                                    .expect("candidate action retains roaming state")
                                    .abort_candidate(prepared.candidate_id);
                                candidate.stop().await;
                                abort_udp_platform_candidate(
                                    path_controller
                                        .as_deref()
                                        .expect("enabled UDP handover retains path controller"),
                                    &prepared,
                                    &reason,
                                )
                                .await;
                            }
                        }
                        crate::transport_core::udp_roaming_client::UdpClientPathAction::CommitReady(commit) => {
                            let candidate = live_udp_candidate
                                .as_ref()
                                .expect("commit action retains live socket");
                            let prepared = candidate.prepared().clone();
                            if commit.candidate_id() != candidate.prepared().candidate_id
                                || commit.epoch() != candidate.epoch
                            {
                                log::error!("UDP candidate commit identity mismatch — reconnecting");
                                break 'udp;
                            }
                            if !path_controller
                                .as_deref()
                                .expect("candidate commit retains path controller")
                                .candidate_is_current(&prepared)
                            {
                                let candidate = live_udp_candidate
                                    .take()
                                    .expect("superseded commit candidate was present");
                                udp_roaming
                                    .as_mut()
                                    .expect("superseded commit retains roaming state")
                                    .abort_candidate(prepared.candidate_id);
                                candidate.stop().await;
                                log::info!(
                                    "UDP candidate {} superseded before platform commit",
                                    prepared.candidate_id
                                );
                                continue 'udp;
                            }
                            let next_payload_budget =
                                crate::protocol::data_frag::conservative_udp_payload_budget(
                                    candidate.socket.peer_is_ipv6(),
                                );
                            let next_record_budget = match crate::protocol::data_frag::unfragmented_record_budget_with_wrapper(
                                next_payload_budget,
                                candidate.socket.seal_overhead(),
                                crate::protocol::roaming::UDP_SHORT_HEADER_LEN,
                            ) {
                                Ok(budget) => budget,
                                Err(error) => {
                                    log::error!("UDP candidate conservative budget is invalid after PATH_COMMIT: {error}");
                                    break 'udp;
                                }
                            };
                            let next_padding_budget = match client_tx
                                .max_padding_for_record_budget(0, next_record_budget)
                            {
                                Ok(budget) => budget,
                                Err(error) => {
                                    log::error!("UDP candidate control budget is invalid after PATH_COMMIT: {error}");
                                    break 'udp;
                                }
                            };
                            let platform_commit = match path_controller
                                .as_deref()
                                .expect("enabled UDP handover retains path controller")
                                .commit_candidate_path(&prepared)
                            {
                                Ok(commit) => commit,
                                Err(error) => {
                                    log::error!("could not start UDP COMMIT_PATH after peer commit: {error}; reconnecting");
                                    break 'udp;
                                }
                            };
                            match tokio::time::timeout(PATH_ACK_TIMEOUT, platform_commit).await {
                                Ok(Ok(())) => {}
                                Ok(Err(error)) => {
                                    log::error!("UDP COMMIT_PATH failed after peer commit for candidate {}: {}; reconnecting", prepared.candidate_id, error);
                                    break 'udp;
                                }
                                Err(_) => {
                                    log::error!("UDP COMMIT_PATH timed out after peer commit for candidate {}; reconnecting", prepared.candidate_id);
                                    break 'udp;
                                }
                            }
                            if let Err(error) = udp_roaming
                                .as_mut()
                                .expect("commit action retains roaming state")
                                .commit_candidate(commit)
                            {
                                // Platform state already committed. The only safe recovery is a
                                // top-level reconnect, never publishing a mismatched actor state.
                                log::error!("UDP state publication failed after platform COMMIT: {error}");
                                break 'udp;
                            }
                            // The accepted PATH_COMMIT is authenticated server ingress on the new
                            // mapping. It ends same-network dead-mapping recovery and establishes a
                            // fresh RX-liveness baseline without waiting for an ordinary data record.
                            last_activity = tokio::time::Instant::now();
                            last_rx_inst = last_activity;
                            #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                            same_network_nat_recovery.on_authenticated_commit();
                            let roaming = udp_roaming
                                .as_ref()
                                .expect("committed UDP handover retains roaming state");
                            let next_framing =
                                crate::transport_core::udp_client_framing::UdpClientFraming::roaming(
                                    *roaming.active_transmit_cid(),
                                    *roaming.active_receive_cid(),
                                );
                            let candidate = live_udp_candidate
                                .take()
                                .expect("committed candidate retains live socket");
                            let (prepared, next_socket, next_receive_task) = candidate.into_active();
                            if let Some(mut previous) = draining_udp_path.take() {
                                previous.receive_task.finish().await;
                            }
                            let old_receive_task =
                                std::mem::replace(&mut udp_receive_task, next_receive_task);
                            draining_udp_path = Some(UdpClientDrainingPath {
                                epoch: active_path_epoch,
                                framing: udp_framing,
                                expires_at: tokio::time::Instant::now()
                                    + crate::protocol::data_frag::REASSEMBLY_TIMEOUT,
                                receive_task: old_receive_task,
                            });
                            socket = next_socket;
                            udp_framing = next_framing;
                            let Some(mut buffered) =
                                early_candidate_data.take_committed(commit.epoch())
                            else {
                                log::error!(
                                    "UDP candidate reorder buffer epoch mismatch after commit"
                                );
                                break 'udp;
                            };
                            committed_early_data.append(&mut buffered);
                            udp_buffer = UdpBufferController::configure(
                                socket.raw_socket(),
                                UdpBufferPolicy {
                                    send_bytes: config.performance.send_buffer_size,
                                    receive_bytes: config.performance.recv_buffer_size,
                                    automatic_receive: config.performance.recv_buffer_auto,
                                    max_receive_bytes: AUTO_MAX_RECV_BYTES,
                                },
                                runtime_counters.udp.clone(),
                                "client UDP migrated",
                            );
                            udp_budget_revision = udp_budget_revision.wrapping_add(1);
                            next_mtu_growth = tokio::time::Instant::now();
                            uplink_udp_payload_budget = next_payload_budget;
                            runtime_counters.udp.path.set(tun_mtu as u32, next_payload_budget, data_frag_enabled, "fallback", Some("path_changed"));
                            data_record_budget = next_record_budget;
                            max_empty_record_padding = next_padding_budget;
                            udp_payload_budget_report_value = None;
                            keep_df_after_live_probe = false;
                            live_mtu_probe.clear();
                            finish_mtu_probe(&socket, false);
                            live_mtu_due = tokio::time::interval(UDP_MTU_REPROBE_INTERVAL);
                            live_mtu_due
                                .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            log::info!(
                                "UDP make-before-break committed candidate {} ({}) at epoch {}",
                                prepared.candidate_id,
                                prepared.update.platform_path_id,
                                roaming.active_epoch()
                            );
                        }
                        crate::transport_core::udp_roaming_client::UdpClientPathAction::PeerAbort {
                            candidate_id,
                            code,
                        } => {
                            let candidate = live_udp_candidate.take();
                            let Some(candidate) = candidate else { continue; };
                            if candidate.prepared().candidate_id != candidate_id {
                                continue;
                            }
                            let prepared = candidate.prepared().clone();
                            candidate.stop().await;
                            let reason = format!("server rejected UDP candidate with code {code}");
                            abort_udp_platform_candidate(
                                path_controller
                                    .as_deref()
                                    .expect("enabled UDP handover retains path controller"),
                                &prepared,
                                &reason,
                            )
                            .await;
                            log::warn!("UDP candidate {} rejected by server", candidate_id);
                        }
                    }
                    continue;
                }
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                let draining_framing = draining_udp_path.as_ref().and_then(|draining| {
                    (receive_path == ClientUdpReceivePath::Draining
                        && draining.epoch == recv_buf.path_epoch
                        && tokio::time::Instant::now() <= draining.expires_at)
                        .then_some(draining.framing)
                });
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                if receive_path == ClientUdpReceivePath::Stale {
                    continue;
                }
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                if let Some(plaintext) = recv_buf.authenticated_plaintext.take() {
                    udp_buffer.note_receive(recv_buf.len());
                    last_activity = tokio::time::Instant::now();
                    last_rx_inst = last_activity;
                    if !deliver_buffered_udp_plaintext(
                        plaintext,
                        &mut udp_rx_recordizer,
                        &tun_write_tx,
                        negotiated_family_mode,
                        runtime_counters.as_ref(),
                        &udp_buffer,
                        &mut unsupported_inner_drops,
                    ) {
                        break 'udp;
                    }
                    continue;
                }
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                let receive_framing = draining_framing.unwrap_or(udp_framing);
                #[cfg(not(all(feature = "experimental-roaming", any(unix, windows))))]
                let receive_framing = udp_framing;
                let n = recv_buf.len();
                if recv_buf.path_epoch == active_path_epoch { udp_buffer.note_receive(n); }
                let payload = match receive_framing.unwrap(&recv_buf[..n]) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                let receive_is_draining = recv_buf.path_epoch != active_path_epoch;
                // The periodic uplink PMTU state machine shares this receive loop. Consume
                // only an exact echo of its current challenge; stale/foreign ACKs continue
                // through the normal authenticated packet path and are rejected there.
                if let Some((probe_token, probe_size)) =
                    crate::protocol::udp_frag::parse_mtu_probe_v2_ack(payload)
                {
                    let matches_live_challenge = !receive_is_draining && live_mtu_probe.matches(
                        probe_token, probe_size, active_path_epoch, udp_budget_revision,
                    );
                    if matches_live_challenge {
                        if let Some(candidate) =
                            live_mtu_probe.acknowledge(probe_token, probe_size)
                        {
                            let new_payload_budget = udp_payload_budget_for_probe(
                                candidate,
                                socket.seal_overhead(),
                                udp_framing.wrapper_len(),
                            );
                            let new_record_budget =
                                crate::protocol::data_frag::unfragmented_record_budget_with_wrapper(
                                    new_payload_budget,
                                    socket.seal_overhead(),
                                    udp_framing.wrapper_len(),
                                );
                            let new_padding_budget = new_record_budget.as_ref().ok().and_then(
                                |budget| {
                                    client_tx
                                        .max_padding_for_record_budget(0, *budget)
                                        .ok()
                                },
                            );
                            let new_mux_payload_budget = new_record_budget
                                .as_ref()
                                .ok()
                                .and_then(|budget| {
                                    client_tx.max_data_for_record_budget(*budget).ok()
                                });
                            match (
                                new_record_budget,
                                new_padding_budget,
                                new_mux_payload_budget,
                            ) {
                                (Ok(record_budget), Some(padding_budget), Some(new_mux_budget)) => {
                                    if new_mux_budget > mux_payload_budget {
                                        if let (Some(mux), Some(config)) =
                                            (udp_tx_recordizer.as_mut(), udp_recordizer_config.as_ref())
                                        {
                                            let runtime = crate::protocol::recordizer::RuntimeConfig::from_config(
                                                config,
                                                new_mux_budget,
                                                crate::protocol::packet::MAX_TUNNEL_MTU,
                                            )
                                            .expect("validated UDP recordizer configuration");
                                            mux.raise_runtime(runtime).expect(
                                                "certified UDP PMTU only raises the recordizer budget",
                                            );
                                            log::info!(
                                                "UDP recordizer widened client payload budget from {} to {} bytes",
                                                mux_payload_budget,
                                                new_mux_budget
                                            );
                                        }
                                        mux_payload_budget = new_mux_budget;
                                    }
                                    let decreased = new_payload_budget < uplink_udp_payload_budget;
                                    let changed = new_payload_budget != uplink_udp_payload_budget;
                                    if changed {
                                        udp_budget_revision = udp_budget_revision.wrapping_add(1);
                                    }
                                    if decreased {
                                        next_mtu_growth = tokio::time::Instant::now() + crate::protocol::pmtu::GROW_INTERVAL;
                                    }
                                    uplink_udp_payload_budget = new_payload_budget;
                                    runtime_counters.udp.path.set(tun_mtu as u32, new_payload_budget, data_frag_enabled, "probe", decreased.then_some("current_size_unconfirmed"));
                                    data_record_budget = record_budget;
                                    max_empty_record_padding = padding_budget;
                                    let report = u16::try_from(new_payload_budget).ok();
                                    if udp_payload_budget_report_value != report {
                                        control_report_resends = UDP_CONTROL_REPORT_RESENDS;
                                    }
                                    udp_payload_budget_report_value = report;
                                    keep_df_after_live_probe = true;
                                    finish_mtu_probe(&socket, true);
                                    if changed {
                                        log::info!(
                                            "UDP live PMTU changed uplink payload budget to {} bytes (probe rung {}, revision {})",
                                            new_payload_budget, candidate, udp_budget_revision,
                                        );
                                    }
                                }
                                (Err(error), _, _) => {
                                    finish_mtu_probe(&socket, keep_df_after_live_probe);
                                    log::warn!(
                                        "UDP live PMTU result could not form a data budget: {error}"
                                    );
                                }
                                (Ok(_), _, _) => {
                                    finish_mtu_probe(&socket, keep_df_after_live_probe);
                                    log::warn!(
                                        "UDP live PMTU result cannot carry authenticated control traffic"
                                    );
                                }
                            }
                        }
                        // The ACK is bare carrier control, not a PacketCodec record. Partial
                        // confirmations prepare a fresh random challenge for the timer branch.
                        continue;
                    }
                }
                // A current server never derives its downlink budget from the opposite
                // client-to-server path. It sends a full-size DF probe of its own and widens
                // only after this tiny echo returns. Handle it before DATA_FRAG/PacketCodec:
                // the probe is deliberately a bare carrier record, just like the original
                // uplink PMTU exchange. It does not count as authenticated liveness.
                if data_frag_enabled && !receive_is_draining {
                    if let Some((probe_token, probe_size)) =
                        crate::protocol::udp_frag::parse_mtu_probe_v2_request(payload)
                    {
                        let ack = crate::protocol::udp_frag::mtu_probe_v2_ack_datagram(
                            probe_token,
                            probe_size,
                        );
                        let send_data =
                            crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                udp_framing,
                                &ack,
                                &mut quic_pn,
                                &mut quic_record,
                            );
                        if let Err(error) = socket.send(send_data).await {
                            log::debug!("could not acknowledge server UDP path probe V2: {error}");
                        }
                        continue;
                    }

                    if let Some((probe_id, probe_size)) =
                        crate::protocol::udp_frag::parse_mtu_probe_request(payload)
                    {
                        let ack = crate::protocol::udp_frag::mtu_probe_ack_datagram(
                            probe_id,
                            probe_size,
                        );
                        let send_data =
                            crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                udp_framing,
                                &ack,
                                &mut quic_pn,
                                &mut quic_record,
                            );
                        if let Err(error) = socket.send(send_data).await {
                            log::debug!("could not acknowledge server UDP path probe: {error}");
                        }
                        continue;
                    }
                }
                let reassembled;
                let payload = if crate::protocol::data_frag::is_data_fragment(payload) {
                    if !data_frag_enabled {
                        log::debug!("UDP: received DATA_FRAG_V1 without negotiation");
                        continue;
                    }
                    match data_reassembler.push(payload, &rx_data_frag_key) {
                        Ok(Some(record)) => {
                            reassembled = record;
                            reassembled.as_slice()
                        }
                        Ok(None) => continue,
                        Err(error) => {
                            log::debug!("UDP: rejected data fragment: {error}");
                            continue;
                        }
                    }
                } else {
                    payload
                };
                // Unlike TCP, UDP must not await a pool slot here: doing so would stall this
                // select loop's heartbeat and dead-link timers. Fragment MAC/reassembly has
                // already completed, so unauthenticated fragments cannot consume a pool slot.
                let mut record = match tun_write_tx.try_acquire() {
                    Some(record) => record,
                    None => {
                        log::trace!("downlink record pool exhausted — dropping inbound datagram");
                        udp_buffer.note_internal_drop(InternalDrop::PoolExhausted);
                        continue;
                    }
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
                        let direct_management = consume_authenticated_management(
                            record.as_ref(),
                            management_v1,
                            &management_reassembler,
                            &management_tx,
                            None,
                        );
                        if direct_management.consumed {
                            drop(record);
                            if let Some(message_id) = direct_management.ack_message_id {
                                let _ = send_client_udp_terminal_control(
                                    &crate::protocol::control_v2::ack(message_id),
                                    &mut client_tx,
                                    &socket,
                                    udp_framing,
                                    &mut quic_pn,
                                    &mut wire_record,
                                    &mut quic_record,
                                )
                                .await;
                            }
                            continue;
                        }
                        if let Some(reassembler) = udp_rx_recordizer.as_mut() {
                            if record.is_empty() {
                                continue;
                            }
                            let mut first_packet = None;
                            let mut extra_packets = Vec::new();
                            let mut management_ack_ids = Vec::new();
                            let mut pool_exhausted_drops = 0_u64;
                            let mut oversize_drops = 0_u64;
                            let decode_result = reassembler.decode_with(&record, |bytes| {
                                let management = consume_authenticated_management(
                                    bytes,
                                    management_v1,
                                    &management_reassembler,
                                    &management_tx,
                                    None,
                                );
                                if management.consumed {
                                    if let Some(message_id) = management.ack_message_id {
                                        management_ack_ids.push(message_id);
                                    }
                                    return;
                                }
                                let Some(mut packet) = tun_write_tx.try_acquire() else {
                                    pool_exhausted_drops =
                                        pool_exhausted_drops.saturating_add(1);
                                    return;
                                };
                                if bytes.len() > packet.capacity() {
                                    oversize_drops = oversize_drops.saturating_add(1);
                                    return;
                                }
                                packet.as_vec_mut().extend_from_slice(bytes);
                                if first_packet.is_none() {
                                    first_packet = Some(packet);
                                } else {
                                    extra_packets.push(packet);
                                }
                            });
                            drop(record);
                            if let Err(error) = decode_result {
                                log::debug!("UDP recordizer decode error: {error}");
                                continue;
                            }
                            for message_id in management_ack_ids {
                                let _ = send_client_udp_terminal_control(
                                    &crate::protocol::control_v2::ack(message_id),
                                    &mut client_tx,
                                    &socket,
                                    udp_framing,
                                    &mut quic_pn,
                                    &mut wire_record,
                                    &mut quic_record,
                                )
                                .await;
                            }
                            for _ in 0..pool_exhausted_drops {
                                udp_buffer.note_internal_drop(InternalDrop::PoolExhausted);
                            }
                            for _ in 0..oversize_drops {
                                udp_buffer.note_internal_drop(InternalDrop::Oversize);
                            }
                            for packet in first_packet
                                .into_iter()
                                .chain(extra_packets)
                            {
                                if !is_supported_inner_packet(
                                    packet.as_ref(),
                                    negotiated_family_mode,
                                ) {
                                    unsupported_inner_drops =
                                        unsupported_inner_drops.saturating_add(1);
                                    udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                                    if unsupported_inner_drops.is_power_of_two() {
                                        log::debug!(
                                            "UDP client dropped invalid or non-negotiated-family mux packet (total {})",
                                            unsupported_inner_drops
                                        );
                                    }
                                    continue;
                                }
                                runtime_counters
                                    .rx_packets
                                    .fetch_add(1, Ordering::Relaxed);
                                runtime_counters
                                    .rx_bytes
                                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                                trace::record(
                                    trace::Dir::Rx,
                                    "client.udp",
                                    packet.len(),
                                    0,
                                );
                                match tun_write_tx.try_send(packet) {
                                    Ok(()) => {}
                                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                        udp_buffer.note_internal_drop(
                                            InternalDrop::QueueFull,
                                        );
                                    }
                                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                        break 'udp;
                                    }
                                }
                            }
                            continue;
                        }
                        if !record.is_empty()
                            && is_supported_inner_packet(
                                record.as_ref(),
                                negotiated_family_mode,
                            )
                        {
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
                        } else if !record.is_empty() {
                            unsupported_inner_drops = unsupported_inner_drops.saturating_add(1);
                            udp_buffer.note_internal_drop(InternalDrop::Unsupported);
                            if unsupported_inner_drops.is_power_of_two() {
                                log::debug!(
                                    "UDP client dropped invalid or non-negotiated-family inner packet (total {})",
                                    unsupported_inner_drops
                                );
                            }
                        }
                    }
                    Err(e) => log::debug!("UDP decrypt error: {}", e),
                }
            }

            _ = tokio::time::sleep_until(heartbeat_deadline), if heartbeat_enabled => {
                let heartbeat_ready = {
                    let mut obf = Obfuscator::new();
                    // Cap the (server-pushable) heartbeat size to the probed MTU so a large
                    // data_size_bytes can't make a DF-marked keepalive overflow the path and
                    // get dropped (which would make the server reap the idle client).
                    let hb_cap = (tun_mtu.max(0) as usize).min(max_empty_record_padding);
                    let hb_lo = (hb_config.data_size_bytes as usize).min(hb_cap) as u16;
                    let hb_hi = ((hb_config.data_size_bytes as usize).saturating_add(32))
                        .min(hb_cap) as u16;
                    obf.generate_padding_into(hb_lo, hb_hi, &mut padding);
                    client_tx
                        .encrypt_packet_into(&[], &padding, &mut cover_record)
                        .is_ok()
                };
                if heartbeat_ready {
                    let send_data =
                        crate::transport_core::udp_client_framing::wrap_next_udp_record(
                            udp_framing,
                            &cover_record,
                            &mut quic_pn,
                            &mut quic_record,
                        );
                    let _ = socket.send(send_data).await;
                }
                last_activity = tokio::time::Instant::now();
                last_tx_inst = last_activity;
                heartbeat_deadline = tokio::time::Instant::now()
                    + crate::protocol::randomized_heartbeat_delay(
                        heartbeat_interval,
                        Duration::from_millis(hb_config.jitter_ms),
                    );
            }
            _ = tokio::time::sleep_until(cover_deadline), if shaping_on => {
                // UDP cover fills genuine idle on our send side (last_tx_inst).
                if last_tx_inst.elapsed() >= Duration::from_millis(50) {
                    // Keep cover within the probed MTU and codec's padding budget.
                    let size = shaper
                        .next_size(&mut rand::rng())
                        .min(tun_mtu.max(0) as usize)
                        .min(max_empty_record_padding);
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
                            let send_data =
                                crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                    udp_framing,
                                    &cover_record,
                                    &mut quic_pn,
                                    &mut quic_record,
                                );
                            let _ = socket.send(send_data).await;
                            last_tx_inst = tokio::time::Instant::now();
                        }
                    }
                }
                cover_deadline = tokio::time::Instant::now()
                    + shaper.next_gap(&mut rand::rng());
            }

            _ = idle_check.tick() => {
                // Re-send all unacknowledged authenticated metadata. The frames are
                // idempotent, and CLIENT_INFO is self-reported diagnostics rather than policy.
                if control_report_resends > 0 {
                    control_report_resends -= 1;
                    if let Some(budget) = udp_payload_budget_report_value {
                        let frame = crate::protocol::ctrl::udp_payload_budget_report(budget);
                        if let Err(error) = send_udp_control!(&frame) {
                            log::debug!(
                                "could not recordize UDP payload budget report retry: {error}"
                            );
                        }
                    }
                    if let Some(mtu) = mtu_report_value {
                        let frame = crate::protocol::ctrl::mtu_report(mtu);
                        if let Err(error) = send_udp_control!(&frame) {
                            log::debug!("could not recordize UDP MTU report retry: {error}");
                        }
                    }
                    if let Some(frame) = client_info_frame.as_ref() {
                        if let Err(error) = send_udp_control!(frame) {
                            log::debug!("could not recordize client version retry: {error}");
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
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                if udp_handover_enabled {
                    let active_epoch = udp_roaming
                        .as_ref()
                        .expect("enabled UDP handover retains roaming state")
                        .active_epoch();
                    if same_network_nat_recovery
                        .recovery_expired(active_epoch, std::time::Instant::now())
                    {
                        log::warn!("UDP replacement-path grace expired; reconnecting");
                        break;
                    }
                }
                // RX-liveness is valid only when the peer promises authenticated heartbeat
                // or shaping cover. Ordinary UDP uplink is allowed to be one-way and has no
                // transport ACK, so it must never be treated as proof that downlink is due.
                if let Some(deadline) = rx_dead {
                    if last_rx_inst.elapsed() > deadline {
                        #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                        if udp_handover_enabled {
                            let active_epoch = udp_roaming
                                .as_ref()
                                .expect("enabled UDP handover retains roaming state")
                                .active_epoch();
                            let path_controller = path_controller
                                .as_deref()
                                .expect("enabled UDP handover retains path controller");
                            let candidate_in_flight = live_udp_candidate.is_some()
                                || candidate_connect_task.is_some()
                                || path_controller.prepared_candidate().is_some();
                            let decision = same_network_nat_recovery.on_receive_timeout(
                                active_epoch,
                                candidate_in_flight,
                                path_controller.can_request_same_network_nat_rebind(),
                                std::time::Instant::now(),
                            );
                            match decision {
                                crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::WaitForPath => {
                                    continue 'udp;
                                }
                                crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::RequestSameNetworkPath => {
                                    match path_controller.request_same_network_nat_rebind() {
                                        Ok(()) => {
                                            log::warn!(
                                                "UDP: authenticated receive silence on an unchanged path; requesting same-network NAT rebind at epoch {}",
                                                active_epoch
                                            );
                                            continue 'udp;
                                        }
                                        Err(error) => {
                                            log::debug!(
                                                "same-network NAT recovery request is unavailable: {error}"
                                            );
                                        }
                                    }
                                }
                                crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::Reconnect => {}
                            }
                        }
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

    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let connect_was_in_flight = candidate_connect_task.is_some();
    // Join candidate connect and path-monitor workers before inspecting/rolling back the
    // platform candidate. No background task may publish a later path or keep receiving.
    connection_tasks.finish().await;
    udp_receive_task.finish().await;
    result = finish_pending_management(core, &management_rx, result);
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    if let Some(candidate) = live_udp_candidate.take() {
        let prepared = candidate.prepared().clone();
        if let Some(roaming) = udp_roaming.as_mut() {
            roaming.abort_candidate(prepared.candidate_id);
        }
        candidate.stop().await;
        abort_udp_platform_candidate(
            path_controller
                .as_deref()
                .expect("live UDP candidate retains path controller"),
            &prepared,
            "UDP tunnel actor stopped before candidate commit",
        )
        .await;
    } else if connect_was_in_flight {
        // Cancellation may land after BIND_SOCKET but before the connect task reports its
        // result. Query the generation-scoped controller and roll back that exact candidate.
        if let Some(controller) = path_controller.as_deref() {
            if let Some(prepared) = controller.prepared_candidate() {
                abort_udp_platform_candidate(
                    controller,
                    &prepared,
                    "UDP tunnel actor stopped during candidate connect",
                )
                .await;
            }
        }
    }

    let pump_shutdown = async move {
        drop(tun_write_tx);
        tun_pump.shutdown().await;
    };
    #[cfg(target_os = "linux")]
    let result =
        crate::client_cleanup::with_cleanup_error(result, tun_guard.shutdown(pump_shutdown).await);
    #[cfg(not(target_os = "linux"))]
    pump_shutdown.await;
    if result.is_ok() {
        log::info!("UDP client disconnected");
    }
    result
}

/// Compute the actual read capacity after the server-selected MTU is known.
///
/// tun_buffer_size describes the IP-packet capacity for TUN/utun; macOS needs an
/// additional 4-byte utun family prefix. TAP buffers already include link framing in the
/// configured value, but must still fit the negotiated IP MTU plus its 14-byte Ethernet
/// header. Expanding here is essential when tun.mtu = 0 because load-time validation cannot
/// know the pushed MTU.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", test))]
fn tun_read_buffer_size(configured: usize, tun_mtu: i32, is_tap: bool, is_utun: bool) -> usize {
    const TAP_ETHERNET_HEADER_BYTES: usize = 14;
    const UTUN_FAMILY_HEADER_BYTES: usize = 4;

    debug_assert!(!(is_tap && is_utun));
    let framing_bytes = if is_tap {
        TAP_ETHERNET_HEADER_BYTES
    } else if is_utun {
        UTUN_FAMILY_HEADER_BYTES
    } else {
        0
    };
    let configured_capacity =
        configured.saturating_add(if is_utun { UTUN_FAMILY_HEADER_BYTES } else { 0 });
    let negotiated_capacity = (tun_mtu.max(0) as usize).saturating_add(framing_bytes);
    configured_capacity.max(negotiated_capacity)
}

#[cfg(test)]
mod tun_read_buffer_tests {
    use super::tun_read_buffer_size;

    #[test]
    fn negotiated_mtu_expands_small_auto_buffers_without_shrinking_large_ones() {
        assert_eq!(tun_read_buffer_size(600, 1400, false, false), 1400);
        assert_eq!(tun_read_buffer_size(590, 1400, true, false), 1414);
        assert_eq!(tun_read_buffer_size(600, 1400, false, true), 1404);
        assert_eq!(tun_read_buffer_size(65_535, 1400, false, false), 65_535);
        assert_eq!(tun_read_buffer_size(65_535, 1400, false, true), 65_539);
    }
}

/// Reserve enough space for one decrypted downlink record without making every pool slot as
/// large as the protocol-wide record limit. Normalization can intentionally produce a record
/// larger than the tunnel MTU, so the larger of MTU and the configured normalization sizes is
/// used, plus the encryption/framing overhead.
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
        // Nonce, tag, counter, padding length and headroom for future record fields.
        .saturating_add(128)
}

#[cfg(all(test, target_os = "linux"))]
fn prefix_to_netmask(prefix: u8) -> String {
    let prefix = if (1..=32).contains(&prefix) {
        prefix
    } else {
        24
    };
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(mask).to_string()
}

/// Explicit pins remain a pure in-memory check, independent of local TOFU files.
#[cfg(any(target_os = "linux", feature = "transport-core-ffi"))]
pub(crate) fn verify_pinned_key(received: &[u8], expected: &str) -> anyhow::Result<()> {
    let received_hex: String = received.iter().map(|b| format!("{b:02x}")).collect();
    let expected_clean = expected.replace([':', '-', ' '], "").to_lowercase();
    anyhow::ensure!(received_hex == expected_clean,
        "SERVER KEY MISMATCH — possible MITM attack!\n  Expected: {expected_clean}\n  Received: {received_hex}");
    log::debug!("Server public key verified: {received_hex}");
    Ok(())
}

/// Path of the TOFU trust store (SSH-`known_hosts`-style). Override with
/// `QELI_KNOWN_HOSTS` (tests, or routers with a different writable path).
#[cfg(target_os = "linux")]
fn known_hosts_path() -> String {
    std::env::var("QELI_KNOWN_HOSTS").unwrap_or_else(|_| "/var/lib/qeli/known_hosts".to_string())
}

#[cfg(all(test, target_os = "linux"))]
mod lifecycle_adapter_tests {
    use super::*;

    const CONFIG: &str = "[qeli]\nserver = 127.0.0.1:443\nproto = tcp\nuser = test\npass = secret\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nmode = fake-tls\n";

    fn plan(generation: u64) -> NetworkPlan {
        NetworkPlan {
            generation,
            family_mode: crate::transport_core::NetworkFamilyMode::Ipv4,
            addresses: vec![crate::transport_core::NetworkAddress {
                family: crate::transport_core::NetworkAddressFamily::Ipv4,
                address: "10.20.0.2".into(),
                prefix_len: 24,
                on_link_prefix_len: 24,
                gateway: Some("10.20.0.1".into()),
            }],
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
            allow_ipv4_leak: false,
            allow_ipv6_leak: false,
            max_streams: 1,
            adaptive: false,
            data_plane: Default::default(),
            connection_log: Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_plan_state_preserves_legacy_address_and_records_generation() {
        assert_eq!(
            network_plan_state(&plan(7)),
            "10.20.0.2\nipv4=10.20.0.2/24\nmtu=1400\ngeneration=7\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_plan_state_distinguishes_same_address_reauthentication_and_aba() {
        let first = plan(7);
        let mut middle = plan(8);
        middle.tunnel_address = "10.20.0.9".into();
        middle.addresses[0].address = "10.20.0.9".into();
        let last = plan(9);
        assert_ne!(network_plan_state(&first), network_plan_state(&last));
        assert_ne!(network_plan_state(&middle), network_plan_state(&last));
        let mut same_address = first.clone();
        same_address.generation = u64::MAX;
        assert!(network_plan_state(&same_address).ends_with("generation=18446744073709551615\n"));
        assert_ne!(
            network_plan_state(&first),
            network_plan_state(&same_address)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_plan_state_preserves_dual_stack_and_ipv6_only_families() {
        let mut dual = plan(11);
        dual.addresses.push(crate::transport_core::NetworkAddress {
            family: crate::transport_core::NetworkAddressFamily::Ipv6,
            address: "fd00::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd00::1".into()),
        });
        let state = network_plan_state(&dual);
        assert!(state.starts_with("10.20.0.2\n"));
        assert!(state.contains("ipv4=10.20.0.2/24\n"));
        assert!(state.contains("ipv6=fd00::2/128\n"));
        dual.addresses.remove(0);
        dual.tunnel_address = "fd00::2".into();
        let state = network_plan_state(&dual);
        assert!(state.starts_with("fd00::2\n"));
        assert!(!state.contains("ipv4="));
        assert!(state.contains("ipv6=fd00::2/128\n"));
    }

    #[test]
    fn client_hook_context_exports_effective_plan_without_secrets() {
        let mut config = crate::config::client::ClientConfig::from_ini(
            &crate::config::format::IniDoc::parse(CONFIG).unwrap(),
        )
        .unwrap();
        config.tun.name = "vpn-test".into();
        config.routing.lan_subnet = "192.168.50.0/24".into();
        config.routing.include = vec!["198.51.100.0/24".into()];
        config.routing.exclude = vec!["203.0.113.0/24".into()];

        let mut effective = plan(7);
        effective.addresses[0].prefix_len = 32;
        effective.carrier_address = Some("192.0.2.44".into());
        effective.data_plane.recordizer_mode =
            Some(crate::transport_core::NetworkRecordizerMode::PacketMuxV1);
        effective.data_plane.recordizer_policy = Some("balanced".into());
        effective.data_plane.roaming_mode =
            Some(crate::transport_core::NetworkRoamingMode::Reconnect);

        let mut context = ClientHookContext::new(&config, "/etc/qeli/clients/office.conf");
        context.refresh(&effective, "vpn-test");
        let hook = context.invocation(
            "/etc/qeli/hooks/up.sh \"$@\"".into(),
            "post_up",
            "connected",
            "",
            "",
            12,
        );
        let env = hook
            .environment
            .iter()
            .cloned()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(hook.positional_arguments, ["vpn-test", "10.20.0.1"]);
        assert_eq!(env["QELI_HOOK_API"], "1");
        assert_eq!(env["QELI_EVENT"], "post_up");
        assert_eq!(env["QELI_PROFILE"], "office");
        assert_eq!(env["QELI_IFNAME"], "vpn-test");
        assert_eq!(env["QELI_GATEWAY"], "10.20.0.1");
        assert_eq!(env["QELI_IPV4_CIDR"], "10.20.0.2/32");
        assert_eq!(env["QELI_IPV4_SUBNET"], "10.20.0.0/24");
        assert_eq!(env["QELI_DNS_0"], "10.20.0.1:53");
        assert_eq!(env["QELI_ROUTE_0_CIDR"], "192.0.2.0/24");
        assert_eq!(env["QELI_INCLUDE_0"], "198.51.100.0/24");
        assert_eq!(env["QELI_RECORDIZER_MODE"], "packet_mux_v1");
        assert_eq!(env["QELI_SESSION_DURATION_SECONDS"], "12");

        let json: serde_json::Value = serde_json::from_str(&hook.context_json).unwrap();
        assert_eq!(json["hook_api"], 1);
        assert_eq!(json["event"], "post_up");
        assert_eq!(json["network_plan"]["generation"], 7);
        assert_eq!(json["network_plan"]["addresses"][0]["prefix_len"], 32);
        assert!(!hook.context_json.contains("secret"));
        assert!(!hook
            .context_json
            .contains("1111111111111111111111111111111111111111111111111111111111111111"));
    }

    #[test]
    fn post_down_before_the_first_plan_is_explicitly_marked_unavailable() {
        let config = crate::config::client::ClientConfig::from_ini(
            &crate::config::format::IniDoc::parse(CONFIG).unwrap(),
        )
        .unwrap();
        let context = ClientHookContext::new(&config, "client.conf");
        let hook = context.invocation(
            "true".into(),
            "post_down",
            "max_retries",
            "max_retries",
            "connection failed",
            0,
        );
        let env = hook
            .environment
            .iter()
            .cloned()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(env["QELI_PLAN_AVAILABLE"], "false");
        assert_eq!(env["QELI_ADDRESS_COUNT"], "0");
        assert_eq!(env["QELI_GATEWAY"], "");
        assert_eq!(env["QELI_ERROR_MESSAGE"], "connection failed");
        assert_eq!(hook.positional_arguments, ["vpn0", ""]);
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn linux_roaming_path_capability_is_policy_transport_and_source_scoped() {
        let mut config = crate::config::client::ClientConfig::default();
        config.server.protocol = "tcp".to_string();
        assert!(linux_roaming_path_supported(&config));

        config.server.protocol = "udp".to_string();
        assert!(linux_roaming_path_supported(&config));

        config.obfuscation.quic.enabled = false;
        assert!(linux_roaming_path_supported(&config));
        config.tun.attach_existing = true;
        assert!(!linux_roaming_path_supported(&config));
        config.tun.attach_existing = false;

        config.roaming = crate::config::client::ClientRoamingPolicy::Off;
        assert!(!linux_roaming_path_supported(&config));
        config.roaming = crate::config::client::ClientRoamingPolicy::Auto;

        config.server.local_address = Some("192.0.2.10".to_string());
        assert!(!linux_roaming_path_supported(&config));

        config.server.local_address = None;
        config.server.local_port = 41000;
        assert!(!linux_roaming_path_supported(&config));

        config.server.local_port = 0;
        config.server.protocol = "other".to_string();
        assert!(!linux_roaming_path_supported(&config));
    }

    #[tokio::test]
    async fn linux_adapter_enters_running_only_after_platform_apply() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        assert_eq!(
            adapter.with_core(|core| core.state()),
            ClientState::Connecting
        );

        let generation = adapter.next_generation();
        let result = adapter
            .apply_network_plan(plan(generation), move |event_plan| {
                assert_eq!(event_plan.generation, generation);
                assert_eq!(event_plan.routes[0].gateway, "10.20.0.1");
                Ok(42)
            })
            .await
            .unwrap();

        assert_eq!(result, 42);
        assert_eq!(adapter.with_core(|core| core.state()), ClientState::Running);
    }

    struct DropFailure(crate::client_cleanup::Failures);

    impl Drop for DropFailure {
        fn drop(&mut self) {
            let _ = self.0.observe::<()>(
                crate::client_cleanup::Resource::Routes,
                Err(anyhow::anyhow!("simulated resource rollback failed")),
            );
        }
    }

    #[tokio::test]
    async fn rejected_core_ack_drops_owned_platform_value_and_reports_rollback_failure() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        let failures = adapter.cleanup_failures.clone();
        let core = adapter.core.clone();
        let generation = adapter.next_generation();
        let result = adapter
            .apply_network_plan(plan(generation), move |_| {
                // Invalidate ACK after apply: the applied value must retain a cleanup owner.
                core.lock().unwrap().stop().unwrap();
                Ok(DropFailure(failures))
            })
            .await;
        assert!(result.is_err());
        assert!(adapter
            .cleanup_failures
            .result()
            .unwrap_err()
            .to_string()
            .contains("simulated resource rollback failed"));
    }

    #[tokio::test]
    async fn partial_apply_drop_fault_reaches_the_adapter_cleanup_check() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        let failures = adapter.cleanup_failures.clone();
        let generation = adapter.next_generation();
        let error = adapter
            .apply_network_plan::<()>(plan(generation), move |_| {
                let _guard = DropFailure(failures);
                anyhow::bail!("platform apply failed")
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("platform apply failed"));
        let checks = crate::client_cleanup::Checks {
            core: adapter.finish_connection(),
            network: adapter.cleanup_failures.result(),
        };
        assert_eq!(
            checks.failure_reason(),
            Some(("network_cleanup_failed", "network_cleanup"))
        );
    }

    #[tokio::test]
    async fn stop_during_platform_apply_rolls_back_before_core_can_run() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        let generation = adapter.next_generation();
        let cancel = adapter.cancel.clone();
        let failures = adapter.cleanup_failures.clone();
        let (ready, waiting) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let request_stop = async move {
            waiting.await.unwrap();
            cancel.store(true, Ordering::Release);
            release.send(()).unwrap();
        };
        let apply = adapter.apply_network_plan(plan(generation), move |_| {
            ready.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(5))?;
            Ok(DropFailure(failures))
        });
        let (result, ()) = tokio::join!(apply, request_stop);
        assert!(result.is_err());
        assert_eq!(adapter.with_core(|core| core.state()), ClientState::Failed);
        assert!(adapter.cleanup_failures.result().is_err());
    }

    #[tokio::test]
    async fn linux_adapter_rejects_a_partial_platform_plan() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        let generation = adapter.next_generation();
        let error = adapter
            .apply_network_plan::<()>(plan(generation), move |_| {
                Err(anyhow::anyhow!("route installation failed"))
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("route installation failed"));
        assert_eq!(adapter.with_core(|core| core.state()), ClientState::Failed);
    }
}

#[cfg(test)]
mod obf_push_tests {
    use super::*;
    use crate::config::PushedObf;

    #[test]
    fn dataplane_accepts_only_negotiated_families_and_strict_packets() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(is_supported_inner_packet(
            &ipv4,
            crate::transport_core::NetworkFamilyMode::Ipv4
        ));

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 59; // No Next Header: a valid empty IPv6 packet.
        assert!(!is_supported_inner_packet(
            &ipv6,
            crate::transport_core::NetworkFamilyMode::Ipv4
        ));
        assert!(is_supported_inner_packet(
            &ipv6,
            crate::transport_core::NetworkFamilyMode::Dual
        ));
        assert!(is_supported_inner_packet(
            &ipv6,
            crate::transport_core::NetworkFamilyMode::Ipv6
        ));
        assert!(!is_supported_inner_packet(
            &ipv4[..19],
            crate::transport_core::NetworkFamilyMode::Dual
        ));
        assert!(!is_supported_inner_packet(
            &[],
            crate::transport_core::NetworkFamilyMode::Dual
        ));
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
    fn fixed_lport_is_primary_only_but_secondary_keeps_local_address() {
        let remote4 = "198.51.100.10:443".parse().unwrap();
        let remote6 = "[2001:db8::10]:443".parse().unwrap();
        assert_eq!(
            tcp_carrier_bind_address(None, 1194, true, remote4),
            Some("0.0.0.0:1194".parse().unwrap())
        );
        assert_eq!(tcp_carrier_bind_address(None, 1194, false, remote4), None);
        assert_eq!(
            tcp_carrier_bind_address(Some("192.0.2.50".parse().unwrap()), 1194, false, remote4),
            Some("192.0.2.50:0".parse().unwrap())
        );
        assert_eq!(
            tcp_carrier_bind_address(None, 1194, true, remote6),
            Some("[::]:1194".parse().unwrap())
        );
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
        let recordizer = crate::config::RecordizerConfig {
            policy: "required".into(),
            batch: crate::config::RecordizerBatchConfig {
                mode: "opportunistic".into(),
                max_packets: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        obf.recordizer = Some(recordizer);
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
        assert_eq!(ok.udp_roaming_session_id, None);
        let po = ok.pushed_obf.expect("obf present");
        assert_eq!(po.padding.min_bytes, 99);
        assert_eq!(po.padding.max_bytes, 777);
        assert_eq!(po.heartbeat.interval_ms, 4242);
        assert!(po.traffic_normalization.enabled);
        assert_eq!(po.traffic_normalization.round_sizes, vec![10, 20, 30]);
        let recordizer = po.recordizer.expect("authenticated recordizer push");
        assert_eq!(recordizer.policy, "required");
        assert_eq!(recordizer.batch.mode, "opportunistic");
        assert_eq!(recordizer.batch.max_packets, 7);
    }

    #[test]
    fn parse_auth_ok_accepts_only_a_nonzero_fixed_width_udp_roaming_session_id() {
        let ok = parse_auth_ok(
            r#"OK:{"client_ip":"10.9.0.5","udp_roaming_session":"0102030405060708"}"#,
        )
        .expect("valid roaming bootstrap parses");
        assert_eq!(ok.udp_roaming_session_id, Some(0x0102_0304_0506_0708));

        for invalid in [
            r#"OK:{"client_ip":"10.9.0.5","udp_roaming_session":"0"}"#,
            r#"OK:{"client_ip":"10.9.0.5","udp_roaming_session":"0000000000000000"}"#,
            r#"OK:{"client_ip":"10.9.0.5","udp_roaming_session":"gggggggggggggggg"}"#,
            r#"OK:{"client_ip":"10.9.0.5","udp_roaming_session":72623859790382856}"#,
        ] {
            assert!(parse_auth_ok(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn parse_auth_ok_rejects_non_ok_and_malformed() {
        assert!(parse_auth_ok("ERR: bad credentials").is_err()); // not an OK frame
        assert!(parse_auth_ok("OK:not json").is_err()); // malformed JSON
        assert!(parse_auth_ok(r#"OK:{"server_ip":"x"}"#).is_err()); // missing client_ip
    }

    #[test]
    fn parse_auth_ok_rejects_malformed_or_inconsistent_pushed_obfuscation() {
        for (label, obfuscation, expected) in [
            (
                "malformed field type",
                r#"{"padding":{"enabled":"yes"}}"#,
                "invalid auth OK obfuscation",
            ),
            (
                "enabled heartbeat without an interval",
                r#"{"heartbeat":{"enabled":true,"interval_ms":0}}"#,
                "heartbeat.interval_ms",
            ),
            (
                "unordered normalization buckets",
                r#"{"traffic_normalization":{"enabled":true,"round_sizes":[512,256]}}"#,
                "strictly increasing",
            ),
            (
                "inverted shaping gaps",
                r#"{"traffic_shaping":{"enabled":true,"idle_gap_min_ms":50,"idle_gap_max_ms":40}}"#,
                "idle_gap_min_ms",
            ),
            (
                "shaping budget smaller than one record",
                r#"{"traffic_shaping":{"enabled":true,"budget_bytes_per_sec":100,"max_size":200}}"#,
                "budget_bytes_per_sec",
            ),
        ] {
            let message = format!(r#"OK:{{"client_ip":"10.9.0.5","obfuscation":{obfuscation}}}"#);
            let error = parse_auth_ok(&message).expect_err(label).to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
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

    #[test]
    fn parse_auth_ok_rejects_wrapped_v2_prefix_projection() {
        // Casting 280 to u8 produces 24. NetworkPlan v2 must reject the original
        // out-of-range number rather than accidentally accepting that wrapped value
        // when it happens to match the canonical on-link prefix.
        let bad = r#"OK:{"family_mode":"ipv4","addresses":[{"family":"ipv4","address":"10.9.0.5","prefix_len":32,"on_link_prefix_len":24,"gateway":"10.9.0.1"}],"client_ip":"10.9.0.5","server_ip":"10.9.0.1","prefix":280,"mtu":1400,"dns_servers":[]}"#;
        assert!(parse_auth_ok(bad).is_err());
    }

    #[test]
    fn parse_auth_ok_rejects_unusable_ipv6_gateway() {
        let bad = r#"OK:{"family_mode":"ipv6","addresses":[{"family":"ipv6","address":"fd71:e1::2","prefix_len":128,"on_link_prefix_len":64,"gateway":"::"}],"client_ip":"fd71:e1::2","server_ip":"::","prefix":64,"mtu":1400,"dns_servers":[]}"#;
        assert!(parse_auth_ok(bad).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod identity_adapter_tests;

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
    fn nonregular_store_fails_closed_even_when_unpinned_is_allowed() {
        // A directory path can be neither read as a file nor opened for append on
        // any platform, so the first-sight write fails deterministically.
        let dir = tmp("directory");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap();
        let key = "cc".repeat(32);
        // Default (fail closed): unpinned + unwritable store => abort.
        assert!(trust_on_first_use_at(path, "h:443", &key, false).is_err());
        // The escape hatch applies to persistence failure, not an unreadable existing store.
        assert!(trust_on_first_use_at(path, "h:443", &key, true).is_err());
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

// The host fixture uses the same stream pumps as every native client, with an in-memory TUN.
#[cfg(test)]
mod tcp_task_shutdown_tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    struct ObservedRead<R> {
        inner: R,
        started: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl<R: AsyncRead + Unpin> AsyncRead for ObservedRead<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    struct ObservedWrite<W> {
        inner: W,
        blocked: bool,
        started: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for ObservedWrite<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if self.blocked {
                Poll::Pending
            } else {
                Pin::new(&mut self.inner).poll_write(cx, bytes)
            }
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    impl<W: AsyncWrite + Unpin> crate::protocol::obfs::CarrierWriteControl for ObservedWrite<W> {}

    async fn stopped_stream(pipeline_rx: bool, final_kick: bool, blocked_writer: bool) {
        let mut tasks = crate::transport_core::tasks::TaskGroup::default();
        let (socket, mut peer) = tokio::io::duplex(1024 * 1024);
        let (read, write) = tokio::io::split(socket);
        let (write_started, write_ready) = tokio::sync::oneshot::channel();
        let write = ObservedWrite {
            inner: write,
            blocked: blocked_writer,
            started: Some(write_started),
        };
        let (started, ready) = tokio::sync::oneshot::channel();
        let read = ObservedRead {
            inner: read,
            started: Some(started),
        };
        let (to_tun, from_stream) = std::sync::mpsc::sync_channel(2);
        let pool = crate::transport_core::buffer_pool::BufferPool::new(300, 2048).unwrap();
        let tun = TunWriter::from_parts(to_tun, pool);
        let (dead, mut dead_rx) = mpsc::channel(1);
        let shaping = crate::protocol::ShapingConfig::default();
        let cover_budget =
            crate::protocol::Shaper::shared_budget(&shaping, std::time::Instant::now());
        let (management_tx, management_rx) = tokio::sync::watch::channel(None);
        let sender = spawn_stream(
            read,
            write,
            PacketCodec::new_raw([1; 32]),
            PacketCodec::new_raw([2; 32]),
            tun,
            dead,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(RuntimeCounters::default()),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            0,
            None,
            None,
            tasks.spawner(),
            StreamPump {
                framing: Framing::Raw,
                family_mode: crate::transport_core::NetworkFamilyMode::Ipv4,
                heartbeat_enabled: false,
                heartbeat_interval: Duration::from_secs(60),
                idle_timeout: Duration::from_secs(60),
                tun_mtu: 1400,
                hb_data: 0,
                hb_jitter: 0,
                padding_enabled: false,
                padding_min: 0,
                padding_max: 0,
                padding_randomize: false,
                padding_prob: 0.0,
                norm_enabled: false,
                norm_sizes: vec![],
                shaping,
                recordizer: None,
                cover_budget,
                uplink_queue_capacity: 4096,
                pipeline_rx,
                management_v1: final_kick,
                management_reassembler: Arc::new(std::sync::Mutex::new(
                    crate::protocol::control_v2::Reassembler::new(),
                )),
                management_tx,
            },
        );
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        if blocked_writer {
            sender
                .try_send(ClientUplink::Owned(vec![0x41; 80]))
                .ok()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), write_ready)
                .await
                .unwrap()
                .unwrap();
            peer.shutdown().await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), dead_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                sender.sender.is_closed(),
                "stream loss was published before writer destruction"
            );
        }
        if final_kick {
            use crate::protocol::control_v2::{Kick, KickReason, ManagementEvent};
            use tokio::io::AsyncWriteExt;
            let event = ManagementEvent::Kick(Kick {
                reason: KickReason::Administrative,
                message: "Session replaced".into(),
                reconnect_allowed: false,
            });
            let mut encoder = PacketCodec::new_raw([1; 32]);
            // A full scheduling quantum of queued records forces Stage A/B interleaving.
            for _ in 0..256 {
                peer.write_all_flush(&encoder.encrypt_packet(&[], &[]).unwrap())
                    .await
                    .unwrap();
            }
            let frame = crate::protocol::control_v2::management_frames(&event, 1)
                .unwrap()
                .pop()
                .unwrap();
            peer.write_all_flush(&encoder.encrypt_packet(&frame, &[]).unwrap())
                .await
                .unwrap();
            peer.shutdown().await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), dead_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                *management_rx.borrow(),
                Some(event),
                "EOF overtook the decrypt drain"
            );
        }
        tokio::time::timeout(Duration::from_secs(5), tasks.finish())
            .await
            .unwrap();
        assert!(sender.sender.is_closed(), "writer still owns its queue");
        assert!(
            matches!(
                from_stream.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Disconnected)
            ),
            "reader/pipeline still owns TUN"
        );
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        if !final_kick {
            assert!(
                remaining.is_empty(),
                "unexpected output without terminal traffic"
            );
        }
    }

    #[tokio::test]
    async fn inline_kick_is_published_before_eof() {
        stopped_stream(false, true, false).await;
    }

    #[tokio::test]
    async fn pipelined_kick_is_published_before_eof() {
        stopped_stream(true, true, false).await;
    }

    #[tokio::test]
    async fn shutdown_releases_inline_stream_socket_queues_and_tun() {
        stopped_stream(false, false, false).await;
    }

    #[tokio::test]
    async fn shutdown_releases_pipeline_stream_socket_queues_and_tun() {
        stopped_stream(true, false, false).await;
    }

    #[tokio::test]
    async fn reader_death_cancels_blocked_write_before_publishing_stream_loss() {
        stopped_stream(false, false, true).await;
    }

    #[tokio::test]
    async fn pipelined_reader_death_cancels_blocked_write_before_stream_loss() {
        stopped_stream(true, false, true).await;
    }
}

#[cfg(all(test, feature = "experimental-roaming", any(unix, windows)))]
mod udp_task_shutdown_tests {
    use super::*;
    use crate::transport_core::path::PathUpdate;
    const DEADLINE: Duration = Duration::from_secs(5);

    async fn socket_pair() -> (Arc<crate::protocol::obfs::ObfsUdp>, tokio::net::UdpSocket) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(peer.local_addr().unwrap()).await.unwrap();
        peer.connect(socket.local_addr().unwrap()).await.unwrap();
        (
            Arc::new(crate::protocol::obfs::ObfsUdp::new(socket, None)),
            peer,
        )
    }

    fn prepared(candidate_id: u64) -> PreparedPathCandidate {
        PreparedPathCandidate {
            candidate_id,
            update: PathUpdate {
                generation: 1,
                update_id: candidate_id,
                platform_path_id: "fixture".into(),
                reason: crate::transport_core::path::PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: None,
                local_addresses: vec![],
                resolved_addresses: vec![],
                flags: Default::default(),
            },
        }
    }

    fn test_receive_queue() -> Arc<crate::transport_core::receive_queue::ReceiveQueue> {
        crate::transport_core::receive_queue::ReceiveQueue::new(Default::default(), "test client")
    }

    async fn receive_epoch(
        rx: &mut mpsc::Receiver<
            crate::transport_core::receive_queue::QueuedBatch<ClientUdpReceivedDatagram>,
        >,
        epoch: u64,
    ) {
        let packets = tokio::time::timeout(DEADLINE, rx.recv())
            .await
            .unwrap()
            .unwrap();
        let packets = packets.into_inner();
        assert!(!packets.is_empty());
        assert!(packets.iter().all(|packet| packet.path_epoch == epoch));
    }

    #[tokio::test]
    async fn active_receive_shutdown_releases_socket_with_full_output_queue() {
        let mut tasks = crate::transport_core::tasks::TaskGroup::default();
        let (socket, peer) = socket_pair().await;
        let (tx, mut rx) = mpsc::channel(1);
        let mut active = spawn_client_udp_receive_pump(
            socket.clone(),
            0,
            tx.clone(),
            &tasks.spawner(),
            test_receive_queue(),
        );
        peer.send(b"first").await.unwrap();
        tokio::time::timeout(DEADLINE, async {
            while tx.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        peer.send(b"second").await.unwrap();
        tokio::task::yield_now().await;
        drop(tx);
        tokio::time::timeout(DEADLINE, tasks.finish())
            .await
            .unwrap();
        active.finish().await;
        assert_eq!(
            Arc::strong_count(&socket),
            1,
            "receive pump retained its socket"
        );
        receive_epoch(&mut rx, 0).await;
        assert!(
            rx.recv().await.is_none(),
            "producer remained after group shutdown"
        );
    }

    #[tokio::test]
    async fn candidate_cancellation_preserves_active_receive_path() {
        let mut tasks = crate::transport_core::tasks::TaskGroup::default();
        let (active_socket, active_peer) = socket_pair().await;
        let (candidate_socket, candidate_peer) = socket_pair().await;
        let (tx, mut rx) = mpsc::channel(4);
        let active = spawn_client_udp_receive_pump(
            active_socket.clone(),
            0,
            tx.clone(),
            &tasks.spawner(),
            test_receive_queue(),
        );
        let candidate_task = spawn_client_udp_receive_pump(
            candidate_socket.clone(),
            1,
            tx.clone(),
            &tasks.spawner(),
            test_receive_queue(),
        );
        let candidate =
            UdpClientLiveCandidate::new(prepared(7), 1, candidate_socket.clone(), candidate_task);
        candidate_peer.send(b"candidate").await.unwrap();
        receive_epoch(&mut rx, 1).await;
        tokio::time::timeout(DEADLINE, candidate.stop())
            .await
            .unwrap();
        assert_eq!(Arc::strong_count(&candidate_socket), 1);
        active_peer.send(b"active survives").await.unwrap();
        receive_epoch(&mut rx, 0).await;
        tasks.finish().await;
        assert_eq!(Arc::strong_count(&active_socket), 1);
        drop(active);
    }

    #[tokio::test]
    async fn committed_candidate_transfers_task_while_old_receive_drains() {
        let mut tasks = crate::transport_core::tasks::TaskGroup::default();
        let (old_socket, old_peer) = socket_pair().await;
        let (new_socket, new_peer) = socket_pair().await;
        let (tx, mut rx) = mpsc::channel(4);
        let mut active = spawn_client_udp_receive_pump(
            old_socket.clone(),
            0,
            tx.clone(),
            &tasks.spawner(),
            test_receive_queue(),
        );
        let candidate_task = spawn_client_udp_receive_pump(
            new_socket.clone(),
            1,
            tx.clone(),
            &tasks.spawner(),
            test_receive_queue(),
        );
        let candidate =
            UdpClientLiveCandidate::new(prepared(8), 1, new_socket.clone(), candidate_task);
        let (identity, committed_socket, next_receive) = candidate.into_active();
        assert_eq!(identity.candidate_id, 8);
        let mut draining = UdpClientDrainingPath {
            epoch: 0,
            framing: crate::transport_core::udp_client_framing::UdpClientFraming::legacy(
                false, [0; 4],
            ),
            expires_at: tokio::time::Instant::now(),
            receive_task: std::mem::replace(&mut active, next_receive),
        };
        old_peer.send(b"draining").await.unwrap();
        receive_epoch(&mut rx, 0).await;
        new_peer.send(b"committed").await.unwrap();
        receive_epoch(&mut rx, 1).await;
        tokio::time::timeout(DEADLINE, draining.receive_task.finish())
            .await
            .unwrap();
        assert_eq!(Arc::strong_count(&old_socket), 1);
        new_peer.send(b"after drain").await.unwrap();
        receive_epoch(&mut rx, 1).await;
        tasks.finish().await;
        drop(committed_socket);
        assert_eq!(Arc::strong_count(&new_socket), 1);
    }

    #[tokio::test]
    async fn early_owner_drop_stops_live_receive_without_dropping_path_handle() {
        let tasks = crate::transport_core::tasks::TaskGroup::default();
        let (socket, peer) = socket_pair().await;
        let (tx, mut rx) = mpsc::channel(1);
        let active = spawn_client_udp_receive_pump(
            socket.clone(),
            0,
            tx,
            &tasks.spawner(),
            test_receive_queue(),
        );
        peer.send(b"started").await.unwrap();
        receive_epoch(&mut rx, 0).await;
        drop(tasks); // Simulate an early return/cancel while a path handle is still alive.
        assert!(tokio::time::timeout(DEADLINE, rx.recv())
            .await
            .unwrap()
            .is_none());
        assert_eq!(Arc::strong_count(&socket), 1);
        drop(active);
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "network_view_tests.rs"]
mod network_view_tests;

#[cfg(test)]
mod q13_stealth_writer_tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    #[tokio::test]
    async fn q13_tcp_writer_waits_for_sub_six_ms_stealth_debt() {
        let cfg = crate::protocol::ShapingConfig {
            enabled: true,
            stealth: true,
            stealth_rate_mbps: 1,
            ..Default::default()
        };
        // Fix refill at zero even if the host scheduler stalls between construction and poll.
        let mut shaper =
            crate::protocol::Shaper::new(cfg, std::time::Instant::now() + Duration::from_secs(1));
        let (mut writer, _reader) = tokio::io::duplex(8192);
        let mut codec = PacketCodec::new_raw([7; 32]);
        let wire = vec![0x42; 700];
        let mut cover = Vec::new();
        let mut padding = Vec::new();
        let mut send = Box::pin(write_client_wire_record(
            &mut writer,
            &mut codec,
            &mut shaper,
            &wire,
            &mut cover,
            &mut padding,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(Pin::new(&mut send).poll(&mut cx), Poll::Pending),
            "5.6 ms debt must park before the data write"
        );
    }
}

// Keep Linux-only CLI wiring after shared code to preserve other targets' source locations.
#[cfg(target_os = "linux")]
mod logging_bootstrap;
#[cfg(target_os = "linux")]
pub use logging_bootstrap::{peek_logging, read_config_text};
