#[cfg(target_os = "linux")]
pub mod dns;
#[cfg(target_os = "linux")]
pub mod gateway;
#[cfg(target_os = "linux")]
pub mod killswitch;
#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
mod roaming_linux;
#[cfg(target_os = "linux")]
pub mod route;

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
use crate::transport_core::path::PreparedPathCandidate;
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
use crate::transport_core::path::{PathCommand, PathCommandAction};
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
/// A widened mobile/Wi-Fi path should not remain pinned to the conservative startup budget
/// for the lifetime of a long session. Re-probing is sparse and uses the one existing socket
/// receive loop, so it neither creates a competing reader nor loses ordinary data records.
const UDP_MTU_REPROBE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const UDP_MTU_REPROBE_TICK: Duration = Duration::from_millis(250);
const UDP_MTU_REPROBE_REPLY_TIMEOUT: Duration = Duration::from_millis(500);
const UDP_MTU_REPROBE_SENDS: u8 = 2;
const UDP_MTU_REPROBE_CONFIRMATIONS: u8 = 3;
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

#[derive(Debug, Clone, Copy)]
struct UdpMtuChallenge {
    candidate: i32,
    id: u16,
    outer_size: u16,
    sends: u8,
    deadline: tokio::time::Instant,
}

#[derive(Debug, Default)]
struct LiveUdpMtuProbe {
    candidates: std::collections::VecDeque<i32>,
    challenge: Option<UdpMtuChallenge>,
    confirmations: u8,
}

impl LiveUdpMtuProbe {
    fn start(&mut self, candidates: impl IntoIterator<Item = i32>) {
        self.candidates = candidates.into_iter().collect();
        self.challenge = None;
        self.confirmations = 0;
    }

    fn is_active(&self) -> bool {
        self.challenge.is_some() || !self.candidates.is_empty()
    }

    fn clear(&mut self) {
        self.candidates.clear();
        self.challenge = None;
        self.confirmations = 0;
    }

    /// Return the next challenge that must be sent. A candidate gets two sends with one
    /// correlation id; a certified candidate then needs three independently random ids.
    fn next_send(&mut self, now: tokio::time::Instant) -> Option<(u16, i32)> {
        loop {
            if self.challenge.is_none() {
                let candidate = self.candidates.pop_front()?;
                self.challenge = Some(UdpMtuChallenge {
                    candidate,
                    id: rand::random(),
                    outer_size: u16::try_from(
                        candidate.max(0) as usize + UDP_RECORD_PROBE_OVERHEAD,
                    )
                    .ok()?,
                    sends: 0,
                    deadline: now,
                });
            }
            let challenge = self.challenge.as_mut()?;
            if challenge.sends != 0 && now < challenge.deadline {
                return None;
            }
            if challenge.sends >= UDP_MTU_REPROBE_SENDS {
                // This rung did not answer. Continue down the already descending ladder.
                self.challenge = None;
                self.confirmations = 0;
                continue;
            }
            challenge.sends += 1;
            challenge.deadline = now + UDP_MTU_REPROBE_REPLY_TIMEOUT;
            return Some((challenge.id, challenge.candidate));
        }
    }

    /// Accept only an exact id+size echo. `Some(candidate)` means the third independent
    /// confirmation completed and the live data-plane budget may be widened.
    fn acknowledge(&mut self, id: u16, outer_size: u16) -> Option<i32> {
        let challenge = self.challenge?;
        if challenge.id != id || challenge.outer_size != outer_size {
            return None;
        }
        self.confirmations = self.confirmations.saturating_add(1);
        if self.confirmations >= UDP_MTU_REPROBE_CONFIRMATIONS {
            self.clear();
            return Some(challenge.candidate);
        }
        self.challenge = Some(UdpMtuChallenge {
            id: rand::random(),
            sends: 0,
            deadline: tokio::time::Instant::now(),
            ..challenge
        });
        None
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
use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

pub(crate) type IdentityFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'static>>;
pub(crate) type IdentityVerifier = Arc<dyn Fn([u8; 32]) -> IdentityFuture + Send + Sync + 'static>;
pub(crate) type PendingLifecycleHook = (String, Vec<(String, String)>);

#[cfg(target_os = "linux")]
fn cleanup_routing_features(
    kill_switch: bool,
    gateway_enabled: bool,
    exit_node: bool,
    tun_if: &str,
    lan_subnet: &str,
    lan_subnet_ipv6: &str,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Keep the kill-switch in place until forwarding/NAT state has been removed. This
    // preserves fail-closed egress throughout teardown instead of opening the host first.
    if gateway_enabled || exit_node {
        if let Err(error) = gateway::disengage_plan(
            tun_if,
            lan_subnet,
            lan_subnet_ipv6,
            gateway_enabled,
            exit_node,
        ) {
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
#[cfg(feature = "experimental-roaming")]
pub(crate) type PathAckFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'static>>;

#[cfg(feature = "experimental-roaming")]
fn path_ack_future(
    receiver: tokio::sync::oneshot::Receiver<Result<(), String>>,
    action: &'static str,
) -> PathAckFuture {
    Box::pin(async move {
        match receiver.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(anyhow::anyhow!("{action} rejected: {reason}")),
            Err(_) => Err(anyhow::anyhow!("{action} acknowledgement was cancelled")),
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
pub(crate) struct LinuxPathController {
    core: Arc<std::sync::Mutex<ClientCore>>,
    shared: CorePathController,
    tunnel_interface: String,
    prepared_routes: std::sync::Mutex<Option<route::LinuxPreparedPathRoutes>>,
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
                let prepared =
                    route::prepare_candidate_path_routes(&candidate, &self.tunnel_interface)?;
                let mut current = crate::util::lock_or_recover(
                    &self.prepared_routes,
                    "client::linux_prepared_routes",
                );
                if current.as_ref().is_some_and(|active| {
                    active.generation != command.generation
                        || active.candidate_id != command.candidate_id
                }) {
                    anyhow::bail!("Linux path executor already owns another prepared candidate");
                }
                *current = Some(prepared);
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
                    if prepared.generation != command.generation
                        || prepared.candidate_id != command.candidate_id
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
                if prepared.generation != command.generation
                    || prepared.candidate_id != command.candidate_id
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
                gateway::refresh_exit_paths_if_active(&self.tunnel_interface)?;
                prepared.commit(&previous_carriers)?;
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
                    prepared.generation != command.generation
                        || prepared.candidate_id != command.candidate_id
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
        self.with_core(|core| {
            core.ack_path_command(
                command.generation,
                command.candidate_id,
                event.sequence,
                execution.is_ok(),
                rejection.as_deref(),
            )
        })?;

        if rejection.is_some() && expected_action != PathCommandAction::AbortPath {
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
    // default-off capability keeps adapters without this exact binding contract on reconnect.
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
    fn prepare_tunnel(
        &mut self,
        config: &crate::config::client::ClientConfig,
        plan: NetworkPlan,
        network: &HandshakeNetwork<'_>,
    ) -> anyhow::Result<TunnelSetup>;
    fn fallback_dns_servers(&self) -> &[String];
    fn cancel_token(&self) -> Arc<AtomicBool>;
    fn counters(&self) -> Arc<RuntimeCounters>;
    /// Consume the client `post_up` hook after the first successfully applied NetworkPlan.
    /// Non-Linux adapters and later reconnect generations have no pending hook.
    fn take_post_up(&mut self) -> Option<PendingLifecycleHook> {
        None
    }
}

async fn run_pending_post_up(core: &mut dyn ClientPlatform) {
    let Some((command, environment)) = core.take_post_up() else {
        return;
    };
    #[cfg(target_os = "linux")]
    {
        let hook_environment = environment
            .iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect::<Vec<_>>();
        crate::hooks::run("post_up", &command, &hook_environment).await;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (command, environment);
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
    post_up: Option<PendingLifecycleHook>,
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

#[cfg(all(target_os = "linux", feature = "experimental-roaming"))]
fn linux_roaming_path_supported(config: &crate::config::client::ClientConfig) -> bool {
    use crate::config::client::ClientRoamingPolicy;

    let transport_supported = matches!(config.server.protocol.as_str(), "tcp" | "udp");
    // Explicit source settings are operator pins, not a path the observer may replace.
    config.roaming != ClientRoamingPolicy::Off
        && transport_supported
        && config.server.local_address.is_none()
        && config.server.local_port == 0
}

#[cfg(target_os = "linux")]
impl LinuxCoreAdapter {
    fn with_core<T>(&self, action: impl FnOnce(&mut ClientCore) -> T) -> T {
        let mut core = crate::util::lock_or_recover(&self.core, "client::linux_core");
        action(&mut core)
    }

    fn new(config_text: &str) -> anyhow::Result<(Self, crate::config::client::ClientConfig)> {
        let preview = crate::config::parse_client_config_strict(config_text)?;
        let mut platform_capabilities = platform_capability::SYSTEM_PLAN
            | platform_capability::IPV6_TUN
            | platform_capability::IPV6_ROUTES
            | platform_capability::IPV6_DNS;
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
        let diagnostics = ClientStatusReporter::from_env();
        diagnostics.publish(&counters);
        Ok((
            Self {
                core,
                next_plan_generation: 1,
                cancel: Arc::new(AtomicBool::new(false)),
                counters,
                diagnostics,
                post_up: None,
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

    fn arm_post_up(&mut self, command: String, environment: &[(&str, String)]) {
        if command.trim().is_empty() {
            return;
        }
        self.post_up = Some((
            command,
            environment
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect(),
        ));
    }

    fn apply_network_plan<T>(
        &mut self,
        plan: NetworkPlan,
        apply: impl FnOnce(&NetworkPlan) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let generation = plan.generation;
        self.with_core(|core| core.publish_network_plan(plan))?;
        let executable = self.drain_events(Some(generation))?.ok_or_else(|| {
            anyhow::anyhow!("core emitted no network plan for generation {generation}")
        })?;

        match apply(&executable) {
            Ok(value) => {
                self.with_core(|core| core.ack_network_plan(generation, true, None))?;
                self.drain_events(None)?;
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

    fn take_post_up(&mut self) -> Option<PendingLifecycleHook> {
        self.post_up.take()
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

/// Desynchronise clients that lose the same server/carrier at once. Jitter only shortens the
/// scheduled delay (by at most 20%), so the configured maximum is never exceeded.
#[cfg(any(target_os = "linux", test))]
fn jitter_reconnect_delay(scheduled: Duration) -> Duration {
    let millis = u64::try_from(scheduled.as_millis()).unwrap_or(u64::MAX);
    let spread = millis / 5;
    if spread == 0 {
        return scheduled;
    }
    let reduction = rand::rng().random_range(0..=spread);
    Duration::from_millis(millis.saturating_sub(reduction))
}

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
    let tun_if = config.tun.name.clone();
    let lan_subnet = config.routing.lan_subnet.clone();
    let lan_subnet_ipv6 = config.routing.lan_subnet_ipv6.clone();
    // Config validation already rejects exit_node + every full-tunnel spelling. Its own
    // internet must remain on the physical WAN so forwarded traffic has an egress path.

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
    // Unlike `post_down`, `post_up` is tied to a successfully created tunnel. Keep the
    // already-vetted command in the platform adapter and consume it after the first
    // authenticated NetworkPlan has installed the TUN and its active-family firewall.
    core_adapter.arm_post_up(post_up.clone(), &hook_env);

    // SIGINT/SIGTERM must enter the same cooperative cancellation path as GUI/native stop.
    // The previous signal task called process::exit after doing its own partial cleanup. That
    // skipped data-plane destructors and, for roaming, made it impossible to send authenticated
    // CLOSE_SESSION before the socket disappeared. Keep one cancellation token alive for the
    // whole CLI retry loop; after the active generation unwinds, the ordinary teardown below
    // restores DNS, routes, firewall state and lifecycle hooks exactly once.
    let shutdown_requested = core_adapter.cancel_token();
    let signal_cancel = shutdown_requested.clone();
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
        log::info!("Shutdown signal received — stopping the active tunnel cleanly");
        signal_cancel.store(true, Ordering::Release);
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
            config.routing.allow_ipv4_leak,
            config.routing.allow_ipv6_leak,
            gw_on,
        )?;
    }
    // Gateway and exit-node firewalling are installed by `setup_tunnel` only after the
    // authenticated NetworkPlan identifies the active families. This keeps an IPv6-only
    // router independent from IPv4 iptables/sysctls (and vice versa). `post_up` is consumed
    // immediately afterwards by the data-plane setup, once on the first successful plan.

    let mut retry_count = 0u64;

    loop {
        core_adapter.begin_connection(retry_count > 0)?;
        // A reconnect generation gets a fresh DNS candidate set. Bonded streams inside
        // that generation are restricted to the set pinned by its authenticated plan.
        reset_carrier_candidates(usize::try_from(retry_count).unwrap_or(usize::MAX));
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

        if shutdown_requested.load(Ordering::Acquire) {
            let cleanup = cleanup_routing_features(
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
                &lan_subnet,
                &lan_subnet_ipv6,
            );
            crate::hooks::run("post_down", &post_down, &hook_env).await;
            let result = cleanup
                .map_err(|error| anyhow::anyhow!("shutdown network cleanup failed: {error}"));
            core_adapter.diagnostics.terminal(result.as_ref().err());
            core_adapter.diagnostics.publish(&core_adapter.counters);
            return result;
        }

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
            let cleanup = cleanup_routing_features(
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
                &lan_subnet,
                &lan_subnet_ipv6,
            );
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
            let cleanup = cleanup_routing_features(
                ks_on,
                gw_on,
                exit_on,
                &tun_if,
                &lan_subnet,
                &lan_subnet_ipv6,
            );
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
        let scheduled_delay = std::cmp::min(
            config
                .server
                .reconnect
                .base_delay_secs
                .saturating_mul(multiplier),
            config.server.reconnect.max_delay_secs,
        );
        let delay = jitter_reconnect_delay(Duration::from_secs(scheduled_delay));
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

        let retry_in_secs =
            u64::try_from(delay.as_millis().saturating_add(999) / 1000).unwrap_or(u64::MAX);
        log::info!(
            "Reconnecting in {:.3}s (attempt {})...",
            delay.as_secs_f64(),
            retry_count
        );
        core_adapter
            .diagnostics
            .retrying(result.as_ref().err(), retry_count, retry_in_secs);
        core_adapter.diagnostics.publish(&core_adapter.counters);
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod reconnect_jitter_tests {
    use super::jitter_reconnect_delay;
    use std::time::Duration;

    #[test]
    fn reconnect_jitter_stays_within_eighty_to_one_hundred_percent() {
        let scheduled = Duration::from_secs(60);
        for _ in 0..256 {
            let delay = jitter_reconnect_delay(scheduled);
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
        let resolved =
            match tokio::time::timeout(total, tokio::net::lookup_host((host, port))).await {
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
        resolved
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
) -> anyhow::Result<tokio::io::DuplexStream> {
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
    let h2 = tokio::time::timeout(to, crate::protocol::h2_carrier::connect(tls, &server_name))
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
        let first = connect_obfs(config, true, LinuxStreamConnectContext::default()).await?;
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
        run_tcp_tunnel(first, connector, config, password, core).await
    } else if config.obfuscation.mode == "reality-tls" {
        log::info!("Wire mode: reality-tls (real TLS 1.3 carrying the tunnel)");
        let first = connect_reality(config, true, LinuxStreamConnectContext::default()).await?;
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
            Box::pin(async move { connect_reality(&cfg, false, context).await })
        });
        run_tcp_tunnel(first, connector, config, password, core).await
    } else {
        // fake-tls / plain: bare TCP transport; the qeli handshake applies the
        // fake-TLS mimicry or the raw framing. Both support stream bonding.
        log::info!("Wire mode: {} (TCP)", config.obfuscation.mode);
        let first = connect_bare_tcp(config, true, LinuxStreamConnectContext::default()).await?;
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
        run_tcp_tunnel(first, connector, config, password, core).await
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
    #[cfg(feature = "experimental-roaming")]
    TerminalControl {
        packet: Vec<u8>,
        written: tokio::sync::oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct ClientStreamSender {
    logical_slot_id: u32,
    sender: mpsc::Sender<ClientUplink>,
}

impl ClientStreamSender {
    fn try_send(
        &self,
        packet: ClientUplink,
    ) -> Result<(), mpsc::error::TrySendError<ClientUplink>> {
        self.sender.try_send(packet)
    }

    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    #[cfg(feature = "experimental-roaming")]
    fn try_send_terminal_control(
        &self,
        packet: Vec<u8>,
    ) -> Result<tokio::sync::oneshot::Receiver<()>, mpsc::error::TrySendError<ClientUplink>> {
        let (written, receipt) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(ClientUplink::TerminalControl { packet, written })?;
        Ok(receipt)
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
        decode_hex_array, mark_tcp_slot_started, mark_tcp_slot_stopped, publish_tcp_path_handover,
        register_tcp_stream_task, should_defer_tcp_resume_for_handover, ClientStreamSender,
        TcpActiveSlots, TcpResumeContext, TcpSecondaryAttach, TCP_HANDOVER_PREPARE_GRACE,
    };
    use portable_atomic::AtomicU64;
    use std::sync::Arc;

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
        let mut outputs = vec![
            ClientStreamSender {
                logical_slot_id: 0,
                sender: old_zero,
            },
            ClientStreamSender {
                logical_slot_id: 1,
                sender: old_one,
            },
            ClientStreamSender {
                logical_slot_id: 2,
                sender: old_two,
            },
        ];
        let retired = publish_tcp_path_handover(
            &mut outputs,
            ClientStreamSender {
                logical_slot_id: 0,
                sender: new_zero,
            },
        );
        assert_eq!(retired, 3);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].logical_slot_id, 0);
        assert!(old_zero_rx.is_closed() && old_one_rx.is_closed() && old_two_rx.is_closed());
    }

    #[tokio::test]
    async fn replacement_stream_reaps_completed_task_handles() {
        let tasks = Arc::new(std::sync::Mutex::new(Vec::new()));
        register_tcp_stream_task(&tasks, tokio::spawn(async {}));

        for _ in 0..100 {
            if crate::util::lock_or_recover(&tasks, "test::stream_tasks")[0].is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(crate::util::lock_or_recover(&tasks, "test::stream_tasks")[0].is_finished());

        register_tcp_stream_task(&tasks, tokio::spawn(std::future::pending::<()>()));
        let registered = crate::util::lock_or_recover(&tasks, "test::stream_tasks");
        assert_eq!(
            registered.len(),
            1,
            "a completed carrier task must not remain registered until tunnel teardown"
        );
        drop(registered);

        register_tcp_stream_task(&tasks, tokio::spawn(std::future::pending::<()>()));
        let mut registered = crate::util::lock_or_recover(&tasks, "test::stream_tasks");
        assert_eq!(
            registered.len(),
            2,
            "active carrier tasks must remain registered for safe tunnel teardown"
        );
        for task in registered.drain(..) {
            task.abort();
        }
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
            Self::Owned(packet) => packet,
            #[cfg(feature = "experimental-roaming")]
            Self::TerminalControl { packet, .. } => packet,
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
        if normalization_padding != 0 {
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
        let mut remaining = delay;
        while remaining > Duration::from_millis(6) {
            let size = shaper.next_size(&mut rand::rng());
            let cover_ready = if shaper.try_spend(size, std::time::Instant::now()) {
                let mut obf = Obfuscator::new();
                obf.generate_padding_into(size as u16, size as u16, padding);
                tx.encrypt_packet_into(&[], padding, cover_record).is_ok()
            } else {
                false
            };
            if cover_ready && write_half.write_all(cover_record).await.is_err() {
                return false;
            }
            let step = Duration::from_millis(rand::rng().random_range(4..=18));
            let sleep = step.min(remaining);
            tokio::time::sleep(sleep).await;
            remaining = remaining.saturating_sub(sleep);
        }
    } else if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    write_half.write_all(wire_record).await.is_ok()
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

fn deliver_client_tcp_plaintext(
    record: PooledBuffer,
    mux: &mut Option<crate::protocol::recordizer::Reassembler>,
    tun: &TunWriter,
    family_mode: crate::transport_core::NetworkFamilyMode,
    metrics: ClientTcpRxMetrics<'_>,
) -> bool {
    metrics
        .last_rx
        .store(metrics.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    if record.is_empty() {
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
                Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
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
        Err(std::sync::mpsc::TrySendError::Full(_)) => true,
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
    }
}

type TcpActiveSlots = Arc<std::sync::Mutex<std::collections::BTreeMap<u32, usize>>>;
type TcpStreamTasks = Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>;

fn register_tcp_stream_task(tasks: &TcpStreamTasks, task: tokio::task::JoinHandle<()>) {
    let mut registered = crate::util::lock_or_recover(tasks, "client::stream_tasks");
    // A successful handover deliberately keeps the tunnel generation alive, so teardown cannot
    // be the only place that drops completed task allocations. Tasks still finishing after their
    // sender was retired stay registered and are collected by the following carrier spawn.
    registered.retain(|registered_task| !registered_task.is_finished());
    registered.push(task);
}

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
    mut write_half: W,
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
    // Every task this stream spawns is registered here so the teardown can abort them.
    // Without it the caller had no handle at all: a reader parked in `read_record` on a
    // half-open connection outlived its connection generation, retaining its socket,
    // codecs and outbound channel. The shared TUN pump can now stop despite sender
    // clones, but the obsolete stream tasks still must not survive a reconnect.
    tasks: TcpStreamTasks,
    cfg: StreamPump,
) -> ClientStreamSender
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out_tx, mut out_rx) = mpsc::channel::<ClientUplink>(4096);
    let stream_sender = ClientStreamSender {
        logical_slot_id,
        sender: out_tx,
    };
    let base = tokio::time::Instant::now();
    let last_rx = Arc::new(AtomicU64::new(0));
    // This stream counts itself as live; its first dying task (reader/writer)
    // decrements and, only if it was the last, signals a full-tunnel teardown.
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

        let mut sink = if cfg.pipeline_rx {
            let (rec_tx, mut rec_rx) = mpsc::channel::<PooledBuffer>(1024);
            let mut inner_rx_codec = rx;
            let inner_tun = tun_write_tx;
            let inner_total_rx = total_rx.clone();
            let inner_runtime = runtime.clone();
            let inner_last_rx = last_rx.clone();
            let mut inner_mux = recordizer_config
                .clone()
                .map(crate::protocol::recordizer::Reassembler::new);
            // Stage B: inner ChaCha decrypt → TUN. Ends when the reader drops
            // `rec_tx`. Never blocks (the TUN send is drop-on-full), so it always
            // drains the FIFO — the reader's backpressure send can therefore
            // always make progress (no deadlock).
            let __h = tokio::spawn(async move {
                let mut unsupported_downlink_drops = 0u64;
                while let Some(mut record) = rec_rx.recv().await {
                    match inner_rx_codec.decrypt_packet_in_place(record.as_vec_mut()) {
                        Ok(()) => {
                            if !deliver_client_tcp_plaintext(
                                record,
                                &mut inner_mux,
                                &inner_tun,
                                family_mode,
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
            });
            register_tcp_stream_task(&tasks, __h);
            RxSink::Pipe(rec_tx)
        } else {
            RxSink::Inline {
                rx,
                tun: tun_write_tx,
                mux: recordizer_config.map(crate::protocol::recordizer::Reassembler::new),
            }
        };

        // Stage A: socket read (+ outer decrypt/framing for reality-tls) → sink.
        let __h = tokio::spawn(async move {
            let mut unsupported_downlink_drops = 0u64;
            loop {
                let mut record = match record_pool.acquire().await {
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
            // Stream lost (read side): tear down the whole tunnel only if this was
            // the last live stream; otherwise the tunnel keeps running on the rest.
            // Dropping `sink` here (its `Pipe` sender, if any) ends the inner task.
            let _ = stream_stop_tx.send(true);
            mark_tcp_stream_stopped(
                logical_slot_id,
                &stream_dead,
                &live,
                &dead_tx,
                active_slots.as_ref(),
                last_live_lost_at.as_ref(),
            );
        });
        register_tcp_stream_task(&tasks, __h);
    }

    // Writer + heartbeat: outgoing plaintext → encrypt → socket.
    {
        let mut tx = tx_codec;
        let dead_tx = dead_tx.clone();
        let stream_dead = stream_dead.clone();
        let live = live.clone();
        let active_slots = active_slots.clone();
        let last_live_lost_at = last_live_lost_at.clone();
        let stream_stop_tx = stream_stop_tx.clone();
        let mut stream_stop_rx = stream_stop_tx.subscribe();
        let __h = tokio::spawn(async move {
            let mut idle_tick = tokio::time::interval(Duration::from_secs(5));
            idle_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_tick_wall = std::time::SystemTime::now();
            let mut last_tick_inst = tokio::time::Instant::now();
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
            'writer: loop {
                let mux_deadline = recordizer
                    .as_ref()
                    .and_then(|mux| mux.deadline())
                    .map(tokio::time::Instant::from_std)
                    .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
                tokio::select! {
                    biased;

                    _ = stream_stop_rx.changed() => break,

                    pt = out_rx.recv() => {
                        let Some(pt) = pt else { break };
                        #[cfg(feature = "experimental-roaming")]
                        let pt = match pt {
                            ClientUplink::TerminalControl { packet, written } => {
                                let data_len = packet.len();
                                let payload_budget = if recordizer.is_some() {
                                    crate::protocol::packet::MAX_TUNNEL_MTU
                                } else {
                                    cfg.tun_mtu
                                };
                                let payloads = if let Some(mux) = recordizer.as_mut() {
                                    match mux.push(&packet, std::time::Instant::now()) {
                                        Ok(mut payloads) => {
                                            // A terminal control frame must not wait behind the
                                            // recordizer's morphology delay: the supervisor is
                                            // about to tear this generation down.
                                            if let Some(payload) = mux.flush() {
                                                payloads.push(payload);
                                            }
                                            Some(payloads)
                                        }
                                        Err(error) => {
                                            log::debug!(
                                                "TCP recordizer rejected CLOSE_SESSION: {error}"
                                            );
                                            None
                                        }
                                    }
                                } else {
                                    Some(vec![packet])
                                };
                                let Some(payloads) = payloads else {
                                    continue;
                                };
                                let mut delivered = true;
                                for payload in payloads {
                                    if !encrypt_client_payload(
                                        &mut tx,
                                        &payload,
                                        payload_budget,
                                        &cfg,
                                        &mut wire_record,
                                        &mut padding,
                                    ) || !write_client_wire_record(
                                        &mut write_half,
                                        &mut tx,
                                        &mut shaper,
                                        &wire_record,
                                        &mut cover_record,
                                        &mut padding,
                                    )
                                    .await
                                    {
                                        delivered = false;
                                        break;
                                    }
                                    last_tx_ms = base.elapsed().as_millis() as u64;
                                    heartbeat_deadline = tokio::time::Instant::now()
                                        + crate::protocol::randomized_heartbeat_delay(
                                            cfg.heartbeat_interval,
                                            Duration::from_millis(cfg.hb_jitter),
                                        );
                                }
                                if delivered {
                                    total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                                    let _ = written.send(());
                                    continue;
                                }
                                break 'writer;
                            }
                            packet => packet,
                        };
                        let data_len = pt.as_ref().len();
                        if let Some(mux) = recordizer.as_mut() {
                            let ready = mux.push(pt.as_ref(), std::time::Instant::now());
                            drop(pt);
                            let payloads = match ready {
                                Ok(payloads) => {
                                    total_tx.fetch_add(data_len as u64, Ordering::Relaxed);
                                    payloads
                                }
                                Err(error) => {
                                    log::debug!("TCP recordizer dropped a packet: {error}");
                                    continue;
                                }
                            };
                            for payload in payloads {
                                if !encrypt_client_payload(
                                    &mut tx,
                                    &payload,
                                    crate::protocol::packet::MAX_TUNNEL_MTU,
                                    &cfg,
                                    &mut wire_record,
                                    &mut padding,
                                ) {
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
                                    break;
                                }
                                last_tx_ms = base.elapsed().as_millis() as u64;
                                heartbeat_deadline = tokio::time::Instant::now()
                                    + crate::protocol::randomized_heartbeat_delay(
                                        cfg.heartbeat_interval,
                                        Duration::from_millis(cfg.hb_jitter),
                                    );
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
                        if hb_ready && write_half.write_all(&cover_record).await.is_err() {
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
                        let last_activity = last_tx_ms.max(last_rx.load(Ordering::Relaxed));
                        if idle_ms > 0 && now.saturating_sub(last_activity) > idle_ms {
                            break;
                        }
                    }

                    else => break,
                }
            }
            // Stream lost (write side): tear down the whole tunnel only if this was
            // the last live stream; otherwise keep running on the remaining streams.
            let _ = stream_stop_tx.send(true);
            mark_tcp_stream_stopped(
                logical_slot_id,
                &stream_dead,
                &live,
                &dead_tx,
                active_slots.as_ref(),
                last_live_lost_at.as_ref(),
            );
        });
        register_tcp_stream_task(&tasks, __h);
    }

    stream_sender
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
    #[cfg(feature = "experimental-roaming")]
    let tcp_control_v2 = client_capabilities.is_some_and(|client| {
        client.core_bits & crate::protocol::capabilities::client_capability::CONTROL_V2 != 0
    }) && server_capabilities.is_some_and(|server| {
        server.contains(crate::protocol::capabilities::server_capability::CONTROL_V2)
    });
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
        client.core_bits & crate::protocol::capabilities::client_capability::TCP_RESUME_V1 != 0
    }) && server_capabilities.is_some_and(
        |server| server.contains(crate::protocol::capabilities::server_capability::TCP_RESUME_V1),
    ) {
        let session_locator =
            decode_hex_array::<{ crate::protocol::roaming::SESSION_LOCATOR_LEN }>(&session_token)
                .ok_or_else(|| {
                anyhow::anyhow!(
                    "server negotiated TCP_RESUME_V1 but returned an invalid session locator"
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
            client.core_bits & crate::protocol::capabilities::client_capability::TCP_HANDOVER_V1
                != 0
        })
        && tcp_resume.is_some()
        && server_capabilities.is_some_and(|server| {
            server.contains(crate::protocol::capabilities::server_capability::TCP_HANDOVER_V1)
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
    let mut plan = build_network_plan(config, core.next_generation(), &network)?;
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_generation = plan.generation;
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
    let negotiated_family_mode = plan.family_mode;
    #[cfg(target_os = "linux")]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        tap_gateway_facts(&plan.addresses);
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        (None, 0, None, 0);
    let tunnel = core.prepare_tunnel(config, plan, &network)?;
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
    let server_addr = pin_target(config);
    #[cfg(target_os = "linux")]
    let tunnel_tun = tunnel.tun;
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
                    gateway_ipv4: tap_gateway_ipv4,
                    ipv4_prefix_len: tap_ipv4_prefix_len,
                    gateway_ipv6: tap_gateway_ipv6,
                    ipv6_prefix_len: tap_ipv6_prefix_len,
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
    // Handles for every task the bonded streams spawn, so the teardown can stop them.
    let stream_tasks: TcpStreamTasks = Arc::new(std::sync::Mutex::new(Vec::new()));
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
    let recordizer = pushed_obf
        .as_ref()
        .and_then(|pushed| pushed.recordizer.as_ref())
        .map(|config| {
            crate::protocol::recordizer::RuntimeConfig::from_config(
                config,
                crate::protocol::packet::MAX_TUNNEL_MTU,
                usize::try_from(tun_mtu)
                    .unwrap_or_default()
                    .saturating_add(64),
            )
        })
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid negotiated recordizer: {error}"))?;
    if recordizer.is_some() {
        log::info!("Packet recordizer: PACKET_MUX_V1 active on TCP");
    }

    let pump = StreamPump {
        framing,
        family_mode: negotiated_family_mode,
        heartbeat_enabled,
        heartbeat_interval,
        idle_timeout,
        tun_mtu: usize::try_from(tun_mtu)
            .map_err(|_| anyhow::anyhow!("authenticated TUN MTU is negative"))?,
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
        ramp_handle = Some(tokio::spawn(async move {
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
        }));
    }

    // Restore lost members of an established bond. Previously a dead secondary
    // merely reduced `live`; once the ramp task had ended nothing ever recreated
    // it, so a long-lived multipath session silently degraded to one stream.
    let maintenance_handle = if bonding || tcp_resume.is_some() {
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
        Some(tokio::spawn(async move {
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
                    Ok((stream, rx, tx)) => {
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
        }))
    } else {
        None
    };

    #[cfg(feature = "experimental-roaming")]
    let handover_handle = path_controller.map(|path_controller| {
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
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(TCP_HANDOVER_POLL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(candidate) = path_controller.prepared_candidate() else {
                    continue;
                };
                if !handover_enabled {
                    match path_controller
                        .abort_candidate_path(&candidate, "peer did not negotiate TCP_HANDOVER_V1")
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
                    tokio::time::timeout(PATH_ACK_TIMEOUT, commit)
                        .await
                        .map_err(|_| anyhow::anyhow!("COMMIT_PATH acknowledgement timed out"))??;
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
                    Ok((stream, rx, tx)) => {
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
        })
    });

    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_monitor_handle = linux_path_controller.map(|path_controller| {
        roaming_linux::spawn(path_controller, tun_name.clone(), path_generation)
    });

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
    // Only an intentional application shutdown is terminal. A carrier failure must retain the
    // server session so hard resume can reuse the existing NetworkPlan and TUN.
    #[cfg(feature = "experimental-roaming")]
    if cancel.load(Ordering::Acquire) && tcp_control_v2 {
        send_tcp_close_session(&outs).await;
    }

    if let Some(h) = ramp_handle {
        h.abort();
    }
    if let Some(h) = maintenance_handle {
        h.abort();
    }
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    if let Some(h) = path_monitor_handle {
        h.abort();
    }
    #[cfg(feature = "experimental-roaming")]
    if let Some(h) = handover_handle {
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
    stream.write_all(&commit).await?;
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
        let join = attach.first_message(transcript_hash);
        let join_packet = client_tx.encrypt_packet(&join, &[])?;
        stream.write_all(&join_packet).await?;
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

    // Present an authenticated resume proof, or the legacy token for an old session.
    let join = attach.first_message(transcript_hash);
    let join_packet = client_tx.encrypt_packet(&join, &[])?;
    stream.write_all(&join_packet).await?;

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
    tun: TunInterface,
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
    ceiling: i32,
    keep_df_after_success: bool,
) -> Option<i32> {
    use crate::protocol::udp_frag::{mtu_probe_datagram, parse_mtu_probe_ack};
    use std::time::Duration;
    if !begin_mtu_probe(socket) {
        return None;
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
    // Every challenge gets an independent id. A random start followed by predictable +1
    // still let one lucky off-path guess predict all later rungs.

    // One rung: send up to twice, accept only an ACK echoing this id AND this size.
    //
    // Requiring the echoed SIZE as well as the id is what stops a stale or forged ACK for a
    // different rung from pinning the client to an MTU the path cannot carry.
    macro_rules! try_mtu {
        ($m:expr) => {{
            let m: i32 = $m;
            let probe_id: u16 = rand::rng().random();
            let probe_size = (m as usize + UDP_RECORD_PROBE_OVERHEAD) as u16;
            match mtu_probe_datagram(probe_id, m as usize + UDP_RECORD_PROBE_OVERHEAD) {
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
                                    if parse_mtu_probe_ack(payload) == Some((probe_id, probe_size))
                                    {
                                        ok = true;
                                        break;
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

    // V1 has only a 16-bit correlation id for compatibility with old servers. Do not let a
    // single lucky off-path guess certify the session's final budget: require two additional,
    // independently random exact echoes after the search converges. Together with the probe
    // that selected the candidate this raises blind-forgery work from 2^16 to roughly 2^48,
    // without changing the wire format. If confirmation is lost/blocked, fail closed to the
    // existing conservative DATA_FRAG budget (or the legacy IP-fragmentation fallback).
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
    found
}

/// Select the inner MTU after a successful UDP path probe.
///
/// With DATA_FRAG_V1 the inner interface and the outer datagram budget are independent. For a
/// legacy peer they are not: lowering an IPv4 TUN to the certified record size avoids oversized
/// sends. IPv6 interfaces may not advertise less than 1280, so dual/IPv6 sessions retain that
/// floor and rely on the fragmentation-enabled outer socket for the remaining compatibility gap.
fn udp_inner_mtu_after_probe(
    base_mtu: i32,
    probed_mtu: i32,
    data_frag_enabled: bool,
    family_mode: crate::transport_core::NetworkFamilyMode,
) -> i32 {
    if data_frag_enabled {
        return base_mtu;
    }
    match family_mode {
        crate::transport_core::NetworkFamilyMode::Ipv4 => probed_mtu,
        crate::transport_core::NetworkFamilyMode::Ipv6
        | crate::transport_core::NetworkFamilyMode::Dual => probed_mtu.max(1280).min(base_mtu),
    }
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
            mtu_probe_ladder(1400, overhead, true),
            vec![1400, 1360, 1320, 1280, 1200, 1280 - overhead as i32]
        );
    }

    #[test]
    fn negotiated_record_fragmentation_keeps_inner_and_outer_mtu_independent() {
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, true, NetworkFamilyMode::Dual),
            1400
        );
    }

    #[test]
    fn legacy_udp_peer_uses_probe_without_breaking_ipv6_minimum_mtu() {
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, false, NetworkFamilyMode::Ipv4),
            1160
        );
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1160, false, NetworkFamilyMode::Ipv6),
            1280
        );
        assert_eq!(
            udp_inner_mtu_after_probe(1400, 1320, false, NetworkFamilyMode::Dual),
            1320
        );
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
                "wrong id must not advance confirmation"
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
    _framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    _quic_pn: &mut u32,
    _ceiling: i32,
    _keep_df_after_success: bool,
) -> Option<i32> {
    None // no kernel DF control off Linux → keep the pushed/effective MTU
}

#[cfg(target_os = "linux")]
struct NetworkPlanApplyGuard {
    if_name: String,
    owns_device: bool,
    server_addr: String,
    exclude: Vec<String>,
    gateway_lan_ipv4: String,
    gateway_lan_ipv6: String,
    gateway_enabled: bool,
    exit_enabled: bool,
    platform_state_touched: bool,
    routes_started: bool,
    dns_started: bool,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl NetworkPlanApplyGuard {
    fn new(config: &crate::config::client::ClientConfig, if_name: &str, owns_device: bool) -> Self {
        Self {
            if_name: if_name.to_string(),
            owns_device,
            server_addr: pin_target(config),
            exclude: config.routing.exclude.clone(),
            gateway_lan_ipv4: config.routing.lan_subnet.clone(),
            gateway_lan_ipv6: config.routing.lan_subnet_ipv6.clone(),
            gateway_enabled: config.routing.gateway_nat || config.routing.forward,
            exit_enabled: config.routing.exit_node,
            platform_state_touched: false,
            routes_started: false,
            dns_started: false,
            armed: true,
        }
    }

    fn touch_platform_state(&mut self) {
        self.platform_state_touched = true;
    }

    fn start_routes(&mut self) {
        self.routes_started = true;
    }

    fn start_dns(&mut self) {
        self.dns_started = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetworkPlanApplyGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        log::warn!(
            "Linux NetworkPlan failed before commit — rolling back platform state for {}",
            self.if_name
        );
        if self.dns_started {
            if let Err(error) = dns::restore_dns_for(&self.if_name) {
                log::warn!("DNS rollback after NetworkPlan failure also failed: {error}");
            }
        }
        if self.routes_started && self.owns_device {
            if let Err(error) =
                route::cleanup_routes(&self.if_name, &self.server_addr, &self.exclude)
            {
                log::warn!("route rollback after NetworkPlan failure also failed: {error}");
            }
        }
        if self.platform_state_touched {
            // A rejected reconnect generation must not leave old router permits active
            // while there is no acknowledged TUN plan. Both teardown functions are
            // idempotent and remove their IPv4 and IPv6 family halves independently.
            if let Err(error) = gateway::disengage_plan(
                &self.if_name,
                &self.gateway_lan_ipv4,
                &self.gateway_lan_ipv6,
                self.gateway_enabled,
                self.exit_enabled,
            ) {
                log::warn!("router rollback after NetworkPlan failure also failed: {error}");
            }
        }
        if self.owns_device {
            if let Err(error) = TunInterface::delete(&self.if_name) {
                log::warn!("TUN rollback after NetworkPlan failure also failed: {error}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn publish_network_plan_state(plan: &NetworkPlan) -> anyhow::Result<()> {
    let Ok(path) = std::env::var("QELI_TUNIP_FILE") else {
        return Ok(());
    };
    if path.is_empty() {
        return Ok(());
    }
    // First line remains compatible with the original attach-mode contract. Named
    // family lines let interface owners and legacy router wrappers consume the exact
    // authenticated family set without guessing from `ipv6=auto`.
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
    _network: &HandshakeNetwork<'_>,
) -> anyhow::Result<TunnelSetup> {
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

    // Attach mode must mirror the existing device's IFF_MULTI_QUEUE flag. Opening a
    // multi-queue TUN/TAP without it fails with EINVAL, while adding it to a single-queue
    // device is equally invalid. The attach helper also verifies TUN vs TAP and IFF_NO_PI.
    let device_type = if is_tap {
        DeviceType::Tap
    } else {
        DeviceType::Tun
    };
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
    // The caller cannot construct TunGuard until this function returns. Keep every
    // platform mutation in one local transaction instead: address/up, gateway and exit
    // firewall state, descriptor duplication, routes, DNS, and the final TAP MAC read.
    // The external interface in attach mode is borrowed and is therefore never deleted.
    let mut plan_guard = NetworkPlanApplyGuard::new(config, &if_name, !attach);
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
        if is_tap {
            TunInterface::set_mac(&if_name, planned_tap_mac)?;
        }
        for address in &plan.addresses {
            TunInterface::set_address(&if_name, &address.address, address.prefix_len)?;
        }
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
    if (config.routing.gateway_nat || config.routing.forward || config.routing.exit_node)
        && has_ipv4
    {
        plan_guard.touch_platform_state();
        crate::client::gateway::apply_tun_rp_filter(&if_name);
    }
    if config.routing.gateway_nat || config.routing.forward {
        if has_ipv4 {
            plan_guard.touch_platform_state();
            // `gateway_nat` masquerades; `forward` alone is pure L3 routing (#13).
            crate::client::gateway::engage(
                &if_name,
                &config.routing.lan_subnet,
                config.routing.gateway_nat,
            )?;
        }
        if has_ipv6 {
            plan_guard.touch_platform_state();
            crate::client::gateway::engage_ipv6(
                &if_name,
                &config.routing.lan_subnet_ipv6,
                config.routing.gateway_nat,
            )?;
        }
    }
    if config.routing.exit_node {
        if has_ipv4 {
            plan_guard.touch_platform_state();
            crate::client::gateway::engage_exit(&if_name)?;
        }
        if has_ipv6 {
            plan_guard.touch_platform_state();
            crate::client::gateway::engage_exit_ipv6(&if_name)?;
        }
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
            &config.routing,
            plan,
            &if_name,
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
    plan_guard.start_dns();
    let dns_result = dns::setup_network_plan_dns(&config.dns, &plan.dns_servers, &if_name);
    if plan.dns_servers.is_empty() {
        if let Err(e) = dns_result {
            log::warn!(
                "DNS was omitted from the network plan ({e}) — keeping the host resolver unchanged. \
                 Configure dns_servers, let the server push a reachable resolver, or set `dns = off` \
                 when the platform manages DNS itself."
            );
        }
    } else if let Err(e) = dns_result {
        return Err(anyhow::anyhow!(
            "DNS network-plan step failed: {e}. Set `dns = off` only when the platform manages DNS itself"
        ));
    }

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
    publish_network_plan_state(plan)?;
    plan_guard.disarm();
    Ok(TunnelSetup {
        tun,
        reader_fd: owned_reader,
        writer_fd: owned_writer,
        if_name,
        is_tap,
        tap_mac,
    })
}

#[cfg(target_os = "linux")]
fn read_interface_mac(ifname: &str) -> anyhow::Result<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))?;
    let bytes = text
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("interface '{ifname}' has an invalid MAC address"))
}

#[cfg(target_os = "linux")]
async fn connect_udp_candidates(
    config: &crate::config::client::ClientConfig,
    total: Duration,
) -> anyhow::Result<UdpSocket> {
    let host = config.server.address.as_str();
    let port = config.server.port;
    let resolved = match tokio::time::timeout(total, tokio::net::lookup_host((host, port))).await {
        Ok(result) => result
            .map_err(|error| anyhow::anyhow!("UDP DNS lookup for {host}:{port} failed: {error}"))?,
        Err(_) => {
            return Err(anyhow::anyhow!(
                "UDP DNS lookup for {host}:{port} timed out after {}s",
                total.as_secs()
            ));
        }
    };
    let mut seen = std::collections::HashSet::new();
    let mut candidates: Vec<std::net::SocketAddr> = resolved
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
#[allow(clippy::too_many_arguments)]
async fn send_client_udp_payload(
    payload: &[u8],
    client_tx: &mut PacketCodec,
    obfuscation: &crate::config::client::ClientObfuscationConfig,
    payload_budget: usize,
    data_record_budget: usize,
    data_frag_enabled: bool,
    tx_data_frag_key: &[u8; 32],
    tx_record_id: &mut u64,
    shaper: &mut crate::protocol::Shaper,
    socket: &crate::protocol::obfs::ObfsUdp,
    framing: crate::transport_core::udp_client_framing::UdpClientFraming,
    quic_pn: &mut u32,
    max_empty_record_padding: usize,
    wire_record: &mut Vec<u8>,
    cover_record: &mut Vec<u8>,
    quic_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
) -> bool {
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
    if normalization_padding != 0 {
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
        return false;
    }

    let delay = shaper.stealth_pace(wire_record.len(), std::time::Instant::now());
    if shaper.stealth() && !delay.is_zero() {
        let mut remaining = delay;
        while remaining > Duration::from_millis(6) {
            let cover_size = shaper
                .next_size(&mut rand::rng())
                .min(max_empty_record_padding);
            if shaper.try_spend(cover_size, std::time::Instant::now()) {
                let mut cover_obf = Obfuscator::new();
                cover_obf.generate_padding_into(cover_size as u16, cover_size as u16, padding);
                if client_tx
                    .encrypt_packet_into(&[], padding, cover_record)
                    .is_ok()
                {
                    let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                        framing,
                        cover_record,
                        quic_pn,
                        quic_record,
                    );
                    let _ = socket.send(send_data).await;
                }
            }
            let step = Duration::from_millis(rand::rng().random_range(4..=18));
            let sleep = step.min(remaining);
            tokio::time::sleep(sleep).await;
            remaining = remaining.saturating_sub(sleep);
        }
    } else if !delay.is_zero() {
        tokio::time::sleep(delay).await;
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
                return false;
            }
        };
        for fragment in fragments {
            let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                framing,
                &fragment,
                quic_pn,
                quic_record,
            );
            if let Err(error) = socket.send(send_data).await {
                log::warn!("UDP carrier fragment send failed: {error}");
                return false;
            }
        }
    } else {
        let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
            framing,
            wire_record,
            quic_pn,
            quic_record,
        );
        if let Err(error) = socket.send(send_data).await {
            log::warn!("UDP carrier send failed: {error}");
            return false;
        }
    }
    true
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
    receive_task: tokio::task::JoinHandle<()>,
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
    received_tx: mpsc::Sender<ClientUdpReceivedDatagram>,
) -> tokio::task::JoinHandle<()> {
    let receive_slots = crate::transport_core::udp_receive::UDP_RECEIVE_QUEUE_PACKETS + 1;
    let (receive_recycler, mut recycled_receivers) = mpsc::channel(receive_slots);
    for _ in 0..receive_slots {
        receive_recycler
            .try_send(bytes::BytesMut::with_capacity(
                crate::transport_core::udp_receive::MAX_UDP_PACKET_SIZE,
            ))
            .expect("fresh UDP receive recycler has exact advertised capacity");
    }
    tokio::spawn(async move {
        while let Some(mut datagram) = recycled_receivers.recv().await {
            match socket.recv_buf(&mut datagram).await {
                Ok(0) => {
                    datagram.clear();
                    if receive_recycler.send(datagram).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    let datagram = crate::transport_core::udp_receive::PooledUdpDatagram::new(
                        datagram,
                        receive_recycler.clone(),
                    );
                    if received_tx
                        .send(ClientUdpReceivedDatagram {
                            path_epoch,
                            datagram,
                            authenticated_plaintext: None,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) => {
                    log::debug!("UDP receive pump stopped: {error}");
                    break;
                }
            }
        }
    })
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
struct UdpClientLiveCandidate {
    prepared: Option<PreparedPathCandidate>,
    epoch: u64,
    socket: Arc<crate::protocol::obfs::ObfsUdp>,
    receive_task: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
impl UdpClientLiveCandidate {
    fn new(
        prepared: PreparedPathCandidate,
        epoch: u64,
        socket: Arc<crate::protocol::obfs::ObfsUdp>,
        receive_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            prepared: Some(prepared),
            epoch,
            socket,
            receive_task: Some(receive_task),
        }
    }

    fn prepared(&self) -> &PreparedPathCandidate {
        self.prepared
            .as_ref()
            .expect("live UDP candidate retains platform identity")
    }

    fn into_active(
        mut self,
    ) -> (
        PreparedPathCandidate,
        Arc<crate::protocol::obfs::ObfsUdp>,
        tokio::task::JoinHandle<()>,
    ) {
        let prepared = self
            .prepared
            .take()
            .expect("committed UDP candidate retains platform identity");
        let receive_task = self
            .receive_task
            .take()
            .expect("committed UDP candidate retains receive pump");
        (prepared, self.socket.clone(), receive_task)
    }
}

#[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
impl Drop for UdpClientLiveCandidate {
    fn drop(&mut self) {
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }
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
    let raw_socket = connect_udp_candidates(
        config,
        Duration::from_secs(config.server.connection_timeout_secs.max(1)),
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

    // Auto MTU on UDP: when `mtu = 0` and probing is on, actively discover the path
    // MTU (DF probes from the pushed ceiling down) before bringing the TUN up — so a
    // narrow LTE/CGNAT path is measured, not guessed. Otherwise adopt the pushed MTU.
    // The client data plane is not running yet, but the server may already emit cover or a
    // heartbeat after AuthOK. The probe receive loop ignores unrelated datagrams until each
    // fixed deadline. Falls back to the pushed/effective MTU on any miss.
    let base_mtu = effective_mtu(config.tun.mtu, pushed_mtu);
    let mut uplink_udp_payload_budget =
        crate::protocol::data_frag::conservative_udp_payload_budget(socket.peer_is_ipv6());
    let mut keep_df_after_live_probe = false;
    let tun_mtu = if config.tun.mtu == 0 && config.tun.mtu_probe {
        match probe_udp_mtu(
            &socket,
            udp_framing,
            &mut quic_pn,
            base_mtu,
            data_frag_enabled,
        )
        .await
        {
            Some(m) => {
                keep_df_after_live_probe = data_frag_enabled;
                // The probe sent `m + record-overhead`, then QUIC/obfs wrapped it. Record
                // the UDP payload size it actually certified separately from inner MTU.
                uplink_udp_payload_budget = udp_payload_budget_for_probe(
                    m,
                    socket.seal_overhead(),
                    udp_framing.wrapper_len(),
                );
                // Inner and outer MTU stay independent when DATA_FRAG_V1 was negotiated.
                // A legacy server cannot reassemble record fragments, so use the certified
                // inner size for IPv4. IPv6 keeps its mandatory 1280 floor; the probe restored
                // outer fragmentation in that compatibility mode.
                let inner_mtu =
                    udp_inner_mtu_after_probe(base_mtu, m, data_frag_enabled, family_mode);
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
        base_mtu
    };
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
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_generation = plan.generation;
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
    let negotiated_family_mode = plan.family_mode;
    #[cfg(target_os = "linux")]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        tap_gateway_facts(&plan.addresses);
    #[cfg(any(target_os = "android", target_os = "macos"))]
    let (tap_gateway_ipv4, tap_ipv4_prefix_len, tap_gateway_ipv6, tap_ipv6_prefix_len) =
        (None, 0, None, 0);
    let tun_setup = core.prepare_tunnel(config, plan, &network)?;
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
    let server_addr = pin_target(config);
    #[cfg(target_os = "linux")]
    let tunnel_tun = tun_setup.tun;
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
                    gateway_ipv4: tap_gateway_ipv4,
                    ipv4_prefix_len: tap_ipv4_prefix_len,
                    gateway_ipv6: tap_gateway_ipv6,
                    ipv6_prefix_len: tap_ipv6_prefix_len,
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
    let mut udp_tx_recordizer = udp_recordizer_runtime
        .clone()
        .map(crate::protocol::recordizer::Recordizer::new);
    let mut udp_rx_recordizer =
        udp_recordizer_runtime.map(crate::protocol::recordizer::Reassembler::new);
    if udp_tx_recordizer.is_some() {
        log::info!("Packet recordizer: PACKET_MUX_V1 active on UDP");
    }
    let mut max_empty_record_padding = client_tx
        .max_padding_for_record_budget(0, data_record_budget)
        .map_err(|error| {
            anyhow::anyhow!("UDP record budget cannot carry control traffic: {error}")
        })?;
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
    let mut udp_payload_budget_report_value = data_frag_enabled
        .then(|| u16::try_from(uplink_udp_payload_budget).ok())
        .flatten()
        .filter(|budget| {
            usize::from(*budget)
                > crate::protocol::data_frag::conservative_udp_payload_budget(socket.peer_is_ipv6())
        });
    // Arm retries from intent, not from the result of the first local send. If both initial
    // datagrams hit a transient socket error, the idle ticks must still get a chance to report.
    let mut control_report_resends =
        if mtu_report_value.is_some() || udp_payload_budget_report_value.is_some() {
            UDP_CONTROL_REPORT_RESENDS
        } else {
            0
        };
    if let Some(budget) = udp_payload_budget_report_value {
        let frame = crate::protocol::ctrl::udp_payload_budget_report(budget);
        if let Some(mux) = udp_tx_recordizer.as_mut() {
            if let Err(error) = mux.push(&frame, std::time::Instant::now()) {
                log::debug!("could not queue UDP payload budget report: {error}");
            }
        } else if client_tx
            .encrypt_packet_into(&frame, &[], &mut cover_record)
            .is_ok()
        {
            let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                udp_framing,
                &cover_record,
                &mut quic_pn,
                &mut quic_record,
            );
            match socket.send(send_data).await {
                Ok(_) => {
                    log::debug!("reported UDP payload budget {budget} to the server");
                }
                Err(e) => log::debug!("could not report UDP payload budget: {e}"),
            }
        }
    }
    if let Some(mtu) = mtu_report_value {
        let frame = crate::protocol::ctrl::mtu_report(mtu);
        if let Some(mux) = udp_tx_recordizer.as_mut() {
            if let Err(error) = mux.push(&frame, std::time::Instant::now()) {
                log::debug!("could not queue UDP MTU report: {error}");
            }
        } else if client_tx
            .encrypt_packet_into(&frame, &[], &mut cover_record)
            .is_ok()
        {
            let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                udp_framing,
                &cover_record,
                &mut quic_pn,
                &mut quic_record,
            );
            match socket.send(send_data).await {
                Ok(_) => {
                    log::debug!("reported tunnel MTU {mtu} to the server");
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
            let send_data = crate::transport_core::udp_client_framing::wrap_next_udp_record(
                udp_framing,
                &cover_record,
                &mut quic_pn,
                &mut quic_record,
            );
            if let Err(e) = socket.send(send_data).await {
                log::debug!("could not report client version: {e}");
            }
        }
    }

    // Live PMTU widening is available only when DATA_FRAG decouples the TUN MTU from the
    // carrier datagram size. A legacy peer would require rebuilding the interface/routes.
    let live_mtu_reprobe_enabled = data_frag_enabled && config.tun.mtu == 0 && config.tun.mtu_probe;
    let mut live_mtu_probe = LiveUdpMtuProbe::default();
    let mut live_mtu_due = tokio::time::interval(UDP_MTU_REPROBE_INTERVAL);
    live_mtu_due.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume interval's immediate first tick: startup probing just ran above.
    live_mtu_due.tick().await;
    let mut live_mtu_tick = tokio::time::interval(UDP_MTU_REPROBE_TICK);
    live_mtu_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    live_mtu_tick.tick().await;

    // Handshake reception is complete. From here one dedicated reader keeps recvmsg moving
    // while this task performs decrypt/reassembly/TUN work. The bounded FIFO preserves packet
    // order and does not touch DATA_FRAG or either PMTU state machine.
    drop(recv_buf);
    let (received_tx, mut received_rx) =
        mpsc::channel(crate::transport_core::udp_receive::UDP_RECEIVE_QUEUE_PACKETS);
    #[cfg_attr(
        not(all(feature = "experimental-roaming", any(unix, windows))),
        allow(unused_mut)
    )]
    let mut udp_receive_task =
        spawn_client_udp_receive_pump(socket.clone(), 0, received_tx.clone());
    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    let path_monitor_handle = if udp_handover_enabled {
        linux_path_controller.map(|path_controller| {
            roaming_linux::spawn(path_controller, tun_name.clone(), path_generation)
        })
    } else {
        None
    };
    let (_candidate_connect_tx, mut candidate_connect_rx) =
        mpsc::channel::<(PreparedPathCandidate, anyhow::Result<UdpSocket>)>(1);
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut candidate_connect_task: Option<tokio::task::JoinHandle<()>> = None;
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
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let mut committed_early_data = std::collections::VecDeque::<ClientUdpReceivedDatagram>::new();

    let mut unsupported_inner_drops = 0u64;
    'udp: loop {
        let mux_deadline = udp_tx_recordizer
            .as_ref()
            .and_then(|mux| mux.deadline())
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            _ = cancel_tick.tick() => {
                if cancel.load(Ordering::Acquire) { break; }
            }

            _ = udp_buffer_tick.tick() => {
                udp_buffer.tick(socket.raw_socket());
            }

            _ = candidate_tick.tick(), if udp_handover_enabled => {
                #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
                {
                let drain_expired = draining_udp_path
                    .as_ref()
                    .is_some_and(|draining| tokio::time::Instant::now() > draining.expires_at);
                if drain_expired {
                    let draining = draining_udp_path
                        .take()
                        .expect("expired UDP receive drain was present");
                    draining.receive_task.abort();
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
                    drop(candidate);
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
                                drop(candidate);
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
                            drop(candidate);
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
                        candidate_connect_task = Some(tokio::spawn(async move {
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
                candidate_connect_task.take();
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
                    drop(live_udp_candidate.take());
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
                    if !send_client_udp_payload(
                        &payload,
                        &mut client_tx,
                        &eff_obf,
                        mux_payload_budget,
                        data_record_budget,
                        data_frag_enabled,
                        &tx_data_frag_key,
                        &mut tx_record_id,
                        &mut shaper,
                        &socket,
                        udp_framing,
                        &mut quic_pn,
                        max_empty_record_padding,
                        &mut wire_record,
                        &mut cover_record,
                        &mut quic_record,
                        &mut padding,
                    )
                    .await
                    {
                        break 'udp;
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

            _ = live_mtu_due.tick(), if live_mtu_reprobe_enabled && !live_mtu_probe.is_active() => {
                let outer_overhead = UDP_RECORD_PROBE_OVERHEAD
                    + socket.seal_overhead()
                    + udp_framing.wrapper_len()
                    + 8
                    + if socket.peer_is_ipv6() { 40 } else { 20 };
                let candidates: Vec<i32> = mtu_probe_ladder(
                    base_mtu,
                    outer_overhead,
                    socket.peer_is_ipv6(),
                )
                .into_iter()
                .filter(|candidate| {
                    udp_payload_budget_for_probe(
                        *candidate,
                        socket.seal_overhead(),
                        udp_framing.wrapper_len(),
                    ) > uplink_udp_payload_budget
                })
                .collect();
                if !candidates.is_empty() {
                    if begin_mtu_probe(&socket) {
                        log::debug!(
                            "UDP live PMTU re-probe started ({} candidate rungs above {}-byte budget)",
                            candidates.len(),
                            uplink_udp_payload_budget,
                        );
                        live_mtu_probe.start(candidates);
                    } else {
                        log::debug!("UDP live PMTU re-probe skipped: DF control is unavailable");
                    }
                }
            }

            _ = live_mtu_tick.tick(), if live_mtu_reprobe_enabled && live_mtu_probe.is_active() => {
                if let Some((probe_id, candidate)) =
                    live_mtu_probe.next_send(tokio::time::Instant::now())
                {
                    if let Some(probe) = crate::protocol::udp_frag::mtu_probe_datagram(
                        probe_id,
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
                    // All larger rungs failed. Preserve the already-certified budget and
                    // restore the DF state that was active before this re-probe.
                    finish_mtu_probe(&socket, keep_df_after_live_probe);
                    log::debug!(
                        "UDP live PMTU re-probe found no wider path; keeping {}-byte budget",
                        uplink_udp_payload_budget,
                    );
                }
            }

            packet = tun_pump.recv_from_tun() => {
                let Some(ip_packet) = packet else {
                    log::warn!("UDP: TUN reader stopped — reconnecting");
                    break;
                };
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
                    let payloads = match mux.push(
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
                    for payload in payloads {
                        if !send_client_udp_payload(
                            &payload,
                            &mut client_tx,
                            &eff_obf,
                            mux_payload_budget,
                            data_record_budget,
                            data_frag_enabled,
                            &tx_data_frag_key,
                            &mut tx_record_id,
                            &mut shaper,
                            &socket,
                            udp_framing,
                            &mut quic_pn,
                            max_empty_record_padding,
                            &mut wire_record,
                            &mut cover_record,
                            &mut quic_record,
                            &mut padding,
                        )
                        .await
                        {
                            break 'udp;
                        }
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
                    if normalization_padding != 0 {
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
                            let csize = shaper
                                .next_size(&mut rand::rng())
                                .min(tun_mtu.max(0) as usize)
                                .min(max_empty_record_padding);
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
                                    let send_data =
                                        crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                            udp_framing,
                                            &cover_record,
                                            &mut quic_pn,
                                            &mut quic_record,
                                        );
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
                        let mut send_failed = None;
                        for fragment in fragments {
                            let send_data =
                                crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                    udp_framing,
                                    &fragment,
                                    &mut quic_pn,
                                    &mut quic_record,
                                );
                            if let Err(error) = socket.send(send_data).await {
                                send_failed = Some(error);
                                break;
                            }
                        }
                        if let Some(error) = send_failed {
                            log::warn!("UDP carrier fragment send failed: {error}");
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
                            break;
                        }
                    }
                }
            }

            received = async {
                if let Some(buffered) = committed_early_data.pop_front() {
                    Some(buffered)
                } else {
                    received_rx.recv().await
                }
            } => {
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
                                drop(candidate);
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
                                drop(candidate);
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
                                drop(candidate);
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
                            if let Some(previous) = draining_udp_path.take() {
                                previous.receive_task.abort();
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
                            uplink_udp_payload_budget = next_payload_budget;
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
                            drop(candidate);
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
                if let Some((probe_id, probe_size)) =
                    crate::protocol::udp_frag::parse_mtu_probe_ack(payload)
                {
                    let matches_live_challenge = live_mtu_probe
                        .challenge
                        .filter(|_| !receive_is_draining)
                        .map(|challenge| {
                            challenge.id == probe_id && challenge.outer_size == probe_size
                        })
                        .unwrap_or(false);
                    if matches_live_challenge {
                        if let Some(candidate) =
                            live_mtu_probe.acknowledge(probe_id, probe_size)
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
                                    uplink_udp_payload_budget = new_payload_budget;
                                    data_record_budget = record_budget;
                                    max_empty_record_padding = padding_budget;
                                    udp_payload_budget_report_value =
                                        u16::try_from(new_payload_budget).ok();
                                    control_report_resends = UDP_CONTROL_REPORT_RESENDS;
                                    keep_df_after_live_probe = true;
                                    finish_mtu_probe(&socket, true);
                                    log::info!(
                                        "UDP live PMTU widened uplink payload budget to {} bytes (probe rung {})",
                                        new_payload_budget,
                                        candidate,
                                    );
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
                        if let Some(reassembler) = udp_rx_recordizer.as_mut() {
                            if record.is_empty() {
                                continue;
                            }
                            let mut first_packet = None;
                            let mut extra_packets = Vec::new();
                            let mut pool_exhausted_drops = 0_u64;
                            let mut oversize_drops = 0_u64;
                            let decode_result = reassembler.decode_with(&record, |bytes| {
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
                // Fill genuine idle on OUR send side (last_tx_inst); in STEALTH run
                // cover under load too so small cover mixes into the rate-capped stream.
                if shaper.stealth() || last_tx_inst.elapsed() >= Duration::from_millis(50) {
                    // Cap idle-cover size to the probed MTU (see the stealth-cover branch).
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
                // Re-send the unacknowledged MTU/budget reports (#5). `idle_check` fires
                // immediately on its first tick, so the copies land at roughly 0 s, 5 s and
                // 10 s: the first covers an isolated drop, the later ones a short burst that
                // would take out back-to-back datagrams. Both server updates are idempotent.
                if control_report_resends > 0 {
                    control_report_resends -= 1;
                    if let Some(budget) = udp_payload_budget_report_value {
                        let frame = crate::protocol::ctrl::udp_payload_budget_report(budget);
                        if let Some(mux) = udp_tx_recordizer.as_mut() {
                            if let Err(error) = mux.push(&frame, std::time::Instant::now()) {
                                log::debug!("could not queue UDP payload budget report retry: {error}");
                            }
                        } else if client_tx
                            .encrypt_packet_into(&frame, &[], &mut cover_record)
                            .is_ok()
                        {
                            let send_data =
                                crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                    udp_framing,
                                    &cover_record,
                                    &mut quic_pn,
                                    &mut quic_record,
                                );
                            let _ = socket.send(send_data).await;
                        }
                    }
                    if let Some(mtu) = mtu_report_value {
                        let frame = crate::protocol::ctrl::mtu_report(mtu);
                        if let Some(mux) = udp_tx_recordizer.as_mut() {
                            if let Err(error) = mux.push(&frame, std::time::Instant::now()) {
                                log::debug!("could not queue UDP MTU report retry: {error}");
                            }
                        } else if client_tx
                            .encrypt_packet_into(&frame, &[], &mut cover_record)
                            .is_ok()
                        {
                            let send_data =
                                crate::transport_core::udp_client_framing::wrap_next_udp_record(
                                    udp_framing,
                                    &cover_record,
                                    &mut quic_pn,
                                    &mut quic_record,
                                );
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
                                crate::transport_core::udp_roaming_client::UdpClientNatRecoveryDecision::WaitForCandidate => {
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

    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    if let Some(task) = path_monitor_handle {
        task.abort();
    }
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    let connect_was_in_flight = if let Some(task) = candidate_connect_task.take() {
        task.abort();
        true
    } else {
        false
    };
    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    if let Some(candidate) = live_udp_candidate.take() {
        let prepared = candidate.prepared().clone();
        if let Some(roaming) = udp_roaming.as_mut() {
            roaming.abort_candidate(prepared.candidate_id);
        }
        drop(candidate);
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

    #[cfg(all(feature = "experimental-roaming", any(unix, windows)))]
    if let Some(draining) = draining_udp_path.take() {
        draining.receive_task.abort();
        let _ = draining.receive_task.await;
    }
    udp_receive_task.abort();
    let _ = udp_receive_task.await;

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

    #[test]
    fn linux_adapter_enters_running_only_after_platform_apply() {
        let (mut adapter, _) = LinuxCoreAdapter::new(CONFIG).unwrap();
        adapter.begin_connection(false).unwrap();
        assert_eq!(
            adapter.with_core(|core| core.state()),
            ClientState::Connecting
        );

        let generation = adapter.next_generation();
        let result = adapter
            .apply_network_plan(plan(generation), |event_plan| {
                assert_eq!(event_plan.generation, generation);
                assert_eq!(event_plan.routes[0].gateway, "10.20.0.1");
                Ok(42)
            })
            .unwrap();

        assert_eq!(result, 42);
        assert_eq!(adapter.with_core(|core| core.state()), ClientState::Running);
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
