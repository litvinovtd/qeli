pub mod acl;
pub mod client_manager;
pub mod control;
pub mod dhcp;
pub mod dns;
pub mod handler;
pub mod metrics;
pub mod nat;
pub mod notify;
pub mod pool;
pub mod preflight;
pub mod reality;
mod roaming_metrics;
pub mod udp_handler;
pub mod update;
pub mod usage;
pub mod web;

use crate::config::server::{ProfileConfig, ServerConfig};
use crate::config::users::UsersDb;
use crate::crypto::StaticKeypair;
use crate::server::handler::SessionShared;
use crate::transport::tcp::{set_tcp_buffers, set_tcp_keepalive};
use crate::transport::TransportProtocol;
use crate::transport_core::buffer_pool::{BufferPool, PooledBuffer};
use crate::tun::iface::TunInterface;
use crate::tun::mac_from_ip;
use crate::tun::prepend_ethernet_header;
use crate::tun::server_tap_control_reply;
use crate::tun::strip_ethernet_header;
use crate::tun::DeviceType;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, RwLock};

const TAP_GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Re-export: the implementation moved to `crate::util` so the CLIENT can use it too.
///
/// `server` is behind `feature = "server"` and is absent from the router/client-only
/// build, which is why the client half of the tree carried 12 raw `.lock().unwrap()`
/// instead — the helper simply was not reachable from there. (Audit 2026-08-04.)
pub use crate::util::lock_or_recover;

/// Hard cap on the number of distinct source IPs tracked at once. A spoofed UDP
/// flood can present a unique forged source IP per packet; without a bound the
/// `attempts` map would grow one small entry per IP until the 300s cleanup
/// interval elapses. When the map exceeds this cap we run [`cleanup`] eagerly
/// (reclaiming any expired entries) and, if it is *still* over the cap (a live
/// flood of unique IPs all inside the window), clear the map entirely. Dropping
/// the table is safe: the entries are transient per-IP counters, and the real
/// pre-auth flood defenses (`MAX_PENDING_HANDSHAKES` + the pre-auth semaphore)
/// are unaffected. The cap is far above any plausible count of legitimate
/// distinct clients within the window.
const MAX_TRACKED_IPS: usize = 100_000;

/// Target memory budget for packets read from all TUN queues of one profile. The former
/// `raw.to_vec()` path allocated once per packet and let every 4096-slot queue retain its own
/// heap allocations. A shared pool bounds the aggregate instead and returns each allocation
/// when the async forwarder finishes with it. At least one slot per queue is retained, so an
/// explicitly extreme queue-count/read-buffer combination may raise the bound above 32 MiB.
const SERVER_TUN_READ_POOL_BYTES: usize = 32 * 1024 * 1024;
/// Independent client→TUN budget. Keeping the directions separate prevents a slow downlink
/// forwarder from consuming every allocation needed to drain authenticated uplink records.
const SERVER_TUN_WRITE_POOL_BYTES: usize = 32 * 1024 * 1024;

fn server_tun_read_buffer_count(queue_count: usize, buffer_capacity: usize) -> usize {
    (SERVER_TUN_READ_POOL_BYTES / buffer_capacity.max(1))
        .max(queue_count)
        .max(1)
}

pub(crate) enum ServerTunPacket {
    Pooled(PooledBuffer),
    /// IPv4 fragmentation is exceptional and inherently creates new packets. Keeping those
    /// owned here lets the common unfragmented path remain allocation-free.
    Fragment(Vec<u8>),
}

/// Internal exit-node defaults granted to one source session by its effective pushed
/// routes. Without this per-family authorization any authenticated client could manually
/// direct a default into qeli and consume an exit assigned to somebody else.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExitAccess {
    pub(crate) ipv4: bool,
    pub(crate) ipv6: bool,
}

impl ExitAccess {
    fn allows(self, destination: std::net::IpAddr) -> bool {
        match destination {
            std::net::IpAddr::V4(_) => self.ipv4,
            std::net::IpAddr::V6(_) => self.ipv6,
        }
    }
}

impl std::ops::Deref for ServerTunPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Pooled(packet) => packet,
            Self::Fragment(packet) => packet,
        }
    }
}

#[derive(Clone)]
pub(crate) struct TunIngress {
    pub(crate) sender: mpsc::Sender<ServerTunPacket>,
    /// Direct client-to-client path into the same downlink forwarder that normally drains
    /// this TUN queue.  A default `client_subnet` (the exit-node case) must never be
    /// installed as the Linux host's default route: doing so would recursively capture the
    /// server's own WAN/control traffic.  Authenticated inner packets can instead enter the
    /// regular lookup/MTU/encryption pipeline here without touching the host routing table.
    pub(crate) forwarder: mpsc::Sender<ServerTunPacket>,
    pub(crate) pool: BufferPool,
}

impl TunIngress {
    /// Deliver one already-authenticated client packet either to another qeli session or
    /// to the host TUN.  Direct delivery is used only when client-to-client routing is
    /// enabled and the longest-prefix destination belongs to a *different* session.
    /// Skipping self-delivery is essential for an exit client: its own internet-bound
    /// packet also matches its `0.0.0.0/0`/`::/0` iroute and must reach the physical WAN,
    /// not bounce back into the same tunnel.
    pub(crate) async fn send_client_packet(
        &self,
        profile: &ProfileRuntime,
        source_session_id: u64,
        exit_access: ExitAccess,
        packet: ServerTunPacket,
    ) -> Result<(), mpsc::error::SendError<ServerTunPacket>> {
        let use_direct_path = if profile.config.routing.client_to_client {
            match crate::protocol::ip::parse_ip_packet(&packet) {
                Ok(meta) => {
                    let sessions = profile.sessions.read().await;
                    let destination = sessions
                        .get_by_address(meta.destination)
                        .map(|session| (session, false))
                        .or_else(|| {
                            sessions
                                .route_match(meta.destination)
                                .map(|route| (&route.session, route.prefix == 0))
                        });
                    destination.is_some_and(|(destination, is_default)| {
                        destination.session_id != source_session_id
                            && !destination.is_revoked()
                            && (!is_default || exit_access.allows(meta.destination))
                    })
                }
                Err(_) => false,
            }
        } else {
            false
        };
        if use_direct_path {
            self.forwarder.send(packet).await
        } else {
            self.sender.send(packet).await
        }
    }
}

pub struct RateLimiter {
    attempts: HashMap<IpAddr, VecDeque<Instant>>,
    max_attempts: usize,
    window: Duration,
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        RateLimiter {
            attempts: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    pub fn check_and_record(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) > self.cleanup_interval
            || self.attempts.len() > MAX_TRACKED_IPS
        {
            self.cleanup();
            // A live spoofed flood can present unique forged source IPs faster
            // than the window expires them, so cleanup alone may not shrink the
            // map. If it is still over the cap, drop the table wholesale to keep
            // memory bounded — these are transient per-IP counters and the real
            // flood defenses live elsewhere (see MAX_TRACKED_IPS).
            if self.attempts.len() > MAX_TRACKED_IPS {
                self.attempts.clear();
            }
            self.last_cleanup = now;
        }
        let window = self.window;
        let entry = self.attempts.entry(ip).or_default();
        while entry
            .front()
            .map(|t| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
            entry.pop_front();
        }
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push_back(now);
        true
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        let window = self.window;
        self.attempts.retain(|_, timestamps| {
            timestamps.retain(|t| now.duration_since(*t) <= window);
            !timestamps.is_empty()
        });
    }
}

/// Anti-replay guard for REALITY `session_id` tokens.
///
/// A censor can capture a genuine ClientHello off the wire and replay it verbatim
/// while the embedded timestamp is still inside the acceptance window. Without a
/// memory of what we have already accepted, the replay re-authenticates and the
/// server unmasks itself: it terminates TLS (serving a ServerHello that does not
/// match `dest`) where a real host would simply relay the target. This guard
/// remembers every accepted token for a TTL and reports a second sighting as a
/// replay, so the caller bridges it to `dest` like any unauthenticated peer.
///
/// Honest clients never trigger a false positive: each connection seals a fresh
/// X25519 ephemeral into the token, so two genuine ClientHellos differ even with
/// the same short_id in the same second. Only a byte-for-byte replay repeats one.
///
/// The TTL is twice the acceptance window (`reality::REALITY_WINDOW_SECS`): a
/// token stays timestamp-valid for up to ±window around its embedded time — a
/// 2×window span — so 2×window retention guarantees we never forget a token that
/// could still be accepted. Expired entries are evicted FIFO on every call, so
/// memory is bounded by the number of distinct tokens accepted within the window.
pub struct ReplayGuard {
    seen: HashSet<[u8; 32]>,
    fifo: VecDeque<(Instant, [u8; 32])>,
    ttl: Duration,
}

impl ReplayGuard {
    pub fn new(ttl: Duration) -> Self {
        ReplayGuard {
            seen: HashSet::new(),
            fifo: VecDeque::new(),
            ttl,
        }
    }

    /// Record `sid` and report whether it is fresh: `true` the first time a token
    /// is seen within the TTL, `false` on replay.
    pub fn observe(&mut self, sid: &[u8; 32]) -> bool {
        self.observe_at(sid, Instant::now())
    }

    /// `observe` with an explicit clock, for deterministic tests.
    fn observe_at(&mut self, sid: &[u8; 32], now: Instant) -> bool {
        // Evict everything older than the window (oldest at the front).
        while let Some(&(t, id)) = self.fifo.front() {
            if now.saturating_duration_since(t) < self.ttl {
                break;
            }
            self.fifo.pop_front();
            self.seen.remove(&id);
        }
        if !self.seen.insert(*sid) {
            return false; // already accepted within the window → replay
        }
        self.fifo.push_back((now, *sid));
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.len()
    }
}

pub struct SessionMap {
    /// Tunnel IP → session. With multipath a session aggregates several bonded
    /// connections (streams) behind this one IP.
    /// Primary tunnel address -> session. A dual-stack session is present exactly once
    /// here, so limits and control-plane enumeration never double-count it.
    pub by_ip: HashMap<std::net::IpAddr, Arc<SessionShared>>,
    /// Every assigned tunnel address -> session. Dual-stack sessions have two entries.
    pub by_address: HashMap<std::net::IpAddr, Arc<SessionShared>>,
    /// Join token → tunnel IP, for attaching secondary bonded streams.
    pub by_token: HashMap<[u8; crate::server::handler::JOIN_TOKEN_LEN], std::net::IpAddr>,
    /// Subnets/addresses behind clients (OpenVPN `iroute`): inbound traffic whose
    /// destination is NOT a pool IP is longest-prefix-matched here, so the server can
    /// route to a client's extra address / LAN, not only its assigned tunnel IP.
    /// Registered at auth from the user's `client_subnets`, removed when the session
    /// ends. Consulted ONLY after a `by_ip` miss (#13).
    pub client_routes: Vec<ClientRoute>,
}

/// One inbound route to a client's session (see [`SessionMap::client_routes`]).
pub struct ClientRoute {
    /// Network address, host bits already zeroed (matches [`route_masked`]).
    net: RouteNetwork,
    /// Prefix length 0..=32 for IPv4 or 0..=128 for IPv6.
    prefix: u8,
    /// Canonical network CIDR — for the kernel `ip route` add/del and log lines.
    pub cidr: String,
    /// The owning session's pool IP, so all its routes drop together on disconnect.
    pub client_ip: std::net::IpAddr,
    /// The session this subnet is routed into.
    pub session: Arc<SessionShared>,
}

/// Mask `ip` to `prefix` bits (host bits zeroed). `prefix == 0` → 0 (avoids the
/// shift-by-32 UB `!0u32 << 32`).
fn route_masked_v4(ip: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        ip & (!0u32 << (32 - prefix))
    }
}

fn route_masked_v6(ip: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        ip & (!0u128 << (128 - prefix))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteNetwork {
    V4(u32),
    V6(u128),
}

impl ClientRoute {
    /// Parse `"10.20.0.0/24"` or a bare `"192.168.5.7"` (= /32) into a route for
    /// `session`. Returns `None` on a malformed CIDR or an out-of-family prefix.
    pub fn parse(
        cidr: &str,
        client_ip: std::net::IpAddr,
        session: Arc<SessionShared>,
    ) -> Option<ClientRoute> {
        let s = cidr.trim();
        let (addr, explicit_prefix) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let ip: std::net::IpAddr = addr.parse().ok()?;
        let prefix = explicit_prefix.unwrap_or(if ip.is_ipv4() { 32 } else { 128 });
        let (net, canonical_cidr) = match ip {
            std::net::IpAddr::V4(ip) if prefix <= 32 => {
                let network = route_masked_v4(u32::from(ip), prefix);
                (
                    RouteNetwork::V4(network),
                    format!("{}/{}", std::net::Ipv4Addr::from(network), prefix),
                )
            }
            std::net::IpAddr::V6(ip) if prefix <= 128 => {
                let network = route_masked_v6(u128::from(ip), prefix);
                (
                    RouteNetwork::V6(network),
                    format!("{}/{}", std::net::Ipv6Addr::from(network), prefix),
                )
            }
            _ => return None,
        };
        Some(ClientRoute {
            net,
            prefix,
            // Kernel route commands require a canonical network prefix on several iproute2
            // versions. Keeping host bits here also let two spellings of one subnet evade
            // the first-owner conflict check.
            cidr: canonical_cidr,
            client_ip,
            session,
        })
    }

    /// Prefix length (0..=32 for IPv4, 0..=128 for IPv6); zero is an internal-only
    /// exit-node default and is never installed into the host routing table.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// True if `ip` falls inside this route's network.
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        match (self.net, ip) {
            (RouteNetwork::V4(net), std::net::IpAddr::V4(ip)) => {
                route_masked_v4(u32::from(ip), self.prefix) == net
            }
            (RouteNetwork::V6(net), std::net::IpAddr::V6(ip)) => {
                route_masked_v6(u128::from(ip), self.prefix) == net
            }
            _ => false,
        }
    }

    pub fn same_network(&self, other: &Self) -> bool {
        self.net == other.net && self.prefix == other.prefix
    }
}

impl SessionMap {
    /// Insert one logical session and all of its family aliases.
    pub fn insert(&mut self, session: Arc<SessionShared>) -> Option<Arc<SessionShared>> {
        let primary = session.client_ip;
        let previous = self.remove(primary);
        self.by_ip.insert(primary, session.clone());
        for address in session.assigned_addresses() {
            self.by_address.insert(address, session.clone());
        }
        self.by_token.insert(session.token, primary);
        previous
    }

    /// Remove one logical session and every address alias that still belongs to it.
    pub fn remove(&mut self, primary: std::net::IpAddr) -> Option<Arc<SessionShared>> {
        let session = self.by_ip.remove(&primary)?;
        self.by_token.remove(&session.token);
        for address in session.assigned_addresses() {
            if self
                .by_address
                .get(&address)
                .is_some_and(|current| current.session_id == session.session_id)
            {
                self.by_address.remove(&address);
            }
        }
        Some(session)
    }

    pub fn get_by_address(&self, address: std::net::IpAddr) -> Option<&Arc<SessionShared>> {
        self.by_address.get(&address)
    }

    /// Longest-prefix-match `dest` against the registered client routes. Linear scan
    /// (the route set is a handful per profile). Returns the owning session.
    pub fn route_lookup(&self, dest: std::net::IpAddr) -> Option<&Arc<SessionShared>> {
        self.route_match(dest).map(|route| &route.session)
    }

    /// Longest-prefix match including route metadata. The direct ingress path uses the
    /// prefix to distinguish an ordinary client LAN from an authorization-gated `/0` exit.
    fn route_match(&self, dest: std::net::IpAddr) -> Option<&ClientRoute> {
        self.client_routes
            .iter()
            .filter(|route| route.contains(dest))
            .max_by_key(|r| r.prefix)
    }

    /// Resolve which client genuinely owns a packet SOURCE for isolation checks.
    ///
    /// A default iroute denotes an internet *next hop* (exit node), not ownership of every
    /// address on the internet.  Treating `/0` as source ownership makes an ordinary reply
    /// from (say) 8.8.8.8 look client-originated and `client_to_client = false` drops it.
    /// Non-default site-to-site iroutes remain source ownership and are still isolated.
    pub fn source_route_lookup(&self, source: std::net::IpAddr) -> Option<&Arc<SessionShared>> {
        self.client_routes
            .iter()
            .filter(|route| route.prefix > 0 && route.contains(source))
            .max_by_key(|route| route.prefix)
            .map(|route| &route.session)
    }

    /// Remove and return the CIDRs of a client's kernel-programmed inbound iroutes (#13)
    /// when its
    /// session leaves `by_ip`. EVERY eviction path must call this — then tear down the
    /// kernel routes after the sessions lock is released but, for authoritative teardown,
    /// before the profile admission guard is dropped — so a dead `ClientRoute` (holding an
    /// `Arc` to a kicked session) never lingers: otherwise it wins `route_lookup` and
    /// blackholes the subnet, and a same-IP reconnect stacks a duplicate each time.
    /// Empty when the client had no iroutes.
    pub fn take_client_routes(&mut self, client_ip: std::net::IpAddr) -> Vec<String> {
        let cidrs: Vec<String> = self
            .client_routes
            .iter()
            // `/0` exists only in qeli's internal exit-node lookup. Returning it to the
            // generic teardown would execute `ip route del default` and remove the host's
            // physical WAN route precisely when an exit client disconnected.
            .filter(|r| r.client_ip == client_ip && r.prefix > 0)
            .map(|r| r.cidr.clone())
            .collect();
        self.client_routes.retain(|r| r.client_ip != client_ip);
        cidrs
    }
}

#[cfg(test)]
mod client_route_tests {
    use super::{ClientRoute, SessionMap};
    use crate::server::handler::{DirectionalRateBuckets, SessionShared, JOIN_TOKEN_LEN};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
    use std::sync::{Arc, Mutex};

    fn session(id: u64, address: std::net::IpAddr) -> Arc<SessionShared> {
        let (client_ipv4, client_ipv6) = match address {
            std::net::IpAddr::V4(address) => (Some(address), None),
            std::net::IpAddr::V6(address) => (None, Some(address)),
        };
        Arc::new(SessionShared {
            session_id: id,
            username: format!("test-{id}"),
            device_key: format!("device-{id}"),
            client_ip: address,
            client_ipv4,
            client_ipv6,
            peer: "127.0.0.1:1".parse().unwrap(),
            token: [0; JOIN_TOKEN_LEN],
            max_streams: 1,
            wire_pool: crate::transport_core::buffer_pool::BufferPool::new(1, 256).unwrap(),
            streams: Mutex::new(Vec::new()),
            #[cfg(feature = "experimental-roaming")]
            tcp_roaming: None,
            #[cfg(feature = "experimental-roaming")]
            tcp_control_v2: false,
            connected_at: std::time::Instant::now(),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_recv: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            bandwidth_limit_mbps: Arc::new(AtomicU32::new(0)),
            rates: DirectionalRateBuckets::new(),
            cover_budget: crate::protocol::Shaper::shared_budget(
                &crate::protocol::ShapingConfig::default(),
                std::time::Instant::now(),
            ),
            recordizer: None,
            dst_acl: crate::server::acl::DstAcl::compile(&[], "test"),
            src_guard: crate::server::acl::SrcGuard::new_dual(&[address], &[], "test"),
            exit_access: super::ExitAccess::default(),
            path_mtu: Arc::new(AtomicU32::new(0)),
            revoked: Arc::new(AtomicBool::new(false)),
            closing: Arc::new(AtomicBool::new(false)),
            client_info: Arc::new(Mutex::new(None)),
        })
    }

    fn empty_map() -> SessionMap {
        SessionMap {
            by_ip: HashMap::new(),
            by_address: HashMap::new(),
            by_token: HashMap::new(),
            client_routes: Vec::new(),
        }
    }

    #[test]
    fn exit_default_is_a_destination_next_hop_not_global_source_ownership() {
        let exit = session(1, "10.9.0.2".parse().unwrap());
        let mut sessions = empty_map();
        sessions
            .client_routes
            .push(ClientRoute::parse("0.0.0.0/0", exit.client_ip, exit.clone()).unwrap());

        assert_eq!(
            sessions
                .route_lookup("8.8.8.8".parse().unwrap())
                .map(|session| session.session_id),
            Some(1)
        );
        assert!(sessions
            .source_route_lookup("8.8.8.8".parse().unwrap())
            .is_none());
    }

    #[test]
    fn default_teardown_never_returns_a_host_route_command() {
        let exit = session(1, "fd71:e1::2".parse().unwrap());
        let mut sessions = empty_map();
        sessions
            .client_routes
            .push(ClientRoute::parse("::/0", exit.client_ip, exit.clone()).unwrap());
        sessions
            .client_routes
            .push(ClientRoute::parse("2001:db8:50::9/64", exit.client_ip, exit.clone()).unwrap());

        assert_eq!(
            sessions.take_client_routes(exit.client_ip),
            vec!["2001:db8:50::/64"]
        );
        assert!(sessions.client_routes.is_empty());
    }
}

/// Per-profile runtime state (pool, sessions, rate limiter).
pub struct ProfileRuntime {
    pub name: String,
    pub config: ProfileConfig,
    /// Generation-scoped owner used by nested session tasks as well as top-level services.
    pub(crate) tasks: ProfileTasks,
    pub pool: Arc<Mutex<pool::IpPool>>,
    pub sessions: Arc<RwLock<SessionMap>>,
    /// Profile-wide exact ownership of TCP sessions retained during roaming grace.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) tcp_orphans:
        Arc<std::sync::Mutex<crate::transport_core::tcp_roaming::OrphanLimiter>>,
    /// Serializes the state-changing half of TCP/UDP authentication and authoritative TCP,
    /// admin and quota teardown. Pool leases, session eviction/insertion/removal and kernel
    /// iroutes form one admission transaction; without this guard concurrent transports or a
    /// reconnect racing cleanup could both pass the limits or steal/free the same lease.
    pub(crate) admission: Arc<Mutex<()>>,
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
    /// Aggregate local UDP diagnostics across this profile's SO_REUSEPORT workers.
    pub(crate) udp_buffer_counters: Arc<crate::transport_core::udp_buffer::UdpBufferCounters>,
    /// Worker-lifetime TCP outcomes; UDP outcomes live in the shared registry itself.
    pub(crate) tcp_roaming_metrics: roaming_metrics::TcpRoamingMetrics,
    /// Generation-safe CID/session ownership shared by every UDP listener and worker.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) udp_roaming_registry: crate::transport_core::udp_roaming::UdpRoamingRegistry,
    /// This profile's own server identity (static X25519) keypair — distinct
    /// per interface, so a client pins the key of the interface it uses.
    pub static_keypair: Arc<StaticKeypair>,
    /// Cached rustls server config for REALITY real-TLS termination, built once
    /// at profile start when `reality_proxy.real_tls` is set — avoids generating
    /// a certificate per connection. `None` when real-TLS is off.
    pub reality_tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Anti-replay memory for accepted REALITY session_id tokens — rejects a
    /// captured ClientHello replayed within the acceptance window.
    pub reality_replay: Arc<Mutex<ReplayGuard>>,
    /// TLS-shape to mirror in the hand-rolled ServerHello, probed once from the
    /// REALITY target at profile start. `Some` only when `real_tls + handrolled`.
    /// Borrowed REALITY state (target ServerHello shape + its real cert chain) behind
    /// a lock so a periodic refresh task tracks the target's TLS rotation. `Some` only
    /// for real_tls + handrolled. Hand-rolled terminator presents the borrowed chain;
    /// `None` falls back to a dummy cert.
    pub reality_borrow:
        Option<Arc<std::sync::RwLock<crate::protocol::realtls::server::BorrowState>>>,
}

/// Failed-auth tracker.
///
/// Source IPs get a *hard lockout* after too many failures — a single abusive
/// IP is cut off. Usernames, by contrast, are **never hard-locked**: doing so
/// would let anyone deny a known account service simply by spending its
/// attempts (the classic account-lockout DoS). Instead a username under active
/// guessing incurs an adaptive, capped **tarpit** (delay) that throttles
/// distributed brute-force just as effectively as a lockout — it bounds
/// guesses/second — while a correct password is always still accepted. The
/// caller sleeps `user_tarpit()` before verifying credentials.
/// Process-wide cap on how many Argon2 verifications may run at once.
///
/// Argon2 is deliberately memory-hard (~19 MiB per verify at the crate defaults), and
/// nothing bounded how many ran concurrently. The brute-force tracker only records a
/// failure AFTER the hash finishes, so every request of an arriving burst passed the
/// pre-check — none of them had been recorded yet — and each spawned its own job. A
/// thousand simultaneous attempts, cheap to send on either transport, meant on the order
/// of 19 GB in flight: an OOM of a small VPS rather than merely a guessing-rate problem.
///
/// Verification is CPU- and memory-bound, so permitting more than the core count buys no
/// throughput; queueing the remainder costs a legitimate client nothing noticeable and
/// denies the attacker the memory blow-up. Note this bounds RESOURCE use, not the number
/// of guesses: a burst can still get up to `permits` verifications in flight before the
/// first failures land in the tracker, so brute-force protection overshoots by at most
/// that much.
pub fn argon2_gate() -> &'static tokio::sync::Semaphore {
    static GATE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    GATE.get_or_init(|| {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        tokio::sync::Semaphore::new(cores.clamp(2, 8))
    })
}

pub struct FailedAuthTracker {
    /// Master switch. When `false` the tracker is inert: `check_ip` always passes,
    /// `user_tarpit` is zero, and `record_*` store nothing — so this surface has no
    /// brute-force protection at all. Lets the panel-login and VPN-auth policies be
    /// toggled independently (`brute_force.enabled` in `[web]` / `[auth]`).
    enabled: bool,
    /// Per-username recent-failure timestamps (drives the tarpit). No lockout
    /// instant: a username is never hard-blocked, so it cannot be DoS'd.
    by_user: HashMap<String, VecDeque<Instant>>,
    by_ip: HashMap<IpAddr, (VecDeque<Instant>, Option<Instant>)>,
    max_attempts: u32,
    window: Duration,
    lockout: Duration,
    /// Tarpit unit delay (applied once recent failures reach `max_attempts`,
    /// then doubled per extra failure) and its hard cap so a legitimate user
    /// authenticating during an attack waits at most `tarpit_max`.
    tarpit_base: Duration,
    tarpit_max: Duration,
    /// Opportunistic-sweep gate: mirrors [`RateLimiter`] so the by_user / by_ip
    /// maps cannot grow without bound (each distinct attacker username / IP would
    /// otherwise leave a permanent, if tiny, entry).
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

/// Longest username key we keep in the tarpit map. A caller may pass an
/// arbitrarily long attacker-controlled username; without this cap each distinct
/// oversized string would be stored verbatim, letting a peer pin megabytes of
/// keys. 64 bytes comfortably covers any legitimate account name.
const MAX_TRACKED_USERNAME_LEN: usize = 64;

/// Upper bound on a configured brute-force window/lockout (30 days).
///
/// `lockout_secs` is parsed as a bare u64 with no ceiling, and the lockout deadline is
/// computed as `Instant::now() + lockout` — which PANICS on overflow. A typo such as
/// `lockout_secs = 99999999999999999999` therefore took the server down on the first failed
/// login rather than being rejected. Anything beyond a month is indistinguishable from
/// "forever" in practice, so clamping loses nothing real.
pub const MAX_BRUTE_FORCE_SECS: u64 = 30 * 24 * 3600;

impl FailedAuthTracker {
    pub fn new(enabled: bool, max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        if window_secs > MAX_BRUTE_FORCE_SECS || lockout_secs > MAX_BRUTE_FORCE_SECS {
            log::warn!(
                "brute_force: window={}s lockout={}s exceeds the {}s ceiling — clamped",
                window_secs,
                lockout_secs,
                MAX_BRUTE_FORCE_SECS
            );
        }
        FailedAuthTracker {
            enabled,
            by_user: HashMap::new(),
            by_ip: HashMap::new(),
            max_attempts,
            window: Duration::from_secs(window_secs.min(MAX_BRUTE_FORCE_SECS)),
            lockout: Duration::from_secs(lockout_secs.min(MAX_BRUTE_FORCE_SECS)),
            tarpit_base: Duration::from_millis(200),
            tarpit_max: Duration::from_secs(3),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    /// Drop entries that no longer hold any live state: a username whose recent
    /// failures have all aged out of the window, and an IP whose failures aged
    /// out AND whose lockout (if any) has expired. Gated by `last_cleanup` /
    /// `cleanup_interval` so it runs at most every 5 minutes, mirroring
    /// [`RateLimiter::cleanup`].
    fn cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) <= self.cleanup_interval {
            return;
        }
        self.last_cleanup = now;
        let window = self.window;
        self.by_user.retain(|_, q| {
            q.retain(|t| now.duration_since(*t) < window);
            !q.is_empty()
        });
        self.by_ip.retain(|_, (fails, until)| {
            fails.retain(|t| now.duration_since(*t) < window);
            let locked = until.map(|u| now < u).unwrap_or(false);
            !fails.is_empty() || locked
        });
    }

    /// Current `(enabled, max_attempts, window, lockout)` — lets a SIGHUP reload
    /// decide whether the brute-force policy actually changed (including a toggle
    /// on/off), so live lockouts can be preserved when it did not.
    pub fn thresholds(&self) -> (bool, u32, Duration, Duration) {
        (self.enabled, self.max_attempts, self.window, self.lockout)
    }

    /// Hard lockout check — source IP only. A username is never hard-locked
    /// (see [`Self::user_tarpit`]), so a flood of failures for a victim's
    /// username can never deny that victim service. Always passes when the policy
    /// is disabled for this surface.
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let now = Instant::now();
        if let Some((_, Some(until))) = self.by_ip.get(&ip) {
            if now < *until {
                let secs = until.duration_since(now).as_secs();
                return Err(format!(
                    "source IP locked for {}s after too many failed attempts",
                    secs
                ));
            }
        }
        Ok(())
    }

    /// Adaptive throttle for `username`: [`Duration::ZERO`] in steady state, a
    /// capped exponential delay once recent failures exceed `max_attempts`. The
    /// caller sleeps this long before the Argon2 verify, so distributed guessing
    /// of one account is rate-limited while a correct credential still passes.
    pub fn user_tarpit(&self, username: &str) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        let now = Instant::now();
        let recent = self
            .by_user
            .get(username)
            .map(|q| {
                q.iter()
                    .filter(|t| now.duration_since(**t) < self.window)
                    .count() as u32
            })
            .unwrap_or(0);
        if recent < self.max_attempts {
            return Duration::ZERO;
        }
        // Exponent capped so the Duration multiply can never overflow; the
        // result is in any case clamped to `tarpit_max`.
        let over = (recent - self.max_attempts + 1).min(16);
        (self.tarpit_base * 2u32.saturating_pow(over)).min(self.tarpit_max)
    }

    /// Record a failure against the source IP only. Used for pre-credential
    /// rejections (e.g. a missing server-key proof): a scanner that never
    /// presented a real username must not be able to drive any username's
    /// tarpit — only its own IP gets locked.
    /// Returns `true` if this failure leaves the source IP in a locked state (so the
    /// caller can fire an "IP lockout" notification).
    pub fn record_ip_failure(&mut self, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        self.cleanup();
        let now = Instant::now();
        let window = self.window;
        let max = self.max_attempts as usize;
        let lockout = self.lockout;
        let ip_entry = self.by_ip.entry(ip).or_default();
        ip_entry.0.retain(|t| now.duration_since(*t) < window);
        ip_entry.0.push_back(now);
        if ip_entry.0.len() >= max {
            // checked_add, not `+`: `Instant + Duration` panics on overflow, and a panic
            // here would be reachable from an unauthenticated failed login.
            ip_entry.1 = now.checked_add(lockout);
            log::warn!(
                "AUTH LOCKOUT (ip): {} locked for {}s after {} failed attempts",
                ip,
                lockout.as_secs(),
                self.max_attempts
            );
            true
        } else {
            false
        }
    }

    /// Record a credential failure (wrong password / unknown user): counts
    /// against both the username tarpit and the source-IP hard lockout. Returns
    /// `true` if the source IP is now locked (for lockout notifications).
    pub fn record_failure(&mut self, username: &str, ip: IpAddr) -> bool {
        if !self.enabled {
            return false;
        }
        let now = Instant::now();
        // Skip storing pathologically long attacker-controlled usernames so the
        // tarpit map can't be inflated with megabyte keys. The IP hard-lock
        // below still fires, so an oversized-username sprayer is not privileged.
        if username.len() <= MAX_TRACKED_USERNAME_LEN {
            let window = self.window;
            let user_entry = self.by_user.entry(username.to_string()).or_default();
            user_entry.retain(|t| now.duration_since(*t) < window);
            user_entry.push_back(now);
        }
        self.record_ip_failure(ip)
    }

    /// Clear failure history for this username on successful auth. The IP
    /// bucket is intentionally not cleared — one good login does not absolve
    /// an IP that has been spraying.
    pub fn record_success(&mut self, username: &str) {
        self.by_user.remove(username);
    }

    /// List IPs currently hard-locked by brute-force protection: for each, the
    /// number of recent failures and how many seconds remain until it unblocks.
    /// Read-only; the caller holds the tracker lock.
    pub fn list_blocked_ips(&self) -> Vec<(IpAddr, u32, u64)> {
        let now = Instant::now();
        self.by_ip
            .iter()
            .filter_map(|(ip, (fails, until))| {
                let until = (*until)?; // only currently-locked IPs
                if until <= now {
                    return None; // lockout already expired
                }
                let count = fails
                    .iter()
                    .filter(|t| now.duration_since(**t) < self.window)
                    .count() as u32;
                Some((*ip, count, until.saturating_duration_since(now).as_secs()))
            })
            .collect()
    }

    /// Manually unblock ONE IP: clears its lockout and failure history.
    /// Returns true if the IP had any tracked state.
    pub fn unblock_ip(&mut self, ip: IpAddr) -> bool {
        let existed = self.by_ip.remove(&ip).is_some();
        if existed {
            log::info!("AUTH UNBLOCK (manual): {} cleared", ip);
        }
        existed
    }

    /// Clear ALL per-IP lockout / failure state. Returns how many IPs were tracked.
    pub fn clear_all_ips(&mut self) -> usize {
        let n = self.by_ip.len();
        self.by_ip.clear();
        if n > 0 {
            log::warn!("AUTH UNBLOCK (manual): all {} tracked IP(s) cleared", n);
        }
        n
    }
}

/// Command the web panel (in the supervisor) sends to the supervisor loop to
/// act on the data-plane worker child process.
#[derive(Debug, Clone, Copy)]
pub enum WorkerCmd {
    /// Restart the worker (SIGTERM + respawn) — applies profile/config changes.
    Restart,
    /// SIGHUP the worker to hot-reload users / brute-force thresholds.
    ReloadUsers,
}

/// Shared server state (auth, users, identity key, profile registry).
///
/// Used in two roles: the **worker** process (full data-plane: profiles +
/// control socket, `worker_tx = None`) and the **supervisor** process (web
/// panel only; `profiles` stays empty and it reaches live data over the control
/// socket; `worker_tx = Some` to drive the worker child).
pub struct ServerState {
    pub config: ServerConfig,
    pub users_db: Arc<RwLock<UsersDb>>,
    pub config_path: Mutex<Option<String>>,
    /// Serializes every panel read-modify-write of the server config. Atomic rename keeps
    /// each individual write crash-safe, but without a process-level lock two panel tabs
    /// could both read the same revision and the later rename would silently erase the
    /// earlier edit. Handlers also compare a content revision while holding this lock.
    pub config_write_lock: Mutex<()>,
    pub profiles: Arc<RwLock<HashMap<String, Arc<ProfileRuntime>>>>,
    /// Actual per-generation values exported to lifecycle hooks. In particular WAN names are
    /// the interfaces selected by auto-detection, not the placeholder text from the config.
    profile_hook_env: Arc<Mutex<HashMap<String, ProfileHookEnv>>>,
    pub failed_auth: Arc<Mutex<FailedAuthTracker>>,
    /// Supervisor → worker control channel. `Some` only in the supervisor.
    pub worker_tx: Option<tokio::sync::mpsc::Sender<WorkerCmd>>,
    /// Outbound client tunnels the web panel can dial to other servers (lives in
    /// the supervisor, which serves the panel and has CAP_NET_ADMIN for the TUN).
    pub client_manager: Arc<client_manager::ClientManager>,
    /// Host + tunnel metrics for the dashboard (1 Hz sampler, supervisor-only).
    pub metrics: Arc<metrics::MetricsState>,
    /// Per-user lifetime traffic + quota bookkeeping (Tier-2). The worker accrues
    /// and enforces it; the supervisor's copy is reloaded for panel reads.
    pub usage: Arc<usage::UsageStore>,
    /// Live, hot-reloadable copy of the `[web]` panel settings the SUPERVISOR
    /// authenticates the panel with (admin password/username, IP allowlist, CSRF
    /// origins, public host). `config.web` is the frozen startup snapshot; the
    /// panel reads THIS instead, so a web-settings change applies without a full
    /// process restart. Socket-bound fields (bind/port/tls/enabled) still need a
    /// restart and are read from `config.web`.
    pub live_web: Arc<RwLock<crate::config::server::WebConfig>>,
    /// One memory-aware cap shared by every UDP profile/listener/SO_REUSEPORT worker.
    pub(crate) udp_buffer_budget: crate::transport_core::udp_buffer::AggregateUdpBudgetPlan,
}

#[derive(Debug, Clone)]
struct ProfileHookEnv {
    profile: String,
    tun: String,
    pool: String,
    pool_ipv4: String,
    pool_ipv6: String,
    wan: String,
    wan_ipv4: String,
    wan_ipv6: String,
    bind_port: String,
}

impl ProfileHookEnv {
    fn new(pcfg: &ProfileConfig, wan_ipv4: String, wan_ipv6: String) -> Self {
        use crate::config::server::IpMode;
        let pool_ipv4 = if pcfg.tun.ip_mode == IpMode::Ipv6 {
            String::new()
        } else {
            pcfg.pool.cidr.clone()
        };
        let pool_ipv6 = if pcfg.tun.ip_mode == IpMode::Ipv4 {
            String::new()
        } else {
            pcfg.pool.ipv6.cidr.clone()
        };
        let (pool, wan) = match pcfg.tun.ip_mode {
            IpMode::Ipv6 => (pool_ipv6.clone(), wan_ipv6.clone()),
            IpMode::Ipv4 | IpMode::Dual => (pool_ipv4.clone(), wan_ipv4.clone()),
        };
        Self {
            profile: pcfg.name.clone(),
            tun: pcfg.tun.name.clone(),
            pool,
            pool_ipv4,
            pool_ipv6,
            wan,
            wan_ipv4,
            wan_ipv6,
            bind_port: pcfg.bind.port.to_string(),
        }
    }

    fn fallback(pcfg: &ProfileConfig) -> Self {
        use crate::config::server::{IpMode, Ipv6RoutingMode};
        let wan_ipv4 = if pcfg.tun.ip_mode != IpMode::Ipv6 && pcfg.routing.nat.enabled {
            nat::resolve_wan_ipv4(&pcfg.routing.nat.interface).unwrap_or_default()
        } else {
            String::new()
        };
        let wan_ipv6 =
            if pcfg.tun.ip_mode != IpMode::Ipv4 && pcfg.routing.ipv6.mode != Ipv6RoutingMode::Off {
                nat::resolve_wan_ipv6(&pcfg.routing.ipv6.interface).unwrap_or_default()
            } else {
                String::new()
            };
        Self::new(pcfg, wan_ipv4, wan_ipv6)
    }

    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("QELI_PROFILE", self.profile.clone()),
            ("QELI_TUN", self.tun.clone()),
            ("QELI_POOL", self.pool.clone()),
            ("QELI_POOL_IPV4", self.pool_ipv4.clone()),
            ("QELI_POOL_IPV6", self.pool_ipv6.clone()),
            ("QELI_WAN", self.wan.clone()),
            ("QELI_WAN_IPV4", self.wan_ipv4.clone()),
            ("QELI_WAN_IPV6", self.wan_ipv6.clone()),
            ("QELI_BIND_PORT", self.bind_port.clone()),
        ]
    }
}

impl ServerState {
    /// Refresh the supervisor's live `[web]` settings from the on-disk config, so
    /// a panel change to the admin password / IP allowlist / CSRF origins /
    /// public host takes effect immediately, without a full process restart.
    /// Called after the panel writes the config file. Bind/port/TLS/enabled are
    /// bound at startup and are NOT swapped here (they still require a restart).
    pub async fn reload_web_settings(&self) {
        let path = match self.config_path.lock().await.clone() {
            Some(p) => p,
            None => return,
        };
        let new_web = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| crate::config::parse_server_config(&s).ok())
            .map(|c| c.web);
        if let Some(web) = new_web {
            // Fail-closed, mirroring the start-time guard (web/mod.rs): a live reload must
            // never leave a non-loopback panel password-less. put_config restores an empty
            // admin hash from disk, but put_config_raw writes verbatim — so a raw save could
            // otherwise swap in an empty password_hash and open the LIVE public panel (no
            // auth) until the next restart (which would then refuse to start). The bind can't
            // change without a restart, so decide loopback from the startup bind.
            // Apply the SAME rule the startup gate uses (web/mod.rs::start): an empty
            // password_hash is refused on ANY bind unless `insecure_no_auth` is set.
            //
            // The loopback exemption here was a hole the startup gate had already closed
            // deliberately — "an open panel on 127.0.0.1 is still full admin for every
            // local process, and for anything that can be induced to make a request on
            // someone else's behalf (SSRF)". Because `put_config_raw` writes verbatim, a
            // raw save could clear `password_hash` on a loopback panel and this reload
            // would apply it live, leaving the panel unauthenticated until a restart — at
            // which point the startup gate would refuse to serve it at all. So the two
            // paths disagreed about the same config, in the unsafe direction.
            // (Audit 2026-07-27, D2.)
            let bind = self.config.web.bind.as_str();
            if web.password_hash.is_empty() && !web.insecure_no_auth {
                log::error!(
                    "panel: REFUSING live web-settings reload — it would leave the panel \
                     (bind {bind}) with NO admin password. Set one with \
                     `qeli set-web-password`, or set web.insecure_no_auth = true if an \
                     unauthenticated panel is genuinely intended. Keeping the previous \
                     settings."
                );
                return;
            }
            // Going password-less deliberately must be as loud live as it is at startup —
            // previously the only trace was a cheerful "settings reloaded".
            if web.password_hash.is_empty() {
                log::warn!(
                    "panel on bind {bind} is now running WITHOUT AUTHENTICATION \
                     (web.insecure_no_auth): every local process — and any SSRF on this \
                     host — has full admin access to users, password hashes and the config."
                );
            }
            *self.live_web.write().await = web;
            log::info!(
                "panel: live web settings reloaded (admin password / allowlist / CSRF origins)"
            );
        }
    }
}

/// Directory holding per-profile server identity keys.
pub const IDENTITY_DIR: &str = "/etc/qeli/identity";

/// Filesystem path of a profile's server identity (private) key. Defaults to
/// `/etc/qeli/identity/<name>.key`; overridable per profile via `identity_key`.
pub fn profile_identity_path(pcfg: &ProfileConfig) -> String {
    pcfg.identity_key
        .clone()
        .unwrap_or_else(|| format!("{}/{}.key", IDENTITY_DIR, pcfg.name))
}

fn prepare_identity_parent(path: &std::path::Path) -> anyhow::Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let existed = parent.exists();
    std::fs::create_dir_all(parent)?;
    // Enforce privacy on qeli's own directory and on a directory we just created. Never chmod
    // an arbitrary existing parent supplied via `identity_key` (for example `/etc`).
    #[cfg(unix)]
    if !existed || parent == std::path::Path::new(IDENTITY_DIR) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Load a profile's identity key, or generate+persist a fresh one on first use.
/// Each profile (interface) has its own identity so clients pin a key specific
/// to the interface they connect to.
pub fn load_or_generate_profile_key(pcfg: &ProfileConfig) -> anyhow::Result<StaticKeypair> {
    let path = profile_identity_path(pcfg);
    let path_ref = std::path::Path::new(&path);

    // Serialise the check-then-generate under a sidecar lock for this identity path. Without
    // it this was a TOCTOU: the worker starting a profile, the panel's identity endpoint
    // and the share endpoint can all run `exists()==false` concurrently and each generate
    // a DIFFERENT key, the last write winning. For an IDENTITY key that is catastrophic —
    // every already-pinned client would then fail to verify a server it never changed. The
    // lock makes "load if present, else generate once" atomic across processes. (identity race)
    prepare_identity_parent(path_ref)?;
    let _lock = crate::util::FileLock::acquire(path_ref)?;

    match std::fs::read(path_ref) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!(
                    "invalid identity key length in {}: {}",
                    path,
                    bytes.len()
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            log::info!("Profile '{}': loaded identity key from {}", pcfg.name, path);
            Ok(StaticKeypair::from_private_bytes(key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            generate_profile_key_unlocked(pcfg, path_ref)
        }
        Err(error) => Err(error.into()),
    }
}

/// Generate a fresh identity key for a profile and persist it (0600), creating
/// the identity directory (0700) if needed. Overwrites any existing key.
pub fn generate_profile_key(pcfg: &ProfileConfig) -> anyhow::Result<StaticKeypair> {
    let path = profile_identity_path(pcfg);
    let path_ref = std::path::Path::new(&path);
    prepare_identity_parent(path_ref)?;
    let _lock = crate::util::FileLock::acquire(path_ref)?;
    generate_profile_key_unlocked(pcfg, path_ref)
}

fn generate_profile_key_unlocked(
    pcfg: &ProfileConfig,
    path: &std::path::Path,
) -> anyhow::Result<StaticKeypair> {
    let kp = StaticKeypair::generate();
    crate::util::write_atomic_private(path, &kp.private_bytes()[..])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    log::info!(
        "Profile '{}': generated new identity key at {}",
        pcfg.name,
        path.display()
    );
    Ok(kp)
}

/// Validate profiles before bringing up any listeners. Pure (no IO) so it is
/// unit-testable. Checks, in order: unique non-empty names; invalid zero values
/// (including manually built configs) for the connection timeout and client limit;
/// and the plain-is-TCP-only
/// invariant (a raw datagram stream has no framing to delimit records and is a
/// high-entropy "fully encrypted traffic" DPI red-flag, so it is refused on UDP).
/// Schema checks the data-plane worker runs before binding anything. Public so
/// the `check-config` subcommand (a separate bin crate) reaches the exact same
/// validation, and its verdict cannot drift from a real start.
/// One address a profile will actually listen on — its primary `bind`, or one of its extra
/// `listen` specs.
struct BoundEndpoint {
    host: String,
    port: u16,
    transport: String,
    profile: String,
    /// The spelling from the config, so an error can point at the line the operator wrote.
    label: String,
}

/// Normalise a bind host for comparison: lowercase, IPv6 brackets stripped, and IP literals
/// put in canonical form so `[::]` and `::` (or `010.0.0.1` and `10.0.0.1`) are one address.
fn normalize_bind_host(host: &str) -> String {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    match h.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => h.to_ascii_lowercase(),
    }
}

/// True for an address that means "every address on this host", which therefore overlaps every
/// concrete address on the same port.
fn is_wildcard_bind_host(host: &str) -> bool {
    matches!(host, "" | "*" | "0.0.0.0" | "::")
}

/// Whether two configured bind hosts may claim the same kernel socket address. IPv4 and
/// IPv6 are separate listener spaces because every numeric IPv6 socket is created V6ONLY;
/// consequently `0.0.0.0:443` + `[::]:443` is the canonical dual-stack pair, not a clash.
/// Hostnames remain conservative/opaque because check-config intentionally does no DNS.
fn bind_hosts_overlap(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left_ip = left.parse::<std::net::IpAddr>().ok();
    let right_ip = right.parse::<std::net::IpAddr>().ok();
    if let (Some(left_ip), Some(right_ip)) = (left_ip, right_ip) {
        if left_ip.is_ipv4() != right_ip.is_ipv4() {
            return false;
        }
        return is_wildcard_bind_host(left) || is_wildcard_bind_host(right);
    }
    // `*`/empty are legacy family-agnostic wildcards. A hostname is only known to
    // overlap the same spelling or such a wildcard; DNS is deliberately not consulted.
    is_wildcard_bind_host(left) || is_wildcard_bind_host(right)
}

/// The `addr:port` the profile's DHCP server binds to.
///
/// `dhcp.listen` defaults to EMPTY, meaning "the profile's tun address" — it used to default
/// to `0.0.0.0:67`, publishing an unauthenticated service on every interface for anyone who
/// merely set `dhcp.enabled = true`. One helper so the preflight collision check and
/// `run_profile` cannot drift apart on what the value means. (Audit 2026-08-04.)
fn dhcp_bind_spec(p: &crate::config::server::ProfileConfig) -> String {
    let host = if p.dhcp.listen.trim().is_empty() {
        p.tun.address.trim()
    } else {
        p.dhcp.listen.trim()
    };
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:67")
    }
}

/// Split an already-form-validated `addr:port` spec into a comparable (host, port).
fn split_listen_spec(spec: &str) -> Option<(String, u16)> {
    let addr = spec.trim();
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return Some((sa.ip().to_string(), sa.port()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    Some((normalize_bind_host(host), port.parse().ok()?))
}

/// Longest interface name the kernel will accept, from `IFNAMSIZ` (16) minus the NUL.
const MAX_IFNAME_LEN: usize = 15;

fn validate_configured_interface(profile: &str, key: &str, value: &str) -> anyhow::Result<()> {
    let name = value.trim();
    // Empty and the historical `eth0` default both mean auto-detect in server/nat.rs.
    if name.is_empty() || name == "eth0" {
        return Ok(());
    }
    if name.len() > MAX_IFNAME_LEN
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.contains(char::is_whitespace)
    {
        anyhow::bail!(
            "profile '{}': {} = '{}' is not a valid Linux interface name",
            profile,
            key,
            value
        );
    }
    Ok(())
}

pub fn validate_profiles(config: &ServerConfig) -> anyhow::Result<()> {
    if !config.web.public_host.trim().is_empty() {
        crate::config::share::supported_public_endpoint(&config.web.public_host, 443)
            .map_err(anyhow::Error::msg)?;
    }
    // Both brute-force policies, before anything profile-specific. This function is the
    // one gate every write path shares — `check-config`, worker startup, `PUT /api/config`
    // and `PUT /api/config/raw` all call it — so validating here is what stops a policy
    // that silently cannot rate-limit from reaching disk. (Audit 2026-07-27, C1.)
    config
        .auth
        .brute_force
        .validate("[auth]")
        .map_err(|e| anyhow::anyhow!(e))?;
    config
        .web
        .brute_force
        .validate("[web]")
        .map_err(|e| anyhow::anyhow!(e))?;
    // The panel binds `web.port`, and 0 gives an ephemeral port while the log still prints the
    // configured zero — the operator is told an address that was never listened on.
    //
    // This check used to sit INSIDE the per-profile loop, and inside that loop's
    // `if p.dns.enabled` branch, so it ran once per DNS-enabled profile and not at all when no
    // profile served DNS — `[web]` has nothing to do with either. Belongs here with the other
    // whole-config checks. (Audit 2026-08-01, §9.)
    if config.web.enabled && config.web.port == 0 {
        anyhow::bail!(
            "web.port = 0 would bind an ephemeral port while the log reports 0 — set the \
             port you actually reach the panel on"
        );
    }
    let mut seen = std::collections::HashSet::new();
    // Every endpoint this configuration will bind, in declaration order. A Vec rather than a
    // map because the collision rule is not key equality: a wildcard address overlaps every
    // concrete one on the same port, so each new endpoint is compared against all the ones
    // already claimed.
    let mut endpoints: Vec<BoundEndpoint> = Vec::new();

    // The PANEL goes in first, because it is not a profile and it starts EARLIER — the
    // supervisor spawns it before the worker. A panel sitting on a port a profile wants
    // therefore wins, and the worker crash-loops against a port that is taken by the same
    // server; from the outside the panel is fine and the VPN "just doesn't work".
    // (Audit 2026-08-01, §4.)
    if config.web.enabled {
        endpoints.push(BoundEndpoint {
            host: normalize_bind_host(&config.web.bind),
            port: config.web.port,
            transport: "tcp".to_string(),
            profile: "[web]".to_string(),
            label: format!("{}:{}", config.web.bind, config.web.port),
        });
    }
    // tun.name -> profile that claimed it first. Two profiles on one device name is not a
    // cosmetic clash: TUNSETIFF can attach another queue to an existing multi-queue device,
    // splitting traffic between unrelated profile generations. (Audit 2026-08-01, §4.)
    let mut tun_names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Cross-profile pool collisions are purely a property of this configuration and must not
    // depend on Linux host-state discovery. `preflight::run` deliberately fails open when the
    // `ip` snapshot cannot be read; keeping this check only there allowed two enabled profiles
    // to install competing connected routes and allocate the same client addresses.
    let mut ipv4_pools: Vec<(String, crate::config::server::PoolSubnet)> = Vec::new();
    let mut ipv6_pools: Vec<(String, crate::config::server::Ipv6PoolSubnet)> = Vec::new();
    for p in &config.profiles {
        // Disabled profiles are not bound/served, so their config is not validated
        // here — this lets an operator turn off a profile that would otherwise fail
        // validation (e.g. a half-edited one) without blocking startup.
        if !p.enabled {
            continue;
        }
        if p.name.is_empty() {
            anyhow::bail!("profile has an empty name");
        }
        if !crate::util::is_valid_ident(&p.name) {
            anyhow::bail!(
                "profile name {:?} is invalid (must be 1..=128 bytes, without edge whitespace or control characters)",
                p.name
            );
        }
        if !seen.insert(&p.name) {
            anyhow::bail!("duplicate profile name: '{}'", p.name);
        }
        if p.roaming.enabled && !cfg!(feature = "experimental-roaming") {
            anyhow::bail!(
                "profile '{}': roaming.enabled = true requires a binary built with experimental-roaming",
                p.name
            );
        }

        if !(crate::config::server::ROAMING_MIN_GRACE_SECS
            ..=crate::config::server::ROAMING_MAX_GRACE_SECS)
            .contains(&p.roaming.grace_secs)
        {
            anyhow::bail!(
                "profile '{}': roaming.grace_secs = {} must be between {} and {}",
                p.name,
                p.roaming.grace_secs,
                crate::config::server::ROAMING_MIN_GRACE_SECS,
                crate::config::server::ROAMING_MAX_GRACE_SECS
            );
        }
        if !(crate::config::server::ROAMING_MIN_ORPHANED
            ..=crate::config::server::ROAMING_MAX_ORPHANED)
            .contains(&p.roaming.max_orphaned)
        {
            anyhow::bail!(
                "profile '{}': roaming.max_orphaned = {} must be between {} and {}",
                p.name,
                p.roaming.max_orphaned,
                crate::config::server::ROAMING_MIN_ORPHANED,
                crate::config::server::ROAMING_MAX_ORPHANED
            );
        }
        if !(crate::config::server::ROAMING_MIN_ORPHAN_BYTES
            ..=crate::config::server::ROAMING_MAX_ORPHAN_BYTES)
            .contains(&p.roaming.max_orphan_bytes)
        {
            anyhow::bail!(
                "profile '{}': roaming.max_orphan_bytes = {} must be between {} and {}",
                p.name,
                p.roaming.max_orphan_bytes,
                crate::config::server::ROAMING_MIN_ORPHAN_BYTES,
                crate::config::server::ROAMING_MAX_ORPHAN_BYTES
            );
        }

        // `tun.name` reaches the kernel through an ioctl that copies only the first 15 bytes
        // (IFNAMSIZ - 1). A longer name therefore CREATED a truncated device and every
        // follow-up `ip ... dev <full name>` then failed against a device that does not exist —
        // late, one command at a time, with the interface already half configured. And two
        // profiles sharing a name is worse than a clash: TUNSETIFF may attach the second
        // profile to the first one's multi-queue device and split packets between them.
        // Neither was checked anywhere. (Audit 2026-08-01, §4.)
        let tun_name = p.tun.name.trim();
        if tun_name.is_empty() {
            anyhow::bail!("profile '{}': tun.name is empty", p.name);
        }
        if tun_name.len() > MAX_IFNAME_LEN {
            // Cut on a CHARACTER boundary, not a byte one. `&tun_name[..15]` panics outright
            // when byte 15 lands inside a multi-byte code point — eight Cyrillic letters is
            // sixteen bytes — and this validator runs inside `PUT /api/config`, so a name typed
            // into the panel could take the request handler down instead of being rejected.
            // (Audit 2026-08-01, §P2.)
            let kept: String = tun_name
                .char_indices()
                .take_while(|(i, c)| i + c.len_utf8() <= MAX_IFNAME_LEN)
                .map(|(_, c)| c)
                .collect();
            anyhow::bail!(
                "profile '{}': tun.name '{}' is {} bytes — the kernel keeps only the first {}, \
                 so the device would be created as '{}' and every later `ip ... dev {}` would \
                 fail",
                p.name,
                tun_name,
                tun_name.len(),
                MAX_IFNAME_LEN,
                kept,
                tun_name
            );
        }
        if tun_name.contains('/') || tun_name.contains(char::is_whitespace) {
            anyhow::bail!(
                "profile '{}': tun.name '{}' contains a space or '/' — not a valid interface name",
                p.name,
                tun_name
            );
        }
        if let Some(other) = tun_names.insert(tun_name.to_string(), p.name.clone()) {
            anyhow::bail!(
                "profiles '{}' and '{}' both use tun.name '{}' — starting the second one \
                 could attach it to the first one's multi-queue device",
                other,
                p.name,
                tun_name
            );
        }
        if p.tun.ip_mode == crate::config::server::IpMode::Ipv6 && p.routing.nat.enabled {
            anyhow::bail!(
                "profile '{}': routing.nat.enabled controls IPv4 NAT44 and cannot be enabled when tun.ip_mode = ipv6; use routing.ipv6.mode = route or nat66",
                p.name
            );
        }
        if p.routing.nat.enabled {
            validate_configured_interface(
                &p.name,
                "routing.nat.interface",
                &p.routing.nat.interface,
            )?;
        }
        if p.routing.ipv6.mode != crate::config::server::Ipv6RoutingMode::Off {
            validate_configured_interface(
                &p.name,
                "routing.ipv6.interface",
                &p.routing.ipv6.interface,
            )?;
        }

        // `perf.tun.read_buffer_size` is the exact size of the buffer each queue reads a TUN
        // frame into, and it was parsed as a bare `usize` with no bounds at all — the only
        // limit anywhere was `min="1500"` on the panel's number input, which a hand-written
        // config or `PUT /api/config/raw` never sees. Zero is the worst of them: `read()` into
        // an empty buffer returns Ok(0), the reader takes that for EOF and the profile's data
        // plane stops with no error. Anything below the MTU silently truncates every packet
        // that fills the interface. (Audit 2026-08-01, §3.)
        let is_tap = p.tun.device_type.eq_ignore_ascii_case("tap");
        // TAP frames carry a 14-byte Ethernet header on top of the IP MTU.
        let min_buf = p.tun.mtu.max(0) as usize + if is_tap { 14 } else { 0 };
        if p.performance.tun.read_buffer_size < min_buf {
            anyhow::bail!(
                "profile '{}': perf.tun.read_buffer_size = {} is smaller than {} ({} mtu {}{}) \
                 — every frame that fills the interface would be truncated, and 0 reads as EOF \
                 and stops the data plane",
                p.name,
                p.performance.tun.read_buffer_size,
                min_buf,
                if is_tap { "TAP" } else { "TUN" },
                p.tun.mtu,
                if is_tap { " + 14 ethernet" } else { "" }
            );
        }
        // The buffer is allocated PER QUEUE, and queues default to one per core, so an absurd
        // value is a multiplied allocation. 1 MiB is far above any real frame.
        const MAX_TUN_READ_BUFFER: usize = 1024 * 1024;
        if p.performance.tun.read_buffer_size > MAX_TUN_READ_BUFFER {
            anyhow::bail!(
                "profile '{}': perf.tun.read_buffer_size = {} exceeds {} — this is allocated \
                 once per TUN queue (default: one per core)",
                p.name,
                p.performance.tun.read_buffer_size,
                MAX_TUN_READ_BUFFER
            );
        }
        // The receive controller has a smaller 16 MiB automatic ceiling. Explicit values
        // remain fixed operator overrides, but still need a hard per-socket bound: UDP uses
        // one SO_REUSEPORT socket per worker, so a typo here is multiplied by the queue count.
        for (field, value) in [
            (
                "perf.udp.recv_buffer_size",
                p.performance.udp.recv_buffer_size,
            ),
            (
                "perf.udp.send_buffer_size",
                p.performance.udp.send_buffer_size,
            ),
        ] {
            if value > crate::transport_core::udp_buffer::MAX_CONFIGURED_SOCKET_BUFFER_BYTES {
                anyhow::bail!(
                    "profile '{}': {field} = {value} exceeds the per-socket UDP buffer limit {}",
                    p.name,
                    crate::transport_core::udp_buffer::MAX_CONFIGURED_SOCKET_BUFFER_BYTES
                );
            }
        }
        // Reject unknown bind.transport / obf.mode outright. Both are plain
        // Strings compared verbatim elsewhere: an unrecognised transport parses
        // via `.unwrap_or(Tcp)` (a typo silently binds TCP) and an unrecognised
        // mode falls through the plain/obfs branches to the fake-tls default —
        // so `obf.mode = "realty-tls"` would silently run fake-tls. Fail loud.
        // Accepted transports: tcp, udp (TransportProtocol::from_str).
        if !matches!(p.bind.transport.as_str(), "tcp" | "udp") {
            anyhow::bail!(
                "profile '{}': unknown bind.transport '{}' — expected 'tcp' or 'udp'",
                p.name,
                p.bind.transport
            );
        }
        // The same class as bind.transport / obf.mode above, and left unguarded: these are
        // compared verbatim against ONE literal at the use site, so anything else silently
        // selects the other branch. `obf.fronting = "webscoket"` drops the WebSocket
        // handshake the profile was configured for (and the peer then disagrees about the
        // wire), `tun.device_type = "tapp"` quietly creates a TUN, and
        // `dns.upstream_protocol = "tls"` — a value the docs advertise — falls back to
        // plaintext UDP while looking like DoT. (Audit 2026-07-29, #23.)
        // The PRIMARY bind, which the extra-listener check below never covered. `bind.port = 0`
        // was accepted and produced an ephemeral port while clients are handed the configured
        // zero; a hostname passed this early check and was then rejected far later, because
        // SO_REUSEPORT needs a numeric SocketAddr. (Audit 2026-08-01, §5.)
        if p.bind.port == 0 {
            anyhow::bail!(
                "profile '{}': bind.port = 0 would listen on an ephemeral port that no client                  can be told about — set the port you publish",
                p.name
            );
        }
        if p.bind.transport == "udp" && p.bind.address.trim().parse::<std::net::IpAddr>().is_err() {
            anyhow::bail!(
                "profile '{}': bind.address = '{}' is a hostname, but a UDP profile binds with                  SO_REUSEPORT and needs a numeric address — use an IP (0.0.0.0 or :: for all)",
                p.name,
                p.bind.address
            );
        }

        if p.obfuscation.quic.enabled {
            if p.bind.transport == "udp" {
                log::warn!(
                    "profile '{}': obf.quic.enabled selects quic-shape compatibility masking, \
                     not a real QUIC/HTTP/3 state machine and not maximum stealth; use a TCP \
                     reality-tls profile for hostile DPI",
                    p.name
                );
            } else {
                log::warn!(
                    "profile '{}': obf.quic.enabled has no effect on a TCP listener",
                    p.name
                );
            }
        }

        // Extra `listen` specs. The runtime parses these too and logs an error for a malformed
        // one, but only once the profile is already starting — so `check-config` passed on a
        // config whose second listener could never bind, and the operator learned about it from
        // a log line on a live server (or not at all). Validate here so the command and a real
        // start agree. (Audit 2026-07-30, #6.)
        for spec in &p.bind.listen {
            if validate_listen_addr(spec).is_none() {
                anyhow::bail!(
                    "profile '{}': malformed listen '{}' — expected a bare `addr:port` \
                     (IPv6 in brackets, e.g. `[::]:443`) with a non-zero port",
                    p.name,
                    spec
                );
            }
        }

        // Two listeners on the SAME endpoint is not a harmless duplicate. On UDP the sockets
        // are opened with SO_REUSEPORT, so the bind SUCCEEDS and the kernel then flow-hashes
        // datagrams across profiles with different keys, users and pools — handshakes fail at
        // random and a client can land in the wrong profile entirely. On TCP the second bind
        // simply loses. Neither is discoverable from the logs. (Audit 2026-08-01, §5.)
        //
        // Only the PRIMARY endpoint used to be entered here; the extra `listen` specs were
        // checked for form and then dropped, so `primary <-> extra` and `extra <-> extra`
        // collisions were invisible — including a profile colliding with ITSELF by repeating
        // its own bind address in `listen`. Every endpoint the profile will actually bind goes
        // in. (Audit 2026-08-01, §2.)
        //
        // Hostname/IP equivalence is deliberately NOT resolved: `check-config` must work on a
        // machine that cannot reach DNS, and a resolver answer at validation time need not be
        // the answer at bind time. Two spellings of one host therefore still slip through.
        let transport = p.bind.transport.clone();
        let mut profile_endpoints: Vec<(String, u16, String, String)> = vec![(
            normalize_bind_host(&p.bind.address),
            p.bind.port,
            transport.clone(),
            format!("bind {}:{}", p.bind.address, p.bind.port),
        )];
        for spec in &p.bind.listen {
            if let Some((host, port)) = split_listen_spec(spec) {
                profile_endpoints.push((
                    host,
                    port,
                    transport.clone(),
                    format!("listen {}", spec.trim()),
                ));
            }
        }
        // The profile's SERVICES bind too, and they were never checked against anything. Two
        // profiles each running a resolver on the same address, or — far likelier — two with
        // DHCP left at its `0.0.0.0:67` default, both passed validation; the second bind then
        // failed inside a detached task and was logged once, so the profile came up serving
        // clients that never got a lease. (Audit 2026-08-01, §4.)
        if p.dns.enabled {
            if p.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
                let dns_host = normalize_bind_host(&p.dns.listen);
                // Both transports: the resolver now serves TCP as well (RFC 7766).
                for t in ["udp", "tcp"] {
                    profile_endpoints.push((
                        dns_host.clone(),
                        p.dns.port,
                        t.to_string(),
                        format!("dns {}:{}", p.dns.listen, p.dns.port),
                    ));
                }
            }
            if p.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
                if let Some(listen_ipv6) = p.dns.listen_ipv6.as_deref() {
                    let dns_host = normalize_bind_host(listen_ipv6);
                    for transport in ["udp", "tcp"] {
                        profile_endpoints.push((
                            dns_host.clone(),
                            p.dns.port,
                            transport.to_string(),
                            format!("dns [{}]:{}", listen_ipv6.trim(), p.dns.port),
                        ));
                    }
                }
            }
        }
        if p.dhcp.enabled {
            // Mirror the runtime's own normalisation: `run_profile` appends `:67` when the
            // value carries no port. Reading the raw string instead meant a bare
            // `dhcp.listen = 10.0.0.1` produced no endpoint at all, so the very collision this
            // map exists to catch — two profiles on the DHCP default — slipped through
            // whenever the operator wrote the address without a port.
            // (Audit 2026-08-01, §2.)
            let spec = dhcp_bind_spec(p);
            if let Some((host, port)) = split_listen_spec(&spec) {
                profile_endpoints.push((host, port, "udp".to_string(), format!("dhcp {spec}")));
            }
        }
        for (host, port, transport, label) in profile_endpoints {
            if let Some(other) = endpoints.iter().find(|e| {
                // A wildcard covers every address on the box, so `0.0.0.0:443` collides with
                // `1.2.3.4:443` just as surely as with another `0.0.0.0:443`.
                e.port == port && e.transport == transport && bind_hosts_overlap(&e.host, &host)
            }) {
                anyhow::bail!(
                    "'{}' ({}) and '{}' ({}) both bind port {}/{} on overlapping addresses — \
                     on UDP SO_REUSEPORT lets both succeed and the kernel then splits clients \
                     between them at random",
                    other.profile,
                    other.label,
                    p.name,
                    label,
                    port,
                    transport
                );
            }
            endpoints.push(BoundEndpoint {
                host,
                port,
                transport,
                profile: p.name.clone(),
                label,
            });
        }
        if !matches!(p.obfuscation.fronting.as_str(), "websocket" | "none") {
            anyhow::bail!(
                "profile '{}': unknown obf.fronting '{}' — expected 'websocket' or 'none'",
                p.name,
                p.obfuscation.fronting
            );
        }
        if !matches!(p.tun.device_type.as_str(), "tun" | "tap") {
            anyhow::bail!(
                "profile '{}': unknown tun.device_type '{}' — expected 'tun' or 'tap'",
                p.name,
                p.tun.device_type
            );
        }
        if !matches!(p.dns.upstream_protocol.as_str(), "udp" | "tcp") {
            anyhow::bail!(
                "profile '{}': unknown dns.upstream_protocol '{}' — expected 'udp' or 'tcp' \
                 (DoT/'tls' is not implemented; it would silently send plaintext UDP)",
                p.name,
                p.dns.upstream_protocol
            );
        }
        // Accepted server wire modes: plain, obfs, fake-tls (matched in
        // handler.rs / udp_handler.rs); reality-tls is honoured as a fake-tls
        // profile driven by obf.tls.reality_proxy (see server-multiprofile.conf).
        if !matches!(
            p.obfuscation.mode.as_str(),
            "plain" | "obfs" | "fake-tls" | "reality-tls"
        ) {
            anyhow::bail!(
                "profile '{}': unknown obf.mode '{}' — expected 'fake-tls', 'obfs', \
                 'plain' or 'reality-tls'",
                p.name,
                p.obfuscation.mode
            );
        }
        let perf = &p.performance.connection;
        if perf.handshake_timeout_secs == 0 || perf.max_clients == 0 {
            anyhow::bail!(
                "profile '{}': perf.connection.handshake_timeout_secs and \
                 perf.connection.max_clients must be > 0; remove an explicit zero to use \
                 the baseline default, or set a positive value",
                p.name
            );
        }
        // The pre-auth flood limiter has to have a working range too.
        //
        // `RateLimiter::new` takes these straight from the config with no bounds, and
        // nothing validated them — the neighbouring check above covers only
        // handshake_timeout_secs and max_clients. `window_secs = 0` makes
        // `now.duration_since(t) > ZERO` true for every recorded attempt, so the deque
        // empties on each call and the limiter always passes; `max_attempts = 0` makes it
        // never pass. This is the ONLY per-source-IP gate ahead of authentication, on TCP
        // accept and on every UDP datagram alike, and `qeli check-config` reported OK either
        // way because `parse_or` accepts a plain 0. `BruteForceConfig::validate` was written
        // for exactly this class of "a zero silently disables the control"; it just never
        // covered ConnectionConfig. (Audit 2026-08-04.)
        if perf.new_session_rate_max == 0 || perf.new_session_rate_window_secs == 0 {
            anyhow::bail!(
                "profile '{}': performance.connection.new_session_rate_max = {} and                  new_session_rate_window_secs = {} — a zero in either one silently DISABLES the                  only pre-authentication rate limit (0 attempts never passes; a 0-second window                  always does). Use real values, e.g. 30 attempts / 10 seconds.",
                p.name,
                perf.new_session_rate_max,
                perf.new_session_rate_window_secs
            );
        }
        p.obfuscation
            .recordizer
            .validate(&format!("profile '{}' obf.recordizer", p.name))?;
        // Heartbeat knobs drive timing and sizing, and the server also PUSHES them to
        // clients, yet nothing range-checked them. The arithmetic itself is now
        // overflow-safe at every use site, but absurd values are still nonsense: a jitter
        // at/above the interval makes the beat aperiodic to the point of meaningless, and
        // a zero interval with the beat enabled is a contradiction. Reject where the
        // config is authored rather than papering over it at runtime.
        let hb = &p.obfuscation.heartbeat;
        if hb.enabled {
            if hb.interval_ms == 0 {
                anyhow::bail!(
                    "profile '{}': obf.heartbeat.interval_ms must be > 0 when the heartbeat \
                     is enabled (set enabled = false to turn it off)",
                    p.name
                );
            }
            // A jitter at/above the interval makes the beat meaningless; cap it there.
            if hb.jitter_ms >= hb.interval_ms {
                anyhow::bail!(
                    "profile '{}': obf.heartbeat.jitter_ms ({}) must be smaller than \
                     interval_ms ({})",
                    p.name,
                    hb.jitter_ms,
                    hb.interval_ms
                );
            }
            // Leave room for the +32 cover-padding sizing adds AND for the record-format
            // ceiling. The former u16-only check accepted heartbeats that encryption could
            // never put on the wire.
            let max_heartbeat_data =
                u16::try_from(crate::protocol::packet::MAX_TUNNEL_MTU - 32).unwrap();
            if hb.data_size_bytes > max_heartbeat_data {
                anyhow::bail!(
                    "profile '{}': obf.heartbeat.data_size_bytes ({}) must be <= {}",
                    p.name,
                    hb.data_size_bytes,
                    max_heartbeat_data
                );
            }
        }
        // The same treatment for the rest of the obfuscation block. Heartbeat was validated
        // and these were not, so a nonsensical value was accepted at load and only showed up
        // as behaviour nobody could explain: an inverted min/max silently disables the
        // feature, `max_fragments_per_packet = 0` leaves the fragmenter with nowhere to put
        // the packet, and a probability outside 0..=1 (or NaN, which every comparison
        // answers `false` to) makes padding fire always or never. Reject where the config is
        // authored. (Audit 2026-07-29, #24.)
        let pad = &p.obfuscation.padding;
        if pad.enabled {
            if pad.min_bytes > pad.max_bytes {
                anyhow::bail!(
                    "profile '{}': obf.padding.min_bytes ({}) must be <= max_bytes ({})",
                    p.name,
                    pad.min_bytes,
                    pad.max_bytes
                );
            }
            if !(pad.probability.is_finite() && (0.0..=1.0).contains(&pad.probability)) {
                anyhow::bail!(
                    "profile '{}': obf.padding.probability ({}) must be a number in 0.0..=1.0",
                    p.name,
                    pad.probability
                );
            }
        }
        let frag = &p.obfuscation.fragmentation;
        if frag.enabled {
            if frag.min_chunk_size == 0 || frag.min_chunk_size > frag.max_chunk_size {
                anyhow::bail!(
                    "profile '{}': obf.fragmentation.min_chunk_size ({}) must be > 0 and \
                     <= max_chunk_size ({})",
                    p.name,
                    frag.min_chunk_size,
                    frag.max_chunk_size
                );
            }
            if frag.max_fragments_per_packet == 0 {
                anyhow::bail!(
                    "profile '{}': obf.fragmentation.max_fragments_per_packet must be > 0 \
                     (set enabled = false to turn fragmentation off)",
                    p.name
                );
            }
        }
        let norm = &p.obfuscation.traffic_normalization;
        if norm.enabled && (norm.round_sizes.is_empty() || norm.round_sizes.contains(&0)) {
            anyhow::bail!(
                "profile '{}': obf.traffic_normalization.round_sizes must be non-empty and \
                 carry no zero (set enabled = false to turn normalization off)",
                p.name
            );
        }
        let sh = &p.obfuscation.traffic_shaping;
        if sh.enabled {
            if sh.idle_gap_min_ms > sh.idle_gap_max_ms {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.idle_gap_min_ms ({}) must be <= \
                     idle_gap_max_ms ({})",
                    p.name,
                    sh.idle_gap_min_ms,
                    sh.idle_gap_max_ms
                );
            }
            if sh.idle_gap_mean_ms == 0 {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.idle_gap_mean_ms must be > 0 when \
                     shaping is enabled",
                    p.name
                );
            }
            if sh.min_size > sh.max_size {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.min_size ({}) must be <= max_size ({})",
                    p.name,
                    sh.min_size,
                    sh.max_size
                );
            }
            if sh.budget_bytes_per_sec < u32::from(sh.max_size) {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.budget_bytes_per_sec ({}) must be at least max_size ({}) so each scheduled cover record can be emitted",
                    p.name,
                    sh.budget_bytes_per_sec,
                    sh.max_size
                );
            }
            if usize::from(sh.max_size) > crate::protocol::packet::MAX_TUNNEL_MTU {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.max_size ({}) must be <= {}",
                    p.name,
                    sh.max_size,
                    crate::protocol::packet::MAX_TUNNEL_MTU
                );
            }
            if sh.budget_bytes_per_sec == 0 {
                anyhow::bail!(
                    "profile '{}': obf.traffic_shaping.budget_bytes_per_sec must be > 0 when \
                     shaping is enabled (0 sends no cover at all)",
                    p.name
                );
            }
        }
        // Validate the exact authenticated object emitted by build_auth_ok_for_addresses.
        // This shared contract also covers fields that are harmless while disabled but become
        // runtime inputs as soon as the corresponding pushed feature is enabled.
        crate::config::PushedObf {
            padding: p.obfuscation.padding.clone(),
            heartbeat: p.obfuscation.heartbeat.clone(),
            traffic_normalization: p.obfuscation.traffic_normalization.clone(),
            traffic_shaping: p.obfuscation.traffic_shaping.clone(),
            recordizer: Some(p.obfuscation.recordizer.clone()),
        }
        .validate(&format!("profile '{}' obf", p.name))?;

        // UDP has no FIN/RST. With every liveness source disabled and an unlimited idle
        // timeout, a vanished client can never be distinguished from a quiet one and keeps
        // its address/max_clients slot forever. Require at least one bounded reaper signal.
        if p.bind.transport == "udp" && !hb.enabled && !sh.enabled && perf.idle_timeout_secs == 0 {
            anyhow::bail!(
                "profile '{}': UDP cannot combine heartbeat=false, traffic_shaping=false and idle_timeout_secs=0; enable heartbeat/shaping or set a finite idle timeout so dead sessions release their IP and client slot",
                p.name
            );
        }
        // TCP normally has kernel keepalive as its final dead-peer detector. If an operator
        // explicitly disables that as well as application liveness and the idle reaper, a
        // vanished half-open peer can retain an address and max_clients slot indefinitely.
        if p.bind.transport == "tcp"
            && !hb.enabled
            && !sh.enabled
            && perf.idle_timeout_secs == 0
            && p.performance.tcp.keepalive_secs == 0
        {
            anyhow::bail!(
                "profile '{}': TCP cannot combine heartbeat=false, traffic_shaping=false, \
                 idle_timeout_secs=0 and perf.tcp.keepalive_secs=0; enable one liveness/reaper \
                 mechanism so dead sessions release their IP and client slot",
                p.name
            );
        }
        if p.obfuscation.mode == "plain" && p.bind.transport == "udp" {
            anyhow::bail!(
                "profile '{}': plain (raw) wire mode is TCP-only — set bind.transport = tcp",
                p.name
            );
        }
        // reality-tls on UDP is a profile that cannot do what its name says. REALITY wraps
        // the tunnel in a REAL TLS 1.3 session, which is a TCP stream; the UDP handler has no
        // such transport and falls through to fake-tls/obfs datagram framing. So the profile
        // started, reported itself as reality-tls, and put no genuine TLS on the wire at all
        // — the operator believes they have the strongest masking available and has the
        // weakest. Only `plain` was rejected here. (Audit 2026-07-29, #18.)
        //
        // The note here used to add that "the iOS client already refuses both combinations",
        // which was not true of any client: all four checked `proto` and `mode` separately and
        // never the pair. They refuse both now, so this end is no longer the strict one on its
        // own. (Audit 2026-08-03, P2.)
        if p.obfuscation.mode == "reality-tls" && p.bind.transport == "udp" {
            anyhow::bail!(
                "profile '{}': reality-tls is TCP-only — it terminates a real TLS session, \
                 which UDP cannot carry. Use bind.transport = tcp, or obfs for a UDP profile",
                p.name
            );
        }
        // Multipath/bonding on a UDP profile is a silent no-op: the UDP handler
        // forces max_streams=1 (UDP has no head-of-line blocking to bond around),
        // so a client that enabled it still gets one stream. Warn rather than fail
        // so a profile copied from a TCP one still starts.
        if p.obfuscation.multipath.enabled && p.bind.transport == "udp" {
            log::warn!(
                "profile '{}': obf.multipath.enabled has no effect on a UDP transport \
                 (stream bonding is TCP-only; the server caps UDP sessions at 1 stream)",
                p.name
            );
        }
        // AmneziaWG junk (obf.awg) is prepended before the handshake on TCP only in
        // the obfs wire mode (protocol::obfs), and on UDP in every mode (jc junk
        // datagrams). It has no effect ONLY on a TCP fake-tls/reality-tls profile:
        // there the client must send a real TLS ClientHello first, so junk would break
        // the mimicry and the handshake never emits it. Warn (don't fail) so the
        // operator doesn't rely on masking that isn't happening; the share link/QR
        // also omits awg for those profiles.
        if p.obfuscation.awg.enabled && p.obfuscation.mode != "obfs" && p.bind.transport != "udp" {
            log::warn!(
                "profile '{}': obf.awg.enabled has no effect on a TCP '{}' profile \
                 (AmneziaWG junk is sent only on TCP obfs and any UDP mode; a TCP \
                 fake-tls/reality-tls handshake never emits it). Use an obfs or UDP \
                 profile, or remove it.",
                p.name,
                p.obfuscation.mode
            );
        }
        // An empty obfs_key would derive a publicly-computable constant key
        // (SHA256("qeli-obfs-key-v1"‖"")) on TCP, and silently disable obfuscation
        // on UDP — either way the obfs wire mode gives zero DPI resistance while
        // looking configured. Refuse to start so the operator notices.
        if p.obfuscation.mode == "obfs" && p.obfuscation.obfs_key.trim().is_empty() {
            anyhow::bail!(
                "profile '{}': obfs wire mode requires a non-empty obfuscation.obfs_key \
                 (an empty key is publicly derivable → no DPI resistance)",
                p.name
            );
        }
        // REALITY proper requires at least one short_id: with an empty list the
        // server falls back to the legacy "no ALPN" heuristic (reality.rs), which an
        // active prober trivially defeats — it would receive the qeli handshake
        // instead of being transparently bridged to `dest`, unmasking the server.
        // Fail loud rather than start a REALITY profile with no crypto token. (An
        // all-blank list — e.g. `short_ids = [""]` — counts as empty.)
        let rp = &p.obfuscation.tls.reality_proxy;
        // `obf.mode` does not TURN ON any of this — that is the whole problem it creates.
        //
        // The runtime picks the REALITY path from `reality_proxy.enabled` and genuine TLS from
        // `real_tls`; the mode string only labels the profile. So `mode = reality-tls` with
        // either flag off started happily, called itself reality-tls in every log and in the
        // panel, and put plain fake-TLS on the wire — the operator believes they have the
        // strongest masking available and has the weakest, which is exactly the failure the
        // udp+reality-tls rule below exists to prevent, one level up.
        //
        // The converse pairing is legitimate and stays allowed: `mode = fake-tls` WITH
        // reality_proxy is the shipped "REALITY token, fake-TLS inner" variant
        // (server-multiprofile.conf) and `fake-tls` + real_tls is server-maxobf.conf. Only the
        // NAME is being held to its promise here. (Audit 2026-08-03, P2.)
        // The hand-rolled REALITY terminator deliberately borrows the decoy's certificate
        // without its private key, so that outer certificate is camouflage rather than an
        // authentication boundary. The inner pinned static key is the real server identity;
        // require the KDF to bind it into every real-TLS session instead of permitting a
        // configuration whose only remaining authentication guarantee is accidentally weaker.
        if rp.enabled && rp.real_tls && !config.auth.bind_static_to_session {
            anyhow::bail!(
                "profile '{}': REALITY real-TLS requires auth.bind_static_to_session = true —                  the borrowed outer certificate is camouflage, so the pinned static identity                  must be bound into the inner session keys",
                p.name
            );
        }
        if p.obfuscation.mode == "reality-tls" && !rp.enabled {
            anyhow::bail!(
                "profile '{}': obf.mode = reality-tls but obf.tls.reality_proxy.enabled is \
                 false — the mode name turns nothing on, so this profile is plain fake-TLS \
                 while calling itself REALITY. Set reality_proxy.enabled = true (with \
                 short_ids), or set obf.mode = fake-tls",
                p.name
            );
        }
        // A WARNING, not a refusal, and the asymmetry is deliberate.
        //
        // `reality-tls` + REALITY + `real_tls = false` is a coherent profile — REALITY token
        // detection with a fake-TLS inner handshake — that the shipped examples spell
        // `obf.mode = fake-tls` (server-multiprofile.conf). So the name overstates the wire
        // without lying about what runs, and refusing it would stop an existing server from
        // booting after an upgrade over a naming convention. The case above is different: with
        // reality_proxy off, NOTHING about REALITY is on and the label is simply false.
        if p.obfuscation.mode == "reality-tls" && !rp.real_tls {
            log::warn!(
                "profile '{}': obf.mode = reality-tls with reality_proxy.real_tls = false — no \
                 genuine TLS session is terminated, so the wire carries the fake-TLS handshake \
                 a TLS-state-machine DPI can spot. Set real_tls = true for what the name \
                 promises, or obf.mode = fake-tls for what this actually is",
                p.name
            );
        }
        // REALITY reads a TLS ClientHello. `obfs` and `plain` never send one, so the token has
        // nowhere to live and the setting is inert — the profile advertises active-probe
        // resistance it does not have.
        if rp.enabled && !matches!(p.obfuscation.mode.as_str(), "fake-tls" | "reality-tls") {
            anyhow::bail!(
                "profile '{}': obf.tls.reality_proxy.enabled with obf.mode = '{}' — REALITY \
                 identifies clients by a token in the TLS ClientHello, which this mode never \
                 sends, so the setting does nothing. Use fake-tls or reality-tls",
                p.name,
                p.obfuscation.mode
            );
        }
        // Same reasoning across transports: the UDP handler has no ClientHello to read.
        // `mode = reality-tls` on UDP is caught below; this catches the fake-tls spelling.
        if rp.enabled && p.bind.transport == "udp" {
            anyhow::bail!(
                "profile '{}': obf.tls.reality_proxy.enabled on a UDP profile — REALITY \
                 inspects a TLS ClientHello, which the datagram path never carries, so the \
                 setting is inert. Use bind.transport = tcp, or obfs for a UDP profile",
                p.name
            );
        }
        if rp.enabled && rp.short_ids.iter().all(|s| s.trim().is_empty()) {
            anyhow::bail!(
                "profile '{}': reality_proxy.enabled requires at least one non-empty \
                 obf.tls.reality_proxy.short_ids entry — an empty list falls back to the \
                 trivially-probeable ALPN-absence heuristic (no active-probe resistance)",
                p.name
            );
        }
        if rp.enabled && rp.target.trim().is_empty() {
            anyhow::bail!(
                "profile '{}': reality_proxy.enabled requires a non-empty \
                 obf.tls.reality_proxy.target for probe/decoy traffic",
                p.name
            );
        }
        if rp.enabled && rp.target_port == 0 {
            anyhow::bail!(
                "profile '{}': obf.tls.reality_proxy.target_port = 0 cannot reach a \
                 probe/decoy backend — set its real TCP port",
                p.name
            );
        }
        // A NON-EMPTY but unusable list is just as dangerous, and used to be silent: the
        // lenient hex parser dropped every non-hex character, so `short_ids = zzzz` became
        // all-zeros and matched any client whose short_id was equally malformed. The
        // allow-list now skips entries that don't parse (server/reality.rs), which would
        // leave such a profile quietly rejecting everyone — so refuse to start instead and
        // say which entry is at fault. (Audit 2026-07-27, C8.)
        if rp.enabled {
            let bad: Vec<&str> = rp
                .short_ids
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && crate::crypto::reality::parse_short_id(s).is_none())
                .collect();
            if !bad.is_empty() {
                anyhow::bail!(
                    "profile '{}': obf.tls.reality_proxy.short_ids contains unusable \
                     entries {:?} — each must be 1..=16 hex digits (0-9a-f, optionally \
                     separated by ':' or '-') and must not be all zeros. Generate one with \
                     `openssl rand -hex 8`",
                    p.name,
                    bad
                );
            }
        }
        // REALITY camouflages as a real TLS site (mimicking its cert + ServerHello by
        // SNI); a bare-IP target can't present a matching hostname, weakening the
        // disguise. Warn (don't fail — an operator may have a reason).
        if rp.enabled && rp.target.parse::<IpAddr>().is_ok() {
            log::warn!(
                "profile '{}': reality_proxy.target '{}' is a bare IP — REALITY mimics a real \
                 TLS site, so a hostname (e.g. www.microsoft.com) is recommended for camouflage",
                p.name,
                rp.target
            );
        }
        // fake-tls as the OUTER wire mode emits a plaintext Certificate/Finished right
        // after ServerHello, where real TLS 1.3 would send encrypted application_data —
        // a TLS-state-machine DPI distinguishes it. It is fine only as the INNER
        // handshake wrapped in real TLS (reality_proxy.real_tls). Warn otherwise so an
        // operator on a hostile network picks reality-tls or obfs instead.
        if p.obfuscation.mode == "fake-tls" && !(rp.enabled && rp.real_tls) {
            // reality-tls wraps the tunnel in a REAL TLS session, which is TCP-only — on a
            // UDP profile it cannot be enabled at all, so advertising it there sends the
            // operator chasing a setting that does not apply. obfs works on both.
            let remedy = if p.bind.transport == "udp" {
                "Prefer obfs on hostile networks (reality-tls is TCP-only and cannot be used \
                 on a UDP profile)."
            } else {
                "Prefer reality-tls (obf.tls.reality_proxy.real_tls=true + handrolled=true) \
                 or obfs on hostile networks."
            };
            // A QUIC-masked profile still puts those records on the wire verbatim — the QUIC
            // layer only prepends a header, it does not encrypt — so the warning stands; only
            // the envelope a DPI has to look inside differs.
            log::warn!(
                "profile '{}': wire mode 'fake-tls' has LOW DPI resistance (plaintext TLS \
                 handshake records on the wire). {}",
                p.name,
                remedy
            );
        }

        // Address fields. The worker parses these only once it STARTS the profile
        // (`run_profile`: `IpPool::new_with_tun`, `TunInterface::set_address`), so nothing here
        // caught a typo: `check-config` answered OK / rc=0 and the worker then died on
        // every respawn — `invalid CIDR`, `invalid CIDR prefix (>32)`, or `ip` rejecting
        // the address with "any valid prefix is expected". The panel's save path calls
        // this function too, so an admin could persist a config that bricked the server.
        //
        let ipv6_subnet = crate::config::server::validate_ipv6_profile(p)
            .map_err(|error| anyhow::anyhow!("profile '{}': {}", p.name, error))?;
        if let Some(subnet) = ipv6_subnet {
            let overlap = ipv6_pools.iter().find(|(_, other)| {
                subnet.contains(other.network) || other.contains(subnet.network)
            });
            if let Some((other_name, _)) = overlap {
                anyhow::bail!(
                    "profiles '{}' and '{}' have overlapping IPv6 pools ('{}' and '{}')",
                    other_name,
                    p.name,
                    config
                        .profiles
                        .iter()
                        .find(|profile| profile.name.as_str() == other_name.as_str())
                        .map(|profile| profile.pool.ipv6.cidr.as_str())
                        .unwrap_or("<unknown>"),
                    p.pool.ipv6.cidr
                );
            }
            ipv6_pools.push((p.name.clone(), subnet));
        }
        let tunnel_ipv6_address = p
            .tun
            .ipv6_address
            .as_deref()
            .and_then(|value| value.trim().parse::<std::net::Ipv6Addr>().ok());

        if p.routing.advertised_routes.len() > crate::transport_core::MAX_ROUTES {
            anyhow::bail!(
                "profile '{}': routing.advertised_routes has {} entries; maximum is {}",
                p.name,
                p.routing.advertised_routes.len(),
                crate::transport_core::MAX_ROUTES
            );
        }
        for route in &p.routing.advertised_routes {
            let route_address = route
                .cidr
                .split_once('/')
                .and_then(|(address, _)| address.parse::<std::net::IpAddr>().ok());
            if let Some(route_address) = route_address {
                if route_address.is_ipv6() && p.tun.ip_mode == crate::config::server::IpMode::Ipv4 {
                    anyhow::bail!(
                        "profile '{}': route {} is IPv6 but tun.ip_mode = ipv4",
                        p.name,
                        route.cidr
                    );
                }
                if route_address.is_ipv4() && p.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
                    anyhow::bail!(
                        "profile '{}': route {} is IPv4 but tun.ip_mode = ipv6",
                        p.name,
                        route.cidr
                    );
                }
            }
        }

        let tunnel_address = if p.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
            let tunnel_subnet = crate::config::server::pool_subnet(&p.pool.cidr)
                .map_err(|e| anyhow::anyhow!("profile '{}': {}", p.name, e))?;
            let overlap = ipv4_pools.iter().find(|(_, other)| {
                u32::from(tunnel_subnet.network) <= u32::from(other.broadcast)
                    && u32::from(other.network) <= u32::from(tunnel_subnet.broadcast)
            });
            if let Some((other_name, other)) = overlap {
                anyhow::bail!(
                    "profiles '{}' and '{}' have overlapping IPv4 pools ('{}/{}' and '{}')",
                    other_name,
                    p.name,
                    other.network,
                    other.prefix,
                    p.pool.cidr
                );
            }
            ipv4_pools.push((p.name.clone(), tunnel_subnet));
            let tunnel_address = p.tun.address.parse::<std::net::Ipv4Addr>().map_err(|e| {
                anyhow::anyhow!(
                    "profile '{}': invalid tun.address '{}': {} — expected a plain IPv4 address \
                     (e.g. 10.9.0.1)",
                    p.name,
                    p.tun.address,
                    e
                )
            })?;
            if !tunnel_subnet.contains_usable_host(tunnel_address) {
                anyhow::bail!(
                    "profile '{}': tun.address {} is not a usable host inside pool.cidr {} \
                     (network {}, broadcast {}). The TUN prefix and all client prefixes are \
                     derived from pool.cidr; choose an address between them.",
                    p.name,
                    tunnel_address,
                    p.pool.cidr,
                    tunnel_subnet.network,
                    tunnel_subnet.broadcast
                );
            }
            pool::IpPool::new_with_tun(&p.pool, tunnel_address).map_err(|e| {
                anyhow::anyhow!("profile '{}': pool.cidr '{}': {}", p.name, p.pool.cidr, e)
            })?;
            Some(tunnel_address)
        } else {
            None
        };
        // tun.mtu is handed straight to `ip link set … mtu N` at profile start
        // (`create_multiqueue` / `set_up`); the kernel then rejects anything outside
        // the TUN device's [68, 65535] range with "mtu less/greater than device
        // minimum/maximum" — and the worker crash-loops on it. Same class as the
        // address fields above: check-config used to answer OK and the box died on
        // every respawn.
        //
        // The bound is now the shared MTU_MIN..=MTU_MAX rather than the kernel's raw
        // 68..=65535, because the kernel accepting a value is not the same as the tunnel
        // working with it: clients discard a pushed MTU outside MTU_MIN..=MTU_MAX and fall back
        // to 1400, so a server configured at, say, 300 came up fine and then black-holed
        // every packet over 300 bytes with nothing logged at either end. Reject it here
        // instead, where the operator can still read the message. (Audit 2026-07-27, C4.)
        if !crate::config::server::mtu_in_range(p.tun.mtu as i64) {
            anyhow::bail!(
                "profile '{}': tun.mtu {} is out of range — expected {}..={} (a VPN \
                 typically wants ~1280-1420). Values the kernel would accept but the \
                 clients would discard are refused here, because the resulting one-way \
                 MTU mismatch is silent on both sides.",
                p.name,
                p.tun.mtu,
                crate::config::server::MTU_MIN,
                crate::config::server::MTU_MAX
            );
        }
        // DHCP pool bounds are parsed as IPv4 only when the server STARTS the DHCP
        // service (`run_profile`, gated on dhcp.enabled), so a malformed address
        // slipped past check-config and crash-looped the worker with "invalid
        // dhcp.pool_start/end". Mirror that parse (defaults included) and the
        // end >= start rule here so the two paths can't drift.
        if p.dhcp.enabled {
            crate::config::server::dhcp_pool_bounds(
                &p.dhcp,
                &p.pool.cidr,
                tunnel_address.expect("DHCPv4 is rejected for IPv6-only profiles"),
            )
            .map_err(|e| anyhow::anyhow!("profile '{}': {}", p.name, e))?;
            // A zero lease is not "no expiry", it is a lease that has already expired: the
            // client is told to renew at half of zero, so it renews continuously and the
            // server's own sweep reclaims the address on its next pass. Nothing about that is
            // a configuration someone meant. (Audit 2026-08-01, §12.)
            if p.dhcp.lease_time_secs == 0 {
                anyhow::bail!(
                    "profile '{}': dhcp.lease_time_secs = 0 hands out leases that are already \
                     expired — clients would renew in a loop and addresses would churn. Set a \
                     real lifetime (the default is 86400).",
                    p.name
                );
            }
            // Option 12/15 carry a single length BYTE, so anything past 255 cannot be encoded.
            // It was silently omitted from the reply instead, leaving clients with no domain
            // and no indication why.
            if p.dhcp.domain_name.len() > 255 {
                anyhow::bail!(
                    "profile '{}': dhcp.domain_name is {} bytes — a DHCP option's length field \
                     is one byte, so anything past 255 cannot be sent at all",
                    p.name,
                    p.dhcp.domain_name.len()
                );
            }
        }
        // dns.upstream entries are only validated lazily, per-query (`parse::<SocketAddr>()`
        // then `continue` on error in dns.rs), so a malformed resolver was accepted at load
        // with no warning and then silently skipped — and if EVERY upstream is bad, DNS just
        // fails with nothing logged. Warn at load (matching pool.exclude's lenient style) so
        // a typo is visible instead of silent. Left non-fatal: one bad entry among good ones
        // still resolves.
        if p.dns.enabled {
            let mut usable = 0usize;
            let mut upstream_addresses = std::collections::HashSet::new();
            for up in &p.dns.upstream {
                let ip = match up.trim().parse::<std::net::IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => {
                        log::warn!(
                            "profile '{}': dns.upstream '{}' is not a valid IP address — this \
                             resolver will be skipped at query time",
                            p.name,
                            up
                        );
                        continue;
                    }
                };
                if ip.is_unspecified() || ip.is_multicast() {
                    log::warn!(
                        "profile '{}': dns.upstream '{}' is not a reachable resolver address — \
                         it will be skipped at query time",
                        p.name,
                        up
                    );
                    continue;
                }
                if !upstream_addresses.insert(ip) {
                    anyhow::bail!(
                        "profile '{}': duplicate dns.upstream address '{}'",
                        p.name,
                        ip
                    );
                }
                usable += 1;
            }
            // One bad entry among good ones is a warning; ALL of them bad is a resolver that
            // can never answer anything. Since clients are handed this proxy as their DNS,
            // that is a black hole for every name they look up — and the old behaviour was to
            // start anyway and fail each query in silence. (Audit 2026-07-29, #22.)
            // An EXPLICIT `dns.upstream =` replaces the defaults with an empty list, and the
            // proxy then abandons every query — clients are handed a resolver that answers
            // nothing. Empty is not "use the defaults"; it is "I configured none".
            // (Audit 2026-07-31, §8.)
            // Bounds the proxy actually needs. `dns.port = 0` binds an EPHEMERAL port the
            // operator never chose and cannot redirect to (`--to-ports 0` is meaningless), and
            // `dns.timeout_secs = 0` makes every upstream wait expire instantly — both parsed
            // cleanly and failed later, or not visibly at all. (Audit 2026-08-01, §3.)
            if p.dns.port == 0 {
                anyhow::bail!(
                    "profile '{}': dns.port = 0 would bind an ephemeral port nothing can be                      pointed at — set 53, or a fixed port",
                    p.name
                );
            }
            if p.dns.timeout_secs == 0 {
                anyhow::bail!(
                    "profile '{}': dns.timeout_secs = 0 gives every upstream query a zero                      deadline, so the proxy can never answer",
                    p.name
                );
            }
            if p.dns.timeout_secs > crate::config::server::DNS_MAX_TIMEOUT_SECS {
                anyhow::bail!(
                    "profile '{}': dns.timeout_secs = {} exceeds the maximum {} seconds",
                    p.name,
                    p.dns.timeout_secs,
                    crate::config::server::DNS_MAX_TIMEOUT_SECS
                );
            }
            if p.dns.upstream.len() > crate::config::server::DNS_MAX_UPSTREAMS {
                anyhow::bail!(
                    "profile '{}': dns.upstream has {} entries; maximum is {}",
                    p.name,
                    p.dns.upstream.len(),
                    crate::config::server::DNS_MAX_UPSTREAMS
                );
            }
            if p.dns.cache_size > crate::config::server::DNS_MAX_CACHE_ENTRIES {
                anyhow::bail!(
                    "profile '{}': dns.cache_size = {} exceeds the maximum {} entries",
                    p.name,
                    p.dns.cache_size,
                    crate::config::server::DNS_MAX_CACHE_ENTRIES
                );
            }
            if p.dns.blocklist.len() > crate::config::server::DNS_MAX_BLOCKLIST_ENTRIES {
                anyhow::bail!(
                    "profile '{}': dns.blocklist has {} entries; maximum is {}",
                    p.name,
                    p.dns.blocklist.len(),
                    crate::config::server::DNS_MAX_BLOCKLIST_ENTRIES
                );
            }
            let mut blocked_domains = std::collections::HashSet::new();
            for raw in &p.dns.blocklist {
                let Some(domain) = crate::config::server::normalize_blocklist_domain(raw) else {
                    anyhow::bail!(
                        "profile '{}': dns.blocklist entry {:?} is not a valid ASCII DNS name \
                         (labels 1..=63 bytes, total <=253; wildcard syntax is not supported)",
                        p.name,
                        raw
                    );
                };
                if !blocked_domains.insert(domain.clone()) {
                    anyhow::bail!(
                        "profile '{}': duplicate dns.blocklist domain '{}'",
                        p.name,
                        domain
                    );
                }
            }
            // On IPv4/dual profiles `dns.listen` is handed to clients as their resolver AND
            // bound locally. IPv6-only profiles deliberately ignore this legacy/default IPv4
            // field and use `dns.listen_ipv6` below.
            if p.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
                match p.dns.listen.trim().parse::<std::net::IpAddr>() {
                Ok(ip) if ip.is_unspecified() || ip.is_multicast() => anyhow::bail!(
                    "profile '{}': dns.listen = {} is not an address a client can query — use                      the profile's tun address",
                    p.name,
                    p.dns.listen
                ),
                // A loopback address is bindable HERE and meaningless THERE. This value is
                // pushed to clients as their resolver, and `127.0.0.1` inside the tunnel means
                // the CLIENT's own loopback — so every lookup goes to whatever is (or is not)
                // listening on the client machine, and the profile's resolver is never asked.
                // It binds cleanly on the server, which is exactly why it was worth catching
                // here rather than leaving to fail as "DNS just doesn't work".
                // (Audit 2026-08-01, §P2.)
                Ok(ip) if ip.is_loopback() => anyhow::bail!(
                    "profile '{}': dns.listen = {} is a loopback address — clients are handed \
                     this as their resolver, and inside the tunnel it points at their OWN \
                     loopback, not at this server. Use the profile's tun address ({}).",
                    p.name,
                    p.dns.listen,
                    p.tun.address
                ),
                // The primary field remains IPv4. IPv6 has its own explicit listen key, so a
                // literal here is ambiguous in dual mode and ignored in IPv6-only mode.
                Ok(ip) if ip.is_ipv6() => anyhow::bail!(
                    "profile '{}': dns.listen = {} is IPv6 — put the IPv6 resolver address in \
                     dns.listen_ipv6; keep dns.listen equal to the IPv4 tun.address ({})",
                    p.name,
                    p.dns.listen,
                    p.tun.address
                ),
                Ok(std::net::IpAddr::V4(address)) => {
                    if tunnel_address.is_some_and(|tunnel_address| address != tunnel_address) {
                        anyhow::bail!(
                            "profile '{}': dns.listen {} must equal tun.address {} — it is the only IPv4 address configured on the server TUN",
                            p.name,
                            address,
                            tunnel_address.expect("IPv4 DNS comparison has an IPv4 tunnel")
                        );
                    }
                }
                Ok(std::net::IpAddr::V6(_)) => unreachable!(),
                Err(_) => anyhow::bail!(
                    "profile '{}': dns.listen = '{}' is not an IP address",
                    p.name,
                    p.dns.listen
                ),
                }
            }
            // A non-default dns.port is only usable because the tunnel bridges 53 to it with
            // an iptables REDIRECT — clients cannot address any other port. Without iptables
            // there is nothing to bridge with, and every client would be handed a resolver it
            // cannot reach. Say so at load instead of at the first DNS lookup.
            // (Audit 2026-07-31.)
            if p.dns.port != 53 {
                if p.tun.ip_mode != crate::config::server::IpMode::Ipv6 && !nat::available() {
                    anyhow::bail!(
                        "profile '{}': dns.port = {} needs iptables for the IPv4 53 -> {} redirect. Set dns.port = 53, or install iptables.",
                        p.name,
                        p.dns.port,
                        p.dns.port
                    );
                }
                if p.tun.ip_mode != crate::config::server::IpMode::Ipv4
                    && nat::ip6tables_path().is_none()
                {
                    anyhow::bail!(
                        "profile '{}': dns.port = {} needs ip6tables for the IPv6 53 -> {} redirect. Set dns.port = 53, or install ip6tables.",
                        p.name,
                        p.dns.port,
                        p.dns.port
                    );
                }
            }
            if p.dns.upstream.is_empty() {
                anyhow::bail!(
                    "profile '{}': dns.enabled = true but dns.upstream is empty — the DNS proxy                      would abandon every query while clients are pushed to use it. Set at least                      one IP upstream, or dns.enabled = false.",
                    p.name
                );
            }
            if usable == 0 && !p.dns.upstream.is_empty() {
                anyhow::bail!(
                    "profile '{}': none of the {} dns.upstream entries is a usable IP address \
                     (all are invalid, unspecified or multicast) — the DNS proxy \
                     would answer nothing while clients are pushed to use it",
                    p.name,
                    p.dns.upstream.len()
                );
            }
        }
        if let Some(raw) = p.dns.listen_ipv6.as_deref() {
            let value = raw.trim();
            let address = value.parse::<std::net::Ipv6Addr>().map_err(|error| {
                anyhow::anyhow!(
                    "profile '{}': dns.listen_ipv6 = '{}' is not a bare IPv6 address: {}",
                    p.name,
                    value,
                    error
                )
            })?;
            crate::config::server::validate_tunnel_ipv6_address("dns.listen_ipv6", address)
                .map_err(|error| anyhow::anyhow!("profile '{}': {}", p.name, error))?;
            if let Some(subnet) = ipv6_subnet {
                if !subnet.contains_assignable(address) {
                    anyhow::bail!(
                        "profile '{}': dns.listen_ipv6 {} is outside pool.ipv6.cidr {}",
                        p.name,
                        address,
                        p.pool.ipv6.cidr
                    );
                }
            }
            if p.dns.enabled && tunnel_ipv6_address != Some(address) {
                anyhow::bail!(
                    "profile '{}': dns.listen_ipv6 {} must equal tun.ipv6_address — it is the only IPv6 address configured on the server TUN",
                    p.name,
                    address
                );
            }
        } else if p.dns.enabled && p.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
            anyhow::bail!(
                "profile '{}': dns.enabled in dual/IPv6 mode requires dns.listen_ipv6",
                p.name
            );
        }
        // The FIRST push_servers entry is what clients are told to use as their resolver, so
        // a typo there silently deprives every client of DNS (the client strict-validates the
        // pushed value and then has nothing left to use). Validate all of them: a later entry
        // being wrong is a latent trap for the day the first one is removed.
        for ps in &p.dns.push_servers {
            let ip = ps.trim().parse::<std::net::IpAddr>().map_err(|_| {
                anyhow::anyhow!(
                    "profile '{}': dns.push_servers entry '{}' is not a valid IP address — it is handed to clients as their resolver",
                    p.name,
                    ps
                )
            })?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
                anyhow::bail!(
                    "profile '{}': dns.push_servers entry '{}' is not a resolver address reachable by tunnel clients",
                    p.name,
                    ps
                );
            }
            if ip.is_ipv6() && p.tun.ip_mode == crate::config::server::IpMode::Ipv4 {
                anyhow::bail!(
                    "profile '{}': IPv6 dns.push_servers entry '{}' requires tun.ip_mode = dual or ipv6",
                    p.name,
                    ps
                );
            }
            if ip.is_ipv4() && p.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
                anyhow::bail!(
                    "profile '{}': IPv4 dns.push_servers entry '{}' is unreachable in an IPv6-only tunnel",
                    p.name,
                    ps
                );
            }
        }

        // DHCP is an UNAUTHENTICATED service and gets the same bind rule as the resolver.
        //
        // The two were treated inconsistently: `dns.listen = 0.0.0.0` is a hard error
        // above, while `dhcp.listen` defaulted to `0.0.0.0:67` and `DhcpServer::bind`
        // merely logged a warning and carried on. So a single `dhcp.enabled = true` — the
        // only key an operator sets — published DHCP on every interface including the
        // public one, where anyone able to reach UDP/67 (qeli programs NAT/FORWARD/MSS
        // rules but never touches INPUT) gets a valid OFFER/ACK carrying an address from
        // the profile's pool, its mask, gateway and DNS servers. Same class of exposure,
        // same treatment. (Audit 2026-08-04.)
        if p.dhcp.enabled {
            let host = p
                .dhcp
                .listen
                .rsplit_once(':')
                .map_or(p.dhcp.listen.as_str(), |(h, _)| h);
            match host.trim().parse::<std::net::IpAddr>() {
                Ok(ip) if ip.is_unspecified() => anyhow::bail!(
                    "profile '{}': dhcp.listen = {} publishes an UNAUTHENTICATED DHCP server on every interface, including any public one. Bind it to the profile's tun address ({}), or to the TAP bridge address if this profile bridges.",
                    p.name,
                    p.dhcp.listen,
                    p.tun.address
                ),
                Ok(ip) if ip.is_multicast() => anyhow::bail!(
                    "profile '{}': dhcp.listen = {} is not a bindable address",
                    p.name,
                    p.dhcp.listen
                ),
                Ok(_) | Err(_) => {}
            }
        }
    }
    // This depends on the complete enabled-profile/listener/queue set, so it cannot be
    // validated one profile at a time. Running it here makes check-config, panel save/restart,
    // supervisor start and direct worker start all reject the same memory overcommit.
    let _ = server_udp_buffer_budget(config)?;
    Ok(())
}

fn validate_fixed_ipv4_address(
    profile: &crate::config::server::ProfileConfig,
    field: &str,
    address: std::net::Ipv4Addr,
) -> anyhow::Result<()> {
    let subnet = crate::config::server::pool_subnet(&profile.pool.cidr)
        .map_err(|error| anyhow::anyhow!("profile '{}': {error}", profile.name))?;
    let tunnel = profile
        .tun
        .address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|error| {
            anyhow::anyhow!(
                "profile '{}': invalid tun.address '{}': {error}",
                profile.name,
                profile.tun.address
            )
        })?;
    let excluded = profile
        .pool
        .exclude
        .iter()
        .map(|raw| {
            raw.parse::<std::net::Ipv4Addr>().map_err(|error| {
                anyhow::anyhow!(
                    "profile '{}': invalid pool.exclude entry '{}': {error}",
                    profile.name,
                    raw
                )
            })
        })
        .collect::<anyhow::Result<std::collections::HashSet<_>>>()?;
    if !subnet.contains_usable_host(address) || address == tunnel || excluded.contains(&address) {
        anyhow::bail!(
            "profile '{}': {field} = {address} is not assignable in pool.cidr {} \
             (outside the usable range, the server TUN address, or pool.exclude)",
            profile.name,
            profile.pool.cidr
        );
    }
    Ok(())
}

fn validate_fixed_ipv6_address(
    profile: &crate::config::server::ProfileConfig,
    field: &str,
    address: std::net::Ipv6Addr,
) -> anyhow::Result<()> {
    crate::config::server::validate_tunnel_ipv6_address(field, address)
        .map_err(|error| anyhow::anyhow!("profile '{}': {error}", profile.name))?;
    let subnet = crate::config::server::ipv6_pool_subnet(&profile.pool.ipv6.cidr)
        .map_err(|error| anyhow::anyhow!("profile '{}': {error}", profile.name))?;
    let tunnel_raw = profile.tun.ipv6_address.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "profile '{}': tun.ipv6_address is required for {field}",
            profile.name
        )
    })?;
    let tunnel = tunnel_raw.parse::<std::net::Ipv6Addr>().map_err(|error| {
        anyhow::anyhow!(
            "profile '{}': invalid tun.ipv6_address '{}': {error}",
            profile.name,
            tunnel_raw
        )
    })?;
    let excluded = profile
        .pool
        .ipv6
        .exclude
        .iter()
        .map(|raw| {
            raw.parse::<std::net::Ipv6Addr>().map_err(|error| {
                anyhow::anyhow!(
                    "profile '{}': invalid pool.ipv6.exclude entry '{}': {error}",
                    profile.name,
                    raw
                )
            })
        })
        .collect::<anyhow::Result<std::collections::HashSet<_>>>()?;
    if !subnet.contains_assignable(address) || address == tunnel || excluded.contains(&address) {
        anyhow::bail!(
            "profile '{}': {field} = {address} is not assignable in pool.ipv6.cidr {} \
             (outside the assignable range, the server TUN address, or pool.ipv6.exclude)",
            profile.name,
            profile.pool.ipv6.cidr
        );
    }
    Ok(())
}

/// Validate the effective address assignment after the profile config and users database
/// have been combined. Each source is valid in isolation, but the runtime gives a user's
/// `static_ip`/`static_ipv6` precedence over `pool.*.reservation.<user>`. Without a joint
/// gate, one source can silently disable the other or steal an address reserved for somebody
/// else on the same profile.
pub fn validate_static_address_sources(config: &ServerConfig, db: &UsersDb) -> anyhow::Result<()> {
    use crate::config::server::IpMode;
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    for profile in config.profiles.iter().filter(|profile| profile.enabled) {
        let ipv4_reservations: HashMap<Ipv4Addr, &str> = if profile.tun.ip_mode != IpMode::Ipv6 {
            profile
                .pool
                .static_reservations
                .iter()
                .map(|(username, raw)| {
                    let address = raw.parse::<Ipv4Addr>().map_err(|error| {
                        anyhow::anyhow!(
                            "profile '{}': pool.reservation.{} = '{}' is invalid: {}",
                            profile.name,
                            username,
                            raw,
                            error
                        )
                    })?;
                    validate_fixed_ipv4_address(
                        profile,
                        &format!("pool.reservation.{username}"),
                        address,
                    )?;
                    Ok((address, username.as_str()))
                })
                .collect::<anyhow::Result<_>>()?
        } else {
            HashMap::new()
        };
        let ipv6_reservations: HashMap<Ipv6Addr, &str> = if profile.tun.ip_mode != IpMode::Ipv4 {
            profile
                .pool
                .ipv6
                .static_reservations
                .iter()
                .map(|(username, raw)| {
                    let address = raw.parse::<Ipv6Addr>().map_err(|error| {
                        anyhow::anyhow!(
                            "profile '{}': pool.ipv6.reservation.{} = '{}' is invalid: {}",
                            profile.name,
                            username,
                            raw,
                            error
                        )
                    })?;
                    validate_fixed_ipv6_address(
                        profile,
                        &format!("pool.ipv6.reservation.{username}"),
                        address,
                    )?;
                    Ok((address, username.as_str()))
                })
                .collect::<anyhow::Result<_>>()?
        } else {
            HashMap::new()
        };
        let mut ipv4_user_assignments: HashMap<Ipv4Addr, &str> = HashMap::new();
        let mut ipv6_user_assignments: HashMap<Ipv6Addr, &str> = HashMap::new();

        for user in db
            .users
            .iter()
            .filter(|user| user.enabled && user.allowed_on_profile(&profile.name))
        {
            if let Some(raw) = user
                .static_ip
                .as_deref()
                .filter(|_| profile.tun.ip_mode != IpMode::Ipv6)
            {
                let address = raw.parse::<Ipv4Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "user '{}': static_ip '{}' is invalid: {}",
                        user.username,
                        raw,
                        error
                    )
                })?;
                validate_fixed_ipv4_address(
                    profile,
                    &format!("user '{}' static_ip", user.username),
                    address,
                )?;
                if let Some(other) = ipv4_user_assignments.insert(address, user.username.as_str()) {
                    anyhow::bail!(
                        "profile '{}': users '{}' and '{}' both request static_ip {}",
                        profile.name,
                        other,
                        user.username,
                        address
                    );
                }
                if let Some(owner) = ipv4_reservations.get(&address) {
                    if *owner != user.username {
                        anyhow::bail!(
                            "profile '{}': user '{}' static_ip {} collides with pool.reservation.{}",
                            profile.name, user.username, address, owner
                        );
                    }
                }
                if let Some(reserved) = profile.pool.static_reservations.get(&user.username) {
                    if reserved.parse::<Ipv4Addr>().ok() != Some(address) {
                        anyhow::bail!(
                            "profile '{}': user '{}' has static_ip {}, but pool.reservation.{} is {} — the user value would silently override the profile reservation",
                            profile.name, user.username, address, user.username, reserved
                        );
                    }
                }
            }
            if let Some(raw) = user
                .static_ipv6
                .as_deref()
                .filter(|_| profile.tun.ip_mode != IpMode::Ipv4)
            {
                let address = raw.parse::<Ipv6Addr>().map_err(|error| {
                    anyhow::anyhow!(
                        "user '{}': static_ipv6 '{}' is invalid: {}",
                        user.username,
                        raw,
                        error
                    )
                })?;
                validate_fixed_ipv6_address(
                    profile,
                    &format!("user '{}' static_ipv6", user.username),
                    address,
                )?;
                if let Some(other) = ipv6_user_assignments.insert(address, user.username.as_str()) {
                    anyhow::bail!(
                        "profile '{}': users '{}' and '{}' both request static_ipv6 {}",
                        profile.name,
                        other,
                        user.username,
                        address
                    );
                }
                if let Some(owner) = ipv6_reservations.get(&address) {
                    if *owner != user.username {
                        anyhow::bail!(
                            "profile '{}': user '{}' static_ipv6 {} collides with pool.ipv6.reservation.{}",
                            profile.name, user.username, address, owner
                        );
                    }
                }
                if let Some(reserved) = profile.pool.ipv6.static_reservations.get(&user.username) {
                    if reserved.parse::<Ipv6Addr>().ok() != Some(address) {
                        anyhow::bail!(
                            "profile '{}': user '{}' has static_ipv6 {}, but pool.ipv6.reservation.{} is {} — the user value would silently override the profile reservation",
                            profile.name, user.username, address, user.username, reserved
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn available_memory_bytes() -> u64 {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(kib) = meminfo.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("MemAvailable:"))
                .then(|| fields.next()?.parse::<u64>().ok())
                .flatten()
        }) {
            return kib.saturating_mul(1024);
        }
    }
    // Conservative fallback when /proc is hidden by a container. `_SC_AVPHYS_PAGES` is
    // current free physical memory (less generous than MemAvailable, which includes cache).
    #[cfg(unix)]
    unsafe {
        let pages = libc::sysconf(libc::_SC_AVPHYS_PAGES);
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if pages > 0 && page_size > 0 {
            return (pages as u64).saturating_mul(page_size as u64);
        }
    }
    // Failing to observe memory must not accidentally authorize an unbounded configuration.
    512 * 1024 * 1024
}

fn server_udp_buffer_budget(
    config: &ServerConfig,
) -> anyhow::Result<crate::transport_core::udp_buffer::AggregateUdpBudgetPlan> {
    const ESTIMATED_OS_DEFAULT_KERNEL_BYTES: u64 = 512 * 1024;
    let automatic_queues = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, 256);
    let mut sockets = 0usize;
    let mut automatic_sockets = 0usize;
    let mut reserved_kernel_bytes = 0u64;
    for profile in config
        .profiles
        .iter()
        .filter(|profile| profile.enabled && profile.bind.transport.eq_ignore_ascii_case("udp"))
    {
        let queues = if profile.tun.queues == 0 {
            automatic_queues
        } else {
            profile.tun.queues.clamp(1, 256)
        };
        let listener_count = 1usize.saturating_add(profile.bind.listen.len());
        let count = queues.saturating_mul(listener_count);
        sockets = sockets.saturating_add(count);
        let perf = &profile.performance.udp;
        let send_kernel = if perf.send_buffer_size == 0 {
            ESTIMATED_OS_DEFAULT_KERNEL_BYTES
        } else {
            u64::from(perf.send_buffer_size).saturating_mul(2)
        };
        reserved_kernel_bytes =
            reserved_kernel_bytes.saturating_add(send_kernel.saturating_mul(count as u64));
        if perf.recv_buffer_auto && perf.recv_buffer_size > 0 {
            automatic_sockets = automatic_sockets.saturating_add(count);
        } else {
            let receive_kernel = if perf.recv_buffer_size == 0 {
                ESTIMATED_OS_DEFAULT_KERNEL_BYTES
            } else {
                u64::from(perf.recv_buffer_size).saturating_mul(2)
            };
            reserved_kernel_bytes =
                reserved_kernel_bytes.saturating_add(receive_kernel.saturating_mul(count as u64));
        }
    }
    crate::transport_core::udp_buffer::plan_aggregate_udp_budget(
        available_memory_bytes(),
        sockets,
        automatic_sockets,
        reserved_kernel_bytes,
    )
    .map_err(anyhow::Error::msg)
}

/// Data-plane worker: control socket + all VPN profiles. Runs as the child
/// process `qeli _worker`; the web panel lives in the supervisor (`run_supervisor`).
/// Load the users database the data plane authenticates against, from BOTH the
/// users file AND any inline `[user:*]` / `[group:*]` sections in the server
/// config.
///
/// The users file (written by the web panel and the `add-client` CLI) is the
/// authoritative dynamic store; inline entries are a static config convenience.
/// We take the UNION, with the **file taking precedence** for a duplicate
/// username / group. Without this, a config that carried inline users made every
/// panel / `add-client` change a silent no-op: the worker kept (re)loading the
/// inline copy and ignored the file the panel writes to, so edits never applied.
///
/// Returns `Err` whenever the users file EXISTS but cannot be loaded — corrupt, truncated,
/// unreadable, or carrying a value or key that will not parse. Inline entries do NOT excuse
/// that: serving a different access-control list than the one on disk, silently, is the worst
/// available outcome. Only a MISSING file falls back to the inline set, and only when there is
/// one; otherwise that is an error too.
///
/// (This used to say inline entries were a fallback for any load failure, which is what the
/// code did until the fix below — see the comment there. Audit 2026-08-02, §5.)
pub fn load_users_db(config: &ServerConfig) -> anyhow::Result<UsersDb> {
    let has_inline = !config.auth.users.is_empty() || !config.auth.groups.is_empty();
    let mut db = match UsersDb::load(&config.auth.users_file) {
        Ok(db) => db,
        Err(e) => {
            // A MISSING file is ordinary: a fresh install whose users all live inline, or a
            // server whose panel has not written one yet. Anything else — corrupt, truncated,
            // unreadable, a limit that will not parse — is refused even when inline entries
            // could cover for it.
            //
            // This used to fall through to an EMPTY database on any error whatsoever, without
            // so much as a log line, as long as one inline user existed. The server then came
            // up serving the inline set alone: every account, group, bandwidth cap and quota
            // in the file was gone, and the only visible symptom was users being unable to log
            // in — with a config that still listed them. Silently serving a DIFFERENT
            // access-control list than the one on disk is the worst available outcome here.
            // (Audit 2026-08-02, §5.)
            let missing = e
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
            if !missing {
                return Err(e.context(format!(
                    "users file '{}' exists but could not be loaded; refusing to run on a \
                     partial access-control list (inline [user:*] entries do NOT substitute \
                     for it)",
                    config.auth.users_file
                )));
            }
            if !has_inline {
                return Err(e);
            }
            log::info!(
                "users: no users file at '{}' — serving the inline [user:*] entries only",
                config.auth.users_file
            );
            UsersDb::default()
        }
    };
    if !has_inline {
        db.validate_group_references()?;
        validate_static_address_sources(config, &db)?;
        return Ok(db);
    }

    // Merge inline entries the file doesn't already define (file wins on a clash).
    let have: std::collections::HashSet<String> =
        db.users.iter().map(|u| u.username.clone()).collect();
    let mut shadowed = Vec::new();
    for u in &config.auth.users {
        if have.contains(&u.username) {
            shadowed.push(u.username.clone());
        } else {
            db.users.push(u.clone());
        }
    }
    for (name, g) in &config.auth.groups {
        db.groups.entry(name.clone()).or_insert_with(|| g.clone());
    }
    if !shadowed.is_empty() {
        log::warn!(
            "users: {} inline [user:*] entry(ies) also exist in the users file '{}'; \
             the FILE copy wins ({:?}) — remove them from the config to avoid confusion",
            shadowed.len(),
            config.auth.users_file,
            shadowed
        );
    }
    // Re-run the complete validator on the UNION. Each source was valid in isolation, but
    // conflicts can exist only after merging (for example the same static IPv6 on one file
    // user and one inline user). Group references are intentionally checked here: a file user
    // may reference a group supplied inline, but a name missing from the final union would
    // silently remove every inherited restriction.
    db.validate_network_fields()?;
    db.validate_group_references()?;
    validate_static_address_sources(config, &db)?;
    Ok(db)
}

/// Load the effective users database with the same first-run semantics used by the
/// data-plane: an actually missing external file and no inline entries means an empty
/// database, while every other load/parse/validation failure remains fatal.
///
/// Keeping this distinction in one place is important because the supervisor, worker,
/// SIGHUP path and web panel must authenticate/validate against the same union. In
/// particular, Path::exists() is not sufficient here: permission errors can also make
/// existence probes return false and must never be converted into an empty ACL.
pub fn load_users_db_for_runtime(config: &ServerConfig) -> anyhow::Result<UsersDb> {
    match load_users_db(config) {
        Ok(db) => Ok(db),
        Err(error)
            if config.auth.users.is_empty()
                && config.auth.groups.is_empty()
                && error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(UsersDb::default())
        }
        Err(error) => Err(error),
    }
}

/// Build and validate the exact external + inline users view used by the data-plane.
/// The external file wins on duplicate names, matching [`load_users_db`]. Callers use
/// this while holding the users-file sidecar lock so an invalid cross-file candidate is
/// rejected before it reaches disk.
pub fn effective_users_from_external(
    config: &ServerConfig,
    mut db: UsersDb,
) -> anyhow::Result<UsersDb> {
    let file_users: HashSet<String> = db.users.iter().map(|user| user.username.clone()).collect();
    for user in &config.auth.users {
        if !file_users.contains(&user.username) {
            db.users.push(user.clone());
        }
    }
    for (name, group) in &config.auth.groups {
        db.groups
            .entry(name.clone())
            .or_insert_with(|| group.clone());
    }
    db.validate_network_fields()?;
    db.validate_access_controls()?;
    db.validate_group_references()?;
    validate_static_address_sources(config, &db)?;
    Ok(db)
}

/// Refuse to start on config values that were PRESENT but not understood.
///
/// These fall back to a default, and the default is frequently the PERMISSIVE end of the
/// setting: `kill_switch = ture` reads as false and disables the kill switch, an unparseable
/// limit reads as 0 and means "no limit". So the running policy silently differs from the
/// written one, in the direction that removes protection, on the file the operator believes
/// describes their server.
///
/// This used to warn and continue. The argument for that was upgrade safety — refusing would
/// take a working server down over a long-standing typo — but it trades a loud failure the
/// operator sees immediately for a quiet one they may never see, and it left the start path
/// disagreeing with `check-config` and the reload path, which both refuse. A server that will
/// not start is a five-minute fix; a server that has been silently running without its kill
/// switch is not. (Audit 2026-08-02, §6.)
///
/// Operationally: the message names every offending key, and `qeli check-config` gives the
/// same list without touching the running service, so an upgrade can be checked before it is
/// applied.
fn reject_bad_config_values(bad: &[String]) -> anyhow::Result<()> {
    if bad.is_empty() {
        return Ok(());
    }
    for msg in bad {
        log::error!("config: {msg}");
    }
    anyhow::bail!(
        "{} config value(s) are present but unreadable, listed above. Each falls back to a \
         default that may be more permissive than what you wrote, so the server refuses to \
         start rather than enforce a policy you did not choose. Fix them, or run \
         `qeli check-config` to review.",
        bad.len()
    )
}

pub async fn run_worker(cfg_path: &str) -> anyhow::Result<()> {
    let config_content = std::fs::read_to_string(cfg_path)?;
    let (config, bad_values): (ServerConfig, Vec<String>) =
        crate::config::parse_server_config_reporting(&config_content)?;
    reject_bad_config_values(&bad_values)?;

    if config.profiles.is_empty() {
        anyhow::bail!("no profiles defined in server config");
    }
    if !config.profiles.iter().any(|p| p.enabled) {
        anyhow::bail!("all profiles are disabled (enabled = false) — enable at least one");
    }

    validate_profiles(&config)?;
    // Defence in depth for every worker entry path, including a hand-started `_worker` and a
    // config changed on disk behind the panel.  The API performs the same check before it
    // stops the current worker, but the worker must not trust that it was its only caller.
    preflight::run(&config)?;

    // A MISSING users file and an UNREADABLE one are not the same thing, and collapsing them
    // was doing real damage. Both landed here as "users file not found, creating empty" — so a
    // file that exists but has one bad line started the server with ZERO accounts: every
    // client refused, and the log said the file was absent. An absent file is the ordinary
    // first-run state (`add-client` creates it); a present-but-broken one is a configuration
    // error, and starting anyway means locking out everybody. The save path already draws this
    // exact distinction (`UsersDb::save`, "not overwriting it with an empty database") — the
    // load path did not. (Audit 2026-08-02, §5.)
    let users_file_missing = std::fs::metadata(&config.auth.users_file)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    let users_db = load_users_db_for_runtime(&config).map_err(|error| {
        anyhow::anyhow!(
            "users configuration using '{}' could not be loaded or validated: {error}. Refusing \
             to start with an empty user database — every client would be rejected. Fix the \
             file, or move it aside to start fresh.",
            config.auth.users_file
        )
    })?;
    if users_file_missing && config.auth.users.is_empty() && config.auth.groups.is_empty() {
        log::warn!(
            "users file '{}' does not exist yet — starting with an empty database (create \
             accounts with `qeli add-client`)",
            config.auth.users_file
        );
    }
    log::info!(
        "Loaded {} user(s) ({} inline in config, rest from '{}')",
        users_db.users.len(),
        config.auth.users.len(),
        config.auth.users_file
    );
    let udp_buffer_budget = server_udp_buffer_budget(&config)?;
    if udp_buffer_budget.socket_count > 0 {
        log::info!(
            "UDP aggregate buffer budget: {} MiB for {} socket(s), {} automatic; auto initial/max={} / {} KiB",
            udp_buffer_budget.budget_bytes / 1024 / 1024,
            udp_buffer_budget.socket_count,
            udp_buffer_budget.auto_socket_count,
            udp_buffer_budget.auto_initial_recv_bytes / 1024,
            udp_buffer_budget.auto_max_recv_bytes / 1024
        );
    }
    let users_db = Arc::new(RwLock::new(users_db));

    // Identity keys are per-profile now (loaded in run_profile), so there is no
    // single server-wide key here.
    // Worker (data plane) — governs VPN user authentication: `[auth] brute_force`.
    let bf_cfg = &config.auth.brute_force;
    let failed_auth = Arc::new(Mutex::new(FailedAuthTracker::new(
        bf_cfg.enabled,
        bf_cfg.max_attempts,
        bf_cfg.window_secs,
        bf_cfg.lockout_secs,
    )));

    let live_web = Arc::new(RwLock::new(config.web.clone()));
    let state = Arc::new(ServerState {
        config,
        users_db,
        config_path: Mutex::new(Some(cfg_path.to_string())),
        config_write_lock: Mutex::new(()),
        profiles: Arc::new(RwLock::new(HashMap::new())),
        profile_hook_env: Arc::new(Mutex::new(HashMap::new())),
        failed_auth,
        worker_tx: None,
        client_manager: Arc::new(client_manager::ClientManager::new()),
        metrics: Arc::new(metrics::MetricsState::new()),
        usage: Arc::new(usage::UsageStore::load(usage::USAGE_PATH)?),
        live_web,
        udp_buffer_budget,
    });

    // Control socket (shared across profiles) — the supervisor's panel reaches
    // live client data (list/kick/bandwidth) through this.
    let control_listener = control::bind_control_server()?;
    let (control_fatal_tx, mut control_fatal_rx) = mpsc::unbounded_channel::<String>();
    let ctrl_state = state.clone();
    let control_task = tokio::spawn(async move {
        let reason = match control::run_control_server(ctrl_state, control_listener).await {
            Ok(()) => "control server stopped unexpectedly".to_string(),
            Err(error) => format!("control server failed: {error}"),
        };
        let _ = control_fatal_tx.send(reason);
    });

    // (The web panel runs in the supervisor process, not here.)

    // Tier-2 usage sweep: accrue per-user traffic + enforce data caps / expiry.
    {
        let usage_state = state.clone();
        tokio::spawn(async move {
            usage_sweep(usage_state).await;
        });
    }

    // Clear any leaked NAT rules from a previous run whose profile has since been
    // REMOVED from the config (its per-profile cleanup never runs again). Active
    // profiles re-install their own rules in run_profile right below.
    nat::cleanup_all()?;

    // Profiles whose `post_down` has already run for their current lifecycle. A
    // profile supervisor clears its entry immediately before every restart, so an
    // aborted active generation is still paired by the worker's shutdown sweep.
    let post_down_done: Arc<Mutex<std::collections::HashSet<String>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    // Start one independent supervisor per profile. The JoinSet only watches for a
    // supervisor panic/return; ordinary profile failures are restarted in place.
    let (profile_shutdown_tx, profile_shutdown_rx) = tokio::sync::watch::channel(false);
    let mut profile_set = tokio::task::JoinSet::new();
    for pcfg in &state.config.profiles {
        if !pcfg.enabled {
            log::info!(
                "Profile '{}' is disabled (enabled = false) — not binding",
                pcfg.name
            );
            continue;
        }
        let state = state.clone();
        let pcfg = pcfg.clone();
        let post_down_done = post_down_done.clone();
        let mut profile_shutdown = profile_shutdown_rx.clone();
        profile_set.spawn(async move {
            let pname = pcfg.name.clone();
            let mut retry_secs = 1u64;
            loop {
                if *profile_shutdown.borrow() {
                    break;
                }
                post_down_done.lock().await.remove(&pname);
                let started = tokio::time::Instant::now();
                let result =
                    run_profile(state.clone(), pcfg.clone(), profile_shutdown.clone()).await;
                let stopping = *profile_shutdown.borrow();
                if !stopping {
                    match result {
                        Ok(()) => log::warn!("Profile '{}' stopped unexpectedly", pname),
                        Err(e) => log::error!("Profile '{}' error: {}", pname, e),
                    }
                }
                run_post_down(&state, &pname, &post_down_done).await;
                if stopping {
                    break;
                }

                // Reset the backoff after a stable generation; persistent setup
                // failures back off so they cannot spin and flood the journal.
                if started.elapsed() >= Duration::from_secs(30) {
                    retry_secs = 1;
                }
                log::warn!(
                    "Profile '{}' will restart in {}s; other profiles remain online",
                    pname,
                    retry_secs
                );
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(retry_secs)) => {}
                    _ = wait_for_profile_shutdown(&mut profile_shutdown) => break,
                }
                retry_secs = retry_secs.saturating_mul(2).min(30);
            }
        });
    }

    // Wait for all profiles. SIGINT (ctrl-c) and SIGTERM (how the supervisor and
    // systemd stop us) both shut down gracefully so we can tear down host NAT;
    // SIGUSR1 dumps the packet trace, when one is armed (no-op otherwise).
    tokio::spawn(crate::trace::watch());

    // SIGHUP hot-reloads users.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sighup = signal(SignalKind::hangup())
        .map_err(|e| anyhow::anyhow!("failed to install SIGHUP handler: {}", e))?;
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {}", e))?;

    let mut via_signal = false;
    let mut fatal_reason: Option<String> = None;
    loop {
        tokio::select! {
            joined = profile_set.join_next() => {
                let reason = match joined {
                    Some(Ok(())) => "a profile supervisor ended unexpectedly".to_string(),
                    Some(Err(e)) => format!("a profile supervisor failed: {e}"),
                    None => "no profile supervisors remain".to_string(),
                };
                log::error!("{reason}");
                fatal_reason = Some(reason);
                break;
            },
            control = control_fatal_rx.recv() => {
                let reason = control
                    .unwrap_or_else(|| "control server task disappeared".to_string());
                log::error!("{reason}");
                fatal_reason = Some(reason);
                break;
            },
            _ = tokio::signal::ctrl_c() => {
                log::info!("Received SIGINT, stopping server...");
                via_signal = true;
                break;
            }
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM, stopping server...");
                via_signal = true;
                break;
            }
            _ = sighup.recv() => {
                log::info!("SIGHUP received — reloading configuration");
                reload_on_sighup(&state).await;
            }
        }
    }

    // Ask every generation to leave through its normal async cleanup path. Aborting the
    // supervisors dropped `ProfileTeardown` synchronously and could remove TUN/NAT while
    // generation-owned tasks were still detached and using those resources.
    let _ = profile_shutdown_tx.send(true);
    while profile_set.join_next().await.is_some() {}
    control_task.abort();
    let _ = control_task.await;

    // Tear down the host NAT rules we installed (the next start also cleans stale
    // rules, so a SIGKILL that skips this is recovered then) and run post_down.
    for pcfg in &state.config.profiles {
        // Unconditional, not `if nat.enabled`. `routing.forward_private` installs rules
        // through `nat::enable_routing` under the SAME `qeli-nat:<profile>` tag — mangle
        // FORWARD TCPMSS plus filter FORWARD ACCEPT for the tun — and nothing removed
        // them on the way out, so `systemctl stop qeli` left ACCEPT rules behind on a host
        // with `FORWARD DROP`. They were only ever cleared by the NEXT start
        // (`cleanup_all`), which never comes if the profile is deleted from the config or
        // the service is disabled. `cleanup` deletes by exact tag and is a no-op when
        // there is nothing to delete, so running it always is strictly safer — it also
        // covers a profile whose NAT was toggled off while running.
        // (Audit 2026-07-27, B6.)
        nat::cleanup(&pcfg.name);
        // Skips any profile whose hook already ran when that profile ended on its own — the
        // interlock lives in `run_post_down`, so a shutdown racing a dying profile cannot fire
        // the hook twice.
        run_post_down(&state, &pcfg.name, &post_down_done).await;
    }

    log::info!("Server shutdown complete");
    // On a signal-driven stop, exit the process directly. The data plane spawns
    // blocking TUN reader threads; a graceful runtime drop joins them and would hang
    // (they block in read()), making `systemctl stop` time out and the unit go
    // "failed". The kernel reclaims the TUN devices / fds on exit, and NAT was already
    // torn down above.
    if via_signal {
        // Persist the last usage deltas before the hard exit: process::exit skips
        // UsageStore's Drop flush, so without this up to one sweep interval of traffic
        // per user is lost from the counters.
        if let Err(error) = state.usage.flush() {
            log::error!("usage: shutdown flush failed: {error}");
        }
        std::process::exit(0);
    }
    if let Some(reason) = fatal_reason {
        anyhow::bail!(reason);
    }
    Ok(())
}

/// Supervisor (`qeli server`): serves the web panel — the always-up control
/// plane — and runs the data-plane as a child process (`qeli _worker`). Applying
/// a config change restarts only the worker (clean OS teardown of TUN/sockets),
/// so the panel never goes down. Live client data is read over the control
/// socket; user edits write the users file and SIGHUP the worker to hot-reload.
/// Tier-2 usage sweep (worker). Every few seconds: fold each live session's byte
/// counters into the per-user lifetime total, persist the `usage.json` sidecar,
/// and disconnect any user over their data cap or past expiry. Runs off the data
/// path (O(sessions) per tick, reusing counters the data plane already maintains)
/// so it adds zero per-packet cost — tunnel throughput is unaffected.
async fn usage_sweep(state: Arc<ServerState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;

        // Per-user caps snapshot from the (hot-reloadable) users DB.
        let (limit_gb, expire): (HashMap<String, u64>, HashMap<String, Option<i64>>) = {
            let db = state.users_db.read().await;
            let mut l = HashMap::new();
            let mut e = HashMap::new();
            for u in &db.users {
                l.insert(u.username.clone(), u.data_limit_gb);
                e.insert(u.username.clone(), u.expire_at);
            }
            (l, e)
        };
        let now = usage::now_unix();

        let mut live: HashSet<u64> = HashSet::new();
        let mut to_kick: Vec<(String, std::net::IpAddr, u64)> = Vec::new();
        {
            let profiles = state.profiles.read().await;
            for (pname, profile) in profiles.iter() {
                let sessions = profile.sessions.read().await;
                for (ip, s) in sessions.by_ip.iter() {
                    // Fold download (server→client) and upload (client→server)
                    // separately; the cap is enforced on download only.
                    let down = s.bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
                    let up = s.bytes_recv.load(std::sync::atomic::Ordering::Relaxed);
                    state.usage.fold(s.session_id, &s.username, down, up);
                    live.insert(s.session_id);

                    let gb = limit_gb.get(&s.username).copied().unwrap_or(0);
                    let over = gb > 0
                        && state.usage.used_down(&s.username) >= gb.saturating_mul(1_000_000_000);
                    let expired = expire
                        .get(&s.username)
                        .copied()
                        .flatten()
                        .map(|x| now >= x)
                        .unwrap_or(false);
                    if over || expired {
                        // Notify (Tier-3) — throttled to once/hour per user so a
                        // client that keeps reconnecting over quota can't spam.
                        let key = format!("quota:{}", s.username);
                        let detail = format!(
                            "user '{}' on profile '{}' — {}",
                            s.username,
                            pname,
                            if over {
                                "over data quota"
                            } else {
                                "subscription expired"
                            }
                        );
                        tokio::spawn(async move {
                            notify::fire_throttled(&key, 3600, notify::Event::QuotaBreach, &detail)
                                .await;
                        });
                        to_kick.push((pname.clone(), *ip, s.session_id));
                    }
                }
            }
        }

        state.usage.prune(&live);
        if let Err(error) = state.usage.flush() {
            log::error!("usage: periodic flush failed: {error}");
        }

        for (pname, ip, session_id) in to_kick {
            let profile = { state.profiles.read().await.get(&pname).cloned() };
            if let Some(profile) = profile {
                // Quota/expiry removal and lease release must be one admission transaction.
                // Otherwise a reconnect can reclaim the same device_key lease after by_ip is
                // cleared but before the old teardown releases it, leaving the new live
                // session backed by an address the pool considers free.
                let _admission_guard = profile.admission.lock().await;
                let mut sessions = profile.sessions.write().await;
                // Guard on session_id: between the read-lock snapshot above and this
                // write lock the flagged session may have disconnected and a DIFFERENT
                // device reconnected onto the same pool IP. Only evict if it's still
                // the same session (mirrors the handler's own session-cleanup).
                let still_same = sessions
                    .by_ip
                    .get(&ip)
                    .map(|s| s.session_id == session_id)
                    .unwrap_or(false);
                if still_same {
                    if let Some(s) = sessions.remove(ip) {
                        let iroutes = sessions.take_client_routes(ip);
                        drop(sessions);
                        // Actually DISCONNECT the flagged session — signal its stream tasks
                        // to stop. Without kick_all it was only unlinked from by_ip: a live
                        // TCP reader kept forwarding uploads and refreshing liveness, so an
                        // over-quota / expired user was never cut off (and a UDP writer task
                        // leaked). This is the teardown, not just a bookkeeping removal.
                        //
                        // Until 0.7.12 this comment was only half true: kick_all signalled
                        // the WRITER, and the TCP reader kept going until the client chose
                        // to close the socket — right after the IP had been released back
                        // to the pool. kick_all now raises the per-stream shutdown watch,
                        // which both halves observe.
                        s.kick_all();
                        // Keep the kernel route transition inside admission as well. A
                        // detached delete could otherwise execute after a reconnect installed
                        // the same CIDR and tear down the new session's iroute.
                        for cidr in &iroutes {
                            let _ = crate::server::handler::program_client_subnet_route(
                                false,
                                cidr,
                                &profile.config.tun.name,
                            )
                            .await;
                        }
                        profile.pool.lock().await.release(&s.device_key);
                        log::info!(
                            "usage: disconnected '{}' on profile '{}' — over quota / expired",
                            crate::util::log_identity(&s.username),
                            pname
                        );
                        // Notify (opt-in): forced off for quota/expiry.
                        crate::server::notify::fire_disconnect(&s.username, &pname, s.peer);
                    }
                }
            }
        }
    }
}

pub async fn run_supervisor(cfg_path: &str) -> anyhow::Result<()> {
    // Validate the config parses and has at least one profile before starting.
    let config_content = std::fs::read_to_string(cfg_path)?;
    let (config, bad_values): (ServerConfig, Vec<String>) =
        crate::config::parse_server_config_reporting(&config_content)?;
    reject_bad_config_values(&bad_values)?;
    if config.profiles.is_empty() {
        anyhow::bail!("no profiles defined in server config");
    }

    // Pre-flight: refuse to start a config that would cut this box off the network
    // (e.g. a tunnel whose address IS the host's default gateway). Deliberately here,
    // in the SUPERVISOR and before the panel or the worker come up: by the time the
    // worker brings up a TUN the damage is done, and a failed worker under
    // Restart=on-failure would re-do it on every retry. Fails open when the host state
    // cannot be read — see the module docs.
    preflight::run(&config)?;

    // Users DB for the panel (display + create/update/delete). The worker holds
    // its own copy and hot-reloads it on SIGHUP after the panel edits the file.
    // Same union-load (file + inline, file wins) the worker uses, so the panel
    // shows exactly what the data plane authenticates against.
    // `?`, not `unwrap_or_default()`: swallowing the error showed the operator an EMPTY user
    // list in the panel and let them "fix" it by re-creating accounts — writing a fresh file
    // over the one that failed to load. The supervisor must fail the same way the worker
    // does. (Audit 2026-08-02, §5.)
    let users_db = Arc::new(RwLock::new(load_users_db_for_runtime(&config)?));

    // Supervisor (web panel) — governs admin-login brute-force: `[web] brute_force`,
    // a policy independent of the VPN-auth one the worker enforces above.
    let bf = &config.web.brute_force;
    let failed_auth = Arc::new(Mutex::new(FailedAuthTracker::new(
        bf.enabled,
        bf.max_attempts,
        bf.window_secs,
        bf.lockout_secs,
    )));

    let (worker_tx, mut worker_rx) = tokio::sync::mpsc::channel::<WorkerCmd>(8);

    let live_web = Arc::new(RwLock::new(config.web.clone()));
    let udp_buffer_budget = server_udp_buffer_budget(&config)?;
    let state = Arc::new(ServerState {
        config,
        users_db,
        config_path: Mutex::new(Some(cfg_path.to_string())),
        config_write_lock: Mutex::new(()),
        profiles: Arc::new(RwLock::new(HashMap::new())),
        profile_hook_env: Arc::new(Mutex::new(HashMap::new())),
        failed_auth,
        worker_tx: Some(worker_tx),
        client_manager: Arc::new(client_manager::ClientManager::new()),
        metrics: Arc::new(metrics::MetricsState::new()),
        // READ-ONLY on purpose: the worker owns this file. The supervisor only serves
        // /api/usage (which calls reload() first), and a writable handle here rolled the
        // file back to its startup snapshot via Drop on every clean shutdown. (K3)
        usage: Arc::new(usage::UsageStore::load_read_only(usage::USAGE_PATH)),
        live_web,
        udp_buffer_budget,
    });

    // Web panel — the always-up control plane.
    //
    // The outcome is AWAITED (briefly) rather than assumed. This used to be spawn-and-forget,
    // and the status line below then said "panel on" regardless — an operator was told the
    // control plane was up while the port refused connections. (Audit 2026-08-01, §P2.)
    let panel_state = if state.config.web.enabled {
        let web_state = state.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            web::start(web_state, Some(tx)).await;
        });
        // Bounded: a panel that has not reported either way within a few seconds is not
        // something to hold the whole worker on. Timing out reports the honest "unknown"
        // rather than inventing success.
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(true)) => "on",
            Ok(Ok(false)) | Ok(Err(_)) => "FAILED TO START",
            Err(_) => "starting (not confirmed)",
        }
    } else {
        log::warn!("web.enabled is false — the supervisor has no panel to serve");
        "off"
    };

    // Dashboard metrics sampler (host /proc + tunnel aggregate, 1 Hz). Only useful
    // with the panel up, so gate it on web.enabled like the panel itself.
    if state.config.web.enabled {
        let m = state.metrics.clone();
        // Exclude THIS server's tunnel interfaces from the WAN counters by name — a
        // profile whose tun.name is not vpn*/tun* used to be counted as WAN. (S4)
        let tun_names: Vec<String> = state
            .config
            .profiles
            .iter()
            .map(|p| p.tun.name.clone())
            .collect();
        tokio::spawn(async move {
            metrics::run_sampler(m, tun_names).await;
        });
    }

    // systemd: publish the running version as the `systemctl status` Status: line, so the
    // service "knows" and shows its version (needs NotifyAccess=main in the unit; no-op
    // otherwise). Also log it plainly so it lands in the journal regardless of systemd.
    // `panel_state` is what the panel ACTUALLY did, not what the config asked for. These two
    // lines are where an operator looks to see the service is healthy, and they used to print
    // "panel on" from `web.enabled` alone — a config field, which says nothing about whether
    // anything bound. (Audit 2026-08-01, §P2.)
    log::info!(
        "qeli v{} — control plane up ({} profile(s), panel {})",
        env!("CARGO_PKG_VERSION"),
        state.config.profiles.len(),
        panel_state
    );
    sd_notify(&format!(
        "STATUS=qeli v{} — {} profile(s), panel {}\n",
        env!("CARGO_PKG_VERSION"),
        state.config.profiles.len(),
        panel_state
    ));

    // Notify (Tier-3): announce that the control plane is up (no-op if disabled).
    tokio::spawn(async {
        notify::fire(
            notify::Event::ServerStart,
            &format!("qeli {} control plane is up", env!("CARGO_PKG_VERSION")),
        )
        .await;
    });

    // Auto-connect any client profiles flagged `autostart = true` (set in the panel's
    // Client tab or directly in the file). A client tunnel dials a REMOTE server, so it
    // is independent of the local worker — bring them up as soon as the supervisor is.
    {
        let cm = state.client_manager.clone();
        tokio::spawn(async move {
            cm.start_autostart().await;
        });
    }

    // Supervise the data-plane worker child process.
    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("cannot resolve current_exe for worker: {}", e))?;
    let spawn_worker = || {
        tokio::process::Command::new(&exe)
            .arg("_worker")
            .arg("-c")
            .arg(cfg_path)
            .kill_on_drop(true) // safety net: don't orphan the worker if we drop it
            .spawn()
    };

    // systemd stops/restarts us with SIGTERM (not SIGINT), so handle both — else
    // the worker child would be orphaned and clash with the next supervisor's worker.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to install SIGTERM handler: {}", e))?;

    let mut stopping = false;
    // Exponential backoff (capped) for a crash-looping worker, so a worker that
    // dies instantly on every start can't thrash iptables/TUN once per second.
    // Reset once an instance has run long enough to look healthy (see exit arm).
    let mut backoff_secs = 1u64;
    'supervise: loop {
        let mut child = match spawn_worker() {
            Ok(c) => c,
            Err(e) => {
                log::error!("supervisor: failed to spawn worker: {e} — retry in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue 'supervise;
            }
        };
        let pid = child.id().map(|p| p as i32).unwrap_or(0);
        state
            .metrics
            .worker_pid
            .store(pid, std::sync::atomic::Ordering::Relaxed);
        log::info!("supervisor: data-plane worker started (pid {pid})");
        let started = std::time::Instant::now();

        // Watch for the worker's exit without borrowing `child` in the select.
        let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = exit_tx.send(child.wait().await);
        });

        loop {
            tokio::select! {
                _ = &mut exit_rx => {
                    if stopping {
                        break 'supervise;
                    }
                    // A worker that ran long enough is healthy — reset the backoff so
                    // an ordinary restart doesn't inherit an escalated delay. A worker
                    // that died fast keeps escalating (capped) to avoid a respawn storm.
                    let ran = started.elapsed();
                    if ran >= Duration::from_secs(30) {
                        backoff_secs = 1;
                    }
                    log::warn!(
                        "supervisor: worker exited after {}s — respawning in {}s",
                        ran.as_secs(),
                        backoff_secs
                    );
                    // Sleep the backoff, but stay responsive to a stop signal. A worker
                    // that crash-loops — e.g. its bind port is already in use — would
                    // otherwise spend all its time in this non-interruptible sleep, so
                    // Ctrl+C / SIGTERM were never handled and the operator had to
                    // `kill -9` the supervisor (issue #69). The worker has already
                    // exited here, so a signal just tears the supervisor down cleanly.
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
                        _ = tokio::signal::ctrl_c() => {
                            log::info!("supervisor: SIGINT during worker backoff — stopping");
                            break 'supervise;
                        }
                        _ = sigterm.recv() => {
                            log::info!("supervisor: SIGTERM during worker backoff — stopping");
                            break 'supervise;
                        }
                    }
                    backoff_secs = (backoff_secs * 2).min(30);
                    continue 'supervise;
                }
                cmd = worker_rx.recv() => match cmd {
                    Some(WorkerCmd::Restart) => {
                        log::info!("supervisor: restarting worker (apply config)");
                        signal_pid(pid, libc::SIGTERM);
                        // The exit watcher will fire and respawn a fresh worker.
                    }
                    Some(WorkerCmd::ReloadUsers) => {
                        log::info!("supervisor: SIGHUP worker (reload users)");
                        signal_pid(pid, libc::SIGHUP); // same worker keeps running
                    }
                    None => {
                        stopping = true;
                        signal_pid(pid, libc::SIGTERM);
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    log::info!("supervisor: SIGINT — stopping worker");
                    stopping = true;
                    signal_pid(pid, libc::SIGTERM);
                }
                _ = sigterm.recv() => {
                    log::info!("supervisor: SIGTERM — stopping worker");
                    stopping = true;
                    signal_pid(pid, libc::SIGTERM);
                }
            }
        }
    }

    // Tear down any panel-managed outbound client tunnels (SIGTERM each so it
    // restores DNS/routes before exit).
    state.client_manager.shutdown_all().await;

    log::info!("Supervisor shutdown complete");
    Ok(())
}

/// Best-effort `kill(pid, sig)` — used by the supervisor to drive the worker.
fn signal_pid(pid: i32, sig: i32) {
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Handle SIGHUP: re-read the config file from disk and hot-reload everything
/// that can be swapped without dropping live tunnels — the users database and
/// the brute-force thresholds. Changes to profiles (bind/tun/transport) require
/// a full restart and are reported, not silently ignored.
async fn reload_on_sighup(state: &Arc<ServerState>) {
    let cfg_path = {
        let guard = state.config_path.lock().await;
        match guard.clone() {
            Some(p) => p,
            None => {
                log::warn!("SIGHUP: no config path recorded, cannot reload");
                return;
            }
        }
    };

    // Findings are FATAL here, unlike at startup — and the difference is not inconsistency,
    // it is what refusing costs. Aborting a start over a long-standing typo takes a working
    // server down on upgrade, so the boot path warns. A reload that refuses simply keeps the
    // configuration already running: nothing stops, nobody is disconnected, and the operator
    // gets a log line naming the key. There is no reason to apply a config we can see is
    // ambiguous when declining is free. (Audit 2026-08-01, §3.)
    let new_config: ServerConfig = match std::fs::read_to_string(&cfg_path)
        .map_err(|e| anyhow::anyhow!("{}", e))
        .and_then(|s| crate::config::parse_server_config_reporting(&s))
    {
        Ok((c, findings)) if findings.is_empty() => c,
        Ok((_, findings)) => {
            log::error!(
                "SIGHUP: refusing to apply '{}' — {} problem(s) whose defaults would be \
                 substituted silently; keeping the running config:\n  {}",
                cfg_path,
                findings.len(),
                findings.join("\n  ")
            );
            return;
        }
        Err(e) => {
            log::error!(
                "SIGHUP: failed to re-read config '{}': {} — keeping current config",
                cfg_path,
                e
            );
            return;
        }
    };

    // 1. Reload the users database (add/disable users, change routes/limits/
    //    allowed-profiles). Union of the users file (what the panel/add-client
    //    write) and inline [user:*], file wins — so a panel edit always applies
    //    even when the config also carries inline users.
    match load_users_db_for_runtime(&new_config) {
        Ok(db) => {
            let count = db.users.len();
            *state.users_db.write().await = db;
            log::info!("SIGHUP: reloaded users database ({} users)", count);
        }
        Err(e) => {
            log::error!(
                "SIGHUP: failed to reload users from '{}': {} — keeping current users",
                new_config.auth.users_file,
                e
            );
        }
    }

    // 2. Rebuild the brute-force tracker ONLY when the thresholds actually change.
    //    Rebuilding wipes every in-flight IP lockout, and the panel SIGHUPs the
    //    worker on ordinary user edits too — so an unconditional reset would let an
    //    attacker clear their own lockout by triggering/timing a reload. Preserve
    //    live lockouts when the policy is unchanged.
    let new_bf = &new_config.auth.brute_force;
    let want = (
        new_bf.enabled,
        new_bf.max_attempts,
        Duration::from_secs(new_bf.window_secs.min(MAX_BRUTE_FORCE_SECS)),
        Duration::from_secs(new_bf.lockout_secs.min(MAX_BRUTE_FORCE_SECS)),
    );
    {
        let mut tracker = state.failed_auth.lock().await;
        if tracker.thresholds() != want {
            *tracker = FailedAuthTracker::new(
                new_bf.enabled,
                new_bf.max_attempts,
                new_bf.window_secs,
                new_bf.lockout_secs,
            );
            log::info!(
                "SIGHUP: VPN-auth brute-force policy changed (enabled={}, max_attempts={}, window={}s, lockout={}s) — tracker reset",
                new_bf.enabled,
                new_bf.max_attempts,
                new_bf.window_secs,
                new_bf.lockout_secs
            );
        } else {
            log::info!("SIGHUP: brute-force thresholds unchanged — live lockouts preserved");
        }
    }

    // 3. Profile-level changes are not hot-reloadable (each owns a TUN device,
    //    socket and runtime task). Warn if the profile set changed on disk.
    let live: std::collections::HashSet<String> =
        state.profiles.read().await.keys().cloned().collect();
    let on_disk: std::collections::HashSet<String> =
        new_config.profiles.iter().map(|p| p.name.clone()).collect();
    if live != on_disk {
        log::warn!(
            "SIGHUP: profile set changed on disk (live: {:?}, config: {:?}) — \
            restart qeli to apply profile/bind/tun changes",
            live,
            on_disk
        );
    }
}

/// Validate one `listen` entry (#12): a bare `addr:port`. ALL listeners of a profile share
/// its `bind.transport` — there is no per-listener transport (a profile is one transport;
/// use a separate profile for the other). Returns the trimmed bind string, or `None` if it
/// isn't a single `addr:port` token (e.g. a stray transport word `addr:port udp`).
fn validate_listen_addr(spec: &str) -> Option<String> {
    let addr = spec.trim();
    if addr.is_empty() || addr.split_whitespace().count() != 1 || !addr.contains(':') {
        return None;
    }
    // "Contains a colon" is not a bind address. `host:99999`, `1.2.3.4:` and a bare IPv6
    // literal all passed that test, sailed through `check-config`, and only failed later at
    // bind time — where the error is never read (see the listener join below), so the port
    // simply did not exist while the server looked healthy. Parse it the same way the bind
    // itself will, and split host/port so a hostname (legitimate here, `SocketAddr` cannot
    // hold one) is still accepted with its port range checked.
    // (Audit 2026-07-29, #20.)
    match addr.parse::<std::net::SocketAddr>() {
        // Port 0 parses happily but asks the OS for an ephemeral port — a listener no client
        // could ever be told to reach. Never what a `listen` entry means.
        Ok(sa) if sa.port() != 0 => {}
        Ok(_) => return None,
        Err(_) => {
            // Not an IP literal: a hostname is legitimate here (`SocketAddr` cannot hold
            // one, it is resolved at bind time), so check the shape by hand.
            let (host, port) = addr.rsplit_once(':')?;
            // A bare IPv6 literal has several colons and must be bracketed to be
            // unambiguous; unbracketed, `rsplit_once` would slice the address itself.
            if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
                return None;
            }
            if host.is_empty() || !matches!(port.parse::<u16>(), Ok(p) if p != 0) {
                return None;
            }
        }
    }
    Some(addr.to_string())
}

#[cfg(test)]
mod listen_addr_tests {
    use super::validate_listen_addr;

    /// The join strategy for the listener tasks, in miniature.
    ///
    /// Awaiting `JoinHandle`s in ORDER is what hid a failed extra listener: an accept loop
    /// never returns, so the first `await` parked forever and no later task's error was ever
    /// read. This models exactly that shape — one task that never finishes plus one that fails
    /// immediately — and asserts the failure is observed. With the old sequential loop this
    /// test hangs instead of failing, which is the point: the bug was silence, not a wrong
    /// value. (Audit 2026-07-30, #6.)
    #[tokio::test]
    async fn a_failing_listener_is_observed_even_behind_an_endless_one() {
        let mut set = tokio::task::JoinSet::new();
        // Stands in for a healthy accept loop: runs until the process ends.
        set.spawn(async {
            std::future::pending::<()>().await;
            Ok::<(), std::io::Error>(())
        });
        // Stands in for `TcpListener::bind` failing on a port already in use.
        set.spawn(async {
            Err::<(), std::io::Error>(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "address already in use",
            ))
        });

        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), set.join_next())
            .await
            .expect("the failure must surface without waiting on the endless listener")
            .expect("the set is not empty");
        let err = joined.expect("the task itself did not panic").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);

        // The endless one is still running at this point — which is exactly why the profile
        // must NOT go on waiting for it. Surfacing the failure was only half the fix: the
        // caller used to loop until every listener had finished, so this survivor kept
        // `run_profile` parked forever, the teardown guard never ran, and the server counted a
        // profile as healthy while the endpoint its clients were handed refused connections.
        // The caller now aborts the survivors and fails the profile. (Audit 2026-08-01, §5.)
        assert_eq!(
            set.len(),
            1,
            "the healthy listener has not finished on its own"
        );
        set.abort_all();
        while tokio::time::timeout(std::time::Duration::from_secs(5), set.join_next())
            .await
            .expect("aborted listeners must be reaped promptly")
            .is_some()
        {}
        assert!(set.is_empty(), "abort_all must leave nothing running");
    }

    #[test]
    fn accepts_real_binds_and_rejects_what_cannot_bind() {
        for ok in [
            "0.0.0.0:443",
            "127.0.0.1:8080",
            "[::1]:443",
            "[2001:db8::5]:443",
            "vpn.example.com:443", // a hostname is resolved at bind time
        ] {
            assert!(validate_listen_addr(ok).is_some(), "{ok} must be accepted");
        }
        for bad in [
            "1.2.3.4:99999", // port out of range — used to pass check-config
            "1.2.3.4:0",     // port 0 asks the OS for a random one; never intended here
            "1.2.3.4:",
            "1.2.3.4:http", // not numeric
            "::1:443",      // unbracketed IPv6 — ambiguous
            "1.2.3.4",      // no port at all
            "",
            "1.2.3.4:443 udp", // stray transport word
        ] {
            assert!(
                validate_listen_addr(bad).is_none(),
                "{bad:?} must be rejected"
            );
        }
    }
}

/// Best-effort systemd `sd_notify`: send `msg` (e.g. `"STATUS=qeli v0.7.11 …"` or `"READY=1"`)
/// to `$NOTIFY_SOCKET`. Makes `systemctl status` show a live `Status:` line with the running
/// version. No-op when not under systemd (socket unset) or on non-Linux; the unit must set
/// `NotifyAccess=main` for systemd to accept it (STATUS works with `Type=simple` — no READY
/// handshake needed). Only pathname sockets (the system-service case, `/run/systemd/notify`)
/// are handled; an abstract `@…` socket is skipped.
#[cfg(target_os = "linux")]
fn sd_notify(msg: &str) {
    let sock_path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) if !p.is_empty() && !p.starts_with('@') => p,
        _ => return,
    };
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(msg.as_bytes(), &sock_path);
    }
}
#[cfg(not(target_os = "linux"))]
fn sd_notify(_msg: &str) {}

/// Wakes a thread parked in a blocking `read()` so it can notice a stop request.
///
/// The TUN queue readers block in `read()` with no timeout, which is exactly right for a data
/// plane — a poll/epoll round per packet would put a syscall on the hot path of a server that
/// moves hundreds of megabits. But it left them with no way to stop: the fds they hold keep a
/// non-persistent TUN device alive long after its profile is gone, and closing an fd another
/// thread is blocked in `read()` on is a use-after-free on the fd number.
///
/// A signal is the POSIX answer and it costs the hot path NOTHING. `read()` returns `EINTR`,
/// which the loop already handles (it was written to retry on it), so the only addition on the
/// packet path is one relaxed atomic load on a branch that essentially never runs.
///
/// The handler is a no-op and is installed WITHOUT `SA_RESTART` on purpose: with it, the kernel
/// silently restarts the interrupted `read()` and the thread never surfaces — which is the
/// default for `signal()` on Linux and would make this whole mechanism a no-op that looks
/// installed. SIGUSR1 is taken (it dumps the packet trace), so this uses SIGUSR2.
#[cfg(target_os = "linux")]
mod reader_wakeup {
    use std::sync::Once;

    pub const SIGNAL: libc::c_int = libc::SIGUSR2;

    extern "C" fn noop(_: libc::c_int) {}

    /// Install the no-op handler once per process.
    pub fn install() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = noop as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0; // NOT SA_RESTART — the point is for read() to return EINTR
            libc::sigaction(SIGNAL, &sa, std::ptr::null_mut());
        });
    }

    /// Interrupt one thread's blocking syscall. Safe to call on a thread that has already
    /// exited only while its handle is still held; callers pair this with the stop flag.
    pub fn interrupt(tid: libc::pthread_t) {
        unsafe {
            libc::pthread_kill(tid, SIGNAL);
        }
    }
}

/// The per-queue TUN threads, so teardown can stop them and their descriptors can close.
///
/// BOTH halves belong here. Readers alone are not enough: a queue's writer holds its own
/// `libc::dup` of the device fd and only closes it when its channel disconnects, so stopping
/// just the readers left the last descriptor open and the device survived anyway — the exact
/// leak this machinery exists to close.
///
/// `std::thread`, not `tokio::task::spawn_blocking`: these loops block for the entire life of
/// the profile, so they permanently occupy blocking-pool slots meant for short operations — and
/// more importantly a pooled thread is reused, so a signal arriving a moment after the closure
/// returned would land on an unrelated task. A dedicated thread is owned by exactly one loop
/// for exactly as long as that loop runs, which is what makes signalling it safe.
struct QueueThreads {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    /// One sender per inbound queue, used only to wake a writer parked in
    /// `blocking_recv()` after the stop flag is raised. A full queue is already a
    /// wake-up, so `try_send` is sufficient and cannot block teardown.
    wake_senders: Vec<mpsc::Sender<ServerTunPacket>>,
    /// Wakes a reader that is waiting for a pooled allocation rather than inside `read()`.
    pool_stop: tokio::sync::watch::Sender<bool>,
    /// Ids of the threads parked in a blocking syscall, published by each thread as it starts.
    /// Late registration is expected and handled — see `ProfileTeardown::drop`.
    #[cfg(target_os = "linux")]
    tids: Arc<std::sync::Mutex<Vec<libc::pthread_t>>>,
}

/// Every asynchronous task owned by one profile generation.
///
/// Dropping a Tokio `JoinHandle` detaches its task. Profiles restart in-process, so all
/// nested service/session tasks must instead be closed as one generation: shutdown rejects
/// new children, aborts the existing ones and joins them before system resources are removed.
#[derive(Clone)]
pub(crate) struct ProfileTasks {
    profile: Arc<str>,
    inner: Arc<std::sync::Mutex<ProfileTasksInner>>,
}

struct ProfileTasksInner {
    stopping: bool,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ProfileTasks {
    fn new(profile: &str) -> Self {
        Self {
            profile: Arc::from(profile),
            inner: Arc::new(std::sync::Mutex::new(ProfileTasksInner {
                stopping: false,
                handles: Vec::new(),
            })),
        }
    }

    pub(crate) fn spawn<F>(&self, future: F) -> bool
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if inner.stopping {
            return false;
        }
        // Completed tasks no longer own resources. Reap their handles so a busy DNS profile
        // does not retain one allocation for every query until the next restart.
        let mut index = 0;
        while index < inner.handles.len() {
            if inner.handles[index].is_finished() {
                inner.handles.swap_remove(index);
            } else {
                index += 1;
            }
        }
        inner.handles.push(tokio::spawn(future));
        true
    }

    fn abort_all(&self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.stopping = true;
        for handle in &inner.handles {
            handle.abort();
        }
    }

    async fn shutdown(&self) {
        let handles = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.stopping = true;
            for handle in &inner.handles {
                handle.abort();
            }
            std::mem::take(&mut inner.handles)
        };
        for handle in handles {
            if let Err(error) = handle.await {
                if !error.is_cancelled() {
                    log::error!(
                        "Profile '{}': child task failed during teardown: {}",
                        self.profile,
                        error
                    );
                }
            }
        }
    }
}

async fn wait_for_profile_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Undoes everything `run_profile` created on the host, however it leaves.
///
/// A profile start is a sequence of side effects on the SYSTEM — a TUN device, iptables rules,
/// a `post_up` hook, an entry in the shared registry — and it is only at the very end that the
/// listeners come up. Any failure after the first of those (a taken port, a bad DNS bind, a
/// pool that will not allocate) returned an error that the spawn site merely LOGGED, leaving
/// the device and the rules behind. In a multi-profile process a healthy sibling then keeps
/// the worker alive, so nothing tears them down until the whole server restarts — and the next
/// start finds a live interface it did not create.
///
/// Tearing down on the success path too is deliberate: `run_profile` only returns once the
/// profile has genuinely stopped serving, and a stopped profile should not keep a configured
/// interface. Every step is idempotent (`ip link delete` and `iptables -D` on something that
/// is already gone are no-ops), so overlapping with the shutdown-time `cleanup_all` is safe.
/// (Audit 2026-08-01, §5.)
struct ProfileTeardown {
    profile: String,
    /// The device as the KERNEL named it, set once the TUN exists.
    ifname: Option<String>,
    state: Arc<ServerState>,
    /// Set once the per-queue reader/writer threads are running, so they can be stopped before
    /// the device is removed — it only disappears when the last descriptor closes.
    readers: Option<QueueThreads>,
    /// Async descendants of this exact generation. The normal path awaits them before Drop;
    /// this synchronous abort is the panic/cancellation fallback.
    tasks: ProfileTasks,
    /// Exact INPUT-rule ownership survives a mixed native-nft chain that `iptables-nft -S`
    /// cannot enumerate. Clearing the leases deletes only this generation's DNS permits.
    dns_input_leases: Vec<nat::DnsInputLease>,
    /// Registry identity installed by this generation. Cleanup must not remove a replacement
    /// generation that registered under the same profile name.
    registered_profile: Option<Arc<ProfileRuntime>>,
}

impl ProfileTeardown {
    async fn unregister(&mut self) {
        let Some(expected) = self.registered_profile.clone() else {
            return;
        };
        let mut profiles = self.state.profiles.write().await;
        if profiles
            .get(&self.profile)
            .is_some_and(|current| Arc::ptr_eq(current, &expected))
        {
            profiles.remove(&self.profile);
        }
        // Clear only after the awaited removal completed. If this future is cancelled while
        // waiting for the lock, Drop still owns the identity and can run its guarded fallback.
        self.registered_profile = None;
    }
}

impl Drop for ProfileTeardown {
    fn drop(&mut self) {
        // Normal exits already awaited `shutdown`; this is essential for a cancelled or
        // panicking generation, whose wrapper cannot run async cleanup.
        self.tasks.abort_all();
        // Exact leases first; the generic tag sweep below cannot list every mixed nft chain.
        self.dns_input_leases.clear();

        // iptables first: the rules reference the interface by name, so removing them before
        // the device keeps the window where a rule points at a vanished device closed.
        nat::cleanup(&self.profile);

        // Stop the queue readers BEFORE removing the device.
        //
        // Two independent defects sat on top of each other here, and the first masked the
        // second. `TunInterface::delete` could not delete a MULTI-QUEUE device at all (missing
        // `multi_queue` on `ip tuntap del` → `ioctl(TUNSETIFF): Invalid argument`), which is
        // every device this server creates. With that fixed the command succeeds — and the
        // interface still survived, because each queue hands a `libc::dup` of its fd to a
        // reader parked in `read()` forever, and a device created without `IFF_PERSIST` only
        // disappears once the LAST descriptor closes. So the order below is not cosmetic: stop
        // the readers, let them close their own fds, and only then ask for the device.
        // (Audit 2026-08-01, §5.)
        if let Some(threads) = self.readers.take() {
            // Order matters: the flag goes up FIRST, so a thread that has not reached its
            // blocking call yet sees it on its own and never parks. The signal is only for the
            // ones already inside a syscall.
            threads
                .stop
                .store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = threads.pool_stop.send(true);
            for sender in &threads.wake_senders {
                let _ = sender.try_send(ServerTunPacket::Fragment(Vec::new()));
            }

            // Signalling is RETRIED rather than done once, and waiting is BOUNDED.
            //
            // A thread publishes its id from inside itself, so between `spawn` returning and
            // that push there is a window in which the id is not known yet. The first version
            // took a single `try_lock` and then joined unconditionally: a queue that failed
            // early — say a DNS bind error immediately after the threads were spawned — could
            // have a reader that never received a signal, never left `read()`, and a `join()`
            // that blocked FOREVER. In a Drop running on a tokio worker that wedges the
            // runtime thread: strictly worse than the leaked device this code is here to fix.
            //
            // Re-signalling every round closes the window (a late registrant is signalled on
            // the next pass), and the deadline means the worst case is a logged leak rather
            // than a hang.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                #[cfg(target_os = "linux")]
                {
                    // A poisoned lock still holds a usable list — a panicking thread must not
                    // cost us the ids of the healthy ones.
                    let tids = threads
                        .tids
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for tid in tids.iter() {
                        reader_wakeup::interrupt(*tid);
                    }
                }
                if threads.handles.iter().all(|h| h.is_finished()) {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    log::warn!(
                        "Profile '{}': {} TUN queue thread(s) did not stop within 3s — leaving \
                         them detached; the device will outlive the profile",
                        self.profile,
                        threads.handles.iter().filter(|h| !h.is_finished()).count()
                    );
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            // Join ONLY what has actually finished. Joining a still-running thread is the hang
            // this whole block exists to avoid; the finished ones are joined so their fds are
            // demonstrably closed before `ip tuntap del` runs, rather than merely scheduled to.
            for h in threads.handles {
                if h.is_finished() {
                    let _ = h.join();
                }
            }
        }

        if let Some(ifname) = &self.ifname {
            if let Err(e) = TunInterface::delete(ifname) {
                log::warn!(
                    "Profile '{}': could not remove TUN '{}' during teardown: {} — the device \
                     outlives the profile",
                    self.profile,
                    ifname,
                    e
                );
            }
        }
        // The normal path removes this entry synchronously before Drop. On panic/cancellation
        // fall back to an async removal, but only if the map still contains THIS generation.
        // An unconditional remove-by-name can erase a replacement generation after restart.
        if let Some(expected) = self.registered_profile.take() {
            let state = self.state.clone();
            let name = self.profile.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let mut profiles = state.profiles.write().await;
                    if profiles
                        .get(&name)
                        .is_some_and(|current| Arc::ptr_eq(current, &expected))
                    {
                        profiles.remove(&name);
                    }
                });
            }
        }
        log::info!("Profile '{}': torn down (TUN, NAT, registry)", self.profile);
    }
}

/// Run a profile's `post_down` hook exactly once, whoever gets there first.
///
/// Two things can end a profile — the profile's own task returning, and the worker shutting
/// down — and both must leave the hook run, but only once. The `done` set is the interlock;
/// it is checked and inserted under one lock so a shutdown racing a dying profile cannot run
/// the hook twice.
///
/// Honoured ONLY from a config the hook layer considers trusted, exactly like `post_up`: the
/// panel and the API never write these fields, and running a command out of an untrusted file
/// would be remote code execution.
async fn run_post_down(
    state: &Arc<ServerState>,
    profile: &str,
    done: &Arc<Mutex<std::collections::HashSet<String>>>,
) {
    let Some(pcfg) = state.config.profiles.iter().find(|p| p.name == profile) else {
        return;
    };
    // Take the generation snapshot even when no post_down command is configured, so a later
    // restart can never inherit the previous generation's auto-detected WAN.
    let hook_env = state.profile_hook_env.lock().await.remove(profile);
    if pcfg.routing.post_down.is_empty() {
        return;
    }
    {
        let mut d = done.lock().await;
        if !d.insert(profile.to_string()) {
            return; // already run for this profile
        }
    }
    let trusted = {
        let p = state.config_path.lock().await.clone();
        p.as_deref()
            .map(|p| crate::hooks::config_is_trusted(p).is_ok())
            .unwrap_or(false)
    };
    if !trusted {
        return;
    }
    let hook_env = hook_env.unwrap_or_else(|| ProfileHookEnv::fallback(pcfg));
    crate::hooks::run(
        &format!("post_down:{profile}"),
        &pcfg.routing.post_down,
        &hook_env.variables(),
    )
    .await;
}

async fn bind_tcp_listener(address: &str) -> std::io::Result<TcpListener> {
    let Ok(socket_address) = address.parse::<std::net::SocketAddr>() else {
        // Hostname binds retain Tokio's resolver behavior. The V6ONLY guarantee matters
        // for the wildcard numeric listener (`[::]`), which always takes this branch.
        return TcpListener::bind(address).await;
    };
    if socket_address.is_ipv4() {
        return TcpListener::bind(socket_address).await;
    }

    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&socket_address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

async fn run_profile(
    state: Arc<ServerState>,
    pcfg: ProfileConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = pcfg.name.clone();
    log::info!(
        "Starting profile '{}' ({}://{}:{})",
        name,
        pcfg.bind.transport,
        pcfg.bind.address,
        pcfg.bind.port
    );

    let tasks = ProfileTasks::new(&name);
    // Armed BEFORE the first side effect on the host. The wrapper deliberately owns this
    // guard while the generation body runs, so it can await every async child BEFORE Drop
    // removes the TUN/NAT resources those children use.
    let mut teardown = ProfileTeardown {
        profile: name.clone(),
        ifname: None,
        state: state.clone(),
        readers: None,
        tasks: tasks.clone(),
        dns_input_leases: Vec::new(),
        registered_profile: None,
    };

    let result =
        run_profile_generation(state, pcfg, &mut teardown, tasks.clone(), &mut shutdown).await;
    tasks.shutdown().await;
    teardown.unregister().await;
    drop(teardown);
    result
}

async fn run_profile_generation(
    state: Arc<ServerState>,
    pcfg: ProfileConfig,
    teardown: &mut ProfileTeardown,
    tasks: ProfileTasks,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let name = pcfg.name.clone();
    let mut service_set = tokio::task::JoinSet::new();

    // Setup TUN interface(s). With tun.queues>1 we open several IFF_MULTI_QUEUE fds
    // attached to ONE device; the kernel RSS-spreads packets across them so the data
    // plane reads/writes the interface — and runs the per-queue encrypt — on multiple
    // cores instead of funnelling everything through one reader/writer/forwarder.
    // Never delete a pre-existing device here: there is no ownership marker proving it is
    // ours, and qeli-created devices are non-persistent and disappear with their last fd.
    // It can therefore be another qeli process, another application, or an operator-owned
    // persistent TUN. Worse, create_multiqueue may ATTACH to an existing multi-queue device
    // instead of returning EEXIST and silently share its traffic. Refuse before TUNSETIFF.
    let tun_sysfs = format!("/sys/class/net/{}", pcfg.tun.name);
    if std::path::Path::new(&tun_sysfs).exists() {
        anyhow::bail!(
            "profile '{}': interface '{}' already exists — refusing to delete or attach to a \
             device whose ownership cannot be proved; stop its owner or choose another tun.name",
            name,
            pcfg.tun.name
        );
    }
    let dev_type = match pcfg.tun.device_type.to_lowercase().as_str() {
        "tap" => DeviceType::Tap,
        _ => DeviceType::Tun,
    };
    let nq = {
        let auto = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let n = if pcfg.tun.queues == 0 {
            auto
        } else {
            pcfg.tun.queues
        };
        // Ceiling = the kernel's tun multi-queue limit (MAX_TAP_QUEUES = 256); this
        // never reduces auto=nproc for real core counts. More queues than cores is
        // pointless (idle pollers), but explicit values are honoured up to the limit.
        n.clamp(1, 256)
    };
    let queues = TunInterface::create_multiqueue(&pcfg.tun.name, pcfg.tun.mtu, dev_type, nq)?;
    // The name the KERNEL gave the device, not the one we asked for. TUNSETIFF copies at most
    // IFNAMSIZ-1 = 15 bytes and writes back what it actually used; `create_multiqueue` has
    // always read that back, and this code then threw it away and kept configuring
    // `pcfg.tun.name` — so a longer name created a truncated device and every command below
    // failed against a device that does not exist. `validate_profiles` now rejects such a name
    // up front, but taking the kernel's answer is what makes the two agree by construction
    // rather than by a check that could drift. (Audit 2026-08-01, §4.)
    let ifname = queues
        .first()
        .map(|q| q.name.clone())
        .unwrap_or_else(|| pcfg.tun.name.clone());
    // The device exists from here on, so record it before the first fallible call below.
    teardown.ifname = Some(ifname.clone());
    if dev_type == DeviceType::Tap {
        TunInterface::set_mac(&ifname, TAP_GATEWAY_MAC)?;
    }
    let profile_subnet = if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
        Some(
            crate::config::server::pool_subnet(&pcfg.pool.cidr)
                .map_err(|e| anyhow::anyhow!("profile '{}': {}", name, e))?,
        )
    } else {
        None
    };
    let ipv6_subnet = crate::config::server::validate_ipv6_profile(&pcfg)
        .map_err(|error| anyhow::anyhow!("profile '{}': {}", name, error))?;
    if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
        TunInterface::set_address(
            &ifname,
            &pcfg.tun.address,
            profile_subnet
                .expect("IPv4/dual profile has a validated IPv4 subnet")
                .prefix,
        )?;
    }
    if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
        let address = pcfg
            .tun
            .ipv6_address
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("profile '{}': missing tun.ipv6_address", name))?;
        let prefix = ipv6_subnet
            .ok_or_else(|| anyhow::anyhow!("profile '{}': missing pool.ipv6.cidr", name))?
            .prefix;
        TunInterface::set_address(&ifname, address, prefix)?;
    }
    TunInterface::set_up(&ifname, pcfg.tun.mtu)?;
    TunInterface::set_queue_len(&ifname, pcfg.tun.tx_queue_len)?;
    log::info!(
        "Profile '{}': {} {} is up with {} queue(s) ({}/{})",
        name,
        if dev_type == DeviceType::Tap {
            "TAP"
        } else {
            "TUN"
        },
        ifname,
        queues.len(),
        if pcfg.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
            pcfg.tun.ipv6_address.as_deref().unwrap_or("<missing>")
        } else {
            &pcfg.tun.address
        },
        if pcfg.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
            ipv6_subnet.map(|subnet| subnet.prefix).unwrap_or(0)
        } else {
            profile_subnet
                .expect("IPv4/dual profile has a validated IPv4 subnet")
                .prefix
        }
    );

    // Host NAT (iptables) for full-tunnel egress. Always clear any rules we left
    // behind first (covers an unclean exit, or routing.nat toggled off then a
    // restart), then (re)install if this profile requests masquerading.
    nat::cleanup(&pcfg.name);
    let peer_tuns: Vec<String> = state
        .config
        .profiles
        .iter()
        .filter(|profile| profile.enabled && profile.name != pcfg.name)
        .map(|profile| profile.tun.name.trim().to_string())
        .collect();
    let mut wan_ipv4 = String::new();
    if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv6 && pcfg.routing.nat.enabled {
        match nat::setup(
            &pcfg.name,
            &pcfg.routing.nat.interface,
            &pcfg.pool.cidr,
            &ifname,
            &peer_tuns,
            pcfg.tun.mtu,
        ) {
            Ok(wan) => {
                log::info!(
                    "Profile '{}': NAT masquerade active via iptables ({} -> {})",
                    name,
                    pcfg.pool.cidr,
                    wan
                );
                wan_ipv4 = wan;
            }
            // Explicitly enabled and not applied is a REFUSAL, not a log line. Clients connect
            // happily and then find that full-tunnel traffic never reaches the internet, which
            // reads as a broken VPN rather than a missing iptables rule. The operator asked for
            // NAT; silently serving without it is answering a different question.
            // (Audit 2026-08-01.)
            Err(e) => anyhow::bail!(
                "profile '{}': routing.nat.enabled is set but NAT was NOT applied — {e}.                  Clients would connect and get no internet through the tunnel.",
                name
            ),
        }
    } else if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv6
        && pcfg.routing.forward_private
    {
        // No NAT, but pure L3 routing requested: enable forwarding (ip_forward + FORWARD
        // ACCEPT) WITHOUT masquerading, so transit traffic between the tunnel and the
        // server's networks keeps its real source IPs (site-to-site). NAT above already
        // does this, hence the else. Server-originated traffic to a client_subnet needs
        // only the route and works regardless (#13).
        // Fails the profile rather than logging: `forward_private` promises transit routing,
        // and a profile that cannot route it serves clients whose packets vanish.
        nat::enable_routing(&pcfg.name, &ifname, &peer_tuns, pcfg.tun.mtu)
            .map_err(|e| anyhow::anyhow!("profile '{}': {e}", pcfg.name))?;
    }
    let mut wan_ipv6 = String::new();
    if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
        if let Some(wan) = nat::setup_ipv6(
            &pcfg.name,
            pcfg.routing.ipv6.mode,
            &pcfg.routing.ipv6.interface,
            &pcfg.pool.ipv6.cidr,
            &ifname,
            &peer_tuns,
            pcfg.tun.mtu,
        )? {
            let target = if wan.is_empty() {
                "kernel routes (no IPv6 default uplink required)"
            } else {
                wan.as_str()
            };
            log::info!(
                "Profile '{}': IPv6 {} active ({} -> {})",
                name,
                pcfg.routing.ipv6.mode,
                pcfg.pool.ipv6.cidr,
                target
            );
            wan_ipv6 = wan;
        }
    }

    let hook_env = ProfileHookEnv::new(&pcfg, wan_ipv4, wan_ipv6);
    state
        .profile_hook_env
        .lock()
        .await
        .insert(name.clone(), hook_env.clone());

    // post_up hook: after this profile's TUN + NAT are up. Honoured ONLY from a
    // trusted config file (the panel/API never writes it — RCE guard).
    if !pcfg.routing.post_up.is_empty() {
        let cfg_path = { state.config_path.lock().await.clone() };
        match cfg_path.as_deref().map(crate::hooks::config_is_trusted) {
            Some(Ok(())) => {
                crate::hooks::run(
                    &format!("post_up:{name}"),
                    &pcfg.routing.post_up,
                    &hook_env.variables(),
                )
                .await;
            }
            Some(Err(why)) => log::error!("Profile '{name}': ignoring post_up — {why}"),
            None => log::error!("Profile '{name}': ignoring post_up — no config path recorded"),
        }
    }

    // One shared fixed-budget pool feeds every queue's TUN reader. Size each slot exactly as
    // the configured read buffer (the kernel writes directly into it), while retaining at
    // least one slot per queue even for an intentionally huge read buffer. Pool exhaustion
    // applies backpressure before the next read; it never allocates a fallback or drops a
    // packet already removed from the kernel.
    let tun_buf_size = pcfg.performance.tun.read_buffer_size;
    let tun_read_buffer_count = server_tun_read_buffer_count(queues.len(), tun_buf_size);
    let tun_read_pool = BufferPool::new(tun_read_buffer_count, tun_buf_size).map_err(|error| {
        anyhow::anyhow!(
            "profile '{name}': cannot allocate bounded TUN read pool ({tun_read_buffer_count} x {tun_buf_size} bytes): {error}"
        )
    })?;
    log::info!(
        "Profile '{}': bounded TUN read pool = {} buffers x {} bytes ({:.1} MiB)",
        name,
        tun_read_buffer_count,
        tun_buf_size,
        tun_read_buffer_count.saturating_mul(tun_buf_size) as f64 / (1024.0 * 1024.0)
    );
    let tun_write_buffer_capacity =
        crate::protocol::packet::TLS_RECORD_HEADER + crate::protocol::packet::MAX_RECORD_SIZE;
    let tun_write_buffer_count = (SERVER_TUN_WRITE_POOL_BYTES / tun_write_buffer_capacity)
        .max(queues.len())
        .max(1);
    let tun_write_pool = BufferPool::new(tun_write_buffer_count, tun_write_buffer_capacity)
        .map_err(|error| {
            anyhow::anyhow!(
                "profile '{name}': cannot allocate bounded TUN write pool ({tun_write_buffer_count} x {tun_write_buffer_capacity} bytes): {error}"
            )
        })?;
    log::info!(
        "Profile '{}': bounded TUN write pool = {} buffers x {} bytes ({:.1} MiB)",
        name,
        tun_write_buffer_count,
        tun_write_buffer_capacity,
        tun_write_buffer_count.saturating_mul(tun_write_buffer_capacity) as f64 / (1024.0 * 1024.0)
    );

    // Per-queue reader/writer fds (dup'd so the blocking reader and writer threads each
    // own a closable fd for their queue). Dropping `queues` after this keeps the device
    // alive via these dups (closed when the threads exit).
    let mut reader_fds: Vec<OwnedFd> = Vec::with_capacity(queues.len());
    let mut writer_fds: Vec<OwnedFd> = Vec::with_capacity(queues.len());
    for q in &queues {
        // Leave the fds BLOCKING: the reader thread sleeps inside read() until a
        // packet arrives (no 1ms busy-poll → 0% idle CPU even with many queues); the
        // writer blocks on a full TUN queue (backpressure, not silent drop).
        // F_DUPFD_CLOEXEC, not dup(2): dup CLEARS FD_CLOEXEC, so every one of these leaked
        // into the server's children — `iptables`/`ip6tables`, `ip`, and the operator's own
        // routing.post_up/post_down commands, which run as `/bin/sh -c <string>`. An
        // inherited TUN queue fd reads the plaintext traffic of EVERY client on the profile.
        // Same defect and same fix as the client side. (Audit 2026-08-04.)
        let rfd = unsafe { libc::fcntl(q.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if rfd < 0 {
            return Err(anyhow::anyhow!("failed to dup TUN queue fd"));
        }
        // SAFETY: fcntl returned a fresh descriptor owned by this function.
        let rfd = unsafe { OwnedFd::from_raw_fd(rfd) };
        let wfd = unsafe { libc::fcntl(q.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if wfd < 0 {
            // `rfd` and every descriptor already in the vectors close through RAII.
            return Err(anyhow::anyhow!("failed to dup TUN queue fd"));
        }
        // SAFETY: fcntl returned a fresh descriptor owned by this function.
        let wfd = unsafe { OwnedFd::from_raw_fd(wfd) };
        reader_fds.push(rfd);
        writer_fds.push(wfd);
    }
    drop(queues);

    // Inbound (client -> TUN): one channel per queue. handle_client gets a sharded
    // sender (sticky per connection) so a connection's packets stay ordered.
    let mut in_txs: Vec<mpsc::Sender<ServerTunPacket>> = Vec::with_capacity(reader_fds.len());
    let mut in_rxs: Vec<mpsc::Receiver<ServerTunPacket>> = Vec::with_capacity(reader_fds.len());
    for _ in 0..reader_fds.len() {
        let (tx, rx) = mpsc::channel::<ServerTunPacket>(4096);
        in_txs.push(tx);
        in_rxs.push(rx);
    }
    // Filled one-for-one with `in_txs` below. Listeners use the matching sender to bypass
    // the Linux routing table for session-to-session traffic (notably exit-node defaults)
    // while retaining the exact same downlink MTU, fragmentation and encryption path.
    let mut direct_out_txs: Vec<mpsc::Sender<ServerTunPacket>> =
        Vec::with_capacity(reader_fds.len());

    let tun_ipv6 = if pcfg.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
        Some(
            pcfg.tun
                .ipv6_address
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("profile '{}': missing tun.ipv6_address", name))?
                .parse::<std::net::Ipv6Addr>()
                .map_err(|error| {
                    anyhow::anyhow!("profile '{}': invalid tun.ipv6_address: {}", name, error)
                })?,
        )
    } else {
        None
    };
    let pool = if pcfg.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
        pool::IpPool::new_ipv6_only(
            &pcfg.pool.ipv6,
            tun_ipv6.expect("IPv6-only profile has a validated IPv6 TUN address"),
        )?
    } else {
        let tun_address: std::net::Ipv4Addr = pcfg
            .tun
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid tun.address: {}", name, e))?;
        let mut pool = pool::IpPool::new_with_tun(&pcfg.pool, tun_address)?;
        if let Some(tun_ipv6) = tun_ipv6 {
            pool.enable_ipv6(&pcfg.pool.ipv6, tun_ipv6)?;
        }
        pool
    };

    // Per-profile server identity (its own static key, bound to this interface).
    let static_keypair = Arc::new(load_or_generate_profile_key(&pcfg)?);
    let pub_hex: String = static_keypair
        .public
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    log::info!(
        "Profile '{}': server identity public key (pin on client): {}",
        name,
        pub_hex
    );

    // Build the REALITY real-TLS rustls config once (cert generation is not free).
    let reality_tls_config = if pcfg.obfuscation.tls.reality_proxy.enabled
        && pcfg.obfuscation.tls.reality_proxy.real_tls
    {
        log::info!(
            "Profile '{}': REALITY real-TLS termination enabled (SNI {})",
            name,
            pcfg.obfuscation.tls.reality_proxy.target
        );
        if !pcfg.obfuscation.tls.reality_proxy.handrolled {
            log::warn!(
                "Profile '{}': real-TLS via rustls — self-signed cert + rustls JA3S. Set \
                 obf.tls.reality_proxy.handrolled=true for cert-borrowing (real target cert \
                 chain) + JA3S mirroring (Xray-REALITY parity).",
                name
            );
        }
        Some(
            crate::protocol::realtls::server::make_server_config(
                &pcfg.obfuscation.tls.reality_proxy.target,
            )
            .map_err(|error| {
                anyhow::anyhow!("profile '{}': REALITY TLS setup failed: {error}", name)
            })?,
        )
    } else {
        None
    };

    // Probe the borrowed target's ServerHello once so the hand-rolled terminator
    // can mirror its shape (cipher, PQ group, extension order) — making the
    // ServerHello's JA3S match whatever `target` is set to, not just microsoft.
    let reality_borrow = if pcfg.obfuscation.tls.reality_proxy.enabled
        && pcfg.obfuscation.tls.reality_proxy.real_tls
        && pcfg.obfuscation.tls.reality_proxy.handrolled
    {
        let host = pcfg.obfuscation.tls.reality_proxy.target.clone();
        let port = pcfg.obfuscation.tls.reality_proxy.target_port;
        let probe = crate::protocol::realtls::server::probe_borrow_profile(&host, port);
        let dflt = crate::protocol::realtls::server::BorrowProfile::default();
        let (bp, cert) = match tokio::time::timeout(Duration::from_secs(8), probe).await {
            Ok(Ok((bp, cert))) => {
                log::info!(
                    "Profile '{}': borrowed TLS shape from {}:{} → {:?} (real cert chain: {})",
                    name,
                    host,
                    port,
                    bp,
                    if cert.is_some() {
                        "captured"
                    } else {
                        "unavailable → dummy"
                    }
                );
                (bp, cert)
            }
            Ok(Err(e)) => {
                log::warn!(
                    "Profile '{}': target probe {}:{} failed ({}); using default {:?}",
                    name,
                    host,
                    port,
                    e,
                    dflt
                );
                (dflt, None)
            }
            Err(_) => {
                log::warn!(
                    "Profile '{}': target probe {}:{} timed out; using default {:?}",
                    name,
                    host,
                    port,
                    dflt
                );
                (dflt, None)
            }
        };
        let state = Arc::new(std::sync::RwLock::new(
            crate::protocol::realtls::server::BorrowState { profile: bp, cert },
        ));
        // Periodic refresh so a long-running server tracks the target's TLS rotation.
        // Only the ServerHello *shape* (JA3S) is on the wire and matters for detection;
        // the borrowed cert rides inside the encrypted flight. Keep cached values if a
        // refresh probe fails (transient target unreachability must not blank the borrow).
        {
            let state = state.clone();
            let host = host.clone();
            let pname = name.clone();
            tasks.spawn(async move {
                const REFRESH: Duration = Duration::from_secs(12 * 3600);
                loop {
                    tokio::time::sleep(REFRESH).await;
                    let probe = crate::protocol::realtls::server::probe_borrow_profile(&host, port);
                    match tokio::time::timeout(Duration::from_secs(8), probe).await {
                        Ok(Ok((bp, cert))) => {
                            // Recover a poisoned lock rather than panicking, matching the
                            // reader in server/reality.rs (which documents exactly this).
                            // The two sides of one lock disagreed: a poisoned lock would
                            // kill the refresh task for good under panic=unwind, so the
                            // borrowed shape would silently freeze and JA3S would drift
                            // away from the live target while the server reported nothing.
                            // (Audit 2026-07-27, S6.)
                            let mut g = state.write().unwrap_or_else(|e| e.into_inner());
                            g.profile = bp;
                            if cert.is_some() {
                                g.cert = cert;
                            }
                            log::info!(
                                "Profile '{}': REALITY borrow refreshed (shape {:?}, cert {})",
                                pname,
                                g.profile,
                                if g.cert.is_some() { "present" } else { "none" }
                            );
                        }
                        _ => log::debug!(
                            "Profile '{}': REALITY borrow refresh failed; keeping cached",
                            pname
                        ),
                    }
                }
            });
        }
        Some(state)
    } else {
        None
    };

    let profile = Arc::new(ProfileRuntime {
        name: name.clone(),
        config: pcfg.clone(),
        tasks: tasks.clone(),
        pool: Arc::new(Mutex::new(pool)),
        sessions: Arc::new(RwLock::new(SessionMap {
            by_ip: HashMap::new(),
            by_address: HashMap::new(),
            by_token: HashMap::new(),
            client_routes: Vec::new(),
        })),
        #[cfg(feature = "experimental-roaming")]
        tcp_orphans: Arc::new(std::sync::Mutex::new(
            crate::transport_core::tcp_roaming::OrphanLimiter::new(
                pcfg.roaming.max_orphaned,
                pcfg.roaming.max_orphan_bytes,
            ),
        )),
        admission: Arc::new(Mutex::new(())),
        rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
            pcfg.performance.connection.new_session_rate_max,
            pcfg.performance.connection.new_session_rate_window_secs,
        ))),
        udp_buffer_counters: Arc::new(
            crate::transport_core::udp_buffer::UdpBufferCounters::default(),
        ),
        tcp_roaming_metrics: roaming_metrics::TcpRoamingMetrics::default(),
        #[cfg(feature = "experimental-roaming")]
        udp_roaming_registry: crate::transport_core::udp_roaming::UdpRoamingRegistry::new(
            (pcfg.performance.connection.max_clients as usize).max(1),
        ),
        static_keypair,
        reality_tls_config,
        reality_replay: Arc::new(Mutex::new(ReplayGuard::new(Duration::from_secs(
            2 * reality::REALITY_WINDOW_SECS,
        )))),
        reality_borrow,
    });

    // Register in shared profile registry
    state
        .profiles
        .write()
        .await
        .insert(name.clone(), profile.clone());
    teardown.registered_profile = Some(profile.clone());

    let is_tap = dev_type == DeviceType::Tap;
    let gateway_mac: [u8; 6] = if is_tap { TAP_GATEWAY_MAC } else { [0u8; 6] };
    let tap_server_ipv4 = is_tap
        .then(|| {
            profile
                .config
                .tun
                .address
                .parse::<std::net::Ipv4Addr>()
                .ok()
        })
        .flatten();
    let tap_server_ipv6 = is_tap
        .then(|| {
            profile
                .config
                .tun
                .ipv6_address
                .as_deref()
                .and_then(|address| address.parse::<std::net::Ipv6Addr>().ok())
        })
        .flatten();

    // Per-queue data-plane pump. Each queue gets: a blocking reader (TUN -> forwarder),
    // an async forwarder (lookup + ENCRYPT + send to client — encrypt now runs N-way in
    // parallel, serialized only per-session by the codec lock), and a blocking writer that
    // drains the bounded inbound channel directly into TUN. The kernel RSS-distributes
    // outbound TUN packets across the queues by flow.
    // Shared with `ProfileTeardown`: the flag the readers check when a signal interrupts their
    // `read()`, and the thread ids to send that signal to.
    #[cfg(target_os = "linux")]
    reader_wakeup::install();
    let reader_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (reader_pool_stop, _) = tokio::sync::watch::channel(false);
    #[cfg(target_os = "linux")]
    let reader_tids: Arc<std::sync::Mutex<Vec<libc::pthread_t>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    // Readers AND writers: both hold a descriptor that keeps the device alive.
    let mut queue_handles: Vec<std::thread::JoinHandle<()>> = Vec::new();
    // A failed `spawn` must not leave the threads already created unowned, so the error is
    // carried out of the loop and returned only AFTER the handles reach the teardown guard.
    // Returning it here with `?` was the leak: everything spawned so far became detached.
    let mut spawn_err: Option<anyhow::Error> = None;
    // A queue thread is part of the profile's health, not a detached best-effort
    // helper. Its fatal exit is delivered to the async owner so the teardown guard
    // dismantles this generation and the profile supervisor can rebuild it.
    let (tun_fatal_tx, mut tun_fatal_rx) = mpsc::channel::<String>(1);
    for (qi, ((reader_fd, writer_fd), mut in_rx)) in reader_fds
        .into_iter()
        .zip(writer_fds)
        .zip(in_rxs)
        .enumerate()
    {
        // Outbound: TUN[qi] -> forwarder -> client writer.
        let (out_tx, mut out_rx) = mpsc::channel::<ServerTunPacket>(4096);
        direct_out_txs.push(out_tx.clone());
        {
            let name_r = name.clone();
            let is_tap_reader = is_tap;
            let stop = reader_stop.clone();
            let pool = tun_read_pool.clone();
            let mut pool_stop = reader_pool_stop.subscribe();
            let fatal = tun_fatal_tx.clone();
            let runtime = tokio::runtime::Handle::current();
            let tap_sessions = profile.sessions.clone();
            #[cfg(target_os = "linux")]
            let tids = reader_tids.clone();
            // A DEDICATED thread, not `spawn_blocking`: this loop blocks for the whole life of
            // the profile, so it would hold a blocking-pool slot meant for short operations —
            // and a pooled thread gets reused, so the wake-up signal could land on an unrelated
            // task moments after this closure returned. One thread, one reader, one owner.
            let handle = std::thread::Builder::new()
                .name(format!("tun-rx-{name}-q{qi}"))
                .spawn(move || {
                    // Publish this thread's id so teardown can interrupt its `read()`.
                    #[cfg(target_os = "linux")]
                    {
                        if let Ok(mut t) = tids.lock() {
                            t.push(unsafe { libc::pthread_self() });
                        }
                    }
                    log::info!("TUN reader q{} for profile '{}' started", qi, name_r);
                    loop {
                        // BEFORE parking, not only after an interrupt. A teardown that happens
                        // while this thread is still starting up would otherwise find it about
                        // to block on a read that no signal had been aimed at yet — and then
                        // wait for a thread that never comes back. Checking here is what makes
                        // the shutdown independent of thread-start timing. One relaxed load per
                        // packet is the entire cost.
                        if stop.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        // The normal path is a lock-free semaphore try-acquire. Only actual
                        // downstream congestion enters the runtime to wait, and teardown has
                        // an explicit wake arm so a pool-starved reader cannot pin its fd.
                        let Some(mut packet) = pool.try_acquire().or_else(|| {
                            runtime.block_on(async {
                                tokio::select! {
                                    packet = pool.acquire() => packet,
                                    _ = pool_stop.changed() => None,
                                }
                            })
                        }) else {
                            break;
                        };
                        // ###################################################################
                        // PERFORMANCE-CRITICAL — do not "simplify" this back to `resize`.
                        //
                        // Rewriting these five lines as the obvious
                        //
                        //     let read_buffer = packet.as_vec_mut();
                        //     read_buffer.resize(tun_buf_size, 0);          // <- WAS THIS
                        //     let n = unsafe {
                        //         libc::read(reader_fd,
                        //                    read_buffer.as_mut_ptr() as *mut libc::c_void,
                        //                    read_buffer.len())
                        //     };
                        //     ...
                        //     packet.as_vec_mut().truncate(n as usize);     // <- AND THIS
                        //
                        // costs ~13% of DOWNLOAD throughput. That form shipped in 0.7.15 and
                        // was reverted here; if a future change ever needs to go back to it,
                        // the block above is the exact code to restore.
                        //
                        // Why it is so expensive: a pooled buffer returns with `len == 0`
                        // (PooledBuffer::drop clears it), so `resize` re-zeroes all 64 KiB
                        // (`perf.tun.read_buffer_size`) before a ~1.4 KiB packet lands in it —
                        // ~62k packets/s x 64 KiB is ~4 GB/s of stores that are immediately
                        // overwritten. 0.7.14 was fast because it kept ONE buffer outside the
                        // loop and never re-zeroed it.
                        //
                        // Measured, not guessed (scripts/ab_crossver_downlink.py,
                        // scripts/ab_memset_fix.py; raw data in release/ab_*.json):
                        //   S14/C14 721 | S14/C15 734 (+1.7%) | S15/C14 631 (-12.5%)
                        //     -> the regression follows the SERVER, the client is innocent
                        //   fixed vs 0.7.15: plain +10.9%, fake-tls +12.5%, obfs +18.2%
                        // A bigger downlink pool does NOT help (16 MiB gave -0.3%): the cost
                        // is the memset, not the queue depth.
                        //
                        // Read straight into the pooled allocation's SPARE capacity instead.
                        // `spare_capacity_mut` hands out the uninitialised tail; `read` writes
                        // the first `n` bytes and `set_len(n)` publishes exactly those, so no
                        // uninitialised byte is ever readable through the Vec.
                        // ###################################################################
                        let read_buffer = packet.as_vec_mut();
                        read_buffer.clear();
                        let spare = read_buffer.spare_capacity_mut();
                        let read_len = tun_buf_size.min(spare.len());
                        let n = unsafe {
                            libc::read(
                                reader_fd.as_raw_fd(),
                                spare.as_mut_ptr() as *mut libc::c_void,
                                read_len,
                            )
                        };
                        if n > 0 {
                            // SAFETY: `read` initialised exactly `n` bytes of the spare tail,
                            // and `n <= read_len <= capacity`.
                            unsafe { read_buffer.set_len(n as usize) };
                        }
                        if n < 0 {
                            let err = std::io::Error::last_os_error();
                            // Blocking read: only EINTR is retryable (the fd is no longer
                            // O_NONBLOCK, so WouldBlock can't happen).
                            if err.kind() == std::io::ErrorKind::Interrupted {
                                // ...unless the interruption WAS the stop request. This is the
                                // whole cost of the shutdown path on the packet hot path: one
                                // relaxed load, on a branch that essentially never runs.
                                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                                    break;
                                }
                                continue;
                            }
                            let _ = fatal.try_send(format!("TUN reader q{qi} failed: {err}"));
                            log::error!("TUN read error q{} on profile '{}': {}", qi, name_r, err);
                            break;
                        }
                        if n == 0 {
                            if !stop.load(std::sync::atomic::Ordering::Relaxed) {
                                let _ = fatal
                                    .try_send(format!("TUN reader q{qi} reached unexpected EOF"));
                            }
                            break;
                        }
                        // Length was published by `set_len(n)` right after the read, so the
                        // old `truncate(n as usize)` that stood here is a no-op — it is left
                        // out deliberately. Re-adding it is harmless on its own, but it only
                        // makes sense together with the `resize` form, which is the slow one
                        // (see the PERFORMANCE-CRITICAL block above before changing either).
                        debug_assert_eq!(packet.len(), n as usize);
                        if is_tap_reader {
                            if let Some(reply) = server_tap_control_reply(
                                &packet,
                                tap_server_ipv4,
                                tap_server_ipv6,
                                |target| {
                                    // A real bridge may ask about arbitrary LAN addresses.
                                    // Claim only an address or iroute currently owned by an
                                    // authenticated session; the old unconditional reply
                                    // poisoned neighbour caches outside qeli's authority.
                                    let Ok(sessions) = tap_sessions.try_read() else {
                                        return false;
                                    };
                                    sessions.get_by_address(target).is_some()
                                        || sessions.route_lookup(target).is_some()
                                },
                            ) {
                                let _ = unsafe {
                                    libc::write(
                                        reader_fd.as_raw_fd(),
                                        reply.as_ptr() as *const libc::c_void,
                                        reply.len(),
                                    )
                                };
                                continue;
                            }
                            let Some(ip_packet) = strip_ethernet_header(&packet) else {
                                continue;
                            };
                            let ip_offset = ip_packet.as_ptr() as usize - packet.as_ptr() as usize;
                            let ip_len = ip_packet.len();
                            let packet_buffer = packet.as_vec_mut();
                            packet_buffer.copy_within(ip_offset..ip_offset + ip_len, 0);
                            packet_buffer.truncate(ip_len);
                        }
                        if out_tx
                            .blocking_send(ServerTunPacket::Pooled(packet))
                            .is_err()
                        {
                            if !stop.load(std::sync::atomic::Ordering::Relaxed) {
                                let _ = fatal
                                    .try_send(format!("TUN reader q{qi} lost its async forwarder"));
                            }
                            break;
                        }
                    }
                    // OwnedFd closes on every thread exit path, including panic.
                    log::info!("TUN reader q{} for profile '{}' stopped", qi, name_r);
                });
            match handle {
                Ok(h) => queue_handles.push(h),
                Err(e) => {
                    spawn_err = Some(anyhow::anyhow!(
                        "profile '{name}': cannot spawn TUN reader q{qi}: {e}"
                    ));
                    break;
                }
            }
        }
        // Created before the outbound forwarder: ICMP "Fragmentation Needed" shares the
        // same bounded inbound queue as client packets and is consumed directly by the
        // dedicated TUN writer thread below.
        {
            let fwd_profile = profile.clone();
            let icmp_tx = in_txs[qi].clone();
            // The address our ICMP errors come from: this profile's TUN address, i.e. the
            // hop that could not forward. Parsed once — an unparseable address just disables
            // the signal rather than failing the profile.
            let icmp_router_ip = fwd_profile
                .config
                .tun
                .address
                .parse::<std::net::Ipv4Addr>()
                .ok();
            let icmpv6_router_ip = fwd_profile
                .config
                .tun
                .ipv6_address
                .as_deref()
                .and_then(|address| address.parse::<std::net::Ipv6Addr>().ok());
            tokio::spawn(async move {
                // Per-stream writers own recordization and encryption after this handoff.
                while let Some(packet) = out_rx.recv().await {
                    let meta = match crate::protocol::ip::parse_ip_packet(&packet) {
                        Ok(meta) => meta,
                        Err(_) => continue,
                    };
                    let dest_ip = meta.destination;
                    let sessions = fwd_profile.sessions.read().await;
                    // Exact pool-IP match first; then longest-prefix-match the client
                    // routes (iroute) so a packet to a client's extra address / LAN behind
                    // it is delivered into that client's tunnel, not dropped (#13).
                    if let Some(session) = sessions
                        .get_by_address(dest_ip)
                        .or_else(|| sessions.route_lookup(dest_ip))
                    {
                        // Client isolation: unless routing.client_to_client is enabled,
                        // drop packets whose SOURCE is ALSO a client tunnel IP (client
                        // A → client B). Internet return traffic (external source) is
                        // unaffected. This flag was previously parsed but never enforced,
                        // so clients could always reach each other regardless.
                        if !fwd_profile.config.routing.client_to_client {
                            let src_ip = meta.source;
                            // "Is the SOURCE a client?" has to be asked the same way the
                            // DESTINATION was resolved two lines up: pool address OR any
                            // subnet routed to a client (iroute).
                            //
                            // Checking only `by_ip` looked at the pool and stopped there,
                            // while `SrcGuard` deliberately lets a client send from any
                            // address inside its own `client_subnets` — the site-to-site
                            // case. So client A with `client_subnets = 192.168.50.0/24`
                            // could source a packet from 192.168.50.9 to client B's tunnel
                            // address: the uplink guard passed it (that source IS A's), the
                            // isolation check saw an address absent from `by_ip` and treated
                            // it as ordinary internet traffic, and B's reply routed straight
                            // back into A's tunnel via `route_lookup`. A full bidirectional
                            // channel with isolation switched ON. (Audit 2026-08-04.)
                            if sessions.get_by_address(src_ip).is_some()
                                || sessions.source_route_lookup(src_ip).is_some()
                            {
                                continue;
                            }
                        }
                        // Downlink path MTU (#13). The origin sized this packet against the
                        // path up to OUR TUN; it knows nothing about the leg from here to the
                        // client. When the client has told us its path is narrower, an
                        // oversized packet handed to the transport is dropped somewhere
                        // downstream and nobody is told — the black hole where a connection
                        // establishes and then stalls on the first big transfer.
                        //
                        // So behave like the router we are: answer the origin with ICMP
                        // Fragmentation Needed carrying the real next-hop MTU (RFC 1191) and
                        // drop the packet. PMTUD then converges and the flow continues at a
                        // size that fits. `downlink_mtu` returns None unless a client actually
                        // reported something narrower, so a pre-#13 client changes nothing.
                        // Set when an oversized non-DF packet was split instead of dropped;
                        // the send below then emits the pieces in place of the original.
                        let mut fragmented: Option<Vec<ServerTunPacket>> = None;
                        let session_mtu =
                            session.downlink_mtu(fwd_profile.config.tun.mtu, meta.version);
                        if let Some(mtu) = session_mtu {
                            if packet.len() > mtu as usize {
                                // Only DF packets get the error: without DF the origin is
                                // entitled to expect fragmentation instead, and answering
                                // anyway would be a lie about why it was dropped. Those are
                                // dropped as they already were — no regression, just visible.
                                if meta.version == crate::protocol::ip::IpVersion::V6 {
                                    if let Some(err) = icmpv6_router_ip.and_then(|ip| {
                                        crate::protocol::icmp::packet_too_big_v6(
                                            &packet,
                                            ip,
                                            u32::from(mtu),
                                        )
                                    }) {
                                        let _ = icmp_tx.try_send(ServerTunPacket::Fragment(err));
                                    }
                                } else if crate::protocol::icmp::has_df(&packet) {
                                    if let Some(err) = icmp_router_ip.and_then(|ip| {
                                        crate::protocol::icmp::frag_needed(&packet, ip, mtu)
                                    }) {
                                        // Best-effort, like every other TUN write here: a full
                                        // queue drops the notice rather than blocking the
                                        // forwarder for every other session.
                                        let _ = icmp_tx.try_send(ServerTunPacket::Fragment(err));
                                    }
                                } else if let Some(frags) =
                                    crate::protocol::icmp::fragment_ipv4(&packet, mtu as usize)
                                {
                                    // No DF: the sender is entitled to fragmentation rather than
                                    // an error, and qeli forwards in userspace so the kernel
                                    // never gets to do it. These used to be dropped with a debug
                                    // line — a black hole for exactly the traffic that said it
                                    // did not want one. Forward the pieces instead; the client's
                                    // stack reassembles them. (Audit 2026-07-30, #10.)
                                    fragmented = Some(
                                        frags.into_iter().map(ServerTunPacket::Fragment).collect(),
                                    );
                                } else {
                                    log::debug!(
                                        "downlink: dropped {} B non-DF packet for {} (path MTU {}) \
                                         — cannot fragment (options, or MTU too small)",
                                        packet.len(),
                                        dest_ip,
                                        mtu
                                    );
                                }
                                if fragmented.is_none() {
                                    session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    continue;
                                }
                            }
                        }
                        // Flow-pin each packet to one of the session's bonded streams
                        // (by inner 5-tuple) so a connection stays in order. Each stream
                        // carries its own crypto, so encrypt with the picked codec.
                        //
                        // The hash comes from the ORIGINAL datagram and is reused for each of
                        // its fragments: only the first fragment carries the L4 ports, so
                        // hashing the pieces separately would scatter one datagram across
                        // different bonded streams and deliver it out of order.
                        let flow = crate::protocol::flow_hash(&packet);
                        // Borrow the original packet as a one-element slice. The old
                        // `unwrap_or_else(|| vec![packet])` allocated a container Vec for every
                        // ordinary downlink packet even when fragmentation was not involved.
                        let packets = fragmented
                            .as_deref()
                            .unwrap_or_else(|| std::slice::from_ref(&packet));
                        for packet in packets {
                            if let Some((writer, wire_pool)) = session.pick_stream(flow) {
                                // The selected stream now owns recordization and AEAD. Queue
                                // bounded plaintext so boundaries can be changed without
                                // crossing bonded streams.
                                let Some(mut queued) = wire_pool.try_acquire() else {
                                    session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    continue;
                                };
                                if packet.len() > queued.capacity() {
                                    session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    continue;
                                }
                                queued.as_vec_mut().extend_from_slice(packet);
                                if writer.try_send(queued).is_err() {
                                    session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Inbound: client -> bounded in_rx -> TUN[qi]. The dedicated writer consumes the
        // Tokio receiver directly with `blocking_recv`: the former async bridge plus a
        // second 256-slot std channel dropped bursts between two otherwise healthy queues.
        {
            let name_w = name.clone();
            let is_tap_writer = is_tap;
            let gw_mac = gateway_mac;
            let stop_w = reader_stop.clone();
            let fatal_w = tun_fatal_tx.clone();
            #[cfg(target_os = "linux")]
            let tids_w = reader_tids.clone();
            let handle = std::thread::Builder::new()
                .name(format!("tun-tx-{name}-q{qi}"))
                .spawn(move || {
                    // Registered like the reader: a writer parked in `write()` needs the same
                    // interruption, and its fd keeps the device alive just as surely.
                    #[cfg(target_os = "linux")]
                    {
                        if let Ok(mut t) = tids_w.lock() {
                            t.push(unsafe { libc::pthread_self() });
                        }
                    }
                    log::info!("TUN writer q{} for profile '{}' started", qi, name_w);
                    // `ProfileTeardown` raises `stop_w` and try-sends one empty wake packet.
                    // If the queue is full the writer is already runnable; if it is empty the
                    // wake releases `blocking_recv`. This keeps teardown bounded without an
                    // idle polling timer or a second channel.
                    'writer: loop {
                        let packet = match in_rx.blocking_recv() {
                            Some(packet) => packet,
                            None => {
                                if !stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                                    let _ = fatal_w.try_send(format!(
                                        "TUN writer q{qi} lost all ingress senders"
                                    ));
                                }
                                break 'writer;
                            }
                        };
                        if stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                            break 'writer;
                        }
                        if packet.is_empty() {
                            continue;
                        }
                        // TAP prepends an Ethernet header (dst = gateway_mac; src = a MAC
                        // derived from the client src-IP for ARP attribution); TUN writes the
                        // raw IP packet as-is.
                        let tap_frame = if is_tap_writer {
                            let meta = match crate::protocol::ip::parse_ip_packet(&packet) {
                                Ok(meta) => meta,
                                Err(error) => {
                                    // A TAP fd accepts complete Ethernet frames only. Never
                                    // fall back to writing an invalid raw L3 packet here: that
                                    // silently turns a malformed ingress record into a TAP
                                    // data-plane black hole.
                                    log::debug!(
                                        "TUN writer q{} '{}': dropped packet that cannot be \
                                         encapsulated for TAP: {}",
                                        qi,
                                        name_w,
                                        error
                                    );
                                    continue 'writer;
                                }
                            };
                            let src_ip_mac = mac_from_ip(meta.source);
                            let Some(frame) =
                                prepend_ethernet_header(&packet, &gw_mac, &src_ip_mac)
                            else {
                                log::debug!(
                                    "TUN writer q{} '{}': dropped packet with no TAP ethertype",
                                    qi,
                                    name_w
                                );
                                continue 'writer;
                            };
                            frame
                        } else {
                            Vec::new()
                        };
                        let buf: &[u8] = if is_tap_writer { &tap_frame } else { &packet };
                        loop {
                            let n = unsafe {
                                libc::write(
                                    writer_fd.as_raw_fd(),
                                    buf.as_ptr() as *const libc::c_void,
                                    buf.len(),
                                )
                            };
                            if n == buf.len() as isize {
                                break;
                            }
                            if n >= 0 {
                                let message = format!(
                                    "TUN writer q{qi} performed a partial packet write ({n}/{})",
                                    buf.len()
                                );
                                log::warn!("{message} — stopping the writer");
                                let _ = fatal_w.try_send(message);
                                break 'writer;
                            }
                            let err = std::io::Error::last_os_error();
                            match err.raw_os_error() {
                                // Interrupted — retry the same buffer, UNLESS the interruption was
                                // the teardown signal aimed at exactly this case.
                                Some(libc::EINTR) => {
                                    if stop_w.load(std::sync::atomic::Ordering::Relaxed) {
                                        break 'writer;
                                    }
                                    continue;
                                }
                                // NB: on Linux EAGAIN == EWOULDBLOCK (same value) — listing one.
                                Some(libc::ENOBUFS) | Some(libc::EAGAIN) => {
                                    // TX queue full — drop this packet like a congested link.
                                    log::debug!(
                                        "TUN writer q{} '{}': dropped packet ({})",
                                        qi,
                                        name_w,
                                        err
                                    );
                                    break;
                                }
                                _ => {
                                    // Bad fd / device gone — stop the writer rather than silently
                                    // discarding every future packet on a dead descriptor.
                                    log::warn!(
                                        "TUN writer q{} '{}': fatal write error ({}) — stopping",
                                        qi,
                                        name_w,
                                        err
                                    );
                                    let _ =
                                        fatal_w.try_send(format!("TUN writer q{qi} failed: {err}"));
                                    break 'writer;
                                }
                            }
                        }
                    }
                    // OwnedFd closes on every thread exit path, including panic.
                    log::info!("TUN writer q{} for profile '{}' stopped", qi, name_w);
                });
            match handle {
                Ok(h) => queue_handles.push(h),
                Err(e) => {
                    spawn_err = Some(anyhow::anyhow!(
                        "profile '{name}': cannot spawn TUN writer q{qi}: {e}"
                    ));
                    break;
                }
            }
        }
    }

    // Hand the readers to the teardown guard, which from here on owns stopping them. Done
    // right after the loop so every path below — including a `?` out of the DNS bind — goes
    // through it.
    teardown.readers = Some(QueueThreads {
        stop: reader_stop,
        handles: queue_handles,
        wake_senders: in_txs.clone(),
        pool_stop: reader_pool_stop,
        #[cfg(target_os = "linux")]
        tids: reader_tids,
    });
    // Only NOW may a spawn failure propagate: the guard owns every thread that did start, so
    // the `?` below tears them down instead of orphaning them.
    if let Some(e) = spawn_err {
        return Err(e);
    }

    // DNS proxy (per-profile)
    if pcfg.dns.enabled {
        let mut primary_dns_cfg = pcfg.dns.clone();
        let primary_dns_pool = if pcfg.tun.ip_mode == crate::config::server::IpMode::Ipv6 {
            primary_dns_cfg.listen =
                pcfg.dns.listen_ipv6.clone().ok_or_else(|| {
                    anyhow::anyhow!("profile '{}': missing dns.listen_ipv6", name)
                })?;
            pcfg.pool.ipv6.cidr.as_str()
        } else {
            pcfg.pool.cidr.as_str()
        };
        // A resolver bound to the profile TUN address is local server traffic: packets hit
        // filter/INPUT, not FORWARD. Install a narrowly scoped permit before advertising the
        // resolver so hosts with INPUT DROP cannot create a connected-but-DNS-dead tunnel.
        let primary_dns_input = nat::enable_dns_input(
            &name,
            &ifname,
            primary_dns_pool,
            &primary_dns_cfg.listen,
            primary_dns_cfg.port,
        )
        .map_err(|error| anyhow::anyhow!("profile '{}': {error}", name))?;
        teardown.dns_input_leases.push(primary_dns_input);

        // Bridge 53 -> dns.port inside the tunnel when the proxy listens somewhere else, so
        // clients can keep using the only port their platform can express. No-op on 53.
        //
        // The result is CHECKED. Ignoring it defeated the point of returning it: without the
        // rule, clients reach 53 and nothing is there, yet the profile came up and kept
        // handing them that address as their resolver — the exact silent black hole the
        // redirect exists to prevent. Validation already demands iptables for a non-default
        // port, so a failure here means the rule was genuinely refused; fail the profile
        // rather than serve DNS that cannot work. (Audit 2026-08-01, §2.)
        if !nat::enable_dns_redirect(
            &name,
            &ifname,
            &primary_dns_cfg.listen,
            primary_dns_cfg.port,
        ) {
            anyhow::bail!(
                "profile '{}': dns.port = {} but the 53 -> {} redirect could not be installed,                  so every client would be pushed a resolver it cannot reach. Fix iptables, or                  set dns.port = 53.",
                name,
                pcfg.dns.port,
                pcfg.dns.port
            );
        }

        let dns_state = state.clone();
        let dns_cfg = primary_dns_cfg.clone();
        let name_dns = name.clone();
        let dns_listen = crate::util::join_host_port(&primary_dns_cfg.listen, primary_dns_cfg.port);
        // BIND FIRST, before the profile is allowed to advertise this resolver. The bind used
        // to live inside the detached task below, so a taken port surfaced as a log line while
        // the tunnel came up and pushed clients an address nothing was listening on — the
        // commonest trigger being a host resolver on `0.0.0.0:53`, which covers the TUN address
        // too. Failing the profile here is the difference between "DNS is misconfigured, and it
        // says so" and "the internet is broken for every client, silently".
        // (Audit 2026-08-01, §4.)
        let dns_socket = match dns::bind_dns_proxy(&primary_dns_cfg).await {
            Ok(s) => s,
            Err(e) => anyhow::bail!(
                "profile '{}': {e}. Clients of this profile would be pushed {} as their                  resolver and get NO name resolution. Free the port (`ss -lunp | grep ':53 '`)                  or set a different dns.port — the tunnel bridges 53 to it automatically.",
                name,
                dns_listen
            ),
        };
        // The TCP half, bound with the same fail-early treatment. RFC 7766 requires a resolver
        // to serve TCP, and it is where a client goes after a truncated UDP answer — so a
        // missing listener is not a degraded mode, it is a resolver that cannot answer anything
        // large. (Audit 2026-08-01, §10.)
        let dns_tcp = match dns::bind_dns_proxy_tcp(&primary_dns_cfg).await {
            Ok(l) => l,
            Err(e) => anyhow::bail!(
                "profile '{}': {e}. Clients that receive a truncated answer retry over TCP \
                 (RFC 7766), so without this listener every oversized lookup fails. Free the \
                 port (`ss -ltnp | grep ':{}'`) or set a different dns.port.",
                name,
                pcfg.dns.port
            ),
        };
        // ONE cache, blocklist and upstream-preference shared by both transports AND both
        // listener families: duplicate state doubles upstream traffic and lets the same name
        // answer differently depending on whether the client reached the IPv4 or IPv6 listener.
        let dns_cache: dns::DnsCache = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let dns_pref = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dns_blocklist = dns::compile_blocklist(&pcfg.dns.blocklist);
        {
            let cfg_tcp = primary_dns_cfg.clone();
            let cache_tcp = dns_cache.clone();
            let pref_tcp = dns_pref.clone();
            let blocklist_tcp = dns_blocklist.clone();
            let dns_tasks = tasks.clone();
            let label = format!("profile '{name}' DNS proxy (TCP)");
            service_set.spawn(async move {
                dns::run_dns_proxy_tcp(
                    cfg_tcp,
                    dns_tcp,
                    cache_tcp,
                    pref_tcp,
                    blocklist_tcp,
                    dns_tasks,
                )
                .await
                .map_err(|error| anyhow::anyhow!("{label} failed: {error}"))
            });
        }
        let dns_tasks = tasks.clone();
        let label = format!("profile '{name_dns}' DNS proxy (UDP) on {dns_listen}");
        let cache_udp = dns_cache.clone();
        let pref_udp = dns_pref.clone();
        let blocklist_udp = dns_blocklist.clone();
        service_set.spawn(async move {
            dns::run_dns_proxy(
                dns_state,
                dns_cfg,
                dns_socket,
                cache_udp,
                pref_udp,
                blocklist_udp,
                dns_tasks,
            )
            .await
            .map_err(|error| anyhow::anyhow!("{label} failed: {error}"))
        });
        if pcfg.tun.ip_mode == crate::config::server::IpMode::Dual {
            let listen_ipv6 =
                pcfg.dns.listen_ipv6.clone().ok_or_else(|| {
                    anyhow::anyhow!("profile '{}': missing dns.listen_ipv6", name)
                })?;
            let ipv6_dns_input = nat::enable_dns_input(
                &name,
                &ifname,
                &pcfg.pool.ipv6.cidr,
                &listen_ipv6,
                pcfg.dns.port,
            )?;
            teardown.dns_input_leases.push(ipv6_dns_input);
            if !nat::enable_dns_redirect(&name, &ifname, &listen_ipv6, pcfg.dns.port) {
                anyhow::bail!(
                    "profile '{}': IPv6 DNS redirect on {} could not be installed",
                    name,
                    listen_ipv6
                );
            }
            let mut ipv6_dns_cfg = pcfg.dns.clone();
            ipv6_dns_cfg.listen = listen_ipv6.clone();
            let udp = dns::bind_dns_proxy(&ipv6_dns_cfg).await?;
            let tcp = dns::bind_dns_proxy_tcp(&ipv6_dns_cfg).await?;
            {
                let cfg = ipv6_dns_cfg.clone();
                let cache = dns_cache.clone();
                let preference = dns_pref.clone();
                let blocklist = dns_blocklist.clone();
                let dns_tasks = tasks.clone();
                let label = format!("profile '{name}' IPv6 DNS proxy (TCP)");
                service_set.spawn(async move {
                    dns::run_dns_proxy_tcp(cfg, tcp, cache, preference, blocklist, dns_tasks)
                        .await
                        .map_err(|error| anyhow::anyhow!("{label} failed: {error}"))
                });
            }
            let dns_state = state.clone();
            let dns_tasks = tasks.clone();
            let label = format!("profile '{name}' IPv6 DNS proxy (UDP) on {listen_ipv6}");
            service_set.spawn(async move {
                dns::run_dns_proxy(
                    dns_state,
                    ipv6_dns_cfg,
                    udp,
                    dns_cache,
                    dns_pref,
                    dns_blocklist,
                    dns_tasks,
                )
                .await
                .map_err(|error| anyhow::anyhow!("{label} failed: {error}"))
            });
        }
    }

    // DHCP server (per-profile)
    if pcfg.dhcp.enabled {
        // Same helper `validate_profiles` uses, so the runtime cannot resolve a different
        // pool than the one that was validated. (Audit 2026-07-27, C9.)
        let server_ip: std::net::Ipv4Addr = pcfg
            .tun
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("profile '{}': invalid tun.address: {}", name, e))?;
        let (pool_start, pool_end) =
            crate::config::server::dhcp_pool_bounds(&pcfg.dhcp, &pcfg.pool.cidr, server_ip)
                .map_err(|e| anyhow::anyhow!("profile '{}': {}", name, e))?;
        let subnet_mask = profile_subnet
            .expect("DHCPv4 is rejected for IPv6-only profiles")
            .netmask;
        let dhcp_dns: Vec<std::net::Ipv4Addr> = if pcfg.dns.enabled {
            vec![server_ip]
        } else {
            vec![
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(8, 8, 8, 8),
            ]
        };
        let dhcp_listen = dhcp_bind_spec(&pcfg);

        let dhcp_server = Arc::new(dhcp::DhcpServer::new(
            server_ip,
            subnet_mask,
            server_ip,
            dhcp_dns,
            pcfg.dhcp.domain_name.clone(),
            pcfg.dhcp.lease_time_secs,
            pool_start,
            pool_end,
            profile.pool.clone(),
        ));
        // BIND FIRST, before the profile is allowed to claim it serves DHCP. This used to be
        // spawn-and-forget with the bind inside the task, so a taken port, a bad address or a
        // refused `set_broadcast` left the profile "running" while every client connected and
        // never got a lease — the cause a single ERROR line in the journal. Same treatment as
        // the DNS proxy. (Audit 2026-08-01, §2.)
        let dhcp_socket = match dhcp::DhcpServer::bind(&dhcp_listen).await {
            Ok(s) => s,
            Err(e) => anyhow::bail!(
                "profile '{}': {e}. Clients of this profile would get no lease at all. Free the \
                 port (`ss -lunp | grep ':67 '`) or set dhcp.enabled = false.",
                name
            ),
        };
        log::info!(
            "DHCP server for profile '{}' starting on {}",
            name,
            dhcp_listen
        );
        let label = format!("profile '{name}' DHCP server on {dhcp_listen}");
        service_set.spawn(async move {
            dhcp_server
                .run(&dhcp_listen, dhcp_socket)
                .await
                .map_err(|error| anyhow::anyhow!("{label} failed: {error}"))
        });
    }

    // Listeners (#12): the primary bind + any extra `listen` specs, all sharing this ONE
    // profile (TUN / pool / identity / users). Each runs its own accept loop concurrently.
    let primary_transport: TransportProtocol = pcfg
        .bind
        .transport
        .parse()
        .unwrap_or(TransportProtocol::Tcp);
    let mut listeners: Vec<(String, TransportProtocol)> = vec![(
        crate::util::join_host_port(&pcfg.bind.address, pcfg.bind.port),
        primary_transport,
    )];
    for spec in &pcfg.bind.listen {
        match validate_listen_addr(spec) {
            // Every listener uses the profile's transport (variant A).
            Some(addr) => listeners.push((addr, primary_transport)),
            None => log::error!(
                "Profile '{}': ignoring malformed listen '{}' (want a bare `addr:port` on the profile's transport)",
                name, spec
            ),
        }
    }
    // Pre-auth admission gate, shared by every TCP listener of this profile. Until now
    // the accept loop spawned a task per connection with no ceiling: the per-IP rate
    // limiter throttles ONE source, but a spread-out flood (or many IPs under the limit)
    // could pile up unbounded pre-auth tasks, each holding sockets and handshake buffers.
    // The permit is released the moment the client authenticates (see handle_client), so
    // this caps concurrent HANDSHAKES, not concurrent sessions — established users are
    // never refused because others are still connecting. Mirrors the UDP worker's
    // `max_concurrent_udp_handshakes`, with a higher floor since TCP also carries the
    // REALITY decoy bridge. (S-01)
    let pre_auth_gate = {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Arc::new(tokio::sync::Semaphore::new(std::cmp::max(
            256,
            cores.saturating_mul(8),
        )))
    };
    let pre_auth_refused = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // SEPARATE budget for decoy bridges (Р4 / S-01 follow-up). A probe that fails the
    // REALITY check is proxied to the cover site and can legitimately stay open for up to
    // BRIDGE_MAX_LIFETIME. While those shared the pre-auth gate, a scan could fill every
    // slot with bridges and starve real handshakes — the resource bound turned into a
    // denial of service. Bridges now hand back the pre-auth permit and take one of these
    // instead, so the two never compete: probing can exhaust the decoy budget (after which
    // strangers are simply dropped, exactly as a firewalled host would) while legitimate
    // clients keep the whole handshake gate to themselves.
    let decoy_gate = Arc::new(tokio::sync::Semaphore::new(std::cmp::max(
        128,
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .saturating_mul(4),
    )));
    let decoy_refused = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // A JoinSet, not a Vec of handles: these are awaited CONCURRENTLY below. See the join
    // loop for why awaiting them in order hid bind failures.
    let mut listener_set = tokio::task::JoinSet::new();
    let udp_worker_count = if matches!(primary_transport, TransportProtocol::Udp) {
        listeners
            .len()
            .checked_mul(nq)
            .ok_or_else(|| anyhow::anyhow!("profile '{}' has too many UDP workers", name))?
    } else {
        0
    };
    let mut udp_roaming_workers =
        udp_handler::build_udp_roaming_workers(&profile, udp_worker_count)?
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
    for (listener_index, (bind_addr, transport)) in listeners.into_iter().enumerate() {
        // SO_REUSEPORT worker ids are profile-wide, not merely unique inside one bind.listen.
        // The CID registry uses this identity to return a migrated datagram to its immutable
        // codec owner even when it arrived on another listener or outer address family.
        let udp_worker_base = listener_index
            .checked_mul(nq)
            .ok_or_else(|| anyhow::anyhow!("profile '{}' has too many UDP workers", name))?;
        let listener_roaming_workers = if matches!(transport, TransportProtocol::Udp) {
            let mut workers = Vec::with_capacity(nq);
            for wid in 0..nq {
                let worker_id = udp_worker_base
                    .checked_add(wid)
                    .ok_or_else(|| anyhow::anyhow!("profile '{}' UDP worker id overflow", name))?;
                let worker = udp_roaming_workers
                    .get_mut(worker_id)
                    .and_then(Option::take)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "profile '{}' missing UDP roaming worker {}",
                            name,
                            worker_id
                        )
                    })?;
                workers.push(worker);
            }
            workers
        } else {
            Vec::new()
        };
        let state = state.clone();
        let profile = profile.clone();
        let pre_auth_gate = pre_auth_gate.clone();
        let pre_auth_refused = pre_auth_refused.clone();
        let decoy_gate = decoy_gate.clone();
        let decoy_refused = decoy_refused.clone();
        let in_txs = in_txs.clone();
        let direct_out_txs = direct_out_txs.clone();
        let tun_write_pool = tun_write_pool.clone();
        let pcfg = pcfg.clone();
        let name = name.clone();
        let profile_tasks = tasks.clone();
        listener_set.spawn(async move {
            match transport {
                TransportProtocol::Tcp => {
                    let listener = bind_tcp_listener(&bind_addr).await?;
                    log::info!("Profile '{}' listening on {} (TCP)", name, bind_addr);
                    loop {
                        let (stream, addr) = match listener.accept().await {
                            Ok(v) => v,
                            Err(e) => {
                                // Back off briefly so a persistent accept error (e.g. EMFILE on
                                // fd exhaustion) can't spin the loop at 100% CPU and flood the log.
                                log::error!(
                                    "Accept error on profile '{}': {} — backing off 100ms",
                                    name,
                                    e
                                );
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            }
                        };

                        {
                            let mut rl = profile.rate_limiter.lock().await;
                            if !rl.check_and_record(addr.ip()) {
                                log::warn!(
                                    "Rate limit exceeded for {} on profile '{}'",
                                    addr.ip(),
                                    name
                                );
                                continue;
                            }
                        }

                        // Admission control BEFORE spawn: refuse the connection outright
                        // when the pre-auth gate is full instead of queueing another task
                        // that owns a socket. (S-01)
                        let pre_auth_permit = match pre_auth_gate.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                let n = pre_auth_refused
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                    + 1;
                                if n % 100 == 1 {
                                    log::warn!(
                                        "Profile '{}': pre-auth gate full — refusing {} (total refused: {})",
                                        name, addr, n
                                    );
                                }
                                drop(stream);
                                continue;
                            }
                        };

                        log::info!("New TCP connection from {} on profile '{}'", addr, name);
                        let state_clone = state.clone();
                        let profile_clone = profile.clone();
                        // Per-CONNECTION clones: the outer bindings are per-listener, and
                        // moving them into the spawn would consume them on the first
                        // iteration of the accept loop.
                        let decoy_gate_conn = decoy_gate.clone();
                        let decoy_refused_conn = decoy_refused.clone();
                        // Shard this connection's inbound packets onto one TUN queue (sticky
                        // per connection so a connection's packets stay ordered).
                        let tun_tx = {
                            use std::hash::{Hash, Hasher};
                            let mut h = std::collections::hash_map::DefaultHasher::new();
                            addr.hash(&mut h);
                            let queue = (h.finish() as usize) % in_txs.len();
                            TunIngress {
                                sender: in_txs[queue].clone(),
                                forwarder: direct_out_txs[queue].clone(),
                                pool: tun_write_pool.clone(),
                            }
                        };
                        let use_reality = pcfg.obfuscation.tls.reality_proxy.enabled;
                        let nodelay = pcfg.performance.tcp.nodelay;
                        let keepalive = pcfg.performance.tcp.keepalive_secs;
                        let sndbuf = pcfg.performance.tcp.send_buffer_size;
                        let rcvbuf = pcfg.performance.tcp.recv_buffer_size;
                        let obfs_key = if pcfg.obfuscation.mode == "obfs" {
                            Some(crate::protocol::obfs::derive_obfs_key(
                                &pcfg.obfuscation.obfs_key,
                            ))
                        } else {
                            None
                        };
                        let obfs_fronting = pcfg.obfuscation.fronting == "websocket";
                        let obfs_awg = crate::protocol::obfs::AwgParams {
                            enabled: pcfg.obfuscation.awg.enabled,
                            jc: pcfg.obfuscation.awg.jc,
                            jmin: pcfg.obfuscation.awg.jmin,
                            jmax: pcfg.obfuscation.awg.jmax,
                        };
                        let name_conn = profile_clone.name.clone();
                        profile_tasks.spawn(async move {
                            // Socket options on the raw TcpStream before any obfs wrapping.
                            let _ = stream.set_nodelay(nodelay);
                            if let Err(error) = set_tcp_keepalive(&stream, keepalive) {
                                log::warn!(
                                    "Profile '{}': failed to apply TCP keepalive to {}: {}",
                                    name_conn,
                                    addr,
                                    error
                                );
                            }
                            let _ = set_tcp_buffers(&stream, sndbuf, rcvbuf);
                            if use_reality {
                                if let Err(e) = reality::handle_connection(
                                    state_clone,
                                    profile_clone,
                                    stream,
                                    addr,
                                    tun_tx,
                                    Some(pre_auth_permit),
                                    reality::DecoyGate {
                                        sem: decoy_gate_conn,
                                        refused: decoy_refused_conn,
                                    },
                                )
                                .await
                                {
                                    log::debug!(
                                        "REALITY {} disconnected on profile '{}': {}",
                                        addr,
                                        name_conn,
                                        e
                                    );
                                }
                            } else if let Some(key) = obfs_key {
                                match crate::protocol::obfs::ObfsStream::accept(
                                    stream,
                                    &key,
                                    obfs_fronting,
                                    obfs_awg,
                                )
                                .await
                                {
                                    Ok(s) => {
                                        if let Err(e) = handler::handle_client(
                                            state_clone,
                                            profile_clone,
                                            s,
                                            addr,
                                            tun_tx,
                                            Some(pre_auth_permit),
                                        )
                                        .await
                                        {
                                            log::debug!(
                                                "Client {} disconnected on profile '{}': {}",
                                                addr,
                                                name_conn,
                                                e
                                            );
                                        }
                                    }
                                    Err(e) => log::debug!(
                                        "obfs accept failed for {} on profile '{}': {}",
                                        addr,
                                        name_conn,
                                        e
                                    ),
                                }
                            } else {
                                if let Err(e) = handler::handle_client(
                                    state_clone,
                                    profile_clone,
                                    stream,
                                    addr,
                                    tun_tx,
                                    Some(pre_auth_permit),
                                )
                                .await
                                {
                                    log::debug!(
                                        "Client {} disconnected on profile '{}': {}",
                                        addr,
                                        name_conn,
                                        e
                                    );
                                }
                            }
                        });
                    }
                }
                TransportProtocol::Udp => {
                    // N UDP workers, each on its own SO_REUSEPORT socket. The kernel
                    // flow-hashes datagrams across them (a client sticks to one worker), so
                    // UDP decrypt spreads across cores. Each worker drains into one TUN queue.
                    let workers = nq;
                    log::info!(
                        "Profile '{}' listening on {} (UDP, {} worker(s))",
                        name,
                        bind_addr,
                        workers
                    );
                    let mut worker_set = tokio::task::JoinSet::new();
                    let mut roaming_workers = listener_roaming_workers.into_iter();
                    for wid in 0..workers {
                        let (socket, udp_buffer) = udp_handler::bind_reuseport(
                            &bind_addr,
                            &profile.config.performance.udp,
                            profile.udp_buffer_counters.clone(),
                            state.udp_buffer_budget,
                        )?;
                        let udp_state = state.clone();
                        let udp_profile = profile.clone();
                        let tun_tx_udp = TunIngress {
                            sender: in_txs[wid % in_txs.len()].clone(),
                            forwarder: direct_out_txs[wid % direct_out_txs.len()].clone(),
                            pool: tun_write_pool.clone(),
                        };
                        let worker_tasks = profile_tasks.clone();
                        let worker_id = udp_worker_base.checked_add(wid).ok_or_else(|| {
                            anyhow::anyhow!("profile '{}' UDP worker id overflow", name)
                        })?;
                        let roaming_worker = roaming_workers.next().ok_or_else(|| {
                            anyhow::anyhow!("profile '{}' missing UDP roaming mailbox", name)
                        })?;
                        worker_set.spawn(async move {
                            udp_handler::run_udp_server(
                                udp_state,
                                udp_profile,
                                socket,
                                udp_buffer,
                                worker_id,
                                roaming_worker,
                                tun_tx_udp,
                                worker_tasks,
                            )
                            .await
                        });
                    }
                    let why = match worker_set.join_next().await {
                        Some(Ok(Err(error))) => format!("UDP worker failed: {error}"),
                        Some(Ok(Ok(()))) => "UDP worker stopped unexpectedly".to_string(),
                        Some(Err(error)) => format!("UDP worker task panicked: {error}"),
                        None => "no UDP workers were started".to_string(),
                    };
                    worker_set.abort_all();
                    while worker_set.join_next().await.is_some() {}
                    Err(anyhow::anyhow!(why))
                }
            }
        });
    }
    // Await the listeners CONCURRENTLY.
    //
    // They used to be awaited IN ORDER, and an accept loop only returns when it breaks — so
    // the first listener's `await` never completed and every later listener's bind error sat
    // unread in its JoinHandle forever. A profile with `listen = 0.0.0.0:8443` whose extra
    // port was already taken came up looking perfectly healthy, logged nothing, and simply
    // did not answer on that port. `join_next` yields whichever task finishes FIRST, so the
    // failure surfaces the moment it happens, whichever listener it was.
    // (Audit 2026-07-30, #6.)
    // The FIRST listener to finish ends the profile — it does not wait for the rest.
    //
    // Waiting for all of them looked thorough and was the bug: an accept loop never returns on
    // its own, so a profile whose primary `:443` was taken while its extra `:8443` bound fine
    // sat here forever. The failure was logged and then nothing happened — `run_profile` never
    // returned, the teardown guard never ran, and the server went on counting the profile as
    // healthy while the endpoint every client was handed refused connections. "Some of the
    // addresses I published work" is not a serving profile; a client configured for the
    // primary has no way to discover it should use the other one.
    //
    // Failing here hands the situation to the layer that can act on it: the guard rolls the
    // profile back (TUN, NAT, registry) and the spawn site logs it per profile while the other
    // profiles keep serving. (Audit 2026-08-01, §5.)
    let why = tokio::select! {
        _ = wait_for_profile_shutdown(shutdown) => None,
        service = service_set.join_next(), if !service_set.is_empty() => Some(match service {
            Some(Ok(Err(error))) => format!("a critical profile service exited: {error}"),
            Some(Ok(Ok(()))) => "a critical profile service stopped unexpectedly".to_string(),
            Some(Err(error)) => format!("a critical profile service task panicked: {error}"),
            None => "all critical profile services disappeared".to_string(),
        }),
        fatal = tun_fatal_rx.recv() => Some(fatal
            .unwrap_or_else(|| "all TUN queue health senders disappeared".to_string())),
        joined = listener_set.join_next() => Some(match joined {
            Some(Ok(Err(e))) => format!("a listener exited: {e}"),
            Some(Ok(Ok(()))) => "a listener stopped unexpectedly".to_string(),
            Some(Err(e)) => format!("a listener task panicked: {e}"),
            // Nothing was ever spawned. The profile has a TUN, a pool and users, and accepts
            // nothing at all — reported rather than returned as success, which is what used to
            // happen when every bind failed.
            None => "no listeners were started at all".to_string(),
        }),
    };
    // Stop the survivors explicitly rather than relying on the JoinSet's drop: their accept
    // loops would otherwise keep taking connections for a profile that is being torn down,
    // and a client could complete a handshake against a pool that is about to disappear.
    listener_set.abort_all();
    while listener_set.join_next().await.is_some() {}
    service_set.abort_all();
    while service_set.join_next().await.is_some() {}
    let Some(why) = why else {
        return Ok(());
    };
    anyhow::bail!(
        "profile '{}': {} — the profile still publishes endpoints it can no longer serve",
        name,
        why
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    #[test]
    fn identity_generation_is_serialized_and_preserves_custom_parent_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("qeli-identity-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key_path = dir.join("custom.key");
        let profile = ProfileConfig {
            name: "identity-test".to_string(),
            identity_key: Some(key_path.to_string_lossy().into_owned()),
            ..ProfileConfig::default()
        };

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let profile = profile.clone();
                std::thread::spawn(move || load_or_generate_profile_key(&profile).unwrap())
            })
            .collect();
        let keys: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().private_bytes())
            .collect();
        assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(
            std::fs::read(&key_path).unwrap().as_slice(),
            keys[0].as_ref()
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing custom parent must not be chmodded"
        );
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn profile_tasks_abort_join_and_close_admission() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let tasks = ProfileTasks::new("test");
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        assert!(tasks.spawn(async move {
            let _signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        assert!(
            started_rx.await.is_ok(),
            "child task must start before shutdown"
        );

        tasks.shutdown().await;

        assert!(
            dropped_rx.await.is_ok(),
            "aborted child future must be dropped"
        );
        assert!(
            !tasks.spawn(async {}),
            "a closed generation must reject late child tasks"
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lifecycle_hook_env_exports_both_families_and_legacy_primary() {
        let mut profile = ProfileConfig::baseline();
        profile.name = "dual".into();
        profile.tun.name = "vpn42".into();
        profile.tun.ip_mode = crate::config::server::IpMode::Dual;
        profile.pool.cidr = "10.42.0.0/24".into();
        profile.pool.ipv6.cidr = "fd42::/64".into();
        profile.bind.port = 8443;
        let env = ProfileHookEnv::new(&profile, "wan4".into(), "wan6".into());
        assert_eq!(env.pool, "10.42.0.0/24");
        assert_eq!(env.pool_ipv4, "10.42.0.0/24");
        assert_eq!(env.pool_ipv6, "fd42::/64");
        assert_eq!(env.wan, "wan4");
        assert_eq!(env.wan_ipv4, "wan4");
        assert_eq!(env.wan_ipv6, "wan6");
        assert_eq!(env.bind_port, "8443");

        profile.tun.ip_mode = crate::config::server::IpMode::Ipv6;
        let env = ProfileHookEnv::new(&profile, String::new(), "wan6".into());
        assert_eq!(env.pool, "fd42::/64");
        assert_eq!(env.wan, "wan6");
        assert!(env.pool_ipv4.is_empty());
    }

    #[test]
    fn tun_read_pool_has_a_fixed_budget_and_at_least_one_buffer_per_queue() {
        assert_eq!(server_tun_read_buffer_count(4, 65_536), 512);
        assert_eq!(server_tun_read_buffer_count(256, 1_048_576), 256);
        assert_eq!(
            server_tun_read_buffer_count(0, SERVER_TUN_READ_POOL_BYTES * 2),
            1
        );
    }

    /// Minimal single-profile config with valid flat `perf.connection.*` keys, so
    /// `validate_profiles` reaches the wire-mode/transport check.
    fn cfg_with(mode: &str, transport: &str) -> ServerConfig {
        let ini = format!(
            "[profile:p]\n\
             bind.address = 0.0.0.0\n\
             bind.port = 4443\n\
             bind.transport = {transport}\n\
             tun.name = vpn0\n\
             tun.address = 10.1.0.1\n\
             tun.mtu = 1400\n\
             pool.cidr = 10.1.0.0/24\n\
             pool.exclude = 10.1.0.1\n\
             obf.mode = {mode}\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n"
        );
        crate::config::parse_server_config(&ini).expect("fixture INI must parse")
    }

    /// The same fixture with the address fields under test made settable.
    fn cfg_addr(tun_address: &str, pool_cidr: &str) -> ServerConfig {
        let ini = format!(
            "[profile:p]\n\
             bind.address = 0.0.0.0\n\
             bind.port = 4443\n\
             bind.transport = tcp\n\
             tun.name = vpn0\n\
             tun.address = {tun_address}\n\
             tun.mtu = 1400\n\
             pool.cidr = {pool_cidr}\n\
             obf.mode = fake-tls\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n"
        );
        crate::config::parse_server_config(&ini).expect("fixture INI must parse")
    }

    #[test]
    fn bad_address_fields_are_rejected_before_the_worker_starts() {
        // These are plain `String`s in the schema, so they parsed happily and only blew
        // up when the worker tried to START the profile: `check-config` reported OK with
        // rc=0, the panel accepted the save, and the server then crash-looped on every
        // respawn. Guard the whole class, not just the reported field.
        for (label, cfg) in [
            ("CIDR prefix >32", cfg_addr("10.1.0.1", "10.9.0.0/33")),
            ("not a CIDR at all", cfg_addr("10.1.0.1", "not-a-cidr")),
            (
                "octet >255 in tun.address",
                cfg_addr("300.1.1.1", "10.1.0.0/24"),
            ),
            (
                "tun.address outside pool.cidr",
                cfg_addr("10.2.0.1", "10.1.0.0/24"),
            ),
        ] {
            assert!(
                validate_profiles(&cfg).is_err(),
                "{label}: must be rejected by validation, not by a crash-looping worker"
            );
        }
    }

    #[test]
    fn valid_address_fields_still_pass() {
        // The guard above must not start rejecting ordinary configs.
        assert!(validate_profiles(&cfg_addr("10.1.0.1", "10.1.0.0/24")).is_ok());
        assert!(validate_profiles(&cfg_addr("10.1.0.1", "10.1.0.0/16")).is_ok());
    }

    #[test]
    fn roaming_resource_bounds_are_validated() {
        use crate::config::server::{
            ROAMING_MAX_GRACE_SECS, ROAMING_MAX_ORPHANED, ROAMING_MAX_ORPHAN_BYTES,
            ROAMING_MIN_GRACE_SECS, ROAMING_MIN_ORPHANED, ROAMING_MIN_ORPHAN_BYTES,
        };

        let baseline = cfg_with("fake-tls", "tcp");
        assert!(!baseline.profiles[0].roaming.enabled);
        validate_profiles(&baseline).expect("documented roaming defaults must validate");

        let mut enabled = baseline.clone();
        enabled.profiles[0].roaming.enabled = true;
        if cfg!(feature = "experimental-roaming") {
            validate_profiles(&enabled).expect("a feature build must accept explicit opt-in");
        } else {
            let error = validate_profiles(&enabled).unwrap_err().to_string();
            assert!(
                error.contains("requires a binary built with experimental-roaming"),
                "{error}"
            );
        }

        for (key, config) in [
            ("roaming.grace_secs", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.grace_secs = ROAMING_MIN_GRACE_SECS - 1;
                config
            }),
            ("roaming.grace_secs", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.grace_secs = ROAMING_MAX_GRACE_SECS + 1;
                config
            }),
            ("roaming.max_orphaned", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.max_orphaned = ROAMING_MIN_ORPHANED - 1;
                config
            }),
            ("roaming.max_orphaned", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.max_orphaned = ROAMING_MAX_ORPHANED + 1;
                config
            }),
            ("roaming.max_orphan_bytes", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.max_orphan_bytes = ROAMING_MIN_ORPHAN_BYTES - 1;
                config
            }),
            ("roaming.max_orphan_bytes", {
                let mut config = baseline.clone();
                config.profiles[0].roaming.max_orphan_bytes = ROAMING_MAX_ORPHAN_BYTES + 1;
                config
            }),
        ] {
            let error = validate_profiles(&config).unwrap_err().to_string();
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    #[test]
    fn overlapping_profile_pools_are_rejected_without_host_discovery() {
        fn profile(
            name: &str,
            port: u16,
            tun: &str,
            mode: &str,
            address: &str,
            pool: &str,
        ) -> String {
            if mode == "ipv4" {
                format!(
                    "[profile:{name}]\n\
                     bind.address = 0.0.0.0\n\
                     bind.port = {port}\n\
                     bind.transport = tcp\n\
                     tun.name = {tun}\n\
                     tun.address = {address}\n\
                     tun.mtu = 1400\n\
                     pool.cidr = {pool}\n\
                     obf.mode = fake-tls\n"
                )
            } else {
                format!(
                    "[profile:{name}]\n\
                     bind.address = 0.0.0.0\n\
                     bind.port = {port}\n\
                     bind.transport = tcp\n\
                     tun.name = {tun}\n\
                     tun.ip_mode = ipv6\n\
                     tun.ipv6_address = {address}\n\
                     tun.mtu = 1400\n\
                     pool.ipv6.cidr = {pool}\n\
                     obf.mode = fake-tls\n"
                )
            }
        }

        let ipv4 = crate::config::parse_server_config(
            &(profile("a", 4401, "vpn0", "ipv4", "10.20.0.1", "10.20.0.0/24")
                + &profile("b", 4402, "vpn1", "ipv4", "10.20.0.129", "10.20.0.128/25")),
        )
        .unwrap();
        let error = validate_profiles(&ipv4).unwrap_err().to_string();
        assert!(error.contains("overlapping IPv4 pools"), "{error}");
        assert!(error.contains("'a'") && error.contains("'b'"), "{error}");

        let ipv6 = crate::config::parse_server_config(
            &(profile(
                "v6a",
                6401,
                "vpn6a",
                "ipv6",
                "fd71:e1:20::1",
                "fd71:e1:20::/64",
            ) + &profile(
                "v6b",
                6402,
                "vpn6b",
                "ipv6",
                "fd71:e1:20::8000:0:0:1",
                "fd71:e1:20:0:8000::/65",
            )),
        )
        .unwrap();
        let error = validate_profiles(&ipv6).unwrap_err().to_string();
        assert!(error.contains("overlapping IPv6 pools"), "{error}");
        assert!(
            error.contains("'v6a'") && error.contains("'v6b'"),
            "{error}"
        );
    }

    /// The PRIMARY bind, which the extra-listener checks never covered (§5).
    ///
    /// Built as a WHOLE config rather than appended to the shared fixture: the INI parser takes
    /// the FIRST value of a duplicate key, so appending `bind.port = 0` to a fixture that
    /// already sets 4443 changes nothing — which is how the first version of this test passed
    /// against a check that had not run at all. (Audit 2026-08-01, §5.)
    #[test]
    fn primary_bind_and_endpoint_collisions_are_rejected() {
        fn cfg(text: &str) -> ServerConfig {
            crate::config::parse_server_config(text).expect("fixture INI must parse")
        }
        fn profile(name: &str, addr: &str, port: &str, transport: &str) -> String {
            let net = if name == "a" { 1 } else { 2 };
            format!(
                "[profile:{name}]
bind.address = {addr}
bind.port = {port}
                 bind.transport = {transport}
tun.name = vpn{name}
tun.address = 10.{net}.0.1
tun.mtu = 1400
pool.cidr = 10.{net}.0.0/24
                 obf.mode = fake-tls
"
            )
        }

        // The control: without a passing case, a check that rejected everything would look
        // exactly like one that works.
        validate_profiles(&cfg(&profile("a", "0.0.0.0", "4443", "tcp")))
            .expect("a sane profile must validate");

        for (label, text) in [
            ("bind.port = 0", profile("a", "0.0.0.0", "0", "tcp")),
            (
                "udp bind.address is a hostname",
                profile("a", "vpn.example.com", "4443", "udp"),
            ),
            (
                "two profiles on one endpoint",
                profile("a", "0.0.0.0", "4443", "udp") + &profile("b", "0.0.0.0", "4443", "udp"),
            ),
        ] {
            assert!(
                validate_profiles(&cfg(&text)).is_err(),
                "{label}: must be rejected at load"
            );
        }

        // Same port on DIFFERENT transports is a legitimate pairing and must still pass.
        let mixed =
            profile("a", "0.0.0.0", "4443", "tcp") + &profile("b", "0.0.0.0", "4443", "udp");
        validate_profiles(&cfg(&mixed)).expect("tcp and udp may share a port");
    }

    /// Endpoint collisions involving the EXTRA `listen` specs, and wildcard overlap.
    ///
    /// Only the primary endpoint used to be entered into the collision map; extra `listen`
    /// entries were checked for shape and then discarded, so `primary <-> extra`,
    /// `extra <-> extra` and a profile colliding with ITSELF all validated cleanly and then
    /// bound twice — on UDP with SO_REUSEPORT both binds SUCCEED and the kernel splits clients
    /// between profiles with different keys and pools. (Audit 2026-08-01, §2.)
    #[test]
    fn extra_listeners_and_wildcards_collide_too() {
        fn cfg(text: &str) -> ServerConfig {
            crate::config::parse_server_config(text).expect("fixture INI must parse")
        }
        fn profile(name: &str, addr: &str, port: &str, tun: u8, listen: &[&str]) -> String {
            let extra: String = listen.iter().map(|l| format!("listen = {l}\n")).collect();
            format!(
                "[profile:{name}]\n\
                 bind.address = {addr}\n\
                 bind.port = {port}\n\
                 bind.transport = udp\n\
                 {extra}\
                 tun.name = vpn{tun}\n\
                 tun.address = 10.{tun}.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.{tun}.0.0/24\n\
                 obf.mode = fake-tls\n"
            )
        }

        // Controls first: extra listeners on free ports are the normal case, and two profiles
        // on genuinely different concrete addresses do not overlap.
        validate_profiles(&cfg(&profile(
            "a",
            "10.0.0.1",
            "4443",
            0,
            &["10.0.0.1:8443", "10.0.0.1:9443"],
        )))
        .expect("extra listeners on free ports must validate");
        validate_profiles(&cfg(
            &(profile("a", "10.0.0.1", "4443", 0, &[]) + &profile("b", "10.0.0.2", "4443", 1, &[]))
        ))
        .expect("different concrete addresses on one port must validate");
        validate_profiles(&cfg(&profile(
            "dual-outer",
            "0.0.0.0",
            "4443",
            2,
            &["[::]:4443"],
        )))
        .expect("separate IPv4 + V6ONLY IPv6 wildcards on one port must validate");

        for (label, text) in [
            (
                "a profile whose listen repeats its own primary",
                profile("a", "10.0.0.1", "4443", 0, &["10.0.0.1:4443"]),
            ),
            (
                "two listen entries on one endpoint",
                profile(
                    "a",
                    "10.0.0.1",
                    "4443",
                    0,
                    &["10.0.0.1:8443", "10.0.0.1:8443"],
                ),
            ),
            (
                "one profile's listen over another's primary",
                profile("a", "10.0.0.1", "4443", 0, &[])
                    + &profile("b", "10.0.0.2", "9443", 1, &["10.0.0.1:4443"]),
            ),
            (
                "wildcard over a concrete address",
                profile("a", "10.0.0.1", "4443", 0, &[]) + &profile("b", "0.0.0.0", "4443", 1, &[]),
            ),
            (
                "concrete address under an existing wildcard",
                profile("a", "0.0.0.0", "4443", 0, &[]) + &profile("b", "10.0.0.1", "4443", 1, &[]),
            ),
        ] {
            let err = validate_profiles(&cfg(&text))
                .expect_err(&format!("{label}: must be rejected at load"));
            assert!(
                err.to_string().contains("both bind port"),
                "{label}: rejected for the wrong reason: {err}"
            );
        }
    }

    /// The panel and the per-profile services bind too, and none of them used to be checked.
    ///
    /// The panel is the nastiest of the three: it is not a profile and it starts EARLIER (the
    /// supervisor spawns it before the worker), so it wins the port and the worker crash-loops
    /// against a port held by the same server — from outside, the panel looks healthy and the
    /// VPN "just doesn't work". DHCP is the likeliest: its default is `0.0.0.0:67`, so two
    /// profiles with DHCP on collide unless the operator changed it, and the loser failed
    /// inside a detached task with one log line. (Audit 2026-08-01, §4.)
    #[test]
    fn the_panel_and_profile_services_are_in_the_conflict_map() {
        fn cfg(text: &str) -> ServerConfig {
            crate::config::parse_server_config(text).expect("fixture INI must parse")
        }
        fn profile(name: &str, port: &str, tun: u8, extra: &str) -> String {
            format!(
                "[profile:{name}]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = {port}\n\
                 bind.transport = tcp\n\
                 tun.name = vpn{tun}\n\
                 tun.address = 10.{tun}.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.{tun}.0.0/24\n\
                 obf.mode = fake-tls\n\
                 {extra}"
            )
        }
        let web = |port: &str| format!("[web]\nenabled = true\nport = {port}\n");

        // Control: a panel on its own port, and per-profile services on distinct addresses.
        validate_profiles(&cfg(&(web("8443")
            + &profile(
                "a",
                "4443",
                0,
                "dns.enabled = true\ndns.listen = 10.0.0.1\n",
            )
            + &profile(
                "b",
                "5443",
                1,
                "dns.enabled = true\ndns.listen = 10.1.0.1\n",
            ))))
        .expect("distinct ports and resolver addresses must validate");

        // IPv6-only binds only dns.listen_ipv6. Its legacy/default dns.listen value is an
        // inactive shadow and must neither be parsed nor reserve an imaginary IPv4 socket.
        validate_profiles(&cfg(&(profile(
            "v6a",
            "6443",
            2,
            "tun.ip_mode = ipv6\n\
                 tun.ipv6_address = fd71:e1:2::1\n\
                 pool.ipv6.cidr = fd71:e1:2::/64\n\
                 dns.enabled = true\n\
                 dns.listen = not-an-ipv4-address\n\
                 dns.listen_ipv6 = fd71:e1:2::1\n",
        ) + &profile(
            "v6b",
            "7443",
            3,
            "tun.ip_mode = ipv6\n\
                 tun.ipv6_address = fd71:e1:3::1\n\
                 pool.ipv6.cidr = fd71:e1:3::/64\n\
                 dns.enabled = true\n\
                 dns.listen = not-an-ipv4-address\n\
                 dns.listen_ipv6 = fd71:e1:3::1\n",
        ))))
        .expect("IPv6-only resolvers must ignore the inactive IPv4 listen field");

        for (label, text) in [
            (
                "the panel over a profile's bind port",
                web("4443") + &profile("a", "4443", 0, ""),
            ),
            (
                "resolver over a profile's transport bind",
                profile("a", "53", 0, "dns.enabled = true\ndns.listen = 10.0.0.1\n"),
            ),
            // NB: "two DHCP servers on the 0.0.0.0:67 default" used to live here. It cannot
            // happen any more: `dhcp.listen` defaults to EMPTY, which resolves to the
            // PROFILE'S OWN tun address, so two default-configured profiles bind two
            // different addresses instead of colliding on the wildcard. The old default
            // published an unauthenticated DHCP server on every interface, which was the
            // real problem — the collision was only how it surfaced. The case below (an
            // EXPLICIT shared address) still exercises the conflict map.
            // (Audit 2026-08-04.)
            (
                // The runtime appends `:67` to a bare address, so reading the raw string let
                // this exact collision through whenever the port was omitted.
                "two DHCP servers on one address written WITHOUT a port",
                profile(
                    "a",
                    "4443",
                    0,
                    "dhcp.enabled = true\ndhcp.listen = 10.9.0.1\n",
                ) + &profile(
                    "b",
                    "5443",
                    1,
                    "dhcp.enabled = true\ndhcp.listen = 10.9.0.1\n",
                ),
            ),
        ] {
            let err = validate_profiles(&cfg(&text))
                .expect_err(&format!("{label}: must be rejected at load"));
            assert!(
                err.to_string().contains("both bind port"),
                "{label}: rejected for the wrong reason: {err}"
            );
        }
    }

    /// A device name the kernel would truncate, or one two profiles share.
    ///
    /// TUNSETIFF copies at most 15 bytes, so a longer name created a device under a DIFFERENT
    /// name than every following `ip ... dev <name>` used. It can also attach another queue
    /// to an existing multi-queue device, so two profiles sharing a name can split traffic
    /// between unrelated generations. (Audit 2026-08-01, §4.)
    #[test]
    fn tun_names_that_truncate_or_collide_are_rejected() {
        fn cfg(text: &str) -> ServerConfig {
            crate::config::parse_server_config(text).expect("fixture INI must parse")
        }
        fn profile(name: &str, tun: &str, port: &str, net: u8) -> String {
            format!(
                "[profile:{name}]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = {port}\n\
                 bind.transport = tcp\n\
                 tun.name = {tun}\n\
                 tun.address = 10.{net}.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.{net}.0.0/24\n\
                 obf.mode = fake-tls\n"
            )
        }

        // Exactly at the limit must pass — an off-by-one here would reject a legal name.
        validate_profiles(&cfg(&profile("a", "abcdefghijklmno", "4443", 0)))
            .expect("a 15-byte name is legal");

        // A NON-ASCII overlong name must be REJECTED, not panic. The error message quotes the
        // part the kernel would keep, and slicing that by byte index lands inside a multi-byte
        // code point — eight Cyrillic letters is sixteen bytes. This validator runs inside
        // `PUT /api/config`, so the panic would have been in the panel's request handler.
        // (Audit 2026-08-01, §P2.)
        let cyrillic = "интерфейс"; // 9 chars, 18 bytes
        assert!(cyrillic.len() > MAX_IFNAME_LEN && cyrillic.chars().count() <= MAX_IFNAME_LEN);
        let err = validate_profiles(&cfg(&profile("a", cyrillic, "4443", 0)))
            .expect_err("an 18-byte name must be rejected");
        assert!(err.to_string().contains("tun.name"), "wrong reason: {err}");

        for (label, text) in [
            ("16 bytes", profile("a", "abcdefghijklmnop", "4443", 0)),
            ("empty", profile("a", "", "4443", 0)),
            ("contains a space", profile("a", "vpn 0", "4443", 0)),
            (
                "two profiles share a device",
                profile("a", "vpn0", "4443", 0) + &profile("b", "vpn0", "5443", 1),
            ),
        ] {
            let err = validate_profiles(&cfg(&text))
                .expect_err(&format!("{label}: must be rejected at load"));
            assert!(
                err.to_string().contains("tun.name"),
                "{label}: rejected for the wrong reason: {err}"
            );
        }
    }

    /// The TUN read buffer had no bounds outside the panel's HTML input, and 0 is not a slow
    /// data plane — `read()` into an empty buffer returns Ok(0), the reader reads that as EOF
    /// and the profile stops moving packets with nothing logged. (Audit 2026-08-01, §3.)
    #[test]
    fn a_tun_read_buffer_smaller_than_the_mtu_is_rejected() {
        fn cfg(dev: &str, mtu: u32, buf: &str) -> ServerConfig {
            crate::config::parse_server_config(&format!(
                "[profile:p]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = 4443\n\
                 bind.transport = tcp\n\
                 tun.name = vpn0\n\
                 tun.address = 10.1.0.1\n\
                 tun.mtu = {mtu}\n\
                 tun.device_type = {dev}\n\
                 pool.cidr = 10.1.0.0/24\n\
                 obf.mode = fake-tls\n\
                 perf.tun.read_buffer_size = {buf}\n"
            ))
            .expect("fixture INI must parse")
        }

        validate_profiles(&cfg("tun", 1400, "65535")).expect("the default buffer must validate");
        // Exactly the MTU is enough for a TUN: no link header.
        validate_profiles(&cfg("tun", 1400, "1400")).expect("a buffer of exactly the mtu is fine");

        assert!(
            validate_profiles(&cfg("tun", 1400, "0")).is_err(),
            "0 reads as EOF and stops the data plane"
        );
        assert!(
            validate_profiles(&cfg("tun", 9000, "1500")).is_err(),
            "a buffer below a jumbo mtu truncates every full frame"
        );
        assert!(
            validate_profiles(&cfg("tap", 1400, "1400")).is_err(),
            "TAP frames carry a 14-byte ethernet header on top of the mtu"
        );
        assert!(
            validate_profiles(&cfg("tun", 1400, "16777216")).is_err(),
            "the buffer is allocated per queue, so an absurd value multiplies"
        );
    }

    #[test]
    fn udp_socket_buffers_have_a_hard_per_worker_limit() {
        fn cfg(key: &str, value: u32) -> ServerConfig {
            crate::config::parse_server_config(&format!(
                "[profile:p]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = 4443\n\
                 bind.transport = udp\n\
                 tun.name = vpn0\n\
                 tun.address = 10.1.0.1\n\
                 tun.mtu = 1400\n\
                 tun.queues = 1\n\
                 pool.cidr = 10.1.0.0/24\n\
                 obf.mode = fake-tls\n\
                 {key} = {value}\n"
            ))
            .expect("fixture INI must parse")
        }

        for key in ["perf.udp.recv_buffer_size", "perf.udp.send_buffer_size"] {
            validate_profiles(&cfg(key, 64 * 1024 * 1024))
                .expect("the documented maximum must validate");
            let error = validate_profiles(&cfg(key, 64 * 1024 * 1024 + 1))
                .unwrap_err()
                .to_string();
            assert!(error.contains(key), "wrong validation error: {error}");
        }
    }

    /// `web.port = 0` is a whole-config property and has nothing to do with DNS — but the check
    /// was written inside the per-profile loop's `if p.dns.enabled` branch, so it never ran for
    /// a config whose profiles do not serve DNS. (Audit 2026-08-01, §9.)
    #[test]
    fn web_port_zero_is_rejected_with_dns_off() {
        fn cfg(dns: bool, port: u16) -> ServerConfig {
            crate::config::parse_server_config(&format!(
                "[web]\n\
                 enabled = true\n\
                 port = {port}\n\
                 [profile:p]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = 4443\n\
                 bind.transport = tcp\n\
                 tun.name = vpn0\n\
                 tun.address = 10.1.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.1.0.0/24\n\
                 obf.mode = fake-tls\n\
                 dns.enabled = {dns}\n"
            ))
            .expect("fixture INI must parse")
        }

        validate_profiles(&cfg(false, 8443)).expect("a real web.port must validate");
        assert!(
            validate_profiles(&cfg(false, 0)).is_err(),
            "web.port = 0 must be rejected even when no profile serves DNS"
        );
        assert!(
            validate_profiles(&cfg(true, 0)).is_err(),
            "and still rejected when DNS is on"
        );
    }

    #[test]
    fn dns_runtime_resource_bounds_are_validated() {
        fn cfg() -> ServerConfig {
            crate::config::parse_server_config(
                "[profile:p]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = 4443\n\
                 bind.transport = tcp\n\
                 tun.name = vpn0\n\
                 tun.address = 10.9.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.9.0.0/24\n\
                 obf.mode = fake-tls\n\
                 dns.enabled = true\n\
                 dns.listen = 10.9.0.1\n\
                 dns.upstream = 1.1.1.1\n",
            )
            .expect("fixture INI must parse")
        }

        let mut valid = cfg();
        valid.profiles[0].dns.timeout_secs = crate::config::server::DNS_MAX_TIMEOUT_SECS;
        valid.profiles[0].dns.cache_size = crate::config::server::DNS_MAX_CACHE_ENTRIES;
        valid.profiles[0].dns.upstream = (1..=crate::config::server::DNS_MAX_UPSTREAMS)
            .map(|last| format!("192.0.2.{last}"))
            .collect();
        validate_profiles(&valid).expect("documented DNS maxima must validate");

        let mut timeout = cfg();
        timeout.profiles[0].dns.timeout_secs = crate::config::server::DNS_MAX_TIMEOUT_SECS + 1;
        assert!(validate_profiles(&timeout)
            .unwrap_err()
            .to_string()
            .contains("dns.timeout_secs"));

        let mut cache = cfg();
        cache.profiles[0].dns.cache_size = crate::config::server::DNS_MAX_CACHE_ENTRIES + 1;
        assert!(validate_profiles(&cache)
            .unwrap_err()
            .to_string()
            .contains("dns.cache_size"));

        let mut upstreams = cfg();
        upstreams.profiles[0].dns.upstream = (1..=crate::config::server::DNS_MAX_UPSTREAMS + 1)
            .map(|last| format!("192.0.2.{last}"))
            .collect();
        assert!(validate_profiles(&upstreams)
            .unwrap_err()
            .to_string()
            .contains("dns.upstream"));

        let mut duplicate_upstream = cfg();
        duplicate_upstream.profiles[0].dns.upstream =
            vec!["2001:db8::1".into(), "2001:0db8:0:0::1".into()];
        assert!(validate_profiles(&duplicate_upstream)
            .unwrap_err()
            .to_string()
            .contains("duplicate dns.upstream"));

        let mut no_cache = cfg();
        no_cache.profiles[0].dns.cache_size = 0;
        validate_profiles(&no_cache).expect("zero explicitly disables DNS caching");

        let mut bad_domain = cfg();
        bad_domain.profiles[0].dns.blocklist = vec!["*.example.com".into()];
        assert!(validate_profiles(&bad_domain)
            .unwrap_err()
            .to_string()
            .contains("dns.blocklist"));

        let mut duplicate = cfg();
        duplicate.profiles[0].dns.blocklist =
            vec!["Ads.Example.com".into(), "ads.example.com.".into()];
        assert!(validate_profiles(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate dns.blocklist"));

        let mut too_many = cfg();
        too_many.profiles[0].dns.blocklist =
            vec!["ads.example.com".into(); crate::config::server::DNS_MAX_BLOCKLIST_ENTRIES + 1];
        assert!(validate_profiles(&too_many)
            .unwrap_err()
            .to_string()
            .contains("dns.blocklist"));
    }

    /// Nonsensical obfuscation values must be refused at load, not accepted and then
    /// silently misbehave. Each case below is a real failure mode: an inverted min/max
    /// disables the feature without saying so, `max_fragments_per_packet = 0` leaves the
    /// fragmenter nowhere to put the packet, and a probability outside 0..=1 — or NaN,
    /// which every comparison answers `false` to — makes padding fire always or never.
    #[test]
    fn nonsensical_obfuscation_values_are_rejected() {
        fn cfg_extra(extra: &str) -> ServerConfig {
            let ini = format!(
                "[profile:p]\n\
                 bind.address = 0.0.0.0\n\
                 bind.port = 4443\n\
                 bind.transport = tcp\n\
                 tun.name = vpn0\n\
                 tun.address = 10.1.0.1\n\
                 tun.mtu = 1400\n\
                 pool.cidr = 10.1.0.0/24\n\
                 obf.mode = fake-tls\n\
                 {extra}"
            );
            crate::config::parse_server_config(&ini).expect("fixture INI must parse")
        }

        for (label, extra) in [
            // Extra listeners: the runtime already logged a malformed one, but only while
            // starting — so `check-config` said the config was fine and the operator found out
            // from a live server's log, or not at all. (Audit 2026-07-30, #6.)
            ("listen without a port", "listen = 0.0.0.0\n"),
            ("listen with port 0", "listen = 0.0.0.0:0\n"),
            ("listen with a bare IPv6 (needs brackets)", "listen = ::1:443\n"),
            ("listen with a non-numeric port", "listen = 0.0.0.0:https\n"),
            (
                "padding min > max",
                "obf.padding.enabled = true\nobf.padding.min_bytes = 200\nobf.padding.max_bytes = 100\n",
            ),
            (
                "padding probability above 1",
                "obf.padding.enabled = true\nobf.padding.probability = 1.5\n",
            ),
            (
                "fragmentation max_fragments = 0",
                "obf.fragmentation.enabled = true\nobf.fragmentation.max_fragments_per_packet = 0\n",
            ),
            (
                "fragmentation min > max",
                "obf.fragmentation.enabled = true\nobf.fragmentation.min_chunk_size = 900\nobf.fragmentation.max_chunk_size = 300\n",
            ),
            (
                "unordered normalization buckets",
                "obf.traffic_normalization.enabled = true\nobf.traffic_normalization.round_sizes = 512,256\n",
            ),
            (
                "shaping gap min > max",
                "obf.traffic_shaping.enabled = true\nobf.traffic_shaping.idle_gap_min_ms = 9000\nobf.traffic_shaping.idle_gap_max_ms = 100\n",
            ),
            (
                "shaping budget 0",
                "obf.traffic_shaping.enabled = true\nobf.traffic_shaping.budget_bytes_per_sec = 0\n",
            ),
            (
                "shaping budget below one cover record",
                "obf.traffic_shaping.enabled = true\nobf.traffic_shaping.budget_bytes_per_sec = 63\nobf.traffic_shaping.max_size = 64\n",
            ),
            (
                "heartbeat larger than one record",
                "obf.heartbeat.enabled = true\nobf.heartbeat.data_size_bytes = 20000\n",
            ),
            (
                "shaping cover larger than one record",
                "obf.traffic_shaping.enabled = true\nobf.traffic_shaping.max_size = 20000\n",
            ),
        ] {
            assert!(
                validate_profiles(&cfg_extra(extra)).is_err(),
                "{label}: must be rejected at load"
            );
        }

        // A profile that merely ENABLES these with sane values must still pass — the guard
        // exists to catch nonsense, not to make the features unusable.
        assert!(validate_profiles(&cfg_extra(
            "obf.padding.enabled = true\nobf.fragmentation.enabled = true\nobf.traffic_shaping.enabled = true\n"
        ))
        .is_ok());
    }

    /// reality-tls terminates a real TLS session, which is a TCP stream. On UDP the handler
    /// silently falls back to datagram framing, so the profile advertises the strongest
    /// masking the project has and puts none of it on the wire.
    #[test]
    fn reality_tls_is_rejected_on_udp() {
        let err = validate_profiles(&cfg_with("reality-tls", "udp")).unwrap_err();
        assert!(
            err.to_string().contains("TCP-only"),
            "expected a TCP-only rejection, got: {err}"
        );
        // …and must still be allowed on TCP, which is where it belongs. The label now has to
        // come with the thing it names — `reality-tls` with reality_proxy off is a profile that
        // announces REALITY and runs plain fake-TLS — so the fixture carries a short_id, the
        // same way the shipped reality profile does.
        let mut tcp = cfg_with("reality-tls", "tcp");
        tcp.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        tcp.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["0123456789abcdef".into()];
        tcp.profiles[0].obfuscation.tls.reality_proxy.real_tls = true;
        assert!(validate_profiles(&tcp).is_ok());
    }

    #[test]
    fn reality_real_tls_requires_static_session_binding() {
        let mut config = cfg_with("reality-tls", "tcp");
        config.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        config.profiles[0].obfuscation.tls.reality_proxy.short_ids =
            vec!["0123456789abcdef".into()];
        config.profiles[0].obfuscation.tls.reality_proxy.real_tls = true;
        config.auth.bind_static_to_session = false;

        let error = validate_profiles(&config)
            .expect_err("REALITY real-TLS must bind the pinned static identity")
            .to_string();
        assert!(
            error.contains("auth.bind_static_to_session = true"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn plain_wire_mode_is_rejected_on_udp() {
        // `plain` (raw) is TCP-only by design: a raw datagram stream is a
        // high-entropy "fully encrypted traffic" DPI red-flag and has no framing
        // to delimit records. The guard must fail loud, not silently misbehave.
        let err = validate_profiles(&cfg_with("plain", "udp")).unwrap_err();
        assert!(
            err.to_string().contains("TCP-only"),
            "expected a TCP-only rejection, got: {err}"
        );
    }

    #[test]
    fn plain_wire_mode_is_allowed_on_tcp() {
        assert!(validate_profiles(&cfg_with("plain", "tcp")).is_ok());
    }

    #[test]
    fn unknown_transport_is_rejected() {
        // A typo like `sctp` must fail loud, not silently fall back to TCP via
        // TransportProtocol::from_str().unwrap_or(Tcp).
        let err = validate_profiles(&cfg_with("fake-tls", "sctp")).unwrap_err();
        assert!(
            err.to_string().contains("unknown bind.transport"),
            "expected an unknown-transport rejection, got: {err}"
        );
    }

    #[test]
    fn unknown_wire_mode_is_rejected() {
        // A typo like `realty-tls` must fail loud, not silently run as fake-tls.
        let err = validate_profiles(&cfg_with("realty-tls", "tcp")).unwrap_err();
        assert!(
            err.to_string().contains("unknown obf.mode"),
            "expected an unknown-mode rejection, got: {err}"
        );
    }

    #[test]
    fn reality_tls_wire_mode_label_is_accepted() {
        // `reality-tls` is a valid server-config label (shipped enabled in
        // server-multiprofile.conf); it must pass the allow-list. It needs a
        // reality_proxy short_id to clear the later REALITY check.
        let mut cfg = cfg_with("reality-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["0123456789abcdef".into()];
        cfg.profiles[0].obfuscation.tls.reality_proxy.real_tls = true;
        assert!(validate_profiles(&cfg).is_ok());

        // …but the label alone is not enough: with reality_proxy off, nothing about REALITY is
        // running and the profile announces the strongest masking the project has while putting
        // plain fake-TLS on the wire. (Audit 2026-08-03, P2.)
        let bare = cfg_with("reality-tls", "tcp");
        let err = validate_profiles(&bare).unwrap_err();
        assert!(
            err.to_string().contains("reality_proxy.enabled is false"),
            "expected the mislabelled profile to be named as such, got: {err}"
        );
    }

    #[test]
    fn fake_tls_is_the_valid_udp_wire_mode() {
        // fake-tls is the only wire mode that also rides UDP (TLS-record-framed
        // datagrams + optional QUIC masking); it must pass validation on UDP.
        assert!(validate_profiles(&cfg_with("fake-tls", "udp")).is_ok());
    }

    #[test]
    fn udp_requires_at_least_one_liveness_or_reaper_signal() {
        let mut dead_forever = cfg_with("fake-tls", "udp");
        dead_forever.profiles[0].obfuscation.heartbeat.enabled = false;
        dead_forever.profiles[0].obfuscation.traffic_shaping.enabled = false;
        dead_forever.profiles[0]
            .performance
            .connection
            .idle_timeout_secs = 0;
        let error = validate_profiles(&dead_forever).unwrap_err();
        assert!(error.to_string().contains("dead sessions"));

        dead_forever.profiles[0]
            .performance
            .connection
            .idle_timeout_secs = 300;
        assert!(validate_profiles(&dead_forever).is_ok());

        dead_forever.profiles[0]
            .performance
            .connection
            .idle_timeout_secs = 0;
        dead_forever.profiles[0].obfuscation.heartbeat.enabled = true;
        assert!(validate_profiles(&dead_forever).is_ok());
    }

    #[test]
    fn tcp_requires_keepalive_when_every_other_reaper_is_disabled() {
        let mut dead_forever = cfg_with("fake-tls", "tcp");
        dead_forever.profiles[0].obfuscation.heartbeat.enabled = false;
        dead_forever.profiles[0].obfuscation.traffic_shaping.enabled = false;
        dead_forever.profiles[0]
            .performance
            .connection
            .idle_timeout_secs = 0;
        dead_forever.profiles[0].performance.tcp.keepalive_secs = 0;
        let error = validate_profiles(&dead_forever).unwrap_err();
        assert!(error.to_string().contains("TCP cannot combine"));

        dead_forever.profiles[0].performance.tcp.keepalive_secs = 60;
        assert!(validate_profiles(&dead_forever).is_ok());

        dead_forever.profiles[0].performance.tcp.keepalive_secs = 0;
        dead_forever.profiles[0]
            .performance
            .connection
            .idle_timeout_secs = 300;
        assert!(validate_profiles(&dead_forever).is_ok());
    }

    #[test]
    fn obfs_wire_mode_requires_obfs_key() {
        // An empty obfs_key derives a publicly-computable constant key (no DPI
        // resistance); validation must fail loud rather than start silently.
        let err = validate_profiles(&cfg_with("obfs", "tcp")).unwrap_err();
        assert!(
            err.to_string().contains("obfs_key"),
            "expected an obfs_key rejection, got: {err}"
        );
    }

    #[test]
    fn obfs_wire_mode_with_key_is_allowed() {
        let mut cfg = cfg_with("obfs", "tcp");
        cfg.profiles[0].obfuscation.obfs_key = "shared-secret".into();
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn ipv6_only_profile_ignores_inactive_ipv4_shadow_fields() {
        let mut cfg = cfg_with("fake-tls", "tcp");
        let profile = &mut cfg.profiles[0];
        profile.tun.ip_mode = crate::config::server::IpMode::Ipv6;
        profile.tun.address = "not-an-ipv4-address".into();
        profile.pool.cidr = "not-an-ipv4-cidr".into();
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        profile.pool.ipv6.cidr = "fd71:e1::/64".into();
        profile.routing.nat.enabled = false;
        profile.routing.forward_private = false;
        validate_profiles(&cfg).expect("inactive IPv4 fields must not block IPv6-only");
    }

    #[test]
    fn ipv6_only_profile_rejects_ipv4_nat44_switch() {
        let mut cfg = cfg_with("fake-tls", "tcp");
        let profile = &mut cfg.profiles[0];
        profile.tun.ip_mode = crate::config::server::IpMode::Ipv6;
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        profile.pool.ipv6.cidr = "fd71:e1::/64".into();
        profile.routing.nat.enabled = true;
        let error = validate_profiles(&cfg).unwrap_err();
        assert!(error.to_string().contains("NAT44"), "wrong reason: {error}");
    }

    #[test]
    fn reality_without_short_ids_is_rejected() {
        // REALITY with no short_id falls back to the trivially-probeable ALPN
        // heuristic — validation must refuse to start it.
        let mut cfg = cfg_with("fake-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec![];
        let err = validate_profiles(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("short_ids"),
            "expected a short_ids rejection, got: {err}"
        );
        // An all-blank list counts as empty too.
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["".into(), "  ".into()];
        assert!(validate_profiles(&cfg).is_err());
    }

    #[test]
    fn reality_with_short_id_is_allowed() {
        let mut cfg = cfg_with("fake-tls", "tcp");
        cfg.profiles[0].obfuscation.tls.reality_proxy.enabled = true;
        cfg.profiles[0].obfuscation.tls.reality_proxy.short_ids = vec!["0123456789abcdef".into()];
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn reality_requires_a_reachable_decoy_endpoint_shape() {
        let mut cfg = cfg_with("fake-tls", "tcp");
        let reality = &mut cfg.profiles[0].obfuscation.tls.reality_proxy;
        reality.enabled = true;
        reality.short_ids = vec!["0123456789abcdef".into()];

        reality.target.clear();
        let err = validate_profiles(&cfg).unwrap_err();
        assert!(err.to_string().contains("reality_proxy.target"));

        cfg.profiles[0].obfuscation.tls.reality_proxy.target = "www.cloudflare.com".into();
        cfg.profiles[0].obfuscation.tls.reality_proxy.target_port = 0;
        let err = validate_profiles(&cfg).unwrap_err();
        assert!(err.to_string().contains("target_port = 0"));

        cfg.profiles[0].obfuscation.tls.reality_proxy.target_port = 443;
        assert!(validate_profiles(&cfg).is_ok());
    }

    #[test]
    fn rate_limiter_allows_up_to_limit_then_blocks() {
        let mut rl = RateLimiter::new(2, 60);
        let addr = ip("203.0.113.7");
        assert!(rl.check_and_record(addr)); // 1st
        assert!(rl.check_and_record(addr)); // 2nd
        assert!(!rl.check_and_record(addr), "3rd attempt must be blocked");
    }

    #[test]
    fn rate_limiter_is_per_ip() {
        let mut rl = RateLimiter::new(1, 60);
        assert!(rl.check_and_record(ip("203.0.113.1")));
        assert!(!rl.check_and_record(ip("203.0.113.1")));
        // a different IP has its own independent budget
        assert!(rl.check_and_record(ip("203.0.113.2")));
    }

    #[test]
    fn failed_auth_tarpits_user_after_max_attempts() {
        let mut t = FailedAuthTracker::new(true, 3, 300, 900);
        let user = "alice";
        let src = ip("198.51.100.5");
        assert!(t.user_tarpit(user).is_zero(), "clean state has no delay");
        for _ in 0..3 {
            t.record_failure(user, src);
        }
        assert!(
            t.user_tarpit(user) > Duration::ZERO,
            "user must be tarpitted after 3 failures"
        );
    }

    #[test]
    fn username_flood_never_hard_blocks_a_clean_ip() {
        // The core L1 guarantee: an attacker spraying a victim's username from
        // many distinct IPs throttles (tarpits) that username, but can NEVER
        // hard-lock the victim out — a clean source IP is always allowed.
        let mut t = FailedAuthTracker::new(true, 3, 300, 900);
        let victim = "alice";
        for i in 0..50u8 {
            t.record_failure(victim, ip(&format!("198.51.100.{}", i)));
        }
        assert!(
            t.user_tarpit(victim) > Duration::ZERO,
            "the sprayed username should be throttled"
        );
        assert!(
            t.check_ip(ip("203.0.113.200")).is_ok(),
            "the victim's own clean IP must never be blocked by a username flood"
        );
    }

    #[test]
    fn failed_auth_success_clears_user_but_not_ip() {
        // Several usernames sprayed from one IP trip the per-IP hard lock; a
        // single good login on one user must not unlock the spraying IP.
        let mut t = FailedAuthTracker::new(true, 3, 300, 900);
        let src = ip("198.51.100.9");
        t.record_failure("u1", src);
        t.record_failure("u2", src);
        t.record_failure("u3", src);
        assert!(t.check_ip(src).is_err(), "IP bucket should be locked");
        t.record_success("u1");
        // u1's tarpit history is cleared, but the IP bucket is intentionally kept
        assert!(
            t.check_ip(src).is_err(),
            "IP must stay locked after one success"
        );
    }

    #[test]
    fn failed_auth_skips_oversized_username_key() {
        // An attacker-supplied username longer than the cap must not be stored,
        // so the tarpit map can't be inflated with huge keys — but the source IP
        // is still counted toward the hard lockout.
        let mut t = FailedAuthTracker::new(true, 3, 300, 900);
        let long_user = "a".repeat(MAX_TRACKED_USERNAME_LEN + 1);
        let src = ip("198.51.100.77");
        for _ in 0..3 {
            t.record_failure(&long_user, src);
        }
        assert!(
            t.by_user.is_empty(),
            "oversized username must never be stored in the tarpit map"
        );
        assert!(
            t.check_ip(src).is_err(),
            "the source IP must still be hard-locked after the failures"
        );
    }

    #[test]
    fn failed_auth_is_isolated_across_ips() {
        let mut t = FailedAuthTracker::new(true, 2, 300, 900);
        let attacker = ip("198.51.100.50");
        t.record_failure("bob", attacker);
        t.record_failure("bob", attacker);
        assert!(t.check_ip(attacker).is_err(), "the abusive IP is locked");
        // a clean IP is unaffected
        assert!(t.check_ip(ip("198.51.100.51")).is_ok());
    }

    #[test]
    fn failed_auth_disabled_never_locks_or_tarpits() {
        // enabled = false → the whole policy is inert for this surface: no lockout,
        // no tarpit, no tracking, regardless of how many failures are recorded.
        let mut t = FailedAuthTracker::new(false, 1, 300, 900);
        let attacker = ip("198.51.100.60");
        for _ in 0..50 {
            assert!(
                !t.record_failure("bob", attacker),
                "a disabled policy never reports a lockout"
            );
            assert!(!t.record_ip_failure(attacker));
        }
        assert!(
            t.check_ip(attacker).is_ok(),
            "a disabled policy never blocks an IP"
        );
        assert!(
            t.user_tarpit("bob").is_zero(),
            "a disabled policy never tarpits"
        );
        assert!(
            t.list_blocked_ips().is_empty(),
            "a disabled policy tracks nothing"
        );
    }

    #[test]
    fn replay_guard_rejects_verbatim_replay() {
        let mut g = ReplayGuard::new(Duration::from_secs(120));
        let sid = [7u8; 32];
        assert!(g.observe(&sid), "first sighting must be fresh");
        assert!(!g.observe(&sid), "a verbatim replay must be rejected");
    }

    #[test]
    fn replay_guard_allows_distinct_tokens() {
        let mut g = ReplayGuard::new(Duration::from_secs(120));
        // Distinct tokens — and genuine reconnects (fresh ephemeral → fresh sid) —
        // are always accepted.
        assert!(g.observe(&[1u8; 32]));
        assert!(g.observe(&[2u8; 32]));
        assert!(g.observe(&[3u8; 32]));
    }

    #[test]
    fn replay_guard_forgets_after_ttl() {
        let ttl = Duration::from_secs(120);
        let mut g = ReplayGuard::new(ttl);
        let t0 = Instant::now();
        let sid = [9u8; 32];
        assert!(g.observe_at(&sid, t0), "first sighting fresh");
        assert!(
            !g.observe_at(&sid, t0 + Duration::from_secs(60)),
            "replay inside the window is rejected"
        );
        // Past the TTL the token is evicted; by then open_session_id's timestamp
        // check rejects it anyway, so a later fresh sighting is correctly accepted.
        assert!(
            g.observe_at(&sid, t0 + ttl + Duration::from_secs(1)),
            "an expired token is forgotten"
        );
    }

    #[test]
    fn replay_guard_evicts_expired_entries() {
        // Memory stays bounded: entries older than the TTL are dropped, not kept.
        let ttl = Duration::from_secs(10);
        let mut g = ReplayGuard::new(ttl);
        let t0 = Instant::now();
        for i in 0..100u32 {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_be_bytes());
            g.observe_at(&sid, t0 + Duration::from_secs(i as u64));
        }
        assert!(
            g.len() <= 11,
            "only entries within the TTL window are retained, got {}",
            g.len()
        );
    }

    #[test]
    fn load_users_db_merges_file_and_inline_file_wins() {
        use crate::config::users::UserEntry;

        // A users file as a panel edit would leave it: u1 restricted to profile "pa".
        let path = std::env::temp_dir().join(format!("qeli-loadusers-{}.conf", std::process::id()));
        let file_db = UsersDb {
            users: vec![UserEntry {
                username: "u1".into(),
                password_hash: "$argon2id$file".into(),
                profiles: vec!["pa".into()],
                ..Default::default()
            }],
            groups: Default::default(),
        };
        file_db.save(&path).unwrap();

        // Config carries inline u1 (unrestricted) + inline-only u2, pointing at the file.
        let mut config = ServerConfig::default();
        config.auth.users_file = path.to_string_lossy().into_owned();
        config.auth.users = vec![
            UserEntry {
                username: "u1".into(),
                password_hash: "$argon2id$inline".into(),
                profiles: vec![],
                ..Default::default()
            },
            UserEntry {
                username: "u2".into(),
                password_hash: "$argon2id$inline2".into(),
                profiles: vec![],
                ..Default::default()
            },
        ];

        let db = load_users_db(&config).unwrap();
        let u1 = db
            .users
            .iter()
            .find(|u| u.username == "u1")
            .expect("u1 present");
        // The FILE copy wins → a panel edit to allowed-profiles applies even with
        // inline users in the config (the reported bug).
        assert_eq!(u1.profiles, vec!["pa".to_string()]);
        assert_eq!(u1.password_hash, "$argon2id$file");
        // Inline-only users are still merged in.
        assert!(
            db.users.iter().any(|u| u.username == "u2"),
            "inline-only u2 must be merged"
        );
        assert_eq!(db.users.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_db_inline_only_when_file_absent() {
        use crate::config::users::UserEntry;
        let missing = std::env::temp_dir().join(format!("qeli-none-{}.conf", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let mut config = ServerConfig::default();
        config.auth.users_file = missing.to_string_lossy().into_owned();
        config.auth.users = vec![UserEntry {
            username: "solo".into(),
            password_hash: "$argon2id$x".into(),
            ..Default::default()
        }];
        // Missing file + inline present → inline loads (no error).
        let db = load_users_db(&config).unwrap();
        assert_eq!(db.users.len(), 1);
        assert_eq!(db.users[0].username, "solo");
    }

    #[test]
    fn runtime_users_loader_allows_only_a_truly_missing_first_run_file() {
        let path =
            std::env::temp_dir().join(format!("qeli-runtime-users-{}.conf", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut config = ServerConfig::default();
        config.auth.users_file = path.to_string_lossy().into_owned();
        assert!(load_users_db(&config).is_err());
        assert!(load_users_db_for_runtime(&config)
            .expect("missing first-run file must become an empty database")
            .users
            .is_empty());

        std::fs::write(
            &path,
            "[user:alice]\npassword_hash = x\nmax_sessions = invalid\n",
        )
        .unwrap();
        assert!(
            load_users_db_for_runtime(&config).is_err(),
            "an existing malformed file must never collapse to an empty ACL"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn static_user_addresses_and_profile_reservations_are_validated_together() {
        use crate::config::server::{IpMode, ProfileConfig};
        use crate::config::users::UserEntry;

        let mut profile = ProfileConfig::baseline();
        profile.name = "edge".into();
        profile.tun.ip_mode = IpMode::Dual;
        profile.tun.ipv6_address = Some("fd71:e1:1234:1::1".into());
        profile.pool.ipv6.cidr = "fd71:e1:1234:1::/64".into();
        profile
            .pool
            .static_reservations
            .insert("alice".into(), "10.9.0.50".into());
        profile
            .pool
            .static_reservations
            .insert("bob".into(), "10.9.0.51".into());
        profile
            .pool
            .ipv6
            .static_reservations
            .insert("alice".into(), "fd71:e1:1234:1::50".into());
        profile
            .pool
            .ipv6
            .static_reservations
            .insert("bob".into(), "fd71:e1:1234:1::51".into());
        let config = ServerConfig {
            profiles: vec![profile],
            ..Default::default()
        };

        let same_owner_same_address = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                enabled: true,
                static_ip: Some("10.9.0.50".into()),
                static_ipv6: Some("fd71:e1:1234:1::50".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        validate_static_address_sources(&config, &same_owner_same_address)
            .expect("the two sources may repeat the same assignment");

        let overrides_own_reservation = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                enabled: true,
                static_ip: Some("10.9.0.60".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &overrides_own_reservation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("silently override"), "{error}");

        let steals_another_reservation = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                enabled: true,
                static_ipv6: Some("fd71:e1:1234:1::51".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &steals_another_reservation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("reservation.bob"), "{error}");

        let mut restricted = steals_another_reservation;
        restricted.users[0].profiles = vec!["other-profile".into()];
        validate_static_address_sources(&config, &restricted)
            .expect("a user forbidden on this profile cannot consume its reservations");

        let duplicate_ipv4 = UsersDb {
            users: vec![
                UserEntry {
                    username: "charlie".into(),
                    enabled: true,
                    static_ip: Some("10.9.0.80".into()),
                    ..Default::default()
                },
                UserEntry {
                    username: "dave".into(),
                    enabled: true,
                    static_ip: Some("10.9.0.80".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &duplicate_ipv4)
            .unwrap_err()
            .to_string();
        assert!(error.contains("both request static_ip"), "{error}");

        let duplicate_ipv6 = UsersDb {
            users: vec![
                UserEntry {
                    username: "charlie".into(),
                    enabled: true,
                    static_ipv6: Some("fd71:e1:1234:1::80".into()),
                    ..Default::default()
                },
                UserEntry {
                    username: "dave".into(),
                    enabled: true,
                    static_ipv6: Some("fd71:e1:1234:1::80".into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &duplicate_ipv6)
            .unwrap_err()
            .to_string();
        assert!(error.contains("both request static_ipv6"), "{error}");

        let outside_pool = UsersDb {
            users: vec![UserEntry {
                username: "charlie".into(),
                enabled: true,
                static_ip: Some("10.10.0.7".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &outside_pool)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not assignable in pool.cidr"), "{error}");

        let outside_ipv6_pool = UsersDb {
            users: vec![UserEntry {
                username: "charlie".into(),
                enabled: true,
                static_ipv6: Some("fd71:e1:9999::7".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = validate_static_address_sources(&config, &outside_ipv6_pool)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("not assignable in pool.ipv6.cidr"),
            "{error}"
        );

        let mut excluded_config = config.clone();
        excluded_config.profiles[0]
            .pool
            .exclude
            .push("10.9.0.70".into());
        excluded_config.profiles[0]
            .pool
            .ipv6
            .exclude
            .push("fd71:e1:1234:1::70".into());
        let excluded = UsersDb {
            users: vec![UserEntry {
                username: "charlie".into(),
                enabled: true,
                static_ip: Some("10.9.0.70".into()),
                static_ipv6: Some("fd71:e1:1234:1::70".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let error = validate_static_address_sources(&excluded_config, &excluded)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pool.exclude"), "{error}");
    }
}
