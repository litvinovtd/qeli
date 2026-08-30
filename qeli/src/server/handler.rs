use crate::crypto::{
    build_server_auth_message, derive_keys, derive_keys_bound, derive_keys_hybrid,
    derive_keys_hybrid_bound, handshake_transcript_hash, Keypair,
};
#[cfg(feature = "experimental-roaming")]
use crate::crypto::{
    derive_session_material, derive_session_material_bound, derive_session_material_hybrid,
    derive_session_material_hybrid_bound,
};
use crate::protocol::obfs::SplitStream;
use crate::protocol::{
    read_record, read_record_into, read_tls_record, FakeTlsHandshake, Framing, Obfuscator,
    PacketCodec,
};
use crate::server::{
    lock_or_recover, ExitAccess, ProfileRuntime, ServerState, ServerTunPacket, TunIngress,
};
use crate::transport_core::buffer_pool::{BufferPool, PooledBuffer};
#[cfg(feature = "experimental-roaming")]
use crate::transport_core::tcp_roaming::{
    CommitOutcome, DetachOutcome, DetachReason, LifecycleError, OrphanLimiter, ReapTicket,
    ResumeReservation, SessionLifecycle,
};
use rand::prelude::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

#[cfg(feature = "experimental-roaming")]
type HandshakeResumeSecret = zeroize::Zeroizing<[u8; 32]>;
#[cfg(not(feature = "experimental-roaming"))]
type HandshakeResumeSecret = ();

/// Default fallback heartbeat interval when none is configured.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 30_000;
#[cfg(feature = "experimental-roaming")]
const TCP_RESUME_COMMIT_TIMEOUT: Duration =
    Duration::from_secs(crate::protocol::roaming::TCP_RESUME_SERVER_COMMIT_TIMEOUT_SECS);

/// Per-session encrypted-record budget for server→client traffic. The pool is shared by
/// every bonded stream, so multipath cannot multiply queued memory by its stream count.
const SERVER_WIRE_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const SERVER_WIRE_RECORD_OVERHEAD: usize = crate::protocol::packet::TLS_RECORD_HEADER
    + crate::protocol::packet::NONCE_SIZE
    + crate::protocol::packet::COUNTER_SIZE
    + crate::protocol::packet::TAG_SIZE
    + 2;

/// Size a server-owned outbound record for what this profile can actually emit. A 1400-byte
/// TUN must not reserve the protocol's ~16 KiB absolute receive ceiling for every queued packet:
/// doing that reduced a 4 MiB pool to 251 records (about 5 ms at lab throughput) and caused
/// avoidable inner-TCP retransmits. Cover and heartbeat maxima participate because UDP uses the
/// same pool for them. The absolute wire ceiling remains unchanged.
pub(crate) fn server_wire_buffer_capacity(pcfg: &crate::config::server::ProfileConfig) -> usize {
    let mtu = usize::try_from(pcfg.tun.mtu)
        .unwrap_or(crate::protocol::packet::MAX_TUNNEL_MTU)
        .clamp(1, crate::protocol::packet::MAX_TUNNEL_MTU);
    let heartbeat = usize::from(pcfg.obfuscation.heartbeat.data_size_bytes).saturating_add(32);
    let cover = usize::from(pcfg.obfuscation.traffic_shaping.max_size);
    let inner_budget = mtu
        .max(heartbeat)
        .max(cover)
        .min(crate::protocol::packet::MAX_TUNNEL_MTU);
    SERVER_WIRE_RECORD_OVERHEAD + inner_budget
}

pub(crate) fn server_wire_pool(
    pcfg: &crate::config::server::ProfileConfig,
) -> std::io::Result<BufferPool> {
    let buffer_capacity = server_wire_buffer_capacity(pcfg);
    BufferPool::new(SERVER_WIRE_BUFFER_BYTES / buffer_capacity, buffer_capacity)
}

// Stream-bonding wire constants live in `crate::protocol` (shared with the
// client); re-export here so existing `server::handler::JOIN_*` paths still work.
pub use crate::protocol::{DEVICE_ID_LEN, JOIN_MAGIC, JOIN_TOKEN_LEN};

/// Token-bucket rate limiter shared by ALL bonded streams of one session.
///
/// The cap MUST be enforced on the aggregate: the old per-stream sleep let each
/// of N multipath streams throttle itself independently, so a client got ~N× its
/// limit. This bucket lives on [`SessionShared`] and is consumed by every stream's
/// writer (TCP) and the single UDP writer alike. `consume` carries a deficit
/// (tokens can go negative) so bursts still average to `limit_mbps` over time.
pub struct RateBucket {
    state: std::sync::Mutex<RateState>,
}

/// Independent aggregate upload/download budgets for one logical session.
///
/// A single shared bucket would cap the sum of both directions. A per-user
/// `limit_mbps` instead applies to each direction concurrently, while every
/// bonded stream in that direction still shares one aggregate allowance.
#[derive(Clone)]
pub struct DirectionalRateBuckets {
    pub upload: Arc<RateBucket>,
    pub download: Arc<RateBucket>,
}

impl Default for DirectionalRateBuckets {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectionalRateBuckets {
    pub fn new() -> Self {
        Self {
            upload: Arc::new(RateBucket::new()),
            download: Arc::new(RateBucket::new()),
        }
    }
}

struct RateState {
    /// Available send budget in bits (may be negative — a carried deficit).
    tokens: f64,
    last: Instant,
}

impl Default for RateBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl RateBucket {
    pub fn new() -> Self {
        RateBucket {
            state: std::sync::Mutex::new(RateState {
                tokens: 0.0,
                last: Instant::now(),
            }),
        }
    }

    /// Account `bits` against a `limit_mbps` cap (0 = unlimited → no delay) and
    /// return how long to sleep before sending. Token accumulation is capped at one
    /// second so an idle session can't bank an unbounded burst; the returned sleep
    /// is capped at one second purely as a guard against a degenerate tiny limit
    /// (a single ≤16 KB record at the 1 Mbps minimum needs only ~130 ms).
    pub fn consume(&self, bits: u64, limit_mbps: u32) -> Duration {
        if limit_mbps == 0 {
            return Duration::ZERO;
        }
        let limit_bps = limit_mbps as f64 * 1_000_000.0;
        let mut s = lock_or_recover(&self.state, "RateBucket::consume");
        let now = Instant::now();
        let refill = now.duration_since(s.last).as_secs_f64() * limit_bps;
        s.tokens = (s.tokens + refill).min(limit_bps);
        s.last = now;
        s.tokens -= bits as f64;
        if s.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((-s.tokens / limit_bps).min(1.0))
        }
    }
}

/// (plaintext writer-channel, shared bounded pool) selected for an outgoing flow.
pub(crate) type StreamPick = (mpsc::Sender<PooledBuffer>, BufferPool);

/// One bonded connection within a [`SessionShared`]. Each stream has its own
/// independent crypto (its connection did its own key exchange) and its own write
/// channel; outgoing packets are striped across streams round-robin.
pub struct StreamHandle {
    /// Stable protocol slot.  The transport id changes on handover; this id does not.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) logical_slot_id: u32,
    /// Scheduler visibility, mutated only while the session's `streams` lock is held.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) ready: bool,
    pub stream_id: u64,
    pub codec: Arc<std::sync::Mutex<PacketCodec>>,
    pub(crate) writer: mpsc::Sender<PooledBuffer>,
    pub kick_tx: mpsc::Sender<()>,
    /// Stops the READER half. `kick_tx` only reaches the writer, so a kicked or
    /// superseded client kept uploading into the TUN until it chose to close the
    /// socket — and the reaper tasks that would have timed it out live in the
    /// writer loop, so nothing bounded it either. Worse after the IP is handed to
    /// the next client: the stale reader keeps injecting packets sourced as an
    /// address that now belongs to someone else.
    ///
    /// `watch` rather than a oneshot/Notify because its value persists: a shutdown
    /// raised before the reader parks is still observed, so there is no lost-wakeup
    /// race with a client that is mid-`read_record`.
    pub shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[cfg(feature = "experimental-roaming")]
pub(crate) struct TcpRoamingSession {
    lifecycle: std::sync::Mutex<SessionLifecycle>,
    resume_secret: zeroize::Zeroizing<[u8; 32]>,
    limiter: Arc<std::sync::Mutex<OrphanLimiter>>,
    initial_transport_attached: std::sync::atomic::AtomicBool,
    retained_bytes: usize,
    handover_enabled: bool,
}
#[cfg(feature = "experimental-roaming")]
#[derive(Clone, Copy)]
struct TcpRoamingPolicy {
    grace: Duration,
    handover_enabled: bool,
}

#[cfg(feature = "experimental-roaming")]
impl TcpRoamingSession {
    fn new(
        session_id: u64,
        locator: [u8; crate::protocol::roaming::SESSION_LOCATOR_LEN],
        max_slots: u32,
        primary_transport: u64,
        resume_secret: HandshakeResumeSecret,
        limiter: Arc<std::sync::Mutex<OrphanLimiter>>,
        policy: TcpRoamingPolicy,
    ) -> Result<Self, LifecycleError> {
        Ok(Self {
            lifecycle: std::sync::Mutex::new(SessionLifecycle::new(
                session_id,
                locator,
                max_slots,
                policy.grace,
                primary_transport,
            )?),
            resume_secret,
            limiter,
            initial_transport_attached: std::sync::atomic::AtomicBool::new(false),
            // The fixed encrypted-record pool dominates retained session memory and is shared
            // by all streams.  Count the complete allocation, not only currently checked-out
            // records, so the profile-wide byte cap is conservative and deterministic.
            retained_bytes: SERVER_WIRE_BUFFER_BYTES,
            handover_enabled: policy.handover_enabled,
        })
    }

    fn mark_initial_transport_attached(&self) {
        self.initial_transport_attached
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn begin_resume(
        &self,
        join: &crate::protocol::roaming::TcpResumeJoin,
        transcript_hash: &[u8; 32],
    ) -> Result<ResumeReservation, LifecycleError> {
        if !self
            .initial_transport_attached
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(LifecycleError::InitialTransportPending);
        }
        if join.input().is_handover() && !self.handover_enabled {
            return Err(LifecycleError::HandoverNotNegotiated);
        }
        lock_or_recover(&self.lifecycle, "TcpRoamingSession::begin_resume").begin_resume(
            join,
            transcript_hash,
            &self.resume_secret,
        )
    }

    fn commit_resume(
        &self,
        reservation: ResumeReservation,
        transport_id: u64,
    ) -> Result<CommitOutcome, LifecycleError> {
        let mut lifecycle = lock_or_recover(&self.lifecycle, "TcpRoamingSession::commit_resume");
        let mut limiter = lock_or_recover(&self.limiter, "TcpRoamingSession::commit_limiter");
        lifecycle.commit_resume(reservation, transport_id, &mut limiter)
    }

    fn abort_resume(&self, reservation: ResumeReservation) {
        let _ = lock_or_recover(&self.lifecycle, "TcpRoamingSession::abort_resume")
            .abort_resume(reservation);
    }

    fn detach(
        &self,
        transport_id: u64,
        reason: DetachReason,
        now: Instant,
    ) -> Result<DetachOutcome, LifecycleError> {
        let mut lifecycle = lock_or_recover(&self.lifecycle, "TcpRoamingSession::detach");
        let mut limiter = lock_or_recover(&self.limiter, "TcpRoamingSession::detach_limiter");
        lifecycle.detach(transport_id, reason, now, self.retained_bytes, &mut limiter)
    }

    fn reap(&self, ticket: ReapTicket, now: Instant) -> bool {
        let mut lifecycle = lock_or_recover(&self.lifecycle, "TcpRoamingSession::reap");
        let mut limiter = lock_or_recover(&self.limiter, "TcpRoamingSession::reap_limiter");
        lifecycle.reap(ticket, now, &mut limiter)
    }

    fn revoke(&self) {
        let mut lifecycle = lock_or_recover(&self.lifecycle, "TcpRoamingSession::revoke");
        let mut limiter = lock_or_recover(&self.limiter, "TcpRoamingSession::revoke_limiter");
        lifecycle.revoke(&mut limiter);
    }

    fn close(&self) {
        let mut lifecycle = lock_or_recover(&self.lifecycle, "TcpRoamingSession::close");
        let mut limiter = lock_or_recover(&self.limiter, "TcpRoamingSession::close_limiter");
        lifecycle.close(&mut limiter);
    }
}

/// A client tunnel session, aggregating one or more bonded connections (streams)
/// behind ONE tun IP. With multipath off there is exactly one stream (identical
/// behaviour to the old single-connection model).
/// Decide the MTU the downlink must respect, given what a client reported (`0` = nothing)
/// and the profile's `tun.mtu`.
///
/// `None` means "nothing to enforce" and the caller skips the check entirely, so the hot path
/// is untouched for a client that never reported. Split out from
/// [`SessionShared::downlink_mtu`] so the policy is testable without building a session.
pub fn downlink_mtu_for(reported: u32, profile_mtu: i32) -> Option<u16> {
    if reported == 0 {
        return None;
    }
    let profile = u32::try_from(profile_mtu).unwrap_or(0);
    // A profile MTU of 0 or negative is not a real ceiling (it means "unset"), so a report
    // stands on its own there rather than being compared against nonsense.
    if profile != 0 && reported >= profile {
        return None;
    }
    u16::try_from(reported).ok()
}

/// Apply the address-family floor to a client-reported downlink MTU.
///
/// The control frame is shared by IPv4 and IPv6, so its parser deliberately accepts the IPv4
/// minimum of 576.  That value must never become an IPv6 next-hop MTU: IPv6 links are required
/// to expose at least 1280 bytes, and advertising anything smaller in Packet Too Big creates an
/// invalid PMTU state.  Keep the original IPv4 policy while making the packet family explicit at
/// the only point where it is known.
pub fn downlink_mtu_for_packet(
    reported: u32,
    profile_mtu: i32,
    version: crate::protocol::ip::IpVersion,
) -> Option<u16> {
    downlink_mtu_for(reported, profile_mtu).map(|mtu| match version {
        crate::protocol::ip::IpVersion::V4 => mtu,
        crate::protocol::ip::IpVersion::V6 => mtu.max(1280),
    })
}

/// Store a client-reported tunnel MTU, logging only when it actually changes.
///
/// A client sends its report once per session, but a reconnect or a re-probe can repeat it,
/// and a peer is free to send it as often as it likes — so the log is edge-triggered rather
/// than one line per frame. Shared by both transports: the TCP reader has the session in
/// hand, the UDP reader only the mirrored cell and the peer address.
pub fn note_path_mtu(cell: &AtomicU32, who: std::fmt::Arguments<'_>, mtu: u16) {
    let prev = cell.swap(u32::from(mtu), Ordering::Relaxed);
    if prev != u32::from(mtu) {
        if prev == 0 {
            log::info!("client {who} reported tunnel MTU {mtu}");
        } else {
            log::info!("client {who} reported tunnel MTU {mtu} (was {prev})");
        }
    }
}

/// Where a session's self-reported `(version, platform)` lives. Shared with the UDP data
/// plane, which holds the cell without holding the session.
pub type ClientInfoCell = Arc<std::sync::Mutex<Option<(String, String)>>>;

/// Record what a client says it is (see [`SessionShared::client_info`]). Logged once per
/// change — an operator watching a fleet upgrade wants that line, but a client that
/// resends the frame every reconnect-in-place must not spam the log.
///
/// `version` and `platform` MUST have come from [`crate::protocol::ctrl::parse_client_info`],
/// which is what guarantees they carry no control characters and cannot forge a log line.
pub fn note_client_info(
    cell: &std::sync::Mutex<Option<(String, String)>>,
    who: std::fmt::Arguments<'_>,
    version: &str,
    platform: &str,
) {
    let mut slot = lock_or_recover(cell, "note_client_info");
    let next = (version.to_string(), platform.to_string());
    if slot.as_ref() == Some(&next) {
        return;
    }
    log::info!("client {who} reports qeli {version} on {platform}");
    *slot = Some(next);
}

pub struct SessionShared {
    pub session_id: u64,
    pub username: String,
    /// Per-device key (`username:hex(device_id)` or just `username`). Sessions are
    /// superseded by this, so multiple devices of one login coexist while the same
    /// device cleanly replaces its own old session on reconnect.
    pub device_key: String,
    /// Stable primary address used as the unique session-map key (IPv4 for dual stack,
    /// otherwise the only assigned family).
    pub client_ip: std::net::IpAddr,
    pub client_ipv4: Option<std::net::Ipv4Addr>,
    pub client_ipv6: Option<std::net::Ipv6Addr>,
    /// Source address of the PRIMARY (auth) connection — shown in list-clients.
    pub peer: SocketAddr,
    pub token: [u8; JOIN_TOKEN_LEN],
    pub max_streams: u32,
    /// Fixed-budget encrypted-record storage shared by every bonded writer in this session.
    /// A checked-out allocation returns here only after the socket writer drops it.
    pub(crate) wire_pool: BufferPool,
    /// Active bonded streams; outgoing traffic is flow-pinned across them
    /// (see [`SessionShared::pick_stream`]).
    pub streams: std::sync::Mutex<Vec<StreamHandle>>,
    /// Present only after authenticated capability negotiation in an experimental build.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) tcp_roaming: Option<TcpRoamingSession>,
    /// True only after authenticated bidirectional CONTROL_V2 negotiation on a TCP session.
    #[cfg(feature = "experimental-roaming")]
    pub(crate) tcp_control_v2: bool,
    pub connected_at: Instant,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    /// Outbound packets dropped because the client writer channel was full — i.e.
    /// rate-limit / slow-client backpressure. Surfaced in `list-clients` so the
    /// loss is observable instead of silent.
    pub dropped: Arc<AtomicU64>,
    pub bandwidth_limit_mbps: Arc<AtomicU32>,
    /// Independent aggregate (all-streams) upload/download token buckets. Each
    /// direction enforces `bandwidth_limit_mbps` across the whole session, not
    /// per stream, without consuming the other direction's allowance.
    pub rates: DirectionalRateBuckets,
    /// Aggregate server→client cover budget shared by all bonded TCP writers.
    pub(crate) cover_budget: crate::protocol::SharedCoverBudget,
    /// Effective mux configuration after authenticated PACKET_MUX_V1 negotiation.
    pub(crate) recordizer: Option<crate::config::RecordizerConfig>,

    /// Compiled `allowed_networks` (user's own, else the group's) — the destination
    /// ACL applied to every inner packet before it reaches the TUN. Empty =
    /// unrestricted, which is the documented default and costs nothing per packet.
    pub dst_acl: crate::server::acl::DstAcl,
    /// Which SOURCE addresses this session may claim (own IP + its iroute
    /// subnets). Without it an authenticated client could forge any source and
    /// walk past `client_to_client = false`.
    pub src_guard: crate::server::acl::SrcGuard,
    /// Per-family permission to use a registered client `/0` exit. Derived from this
    /// session's effective pushed routes, so the documented per-user `route = .../0`
    /// actually acts as authorization rather than a cosmetic config line.
    pub(crate) exit_access: ExitAccess,
    /// Tunnel MTU the client reported after probing its path, or 0 when it never told us
    /// (every pre-#13 client, and any client with probing off).
    ///
    /// The client discovers this AFTER the handshake and sends it as an in-tunnel control
    /// frame (see [`crate::protocol::ctrl`]). Without it the server sizes the downlink by
    /// the profile's `tun.mtu` alone, so on a path narrower than the profile every large
    /// packet we forward is dropped somewhere downstream with no signal — the connection
    /// establishes and then stalls on the first big transfer. 0 keeps the old behaviour
    /// exactly, which is what an old client must get. (Audit 2026-07-30, #13.)
    pub path_mtu: Arc<AtomicU32>,
    /// Set once this session has been revoked (kick, quota cut-off, supersede).
    ///
    /// The UDP data plane demultiplexes ingress from a PER-WORKER
    /// `HashMap<SocketAddr, UdpClient>`, while every control action operates on
    /// `profile.sessions.by_ip`. Those are two different registries, and nothing
    /// connected them: `kick_all` reached only the writer task, because the UDP
    /// `shutdown_tx` is a `watch` channel with no receiver by construction. So a kicked
    /// or over-quota client stopped RECEIVING but kept injecting packets into the TUN
    /// until the reaper expired it 30-45 s later — with its pool IP already released and
    /// possibly reassigned to somebody else, which defeats `client_to_client = false`
    /// and misattributes traffic in NAT and the logs. This flag is the missing link: it
    /// lives in the session both registries point at, `kick_all` raises it, and the UDP
    /// receive loop drops (and forgets) the peer the moment it sees it.
    /// (Audit 2026-07-27, A1/A2/A3.)
    pub revoked: Arc<std::sync::atomic::AtomicBool>,
    /// Set by authenticated CLOSE_SESSION before the bonded stream tasks are stopped. Unlike
    /// revocation this is an orderly terminal state and must never enter roaming grace.
    pub closing: Arc<std::sync::atomic::AtomicBool>,
    /// `(version, platform)` the client reported about itself over the tunnel, so
    /// `list-clients` and the panel can answer "which build is this session running?".
    /// `None` for every client that predates the report, and for anything that failed
    /// validation.
    ///
    /// SELF-REPORTED. Validated for shape only (see [`crate::protocol::ctrl`]); it is a
    /// label for the operator, never an input to any decision about the session.
    ///
    /// `Arc` for the same reason as [`Self::path_mtu`]: the UDP data plane holds the cell
    /// directly on its per-worker `UdpClient` and never has the session in hand.
    pub client_info: ClientInfoCell,
}

impl SessionShared {
    pub fn assigned_addresses(&self) -> impl Iterator<Item = std::net::IpAddr> + '_ {
        self.client_ipv4
            .map(std::net::IpAddr::V4)
            .into_iter()
            .chain(self.client_ipv6.map(std::net::IpAddr::V6))
    }

    /// The MTU the downlink to this client must respect: the profile's `tun.mtu` narrowed
    /// by whatever the client reported, if anything.
    ///
    /// Returns `None` when there is nothing to enforce — no report, or a report that is not
    /// narrower than the profile — so the hot path can skip the check entirely and behave
    /// bit-for-bit as it did before #13.
    pub fn downlink_mtu(
        &self,
        profile_mtu: i32,
        version: crate::protocol::ip::IpVersion,
    ) -> Option<u16> {
        downlink_mtu_for_packet(self.path_mtu.load(Ordering::Relaxed), profile_mtu, version)
    }

    /// Record a client's reported tunnel MTU (see [`note_path_mtu`]).
    pub fn note_path_mtu(&self, mtu: u16) {
        note_path_mtu(
            &self.path_mtu,
            format_args!(
                "'{}' ({})",
                crate::util::log_identity(&self.username),
                self.client_ip
            ),
            mtu,
        );
    }

    /// Record what this client says it is (see [`note_client_info`]).
    pub fn note_client_info(&self, version: &str, platform: &str) {
        note_client_info(
            &self.client_info,
            format_args!(
                "'{}' ({})",
                crate::util::log_identity(&self.username),
                self.client_ip
            ),
            version,
            platform,
        );
    }

    /// `(version, platform)` as reported, for the control socket. See [`note_client_info`].
    pub fn reported_client(&self) -> Option<(String, String)> {
        lock_or_recover(&self.client_info, "reported_client").clone()
    }

    /// Pick the (codec, writer, record pool) of the bonded stream this packet's flow is pinned
    /// to (`flow_hash`). Pinning a flow to one stream keeps that inner connection's
    /// packets ordered (round-robin striping reordered them); returns `None` only
    /// if every stream has detached (session is dying).
    pub(crate) fn pick_stream(&self, flow_hash: u64) -> Option<StreamPick> {
        let streams = lock_or_recover(&self.streams, "pick_stream");
        #[cfg(feature = "experimental-roaming")]
        if self.tcp_roaming.is_some() {
            let ready = streams.iter().filter(|stream| stream.ready);
            let ready_count = ready.clone().count();
            if ready_count == 0 {
                return None;
            }
            let width = self.max_streams.max(1);
            let desired = (flow_hash % u64::from(width)) as u32;
            let selected = streams
                .iter()
                .filter(|stream| stream.ready)
                .find(|stream| stream.logical_slot_id == desired)
                .or_else(|| {
                    // Walk clockwise through stable slot ids. Adding/removing another slot does
                    // not renumber the survivors, so only flows owned by an unavailable slot move.
                    streams
                        .iter()
                        .filter(|stream| stream.ready)
                        .min_by_key(|stream| {
                            let slot = stream.logical_slot_id % width;
                            (slot + width - desired) % width
                        })
                })?;
            return Some((selected.writer.clone(), self.wire_pool.clone()));
        }

        // Preserve the exact legacy scheduler for normal and feature-disabled sessions. Merely
        // compiling roaming support must not alter stream selection for existing clients.
        if streams.is_empty() {
            return None;
        }
        let i = (flow_hash % streams.len() as u64) as usize;
        Some((streams[i].writer.clone(), self.wire_pool.clone()))
    }

    /// All streams' kick channels (used by control-plane kick / supersede).
    ///
    /// Also raises `revoked`, which is what actually stops the UDP INGRESS — the stream
    /// handles below only cover the TCP reader and the (UDP or TCP) writer. See the
    /// `revoked` field for why the two paths need separate treatment.
    pub fn kick_all(&self) {
        // Serialize revocation with try_add_stream. Whichever operation obtains the streams
        // lock first wins: an already-attached stream is kicked, while a later JOIN observes
        // revoked=true and is rejected. There is no window in which a stream can attach after
        // the kick snapshot and escape both mechanisms.
        let streams = lock_or_recover(&self.streams, "kick_all");
        self.revoked
            .store(true, std::sync::atomic::Ordering::Release);
        for s in streams.iter() {
            let _ = s.kick_tx.try_send(());
            // ...and the reader, which kick_tx never reached.
            let _ = s.shutdown_tx.send(true);
        }
        drop(streams);
        #[cfg(feature = "experimental-roaming")]
        if let Some(roaming) = &self.tcp_roaming {
            roaming.revoke();
        }
    }

    /// Orderly session shutdown requested by the authenticated peer. Publish the terminal flag
    /// before stopping streams so concurrent JOIN/resume admission fails closed and every detach
    /// observes CleanClose rather than incorrectly entering orphan grace.
    #[cfg(feature = "experimental-roaming")]
    fn close_all(&self) {
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
        #[cfg(feature = "experimental-roaming")]
        if let Some(roaming) = &self.tcp_roaming {
            roaming.close();
        }
        let streams = lock_or_recover(&self.streams, "close_all");
        for stream in streams.iter() {
            let _ = stream.kick_tx.try_send(());
            let _ = stream.shutdown_tx.send(true);
        }
    }

    /// True once this session has been kicked / cut off / superseded.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(feature = "experimental-roaming")]
    fn is_closing(&self) -> bool {
        self.closing.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Atomically attach a stream iff the session is live and under its `max_streams` cap.
    /// Revocation, the length check and the push are serialized by the same lock, so neither
    /// a concurrent kick nor N concurrent JOINs can race past the decision.
    fn try_add_stream(&self, h: StreamHandle, authenticated_resume_overflow: bool) -> bool {
        let mut streams = lock_or_recover(&self.streams, "try_add_stream");
        // An authenticated resume gets one temporary candidate above max_streams even without
        // make-before-break negotiation: after an asymmetric failure the server can still hold
        // the dead old carrier. SessionLifecycle::ResumeBusy bounds the overflow to one, and
        // commit immediately drains the obsolete carrier occupying the same stable slot.
        let limit = self.max_streams as usize + usize::from(authenticated_resume_overflow);
        if self.revoked.load(std::sync::atomic::Ordering::Acquire)
            || self.closing.load(std::sync::atomic::Ordering::Acquire)
            || streams.len() >= limit
        {
            return false;
        }
        streams.push(h);
        true
    }

    #[cfg(feature = "experimental-roaming")]
    fn activate_resume_stream(&self, new_transport: u64, outcome: CommitOutcome) {
        let mut streams = lock_or_recover(&self.streams, "activate_resume_stream");
        if self.revoked.load(std::sync::atomic::Ordering::Acquire)
            || self.closing.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }

        for stream in streams.iter_mut() {
            if stream.stream_id == new_transport {
                stream.ready = true;
            }
            if Some(stream.stream_id) == outcome.drain_transport {
                stream.ready = false;
                let _ = stream.kick_tx.try_send(());
                let _ = stream.shutdown_tx.send(true);
            }
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn begin_tcp_resume(
        &self,
        join: &crate::protocol::roaming::TcpResumeJoin,
        transcript_hash: &[u8; 32],
    ) -> Result<ResumeReservation, LifecycleError> {
        self.tcp_roaming
            .as_ref()
            .ok_or(LifecycleError::Terminal)?
            .begin_resume(join, transcript_hash)
    }

    /// Remove a stream by id; returns true if NO streams remain (session empty).
    fn remove_stream(&self, stream_id: u64) -> bool {
        let mut streams = lock_or_recover(&self.streams, "remove_stream");
        streams.retain(|s| s.stream_id != stream_id);
        streams.is_empty()
    }

    /// Active bonded streams (1 = single-link). Used by the panel clients view.
    pub fn stream_count(&self) -> usize {
        lock_or_recover(&self.streams, "stream_count").len()
    }
}

/// First post-handshake client message: AUTH (primary connection) or JOIN (a
/// secondary bonded stream presenting the session token).
enum FirstMessage {
    Auth {
        proof: [u8; 32],
        username: String,
        password: String,
        /// Stable per-device id (None = old client without one).
        device_id: Option<[u8; DEVICE_ID_LEN]>,
        /// Present only when this server advertised the authenticated extension.
        capabilities: Option<crate::protocol::capabilities::ClientCapabilities>,
    },
    Join {
        token: [u8; JOIN_TOKEN_LEN],
        stream_index: u8,
    },
    #[cfg(feature = "experimental-roaming")]
    Resume {
        join: crate::protocol::roaming::TcpResumeJoin,
    },
}

#[derive(Clone, Copy)]
enum StreamAttach {
    Primary,
    LegacyJoin {
        logical_slot_id: u32,
    },
    #[cfg(feature = "experimental-roaming")]
    Resume {
        reservation: ResumeReservation,
    },
}

impl StreamAttach {
    #[cfg(feature = "experimental-roaming")]
    fn logical_slot_id(self) -> u32 {
        match self {
            Self::Primary => 0,
            Self::LegacyJoin { logical_slot_id } => logical_slot_id,
            #[cfg(feature = "experimental-roaming")]
            Self::Resume { reservation } => reservation.logical_slot_id(),
        }
    }

    #[cfg(feature = "experimental-roaming")]
    fn initially_ready(self) -> bool {
        #[cfg(feature = "experimental-roaming")]
        if matches!(self, Self::Resume { .. }) {
            return false;
        }
        true
    }

    fn authenticated_resume_overflow(self) -> bool {
        match self {
            #[cfg(feature = "experimental-roaming")]
            Self::Resume { .. } => true,
            _ => false,
        }
    }
}

pub(crate) async fn handle_client<S>(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    stream: S,
    addr: SocketAddr,
    tun_tx: TunIngress,
    pre_auth_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + SplitStream,
{
    handle_client_inner(
        server_state,
        profile,
        stream,
        addr,
        tun_tx,
        pre_auth_permit,
        false,
    )
    .await
}

/// Handle a new maximum-stealth REALITY connection. The outer TLS + genuine
/// HTTP/2 carrier already supplies public framing, so the inner qeli exchange
/// uses raw records and cannot create a second fake-TLS fingerprint.
pub(crate) async fn handle_h2_client<S>(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    stream: S,
    addr: SocketAddr,
    tun_tx: TunIngress,
    pre_auth_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + SplitStream,
{
    handle_client_inner(
        server_state,
        profile,
        stream,
        addr,
        tun_tx,
        pre_auth_permit,
        true,
    )
    .await
}
async fn handle_client_inner<S>(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    mut stream: S,
    addr: SocketAddr,
    tun_tx: TunIngress,
    // Admission permit taken by the accept loop before spawning this task. Dropped as
    // soon as the client is authenticated, so the gate bounds concurrent HANDSHAKES and
    // an established session never occupies a slot. `None` for callers with no gate
    // (tests, and transports that do their own admission control). (S-01)
    mut pre_auth_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    inner_raw: bool,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + SplitStream,
{
    let pcfg = &profile.config;
    let handshake_timeout = Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let framing = if pcfg.obfuscation.mode == "plain" || inner_raw {
        Framing::Raw
    } else {
        Framing::Tls
    };

    // KE + server identity proof + read the first client message (AUTH or JOIN).
    let (
        mut server_tx_codec,
        server_rx,
        static_shared,
        shared,
        transcript_hash,
        _handshake_resume_secret,
        first,
    ) = tokio::time::timeout(
        handshake_timeout,
        qeli_handshake(&server_state, &profile, &mut stream, addr, pcfg, inner_raw),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timeout for {}", addr))?
    .map_err(|e| anyhow::anyhow!("handshake failed for {}: {}", addr, e))?;
    let max_streams = if pcfg.obfuscation.multipath.enabled {
        pcfg.obfuscation.multipath.max_streams.max(1)
    } else {
        1
    };

    let stream_id = loop {
        let candidate = rand::random::<u64>();
        if candidate != 0 {
            break candidate;
        }
    };
    let (session, stream_attach): (Arc<SessionShared>, StreamAttach) = match first {
        FirstMessage::Auth {
            proof,
            username,
            password,
            device_id,
            capabilities,
        } => {
            log::info!(
                "AUTH attempt from {} on profile '{}': user={}",
                addr,
                pcfg.name,
                crate::util::log_identity(&username)
            );
            verify_client_auth(
                &server_state,
                &profile,
                addr,
                "TCP",
                &proof,
                &username,
                &password,
                &static_shared,
                &shared,
                &transcript_hash,
            )
            .await?;

            // Select the wire-breaking post-auth format before allocating a lease.
            let negotiated_recordizer = match crate::protocol::capabilities::negotiate_recordizer(
                &pcfg.obfuscation.recordizer,
                capabilities,
            ) {
                Ok(config) => config,
                Err(error) => {
                    let reason = error.to_string();
                    let message = build_auth_error(&reason);
                    if let Ok(record) = server_tx_codec.encrypt_packet(message.as_bytes(), &[]) {
                        if let Err(send_error) = stream.write_all(&record).await {
                            log::debug!(
                                "TCP {addr}: failed to send recordizer negotiation error: {send_error}"
                            );
                        }
                    }
                    return Err(anyhow::anyhow!("profile '{}': {error}", pcfg.name));
                }
            };

            // Negotiate the family set before touching either pool. IPv6-only incapable
            // clients fail here; dual profiles downgrade old/off clients to legacy IPv4.
            let negotiated_ip_mode = match crate::protocol::capabilities::negotiated_profile_ip_mode(
                pcfg.tun.ip_mode,
                capabilities,
            ) {
                Ok(mode) => mode,
                Err(error) => {
                    let reason = error.to_string();
                    let message = build_auth_error(&reason);
                    match server_tx_codec.encrypt_packet(message.as_bytes(), &[]) {
                        Ok(record) => {
                            if let Err(send_error) = stream.write_all(&record).await {
                                log::debug!(
                                    "TCP {addr}: failed to send authenticated negotiation error: {send_error}"
                                );
                            }
                        }
                        Err(send_error) => log::debug!(
                            "TCP {addr}: failed to encrypt authenticated negotiation error: \
                             {send_error}"
                        ),
                    }
                    return Err(anyhow::anyhow!("profile '{}': {error}", pcfg.name));
                }
            };

            // Identify the device: same login + same device-id supersedes its own
            // old session (clean reconnect on IP change); different devices of one
            // login keep separate sessions/IPs (multi-device). Old clients send no
            // device-id → key is the bare username (one session/IP per login).
            let dkey = device_key(&username, device_id);

            // Per-user session cap (0 = unlimited): own value, else group, else none.
            let max_sessions = {
                let users_db = server_state.users_db.read().await;
                users_db
                    .find_user(&username)
                    .map(|u| u.effective_max_sessions(&users_db.groups))
                    .unwrap_or(0)
            };

            // Supersede any prior session(s) of THIS device (stale reconnect), then —
            // if the user is at their session cap — evict their OLDEST device to make
            // room. Newest primary wins; kicked sessions' streams are torn down.
            // (Multipath JOINs of the SAME live session attach instead.)
            // Variant-b static IP: a user's fixed address always wins. Resolved from the
            // LIVE users db (so a panel edit + SIGHUP applies at once); the holder is evicted
            // below and the address is stolen, so a reconnect from a new source IP keeps the
            // same tunnel IP. None = normal dynamic allocation.
            let (fixed_ip, fixed_ipv6) = {
                let db = server_state.users_db.read().await;
                resolve_static_addresses(&db, pcfg, &username, negotiated_ip_mode)?
            };
            // #13 iroute: subnets/addresses behind THIS client (its extra address or LAN),
            // from the LIVE users db so a panel edit + SIGHUP applies. Registered in the
            // session map below (inbound routing) and programmed as kernel routes after the
            // locks drop, so the server can reach them through this client's tunnel.
            let client_subnets: Vec<String> = {
                let db = server_state.users_db.read().await;
                db.find_user(&username)
                    .map(|u| u.client_subnets.clone())
                    .unwrap_or_default()
            };
            // CIDRs actually registered below (valid + not refused) — their kernel routes
            // are programmed AFTER the session locks drop (an `ip` command must not run
            // while holding the sessions write lock).
            // Pool leases, session ownership and kernel iroutes must change atomically
            // across TCP and UDP authentication for this profile.
            let admission_guard = profile.admission.lock().await;
            let mut programmed_client_routes: Vec<String> = Vec::new();
            let mut evicted_client_routes: Vec<String> = Vec::new();
            // Devices evicted by the per-user session cap below whose pool IP must be
            // released AFTER the sessions write lock drops (lock order: sessions → pool).
            let mut cap_evicted = Vec::new();
            let mut superseded = Vec::new();
            {
                let mut sessions = profile.sessions.write().await;
                let stale: Vec<std::net::IpAddr> = sessions
                    .by_ip
                    .iter()
                    .filter(|(_, s)| s.device_key == dkey)
                    .map(|(ip, _)| *ip)
                    .collect();
                for ip in stale {
                    if let Some(old) = sessions.remove(ip) {
                        old.kick_all();
                        // Strip the old session's inbound iroutes from the map — a dead
                        // ClientRoute would otherwise win route_lookup or stack a duplicate
                        // on this same-device reconnect. Kernel deletion is deferred until
                        // after the sessions lock drops, then completed under the same
                        // admission guard before the replacement uses fail-closed `route add`.
                        evicted_client_routes.extend(sessions.take_client_routes(ip));
                        log::info!(
                            "Superseding previous session for device '{}' (was {}) on profile '{}' — reconnect from {}",
                            dkey, ip, profile.name, addr
                        );
                        superseded.push(old);
                    }
                }
                // Static IP (variant-b): evict whoever currently holds this user's fixed
                // address — a different device of theirs, or a dynamic user who grabbed it
                // while the owner was offline — so we can steal it below. (Our own prior
                // session was already dropped by the supersede loop above.)
                let fixed_addresses = fixed_ip
                    .filter(|_| {
                        matches!(
                            negotiated_ip_mode,
                            crate::config::server::IpMode::Ipv4
                                | crate::config::server::IpMode::Dual
                        )
                    })
                    .map(std::net::IpAddr::V4)
                    .into_iter()
                    .chain(
                        fixed_ipv6
                            .filter(|_| {
                                matches!(
                                    negotiated_ip_mode,
                                    crate::config::server::IpMode::Ipv6
                                        | crate::config::server::IpMode::Dual
                                )
                            })
                            .map(std::net::IpAddr::V6),
                    )
                    .collect::<Vec<_>>();
                for address in fixed_addresses {
                    let holder_primary = sessions
                        .get_by_address(address)
                        .map(|holder| holder.client_ip);
                    if let Some(old) = holder_primary.and_then(|primary| sessions.remove(primary)) {
                        old.kick_all();
                        // Strip the evicted holder's iroutes (map only — see the supersede
                        // note above; the admitted session re-programs the kernel).
                        evicted_client_routes.extend(sessions.take_client_routes(old.client_ip));
                        log::info!(
                            "Static IP {} for user '{}' — evicting current holder device '{}' on profile '{}'",
                            address, crate::util::log_identity(&username), crate::util::log_device_identity(&old.device_key), profile.name
                        );
                        cap_evicted.push(old);
                    }
                }
                // This device freed its own slot above, so the remaining count is of
                // OTHER devices of this user; evict the oldest until the new one fits.
                if max_sessions > 0 {
                    loop {
                        let mut user_sessions: Vec<(std::net::IpAddr, Instant)> = sessions
                            .by_ip
                            .iter()
                            .filter(|(_, s)| s.username == username)
                            .map(|(ip, s)| (*ip, s.connected_at))
                            .collect();
                        if user_sessions.len() < max_sessions as usize {
                            break;
                        }
                        user_sessions.sort_by_key(|(_, t)| *t); // oldest first
                        let oldest_ip = user_sessions[0].0;
                        match sessions.remove(oldest_ip) {
                            Some(old) => {
                                old.kick_all();
                                // Strip the evicted device's iroutes (map only).
                                evicted_client_routes
                                    .extend(sessions.take_client_routes(oldest_ip));
                                log::info!(
                                    "User '{}' at session cap {} — evicting oldest device {} on profile '{}' for new device '{}'",
                                    crate::util::log_identity(&username), max_sessions, oldest_ip, profile.name, crate::util::log_device_identity(&dkey)
                                );
                                // This evicted device's own stream won't release its IP
                                // (it's no longer in by_ip under its session_id), so the
                                // address would leak — release it post-lock below.
                                cap_evicted.push(old);
                            }
                            None => break,
                        }
                    }
                }
            }
            // Notify (opt-in): forcibly evicted (static-IP steal / session-cap).
            // Already out of by_ip, so the TCP teardown guard won't double-fire.
            //
            // The addresses themselves are NOT released here any more — see the single
            // pool-lock block below. This loop used to release each one under its own
            // `profile.pool.lock()`, i.e. released → dropped the lock → hit at least two
            // more await points (`sessions.read()`, then re-taking the pool lock) before
            // allocating our own. `IpPool::release` pushes onto `freed` and `allocate` pops
            // `freed` FIRST, so a concurrent handler in that window was HANDED the address
            // we had just evicted someone from. Our `allocate_fixed` then took it back — but
            // only in the pool's bookkeeping (`user_allocations.retain`), because killing the
            // session is the caller's job and this caller only knew about the holders it
            // had seen under the earlier write lock. Result: two live sessions on one tunnel
            // IP. The orphan keeps injecting packets with that source while all return
            // traffic — including replies to its own connections — is routed to the other
            // client. (Audit 2026-08-04.)
            for s in superseded.iter().chain(&cap_evicted) {
                crate::server::notify::fire_disconnect(&s.username, &profile.name, s.peer);
            }

            let max_clients = pcfg.performance.connection.max_clients;
            let capacity_rejected = {
                let sessions = profile.sessions.read().await;
                sessions.by_ip.len() >= max_clients as usize
            };
            if capacity_rejected {
                // Evictions already removed these sessions from the authoritative map.
                // Release their leases and routes even when a lowered global cap still
                // leaves no room for the replacement.
                {
                    let mut pool = profile.pool.lock().await;
                    for session in &cap_evicted {
                        pool.release(&session.device_key);
                    }
                    // A same-device reconnect was removed above but deliberately kept its
                    // lease for reuse. If the replacement is rejected, no live session owns
                    // that lease any more.
                    pool.release(&dkey);
                }
                for cidr in &evicted_client_routes {
                    let _ = program_client_subnet_route(false, cidr, &pcfg.tun.name).await;
                }
                drop(admission_guard);
                return Err(anyhow::anyhow!(
                    "max clients ({}) reached on profile '{}'",
                    max_clients,
                    profile.name
                ));
            }

            // Old ownership is gone from the in-memory router. Remove the corresponding
            // host routes before any replacement route is installed below.
            for cidr in &evicted_client_routes {
                let _ = program_client_subnet_route(false, cidr, &pcfg.tun.name).await;
            }

            let session_id = loop {
                let candidate = rand::random::<u64>();
                if candidate != 0 {
                    break candidate;
                }
            };
            let assigned_result: Result<crate::server::pool::AssignedAddresses, anyhow::Error> = {
                // ONE pool lock for "give back what we evicted, then take ours". Splitting
                // the two — as this used to — leaves the freed address on the pool's `freed`
                // stack across an await, and `allocate` pops that stack first. See the
                // eviction loop above. (Audit 2026-08-04.)
                let mut pool = profile.pool.lock().await;
                for s in &cap_evicted {
                    pool.release(&s.device_key);
                }
                let result = pool
                    .allocate_for_mode(&dkey, negotiated_ip_mode, fixed_ip, fixed_ipv6)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "cannot allocate {} address set for '{}' on profile '{}': {}",
                            negotiated_ip_mode,
                            crate::util::log_identity(&username),
                            profile.name,
                            error
                        )
                    });
                // A reconnect removes the old authoritative session before allocation. The
                // allocator transaction intentionally restores this device's previous leases
                // on failure, but with no session left those leases would be orphaned forever.
                // Roll back the admission as a whole while the same pool lock is still held.
                if result.is_err() {
                    pool.release(&dkey);
                }
                result
            };
            let assigned = assigned_result?;
            let client_ip = assigned
                .ipv4
                .map(std::net::IpAddr::V4)
                .or_else(|| assigned.ipv6.map(std::net::IpAddr::V6))
                .expect("negotiated address mode assigns at least one family");
            let mut token = [0u8; JOIN_TOKEN_LEN];
            rand::rng().fill_bytes(&mut token[..]);

            let (routes_json, exit_access, initial_bandwidth_mbps, dst_acl, src_subnets) = {
                let users_db = server_state.users_db.read().await;
                let raw_routes = build_routes_json_for_user(pcfg, &users_db, &username, assigned);
                let exit_access = exit_access_from_routes_json(&raw_routes);
                let routes = routes_without_exit_defaults(&raw_routes);
                let u = users_db.find_user(&username);
                let bw = u
                    .map(|u| u.effective_bandwidth_limit(&users_db.groups))
                    .unwrap_or(0);
                // Destination ACL (`allowed_networks`), own or inherited from the
                // group; compiled once here so the per-packet check is a few masks.
                let acl = crate::server::acl::DstAcl::compile(
                    &u.map(|u| crate::server::acl::effective_allowed_networks(u, &users_db.groups))
                        .unwrap_or_default(),
                    &crate::util::log_identity(&username),
                );
                let subnets = u.map(|u| u.client_subnets.clone()).unwrap_or_default();
                (routes, exit_access, bw, acl, subnets)
            };
            let assigned_sources: Vec<std::net::IpAddr> = assigned
                .ipv4
                .map(std::net::IpAddr::V4)
                .into_iter()
                .chain(assigned.ipv6.map(std::net::IpAddr::V6))
                .collect();
            let src_guard = crate::server::acl::SrcGuard::new_dual(
                &assigned_sources,
                &src_subnets,
                &crate::util::log_identity(&username),
            );
            if !dst_acl.is_unrestricted() {
                log::info!(
                    "User '{}' is restricted to {} destination network(s) (allowed_networks)",
                    crate::util::log_identity(&username),
                    dst_acl.rule_count()
                );
            }

            let wire_pool = match server_wire_pool(pcfg) {
                Ok(pool) => pool,
                Err(error) => {
                    profile.pool.lock().await.release(&dkey);
                    return Err(anyhow::anyhow!(
                        "cannot allocate the bounded wire-record pool for user '{}' on profile '{}': {}",
                        crate::util::log_identity(&username),
                        profile.name,
                        error
                    ));
                }
            };

            let session = Arc::new(SessionShared {
                session_id,
                username: username.clone(),
                device_key: dkey.clone(),
                client_ip,
                client_ipv4: assigned.ipv4,
                client_ipv6: assigned.ipv6,
                peer: addr,
                token,
                max_streams,
                wire_pool,
                streams: std::sync::Mutex::new(Vec::new()),
                #[cfg(feature = "experimental-roaming")]
                tcp_roaming: if pcfg.roaming.enabled
                    && crate::protocol::capabilities::tcp_resume_supported(capabilities)
                {
                    Some(TcpRoamingSession::new(
                        session_id,
                        token,
                        max_streams,
                        stream_id,
                        _handshake_resume_secret,
                        profile.tcp_orphans.clone(),
                        TcpRoamingPolicy {
                            grace: Duration::from_secs(pcfg.roaming.grace_secs),
                            handover_enabled: crate::protocol::capabilities::tcp_handover_supported(
                                capabilities,
                            ),
                        },
                    )?)
                } else {
                    None
                },
                #[cfg(feature = "experimental-roaming")]
                tcp_control_v2: pcfg.roaming.enabled
                    && crate::protocol::capabilities::control_v2_supported(capabilities),
                connected_at: Instant::now(),
                bytes_sent: Arc::new(AtomicU64::new(0)),
                bytes_recv: Arc::new(AtomicU64::new(0)),
                dropped: Arc::new(AtomicU64::new(0)),
                bandwidth_limit_mbps: Arc::new(AtomicU32::new(initial_bandwidth_mbps)),
                rates: DirectionalRateBuckets::new(),
                cover_budget: crate::protocol::Shaper::shared_budget(
                    &pcfg.obfuscation.traffic_shaping.to_shaping(),
                    std::time::Instant::now(),
                ),
                dst_acl,
                src_guard,
                exit_access,
                recordizer: negotiated_recordizer,
                // 0 = the client has not reported a path MTU. Every pre-#13 client stays
                // here, and the downlink check stays switched off for them.
                path_mtu: Arc::new(AtomicU32::new(0)),
                revoked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                closing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                // None = the client has not said what it is. Every client that predates
                // the report stays here, and both surfaces show it as unknown.
                client_info: Arc::new(std::sync::Mutex::new(None)),
            });
            let mut replaced_session = None;
            let mut replaced_routes = Vec::new();
            {
                let mut sessions = profile.sessions.write().await;
                // Admission is serialized across TCP and UDP, so this insert cannot race a
                // competing authenticator. Handle an inconsistent pre-existing owner
                // defensively instead of silently dropping its routes and lease.
                if let Some(old) = sessions.insert(session.clone()) {
                    old.kick_all();
                    replaced_routes.extend(sessions.take_client_routes(old.client_ip));
                    replaced_session = Some(old);
                }
                // #13 iroute: register the subnets behind this client for INBOUND routing.
                // Defaults are internal-only exit next hops; non-default routes covering the
                // server's own tunnel IP are refused, and a subnet already claimed by a
                // DIFFERENT client is skipped (first-registered wins). Admin-configured here
                // (per-user client_subnets), so this is a footgun guard, not an
                // untrusted-input gate.
                let server_tun = configured_tun_addresses(pcfg);
                programmed_client_routes.extend(register_client_subnets(
                    &mut sessions,
                    &client_subnets,
                    client_ip,
                    &session,
                    &server_tun,
                    &username,
                    &profile.name,
                ));
            }
            // Program the kernel routes now that the sessions write lock is released.
            for cidr in &replaced_routes {
                let _ = program_client_subnet_route(false, cidr, &pcfg.tun.name).await;
            }
            if let Some(old) = &replaced_session {
                if old.device_key != dkey {
                    profile.pool.lock().await.release(&old.device_key);
                }
                crate::server::notify::fire_disconnect(&old.username, &profile.name, old.peer);
            }
            let mut installed_client_routes: Vec<String> = Vec::new();
            for cidr in &programmed_client_routes {
                if let Err(error) = program_client_subnet_route(true, cidr, &pcfg.tun.name).await {
                    // The session is not client-visible until AUTH OK. Roll back every part
                    // of the admission when the host route cannot be owned; otherwise the
                    // panel reports a connected client whose site-to-site route black-holes.
                    let orphan_routes = {
                        let mut sessions = profile.sessions.write().await;
                        if sessions
                            .by_ip
                            .get(&client_ip)
                            .is_some_and(|current| current.session_id == session_id)
                        {
                            sessions.remove(client_ip);
                            sessions.take_client_routes(client_ip)
                        } else {
                            Vec::new()
                        }
                    };
                    for installed in installed_client_routes.iter().rev() {
                        let _ = program_client_subnet_route(false, installed, &pcfg.tun.name).await;
                    }
                    profile.pool.lock().await.release(&dkey);
                    return Err(anyhow::anyhow!(
                        "cannot install client_subnet '{}' for user '{}' on profile '{}': {} ({} in-memory route(s) rolled back)",
                        cidr,
                        crate::util::log_identity(&username),
                        profile.name,
                        error,
                        orphan_routes.len()
                    ));
                }
                installed_client_routes.push(cidr.clone());
            }
            // AUTH OK carries the join token + stream cap so the client can open
            // the remaining bonded streams.
            // Everything from here is already COMMITTED: the session sits in
            // by_ip/by_token, the pool IP is taken, and the iroutes are in the kernel. The
            // only code that undoes all that lives in `run_stream`, which is reached only
            // if we return Ok — so a failure below used to leak the lot. A client that
            // authenticates and immediately RSTs (write_all → EPIPE) left a ghost session
            // holding a pool address, a max_clients slot and a live `ip route … dev vpn0`,
            // with no reaper for a session that never had a stream. `device_id` is
            // client-controlled, so a legitimate user could repeat that with fresh device
            // ids until the pool or the cap was exhausted (`max_sessions = 0` is the
            // default). Roll the whole thing back before propagating the error.
            // (Audit 2026-07-27, B5.)
            let send_result = async {
                let msg = build_auth_ok_for_addresses(
                    assigned,
                    pcfg,
                    &routes_json,
                    &token,
                    max_streams,
                    capabilities,
                );
                let auth_response = server_tx_codec.encrypt_packet(msg.as_bytes(), &[])?;
                stream.write_all(&auth_response).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(e) = send_result {
                let orphan_routes = {
                    let mut sessions = profile.sessions.write().await;
                    sessions.remove(client_ip);
                    sessions.take_client_routes(client_ip)
                };
                for cidr in &orphan_routes {
                    let _ = program_client_subnet_route(false, cidr, &pcfg.tun.name).await;
                }
                profile.pool.lock().await.release(&dkey);
                log::warn!(
                    "Client {} ({}) failed to receive AUTH OK on profile '{}' ({}) — session, \
                     pool address {} and {} iroute(s) rolled back",
                    addr,
                    crate::util::log_identity(&username),
                    profile.name,
                    e,
                    client_ip,
                    orphan_routes.len()
                );
                return Err(e);
            }

            // Client-visible admission commits at AUTH OK. Keeping the profile admission
            // guard through this small write prevents a concurrent TCP/UDP reconnect from
            // superseding the session before the older handler has even acknowledged it.
            drop(admission_guard);
            crate::server::notify::fire_connect(&username, &profile.name, addr);

            log::info!(
                "Client {} ({}) connected on profile '{}', IP: {}, bandwidth_limit: {} Mbps, streams<={}",
                addr,
                crate::util::log_identity(&username),
                profile.name,
                client_ip,
                initial_bandwidth_mbps,
                max_streams
            );
            (session, StreamAttach::Primary)
        }
        FirstMessage::Join {
            token,
            stream_index,
        } => {
            let session = {
                let sessions = profile.sessions.read().await;
                sessions
                    .by_token
                    .get(&token)
                    .and_then(|ip| sessions.by_ip.get(ip).cloned())
            };
            let session = session
                .ok_or_else(|| anyhow::anyhow!("JOIN with unknown/stale token from {}", addr))?;
            if session.is_revoked() || session.stream_count() >= session.max_streams as usize {
                return Err(anyhow::anyhow!(
                    "JOIN rejected for revoked/full session (max_streams={}) for user '{}'",
                    session.max_streams,
                    crate::util::log_identity(&session.username)
                ));
            }
            #[cfg(feature = "experimental-roaming")]
            if session.tcp_roaming.is_some() {
                return Err(anyhow::anyhow!(
                    "legacy bearer JOIN rejected for an authenticated-resume session"
                ));
            }
            // The authoritative check and JOINOK are deliberately deferred until run_stream
            // has atomically inserted this connection into the session.
            (
                session,
                StreamAttach::LegacyJoin {
                    logical_slot_id: u32::from(stream_index),
                },
            )
        }
        #[cfg(feature = "experimental-roaming")]
        FirstMessage::Resume { join } => {
            let locator = *join.input().session_locator();
            let session = {
                let sessions = profile.sessions.read().await;
                sessions
                    .by_token
                    .get(&locator)
                    .and_then(|ip| sessions.by_ip.get(ip).cloned())
            }
            .ok_or_else(|| anyhow::anyhow!("resume JOIN with unknown locator from {addr}"))?;
            profile.tcp_roaming_metrics.note_attempt();
            let reservation = match session.begin_tcp_resume(&join, &transcript_hash) {
                Ok(reservation) => reservation,
                Err(error) => {
                    profile.tcp_roaming_metrics.note_failure();
                    return Err(anyhow::anyhow!(
                        "authenticated resume JOIN rejected: {error}"
                    ));
                }
            };
            log::info!(
                "ROAMING transport=tcp event=attempt profile='{}' user='{}' peer={}",
                profile.name,
                crate::util::log_identity(&session.username),
                addr
            );
            (session, StreamAttach::Resume { reservation })
        }
    };

    // Authenticated (AUTH accepted or JOIN matched a live session) — hand the pre-auth
    // slot back now. Holding it for the session's lifetime would turn a handshake gate
    // into a hard cap on concurrent users. (S-01)
    drop(pre_auth_permit.take());

    // Attach this connection as a stream and pump it until it closes. Teardown
    // (release IP, drop session) happens inside when the LAST stream detaches.
    let server_tx = Arc::new(std::sync::Mutex::new(server_tx_codec));
    let (read_half, write_half) = stream.split_io();
    run_stream(
        profile,
        session,
        addr,
        tun_tx,
        read_half,
        write_half,
        server_tx,
        server_rx,
        framing,
        stream_id,
        stream_attach,
    )
    .await;
    Ok(())
}

/// KE (fake-TLS / raw) + server identity proof + read the first client message.
/// Returns the per-connection codecs, the static & ephemeral shared-secret bytes
/// (for auth verification), the transcript hash, and the parsed first message.
async fn qeli_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    stream: &mut S,
    addr: SocketAddr,
    pcfg: &crate::config::server::ProfileConfig,
    inner_raw: bool,
) -> anyhow::Result<(
    PacketCodec,
    PacketCodec,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    HandshakeResumeSecret,
    FirstMessage,
)> {
    let server_kp = Keypair::generate();
    let plain = pcfg.obfuscation.mode == "plain" || inner_raw;
    // Plain has no outer carrier; current reality-tls already has an authenticated
    // PQ-capable TLS layer and deliberately avoids a second visible fake-TLS
    // handshake. Both use classic X25519 for this private inner exchange. Legacy
    // camouflage modes keep the hybrid X25519+ML-KEM inner exchange.
    let (client_pub, transcript_hash, mlkem_shared) = if plain {
        let (cp, th) = raw_server_handshake(stream, &server_kp).await?;
        (cp, th, None)
    } else {
        let (cp, th, ml) = server_handshake(stream, &server_kp, pcfg).await?;
        (cp, th, Some(ml))
    };

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order client public key"))?;
    // H-1: optionally bind the data keys to the server static identity by folding
    // the static-ephemeral DH (es) into the KDF. Gated by `bind_static_to_session`.
    let es = server_state
        .config
        .auth
        .bind_static_to_session
        .then(|| profile.static_keypair.derive_shared(&client_pub).0);
    let (server_to_client, client_to_server) = match (&mlkem_shared, &es) {
        (Some(ml), Some(es)) => derive_keys_hybrid_bound(&shared.0, ml, es),
        (Some(ml), None) => derive_keys_hybrid(&shared.0, ml),
        (None, Some(es)) => derive_keys_bound(&shared.0, es),
        (None, None) => derive_keys(&shared.0),
    };
    // The original authenticated handshake is the sole source of the resume secret.  Keep
    // legacy builds bit-for-bit on the existing KDF path; the extra domain-separated material
    // is derived only in an experimental-roaming build and is zeroized when its owner drops.
    #[cfg(feature = "experimental-roaming")]
    let resume_secret = {
        let material = match (&mlkem_shared, &es) {
            (Some(ml), Some(es)) => derive_session_material_hybrid_bound(&shared.0, ml, es),
            (Some(ml), None) => derive_session_material_hybrid(&shared.0, ml),
            (None, Some(es)) => derive_session_material_bound(&shared.0, es),
            (None, None) => derive_session_material(&shared.0),
        };
        zeroize::Zeroizing::new(*material.resume_secret())
    };
    #[cfg(not(feature = "experimental-roaming"))]
    let resume_secret = ();
    let (mut server_tx, mut server_rx) = if plain {
        (
            PacketCodec::new_raw(server_to_client),
            PacketCodec::new_raw(client_to_server),
        )
    } else {
        (
            PacketCodec::new(server_to_client),
            PacketCodec::new(client_to_server),
        )
    };

    let static_shared = profile.static_keypair.derive_shared(&client_pub);
    let hide_identity = server_state.config.auth.require_client_key_proof;
    {
        let auth_msg = build_server_auth_msg_with_capabilities(
            &profile.static_keypair,
            &client_pub,
            &shared.0,
            &transcript_hash,
            hide_identity,
            crate::protocol::capabilities::server_capabilities_for_profile(pcfg.roaming.enabled),
        );
        let encrypted = server_tx.encrypt_packet(&auth_msg, &[])?;
        stream.write_all(&encrypted).await?;
        log::debug!("Sent server auth proof to {}", addr);
    }

    let framing = if plain { Framing::Raw } else { Framing::Tls };
    let record = read_record(stream, framing)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read first packet: {}", e))?;
    let plaintext = server_rx.decrypt_packet(&record)?;
    let first = parse_first_message(&plaintext)?;

    Ok((
        server_tx,
        server_rx,
        static_shared.0,
        shared.0,
        transcript_hash,
        resume_secret,
        first,
    ))
}

/// Classify the first client message: JOIN (magic prefix) vs AUTH (legacy
/// `[proof:32][user:pass]`). The 8-byte magic can't collide with a real auth's
/// random proof, so old single-stream clients are still parsed as AUTH.
fn parse_first_message(plaintext: &[u8]) -> anyhow::Result<FirstMessage> {
    #[cfg(feature = "experimental-roaming")]
    if plaintext.starts_with(crate::protocol::roaming::TCP_RESUME_MAGIC.as_slice()) {
        let join = crate::protocol::roaming::TcpResumeJoin::decode(plaintext)
            .map_err(|error| anyhow::anyhow!("invalid TCP resume JOIN: {error}"))?;
        return Ok(FirstMessage::Resume { join });
    }
    if plaintext.len() > JOIN_MAGIC.len() + JOIN_TOKEN_LEN
        && &plaintext[..JOIN_MAGIC.len()] == JOIN_MAGIC.as_slice()
    {
        let off = JOIN_MAGIC.len();
        let mut token = [0u8; JOIN_TOKEN_LEN];
        token.copy_from_slice(&plaintext[off..off + JOIN_TOKEN_LEN]);
        let stream_index = plaintext[off + JOIN_TOKEN_LEN];
        return Ok(FirstMessage::Join {
            token,
            stream_index,
        });
    }
    if plaintext.len() < 32 {
        return Err(anyhow::anyhow!("auth packet too short"));
    }
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&plaintext[..32]);
    let (device_id, auth_bytes) = split_device_id(&plaintext[32..]);
    let (capabilities, creds) =
        crate::protocol::capabilities::split_client_capabilities(auth_bytes)?;
    let auth_str = String::from_utf8(creds.to_vec())?;
    let (user, pass) = auth_str
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid auth format"))?;
    Ok(FirstMessage::Auth {
        proof,
        username: user.to_string(),
        password: pass.to_string(),
        device_id,
        capabilities,
    })
}

#[cfg(all(test, feature = "experimental-roaming"))]
mod tcp_resume_handler_tests {
    use super::{
        classify_control_v2, parse_first_message, ControlV2Disposition, FirstMessage,
        TcpRoamingPolicy, TcpRoamingSession,
    };
    use crate::protocol::roaming::{ResumeProofInput, TcpResumeJoin, TCP_RESUME_MAGIC};
    use crate::transport_core::tcp_roaming::{
        DetachOutcome, DetachReason, LifecycleError, OrphanLimiter,
    };
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const LOCATOR: [u8; 16] = [0x61; 16];
    const SECRET: [u8; 32] = [0x72; 32];

    fn resume(transcript: [u8; 32], epoch: u64, handover: bool) -> TcpResumeJoin {
        TcpResumeJoin::new(
            ResumeProofInput::new(transcript, LOCATOR, epoch, 0, handover),
            &SECRET,
        )
    }

    #[test]
    fn resume_magic_is_parsed_strictly_and_never_falls_back_to_auth() {
        let transcript = [0x53; 32];
        let wire = resume(transcript, 1, false).encode();
        match parse_first_message(&wire).expect("authenticated resume message") {
            FirstMessage::Resume { join } => {
                assert!(join.matches_transcript(&transcript));
                assert!(join.verify(&SECRET));
            }
            _ => panic!("resume wire was misclassified"),
        }

        let mut truncated = Vec::from(TCP_RESUME_MAGIC);
        truncated.extend_from_slice(&[0u8; 40]);
        assert!(parse_first_message(&truncated).is_err());
    }

    #[test]
    fn handler_wrapper_uses_original_secret_and_shared_orphan_budget() {
        let limiter = Arc::new(Mutex::new(OrphanLimiter::new(1, 4 * 1024 * 1024)));
        let session = TcpRoamingSession::new(
            9,
            LOCATOR,
            1,
            90,
            zeroize::Zeroizing::new(SECRET),
            limiter.clone(),
            TcpRoamingPolicy {
                grace: Duration::from_secs(30),
                handover_enabled: true,
            },
        )
        .unwrap();
        session.mark_initial_transport_attached();
        let now = Instant::now();
        let ticket = match session.detach(90, DetachReason::Unexpected, now).unwrap() {
            DetachOutcome::Orphaned(ticket) => ticket,
            _ => panic!("last transport must enter grace"),
        };
        {
            let limiter = limiter.lock().unwrap();
            assert_eq!(limiter.sessions(), 1);
            assert_eq!(limiter.bytes(), 4 * 1024 * 1024);
        }

        let transcript = [0x44; 32];
        let reservation = session
            .begin_resume(&resume(transcript, 1, false), &transcript)
            .unwrap();
        session.commit_resume(reservation, 91).unwrap();
        let limiter = limiter.lock().unwrap();
        assert_eq!((limiter.sessions(), limiter.bytes()), (0, 0));
        drop(limiter);
        assert!(!session.reap(ticket, now + Duration::from_secs(31)));
    }

    #[test]
    fn handover_requires_its_own_authenticated_capability() {
        let limiter = Arc::new(Mutex::new(OrphanLimiter::new(1, 4 * 1024 * 1024)));
        let session = TcpRoamingSession::new(
            10,
            LOCATOR,
            1,
            100,
            zeroize::Zeroizing::new(SECRET),
            limiter,
            TcpRoamingPolicy {
                grace: Duration::from_secs(30),
                handover_enabled: false,
            },
        )
        .unwrap();
        let transcript = [0x45; 32];
        assert_eq!(
            session
                .begin_resume(&resume(transcript, 1, false), &transcript)
                .unwrap_err(),
            LifecycleError::InitialTransportPending
        );
        session.mark_initial_transport_attached();
        let now = Instant::now();
        match session.detach(100, DetachReason::Unexpected, now).unwrap() {
            DetachOutcome::Orphaned(_) => {}
            _ => panic!("last transport must enter grace"),
        }
        assert_eq!(
            session
                .begin_resume(&resume(transcript, 1, true), &transcript)
                .unwrap_err(),
            LifecycleError::HandoverNotNegotiated
        );
        // Rejection happens before epoch reservation, so a permitted hard resume with the same
        // fresh handshake and epoch can still commit.
        let reservation = session
            .begin_resume(&resume(transcript, 1, false), &transcript)
            .unwrap();
        session.commit_resume(reservation, 101).unwrap();
    }

    #[test]
    fn control_v2_dispatch_accepts_only_the_strict_terminal_close_shape() {
        let close = crate::protocol::control_v2::close_session(7);
        assert_eq!(
            classify_control_v2(&close),
            ControlV2Disposition::CloseSession
        );

        let fragmented_close = crate::protocol::control_v2::Frame {
            message_type: crate::protocol::control_v2::TYPE_CLOSE_SESSION,
            flags: 0,
            message_id: 8,
            part_index: 0,
            part_count: 2,
            payload: &[],
        }
        .encode()
        .unwrap();
        assert_eq!(
            classify_control_v2(&fragmented_close),
            ControlV2Disposition::ProtocolViolation
        );

        let notice = crate::protocol::control_v2::fragment_message(
            crate::protocol::control_v2::TYPE_NOTICE,
            0,
            9,
            b"future-safe",
        )
        .unwrap();
        assert_eq!(
            classify_control_v2(&notice[0]),
            ControlV2Disposition::Ignore
        );
        assert_eq!(
            classify_control_v2(&crate::protocol::control_v2::MAGIC),
            ControlV2Disposition::ProtocolViolation
        );
    }
}

/// Split the post-proof auth bytes into (optional device-id, `user:pass` bytes).
/// A new client prefixes a single `0x00` marker + DEVICE_ID_LEN id; an old client
/// sends the creds directly (its first byte is a username char, never `0x00`).
/// Shared by the TCP (`parse_first_message`) and UDP (`handle_udp_auth`) paths.
pub fn split_device_id(rest: &[u8]) -> (Option<[u8; DEVICE_ID_LEN]>, &[u8]) {
    if rest.first() == Some(&0) && rest.len() > DEVICE_ID_LEN {
        let mut did = [0u8; DEVICE_ID_LEN];
        did.copy_from_slice(&rest[1..1 + DEVICE_ID_LEN]);
        (Some(did), &rest[1 + DEVICE_ID_LEN..])
    } else {
        (None, rest)
    }
}

/// Session/pool key for a client: `username:hex(device_id)` when the client sent a
/// device-id, else just `username` (old clients = one session/IP per login, as
/// before). Same device → same key → its old session is superseded; different
/// devices of one login → different keys → they coexist.
pub fn device_key(username: &str, device_id: Option<[u8; DEVICE_ID_LEN]>) -> String {
    match device_id {
        Some(id) => {
            let hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
            format!("{}:{}", username, hex)
        }
        None => username.to_string(),
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlV2Disposition {
    Ignore,
    CloseSession,
    ProtocolViolation,
}

#[cfg(feature = "experimental-roaming")]
fn classify_control_v2(bytes: &[u8]) -> ControlV2Disposition {
    match crate::protocol::control_v2::decode(bytes) {
        Ok(frame) if crate::protocol::control_v2::is_close_session(frame) => {
            ControlV2Disposition::CloseSession
        }
        Ok(frame) if frame.message_type == crate::protocol::control_v2::TYPE_CLOSE_SESSION => {
            ControlV2Disposition::ProtocolViolation
        }
        Ok(_) => ControlV2Disposition::Ignore,
        Err(_) => ControlV2Disposition::ProtocolViolation,
    }
}

/// Consume an authenticated in-tunnel control frame before it can reach the packet ACL/TUN.
/// `Some(false)` means the current reader must stop because the whole session is terminal.
fn handle_server_control(
    packet: &[u8],
    session: &Arc<SessionShared>,
    _peer: SocketAddr,
) -> Option<bool> {
    #[cfg(feature = "experimental-roaming")]
    if crate::protocol::control_v2::is_control_v2(packet) {
        if !session.tcp_control_v2 {
            log::debug!(
                "dropping unnegotiated CONTROL_V2 frame from {} for '{}'",
                _peer,
                crate::util::log_identity(&session.username)
            );
            return Some(true);
        }
        return match classify_control_v2(packet) {
            ControlV2Disposition::CloseSession => {
                log::info!(
                    "client '{}' ({}) requested orderly session close",
                    crate::util::log_identity(&session.username),
                    _peer
                );
                session.close_all();
                Some(false)
            }
            ControlV2Disposition::Ignore => Some(true),
            ControlV2Disposition::ProtocolViolation => {
                log::warn!(
                    "malformed CONTROL_V2 frame from {} for '{}' - revoking session",
                    _peer,
                    crate::util::log_identity(&session.username)
                );
                session.kick_all();
                Some(false)
            }
        };
    }

    if crate::protocol::ctrl::is_ctrl(packet) {
        if let Some(mtu) = crate::protocol::ctrl::parse_mtu_report(packet) {
            session.note_path_mtu(mtu);
        } else if let Some((version, platform)) = crate::protocol::ctrl::parse_client_info(packet) {
            session.note_client_info(&version, &platform);
        }
        return Some(true);
    }
    None
}
async fn forward_server_uplink_packet(
    packet: ServerTunPacket,
    profile: &Arc<ProfileRuntime>,
    session: &Arc<SessionShared>,
    tun_tx: &TunIngress,
    bytes_recv: &AtomicU64,
    stream_id: u64,
) -> bool {
    if let Some(keep_reading) = handle_server_control(&packet, session, session.peer) {
        return keep_reading;
    }
    if packet.is_empty() {
        return true;
    }
    if !session.src_guard.allows_packet(&packet) {
        log::debug!(
            "dropped packet from '{}' - disallowed inner source {} (expected {} or a routed subnet)",
            crate::util::log_identity(&session.username),
            crate::server::acl::packet_source(&packet)
                .map(|source| source.to_string())
                .unwrap_or_else(|| "<malformed>".to_string()),
            session.client_ip
        );
        return true;
    }
    if !session.dst_acl.is_unrestricted() && !session.dst_acl.allows_packet(&packet) {
        log::debug!(
            "ACL: dropped packet from '{}' - destination not in allowed_networks",
            crate::util::log_identity(&session.username)
        );
        return true;
    }
    let limit = session.bandwidth_limit_mbps.load(Ordering::Relaxed);
    let delay = session.rates.upload.consume(packet.len() as u64 * 8, limit);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    bytes_recv.fetch_add(packet.len() as u64, Ordering::Relaxed);
    crate::trace::record(
        crate::trace::Dir::Rx,
        "server.stream",
        packet.len(),
        stream_id,
    );
    tun_tx
        .send_client_packet(profile, session.session_id, session.exit_access, packet)
        .await
        .is_ok()
}

pub(crate) fn encrypt_server_stream_payload(
    server_tx: &std::sync::Mutex<PacketCodec>,
    data: &[u8],
    payload_budget: usize,
    pcfg: &crate::config::server::ProfileConfig,
    wire_record: &mut Vec<u8>,
    padding: &mut Vec<u8>,
) -> bool {
    let pad_cfg = &pcfg.obfuscation.padding;
    let norm_cfg = &pcfg.obfuscation.traffic_normalization;
    let mut obf = Obfuscator::new();
    let normalization_padding = if norm_cfg.enabled && !norm_cfg.round_sizes.is_empty() {
        Obfuscator::normalization_padding_len(data.len(), &norm_cfg.round_sizes, payload_budget)
    } else {
        0
    };
    let base = data
        .len()
        .saturating_add(normalization_padding)
        .saturating_add(60);
    let pad_cap = (pad_cfg.max_bytes as usize).min(payload_budget.saturating_sub(base)) as u16;
    obf.generate_padding_opts_into(
        pad_cfg.enabled,
        pad_cfg.min_bytes,
        pad_cap,
        pad_cfg.randomize,
        pad_cfg.probability,
        padding,
    );
    if normalization_padding != 0 {
        obf.append_normalization_padding_into(
            data.len(),
            &norm_cfg.round_sizes,
            payload_budget,
            padding,
        );
    }
    lock_or_recover(server_tx, "handler::data_encrypt")
        .encrypt_packet_into(data, padding, wire_record)
        .is_ok()
}

/// Run one bonded connection (stream) of a session: a reader task (decrypt →
/// TUN) and the writer/heartbeat/idle loop. Adds itself to the session on entry
/// and detaches on exit, tearing the session down when it was the last stream.
#[allow(clippy::too_many_arguments)]
async fn run_stream<R, W>(
    profile: Arc<ProfileRuntime>,
    session: Arc<SessionShared>,
    addr: SocketAddr,
    tun_tx: TunIngress,
    mut read_half: R,
    mut write_half: W,
    server_tx: Arc<std::sync::Mutex<PacketCodec>>,
    server_rx: PacketCodec,
    framing: Framing,
    stream_id: u64,
    stream_attach: StreamAttach,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    let pcfg = &profile.config;
    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled
        && hb_config.interval_ms > 0
        && !(framing == Framing::Raw && pcfg.obfuscation.mode == "reality-tls");
    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        DEFAULT_HEARTBEAT_INTERVAL_MS
    });
    let idle_timeout = Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);

    let (tx, mut rx) = mpsc::channel::<PooledBuffer>(session.wire_pool.buffer_count());
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if !session.try_add_stream(
        StreamHandle {
            #[cfg(feature = "experimental-roaming")]
            logical_slot_id: stream_attach.logical_slot_id(),
            #[cfg(feature = "experimental-roaming")]
            ready: stream_attach.initially_ready(),
            stream_id,
            codec: server_tx.clone(),
            writer: tx,
            kick_tx,
            shutdown_tx: shutdown_tx.clone(),
        },
        stream_attach.authenticated_resume_overflow(),
    ) {
        // The lookup/count in handle_client is only a fast-path. This is the authoritative,
        // lock-serialized admission against both max_streams and session revocation.
        log::warn!(
            "Stream from {} dropped: session for '{}' is revoked or at max_streams ({})",
            addr,
            crate::util::log_identity(&session.username),
            session.max_streams
        );
        #[cfg(feature = "experimental-roaming")]
        if let StreamAttach::Resume { reservation } = stream_attach {
            profile.tcp_roaming_metrics.note_failure();
            if let Some(roaming) = &session.tcp_roaming {
                roaming.abort_resume(reservation);
            }
        }
        return;
    }

    #[cfg(feature = "experimental-roaming")]
    if matches!(stream_attach, StreamAttach::Primary) {
        if let Some(roaming) = &session.tcp_roaming {
            roaming.mark_initial_transport_attached();
        }
    }

    // Keep the receive codec here until a resume transaction has completed its second phase.
    // A candidate occupies a non-ready overflow slot while the old carrier remains schedulable.
    let mut server_rx = server_rx;

    // A JOIN is prepared only after its StreamHandle occupies a real slot. For authenticated
    // resume this acknowledgement is deliberately not the commit point: the client must first
    // commit its exact platform path and prove that fact over this fresh carrier.
    let join_slot = match stream_attach {
        StreamAttach::Primary => None,
        StreamAttach::LegacyJoin { logical_slot_id } => Some(logical_slot_id),
        #[cfg(feature = "experimental-roaming")]
        StreamAttach::Resume { reservation } => Some(reservation.logical_slot_id()),
    };
    if let Some(stream_index) = join_slot {
        let ack = {
            let mut codec = lock_or_recover(&server_tx, "handler::join_ack");
            codec.encrypt_packet(crate::protocol::roaming::TCP_RESUME_PREPARED_ACK, &[])
        };
        let ack_result = match ack {
            Ok(bytes) => write_half
                .write_all(&bytes)
                .await
                .map_err(anyhow::Error::from),
            Err(error) => Err(anyhow::Error::from(error)),
        };
        if let Err(error) = ack_result {
            log::warn!(
                "Stream #{} for '{}' failed before JOINOK on profile '{}' from {}: {}",
                stream_index,
                crate::util::log_identity(&session.username),
                profile.name,
                addr,
                error
            );
            #[cfg(feature = "experimental-roaming")]
            if let StreamAttach::Resume { reservation } = stream_attach {
                profile.tcp_roaming_metrics.note_failure();
                session.remove_stream(stream_id);
                if let Some(roaming) = &session.tcp_roaming {
                    roaming.abort_resume(reservation);
                }
                return;
            }
            detach_stream(&profile, &session, stream_id, addr).await;
            return;
        }

        #[cfg(feature = "experimental-roaming")]
        if let StreamAttach::Resume { reservation } = stream_attach {
            let client_commit = async {
                let record = tokio::time::timeout(
                    TCP_RESUME_COMMIT_TIMEOUT,
                    read_record(&mut read_half, framing),
                )
                .await
                .map_err(|_| anyhow::anyhow!("client commit confirmation timed out"))??;
                let plaintext = server_rx.decrypt_packet(&record)?;
                if plaintext != crate::protocol::roaming::TCP_RESUME_COMMIT {
                    anyhow::bail!("unexpected TCP resume commit confirmation");
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = client_commit {
                profile.tcp_roaming_metrics.note_failure();
                session.remove_stream(stream_id);
                if let Some(roaming) = &session.tcp_roaming {
                    roaming.abort_resume(reservation);
                }
                log::warn!(
                    "TCP resume candidate for '{}' aborted before commit; old carrier remains active: {}",
                    crate::util::log_identity(&session.username),
                    error
                );
                return;
            }

            let Some(roaming) = &session.tcp_roaming else {
                profile.tcp_roaming_metrics.note_failure();
                session.remove_stream(stream_id);
                return;
            };
            let outcome = match roaming.commit_resume(reservation, stream_id) {
                Ok(outcome) => outcome,
                Err(error) => {
                    profile.tcp_roaming_metrics.note_failure();
                    session.remove_stream(stream_id);
                    roaming.abort_resume(reservation);
                    log::warn!(
                        "Authenticated JOIN for '{}' lost its reservation before commit: {}",
                        crate::util::log_identity(&session.username),
                        error
                    );
                    return;
                }
            };
            // This is the only point that retires the old carrier: the new socket completed its
            // handshake, JOINOK reached the client, and COMMIT_PATH succeeded on the platform.
            session.activate_resume_stream(stream_id, outcome);
            let commit_ack = {
                let mut codec = lock_or_recover(&server_tx, "handler::join_commit_ack");
                codec.encrypt_packet(crate::protocol::roaming::TCP_RESUME_COMMIT_ACK, &[])
            };
            let commit_ack_result = match commit_ack {
                Ok(bytes) => write_half
                    .write_all(&bytes)
                    .await
                    .map_err(anyhow::Error::from),
                Err(error) => Err(anyhow::Error::from(error)),
            };
            if let Err(error) = commit_ack_result {
                profile.tcp_roaming_metrics.note_failure();
                log::warn!(
                    "TCP resume for '{}' committed but its final acknowledgement failed: {}",
                    crate::util::log_identity(&session.username),
                    error
                );
                detach_stream(&profile, &session, stream_id, addr).await;
                return;
            }
            profile.tcp_roaming_metrics.note_commit();
            log::info!(
                "ROAMING transport=tcp event=commit profile='{}' user='{}' peer={}",
                profile.name,
                crate::util::log_identity(&session.username),
                addr
            );
        }

        log::info!(
            "Stream #{} JOINed session for user '{}' (IP {}) on profile '{}' from {}",
            stream_index,
            crate::util::log_identity(&session.username),
            session.client_ip,
            profile.name,
            addr
        );
    }

    let base = tokio::time::Instant::now();
    let last_act = Arc::new(AtomicU64::new(0));
    let last_rx = Arc::new(AtomicU64::new(0));
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);

    {
        let tun_tx = tun_tx.clone();
        let profile_r = profile.clone();
        let bytes_recv = session.bytes_recv.clone();
        let session_r = session.clone();
        let last_act = last_act.clone();
        let last_rx = last_rx.clone();
        let addr_r = addr;
        let mut shutdown_rx = shutdown_rx;
        profile.tasks.spawn(async move {
            let recordizer_runtime = session_r.recordizer.as_ref().map(|config| {
                crate::protocol::recordizer::RuntimeConfig::from_config(
                    config,
                    crate::protocol::packet::MAX_TUNNEL_MTU,
                    profile_r.config.tun.mtu.max(0) as usize + 64,
                )
                .expect("validated TCP recordizer configuration")
            });
            let mut mux_rx =
                recordizer_runtime.map(crate::protocol::recordizer::Reassembler::new);
            'reader: loop {
                // Acquire before reading so queue depth and allocation count are one fixed
                // budget. Race both the pool wait and the socket read against shutdown: a
                // kicked client must not remain parked on either resource.
                let mut plaintext = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    packet = tun_tx.pool.acquire() => match packet {
                        Some(packet) => packet,
                        None => break,
                    },
                };
                // Cancellation-safety invariant: cancelling read_record_into may leave the
                // framing reader between a header and its payload. That is safe here only
                // because shutdown_rx is terminal for this stream: after this branch we break,
                // drop read_half and never attempt another record read on it. Do not add a
                // "soft" pause/reload branch to this select without moving the reader into an
                // owning task or retaining its partial-record state across cancellation.
                let record = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    result = read_record_into(
                        &mut read_half,
                        framing,
                        plaintext.as_vec_mut(),
                    ) => result,
                };
                match record {
                    Ok(()) => {
                        let now = base.elapsed().as_millis() as u64;
                        match server_rx.decrypt_packet_in_place(plaintext.as_vec_mut()) {
                            Ok(()) => {
                                // Outer framing alone is not activity: only a record that
                                // passes the inner AEAD may retain the lease/client slot.
                                last_act.store(now, Ordering::Relaxed);
                                // rx-liveness advances ONLY on a successful decrypt:
                                // undecryptable traffic must not keep a dead session
                                // (and its pool IP) alive past the rx-dead reaper.
                                last_rx.store(now, Ordering::Relaxed);
                                if let Some(reassembler) = mux_rx.as_mut() {
                                    if plaintext.is_empty() {
                                        continue;
                                    }
                                    let packets = match reassembler.decode(&plaintext) {
                                        Ok(packets) => packets,
                                        Err(error) => {
                                            log::debug!(
                                                "recordizer decode error from {}: {}",
                                                addr_r,
                                                error
                                            );
                                            continue;
                                        }
                                    };
                                    drop(plaintext);
                                    for packet in packets {
                                        if !forward_server_uplink_packet(
                                            ServerTunPacket::Fragment(packet),
                                            &profile_r,
                                            &session_r,
                                            &tun_tx,
                                            &bytes_recv,
                                            stream_id,
                                        )
                                        .await
                                        {
                                            break 'reader;
                                        }
                                    }
                                    continue;
                                }
                                // In-tunnel control frame, not a packet: authenticated by
                                // the AEAD above and bound to THIS session, which is why the
                                // MTU report rides here rather than as a bare datagram next
                                // to the UDP probes (those are keyed only by source address,
                                // so anyone able to guess a session's IP:port could shrink
                                // its MTU). Handled before the packet path so it never
                                // reaches the ACLs or the TUN. (Audit 2026-07-30, #13.)
                                if let Some(keep_reading) =
                                    handle_server_control(&plaintext, &session_r, addr_r)
                                {
                                    if keep_reading {
                                        continue;
                                    }
                                    break 'reader;
                                }
                                if !plaintext.is_empty() {
                                    // Destination ACL (`allowed_networks`). Checked AFTER
                                    // AEAD/replay (so only authenticated traffic is judged)
                                    // and BEFORE the TUN. Unrestricted sessions — the
                                    // default — short-circuit and pay nothing.
                                    // Source guard first: a forged source is a lie
                                    // about identity, so judge it before anything that
                                    // reasons about this session's rights.
                                    if !session_r.src_guard.allows_packet(&plaintext) {
                                        log::debug!(
                                            "dropped packet from '{}' — disallowed inner source {} (expected {} or a routed subnet)",
                                            crate::util::log_identity(&session_r.username),
                                            crate::server::acl::packet_source(&plaintext)
                                                .map(|source| source.to_string())
                                                .unwrap_or_else(|| "<malformed>".to_string()),
                                            session_r.client_ip
                                        );
                                        continue;
                                    }
                                    if !session_r.dst_acl.is_unrestricted()
                                        && !session_r.dst_acl.allows_packet(&plaintext)
                                    {
                                        log::debug!(
                                            "ACL: dropped packet from '{}' — destination not in allowed_networks",
                                            crate::util::log_identity(&session_r.username)
                                        );
                                        continue;
                                    }
                                    // Throttle client->server upload against the aggregate
                                    // per-session upload bucket. It is shared by all bonded
                                    // readers but independent from the download allowance.
                                    let limit =
                                        session_r.bandwidth_limit_mbps.load(Ordering::Relaxed);
                                    let delay = session_r
                                        .rates
                                        .upload
                                        .consume(plaintext.len() as u64 * 8, limit);
                                    if !delay.is_zero() {
                                        tokio::time::sleep(delay).await;
                                    }
                                    bytes_recv.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                                    crate::trace::record(
                                        crate::trace::Dir::Rx,
                                        "server.stream",
                                        plaintext.len(),
                                        stream_id,
                                    );
                                    if tun_tx
                                        .send_client_packet(
                                            &profile_r,
                                            session_r.session_id,
                                            session_r.exit_access,
                                            ServerTunPacket::Pooled(plaintext),
                                        )
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            }
                            Err(e) => log::debug!("Decrypt error from {}: {}", addr_r, e),
                        }
                    }
                    Err(e) => {
                        // Distinguish a clean close/EOF from a framing desync (under-load
                        // PacketTooLarge / short-record) so the latter shows up in logs;
                        // the stream teardown path is the same either way.
                        match e {
                            crate::protocol::packet::PacketError::ConnectionClosed => {
                                log::debug!("Stream {} read closed (clean)", addr_r)
                            }
                            other => log::warn!(
                                "Stream {} framing desync ({:?}) — closing",
                                addr_r,
                                other
                            ),
                        }
                        break;
                    }
                }
            }
            let _ = dead_tx.try_send(());
        });
    }

    let mut idle_check = tokio::time::interval(Duration::from_secs(5));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let idle_ms = idle_timeout.as_millis() as u64;
    let mut last_tx_ms: u64 = base.elapsed().as_millis() as u64;

    // Flow-shaping (Phase 1, DPI-AUDIT 6.1/6.2): when enabled, idle cover traffic
    // at exponential (non-periodic) gaps REPLACES the fixed heartbeat — the same
    // empty-payload encrypted record the peer drops, but no metronome beacon and
    // no dead air. Real packets are never delayed; only genuine idle is filled,
    // capped by the cover budget.
    let mut shaper = crate::protocol::Shaper::new(
        pcfg.obfuscation.traffic_shaping.to_shaping(),
        std::time::Instant::now(),
    )
    .with_shared_budget(session.cover_budget.clone());
    let shaping_on = shaper.enabled();
    let heartbeat_enabled = heartbeat_enabled && !shaping_on;
    let mut heartbeat_deadline = tokio::time::Instant::now()
        + crate::protocol::randomized_heartbeat_delay(
            heartbeat_interval,
            Duration::from_millis(hb_config.jitter_ms),
        );
    let rx_dead_ms = crate::protocol::liveness_deadline(
        heartbeat_enabled,
        heartbeat_interval,
        Duration::from_millis(hb_config.jitter_ms),
        shaping_on,
        Duration::from_millis(pcfg.obfuscation.traffic_shaping.idle_gap_max_ms),
    )
    .map(|deadline| u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX));
    // NB: never hold a `ThreadRng` (it is `!Send`) across the loop's `.await`s —
    // pass a fresh temporary at each call so the select future stays `Send`.
    let mut cover_deadline = tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());
    let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
    let mut cover_record = Vec::with_capacity(session.wire_pool.buffer_capacity());
    let mut wire_record = Vec::with_capacity(
        crate::protocol::packet::TLS_RECORD_HEADER + crate::protocol::packet::MAX_RECORD_SIZE,
    );
    let recordizer_runtime = session.recordizer.as_ref().map(|config| {
        crate::protocol::recordizer::RuntimeConfig::from_config(
            config,
            crate::protocol::packet::MAX_TUNNEL_MTU,
            pcfg.tun.mtu.max(0) as usize + 64,
        )
        .expect("validated TCP recordizer configuration")
    });
    let mut recordizer = recordizer_runtime.map(crate::protocol::recordizer::Recordizer::new);

    'writer: loop {
        let mux_deadline = recordizer
            .as_ref()
            .and_then(|mux| mux.deadline())
            .map(tokio::time::Instant::from_std)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            biased;

            _ = kick_rx.recv() => { break; }
            _ = dead_rx.recv() => { break; }

            Some(packet) = rx.recv() => {
                last_act.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                crate::trace::record(
                    crate::trace::Dir::Tx, "server.stream", packet.len(), stream_id,
                );
                // Aggregate per-session download throttle: all bonded writers share this
                // bucket, so multipath cannot multiply the cap by N. Upload has an
                // independent bucket, allowing the configured rate in both directions.
                // Stealth mode caps the data plane to the (lower) stealth rate so the
                // flow stops looking like a line-rate bulk download.
                let bw = session.bandwidth_limit_mbps.load(Ordering::Relaxed);
                let limit = if shaping_on && shaper.stealth() {
                    let sr = shaper.stealth_rate_mbps();
                    if bw == 0 { sr } else { bw.min(sr) }
                } else {
                    bw
                };
                let delay = session
                    .rates
                    .download
                    .consume(packet.len() as u64 * 8, limit);
                if shaping_on && shaper.stealth() && !delay.is_zero() {
                    // STEALTH: instead of one smooth sleep (which evens the spacing
                    // into a metronome — a WORSE tell), fill the rate-cap gap with
                    // jittered small cover packets. This (a) breaks the 100% full-MTU
                    // size histogram and (b) makes the timing irregular (not a flat
                    // rate). Cover is budget-capped separately from the data rate.
                    let mut remaining = delay;
                    while remaining > Duration::from_millis(6) {
                        let csize = shaper.next_size(&mut rand::rng());
                        let cover_ready = if shaper.try_spend(csize, std::time::Instant::now()) {
                            let mut obf = Obfuscator::new();
                            obf.generate_padding_into(
                                csize as u16,
                                csize as u16,
                                &mut padding,
                            );
                            let mut codec = lock_or_recover(&server_tx, "handler::stealth_cover");
                            codec
                                .encrypt_packet_into(&[], &padding, &mut cover_record)
                                .is_ok()
                        } else {
                            false
                        };
                        if cover_ready && write_half.write_all(&cover_record).await.is_err() {
                            break;
                        }
                        let step = Duration::from_millis(rand::rng().random_range(4..=18));
                        let s = step.min(remaining);
                        tokio::time::sleep(s).await;
                        remaining = remaining.saturating_sub(s);
                    }
                } else if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let packet_len = packet.len();
                session.bytes_sent.fetch_add(packet_len as u64, Ordering::Relaxed);
                if let Some(mux) = recordizer.as_mut() {
                    let ready = mux.push(packet.as_ref(), std::time::Instant::now());
                    drop(packet);
                    let payloads = match ready {
                        Ok(payloads) => payloads,
                        Err(error) => {
                            log::debug!("server TCP recordizer dropped a packet: {error}");
                            continue;
                        }
                    };
                    for payload in payloads {
                        if !encrypt_server_stream_payload(
                            &server_tx,
                            &payload,
                            crate::protocol::packet::MAX_TUNNEL_MTU,
                            pcfg,
                            &mut wire_record,
                            &mut padding,
                        ) {
                            continue;
                        }
                        if write_half.write_all(&wire_record).await.is_err() {
                            break 'writer;
                        }
                        last_tx_ms = base.elapsed().as_millis() as u64;
                        heartbeat_deadline = tokio::time::Instant::now()
                            + crate::protocol::randomized_heartbeat_delay(
                                heartbeat_interval,
                                Duration::from_millis(hb_config.jitter_ms),
                            );
                    }
                } else {
                    let packet_budget = crate::protocol::ip::parse_ip_packet(packet.as_ref())
                        .ok()
                        .and_then(|meta| session.downlink_mtu(pcfg.tun.mtu, meta.version))
                        .map(usize::from)
                        .unwrap_or_else(|| pcfg.tun.mtu.max(0) as usize)
                        .max(packet_len)
                        .min(crate::protocol::packet::MAX_TUNNEL_MTU);
                    let encrypted = encrypt_server_stream_payload(
                        &server_tx,
                        packet.as_ref(),
                        packet_budget,
                        pcfg,
                        &mut wire_record,
                        &mut padding,
                    );
                    drop(packet);
                    if encrypted {
                        if write_half.write_all(&wire_record).await.is_err() {
                            break;
                        }
                        last_tx_ms = base.elapsed().as_millis() as u64;
                        heartbeat_deadline = tokio::time::Instant::now()
                            + crate::protocol::randomized_heartbeat_delay(
                                heartbeat_interval,
                                Duration::from_millis(hb_config.jitter_ms),
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
                    let encrypted = encrypt_server_stream_payload(
                        &server_tx,
                        &payload,
                        crate::protocol::packet::MAX_TUNNEL_MTU,
                        pcfg,
                        &mut wire_record,
                        &mut padding,
                    );
                    if encrypted && write_half.write_all(&wire_record).await.is_err() {
                        break;
                    }
                    last_tx_ms = base.elapsed().as_millis() as u64;
                    heartbeat_deadline = tokio::time::Instant::now()
                        + crate::protocol::randomized_heartbeat_delay(
                            heartbeat_interval,
                            Duration::from_millis(hb_config.jitter_ms),
                        );
                }
            }

            _ = tokio::time::sleep_until(heartbeat_deadline), if heartbeat_enabled => {
                let heartbeat_ready = {
                    let mut obf = Obfuscator::new();
                    obf.generate_padding_into(
                        hb_config.data_size_bytes,
                        hb_config.data_size_bytes.saturating_add(32),
                        &mut padding,
                    );
                    let mut codec = lock_or_recover(&server_tx, "handler::heartbeat");
                    codec
                        .encrypt_packet_into(&[], &padding, &mut cover_record)
                        .is_ok()
                };
                if heartbeat_ready && write_half.write_all(&cover_record).await.is_err() {
                    break;
                }
                let now_ms = base.elapsed().as_millis() as u64;
                last_act.store(now_ms, Ordering::Relaxed);
                last_tx_ms = now_ms;
                heartbeat_deadline = tokio::time::Instant::now()
                    + crate::protocol::randomized_heartbeat_delay(
                        heartbeat_interval,
                        Duration::from_millis(hb_config.jitter_ms),
                    );
            }
            _ = tokio::time::sleep_until(cover_deadline), if shaping_on => {
                let now_ms = base.elapsed().as_millis() as u64;
                // Normally fill only GENUINE idle (save budget when traffic flows).
                // In STEALTH, run cover UNDER LOAD too: the small cover packets mix
                // into the rate-capped full-MTU stream, breaking the size+timing tell.
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
                            let mut codec = lock_or_recover(&server_tx, "handler::cover");
                            codec
                                .encrypt_packet_into(&[], &padding, &mut cover_record)
                                .is_ok()
                        };
                        if cover_ready {
                            if write_half.write_all(&cover_record).await.is_err() {
                                break;
                            }
                            let n = base.elapsed().as_millis() as u64;
                            last_act.store(n, Ordering::Relaxed);
                            last_tx_ms = n;
                        }
                    }
                }
                cover_deadline =
                    tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());
            }

            _ = idle_check.tick() => {
                // saturating_sub, not `-`: `now` is sampled before the atomic load, and the
                // READER task (a different task) writes `last_act`/`last_rx` in between. A
                // timestamp newer than `now` therefore happens under load, and release
                // builds have `overflow-checks` off — plain subtraction wrapped to ~2^64,
                // sailed past the threshold and reaped a perfectly healthy session. The
                // cover-traffic arm above already uses saturating_sub for the same value.
                // (Audit 2026-07-27, F2.)
                let now = base.elapsed().as_millis() as u64;
                if idle_timeout.as_secs() > 0
                    && now.saturating_sub(last_act.load(Ordering::Relaxed)) > idle_ms {
                    break;
                }
                // An RX deadline is meaningful only while the client promises
                // heartbeat/shaping traffic. With both disabled a healthy TCP tunnel
                // may legitimately be silent for hours; the old 120 s fallback reaped it.
                if let Some(rx_dead) = rx_dead_ms {
                    if now.saturating_sub(last_rx.load(Ordering::Relaxed)) > rx_dead {
                        log::info!("Stream {} ({}) reaped: no inbound for >{}s on profile '{}'",
                            addr, crate::util::log_identity(&session.username), rx_dead / 1000, profile.name);
                        break;
                    }
                }
            }
        }
    }

    // The writer loop has ended — for ANY reason: kick, idle reap, rx-dead reap,
    // peer close. Take the reader with it. The two reapers above live in this loop,
    // so once it exits nothing else bounds the reader in time; without this a stream
    // that died on a timeout could leave a reader forwarding uploads indefinitely.
    let _ = shutdown_tx.send(true);

    detach_stream(&profile, &session, stream_id, addr).await;
}

/// Detach one bonded stream and perform the fire-once session teardown when it was the last.
/// Kept in one helper so failures before the pump starts (notably JOINOK write failure) cannot
/// leave a token, pool lease or client route orphaned.
async fn detach_stream(
    profile: &Arc<ProfileRuntime>,
    session: &Arc<SessionShared>,
    stream_id: u64,
    addr: SocketAddr,
) {
    let was_last = session.remove_stream(stream_id);
    #[cfg(feature = "experimental-roaming")]
    if let Some(roaming) = &session.tcp_roaming {
        let reason = if session.is_revoked() {
            DetachReason::Revoked
        } else if session.is_closing() {
            DetachReason::CleanClose
        } else {
            DetachReason::Unexpected
        };
        match roaming.detach(stream_id, reason, Instant::now()) {
            Ok(DetachOutcome::StreamRemains) => return,
            Ok(DetachOutcome::Orphaned(ticket)) => {
                log::info!(
                    "Client {} ({}) lost its last TCP path on profile '{}'; retaining session for authenticated resume",
                    addr,
                    crate::util::log_identity(&session.username),
                    profile.name
                );
                schedule_tcp_orphan_reaper(profile.clone(), session.clone(), ticket, addr);
                return;
            }
            Ok(DetachOutcome::Closing | DetachOutcome::Revoked) => {}
            Err(error) => {
                profile.tcp_roaming_metrics.note_failure();
                // Cap exhaustion and terminal races fail closed. A concurrent authoritative
                // removal makes the legacy guarded cleanup below a no-op.
                log::warn!(
                    "TCP roaming detach for '{}' closed the session: {}",
                    crate::util::log_identity(&session.username),
                    error
                );
            }
        }
    }
    if was_last {
        // Serialize the authoritative session removal and pool release with every new
        // authentication for this profile. Without the admission guard, a reconnect of the
        // same device_key could observe no live session, idempotently reclaim its old lease,
        // and then have that live lease freed by this older teardown before the new session
        // was inserted. Keep the guard through release; the sessions lock itself is still
        // dropped before taking the pool lock, preserving the established lock order.
        let _admission_guard = profile.admission.lock().await;
        let mut sessions = profile.sessions.write().await;
        if sessions.by_ip.get(&session.client_ip).map(|s| s.session_id) == Some(session.session_id)
        {
            sessions.remove(session.client_ip);
            // #13 iroute: drop this client's inbound routes; delete their kernel routes
            // after the lock is released.
            let iroutes: Vec<String> = sessions
                .client_routes
                .iter()
                .filter(|r| r.client_ip == session.client_ip)
                .map(|r| r.cidr.clone())
                .collect();
            sessions
                .client_routes
                .retain(|r| r.client_ip != session.client_ip);
            drop(sessions);
            for cidr in &iroutes {
                let _ = program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
            }
            profile.pool.lock().await.release(&session.device_key);
            log::info!(
                "Client {} ({}) disconnected from profile '{}'",
                addr,
                crate::util::log_identity(&session.username),
                profile.name
            );
            // Notify (opt-in) — this guarded block is the fire-once per-session TCP
            // teardown (clean close), so no double-fire across bonded streams.
            crate::server::notify::fire_disconnect(&session.username, &profile.name, addr);
        }
    }
}

#[cfg(feature = "experimental-roaming")]
fn schedule_tcp_orphan_reaper(
    profile: Arc<ProfileRuntime>,
    session: Arc<SessionShared>,
    ticket: ReapTicket,
    addr: SocketAddr,
) {
    let tasks = profile.tasks.clone();
    tasks.spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(ticket.deadline())).await;
        let should_reap = session
            .tcp_roaming
            .as_ref()
            .is_some_and(|roaming| roaming.reap(ticket, Instant::now()));
        if should_reap {
            profile.tcp_roaming_metrics.note_grace_expired();
            finalize_orphaned_tcp_session(&profile, &session, addr).await;
        }
    });
}

#[cfg(feature = "experimental-roaming")]
async fn finalize_orphaned_tcp_session(
    profile: &Arc<ProfileRuntime>,
    session: &Arc<SessionShared>,
    addr: SocketAddr,
) {
    let _admission_guard = profile.admission.lock().await;
    let mut sessions = profile.sessions.write().await;
    if sessions.by_ip.get(&session.client_ip).map(|s| s.session_id) != Some(session.session_id) {
        return;
    }
    sessions.remove(session.client_ip);
    let iroutes = sessions.take_client_routes(session.client_ip);
    drop(sessions);
    for cidr in &iroutes {
        let _ = program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
    }
    profile.pool.lock().await.release(&session.device_key);
    log::info!(
        "Client {} ({}) disconnected from profile '{}' (roaming grace expired)",
        addr,
        crate::util::log_identity(&session.username),
        profile.name
    );
    crate::server::notify::fire_disconnect(&session.username, &profile.name, addr);
}

/// Interpret effective pushed `/0` routes as permissions to use an internal exit node.
/// The route JSON is already the exact per-user-or-profile set sent in AuthOK, so personal
/// route override semantics and negotiated-family filtering stay identical in both places.
pub(crate) fn exit_access_from_routes_json(routes_json: &str) -> ExitAccess {
    let Ok(routes) = serde_json::from_str::<Vec<serde_json::Value>>(routes_json) else {
        return ExitAccess::default();
    };
    let mut access = ExitAccess::default();
    for route in routes {
        let Some(cidr) = route.get("cidr").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some((address, prefix)) = cidr.trim().split_once('/') else {
            continue;
        };
        if prefix.trim() != "0" {
            continue;
        }
        match address.trim().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => access.ipv4 = true,
            Ok(std::net::IpAddr::V6(_)) => access.ipv6 = true,
            Err(_) => {}
        }
    }
    access
}

/// Remove server-internal exit authorization markers from AuthOK. Qeli deliberately does
/// not let a server force a client into full tunnel with a pushed `/0`; the consumer opts in
/// locally with `gateway = true`. More-specific advertised routes are unchanged.
pub(crate) fn routes_without_exit_defaults(routes_json: &str) -> String {
    let Ok(mut routes) = serde_json::from_str::<Vec<serde_json::Value>>(routes_json) else {
        return "[]".to_string();
    };
    routes.retain(|route| {
        let Some(cidr) = route.get("cidr").and_then(serde_json::Value::as_str) else {
            return true;
        };
        let Some((address, prefix)) = cidr.trim().split_once('/') else {
            return true;
        };
        !(prefix.trim() == "0" && address.trim().parse::<std::net::IpAddr>().is_ok())
    });
    serde_json::Value::Array(routes).to_string()
}

async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_kp: &Keypair,
    pcfg: &crate::config::server::ProfileConfig,
) -> anyhow::Result<(crate::crypto::PublicKey, [u8; 32], [u8; 32])> {
    let record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read ClientHello: {}", e))?;

    log::debug!("Received ClientHello: {} bytes", record.len());

    // Build the records + transcript once (shared with the UDP path).
    let HandshakeRecords {
        client_pub,
        server_hello,
        ccs,
        cert,
        finished,
        nst,
        transcript_hash,
        mlkem_shared,
    } = build_handshake_records(&record, server_kp.public())?;

    // Anti-fingerprinting: a constant server think-time between the ClientHello and
    // our reply is itself a tell. Spread the reply over a few ms so the timing
    // histogram stops being a spike. Cheap, and it costs the client nothing.
    if pcfg.obfuscation.anti_fingerprinting.enabled
        && pcfg.obfuscation.anti_fingerprinting.add_jitter_to_handshake
    {
        let jitter_ms = rand::random::<u64>() % 12;
        if jitter_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
        }
    }

    if pcfg.obfuscation.fragmentation.enabled {
        // Split the ServerHello with the configured chunk sizes instead of the old
        // fixed `1 + (len-1) % 4` two-way cut: a deterministic split is itself a
        // signature, and the sizes were config-surfaced but never reached the wire.
        let fcfg = &pcfg.obfuscation.fragmentation;
        // Compute the split in a scope that ENDS before the first .await: the
        // Obfuscator holds a ThreadRng, which is !Send, and holding it across an
        // await would make this whole future !Send and break tokio::spawn.
        let parts = {
            let mut obf = crate::protocol::obfuscate::Obfuscator::new();
            obf.fragment_packet(
                &server_hello,
                fcfg.min_chunk_size,
                fcfg.max_chunk_size,
                fcfg.max_fragments_per_packet,
            )
        };
        for (i, part) in parts.iter().enumerate() {
            stream.write_all(part).await?;
            stream.flush().await?;
            if i + 1 < parts.len() {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        }

        stream.write_all(&ccs).await?;
        stream.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let mut cert_fin = Vec::with_capacity(cert.len() + finished.len());
        cert_fin.extend_from_slice(&cert);
        cert_fin.extend_from_slice(&finished);
        let cf_split = 3 + (cert_fin.len() - 3) % 7;
        stream.write_all(&cert_fin[..cf_split]).await?;
        stream.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        stream.write_all(&cert_fin[cf_split..]).await?;
        stream.flush().await?;

        stream.write_all(&nst).await?;
    } else {
        stream.write_all(&server_hello).await?;
        stream.write_all(&ccs).await?;
        stream.write_all(&cert).await?;
        stream.write_all(&finished).await?;
        stream.write_all(&nst).await?;
    }

    Ok((client_pub, transcript_hash, mlkem_shared))
}

/// `plain` wire mode server handshake: read the client's raw 32-byte ephemeral
/// X25519 public key, reply with ours, and channel-bind to H(client‖server). No
/// TLS records — the mirror of the client's `plain` branch in `tcp_handshake`.
async fn raw_server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_kp: &Keypair,
) -> anyhow::Result<(crate::crypto::PublicKey, [u8; 32])> {
    let mut cp = [0u8; 32];
    stream
        .read_exact(&mut cp)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read client key (plain): {}", e))?;
    let client_pub = crate::crypto::PublicKey::from_bytes(&cp);
    stream.write_all(server_kp.public().as_bytes()).await?;
    let transcript_hash = handshake_transcript_hash(&[&cp, server_kp.public().as_bytes()]);
    Ok((client_pub, transcript_hash))
}

// ── shared, transport-agnostic handshake + auth (used by TCP handler.rs AND
//    UDP udp_handler.rs — the only difference between the two is framing/IO,
//    so all the crypto and auth verification lives here once) ─────────────────

/// The fake-TLS handshake records the server emits + the channel-binding
/// transcript hash, derived from the client's ClientHello. Pure crypto; the
/// caller sends these over its own transport (stream writes / datagram bundle).
pub struct HandshakeRecords {
    pub client_pub: crate::crypto::PublicKey,
    pub server_hello: Vec<u8>,
    pub ccs: Vec<u8>,
    pub cert: Vec<u8>,
    pub finished: Vec<u8>,
    pub nst: Vec<u8>,
    pub transcript_hash: [u8; 32],
    /// ML-KEM-768 shared secret from encapsulating against the client's
    /// X25519MLKEM768 key_share — folded with the X25519 secret into the tunnel KDF
    /// ([`crate::crypto::derive_keys_hybrid`]) so the tunnel is post-quantum.
    pub mlkem_shared: [u8; 32],
}

/// Parse the ClientHello, build ServerHello/CCS/Cert/Finished/NST and the
/// transcript hash (ClientHello‖ServerHello‖Cert‖Finished — CCS/NST excluded).
pub fn build_handshake_records(
    client_hello: &[u8],
    server_pub: &crate::crypto::PublicKey,
) -> anyhow::Result<HandshakeRecords> {
    let cpk = FakeTlsHandshake::parse_client_hello(client_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to parse ClientHello"))?;
    if cpk.len() != 32 {
        return Err(anyhow::anyhow!("invalid client public key length"));
    }
    let mut kb = [0u8; 32];
    kb.copy_from_slice(&cpk);
    let client_pub = crate::crypto::PublicKey::from_bytes(&kb);

    // Hybrid PQ key exchange: encapsulate against the client's ML-KEM-768
    // encapsulation key (carried in the ClientHello's X25519MLKEM768 key_share) and
    // return the ciphertext in the (hybrid) ServerHello, so both sides fold the
    // ML-KEM secret into the tunnel KDF. A ClientHello with no usable ek cannot do
    // the hybrid handshake (an old classic-only peer) and is rejected here.
    let client_ek = FakeTlsHandshake::extract_client_mlkem_ek(client_hello)
        .ok_or_else(|| anyhow::anyhow!("ClientHello missing the X25519MLKEM768 key_share"))?;
    let (ct, ml_ss) = crate::crypto::mlkem::mlkem768_encapsulate(&client_ek)
        .ok_or_else(|| anyhow::anyhow!("ML-KEM encapsulation failed (malformed ek)"))?;
    let mlkem_shared: [u8; 32] = ml_ss
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ML-KEM shared secret not 32 bytes"))?;

    let server_hello = FakeTlsHandshake::build_server_hello_pq(server_pub, &ct);
    let cert = FakeTlsHandshake::build_certificate();
    let finished = FakeTlsHandshake::build_finished();
    let transcript_hash =
        handshake_transcript_hash(&[client_hello, &server_hello, &cert, &finished]);
    Ok(HandshakeRecords {
        client_pub,
        server_hello,
        ccs: FakeTlsHandshake::build_change_cipher_spec(),
        cert,
        finished,
        nst: FakeTlsHandshake::build_new_session_ticket(),
        transcript_hash,
        mlkem_shared,
    })
}

/// Build the server's auth-proof message. In `hide_identity`
/// (require_client_key_proof) mode the static public key is NOT put on the wire
/// — only the proof; otherwise `static_pub‖proof` for TOFU clients.
pub fn build_server_auth_msg(
    static_kp: &crate::crypto::StaticKeypair,
    client_pub: &crate::crypto::PublicKey,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    hide_identity: bool,
) -> Vec<u8> {
    build_server_auth_msg_with_capabilities(
        static_kp,
        client_pub,
        ephemeral_shared,
        transcript_hash,
        hide_identity,
        crate::protocol::capabilities::implemented_server_capabilities(),
    )
}

pub fn build_server_auth_msg_with_capabilities(
    static_kp: &crate::crypto::StaticKeypair,
    client_pub: &crate::crypto::PublicKey,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    hide_identity: bool,
    capabilities: crate::protocol::capabilities::ServerCapabilities,
) -> Vec<u8> {
    let mut message = if hide_identity {
        crate::crypto::build_server_proof_only(
            static_kp,
            client_pub,
            ephemeral_shared,
            transcript_hash,
        )
        .to_vec()
    } else {
        build_server_auth_message(static_kp, client_pub, ephemeral_shared, transcript_hash)
    };
    crate::protocol::capabilities::append_server_capabilities(&mut message, capabilities);
    message
}

/// A cached, valid Argon2id PHC hash of a throwaway password. Verifying a
/// candidate password against it costs the same memory-hard work as a real
/// user's hash, so the "user not found" path can spend that work too and not
/// betray (by being fast) which usernames exist. Built once on first use with
/// the crate's default params; the hashed value itself is irrelevant.
fn dummy_password_hash() -> &'static str {
    use std::sync::OnceLock;
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(b"qeli-dummy-salt!").expect("valid dummy salt");
        // Must use the SAME profile as real password hashing: this hash exists so an
        // unknown username costs the attacker exactly what a known one does. If the two
        // ever diverge — say the real cost is raised here but the dummy keeps the crate
        // default — the work gap becomes a username oracle again, which is the whole
        // thing this dummy prevents. (Audit 2026-07-27, H2.)
        crate::crypto::password_hasher()
            .hash_password(b"qeli-nonexistent-user", &salt)
            .expect("hash dummy password")
            .to_string()
    })
}

/// Verify a client's authentication (after the parsed `[key_proof][user:pass]`).
/// Runs every check in the canonical order — server-key-proof (when required),
/// brute-force lockout, user lookup, Argon2 password, per-profile authorisation
/// — recording failures/success so both transports behave identically. Returns
/// `Ok(())` only when fully authenticated; the caller then does its own
/// (transport-specific) session setup. `proto` is just a log label ("TCP"/"UDP").
#[allow(clippy::too_many_arguments)]
pub async fn verify_client_auth(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    addr: SocketAddr,
    proto: &str,
    client_key_proof: &[u8],
    username: &str,
    password: &str,
    static_shared: &[u8; 32],
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> anyhow::Result<()> {
    // Server-key pinning: only a client that already had our static key can
    // produce a valid proof — rejects unpinned/TOFU clients (and scanners).
    if server_state.config.auth.require_client_key_proof {
        let expected = crate::crypto::compute_client_key_proof(
            static_shared,
            ephemeral_shared,
            transcript_hash,
        );
        if !crate::crypto::auth::ct_eq(client_key_proof, &expected[..]) {
            log::warn!(
                "AUTH DENIED {} {}: user={} — server key not pinned (require_client_key_proof)",
                proto,
                addr,
                crate::util::log_identity(username)
            );
            // Count against the source IP only: a probe that fails the
            // server-key proof never proved interest in this username, so it
            // must not be able to drive that username's tarpit (L1).
            server_state
                .failed_auth
                .lock()
                .await
                .record_ip_failure(addr.ip());
            return Err(anyhow::anyhow!(
                "client must pin server key (require_client_key_proof)"
            ));
        }
    }

    // Brute-force defence. Hard lockout is per source IP only — a username is
    // never hard-locked, so a flood of failures for a victim's username cannot
    // deny that victim service (L1).
    {
        let tracker = server_state.failed_auth.lock().await;
        if let Err(msg) = tracker.check_ip(addr.ip()) {
            log::warn!(
                "AUTH BLOCKED {} {}: user={} — {}",
                proto,
                addr,
                crate::util::log_identity(username),
                msg
            );
            return Err(anyhow::anyhow!("authentication blocked: {}", msg));
        }
    }
    // Adaptive per-username tarpit: throttles distributed guessing of THIS
    // username (an attacker rotating IPs still pays an escalating, capped delay
    // per attempt) without ever blocking it — a correct password below still
    // authenticates. Zero in steady state.
    let tarpit = server_state.failed_auth.lock().await.user_tarpit(username);
    if !tarpit.is_zero() {
        tokio::time::sleep(tarpit).await;
    }

    let (password_hash, allowed_here, data_limit_gb, expire_at) = {
        let db = server_state.users_db.read().await;
        match db.find_user(username) {
            Some(user) => (
                user.password_hash.clone(),
                user.allowed_on_profile(&profile.name),
                user.data_limit_gb,
                user.expire_at,
            ),
            None => {
                log::warn!(
                    "AUTH FAIL {} {}: user={} — not found or disabled",
                    proto,
                    addr,
                    crate::util::log_identity(username)
                );
                drop(db);
                // Spend the same Argon2 work as the wrong-password path below, so an
                // unknown username is not distinguishable from a known one by how
                // fast the server rejects it (anti-enumeration). Result discarded.
                //
                // Take the SAME concurrency permit the real verify holds. Without it this
                // path bypassed the memory-hard limiter entirely: a flood of made-up
                // usernames — which needs no valid credentials at all — spawned an
                // unbounded number of ~19 MiB Argon2 jobs, defeating the very gate that
                // exists to bound them. Holding it also keeps the timing equivalent under
                // load, which is the point of doing this work in the first place.
                let pw_bytes = password.as_bytes().to_vec();
                {
                    let _permit = crate::server::argon2_gate().acquire().await;
                    let _ = tokio::task::spawn_blocking(move || {
                        use argon2::PasswordVerifier;
                        if let Ok(ph) = argon2::PasswordHash::new(dummy_password_hash()) {
                            let _ = argon2::Argon2::default().verify_password(&pw_bytes, &ph);
                        }
                    })
                    .await;
                }
                let locked = server_state
                    .failed_auth
                    .lock()
                    .await
                    .record_failure(username, addr.ip());
                if locked {
                    crate::server::notify::fire_throttled(
                        &format!("authlock:{}", addr.ip()),
                        3600,
                        crate::server::notify::Event::AuthLockout,
                        &format!(
                            "{} locked after repeated wrong VPN credentials (last user: {})",
                            addr.ip(),
                            crate::util::log_identity(username)
                        ),
                    )
                    .await;
                }
                return Err(anyhow::anyhow!(
                    "user not found or disabled: {}",
                    crate::util::log_identity(username)
                ));
            }
        }
    };

    let pw_bytes = password.as_bytes().to_vec();
    let uname = username.to_string();
    // Bound concurrent memory-hard work. Nothing recorded a failure until the hash
    // finished, so a burst of auth datagrams/connections all passed the pre-check and
    // each started its own ~19 MiB Argon2 job; up to MAX_PENDING_HANDSHAKES of them on
    // the UDP path alone. Held across the verify.
    let _permit = crate::server::argon2_gate().acquire().await;
    let auth_result = tokio::task::spawn_blocking(move || {
        let ph = argon2::PasswordHash::new(&password_hash)
            .map_err(|e| anyhow::anyhow!("invalid password hash: {}", e))?;
        use argon2::PasswordVerifier;
        argon2::Argon2::default()
            .verify_password(&pw_bytes, &ph)
            .map_err(|_| {
                anyhow::anyhow!(
                    "invalid password for user: {}",
                    crate::util::log_identity(&uname)
                )
            })
    })
    .await?;

    if let Err(e) = auth_result {
        log::warn!(
            "AUTH FAIL {} {}: user={} — wrong password",
            proto,
            addr,
            crate::util::log_identity(username)
        );
        let locked = server_state
            .failed_auth
            .lock()
            .await
            .record_failure(username, addr.ip());
        if locked {
            crate::server::notify::fire_throttled(
                &format!("authlock:{}", addr.ip()),
                3600,
                crate::server::notify::Event::AuthLockout,
                &format!(
                    "{} locked after repeated wrong VPN credentials (last user: {})",
                    addr.ip(),
                    crate::util::log_identity(username)
                ),
            )
            .await;
        }
        return Err(e);
    }

    server_state
        .failed_auth
        .lock()
        .await
        .record_success(username);

    // Per-profile authorisation: valid credentials are not enough.
    if !allowed_here {
        log::warn!(
            "AUTH DENIED {} {}: user={} not permitted on profile '{}'",
            proto,
            addr,
            crate::util::log_identity(username),
            profile.name
        );
        return Err(anyhow::anyhow!(
            "user '{}' not authorised for profile '{}'",
            crate::util::log_identity(username),
            profile.name
        ));
    }
    // Tier-2: data-cap / expiry enforcement. A rejection here is an ordinary auth
    // failure on the wire (same as a disabled account / wrong password), so every
    // client handles it unchanged — no protocol change, no client rebuild.
    if let Some(exp) = expire_at {
        if crate::server::usage::now_unix() >= exp {
            log::warn!(
                "AUTH DENIED {} {}: user={} — account expired",
                proto,
                addr,
                crate::util::log_identity(username)
            );
            return Err(anyhow::anyhow!("account expired"));
        }
    }
    if data_limit_gb > 0 {
        // The cap applies to DOWNLOAD only (server→client); uploads are unmetered.
        let used = server_state.usage.used_down(username);
        if used >= data_limit_gb.saturating_mul(1_000_000_000) {
            log::warn!(
                "AUTH DENIED {} {}: user={} — download quota exhausted ({} / {} GB down)",
                proto,
                addr,
                crate::util::log_identity(username),
                used / 1_000_000_000,
                data_limit_gb
            );
            return Err(anyhow::anyhow!("data quota exhausted"));
        }
    }

    log::info!(
        "AUTH OK {} {}: user={} on profile '{}'",
        proto,
        addr,
        crate::util::log_identity(username),
        profile.name
    );
    Ok(())
}

pub fn build_routes_json_pub(
    pcfg: &crate::config::server::ProfileConfig,
    users_db: &crate::config::users::UsersDb,
    username: &str,
    assigned: crate::server::pool::AssignedAddresses,
) -> String {
    build_routes_json_for_user(pcfg, users_db, username, assigned)
}

/// Resolve a user's FIXED tunnel address for this profile (variant-b static IP): the
/// per-user `static_ip`, else a profile-level `pool.reservation.<user>`. A configured value
/// that cannot be parsed is an admission error; only an actually absent value becomes `None`.
/// Read from the LIVE users_db at auth time, so a panel edit + SIGHUP takes effect at once.
pub fn resolve_static_ip(
    users_db: &crate::config::users::UsersDb,
    pcfg: &crate::config::server::ProfileConfig,
    username: &str,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    let Some(configured) = users_db
        .find_user(username)
        .and_then(|u| u.static_ip.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| pcfg.pool.static_reservations.get(username).cloned())
    else {
        return Ok(None);
    };
    configured
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map(Some)
        .map_err(|error| {
            anyhow::anyhow!(
                "static_ip '{}' for user '{}' on profile '{}' is invalid: {error}",
                configured,
                crate::util::log_identity(username),
                pcfg.name
            )
        })
}

/// Resolve a user's fixed IPv6 tunnel address from the live user database, falling back
/// to the profile-level IPv6 reservation. Pool membership and exclusions are enforced by
/// the allocator under the same lock as the IPv4 side of a dual allocation.
pub fn resolve_static_ipv6(
    users_db: &crate::config::users::UsersDb,
    pcfg: &crate::config::server::ProfileConfig,
    username: &str,
) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
    let Some(configured) = users_db
        .find_user(username)
        .and_then(|user| user.static_ipv6.clone())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| pcfg.pool.ipv6.static_reservations.get(username).cloned())
    else {
        return Ok(None);
    };
    configured
        .trim()
        .parse::<std::net::Ipv6Addr>()
        .map(Some)
        .map_err(|error| {
            anyhow::anyhow!(
                "static_ipv6 '{}' for user '{}' on profile '{}' is invalid: {error}",
                configured,
                crate::util::log_identity(username),
                pcfg.name
            )
        })
}

pub fn resolve_static_addresses(
    users_db: &crate::config::users::UsersDb,
    pcfg: &crate::config::server::ProfileConfig,
    username: &str,
    mode: crate::config::server::IpMode,
) -> anyhow::Result<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    let ipv4 = if matches!(
        mode,
        crate::config::server::IpMode::Ipv4 | crate::config::server::IpMode::Dual
    ) {
        resolve_static_ip(users_db, pcfg, username)?
    } else {
        None
    };
    let ipv6 = if matches!(
        mode,
        crate::config::server::IpMode::Ipv6 | crate::config::server::IpMode::Dual
    ) {
        resolve_static_ipv6(users_db, pcfg, username)?
    } else {
        None
    };
    Ok((ipv4, ipv6))
}

/// Build the auth-OK payload sent to the client after a successful login.
///
/// Self-describing keyed JSON (each parameter labelled by its key), prefixed
/// with the `OK:` success marker. This replaced a positional `OK:a:b:c:…` line
/// that was fragile — a shifted/added field silently broke client parsing.
/// `routes` is the advertised-routes array; `obfuscation` carries the pushed
/// padding/heartbeat/traffic-normalization params inline (no base64 needed —
/// JSON nests without the `:` delimiter collision the old format worked around).
pub fn build_auth_ok(
    client_ip: &str,
    pcfg: &crate::config::server::ProfileConfig,
    routes_json: &str,
    token: &[u8; JOIN_TOKEN_LEN],
    max_streams: u32,
    client_capabilities: Option<crate::protocol::capabilities::ClientCapabilities>,
) -> String {
    let ipv4 = client_ip.parse::<std::net::Ipv4Addr>().ok();
    build_auth_ok_for_addresses(
        crate::server::pool::AssignedAddresses { ipv4, ipv6: None },
        pcfg,
        routes_json,
        token,
        max_streams,
        client_capabilities,
    )
}

pub(crate) fn build_auth_error(reason: &str) -> String {
    format!("ERR:{reason}")
}

pub fn build_auth_ok_for_addresses(
    assigned: crate::server::pool::AssignedAddresses,
    pcfg: &crate::config::server::ProfileConfig,
    routes_json: &str,
    token: &[u8; JOIN_TOKEN_LEN],
    max_streams: u32,
    client_capabilities: Option<crate::protocol::capabilities::ClientCapabilities>,
) -> String {
    build_auth_ok_for_addresses_with_udp_roaming(
        assigned,
        pcfg,
        routes_json,
        token,
        max_streams,
        client_capabilities,
        None,
    )
}

/// UDP-only AuthOK extension. The session id is encrypted inside PacketCodec and emitted only
/// after UDP_ROAM_V1 negotiation; legacy TCP/UDP callers stay byte-compatible through the wrapper.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_auth_ok_for_addresses_with_udp_roaming(
    assigned: crate::server::pool::AssignedAddresses,
    pcfg: &crate::config::server::ProfileConfig,
    routes_json: &str,
    token: &[u8; JOIN_TOKEN_LEN],
    max_streams: u32,
    client_capabilities: Option<crate::protocol::capabilities::ClientCapabilities>,
    udp_roaming_session_id: Option<u64>,
) -> String {
    let primary_address = assigned
        .ipv4
        .map(std::net::IpAddr::V4)
        .or_else(|| assigned.ipv6.map(std::net::IpAddr::V6));
    let client_ip = primary_address
        .map(|address| address.to_string())
        .unwrap_or_default();
    let obf = crate::config::PushedObf {
        padding: pcfg.obfuscation.padding.clone(),
        heartbeat: pcfg.obfuscation.heartbeat.clone(),
        traffic_normalization: pcfg.obfuscation.traffic_normalization.clone(),
        traffic_shaping: pcfg.obfuscation.traffic_shaping.clone(),
        recordizer: if !pcfg.obfuscation.recordizer.is_off()
            && crate::protocol::capabilities::packet_mux_supported(client_capabilities)
        {
            Some(pcfg.obfuscation.recordizer.clone())
        } else {
            None
        },
    };
    let routes: serde_json::Value =
        serde_json::from_str(routes_json).unwrap_or_else(|_| serde_json::json!([]));
    // DNS pushed to the client: an explicit `dns.push_servers` (first entry) wins and
    // works WITHOUT the in-tunnel proxy — hand clients a chosen resolver (a LAN /
    // AdGuard / NextDNS box) directly. Otherwise push the proxy's listen IP only when
    // the proxy runs (its default 10.9.0.1 resolves nowhere — pushing it would black-
    // hole client name resolution). Empty => the client keeps its own resolvers. The
    // client strict-IP-validates the pushed value before touching resolv.conf.
    let family_is_active = |address: std::net::IpAddr| {
        (address.is_ipv4() && assigned.ipv4.is_some())
            || (address.is_ipv6() && assigned.ipv6.is_some())
    };
    let mut pushed_dns_servers: Vec<&str> = if !pcfg.dns.push_servers.is_empty() {
        pcfg.dns
            .push_servers
            .iter()
            .filter_map(|value| {
                value
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .filter(|address| family_is_active(*address))
                    .map(|_| value.as_str())
            })
            .collect()
    } else {
        Vec::new()
    };
    if pushed_dns_servers.is_empty() && pcfg.dns.enabled {
        if assigned.ipv4.is_some() {
            pushed_dns_servers.push(pcfg.dns.listen.as_str());
        }
        if assigned.ipv6.is_some() {
            if let Some(address) = pcfg.dns.listen_ipv6.as_deref() {
                pushed_dns_servers.push(address);
            }
        }
    }
    let pushed_dns = pushed_dns_servers.first().copied().unwrap_or("");
    // Push the VPN subnet prefix length so the client sets the correct on-link
    // prefix instead of assuming /24. Derived from the canonical pool CIDR parser;
    // falls back to 24 if it cannot be parsed (a non-/24 pool would otherwise break
    // client↔client on-link routing). Additive: older clients ignore the field and
    // default to 24.
    let prefix: u8 = crate::config::server::pool_subnet(&pcfg.pool.cidr)
        .map(|subnet| subnet.prefix)
        .unwrap_or(24);
    let ipv6_prefix = crate::config::server::ipv6_pool_subnet(&pcfg.pool.ipv6.cidr)
        .map(|subnet| subnet.prefix)
        .unwrap_or(64);
    let legacy_prefix = if assigned.ipv4.is_some() {
        prefix
    } else {
        ipv6_prefix
    };
    let legacy_gateway = if assigned.ipv4.is_some() {
        pcfg.tun.address.as_str()
    } else {
        pcfg.tun.ipv6_address.as_deref().unwrap_or("")
    };
    let mut body = serde_json::json!({
        "client_ip": client_ip,
        "server_ip": legacy_gateway,
        "prefix": legacy_prefix,
        // Push the server profile's TUN MTU. A client with mtu=0 (auto — the
        // default) adopts this value; a client that set its own mtu keeps it.
        // Additive: older clients ignore the field and use their own default.
        "mtu": pcfg.tun.mtu,
        "dns": pushed_dns,
        // ALWAYS 53, never pcfg.dns.port. No client platform can express a different one —
        // VpnService.Builder and NEDNSSettings take an address and nothing else, Windows and
        // macOS configure resolvers by IP, while the Rust client uses resolvectl's `IP#port`
        // form. Pushing the real port therefore black-holed DNS on every client but one. The
        // proxy keeps its own port; `nat::enable_dns_redirect` bridges 53 to it inside the tunnel.
        // (Audit 2026-07-31.)
        "dns_port": 53,
        "routes": routes,
        "obfuscation": obf,
        // Stream bonding: the per-session join token + how many parallel
        // connections the client may open. max_streams=1 (or a client that
        // ignores these fields) → plain single-stream behaviour.
        "session_token": token.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        "max_streams": max_streams,
        // When true the client auto-ramps streams up to max_streams; else it
        // opens exactly max_streams. Only meaningful when bonding is active.
        "multipath_adaptive": max_streams > 1 && pcfg.obfuscation.multipath.adaptive,
    });
    if let Some(session_id) = udp_roaming_session_id {
        if let Some(object) = body.as_object_mut() {
            object.insert(
                "udp_roaming_session".into(),
                serde_json::json!(format!("{session_id:016x}")),
            );
        }
    }
    let plan_v2 = client_capabilities.is_some_and(|capabilities| {
        capabilities.core_bits & crate::protocol::capabilities::client_capability::NETWORK_PLAN_V2
            != 0
    });
    if plan_v2 {
        // An L3 TUN is point-to-point: assigning the pool prefix (especially an IPv6 /64)
        // would make the client kernel treat every peer as on-link and start ARP/NDP on an
        // interface that carries IP packets, not Ethernet frames.  Keep the pool prefix in
        // `on_link_prefix_len` for ACL/routing calculations, but assign a host prefix to the
        // TUN. TAP is a real L2 segment, so it deliberately receives the pool prefix. The
        // current shared client core normalizes this projection once more against its own
        // local device type because TUN/TAP need not match across the L3 qeli wire; keeping
        // this server-side projection preserves compatibility with older v2 clients.
        let is_tap = pcfg.tun.device_type.eq_ignore_ascii_case("tap");
        let ipv4_address_prefix = if is_tap { prefix } else { 32 };
        let ipv6_address_prefix = if is_tap { ipv6_prefix } else { 128 };
        let mut addresses = Vec::with_capacity(2);
        if let Some(address) = assigned.ipv4 {
            addresses.push(serde_json::json!({
                "family": "ipv4",
                "address": address,
                "prefix_len": ipv4_address_prefix,
                "on_link_prefix_len": prefix,
                "gateway": pcfg.tun.address,
            }));
        }
        if let Some(address) = assigned.ipv6 {
            addresses.push(serde_json::json!({
                "family": "ipv6",
                "address": address,
                "prefix_len": ipv6_address_prefix,
                "on_link_prefix_len": ipv6_prefix,
                "gateway": pcfg.tun.ipv6_address,
            }));
        }
        let family_mode = match (assigned.ipv4.is_some(), assigned.ipv6.is_some()) {
            (true, false) => "ipv4",
            (true, true) => "dual",
            (false, true) => "ipv6",
            (false, false) => "ipv4",
        };
        let dns_servers: Vec<serde_json::Value> = pushed_dns_servers
            .iter()
            .map(|address| serde_json::json!({"address": address, "port": 53}))
            .collect();
        if let Some(object) = body.as_object_mut() {
            object.insert("family_mode".into(), serde_json::json!(family_mode));
            object.insert("addresses".into(), serde_json::json!(addresses));
            object.insert("dns_servers".into(), serde_json::json!(dns_servers));
        }
    }
    format!("OK:{}", serde_json::to_string(&body).unwrap_or_default())
}

#[cfg(test)]
mod auth_ok_prefix_tests {
    use super::{
        build_auth_error, build_auth_ok, build_auth_ok_for_addresses,
        build_auth_ok_for_addresses_with_udp_roaming, build_routes_json_for_user,
        resolve_static_addresses, JOIN_TOKEN_LEN,
    };

    #[test]
    fn inactive_static_address_family_is_not_parsed() {
        use crate::config::server::{IpMode, ProfileConfig};
        use crate::config::users::{UserEntry, UsersDb};

        let profile = ProfileConfig::baseline();
        let ipv4_db = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                enabled: true,
                static_ip: Some("10.8.0.7".into()),
                static_ipv6: Some("not-an-ipv6-address".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            resolve_static_addresses(&ipv4_db, &profile, "alice", IpMode::Ipv4).unwrap(),
            (Some("10.8.0.7".parse().unwrap()), None)
        );

        let ipv6_db = UsersDb {
            users: vec![UserEntry {
                username: "alice".into(),
                enabled: true,
                static_ip: Some("not-an-ipv4-address".into()),
                static_ipv6: Some("fd71:e1::7".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            resolve_static_addresses(&ipv6_db, &profile, "alice", IpMode::Ipv6).unwrap(),
            (None, Some("fd71:e1::7".parse().unwrap()))
        );
    }

    #[test]
    fn authenticated_negotiation_error_has_client_visible_wire_marker() {
        assert_eq!(
            build_auth_error("profile requires IPv6 capability"),
            "ERR:profile requires IPv6 capability"
        );
    }

    #[test]
    fn pool_cidr_prefix_is_pushed_without_a_24_fallback() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.pool.cidr = "10.20.0.0/16".into();
        profile.tun.address = "10.20.0.1".into();

        let message = build_auth_ok("10.20.0.2", &profile, "[]", &[0; JOIN_TOKEN_LEN], 1, None);
        let body: serde_json::Value = serde_json::from_str(
            message
                .strip_prefix("OK:")
                .expect("auth response must carry the OK marker"),
        )
        .unwrap();

        assert_eq!(body["prefix"], 16);
        assert_eq!(body["server_ip"], "10.20.0.1");
    }

    #[test]
    fn recordizer_is_pushed_only_to_a_packet_mux_capable_client() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.obfuscation.recordizer.policy = "prefer".into();
        profile.obfuscation.recordizer.batch.max_packets = 7;

        let legacy = build_auth_ok("10.20.0.2", &profile, "[]", &[0; JOIN_TOKEN_LEN], 1, None);
        let legacy: serde_json::Value = serde_json::from_str(
            legacy
                .strip_prefix("OK:")
                .expect("auth response must carry the OK marker"),
        )
        .unwrap();
        assert!(legacy["obfuscation"].get("recordizer").is_none());

        let capabilities = crate::protocol::capabilities::ClientCapabilities {
            core_bits: crate::protocol::capabilities::client_capability::PACKET_MUX_V1,
            ..Default::default()
        };
        let current = build_auth_ok(
            "10.20.0.2",
            &profile,
            "[]",
            &[0; JOIN_TOKEN_LEN],
            1,
            Some(capabilities),
        );
        let current: serde_json::Value = serde_json::from_str(
            current
                .strip_prefix("OK:")
                .expect("auth response must carry the OK marker"),
        )
        .unwrap();
        assert_eq!(current["obfuscation"]["recordizer"]["policy"], "prefer");
        assert_eq!(
            current["obfuscation"]["recordizer"]["batch"]["max_packets"],
            7
        );
    }

    #[test]
    fn udp_roaming_bootstrap_is_additive_canonical_and_absent_from_legacy_auth_ok() {
        let profile = crate::config::server::ProfileConfig::baseline();
        let assigned = crate::server::pool::AssignedAddresses {
            ipv4: Some("10.9.0.2".parse().unwrap()),
            ipv6: None,
        };
        let legacy =
            build_auth_ok_for_addresses(assigned, &profile, "[]", &[0; JOIN_TOKEN_LEN], 1, None);
        let legacy: serde_json::Value =
            serde_json::from_str(legacy.strip_prefix("OK:").unwrap()).unwrap();
        assert!(legacy.get("udp_roaming_session").is_none());

        let roaming = build_auth_ok_for_addresses_with_udp_roaming(
            assigned,
            &profile,
            "[]",
            &[0; JOIN_TOKEN_LEN],
            1,
            Some(crate::protocol::capabilities::ClientCapabilities {
                core_bits: crate::protocol::capabilities::client_capability::CONTROL_V2
                    | crate::protocol::capabilities::client_capability::UDP_ROAM_V1
                    | crate::protocol::capabilities::client_capability::UDP_DATA_FRAG_V1,
                ..Default::default()
            }),
            Some(0x0102_0304_0506_0708),
        );
        let roaming: serde_json::Value =
            serde_json::from_str(roaming.strip_prefix("OK:").unwrap()).unwrap();
        assert_eq!(
            roaming["udp_roaming_session"],
            serde_json::json!("0102030405060708")
        );
    }

    #[test]
    fn network_plan_v2_is_additive_and_keeps_legacy_projection() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.pool.cidr = "10.30.0.0/20".into();
        profile.tun.address = "10.30.0.1".into();
        let capabilities = crate::protocol::capabilities::ClientCapabilities {
            core_bits: crate::protocol::capabilities::client_capability::NETWORK_PLAN_V2,
            ..Default::default()
        };
        let message = build_auth_ok(
            "10.30.0.2",
            &profile,
            "[]",
            &[0; JOIN_TOKEN_LEN],
            1,
            Some(capabilities),
        );
        let body: serde_json::Value =
            serde_json::from_str(message.strip_prefix("OK:").unwrap()).unwrap();
        assert_eq!(body["client_ip"], "10.30.0.2");
        assert_eq!(body["family_mode"], "ipv4");
        assert_eq!(body["addresses"][0]["prefix_len"], 32);
        assert_eq!(body["addresses"][0]["on_link_prefix_len"], 20);
        assert_eq!(body["addresses"][0]["gateway"], "10.30.0.1");
    }

    #[test]
    fn ipv6_tun_uses_host_prefix_without_losing_pool_prefix() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.tun.device_type = "tun".into();
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        profile.pool.ipv6.cidr = "fd71:e1::/64".into();
        let capabilities = crate::protocol::capabilities::ClientCapabilities {
            core_bits: crate::protocol::capabilities::client_capability::NETWORK_PLAN_V2,
            ..Default::default()
        };
        let message = build_auth_ok_for_addresses(
            crate::server::pool::AssignedAddresses {
                ipv4: None,
                ipv6: Some("fd71:e1::2".parse().unwrap()),
            },
            &profile,
            "[]",
            &[0; JOIN_TOKEN_LEN],
            1,
            Some(capabilities),
        );
        let body: serde_json::Value =
            serde_json::from_str(message.strip_prefix("OK:").unwrap()).unwrap();
        assert_eq!(body["addresses"][0]["prefix_len"], 128);
        assert_eq!(body["addresses"][0]["on_link_prefix_len"], 64);
        assert_eq!(body["addresses"][0]["gateway"], "fd71:e1::1");
    }

    #[test]
    fn tap_keeps_pool_prefix_for_layer_two_neighbor_discovery() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.tun.device_type = "tap".into();
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        profile.pool.ipv6.cidr = "fd71:e1::/64".into();
        let capabilities = crate::protocol::capabilities::ClientCapabilities {
            core_bits: crate::protocol::capabilities::client_capability::NETWORK_PLAN_V2,
            ..Default::default()
        };
        let message = build_auth_ok_for_addresses(
            crate::server::pool::AssignedAddresses {
                ipv4: None,
                ipv6: Some("fd71:e1::2".parse().unwrap()),
            },
            &profile,
            "[]",
            &[0; JOIN_TOKEN_LEN],
            1,
            Some(capabilities),
        );
        let body: serde_json::Value =
            serde_json::from_str(message.strip_prefix("OK:").unwrap()).unwrap();
        assert_eq!(body["addresses"][0]["prefix_len"], 64);
        assert_eq!(body["addresses"][0]["on_link_prefix_len"], 64);
    }

    #[test]
    fn route_defaults_and_filtering_follow_the_assigned_families() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        profile.routing.advertised_routes = vec![
            crate::config::server::PushedRoute {
                cidr: "10.20.0.0/16".into(),
                ..Default::default()
            },
            crate::config::server::PushedRoute {
                cidr: "2001:db8:20::/64".into(),
                ..Default::default()
            },
        ];
        let users = crate::config::users::UsersDb::default();

        let ipv4 = build_routes_json_for_user(
            &profile,
            &users,
            "alice",
            crate::server::pool::AssignedAddresses {
                ipv4: Some("10.9.0.2".parse().unwrap()),
                ipv6: None,
            },
        );
        let ipv4: serde_json::Value = serde_json::from_str(&ipv4).unwrap();
        assert_eq!(ipv4.as_array().unwrap().len(), 1);
        assert_eq!(ipv4[0]["gateway"], "10.9.0.1");

        let ipv6 = build_routes_json_for_user(
            &profile,
            &users,
            "alice",
            crate::server::pool::AssignedAddresses {
                ipv4: None,
                ipv6: Some("fd71:e1::2".parse().unwrap()),
            },
        );
        let ipv6: serde_json::Value = serde_json::from_str(&ipv6).unwrap();
        assert_eq!(ipv6.as_array().unwrap().len(), 1);
        assert_eq!(ipv6[0]["gateway"], "fd71:e1::1");
    }
}

/// Register a client's inbound iroute subnets (#13) into the sessions map under the write
/// lock, returning the non-default CIDRs whose kernel `ip route` must be programmed after
/// the lock drops. A default route is kept only in qeli's internal longest-prefix table
/// (exit-node); installing it in the host table would capture the server's own WAN. Refuses
/// a non-default route covering the server's tunnel IP, and skips a
/// subnet already claimed by a DIFFERENT client (first-registered wins). Admin-configured
/// (per-user `client_subnets`) — a footgun guard, not an untrusted-input gate. Shared by
/// the TCP (handler) and UDP (udp_handler) auth paths so both transports route to a
/// client's LAN identically.
pub(crate) fn register_client_subnets(
    sessions: &mut crate::server::SessionMap,
    client_subnets: &[String],
    client_ip: std::net::IpAddr,
    session: &std::sync::Arc<SessionShared>,
    server_tun_addresses: &[std::net::IpAddr],
    username: &str,
    profile_name: &str,
) -> Vec<String> {
    let mut programmed = Vec::new();
    for cidr in client_subnets {
        if !client_subnet_family_active(
            cidr,
            session.client_ipv4.is_some(),
            session.client_ipv6.is_some(),
        ) {
            log::warn!(
                "iroute: skipping client_subnet '{cidr}' for user '{}' because its address family was not negotiated for this session",
                crate::util::log_identity(username)
            );
            continue;
        }
        let r = match crate::server::ClientRoute::parse(cidr, client_ip, session.clone()) {
            Some(r) => r,
            None => {
                log::warn!(
                    "iroute: skipping malformed client_subnet '{cidr}' for user '{}'",
                    crate::util::log_identity(username)
                );
                continue;
            }
        };
        let is_default = r.prefix() == 0;
        if !is_default
            && server_tun_addresses
                .iter()
                .any(|address| r.contains(*address))
        {
            log::warn!(
                "iroute: refusing client_subnet '{cidr}' (user '{}') — it would capture the tunnel gateway",
                crate::util::log_identity(username)
                );
            continue;
        }
        if let Some(existing) = sessions
            .client_routes
            .iter()
            .find(|existing| existing.same_network(&r))
        {
            if existing.client_ip != client_ip {
                log::warn!(
                    "iroute: '{cidr}' (user '{}') is already claimed by another client — skipping",
                    crate::util::log_identity(username)
                );
            } else {
                log::debug!(
                    "iroute: duplicate client_subnet '{cidr}' for user '{}' — keeping one canonical route",
                    crate::util::log_identity(username)
                );
            }
            continue;
        }
        log::info!(
            "iroute: {cidr} -> client {} ({client_ip}) on profile '{profile_name}'",
            crate::util::log_identity(username)
        );
        // `/0` is an internal session-to-session next hop. Never turn it into the Linux
        // host default route: the qeli server's own listener/WAN packets would be captured
        // by its TUN and the profile would disconnect itself. Non-default iroutes still need
        // a kernel route so traffic originating outside another qeli client reaches the TUN.
        if !is_default {
            programmed.push(r.cidr.clone());
        }
        sessions.client_routes.push(r);
    }
    programmed
}

fn client_subnet_family_active(cidr: &str, has_ipv4: bool, has_ipv6: bool) -> bool {
    let address = cidr
        .trim()
        .split_once('/')
        .map_or(cidr.trim(), |(address, _)| address.trim());
    match address.parse::<std::net::IpAddr>() {
        Ok(address) if address.is_ipv4() => has_ipv4,
        Ok(_) => has_ipv6,
        // Leave malformed diagnostics to ClientRoute::parse below.
        Err(_) => true,
    }
}

pub(crate) fn configured_tun_addresses(
    profile: &crate::config::server::ProfileConfig,
) -> Vec<std::net::IpAddr> {
    let mut addresses = Vec::with_capacity(2);
    if profile.tun.ip_mode != crate::config::server::IpMode::Ipv6 {
        if let Ok(address) = profile.tun.address.parse::<std::net::Ipv4Addr>() {
            addresses.push(std::net::IpAddr::V4(address));
        }
    }
    if profile.tun.ip_mode != crate::config::server::IpMode::Ipv4 {
        if let Some(address) = profile
            .tun
            .ipv6_address
            .as_deref()
            .and_then(|address| address.parse::<std::net::Ipv6Addr>().ok())
        {
            addresses.push(std::net::IpAddr::V6(address));
        }
    }
    addresses
}

/// Program (add on connect / delete on disconnect) a kernel route that sends `cidr` into
/// the profile's TUN. Connect is fail-closed: an existing exact route is never replaced.
/// It is adopted only when both the TUN and qeli's ownership metric match, allowing safe
/// recovery of a route left by an earlier qeli process without deleting admin-owned state.
/// The caller decides whether an error is fatal (authentication) or best-effort (teardown).
pub(crate) async fn program_client_subnet_route(
    add: bool,
    cidr: &str,
    tun: &str,
) -> anyhow::Result<()> {
    let result = program_client_subnet_route_inner(add, cidr, tun).await;
    if let Err(error) = &result {
        log::warn!("iroute: {error}");
    }
    result
}

async fn program_client_subnet_route_inner(add: bool, cidr: &str, tun: &str) -> anyhow::Result<()> {
    // Defence in depth: exit-node defaults live only in SessionMap. Even if a future caller
    // accidentally includes one in its programmed/teardown list, never add *or delete* the
    // Linux host default route here.
    if client_subnet_is_default(cidr) {
        log::debug!("iroute: keeping internal default '{cidr}' out of the host route table");
        return Ok(());
    }

    if add {
        let existing = query_client_subnet_routes(cidr).await?;
        if !existing.is_empty() {
            if route_lines_are_owned_by_qeli(&existing, tun) {
                log::info!(
                    "iroute: adopting existing qeli-owned route for {cidr} on {}",
                    crate::util::log_sanitize(tun)
                );
                return Ok(());
            }
            anyhow::bail!(
                "refusing to replace or adopt unowned host route for {cidr}: {}",
                crate::util::log_sanitize(&existing.join(" | "))
            );
        }
    }

    let action = if add { "add" } else { "del" };
    let args = client_subnet_route_args(action, cidr, tun);
    run_client_subnet_ip(&args, true).await?;

    if add {
        // Re-read after the atomic RTM_NEWROUTE operation. This catches an administrator or
        // another network manager racing our preflight with a different exact route. Delete
        // only our device-qualified route before refusing the admission.
        let verified = match query_client_subnet_routes(cidr).await {
            Ok(routes) => routes,
            Err(verify_error) => {
                // `route add` has already succeeded. A failed ownership query must not
                // leave that route behind after admission is rejected and its session/IP
                // allocation is rolled back by the caller.
                let cleanup = client_subnet_route_args("del", cidr, tun);
                let cleanup_error = run_client_subnet_ip(&cleanup, true).await.err();
                if let Some(cleanup_error) = cleanup_error {
                    anyhow::bail!(
                        "could not verify newly added host route for {cidr}: {verify_error}; rollback also failed: {cleanup_error}"
                    );
                }
                anyhow::bail!(
                    "could not verify newly added host route for {cidr}: {verify_error}; route was rolled back"
                );
            }
        };
        if verified.is_empty() || !route_lines_are_owned_by_qeli(&verified, tun) {
            let cleanup = client_subnet_route_args("del", cidr, tun);
            let cleanup_error = run_client_subnet_ip(&cleanup, true).await.err();
            if let Some(cleanup_error) = cleanup_error {
                anyhow::bail!(
                    "host route ownership changed while adding {cidr}; observed: {}; rollback also failed: {cleanup_error}",
                    crate::util::log_sanitize(&verified.join(" | "))
                );
            }
            anyhow::bail!(
                "host route ownership changed while adding {cidr}; observed: {}; route was rolled back",
                crate::util::log_sanitize(&verified.join(" | "))
            );
        }
    }
    Ok(())
}

const CLIENT_SUBNET_ROUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

async fn run_client_subnet_ip(
    args: &[String],
    log_success: bool,
) -> anyhow::Result<std::process::Output> {
    let display_command = format!("ip {}", args.join(" "));
    let mut process = tokio::process::Command::new("ip");
    process.args(args).kill_on_drop(true);
    let output = tokio::time::timeout(CLIENT_SUBNET_ROUTE_TIMEOUT, process.output())
        .await
        .map_err(|_| anyhow::anyhow!("`{display_command}` timed out after 1 second"))?
        .map_err(|error| anyhow::anyhow!("could not run `{display_command}`: {error}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`{display_command}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if log_success {
        log::info!("iroute: {display_command}");
    }
    Ok(output)
}

async fn query_client_subnet_routes(cidr: &str) -> anyhow::Result<Vec<String>> {
    let args = client_subnet_route_show_args(cidr);
    let output = run_client_subnet_ip(&args, false).await?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn route_lines_are_owned_by_qeli(lines: &[String], tun: &str) -> bool {
    !lines.is_empty()
        && lines.iter().all(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let devices = fields
                .windows(2)
                .filter(|pair| pair[0] == "dev")
                .map(|pair| pair[1])
                .collect::<Vec<_>>();
            let metrics = fields
                .windows(2)
                .filter(|pair| pair[0] == "metric")
                .map(|pair| pair[1])
                .collect::<Vec<_>>();
            devices == [tun]
                && metrics == [CLIENT_SUBNET_ROUTE_METRIC]
                && !fields.contains(&"via")
                && !fields.contains(&"nexthop")
        })
}

fn client_subnet_is_default(cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.trim().split_once('/') else {
        return false;
    };
    prefix.trim() == "0" && address.trim().parse::<std::net::IpAddr>().is_ok()
}

// A non-default metric is an ownership marker, not a routing preference: admission rejects
// every competing exact prefix before add. Including it in both add and del means a later
// admin/network-manager replacement on the same TUN cannot be mistaken for qeli's route.
const CLIENT_SUBNET_ROUTE_METRIC: &str = "42760";

fn client_subnet_route_args(action: &str, cidr: &str, tun: &str) -> Vec<String> {
    let ipv6 = cidr
        .trim()
        .split_once('/')
        .map(|(address, _)| address.trim())
        .and_then(|address| address.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_ipv6());
    let mut args = Vec::with_capacity(if ipv6 { 8 } else { 7 });
    if ipv6 {
        args.push("-6".to_string());
    }
    args.extend(
        [
            "route",
            action,
            cidr,
            "dev",
            tun,
            "metric",
            CLIENT_SUBNET_ROUTE_METRIC,
        ]
        .into_iter()
        .map(str::to_string),
    );
    args
}

fn client_subnet_route_show_args(cidr: &str) -> Vec<String> {
    let ipv6 = cidr
        .trim()
        .split_once('/')
        .map(|(address, _)| address.trim())
        .and_then(|address| address.parse::<std::net::IpAddr>().ok())
        .is_some_and(|address| address.is_ipv6());
    let mut args = Vec::with_capacity(if ipv6 { 8 } else { 7 });
    if ipv6 {
        args.push("-6".to_string());
    }
    args.extend(
        ["route", "show", "table", "main", "exact", cidr]
            .into_iter()
            .map(str::to_string),
    );
    args
}

#[cfg(test)]
mod iroute_family_tests {
    use super::{
        client_subnet_family_active, client_subnet_is_default, client_subnet_route_args,
        client_subnet_route_show_args, configured_tun_addresses, exit_access_from_routes_json,
        route_lines_are_owned_by_qeli, routes_without_exit_defaults,
    };

    #[test]
    fn routed_subnets_are_limited_to_the_negotiated_families() {
        assert!(client_subnet_family_active("10.20.0.0/16", true, false));
        assert!(!client_subnet_family_active(
            "2001:db8:20::/64",
            true,
            false
        ));
        assert!(client_subnet_family_active("2001:db8:20::/64", false, true));
        assert!(!client_subnet_family_active("10.20.0.0/16", false, true));
    }

    #[test]
    fn ipv6_kernel_iroutes_select_the_ipv6_route_table() {
        assert_eq!(
            client_subnet_route_args("add", "2001:db8:20::/64", "qeli0"),
            [
                "-6",
                "route",
                "add",
                "2001:db8:20::/64",
                "dev",
                "qeli0",
                "metric",
                "42760"
            ]
        );
        assert_eq!(
            client_subnet_route_args("del", "10.20.0.0/16", "qeli0"),
            [
                "route",
                "del",
                "10.20.0.0/16",
                "dev",
                "qeli0",
                "metric",
                "42760"
            ]
        );
        assert_eq!(
            client_subnet_route_show_args("2001:db8:20::/64"),
            [
                "-6",
                "route",
                "show",
                "table",
                "main",
                "exact",
                "2001:db8:20::/64"
            ]
        );
    }

    #[test]
    fn post_add_ownership_requires_our_tun_and_metric_on_every_exact_route() {
        assert!(route_lines_are_owned_by_qeli(
            &["192.168.50.0/24 dev vpn0 scope link metric 42760".into()],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(
            &["192.168.50.0/24 dev vpn0 scope link".into()],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(
            &["192.168.50.0/24 dev vpn0 scope link metric 10".into()],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(
            &["192.168.50.0/24 via 10.9.0.2 dev vpn0 metric 42760".into()],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(
            &[
                "192.168.50.0/24 metric 42760 nexthop dev vpn0 weight 1 nexthop dev eth0 weight 1"
                    .into(),
            ],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(
            &[
                "192.168.50.0/24 dev vpn0 scope link metric 42760".into(),
                "192.168.50.0/24 via 192.0.2.1 dev eth0 metric 10".into(),
            ],
            "vpn0"
        ));
        assert!(!route_lines_are_owned_by_qeli(&[], "vpn0"));
    }

    #[test]
    fn exit_defaults_never_reach_kernel_route_commands() {
        assert!(client_subnet_is_default("0.0.0.0/0"));
        assert!(client_subnet_is_default("::/0"));
        assert!(!client_subnet_is_default("0.0.0.0/1"));
        assert!(!client_subnet_is_default("not-an-ip/0"));
    }

    #[test]
    fn effective_default_routes_authorize_only_their_own_family() {
        let access = exit_access_from_routes_json(
            r#"[
                {"cidr":"0.0.0.0/0"},
                {"cidr":"2001:db8:20::/64"}
            ]"#,
        );
        assert!(access.ipv4);
        assert!(!access.ipv6);

        let both =
            exit_access_from_routes_json(r#"[{"cidr":"203.0.113.7/0"},{"cidr":"2001:db8::7/0"}]"#);
        assert!(both.ipv4 && both.ipv6);
        assert_eq!(
            exit_access_from_routes_json("not-json"),
            crate::server::ExitAccess::default()
        );

        let client_routes = routes_without_exit_defaults(
            r#"[
                {"cidr":"0.0.0.0/0"},
                {"cidr":"::/0"},
                {"cidr":"10.20.0.0/16","metric":42}
            ]"#,
        );
        let client_routes: serde_json::Value = serde_json::from_str(&client_routes).unwrap();
        assert_eq!(client_routes.as_array().unwrap().len(), 1);
        assert_eq!(client_routes[0]["cidr"], "10.20.0.0/16");
    }

    #[test]
    fn inactive_profile_address_fields_are_not_treated_as_live_gateways() {
        let mut profile = crate::config::server::ProfileConfig::baseline();
        profile.tun.ipv6_address = Some("fd71:e1::1".into());
        assert_eq!(
            configured_tun_addresses(&profile),
            vec!["10.9.0.1".parse::<std::net::IpAddr>().unwrap()]
        );

        profile.tun.ip_mode = crate::config::server::IpMode::Ipv6;
        assert_eq!(
            configured_tun_addresses(&profile),
            vec!["fd71:e1::1".parse::<std::net::IpAddr>().unwrap()]
        );
    }
}

fn build_routes_json_for_user(
    pcfg: &crate::config::server::ProfileConfig,
    users_db: &crate::config::users::UsersDb,
    username: &str,
    assigned: crate::server::pool::AssignedAddresses,
) -> String {
    let user_routes = users_db
        .find_user(username)
        .filter(|u| !u.routes.is_empty())
        .map(|u| u.routes.as_slice());

    // Build the JSON via serde_json so any value (cidr/gateway from config) is
    // properly escaped — a stray quote can't break the array (C-3). cidr/gateway
    // are admin-trusted config, so this is hygiene, not an injection sink. The two
    // route types (UserRoute / PushedRoute) share the cidr/gateway/metric fields.
    if let Some(routes) = user_routes {
        let arr: Vec<serde_json::Value> = routes
            .iter()
            .filter_map(|r| {
                active_route_json(pcfg, assigned, &r.cidr, r.gateway.as_deref(), r.metric)
            })
            .collect();
        serde_json::Value::Array(arr).to_string()
    } else {
        let arr: Vec<serde_json::Value> = pcfg
            .routing
            .advertised_routes
            .iter()
            .filter_map(|r| {
                active_route_json(pcfg, assigned, &r.cidr, r.gateway.as_deref(), r.metric)
            })
            .collect();
        serde_json::Value::Array(arr).to_string()
    }
}

fn active_route_json(
    pcfg: &crate::config::server::ProfileConfig,
    assigned: crate::server::pool::AssignedAddresses,
    cidr: &str,
    configured_gateway: Option<&str>,
    metric: Option<u32>,
) -> Option<serde_json::Value> {
    let route_address = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<std::net::IpAddr>().ok())?;
    let family_is_active = if route_address.is_ipv4() {
        assigned.ipv4.is_some()
    } else {
        assigned.ipv6.is_some()
    };
    if !family_is_active {
        return None;
    }
    let default_gateway = if route_address.is_ipv4() {
        Some(pcfg.tun.address.as_str())
    } else {
        pcfg.tun.ipv6_address.as_deref()
    }?;
    let gateway = configured_gateway.unwrap_or(default_gateway);
    let gateway_address = gateway.parse::<std::net::IpAddr>().ok()?;
    if route_address.is_ipv4() != gateway_address.is_ipv4() {
        log::warn!(
            "Profile '{}': route '{}' and gateway '{}' use different address families; route not pushed",
            pcfg.name,
            cidr,
            gateway
        );
        return None;
    }
    Some(serde_json::json!({
        "cidr": cidr,
        "gateway": gateway,
        "metric": metric.unwrap_or(100),
    }))
}

#[cfg(test)]
mod device_id_tests {
    use super::{device_key, split_device_id, DEVICE_ID_LEN};

    #[test]
    fn old_client_no_device_id() {
        // Old client: `[user:pass]` directly after the proof — first byte is a
        // username char, never 0x00. No device-id parsed; key is the bare username.
        let (id, creds) = split_device_id(b"user01:pass");
        assert!(id.is_none());
        assert_eq!(creds, b"user01:pass");
        assert_eq!(device_key("user01", id), "user01");
    }

    #[test]
    fn new_client_with_device_id() {
        // New client: 0x00 marker + 16-byte id + creds.
        let mut buf = vec![0u8];
        let did = [0xABu8; DEVICE_ID_LEN];
        buf.extend_from_slice(&did);
        buf.extend_from_slice(b"user01:pass");
        let (id, creds) = split_device_id(&buf);
        assert_eq!(id, Some(did));
        assert_eq!(creds, b"user01:pass");
        assert_eq!(
            device_key("user01", id),
            format!("user01:{}", "ab".repeat(DEVICE_ID_LEN))
        );
    }

    #[test]
    fn two_devices_one_login_get_distinct_keys() {
        let a = device_key("user01", Some([1u8; DEVICE_ID_LEN]));
        let b = device_key("user01", Some([2u8; DEVICE_ID_LEN]));
        assert_ne!(a, b);
        // ...but the SAME device is stable -> supersedes itself on reconnect.
        assert_eq!(a, device_key("user01", Some([1u8; DEVICE_ID_LEN])));
    }
}

#[cfg(test)]
mod rate_bucket_tests {
    use super::{DirectionalRateBuckets, RateBucket};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn zero_limit_never_delays() {
        let b = RateBucket::new();
        assert_eq!(b.consume(10_000_000, 0), Duration::ZERO);
    }

    #[test]
    fn empty_bucket_throttles_a_full_second_burst() {
        // The bucket starts empty, so a 1 Mbit send at 1 Mbps must wait ~1s — proof
        // the cap actually bites (the old per-stream sleep was bypassable via N
        // streams; this single bucket is shared).
        let b = RateBucket::new();
        let d = b.consume(1_000_000, 1);
        assert!(
            d > Duration::from_millis(500),
            "expected ~1s throttle on an empty bucket, got {:?}",
            d
        );
    }

    #[test]
    fn upload_and_download_have_independent_allowances() {
        let rates = DirectionalRateBuckets::new();
        assert!(!Arc::ptr_eq(&rates.upload, &rates.download));

        // Each direction starts with its own empty bucket. Half a megabit at 1 Mbps
        // therefore costs about 500 ms in BOTH directions. With the former shared
        // bucket the second call inherited the first call's deficit and cost ~1 s.
        let upload = rates.upload.consume(500_000, 1);
        let download = rates.download.consume(500_000, 1);
        assert!(upload > Duration::from_millis(250));
        assert!(download > Duration::from_millis(250));
        assert!(upload < Duration::from_millis(750));
        assert!(download < Duration::from_millis(750));
    }
}

#[cfg(test)]
mod server_wire_pool_tests {
    use super::{server_wire_pool, SERVER_WIRE_BUFFER_BYTES};

    #[test]
    fn bounded_pool_exhausts_and_reuses_the_returned_record() {
        let profile = crate::config::server::ProfileConfig::default();
        let pool = server_wire_pool(&profile).unwrap();
        let count = pool.buffer_count();
        let capacity = pool.buffer_capacity();
        assert!(
            count > 2_000,
            "a normal-MTU pool must retain useful queue depth"
        );
        assert!(count * capacity <= SERVER_WIRE_BUFFER_BYTES);
        assert!((count + 1) * capacity > SERVER_WIRE_BUFFER_BYTES);

        let mut held = Vec::with_capacity(count);
        for _ in 0..count {
            held.push(pool.try_acquire().expect("every configured slot exists"));
        }
        assert!(pool.try_acquire().is_none(), "no fallback allocation");

        let allocation = held[0].as_ptr();
        assert_eq!(held[0].capacity(), capacity);
        drop(held.swap_remove(0));

        let reused = pool
            .try_acquire()
            .expect("dropping a record must return its allocation");
        assert!(reused.is_empty());
        assert_eq!(reused.as_ptr(), allocation);
    }
}

#[cfg(test)]
mod downlink_mtu_tests {
    use super::{downlink_mtu_for, downlink_mtu_for_packet};
    use crate::protocol::ip::IpVersion;

    /// The whole point of returning `None`: a client that never reported must leave the
    /// forwarder's behaviour bit-for-bit as it was before #13.
    #[test]
    fn no_report_means_no_enforcement() {
        assert_eq!(downlink_mtu_for(0, 1500), None);
        assert_eq!(downlink_mtu_for(0, 0), None);
    }

    /// Only a NARROWER path is worth enforcing. A client on an equal or wider path must not
    /// make the server start policing (or worse, shrinking) its own profile MTU.
    #[test]
    fn only_a_narrower_report_is_enforced() {
        assert_eq!(downlink_mtu_for(1280, 1500), Some(1280));
        assert_eq!(downlink_mtu_for(1499, 1500), Some(1499));
        assert_eq!(downlink_mtu_for(1500, 1500), None, "equal is not narrower");
        assert_eq!(
            downlink_mtu_for(9000, 1500),
            None,
            "wider must not raise the ceiling"
        );
    }

    /// An unset/absurd profile MTU is not a ceiling to compare against, so the report stands
    /// alone rather than being silently discarded (or compared against a negative).
    #[test]
    fn unset_profile_mtu_lets_the_report_stand() {
        assert_eq!(downlink_mtu_for(1280, 0), Some(1280));
        assert_eq!(downlink_mtu_for(1280, -1), Some(1280));
    }

    /// A report too large for u16 cannot be represented on the wire we act on; drop it rather
    /// than truncating into a plausible-looking small MTU.
    #[test]
    fn unrepresentable_report_is_dropped_not_truncated() {
        assert_eq!(downlink_mtu_for(70_000, 0), None);
        // 65_536 truncates to 0 in 16 bits — exactly the value that would look like "unset".
        assert_eq!(downlink_mtu_for(65_536, 0), None);
    }

    #[test]
    fn ipv6_never_inherits_the_ipv4_report_floor() {
        assert_eq!(downlink_mtu_for_packet(576, 1500, IpVersion::V4), Some(576));
        assert_eq!(
            downlink_mtu_for_packet(576, 1500, IpVersion::V6),
            Some(1280)
        );
        assert_eq!(
            downlink_mtu_for_packet(1279, 1500, IpVersion::V6),
            Some(1280)
        );
        assert_eq!(
            downlink_mtu_for_packet(1280, 1500, IpVersion::V6),
            Some(1280)
        );
    }
}
