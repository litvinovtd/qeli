use crate::config::QuicMaskingConfig;
use crate::crypto::{derive_data_frag_key, derive_keys_hybrid, derive_keys_hybrid_bound, Keypair};
use crate::protocol::{
    generate_connection_id, looks_like_quic_initial, unwrap_quic_payload, wrap_quic_long,
    wrap_quic_short, wrap_quic_short_into, Obfuscator, PacketCodec,
};
use crate::server::handler::{self, DEFAULT_HEARTBEAT_INTERVAL_MS};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState, ServerTunPacket, TunIngress};
use crate::transport_core::buffer_pool::{BufferPool, PooledBuffer};
use crate::transport_core::udp_buffer::{
    AggregateUdpBudgetPlan, InternalDrop, UdpBufferController, UdpBufferCounters, UdpBufferPolicy,
    AUTO_MAX_RECV_BYTES,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Semaphore};

/// Per-client queue for UDP upload pacing. Packets still come from the profile-wide
/// fixed buffer pool, so this bounds queue metadata and one limited client cannot
/// consume unbounded memory or block the shared socket receive loop.
const UDP_UPLOAD_QUEUE_PACKETS: usize = 256;

/// Upper bound on simultaneous half-open (unauthenticated, `AwaitingAuth`) UDP
/// handshakes per worker. A connectionless listener can't trust the source
/// address, so a spoofed-source flood would otherwise add one `AwaitingAuth`
/// entry per fake IP until the handshake-timeout reaper runs (memory DoS). When
/// the cap is hit, the OLDEST pending handshake is evicted to admit a new one;
/// authenticated sessions are never affected.
const MAX_PENDING_HANDSHAKES: usize = 1024;

/// Upper bound on CONCURRENT new-handshake crypto (Keypair::generate + ML-KEM
/// encapsulate + key derivation) per worker. The per-source-IP rate limiter is
/// bypassed by source spoofing on a connectionless listener, so without this a
/// spoofed flood drives one full PQ handshake per datagram → CPU exhaustion.
/// A datagram that can't grab a permit is DROPPED silently (not queued) so
/// pre-auth crypto/sec stays bounded regardless of source-IP diversity; the
/// client simply retransmits its ClientHello. Sized to a few per core.
fn max_concurrent_udp_handshakes() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    std::cmp::max(64, cores.saturating_mul(4))
}

fn empty_udp_record_padding_cap(
    codec: &PacketCodec,
    outer_ipv6: bool,
    obfs_overhead: usize,
    quic_enabled: bool,
) -> usize {
    let record_budget = crate::protocol::data_frag::unfragmented_record_budget(
        crate::protocol::data_frag::conservative_udp_payload_budget(outer_ipv6),
        obfs_overhead,
        quic_enabled,
    )
    .expect("conservative UDP budget always fits one empty encrypted record");
    codec
        .max_padding_for_record_budget(0, record_budget)
        .unwrap_or(0)
}

fn max_useful_udp_payload_budget(obfs_overhead: usize, quic_enabled: bool) -> usize {
    crate::protocol::data_frag::MAX_REASSEMBLED_RECORD
        + obfs_overhead
        + if quic_enabled {
            crate::protocol::quic::QUIC_SHORT_HEADER_MIN
        } else {
            0
        }
}

fn sanitized_udp_payload_budget(
    reported: u16,
    outer_ipv6: bool,
    obfs_overhead: usize,
    quic_enabled: bool,
) -> usize {
    usize::from(reported).clamp(
        crate::protocol::data_frag::conservative_udp_payload_budget(outer_ipv6),
        max_useful_udp_payload_budget(obfs_overhead, quic_enabled),
    )
}

fn note_certified_udp_payload_budget(
    cell: &std::sync::atomic::AtomicU32,
    who: std::fmt::Arguments<'_>,
    certified: u32,
) {
    let previous = cell.swap(certified, std::sync::atomic::Ordering::Relaxed);
    if previous != certified {
        log::info!(
            "client {who} reverse-probe certified UDP downlink budget {certified} bytes (was {previous})"
        );
    }
}
#[inline]
fn is_message_too_long(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownlinkMtuProbe {
    generation: u64,
    token: u128,
    payload_size: u16,
    udp_payload_budget: u32,
}

const DOWNLINK_MTU_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

fn build_downlink_mtu_probe(
    token: u128,
    udp_payload_budget: usize,
    obfs_overhead: usize,
    quic_enabled: bool,
    connection_id: &[u8; 4],
    packet_number: u32,
) -> Option<(Vec<u8>, u16)> {
    let wrapper_bytes = obfs_overhead
        + if quic_enabled {
            crate::protocol::quic::QUIC_SHORT_HEADER_MIN
        } else {
            0
        };
    let payload_size = udp_payload_budget.checked_sub(wrapper_bytes)?;
    let payload_size_u16 = u16::try_from(payload_size).ok()?;
    let probe = crate::protocol::udp_frag::mtu_probe_v2_datagram(token, payload_size)?;
    let packet = if quic_enabled {
        wrap_quic_short(&probe, connection_id, packet_number)
    } else {
        probe
    };
    debug_assert_eq!(packet.len() + obfs_overhead, udp_payload_budget);
    Some((packet, payload_size_u16))
}

fn set_probe_df(socket: &socket2::Socket, peer_is_ipv6: bool) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // Linux UAPI: IPV6_MTU_DISCOVER uses the IP_PMTUDISC_* values, just like
    // IP_MTU_DISCOVER. The libc crate exposes the latter constants but not this option
    // number; keep it beside the setsockopt call instead of spreading a numeric literal.
    const IPV6_MTU_DISCOVER: libc::c_int = 23;
    let (level, option) = if peer_is_ipv6 {
        (libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER)
    } else {
        (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
    };
    let value: libc::c_int = crate::protocol::data_frag::ACTIVE_PMTUDISC_MODE;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Send one reverse PMTU probe through a short-lived connected socket. The dedicated socket
/// carries the same local address/port via SO_REUSEPORT, but its DF option cannot race with
/// legacy data sends on the shared listener. It is closed immediately after `send`, so the
/// ACK returns to the stable listener worker selected by the original four-tuple.
fn send_downlink_mtu_probe(
    local_addr: SocketAddr,
    peer: SocketAddr,
    packet: &[u8],
    obfs_key: Option<[u8; 32]>,
) -> std::io::Result<()> {
    use socket2::{Domain, Protocol, Socket, Type};
    if local_addr.is_ipv6() != peer.is_ipv6() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reverse PMTU probe address-family mismatch",
        ));
    }
    let domain = if peer.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if peer.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&local_addr.into())?;
    socket.connect(&peer.into())?;
    set_probe_df(&socket, peer.is_ipv6())?;

    let sealed;
    let wire = if let Some(key) = obfs_key {
        sealed = crate::protocol::obfs::obfs_datagram_seal(&key, packet);
        sealed.as_slice()
    } else {
        packet
    };
    let sent = socket.send(wire)?;
    if sent == wire.len() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "reverse PMTU probe was only partially sent",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn schedule_downlink_mtu_probe(
    sessions: &Arc<RwLock<HashMap<SocketAddr, UdpClient>>>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    tasks: &super::ProfileTasks,
    profile_name: &str,
    addr: SocketAddr,
    budget_cell: &Arc<std::sync::atomic::AtomicU32>,
    reported: u16,
    obfs_key: Option<[u8; 32]>,
) {
    let local_addr = match socket.raw_socket().local_addr() {
        Ok(value) => value,
        Err(error) => {
            log::debug!("UDP {addr}: cannot start reverse PMTU probe: {error}");
            return;
        }
    };
    let (expected, packet) = {
        let mut guard = sessions.write().await;
        let Some(client) = guard.get_mut(&addr) else {
            return;
        };
        if !matches!(client.state, UdpSessionState::Authenticated { .. })
            || !client.data_frag_enabled
            || client.downlink_mtu_probe.is_some()
            || client
                .udp_payload_budget
                .as_ref()
                .is_none_or(|cell| !Arc::ptr_eq(cell, budget_cell))
        {
            return;
        }
        let target = sanitized_udp_payload_budget(
            reported,
            addr.is_ipv6(),
            socket.seal_overhead(),
            client.quic_enabled,
        );
        if budget_cell.load(std::sync::atomic::Ordering::Relaxed) as usize >= target {
            return;
        }
        let token: u128 = rand::random();
        let generation: u64 = rand::random();
        let packet_number = client
            .packet_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some((packet, payload_size)) = build_downlink_mtu_probe(
            token,
            target,
            socket.seal_overhead(),
            client.quic_enabled,
            &client.connection_id,
            packet_number,
        ) else {
            return;
        };
        let expected = DownlinkMtuProbe {
            generation,
            token,
            payload_size,
            udp_payload_budget: target as u32,
        };
        client.downlink_mtu_probe = Some(expected);
        (expected, packet)
    };

    let sessions = sessions.clone();
    let profile_name = profile_name.to_string();
    let budget_cell = budget_cell.clone();
    tasks.spawn(async move {
        let send_result = send_downlink_mtu_probe(local_addr, addr, &packet, obfs_key);
        if send_result.is_ok() {
            tokio::time::sleep(DOWNLINK_MTU_PROBE_TIMEOUT).await;
        }
        let cleared = {
            let mut guard = sessions.write().await;
            guard.get_mut(&addr).is_some_and(|client| {
                if client.downlink_mtu_probe == Some(expected) {
                    client.downlink_mtu_probe = None;
                    true
                } else {
                    false
                }
            })
        };
        if let Err(error) = send_result {
            log::debug!(
                "UDP {addr} on profile '{profile_name}': reverse PMTU probe send failed: {error}"
            );
        } else if cleared
            && budget_cell.load(std::sync::atomic::Ordering::Relaxed) < expected.udp_payload_budget
        {
            log::debug!(
                "UDP {addr} on profile '{profile_name}': reverse PMTU probe timed out at {} bytes",
                expected.udp_payload_budget
            );
        }
    });
}

#[allow(dead_code)] // session_id retained for symmetry with the TCP session model
enum UdpSessionState {
    AwaitingAuth,
    Authenticated {
        session_id: u64,
        /// Per-device pool/session key — used to release the IP on cleanup.
        device_key: String,
        client_ip: std::net::IpAddr,
    },
}

struct UdpClient {
    rx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    tx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    rx_data_frag_key: [u8; 32],
    tx_data_frag_key: [u8; 32],
    data_frag_enabled: bool,
    data_reassembler: crate::protocol::data_frag::DataReassembler,
    state: UdpSessionState,
    last_activity: std::time::Instant,
    /// Inbound (client->server) byte counter, shared with this client's
    /// `SessionShared` so `list-clients` RECV reflects UDP receives. Set on auth
    /// (a placeholder Arc until then) — UDP RECV used to be stuck at 0 because it
    /// was never incremented on the UDP receive path.
    bytes_recv: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Live per-user limit shared with `SessionShared`, updated by set-bandwidth.
    /// `None` until authentication completes.
    bandwidth_limit_mbps: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Bounded path to this client's upload pacing task. Limited UDP traffic must
    /// never sleep in the shared socket receive loop, which would stall every peer.
    upload_tx: Option<mpsc::Sender<PooledBuffer>>,
    /// Shared with `SessionShared::dropped`, so local ingress-pool pressure is visible in
    /// `list-clients` instead of becoming an unexplained wire loss.
    dropped: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// When the client first appeared — used to evict stale AwaitingAuth entries
    created_at: std::time::Instant,
    connection_id: [u8; 4],
    quic_enabled: bool,
    packet_counter: Arc<std::sync::atomic::AtomicU32>,
    /// Crypto material kept to verify the client key-proof at auth time
    /// (require_client_key_proof). Mirrors the TCP handshake.
    ephemeral_shared: [u8; 32],
    static_shared: [u8; 32],
    transcript_hash: [u8; 32],
    /// Per-client flow-shaping cover scheduler (server->client idle cover;
    /// DPI-AUDIT 6.1/6.2). Carries this client's cover budget; disabled unless the
    /// profile enables `obf.traffic_shaping`.
    shaper: crate::protocol::Shaper,
    /// Next instant a cover packet is due for this client (Poisson schedule).
    next_cover_at: std::time::Instant,
    /// Cached RAW ServerHello, for idempotent re-emit while `AwaitingAuth`. A lost
    /// ServerHello leaves the client retransmitting its (fragmented) ClientHello,
    /// which fails AEAD decrypt on the existing-session path and would otherwise be
    /// dropped — stalling the client for the whole `connection_timeout` before a
    /// fresh-port reconnect. Cleared on auth (only needed pre-auth).
    server_hello: Vec<u8>,
    /// Framing the ClientHello used, so the re-emitted ServerHello matches it.
    hello_frag_mode: bool,
    /// Cached post-unwrap AUTH request + framed AuthOK, for idempotent re-emit once
    /// `Authenticated`. A lost AuthOK leaves the client retransmitting the EXACT
    /// AUTH datagram, which the replay window rejects; on a byte match we re-send
    /// the cached AuthOK instead of dropping it. Empty until authenticated.
    ///
    /// A LIST of datagrams, not one: a large pushed-route set splits the AuthOK into
    /// fragments (see `build_auth_ok_datagrams`), and re-emitting only the first of them
    /// would leave the client's reassembly permanently one fragment short — the very stall
    /// this cache exists to prevent. Usually holds exactly one element.
    auth_request: Vec<u8>,
    auth_ok: Vec<Vec<u8>>,
    /// Compiled `allowed_networks` destination ACL for the authenticated user (own or
    /// inherited from the group). Empty = unrestricted; set at auth, checked on every
    /// inner packet before the TUN. Mirrors `SessionShared.dst_acl` on the TCP path.
    dst_acl: crate::server::acl::DstAcl,
    /// Which SOURCE addresses this session may claim. Mirrors
    /// `SessionShared.src_guard` on the TCP path.
    src_guard: Option<crate::server::acl::SrcGuard>,
    /// Per-family authorization for an internal `/0` exit route.
    exit_access: crate::server::ExitAccess,
    /// Shared with this client's `SessionShared`; raised by `kick_all` (kick, quota
    /// cut-off, supersede). `None` until authenticated.
    ///
    /// Ingress is demultiplexed from THIS per-worker map, but every control action edits
    /// `profile.sessions.by_ip` — a different registry. Without this link a revoked
    /// client kept feeding the TUN until the reaper expired it, by which time its pool IP
    /// could already belong to somebody else. (Audit 2026-07-27, A1/A2/A3.)
    revoked: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Shared with this client's `SessionShared.path_mtu` — the tunnel MTU it reported after
    /// probing its path, written here by the receive loop and read by the TUN forwarder.
    /// `None` until authenticated; 0 inside means "never reported". (Audit 2026-07-30, #13.)
    path_mtu: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Complete server→client outer UDP payload size certified in that same direction. The
    /// authenticated client report is only an upper bound used to size a reverse DF probe;
    /// the writer starts at the family-safe minimum and widens only after the probe ACK.
    /// Kept separate from `path_mtu`: DATA_FRAG makes inner MTU and outer datagram size
    /// independent. `None` until authentication completes.
    udp_payload_budget: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// One bounded reverse probe awaiting its matching ACK. `None` is also the retry gate.
    downlink_mtu_probe: Option<DownlinkMtuProbe>,
    /// Shared with this client's `SessionShared.client_info` — the `(version, platform)` it
    /// reported about itself, written here by the receive loop and read by `list-clients`
    /// through the session. `None` until authenticated; `None` inside means "never said".
    client_info: Option<crate::server::handler::ClientInfoCell>,
    /// Fixed-budget encrypted-record storage shared with this client's `SessionShared`.
    /// `None` while the peer is half-open; allocated only after authentication succeeds.
    wire_pool: Option<BufferPool>,
    /// Cumulative anti-amplification budget for this session — an APPROXIMATION of the wire,
    /// deliberately, and read the next paragraph before trusting either number.
    ///
    /// `handle_new_udp_client` bounds the FIRST exchange (a ≥1200 B floor plus an explicit 3×
    /// check), but the idempotent re-emit path below it repeated neither: a 6-byte datagram
    /// carrying the fragment magic re-sent the whole cached ServerHello (~2-3.4 KB) for free,
    /// and could be repeated for the life of the half-open session — a ~500× reflector for a
    /// spoofed source, i.e. exactly the property the initial check exists to deny. Counting
    /// both directions and refusing to exceed 3× received closes the gap for every reply path,
    /// present and future, instead of re-deriving the bound at each of them.
    ///
    /// **What these actually count**, since it is not the same thing on both sides:
    ///
    /// * `amp_received` adds `data.len()` after transparent obfs-open but before QUIC-unwrap.
    ///   The 13-byte obfs envelope and the IP/UDP headers are therefore not included. Omitting
    ///   received bytes makes the allowance stricter, not looser.
    /// * the seed for `amp_received` is the REASSEMBLED ClientHello, not the sum of the
    ///   datagrams that carried it, so a fragmented one is undercounted by the per-fragment
    ///   headers. **Undercounting received makes the budget stricter**, so this errs safe.
    /// * `amp_sent` adds message bodies, not wrapped datagrams: the QUIC and obfs headers put
    ///   around a ServerHello or an AuthOK fragment are not counted. **Undercounting sent
    ///   makes the budget looser** — by roughly 20-30 bytes per datagram, against a 3× bound
    ///   on kilobyte-scale messages.
    ///
    /// So the ratio is real but not exact, and it is not trying to be: the job is to deny a
    /// large multiplier to an unverified source, not to meter traffic. Making it exact would
    /// mean threading the emitted size back out of `send_handshake_response` and the AuthOK
    /// send loop — changing signatures to sharpen a bound whose slack is a rounding error
    /// against what it prevents. If that ever becomes worth doing, do it in those two places
    /// and delete this paragraph; do not leave the doc claiming precision the code lacks,
    /// which is what it did before. (Audit 2026-08-02, §7 of the follow-up.)
    amp_received: u64,
    amp_sent: u64,
    /// AuthOK re-emits already granted to this session, bounded by [`MAX_AUTH_OK_REEMITS`].
    ///
    /// The 3× byte budget above guards the UNVERIFIED path, where a 6-byte datagram carrying
    /// the fragment magic could pull a whole ServerHello out of us. It is the wrong instrument
    /// once the session is `Authenticated`, and actively harmful there: a profile with a large
    /// pushed-route set makes the AuthOK several KB, so re-sending it needs more budget than
    /// the client's ~350-byte AUTH retransmits can earn inside the handshake deadline. The
    /// recovery path would then be denied on exactly the profiles fragmentation was added for.
    ///
    /// An authenticated peer has already proven return-routability — it completed the PQ
    /// handshake and authenticated from this address — so reflection to a spoofed source is not
    /// the risk here. What remains is an on-path attacker replaying the observed AUTH to make
    /// us re-send; a small count cap bounds that to a handful of datagrams per session, which
    /// is all the legitimate path ever needs. (Audit 2026-08-02, §4.)
    auth_ok_reemits: u8,
    /// Whether this session's AuthOK has actually reached the socket.
    ///
    /// NOTHING may precede the AuthOK on an authenticated session, and `Authenticated` alone
    /// does not mean it has been sent: `handle_udp_auth` runs on its own task (spawned off the
    /// recv loop so Argon2 cannot stall the worker), sets this state, and only then takes the
    /// pool lock, checks `max_clients` and programs routes before sending. The select! loop
    /// keeps running throughout, so a heartbeat or cover tick landing in that window found a
    /// session it considered live and wrote to the wire first.
    ///
    /// What the client does with that is not graceful: it takes the first record that decrypts
    /// as the AuthOK, so a cover packet — which decrypts perfectly into an EMPTY payload —
    /// fails the `OK:` parse and the connect dies. On a fragmented AuthOK the stray datagram
    /// also resets reassembly. Rare (the window is short against a 15 s beacon), and a random
    /// UDP auth failure with a reconnect loop is exactly the kind of rare that never gets
    /// diagnosed. (Audit 2026-08-03, P1.)
    auth_ok_sent: bool,
}

/// How many times one session may have its AuthOK re-sent. The client retransmits AUTH on a
/// ~1 s jittered timer inside a 10 s handshake deadline, so the legitimate path needs a few at
/// most; past that the reply is not being lost, it is being milked.
const MAX_AUTH_OK_REEMITS: u8 = 5;

/// Bind one `SO_REUSEPORT` UDP socket. Several of these on the same address let the
/// kernel flow-hash incoming datagrams across them, so multiple workers can decrypt
/// on separate cores. Each flow (client) sticks to one socket → one worker, so its
/// session stays on a single thread.
pub(crate) fn bind_reuseport(
    addr: &str,
    perf: &crate::config::UdpPerfConfig,
    counters: Arc<UdpBufferCounters>,
    aggregate_budget: AggregateUdpBudgetPlan,
) -> anyhow::Result<(UdpSocket, UdpBufferController)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sa: SocketAddr = addr.parse()?;
    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if sa.is_ipv6() {
        // Keep the IPv6 listener in its own address family. Without V6ONLY, binding
        // `[::]:port` can also claim IPv4-mapped traffic and either collide with the
        // explicit `0.0.0.0:port` listener or distribute IPv4 datagrams across the wrong
        // profile/socket set.
        sock.set_only_v6(true)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;

    sock.bind(&sa.into())?;
    let socket = UdpSocket::from_std(sock.into())?;
    let controller = UdpBufferController::configure(
        &socket,
        UdpBufferPolicy {
            send_bytes: perf.send_buffer_size,
            receive_bytes: if perf.recv_buffer_auto && perf.recv_buffer_size > 0 {
                aggregate_budget.auto_initial_recv_bytes
            } else {
                perf.recv_buffer_size
            },
            automatic_receive: perf.recv_buffer_auto,
            max_receive_bytes: if perf.recv_buffer_auto && perf.recv_buffer_size > 0 {
                aggregate_budget.auto_max_recv_bytes
            } else {
                AUTO_MAX_RECV_BYTES
            },
        },
        counters,
        format!("server UDP {addr}"),
    );
    Ok((socket, controller))
}

/// How long an authenticated UDP session may go with no received datagram before
/// it is reaped as dead. The RX-liveness deadline exists only when the client is
/// configured to emit heartbeat/shaping traffic. Otherwise a completely idle UDP
/// tunnel is indistinguishable from a dead one, so only an explicit idle timeout may
/// reap it.
fn udp_reap_window(
    idle_timeout: std::time::Duration,
    liveness_deadline: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    let explicit = (idle_timeout.as_secs() > 0).then_some(idle_timeout);
    match (explicit, liveness_deadline) {
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

pub(crate) async fn run_udp_server(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    socket: UdpSocket,
    mut udp_buffer: UdpBufferController,
    worker_id: usize,
    tun_tx: TunIngress,
    tasks: super::ProfileTasks,
) -> anyhow::Result<()> {
    let pcfg = &profile.config;
    log::info!(
        "UDP worker {} for profile '{}' started",
        worker_id,
        profile.name
    );

    // `obfs` wire mode wraps every datagram in a per-datagram ChaCha20 XOR
    // (transparent here via ObfsUdp). `None` = pass-through (fake-tls mode).
    let obfs_key = if pcfg.obfuscation.mode == "obfs" && !pcfg.obfuscation.obfs_key.is_empty() {
        Some(crate::protocol::obfs::derive_obfs_key(
            &pcfg.obfuscation.obfs_key,
        ))
    } else {
        None
    };
    let socket = Arc::new(crate::protocol::obfs::ObfsUdp::new(socket, obfs_key));
    let sessions: Arc<RwLock<HashMap<SocketAddr, UdpClient>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // Per-worker admission gate for pre-auth handshake crypto (see
    // max_concurrent_udp_handshakes). Acquired just before the PQ handshake in
    // the new-session branch; a datagram that can't get a permit is dropped.
    let handshake_permits = Arc::new(Semaphore::new(max_concurrent_udp_handshakes()));

    // Sources with an authentication in flight. The auth path (tarpit sleep + Argon2) is
    // dispatched off this recv loop — see handle_udp_datagram — because `.await`ing it
    // inline froze the whole SO_REUSEPORT worker, and with it EVERY established session
    // hashed to this worker, for the duration of one login (head-of-line blocking DoS).
    // This set stops a duplicate datagram from the same source launching a SECOND parallel
    // Argon2 while the first is still running. (H1)
    let auth_inflight: Arc<tokio::sync::Mutex<std::collections::HashSet<SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));

    let idle_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);
    let handshake_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let quic_config = &pcfg.obfuscation.quic;
    // Flow-shaping (DPI-AUDIT 6.1/6.2): when on, per-client Poisson idle cover
    // REPLACES the fixed heartbeat. The tick polls at the gap floor so per-client
    // cover deadlines are honoured at a reasonable granularity.
    let shaping_cfg = pcfg.obfuscation.traffic_shaping.to_shaping();
    let shaping_on = shaping_cfg.enabled && shaping_cfg.budget_bytes_per_sec > 0;

    let mut recv_buf = vec![0u8; crate::transport::udp::MAX_UDP_PACKET_SIZE];
    let tick_ms = if shaping_on {
        shaping_cfg.idle_gap_min_ms.max(20)
    } else if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        DEFAULT_HEARTBEAT_INTERVAL_MS
    };
    let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_millis(tick_ms));
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut udp_buffer_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    udp_buffer_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Partial ClientHello reassembly, keyed by source address: the UDP handshake is
    // fragmented to dodge IP fragmentation on mobile / CGNAT paths (which drop IP
    // fragments). Bounded by MAX_PENDING_HANDSHAKES and aged out in the cleanup tick.
    let mut frag_pending: HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler> =
        HashMap::new();
    // Cover and heartbeat records are generated serially by this task. Keep their
    // random padding in task-owned storage instead of allocating a fresh Vec for
    // every client on every tick.
    let mut padding = Vec::with_capacity(crate::protocol::packet::MAX_RECORD_SIZE);
    let mut quic_record = Vec::with_capacity(
        handler::server_wire_buffer_capacity(pcfg) + crate::protocol::quic::QUIC_SHORT_HEADER_MIN,
    );

    loop {
        tokio::select! {
            result = socket.recv_from(&mut recv_buf) => {
                let (n, addr) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("UDP recv error on profile '{}': {}", profile.name, e);
                        continue;
                    }
                };
                udp_buffer.note_receive(n);

                if n == 0 { continue; }  // malformed obfs frame
                // Rate-limit only NEW UDP sessions. Applying the limiter to
                // every datagram (as the original code did) caps an active
                // tunnel at 10 packets / 60 s and silently drops the rest,
                // which is why a working handshake produced 100 % loss on the
                // first sustained data flow.
                // A continuation fragment of a ClientHello already being reassembled
                // (addr in frag_pending) is NOT a new session — don't re-charge the
                // new-session rate limiter for each fragment.
                let is_new_session = !sessions.read().await.contains_key(&addr)
                    && !frag_pending.contains_key(&addr);
                if is_new_session {
                    // AWG junk (AmneziaWG-style Jc on UDP): a client may prepend `jc`
                    // throwaway decoy datagrams before its ClientHello to blur the
                    // size/count fingerprint of the first packets. Drop them here —
                    // BEFORE the new-session rate limiter, any crypto or the
                    // reassembler — so junk is free and harmless (a lost / reordered
                    // junk datagram never matters). Junk rides the same QUIC mask as
                    // real datagrams, so peek through it first.
                    // Detect the QUIC mask by signature (not the profile flag): a
                    // udp-quic client wraps its junk in a QUIC long header just like its
                    // ClientHello, so the early drop must peek through it even when this
                    // profile's own `quic.enabled` is off. If detection misses, the junk
                    // still gets dropped one stage later in handle_udp_datagram (pre-crypto).
                    let is_junk = if looks_like_quic_initial(&recv_buf[..n]) {
                        unwrap_quic_payload(&recv_buf[..n])
                            .ok()
                            .map(crate::protocol::udp_frag::is_junk)
                            .unwrap_or(false)
                    } else {
                        crate::protocol::udp_frag::is_junk(&recv_buf[..n])
                    };
                    if is_junk {
                        continue;
                    }
                    let mut rl = profile.rate_limiter.lock().await;
                    if !rl.check_and_record(addr.ip()) {
                        continue;
                    }
                }

                handle_udp_datagram(
                    &server_state,
                    &profile,
                    &sessions,
                    &mut frag_pending,
                    &socket,
                    addr,
                    &recv_buf[..n],
                    &tun_tx,
                    quic_config,
                    &handshake_permits,
                    &auth_inflight,
                    &tasks,
                    obfs_key,
                )
                .await;
            }

            _ = udp_buffer_tick.tick() => {
                udp_buffer.tick(socket.raw_socket());
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled || shaping_on => {
                let now = std::time::Instant::now();
                // Collect packets to send before any .await so non-Send types (MutexGuard,
                // Obfuscator/ThreadRng) are guaranteed dropped before the async resume point.
                let to_send: Vec<(std::net::SocketAddr, PooledBuffer, bool, [u8; 4], u32)> = if shaping_on {
                    // Flow-shaping: per-client Poisson idle cover (replaces heartbeat).
                    // Needs a write lock to advance each client's cover deadline + budget.
                    let mut sessions_guard = sessions.write().await;
                    let mut out = Vec::new();
                    for (addr, client) in sessions_guard.iter_mut() {
                        // Authenticated is not enough: the AuthOK may still be in flight on the
                        // auth task. A cover packet reaching the client first is taken for the
                        // AuthOK, decrypts into nothing, and kills the connect. See
                        // `auth_ok_sent`. (Audit 2026-08-03, P1.)
                        if !matches!(client.state, UdpSessionState::Authenticated { .. })
                            || !client.auth_ok_sent
                        {
                            continue;
                        }
                        if now < client.next_cover_at {
                            continue;
                        }
                        client.next_cover_at =
                            now + client.shaper.next_gap(&mut rand::rng());
                        // Fill genuine idle; in STEALTH run cover under load too so
                        // small cover mixes into the (rate-capped) stream.
                        if !client.shaper.stealth()
                            && now.duration_since(client.last_activity)
                                < std::time::Duration::from_millis(50)
                        {
                            continue;
                        }
                        let requested_size = client.shaper.next_size(&mut rand::rng());
                        let size = {
                            let tx = lock_or_recover(&client.tx_codec, "udp::cover_budget");
                            requested_size.min(empty_udp_record_padding_cap(
                                &tx,
                                addr.is_ipv6(),
                                socket.seal_overhead(),
                                client.quic_enabled,
                            ))
                        };
                        if !client.shaper.try_spend(size, now) {
                            continue;
                        }
                        let Some(mut pkt) = client
                            .wire_pool
                            .as_ref()
                            .and_then(BufferPool::try_acquire)
                        else {
                            continue;
                        };
                        let encrypted = {
                            let mut obf = Obfuscator::new();
                            obf.generate_padding_into(size as u16, size as u16, &mut padding);
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::cover");
                            let ok = tx
                                .encrypt_packet_into(&[], &padding, pkt.as_vec_mut())
                                .is_ok();
                            drop(tx);
                            ok
                        };
                        if encrypted {
                            let pn = if client.quic_enabled {
                                client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            } else {
                                0
                            };
                            out.push((*addr, pkt, client.quic_enabled, client.connection_id, pn));
                        }
                    }
                    out
                } else {
                    let sessions_guard = sessions.read().await;
                    let mut out = Vec::new();
                    for (addr, client) in sessions_guard.iter() {
                        // Only beacon AUTHENTICATED clients (a fresh AwaitingAuth entry
                        // is not a real session yet) whose AuthOK has actually gone out —
                        // this loop deliberately does NOT idle-gate (see below), so without
                        // that second condition it is the most likely thing to overtake the
                        // AuthOK. See `auth_ok_sent`. (Audit 2026-08-03, P1.)
                        if !matches!(client.state, UdpSessionState::Authenticated { .. })
                            || !client.auth_ok_sent
                        {
                            continue;
                        }
                        if idle_timeout.as_secs() > 0 && now.duration_since(client.last_activity) > idle_timeout {
                            continue;
                        }
                        // Beacon every interval REGARDLESS of client->server activity. We
                        // must NOT idle-gate on `client.last_activity`: an idle client
                        // sends its OWN keepalives, which refresh `last_activity` and would
                        // suppress this beacon — so a fully idle tunnel got no server->client
                        // traffic and the client (whose RX-liveness counts server->client
                        // only) reconnected every rx_dead. Beaconing unconditionally fixes
                        // that; the redundant beacon under an active server->client flow is
                        // one small packet per interval — negligible.
                        let Some(mut pkt) = client
                            .wire_pool
                            .as_ref()
                            .and_then(BufferPool::try_acquire)
                        else {
                            continue;
                        };
                        let encrypted = {
                            let mut obf = Obfuscator::new();
                            // saturating: data_size_bytes is a u16 config knob — `+ 32`
                            // would wrap in release / panic in debug at the top of range.
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::heartbeat");
                            let cap = empty_udp_record_padding_cap(
                                &tx,
                                addr.is_ipv6(),
                                socket.seal_overhead(),
                                client.quic_enabled,
                            )
                            .min(u16::MAX as usize) as u16;
                            let low = hb_config.data_size_bytes.min(cap);
                            let high = hb_config.data_size_bytes.saturating_add(32).min(cap);
                            obf.generate_padding_into(low, high, &mut padding);
                            let ok = tx
                                .encrypt_packet_into(&[], &padding, pkt.as_vec_mut())
                                .is_ok();
                            drop(tx);
                            ok
                        };
                        if encrypted {
                            let pn = if client.quic_enabled {
                                client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                            } else {
                                0
                            };
                            out.push((*addr, pkt, client.quic_enabled, client.connection_id, pn));
                        }
                    }
                    out
                };
                // Now we can .await freely — no non-Send types in scope
                for (addr, pkt, quic_enabled, connection_id, packet_number) in to_send {
                    let data: &[u8] = if quic_enabled {
                        wrap_quic_short_into(
                            &pkt,
                            &connection_id,
                            packet_number,
                            &mut quic_record,
                        );
                        &quic_record
                    } else {
                        &pkt
                    };
                    let _ = socket.send_to(data, addr).await;
                }
            }

            _ = cleanup_tick.tick() => {
                let now = std::time::Instant::now();
                // Heartbeat and shaping both generate authenticated client→server
                // traffic, so their cadence is a valid liveness contract. With both
                // disabled only an explicit idle_timeout is meaningful.
                let liveness_deadline = crate::protocol::liveness_deadline(
                    heartbeat_enabled,
                    std::time::Duration::from_millis(hb_config.interval_ms),
                    std::time::Duration::from_millis(hb_config.jitter_ms),
                    shaping_on,
                    std::time::Duration::from_millis(shaping_cfg.idle_gap_max_ms),
                );
                let reap_after = udp_reap_window(idle_timeout, liveness_deadline);
                let expired: Vec<SocketAddr> = {
                    let sessions_guard = sessions.read().await;
                    sessions_guard.iter()
                        .filter(|(_, c)| match &c.state {
                            UdpSessionState::AwaitingAuth => {
                                now.duration_since(c.created_at) > handshake_timeout
                            }
                            UdpSessionState::Authenticated { .. } => reap_after
                                .is_some_and(|limit| now.duration_since(c.last_activity) > limit),
                        })
                        .map(|(addr, _)| *addr)
                        .collect()
                };
                if !expired.is_empty() {
                    // Lock order (finding B): the auth path releases the per-worker
                    // `sessions` guard BEFORE taking profile.pool / profile.sessions.
                    // Collect the authenticated victims' pool/IP keys under the
                    // `sessions` write guard, drop it, then release pool + remove
                    // from profile.sessions in a second loop — same order everywhere.
                    let mut to_release: Vec<(String, std::net::IpAddr, u64)> = Vec::new();
                    {
                        let mut sessions_guard = sessions.write().await;
                        for addr in expired {
                            if let Some(client) = sessions_guard.remove(&addr) {
                                match client.state {
                                    UdpSessionState::Authenticated {
                                        session_id,
                                        device_key,
                                        client_ip,
                                        ..
                                    } => {
                                        to_release.push((device_key, client_ip, session_id));
                                    }
                                    UdpSessionState::AwaitingAuth => {
                                        log::debug!("UDP: evicted stale handshake from {} on profile '{}'", addr, profile.name);
                                    }
                                }
                            }
                        }
                    }
                    for (device_key, client_ip, session_id) in to_release {
                        // A reconnect may have reused this IP under a NEW session_id, or
                        // re-allocated the same device_key elsewhere. Guard both actions on
                        // the reaped session still being the live one — else we'd yank a
                        // live session out of by_ip / free its pool slot from under it.
                        //
                        // Join the same authoritative admission transaction as TCP teardown,
                        // admin kick, quota expiry and authentication. Merely taking `pool`
                        // before checking `profile.sessions` is insufficient: a reconnect can
                        // allocate first, drop the pool lock, and still be building AuthOK
                        // before it publishes the replacement session. A reaper in that gap
                        // sees no live device and frees the newly allocated lease. Admission
                        // covers removal, the liveness decision and release as one transition.
                        let admission_guard = profile.admission.lock().await;
                        let (device_still_live, iroutes) = {
                            let mut prof_sessions = profile.sessions.write().await;
                            let ip_still_ours = prof_sessions
                                .by_ip
                                .get(&client_ip)
                                .map(|s| s.session_id == session_id)
                                .unwrap_or(false);
                            let mut iroutes: Vec<String> = Vec::new();
                            if ip_still_ours {
                                if let Some(sess) = prof_sessions.remove(client_ip) {
                                    // Signal the UDP writer task to exit. Without kick_all it
                                    // parks forever on writer_rx (whose Sender lives in this
                                    // session), leaking the task + session on the normal
                                    // idle/dead reap path — the usual UDP teardown (no clean
                                    // close), so this leaked on essentially every dropped client.
                                    sess.kick_all();
                                    iroutes = prof_sessions.take_client_routes(client_ip);
                                    // Notify (opt-in): UDP session reaped (idle/dead — UDP has
                                    // no clean close). Guarded on session_id, so fire-once.
                                    crate::server::notify::fire_disconnect(
                                        &sess.username,
                                        &profile.name,
                                        sess.peer,
                                    );
                                }
                            }
                            let device_still_live = prof_sessions
                                .by_ip
                                .values()
                                .any(|s| s.device_key == device_key);
                            (device_still_live, iroutes)
                        };
                        if !device_still_live {
                            profile.pool.lock().await.release(&device_key);
                        }
                        // Admission must cover the kernel side of the same ownership change.
                        // Spawning this after dropping the guard lets a reconnect install the
                        // same CIDR first and then lose it to this stale `ip route del`.
                        for cidr in &iroutes {
                            let _ = crate::server::handler::program_client_subnet_route(
                                false,
                                cidr,
                                &profile.config.tun.name,
                            )
                            .await;
                        }
                        drop(admission_guard);
                    }
                }

                // Drop partially-reassembled ClientHellos that never completed (lost
                // fragment / spoofed-source flood) so the buffer can't grow unbounded.
                frag_pending
                    .retain(|_, r| r.age() < crate::protocol::udp_frag::REASSEMBLY_TIMEOUT);
            }

            _ = tokio::signal::ctrl_c() => {
                log::info!("UDP server for profile '{}' shutdown signal received", profile.name);
                break;
            }
        }
    }

    Ok(())
}

/// Send the ServerHello handshake response. A client that fragmented its ClientHello
/// (LTE/CGNAT fix) gets a fragmented response too, so no datagram needs IP
/// fragmentation; a legacy single-datagram client gets one packet, byte-identical to
/// the old behaviour. Each datagram is QUIC-wrapped with `connection_id` when enabled.
async fn send_handshake_response(
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    raw: &[u8],
    quic_enabled: bool,
    connection_id: &[u8; 4],
    fragment_it: bool,
) {
    if fragment_it {
        let frags = match crate::protocol::udp_frag::fragment(
            crate::protocol::udp_frag::MSG_SERVER_HELLO,
            raw,
        ) {
            Ok(f) => f,
            Err(e) => {
                log::error!("ServerHello too large to fragment ({e}) — dropping response");
                return;
            }
        };
        for (i, frag) in frags.into_iter().enumerate() {
            let pkt = if quic_enabled {
                // Initial, matching the single-datagram path below and every new client.
                // The receive side still accepts the historical Handshake-type spelling.
                wrap_quic_long(&frag, connection_id, i as u32)
            } else {
                frag
            };
            let _ = socket.send_to(&pkt, addr).await;
        }
    } else {
        let pkt = if quic_enabled {
            wrap_quic_long(raw, connection_id, 0)
        } else {
            raw.to_vec()
        };
        let _ = socket.send_to(&pkt, addr).await;
    }
}

/// First QUIC packet number the DATA plane may use.
///
/// The handshake numbers positionally: ServerHello is 0, the AuthOK is 1, so the session
/// starts at 2. A fragmented AuthOK consumes 1..=N instead of just 1, and the session counter
/// is pushed past them at auth time — this constant is the floor it starts from, and the
/// arithmetic tying the two together is pinned by `the_data_plane_never_reuses_an_authok_pn`.
const UDP_SESSION_FIRST_PN: u32 = 2;

/// Packet number of the FIRST AuthOK fragment; the rest follow it consecutively.
const AUTH_OK_FIRST_PN: u32 = 1;

/// Turn an encrypted AuthOK record into the datagram(s) that carry it.
///
/// One datagram whenever it fits the fragment budget — byte-identical to what every build
/// before this emitted, which is what keeps clients that predate [`MSG_AUTH_OK`] working. Over
/// the budget it is split, because the alternative is what shipped: a single oversized
/// datagram that an IP-fragment-dropping path (mobile, CGNAT) silently destroys, leaving the
/// client to time out at the AUTHENTICATION step with nothing in either log to say why.
/// (Audit 2026-08-02, §4.)
///
/// Layering matches [`send_handshake_response`]: split first, then QUIC-wrap each fragment
/// separately, so no datagram ever needs IP fragmentation. The AuthOK is post-handshake, so
/// it uses the SHORT header the data plane uses, not the long one — and each fragment gets
/// its own packet number for the same reason the ServerHello's do.
///
/// `Err` only if the record needs more than `MAX_FRAGS` fragments (~28 KB of pushed routes),
/// which the receiver would reject anyway; the caller reports it instead of emitting a
/// message the client silently drops.
fn build_auth_ok_datagrams(
    record: &[u8],
    quic_enabled: bool,
    connection_id: &[u8; 4],
) -> Result<Vec<Vec<u8>>, &'static str> {
    use crate::protocol::udp_frag;
    if record.len() <= udp_frag::MAX_CHUNK {
        return Ok(vec![if quic_enabled {
            wrap_quic_short(record, connection_id, AUTH_OK_FIRST_PN)
        } else {
            record.to_vec()
        }]);
    }
    let frags = udp_frag::fragment(udp_frag::MSG_AUTH_OK, record)?;
    Ok(frags
        .into_iter()
        .enumerate()
        .map(|(i, frag)| {
            if quic_enabled {
                wrap_quic_short(&frag, connection_id, AUTH_OK_FIRST_PN + i as u32)
            } else {
                frag
            }
        })
        .collect())
}

fn build_auth_error_datagrams(
    tx_codec: &mut PacketCodec,
    reason: &str,
    quic_enabled: bool,
    connection_id: &[u8; 4],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let message = handler::build_auth_error(reason);
    let record = tx_codec.encrypt_packet(message.as_bytes(), &[])?;
    build_auth_ok_datagrams(&record, quic_enabled, connection_id).map_err(anyhow::Error::msg)
}

#[allow(clippy::too_many_arguments)] // datagram dispatch threads the shared UDP state
async fn handle_udp_datagram(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, UdpClient>>>,
    frag_pending: &mut HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    data: &[u8],
    tun_tx: &TunIngress,
    quic_config: &QuicMaskingConfig,
    handshake_permits: &Arc<Semaphore>,
    auth_inflight: &Arc<tokio::sync::Mutex<std::collections::HashSet<SocketAddr>>>,
    tasks: &super::ProfileTasks,
    obfs_key: Option<[u8; 32]>,
) {
    // Decide whether this datagram is QUIC-masked. For an ESTABLISHED session we honour
    // the choice recorded at handshake time — a QUIC data packet is a short header over
    // ciphertext and cannot be classified by signature. For a BRAND-NEW source we
    // classify by the first packet's signature (a QUIC v1 long-header Initial), so a
    // udp-quic client is accepted even when THIS profile's own `quic.enabled` is off:
    // the server mirrors the client's choice for the whole connection, exactly like it
    // already does for fragmentation. `quic.enabled` now only governs whether the server
    // stamps `quic=1` into the qeli:// links it generates. (#69)
    let session_quic = {
        let guard = sessions.read().await;
        guard.get(&addr).map(|c| c.quic_enabled)
    };
    let treat_as_quic = match session_quic {
        Some(q) => q,
        None => looks_like_quic_initial(data),
    };
    let (payload, quic_detected) = if treat_as_quic {
        match unwrap_quic_payload(data) {
            Ok(payload) => (payload, true),
            Err(e) => {
                log::debug!(
                    "UDP drop from {} on profile '{}': QUIC unwrap failed ({})",
                    addr,
                    profile.name,
                    e
                );
                return;
            }
        }
    } else {
        (data, false)
    };

    // AWG junk decoy — carries no real data. The receive loop already drops junk from
    // a brand-new source before the rate limiter; this also catches junk that arrived
    // reordered AFTER the first ClientHello fragment (is_new_session was false then),
    // so it is never fed to the per-source reassembler.
    if crate::protocol::udp_frag::is_junk(payload) {
        return;
    }

    // Reverse PMTU ACK: only an exact response to the one outstanding server→client probe
    // may widen this session. It is deliberately handled before PacketCodec because the
    // full-size probe/short ACK exchange is carrier framing, not encrypted inner traffic.
    if crate::protocol::udp_frag::is_mtu_probe_ack_v2(payload) {
        let certified = if let Some((token, payload_size)) =
            crate::protocol::udp_frag::parse_mtu_probe_v2_ack(payload)
        {
            let mut guard = sessions.write().await;
            guard.get_mut(&addr).and_then(|client| {
                let expected = client.downlink_mtu_probe?;
                if expected.token == token && expected.payload_size == payload_size {
                    client.downlink_mtu_probe = None;
                    client
                        .udp_payload_budget
                        .as_ref()
                        .map(|cell| (cell.clone(), expected.udp_payload_budget))
                } else {
                    None
                }
            })
        } else {
            None
        };
        if let Some((cell, budget)) = certified {
            note_certified_udp_payload_budget(&cell, format_args!("at {addr}"), budget);
        }
        return;
    }
    // Legacy ACKs remain valid for the client-driven uplink ladder, but their 16-bit id is
    // not sufficient proof for widening the opposite direction. Drop them as carrier frames.
    if crate::protocol::udp_frag::is_mtu_probe_ack(payload) {
        return;
    }

    // Path-MTU probe (client→server): echo a tiny ACK carrying the same id+size so the
    // client's probe ladder learns which datagram sizes traverse the path unfragmented.
    // A probe is NOT an AEAD data packet — echo and STOP before the decrypt below (its
    // oversized chunk would also be rejected by the reassembler). Only a known session
    // is echoed (gates it to an authenticated peer); the ACK is QUIC-wrapped with the
    // session's connection id + next packet number, exactly like the heartbeat reply.
    if crate::protocol::udp_frag::is_mtu_probe(payload) {
        if let Some((id, size)) = crate::protocol::udp_frag::parse_mtu_probe_request(payload) {
            let wrap = {
                let guard = sessions.read().await;
                guard.get(&addr).map(|c| {
                    let pn = c
                        .packet_counter
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (c.quic_enabled, c.connection_id, pn)
                })
            };
            if let Some((quic, cid, pn)) = wrap {
                let ack = crate::protocol::udp_frag::mtu_probe_ack_datagram(id, size);
                let pkt = if quic {
                    wrap_quic_short(&ack, &cid, pn)
                } else {
                    ack
                };
                let _ = socket.send_to(&pkt, addr).await;
            }
        }
        return;
    }

    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            // Idempotent handshake re-emit BEFORE decrypt: a lost server->client
            // handshake datagram (ServerHello or AuthOK) leaves the client
            // retransmitting its request, which the normal path drops — a
            // retransmitted ClientHello is a plaintext fragment that fails AEAD, and a
            // retransmitted AUTH is an exact replay the window rejects. Detect the
            // retransmit and re-send the CACHED response so the client recovers in
            // ~1 RTT instead of stalling the full connection_timeout before a
            // fresh-port reconnect. This never creates or mutates crypto state.
            // Everything this source sends counts toward its budget, including the
            // datagrams that trigger a re-emit — otherwise the trigger would be free.
            // `data` is the datagram after transparent obfs-open but before QUIC-unwrap; see
            // the note on `amp_received` for what the two counters do and do not include.
            client.amp_received = client.amp_received.saturating_add(data.len() as u64);

            let reemit_auth_response =
                !client.auth_ok.is_empty() && payload == client.auth_request.as_slice();
            let reemit_hello = !reemit_auth_response
                && matches!(client.state, UdpSessionState::AwaitingAuth)
                && crate::protocol::udp_frag::is_fragment(payload);
            if reemit_hello || reemit_auth_response {
                // NOTE: `last_activity` is deliberately NOT touched here — see below.
                let hello = client.server_hello.clone();
                let cid = client.connection_id;
                let quic = client.quic_enabled;
                let frag = client.hello_frag_mode;
                let authok = client.auth_ok.clone();
                // Every fragment goes back on the wire, so every fragment is charged.
                //
                // Note the asymmetry: the AuthOK is cached AS DATAGRAMS, so summing them is
                // exact, while the ServerHello is cached as the MESSAGE and re-fragmented and
                // re-wrapped on the way out — its charge therefore misses the per-datagram
                // QUIC/obfs headers. Undercounting what we send is the loose direction; see
                // the note on `amp_received` for why that slack is accepted rather than
                // plumbed away.
                let reply_len: u64 = if reemit_hello {
                    hello.len() as u64
                } else {
                    authok.iter().map(|d| d.len() as u64).sum()
                };
                // Two different instruments, because the two paths carry different risk.
                //
                // ServerHello (half-open, source UNVERIFIED): the cumulative 3× bound. The
                // trigger can be a 6-byte datagram, so without it this is a ~500× reflector
                // for a spoofed source — the exact property the initial check exists to deny.
                //
                // AuthOK (session AUTHENTICATED): a count cap instead. Return-routability is
                // already proven here, and the byte bound actively breaks the recovery path
                // for a large pushed-route set — several KB of AuthOK cannot be earned back
                // by ~350-byte AUTH retransmits inside the handshake deadline, so the client
                // would sit there re-asking for a reply it is never allowed to receive.
                // (Audit 2026-08-02, §4.)
                if reemit_hello {
                    let over_budget = client.amp_sent.saturating_add(reply_len)
                        > client.amp_received.saturating_mul(3);
                    if over_budget {
                        log::debug!(
                            "UDP {}: suppressing handshake re-emit — would exceed the 3x \
                             anti-amplification budget (sent {}B + {}B vs received {}B)",
                            addr,
                            client.amp_sent,
                            reply_len,
                            client.amp_received
                        );
                        return;
                    }
                } else if client.auth_ok_reemits >= MAX_AUTH_OK_REEMITS {
                    log::debug!(
                        "UDP {}: suppressing AuthOK re-emit — already re-sent {} times, which \
                         is past what a lost reply needs",
                        addr,
                        client.auth_ok_reemits
                    );
                    return;
                } else {
                    client.auth_ok_reemits = client.auth_ok_reemits.saturating_add(1);
                }
                // Liveness is proven by a datagram we could DECRYPT, never by a replayed one.
                //
                // `last_activity` used to be bumped at the top of this branch, before the
                // budget/count checks and without any AEAD. The trigger condition for the
                // AuthOK path is `payload == client.auth_request` — a byte-for-byte replay of
                // an AUTH datagram this peer sent earlier. On UDP the session map is keyed on
                // the source address alone, so anyone who observed that datagram, or who can
                // simply spoof the source, could retransmit it forever and keep the entry
                // alive: `cleanup_tick` reaps on `last_activity`, so the session never aged
                // out, and its pool address, its `max_clients` slot and its `by_ip` entry were
                // held indefinitely after the real client had gone. Worse, the suppression
                // above returns EARLY, so once the re-emit budget was spent the timer kept
                // being refreshed while nothing was sent — the throttle stopped the reply and
                // not the resource hold.
                //
                // The TCP path states the same rule explicitly and only moves rx-liveness
                // after a successful decrypt. Bumping it only when we actually re-emit keeps
                // the legitimate case working (a client whose reply was lost is genuinely
                // there and gets MAX_AUTH_OK_REEMITS worth of grace) and bounds the abuse to
                // that same small count. (Audit 2026-08-04.)
                client.last_activity = std::time::Instant::now();
                client.amp_sent = client.amp_sent.saturating_add(reply_len);
                drop(sessions_guard);
                if reemit_hello {
                    if !hello.is_empty() {
                        send_handshake_response(socket, addr, &hello, quic, &cid, frag).await;
                    }
                } else {
                    for pkt in &authok {
                        let _ = socket.send_to(pkt, addr).await;
                    }
                }
                return;
            }
            // Revoked? Forget the peer and drop the datagram, before spending any AEAD.
            //
            // `kick_all` raises this flag; the control plane calls it for an admin kick,
            // for the quota sweep's cut-off, and when a reconnect supersedes an old
            // session. Previously none of those reached ingress at all — they edit
            // `profile.sessions.by_ip`, whereas this loop demultiplexes from the
            // per-worker map — so a kicked client went on injecting packets into the TUN
            // for the remaining 30-45 s of its reaper window, using a source address the
            // pool had already released and might have reassigned.
            // (Audit 2026-07-27, A2/A3.)
            let revoked_now = client
                .revoked
                .as_ref()
                .is_some_and(|r| r.load(std::sync::atomic::Ordering::Relaxed));
            if revoked_now {
                sessions_guard.remove(&addr);
                drop(sessions_guard);
                log::debug!(
                    "UDP {}: dropping datagram — session revoked (kick / quota / supersede)",
                    addr
                );
                return;
            }
            let source_session_id = match &client.state {
                UdpSessionState::Authenticated { session_id, .. } => Some(*session_id),
                UdpSessionState::AwaitingAuth => None,
            };
            let is_awaiting_auth = source_session_id.is_none();
            let reassembled_record;
            let payload = if crate::protocol::data_frag::is_data_fragment(payload) {
                if is_awaiting_auth || !client.data_frag_enabled {
                    log::debug!(
                        "UDP drop from {} on profile '{}': DATA_FRAG_V1 was not negotiated",
                        addr,
                        profile.name
                    );
                    return;
                }
                match client
                    .data_reassembler
                    .push(payload, &client.rx_data_frag_key)
                {
                    Ok(Some(record)) => {
                        reassembled_record = record;
                        reassembled_record.as_slice()
                    }
                    Ok(None) => return,
                    Err(error) => {
                        log::debug!(
                            "UDP drop from {} on profile '{}': bad data fragment ({})",
                            addr,
                            profile.name,
                            error
                        );
                        return;
                    }
                }
            } else {
                payload
            };
            let Some(mut plaintext) = tun_tx.pool.try_acquire() else {
                client
                    .dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                profile
                    .udp_buffer_counters
                    .note_internal_drop(InternalDrop::PoolExhausted);
                log::debug!(
                    "UDP drop from {} on profile '{}': inbound TUN pool exhausted",
                    addr,
                    profile.name
                );
                return;
            };
            if payload.len() > plaintext.capacity() {
                client
                    .dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                profile
                    .udp_buffer_counters
                    .note_internal_drop(InternalDrop::Oversize);
                log::debug!(
                    "UDP drop from {} on profile '{}': {}-byte record exceeds inbound pool slot",
                    addr,
                    profile.name,
                    payload.len()
                );
                return;
            }
            plaintext.as_vec_mut().extend_from_slice(payload);
            {
                let mut rx = lock_or_recover(&client.rx_codec, "udp::decrypt");
                if let Err(e) = rx.decrypt_packet_in_place(plaintext.as_vec_mut()) {
                    log::debug!(
                        "UDP decrypt error from {} on profile '{}': {}",
                        addr,
                        profile.name,
                        e
                    );
                    return;
                }
            }
            client.last_activity = std::time::Instant::now();
            // Account inbound (client->server) bytes so `list-clients` RECV is correct
            // (the UDP path never incremented this → RECV always showed 0). Captured
            // before the lock drops; counts plaintext.len() like the TCP path. For an
            // AwaitingAuth client this is a placeholder Arc that is never incremented.
            let recv_ctr = client.bytes_recv.clone();
            let client_dropped = client.dropped.clone();
            let bandwidth_limit = client.bandwidth_limit_mbps.clone();
            let upload_tx = client.upload_tx.clone();
            // Captured with the lock, like recv_ctr — the ACL is consulted below after
            // the guard is dropped. Cheap: an unrestricted ACL is an empty Vec.
            let dst_acl = client.dst_acl.clone();
            let src_guard = client.src_guard.clone();
            let exit_access = client.exit_access;
            // Same reason as recv_ctr: taken with the lock, used after it drops.
            let path_mtu = client.path_mtu.clone();
            let udp_payload_budget = client.udp_payload_budget.clone();
            let client_info = client.client_info.clone();
            drop(sessions_guard);

            if is_awaiting_auth {
                // Dispatch the auth OFF the recv loop: it runs the per-username tarpit sleep
                // and the memory-hard Argon2 (behind argon2_gate), and `.await`ing it here
                // stalled every established session on this worker (H1). The in-flight guard
                // makes a duplicate/retransmitted AUTH from the same source a no-op instead
                // of a second parallel Argon2. On completion the guard is cleared; the auth
                // itself installs the session under the sessions lock as before.
                let already_running = {
                    let mut inflight = auth_inflight.lock().await;
                    !inflight.insert(addr)
                };
                if already_running {
                    return;
                }
                let server_state = server_state.clone();
                let profile = profile.clone();
                let sessions = sessions.clone();
                let socket = socket.clone();
                let quic_config = quic_config.clone();
                let auth_inflight = auth_inflight.clone();
                let auth_tun_tx = tun_tx.clone();
                let raw = payload.to_vec();
                let auth_tasks = tasks.clone();
                tasks.spawn(async move {
                    handle_udp_auth(
                        &server_state,
                        &profile,
                        &sessions,
                        &socket,
                        addr,
                        &plaintext,
                        &raw,
                        &quic_config,
                        auth_tun_tx,
                        auth_tasks,
                    )
                    .await;
                    auth_inflight.lock().await.remove(&addr);
                });
            } else if crate::protocol::ctrl::is_ctrl(&plaintext) {
                // In-tunnel control frame, not a packet: authenticated by the AEAD above and
                // bound to THIS session — which is why the MTU report rides here rather than
                // as a bare datagram alongside the UDP path-MTU probes, whose only identity
                // is a source address anyone could spoof. Handled before the packet path so
                // it never reaches the ACLs or the TUN. (Audit 2026-07-30, #13.)
                if let (Some(cell), Some(mtu)) = (
                    path_mtu.as_ref(),
                    crate::protocol::ctrl::parse_mtu_report(&plaintext),
                ) {
                    crate::server::handler::note_path_mtu(cell, format_args!("at {addr}"), mtu);
                } else if let (Some(cell), Some(budget)) = (
                    udp_payload_budget.as_ref(),
                    crate::protocol::ctrl::parse_udp_payload_budget_report(&plaintext),
                ) {
                    schedule_downlink_mtu_probe(
                        sessions,
                        socket,
                        tasks,
                        &profile.name,
                        addr,
                        cell,
                        budget,
                        obfs_key,
                    )
                    .await;
                } else if let (Some(cell), Some((v, p))) = (
                    client_info.as_ref(),
                    crate::protocol::ctrl::parse_client_info(&plaintext),
                ) {
                    crate::server::handler::note_client_info(
                        cell,
                        format_args!("at {addr}"),
                        &v,
                        &p,
                    );
                }
                return;
            } else if !plaintext.is_empty() {
                // Destination ACL — after AEAD/replay (authenticated traffic only),
                // before the TUN. Unrestricted sessions short-circuit.
                // Source guard first — a forged source is a lie about identity,
                // so judge it before anything that reasons about this session's
                // rights. `None` only for a session that has not authenticated yet,
                // which cannot reach here.
                if let Some(ref g) = src_guard {
                    if !g.allows_packet(&plaintext) {
                        log::debug!("dropped UDP packet from {} — forged source address", addr);
                        return;
                    }
                }
                if !dst_acl.is_unrestricted() && !dst_acl.allows_packet(&plaintext) {
                    log::debug!(
                        "ACL: dropped UDP packet from {} — destination not in allowed_networks",
                        addr
                    );
                    return;
                }
                // Apply the user cap to UDP upload too. Limited packets go through the
                // client's own pacing task; unlimited packets retain the direct hot path.
                let limit = bandwidth_limit
                    .as_ref()
                    .map(|value| value.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(0);
                if limit == 0 {
                    // Preserve the direct fast path for unlimited users.
                    recv_ctr
                        .fetch_add(plaintext.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    // Keep exit-node/default iroutes out of the host routing table. The
                    // direct branch still enters the common TUN downlink forwarder, so UDP
                    // receives the same MTU, fragmentation, rate and encryption treatment.
                    let _ = tun_tx
                        .send_client_packet(
                            profile,
                            source_session_id.expect("authenticated UDP session has an id"),
                            exit_access,
                            ServerTunPacket::Pooled(plaintext),
                        )
                        .await;
                } else if upload_tx
                    .as_ref()
                    .is_none_or(|tx| tx.try_send(plaintext).is_err())
                {
                    // Never await a full per-client pacing queue in this shared receive loop:
                    // one capped peer must not head-of-line block every UDP session.
                    client_dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    profile
                        .udp_buffer_counters
                        .note_internal_drop(InternalDrop::QueueFull);
                    log::debug!(
                        "UDP upload pacing queue full for {} on profile '{}'; dropping packet",
                        addr,
                        profile.name
                    );
                }
            }
            return;
        }
    }

    // New source address: this is the ClientHello. It arrives fragmented (LTE/CGNAT
    // fix) — reassemble it; a legacy single-datagram ClientHello (no fragment magic)
    // is accepted as-is for backward compatibility. We reply in the same shape.
    let (ch, frag_mode): (Vec<u8>, bool) = if crate::protocol::udp_frag::is_fragment(payload) {
        // Bound the reassembly map against a spoofed-source flood: evict the oldest
        // partial when full (same cap as half-open sessions). Only the full,
        // reassembled ClientHello triggers a response (anti-amplification preserved).
        if !frag_pending.contains_key(&addr) && frag_pending.len() >= MAX_PENDING_HANDSHAKES {
            if let Some(oldest) = frag_pending
                .iter()
                .max_by_key(|(_, r)| r.age())
                .map(|(a, _)| *a)
            {
                frag_pending.remove(&oldest);
            }
        }
        match frag_pending.entry(addr).or_default().push(payload) {
            Ok(Some(full)) => {
                frag_pending.remove(&addr);
                (full, true)
            }
            Ok(None) => return, // need more fragments
            Err(_) => {
                frag_pending.remove(&addr); // malformed — drop the partial
                return;
            }
        }
    } else {
        (payload.to_vec(), false)
    };

    // Bound concurrent pre-auth handshake crypto per worker. A spoofed-source
    // flood can bypass the per-IP rate limiter, so without this each ClientHello
    // would run a full PQ handshake (Keypair::generate + ML-KEM + derive) →
    // CPU exhaustion. If no permit is free, DROP silently (don't queue): the
    // client retransmits its ClientHello. The permit is held across the
    // handshake crypto and released when `_permit` drops at the end of this arm.
    let _permit = match handshake_permits.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            log::debug!(
                "UDP drop from {} on profile '{}': no handshake permit (pre-auth crypto saturated)",
                addr,
                profile.name
            );
            return;
        }
    };

    let hide_identity = server_state.config.auth.require_client_key_proof;
    let bind_static = server_state.config.auth.bind_static_to_session;
    match handle_new_udp_client(
        profile,
        &ch,
        addr,
        quic_detected,
        hide_identity,
        bind_static,
    )
    .await
    {
        Ok((mut client, raw_response)) => {
            let cid = client.connection_id;
            // Cache the ServerHello so a retransmitted ClientHello (i.e. a lost
            // ServerHello) can be answered idempotently — see the existing-session
            // re-emit branch. Freed on auth.
            client.server_hello = raw_response.clone();
            client.hello_frag_mode = frag_mode;
            let mut sessions_guard = sessions.write().await;
            // Bound half-open handshakes (U2): under a spoofed-source flood, evict a
            // still-unauthenticated entry instead of growing without limit.
            // Authenticated sessions are skipped by the filter.
            //
            // Evict a RANDOM half-open, not the oldest: under a flood the real,
            // about-to-authenticate clients are a tiny and transient fraction of the
            // AwaitingAuth set (they auth within ~1 RTT), so a random pick hits a real
            // entry only with probability ≈ that small fraction, whereas always taking
            // the oldest can systematically evict a legitimate client whose ServerHello
            // was lost and is retransmitting. Reservoir sample of size 1 in a single
            // pass (no allocation), then remove after the borrow ends.
            let pending = sessions_guard
                .values()
                .filter(|c| matches!(c.state, UdpSessionState::AwaitingAuth))
                .count();
            if pending >= MAX_PENDING_HANDSHAKES {
                let mut victim: Option<SocketAddr> = None;
                let mut seen: u64 = 0;
                for (a, c) in sessions_guard.iter() {
                    if matches!(c.state, UdpSessionState::AwaitingAuth) {
                        seen += 1;
                        // Reservoir sample of size 1: replace the pick with probability
                        // 1/seen (`random % seen == 0`, i.e. a multiple of `seen`).
                        if rand::random::<u64>().is_multiple_of(seen) {
                            victim = Some(*a);
                        }
                    }
                }
                if let Some(stale_addr) = victim {
                    sessions_guard.remove(&stale_addr);
                    log::debug!(
                        "UDP: pending-handshake cap on profile '{}' — evicted a half-open {}",
                        profile.name,
                        stale_addr
                    );
                }
            }
            sessions_guard.insert(addr, client);
            drop(sessions_guard);
            // Reply in the same shape the client used: fragmented for a fragmenting
            // client (no IP fragmentation → works on LTE), single for a legacy one.
            send_handshake_response(socket, addr, &raw_response, quic_detected, &cid, frag_mode)
                .await;
            log::info!(
                "UDP handshake started for {} on profile '{}' ({}{})",
                addr,
                profile.name,
                if frag_mode { "fragmented" } else { "single" },
                if quic_detected { ", QUIC-masked" } else { "" }
            );
        }
        Err(e) => {
            log::debug!(
                "UDP handshake failed for {} on profile '{}': {}",
                addr,
                profile.name,
                e
            );
        }
    }
}

#[allow(clippy::too_many_arguments)] // auth dispatch threads the shared UDP state
async fn handle_udp_auth(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, UdpClient>>>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    plaintext: &[u8],
    // The RAW (post-unwrap, pre-decrypt) AUTH datagram — cached on success so a
    // retransmit (i.e. a lost AuthOK) is recognised and answered idempotently.
    raw_request: &[u8],
    _quic_config: &QuicMaskingConfig,
    tun_tx: TunIngress,
    tasks: super::ProfileTasks,
) {
    let pcfg = &profile.config;
    // Auth plaintext: [client_key_proof:32]([0x00][device_id:16])?[username:password]
    if plaintext.len() < 32 {
        sessions.write().await.remove(&addr);
        return;
    }
    let mut client_key_proof = [0u8; 32];
    client_key_proof.copy_from_slice(&plaintext[..32]);
    let (device_id, auth_bytes) = handler::split_device_id(&plaintext[32..]);
    let (capabilities, creds) =
        match crate::protocol::capabilities::split_client_capabilities(auth_bytes) {
            Ok(value) => value,
            Err(error) => {
                log::warn!("UDP: invalid client capability extension from {addr}: {error}");
                sessions.write().await.remove(&addr);
                return;
            }
        };
    let auth_str = match String::from_utf8(creds.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&addr);
            return;
        }
    };
    let (username, password) = match auth_str.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&addr);
            return;
        }
    };

    log::info!(
        "AUTH attempt UDP from {}: user={} on profile '{}'",
        addr,
        crate::util::log_identity(&username),
        profile.name
    );

    // Pull the channel-binding material captured during the handshake so the
    // shared verifier can check the server-key proof, then run the identical
    // auth policy as TCP (key-proof, brute-force, user lookup, Argon2, profile).
    let (static_shared, ephemeral_shared, transcript_hash) = {
        let g = sessions.read().await;
        match g
            .get(&addr)
            .map(|c| (c.static_shared, c.ephemeral_shared, c.transcript_hash))
        {
            Some(m) => m,
            None => return,
        }
    };
    if let Err(e) = handler::verify_client_auth(
        server_state,
        profile,
        addr,
        "UDP",
        &client_key_proof,
        &username,
        &password,
        &static_shared,
        &ephemeral_shared,
        &transcript_hash,
    )
    .await
    {
        log::debug!(
            "UDP auth rejected for {} on profile '{}': {}",
            addr,
            profile.name,
            e
        );
        sessions.write().await.remove(&addr);
        return;
    }

    let negotiated_ip_mode = match crate::protocol::capabilities::negotiated_profile_ip_mode(
        pcfg.tun.ip_mode,
        capabilities,
    ) {
        Ok(mode) => mode,
        Err(error) => {
            let reason = error.to_string();
            let response_result: anyhow::Result<Vec<Vec<u8>>> = {
                let mut sessions_guard = sessions.write().await;
                let Some(client) = sessions_guard.get_mut(&addr) else {
                    return;
                };
                let packets = {
                    let mut tx = lock_or_recover(&client.tx_codec, "udp::auth_error");
                    build_auth_error_datagrams(
                        &mut tx,
                        &reason,
                        client.quic_enabled,
                        &client.connection_id,
                    )
                };
                match packets {
                    Ok(packets) => {
                        client.auth_request = raw_request.to_vec();
                        client.auth_ok = packets.clone();
                        client.server_hello.clear();
                        client.hello_frag_mode = false;
                        client.packet_counter.fetch_max(
                            AUTH_OK_FIRST_PN + packets.len() as u32,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        let response_len: u64 =
                            packets.iter().map(|packet| packet.len() as u64).sum();
                        client.amp_sent = client.amp_sent.saturating_add(response_len);
                        Ok(packets)
                    }
                    Err(send_error) => Err(send_error),
                }
            };
            let response_pkts = match response_result {
                Ok(packets) => packets,
                Err(send_error) => {
                    log::warn!(
                        "UDP: cannot build negotiation error for {addr} on profile '{}': \
                         {send_error}",
                        profile.name
                    );
                    sessions.write().await.remove(&addr);
                    return;
                }
            };
            for packet in &response_pkts {
                let _ = socket.send_to(packet, addr).await;
            }
            log::warn!(
                "UDP: client {addr} cannot use profile '{}': {error}",
                profile.name
            );
            return;
        }
    };
    let data_frag_enabled = capabilities.is_some_and(|caps| {
        caps.core_bits & crate::protocol::capabilities::client_capability::UDP_DATA_FRAG_V1 != 0
    });

    // Per-device key (same as the TCP path) — pool IPs + sessions are keyed by it
    // so multiple devices of one login coexist.
    let dkey = handler::device_key(&username, device_id);
    // Serialize the state-changing half of authentication with TCP and the other UDP
    // workers. The guard is released only after the session and kernel iroutes commit.
    let admission_guard = profile.admission.lock().await;
    // Addresses freed by an eviction, released ONLY under the same pool lock that allocates
    // ours. Releasing each one immediately — as this used to — put it on the pool's `freed`
    // stack and then dropped the lock, and `allocate` pops `freed` FIRST: a concurrent
    // handler was handed the address we had just evicted someone from, and our
    // `allocate_fixed` took it back in the pool's bookkeeping only, without killing that
    // session. Two live sessions on one tunnel IP. Same defect and same fix as the TCP path.
    // (Audit 2026-08-04.)
    let mut deferred_release: Vec<String> = Vec::new();
    let mut evicted_iroutes: Vec<String> = Vec::new();
    let mut evicted_sessions: Vec<Arc<handler::SessionShared>> = Vec::new();

    // Supersede this exact device before enforcing either limit. Its pool lease is kept
    // for the replacement, but its session and iroutes must no longer be authoritative.
    let stale_device_sessions: Vec<std::net::IpAddr> = {
        let session_map = profile.sessions.read().await;
        session_map
            .by_ip
            .iter()
            .filter(|(_, session)| session.device_key == dkey)
            .map(|(primary, _)| *primary)
            .collect()
    };
    for primary in stale_device_sessions {
        let old = {
            let mut session_map = profile.sessions.write().await;
            let old = session_map.remove(primary);
            if old.is_some() {
                evicted_iroutes.extend(session_map.take_client_routes(primary));
            }
            old
        };
        if let Some(old) = old {
            old.kick_all();
            sessions.write().await.remove(&old.peer);
            evicted_sessions.push(old);
        }
    }

    // Per-user session cap (0 = unlimited): evict this user's oldest device(s) so the
    // new one fits. A reconnecting device keeps its own IP (pool is per-device), so we
    // count only OTHER devices here; its self-supersede happens at the IP step below.
    {
        let max_sessions = {
            let db = server_state.users_db.read().await;
            db.find_user(&username)
                .map(|u| u.effective_max_sessions(&db.groups))
                .unwrap_or(0)
        };
        if max_sessions > 0 {
            loop {
                let victim = {
                    let sess_map = profile.sessions.read().await;
                    let mut others: Vec<(
                        SocketAddr,
                        std::net::IpAddr,
                        std::time::Instant,
                        String,
                    )> = sess_map
                        .by_ip
                        .iter()
                        .filter(|(_, s)| s.username == username && s.device_key != dkey)
                        .map(|(ip, s)| (s.peer, *ip, s.connected_at, s.device_key.clone()))
                        .collect();
                    if others.len() < max_sessions as usize {
                        None
                    } else {
                        others.sort_by_key(|(_, _, t, _)| *t); // oldest first
                        Some(others.swap_remove(0))
                    }
                };
                match victim {
                    Some((peer, ip, _, ev_dkey)) => {
                        let old = {
                            let mut sm = profile.sessions.write().await;
                            match sm.remove(ip) {
                                Some(old) => {
                                    // Strip the evicted session's iroutes (map only — a new
                                    // session is admitted at this IP; no kernel del to race it).
                                    evicted_iroutes.extend(sm.take_client_routes(ip));
                                    Some(old)
                                }
                                None => None,
                            }
                        };
                        sessions.write().await.remove(&peer);
                        deferred_release.push(ev_dkey.clone());
                        if let Some(old) = old {
                            old.kick_all();
                            evicted_sessions.push(old);
                        }
                        log::info!(
                            "User '{}' at session cap {} — evicting oldest device {} on profile '{}' for new device '{}'",
                            crate::util::log_identity(&username), max_sessions, ip, profile.name, crate::util::log_device_identity(&dkey)
                        );
                    }
                    None => break,
                }
            }
        }
    }

    // Static IP (variant-b): a user's fixed address always wins. Resolved from the LIVE
    // users db (a panel edit + SIGHUP applies at once). Evict its current holder (a
    // different device, or a dynamic user who took it while the owner was offline) from
    // BOTH the shared session map and the per-source-addr UDP map, then steal it below —
    // so a reconnect from a new source IP always lands on the same tunnel address.
    let fixed_addresses = {
        let db = server_state.users_db.read().await;
        handler::resolve_static_addresses(&db, pcfg, &username, negotiated_ip_mode)
    };
    let (fixed_ip, fixed_ipv6) = match fixed_addresses {
        Ok(addresses) => addresses,
        Err(error) => {
            log::error!(
                "UDP: refusing user '{}' on profile '{}': {error}",
                crate::util::log_identity(&username),
                profile.name
            );
            sessions.write().await.remove(&addr);
            return;
        }
    };
    if negotiated_ip_mode != crate::config::server::IpMode::Ipv6 {
        if let Some(ip) = fixed_ip {
            let primary = std::net::IpAddr::V4(ip);
            let holder = {
                let sess_map = profile.sessions.read().await;
                sess_map
                    .by_ip
                    .get(&primary)
                    .map(|s| (s.peer, s.device_key.clone()))
            };
            if let Some((peer, ev_dkey)) = holder {
                if ev_dkey != dkey {
                    let old = {
                        let mut sm = profile.sessions.write().await;
                        match sm.remove(primary) {
                            Some(old) => {
                                // Strip the evicted holder's iroutes (map only — a new session is
                                // admitted at this IP; no kernel del to race its re-program).
                                evicted_iroutes.extend(sm.take_client_routes(primary));
                                Some(old)
                            }
                            None => None,
                        }
                    };
                    sessions.write().await.remove(&peer);
                    deferred_release.push(ev_dkey.clone());
                    if let Some(old) = old {
                        old.kick_all();
                        evicted_sessions.push(old);
                    }
                    log::info!(
                    "Static IP {} for user '{}' — evicting current holder device '{}' on profile '{}'",
                    ip, crate::util::log_identity(&username), crate::util::log_device_identity(&ev_dkey), profile.name
                );
                }
            }
        }
    }
    if negotiated_ip_mode != crate::config::server::IpMode::Ipv4 {
        if let Some(address) = fixed_ipv6 {
            let requested = std::net::IpAddr::V6(address);
            let holder = {
                let session_map = profile.sessions.read().await;
                session_map
                    .get_by_address(requested)
                    .map(|session| (session.client_ip, session.peer, session.device_key.clone()))
            };
            if let Some((primary, peer, evicted_key)) = holder {
                if evicted_key != dkey {
                    let old = {
                        let mut session_map = profile.sessions.write().await;
                        let old = session_map.remove(primary);
                        if let Some(old) = &old {
                            evicted_iroutes.extend(session_map.take_client_routes(old.client_ip));
                        }
                        old
                    };
                    sessions.write().await.remove(&peer);
                    deferred_release.push(evicted_key.clone());
                    if let Some(old) = old {
                        old.kick_all();
                        evicted_sessions.push(old);
                    }
                    log::info!(
                        "Static IPv6 {} for user '{}' evicts holder device '{}' on profile '{}'",
                        address,
                        crate::util::log_identity(&username),
                        crate::util::log_device_identity(&evicted_key),
                        profile.name
                    );
                }
            }
        }
    }

    let max_clients = profile.config.performance.connection.max_clients as usize;
    let capacity_rejected = {
        let session_map = profile.sessions.read().await;
        session_map.by_ip.len() >= max_clients
    };
    for old in &evicted_sessions {
        crate::server::notify::fire_disconnect(&old.username, &profile.name, old.peer);
    }
    if capacity_rejected {
        {
            let mut pool = profile.pool.lock().await;
            for key in &deferred_release {
                pool.release(key);
            }
            pool.release(&dkey);
        }
        for cidr in &evicted_iroutes {
            let _ =
                handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
        }
        sessions.write().await.remove(&addr);
        drop(admission_guard);
        log::warn!(
            "UDP: profile '{}' at max_clients ({}) - rejecting {}",
            profile.name,
            max_clients,
            addr
        );
        return;
    }

    // Delete routes of evicted owners before the replacement can install the same CIDR.
    for cidr in &evicted_iroutes {
        let _ = handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
    }

    let assigned_result: Result<crate::server::pool::AssignedAddresses, String> = {
        let mut pool = profile.pool.lock().await;
        for k in &deferred_release {
            pool.release(k);
        }
        let result = pool
            .allocate_for_mode(&dkey, negotiated_ip_mode, fixed_ip, fixed_ipv6)
            .map_err(|error| {
                format!(
                    "cannot allocate {} address set for '{}' on profile '{}': {}",
                    negotiated_ip_mode,
                    crate::util::log_identity(&username),
                    profile.name,
                    error
                )
            });
        // The old UDP ownership was already evicted under the profile admission lock. If
        // allocation restored an earlier lease and then failed, no live session would own it;
        // release it before publishing the error so the pool cannot shrink on failed mode
        // upgrades (for example IPv4 -> dual while the IPv6 pool is exhausted).
        if result.is_err() {
            pool.release(&dkey);
        }
        result
    };
    let assigned = match assigned_result {
        Ok(assigned) => assigned,
        Err(error) => {
            log::warn!("UDP: {error}");
            sessions.write().await.remove(&addr);
            return;
        }
    };
    let client_ip = assigned
        .ipv4
        .map(std::net::IpAddr::V4)
        .or_else(|| assigned.ipv6.map(std::net::IpAddr::V6))
        .expect("negotiated address mode assigns at least one family");

    let session_id: u64 = rand::random();

    // Extract session data in a scoped borrow so sessions_guard is free for error handling
    let (
        auth_response,
        quic_enabled,
        connection_id,
        writer_codec,
        writer_pn,
        writer_data_frag_key,
        exit_access,
    ) = {
        let mut sessions_guard = sessions.write().await;
        let client = match sessions_guard.get_mut(&addr) {
            Some(c) => c,
            None => {
                log::warn!(
                    "UDP: session for {} vanished before auth completion on profile '{}'",
                    addr,
                    profile.name
                );
                // Release the pool IP reserved above, matching the encrypt-failure branch
                // below. Only reachable if the single-task-per-worker invariant is ever
                // broken, but an unguarded leak here would slowly exhaust the pool. (L1)
                drop(sessions_guard);
                profile.pool.lock().await.release(&dkey);
                return;
            }
        };

        let (routes_json, exit_access) = {
            let db = server_state.users_db.read().await;
            let raw_routes = handler::build_routes_json_pub(pcfg, &db, &username, assigned);
            (
                handler::routes_without_exit_defaults(&raw_routes),
                handler::exit_access_from_routes_json(&raw_routes),
            )
        };

        let qe = client.quic_enabled;
        let cid = client.connection_id;
        let wc = client.tx_codec.clone();
        let wpn = client.packet_counter.clone();
        let fragment_key = client.tx_data_frag_key;

        // Self-describing keyed OK payload, same as the TCP path (handler.rs).
        let enc_result = {
            // UDP has no head-of-line blocking, so no stream bonding: empty token,
            // single stream.
            let msg = handler::build_auth_ok_for_addresses(
                assigned,
                pcfg,
                &routes_json,
                &[0u8; crate::server::handler::JOIN_TOKEN_LEN],
                1,
                capabilities,
            );
            let mut tx = lock_or_recover(&client.tx_codec, "udp::auth_response");
            tx.encrypt_packet(msg.as_bytes(), &[])
        };

        match enc_result {
            Ok(enc) => (enc, qe, cid, wc, wpn, fragment_key, exit_access),
            Err(e) => {
                log::error!(
                    "UDP: failed to encrypt auth response for {} on profile '{}': {}",
                    addr,
                    profile.name,
                    e
                );
                sessions_guard.remove(&addr);
                drop(sessions_guard);
                profile.pool.lock().await.release(&dkey);
                return;
            }
        }
    };

    // Shared inbound counter: the UdpClient (RX path) and the SessionShared
    // (read by list-clients) point at the SAME AtomicU64, so UDP receives are
    // accounted (RECV used to be stuck at 0 — never incremented on UDP).
    let bytes_recv = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Build the AuthOK first so the same bytes can be BOTH sent and cached for
    // idempotent re-emit. Usually one datagram; more when the pushed route list puts the
    // record over the fragment budget (see `build_auth_ok_datagrams`).
    let auth_ok_len = auth_response.len();
    let response_pkts = match build_auth_ok_datagrams(&auth_response, quic_enabled, &connection_id)
    {
        Ok(p) => p,
        Err(e) => {
            log::error!(
                "Profile '{}': the AuthOK for '{}' is {} bytes and cannot be fragmented ({}). \
                 This profile pushes more than the UDP handshake can carry — reduce the pushed \
                 routes for this user/profile, or use a TCP profile.",
                profile.name,
                crate::util::log_identity(&username),
                auth_ok_len,
                e
            );
            sessions.write().await.remove(&addr);
            profile.pool.lock().await.release(&dkey);
            return;
        }
    };
    // Reserve the packet numbers the AuthOK just consumed.
    //
    // The wire convention is positional: ServerHello is 0, AuthOK is 1, and the session
    // counter therefore starts at 2. Fragmenting the AuthOK broke that arithmetic — N
    // fragments take 1..=N, so with two or more the data plane's first packet reused PN 2
    // (and beyond). Nothing rejects it today, because the QUIC wrapper is a mask rather
    // than a protocol and no client replay-filters it; but a duplicate packet number is a
    // lie about the wire, and it would fail the moment anything started checking.
    //
    // `fetch_max` rather than `store`: the counter is shared with the writer task and the
    // MTU-probe reply path, so it may only ever move FORWARD. For the single-datagram case
    // this is `max(2, 2)` — the pre-existing behaviour, byte for byte.
    writer_pn.fetch_max(
        AUTH_OK_FIRST_PN + response_pkts.len() as u32,
        std::sync::atomic::Ordering::Relaxed,
    );

    // Destination ACL (`allowed_networks`), own or inherited from the group — compiled
    // once here (before the session goes Authenticated) so the data path can check it
    // per packet with a few masks. Empty = unrestricted, the documented default.
    let dst_acl = {
        let db = server_state.users_db.read().await;
        crate::server::acl::DstAcl::compile(
            &db.find_user(&username)
                .map(|u| crate::server::acl::effective_allowed_networks(u, &db.groups))
                .unwrap_or_default(),
            &crate::util::log_identity(&username),
        )
    };
    if !dst_acl.is_unrestricted() {
        log::info!(
            "User '{}' is restricted to {} destination network(s) (allowed_networks)",
            crate::util::log_identity(&username),
            dst_acl.rule_count()
        );
    }
    // Subnets routed behind this client (iroute) are legitimate sources too.
    let src_subnets: Vec<String> = {
        let db = server_state.users_db.read().await;
        db.find_user(&username)
            .map(|u| u.client_subnets.clone())
            .unwrap_or_default()
    };

    let wire_pool = match handler::server_wire_pool(pcfg) {
        Ok(pool) => pool,
        Err(error) => {
            log::error!(
                "UDP: cannot allocate the bounded wire-record pool for '{}' on profile '{}': {}",
                crate::util::log_identity(&username),
                profile.name,
                error
            );
            sessions.write().await.remove(&addr);
            profile.pool.lock().await.release(&dkey);
            return;
        }
    };

    // Resolve the live per-user policy once and share it with both directions. The
    // control socket updates the same AtomicU32, so set-bandwidth takes effect for the
    // UDP upload pacing task and download writer without reconnecting the client.
    let (initial_bw, client_subnets) = {
        let db = server_state.users_db.read().await;
        let user = db.find_user(&username);
        (
            user.map(|entry| entry.effective_bandwidth_limit(&db.groups))
                .unwrap_or(0),
            user.map(|entry| entry.client_subnets.clone())
                .unwrap_or_default(),
        )
    };
    let bandwidth_limit_mbps = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(initial_bw));
    let rates = crate::server::handler::DirectionalRateBuckets::new();
    let revoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // UDP has one shared socket receive loop for all peers. Sleeping there would let one
    // capped client stall the entire profile, so limited uploads are handed to a bounded
    // per-client pacing task. Unlimited clients retain the direct fast path above.
    let (upload_tx, mut upload_rx) = mpsc::channel::<PooledBuffer>(UDP_UPLOAD_QUEUE_PACKETS);
    let upload_limit = bandwidth_limit_mbps.clone();
    let upload_rate = rates.upload.clone();
    let upload_bytes = bytes_recv.clone();
    let upload_tun = tun_tx.clone();
    let upload_profile = profile.clone();
    let upload_session_id = session_id;
    let upload_exit_access = exit_access;
    let upload_revoked = revoked.clone();
    tasks.spawn(async move {
        while let Some(packet) = upload_rx.recv().await {
            // Dropping the per-worker UdpClient closes the only long-lived sender.
            // A kick/quota/supersede raises `revoked` even before that map entry is
            // removed. In either case discard the queued tail instead of injecting
            // traffic after the session has lost its IP/authorization.
            if upload_rx.is_closed() || upload_revoked.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let limit = upload_limit.load(std::sync::atomic::Ordering::Relaxed);
            let delay = upload_rate.consume(packet.len() as u64 * 8, limit);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if upload_rx.is_closed() || upload_revoked.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            upload_bytes.fetch_add(packet.len() as u64, std::sync::atomic::Ordering::Relaxed);
            if upload_tun
                .send_client_packet(
                    &upload_profile,
                    upload_session_id,
                    upload_exit_access,
                    ServerTunPacket::Pooled(packet),
                )
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Update session state now that encryption succeeded
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.bytes_recv = bytes_recv.clone();
            client.dropped = dropped.clone();
            client.bandwidth_limit_mbps = Some(bandwidth_limit_mbps.clone());
            client.upload_tx = Some(upload_tx);
            client.revoked = Some(revoked.clone());
            client.state = UdpSessionState::Authenticated {
                session_id,
                device_key: dkey.clone(),
                client_ip,
            };
            client.data_frag_enabled = data_frag_enabled;
            // Cache for idempotent AuthOK re-emit: a lost AuthOK leaves the client
            // retransmitting THIS exact AUTH datagram, which the replay window would
            // drop — the existing-session re-emit branch resends `auth_ok` on a byte
            // match. Free the ServerHello cache (only needed pre-auth).
            client.auth_request = raw_request.to_vec();
            client.auth_ok = response_pkts.clone();
            client.server_hello = Vec::new();
            client.hello_frag_mode = false;
            // Destination ACL now that we know WHICH user this session belongs to;
            // the data path below checks it on every inner packet.
            client.dst_acl = dst_acl.clone();
            let assigned_sources: Vec<std::net::IpAddr> = assigned
                .ipv4
                .map(std::net::IpAddr::V4)
                .into_iter()
                .chain(assigned.ipv6.map(std::net::IpAddr::V6))
                .collect();
            client.src_guard = Some(crate::server::acl::SrcGuard::new_dual(
                &assigned_sources,
                &src_subnets,
                &crate::util::log_identity(&username),
            ));
            client.exit_access = exit_access;
            client.wire_pool = Some(wire_pool.clone());
        }
    }

    // Over the budget the AuthOK now goes out fragmented rather than as one oversized
    // datagram an LTE/CGNAT path would silently eat. Worth saying out loud even so: a client
    // built before `MSG_AUTH_OK` cannot reassemble it, and this is the size at which such a
    // client stops being able to connect over UDP at all. (Audit 2026-08-02, §4.)
    if response_pkts.len() > 1 {
        log::info!(
            "Profile '{}': the AuthOK for '{}' is {} bytes, above the {}-byte UDP handshake \
             budget, and is being sent as {} fragments. Clients older than 0.7.14 cannot \
             reassemble it — reduce the pushed routes for this user/profile, or use a TCP \
             profile, if any are still in the field.",
            profile.name,
            crate::util::log_identity(&username),
            auth_ok_len,
            crate::protocol::udp_frag::MAX_CHUNK,
            response_pkts.len()
        );
    }
    // The AuthOK is NOT sent here. It is built and cached now, and goes on the wire only
    // once `max_clients` has admitted this client — see the send below the capacity check.

    let (writer_tx, mut writer_rx) = mpsc::channel::<PooledBuffer>(wire_pool.buffer_count());
    let writer_socket = socket.clone();
    let writer_addr = addr;
    let writer_quic = quic_enabled;
    let writer_cid = connection_id;
    let writer_obfs_overhead = socket.seal_overhead();
    let writer_outer_ipv6 = addr.is_ipv6();
    let initial_udp_payload_budget =
        crate::protocol::data_frag::conservative_udp_payload_budget(writer_outer_ipv6);
    let writer_udp_payload_budget = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(
        initial_udp_payload_budget as u32,
    ));
    let fallback_record_budget = crate::protocol::data_frag::unfragmented_record_budget(
        initial_udp_payload_budget,
        writer_obfs_overhead,
        writer_quic,
    )
    .expect("conservative UDP budget always fits the data-fragment header");

    // Per-user bandwidth cap (own value, else group, else 0 = unlimited). Upload and
    // download use independent session-wide buckets, and `set-bandwidth` updates both.
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    // UDP is a single logical stream per session (no bonding).
    // Built before the struct literal: `username` is moved into it below.
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
    let session = std::sync::Arc::new(crate::server::handler::SessionShared {
        session_id,
        username,
        device_key: dkey,
        client_ip,
        client_ipv4: assigned.ipv4,
        client_ipv6: assigned.ipv6,
        peer: addr,
        token: [0u8; crate::server::handler::JOIN_TOKEN_LEN],
        max_streams: 1,
        wire_pool: wire_pool.clone(),
        streams: std::sync::Mutex::new(vec![crate::server::handler::StreamHandle {
            stream_id: session_id,
            codec: writer_codec,
            writer: writer_tx,
            kick_tx,
            // UDP has no long-lived reader task to stop: every inbound datagram is
            // re-matched against the sessions map, so removing the session already
            // cuts ingress at the next packet. The field exists for the TCP reader;
            // here it is a sink so `kick_all` stays uniform across transports.
            shutdown_tx: tokio::sync::watch::channel(false).0,
        }]),
        connected_at: std::time::Instant::now(),
        bytes_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        bytes_recv,
        dropped,
        bandwidth_limit_mbps,
        rates,
        dst_acl: dst_acl.clone(),
        src_guard,
        exit_access,
        // 0 = not reported yet; the receive loop fills it in from the client's in-tunnel
        // control frame, and the TUN forwarder reads it. (Audit 2026-07-30, #13.)
        path_mtu: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        // None = the client has not said what it is; filled in from the same control
        // frame path as the MTU report above.
        client_info: std::sync::Arc::new(std::sync::Mutex::new(None)),
        revoked,
    });
    // The writer task outlives this function and needs the rate bucket + byte
    // counter, but `session` is moved into the profile map below — clone first.
    let writer_session = session.clone();

    // Kick any previous session occupying this IP before inserting, and register this
    // client's inbound iroute subnets (#13) — the same helper as the TCP path, so a
    // UDP-profile user with client_subnets gets inbound routing too (previously a no-op).
    let server_tun = crate::server::handler::configured_tun_addresses(&profile.config);
    let (old_to_evict, replaced_iroutes, programmed_iroutes) = {
        let mut sess_map = profile.sessions.write().await;
        let primary = client_ip;
        let old = sess_map.remove(primary);
        // Enforce max_clients on UDP too — the TCP auth path does (T7), but this one never
        // did, so a UDP profile admitted clients up to the pool size and silently ignored a
        // smaller configured cap. A brand-new client (no prior session at this IP) beyond
        // the cap is refused under the same lock as the insert; a reconnect reusing its own
        // IP is not counted. The reserved pool IP is released below on rejection. (M3)
        let replaced_routes = if old.is_some() {
            sess_map.take_client_routes(primary)
        } else {
            Vec::new()
        };
        if let Some(previous) = sess_map.insert(session) {
            previous.kick_all();
        }
        let programmed = crate::server::handler::register_client_subnets(
            &mut sess_map,
            &client_subnets,
            client_ip,
            &writer_session,
            &server_tun,
            &writer_session.username,
            &profile.name,
        );
        (old, replaced_routes, programmed)
    };
    for cidr in &replaced_iroutes {
        let _ = handler::program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
    }
    if let Some(old) = old_to_evict {
        old.kick_all();
        if old.device_key != writer_session.device_key {
            profile.pool.lock().await.release(&old.device_key);
        }
        if old.peer != addr {
            sessions.write().await.remove(&old.peer);
        }
    }
    let mut installed_iroutes: Vec<String> = Vec::new();
    for cidr in &programmed_iroutes {
        if let Err(error) =
            handler::program_client_subnet_route(true, cidr, &profile.config.tun.name).await
        {
            let orphan_routes = {
                let mut session_map = profile.sessions.write().await;
                if session_map
                    .by_ip
                    .get(&client_ip)
                    .is_some_and(|current| current.session_id == writer_session.session_id)
                {
                    session_map.remove(client_ip);
                    session_map.take_client_routes(client_ip)
                } else {
                    Vec::new()
                }
            };
            for installed in installed_iroutes.iter().rev() {
                let _ = handler::program_client_subnet_route(
                    false,
                    installed,
                    &profile.config.tun.name,
                )
                .await;
            }
            profile
                .pool
                .lock()
                .await
                .release(&writer_session.device_key);
            sessions.write().await.remove(&addr);
            log::warn!(
                "UDP: refusing client {} on profile '{}' because client_subnet '{}' could not be installed: {} ({} in-memory route(s) rolled back)",
                addr,
                profile.name,
                cidr,
                error,
                orphan_routes.len()
            );
            drop(admission_guard);
            return;
        }
        installed_iroutes.push(cidr.clone());
    }
    // Publish every authenticated-session cell before AuthOK. Once AuthOK is on the wire the
    // client may immediately send its one-shot info and path reports on another worker turn;
    // linking these cells afterwards created a race where those valid control frames saw
    // `None` and were silently ignored. Admission and route programming are already complete,
    // so an early authenticated frame cannot observe a half-admitted session.
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.revoked = Some(writer_session.revoked.clone());
            client.path_mtu = Some(writer_session.path_mtu.clone());
            if data_frag_enabled {
                client.udp_payload_budget = Some(writer_udp_payload_budget.clone());
            }
            client.client_info = Some(writer_session.client_info.clone());
        }
    }

    // ADMITTED — only now does the client learn it is authenticated.
    //
    // Charge what actually goes on the wire first: this send used to be invisible to the
    // budget, so `amp_sent` described a server that had replied with the ServerHello and
    // nothing since, and every later decision was made against a history missing its largest
    // entry. (Audit 2026-08-02, §4.)
    let sent_now: u64 = response_pkts.iter().map(|d| d.len() as u64).sum();
    if let Some(client) = sessions.write().await.get_mut(&addr) {
        client.amp_sent = client.amp_sent.saturating_add(sent_now);
    }
    for pkt in &response_pkts {
        let _ = socket.send_to(pkt, addr).await;
    }
    // The AuthOK is on the wire — the beacon and cover loops may write to this session now.
    // Set AFTER the sends, not before: the whole point is that nothing precedes it, and the
    // flag exists to make that an invariant rather than a timing accident. See `auth_ok_sent`.
    if let Some(client) = sessions.write().await.get_mut(&addr) {
        client.auth_ok_sent = true;
    }

    // Do not let another transport supersede this session between the authoritative insert
    // and its first client-visible AuthOK. UDP sends are bounded to the already-built
    // fragment list, so this does not place an unbounded operation under the admission lock.
    drop(admission_guard);
    log::info!(
        "UDP client {} authenticated on profile '{}', IP: {}",
        addr,
        profile.name,
        client_ip
    );

    // Notify (opt-in, off by default): a new UDP session came up.
    crate::server::notify::fire_connect(&writer_session.username, &profile.name, addr);

    let profile_name = profile.name.clone();
    tasks.spawn(async move {
        let mut quic_record = Vec::with_capacity(
            wire_pool.buffer_capacity() + crate::protocol::quic::QUIC_SHORT_HEADER_MIN,
        );
        let mut record_id: u64 = rand::random();
        loop {
            tokio::select! {
                biased;
                _ = kick_rx.recv() => {
                    log::info!("UDP writer for {} kicked on profile '{}'", writer_addr, profile_name);
                    break;
                }
                msg = writer_rx.recv() => {
                    let data = match msg {
                        Some(d) => d,
                        None => break,
                    };
                    // Aggregate per-session DOWNLOAD throttle. The independent upload
                    // pacing task applies the same limit concurrently. Also account
                    // outbound bytes for list-clients and quota tracking.
                    let limit = writer_session
                        .bandwidth_limit_mbps
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let mut retried_at_floor = false;
                    'budget_attempt: loop {
                        let current_udp_payload_budget = writer_udp_payload_budget
                            .load(std::sync::atomic::Ordering::Relaxed) as usize;
                        let writer_record_budget =
                            crate::protocol::data_frag::unfragmented_record_budget(
                                current_udp_payload_budget,
                                writer_obfs_overhead,
                                writer_quic,
                            )
                            .unwrap_or(fallback_record_budget);
                        if data_frag_enabled && data.len() > writer_record_budget {
                            let this_record_id = record_id;
                            record_id = record_id.wrapping_add(1);
                            let fragments = match crate::protocol::data_frag::fragment_record(
                                &data,
                                &writer_data_frag_key,
                                this_record_id,
                                writer_record_budget - crate::protocol::data_frag::HEADER_LEN,
                            ) {
                                Ok(fragments) => fragments,
                                Err(error) => {
                                    log::warn!(
                                        "UDP writer for {} could not fragment a data record: {}",
                                        writer_addr,
                                        error
                                    );
                                    writer_session
                                        .dropped
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    break 'budget_attempt;
                                }
                            };
                            let wrappers = writer_obfs_overhead
                                + if writer_quic {
                                    crate::protocol::quic::QUIC_SHORT_HEADER_MIN
                                } else {
                                    0
                                };
                            let attempted_wire_len: u64 = fragments
                                .iter()
                                .map(|fragment| (fragment.len() + wrappers) as u64)
                                .sum();
                            let delay = writer_session
                                .rates
                                .download
                                .consume(attempted_wire_len * 8, limit);
                            if !delay.is_zero() {
                                tokio::time::sleep(delay).await;
                            }
                            let mut sent_wire_len = 0u64;
                            let mut send_error = None;
                            for fragment in fragments {
                                let pkt: &[u8] = if writer_quic {
                                    let pn = writer_pn
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    wrap_quic_short_into(
                                        &fragment,
                                        &writer_cid,
                                        pn,
                                        &mut quic_record,
                                    );
                                    &quic_record
                                } else {
                                    &fragment
                                };
                                match writer_socket.send_to(pkt, writer_addr).await {
                                    Ok(sent) => sent_wire_len += sent as u64,
                                    Err(error) => {
                                        send_error = Some(error);
                                        break;
                                    }
                                }
                            }
                            if sent_wire_len > 0 {
                                writer_session
                                    .bytes_sent
                                    .fetch_add(sent_wire_len, std::sync::atomic::Ordering::Relaxed);
                            }
                            if let Some(error) = send_error {
                                if is_message_too_long(&error)
                                    && !retried_at_floor
                                    && current_udp_payload_budget > initial_udp_payload_budget
                                {
                                    writer_udp_payload_budget.store(
                                        initial_udp_payload_budget as u32,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                    retried_at_floor = true;
                                    log::warn!(
                                        "UDP writer for {} hit EMSGSIZE at {} bytes; retrying the complete record at the conservative {}-byte budget",
                                        writer_addr,
                                        current_udp_payload_budget,
                                        initial_udp_payload_budget
                                    );
                                    continue 'budget_attempt;
                                }
                                writer_session
                                    .dropped
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                log::warn!(
                                    "UDP writer for {} dropped a fragmented record after send failure: {}",
                                    writer_addr,
                                    error
                                );
                            }
                            break 'budget_attempt;
                        }

                        // Build the actual wire datagram before accounting. Only a successful
                        // send is charged; a local EMSGSIZE after a path change downgrades the
                        // session and retries the SAME encrypted record through DATA_FRAG.
                        let pkt: &[u8] = if writer_quic {
                            let pn = writer_pn
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            wrap_quic_short_into(&data, &writer_cid, pn, &mut quic_record);
                            &quic_record
                        } else {
                            &data
                        };
                        let wire_len = (pkt.len() + writer_obfs_overhead) as u64;
                        let delay = writer_session.rates.download.consume(wire_len * 8, limit);
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        match writer_socket.send_to(pkt, writer_addr).await {
                            Ok(sent) => {
                                writer_session
                                    .bytes_sent
                                    .fetch_add(sent as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(error)
                                if data_frag_enabled
                                    && is_message_too_long(&error)
                                    && !retried_at_floor
                                    && current_udp_payload_budget > initial_udp_payload_budget =>
                            {
                                writer_udp_payload_budget.store(
                                    initial_udp_payload_budget as u32,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                retried_at_floor = true;
                                log::warn!(
                                    "UDP writer for {} hit EMSGSIZE at {} bytes; retrying through DATA_FRAG at the conservative {}-byte budget",
                                    writer_addr,
                                    current_udp_payload_budget,
                                    initial_udp_payload_budget
                                );
                                continue 'budget_attempt;
                            }
                            Err(error) => {
                                writer_session
                                    .dropped
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                log::warn!(
                                    "UDP writer for {} dropped a record after send failure: {}",
                                    writer_addr,
                                    error
                                );
                            }
                        }
                        break 'budget_attempt;
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_arguments)] // handshake threads server-auth policy flags
async fn handle_new_udp_client(
    profile: &Arc<ProfileRuntime>,
    initial_packet: &[u8],
    _addr: SocketAddr,
    quic_detected: bool,
    hide_identity: bool,
    bind_static: bool,
) -> anyhow::Result<(UdpClient, Vec<u8>)> {
    // Anti-amplification (QUIC RFC 9000 §8 style). This does NOT make reflection
    // impossible — our handshake response is still larger than the request (~2-3.4 KB vs
    // ~1.35 KB) — but it BOUNDS the gain: the size floor here plus the explicit 3× check
    // after the response is built keep a spoofed-source attacker from turning us into a
    // high-gain reflector (the reply stays within the QUIC-accepted 3× of bytes received).
    // Legitimate clients pad their UDP ClientHello to ≥1200B (see client/mod.rs).
    const MIN_UDP_INITIAL: usize = 1200;
    if initial_packet.len() < MIN_UDP_INITIAL {
        return Err(anyhow::anyhow!(
            "UDP initial too small ({}B < {}B) — anti-amplification guard",
            initial_packet.len(),
            MIN_UDP_INITIAL
        ));
    }

    // Build the handshake records + channel-binding transcript via the shared
    // helper (identical to the TCP path in handler.rs). The "ClientHello" is the
    // unwrapped initial datagram; the transcript order matches the client
    // (ClientHello‖ServerHello‖Cert‖Finished).
    let server_kp = Keypair::generate();
    let handler::HandshakeRecords {
        client_pub,
        server_hello,
        ccs,
        cert,
        finished,
        nst,
        transcript_hash,
        mlkem_shared,
    } = handler::build_handshake_records(initial_packet, server_kp.public())?;

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order client public key"))?;
    // UDP is always a fake-tls-family mode (plain is TCP-only), so always hybrid PQ.
    // H-1: optionally bind the keys to the server static identity (es folded in).
    let es = bind_static.then(|| profile.static_keypair.derive_shared(&client_pub).0);
    let (server_to_client_key, client_to_server_key) = match &es {
        Some(es) => derive_keys_hybrid_bound(&shared.0, &mlkem_shared, es),
        None => derive_keys_hybrid(&shared.0, &mlkem_shared),
    };

    let tx_data_frag_key = derive_data_frag_key(&server_to_client_key);
    let rx_data_frag_key = derive_data_frag_key(&client_to_server_key);

    let mut server_tx = PacketCodec::new(server_to_client_key);
    let server_rx = PacketCodec::new(client_to_server_key);

    let static_shared = profile.static_keypair.derive_shared(&client_pub);
    let auth_proof_encrypted = {
        let auth_msg = handler::build_server_auth_msg(
            &profile.static_keypair,
            &client_pub,
            &shared.0,
            &transcript_hash,
            hide_identity,
        );
        server_tx.encrypt_packet(&auth_msg, &[])?
    };

    let mut response = Vec::with_capacity(
        server_hello.len()
            + ccs.len()
            + cert.len()
            + finished.len()
            + nst.len()
            + auth_proof_encrypted.len(),
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&ccs);
    response.extend_from_slice(&cert);
    response.extend_from_slice(&finished);
    response.extend_from_slice(&nst);
    response.extend_from_slice(&auth_proof_encrypted);

    // Enforce the 3× anti-amplification bound explicitly (see MIN_UDP_INITIAL above). Today
    // the response is well under 3× a ≥1200B initial, but a future larger cert / handshake
    // extension could push it over — refuse to reply rather than become a high-gain
    // reflector for a spoofed source.
    if response.len() > 3 * initial_packet.len() {
        return Err(anyhow::anyhow!(
            "handshake response {}B exceeds 3x the {}B initial datagram — refusing to reply \
             (anti-amplification)",
            response.len(),
            initial_packet.len()
        ));
    }

    let connection_id = if quic_detected {
        generate_connection_id()
    } else {
        [0u8; 4]
    };

    // Return the RAW handshake response. The caller fragments it (LTE/CGNAT fix) and
    // QUIC-wraps each fragment with the client's `connection_id` — see
    // `send_handshake_response`.
    let now = std::time::Instant::now();
    Ok((
        UdpClient {
            rx_codec: Arc::new(std::sync::Mutex::new(server_rx)),
            tx_codec: Arc::new(std::sync::Mutex::new(server_tx)),
            rx_data_frag_key,
            tx_data_frag_key,
            data_frag_enabled: false,
            data_reassembler: crate::protocol::data_frag::DataReassembler::new(),
            state: UdpSessionState::AwaitingAuth,
            src_guard: None,
            exit_access: crate::server::ExitAccess::default(),
            revoked: None,
            path_mtu: None,
            udp_payload_budget: None,
            downlink_mtu_probe: None,
            client_info: None,
            wire_pool: None,
            // Seed the budget with the exchange that just happened, so the session starts
            // already accounted for rather than with a free allowance. Both sides are the
            // MESSAGE, not the datagrams: a fragmented ClientHello is undercounted by its
            // fragment headers (stricter) and the ServerHello by its QUIC/obfs wrappers
            // (looser). See the note on `amp_received`.
            amp_received: initial_packet.len() as u64,
            amp_sent: response.len() as u64,
            auth_ok_reemits: 0,
            auth_ok_sent: false,
            last_activity: now,
            bytes_recv: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            bandwidth_limit_mbps: None,
            upload_tx: None,
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            created_at: now,
            connection_id,
            quic_enabled: quic_detected,
            packet_counter: Arc::new(std::sync::atomic::AtomicU32::new(UDP_SESSION_FIRST_PN)),
            ephemeral_shared: shared.0,
            static_shared: static_shared.0,
            transcript_hash,
            shaper: {
                // Stealth is TCP-only: on UDP the rate-cap + cover-under-load was
                // measured to crater throughput (lock contention under load), so
                // UDP keeps Phase-1 idle cover only. (bench_stealth.py)
                let mut sh = profile.config.obfuscation.traffic_shaping.to_shaping();
                sh.stealth = false;
                crate::protocol::Shaper::new(sh, now)
            },
            next_cover_at: now,
            server_hello: Vec::new(),
            hello_frag_mode: false,
            auth_request: Vec::new(),
            auth_ok: Vec::new(), // no datagrams cached until authenticated
            dst_acl: crate::server::acl::DstAcl::compile(&[], "unauthenticated UDP session"),
        },
        response,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        build_auth_error_datagrams, build_auth_ok_datagrams, build_downlink_mtu_probe,
        max_useful_udp_payload_budget, sanitized_udp_payload_budget, udp_reap_window,
        AUTH_OK_FIRST_PN, UDP_SESSION_FIRST_PN,
    };
    use crate::protocol::udp_frag;
    use std::time::Duration;

    #[test]
    fn negotiation_error_uses_the_authenticated_record_and_quic_framing() {
        let key = [0x5au8; 32];
        let cid = [9u8, 8, 7, 6];
        for quic_enabled in [false, true] {
            let mut tx = crate::protocol::PacketCodec::new(key);
            let mut rx = crate::protocol::PacketCodec::new(key);
            let packets = build_auth_error_datagrams(
                &mut tx,
                "profile requires IPv6 capability",
                quic_enabled,
                &cid,
            )
            .expect("ERR response builds");
            assert_eq!(packets.len(), 1);
            let record = if quic_enabled {
                crate::protocol::quic::unwrap_quic(&packets[0])
                    .expect("QUIC response")
                    .payload
            } else {
                packets[0].clone()
            };
            let response = String::from_utf8(rx.decrypt_packet(&record).unwrap()).unwrap();
            assert_eq!(response, "ERR:profile requires IPv6 capability");
        }
    }

    /// A small AuthOK must go out EXACTLY as it always did.
    ///
    /// This is the whole backward-compatibility argument for adding `MSG_AUTH_OK`: clients
    /// that predate it keep working because they never see a fragment in any case that works
    /// today. If this test ever goes red, every deployed client breaks at once.
    #[test]
    fn a_small_auth_ok_is_still_one_unfragmented_datagram() {
        let record = vec![0xABu8; 400];
        let plain = build_auth_ok_datagrams(&record, false, &[0; 4]).expect("fits");
        assert_eq!(plain, vec![record.clone()], "byte-identical to the record");
        assert!(!udp_frag::is_fragment(&plain[0]), "no fragment envelope");

        // Exactly at the budget is still one datagram — the boundary the receiver's
        // MAX_CHUNK bound is written against.
        let edge = vec![0x11u8; udp_frag::MAX_CHUNK];
        assert_eq!(
            build_auth_ok_datagrams(&edge, false, &[0; 4])
                .expect("fits")
                .len(),
            1
        );

        // With QUIC masking on it is the short header, not the long one: the AuthOK is
        // post-handshake, so it must look like the data plane that follows it.
        let masked = build_auth_ok_datagrams(&record, true, &[9, 8, 7, 6]).expect("fits");
        assert_eq!(masked.len(), 1);
        assert_ne!(masked[0], record, "QUIC wrapper applied");
    }

    /// Over the budget it splits, and every piece is small enough to cross a path that
    /// drops IP fragments — the LTE/CGNAT failure this exists to remove.
    #[test]
    fn a_large_auth_ok_is_split_and_reassembles_to_the_same_record() {
        // ~40 pushed routes' worth: the size at which the single datagram was being eaten.
        let record: Vec<u8> = (0..3_000u32).map(|i| (i * 7) as u8).collect();
        let dgrams = build_auth_ok_datagrams(&record, false, &[0; 4]).expect("splits");
        assert!(
            dgrams.len() > 1,
            "must not be sent as one oversized datagram"
        );

        let mut re = udp_frag::Reassembler::new();
        let mut done = None;
        for d in &dgrams {
            assert!(
                udp_frag::is_auth_ok_fragment(d),
                "the client recognizes it by MSG_AUTH_OK, not by guessing"
            );
            assert!(
                d.len() <= udp_frag::FRAG_HDR_LEN + udp_frag::MAX_CHUNK,
                "fragment {} is over the per-datagram budget",
                d.len()
            );
            done = re.push(d).expect("well-formed fragment");
        }
        assert_eq!(
            done.expect("completes"),
            record,
            "reassembly must return the encrypted record unchanged — it is decrypted after"
        );
    }

    /// No packet number may be issued twice — not between fragments, and not between the
    /// fragments and the DATA plane that follows them.
    ///
    /// The wire numbers positionally: ServerHello 0, AuthOK 1, session from
    /// [`UDP_SESSION_FIRST_PN`]. Fragmenting the AuthOK broke that arithmetic, because N
    /// fragments consume 1..=N and the session counter still started at 2 — so with two or
    /// more fragments the first data packet reused PN 2. The earlier version of this test
    /// compared the fragments only WITH EACH OTHER and was green throughout.
    /// (Audit 2026-08-02, §8.)
    #[test]
    fn the_data_plane_never_reuses_an_authok_pn() {
        use crate::protocol::quic::unwrap_quic;
        let cid = [1u8, 2, 3, 4];

        for record_len in [400usize, 3_000, 9_000] {
            let record: Vec<u8> = (0..record_len).map(|i| (i * 7) as u8).collect();
            let dgrams = build_auth_ok_datagrams(&record, true, &cid).expect("builds");

            let pns: Vec<u32> = dgrams
                .iter()
                .map(|d| unwrap_quic(d).expect("QUIC-wrapped").packet_number)
                .collect();
            let expected: Vec<u32> = (0..dgrams.len() as u32)
                .map(|i| AUTH_OK_FIRST_PN + i)
                .collect();
            assert_eq!(
                pns, expected,
                "{record_len}B: fragments must number consecutively"
            );

            // What the auth path reserves, and the invariant that makes it correct.
            let reserved = AUTH_OK_FIRST_PN + dgrams.len() as u32;
            assert!(
                pns.iter().all(|&pn| pn < reserved),
                "{record_len}B: the reservation must clear every fragment's PN"
            );
            // The session counter only moves forward (`fetch_max`), so the first data packet
            // takes max(UDP_SESSION_FIRST_PN, reserved) — which must clear the fragments too.
            let first_data_pn = reserved.max(UDP_SESSION_FIRST_PN);
            assert!(
                !pns.contains(&first_data_pn),
                "{record_len}B: the data plane's first PN collides with a fragment"
            );
        }

        // The single-datagram case must be untouched: PN 1, session still starts at 2.
        let small = build_auth_ok_datagrams(&[0xAB; 400], true, &cid).expect("fits");
        assert_eq!(small.len(), 1);
        assert_eq!(
            unwrap_quic(&small[0]).unwrap().packet_number,
            AUTH_OK_FIRST_PN
        );
        assert_eq!(
            AUTH_OK_FIRST_PN + small.len() as u32,
            UDP_SESSION_FIRST_PN,
            "the reservation must be a no-op for an unfragmented AuthOK"
        );
    }

    /// Past `MAX_FRAGS` the receiver would reject the message, so the sender must refuse
    /// it here rather than emit something the client silently drops.
    #[test]
    fn an_unfragmentable_auth_ok_is_refused_not_emitted() {
        let huge = vec![0u8; udp_frag::MAX_FRAGS as usize * udp_frag::MAX_CHUNK + 1];
        assert!(build_auth_ok_datagrams(&huge, false, &[0; 4]).is_err());
    }

    #[test]
    fn reap_window_uses_configured_liveness_when_idle_disabled() {
        assert_eq!(
            udp_reap_window(Duration::ZERO, Some(Duration::from_secs(45))),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            udp_reap_window(Duration::ZERO, Some(Duration::from_secs(30))),
            Some(Duration::from_secs(30))
        );
        assert_eq!(udp_reap_window(Duration::ZERO, None), None);
    }

    #[test]
    fn reap_window_honors_shorter_idle_timeout() {
        // An explicit idle_timeout shorter than the liveness window wins (reap sooner).
        assert_eq!(
            udp_reap_window(Duration::from_secs(10), Some(Duration::from_secs(45))),
            Some(Duration::from_secs(10))
        );
        // A longer idle_timeout is capped by the liveness window (dead detection).
        assert_eq!(
            udp_reap_window(Duration::from_secs(600), Some(Duration::from_secs(45))),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            udp_reap_window(Duration::from_secs(600), None),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn reported_udp_budget_never_drops_below_the_family_safe_floor() {
        assert_eq!(sanitized_udp_payload_budget(1, false, 0, false), 548);
        assert_eq!(sanitized_udp_payload_budget(1, true, 0, false), 1232);
        assert_eq!(sanitized_udp_payload_budget(1500, false, 13, true), 1500);
        assert_eq!(sanitized_udp_payload_budget(1500, true, 13, true), 1500);
        assert_eq!(
            sanitized_udp_payload_budget(u16::MAX, false, 13, true),
            max_useful_udp_payload_budget(13, true),
            "an authenticated client still cannot make the server emit a useless 64K probe"
        );
    }

    #[test]
    fn reverse_probe_exactly_fills_the_reported_udp_payload_budget() {
        for (obfs, quic) in [(0usize, false), (13, false), (0, true), (13, true)] {
            let target = 1500;
            let (packet, payload_size) =
                build_downlink_mtu_probe(7, target, obfs, quic, &[1, 2, 3, 4], 9)
                    .expect("target fits");
            assert_eq!(packet.len() + obfs, target);
            assert_eq!(
                usize::from(payload_size)
                    + obfs
                    + if quic {
                        crate::protocol::quic::QUIC_SHORT_HEADER_MIN
                    } else {
                        0
                    },
                target
            );
        }
    }
}
