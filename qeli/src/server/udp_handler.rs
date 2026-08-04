use crate::config::QuicMaskingConfig;
use crate::crypto::{derive_keys_hybrid, derive_keys_hybrid_bound, Keypair};
use crate::protocol::{
    generate_connection_id, looks_like_quic_initial, unwrap_quic, wrap_quic_long, wrap_quic_short,
    Obfuscator, PacketCodec,
};
use crate::server::handler::{self, DEFAULT_HEARTBEAT_INTERVAL_MS};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, Semaphore};

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

#[allow(dead_code)] // session_id retained for symmetry with the TCP session model
enum UdpSessionState {
    AwaitingAuth,
    Authenticated {
        session_id: u64,
        username: String,
        /// Per-device pool/session key — used to release the IP on cleanup.
        device_key: String,
        client_ip: std::net::Ipv4Addr,
    },
}

struct UdpClient {
    rx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    tx_codec: Arc<std::sync::Mutex<PacketCodec>>,
    state: UdpSessionState,
    last_activity: std::time::Instant,
    /// Inbound (client->server) byte counter, shared with this client's
    /// `SessionShared` so `list-clients` RECV reflects UDP receives. Set on auth
    /// (a placeholder Arc until then) — UDP RECV used to be stuck at 0 because it
    /// was never incremented on the UDP receive path.
    bytes_recv: std::sync::Arc<std::sync::atomic::AtomicU64>,
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
    /// Shared with this client's `SessionShared.client_info` — the `(version, platform)` it
    /// reported about itself, written here by the receive loop and read by `list-clients`
    /// through the session. `None` until authenticated; `None` inside means "never said".
    client_info: Option<crate::server::handler::ClientInfoCell>,
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
    /// * `amp_received` adds `data.len()` — the raw datagram as it came off the socket, before
    ///   obfs-open and QUIC-unwrap. That is the payload the network delivered; the IP and UDP
    ///   headers around it are not included.
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
pub fn bind_reuseport(
    addr: &str,
    perf: &crate::config::UdpPerfConfig,
) -> anyhow::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sa: SocketAddr = addr.parse()?;
    let domain = if sa.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;

    // Size the buffers BEFORE bind, while nothing can arrive yet.
    //
    // Relying on `net.core.rmem_default` was the bug: the installer raises `rmem_max`, which
    // is only a CEILING for explicit requests and changes no socket by itself. A container, a
    // hand-started binary or an existing install therefore ran on the 208 KB default however
    // the installer was configured. (Audit 2026-08-02, §14.)
    //
    // Best-effort in both directions: a refusal degrades throughput, never correctness, so it
    // must not fail the bind. The kernel also silently HALVES nothing but clamps to
    // `rmem_max`, so the granted size is read back and logged — without that, a clamped buffer
    // is indistinguishable from a working one when reading a throughput report.
    if perf.recv_buffer_size > 0 {
        if let Err(e) = sock.set_recv_buffer_size(perf.recv_buffer_size as usize) {
            log::warn!("UDP {addr}: SO_RCVBUF could not be set ({e}); using the kernel default");
        }
    }
    if perf.send_buffer_size > 0 {
        if let Err(e) = sock.set_send_buffer_size(perf.send_buffer_size as usize) {
            log::warn!("UDP {addr}: SO_SNDBUF could not be set ({e}); using the kernel default");
        }
    }
    if perf.recv_buffer_size > 0 {
        // Linux reports twice what it granted (bookkeeping overhead), hence the /2 — it is
        // the number to compare against the request, not the raw readback.
        if let Ok(granted) = sock.recv_buffer_size() {
            let effective = granted / 2;
            if effective < perf.recv_buffer_size as usize {
                log::warn!(
                    "UDP {}: asked for a {} KB receive buffer, the kernel granted {} KB — \
                     raise net.core.rmem_max to lift the cap, or datagrams will be dropped \
                     under load",
                    addr,
                    perf.recv_buffer_size / 1024,
                    effective / 1024
                );
            } else {
                log::info!("UDP {}: receive buffer {} KB", addr, effective / 1024);
            }
        }
    }

    sock.bind(&sa.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

/// How long an authenticated UDP session may go with no received datagram before
/// it is reaped as dead. Mirrors the TCP RX-liveness window: 3×heartbeat, floored
/// at 30s. A shorter explicit `idle_timeout` (when set) wins; a disabled
/// `idle_timeout` (0) still gets the liveness floor so dead sessions can't leak.
fn udp_reap_window(idle_timeout: std::time::Duration, hb_interval_ms: u64) -> std::time::Duration {
    let liveness = std::cmp::max(
        std::time::Duration::from_millis(hb_interval_ms.saturating_mul(3)),
        std::time::Duration::from_secs(30),
    );
    if idle_timeout.as_secs() > 0 {
        std::cmp::min(idle_timeout, liveness)
    } else {
        liveness
    }
}

pub async fn run_udp_server(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    socket: UdpSocket,
    worker_id: usize,
    tun_tx: mpsc::Sender<Vec<u8>>,
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

    // Partial ClientHello reassembly, keyed by source address: the UDP handshake is
    // fragmented to dodge IP fragmentation on mobile / CGNAT paths (which drop IP
    // fragments). Bounded by MAX_PENDING_HANDSHAKES and aged out in the cleanup tick.
    let mut frag_pending: HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler> =
        HashMap::new();

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
                        unwrap_quic(&recv_buf[..n])
                            .ok()
                            .map(|p| crate::protocol::udp_frag::is_junk(&p.payload))
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

                let data = recv_buf[..n].to_vec();
                handle_udp_datagram(&server_state, &profile, &sessions, &mut frag_pending, &socket, addr, &data, &tun_tx, quic_config, &handshake_permits, &auth_inflight).await;
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled || shaping_on => {
                let now = std::time::Instant::now();
                // Collect packets to send before any .await so non-Send types (MutexGuard,
                // Obfuscator/ThreadRng) are guaranteed dropped before the async resume point.
                let to_send: Vec<(std::net::SocketAddr, Vec<u8>)> = if shaping_on {
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
                        let size = client.shaper.next_size(&mut rand::rng());
                        if !client.shaper.try_spend(size, now) {
                            continue;
                        }
                        let pkt = {
                            let mut obf = Obfuscator::new();
                            let padding = obf.generate_padding(size as u16, size as u16);
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::cover");
                            let c = tx.encrypt_packet(&[], &padding).ok();
                            drop(tx);
                            c.map(|c| if client.quic_enabled {
                                let pn = client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                wrap_quic_short(&c, &client.connection_id, pn)
                            } else { c })
                        };
                        if let Some(pkt) = pkt {
                            out.push((*addr, pkt));
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
                        let pkt = {
                            let mut obf = Obfuscator::new();
                            // saturating: data_size_bytes is a u16 config knob — `+ 32`
                            // would wrap in release / panic in debug at the top of range.
                            let padding = obf.generate_padding(
                                hb_config.data_size_bytes,
                                hb_config.data_size_bytes.saturating_add(32),
                            );
                            let mut tx = lock_or_recover(&client.tx_codec, "udp::heartbeat");
                            let hb = tx.encrypt_packet(&[], &padding).ok();
                            drop(tx);
                            hb.map(|hb| if client.quic_enabled {
                                let pn = client.packet_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                wrap_quic_short(&hb, &client.connection_id, pn)
                            } else { hb })
                        };
                        if let Some(pkt) = pkt {
                            out.push((*addr, pkt));
                        }
                    }
                    out
                };
                // Now we can .await freely — no non-Send types in scope
                for (addr, pkt) in to_send {
                    let _ = socket.send_to(&pkt, addr).await;
                }
            }

            _ = cleanup_tick.tick() => {
                let now = std::time::Instant::now();
                // A dead UDP client just stops sending, so its `last_activity` goes
                // stale. Reap it on an RX-liveness window (3×heartbeat, ≥30s) the same
                // way the TCP path does — an *alive* client keeps the session warm with
                // its own heartbeats. This must NOT be gated on `idle_timeout` (which is
                // 0 / disabled on most profiles), or a disconnected UDP client's session
                // would linger forever, leaking its pool IP + client slot and showing as
                // a ghost in `list-clients` that `kick` can't clear.
                let hb_interval_ms = if heartbeat_enabled { hb_config.interval_ms } else { DEFAULT_HEARTBEAT_INTERVAL_MS };
                let reap_after = udp_reap_window(idle_timeout, hb_interval_ms);
                let expired: Vec<SocketAddr> = {
                    let sessions_guard = sessions.read().await;
                    sessions_guard.iter()
                        .filter(|(_, c)| match &c.state {
                            UdpSessionState::AwaitingAuth => {
                                now.duration_since(c.created_at) > handshake_timeout
                            }
                            UdpSessionState::Authenticated { .. } => {
                                now.duration_since(c.last_activity) > reap_after
                            }
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
                    let mut to_release: Vec<(String, std::net::Ipv4Addr, u64)> = Vec::new();
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
                        // Hold the POOL lock across the liveness check AND the release, in
                        // pool->sessions order (the same order handle_new_udp_client's
                        // allocate path uses). Previously `device_still_live` was read under
                        // the sessions lock, the lock dropped, THEN the pool released — so a
                        // same-device reconnect on another worker could `pool.allocate` the
                        // IP in that gap (its allocate reuses the still-present device_key ->
                        // same IP) before inserting into by_ip; the reaper then read
                        // "not live" and freed the just-reallocated LIVE IP, handing it to
                        // the next client (two clients on one tunnel IP). Holding the pool
                        // lock makes that reconnect's allocate wait until after the release,
                        // closing the window. (M2)
                        let mut pool = profile.pool.lock().await;
                        let mut prof_sessions = profile.sessions.write().await;
                        let ip_still_ours = prof_sessions
                            .by_ip
                            .get(&client_ip)
                            .map(|s| s.session_id == session_id)
                            .unwrap_or(false);
                        let mut iroutes: Vec<String> = Vec::new();
                        if ip_still_ours {
                            if let Some(sess) = prof_sessions.by_ip.remove(&client_ip) {
                                prof_sessions.by_token.remove(&sess.token);
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
                        drop(prof_sessions);
                        // Release under the still-held pool lock, then drop it before the
                        // (lock-free) kernel-route teardown. (M2)
                        if !device_still_live {
                            pool.release(&device_key);
                        }
                        drop(pool);
                        crate::server::handler::spawn_client_route_teardown(
                            iroutes,
                            profile.config.tun.name.clone(),
                        );
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
                // Initial, matching the single-datagram path below and the client — a
                // Handshake packet has no Token Length field. (Audit 2026-07-27, E4.)
                wrap_quic_long(&frag, connection_id, i as u32, 0x00)
            } else {
                frag
            };
            let _ = socket.send_to(&pkt, addr).await;
        }
    } else {
        let pkt = if quic_enabled {
            wrap_quic_long(raw, connection_id, 0, 0x00)
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

#[allow(clippy::too_many_arguments)] // datagram dispatch threads the shared UDP state
async fn handle_udp_datagram(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, UdpClient>>>,
    frag_pending: &mut HashMap<SocketAddr, crate::protocol::udp_frag::Reassembler>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    data: &[u8],
    tun_tx: &mpsc::Sender<Vec<u8>>,
    quic_config: &QuicMaskingConfig,
    handshake_permits: &Arc<Semaphore>,
    auth_inflight: &Arc<tokio::sync::Mutex<std::collections::HashSet<SocketAddr>>>,
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
    let (payload, quic_detected, _connection_id) = if treat_as_quic {
        match unwrap_quic(data) {
            Ok(quic_pkt) => (quic_pkt.payload.clone(), true, quic_pkt.connection_id),
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
        (data.to_vec(), false, [0u8; 4])
    };

    // AWG junk decoy — carries no real data. The receive loop already drops junk from
    // a brand-new source before the rate limiter; this also catches junk that arrived
    // reordered AFTER the first ClientHello fragment (is_new_session was false then),
    // so it is never fed to the per-source reassembler.
    if crate::protocol::udp_frag::is_junk(&payload) {
        return;
    }

    // Path-MTU probe (client→server): echo a tiny ACK carrying the same id+size so the
    // client's probe ladder learns which datagram sizes traverse the path unfragmented.
    // A probe is NOT an AEAD data packet — echo and STOP before the decrypt below (its
    // oversized chunk would also be rejected by the reassembler). Only a known session
    // is echoed (gates it to an authenticated peer); the ACK is QUIC-wrapped with the
    // session's connection id + next packet number, exactly like the heartbeat reply.
    if crate::protocol::udp_frag::is_mtu_probe(&payload) {
        if let Some((id, size)) = crate::protocol::udp_frag::parse_mtu_probe(&payload) {
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
            // `data` is the raw datagram off the socket (pre obfs-open, pre QUIC-unwrap);
            // see the note on `amp_received` for what the two counters do and do not include.
            client.amp_received = client.amp_received.saturating_add(data.len() as u64);

            let reemit_hello = matches!(client.state, UdpSessionState::AwaitingAuth)
                && crate::protocol::udp_frag::is_fragment(&payload);
            let reemit_authok = matches!(client.state, UdpSessionState::Authenticated { .. })
                && !client.auth_ok.is_empty()
                && payload == client.auth_request;
            if reemit_hello || reemit_authok {
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
            let is_awaiting_auth = matches!(client.state, UdpSessionState::AwaitingAuth);
            let plaintext = {
                let mut rx = lock_or_recover(&client.rx_codec, "udp::decrypt");
                match rx.decrypt_packet(&payload) {
                    Ok(p) => p,
                    Err(e) => {
                        log::debug!(
                            "UDP decrypt error from {} on profile '{}': {}",
                            addr,
                            profile.name,
                            e
                        );
                        return;
                    }
                }
            };
            client.last_activity = std::time::Instant::now();
            // Account inbound (client->server) bytes so `list-clients` RECV is correct
            // (the UDP path never incremented this → RECV always showed 0). Captured
            // before the lock drops; counts plaintext.len() like the TCP path. For an
            // AwaitingAuth client this is a placeholder Arc that is never incremented.
            let recv_ctr = client.bytes_recv.clone();
            // Captured with the lock, like recv_ctr — the ACL is consulted below after
            // the guard is dropped. Cheap: an unrestricted ACL is an empty Vec.
            let dst_acl = client.dst_acl.clone();
            let src_guard = client.src_guard.clone();
            // Same reason as recv_ctr: taken with the lock, used after it drops.
            let path_mtu = client.path_mtu.clone();
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
                let tun_tx = tun_tx.clone();
                let quic_config = quic_config.clone();
                let auth_inflight = auth_inflight.clone();
                let raw = payload.to_vec();
                tokio::spawn(async move {
                    handle_udp_auth(
                        &server_state,
                        &profile,
                        &sessions,
                        &socket,
                        addr,
                        &plaintext,
                        &raw,
                        &tun_tx,
                        &quic_config,
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
                // NOTE (L2): the UDP client->server (upload) path is NOT rate-throttled,
                // unlike the TCP reader. This is deliberate: the download quota — the
                // billed control — is enforced download-only and the server->client writer
                // path already throttles against the per-user cap, so no quota is bypassed.
                // The advertised bandwidth cap is therefore asymmetric between transports on
                // upload only. Applying rate.consume here would mean carrying the session's
                // rate bucket onto the hot ingress path; do that only if upload shaping is
                // explicitly required and load-tested.
                recv_ctr.fetch_add(plaintext.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let _ = tun_tx.send(plaintext).await;
            }
            return;
        }
    }

    // New source address: this is the ClientHello. It arrives fragmented (LTE/CGNAT
    // fix) — reassemble it; a legacy single-datagram ClientHello (no fragment magic)
    // is accepted as-is for backward compatibility. We reply in the same shape.
    let (ch, frag_mode): (Vec<u8>, bool) = if crate::protocol::udp_frag::is_fragment(&payload) {
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
        match frag_pending.entry(addr).or_default().push(&payload) {
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
        (payload.clone(), false)
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
    _tun_tx: &mpsc::Sender<Vec<u8>>,
    _quic_config: &QuicMaskingConfig,
) {
    let pcfg = &profile.config;
    // Auth plaintext: [client_key_proof:32]([0x00][device_id:16])?[username:password]
    if plaintext.len() < 32 {
        sessions.write().await.remove(&addr);
        return;
    }
    let mut client_key_proof = [0u8; 32];
    client_key_proof.copy_from_slice(&plaintext[..32]);
    let (device_id, creds) = handler::split_device_id(&plaintext[32..]);
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
        crate::util::log_sanitize(&username),
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

    // Per-device key (same as the TCP path) — pool IPs + sessions are keyed by it
    // so multiple devices of one login coexist.
    let dkey = handler::device_key(&username, device_id);
    // Addresses freed by an eviction, released ONLY under the same pool lock that allocates
    // ours. Releasing each one immediately — as this used to — put it on the pool's `freed`
    // stack and then dropped the lock, and `allocate` pops `freed` FIRST: a concurrent
    // handler was handed the address we had just evicted someone from, and our
    // `allocate_fixed` took it back in the pool's bookkeeping only, without killing that
    // session. Two live sessions on one tunnel IP. Same defect and same fix as the TCP path.
    // (Audit 2026-08-04.)
    let mut deferred_release: Vec<String> = Vec::new();

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
                        std::net::Ipv4Addr,
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
                            match sm.by_ip.remove(&ip) {
                                Some(old) => {
                                    sm.by_token.remove(&old.token);
                                    // Strip the evicted session's iroutes (map only — a new
                                    // session is admitted at this IP; no kernel del to race it).
                                    let _ = sm.take_client_routes(ip);
                                    Some(old)
                                }
                                None => None,
                            }
                        };
                        sessions.write().await.remove(&peer);
                        deferred_release.push(ev_dkey.clone());
                        if let Some(old) = old {
                            old.kick_all();
                        }
                        log::info!(
                            "User '{}' at session cap {} — evicting oldest device {} on profile '{}' for new device '{}'",
                            username, max_sessions, ip, profile.name, dkey
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
    let fixed_ip = {
        let db = server_state.users_db.read().await;
        handler::resolve_static_ip(&db, pcfg, &username)
    };
    if let Some(ip) = fixed_ip {
        let holder = {
            let sess_map = profile.sessions.read().await;
            sess_map
                .by_ip
                .get(&ip)
                .map(|s| (s.peer, s.device_key.clone()))
        };
        if let Some((peer, ev_dkey)) = holder {
            if ev_dkey != dkey {
                let old = {
                    let mut sm = profile.sessions.write().await;
                    match sm.by_ip.remove(&ip) {
                        Some(old) => {
                            sm.by_token.remove(&old.token);
                            // Strip the evicted holder's iroutes (map only — a new session is
                            // admitted at this IP; no kernel del to race its re-program).
                            let _ = sm.take_client_routes(ip);
                            Some(old)
                        }
                        None => None,
                    }
                };
                sessions.write().await.remove(&peer);
                deferred_release.push(ev_dkey.clone());
                if let Some(old) = old {
                    old.kick_all();
                }
                log::info!(
                    "Static IP {} for user '{}' — evicting current holder device '{}' on profile '{}'",
                    ip, username, ev_dkey, profile.name
                );
            }
        }
    }

    let client_ip = {
        let mut pool = profile.pool.lock().await;
        for k in &deferred_release {
            pool.release(k);
        }
        let allocated = match fixed_ip {
            Some(want) => pool.allocate_fixed(&dkey, want).or_else(|| {
                log::warn!(
                    "UDP: static IP {} for user '{}' is outside profile '{}' pool or excluded — using a dynamic address",
                    want, username, profile.name
                );
                pool.allocate(&dkey)
            }),
            None => pool.allocate(&dkey),
        };
        match allocated {
            Some(ip) => ip,
            None => {
                log::warn!(
                    "UDP: no IP available for {} on profile '{}'",
                    username,
                    profile.name
                );
                sessions.write().await.remove(&addr);
                return;
            }
        }
    };

    let session_id: u64 = rand::random();

    // Extract session data in a scoped borrow so sessions_guard is free for error handling
    let (auth_response, quic_enabled, connection_id, writer_codec, writer_pn) = {
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

        let routes_json = {
            let db = server_state.users_db.read().await;
            handler::build_routes_json_pub(pcfg, &db, &username)
        };

        let qe = client.quic_enabled;
        let cid = client.connection_id;
        let wc = client.tx_codec.clone();
        let wpn = client.packet_counter.clone();

        // Self-describing keyed OK payload, same as the TCP path (handler.rs).
        let enc_result = {
            // UDP has no head-of-line blocking, so no stream bonding: empty token,
            // single stream.
            let msg = handler::build_auth_ok(
                &client_ip.to_string(),
                pcfg,
                &routes_json,
                &[0u8; crate::server::handler::JOIN_TOKEN_LEN],
                1,
            );
            let mut tx = lock_or_recover(&client.tx_codec, "udp::auth_response");
            tx.encrypt_packet(msg.as_bytes(), &[])
        };

        match enc_result {
            Ok(enc) => (enc, qe, cid, wc, wpn),
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
                username,
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
            &username,
        )
    };
    if !dst_acl.is_unrestricted() {
        log::info!(
            "User '{}' is restricted to {} destination network(s) (allowed_networks)",
            username,
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

    // Update session state now that encryption succeeded
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.bytes_recv = bytes_recv.clone();
            client.state = UdpSessionState::Authenticated {
                session_id,
                username: username.clone(),
                device_key: dkey.clone(),
                client_ip,
            };
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
            client.src_guard = Some(crate::server::acl::SrcGuard::new(
                client_ip,
                &src_subnets,
                &username,
            ));
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
            username,
            auth_ok_len,
            crate::protocol::udp_frag::MAX_CHUNK,
            response_pkts.len()
        );
    }
    // The AuthOK is NOT sent here. It is built and cached now, and goes on the wire only
    // once `max_clients` has admitted this client — see the send below the capacity check.

    let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(4096);
    let writer_socket = socket.clone();
    let writer_addr = addr;
    let writer_quic = quic_enabled;
    let writer_cid = connection_id;

    // Per-user bandwidth cap (own value, else group, else 0 = unlimited) — UDP
    // honoured it as 0 before, silently ignoring limits. Now the writer applies it
    // via the session's shared token bucket, and `set-bandwidth` works on UDP too.
    let (initial_bw, client_subnets) = {
        let db = server_state.users_db.read().await;
        let u = db.find_user(&username);
        let bw = u
            .map(|x| x.effective_bandwidth_limit(&db.groups))
            .unwrap_or(0);
        // #13 iroute: the subnets behind this client, registered for inbound routing below.
        let subnets = u.map(|x| x.client_subnets.clone()).unwrap_or_default();
        (bw, subnets)
    };

    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    // UDP is a single logical stream per session (no bonding).
    // Built before the struct literal: `username` is moved into it below.
    let src_guard = crate::server::acl::SrcGuard::new(client_ip, &src_subnets, &username);
    let session = std::sync::Arc::new(crate::server::handler::SessionShared {
        session_id,
        username,
        device_key: dkey,
        client_ip,
        peer: addr,
        token: [0u8; crate::server::handler::JOIN_TOKEN_LEN],
        max_streams: 1,
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
        dropped: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        bandwidth_limit_mbps: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(initial_bw)),
        rate: crate::server::handler::RateBucket::new(),
        dst_acl: dst_acl.clone(),
        src_guard,
        // 0 = not reported yet; the receive loop fills it in from the client's in-tunnel
        // control frame, and the TUN forwarder reads it. (Audit 2026-07-30, #13.)
        path_mtu: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        // None = the client has not said what it is; filled in from the same control
        // frame path as the MTU report above.
        client_info: std::sync::Arc::new(std::sync::Mutex::new(None)),
        revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });
    // The writer task outlives this function and needs the rate bucket + byte
    // counter, but `session` is moved into the profile map below — clone first.
    let writer_session = session.clone();

    // Kick any previous session occupying this IP before inserting, and register this
    // client's inbound iroute subnets (#13) — the same helper as the TCP path, so a
    // UDP-profile user with client_subnets gets inbound routing too (previously a no-op).
    let server_tun: Option<std::net::Ipv4Addr> = profile.config.tun.address.parse().ok();
    let max_clients = profile.config.performance.connection.max_clients as usize;
    let (old_to_evict, programmed_iroutes, rejected) = {
        let mut sess_map = profile.sessions.write().await;
        let old = sess_map.by_ip.remove(&client_ip);
        // Enforce max_clients on UDP too — the TCP auth path does (T7), but this one never
        // did, so a UDP profile admitted clients up to the pool size and silently ignored a
        // smaller configured cap. A brand-new client (no prior session at this IP) beyond
        // the cap is refused under the same lock as the insert; a reconnect reusing its own
        // IP is not counted. The reserved pool IP is released below on rejection. (M3)
        if old.is_none() && sess_map.by_ip.len() >= max_clients {
            (None, Vec::new(), true)
        } else {
            sess_map.by_ip.insert(client_ip, session);
            // Strip any stale iroutes for a reused IP before re-registering (avoids dups).
            let _ = sess_map.take_client_routes(client_ip);
            let programmed = crate::server::handler::register_client_subnets(
                &mut sess_map,
                &client_subnets,
                client_ip,
                &writer_session,
                server_tun,
                &writer_session.username,
                &profile.name,
            );
            (old, programmed, false)
        }
    };
    if rejected {
        profile
            .pool
            .lock()
            .await
            .release(&writer_session.device_key);
        // Drop the PER-WORKER entry too, not just the pool reservation.
        //
        // Releasing the IP while leaving the ingress entry in place meant the refused client
        // kept decrypting into the TUN — with a `src_guard` built around an address the pool
        // had just handed back and could immediately reissue to somebody else — until the
        // reaper expired it 30-45 s later. Forget the peer here so the refusal takes effect
        // on the very next datagram. (Audit 2026-07-27, A1.)
        //
        // The client never saw an AuthOK: it is sent below this point now. Previously it went
        // out several steps earlier, so a client refused by the cap had already been told it
        // was authenticated — it configured its TUN, reported "connected", and then had every
        // packet dropped by a server that had already forgotten it. A false success followed
        // by silence is far worse to diagnose than a refusal, and it drove reconnect loops.
        // (Audit 2026-08-02, §5 of the follow-up.)
        sessions.write().await.remove(&addr);
        log::warn!(
            "UDP: profile '{}' at max_clients ({}) — rejecting {}",
            profile.name,
            max_clients,
            addr
        );
        return;
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

    // Link the per-worker ingress entry to the session's revocation flag, so a later
    // kick / quota cut-off / supersede stops this client's UPLOAD as well as its
    // download. Ingress is keyed by source address here, but every control action edits
    // `profile.sessions.by_ip` — the flag is the only thing joining the two registries.
    // (Audit 2026-07-27, A2/A3.)
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.revoked = Some(writer_session.revoked.clone());
            client.path_mtu = Some(writer_session.path_mtu.clone());
            client.client_info = Some(writer_session.client_info.clone());
        }
    }
    // Program the kernel routes now the sessions lock is released.
    for cidr in &programmed_iroutes {
        crate::server::handler::program_client_subnet_route(true, cidr, &profile.config.tun.name)
            .await;
    }
    if let Some(old) = old_to_evict {
        old.kick_all();
        // The new session reuses this device's IP/key, so DON'T release the pool (that
        // would free an in-use IP for old single-key clients). Drop the OLD addr's stale
        // per-session entry so the reaper can't later evict the new session at this IP
        // (reconnect arriving from a new src addr, e.g. Wi-Fi <-> LTE).
        if old.peer != addr {
            sessions.write().await.remove(&old.peer);
        }
    }

    log::info!(
        "UDP client {} authenticated on profile '{}', IP: {}",
        addr,
        profile.name,
        client_ip
    );

    // Notify (opt-in, off by default): a new UDP session came up.
    crate::server::notify::fire_connect(&writer_session.username, &profile.name, addr);

    let profile_name = profile.name.clone();
    tokio::spawn(async move {
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
                    // Aggregate per-session throttle (same token bucket as the TCP
                    // path) — applies the per-user cap on UDP, which used to be
                    // ignored. Also account outbound bytes (previously untracked on
                    // UDP, so list-clients under-reported bytes_sent).
                    let limit = writer_session
                        .bandwidth_limit_mbps
                        .load(std::sync::atomic::Ordering::Relaxed);
                    // Build the actual wire datagram FIRST, then account and throttle on its
                    // length. `data` is the encrypted record; in QUIC mode the short-header
                    // wrapper adds bytes that genuinely go on the wire. Counting `data.len()`
                    // meant a udp+quic session under-reported bytes_sent by the header on
                    // every packet — and since the download quota is checked against this
                    // counter, that user got more than their cap. TCP already accounts the
                    // full on-wire `packet.len()`, so this also removes a UDP-vs-TCP skew.
                    let pkt = if writer_quic {
                        let pn = writer_pn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        wrap_quic_short(&data, &writer_cid, pn)
                    } else {
                        data
                    };
                    let wire_len = pkt.len() as u64;
                    let delay = writer_session.rate.consume(wire_len * 8, limit);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    writer_session
                        .bytes_sent
                        .fetch_add(wire_len, std::sync::atomic::Ordering::Relaxed);
                    let _ = writer_socket.send_to(&pkt, writer_addr).await;
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
            state: UdpSessionState::AwaitingAuth,
            src_guard: None,
            revoked: None,
            path_mtu: None,
            client_info: None,
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
            dst_acl: crate::server::acl::DstAcl::default(),
        },
        response,
    ))
}

#[cfg(test)]
mod tests {
    use super::{build_auth_ok_datagrams, udp_reap_window, AUTH_OK_FIRST_PN, UDP_SESSION_FIRST_PN};
    use crate::protocol::udp_frag;
    use std::time::Duration;

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
    fn reap_window_uses_liveness_when_idle_disabled() {
        // idle_timeout = 0 (disabled, as on prod) must NOT mean "never reap": a dead
        // UDP client is still reaped on the 3×heartbeat liveness window. This is the
        // bug that left ghost UDP sessions in list-clients forever.
        assert_eq!(
            udp_reap_window(Duration::ZERO, 15_000),
            Duration::from_secs(45)
        );
        // Liveness is floored at 30s for short heartbeat intervals.
        assert_eq!(
            udp_reap_window(Duration::ZERO, 5_000),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn reap_window_honors_shorter_idle_timeout() {
        // An explicit idle_timeout shorter than the liveness window wins (reap sooner).
        assert_eq!(
            udp_reap_window(Duration::from_secs(10), 15_000),
            Duration::from_secs(10)
        );
        // A longer idle_timeout is capped by the liveness window (dead detection).
        assert_eq!(
            udp_reap_window(Duration::from_secs(600), 15_000),
            Duration::from_secs(45)
        );
    }
}
