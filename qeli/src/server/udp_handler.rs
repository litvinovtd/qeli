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
    auth_request: Vec<u8>,
    auth_ok: Vec<u8>,
    /// Compiled `allowed_networks` destination ACL for the authenticated user (own or
    /// inherited from the group). Empty = unrestricted; set at auth, checked on every
    /// inner packet before the TUN. Mirrors `SessionShared.dst_acl` on the TCP path.
    dst_acl: crate::server::acl::DstAcl,
    /// Which SOURCE addresses this session may claim. Mirrors
    /// `SessionShared.src_guard` on the TCP path.
    src_guard: Option<crate::server::acl::SrcGuard>,
}

/// Bind one `SO_REUSEPORT` UDP socket. Several of these on the same address let the
/// kernel flow-hash incoming datagrams across them, so multiple workers can decrypt
/// on separate cores. Each flow (client) sticks to one socket → one worker, so its
/// session stays on a single thread.
pub fn bind_reuseport(addr: &str) -> anyhow::Result<UdpSocket> {
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
                handle_udp_datagram(&server_state, &profile, &sessions, &mut frag_pending, &socket, addr, &data, &tun_tx, quic_config, &handshake_permits).await;
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
                        if !matches!(client.state, UdpSessionState::Authenticated { .. }) {
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
                        // is not a real session yet).
                        if !matches!(client.state, UdpSessionState::Authenticated { .. }) {
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
                        crate::server::handler::spawn_client_route_teardown(
                            iroutes,
                            profile.config.tun.name.clone(),
                        );
                        if !device_still_live {
                            profile.pool.lock().await.release(&device_key);
                        }
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
                wrap_quic_long(&frag, connection_id, i as u32, 0x02)
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
            let reemit_hello = matches!(client.state, UdpSessionState::AwaitingAuth)
                && crate::protocol::udp_frag::is_fragment(&payload);
            let reemit_authok = matches!(client.state, UdpSessionState::Authenticated { .. })
                && !client.auth_ok.is_empty()
                && payload == client.auth_request;
            if reemit_hello || reemit_authok {
                client.last_activity = std::time::Instant::now();
                let hello = client.server_hello.clone();
                let cid = client.connection_id;
                let quic = client.quic_enabled;
                let frag = client.hello_frag_mode;
                let authok = client.auth_ok.clone();
                drop(sessions_guard);
                if reemit_hello {
                    if !hello.is_empty() {
                        send_handshake_response(socket, addr, &hello, quic, &cid, frag).await;
                    }
                } else {
                    let _ = socket.send_to(&authok, addr).await;
                }
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
            drop(sessions_guard);

            if is_awaiting_auth {
                handle_udp_auth(
                    server_state,
                    profile,
                    sessions,
                    socket,
                    addr,
                    &plaintext,
                    &payload,
                    tun_tx,
                    quic_config,
                )
                .await;
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
        username,
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
                        profile.pool.lock().await.release(&ev_dkey);
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
                profile.pool.lock().await.release(&ev_dkey);
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
    // idempotent re-emit.
    let response_pkt = if quic_enabled {
        wrap_quic_short(&auth_response, &connection_id, 1u32)
    } else {
        auth_response
    };

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
            client.auth_ok = response_pkt.clone();
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

    let _ = socket.send_to(&response_pkt, addr).await;

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
    });
    // The writer task outlives this function and needs the rate bucket + byte
    // counter, but `session` is moved into the profile map below — clone first.
    let writer_session = session.clone();

    // Kick any previous session occupying this IP before inserting, and register this
    // client's inbound iroute subnets (#13) — the same helper as the TCP path, so a
    // UDP-profile user with client_subnets gets inbound routing too (previously a no-op).
    let server_tun: Option<std::net::Ipv4Addr> = profile.config.tun.address.parse().ok();
    let (old_to_evict, programmed_iroutes) = {
        let mut sess_map = profile.sessions.write().await;
        let old = sess_map.by_ip.remove(&client_ip);
        sess_map.by_ip.insert(client_ip, session);
        // Strip any stale iroutes for a reused IP before re-registering (avoids duplicates).
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
        (old, programmed)
    };
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
                    let delay = writer_session.rate.consume(data.len() as u64 * 8, limit);
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    writer_session
                        .bytes_sent
                        .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    let pkt = if writer_quic {
                        let pn = writer_pn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        wrap_quic_short(&data, &writer_cid, pn)
                    } else {
                        data
                    };
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
            last_activity: now,
            bytes_recv: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            created_at: now,
            connection_id,
            quic_enabled: quic_detected,
            packet_counter: Arc::new(std::sync::atomic::AtomicU32::new(2)),
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
            auth_ok: Vec::new(),
            dst_acl: crate::server::acl::DstAcl::default(),
        },
        response,
    ))
}

#[cfg(test)]
mod tests {
    use super::udp_reap_window;
    use std::time::Duration;

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
