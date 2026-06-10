use crate::config::QuicMaskingConfig;
use crate::crypto::{derive_keys, Keypair};
use crate::protocol::{
    generate_connection_id, unwrap_quic, wrap_quic_long, wrap_quic_short, Obfuscator, PacketCodec,
};
use crate::server::handler::{self, DEFAULT_HEARTBEAT_INTERVAL_MS};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

/// Upper bound on simultaneous half-open (unauthenticated, `AwaitingAuth`) UDP
/// handshakes per worker. A connectionless listener can't trust the source
/// address, so a spoofed-source flood would otherwise add one `AwaitingAuth`
/// entry per fake IP until the handshake-timeout reaper runs (memory DoS). When
/// the cap is hit, the OLDEST pending handshake is evicted to admit a new one;
/// authenticated sessions are never affected.
const MAX_PENDING_HANDSHAKES: usize = 1024;

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

    let idle_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);
    let handshake_timeout =
        std::time::Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let quic_config = &pcfg.obfuscation.quic;

    let mut recv_buf = vec![0u8; crate::transport::udp::MAX_UDP_PACKET_SIZE];
    let mut heartbeat_tick =
        tokio::time::interval(std::time::Duration::from_millis(if heartbeat_enabled {
            hb_config.interval_ms
        } else {
            DEFAULT_HEARTBEAT_INTERVAL_MS
        }));
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                let is_new_session = !sessions.read().await.contains_key(&addr);
                if is_new_session {
                    let mut rl = profile.rate_limiter.lock().await;
                    if !rl.check_and_record(addr.ip()) {
                        continue;
                    }
                }

                let data = recv_buf[..n].to_vec();
                handle_udp_datagram(&server_state, &profile, &sessions, &socket, addr, &data, &tun_tx, quic_config).await;
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                let now = std::time::Instant::now();
                // Collect packets to send before any .await so non-Send types (MutexGuard,
                // Obfuscator/ThreadRng) are guaranteed dropped before the async resume point.
                let to_send: Vec<(std::net::SocketAddr, Vec<u8>)> = {
                    let hb_interval = std::time::Duration::from_millis(
                        if heartbeat_enabled { hb_config.interval_ms } else { DEFAULT_HEARTBEAT_INTERVAL_MS }
                    );
                    let sessions_guard = sessions.read().await;
                    let mut out = Vec::new();
                    for (addr, client) in sessions_guard.iter() {
                        if idle_timeout.as_secs() > 0 && now.duration_since(client.last_activity) > idle_timeout {
                            continue;
                        }
                        // Idle-gate: only beacon clients that have been quiet for a
                        // full interval; active flows already keep the path warm.
                        if now.duration_since(client.last_activity) < hb_interval {
                            continue;
                        }
                        let pkt = {
                            let mut obf = Obfuscator::new();
                            let padding = obf.generate_padding(
                                hb_config.data_size_bytes,
                                hb_config.data_size_bytes + 32,
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
                    let mut sessions_guard = sessions.write().await;
                    for addr in expired {
                        if let Some(client) = sessions_guard.remove(&addr) {
                            match client.state {
                                UdpSessionState::Authenticated { device_key, client_ip, .. } => {
                                    let mut pool = profile.pool.lock().await;
                                    pool.release(&device_key);
                                    profile.sessions.write().await.by_ip.remove(&client_ip);
                                }
                                UdpSessionState::AwaitingAuth => {
                                    log::debug!("UDP: evicted stale handshake from {} on profile '{}'", addr, profile.name);
                                }
                            }
                        }
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                log::info!("UDP server for profile '{}' shutdown signal received", profile.name);
                break;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)] // datagram dispatch threads the shared UDP state
async fn handle_udp_datagram(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    sessions: &Arc<RwLock<HashMap<SocketAddr, UdpClient>>>,
    socket: &Arc<crate::protocol::obfs::ObfsUdp>,
    addr: SocketAddr,
    data: &[u8],
    tun_tx: &mpsc::Sender<Vec<u8>>,
    quic_config: &QuicMaskingConfig,
) {
    let (payload, _quic_enabled, _connection_id) = if quic_config.enabled {
        if let Ok(quic_pkt) = unwrap_quic(data) {
            (quic_pkt.payload.clone(), true, quic_pkt.connection_id)
        } else if data.len() > 5 && data[0] == 0x16 {
            (data.to_vec(), false, [0u8; 4])
        } else {
            return;
        }
    } else {
        (data.to_vec(), false, [0u8; 4])
    };

    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
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
            drop(sessions_guard);

            if is_awaiting_auth {
                handle_udp_auth(
                    server_state,
                    profile,
                    sessions,
                    socket,
                    addr,
                    &plaintext,
                    tun_tx,
                    quic_config,
                )
                .await;
            } else if !plaintext.is_empty() {
                let _ = tun_tx.send(plaintext).await;
            }
            return;
        }
    }

    let hide_identity = server_state.config.auth.require_client_key_proof;
    match handle_new_udp_client(profile, &payload, addr, quic_config, hide_identity).await {
        Ok((client, response_data)) => {
            let mut sessions_guard = sessions.write().await;
            // Bound half-open handshakes (U2): under a spoofed-source flood, evict
            // the oldest still-unauthenticated entry instead of growing without
            // limit. Authenticated sessions are skipped by the filter.
            let pending = sessions_guard
                .values()
                .filter(|c| matches!(c.state, UdpSessionState::AwaitingAuth))
                .count();
            if pending >= MAX_PENDING_HANDSHAKES {
                // Bind the oldest address out of the borrow first, so the immutable
                // iterator borrow has ended before the mutable `remove` below.
                let oldest = sessions_guard
                    .iter()
                    .filter(|(_, c)| matches!(c.state, UdpSessionState::AwaitingAuth))
                    .min_by_key(|(_, c)| c.created_at)
                    .map(|(a, _)| *a);
                if let Some(stale_addr) = oldest {
                    sessions_guard.remove(&stale_addr);
                    log::debug!(
                        "UDP: pending-handshake cap on profile '{}' — evicted oldest half-open {}",
                        profile.name,
                        stale_addr
                    );
                }
            }
            sessions_guard.insert(addr, client);
            let _ = socket.send_to(&response_data, addr).await;
            log::info!(
                "UDP handshake started for {} on profile '{}'",
                addr,
                profile.name
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
                        let old = profile.sessions.write().await.by_ip.remove(&ip);
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

    let client_ip = {
        let mut pool = profile.pool.lock().await;
        match pool.allocate(&dkey) {
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

    // Update session state now that encryption succeeded
    {
        let mut sessions_guard = sessions.write().await;
        if let Some(client) = sessions_guard.get_mut(&addr) {
            client.state = UdpSessionState::Authenticated {
                session_id,
                username: username.clone(),
                device_key: dkey.clone(),
                client_ip,
            };
        }
    }

    let response_pkt = if quic_enabled {
        wrap_quic_short(&auth_response, &connection_id, 1u32)
    } else {
        auth_response
    };
    let _ = socket.send_to(&response_pkt, addr).await;

    let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(4096);
    let writer_socket = socket.clone();
    let writer_addr = addr;
    let writer_quic = quic_enabled;
    let writer_cid = connection_id;

    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    // UDP is a single logical stream per session (no bonding).
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
        }]),
        next: std::sync::atomic::AtomicUsize::new(0),
        connected_at: std::time::Instant::now(),
        bytes_sent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        bytes_recv: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        bandwidth_limit_mbps: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
    });

    // Kick any previous session occupying this IP before inserting
    let old_to_evict = {
        let mut sess_map = profile.sessions.write().await;
        let old = sess_map.by_ip.remove(&client_ip);
        sess_map.by_ip.insert(client_ip, session);
        old
    };
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

async fn handle_new_udp_client(
    profile: &Arc<ProfileRuntime>,
    initial_packet: &[u8],
    _addr: SocketAddr,
    quic_config: &QuicMaskingConfig,
    hide_identity: bool,
) -> anyhow::Result<(UdpClient, Vec<u8>)> {
    // Anti-amplification: refuse to emit our larger handshake response unless the
    // client's initial datagram is at least as big. A spoofed-source attacker
    // therefore cannot use us as a reflector/amplifier. Legitimate clients pad
    // their UDP ClientHello to ≥1200B (see client/mod.rs).
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
    } = handler::build_handshake_records(initial_packet, server_kp.public())?;

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order client public key"))?;
    let (server_to_client_key, client_to_server_key) = derive_keys(&shared.0);

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

    let connection_id = if quic_config.enabled {
        generate_connection_id()
    } else {
        [0u8; 4]
    };

    let final_response = if quic_config.enabled {
        wrap_quic_long(&response, &connection_id, 0, 0x00)
    } else {
        response
    };

    let now = std::time::Instant::now();
    Ok((
        UdpClient {
            rx_codec: Arc::new(std::sync::Mutex::new(server_rx)),
            tx_codec: Arc::new(std::sync::Mutex::new(server_tx)),
            state: UdpSessionState::AwaitingAuth,
            last_activity: now,
            created_at: now,
            connection_id,
            quic_enabled: quic_config.enabled,
            packet_counter: Arc::new(std::sync::atomic::AtomicU32::new(2)),
            ephemeral_shared: shared.0,
            static_shared: static_shared.0,
            transcript_hash,
        },
        final_response,
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
