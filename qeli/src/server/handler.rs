use crate::crypto::{
    build_server_auth_message, derive_keys, derive_keys_bound, derive_keys_hybrid,
    derive_keys_hybrid_bound, handshake_transcript_hash, Keypair,
};
use crate::protocol::obfs::SplitStream;
use crate::protocol::{
    read_record, read_tls_record, FakeTlsHandshake, Framing, Obfuscator, PacketCodec,
};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState};
use rand::prelude::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Default fallback heartbeat interval when none is configured.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 30_000;

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

/// (codec, writer-channel) of the stream chosen for an outgoing packet.
pub type StreamPick = (Arc<std::sync::Mutex<PacketCodec>>, mpsc::Sender<Vec<u8>>);

/// One bonded connection within a [`SessionShared`]. Each stream has its own
/// independent crypto (its connection did its own key exchange) and its own write
/// channel; outgoing packets are striped across streams round-robin.
pub struct StreamHandle {
    pub stream_id: u64,
    pub codec: Arc<std::sync::Mutex<PacketCodec>>,
    pub writer: mpsc::Sender<Vec<u8>>,
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

/// A client tunnel session, aggregating one or more bonded connections (streams)
/// behind ONE tun IP. With multipath off there is exactly one stream (identical
/// behaviour to the old single-connection model).
pub struct SessionShared {
    pub session_id: u64,
    pub username: String,
    /// Per-device key (`username:hex(device_id)` or just `username`). Sessions are
    /// superseded by this, so multiple devices of one login coexist while the same
    /// device cleanly replaces its own old session on reconnect.
    pub device_key: String,
    pub client_ip: std::net::Ipv4Addr,
    /// Source address of the PRIMARY (auth) connection — shown in list-clients.
    pub peer: SocketAddr,
    pub token: [u8; JOIN_TOKEN_LEN],
    pub max_streams: u32,
    /// Active bonded streams; outgoing traffic is flow-pinned across them
    /// (see [`SessionShared::pick_stream`]).
    pub streams: std::sync::Mutex<Vec<StreamHandle>>,
    pub connected_at: Instant,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    /// Outbound packets dropped because the client writer channel was full — i.e.
    /// rate-limit / slow-client backpressure. Surfaced in `list-clients` so the
    /// loss is observable instead of silent.
    pub dropped: Arc<AtomicU64>,
    pub bandwidth_limit_mbps: Arc<AtomicU32>,
    /// Aggregate (all-streams) bandwidth token bucket — enforces
    /// `bandwidth_limit_mbps` across the whole session, not per stream.
    pub rate: RateBucket,
    /// Compiled `allowed_networks` (user's own, else the group's) — the destination
    /// ACL applied to every inner packet before it reaches the TUN. Empty =
    /// unrestricted, which is the documented default and costs nothing per packet.
    pub dst_acl: crate::server::acl::DstAcl,
    /// Which SOURCE addresses this session may claim (own IP + its iroute
    /// subnets). Without it an authenticated client could forge any source and
    /// walk past `client_to_client = false`.
    pub src_guard: crate::server::acl::SrcGuard,
}

impl SessionShared {
    /// Pick the (codec, writer) of the bonded stream this packet's flow is pinned
    /// to (`flow_hash`). Pinning a flow to one stream keeps that inner connection's
    /// packets ordered (round-robin striping reordered them); returns `None` only
    /// if every stream has detached (session is dying).
    pub fn pick_stream(&self, flow_hash: u64) -> Option<StreamPick> {
        let streams = lock_or_recover(&self.streams, "pick_stream");
        if streams.is_empty() {
            return None;
        }
        let i = (flow_hash % streams.len() as u64) as usize;
        Some((streams[i].codec.clone(), streams[i].writer.clone()))
    }

    /// All streams' kick channels (used by control-plane kick / supersede).
    pub fn kick_all(&self) {
        let streams = lock_or_recover(&self.streams, "kick_all");
        for s in streams.iter() {
            let _ = s.kick_tx.try_send(());
            // ...and the reader, which kick_tx never reached.
            let _ = s.shutdown_tx.send(true);
        }
    }

    /// Atomically attach a stream iff the session is still under its
    /// `max_streams` cap. Returns `false` (and adds nothing) when the cap is
    /// already reached: the length check and the push share one lock, so N
    /// concurrent JOINs can never race past the limit (T8).
    fn try_add_stream(&self, h: StreamHandle) -> bool {
        let mut streams = lock_or_recover(&self.streams, "try_add_stream");
        if streams.len() >= self.max_streams as usize {
            return false;
        }
        streams.push(h);
        true
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
    },
    Join {
        token: [u8; JOIN_TOKEN_LEN],
        stream_index: u8,
    },
}

pub async fn handle_client<S>(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    mut stream: S,
    addr: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
    // Admission permit taken by the accept loop before spawning this task. Dropped as
    // soon as the client is authenticated, so the gate bounds concurrent HANDSHAKES and
    // an established session never occupies a slot. `None` for callers with no gate
    // (tests, and transports that do their own admission control). (S-01)
    mut pre_auth_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + SplitStream,
{
    let pcfg = &profile.config;
    let handshake_timeout = Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let framing = if pcfg.obfuscation.mode == "plain" {
        Framing::Raw
    } else {
        Framing::Tls
    };

    // KE + server identity proof + read the first client message (AUTH or JOIN).
    let (mut server_tx_codec, server_rx, static_shared, shared, transcript_hash, first) =
        tokio::time::timeout(
            handshake_timeout,
            qeli_handshake(&server_state, &profile, &mut stream, addr, pcfg),
        )
        .await
        .map_err(|_| anyhow::anyhow!("handshake timeout for {}", addr))?
        .map_err(|e| anyhow::anyhow!("handshake failed for {}: {}", addr, e))?;

    let max_streams = if pcfg.obfuscation.multipath.enabled {
        pcfg.obfuscation.multipath.max_streams.max(1)
    } else {
        1
    };

    let (session, _is_primary): (Arc<SessionShared>, bool) = match first {
        FirstMessage::Auth {
            proof,
            username,
            password,
            device_id,
        } => {
            log::info!(
                "AUTH attempt from {} on profile '{}': user={}",
                addr,
                pcfg.name,
                crate::util::log_sanitize(&username)
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
            let fixed_ip = {
                let db = server_state.users_db.read().await;
                resolve_static_ip(&db, pcfg, &username)
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
            let mut programmed_client_routes: Vec<String> = Vec::new();
            // Devices evicted by the per-user session cap below whose pool IP must be
            // released AFTER the sessions write lock drops (lock order: sessions → pool).
            let mut cap_evicted = Vec::new();
            {
                let mut sessions = profile.sessions.write().await;
                let stale: Vec<std::net::Ipv4Addr> = sessions
                    .by_ip
                    .iter()
                    .filter(|(_, s)| s.device_key == dkey)
                    .map(|(ip, _)| *ip)
                    .collect();
                for ip in stale {
                    if let Some(old) = sessions.by_ip.remove(&ip) {
                        sessions.by_token.remove(&old.token);
                        old.kick_all();
                        // Strip the old session's inbound iroutes from the map — a dead
                        // ClientRoute would otherwise win route_lookup or stack a duplicate
                        // on this same-device reconnect. Map only: the new session
                        // re-registers (and `ip route replace`s) below, so an `ip route del`
                        // here would race that replace and blackhole the re-added subnet.
                        let _ = sessions.take_client_routes(ip);
                        log::info!(
                            "Superseding previous session for device '{}' (was {}) on profile '{}' — reconnect from {}",
                            dkey, ip, profile.name, addr
                        );
                    }
                }
                // Static IP (variant-b): evict whoever currently holds this user's fixed
                // address — a different device of theirs, or a dynamic user who grabbed it
                // while the owner was offline — so we can steal it below. (Our own prior
                // session was already dropped by the supersede loop above.)
                if let Some(ip) = fixed_ip {
                    if let Some(old) = sessions.by_ip.remove(&ip) {
                        sessions.by_token.remove(&old.token);
                        old.kick_all();
                        // Strip the evicted holder's iroutes (map only — see the supersede
                        // note above; the admitted session re-programs the kernel).
                        let _ = sessions.take_client_routes(ip);
                        log::info!(
                            "Static IP {} for user '{}' — evicting current holder device '{}' on profile '{}'",
                            ip, username, old.device_key, profile.name
                        );
                        cap_evicted.push(old);
                    }
                }
                // This device freed its own slot above, so the remaining count is of
                // OTHER devices of this user; evict the oldest until the new one fits.
                if max_sessions > 0 {
                    loop {
                        let mut user_sessions: Vec<(std::net::Ipv4Addr, Instant)> = sessions
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
                        match sessions.by_ip.remove(&oldest_ip) {
                            Some(old) => {
                                sessions.by_token.remove(&old.token);
                                old.kick_all();
                                // Strip the evicted device's iroutes (map only).
                                let _ = sessions.take_client_routes(oldest_ip);
                                log::info!(
                                    "User '{}' at session cap {} — evicting oldest device {} on profile '{}' for new device '{}'",
                                    username, max_sessions, oldest_ip, profile.name, dkey
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
            // Return evicted devices' addresses to the pool now the write lock is gone
            // (lock order: sessions → pool), else those slots leak until a restart.
            for s in &cap_evicted {
                profile.pool.lock().await.release(&s.device_key);
                // Notify (opt-in): forcibly evicted (static-IP steal / session-cap).
                // Already out of by_ip, so the TCP teardown guard won't double-fire.
                crate::server::notify::fire_disconnect(&s.username, &profile.name, s.peer);
            }

            {
                let max_clients = pcfg.performance.connection.max_clients;
                let sessions = profile.sessions.read().await;
                if sessions.by_ip.len() >= max_clients as usize {
                    return Err(anyhow::anyhow!(
                        "max clients ({}) reached on profile '{}'",
                        max_clients,
                        profile.name
                    ));
                }
            }

            let session_id = rand::random::<u64>();
            let client_ip = {
                let mut pool = profile.pool.lock().await;
                let ip = match fixed_ip {
                    // Fixed address for this user; if it's out of the pool / excluded,
                    // allocate_fixed returns None and we fall back to a dynamic address.
                    Some(want) => pool.allocate_fixed(&dkey, want).or_else(|| {
                        log::warn!(
                            "static IP {} for user '{}' is outside profile '{}' pool or excluded — using a dynamic address",
                            want, username, profile.name
                        );
                        pool.allocate(&dkey)
                    }),
                    None => pool.allocate(&dkey),
                };
                ip.ok_or_else(|| {
                    anyhow::anyhow!(
                        "no IP available for {} on profile '{}'",
                        username,
                        profile.name
                    )
                })?
            };
            let mut token = [0u8; JOIN_TOKEN_LEN];
            rand::rng().fill_bytes(&mut token[..]);

            let (routes_json, initial_bandwidth_mbps, dst_acl, src_subnets) = {
                let users_db = server_state.users_db.read().await;
                let routes = build_routes_json_for_user(pcfg, &users_db, &username);
                let u = users_db.find_user(&username);
                let bw = u
                    .map(|u| u.effective_bandwidth_limit(&users_db.groups))
                    .unwrap_or(0);
                // Destination ACL (`allowed_networks`), own or inherited from the
                // group; compiled once here so the per-packet check is a few masks.
                let acl = crate::server::acl::DstAcl::compile(
                    &u.map(|u| crate::server::acl::effective_allowed_networks(u, &users_db.groups))
                        .unwrap_or_default(),
                    &username,
                );
                let subnets = u.map(|u| u.client_subnets.clone()).unwrap_or_default();
                (routes, bw, acl, subnets)
            };
            let src_guard = crate::server::acl::SrcGuard::new(client_ip, &src_subnets, &username);
            if !dst_acl.is_unrestricted() {
                log::info!(
                    "User '{}' is restricted to {} destination network(s) (allowed_networks)",
                    username,
                    dst_acl.rule_count()
                );
            }

            let session = Arc::new(SessionShared {
                session_id,
                username: username.clone(),
                device_key: dkey.clone(),
                client_ip,
                peer: addr,
                token,
                max_streams,
                streams: std::sync::Mutex::new(Vec::new()),
                connected_at: Instant::now(),
                bytes_sent: Arc::new(AtomicU64::new(0)),
                bytes_recv: Arc::new(AtomicU64::new(0)),
                dropped: Arc::new(AtomicU64::new(0)),
                bandwidth_limit_mbps: Arc::new(AtomicU32::new(initial_bandwidth_mbps)),
                rate: RateBucket::new(),
                dst_acl,
                src_guard,
            });
            {
                let mut sessions = profile.sessions.write().await;
                // Authoritative re-check under the SAME write lock as the insert:
                // the earlier read-lock check is only a fast-path, so without this
                // N concurrent connects could each pass it and race past
                // max_clients (T7). On rejection, release the IP we reserved.
                if sessions.by_ip.len() >= pcfg.performance.connection.max_clients as usize {
                    drop(sessions);
                    profile.pool.lock().await.release(&dkey);
                    return Err(anyhow::anyhow!(
                        "max clients ({}) reached on profile '{}'",
                        pcfg.performance.connection.max_clients,
                        profile.name
                    ));
                }
                sessions.by_ip.insert(client_ip, session.clone());
                sessions.by_token.insert(token, client_ip);
                // #13 iroute: register the subnets behind this client for INBOUND routing.
                // Refuse a default route or one covering the server's own tunnel IP (would
                // hijack the pool), and skip a subnet already claimed by a DIFFERENT client
                // (first-registered wins). Admin-configured here (per-user client_subnets),
                // so this is a footgun guard, not an untrusted-input gate.
                let server_tun: Option<std::net::Ipv4Addr> = pcfg.tun.address.parse().ok();
                programmed_client_routes.extend(register_client_subnets(
                    &mut sessions,
                    &client_subnets,
                    client_ip,
                    &session,
                    server_tun,
                    &username,
                    &profile.name,
                ));
            }
            // Program the kernel routes now that the sessions write lock is released.
            for cidr in &programmed_client_routes {
                program_client_subnet_route(true, cidr, &pcfg.tun.name).await;
            }

            // Notify (opt-in, off by default): a new session came up.
            crate::server::notify::fire_connect(&username, &profile.name, addr);

            // AUTH OK carries the join token + stream cap so the client can open
            // the remaining bonded streams.
            let auth_response = {
                let msg = build_auth_ok(
                    &client_ip.to_string(),
                    pcfg,
                    &routes_json,
                    &token,
                    max_streams,
                );
                server_tx_codec.encrypt_packet(msg.as_bytes(), &[])?
            };
            stream.write_all(&auth_response).await?;

            log::info!(
                "Client {} ({}) connected on profile '{}', IP: {}, bandwidth_limit: {} Mbps, streams<={}",
                addr, username, profile.name, client_ip, initial_bandwidth_mbps, max_streams
            );
            (session, true)
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
            if session.stream_count() >= session.max_streams as usize {
                return Err(anyhow::anyhow!(
                    "JOIN exceeds max_streams ({}) for user '{}'",
                    session.max_streams,
                    session.username
                ));
            }
            // Ack so the client confirms attachment before pumping data.
            let ack = server_tx_codec.encrypt_packet(b"JOINOK", &[])?;
            stream.write_all(&ack).await?;
            log::info!(
                "Stream #{} JOINed session for user '{}' (IP {}) on profile '{}' from {}",
                stream_index,
                session.username,
                session.client_ip,
                profile.name,
                addr
            );
            (session, false)
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
        profile, session, addr, tun_tx, read_half, write_half, server_tx, server_rx, framing,
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
) -> anyhow::Result<(
    PacketCodec,
    PacketCodec,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    FirstMessage,
)> {
    let server_kp = Keypair::generate();
    let plain = pcfg.obfuscation.mode == "plain";
    // `plain` has no TLS-shaped handshake to carry an ML-KEM share → classic X25519.
    // Every other mode runs the hybrid X25519+ML-KEM exchange (PQ tunnel).
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
        let auth_msg = build_server_auth_msg(
            &profile.static_keypair,
            &client_pub,
            &shared.0,
            &transcript_hash,
            hide_identity,
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
        first,
    ))
}

/// Classify the first client message: JOIN (magic prefix) vs AUTH (legacy
/// `[proof:32][user:pass]`). The 8-byte magic can't collide with a real auth's
/// random proof, so old single-stream clients are still parsed as AUTH.
fn parse_first_message(plaintext: &[u8]) -> anyhow::Result<FirstMessage> {
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
    let (device_id, creds) = split_device_id(&plaintext[32..]);
    let auth_str = String::from_utf8(creds.to_vec())?;
    let (user, pass) = auth_str
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid auth format"))?;
    Ok(FirstMessage::Auth {
        proof,
        username: user.to_string(),
        password: pass.to_string(),
        device_id,
    })
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

/// Run one bonded connection (stream) of a session: a reader task (decrypt →
/// TUN) and the writer/heartbeat/idle loop. Adds itself to the session on entry
/// and detaches on exit, tearing the session down when it was the last stream.
#[allow(clippy::too_many_arguments)]
async fn run_stream<R, W>(
    profile: Arc<ProfileRuntime>,
    session: Arc<SessionShared>,
    addr: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
    mut read_half: R,
    mut write_half: W,
    server_tx: Arc<std::sync::Mutex<PacketCodec>>,
    server_rx: PacketCodec,
    framing: Framing,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    let pcfg = &profile.config;
    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        DEFAULT_HEARTBEAT_INTERVAL_MS
    });
    let idle_timeout = Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let stream_id = rand::random::<u64>();
    if !session.try_add_stream(StreamHandle {
        stream_id,
        codec: server_tx.clone(),
        writer: tx,
        kick_tx,
        shutdown_tx: shutdown_tx.clone(),
    }) {
        // Lost the race against a concurrent JOIN that filled the last slot
        // (the early stream_count check is only a fast-path). Drop this stream
        // rather than exceed max_streams.
        log::warn!(
            "Stream from {} dropped: session for '{}' already at max_streams ({})",
            addr,
            session.username,
            session.max_streams
        );
        return;
    }

    let base = tokio::time::Instant::now();
    let last_act = Arc::new(AtomicU64::new(0));
    let last_rx = Arc::new(AtomicU64::new(0));
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);

    {
        let mut server_rx = server_rx;
        let tun_tx = tun_tx.clone();
        let bytes_recv = session.bytes_recv.clone();
        let session_r = session.clone();
        let last_act = last_act.clone();
        let last_rx = last_rx.clone();
        let addr_r = addr;
        let mut shutdown_rx = shutdown_rx;
        tokio::spawn(async move {
            loop {
                // Race the read against the shutdown signal: a kicked client that
                // simply stops sending would otherwise sit here forever.
                let record = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    r = read_record(&mut read_half, framing) => r,
                };
                match record {
                    Ok(record) => {
                        let now = base.elapsed().as_millis() as u64;
                        last_act.store(now, Ordering::Relaxed);
                        match server_rx.decrypt_packet(&record) {
                            Ok(plaintext) => {
                                // rx-liveness advances ONLY on a successful decrypt:
                                // undecryptable traffic must not keep a dead session
                                // (and its pool IP) alive past the rx-dead reaper.
                                last_rx.store(now, Ordering::Relaxed);
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
                                            "dropped packet from '{}' — forged source address (not {} nor a routed subnet)",
                                            session_r.username,
                                            session_r.client_ip
                                        );
                                        continue;
                                    }
                                    if !session_r.dst_acl.is_unrestricted()
                                        && !session_r.dst_acl.allows_packet(&plaintext)
                                    {
                                        log::debug!(
                                            "ACL: dropped packet from '{}' — destination not in allowed_networks",
                                            session_r.username
                                        );
                                        continue;
                                    }
                                    // Throttle client->server upload against the SAME
                                    // aggregate per-session bucket as the outbound arm
                                    // (stealth-rate is outbound-only). Apply the returned
                                    // sleep as backpressure before draining to the TUN.
                                    let limit =
                                        session_r.bandwidth_limit_mbps.load(Ordering::Relaxed);
                                    let delay =
                                        session_r.rate.consume(plaintext.len() as u64 * 8, limit);
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
                                    if tun_tx.send(plaintext).await.is_err() {
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

    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut idle_check = tokio::time::interval(Duration::from_secs(5));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let idle_ms = idle_timeout.as_millis() as u64;
    let hb_ms = heartbeat_interval.as_millis() as u64;
    let mut last_tx_ms: u64 = base.elapsed().as_millis() as u64;

    // Flow-shaping (Phase 1, DPI-AUDIT 6.1/6.2): when enabled, idle cover traffic
    // at exponential (non-periodic) gaps REPLACES the fixed heartbeat — the same
    // empty-payload encrypted record the peer drops, but no metronome beacon and
    // no dead air. Real packets are never delayed; only genuine idle is filled,
    // capped by the cover budget.
    let mut shaper = crate::protocol::Shaper::new(
        pcfg.obfuscation.traffic_shaping.to_shaping(),
        std::time::Instant::now(),
    );
    let shaping_on = shaper.enabled();
    let heartbeat_enabled = heartbeat_enabled && !shaping_on;
    // NB: never hold a `ThreadRng` (it is `!Send`) across the loop's `.await`s —
    // pass a fresh temporary at each call so the select future stays `Send`.
    let mut cover_deadline = tokio::time::Instant::now() + shaper.next_gap(&mut rand::rng());

    loop {
        tokio::select! {
            biased;

            _ = kick_rx.recv() => { break; }
            _ = dead_rx.recv() => { break; }

            Some(packet) = rx.recv() => {
                last_act.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                crate::trace::record(
                    crate::trace::Dir::Tx, "server.stream", packet.len(), stream_id,
                );
                // Aggregate per-session throttle: the shared token bucket enforces the
                // cap across ALL bonded streams, so multipath can't multiply it by N.
                // Stealth mode caps the data plane to the (lower) stealth rate so the
                // flow stops looking like a line-rate bulk download.
                let bw = session.bandwidth_limit_mbps.load(Ordering::Relaxed);
                let limit = if shaping_on && shaper.stealth() {
                    let sr = shaper.stealth_rate_mbps();
                    if bw == 0 { sr } else { bw.min(sr) }
                } else {
                    bw
                };
                let delay = session.rate.consume(packet.len() as u64 * 8, limit);
                if shaping_on && shaper.stealth() && !delay.is_zero() {
                    // STEALTH: instead of one smooth sleep (which evens the spacing
                    // into a metronome — a WORSE tell), fill the rate-cap gap with
                    // jittered small cover packets. This (a) breaks the 100% full-MTU
                    // size histogram and (b) makes the timing irregular (not a flat
                    // rate). Cover is budget-capped separately from the data rate.
                    let mut remaining = delay;
                    while remaining > Duration::from_millis(6) {
                        let csize = shaper.next_size(&mut rand::rng());
                        let cover = if shaper.try_spend(csize, std::time::Instant::now()) {
                            let mut obf = Obfuscator::new();
                            let padding = obf.generate_padding(csize as u16, csize as u16);
                            let mut codec = lock_or_recover(&server_tx, "handler::stealth_cover");
                            codec.encrypt_packet(&[], &padding).ok()
                        } else {
                            None
                        };
                        if let Some(c) = cover {
                            if write_half.write_all(&c).await.is_err() {
                                break;
                            }
                        }
                        let step = Duration::from_millis(rand::rng().random_range(4..=18));
                        let s = step.min(remaining);
                        tokio::time::sleep(s).await;
                        remaining = remaining.saturating_sub(s);
                    }
                } else if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                session.bytes_sent.fetch_add(packet.len() as u64, Ordering::Relaxed);
                last_tx_ms = base.elapsed().as_millis() as u64;
                if write_half.write_all(&packet).await.is_err() {
                    break;
                }
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                let since = base.elapsed().as_millis() as u64 - last_tx_ms;
                if since < hb_ms {
                    continue;
                }
                // The beat fires on a fixed-interval tick and this sleep is ADDED to it, so a
                // symmetric ±jitter is impossible by construction. The old shape (draw from
                // [0, 2*jitter), then saturating_sub jitter) put >50% of the mass at exactly
                // 0 — mean ≈ jitter/4, i.e. far weaker aperiodicity than intended — and
                // `jitter * 2` could overflow into an empty RNG range. Draw it directly.
                let jitter = if hb_config.jitter_ms > 0 {
                    let mut rng = rand::rng();
                    Duration::from_millis(rng.random_range(0..=hb_config.jitter_ms))
                } else {
                    Duration::ZERO
                };
                tokio::time::sleep(jitter).await;

                let heartbeat = {
                    let mut obf = Obfuscator::new();
                    let padding = obf.generate_padding(
                        hb_config.data_size_bytes,
                        hb_config.data_size_bytes.saturating_add(32),
                    );
                    let mut codec = lock_or_recover(&server_tx, "handler::heartbeat");
                    codec.encrypt_packet(&[], &padding).ok()
                };
                if let Some(hb) = heartbeat {
                    if write_half.write_all(&hb).await.is_err() {
                        break;
                    }
                }
                let now_ms = base.elapsed().as_millis() as u64;
                last_act.store(now_ms, Ordering::Relaxed);
                last_tx_ms = now_ms;
            }

            _ = tokio::time::sleep_until(cover_deadline), if shaping_on => {
                let now_ms = base.elapsed().as_millis() as u64;
                // Normally fill only GENUINE idle (save budget when traffic flows).
                // In STEALTH, run cover UNDER LOAD too: the small cover packets mix
                // into the rate-capped full-MTU stream, breaking the size+timing tell.
                if shaper.stealth() || now_ms.saturating_sub(last_tx_ms) >= 50 {
                    let size = shaper.next_size(&mut rand::rng());
                    if shaper.try_spend(size, std::time::Instant::now()) {
                        let cover = {
                            let mut obf = Obfuscator::new();
                            let padding = obf.generate_padding(size as u16, size as u16);
                            let mut codec = lock_or_recover(&server_tx, "handler::cover");
                            codec.encrypt_packet(&[], &padding).ok()
                        };
                        if let Some(pkt) = cover {
                            if write_half.write_all(&pkt).await.is_err() {
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
                let now = base.elapsed().as_millis() as u64;
                if idle_timeout.as_secs() > 0
                    && now - last_act.load(Ordering::Relaxed) > idle_ms {
                    break;
                }
                let rx_dead = hb_ms.saturating_mul(3).max(120_000);
                if now - last_rx.load(Ordering::Relaxed) > rx_dead {
                    log::info!("Stream {} ({}) reaped: no inbound for >{}s on profile '{}'",
                        addr, session.username, rx_dead / 1000, profile.name);
                    break;
                }
            }
        }
    }

    // The writer loop has ended — for ANY reason: kick, idle reap, rx-dead reap,
    // peer close. Take the reader with it. The two reapers above live in this loop,
    // so once it exits nothing else bounds the reader in time; without this a stream
    // that died on a timeout could leave a reader forwarding uploads indefinitely.
    let _ = shutdown_tx.send(true);

    // Detach this stream; tear down the session when it was the last one.
    let was_last = session.remove_stream(stream_id);
    if was_last {
        let mut sessions = profile.sessions.write().await;
        if sessions.by_ip.get(&session.client_ip).map(|s| s.session_id) == Some(session.session_id)
        {
            sessions.by_ip.remove(&session.client_ip);
            sessions.by_token.remove(&session.token);
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
                program_client_subnet_route(false, cidr, &profile.config.tun.name).await;
            }
            profile.pool.lock().await.release(&session.device_key);
            log::info!(
                "Client {} ({}) disconnected from profile '{}'",
                addr,
                session.username,
                profile.name
            );
            // Notify (opt-in) — this guarded block is the fire-once per-session TCP
            // teardown (clean close), so no double-fire across bonded streams.
            crate::server::notify::fire_disconnect(&session.username, &profile.name, addr);
        }
    }
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
    if hide_identity {
        crate::crypto::build_server_proof_only(
            static_kp,
            client_pub,
            ephemeral_shared,
            transcript_hash,
        )
        .to_vec()
    } else {
        build_server_auth_message(static_kp, client_pub, ephemeral_shared, transcript_hash)
    }
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
        argon2::Argon2::default()
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
                crate::util::log_sanitize(username)
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
                crate::util::log_sanitize(username),
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
                    crate::util::log_sanitize(username)
                );
                drop(db);
                // Spend the same Argon2 work as the wrong-password path below, so an
                // unknown username is not distinguishable from a known one by how
                // fast the server rejects it (anti-enumeration). Result discarded.
                let pw_bytes = password.as_bytes().to_vec();
                let _ = tokio::task::spawn_blocking(move || {
                    use argon2::PasswordVerifier;
                    if let Ok(ph) = argon2::PasswordHash::new(dummy_password_hash()) {
                        let _ = argon2::Argon2::default().verify_password(&pw_bytes, &ph);
                    }
                })
                .await;
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
                            "{} locked after repeated wrong VPN credentials (last user: '{}')",
                            addr.ip(),
                            username
                        ),
                    )
                    .await;
                }
                return Err(anyhow::anyhow!("user not found or disabled: {}", username));
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
            .map_err(|_| anyhow::anyhow!("invalid password for user: {}", uname))
    })
    .await?;

    if let Err(e) = auth_result {
        log::warn!(
            "AUTH FAIL {} {}: user={} — wrong password",
            proto,
            addr,
            crate::util::log_sanitize(username)
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
                    "{} locked after repeated wrong VPN credentials (last user: '{}')",
                    addr.ip(),
                    username
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
            crate::util::log_sanitize(username),
            profile.name
        );
        return Err(anyhow::anyhow!(
            "user '{}' not authorised for profile '{}'",
            username,
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
                crate::util::log_sanitize(username)
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
                crate::util::log_sanitize(username),
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
        crate::util::log_sanitize(username),
        profile.name
    );
    Ok(())
}

pub fn build_routes_json_pub(
    pcfg: &crate::config::server::ProfileConfig,
    users_db: &crate::config::users::UsersDb,
    username: &str,
) -> String {
    build_routes_json_for_user(pcfg, users_db, username)
}

/// Resolve a user's FIXED tunnel address for this profile (variant-b static IP): the
/// per-user `static_ip`, else a profile-level `pool.reservation.<user>`. Returns the
/// parsed address if configured; the pool's `allocate_fixed` then validates it against the
/// pool range/exclusions, and the caller falls back to dynamic allocation on a `None`.
/// Read from the LIVE users_db at auth time, so a panel edit + SIGHUP takes effect at once.
pub fn resolve_static_ip(
    users_db: &crate::config::users::UsersDb,
    pcfg: &crate::config::server::ProfileConfig,
    username: &str,
) -> Option<std::net::Ipv4Addr> {
    let configured = users_db
        .find_user(username)
        .and_then(|u| u.static_ip.clone())
        .filter(|s| !s.trim().is_empty())
        .or_else(|| pcfg.pool.static_reservations.get(username).cloned())?;
    match configured.trim().parse::<std::net::Ipv4Addr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
            // Previously `.ok()` swallowed this, making a malformed address
            // indistinguishable from "no static IP" — the user silently got a dynamic
            // one with NOTHING in the log. The out-of-pool case already warns in the
            // caller; this covers the typo case. (The panel now rejects it at
            // authoring time too, but a hand-edited file still reaches here.)
            log::warn!(
                "static IP {:?} for user '{}' on profile '{}' is not a valid IPv4 address — \
                 using a dynamic address",
                configured,
                crate::util::log_sanitize(username),
                profile_name_of(pcfg)
            );
            None
        }
    }
}

/// Profile name for a log line (the config carries it; kept tiny so `resolve_static_ip`
/// stays a pure lookup).
fn profile_name_of(pcfg: &crate::config::server::ProfileConfig) -> &str {
    &pcfg.name
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
) -> String {
    let obf = crate::config::PushedObf {
        padding: pcfg.obfuscation.padding.clone(),
        heartbeat: pcfg.obfuscation.heartbeat.clone(),
        traffic_normalization: pcfg.obfuscation.traffic_normalization.clone(),
        traffic_shaping: pcfg.obfuscation.traffic_shaping.clone(),
    };
    let routes: serde_json::Value =
        serde_json::from_str(routes_json).unwrap_or_else(|_| serde_json::json!([]));
    // DNS pushed to the client: an explicit `dns.push_servers` (first entry) wins and
    // works WITHOUT the in-tunnel proxy — hand clients a chosen resolver (a LAN /
    // AdGuard / NextDNS box) directly. Otherwise push the proxy's listen IP only when
    // the proxy runs (its default 10.0.0.1 resolves nowhere — pushing it would black-
    // hole client name resolution). Empty => the client keeps its own resolvers. The
    // client strict-IP-validates the pushed value before touching resolv.conf.
    let pushed_dns = if let Some(ip) = pcfg.dns.push_servers.first() {
        ip.as_str()
    } else if pcfg.dns.enabled {
        pcfg.dns.listen.as_str()
    } else {
        ""
    };
    // Push the VPN subnet prefix length so the client sets the correct on-link
    // netmask instead of assuming /24. Derived from the pool CIDR; falls back to
    // 24 if it cannot be parsed (a non-/24 pool would otherwise break client↔client
    // on-link routing). Additive: older clients ignore the field and default to 24.
    let prefix: u8 = crate::server::pool::parse_cidr(&pcfg.pool.cidr)
        .map(|(_, p)| p)
        .unwrap_or(24);
    let body = serde_json::json!({
        "client_ip": client_ip,
        "server_ip": pcfg.tun.address,
        "prefix": prefix,
        // Push the server profile's TUN MTU. A client with mtu=0 (auto — the
        // default) adopts this value; a client that set its own mtu keeps it.
        // Additive: older clients ignore the field and use their own default.
        "mtu": pcfg.tun.mtu,
        "dns": pushed_dns,
        "dns_port": pcfg.dns.port,
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
    format!("OK:{}", serde_json::to_string(&body).unwrap_or_default())
}

/// Program (add on connect / delete on disconnect) a kernel route that sends `cidr` into
/// the profile's TUN, so the server's own stack delivers packets destined for a client's
/// behind-subnet (iroute, #13) to qeli's TUN reader instead of the default route. Linux
/// only, best-effort (a failure is logged, not fatal). `replace` is idempotent on connect.
/// Best-effort teardown of a client's inbound kernel iroutes (#13) after its session
/// left the map — see [`crate::server::SessionMap::take_client_routes`]. Spawned so a
/// caller still holding the sessions write lock never blocks on `ip route del` (an `ip`
/// command must not run under the lock). No-op when the client had no iroutes.
pub(crate) fn spawn_client_route_teardown(cidrs: Vec<String>, tun: String) {
    if cidrs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for cidr in &cidrs {
            program_client_subnet_route(false, cidr, &tun).await;
        }
    });
}

/// Register a client's inbound iroute subnets (#13) into the sessions map under the write
/// lock, returning the CIDRs whose kernel `ip route` must be programmed after the lock
/// drops. Refuses a default route or one covering the server's tunnel IP, and skips a
/// subnet already claimed by a DIFFERENT client (first-registered wins). Admin-configured
/// (per-user `client_subnets`) — a footgun guard, not an untrusted-input gate. Shared by
/// the TCP (handler) and UDP (udp_handler) auth paths so both transports route to a
/// client's LAN identically.
pub(crate) fn register_client_subnets(
    sessions: &mut crate::server::SessionMap,
    client_subnets: &[String],
    client_ip: std::net::Ipv4Addr,
    session: &std::sync::Arc<SessionShared>,
    server_tun: Option<std::net::Ipv4Addr>,
    username: &str,
    profile_name: &str,
) -> Vec<String> {
    let mut programmed = Vec::new();
    for cidr in client_subnets {
        let r = match crate::server::ClientRoute::parse(cidr, client_ip, session.clone()) {
            Some(r) => r,
            None => {
                log::warn!(
                    "iroute: skipping malformed client_subnet '{cidr}' for user '{username}'"
                );
                continue;
            }
        };
        if r.prefix() == 0 || server_tun.map(|t| r.contains(t)).unwrap_or(false) {
            log::warn!(
                "iroute: refusing client_subnet '{cidr}' (user '{username}') — it would capture the default route or the tunnel gateway"
            );
            continue;
        }
        if sessions
            .client_routes
            .iter()
            .any(|e| e.cidr == r.cidr && e.client_ip != client_ip)
        {
            log::warn!(
                "iroute: '{cidr}' (user '{username}') is already claimed by another client — skipping"
            );
            continue;
        }
        log::info!("iroute: {cidr} -> client {username} ({client_ip}) on profile '{profile_name}'");
        programmed.push(r.cidr.clone());
        sessions.client_routes.push(r);
    }
    programmed
}

pub(crate) async fn program_client_subnet_route(add: bool, cidr: &str, tun: &str) {
    let action = if add { "replace" } else { "del" };
    match tokio::process::Command::new("ip")
        .args(["route", action, cidr, "dev", tun])
        .output()
        .await
    {
        Ok(o) if o.status.success() => {
            log::info!("iroute: ip route {} {} dev {}", action, cidr, tun)
        }
        Ok(o) => log::warn!(
            "iroute: `ip route {} {} dev {}` failed: {}",
            action,
            cidr,
            tun,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => log::warn!(
            "iroute: could not run `ip route {} {}`: {}",
            action,
            cidr,
            e
        ),
    }
}

fn build_routes_json_for_user(
    pcfg: &crate::config::server::ProfileConfig,
    users_db: &crate::config::users::UsersDb,
    username: &str,
) -> String {
    let user_routes = users_db
        .find_user(username)
        .filter(|u| !u.routes.is_empty())
        .map(|u| u.routes.as_slice());

    let gw_default = &pcfg.tun.address;

    // Build the JSON via serde_json so any value (cidr/gateway from config) is
    // properly escaped — a stray quote can't break the array (C-3). cidr/gateway
    // are admin-trusted config, so this is hygiene, not an injection sink. The two
    // route types (UserRoute / PushedRoute) share the cidr/gateway/metric fields.
    if let Some(routes) = user_routes {
        let arr: Vec<serde_json::Value> = routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "cidr": r.cidr,
                    "gateway": r.gateway.as_deref().unwrap_or(gw_default),
                    "metric": r.metric.unwrap_or(100),
                })
            })
            .collect();
        serde_json::Value::Array(arr).to_string()
    } else {
        let arr: Vec<serde_json::Value> = pcfg
            .routing
            .advertised_routes
            .iter()
            .map(|r| {
                serde_json::json!({
                    "cidr": r.cidr,
                    "gateway": r.gateway.as_deref().unwrap_or(gw_default),
                    "metric": r.metric.unwrap_or(100),
                })
            })
            .collect();
        serde_json::Value::Array(arr).to_string()
    }
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
    use super::RateBucket;
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
}
