use crate::crypto::{build_server_auth_message, derive_keys, handshake_transcript_hash, Keypair};
use crate::protocol::obfs::SplitStream;
use crate::protocol::{
    read_record, read_tls_record, FakeTlsHandshake, Framing, Obfuscator, PacketCodec,
};
use crate::server::{lock_or_recover, ProfileRuntime, ServerState};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Default fallback heartbeat interval when none is configured.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 30_000;
/// Upper bound for per-packet bandwidth throttling sleep. Without this a low
/// `limit_mbps` combined with a large packet could pin the writer task for
/// hundreds of ms, effectively a self-DoS.
const MAX_BANDWIDTH_DELAY_US: u64 = 100_000;

pub struct ClientSession {
    pub session_id: u64,
    pub username: String,
    pub client_ip: std::net::Ipv4Addr,
    /// Remote source address (the client's public ip:port) — shown in list-clients.
    pub peer: SocketAddr,
    pub codec: Arc<std::sync::Mutex<PacketCodec>>,
    pub writer: mpsc::Sender<Vec<u8>>,
    pub kick_tx: mpsc::Sender<()>,
    pub connected_at: Instant,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_recv: Arc<AtomicU64>,
    pub bandwidth_limit_mbps: Arc<AtomicU32>,
}

pub async fn handle_client<S>(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    mut stream: S,
    addr: SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + SplitStream,
{
    // Socket options (nodelay/keepalive) are set on the raw TcpStream by the
    // accept loop before any obfs wrapping, so this fn is transport-agnostic.
    let pcfg = &profile.config;
    let handshake_timeout = Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);

    let (server_tx_codec, server_rx, username, client_ip, session_id) = tokio::time::timeout(
        handshake_timeout,
        handshake_and_auth(&server_state, &profile, &mut stream, addr, pcfg),
    )
    .await
    .map_err(|_| anyhow::anyhow!("handshake timeout for {}", addr))?
    .map_err(|e| anyhow::anyhow!("handshake failed for {}: {}", addr, e))?;

    let server_tx = Arc::new(std::sync::Mutex::new(server_tx_codec));

    let (routes_json, initial_bandwidth_mbps) = {
        let users_db = server_state.users_db.read().await;
        let routes = build_routes_json_for_user(pcfg, &users_db, &username);
        let bw = users_db
            .find_user(&username)
            .map(|u| u.effective_bandwidth_limit(&users_db.groups))
            .unwrap_or(0);
        (routes, bw)
    };

    let auth_response = {
        let msg = build_auth_ok(&client_ip.to_string(), pcfg, &routes_json);
        let mut codec = lock_or_recover(&server_tx, "handler::auth_response");
        codec.encrypt_packet(msg.as_bytes(), &[])?
    };
    stream.write_all(&auth_response).await?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
    let (kick_tx, mut kick_rx) = mpsc::channel::<()>(1);

    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_recv = Arc::new(AtomicU64::new(0));
    let bandwidth_arc = Arc::new(AtomicU32::new(initial_bandwidth_mbps));

    let session = ClientSession {
        session_id,
        username: username.clone(),
        client_ip,
        peer: addr,
        codec: server_tx.clone(),
        writer: tx.clone(),
        kick_tx,
        connected_at: Instant::now(),
        bytes_sent: bytes_sent.clone(),
        bytes_recv: bytes_recv.clone(),
        bandwidth_limit_mbps: bandwidth_arc.clone(),
    };

    // Kick any existing session occupying this IP
    let old_to_evict = {
        let mut sessions = profile.sessions.write().await;
        let old = sessions.by_ip.remove(&client_ip);
        sessions.by_ip.insert(client_ip, session);
        old
    };
    if let Some(old) = old_to_evict {
        let _ = old.kick_tx.try_send(());
        let mut pool = profile.pool.lock().await;
        pool.release(&old.username);
    }

    log::info!(
        "Client {} ({}) connected on profile '{}', IP: {}, bandwidth_limit: {} Mbps",
        addr,
        username,
        profile.name,
        client_ip,
        initial_bandwidth_mbps
    );

    let hb_config = &pcfg.obfuscation.heartbeat;
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        DEFAULT_HEARTBEAT_INTERVAL_MS
    });
    let idle_timeout = Duration::from_secs(pcfg.performance.connection.idle_timeout_secs);

    // Split the socket so reads and writes live in independent tasks. This is
    // required for correctness, not just throughput: `read_tls_record` is NOT
    // cancellation-safe (a partially-read record header is lost if its future is
    // dropped). Used directly as a `tokio::select!` precondition it desynced the
    // record framing under bidirectional load (→ PacketTooLarge). A dedicated
    // reader task does sequential awaits that are never cancelled.
    let (mut read_half, mut write_half) = stream.split_io();
    // `plain` mode reads bare length-prefixed records; all others read TLS-dressed
    // records. (Matches the session codecs built in handshake_and_auth.)
    let framing = if pcfg.obfuscation.mode == "plain" {
        Framing::Raw
    } else {
        Framing::Tls
    };
    let base = tokio::time::Instant::now();
    let last_act = Arc::new(AtomicU64::new(0));
    // Inbound-only timestamp (NOT bumped by our own beacons) for server-side
    // RX-liveness reaping of half-open / vanished clients.
    let last_rx = Arc::new(AtomicU64::new(0));
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);

    {
        let mut server_rx = server_rx;
        let tun_tx = tun_tx.clone();
        let bytes_recv = bytes_recv.clone();
        let last_act = last_act.clone();
        let last_rx = last_rx.clone();
        let addr_r = addr;
        tokio::spawn(async move {
            loop {
                match read_record(&mut read_half, framing).await {
                    Ok(record) => {
                        let now = base.elapsed().as_millis() as u64;
                        last_act.store(now, Ordering::Relaxed);
                        last_rx.store(now, Ordering::Relaxed);
                        match server_rx.decrypt_packet(&record) {
                            Ok(plaintext) => {
                                if !plaintext.is_empty() {
                                    bytes_recv.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                                    if tun_tx.send(plaintext).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(e) => log::debug!("Decrypt error from {}: {}", addr_r, e),
                        }
                    }
                    Err(e) => {
                        log::debug!("Client {} read closed: {:?}", addr_r, e);
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
    // Gate the server beacon on how long since WE last *sent* to the client, not
    // on `last_act` (which also counts inbound traffic). Otherwise a client that
    // sends its own keepalives keeps `last_act` fresh, the server never beacons,
    // and a client relying on receiving periodic data (RX-liveness) times out and
    // disconnects on an otherwise healthy idle tunnel. Initialise to "now": the
    // auth response was just sent.
    let mut last_tx_ms: u64 = base.elapsed().as_millis() as u64;

    loop {
        tokio::select! {
            biased;

            _ = kick_rx.recv() => {
                log::info!("Client {} ({}) kicked on profile '{}'", addr, username, profile.name);
                break;
            }

            _ = dead_rx.recv() => {
                // Reader task ended → connection closed by peer or read error.
                break;
            }

            Some(packet) = rx.recv() => {
                last_act.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                let limit = bandwidth_arc.load(Ordering::Relaxed);
                if limit > 0 {
                    let delay_us = ((packet.len() as u64 * 8) / limit as u64)
                        .min(MAX_BANDWIDTH_DELAY_US);
                    if delay_us > 0 {
                        tokio::time::sleep(Duration::from_micros(delay_us)).await;
                    }
                }
                bytes_sent.fetch_add(packet.len() as u64, Ordering::Relaxed);
                last_tx_ms = base.elapsed().as_millis() as u64;
                if write_half.write_all(&packet).await.is_err() {
                    break;
                }
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                // Beacon when WE have been silent for a full interval (TX-idle),
                // regardless of inbound traffic, so a client's RX-liveness check
                // always sees server data on a healthy idle tunnel.
                let since = base.elapsed().as_millis() as u64 - last_tx_ms;
                if since < hb_ms {
                    continue;
                }
                let jitter = if hb_config.jitter_ms > 0 {
                    let mut rng = rand::thread_rng();
                    let j: u64 = rng.gen_range(0..(hb_config.jitter_ms * 2));
                    Duration::from_millis(j.saturating_sub(hb_config.jitter_ms))
                } else {
                    Duration::ZERO
                };
                tokio::time::sleep(jitter).await;

                let heartbeat = {
                    let mut obf = Obfuscator::new();
                    let padding = obf.generate_padding(
                        hb_config.data_size_bytes,
                        hb_config.data_size_bytes + 32,
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

            _ = idle_check.tick() => {
                let now = base.elapsed().as_millis() as u64;
                if idle_timeout.as_secs() > 0
                    && now - last_act.load(Ordering::Relaxed) > idle_ms {
                    log::debug!("Client {} idle timeout reached on profile '{}'", addr, profile.name);
                    break;
                }
                // RX-liveness reaping (runs ALWAYS, not only when the server itself
                // beacons): any live client sends a heartbeat every interval, so no
                // inbound for several intervals means it's gone (vanished / half-open
                // TCP with no FIN — e.g. the phone's app process was killed). Reap to
                // free the IP/slot even when idle_timeout=0 AND the server heartbeat
                // is off — otherwise such sessions linger for hours (as seen in
                // list-clients) and only the same user reconnecting could evict them.
                let rx_dead = hb_ms.saturating_mul(3).max(120_000);
                if now - last_rx.load(Ordering::Relaxed) > rx_dead {
                    log::info!("Client {} ({}) reaped: no inbound for >{}s on profile '{}'",
                        addr, username, rx_dead / 1000, profile.name);
                    break;
                }
            }
        }
    }

    // Only remove our session entry
    let is_owner = {
        let mut sessions = profile.sessions.write().await;
        if sessions.by_ip.get(&client_ip).map(|s| s.session_id) == Some(session_id) {
            sessions.by_ip.remove(&client_ip);
            true
        } else {
            false
        }
    };
    if is_owner {
        let mut pool = profile.pool.lock().await;
        pool.release(&username);
    }

    log::info!(
        "Client {} ({}) disconnected from profile '{}'",
        addr,
        username,
        profile.name
    );
    Ok(())
}

async fn handshake_and_auth<S: AsyncRead + AsyncWrite + Unpin>(
    server_state: &Arc<ServerState>,
    profile: &Arc<ProfileRuntime>,
    stream: &mut S,
    addr: SocketAddr,
    pcfg: &crate::config::server::ProfileConfig,
) -> anyhow::Result<(PacketCodec, PacketCodec, String, std::net::Ipv4Addr, u64)> {
    let server_kp = Keypair::generate();
    // `plain` wire mode skips all TLS mimicry: a raw 32-byte key exchange and
    // bare length-prefixed records. Every other mode uses the fake-TLS handshake.
    let plain = pcfg.obfuscation.mode == "plain";
    let (client_pub, transcript_hash) = if plain {
        raw_server_handshake(stream, &server_kp).await?
    } else {
        server_handshake(stream, &server_kp, pcfg).await?
    };

    let shared = server_kp
        .derive_shared_checked(&client_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order client public key"))?;
    let (server_to_client, client_to_server) = derive_keys(&shared.0);
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
        // Build the server proof (identity-hiding under require_client_key_proof,
        // TOFU static_pub||proof otherwise) via the shared transport-agnostic helper.
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

    // Inner timeout for the auth phase specifically. The outer wrapper around
    // handshake_and_auth covers this too, but a dedicated budget gives a clear
    // error and protects future call sites that may not wrap the whole flow.
    let auth_timeout = Duration::from_secs(pcfg.performance.connection.handshake_timeout_secs);
    let framing = if plain { Framing::Raw } else { Framing::Tls };
    let (client_key_proof, username, password) =
        tokio::time::timeout(auth_timeout, receive_auth(stream, &mut server_rx, framing))
            .await
            .map_err(|_| anyhow::anyhow!("auth phase timeout for {}", addr))??;
    log::info!("AUTH attempt from {}: user={}", addr, username);

    // All transport-agnostic checks (server-key pinning, brute-force lockout,
    // user lookup, Argon2 password verify, per-profile authorisation) live in
    // the shared helper so TCP and UDP enforce identical policy.
    verify_client_auth(
        server_state,
        profile,
        addr,
        "TCP",
        &client_key_proof,
        &username,
        &password,
        &static_shared.0,
        &shared.0,
        &transcript_hash,
    )
    .await?;

    // Supersede any prior session(s) for this user. Tunnel IPs are sticky per
    // user (see pool::allocate), so a client reconnecting from a NEW source IP
    // (cell handover, Wi-Fi↔LTE) reuses its tunnel IP — but its previous, now
    // dead session still occupies the slot until idle timeout. Without evicting
    // it here, the max-sessions check below would reject the reconnect. Newest
    // connection wins. (The old session's data task exits on the kick signal;
    // its cleanup is session_id-guarded so it won't touch the new session.)
    {
        let mut sessions = profile.sessions.write().await;
        let stale: Vec<std::net::Ipv4Addr> = sessions
            .by_ip
            .iter()
            .filter(|(_, s)| s.username == username)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in stale {
            if let Some(old) = sessions.by_ip.remove(&ip) {
                let _ = old.kick_tx.try_send(());
                log::info!(
                    "Superseding previous session for user '{}' (was {}) on profile '{}' — reconnect from {}",
                    username, ip, profile.name, addr
                );
            }
        }
    }

    let max_clients = pcfg.performance.connection.max_clients;
    let sessions = profile.sessions.read().await;
    if sessions.by_ip.len() >= max_clients as usize {
        return Err(anyhow::anyhow!(
            "max clients ({}) reached on profile '{}'",
            max_clients,
            profile.name
        ));
    }
    drop(sessions);

    let session_id = rand::random::<u64>();

    let client_ip = {
        let mut pool = profile.pool.lock().await;
        pool.allocate(&username).ok_or_else(|| {
            anyhow::anyhow!(
                "no IP available for {} on profile '{}'",
                username,
                profile.name
            )
        })?
    };

    Ok((server_tx, server_rx, username, client_ip, session_id))
}

async fn server_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    server_kp: &Keypair,
    pcfg: &crate::config::server::ProfileConfig,
) -> anyhow::Result<(crate::crypto::PublicKey, [u8; 32])> {
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
    } = build_handshake_records(&record, server_kp.public())?;

    if pcfg.obfuscation.fragmentation.enabled {
        let sh_split = 1 + (server_hello.len() - 1) % 4;
        stream.write_all(&server_hello[..sh_split]).await?;
        stream.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        stream.write_all(&server_hello[sh_split..]).await?;
        stream.flush().await?;

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

    Ok((client_pub, transcript_hash))
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
    let server_hello = FakeTlsHandshake::build_server_hello(server_pub);
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
                username
            );
            server_state
                .failed_auth
                .lock()
                .await
                .record_failure(username, addr.ip());
            return Err(anyhow::anyhow!(
                "client must pin server key (require_client_key_proof)"
            ));
        }
    }

    // Brute-force lockout (per user+IP).
    {
        let tracker = server_state.failed_auth.lock().await;
        if let Err(msg) = tracker.check(username, addr.ip()) {
            log::warn!(
                "AUTH BLOCKED {} {}: user={} — {}",
                proto,
                addr,
                username,
                msg
            );
            return Err(anyhow::anyhow!("authentication blocked: {}", msg));
        }
    }

    let (password_hash, allowed_here) = {
        let db = server_state.users_db.read().await;
        match db.find_user(username) {
            Some(user) => (
                user.password_hash.clone(),
                user.allowed_on_profile(&profile.name),
            ),
            None => {
                log::warn!(
                    "AUTH FAIL {} {}: user={} — not found or disabled",
                    proto,
                    addr,
                    username
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
                server_state
                    .failed_auth
                    .lock()
                    .await
                    .record_failure(username, addr.ip());
                return Err(anyhow::anyhow!("user not found or disabled: {}", username));
            }
        }
    };

    let pw_bytes = password.as_bytes().to_vec();
    let uname = username.to_string();
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
            username
        );
        server_state
            .failed_auth
            .lock()
            .await
            .record_failure(username, addr.ip());
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
            username,
            profile.name
        );
        return Err(anyhow::anyhow!(
            "user '{}' not authorised for profile '{}'",
            username,
            profile.name
        ));
    }
    log::info!(
        "AUTH OK {} {}: user={} on profile '{}'",
        proto,
        addr,
        username,
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
) -> String {
    let obf = crate::config::PushedObf {
        padding: pcfg.obfuscation.padding.clone(),
        heartbeat: pcfg.obfuscation.heartbeat.clone(),
        traffic_normalization: pcfg.obfuscation.traffic_normalization.clone(),
    };
    let routes: serde_json::Value =
        serde_json::from_str(routes_json).unwrap_or_else(|_| serde_json::json!([]));
    // Only push a DNS address when the in-tunnel proxy is actually running.
    // Otherwise `dns.listen` is its default (10.0.0.1) which resolves nowhere —
    // pushing it black-holed client name resolution. Empty => the client keeps
    // its own configured resolvers.
    let pushed_dns = if pcfg.dns.enabled {
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
    });
    format!("OK:{}", serde_json::to_string(&body).unwrap_or_default())
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

    if let Some(routes) = user_routes {
        let parts: Vec<String> = routes
            .iter()
            .map(|r| {
                let gw = r.gateway.as_deref().unwrap_or(gw_default);
                let metric = r.metric.unwrap_or(100);
                format!(
                    r#"{{"cidr":"{}","gateway":"{}","metric":{}}}"#,
                    r.cidr, gw, metric
                )
            })
            .collect();
        format!("[{}]", parts.join(","))
    } else {
        let routes = &pcfg.routing.advertised_routes;
        if routes.is_empty() {
            return "[]".to_string();
        }
        let parts: Vec<String> = routes
            .iter()
            .map(|r| {
                let gw = r.gateway.as_deref().unwrap_or(gw_default);
                let metric = r.metric.unwrap_or(100);
                format!(
                    r#"{{"cidr":"{}","gateway":"{}","metric":{}}}"#,
                    r.cidr, gw, metric
                )
            })
            .collect();
        format!("[{}]", parts.join(","))
    }
}

/// Auth packet plaintext layout: `[client_key_proof: 32 bytes][username:password]`.
/// The proof is all-zero when the client has no pinned key.
async fn receive_auth<S: AsyncRead + Unpin>(
    stream: &mut S,
    codec: &mut PacketCodec,
    framing: Framing,
) -> anyhow::Result<([u8; 32], String, String)> {
    let record = read_record(stream, framing)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read auth packet: {}", e))?;
    let plaintext = codec.decrypt_packet(&record)?;
    if plaintext.len() < 32 {
        return Err(anyhow::anyhow!("auth packet too short"));
    }
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&plaintext[..32]);
    let auth_str = String::from_utf8(plaintext[32..].to_vec())?;

    if let Some((user, pass)) = auth_str.split_once(':') {
        Ok((proof, user.to_string(), pass.to_string()))
    } else {
        Err(anyhow::anyhow!("invalid auth format"))
    }
}
