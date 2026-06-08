pub mod dns;
pub mod route;

use crate::crypto::{derive_keys, handshake_transcript_hash, Keypair};
use crate::protocol::{
    generate_connection_id, pick_random_sni, read_record, read_tls_record, unwrap_quic,
    wrap_quic_long, wrap_quic_short, FakeTlsHandshake, Framing, Obfuscator, PacketCodec,
};
use crate::transport::tcp::set_tcp_keepalive;
use crate::tun::iface::TunInterface;
use crate::tun::{
    generate_mac, is_tap_mode, prepend_ethernet_header, strip_ethernet_header, tap_interface_name,
};
use rand::Rng;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub async fn run_client(config_path: &str) -> anyhow::Result<()> {
    let config_content = std::fs::read_to_string(config_path)?;
    let config: crate::config::client::ClientConfig =
        crate::config::parse_client_config(&config_content)?;

    let password = if let Some(ref pw) = config.auth.password {
        pw.clone()
    } else if let Some(ref pw_file) = config.auth.password_file {
        std::fs::read_to_string(pw_file)?.trim().to_string()
    } else if let Some(ref pw_cmd) = config.auth.password_command {
        let output = std::process::Command::new("sh")
            .args(["-c", pw_cmd])
            .output()?;
        String::from_utf8(output.stdout)?.trim().to_string()
    } else {
        return Err(anyhow::anyhow!(
            "auth.password, auth.password_file or auth.password_command required"
        ));
    };

    // Repair any DNS state left behind by a previous run that died without
    // restoring (SIGKILL / power loss / panic). Must run before we touch DNS.
    dns::recover_stale();

    // Graceful shutdown: on SIGINT/SIGTERM restore DNS before exiting, so a
    // `systemctl stop` or Ctrl-C never strands the system on the tunnel
    // resolver. This is the last line of defence on top of the per-connection
    // restore in the data-plane loops below.
    tokio::spawn(async {
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
        log::info!("Shutdown signal received — restoring DNS and exiting");
        dns::restore_dns();
        std::process::exit(0);
    });

    let mut retry_count = 0u64;

    loop {
        let result = if config.server.protocol == "udp" {
            connect_and_run_udp(&config, &password).await
        } else {
            connect_and_run_tcp(&config, &password).await
        };

        match &result {
            Ok(_) => {
                log::info!("Connection closed, reconnecting...");
                // The tunnel was established (auth succeeded) — a healthy session
                // that simply dropped. Reset the backoff counter so only
                // *consecutive* connect/auth failures escalate the delay; without
                // this, a long-lived link that flaps (cell handover, Wi-Fi↔LTE)
                // would reconnect ever more slowly, eventually waiting max_delay.
                retry_count = 0;
            }
            Err(e) => log::error!("Connection error: {}", e),
        }

        if !config.server.reconnect.enabled {
            return result;
        }

        let max_retries = config.server.reconnect.max_retries;
        if max_retries >= 0 && retry_count >= max_retries as u64 {
            return Err(anyhow::anyhow!("max retries ({}) reached", max_retries));
        }

        retry_count += 1;

        let multiplier = 1u64
            .checked_shl(retry_count as u32)
            .unwrap_or(u64::MAX)
            .min(100);
        let delay = std::cmp::min(
            config
                .server
                .reconnect
                .base_delay_secs
                .saturating_mul(multiplier),
            config.server.reconnect.max_delay_secs,
        );

        log::info!("Reconnecting in {}s (attempt {})...", delay, retry_count);
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

async fn connect_and_run_tcp(
    config: &crate::config::client::ClientConfig,
    password: &str,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.server.address, config.server.port);
    log::info!("Connecting to {} (TCP)", addr);

    let stream = TcpStream::connect(&addr).await?;
    stream.set_nodelay(config.performance.tcp_nodelay)?;
    set_tcp_keepalive(&stream, config.server.tcp_keepalive_secs)?;

    if config.obfuscation.mode == "obfs" {
        if config.obfuscation.obfs_key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "obfs wire mode requires a non-empty obfuscation.obfs_key \
                 (an empty key is publicly derivable → no DPI resistance)"
            ));
        }
        log::info!("Wire mode: obfs (ChaCha20 stream obfuscation)");
        let key = crate::protocol::obfs::derive_obfs_key(&config.obfuscation.obfs_key);
        let fronting = config.obfuscation.fronting == "websocket";
        let s = crate::protocol::obfs::ObfsStream::connect(stream, &key, fronting).await?;
        run_tcp_tunnel(s, config, password).await
    } else if config.obfuscation.mode == "reality-tls" {
        log::info!("Wire mode: reality-tls (real TLS 1.3 carrying the tunnel)");
        // SNI precedence mirrors the inner handshake.
        let server_name: String = match config.obfuscation.sni.as_deref() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => {
                crate::protocol::pick_random_sni().to_string()
            }
            _ => config.server.address.clone(),
        };
        // Seal the REALITY token into the real ClientHello's session_id, with a
        // fresh ephemeral (distinct from the inner fake-TLS keys). Requires a
        // pinned server key + short_id — without them the server cannot
        // recognise us and would proxy the connection to the real site.
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
        let mut stream = stream;
        let est = crate::protocol::realtls::client::client_handshake(
            &mut stream,
            eph,
            session_id,
            &server_name,
        )
        .await?;
        let tls = crate::protocol::realtls::stream::RealTlsStream::new(stream, est);
        run_tcp_tunnel(tls, config, password).await
    } else {
        run_tcp_tunnel(stream, config, password).await
    }
}

async fn run_tcp_tunnel<S>(
    mut stream: S,
    config: &crate::config::client::ClientConfig,
    password: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static + crate::protocol::obfs::SplitStream,
{
    let (
        client_rx,
        mut client_tx,
        client_ip_str,
        server_ip,
        dns_ip,
        dns_port,
        routes_json,
        pushed_obf,
        prefix,
        pushed_mtu,
    ) = tcp_handshake(&mut stream, config, password).await?;

    // Effective obfuscation = client config, with the data-phase params
    // (padding / heartbeat / traffic-normalization) overridden by whatever the
    // server pushed, so the two ends always agree without the client carrying
    // them in its config.
    let mut eff_obf = config.obfuscation.clone();
    if let Some(po) = pushed_obf {
        eff_obf.padding = po.padding;
        eff_obf.heartbeat = po.heartbeat;
        eff_obf.traffic_normalization = po.traffic_normalization;
    }

    let tunnel = setup_tunnel(
        config,
        &client_ip_str,
        &prefix_to_netmask(prefix),
        &server_ip,
        &dns_ip,
        &dns_port,
        effective_mtu(config.tun.mtu, pushed_mtu),
    )?;
    route::apply_local_networks(&config.routing, &routes_json, &tunnel.if_name, &server_ip);
    let reader_fd = tunnel.reader_fd;
    let writer_fd = tunnel.writer_fd;
    let tun_fd = tunnel.tun.as_raw_fd();
    let tun_name = tunnel.if_name;
    let is_tap = tunnel.is_tap;
    let server_addr = config.server.address.clone();
    let tunnel_tun = tunnel.tun;
    let tap_mac = if is_tap { generate_mac() } else { [0u8; 6] };
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
    let heartbeat_enabled = hb_config.enabled && hb_config.interval_ms > 0;
    let padding_min = eff_obf.padding.min_bytes;
    let padding_max = eff_obf.padding.max_bytes;
    let padding_enabled = eff_obf.padding.enabled;
    let padding_randomize = eff_obf.padding.randomize;
    let padding_prob = eff_obf.padding.probability;
    let tun_buf_size = config.performance.tun_buffer_size;
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;

    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(4096);

    let is_tap_reader = is_tap;
    // Stop flag so the blocking TUN-reader thread terminates promptly when the
    // connection drops. The tun fd is non-blocking, so the loop spins on
    // WouldBlock; without this flag it would never notice the channel closing
    // (it only checks on a successful read) and `tun_reader_handle.await` in
    // cleanup would hang forever — blocking reconnect.
    let tun_stop = Arc::new(AtomicBool::new(false));
    let tun_stop_r = tun_stop.clone();
    let tun_reader_handle = tokio::task::spawn_blocking(move || {
        let mut buf2 = vec![0u8; tun_buf_size];
        loop {
            if tun_stop_r.load(Ordering::Relaxed) {
                break;
            }
            let n = unsafe {
                libc::read(
                    reader_fd,
                    buf2.as_mut_ptr() as *mut libc::c_void,
                    buf2.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                log::error!("TUN read error: {}", err);
                break;
            }
            if n == 0 {
                break;
            }
            let raw = &buf2[..n as usize];
            let packet = if is_tap_reader {
                match strip_ethernet_header(raw) {
                    Some(ip) => ip.to_vec(),
                    None => continue,
                }
            } else {
                raw.to_vec()
            };
            if tun_read_tx.blocking_send(packet).is_err() {
                break;
            }
        }
        unsafe {
            libc::close(reader_fd);
        }
        log::info!("TUN reader stopped");
    });

    // Dedicated TUN writer thread — exact same architecture as
    // server/mod.rs:411–438. One std::thread reads packets out of a bounded
    // std::sync::mpsc::sync_channel and does a single libc::write per packet,
    // with no per-packet spawn_blocking. Replaces the prior pattern where
    // every inbound packet did `tokio::task::spawn_blocking(libc::write)`,
    // overflowing the 512-thread tokio blocking pool under sustained traffic
    // (cliff ~200 Mbps plain, far lower with obfuscation). See ROADMAP P0.1.
    let is_tap_writer = is_tap;
    let (tun_write_tx, tun_write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2048);
    let _tun_writer_thread = {
        let tap_mac_w = tap_mac;
        let gateway_mac_w = gateway_mac;
        std::thread::spawn(move || {
            log::info!("TUN writer started");
            for packet in tun_write_rx {
                if packet.is_empty() {
                    continue;
                }
                unsafe {
                    if is_tap_writer {
                        let frame = prepend_ethernet_header(&packet, &tap_mac_w, &gateway_mac_w);
                        libc::write(
                            writer_fd,
                            frame.as_ptr() as *const libc::c_void,
                            frame.len(),
                        );
                    } else {
                        libc::write(
                            writer_fd,
                            packet.as_ptr() as *const libc::c_void,
                            packet.len(),
                        );
                    }
                }
            }
            unsafe {
                libc::close(writer_fd);
            }
            log::info!("TUN writer stopped");
        })
    };

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
    let (mut read_half, mut write_half) = stream.split_io();
    // Records on the wire are TLS-dressed for every mode except `plain`, which
    // uses bare length-prefixed framing (matching the codecs from the handshake).
    let framing = if config.obfuscation.mode == "plain" {
        Framing::Raw
    } else {
        Framing::Tls
    };
    let base = tokio::time::Instant::now();
    let last_act = Arc::new(AtomicU64::new(0));
    // Time (ms since `base`) of the last data RECEIVED from the server. Distinct
    // from last_act (which our own heartbeats bump) so we can tell a one-way-dead
    // link — a server that vanished while the tunnel was idle — apart from a live
    // idle one. The server independently heartbeats, so silence = dead.
    let last_rx = Arc::new(AtomicU64::new(0));
    let (dead_tx, mut dead_rx) = mpsc::channel::<()>(1);

    {
        let mut client_rx = client_rx;
        let tun_write_tx = tun_write_tx.clone();
        let last_act = last_act.clone();
        let last_rx = last_rx.clone();
        tokio::spawn(async move {
            loop {
                match read_record(&mut read_half, framing).await {
                    Ok(record) => {
                        let now = base.elapsed().as_millis() as u64;
                        last_act.store(now, Ordering::Relaxed);
                        last_rx.store(now, Ordering::Relaxed);
                        match client_rx.decrypt_packet(&record) {
                            Ok(plaintext) => {
                                if !plaintext.is_empty() {
                                    // Non-blocking hand-off to the TUN writer thread.
                                    // A blocking send() would stall this reader (and
                                    // tie up a runtime worker) whenever the TUN write
                                    // side falls behind; dropping under a full queue is
                                    // the correct congestion behaviour (like a full NIC
                                    // tx ring), and the inner traffic is retransmitted
                                    // by the upper-layer protocols.
                                    match tun_write_tx.try_send(plaintext) {
                                        Ok(()) => {}
                                        Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                            log::trace!(
                                                "TUN write queue full — dropping inbound packet"
                                            );
                                        }
                                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                            break
                                        }
                                    }
                                }
                            }
                            Err(e) => log::debug!("Decrypt error: {}", e),
                        }
                    }
                    Err(e) => {
                        log::debug!("Server read closed: {:?}", e);
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
    let hb_ms = heartbeat_interval.as_millis() as u64;
    let idle_ms = idle_timeout.as_millis() as u64;

    loop {
        tokio::select! {
            biased;

            _ = dead_rx.recv() => {
                // Reader task ended → server closed the connection or read error.
                break;
            }

            Some(ip_packet) = tun_read_rx.recv() => {
                last_act.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                let encrypted = {
                    let mut obf = Obfuscator::new();
                    let mut data_with_route = ip_packet;
                    if eff_obf.traffic_normalization.enabled && !norm_sizes.is_empty() {
                        data_with_route = obf.normalize_packet_length(&data_with_route, norm_sizes);
                    }
                    // Clamp padding so the resulting datagram stays under the path
                    // MTU (avoids IP fragmentation on UDP; harmless on TCP). 60B
                    // covers record header + nonce + tag + counter + padlen + QUIC.
                    let pad_cap = {
                        let base = data_with_route.len().saturating_add(60);
                        (padding_max as usize).min(1400usize.saturating_sub(base)) as u16
                    };
                    let padding = obf.generate_padding_opts(
                        padding_enabled, padding_min, pad_cap, padding_randomize, padding_prob,
                    );
                    client_tx.encrypt_packet(&data_with_route, &padding).ok()
                };
                if let Some(pkt) = encrypted {
                    if write_half.write_all(&pkt).await.is_err() {
                        break;
                    }
                }
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                // Idle-gate: skip the beacon while real traffic is flowing.
                let since = base.elapsed().as_millis() as u64 - last_act.load(Ordering::Relaxed);
                if since < hb_ms {
                    continue;
                }
                let jitter = if hb_config.jitter_ms > 0 {
                    let mut rng = rand::thread_rng();
                    let j = rng.gen_range(0..(hb_config.jitter_ms * 2));
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
                    client_tx.encrypt_packet(&[], &padding).ok()
                };
                if let Some(hb) = heartbeat {
                    if write_half.write_all(&hb).await.is_err() {
                        break;
                    }
                }
                last_act.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
            }

            _ = idle_check.tick() => {
                let now = base.elapsed().as_millis() as u64;
                // RX-liveness: a dead/idle server is detected here in seconds.
                // TCP alone would take minutes (unacked writes retransmit; keepalive
                // is suppressed by our heartbeats). The server heartbeats too, so no
                // data for 3 intervals ⇒ link is gone ⇒ break to trigger reconnect.
                if heartbeat_enabled {
                    let rx_dead = hb_ms.saturating_mul(3).max(30_000);
                    if now.saturating_sub(last_rx.load(Ordering::Relaxed)) > rx_dead {
                        log::warn!("No data from server for >{}s — assuming dead, reconnecting", rx_dead / 1000);
                        break;
                    }
                }
                if idle_ms > 0 && now.saturating_sub(last_act.load(Ordering::Relaxed)) > idle_ms {
                    log::debug!("Idle timeout reached");
                    break;
                }
            }
        }
    }

    dns::restore_dns();
    tun_stop.store(true, Ordering::Relaxed); // tell the reader thread to exit
    drop(tun_read_rx);
    let _ = tun_reader_handle.await;
    // tun_write_tx dropped here, dedicated writer thread closes writer_fd
    // inside the thread when its channel-receive loop ends.
    drop(tun_write_tx);
    drop(tunnel_tun);
    unsafe {
        libc::close(tun_fd);
    }
    TunInterface::delete(&tun_name).ok();
    route::cleanup_routes(&tun_name, &server_addr).ok();
    log::info!("Client disconnected");
    Ok(())
}

/// Verify the server identity message in either format:
///  * ≥64 bytes — `static_pub||proof` (TOFU or pinned cross-check),
///  * 32 bytes — proof-only (server hid its key in require-pinned mode; the
///    client must have the key pinned to verify).
///
/// Returns the server static public key bytes.
fn verify_server_identity(
    auth_proof_msg: &[u8],
    client_kp: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    pinned: &Option<String>,
) -> anyhow::Result<[u8; 32]> {
    if auth_proof_msg.len() >= 64 {
        crate::crypto::verify_server_auth_message(
            auth_proof_msg,
            client_kp,
            ephemeral_shared,
            transcript_hash,
        )
    } else {
        let pin = pinned.as_deref().and_then(crate::crypto::parse_pubkey_hex)
            .ok_or_else(|| anyhow::anyhow!(
                "server sent proof-only (require-pinned mode) but client has no server_public_key pinned"))?;
        crate::crypto::verify_server_proof_only(
            auth_proof_msg,
            client_kp,
            &pin,
            ephemeral_shared,
            transcript_hash,
        )
    }
}

/// Build the auth packet plaintext: `[client_key_proof:32][username:password]`.
/// The proof is computed from the *pinned* server public key (config), so only a
/// client that has pinned the key can produce a valid one — letting a server with
/// `require_client_key_proof` reject unpinned clients. All-zero when not pinned.
fn build_client_auth_plaintext(
    config: &crate::config::client::ClientConfig,
    client_kp: &Keypair,
    ephemeral_shared: &[u8; 32],
    transcript_hash: &[u8; 32],
    password: &str,
) -> Vec<u8> {
    let proof = config
        .auth
        .server_public_key
        .as_deref()
        .and_then(crate::crypto::parse_pubkey_hex)
        .map(|pk| {
            let ss = client_kp.derive_shared(&crate::crypto::PublicKey::from_bytes(&pk));
            crate::crypto::compute_client_key_proof(&ss.0, ephemeral_shared, transcript_hash)
        })
        .unwrap_or([0u8; 32]);
    let creds = format!("{}:{}", config.auth.username, password);
    let mut out = Vec::with_capacity(32 + creds.len());
    out.extend_from_slice(&proof);
    out.extend_from_slice(creds.as_bytes());
    out
}

async fn tcp_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &crate::config::client::ClientConfig,
    password: &str,
) -> anyhow::Result<(
    PacketCodec,
    PacketCodec,
    String,
    String,
    String,
    String,
    String,
    Option<crate::config::PushedObf>,
    u8,
    i32,
)> {
    let client_kp = Keypair::generate();

    // `plain` wire mode: no TLS mimicry at all. Exchange ephemeral X25519 publics
    // raw, bind the channel to H(client_pub‖server_pub), then run the same
    // encrypted auth flow over bare length-prefixed records (Framing::Raw). The
    // data plane that follows is header-only ([len][nonce][ct]) too.
    if config.obfuscation.mode == "plain" {
        stream.write_all(client_kp.public().as_bytes()).await?;
        let mut sp = [0u8; 32];
        stream
            .read_exact(&mut sp)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read server key (plain): {}", e))?;
        let server_pub = crate::crypto::PublicKey::from_bytes(&sp);
        let transcript_hash = handshake_transcript_hash(&[client_kp.public().as_bytes(), &sp]);

        let shared = client_kp
            .derive_shared_checked(&server_pub)
            .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
        let (server_to_client, client_to_server) = derive_keys(&shared.0);
        let mut client_rx = PacketCodec::new_raw(server_to_client);
        let mut client_tx = PacketCodec::new_raw(client_to_server);

        let auth_proof_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read auth proof (plain): {}", e))?;
        let auth_proof_msg = client_rx.decrypt_packet(&auth_proof_record)?;
        let server_static_pub_bytes = verify_server_identity(
            &auth_proof_msg,
            &client_kp,
            &shared.0,
            &transcript_hash,
            &config.auth.server_public_key,
        )?;
        verify_server_key(&server_static_pub_bytes, &config.auth.server_public_key)?;
        log::info!("Server identity verified (plain)");

        let auth_plain =
            build_client_auth_plaintext(config, &client_kp, &shared.0, &transcript_hash, password);
        let auth_packet = client_tx.encrypt_packet(&auth_plain, &[])?;
        stream.write_all(&auth_packet).await?;

        let auth_response_record = read_record(stream, Framing::Raw)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read auth response (plain): {}", e))?;
        let auth_response = client_rx.decrypt_packet(&auth_response_record)?;
        let ok = parse_auth_ok(&String::from_utf8(auth_response)?)?;
        log::info!("Auth OK (plain), assigned IP: {}", ok.client_ip);
        return Ok((
            client_rx,
            client_tx,
            ok.client_ip,
            ok.server_ip,
            ok.dns_ip,
            ok.dns_port,
            ok.routes_json,
            ok.pushed_obf,
            ok.prefix,
            ok.mtu,
        ));
    }

    // SNI precedence: an explicit `obfuscation.sni` override (e.g. pinned by a
    // qeli:// link) wins; else the connect hostname; else a random decoy when
    // connecting to a bare IP.
    let server_name: &str = match config.obfuscation.sni.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => pick_random_sni(),
        _ => &config.server.address,
    };

    // REALITY: when a short_id + pinned server key are configured, embed a crypto
    // auth token in the (browser-like) ClientHello's session_id. The server uses
    // it to recognise us instead of the legacy "no ALPN" signal.
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

    let client_hello = FakeTlsHandshake::build_client_hello(
        client_kp.public(),
        server_name,
        0,
        reality_sid.as_ref(),
    );
    stream.write_all(&client_hello).await?;

    let server_hello_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read ServerHello: {}", e))?;
    let server_pub_key = FakeTlsHandshake::parse_server_hello(&server_hello_record)
        .ok_or_else(|| anyhow::anyhow!("failed to parse ServerHello"))?;

    if server_pub_key.len() != 32 {
        return Err(anyhow::anyhow!("invalid server key length"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&server_pub_key);
    let server_pub = crate::crypto::PublicKey::from_bytes(&key_bytes);

    let _ccs_record = read_tls_record(stream).await.ok();
    let cert_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read Certificate: {}", e))?;
    let finished_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read Finished: {}", e))?;
    let _nst_record = read_tls_record(stream).await.ok();

    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
    let (server_to_client, client_to_server) = derive_keys(&shared.0);
    let mut client_rx = PacketCodec::new(server_to_client);
    let mut client_tx = PacketCodec::new(client_to_server);

    // Same handshake transcript the server bound the proof to. Order must match
    // server/handler.rs::server_handshake: ClientHello, ServerHello, Cert, Finished.
    let transcript_hash = handshake_transcript_hash(&[
        &client_hello,
        &server_hello_record,
        &cert_record,
        &finished_record,
    ]);

    log::info!("Handshake complete, reading server auth proof");

    let auth_proof_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read auth proof: {}", e))?;
    let auth_proof_msg = client_rx.decrypt_packet(&auth_proof_record)?;

    let server_static_pub_bytes = verify_server_identity(
        &auth_proof_msg,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &config.auth.server_public_key,
    )?;

    // Key pinning: verify server static key against pinned value, or warn TOFU
    verify_server_key(&server_static_pub_bytes, &config.auth.server_public_key)?;

    log::info!("Server identity verified");

    let auth_plain =
        build_client_auth_plaintext(config, &client_kp, &shared.0, &transcript_hash, password);
    let auth_packet = client_tx.encrypt_packet(&auth_plain, &[])?;
    stream.write_all(&auth_packet).await?;

    let auth_response_record = read_tls_record(stream)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read auth response: {}", e))?;
    let auth_response = client_rx.decrypt_packet(&auth_response_record)?;
    let response_str = String::from_utf8(auth_response)?;

    let ok = parse_auth_ok(&response_str)?;
    log::info!("Auth OK, assigned IP: {}", ok.client_ip);
    if ok.pushed_obf.is_some() {
        log::info!("Applying server-pushed obfuscation params");
    }
    if ok.routes_json != "[]" && !ok.routes_json.is_empty() {
        log::info!(
            "Server pushed {} route(s)",
            ok.routes_json.matches("cidr").count()
        );
    }

    Ok((
        client_rx,
        client_tx,
        ok.client_ip,
        ok.server_ip,
        ok.dns_ip,
        ok.dns_port,
        ok.routes_json,
        ok.pushed_obf,
        ok.prefix,
        ok.mtu,
    ))
}

/// Parsed auth-OK payload. The server sends self-describing keyed JSON behind
/// the `OK:` success marker (see handler::build_auth_ok); each field is looked up
/// by key so an added/reordered field can't silently mis-map.
struct AuthOk {
    client_ip: String,
    server_ip: String,
    /// VPN subnet prefix length pushed by the server (default 24 for older
    /// servers that don't send it). Determines the on-link netmask.
    prefix: u8,
    /// TUN MTU pushed by the server (its profile's tun.mtu). 0 = the server is
    /// too old to push one; the client then uses its own config value or the
    /// auto fallback.
    mtu: i32,
    dns_ip: String,
    dns_port: String,
    routes_json: String,
    pushed_obf: Option<crate::config::PushedObf>,
}

fn parse_auth_ok(response_str: &str) -> anyhow::Result<AuthOk> {
    let json = response_str
        .strip_prefix("OK:")
        .ok_or_else(|| anyhow::anyhow!("auth failed: {}", response_str))?;
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| anyhow::anyhow!("malformed auth OK json: {}", e))?;
    let client_ip = v["client_ip"].as_str().unwrap_or("").to_string();
    if client_ip.is_empty() {
        return Err(anyhow::anyhow!("auth OK missing client_ip"));
    }
    let dns_port = match &v["dns_port"] {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => "53".to_string(),
    };
    // VPN subnet prefix (default /24 when the server is older and omits it).
    let prefix: u8 = v["prefix"]
        .as_u64()
        .map(|n| n as u8)
        .filter(|p| (1..=32).contains(p))
        .unwrap_or(24);
    // Server-pushed TUN MTU; 0/absent => server did not push one.
    let mtu: i32 = v["mtu"]
        .as_i64()
        .filter(|m| (576..=9000).contains(m))
        .map(|m| m as i32)
        .unwrap_or(0);
    Ok(AuthOk {
        client_ip,
        server_ip: v["server_ip"].as_str().unwrap_or("").to_string(),
        prefix,
        mtu,
        dns_ip: v["dns"].as_str().unwrap_or("").to_string(),
        dns_port,
        routes_json: v
            .get("routes")
            .map(|r| r.to_string())
            .unwrap_or_else(|| "[]".into()),
        pushed_obf: v
            .get("obfuscation")
            .and_then(|o| serde_json::from_value(o.clone()).ok()),
    })
}

struct TunnelSetup {
    tun: TunInterface,
    reader_fd: i32,
    writer_fd: i32,
    if_name: String,
    is_tap: bool,
}

/// Resolve the effective TUN MTU by precedence: an explicit client config value
/// (`> 0`) wins; otherwise the server-pushed MTU (`> 0`); otherwise the auto
/// fallback (1400, for servers too old to push one).
fn effective_mtu(client_mtu: i32, pushed_mtu: i32) -> i32 {
    if client_mtu > 0 {
        client_mtu
    } else if pushed_mtu > 0 {
        pushed_mtu
    } else {
        crate::config::client::MTU_AUTO_FALLBACK
    }
}

fn setup_tunnel(
    config: &crate::config::client::ClientConfig,
    client_ip: &str,
    netmask: &str,
    server_ip: &str,
    dns_ip: &str,
    dns_port: &str,
    mtu: i32,
) -> anyhow::Result<TunnelSetup> {
    let is_tap = is_tap_mode(&config.tun.device_type);
    let if_name = tap_interface_name(&config.tun.name, &config.tun.device_type);
    log::info!("TUN MTU: {}", mtu);

    // If the interface already exists, warn before reclaiming it. Usually it's our
    // own stale interface from a previous run (delete+recreate is intentional
    // self-healing); if it belongs to another app, the operator should pick a
    // distinct name via `dev=` in [qeli] instead of having it clobbered.
    if std::path::Path::new(&format!("/sys/class/net/{}", if_name)).exists() {
        log::warn!(
            "interface '{}' already exists — reclaiming it (set 'dev=<name>' in [qeli] to use a different one)",
            if_name
        );
    }
    TunInterface::delete(&if_name).ok();
    let tun_res = if is_tap {
        log::info!("Creating TAP interface {}", if_name);
        TunInterface::create_tap(&if_name, mtu)
    } else {
        log::info!("Creating TUN interface {}", if_name);
        TunInterface::create(&if_name, mtu)
    };
    let tun = tun_res.map_err(|e| {
        anyhow::anyhow!(
            "failed to create {} interface '{}': {} — is it already in use by another app? \
             Set 'dev=<name>' in [qeli] to use a different interface name.",
            if is_tap { "TAP" } else { "TUN" },
            if_name,
            e
        )
    })?;
    TunInterface::set_address(&if_name, client_ip, netmask)?;
    TunInterface::set_up(&if_name, mtu)?;
    tun.set_nonblocking()?;

    let dev_label = if is_tap { "TAP" } else { "TUN" };
    log::info!("{} {} is up (IP: {})", dev_label, if_name, client_ip);

    let raw_reader = unsafe { libc::dup(tun.as_raw_fd()) };
    let raw_writer = unsafe { libc::dup(tun.as_raw_fd()) };
    if raw_reader < 0 || raw_writer < 0 {
        if raw_reader >= 0 {
            unsafe {
                libc::close(raw_reader);
            }
        }
        if raw_writer >= 0 {
            unsafe {
                libc::close(raw_writer);
            }
        }
        return Err(anyhow::anyhow!("failed to dup TUN fd"));
    }

    route::setup_routes(&config.routing, server_ip, &if_name, &config.server.address)?;
    dns::setup_dns_for_interface(&config.dns, dns_ip, dns_port, &if_name)?;

    Ok(TunnelSetup {
        tun,
        reader_fd: raw_reader,
        writer_fd: raw_writer,
        if_name,
        is_tap,
    })
}

async fn connect_and_run_udp(
    config: &crate::config::client::ClientConfig,
    password: &str,
) -> anyhow::Result<()> {
    if config.obfuscation.mode == "plain" {
        return Err(anyhow::anyhow!(
            "plain (raw) wire mode is TCP-only; set server.protocol = tcp"
        ));
    }
    let addr = format!("{}:{}", config.server.address, config.server.port);
    log::info!("Connecting to {} (UDP)", addr);

    if config.obfuscation.mode == "obfs" && config.obfuscation.obfs_key.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "obfs wire mode requires a non-empty obfuscation.obfs_key \
             (an empty key is publicly derivable → no DPI resistance)"
        ));
    }
    let raw_socket = UdpSocket::bind("0.0.0.0:0").await?;
    raw_socket.connect(&addr).await?;
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
    let connection_id = if quic_enabled {
        generate_connection_id()
    } else {
        [0u8; 4]
    };
    let mut quic_pn = 0u32;

    let client_kp = Keypair::generate();
    // SNI precedence: an explicit `obfuscation.sni` override (e.g. pinned by a
    // qeli:// link) wins; else the connect hostname; else a random decoy when
    // connecting to a bare IP.
    let server_name: &str = match config.obfuscation.sni.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ if config.server.address.parse::<std::net::IpAddr>().is_ok() => pick_random_sni(),
        _ => &config.server.address,
    };

    // Pad the UDP ClientHello to ≥1200B (anti-amplification floor; see
    // build_client_hello). The server rejects shorter UDP initials.
    let client_hello =
        FakeTlsHandshake::build_client_hello(client_kp.public(), server_name, 1200, None);
    let send_data = if quic_enabled {
        quic_pn += 1;
        wrap_quic_long(&client_hello, &connection_id, quic_pn - 1, 0x02)
    } else {
        client_hello.clone()
    };
    socket.send(&send_data).await?;

    log::info!(
        "UDP: Sent ClientHello{}",
        if quic_enabled { " (QUIC)" } else { "" }
    );

    let mut recv_buf = vec![0u8; 65535];
    let timeout = Duration::from_secs(config.server.connection_timeout_secs);
    let n = tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await??;
    log::info!("UDP: Received server response ({} bytes)", n);

    let raw_response = if quic_enabled {
        let quic_pkt = unwrap_quic(&recv_buf[..n])
            .map_err(|e| anyhow::anyhow!("UDP: failed to parse QUIC header: {:?}", e))?;
        quic_pkt.payload
    } else {
        recv_buf[..n].to_vec()
    };

    let data = &raw_response;

    if data.len() < 5 {
        return Err(anyhow::anyhow!("UDP: server response too short"));
    }

    let mut offset = 0usize;

    if offset + 5 > data.len() {
        return Err(anyhow::anyhow!("UDP: truncated ServerHello"));
    }
    let sh_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
    let server_hello = data[offset..offset + 5 + sh_len].to_vec();
    offset += 5 + sh_len;

    let server_pub_key = FakeTlsHandshake::parse_server_hello(&server_hello)
        .ok_or_else(|| anyhow::anyhow!("failed to parse ServerHello"))?;
    if server_pub_key.len() != 32 {
        return Err(anyhow::anyhow!("invalid server key length"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&server_pub_key);
    let server_pub = crate::crypto::PublicKey::from_bytes(&key_bytes);

    if offset + 5 <= data.len() && data[offset] == 0x14 {
        let ccs_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        offset += 5 + ccs_len;
    }

    // Capture Certificate and Finished records for the handshake transcript.
    let mut cert_record: Vec<u8> = Vec::new();
    if offset + 5 <= data.len() && data[offset] == 0x16 {
        let cert_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + cert_len <= data.len() {
            cert_record = data[offset..offset + 5 + cert_len].to_vec();
        }
        offset += 5 + cert_len;
    }

    let mut finished_record: Vec<u8> = Vec::new();
    if offset + 5 <= data.len() && data[offset] == 0x16 {
        let fin_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if offset + 5 + fin_len <= data.len() {
            finished_record = data[offset..offset + 5 + fin_len].to_vec();
        }
        offset += 5 + fin_len;
    }

    if offset + 5 <= data.len() && data[offset] == 0x16 {
        let nst_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        offset += 5 + nst_len;
    }

    let shared = client_kp
        .derive_shared_checked(&server_pub)
        .ok_or_else(|| anyhow::anyhow!("rejected low-order server public key"))?;
    let (server_to_client, client_to_server) = derive_keys(&shared.0);
    let mut client_rx = PacketCodec::new(server_to_client);
    let mut client_tx = PacketCodec::new(client_to_server);

    // Same transcript the server bound the proof to. Order must match
    // server/udp_handler.rs: ClientHello, ServerHello, Cert, Finished.
    let transcript_hash =
        handshake_transcript_hash(&[&client_hello, &server_hello, &cert_record, &finished_record]);

    log::info!("UDP: Handshake derived keys");

    let auth_proof_msg = if offset >= data.len() {
        let n2 = tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await??;
        let auth_raw = if quic_enabled {
            let quic_pkt = unwrap_quic(&recv_buf[..n2])
                .map_err(|e| anyhow::anyhow!("UDP: failed to parse QUIC auth response: {:?}", e))?;
            quic_pkt.payload
        } else {
            recv_buf[..n2].to_vec()
        };
        client_rx.decrypt_packet(&auth_raw)?
    } else {
        let auth_record = data[offset..].to_vec();
        client_rx.decrypt_packet(&auth_record)?
    };

    let server_static_pub_bytes = verify_server_identity(
        &auth_proof_msg,
        &client_kp,
        &shared.0,
        &transcript_hash,
        &config.auth.server_public_key,
    )?;
    verify_server_key(&server_static_pub_bytes, &config.auth.server_public_key)?;

    log::info!("UDP: Server identity verified");

    let auth_plain =
        build_client_auth_plaintext(config, &client_kp, &shared.0, &transcript_hash, password);
    let auth_packet = client_tx.encrypt_packet(&auth_plain, &[])?;
    let auth_send = if quic_enabled {
        quic_pn += 1;
        wrap_quic_short(&auth_packet, &connection_id, quic_pn - 1)
    } else {
        auth_packet
    };
    socket.send(&auth_send).await?;

    log::info!("UDP: Sent auth credentials");

    let n3 = tokio::time::timeout(timeout, socket.recv(&mut recv_buf)).await??;
    let auth_response_raw = if quic_enabled {
        let quic_pkt = unwrap_quic(&recv_buf[..n3])
            .map_err(|e| anyhow::anyhow!("UDP: failed to parse QUIC auth response: {:?}", e))?;
        quic_pkt.payload
    } else {
        recv_buf[..n3].to_vec()
    };
    let auth_response = client_rx.decrypt_packet(&auth_response_raw)?;
    let response_str = String::from_utf8(auth_response)?;

    let ok = parse_auth_ok(&response_str)?;
    let client_ip = ok.client_ip;
    let server_ip = ok.server_ip;
    let prefix = ok.prefix;
    let pushed_mtu = ok.mtu;
    let dns_ip = ok.dns_ip;
    let dns_port = ok.dns_port;
    let routes_json_udp = ok.routes_json;

    let mut eff_obf = config.obfuscation.clone();
    if let Some(po) = ok.pushed_obf {
        eff_obf.padding = po.padding;
        eff_obf.heartbeat = po.heartbeat;
        eff_obf.traffic_normalization = po.traffic_normalization;
        log::info!("UDP: Applying server-pushed obfuscation params");
    }

    log::info!("UDP: Auth OK, assigned IP: {}", client_ip);
    if !routes_json_udp.is_empty() && routes_json_udp != "[]" {
        log::info!(
            "UDP: Server pushed {} route(s)",
            routes_json_udp.matches("cidr").count()
        );
    }

    let tun_setup = setup_tunnel(
        config,
        &client_ip,
        &prefix_to_netmask(prefix),
        &server_ip,
        &dns_ip,
        &dns_port,
        effective_mtu(config.tun.mtu, pushed_mtu),
    )?;
    route::apply_local_networks(
        &config.routing,
        &routes_json_udp,
        &tun_setup.if_name,
        &server_ip,
    );
    let reader_fd = tun_setup.reader_fd;
    let writer_fd = tun_setup.writer_fd;
    let tun_fd = tun_setup.tun.as_raw_fd();
    let tun_name = tun_setup.if_name;
    let is_tap = tun_setup.is_tap;
    let server_addr = config.server.address.clone();
    let tunnel_tun = tun_setup.tun;
    let tap_mac = if is_tap { generate_mac() } else { [0u8; 6] };
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
    let tun_buf_size = config.performance.tun_buffer_size;
    let norm_sizes = &eff_obf.traffic_normalization.round_sizes;

    let (tun_read_tx, mut tun_read_rx) = mpsc::channel::<Vec<u8>>(4096);

    let is_tap_reader_udp = is_tap;
    let tun_stop = Arc::new(AtomicBool::new(false));
    let tun_stop_r = tun_stop.clone();
    let tun_reader_handle = tokio::task::spawn_blocking(move || {
        let mut buf2 = vec![0u8; tun_buf_size];
        loop {
            if tun_stop_r.load(Ordering::Relaxed) {
                break;
            }
            let n = unsafe {
                libc::read(
                    reader_fd,
                    buf2.as_mut_ptr() as *mut libc::c_void,
                    buf2.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                log::error!("TUN read error: {}", err);
                break;
            }
            if n == 0 {
                break;
            }
            let raw = &buf2[..n as usize];
            let packet = if is_tap_reader_udp {
                match strip_ethernet_header(raw) {
                    Some(ip) => ip.to_vec(),
                    None => continue,
                }
            } else {
                raw.to_vec()
            };
            if tun_read_tx.blocking_send(packet).is_err() {
                break;
            }
        }
        unsafe {
            libc::close(reader_fd);
        }
        log::info!("TUN reader stopped");
    });

    // Dedicated UDP-side TUN writer thread; same pattern as the TCP-side fix.
    let is_tap_writer_udp = is_tap;
    let (tun_write_tx, tun_write_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2048);
    let _tun_writer_thread = {
        let tap_mac_w = tap_mac;
        let gateway_mac_w = gateway_mac;
        std::thread::spawn(move || {
            log::info!("UDP: TUN writer started");
            for packet in tun_write_rx {
                if packet.is_empty() {
                    continue;
                }
                unsafe {
                    if is_tap_writer_udp {
                        let frame = prepend_ethernet_header(&packet, &tap_mac_w, &gateway_mac_w);
                        libc::write(
                            writer_fd,
                            frame.as_ptr() as *const libc::c_void,
                            frame.len(),
                        );
                    } else {
                        libc::write(
                            writer_fd,
                            packet.as_ptr() as *const libc::c_void,
                            packet.len(),
                        );
                    }
                }
            }
            unsafe {
                libc::close(writer_fd);
            }
            log::info!("UDP: TUN writer stopped");
        })
    };

    let heartbeat_interval = Duration::from_millis(if heartbeat_enabled {
        hb_config.interval_ms
    } else {
        30000
    });
    let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);
    heartbeat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut idle_check = tokio::time::interval(Duration::from_secs(5));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_activity = tokio::time::Instant::now();
    // Last datagram RECEIVED from the server (RX-only) — for dead-link detection,
    // independent of our own heartbeats. (UDP has no connection state, so this is
    // the only way to notice a vanished server.)
    let mut last_rx_inst = tokio::time::Instant::now();
    let idle_timeout = Duration::from_secs(config.performance.idle_timeout_secs);
    let rx_dead = std::cmp::max(heartbeat_interval * 3, Duration::from_secs(30));

    let socket = Arc::new(socket);

    loop {
        tokio::select! {
            Some(ip_packet) = tun_read_rx.recv() => {
                last_activity = tokio::time::Instant::now();
                let encrypted = {
                    let mut obf = Obfuscator::new();
                    let mut data_with_route = ip_packet;
                    if eff_obf.traffic_normalization.enabled && !norm_sizes.is_empty() {
                        data_with_route = obf.normalize_packet_length(&data_with_route, norm_sizes);
                    }
                    // Clamp padding so the resulting datagram stays under the path
                    // MTU (avoids IP fragmentation on UDP; harmless on TCP). 60B
                    // covers record header + nonce + tag + counter + padlen + QUIC.
                    let pad_cap = {
                        let base = data_with_route.len().saturating_add(60);
                        (padding_max as usize).min(1400usize.saturating_sub(base)) as u16
                    };
                    let padding = obf.generate_padding_opts(
                        padding_enabled, padding_min, pad_cap, padding_randomize, padding_prob,
                    );
                    client_tx.encrypt_packet(&data_with_route, &padding).ok()
                };
                if let Some(pkt) = encrypted {
                    let send_data = if quic_enabled {
                        quic_pn += 1;
                        wrap_quic_short(&pkt, &connection_id, quic_pn - 1)
                    } else {
                        pkt
                    };
                    let _ = socket.send(&send_data).await;
                }
            }

            result = socket.recv(&mut recv_buf) => {
                let n = match result {
                    Ok(n) => n,
                    Err(_) => break,
                };
                last_activity = tokio::time::Instant::now();
                last_rx_inst = last_activity;
                let payload = if quic_enabled {
                    match unwrap_quic(&recv_buf[..n]) {
                        Ok(pkt) => pkt.payload,
                        Err(_) => continue,
                    }
                } else {
                    recv_buf[..n].to_vec()
                };
                match client_rx.decrypt_packet(&payload) {
                    Ok(plaintext) => {
                        if !plaintext.is_empty() {
                            // Non-blocking: a blocking send() here would stall the
                            // entire select! loop (heartbeat, RX-liveness, reads)
                            // whenever the TUN writer falls behind. Drop on a full
                            // queue — correct congestion behaviour.
                            match tun_write_tx.try_send(plaintext) {
                                Ok(()) => {}
                                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                    log::trace!("TUN write queue full — dropping inbound datagram");
                                }
                                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                            }
                        }
                    }
                    Err(e) => log::debug!("UDP decrypt error: {}", e),
                }
            }

            _ = heartbeat_tick.tick(), if heartbeat_enabled => {
                // Idle-gate: skip the beacon while real traffic is flowing.
                if last_activity.elapsed() < heartbeat_interval {
                    continue;
                }
                let jitter = if hb_config.jitter_ms > 0 {
                    let mut rng = rand::thread_rng();
                    let j = rng.gen_range(0..(hb_config.jitter_ms * 2));
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
                    client_tx.encrypt_packet(&[], &padding).ok()
                };
                if let Some(hb) = heartbeat {
                    let send_data = if quic_enabled {
                        quic_pn += 1;
                        wrap_quic_short(&hb, &connection_id, quic_pn - 1)
                    } else {
                        hb
                    };
                    let _ = socket.send(&send_data).await;
                }
                last_activity = tokio::time::Instant::now();
            }

            _ = idle_check.tick() => {
                // RX-liveness: server silent for >3 heartbeat intervals ⇒ dead ⇒
                // break to reconnect. The server heartbeats while idle, so a live
                // link always refreshes last_rx_inst.
                if heartbeat_enabled && last_rx_inst.elapsed() > rx_dead {
                    log::warn!("UDP: no data from server for >{}s — reconnecting", rx_dead.as_secs());
                    break;
                }
                if idle_timeout.as_secs() > 0 && last_activity.elapsed() > idle_timeout {
                    log::debug!("Idle timeout reached");
                    break;
                }
            }
        }
    }

    dns::restore_dns();
    tun_stop.store(true, Ordering::Relaxed); // tell the reader thread to exit
    drop(tun_read_rx);
    let _ = tun_reader_handle.await;
    // tun_write_tx dropped here, dedicated writer thread closes writer_fd
    drop(tun_write_tx);
    drop(tunnel_tun);
    unsafe {
        libc::close(tun_fd);
    }
    TunInterface::delete(&tun_name).ok();
    route::cleanup_routes(&tun_name, &server_addr).ok();
    log::info!("UDP client disconnected");
    Ok(())
}

/// Convert a CIDR prefix length (e.g. 24) to a dotted IPv4 netmask (e.g.
/// "255.255.255.0"). Out-of-range values fall back to /24 so a malformed push
/// can never produce an unusable mask.
fn prefix_to_netmask(prefix: u8) -> String {
    let p = if (1..=32).contains(&prefix) {
        prefix
    } else {
        24
    };
    let mask: u32 = if p == 32 { u32::MAX } else { !0u32 << (32 - p) };
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

/// Verify server static public key against pinned value.
/// If `pinned_hex` is Some, the received bytes must match exactly.
/// If None, print a TOFU warning with the key so the user can pin it.
fn verify_server_key(received: &[u8], pinned_hex: &Option<String>) -> anyhow::Result<()> {
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
        }
        None => {
            log::warn!(
                "⚠ Server public key not pinned. To enable MITM protection, add to client config:"
            );
            log::warn!(
                "  \"auth\": {{ \"server_public_key\": \"{}\" }}",
                received_hex
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod obf_push_tests {
    use super::*;
    use crate::config::PushedObf;

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
        let po = ok.pushed_obf.expect("obf present");
        assert_eq!(po.padding.min_bytes, 99);
        assert_eq!(po.padding.max_bytes, 777);
        assert_eq!(po.heartbeat.interval_ms, 4242);
        assert!(po.traffic_normalization.enabled);
        assert_eq!(po.traffic_normalization.round_sizes, vec![10, 20, 30]);
    }

    #[test]
    fn parse_auth_ok_rejects_non_ok_and_malformed() {
        assert!(parse_auth_ok("ERR: bad credentials").is_err()); // not an OK frame
        assert!(parse_auth_ok("OK:not json").is_err()); // malformed JSON
        assert!(parse_auth_ok(r#"OK:{"server_ip":"x"}"#).is_err()); // missing client_ip
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
}
