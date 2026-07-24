use crate::crypto::{reality, PublicKey};
use crate::protocol::FakeTlsHandshake;
use crate::server::handler;
use crate::server::{ProfileRuntime, ServerState};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Acceptance window for the REALITY session_id timestamp (anti-replay). The
/// replay guard remembers accepted tokens for twice this long (see
/// `ProfileRuntime::reality_replay`), covering a token's full ±window validity.
pub(crate) const REALITY_WINDOW_SECS: u64 = 120;

/// Bounds on the decoy bridge. This path is reachable by ANY unauthenticated peer —
/// every probe that fails the REALITY check gets proxied to the cover site — so
/// without them one peer can park a socket here (plus a backend socket) forever and
/// exhaust the server's fd budget for free. The camouflage still works: a real prober
/// finishes in milliseconds; only connections that go silent or run absurdly long are
/// cut. (S-01)
const BRIDGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const BRIDGE_MAX_LIFETIME: Duration = Duration::from_secs(600);

/// The decoy bridges' own admission budget, separate from the handshake gate. (Р4)
#[derive(Clone)]
pub struct DecoyGate {
    pub sem: Arc<tokio::sync::Semaphore>,
    pub refused: Arc<std::sync::atomic::AtomicU64>,
}

impl DecoyGate {
    /// Swap a pre-auth permit for a decoy permit: this connection is no longer a
    /// prospective client, so it must stop occupying a handshake slot. Returns `None` when
    /// the decoy budget is exhausted — the caller then drops the connection instead of
    /// bridging, which is what a firewalled host would look like anyway.
    ///
    /// Order matters: acquire first, release second. Releasing first would briefly free a
    /// handshake slot that a flood could immediately take.
    fn take_over(
        &self,
        pre_auth: Option<tokio::sync::OwnedSemaphorePermit>,
        addr: std::net::SocketAddr,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.sem.clone().try_acquire_owned() {
            Ok(p) => {
                drop(pre_auth); // hand the handshake slot back
                Some(p)
            }
            Err(_) => {
                let n = self
                    .refused
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                if n % 100 == 1 {
                    log::warn!(
                        "REALITY: decoy budget full — dropping probe from {} without bridging \
                         (total dropped: {})",
                        addr,
                        n
                    );
                }
                None
            }
        }
    }
}

pub async fn handle_connection(
    server_state: Arc<ServerState>,
    profile: Arc<ProfileRuntime>,
    stream: TcpStream,
    addr: std::net::SocketAddr,
    tun_tx: mpsc::Sender<Vec<u8>>,
    // Pre-auth admission permit (see the accept loop). Passed to `handle_client`, which
    // releases it once the peer authenticates. (S-01)
    pre_auth_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    // Budget for connections that turn out NOT to be qeli clients. A bridge can live for
    // BRIDGE_MAX_LIFETIME, so charging it to the handshake gate let a scan starve real
    // clients; it is charged here instead. (Р4)
    decoy_gate: DecoyGate,
) -> anyhow::Result<()> {
    let pcfg = &profile.config;
    let target = format!(
        "{}:{}",
        pcfg.obfuscation.tls.reality_proxy.target, pcfg.obfuscation.tls.reality_proxy.target_port,
    );

    // Clamp so a 0 (a Default-constructed config, or a misconfigured 0) can't give
    // recv_peek an already-expired deadline that instant-bridges every client.
    let peek_ms = pcfg.obfuscation.tls.reality_proxy.peek_timeout_ms.max(300);
    let header = match tokio::time::timeout(
        Duration::from_millis(peek_ms + 300),
        recv_peek(&stream, 6, peek_ms),
    )
    .await
    {
        Ok(Ok(h)) if h.len() >= 6 => h,
        _ => {
            // Not a qeli client — stop holding a handshake slot and charge the bridge to the
            // decoy budget instead. No budget left => drop without bridging. (Р4)
            let Some(_decoy) = decoy_gate.take_over(pre_auth_permit, addr) else {
                return Ok(());
            };
            return bridge_to_target(stream, &target).await;
        }
    };

    if header[0] != 0x16 || header[5] != 0x01 {
        // Not even a TLS ClientHello — same swap as the other decoy paths. (Р4)
        let Some(_decoy) = decoy_gate.take_over(pre_auth_permit, addr) else {
            return Ok(());
        };
        return bridge_to_target(stream, &target).await;
    }

    let record_len = ((header[3] as usize) << 8) | header[4] as usize;
    // Peek the whole ClientHello: with the PQ key_share the realtls hello is ~1.5 KB
    // and the x25519 key_share the REALITY token check needs sits *after* the
    // 1216-byte X25519MLKEM768 entry — a small cap would truncate it and the token
    // would never authenticate (client would be wrongly bridged).
    let peek_total = 5 + record_len.min(16384);

    let full = match tokio::time::timeout(
        Duration::from_millis(peek_ms + 300),
        recv_peek(&stream, peek_total, peek_ms),
    )
    .await
    {
        Ok(Ok(f)) if f.len() >= 5 => f,
        _ => {
            // Not a qeli client — stop holding a handshake slot and charge the bridge to the
            // decoy budget instead. No budget left => drop without bridging. (Р4)
            let Some(_decoy) = decoy_gate.take_over(pre_auth_permit, addr) else {
                return Ok(());
            };
            return bridge_to_target(stream, &target).await;
        }
    };

    // Discriminate qeli clients. When `short_ids` is configured (REALITY proper),
    // require a valid crypto token in the ClientHello session_id; otherwise fall
    // back to the legacy "no ALPN" heuristic. Non-qeli → transparently proxy to the
    // real dest (active-probe defence).
    let short_ids = &pcfg.obfuscation.tls.reality_proxy.short_ids;
    let is_qeli = if short_ids.is_empty() {
        !has_alpn_extension(&full)
    } else {
        match authenticate_reality(&full, &profile, short_ids) {
            // Anti-replay: a ClientHello captured off the wire and replayed
            // verbatim within the acceptance window would re-authenticate here and
            // betray the server — it would terminate TLS (with a ServerHello that
            // does not match `dest`) where a real host just relays the target. A
            // token we have already accepted is therefore treated as a probe and
            // bridged like any stranger. Honest clients never collide: every
            // connection seals a fresh ephemeral, so two genuine ClientHellos —
            // even same short_id, same second — carry different session_ids.
            Some(session_id) => {
                let fresh = profile.reality_replay.lock().await.observe(&session_id);
                if !fresh {
                    log::warn!(
                        "REALITY: replayed session_id from {} on profile '{}' — bridging as probe",
                        addr,
                        profile.name
                    );
                }
                fresh
            }
            None => false,
        }
    };

    if is_qeli {
        log::info!(
            "REALITY: Qeli client detected from {} on profile '{}'",
            addr,
            profile.name
        );
        let pname = profile.name.clone();
        let r = if pcfg.obfuscation.tls.reality_proxy.real_tls {
            if pcfg.obfuscation.tls.reality_proxy.handrolled {
                // Hand-rolled byte-grade TLS 1.3 (L3, borrowed-ServerHello path):
                // mirror the shape probed from `target` at profile start (cipher, PQ
                // group, extension order) so the ServerHello's JA3S matches whatever
                // target is configured. The ClientHello is still in the socket (peek
                // did not consume it). Requires clients on the realtls stack.
                // Snapshot the borrowed shape + cert (cloned out so the lock is not
                // held across the await — the refresh task may update it concurrently).
                let (borrow, cert) = match &profile.reality_borrow {
                    Some(state) => {
                        // Recover a poisoned lock instead of panicking, mirroring
                        // lock_or_recover used for the session mutexes (T6). Under
                        // panic=abort this branch is moot, but it keeps the pattern
                        // uniform and stays correct if the panic strategy changes.
                        let g = state.read().unwrap_or_else(|e| e.into_inner());
                        (g.profile, g.cert.clone())
                    }
                    None => (Default::default(), None),
                };
                let tls = crate::protocol::realtls::server::terminate_handrolled(
                    stream,
                    crate::crypto::Keypair::generate(),
                    borrow,
                    cert.as_deref(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("REALITY hand-rolled TLS termination failed: {}", e)
                })?;
                log::debug!(
                    "REALITY: hand-rolled TLS established with {} — tunnel inside",
                    addr
                );
                handler::handle_client(server_state, profile, tls, addr, tun_tx, pre_auth_permit)
                    .await
            } else {
                // Terminate a genuine TLS 1.3 session (rustls) and run the tunnel
                // inside it. The rustls config (incl. the cert) is built once at
                // profile start and cached on the profile.
                let tls_config = match &profile.reality_tls_config {
                    Some(c) => c.clone(),
                    None => crate::protocol::realtls::server::make_server_config(
                        &pcfg.obfuscation.tls.reality_proxy.target,
                    ),
                };
                let tls =
                    crate::protocol::realtls::server::terminate(Vec::new(), stream, tls_config)
                        .await
                        .map_err(|e| anyhow::anyhow!("REALITY TLS termination failed: {}", e))?;
                log::debug!(
                    "REALITY: real TLS established with {} — tunnel inside",
                    addr
                );
                handler::handle_client(server_state, profile, tls, addr, tun_tx, pre_auth_permit)
                    .await
            }
        } else {
            handler::handle_client(server_state, profile, stream, addr, tun_tx, pre_auth_permit)
                .await
        };
        // A client that passed the reality discriminator but then failed the INNER
        // qeli handshake/session is a real problem (config / version / native-core
        // mismatch), not prober noise — surface it at warn so it's visible at the
        // default log level instead of being lost among debug bridge lines.
        if let Err(e) = &r {
            log::warn!(
                "REALITY: Qeli client {} on profile '{}' failed after the handshake \
                 discriminator (likely config/version/core mismatch): {}",
                addr,
                pname,
                e
            );
        }
        r
    } else {
        log::debug!(
            "REALITY: bridging non-Qeli connection from {} to {}",
            addr,
            target
        );
        let Some(_decoy) = decoy_gate.take_over(pre_auth_permit, addr) else {
            return Ok(());
        };
        bridge_to_target(stream, &target).await
    }
}

/// REALITY crypto-auth: recover the session_id + key_share from the (peeked)
/// ClientHello, open the session_id with this profile's identity (REALITY) key,
/// and accept iff the embedded short_id is allow-listed. Returns the validated
/// 32-byte session_id (the replay guard keys on it) on success, `None` otherwise.
fn authenticate_reality(
    full: &[u8],
    profile: &ProfileRuntime,
    short_ids: &[String],
) -> Option<[u8; 32]> {
    let (session_id, key_share) = FakeTlsHandshake::parse_client_hello_full(full)?;
    let eph = <[u8; 32]>::try_from(key_share.as_slice()).ok()?;
    let got = reality::open_session_id(
        &profile.static_keypair,
        &PublicKey::from_bytes(&eph),
        &session_id,
        REALITY_WINDOW_SECS,
    )?;
    short_ids
        .iter()
        .any(|h| reality::short_id_from_hex(h) == got)
        .then_some(session_id)
}

/// `tokio::io::copy` with an idle timeout: a direction that delivers no bytes at all
/// for `idle` is torn down. Plain `io::copy` waits forever, which is what let a silent
/// peer pin the bridge open. (S-01)
async fn copy_until_idle<R, W>(mut r: R, mut w: W, idle: Duration) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match tokio::time::timeout(idle, r.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()), // clean EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "decoy bridge idle timeout",
                ))
            }
        };
        w.write_all(&buf[..n]).await?;
    }
}

async fn bridge_to_target(inbound: TcpStream, target: &str) -> anyhow::Result<()> {
    // An unreachable/blackholed cover site must not hold the inbound socket while the
    // TCP connect runs to the kernel's full SYN-retry budget (~2 min). (S-01)
    let outbound =
        match tokio::time::timeout(BRIDGE_CONNECT_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::warn!("REALITY: failed to connect to backend {}: {}", target, e);
                return Err(e.into());
            }
            Err(_) => {
                log::warn!(
                    "REALITY: connecting to backend {} timed out after {:?}",
                    target,
                    BRIDGE_CONNECT_TIMEOUT
                );
                return Err(anyhow::anyhow!("decoy backend connect timed out"));
            }
        };

    let _ = outbound.set_nodelay(true);
    let _ = inbound.set_nodelay(true);

    let (ri, wi) = tokio::io::split(inbound);
    let (ro, wo) = tokio::io::split(outbound);

    let fwd = copy_until_idle(ri, wo, BRIDGE_IDLE_TIMEOUT);
    let rev = copy_until_idle(ro, wi, BRIDGE_IDLE_TIMEOUT);

    let bridged = async {
        tokio::select! {
            r = fwd => r,
            r = rev => r,
        }
    };

    // Absolute cap on top of the idle timeout: a peer that dribbles one byte per
    // minute stays under the idle bound indefinitely otherwise.
    match tokio::time::timeout(BRIDGE_MAX_LIFETIME, bridged).await {
        Ok(r) => r.map_err(Into::into),
        Err(_) => {
            log::debug!("REALITY: decoy bridge to {} hit the lifetime cap", target);
            Ok(())
        }
    }
}

fn has_alpn_extension(data: &[u8]) -> bool {
    if data.len() < 43 {
        return false;
    }
    if data[5] != 0x01 {
        return false;
    }
    let mut off = 43;
    if off >= data.len() {
        return false;
    }
    let sid_len = data[off] as usize;
    off += 1 + sid_len;
    if off + 2 > data.len() {
        return false;
    }
    let cs_len = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2 + cs_len;
    if off + 1 > data.len() {
        return false;
    }
    let comp_len = data[off] as usize;
    off += 1 + comp_len;
    if off + 2 > data.len() {
        return false;
    }
    let ext_total = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    off += 2;
    let mut ext_end = off + ext_total;
    if ext_end > data.len() {
        ext_end = data.len();
    }
    while off + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[off], data[off + 1]]);
        let ext_len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if ext_type == 0x0010 {
            return true;
        }
        off += 4 + ext_len;
    }
    false
}

async fn recv_peek(stream: &TcpStream, len: usize, budget_ms: u64) -> std::io::Result<Vec<u8>> {
    // The ClientHello can span several TCP segments; `peek` does not consume, so
    // poll until the whole requested window is buffered. The budget is a TIME
    // window, not a fixed iteration count: a ClientHello that arrives in many
    // tiny segments must not exhaust the loop and leave us with a truncated
    // buffer — that would fail the REALITY token check and wrongly bridge a
    // legitimate client to the decoy. We keep waiting as long as bytes keep
    // arriving, and only give up after a short no-progress stall or the overall
    // budget (the callers also wrap this in their own outer timeout).
    let mut buf = vec![0u8; len];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(budget_ms);
    let stall = Duration::from_millis((budget_ms / 5).max(100));
    let mut last = 0usize;
    let mut last_progress = tokio::time::Instant::now();
    loop {
        let n = stream.peek(&mut buf).await?;
        if n >= len {
            buf.truncate(n);
            return Ok(buf);
        }
        let now = tokio::time::Instant::now();
        if n > last {
            last = n;
            last_progress = now;
        }
        // Peer stopped sending mid-ClientHello, or the budget is exhausted →
        // return what we have and let the caller decide (it will bridge).
        if now >= deadline || now.duration_since(last_progress) >= stall {
            buf.truncate(n);
            return Ok(buf);
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// recv_peek must reassemble a window delivered in many small TCP segments —
    /// regression for the old fixed-iteration loop that could return a truncated
    /// ClientHello and wrongly bridge a legitimate REALITY client to the decoy.
    #[tokio::test]
    async fn recv_peek_reassembles_segmented_window() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let payload_w = payload.clone();
        let writer = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // Dribble the window out in 10-byte segments with a small gap each,
            // so it spans far more than the old 40-iteration budget would survive.
            for chunk in payload_w.chunks(10) {
                s.write_all(chunk).await.unwrap();
                s.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            // Hold the connection open so peek can still observe the buffered bytes.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let (server, _) = listener.accept().await.unwrap();
        let got = recv_peek(&server, payload.len(), 1500).await.unwrap();
        assert_eq!(got, payload, "recv_peek must reassemble every segment");
        writer.await.unwrap();
    }
}
