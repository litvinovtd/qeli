use crate::config::server::DnsConfig;
use crate::server::ServerState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};

/// (response_bytes, inserted_at, ttl), keyed by the txid-normalised query.
///
/// The TTL is PER ENTRY, taken from the record itself (S-14). It used to be one global
/// `dns.timeout_secs` for everything, which is not a caching policy at all: a record the
/// zone says is valid for 5 s was served stale for the whole timeout, and a record valid
/// for a day was re-queried just as often. `timeout_secs` is a network timeout; reusing it
/// as a cache lifetime conflated two unrelated settings.
type DnsCache = Arc<RwLock<HashMap<Vec<u8>, (Vec<u8>, Instant, Duration)>>>;

/// Floor/ceiling on a record-derived cache lifetime. The floor keeps a zone that publishes
/// TTL 0/1 from turning the cache into a no-op (and us into an amplifier of upstream
/// load); the ceiling stops a record with a week-long TTL pinning a stale answer after a
/// real IP change.
const MIN_CACHE_TTL: Duration = Duration::from_secs(5);
const MAX_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Smallest TTL across the ANSWER section, or `None` when the message carries no answers
/// (NXDOMAIN / NODATA) or is malformed.
///
/// Walks names rather than assuming a fixed offset: DNS names are label sequences that may
/// end in a compression pointer, so the record header is not at a predictable position.
/// Only the ANSWER section is read — the OPT pseudo-record in ADDITIONAL stores extended
/// flags in its TTL field, so including it would produce a nonsense lifetime.
fn answer_min_ttl(msg: &[u8]) -> Option<u32> {
    /// Advance past a (possibly compressed) name; returns the offset just after it.
    fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
        // Bounded: a malformed message must not spin here.
        for _ in 0..128 {
            let len = *msg.get(pos)?;
            if len & 0xC0 == 0xC0 {
                return pos.checked_add(2).filter(|p| *p <= msg.len()); // pointer ends the name
            }
            if len == 0 {
                return pos.checked_add(1);
            }
            pos = pos.checked_add(1 + len as usize)?;
        }
        None
    }

    if msg.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?.checked_add(4)?; // QTYPE + QCLASS
    }
    let mut min = u32::MAX;
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        if pos.checked_add(10)? > msg.len() {
            return None;
        }
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        min = min.min(ttl);
        pos = pos.checked_add(10)?.checked_add(rdlen)?;
    }
    Some(min)
}

/// Upper bound on in-flight query TASKS. The permit is taken in the accept loop
/// BEFORE spawning (see the loop below), so a flood is bounded by refusing to
/// start work rather than by parking an unbounded number of started tasks.
const MAX_INFLIGHT: usize = 512;

pub async fn run_dns_proxy(_state: Arc<ServerState>, dns_cfg: DnsConfig) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", dns_cfg.listen, dns_cfg.port);
    // Shared listen socket: query tasks send their answers back through it.
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    log::info!("DNS proxy listening on {}", bind_addr);

    let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
    let cfg = Arc::new(dns_cfg);
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    // Count of queries refused because the in-flight gate was full (for rate-limited logging).
    let dropped = Arc::new(AtomicU64::new(0));
    // Preferred upstream index (best-effort: updated to the last resolver that
    // answered, so a dead first resolver isn't retried first every time).
    let pref = Arc::new(AtomicUsize::new(0));

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // A transient recv error must not tear down the whole DNS proxy for the
                // profile (mirrors the UDP data-plane worker's log-and-continue).
                log::warn!("DNS proxy recv error: {} — continuing", e);
                continue;
            }
        };
        // A valid DNS message has at least the 12-byte header.
        if n < 12 {
            continue;
        }
        // Take the in-flight permit HERE, before spawning. Acquiring it inside the task
        // (as this did) bounds only the upstream work: the spawn itself always succeeds,
        // so a flood piles up an unbounded number of tasks, each parked on the semaphore
        // while holding its own copy of the datagram — memory grows without limit even
        // though "in-flight" looks capped. Refusing to start the task is the actual bound;
        // a dropped UDP query is retried by the client, an OOM is not. (S-02)
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                // Rate-limited: under a flood this fires on every packet otherwise.
                let n = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 1000 == 1 {
                    log::warn!(
                        "DNS proxy: {} in-flight queries — dropping (total dropped: {})",
                        MAX_INFLIGHT,
                        n
                    );
                }
                continue;
            }
        };
        let query = buf[..n].to_vec();
        // Each query is handled on its own task so a slow/unreachable upstream
        // can't stall every other client's lookup (the old single-socket loop
        // blocked the whole proxy on each query — head-of-line blocking).
        let socket = socket.clone();
        let cache = cache.clone();
        let cfg = cfg.clone();
        let pref = pref.clone();
        tokio::spawn(async move {
            handle_query(socket, cache, cfg, permit, pref, query, src).await;
        });
    }
}

/// One DNS query over TCP (RFC 1035 §4.2.2: each message is prefixed with its 2-byte
/// big-endian length). Used both when `dns.upstream_protocol = tcp` and as the retry
/// path when a UDP answer comes back truncated. Returns the raw response message, or
/// `None` on any timeout/IO/protocol error — the caller then falls back. (S-14)
///
/// The whole exchange shares one deadline, so a resolver that accepts the connection and
/// then stalls cannot hold the task (and its in-flight permit) open.
async fn query_tcp(addr: &str, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let deadline = tokio::time::Instant::now() + timeout;
    let remaining =
        |d: tokio::time::Instant| d.saturating_duration_since(tokio::time::Instant::now());

    let mut stream =
        match tokio::time::timeout(remaining(deadline), tokio::net::TcpStream::connect(addr)).await
        {
            Ok(Ok(s)) => s,
            _ => return None,
        };

    // Length-prefixed request.
    let len = u16::try_from(query.len()).ok()?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    if tokio::time::timeout(remaining(deadline), stream.write_all(&framed))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }

    // Length-prefixed response. The 2-byte prefix is what makes the >512-byte answers
    // that triggered the TCP retry readable in the first place.
    let mut len_buf = [0u8; 2];
    if tokio::time::timeout(remaining(deadline), stream.read_exact(&mut len_buf))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len < 12 {
        return None; // shorter than a DNS header — not a usable message
    }
    let mut resp = vec![0u8; resp_len];
    if tokio::time::timeout(remaining(deadline), stream.read_exact(&mut resp))
        .await
        .ok()?
        .is_err()
    {
        return None;
    }
    Some(resp)
}

#[allow(clippy::too_many_arguments)]
async fn handle_query(
    socket: Arc<UdpSocket>,
    cache: DnsCache,
    cfg: Arc<DnsConfig>,
    // Held for the whole task and released on return — the caller acquired it before
    // spawning us, so the number of live tasks is what MAX_INFLIGHT actually bounds. (S-02)
    _permit: OwnedSemaphorePermit,
    pref: Arc<AtomicUsize>,
    query: Vec<u8>,
    src: SocketAddr,
) {
    let query_txid = [query[0], query[1]];

    if is_blocked(&query, &cfg.blocklist) {
        let mut nxdomain = query.clone();
        nxdomain[2] = 0x81;
        nxdomain[3] = 0x83;
        let _ = socket.send_to(&nxdomain, src).await;
        return;
    }

    // Cache key ignores the per-query transaction ID (bytes 0..2) so the same
    // question shares one entry regardless of txid.
    let mut cache_key = query.clone();
    cache_key[0] = 0;
    cache_key[1] = 0;

    let ttl = Duration::from_secs(cfg.timeout_secs);
    let cached = {
        let cache_read = cache.read().await;
        cache_read
            .get(&cache_key)
            .and_then(|(resp, time, entry_ttl)| {
                // Per-entry lifetime from the record, not the global network timeout. (S-14)
                if time.elapsed() < *entry_ttl {
                    Some(resp.clone())
                } else {
                    None
                }
            })
    };
    if let Some(mut response) = cached {
        if response.len() >= 2 {
            response[0] = query_txid[0];
            response[1] = query_txid[1];
        }
        let _ = socket.send_to(&response, src).await;
        return;
    }

    let upstreams = &cfg.upstream;
    if upstreams.is_empty() {
        return;
    }

    // (The in-flight permit is already held — acquired by the accept loop before spawn.)
    // A fresh ephemeral socket per query: no cross-query demux, so one slow
    // resolver only delays its own task.
    let upstream_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("DNS: cannot open upstream socket: {}", e);
            return;
        }
    };

    // `dns.upstream_protocol` was parsed, serialized back out and shown in the panel, but
    // NOTHING read it — every query went out over UDP regardless. An operator who set
    // `tcp` (e.g. because the network mangles UDP/53) got silent UDP anyway. (S-14)
    let force_tcp = cfg.upstream_protocol.eq_ignore_ascii_case("tcp");

    let start = pref.load(Ordering::Relaxed) % upstreams.len();
    let mut response = None;
    for attempt in 0..upstreams.len() {
        let idx = (start + attempt) % upstreams.len();
        let upstream_addr = format!("{}:53", upstreams[idx]);
        let upstream_ip = match upstream_addr.parse::<SocketAddr>() {
            Ok(sa) => sa.ip(),
            Err(_) => continue,
        };
        if force_tcp {
            if let Some(full) = query_tcp(&upstream_addr, &query, ttl).await {
                // Same anti-spoof txid check as the UDP path (TCP is connection-bound, so
                // the source is implicitly the resolver we dialled).
                if full.len() >= 12 && full[0] == query_txid[0] && full[1] == query_txid[1] {
                    response = Some(full);
                    pref.store(idx, Ordering::Relaxed);
                    break;
                }
            }
            continue;
        }
        if upstream_sock.send_to(&query, &upstream_addr).await.is_err() {
            continue;
        }
        // Accept only a reply that (a) came from the resolver we queried and (b)
        // carries the matching transaction ID — otherwise an off-/on-path spoof
        // could poison the cache. Bound the total wait by the configured timeout.
        let deadline = tokio::time::Instant::now() + ttl;
        // 4 KiB, not 1500: with EDNS0 the client can advertise a larger UDP payload and the
        // resolver will use it. `recv_from` DISCARDS whatever does not fit the buffer, so a
        // 1500-byte buffer silently chopped such a reply and forwarded a malformed answer —
        // no error anywhere, just a broken lookup. 4096 covers the common advertisements
        // (1232/4096); anything beyond still arrives truncated at the DNS level and is
        // handled by the TC path above. (S-14)
        let mut resp_buf = vec![0u8; 4096];
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, upstream_sock.recv_from(&mut resp_buf)).await {
                Ok(Ok((m, from))) => {
                    if from.ip() != upstream_ip {
                        continue; // not from the queried resolver — ignore
                    }
                    if m < 12 || resp_buf[0] != query_txid[0] || resp_buf[1] != query_txid[1] {
                        continue; // wrong/short txid — spoof or stale, ignore
                    }
                    // TC (TRUNCATED, bit 1 of byte 2): the answer did not fit in a UDP
                    // datagram and the resolver sent a stub. Forwarding it as-is made the
                    // client see an empty/partial answer set — the classic "big TXT or
                    // DNSSEC record silently resolves to nothing". RFC 1035 §4.2.1 says to
                    // retry over TCP; nothing here did. (S-14)
                    if resp_buf[2] & 0x02 != 0 {
                        log::debug!(
                            "DNS: truncated reply from {} — retrying over TCP",
                            upstream_ip
                        );
                        if let Some(full) = query_tcp(&upstream_addr, &query, ttl).await {
                            response = Some(full);
                            pref.store(idx, Ordering::Relaxed);
                            break;
                        }
                        // TCP retry failed — fall through and use the truncated answer
                        // rather than nothing (a stub reply still carries the header flags).
                    }
                    response = Some(resp_buf[..m].to_vec());
                    pref.store(idx, Ordering::Relaxed);
                    break;
                }
                _ => break, // timeout or socket error → try next upstream
            }
        }
        if response.is_some() {
            break;
        }
    }

    if let Some(resp) = response {
        let _ = socket.send_to(&resp, src).await;

        // Cache lifetime from the record itself, clamped. A TTL of 0 means "do not cache"
        // (RFC 2181 §8) and is honoured by skipping the insert entirely — it is used for
        // things like round-robin load balancing, where caching defeats the point. With no
        // ANSWER section (NXDOMAIN/NODATA) there is no record TTL to read; those fall back
        // to the configured timeout rather than being cached indefinitely. (S-14)
        let entry_ttl = match answer_min_ttl(&resp) {
            Some(0) => {
                return; // uncacheable by policy — already sent to the client
            }
            Some(secs) => Duration::from_secs(secs as u64).clamp(MIN_CACHE_TTL, MAX_CACHE_TTL),
            None => ttl,
        };

        let mut cache_write = cache.write().await;
        if cache_write.len() >= cfg.cache_size {
            // Drop expired entries first (cheap win). If the cache is still full of
            // FRESH entries, evict a batch of arbitrary keys so we make real room —
            // otherwise every insert at steady-state saturation would re-scan the
            // whole map (O(n)) and free nothing, stalling all DNS tasks. Batching
            // amortizes the scan over ~cache_size/10 inserts.
            let now = Instant::now();
            cache_write.retain(|_, (_, time, entry_ttl)| now.duration_since(*time) < *entry_ttl);
            if cache_write.len() >= cfg.cache_size {
                let evict = (cfg.cache_size / 10).max(1);
                let victims: Vec<_> = cache_write.keys().take(evict).cloned().collect();
                for k in victims {
                    cache_write.remove(&k);
                }
            }
        }
        if cache_write.len() < cfg.cache_size {
            cache_write.insert(cache_key, (resp, Instant::now(), entry_ttl));
        }
    }
}

fn is_blocked(query: &[u8], blocklist: &[String]) -> bool {
    if blocklist.is_empty() || query.len() < 12 {
        return false;
    }

    let mut labels = Vec::new();
    let mut pos = 12;

    while pos < query.len() {
        let label_len = query[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len <= query.len() {
            if let Ok(label) = std::str::from_utf8(&query[pos..pos + label_len]) {
                labels.push(label.to_string());
            }
        }
        pos += label_len;
    }

    let domain = labels.join(".").to_lowercase();
    blocklist.iter().any(|blocked| {
        let blocked_lower = blocked.to_lowercase();
        domain == blocked_lower || domain.ends_with(&format!(".{}", blocked_lower))
    })
}

#[cfg(test)]
mod tests {
    //! Coverage for the answer-TTL parser (S-14). It walks attacker-influenced bytes —
    //! an upstream reply is untrusted input — so the cases that matter are the malformed
    //! ones: it must return None, never panic or loop.
    use super::*;

    /// Build a minimal DNS response: one question, `answers` A-records with the given TTLs.
    fn response(ttls: &[u32], compressed_names: bool) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[0] = 0xAB;
        m[1] = 0xCD; // txid
        m[2] = 0x81;
        m[3] = 0x80; // response, no error
        m[4] = 0;
        m[5] = 1; // QDCOUNT = 1
        m[6] = 0;
        m[7] = ttls.len() as u8; // ANCOUNT
                                 // Question: "example.com" A IN
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        for ttl in ttls {
            if compressed_names {
                m.extend_from_slice(&[0xC0, 0x0C]); // pointer back to the question name
            } else {
                m.extend_from_slice(&[7]);
                m.extend_from_slice(b"example");
                m.extend_from_slice(&[3]);
                m.extend_from_slice(b"com");
                m.push(0);
            }
            m.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A, CLASS=IN
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]); // RDLENGTH
            m.extend_from_slice(&[93, 184, 216, 34]); // RDATA
        }
        m
    }

    #[test]
    fn reads_the_smallest_answer_ttl() {
        assert_eq!(answer_min_ttl(&response(&[300], false)), Some(300));
        assert_eq!(answer_min_ttl(&response(&[300, 60, 900], false)), Some(60));
    }

    #[test]
    fn follows_compressed_names() {
        // The common real-world shape: answers point back at the question's name.
        assert_eq!(answer_min_ttl(&response(&[120, 45], true)), Some(45));
    }

    #[test]
    fn no_answers_yields_none() {
        // NXDOMAIN / NODATA — nothing to derive a lifetime from.
        assert_eq!(answer_min_ttl(&response(&[], false)), None);
    }

    #[test]
    fn malformed_input_never_panics() {
        // Truncated at every possible length: each must be rejected, not crash.
        let full = response(&[300, 60], true);
        for cut in 0..full.len() {
            let _ = answer_min_ttl(&full[..cut]);
        }
        // Header claims answers that are not there.
        let mut lying = response(&[300], false);
        lying[7] = 200;
        assert_eq!(answer_min_ttl(&lying), None);
        // A name length that runs past the buffer.
        let mut runaway = response(&[300], false);
        let qname = 12;
        runaway[qname] = 0xFF;
        assert_eq!(answer_min_ttl(&runaway), None);
        // Compression pointer loop: must terminate (the pointer is not followed, so this
        // is really a check that a pointer always ends the name walk).
        let mut looped = response(&[300], true);
        looped[12] = 0xC0;
        looped[13] = 0x0C;
        let _ = answer_min_ttl(&looped);
        assert_eq!(answer_min_ttl(&[]), None);
        assert_eq!(answer_min_ttl(&[0u8; 11]), None);
    }

    #[test]
    fn ttl_zero_is_distinguishable() {
        // Some(0) must survive to the caller so it can skip caching entirely.
        assert_eq!(answer_min_ttl(&response(&[0], false)), Some(0));
    }
}
