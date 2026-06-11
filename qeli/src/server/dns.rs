use crate::config::server::DnsConfig;
use crate::server::ServerState;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, Semaphore};

/// (response_bytes, inserted_at), keyed by the txid-normalised query.
type DnsCache = Arc<RwLock<HashMap<Vec<u8>, (Vec<u8>, Instant)>>>;

/// Upper bound on in-flight upstream queries. Each query that misses the cache
/// holds one permit while it waits for the resolver, so a flood (or a slow
/// upstream) is bounded instead of spawning unboundedly.
const MAX_INFLIGHT: usize = 512;

pub async fn run_dns_proxy(_state: Arc<ServerState>, dns_cfg: DnsConfig) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", dns_cfg.listen, dns_cfg.port);
    // Shared listen socket: query tasks send their answers back through it.
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    log::info!("DNS proxy listening on {}", bind_addr);

    let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
    let cfg = Arc::new(dns_cfg);
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    // Preferred upstream index (best-effort: updated to the last resolver that
    // answered, so a dead first resolver isn't retried first every time).
    let pref = Arc::new(AtomicUsize::new(0));

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        // A valid DNS message has at least the 12-byte header.
        if n < 12 {
            continue;
        }
        let query = buf[..n].to_vec();
        // Each query is handled on its own task so a slow/unreachable upstream
        // can't stall every other client's lookup (the old single-socket loop
        // blocked the whole proxy on each query — head-of-line blocking).
        let socket = socket.clone();
        let cache = cache.clone();
        let cfg = cfg.clone();
        let sem = sem.clone();
        let pref = pref.clone();
        tokio::spawn(async move {
            handle_query(socket, cache, cfg, sem, pref, query, src).await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_query(
    socket: Arc<UdpSocket>,
    cache: DnsCache,
    cfg: Arc<DnsConfig>,
    sem: Arc<Semaphore>,
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
        cache_read.get(&cache_key).and_then(|(resp, time)| {
            if time.elapsed() < ttl {
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

    // Bound concurrent upstream work; drop the query if the gate is closed.
    let _permit = match sem.acquire().await {
        Ok(p) => p,
        Err(_) => return,
    };
    // A fresh ephemeral socket per query: no cross-query demux, so one slow
    // resolver only delays its own task.
    let upstream_sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            log::debug!("DNS: cannot open upstream socket: {}", e);
            return;
        }
    };

    let start = pref.load(Ordering::Relaxed) % upstreams.len();
    let mut response = None;
    for attempt in 0..upstreams.len() {
        let idx = (start + attempt) % upstreams.len();
        let upstream_addr = format!("{}:53", upstreams[idx]);
        let upstream_ip = match upstream_addr.parse::<SocketAddr>() {
            Ok(sa) => sa.ip(),
            Err(_) => continue,
        };
        if upstream_sock.send_to(&query, &upstream_addr).await.is_err() {
            continue;
        }
        // Accept only a reply that (a) came from the resolver we queried and (b)
        // carries the matching transaction ID — otherwise an off-/on-path spoof
        // could poison the cache. Bound the total wait by the configured timeout.
        let deadline = tokio::time::Instant::now() + ttl;
        let mut resp_buf = vec![0u8; 1500];
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
        let mut cache_write = cache.write().await;
        if cache_write.len() >= cfg.cache_size {
            let now = Instant::now();
            cache_write.retain(|_, (_, time)| now.duration_since(*time) < ttl);
        }
        if cache_write.len() < cfg.cache_size {
            cache_write.insert(cache_key, (resp, Instant::now()));
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
