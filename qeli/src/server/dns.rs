use crate::config::server::DnsConfig;
use crate::server::ServerState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub async fn run_dns_proxy(_state: Arc<ServerState>, dns_cfg: DnsConfig) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", dns_cfg.listen, dns_cfg.port);
    let socket = UdpSocket::bind(&bind_addr).await?;
    log::info!("DNS proxy listening on {}", bind_addr);

    // (response_bytes, inserted_at), keyed by the txid-normalised query.
    type DnsCache = Arc<RwLock<HashMap<Vec<u8>, (Vec<u8>, std::time::Instant)>>>;
    let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));
    let max_cache = dns_cfg.cache_size;
    let timeout = dns_cfg.timeout_secs;

    let upstream_sock = UdpSocket::bind("0.0.0.0:0").await?;
    let mut upstream_idx = 0usize;

    let mut buf = vec![0u8; 1500];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        // A valid DNS message has at least the 12-byte header. Anything shorter
        // can't be parsed and would index-panic below.
        if n < 12 {
            continue;
        }
        let query = buf[..n].to_vec();
        let query_txid = [query[0], query[1]];

        if is_blocked(&query, &dns_cfg.blocklist) {
            let mut nxdomain = query.clone();
            nxdomain[2] = 0x81;
            nxdomain[3] = 0x83;
            let _ = socket.send_to(&nxdomain, src).await;
            continue;
        }

        // Cache key ignores the per-query transaction ID (bytes 0..2) so the
        // same question shares one entry regardless of txid — otherwise every
        // query has a fresh random txid and the cache never hits.
        let mut cache_key = query.clone();
        cache_key[0] = 0;
        cache_key[1] = 0;

        let cached = {
            let cache_read = cache.read().await;
            cache_read.get(&cache_key).and_then(|(resp, time)| {
                if time.elapsed() < std::time::Duration::from_secs(timeout) {
                    Some(resp.clone())
                } else {
                    None
                }
            })
        };

        if let Some(mut response) = cached {
            // Restore the caller's transaction ID on the cached answer.
            if response.len() >= 2 {
                response[0] = query_txid[0];
                response[1] = query_txid[1];
            }
            let _ = socket.send_to(&response, src).await;
            continue;
        }

        let upstreams = &dns_cfg.upstream;
        if upstreams.is_empty() {
            continue;
        }
        let mut response = None;
        for attempt in 0..upstreams.len() {
            let idx = (upstream_idx + attempt) % upstreams.len();
            let upstream_addr = format!("{}:53", upstreams[idx]);
            // Resolve once so we can match the response source address.
            let upstream_ip = match upstream_addr.parse::<std::net::SocketAddr>() {
                Ok(sa) => sa.ip(),
                Err(_) => continue,
            };
            if upstream_sock.send_to(&query, &upstream_addr).await.is_err() {
                continue;
            }
            // The upstream socket faces the public internet. Accept only a reply
            // that (a) came from the upstream we actually queried and (b) carries
            // the matching transaction ID. Without these checks an off-path or
            // on-path attacker could inject a spoofed answer that we'd forward to
            // the client and poison the cache with. Bound the total wait to the
            // configured timeout even under a spoof flood by tracking a deadline.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
            let mut resp_buf = vec![0u8; 1500];
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, upstream_sock.recv_from(&mut resp_buf)).await
                {
                    Ok(Ok((m, from))) => {
                        if from.ip() != upstream_ip {
                            continue; // not from the queried resolver — ignore
                        }
                        if m < 12 || resp_buf[0] != query_txid[0] || resp_buf[1] != query_txid[1] {
                            continue; // wrong/short txid — spoof or stale, ignore
                        }
                        response = Some(resp_buf[..m].to_vec());
                        upstream_idx = idx;
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
            if cache_write.len() >= max_cache {
                let timeout_dur = std::time::Duration::from_secs(timeout);
                let now = std::time::Instant::now();
                cache_write.retain(|_, (_, time)| now.duration_since(*time) < timeout_dur);
            }
            if cache_write.len() < max_cache {
                cache_write.insert(cache_key, (resp, std::time::Instant::now()));
            }
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
