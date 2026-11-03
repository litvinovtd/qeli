//! Profile DNS listeners. Packet parsing, cache policy and upstream exchanges
//! live in the portable resolver engine so host tests exercise the production code.

use crate::config::server::DnsConfig;
use crate::dns_resolver::{apply_udp_size_limit, resolve};
pub(crate) use crate::dns_resolver::{compile_blocklist, new_cache};
pub use crate::dns_resolver::{DnsBlocklist, DnsCache};
use crate::profile_tasks::ProfileTasks;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Upper bound per listener: UDP query tasks or persistent TCP connection tasks. The permit is taken in the accept loop
/// BEFORE spawning (see the loop below), so a flood is bounded by refusing to
/// start work rather than by parking an unbounded number of started tasks.
const MAX_INFLIGHT: usize = 512;

/// Bind the proxy's listen socket, SEPARATELY from serving on it.
///
/// The bind used to happen inside the detached serve task, so a port already taken — the
/// common case, a host resolver on `0.0.0.0:53` covering the TUN address — surfaced as one
/// ERROR line while the profile came up regardless and handed every client the address of a
/// resolver that does not exist. Names then simply stopped resolving with nothing pointing at
/// the cause. Binding here lets the caller fail the profile BEFORE it advertises a resolver it
/// cannot provide. (Audit 2026-08-01, §4.)
pub async fn bind_dns_proxy(dns_cfg: &DnsConfig) -> anyhow::Result<UdpSocket> {
    bind_dns_proxy_at(dns_cfg, &dns_cfg.listen).await
}

pub async fn bind_dns_proxy_at(dns_cfg: &DnsConfig, listen: &str) -> anyhow::Result<UdpSocket> {
    let bind_addr = crate::util::join_host_port(listen, dns_cfg.port);
    UdpSocket::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("DNS proxy cannot bind {bind_addr}: {e}"))
}

/// Bind the TCP half of the resolver, on the same address and port as the UDP one.
///
/// DNS over TCP is not an optional extra: RFC 7766 makes it a REQUIREMENT for every resolver,
/// and it is what a client does after receiving a truncated answer. Without it this proxy could
/// not honestly set TC — telling a client "ask again over TCP" while listening on UDP alone
/// would have turned every oversized answer into a failed lookup, which is why the UDP path
/// used to forward answers whole regardless of size. Binding it is what makes the TC path in
/// `apply_udp_size_limit` truthful. (Audit 2026-08-01, §10.)
pub async fn bind_dns_proxy_tcp(dns_cfg: &DnsConfig) -> anyhow::Result<TcpListener> {
    bind_dns_proxy_tcp_at(dns_cfg, &dns_cfg.listen).await
}

pub async fn bind_dns_proxy_tcp_at(
    dns_cfg: &DnsConfig,
    listen: &str,
) -> anyhow::Result<TcpListener> {
    let bind_addr = crate::util::join_host_port(listen, dns_cfg.port);
    TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| anyhow::anyhow!("DNS proxy cannot bind {bind_addr}/tcp: {e}"))
}

/// Serve DNS over TCP: length-prefixed messages (RFC 1035 §4.2.2), one task per connection,
/// sharing the blocklist, cache and upstream policy with the UDP path via [`resolve`].
pub(crate) async fn run_dns_proxy_tcp(
    dns_cfg: DnsConfig,
    listener: TcpListener,
    cache: DnsCache,
    pref: Arc<AtomicUsize>,
    blocklist: DnsBlocklist,
    tasks: ProfileTasks,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let cfg = Arc::new(dns_cfg);
    // The same in-flight bound as UDP, for the same reason: a flood must be refused rather
    // than parked. TCP additionally bounds itself by the accept queue.
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("DNS proxy (tcp) accept error: {} — continuing", e);
                continue;
            }
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            continue; // at capacity: dropping the connection is the bound
        };
        let cache = cache.clone();
        let cfg = cfg.clone();
        let pref = pref.clone();
        let blocklist = blocklist.clone();
        tasks.spawn(async move {
            let _permit = permit;
            // The timeout bounds IDLE time, not the connection.
            //
            // It used to wrap the whole exchange, so a perfectly healthy persistent connection
            // — which is the entire point of RFC 7766 — was cut off `timeout_secs` after
            // accept, mid-query, however busy it was. What needs bounding is a peer that
            // connects and then says nothing; a peer that keeps asking questions is a peer the
            // service exists for. Applying it per read gives that, and still releases the
            // in-flight slot from a stalled client. (Audit 2026-08-01, §10.)
            let idle = Duration::from_secs(
                cfg.timeout_secs
                    .clamp(1, crate::config::server::DNS_MAX_TIMEOUT_SECS),
            );
            // RFC 7766 allows several queries per connection; serve until the peer closes.
            loop {
                let mut len_buf = [0u8; 2];
                match tokio::time::timeout(idle, stream.read_exact(&mut len_buf)).await {
                    Ok(Ok(_)) => {}
                    // Clean close, broken peer or an idle timeout — either way, done.
                    _ => return,
                }
                let qlen = u16::from_be_bytes(len_buf) as usize;
                if qlen < 12 {
                    return; // shorter than a DNS header
                }
                let mut query = vec![0u8; qlen];
                // The BODY gets its own deadline too: a peer that announces a length and then
                // dribbles could otherwise hold the slot indefinitely between reads.
                match tokio::time::timeout(idle, stream.read_exact(&mut query)).await {
                    Ok(Ok(_)) => {}
                    _ => return,
                }
                let Some(resp) = resolve(
                    cache.clone(),
                    cfg.clone(),
                    pref.clone(),
                    blocklist.clone(),
                    &query,
                )
                .await
                else {
                    return;
                };
                // TCP carries the full answer without the downstream UDP size cap. If no
                // upstream supplied a full answer, preserve the last-resort TC response.
                let Ok(len) = u16::try_from(resp.len()) else {
                    return;
                };
                let mut framed = Vec::with_capacity(2 + resp.len());
                framed.extend_from_slice(&len.to_be_bytes());
                framed.extend_from_slice(&resp);
                match tokio::time::timeout(idle, stream.write_all(&framed)).await {
                    Ok(Ok(())) => {}
                    _ => return,
                }
            }
        });
    }
}

pub(crate) async fn run_dns_proxy(
    dns_cfg: DnsConfig,
    bound: UdpSocket,
    cache: DnsCache,
    pref: Arc<AtomicUsize>,
    blocklist: DnsBlocklist,
    tasks: ProfileTasks,
) -> anyhow::Result<()> {
    let bind_addr = crate::util::join_host_port(&dns_cfg.listen, dns_cfg.port);
    // Shared listen socket: query tasks send their answers back through it.
    let socket = Arc::new(bound);
    log::info!("DNS proxy listening on {}", bind_addr);

    let cfg = Arc::new(dns_cfg);
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    // Count of queries refused because the in-flight gate was full (for rate-limited logging).
    let dropped = Arc::new(AtomicU64::new(0));
    // The full UDP payload maximum, not a guess at what clients "should" send. `recv_from`
    // discards whatever does not fit, silently, so any bound below 65535 turns a legal
    // datagram — a large TSIG or an EDNS0 query from a client that advertised
    // room for it — into a truncated message forwarded upstream as if it were whole. This is
    // ONE buffer for the whole accept loop, so the ceiling costs 64 KiB per profile, once.
    // (Audit 2026-08-01, §10.)
    let mut buf = vec![0u8; 65_535];
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
        let blocklist = blocklist.clone();
        tasks.spawn(async move {
            handle_query(socket, cache, cfg, permit, pref, blocklist, query, src).await;
        });
    }
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
    blocklist: Arc<HashSet<String>>,
    query: Vec<u8>,
    src: SocketAddr,
) {
    let Some(resp) = resolve(cache, cfg, pref, blocklist, &query).await else {
        return;
    };
    // Only the UDP path has a size limit to respect; over TCP the answer goes out whole.
    let Some(out) = apply_udp_size_limit(&query, resp) else {
        return;
    };
    let _ = socket.send_to(&out, src).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_tasks::ProfileServices;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;

    const DEADLINE: Duration = Duration::from_secs(5);

    struct Proxy {
        addr: SocketAddr,
        cfg: DnsConfig,
        cache: DnsCache,
        tasks: ProfileTasks,
        services: ProfileServices,
    }

    impl Proxy {
        async fn start(listen: &str, upstream: Vec<String>, timeout_secs: u64) -> Self {
            let mut cfg = DnsConfig {
                enabled: true,
                listen: listen.into(),
                upstream,
                upstream_protocol: "udp".into(),
                timeout_secs,
                cache_size: 128,
                blocklist: vec!["blocked.test".into()],
                ..Default::default()
            };
            let (tcp, udp) =
                crate::dns_test_support::bind_pair(&crate::util::join_host_port(listen, 0))
                    .await
                    .unwrap();
            let addr = udp.local_addr().unwrap();
            cfg.port = addr.port();
            let cache = new_cache();
            let preference = Arc::new(AtomicUsize::new(0));
            let blocklist = compile_blocklist(&cfg.blocklist);
            let tasks = ProfileTasks::new("dns-test");
            let mut services = ProfileServices::default();
            services.services.spawn(run_dns_proxy(
                cfg.clone(),
                udp,
                cache.clone(),
                preference.clone(),
                blocklist.clone(),
                tasks.clone(),
            ));
            services.services.spawn(run_dns_proxy_tcp(
                cfg.clone(),
                tcp,
                cache.clone(),
                preference,
                blocklist,
                tasks.clone(),
            ));
            Self {
                addr,
                cfg,
                cache,
                tasks,
                services,
            }
        }

        async fn stop(&mut self) {
            timeout(DEADLINE, self.services.shutdown(&self.tasks))
                .await
                .unwrap()
                .unwrap();
        }

        async fn assert_rebind(&self) {
            let _udp = bind_dns_proxy(&self.cfg)
                .await
                .expect("UDP port still owned after shutdown");
            let _tcp = bind_dns_proxy_tcp(&self.cfg)
                .await
                .expect("TCP port still owned after shutdown");
        }
    }

    impl Drop for Proxy {
        fn drop(&mut self) {
            // Tests also clean up on assertion failure; Drop cannot await the final joins.
            self.tasks.abort_all();
        }
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[..2].copy_from_slice(&id.to_be_bytes());
        msg[2] = 1;
        msg[5] = 1;
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.extend_from_slice(&[0, 0, 1, 0, 1]);
        msg
    }

    fn framed(query: &[u8]) -> Vec<u8> {
        let mut frame = (query.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(query);
        frame
    }

    async fn read_answer(stream: &mut TcpStream) -> Vec<u8> {
        timeout(DEADLINE, async {
            let n = stream.read_u16().await.unwrap();
            let mut answer = vec![0; n as usize];
            stream.read_exact(&mut answer).await.unwrap();
            answer
        })
        .await
        .unwrap()
    }

    fn assert_blocked(answer: &[u8], id: u16) {
        assert!(answer.len() >= 12);
        assert_eq!(&answer[..2], &id.to_be_bytes());
        assert_ne!(answer[2] & 0x80, 0);
        assert_eq!(answer[3] & 0x0f, 3);
    }

    async fn udp_answer(proxy: &Proxy, id: u16) {
        let listen = if proxy.addr.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let client = UdpSocket::bind(listen).await.unwrap();
        client
            .send_to(&query(id, "blocked.test"), proxy.addr)
            .await
            .unwrap();
        let mut answer = [0; 512];
        let (n, src) = timeout(DEADLINE, client.recv_from(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(src, proxy.addr);
        assert_blocked(&answer[..n], id);
    }

    async fn assert_closed(stream: &mut TcpStream) {
        let mut byte = [0];
        match timeout(DEADLINE, stream.read(&mut byte)).await.unwrap() {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("expected closed TCP connection, got {other:?}"),
        }
    }

    async fn exercise_listeners(listen: &str) {
        let mut proxy = Proxy::start(listen, vec![], 30).await;
        udp_answer(&proxy, 11).await;
        let mut client = TcpStream::connect(proxy.addr).await.unwrap();
        // Two pipelined questions, followed by another exchange on the same connection.
        let mut batch = framed(&query(12, "blocked.test"));
        batch.extend(framed(&query(13, "blocked.test")));
        client.write_all(&batch).await.unwrap();
        assert_blocked(&read_answer(&mut client).await, 12);
        assert_blocked(&read_answer(&mut client).await, 13);
        client
            .write_all(&framed(&query(14, "blocked.test")))
            .await
            .unwrap();
        assert_blocked(&read_answer(&mut client).await, 14);
        proxy.stop().await;
        assert_closed(&mut client).await;
        drop(client);
        proxy.assert_rebind().await;
    }

    #[tokio::test]
    async fn ipv4_udp_and_persistent_tcp_stop_and_rebind() {
        exercise_listeners("127.0.0.1").await;
    }

    #[tokio::test]
    async fn ipv6_udp_and_persistent_tcp_stop_and_rebind() {
        exercise_listeners("::1").await;
    }

    #[tokio::test]
    async fn stop_cancels_pending_queries_and_preserves_sibling_profile() {
        let mut proxy = Proxy::start("127.0.0.1", vec![], 30).await;
        let mut sibling = Proxy::start("127.0.0.1", vec![], 30).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Park real query tasks on the shared cache lock without using a public upstream.
        // Each blocked query owns a cache Arc and the listener socket until it is dropped.
        let cache = proxy.cache.clone();
        let cache_lock = cache.write().await;
        let baseline = Arc::strong_count(&cache);
        for id in 0..32 {
            client
                .send_to(&query(id, "pending.test"), proxy.addr)
                .await
                .unwrap();
        }
        timeout(DEADLINE, async {
            while Arc::strong_count(&cache) < baseline + 32 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut tcp = TcpStream::connect(proxy.addr).await.unwrap();
        tcp.write_all(&framed(&query(40, "blocked.test")))
            .await
            .unwrap();
        assert_blocked(&read_answer(&mut tcp).await, 40);
        tcp.write_all(&[0, 32, 1]).await.unwrap(); // incomplete next body
        proxy.stop().await;
        assert_eq!(
            Arc::strong_count(&cache),
            2,
            "query tasks still retain the cache"
        );
        drop(cache_lock);
        assert_closed(&mut tcp).await;
        drop(tcp);
        proxy.assert_rebind().await;
        udp_answer(&sibling, 41).await;
        sibling.stop().await;
    }

    #[tokio::test]
    async fn partial_tcp_prefix_and_body_expire_without_stopping_listener() {
        let mut proxy = Proxy::start("127.0.0.1", vec![], 1).await;
        let mut prefix = TcpStream::connect(proxy.addr).await.unwrap();
        let mut body = TcpStream::connect(proxy.addr).await.unwrap();
        prefix.write_all(&[0]).await.unwrap();
        body.write_all(&[0, 32, 1]).await.unwrap();
        tokio::join!(assert_closed(&mut prefix), assert_closed(&mut body));
        udp_answer(&proxy, 50).await;
        let mut healthy = TcpStream::connect(proxy.addr).await.unwrap();
        healthy
            .write_all(&framed(&query(51, "blocked.test")))
            .await
            .unwrap();
        assert_blocked(&read_answer(&mut healthy).await, 51);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn failed_additional_bind_then_cleanup_releases_primary_listeners() {
        let mut proxy = Proxy::start("127.0.0.1", vec![], 30).await;
        udp_answer(&proxy, 60).await; // primary services are already running
                                      // Model a subsequent startup bind failure through the real binding functions.
        assert!(bind_dns_proxy_tcp(&proxy.cfg).await.is_err());
        assert!(bind_dns_proxy(&proxy.cfg).await.is_err());
        proxy.stop().await;
        proxy.assert_rebind().await;
    }

    #[tokio::test]
    async fn malformed_tcp_frame_does_not_take_down_other_connections() {
        let mut proxy = Proxy::start("127.0.0.1", vec![], 30).await;
        let mut bad = TcpStream::connect(proxy.addr).await.unwrap();
        bad.write_all(&[0, 11]).await.unwrap();
        assert_closed(&mut bad).await;
        let mut healthy = TcpStream::connect(proxy.addr).await.unwrap();
        healthy
            .write_all(&framed(&query(70, "blocked.test")))
            .await
            .unwrap();
        assert_blocked(&read_answer(&mut healthy).await, 70);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn tcp_capacity_is_bounded_and_recovers_after_disconnect() {
        let mut proxy = Proxy::start("127.0.0.1", vec![], 30).await;
        let mut connections = Vec::new();
        for id in 0..MAX_INFLIGHT {
            let mut client = TcpStream::connect(proxy.addr).await.unwrap();
            client
                .write_all(&framed(&query(id as u16, "blocked.test")))
                .await
                .unwrap();
            assert_blocked(&read_answer(&mut client).await, id as u16);
            connections.push(client);
        }
        let mut refused = TcpStream::connect(proxy.addr).await.unwrap();
        assert_closed(&mut refused).await;
        // The live connections, not queries within one connection, consume permits.
        let mut released = connections.pop().unwrap();
        released.shutdown().await.unwrap();
        assert_closed(&mut released).await;
        let mut replacement = TcpStream::connect(proxy.addr).await.unwrap();
        replacement
            .write_all(&framed(&query(80, "blocked.test")))
            .await
            .unwrap();
        assert_blocked(&read_answer(&mut replacement).await, 80);
        proxy.stop().await;
        assert_closed(&mut replacement).await;
    }
}
