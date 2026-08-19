//! Narrow, side-effect-free transport diagnostics shared by platform adapters.
//!
//! A UDP reachability check intentionally stops after the server's first reply: it proves
//! that the configured fake-TLS/QUIC/obfs first flight crosses the path without authenticating
//! or creating a tunnel. The first flight itself is built by `session`, exactly like the live
//! data plane.

use crate::config::client::ClientConfig;
use crate::protocol::{generate_connection_id, wrap_quic_long};
use crate::transport_core::session::build_udp_client_hello_flight;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(feature = "transport-core-ffi")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const PROBE_ATTEMPTS: usize = 2;
const MAX_PROBE_ADDRESSES: usize = 16;
#[cfg(feature = "transport-core-ffi")]
pub(crate) const MIN_PROBE_TIMEOUT_MS: u32 = 100;
#[cfg(feature = "transport-core-ffi")]
pub(crate) const MAX_PROBE_TIMEOUT_MS: u32 = 5_000;

/// Blocking entry point for JNI and the C ABI. `per_attempt_timeout` is bounded by the adapter
/// before this function is called; keeping the runtime local means the probe owns no global
/// thread or state.
#[cfg(feature = "transport-core-ffi")]
pub(crate) fn udp_reachability(
    config: &ClientConfig,
    host: &str,
    per_attempt_timeout: Duration,
) -> anyhow::Result<u64> {
    udp_reachability_blocking(config, host, per_attempt_timeout, None)
}

/// Android's automatic profile sweep is user-disableable while a native probe is blocked in
/// DNS/recv. A per-call atomic lets JNI cancel that exact diagnostic; dropping the selected
/// future closes its UDP socket immediately. The C ABI keeps the bounded non-cancellable entry
/// above for existing desktop/iOS callers.
#[cfg(all(feature = "transport-core-ffi", any(target_os = "android", test)))]
pub(crate) fn udp_reachability_cancellable(
    config: &ClientConfig,
    host: &str,
    per_attempt_timeout: Duration,
    cancelled: &AtomicBool,
) -> anyhow::Result<u64> {
    udp_reachability_blocking(config, host, per_attempt_timeout, Some(cancelled))
}

#[cfg(feature = "transport-core-ffi")]
fn udp_reachability_blocking(
    config: &ClientConfig,
    host: &str,
    per_attempt_timeout: Duration,
    cancelled: Option<&AtomicBool>,
) -> anyhow::Result<u64> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("qeli-udp-probe")
        .build()?;
    let result = runtime.block_on(async {
        if let Some(cancelled) = cancelled {
            tokio::select! {
                biased;
                _ = wait_until_cancelled(cancelled) => {
                    Err(anyhow::anyhow!("UDP reachability probe cancelled"))
                }
                result = udp_reachability_async(config, host, per_attempt_timeout) => result,
            }
        } else {
            udp_reachability_async(config, host, per_attempt_timeout).await
        }
    });
    // `lookup_host` may have delegated libc DNS to Tokio's blocking pool. Dropping a Runtime
    // waits indefinitely for such work even after `select!` cancelled the async lookup, which
    // would make Android's coroutine cancellation appear to hang. Bound shutdown here; the
    // abandoned resolver worker owns no socket/config reference and exits on its own.
    runtime.shutdown_timeout(Duration::from_millis(50));
    result
}

#[cfg(feature = "transport-core-ffi")]
async fn wait_until_cancelled(cancelled: &AtomicBool) {
    while !cancelled.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn udp_reachability_async(
    config: &ClientConfig,
    host: &str,
    per_attempt_timeout: Duration,
) -> anyhow::Result<u64> {
    if config.server.protocol != "udp" {
        anyhow::bail!("native UDP reachability requires proto = udp");
    }
    let addresses = resolve_ipv4(host, config.server.port, per_attempt_timeout).await?;
    let flight = build_udp_client_hello_flight(config)?;
    let fragments = Arc::new(flight.fragments);
    let obfs_key = if config.obfuscation.mode == "obfs" {
        Some(crate::protocol::obfs::derive_obfs_key(
            &config.obfuscation.obfs_key,
        ))
    } else {
        None
    };
    let quic_enabled = config.obfuscation.quic.enabled;
    let started = Instant::now();
    let mut probes = tokio::task::JoinSet::new();
    for address in addresses {
        let fragments = Arc::clone(&fragments);
        probes.spawn(async move {
            udp_reachability_candidate(
                address,
                fragments,
                obfs_key,
                quic_enabled,
                per_attempt_timeout,
            )
            .await
        });
    }

    let mut failures = Vec::new();
    while let Some(result) = probes.join_next().await {
        match result {
            Ok(Ok(())) => {
                probes.abort_all();
                return Ok(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            }
            Ok(Err(error)) => failures.push(error.to_string()),
            Err(error) => failures.push(format!("UDP probe task failed: {error}")),
        }
    }

    anyhow::bail!(
        "no UDP server reply from any IPv4 candidate: {}",
        failures.join("; ")
    )
}

async fn udp_reachability_candidate(
    address: SocketAddr,
    fragments: Arc<Vec<Vec<u8>>>,
    obfs_key: Option<[u8; 32]>,
    quic_enabled: bool,
    per_attempt_timeout: Duration,
) -> anyhow::Result<()> {
    let raw_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    raw_socket.connect(address).await?;
    let socket = crate::protocol::obfs::ObfsUdp::new(raw_socket, obfs_key);
    let connection_id = generate_connection_id();
    let mut packet_number = 0u32;
    let mut receive = [0u8; 4096];

    for _ in 0..PROBE_ATTEMPTS {
        for fragment in fragments.iter() {
            let datagram = if quic_enabled {
                let current = packet_number;
                packet_number = packet_number.wrapping_add(1);
                wrap_quic_long(fragment, &connection_id, current)
            } else {
                fragment.clone()
            };
            socket.send(&datagram).await?;
        }

        match tokio::time::timeout(per_attempt_timeout, socket.recv(&mut receive)).await {
            Ok(Ok(received)) if received > 0 => {
                return Ok(());
            }
            Ok(Ok(_)) | Err(_) => continue,
            Ok(Err(error)) => return Err(error.into()),
        }
    }

    anyhow::bail!(
        "{address}: no UDP server reply after {PROBE_ATTEMPTS} attempts of {} ms",
        per_attempt_timeout.as_millis()
    )
}

async fn resolve_ipv4(host: &str, port: u16, timeout: Duration) -> anyhow::Result<Vec<SocketAddr>> {
    let addresses = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("UDP probe DNS resolution timed out"))??;
    let addresses = collect_ipv4_candidates(addresses);
    if addresses.is_empty() {
        anyhow::bail!("probe host '{host}' has no IPv4 address");
    }
    Ok(addresses)
}

fn collect_ipv4_candidates(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    addresses
        .into_iter()
        .filter(|address| address.is_ipv4())
        .filter(|address| seen.insert(*address))
        .take(MAX_PROBE_ADDRESSES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(port: u16) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.server.address = "127.0.0.1".into();
        config.server.port = port;
        config.server.protocol = "udp".into();
        config.obfuscation.mode = "fake-tls".into();
        config
    }

    #[test]
    fn resolver_keeps_distinct_ipv4_candidates_and_ignores_ipv6() {
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let second: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let ipv6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(
            collect_ipv4_candidates([first, ipv6, first, second]),
            vec![first, second]
        );
    }

    #[tokio::test]
    async fn shared_udp_first_flight_reaches_a_real_socket() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let (received, peer) = server.recv_from(&mut buffer).await.unwrap();
                assert!(received > crate::protocol::udp_frag::FRAG_HDR_LEN);
                server.send_to(b"server hello", peer).await.unwrap();
            }
        });

        let elapsed =
            udp_reachability_async(&config(port), "127.0.0.1", Duration::from_millis(500))
                .await
                .unwrap();
        assert!(elapsed < 1_000);
        echo.abort();
    }

    #[tokio::test]
    async fn rejects_a_tcp_profile_before_sending() {
        let mut config = config(9);
        config.server.protocol = "tcp".into();
        let error = udp_reachability_async(&config, "127.0.0.1", Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("proto = udp"));
    }

    #[cfg(feature = "transport-core-ffi")]
    #[test]
    fn cancellable_probe_stops_before_dns_or_socket_timeout() {
        let cancelled = AtomicBool::new(true);
        let started = Instant::now();
        let error = udp_reachability_cancellable(
            &config(9),
            "192.0.2.1",
            Duration::from_secs(5),
            &cancelled,
        )
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(started.elapsed() < Duration::from_millis(250));
    }
}
