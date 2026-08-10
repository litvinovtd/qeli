//! Narrow, side-effect-free transport diagnostics shared by platform adapters.
//!
//! A UDP reachability check intentionally stops after the server's first reply: it proves
//! that the configured fake-TLS/QUIC/obfs first flight crosses the path without authenticating
//! or creating a tunnel. The first flight itself is built by `session`, exactly like the live
//! data plane.

use crate::config::client::ClientConfig;
use crate::protocol::{generate_connection_id, wrap_quic_long};
use crate::transport_core::session::build_udp_client_hello_flight;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const PROBE_ATTEMPTS: usize = 2;
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("qeli-udp-probe")
        .build()?;
    runtime.block_on(udp_reachability_async(config, host, per_attempt_timeout))
}

async fn udp_reachability_async(
    config: &ClientConfig,
    host: &str,
    per_attempt_timeout: Duration,
) -> anyhow::Result<u64> {
    if config.server.protocol != "udp" {
        anyhow::bail!("native UDP reachability requires proto = udp");
    }
    let address = resolve_ipv4(host, config.server.port, per_attempt_timeout).await?;
    let raw_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    raw_socket.connect(address).await?;

    let flight = build_udp_client_hello_flight(config)?;
    let obfs_key = if config.obfuscation.mode == "obfs" {
        Some(crate::protocol::obfs::derive_obfs_key(
            &config.obfuscation.obfs_key,
        ))
    } else {
        None
    };
    let socket = crate::protocol::obfs::ObfsUdp::new(raw_socket, obfs_key);
    let quic_enabled = config.obfuscation.quic.enabled;
    let connection_id = generate_connection_id();
    let mut packet_number = 0u32;
    let mut receive = [0u8; 4096];
    let started = Instant::now();

    for _ in 0..PROBE_ATTEMPTS {
        for fragment in &flight.fragments {
            let datagram = if quic_enabled {
                let current = packet_number;
                packet_number = packet_number.wrapping_add(1);
                wrap_quic_long(fragment, &connection_id, current, 0x00)
            } else {
                fragment.clone()
            };
            socket.send(&datagram).await?;
        }

        match tokio::time::timeout(per_attempt_timeout, socket.recv(&mut receive)).await {
            Ok(Ok(received)) if received > 0 => {
                return Ok(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            }
            Ok(Ok(_)) | Err(_) => continue,
            Ok(Err(error)) => return Err(error.into()),
        }
    }

    anyhow::bail!(
        "no UDP server reply after {PROBE_ATTEMPTS} attempts of {} ms",
        per_attempt_timeout.as_millis()
    )
}

async fn resolve_ipv4(host: &str, port: u16, timeout: Duration) -> anyhow::Result<SocketAddr> {
    let addresses = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("UDP probe DNS resolution timed out"))??;
    addresses
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow::anyhow!("probe host '{host}' has no IPv4 address"))
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
}
