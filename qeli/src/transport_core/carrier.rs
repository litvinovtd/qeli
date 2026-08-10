//! Platform-neutral connection of a carrier socket already prepared by the core.
//!
//! Android must call `VpnService.protect(fd)` before this module sees the socket. Other
//! adapters can pass an ordinary nonblocking socket. Resolution and connect share one
//! deadline, and only IPv4 results are considered until the client configuration accepts
//! IPv6 endpoints consistently on every platform.

use crate::config::client::ClientConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

#[derive(Debug)]
#[allow(dead_code)] // Some feature-only host builds expose lifecycle ABI without the runner.
pub(crate) enum ConnectedCarrier {
    Tcp(tokio::net::TcpStream),
    Udp(tokio::net::UdpSocket),
}

pub(crate) fn open(config: &ClientConfig) -> anyhow::Result<Socket> {
    open_socket(config, true)
}

/// Additional bonded streams historically used an ephemeral source even when the primary
/// desktop carrier had `local`/`lport`; keep that contract (and avoid fixed-port collisions).
pub(crate) fn open_secondary(config: &ClientConfig) -> anyhow::Result<Socket> {
    open_socket(config, false)
}

fn open_socket(config: &ClientConfig, bind_primary: bool) -> anyhow::Result<Socket> {
    let (socket_type, protocol) = match config.server.protocol.as_str() {
        "tcp" => (Type::STREAM, Protocol::TCP),
        "udp" => (Type::DGRAM, Protocol::UDP),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    };
    let socket = Socket::new(Domain::IPV4, socket_type, Some(protocol))?;
    if bind_primary {
        bind_desktop_primary(&socket, config)?;
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn bind_desktop_primary(socket: &Socket, config: &ClientConfig) -> anyhow::Result<()> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    if config.server.local_address.is_none() && config.server.local_port == 0 {
        return Ok(());
    }
    let address = match config.server.local_address.as_deref() {
        Some(value) => value.parse::<Ipv4Addr>().map_err(|_| {
            anyhow::anyhow!("invalid local carrier address '{value}' (expected IPv4)")
        })?,
        None => Ipv4Addr::UNSPECIFIED,
    };
    socket
        .bind(&SocketAddrV4::new(address, config.server.local_port).into())
        .map_err(|error| {
            anyhow::anyhow!(
                "could not bind primary carrier to {}:{}: {error}",
                address,
                config.server.local_port
            )
        })
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn bind_desktop_primary(_socket: &Socket, _config: &ClientConfig) -> anyhow::Result<()> {
    Ok(())
}

pub(crate) async fn connect(
    socket: Socket,
    config: &ClientConfig,
) -> anyhow::Result<ConnectedCarrier> {
    let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let address = resolve_ipv4_candidates(&config.server.address, config.server.port, &[])
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("server did not yield an IPv4 carrier address"))?;
    connect_to(socket, config, address, timeout).await
}

/// Connect one already-created (and, on Android, already-protected) socket to one exact
/// physical carrier address. Resolution is deliberately outside this function so reconnects
/// never have to ask a resolver that may already be routed into the failed VPN.
pub(crate) async fn connect_to(
    socket: Socket,
    config: &ClientConfig,
    address: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<ConnectedCarrier> {
    tokio::time::timeout(timeout, connect_inner(socket, config, address))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "carrier connect to {address} timed out after {}s",
                timeout.as_secs()
            )
        })?
}

async fn connect_inner(
    socket: Socket,
    config: &ClientConfig,
    address: SocketAddr,
) -> anyhow::Result<ConnectedCarrier> {
    match config.server.protocol.as_str() {
        "tcp" => connect_tcp(socket, address)
            .await
            .map(ConnectedCarrier::Tcp),
        "udp" => connect_udp(socket, address).map(ConnectedCarrier::Udp),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    }
}

/// Return every distinct IPv4 candidate in stable order. Platform-supplied addresses are
/// authoritative: Android resolves them through `Network.getAllByName`, and desktop/iOS
/// resolve them before installing or while retaining fail-closed tunnel settings. Falling
/// back to Tokio DNS is only for adapters that have not supplied that physical-network fact.
pub(crate) async fn resolve_ipv4_candidates(
    host: &str,
    port: u16,
    preferred: &[Ipv4Addr],
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    if !preferred.is_empty() {
        for address in preferred {
            if seen.insert(*address) {
                output.push(SocketAddr::V4(SocketAddrV4::new(*address, port)));
            }
        }
    } else {
        for address in tokio::net::lookup_host((host, port)).await? {
            let SocketAddr::V4(address) = address else {
                continue;
            };
            if seen.insert(*address.ip()) {
                output.push(SocketAddr::V4(address));
            }
        }
    }
    if output.is_empty() {
        anyhow::bail!("server '{host}' did not resolve to an IPv4 address");
    }
    Ok(output)
}

async fn connect_tcp(socket: Socket, address: SocketAddr) -> anyhow::Result<tokio::net::TcpStream> {
    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(error) if connect_is_pending(&error) => {}
        Err(error) => return Err(error.into()),
    }

    let stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error.into());
    }
    Ok(stream)
}

fn connect_udp(socket: Socket, address: SocketAddr) -> anyhow::Result<tokio::net::UdpSocket> {
    socket.connect(&address.into())?;
    Ok(tokio::net::UdpSocket::from_std(socket.into())?)
}

fn connect_is_pending(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    // Some Unix targets expose EINPROGRESS directly rather than mapping it to WouldBlock.
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::EINPROGRESS) {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(protocol: &str, port: u16) -> ClientConfig {
        let mut config = ClientConfig::default();
        config.server.address = "127.0.0.1".into();
        config.server.port = port;
        config.server.protocol = protocol.into();
        config.server.connection_timeout_secs = 2;
        config
    }

    #[tokio::test]
    async fn connects_a_preopened_tcp_carrier() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let config = config("tcp", listener.local_addr().unwrap().port());
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });

        let connected = connect(open(&config).unwrap(), &config).await.unwrap();
        assert!(matches!(connected, ConnectedCarrier::Tcp(_)));
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn connects_a_preopened_udp_carrier() {
        let peer = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let config = config("udp", peer.local_addr().unwrap().port());

        let connected = connect(open(&config).unwrap(), &config).await.unwrap();
        let ConnectedCarrier::Udp(socket) = connected else {
            panic!("expected UDP carrier")
        };
        socket.send(b"ok").await.unwrap();
        let mut received = [0u8; 2];
        assert_eq!(peer.recv(&mut received).await.unwrap(), 2);
        assert_eq!(&received, b"ok");
    }

    #[tokio::test]
    async fn reports_tcp_connect_failure_without_hiding_the_io_error() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let config = config("tcp", port);

        let error = connect(open(&config).unwrap(), &config)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.is_empty());
    }

    #[tokio::test]
    async fn preserves_all_distinct_platform_candidates() {
        let addresses = resolve_ipv4_candidates(
            "resolver-must-not-be-used.invalid",
            443,
            &[
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 11),
                Ipv4Addr::new(192, 0, 2, 10),
            ],
        )
        .await
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], "192.0.2.10:443".parse().unwrap());
        assert_eq!(addresses[1], "192.0.2.11:443".parse().unwrap());
    }
}
