//! Platform-neutral connection of a carrier socket already prepared by the core.
//!
//! Android must call `VpnService.protect(fd)` before this module sees the socket. Other
//! adapters can pass an ordinary nonblocking socket. Resolution and connect share one
//! deadline, and only IPv4 results are considered until the client configuration accepts
//! IPv6 endpoints consistently on every platform.

use crate::config::client::ClientConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug)]
#[allow(dead_code)] // The shadow ABI prepares this owner; live handoff consumes it next.
pub(crate) enum ConnectedCarrier {
    Tcp(tokio::net::TcpStream),
    Udp(tokio::net::UdpSocket),
}

pub(crate) fn open(config: &ClientConfig) -> anyhow::Result<Socket> {
    let (socket_type, protocol) = match config.server.protocol.as_str() {
        "tcp" => (Type::STREAM, Protocol::TCP),
        "udp" => (Type::DGRAM, Protocol::UDP),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    };
    let socket = Socket::new(Domain::IPV4, socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub(crate) async fn connect(
    socket: Socket,
    config: &ClientConfig,
) -> anyhow::Result<ConnectedCarrier> {
    let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    tokio::time::timeout(timeout, connect_inner(socket, config))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "carrier connect to {}:{} timed out after {}s",
                config.server.address,
                config.server.port,
                timeout.as_secs()
            )
        })?
}

async fn connect_inner(socket: Socket, config: &ClientConfig) -> anyhow::Result<ConnectedCarrier> {
    let address = resolve_ipv4(&config.server.address, config.server.port).await?;
    match config.server.protocol.as_str() {
        "tcp" => connect_tcp(socket, address)
            .await
            .map(ConnectedCarrier::Tcp),
        "udp" => connect_udp(socket, address).map(ConnectedCarrier::Udp),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    }
}

async fn resolve_ipv4(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    tokio::net::lookup_host((host, port))
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow::anyhow!("server '{host}' did not resolve to an IPv4 address"))
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
}
