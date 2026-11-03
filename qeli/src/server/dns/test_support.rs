//! Loopback-only socket fixtures. Never linked into release builds.
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

/// Port 0 is allocated independently for TCP and UDP. A free ephemeral TCP port can
/// already be occupied by UDP in another parallel test; retry the pair, keeping both
/// sockets reserved once successful. Never retry unrelated bind failures.
pub(crate) async fn bind_pair(bind: &str) -> io::Result<(TcpListener, UdpSocket)> {
    let bind: SocketAddr = bind
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    assert!(bind.ip().is_loopback() && bind.port() == 0);
    for _ in 0..64 {
        let tcp = TcpListener::bind(bind).await?;
        match UdpSocket::bind(tcp.local_addr()?).await {
            Ok(udp) => return Ok((tcp, udp)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "could not reserve a loopback TCP/UDP pair",
    ))
}
