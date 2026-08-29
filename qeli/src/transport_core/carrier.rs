//! Platform-neutral connection of a carrier socket already prepared by the core.
//!
//! Android must call `VpnService.protect(fd)` before this module sees the socket. Other
//! adapters can pass an ordinary nonblocking socket. Resolution and connect share one
//! deadline. Socket families are selected from the concrete resolved candidate so IPv4 and
//! IPv6 carriers use the same protection/connect lifecycle.

use crate::config::client::ClientConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug)]
#[allow(dead_code)] // Some feature-only host builds expose lifecycle ABI without the runner.
pub(crate) enum ConnectedCarrier {
    Tcp(tokio::net::TcpStream),
    Udp(tokio::net::UdpSocket),
}

pub(crate) fn open_for(config: &ClientConfig, address: IpAddr) -> anyhow::Result<Socket> {
    open_socket(config, address, true)
}

/// Additional bonded streams use an ephemeral source port even when the primary desktop
/// carrier has `local`/`lport`; they still retain `local` to keep the requested egress NIC.
pub(crate) fn open_secondary_for(config: &ClientConfig, address: IpAddr) -> anyhow::Result<Socket> {
    open_socket(config, address, false)
}

/// A roaming candidate must not inherit a desktop `local` address from the active path.
/// PREPARE_PATH installed temporary reachability and BIND_SOCKET will attach this unconnected
/// socket to the exact candidate network before connect.
#[cfg(feature = "experimental-roaming")]
pub(crate) fn open_candidate_for(config: &ClientConfig, address: IpAddr) -> anyhow::Result<Socket> {
    open_unbound_socket(config, address)
}

#[cfg(feature = "experimental-roaming")]
pub(crate) fn candidate_socket_handle(socket: &Socket) -> anyhow::Result<i64> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        Ok(i64::from(socket.as_raw_fd()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        i64::try_from(socket.as_raw_socket()).map_err(|_| {
            anyhow::anyhow!("candidate socket handle is outside the signed 64-bit ABI range")
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = socket;
        anyhow::bail!("candidate socket binding is unsupported on this platform");
    }
}

fn open_socket(
    config: &ClientConfig,
    remote: IpAddr,
    bind_primary: bool,
) -> anyhow::Result<Socket> {
    let (socket_type, protocol) = match config.server.protocol.as_str() {
        "tcp" => (Type::STREAM, Protocol::TCP),
        "udp" => (Type::DGRAM, Protocol::UDP),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    };
    let domain = if remote.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, socket_type, Some(protocol))?;
    bind_desktop(&socket, config, remote, bind_primary)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

#[cfg(feature = "experimental-roaming")]
fn open_unbound_socket(config: &ClientConfig, remote: IpAddr) -> anyhow::Result<Socket> {
    let (socket_type, protocol) = match config.server.protocol.as_str() {
        "tcp" => (Type::STREAM, Protocol::TCP),
        "udp" => (Type::DGRAM, Protocol::UDP),
        protocol => anyhow::bail!("unsupported wire protocol '{protocol}'"),
    };
    let domain = if remote.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Bind one unconnected candidate socket to the exact Linux interface and source address
/// carried by the validated PathUpdate. `SO_BINDTODEVICE` constrains route lookup to that
/// physical link even while the active carrier still owns a more-specific server bypass.
/// Binding the source address additionally proves that the address still belongs to the
/// candidate; a stale address/interface observation fails before any SYN leaves the host.
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
pub(crate) fn bind_linux_candidate_socket(
    socket_fd: i32,
    candidate: &super::path::PreparedPathCandidate,
) -> anyhow::Result<()> {
    if socket_fd < 0 {
        anyhow::bail!("candidate socket descriptor must be non-negative");
    }
    let interface_index = candidate
        .update
        .interface_index
        .ok_or_else(|| anyhow::anyhow!("Linux candidate path requires a stable interface index"))?;
    let interface_name = linux_interface_name(interface_index)?;
    let domain = linux_socket_domain(socket_fd)?;
    let local =
        linux_candidate_bind_address(interface_index, &candidate.update.local_addresses, domain)?;

    let name = interface_name.as_bytes_with_nul();
    // SAFETY: `socket_fd` is borrowed from the still-owned socket, and `name` is a live,
    // NUL-terminated interface name returned by `if_indextoname` for this exact index.
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(anyhow::anyhow!(
            "could not bind candidate socket to interface {} (index {}): {}",
            interface_name.to_string_lossy(),
            interface_index,
            io::Error::last_os_error()
        ));
    }

    let address = socket2::SockAddr::from(local);
    // SAFETY: `address` owns a correctly sized sockaddr for the socket domain, and the
    // transport retains ownership of `socket_fd` for the whole synchronous call.
    if unsafe { libc::bind(socket_fd, address.as_ptr().cast(), address.len()) } != 0 {
        return Err(anyhow::anyhow!(
            "could not bind candidate socket to source {local} on {}: {}",
            interface_name.to_string_lossy(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
pub(crate) fn linux_interface_name(interface_index: u32) -> anyhow::Result<std::ffi::CString> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name` is an IF_NAMESIZE writable buffer and remains alive until copied below.
    let resolved = unsafe { libc::if_indextoname(interface_index, name.as_mut_ptr()) };
    if resolved.is_null() {
        return Err(anyhow::anyhow!(
            "candidate interface index {interface_index} no longer exists: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: successful `if_indextoname` writes a NUL-terminated name into `name`.
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned())
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
fn linux_socket_domain(socket_fd: i32) -> anyhow::Result<i32> {
    let mut domain = 0 as libc::c_int;
    let mut length = std::mem::size_of_val(&domain) as libc::socklen_t;
    // SAFETY: both output pointers are valid for the declared lengths and `socket_fd` is
    // borrowed from a live socket owned by the candidate dialer.
    let result = unsafe {
        libc::getsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut domain as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(anyhow::anyhow!(
            "could not inspect candidate socket family: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(domain)
}

#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
fn linux_candidate_bind_address(
    interface_index: u32,
    local_addresses: &[String],
    socket_domain: i32,
) -> anyhow::Result<SocketAddr> {
    let want_ipv4 = match socket_domain {
        libc::AF_INET => true,
        libc::AF_INET6 => false,
        domain => anyhow::bail!("unsupported candidate socket domain {domain}"),
    };
    for value in local_addresses {
        let address = value
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid validated candidate source address '{value}'"))?;
        match address {
            IpAddr::V4(address) if want_ipv4 => {
                return Ok(SocketAddr::new(IpAddr::V4(address), 0));
            }
            IpAddr::V6(address) if !want_ipv4 => {
                let scope_id = if address.is_unicast_link_local() {
                    interface_index
                } else {
                    0
                };
                return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                    address, 0, 0, scope_id,
                )));
            }
            _ => {}
        }
    }
    anyhow::bail!(
        "candidate path has no {} source address",
        if want_ipv4 { "IPv4" } else { "IPv6" }
    )
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn bind_desktop(
    socket: &Socket,
    config: &ClientConfig,
    remote: IpAddr,
    primary: bool,
) -> anyhow::Result<()> {
    let Some(bind) = desktop_bind_address(config, remote, primary)? else {
        return Ok(());
    };
    socket.bind(&bind.into()).map_err(|error| {
        anyhow::anyhow!(
            "could not bind {} carrier to {bind}: {error}",
            if primary { "primary" } else { "bonded" }
        )
    })
}

/// Preserve the configured source interface on every desktop carrier while reserving a
/// fixed `lport` for the primary connection only. Two simultaneous TCP connections to the
/// same peer cannot share one four-tuple; the secondary therefore binds `local:0`.
#[cfg(any(target_os = "windows", target_os = "macos", test))]
fn desktop_bind_address(
    config: &ClientConfig,
    remote: IpAddr,
    primary: bool,
) -> anyhow::Result<Option<SocketAddr>> {
    if config.server.local_address.is_none() && (!primary || config.server.local_port == 0) {
        return Ok(None);
    }
    let address = match config.server.local_address.as_deref() {
        Some(value) => value
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid local carrier address '{value}'"))?,
        None if remote.is_ipv4() => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        None => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    if address.is_ipv4() != remote.is_ipv4() {
        anyhow::bail!("local carrier address {address} and remote {remote} use different families");
    }
    Ok(Some(SocketAddr::new(
        address,
        if primary { config.server.local_port } else { 0 },
    )))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn bind_desktop(
    _socket: &Socket,
    _config: &ClientConfig,
    _remote: IpAddr,
    _primary: bool,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) async fn connect(
    socket: Socket,
    config: &ClientConfig,
) -> anyhow::Result<ConnectedCarrier> {
    let timeout = Duration::from_secs(config.server.connection_timeout_secs.max(1));
    let address = resolve_ip_candidates(&config.server.address, config.server.port, &[])
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("server did not yield a carrier address"))?;
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

/// Return every distinct IP candidate in stable order. Platform-supplied addresses are
/// authoritative: Android resolves them through `Network.getAllByName`, and desktop/iOS
/// resolve them before installing or while retaining fail-closed tunnel settings. Falling
/// back to Tokio DNS is only for adapters that have not supplied that physical-network fact.
pub(crate) async fn resolve_ip_candidates(
    host: &str,
    port: u16,
    preferred: &[IpAddr],
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    if !preferred.is_empty() {
        for address in preferred {
            let address = canonical_carrier_ip(*address);
            if seen.insert(address) {
                output.push(SocketAddr::new(address, port));
            }
        }
    } else {
        for address in tokio::net::lookup_host((host, port)).await? {
            let ip = canonical_carrier_ip(address.ip());
            if seen.insert(ip) {
                output.push(SocketAddr::new(ip, address.port()));
            }
        }
    }
    if output.is_empty() {
        anyhow::bail!("server '{host}' did not resolve to an IPv4 or IPv6 address");
    }
    Ok(output)
}

/// DNS APIs are allowed to expose IPv4 answers as IPv4-mapped IPv6 addresses. Treat those
/// as their canonical IPv4 value so candidate de-duplication, socket-family selection and
/// carrier MTU accounting all describe the packet that will actually be sent on the wire.
pub(crate) fn canonical_carrier_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
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

        let connected = connect(
            open_for(&config, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap(),
            &config,
        )
        .await
        .unwrap();
        assert!(matches!(connected, ConnectedCarrier::Tcp(_)));
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn connects_a_preopened_udp_carrier() {
        let peer = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let config = config("udp", peer.local_addr().unwrap().port());

        let connected = connect(
            open_for(&config, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap(),
            &config,
        )
        .await
        .unwrap();
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

        let error = connect(
            open_for(&config, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).unwrap(),
            &config,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!error.is_empty());
    }

    #[tokio::test]
    async fn preserves_all_distinct_platform_candidates() {
        let addresses = resolve_ip_candidates(
            "resolver-must-not-be-used.invalid",
            443,
            &[
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
                "192.0.2.10".parse().unwrap(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], "192.0.2.10:443".parse().unwrap());
        assert_eq!(addresses[1], "[2001:db8::10]:443".parse().unwrap());
    }

    #[tokio::test]
    async fn canonicalizes_and_deduplicates_ipv4_mapped_candidates() {
        let addresses = resolve_ip_candidates(
            "resolver-must-not-be-used.invalid",
            443,
            &[
                "::ffff:192.0.2.10".parse().unwrap(),
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.10:443".parse().unwrap(),
                "[2001:db8::10]:443".parse().unwrap(),
            ]
        );
    }

    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    #[test]
    fn linux_candidate_source_selection_matches_socket_family_and_ipv6_scope() {
        let addresses = vec![
            "192.0.2.20".to_string(),
            "2001:db8::20".to_string(),
            "fe80::20".to_string(),
        ];
        assert_eq!(
            linux_candidate_bind_address(7, &addresses, libc::AF_INET).unwrap(),
            "192.0.2.20:0".parse().unwrap()
        );
        assert_eq!(
            linux_candidate_bind_address(7, &addresses[1..], libc::AF_INET6).unwrap(),
            "[2001:db8::20]:0".parse().unwrap()
        );
        let link_local = linux_candidate_bind_address(7, &addresses[2..], libc::AF_INET6).unwrap();
        let SocketAddr::V6(link_local) = link_local else {
            panic!("expected IPv6 candidate source")
        };
        assert_eq!(
            link_local.ip(),
            &"fe80::20".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(link_local.scope_id(), 7);
        assert!(linux_candidate_bind_address(7, &addresses[..1], libc::AF_INET6).is_err());
    }

    #[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
    #[test]
    #[ignore = "requires a privileged Linux host with iproute2 and a global IPv4 address"]
    fn linux_candidate_socket_binds_exact_interface_and_source() {
        use std::os::fd::AsRawFd;

        let output = std::process::Command::new("ip")
            .args(["-o", "-4", "addr", "show", "scope", "global"])
            .output()
            .expect("iproute2 is required");
        assert!(output.status.success());
        let line = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .next()
            .expect("host has no global IPv4 interface")
            .to_string();
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let interface = fields
            .get(1)
            .expect("ip output omitted the interface")
            .trim_end_matches(':')
            .split('@')
            .next()
            .unwrap();
        let local = fields
            .windows(2)
            .find(|pair| pair[0] == "inet")
            .and_then(|pair| pair[1].split('/').next())
            .expect("ip output omitted the IPv4 address")
            .parse::<IpAddr>()
            .unwrap();
        let interface_name = std::ffi::CString::new(interface).unwrap();
        // SAFETY: `interface_name` is a live NUL-terminated string.
        let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
        assert_ne!(interface_index, 0);

        let candidate = super::super::path::PreparedPathCandidate {
            candidate_id: 1,
            update: super::super::path::PathUpdate {
                generation: 1,
                update_id: 1,
                platform_path_id: format!("linux:{interface_index}"),
                reason: super::super::path::PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: Some(interface_index),
                local_addresses: vec![local.to_string()],
                resolved_addresses: vec![super::super::path::PathResolution {
                    address: "198.51.100.10".to_string(),
                    ttl_secs: 60,
                }],
                flags: super::super::path::PathUpdateFlags::default(),
            },
        };
        let config = config("tcp", 443);
        let socket = open_candidate_for(&config, "198.51.100.10".parse().unwrap()).unwrap();
        bind_linux_candidate_socket(socket.as_raw_fd(), &candidate).unwrap();
        assert_eq!(
            socket.local_addr().unwrap().as_socket().unwrap().ip(),
            local
        );

        let mut bound_name = [0 as libc::c_char; libc::IF_NAMESIZE];
        let mut bound_name_len = bound_name.len() as libc::socklen_t;
        // SAFETY: output pointers are valid for `bound_name_len`; the socket remains live.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                bound_name.as_mut_ptr().cast(),
                &mut bound_name_len,
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        // SAFETY: Linux returns a NUL-terminated interface name for SO_BINDTODEVICE.
        let actual = unsafe { std::ffi::CStr::from_ptr(bound_name.as_ptr()) };
        assert_eq!(actual, interface_name.as_c_str());
    }

    #[test]
    fn desktop_bonded_bind_keeps_local_ip_but_not_the_fixed_port() {
        let mut config = config("tcp", 443);
        config.server.local_address = Some("192.0.2.50".into());
        config.server.local_port = 1194;
        let remote: IpAddr = "198.51.100.10".parse().unwrap();

        assert_eq!(
            desktop_bind_address(&config, remote, true).unwrap(),
            Some("192.0.2.50:1194".parse().unwrap())
        );
        assert_eq!(
            desktop_bind_address(&config, remote, false).unwrap(),
            Some("192.0.2.50:0".parse().unwrap())
        );

        config.server.local_address = None;
        assert_eq!(desktop_bind_address(&config, remote, false).unwrap(), None);
    }
}
