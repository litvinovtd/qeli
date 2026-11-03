//! Linux/Android ancillary addresses, owned by each datagram/path, never by a peer cache.
#![allow(dead_code)] // Source-pinned replies are used by the Linux server.
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalAddress {
    ip: IpAddr,
    scope: u32,
}
impl LocalAddress {
    fn new(ip: IpAddr, interface: u32) -> io::Result<Self> {
        if ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::V4(Ipv4Addr::BROADCAST) {
            return Err(invalid("UDP destination is not unicast"));
        }
        let scope = match ip {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => interface,
            _ => 0,
        };
        if matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local()) && scope == 0 {
            return Err(invalid("UDP link-local destination has no interface"));
        }
        Ok(Self { ip, scope })
    }
    pub(crate) fn socket_addr(self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V4(ip) => SocketAddr::from((ip, port)),
            IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, self.scope)),
        }
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Enough space and native alignment for pktinfo plus SO_RXQ_OVFL. Never retain pointers.
#[derive(Clone, Default)]
pub(crate) struct Control([usize; 64 / std::mem::size_of::<usize>()]);
impl Control {
    pub(crate) fn receive(&mut self, header: &mut libc::msghdr) {
        header.msg_control = self.0.as_mut_ptr().cast();
        header.msg_controllen = std::mem::size_of_val(&self.0) as _;
    }
    pub(crate) fn decode(&self, header: &libc::msghdr) -> io::Result<LocalAddress> {
        #[allow(clippy::unnecessary_cast)] // msghdr field types differ across libc targets.
        let length = header.msg_controllen as usize;
        if header.msg_flags & libc::MSG_CTRUNC != 0 || length > std::mem::size_of_val(&self.0) {
            return Err(invalid("truncated UDP packet info"));
        }
        let base = self.0.as_ptr().cast::<u8>();
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let mut offset = 0;
        let mut found = None;
        while length.saturating_sub(offset) >= std::mem::size_of::<libc::cmsghdr>() {
            // SAFETY: bounds cover the header; unaligned read also supports hostile test input.
            let cmsg =
                unsafe { std::ptr::read_unaligned(base.add(offset).cast::<libc::cmsghdr>()) };
            let size = cmsg.cmsg_len as usize;
            if size < header_len || size > length - offset {
                return Err(invalid("invalid UDP packet info length"));
            }
            let payload = size - header_len;
            let address = match (cmsg.cmsg_level, cmsg.cmsg_type) {
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    if payload != std::mem::size_of::<libc::in_pktinfo>() {
                        return Err(invalid("invalid IPv4 packet info"));
                    }
                    // SAFETY: the complete payload is inside the checked control buffer.
                    let info = unsafe {
                        std::ptr::read_unaligned(
                            base.add(offset + header_len).cast::<libc::in_pktinfo>(),
                        )
                    };
                    if info.ipi_addr.s_addr != info.ipi_spec_dst.s_addr {
                        return Err(invalid("UDP destination is not a local unicast address"));
                    }
                    Some(LocalAddress::new(
                        Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                        0,
                    )?)
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    if payload != std::mem::size_of::<libc::in6_pktinfo>() {
                        return Err(invalid("invalid IPv6 packet info"));
                    }
                    // SAFETY: the complete payload is inside the checked control buffer.
                    let info = unsafe {
                        std::ptr::read_unaligned(
                            base.add(offset + header_len).cast::<libc::in6_pktinfo>(),
                        )
                    };
                    #[allow(clippy::useless_conversion)] // Android: i32 -> u32; Linux: u32 -> u32.
                    let interface = info
                        .ipi6_ifindex
                        .try_into()
                        .map_err(|_| invalid("invalid IPv6 packet info interface"))?;
                    Some(LocalAddress::new(
                        Ipv6Addr::from(info.ipi6_addr.s6_addr).into(),
                        interface,
                    )?)
                }
                _ => None,
            };
            if let Some(address) = address {
                if found.replace(address).is_some() {
                    return Err(invalid("duplicate UDP packet info"));
                }
            }
            let aligned = size
                .checked_add(std::mem::size_of::<usize>() - 1)
                .ok_or_else(|| invalid("UDP control length overflow"))?
                & !(std::mem::size_of::<usize>() - 1);
            offset += aligned;
        }
        found.ok_or_else(|| invalid("UDP destination packet info missing"))
    }
    pub(crate) fn send(
        &mut self,
        source: LocalAddress,
        header: &mut libc::msghdr,
    ) -> io::Result<()> {
        // Android libc uses a signed ipi6_ifindex; Linux uses an unsigned field.
        // Reject an unrepresentable scope instead of wrapping it onto another interface.
        #[allow(clippy::useless_conversion)] // Android: u32 -> i32; Linux: u32 -> u32.
        let interface = source
            .scope
            .try_into()
            .map_err(|_| invalid("IPv6 packet info interface is out of range"))?;
        self.0.fill(0);
        self.receive(header);
        // SAFETY: the aligned owned buffer fits cmsghdr and either pktinfo payload.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(header);
            let payload_len = match source.ip {
                IpAddr::V4(ip) => {
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from_ne_bytes(ip.octets()),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>(),
                        info,
                    );
                    std::mem::size_of::<libc::in_pktinfo>()
                }
                IpAddr::V6(ip) => {
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: interface,
                    };
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>(),
                        info,
                    );
                    std::mem::size_of::<libc::in6_pktinfo>()
                }
            };
            (*cmsg).cmsg_len = libc::CMSG_LEN(payload_len as _) as _;
            header.msg_controllen = libc::CMSG_SPACE(payload_len as _) as _;
        }
        Ok(())
    }
}

pub(crate) fn enable(socket: &tokio::net::UdpSocket) -> io::Result<()> {
    let ipv6 = socket.local_addr()?.is_ipv6();
    let (level, option) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    let value: libc::c_int = 1;
    // SAFETY: live fd and correctly-sized option value; no ownership is transferred.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as _,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Raw nonblocking sendmsg. The caller owns Tokio readiness; never fall back to a new source.
pub(crate) fn send(
    socket: &tokio::net::UdpSocket,
    wire: &[u8],
    peer: SocketAddr,
    source: LocalAddress,
) -> io::Result<usize> {
    if source.ip.is_ipv4() != peer.is_ipv4() {
        return Err(invalid("UDP reply address-family mismatch"));
    }
    let name = socket2::SockAddr::from(peer);
    let mut iovec = libc::iovec {
        iov_base: wire.as_ptr() as *mut _,
        iov_len: wire.len(),
    };
    // SAFETY: zero is valid for the C header, then all used pointers are initialized below.
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_name = name.as_ptr() as *mut _;
    header.msg_namelen = name.len();
    header.msg_iov = &mut iovec;
    header.msg_iovlen = 1;
    let mut control = Control::default();
    control.send(source, &mut header)?;
    // SAFETY: name, iovec, wire and control remain borrowed and alive for this syscall.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &header, libc::MSG_DONTWAIT) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "udp_source/tests.rs"]
mod tests;
