//! Session-aware upstream IPv6 Neighbor Discovery proxy.
//!
//! Some providers deliver a prefix as on-link instead of routing it to the server's own
//! address. Their router consequently sends a Neighbor Solicitation for each VPN client.
//! Relaying all multicast into the tunnel would expose every client to unrelated L2 control
//! traffic and still would not identify the owner of a delegated prefix. This responder keeps
//! NDP on the server: it emits a proxy Neighbor Advertisement only when the current SessionMap
//! contains the exact `/128` lease or a non-default IPv6 `client_subnet` covering the target.

use crate::server::ProfileRuntime;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ICMPV6_NS: u8 = 135;
const ICMPV6_NA: u8 = 136;
const ICMPV6_NEXT_HEADER: u8 = 58;
const PACKET_OUTGOING: u8 = 4;
const SOL_PACKET: libc::c_int = 263;
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
const MAX_FRAME_SIZE: usize = 65_535 + 64;
const RATE_WINDOW: Duration = Duration::from_secs(1);
const GLOBAL_RESPONSES_PER_WINDOW: u32 = 4_096;
const RESPONSES_PER_MAC_PER_WINDOW: u32 = 256;
const MAX_RATE_SOURCES: usize = 4_096;
const MAX_KNOWN_TARGETS: usize = 1_024;
const ANNOUNCEMENTS_PER_TICK: usize = 16;
const MEMBERSHIP_REFRESH: Duration = Duration::from_secs(1);

pub(crate) struct NdpProxy {
    fd: AsyncFd<OwnedFd>,
    interface: String,
    ifindex: i32,
    mac: [u8; 6],
    memberships: OwnedFd,
    policy: crate::config::server::Ipv6RoutingConfig,
}

/// A socket created in the worker's network namespace, before Tokio registration.
/// If startup is cancelled before adoption, its fd closes on that worker.
struct BoundNdpProxy {
    fd: OwnedFd,
    interface: String,
    ifindex: i32,
    mac: [u8; 6],
}

/// Keep the responder's startup requirement independent from firewall ownership.
pub(crate) async fn start(
    profile: &str,
    mode: crate::config::server::Ipv6NdpProxyMode,
    interface: Option<&str>,
    policy: &crate::config::server::Ipv6RoutingConfig,
) -> anyhow::Result<Option<NdpProxy>> {
    use crate::config::server::Ipv6NdpProxyMode;
    if mode == Ipv6NdpProxyMode::Off {
        return Ok(None);
    }
    let worker_profile = profile.to_owned();
    let worker_interface = interface.map(str::to_owned);
    let bound = crate::profile_teardown::blocking("qeli-profile-ndp-bind", move || {
        start_with(
            &worker_profile,
            mode,
            worker_interface.as_deref(),
            BoundNdpProxy::bind,
        )
    })
    .await??;
    match bound {
        None => Ok(None),
        Some(bound) => match NdpProxy::register(bound, policy.clone()) {
            Ok(proxy) => Ok(Some(proxy)),
            Err(error) if mode == Ipv6NdpProxyMode::Auto => {
                log::warn!("Profile '{profile}': IPv6 NDP proxy auto mode is unavailable: {error} — continuing without it");
                Ok(None)
            }
            Err(error) => anyhow::bail!("profile '{profile}': routing.ipv6.ndp_proxy = required but the responder could not start: {error}"),
        },
    }
}

fn start_with<T>(
    profile: &str,
    mode: crate::config::server::Ipv6NdpProxyMode,
    interface: Option<&str>,
    bind: impl FnOnce(&str) -> anyhow::Result<T>,
) -> anyhow::Result<Option<T>> {
    use crate::config::server::Ipv6NdpProxyMode;
    if mode == Ipv6NdpProxyMode::Off {
        return Ok(None);
    }
    let result = interface
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no IPv6 uplink was detected; set routing.ipv6.ndp_proxy_interface explicitly"
            )
        })
        .and_then(bind);
    match result {
        Ok(proxy) => Ok(Some(proxy)),
        Err(error) if mode == Ipv6NdpProxyMode::Auto => {
            log::warn!("Profile '{profile}': IPv6 NDP proxy auto mode is unavailable: {error} — continuing without it");
            Ok(None)
        }
        Err(error) => anyhow::bail!("profile '{profile}': routing.ipv6.ndp_proxy = required but the responder could not start: {error}"),
    }
}

impl BoundNdpProxy {
    fn bind(interface: &str) -> anyhow::Result<Self> {
        let interface = interface.trim();
        if interface.is_empty()
            || interface.len() > 15
            || interface.contains('/')
            || interface.contains('\\')
            || interface.contains('\0')
            || interface.contains(char::is_whitespace)
        {
            anyhow::bail!("invalid NDP proxy interface name '{interface}'");
        }
        let (ifindex, mac) = crate::network_interface::ethernet(interface).map_err(|error| {
            anyhow::anyhow!("cannot inspect NDP interface '{interface}': {error}")
        })?;
        if mac == [0; 6] || mac[0] & 1 != 0 {
            anyhow::bail!("interface '{interface}' has no usable unicast MAC address");
        }
        let protocol = i32::from(ETH_P_IPV6.to_be());
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if raw < 0 {
            return Err(anyhow::anyhow!(
                "cannot open AF_PACKET socket on '{interface}': {}",
                io::Error::last_os_error()
            ));
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETH_P_IPV6.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let bind_result = unsafe {
            libc::bind(
                owned.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if bind_result != 0 {
            return Err(anyhow::anyhow!(
                "cannot bind AF_PACKET socket to '{interface}': {}",
                io::Error::last_os_error()
            ));
        }
        // Client /128 addresses are intentionally not assigned to this host, so the NIC is
        // not subscribed to their many solicited-node multicast MACs. A packet socket alone
        // does not change the physical multicast filter. Join ALLMULTI for this socket only;
        // the membership is released automatically with the fd and does not toggle the
        // interface's persistent IFF_ALLMULTI flag.
        let membership = libc::packet_mreq {
            mr_ifindex: ifindex as i32,
            mr_type: libc::PACKET_MR_ALLMULTI as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        let membership_result = unsafe {
            libc::setsockopt(
                owned.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                (&membership as *const libc::packet_mreq).cast(),
                std::mem::size_of_val(&membership) as libc::socklen_t,
            )
        };
        if membership_result != 0 {
            return Err(anyhow::anyhow!(
                "cannot enable socket-local all-multicast reception on '{interface}': {}",
                io::Error::last_os_error()
            ));
        }
        // Best-effort kernel filtering; recv_frame also rejects PACKET_OUTGOING so older
        // kernels remain correct when this socket option is unavailable.
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                owned.as_raw_fd(),
                SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of_val(&one) as libc::socklen_t,
            );
        }
        Ok(Self {
            fd: owned,
            interface: interface.to_string(),
            ifindex: ifindex as i32,
            mac,
        })
    }
}

impl NdpProxy {
    fn register(
        bound: BoundNdpProxy,
        policy: crate::config::server::Ipv6RoutingConfig,
    ) -> anyhow::Result<Self> {
        // SAFETY: OwnedFd owns the open socket. NdpProxy never replaces or closes
        // its inner descriptor while registered; I/O only borrows it through
        // get_ref(), and dropping AsyncFd deregisters before dropping OwnedFd.
        let fd = unsafe { AsyncFd::register(bound.fd) }
            .map_err(|error| anyhow::anyhow!("cannot register NDP socket: {error}"))?;
        selected_source(bound.ifindex, &policy.ndp_proxy_source)?;
        let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let memberships = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd,
            interface: bound.interface,
            ifindex: bound.ifindex,
            mac: bound.mac,
            memberships,
            policy,
        })
    }

    pub(crate) async fn run(self, profile: Arc<ProfileRuntime>) -> anyhow::Result<()> {
        log::info!(
            "Profile '{}': session-aware IPv6 NDP proxy active on '{}' ({})",
            profile.name,
            self.interface,
            format_mac(self.mac)
        );
        let mut frame = vec![0u8; MAX_FRAME_SIZE];
        let mut limiter = NdpRateLimiter::new(Instant::now());
        let mut refresh = tokio::time::interval(MEMBERSHIP_REFRESH);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut announced = HashMap::<Ipv6Addr, (u64, Instant)>::new();
        let mut groups = HashSet::new();
        let mut source = selected_source(self.ifindex, &self.policy.ndp_proxy_source).ok();
        loop {
            let incoming = tokio::select! {
                _ = refresh.tick() => {
                    // A replacement interface with the same name is not this socket's owner.
                    let (index, mac) = crate::network_interface::ethernet(&self.interface)?;
                    if index != self.ifindex as u32 || mac != self.mac {
                        anyhow::bail!("NDP uplink '{}' was replaced", self.interface);
                    }
                    let next_source = selected_source(self.ifindex, &self.policy.ndp_proxy_source).ok();
                    if source.is_some() && next_source.is_none() {
                        log::warn!("Profile '{}': NDP paused: no usable IPv6 source on '{}'", profile.name, self.interface);
                    }
                    if source != next_source { announced.clear(); }
                    source = next_source;
                    let targets = {
                        let sessions = profile.sessions.read().await;
                        known_targets(&sessions)
                    };
                    let desired: HashSet<_> = targets.keys().copied().map(solicited_node_multicast).collect();
                    // Remove before joining to respect the membership bound during churn.
                    for group in groups.difference(&desired) {
                        update_membership(self.memberships.as_raw_fd(), self.ifindex, *group, false)?;
                    }
                    for group in desired.difference(&groups) {
                        update_membership(self.memberships.as_raw_fd(), self.ifindex, *group, true)?;
                    }
                    groups = desired;
                    announced.retain(|address, (owner, _)| targets.get(address) == Some(owner));
                    if let Some(source) = source {
                        let pending = pending_announcements(&targets, &announced, Instant::now(), self.policy.ndp_proxy_announce_interval_secs);
                        for (target, owner) in pending {
                            if !limiter.allow(self.mac, Instant::now()) { break; }
                            let response = build_unsolicited_with_policy(target, source, self.mac, self.policy.ndp_proxy_router, self.policy.ndp_proxy_override);
                            if self.send_owned(&profile, target, owner, &response).await? {
                                announced.insert(target, (owner, Instant::now()));
                            }
                        }
                    }
                    continue;
                }
                ready = self.fd.readable() => ready?,
            };
            let mut incoming = incoming;
            let (length, outgoing) = match incoming
                .try_io(|inner| recv_frame(inner.get_ref().as_raw_fd(), &mut frame))
            {
                Ok(result) => result?,
                Err(_) => continue,
            };
            if outgoing {
                continue;
            }
            let Some(request) = parse_solicitation(&frame[..length]) else {
                continue;
            };
            let Some(source) = source else {
                continue;
            };
            let owner = profile
                .sessions
                .read()
                .await
                .ipv6_neighbor_owner(request.target);
            let Some(owner) = owner else {
                continue;
            };
            if !limiter.allow(request.source_mac, Instant::now()) {
                if limiter.take_warning() {
                    log::warn!(
                        "Profile '{}': IPv6 NDP proxy rate limit reached on '{}'",
                        profile.name,
                        self.interface
                    );
                }
                continue;
            }
            let target = request.target;
            let response = build_advertisement_with_policy(
                &frame[..length],
                request,
                self.mac,
                source,
                self.policy.ndp_proxy_router,
                self.policy.ndp_proxy_override,
                false,
            );
            if self.send_owned(&profile, target, owner, &response).await?
                && (announced.contains_key(&target) || announced.len() < MAX_KNOWN_TARGETS)
            {
                announced.insert(target, (owner, Instant::now()));
            }
        }
    }

    async fn send_owned(
        &self,
        profile: &ProfileRuntime,
        target: Ipv6Addr,
        owner: u64,
        response: &Advertisement,
    ) -> anyhow::Result<bool> {
        // Never retain the session read guard across writable(). Recheck the exact
        // generation after every readiness wait; keep the guard through nonblocking send.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        loop {
            let mut ready = match tokio::time::timeout_at(deadline, self.fd.writable()).await {
                Ok(ready) => ready?,
                Err(_) => return Ok(false),
            };
            let sessions = profile.sessions.read().await;
            if sessions.ipv6_neighbor_owner(target) != Some(owner) {
                return Ok(false);
            }
            match ready.try_io(|inner| {
                send_frame(
                    inner.get_ref().as_raw_fd(),
                    self.ifindex,
                    response.destination_mac,
                    &response.bytes,
                )
            }) {
                Ok(result) => {
                    result?;
                    return Ok(true);
                }
                Err(_) => continue,
            }
        }
    }
}

fn usable_source_rows_selected(
    rows: &str,
    ifindex: i32,
    requested: Option<Ipv6Addr>,
) -> Option<Ipv6Addr> {
    let mut choices = Vec::new();
    for row in rows.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.len() != 6 || u32::from_str_radix(fields[1], 16).ok() != Some(ifindex as u32) {
            continue;
        }
        let Some(flags) = u32::from_str_radix(fields[4], 16).ok() else {
            continue;
        };
        // Do not borrow tentative, DAD-failed, deprecated or optimistic addresses.
        if flags & (0x08 | 0x20 | 0x40 | 0x04) != 0 {
            continue;
        }
        let Some(bits) = u128::from_str_radix(fields[0], 16).ok() else {
            continue;
        };
        let address = Ipv6Addr::from(bits);
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.to_ipv4_mapped().is_some()
        {
            continue;
        }
        choices.push(address);
    }
    choices.sort_by_key(|a| (!a.is_unicast_link_local(), *a));
    choices
        .into_iter()
        .find(|address| requested.is_none_or(|requested| requested == *address))
}

#[cfg(test)]
fn usable_source_rows(rows: &str, ifindex: i32) -> Option<Ipv6Addr> {
    usable_source_rows_selected(rows, ifindex, None)
}

#[cfg(test)]
fn assigned_source(ifindex: i32) -> anyhow::Result<Ipv6Addr> {
    selected_source(ifindex, "")
}

fn selected_source(ifindex: i32, requested: &str) -> anyhow::Result<Ipv6Addr> {
    let requested = match requested.trim() {
        "" | "auto" => None,
        value => Some(value.parse::<Ipv6Addr>()?),
    };
    // procfs reflects the current worker network namespace, not the startup namespace.
    let rows = std::fs::read_to_string("/proc/thread-self/net/if_inet6")?;
    usable_source_rows_selected(&rows, ifindex, requested).ok_or_else(|| {
        anyhow::anyhow!(
            "NDP uplink has no usable assigned IPv6 source matching {:?}",
            requested
        )
    })
}

/// Initial announcements first, then oldest refreshes; bounded work cannot starve later leases.
fn pending_announcements(
    targets: &HashMap<Ipv6Addr, u64>,
    announced: &HashMap<Ipv6Addr, (u64, Instant)>,
    now: Instant,
    interval: u64,
) -> Vec<(Ipv6Addr, u64)> {
    let mut pending: Vec<_> = targets
        .iter()
        .filter_map(|(target, owner)| {
            let last = announced
                .get(target)
                .filter(|(previous, _)| previous == owner)
                .map(|(_, time)| *time);
            (last.is_none()
                || (interval != 0
                    && last.is_some_and(|time| {
                        now.saturating_duration_since(time) >= Duration::from_secs(interval)
                    })))
            .then_some((last, *target, *owner))
        })
        .collect();
    pending.sort_unstable();
    pending
        .into_iter()
        .take(ANNOUNCEMENTS_PER_TICK)
        .map(|(_, target, owner)| (target, owner))
        .collect()
}

fn update_membership(fd: i32, ifindex: i32, group: Ipv6Addr, join: bool) -> io::Result<()> {
    let request = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr {
            s6_addr: group.octets(),
        },
        ipv6mr_interface: ifindex as u32,
    };
    let option = if join {
        libc::IPV6_ADD_MEMBERSHIP
    } else {
        libc::IPV6_DROP_MEMBERSHIP
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            option,
            (&request as *const libc::ipv6_mreq).cast(),
            std::mem::size_of_val(&request) as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn known_targets(sessions: &crate::server::SessionMap) -> HashMap<Ipv6Addr, u64> {
    use std::sync::atomic::Ordering;
    // Only concrete, fully admitted leases. Never enumerate a delegated prefix.
    let mut targets: Vec<_> = sessions
        .by_address
        .iter()
        .filter_map(|(address, session)| {
            let std::net::IpAddr::V6(address) = address else {
                return None;
            };
            (proxyable_target(*address)
                && session.ndp_ready.load(Ordering::Acquire)
                && sessions.ipv6_neighbor_owner(*address) == Some(session.session_id))
            .then_some((*address, session.session_id))
        })
        .collect();
    targets.sort_unstable();
    targets.into_iter().take(MAX_KNOWN_TARGETS).collect()
}

#[cfg(test)]
fn build_unsolicited(target: Ipv6Addr, source: Ipv6Addr, proxy_mac: [u8; 6]) -> Advertisement {
    build_unsolicited_with_policy(target, source, proxy_mac, false, false)
}

fn build_unsolicited_with_policy(
    target: Ipv6Addr,
    source: Ipv6Addr,
    proxy_mac: [u8; 6],
    router: bool,
    override_flag: bool,
) -> Advertisement {
    let mut ethernet = [0u8; 14];
    ethernet[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    build_advertisement_with_policy(
        &ethernet,
        Solicitation {
            l3_offset: 14,
            source_mac: [0; 6],
            source_ip: Ipv6Addr::UNSPECIFIED,
            target,
            dad: true,
        },
        proxy_mac,
        source,
        router,
        override_flag,
        true,
    )
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn recv_frame(fd: i32, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let length = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
            (&mut address as *mut libc::sockaddr_ll).cast(),
            &mut address_len,
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((length as usize, address.sll_pkttype == PACKET_OUTGOING))
}

fn send_frame(fd: i32, ifindex: i32, destination: [u8; 6], frame: &[u8]) -> io::Result<()> {
    let mut address = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_IPV6.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0; 8],
    };
    address.sll_addr[..6].copy_from_slice(&destination);
    let written = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("partial NDP frame send: {written}/{}", frame.len()),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Solicitation {
    l3_offset: usize,
    source_mac: [u8; 6],
    source_ip: Ipv6Addr,
    target: Ipv6Addr,
    dad: bool,
}

fn parse_solicitation(frame: &[u8]) -> Option<Solicitation> {
    if frame.len() < 14 {
        return None;
    }
    let source_mac: [u8; 6] = frame[6..12].try_into().ok()?;
    if source_mac == [0; 6] || source_mac[0] & 1 != 0 {
        return None;
    }
    let mut ether_type = u16::from_be_bytes(frame[12..14].try_into().ok()?);
    let mut l3_offset = 14usize;
    let mut vlan_depth = 0;
    while matches!(ether_type, ETH_P_8021Q | ETH_P_8021AD) {
        if vlan_depth == 2 || frame.len() < l3_offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes(frame[l3_offset + 2..l3_offset + 4].try_into().ok()?);
        l3_offset += 4;
        vlan_depth += 1;
    }
    if ether_type != ETH_P_IPV6 || frame.len() < l3_offset + 40 {
        return None;
    }
    let ipv6 = &frame[l3_offset..];
    if ipv6[0] >> 4 != 6 || ipv6[6] != ICMPV6_NEXT_HEADER || ipv6[7] != 255 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes(ipv6[4..6].try_into().ok()?));
    let packet_len = 40usize.checked_add(payload_len)?;
    if payload_len < 24 || packet_len > ipv6.len() {
        return None;
    }
    let source_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[8..24]).ok()?);
    let destination_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[24..40]).ok()?);
    let icmp = &ipv6[40..packet_len];
    if icmp[0] != ICMPV6_NS || icmp[1] != 0 || icmpv6_checksum(source_ip, destination_ip, icmp) != 0
    {
        return None;
    }
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&icmp[8..24]).ok()?);
    if !proxyable_target(target) {
        return None;
    }
    if destination_ip.is_multicast() && destination_ip != solicited_node_multicast(target) {
        return None;
    }
    if destination_ip.is_unspecified()
        || (!source_ip.is_unspecified() && (source_ip.is_multicast() || source_ip.is_loopback()))
    {
        return None;
    }
    let dad = source_ip.is_unspecified();
    // RFC 4861 section 7.1.1: source :: is valid only for DAD addressed to
    // the target's solicited-node multicast group, never a unicast destination.
    if dad && destination_ip != solicited_node_multicast(target) {
        return None;
    }
    let mut options = &icmp[24..];
    while !options.is_empty() {
        if options.len() < 2 {
            return None;
        }
        let length = usize::from(options[1]).checked_mul(8)?;
        if length == 0 || length > options.len() {
            return None;
        }
        // RFC 4861: a DAD solicitation (source ::) must not contain SLLA.
        if dad && options[0] == 1 {
            return None;
        }
        options = &options[length..];
    }
    Some(Solicitation {
        l3_offset,
        source_mac,
        source_ip,
        target,
        dad,
    })
}

fn proxyable_target(target: Ipv6Addr) -> bool {
    let first = target.segments()[0];
    !target.is_unspecified()
        && !target.is_loopback()
        && !target.is_multicast()
        && first & 0xffc0 != 0xfe80
        && target.to_ipv4_mapped().is_none()
}

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target = target.octets();
    let mut address = [0u8; 16];
    address[0] = 0xff;
    address[1] = 0x02;
    address[11] = 0x01;
    address[12] = 0xff;
    address[13..].copy_from_slice(&target[13..]);
    Ipv6Addr::from(address)
}

struct Advertisement {
    destination_mac: [u8; 6],
    bytes: Vec<u8>,
}

#[cfg(test)]
fn build_advertisement(
    request_frame: &[u8],
    request: Solicitation,
    proxy_mac: [u8; 6],
    source: Ipv6Addr,
) -> Advertisement {
    build_advertisement_with_policy(
        request_frame,
        request,
        proxy_mac,
        source,
        false,
        false,
        false,
    )
}

fn build_advertisement_with_policy(
    request_frame: &[u8],
    request: Solicitation,
    proxy_mac: [u8; 6],
    source: Ipv6Addr,
    router: bool,
    override_flag: bool,
    unsolicited: bool,
) -> Advertisement {
    // Proxy Override defaults to zero (RFC 4861 7.2.8). Expert opt-in never sets
    // Solicited/Override on a DAD reply; unsolicited refreshes are a separate case.
    let (destination_ip, destination_mac, flags) = if request.dad {
        (
            "ff02::1".parse::<Ipv6Addr>().expect("constant IPv6"),
            [0x33, 0x33, 0, 0, 0, 1],
            0u32,
        )
    } else {
        (request.source_ip, request.source_mac, 0x4000_0000u32)
    };
    let flags = flags
        | if router { 0x8000_0000 } else { 0 }
        | if override_flag && (!request.dad || unsolicited) {
            0x2000_0000
        } else {
            0
        };
    let mut frame = Vec::with_capacity(request.l3_offset + 72);
    frame.extend_from_slice(&request_frame[..request.l3_offset]);
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&proxy_mac);

    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60;
    ipv6[4..6].copy_from_slice(&32u16.to_be_bytes());
    ipv6[6] = ICMPV6_NEXT_HEADER;
    ipv6[7] = 255;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination_ip.octets());
    frame.extend_from_slice(&ipv6);

    let mut icmp = [0u8; 32];
    icmp[0] = ICMPV6_NA;
    icmp[4..8].copy_from_slice(&flags.to_be_bytes());
    icmp[8..24].copy_from_slice(&request.target.octets());
    icmp[24] = 2; // Target Link-Layer Address
    icmp[25] = 1; // 8-byte option
    icmp[26..32].copy_from_slice(&proxy_mac);
    let checksum = icmpv6_checksum(source, destination_ip, &icmp);
    icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    frame.extend_from_slice(&icmp);
    Advertisement {
        destination_mac,
        bytes: frame,
    }
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = add_words(sum, &source.octets());
    sum = add_words(sum, &destination.octets());
    sum = add_words(sum, &(payload.len() as u32).to_be_bytes());
    sum = add_words(sum, &[0, 0, 0, ICMPV6_NEXT_HEADER]);
    sum = add_words(sum, payload);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

struct NdpRateLimiter {
    window_started: Instant,
    global: u32,
    by_mac: HashMap<[u8; 6], u32>,
    warning_pending: bool,
    warning_reported: bool,
}

impl NdpRateLimiter {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            global: 0,
            by_mac: HashMap::new(),
            warning_pending: false,
            warning_reported: false,
        }
    }

    fn allow(&mut self, source: [u8; 6], now: Instant) -> bool {
        if now.duration_since(self.window_started) >= RATE_WINDOW {
            self.window_started = now;
            self.global = 0;
            self.by_mac.clear();
            self.warning_pending = false;
            self.warning_reported = false;
        }
        if self.global >= GLOBAL_RESPONSES_PER_WINDOW {
            self.warning_pending = true;
            return false;
        }
        if !self.by_mac.contains_key(&source) && self.by_mac.len() >= MAX_RATE_SOURCES {
            self.warning_pending = true;
            return false;
        }
        let source_count = self.by_mac.entry(source).or_default();
        if *source_count >= RESPONSES_PER_MAC_PER_WINDOW {
            self.warning_pending = true;
            return false;
        }
        self.global += 1;
        *source_count += 1;
        true
    }

    fn take_warning(&mut self) -> bool {
        let pending = std::mem::take(&mut self.warning_pending);
        if pending && !self.warning_reported {
            self.warning_reported = true;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_source_never_falls_back_or_uses_another_interface() {
        let rows = "20010db8000000000000000000000001 02 40 00 80 uplink\nfe800000000000000000000000000001 02 40 20 80 uplink\n20010db8000000000000000000000002 03 40 00 80 other\n20010db8000000000000000000000003 02 40 00 88 uplink\n";
        let selected = "2001:db8::1".parse().unwrap();
        assert_eq!(
            usable_source_rows_selected(rows, 2, Some(selected)),
            Some(selected)
        );
        for address in ["2001:db8::2", "2001:db8::3", "2001:db8::4"] {
            assert_eq!(
                usable_source_rows_selected(rows, 2, Some(address.parse().unwrap())),
                None
            );
        }
    }

    #[test]
    fn periodic_announcements_are_bounded_fair_and_generation_aware() {
        let now = Instant::now();
        let targets: HashMap<_, _> = (1..=32)
            .map(|i| {
                (
                    Ipv6Addr::from(0x20010db8000000000000000000000000u128 + i),
                    1,
                )
            })
            .collect();
        let mut sent = HashMap::new();
        let first = pending_announcements(&targets, &sent, now, 0);
        assert_eq!(first.len(), ANNOUNCEMENTS_PER_TICK);
        for (ip, owner) in &first {
            sent.insert(*ip, (*owner, now));
        }
        let next = pending_announcements(&targets, &sent, now, 0);
        assert_eq!(next.len(), ANNOUNCEMENTS_PER_TICK);
        assert!(next.iter().all(|item| !first.contains(item)));
        for (ip, owner) in &next {
            sent.insert(*ip, (*owner, now));
        }
        assert!(
            pending_announcements(&targets, &sent, now + Duration::from_secs(600), 0).is_empty()
        );
        assert!(
            pending_announcements(&targets, &sent, now + Duration::from_secs(59), 60).is_empty()
        );
        let refreshed = pending_announcements(&targets, &sent, now + Duration::from_secs(60), 60);
        for (ip, owner) in &refreshed {
            sent.insert(*ip, (*owner, now + Duration::from_secs(60)));
        }
        assert!(
            pending_announcements(&targets, &sent, now + Duration::from_secs(60), 60)
                .iter()
                .all(|item| !refreshed.contains(item))
        );
        let mut replacement = targets.clone();
        replacement.insert(first[0].0, 2);
        assert_eq!(
            pending_announcements(&replacement, &sent, now + Duration::from_secs(1), 0),
            vec![(first[0].0, 2)]
        );
    }

    #[test]
    fn configured_flags_preserve_dad_and_checksum_rules() {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target = "2001:db8::42".parse().unwrap();
        let mac = [2, 1, 2, 3, 4, 5];
        for router in [false, true] {
            for override_flag in [false, true] {
                let reply =
                    build_unsolicited_with_policy(target, source, mac, router, override_flag);
                let expected: u32 = if router { 0x8000_0000 } else { 0 }
                    | if override_flag { 0x2000_0000 } else { 0 };
                assert_eq!(&reply.bytes[58..62], &expected.to_be_bytes());
                assert_eq!(
                    icmpv6_checksum(source, "ff02::1".parse().unwrap(), &reply.bytes[54..]),
                    0
                );
                let frame = solicitation(Ipv6Addr::UNSPECIFIED, target, false);
                let request = parse_solicitation(&frame).unwrap();
                let reply = build_advertisement_with_policy(
                    &frame,
                    request,
                    mac,
                    source,
                    router,
                    override_flag,
                    false,
                );
                let flags = u32::from_be_bytes(reply.bytes[58..62].try_into().unwrap());
                assert_eq!(flags & 0x6000_0000, 0, "DAD never sets Solicited/Override");
                let frame = solicitation("fe80::1234".parse().unwrap(), target, true);
                let request = parse_solicitation(&frame).unwrap();
                let reply = build_advertisement_with_policy(
                    &frame,
                    request,
                    mac,
                    source,
                    router,
                    override_flag,
                    false,
                );
                assert_eq!(
                    u32::from_be_bytes(reply.bytes[58..62].try_into().unwrap()),
                    expected | 0x4000_0000
                );
            }
        }
    }

    #[test]
    fn required_ndp_refuses_missing_links_and_bind_failures_in_any_routing_mode() {
        use crate::config::server::Ipv6NdpProxyMode::{Auto, Off, Required};
        let missing =
            start_with::<()>("manual", Required, None, |_| panic!("no link to bind")).unwrap_err();
        assert!(missing
            .to_string()
            .contains("set routing.ipv6.ndp_proxy_interface"));
        let refused = start_with::<()>("manual", Required, Some("ens3"), |_| {
            anyhow::bail!("fixture bind failure")
        })
        .unwrap_err();
        assert!(refused
            .to_string()
            .contains("required but the responder could not start"));
        assert!(refused.to_string().contains("fixture bind failure"));
        assert!(
            start_with::<()>("manual", Auto, Some("ens3"), |_| anyhow::bail!(
                "fixture bind failure"
            ))
            .unwrap()
            .is_none()
        );
        assert!(start_with::<()>("manual", Off, Some("ens3"), |_| panic!(
            "disabled responder"
        ))
        .unwrap()
        .is_none());
        assert_eq!(
            start_with(
                "manual",
                Required,
                Some("ens3"),
                |link| Ok(link.to_string())
            )
            .unwrap()
            .as_deref(),
            Some("ens3")
        );
    }

    fn solicitation(source: Ipv6Addr, target: Ipv6Addr, include_slla: bool) -> Vec<u8> {
        let source_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let destination = solicited_node_multicast(target);
        let mut frame = vec![0u8; 14 + 40];
        frame[..6].copy_from_slice(&[
            0x33,
            0x33,
            0xff,
            target.octets()[13],
            target.octets()[14],
            target.octets()[15],
        ]);
        frame[6..12].copy_from_slice(&source_mac);
        frame[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        frame[14] = 0x60;
        let payload_len = if include_slla { 32u16 } else { 24u16 };
        frame[18..20].copy_from_slice(&payload_len.to_be_bytes());
        frame[20] = ICMPV6_NEXT_HEADER;
        frame[21] = 255;
        frame[22..38].copy_from_slice(&source.octets());
        frame[38..54].copy_from_slice(&destination.octets());
        let mut icmp = vec![0u8; usize::from(payload_len)];
        icmp[0] = ICMPV6_NS;
        icmp[8..24].copy_from_slice(&target.octets());
        if include_slla {
            icmp[24] = 1;
            icmp[25] = 1;
            icmp[26..32].copy_from_slice(&source_mac);
        }
        let checksum = icmpv6_checksum(source, destination, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        frame.extend_from_slice(&icmp);
        frame
    }

    #[test]
    fn valid_solicitation_builds_a_valid_proxy_advertisement() {
        let source = "fe80::1234".parse().unwrap();
        let target = "2001:db8:100::42".parse().unwrap();
        let request = solicitation(source, target, true);
        let parsed = parse_solicitation(&request).unwrap();
        let proxy_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let reply = build_advertisement(&request, parsed, proxy_mac, "fe80::99".parse().unwrap());

        assert_eq!(&reply.bytes[..6], &parsed.source_mac);
        assert_eq!(&reply.bytes[6..12], &proxy_mac);
        let ipv6 = &reply.bytes[14..];
        assert_eq!(ipv6[7], 255);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[8..24]).unwrap()),
            "fe80::99".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[48..64]).unwrap()),
            target
        );
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[24..40]).unwrap()),
            source
        );
        let icmp = &ipv6[40..72];
        assert_eq!(icmp[0], ICMPV6_NA);
        assert_eq!(
            u32::from_be_bytes(icmp[4..8].try_into().unwrap()),
            0x4000_0000
        );
        assert_eq!(
            icmpv6_checksum("fe80::99".parse().unwrap(), source, icmp),
            0
        );
    }

    #[test]
    fn source_selection_uses_only_ready_addresses_on_the_bound_interface() {
        let rows = "20010db8000000000000000000000001 02 40 00 80 uplink\nfe800000000000000000000000000001 03 40 20 80 other\nfe800000000000000000000000000002 02 40 20 c0 uplink\nfe800000000000000000000000000003 02 40 20 88 uplink\n";
        assert_eq!(
            usable_source_rows(rows, 2),
            Some("2001:db8::1".parse().unwrap())
        );
        let ready = format!("{rows}fe800000000000000000000000000004 02 40 20 80 uplink\n");
        assert_eq!(
            usable_source_rows(&ready, 2),
            Some("fe80::4".parse().unwrap())
        );
        assert_eq!(usable_source_rows(&ready, 4), None);
    }

    #[test]
    fn unsolicited_proxy_announcement_has_no_solicited_or_override_flag() {
        let source = "fe80::1".parse().unwrap();
        let target = "2001:db8::42".parse().unwrap();
        let reply = build_unsolicited(target, source, [2, 1, 2, 3, 4, 5]);
        assert_eq!(reply.destination_mac, [0x33, 0x33, 0, 0, 0, 1]);
        let v6 = &reply.bytes[14..];
        assert_eq!(&v6[8..24], &source.octets());
        assert_eq!(&v6[48..64], &target.octets());
        assert_eq!(&v6[44..48], &[0; 4]);
        assert_eq!(v6[7], 255);
        assert_eq!(
            icmpv6_checksum(source, "ff02::1".parse().unwrap(), &v6[40..]),
            0
        );
    }

    #[test]
    fn malformed_or_unsafe_solicitations_are_ignored() {
        let source = "fe80::1234".parse().unwrap();
        let target = "2001:db8:100::42".parse().unwrap();
        let valid = solicitation(source, target, true);

        let mut bad_hop = valid.clone();
        bad_hop[21] = 64;
        assert!(parse_solicitation(&bad_hop).is_none());
        let mut bad_checksum = valid.clone();
        *bad_checksum.last_mut().unwrap() ^= 1;
        assert!(parse_solicitation(&bad_checksum).is_none());
        let multicast_target = solicitation(source, "ff02::1".parse().unwrap(), true);
        assert!(parse_solicitation(&multicast_target).is_none());
        let dad_with_slla = solicitation(Ipv6Addr::UNSPECIFIED, target, true);
        assert!(parse_solicitation(&dad_with_slla).is_none());
    }

    #[test]
    fn dad_gets_an_unsolicited_all_nodes_advertisement() {
        let target = "2001:db8:100::42".parse().unwrap();
        let request = solicitation(Ipv6Addr::UNSPECIFIED, target, false);
        let parsed = parse_solicitation(&request).unwrap();
        let reply = build_advertisement(
            &request,
            parsed,
            [0x02, 1, 2, 3, 4, 5],
            "fe80::99".parse().unwrap(),
        );
        assert_eq!(reply.destination_mac, [0x33, 0x33, 0, 0, 0, 1]);
        let ipv6 = &reply.bytes[14..];
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&ipv6[24..40]).unwrap()),
            "ff02::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(u32::from_be_bytes(ipv6[44..48].try_into().unwrap()), 0);
        assert_eq!(
            icmpv6_checksum(
                "fe80::99".parse().unwrap(),
                "ff02::1".parse().unwrap(),
                &ipv6[40..72]
            ),
            0
        );
    }

    #[test]
    fn dad_with_a_unicast_destination_is_discarded() {
        let target: Ipv6Addr = "2001:db8:100::42".parse().unwrap();
        let valid = solicitation(Ipv6Addr::UNSPECIFIED, target, false);
        assert!(parse_solicitation(&valid).is_some());
        for destination in [target, "2001:db8:ffff::1".parse().unwrap()] {
            let mut invalid = valid.clone();
            invalid[38..54].copy_from_slice(&destination.octets());
            invalid[56..58].fill(0);
            let checksum = icmpv6_checksum(Ipv6Addr::UNSPECIFIED, destination, &invalid[54..]);
            invalid[56..58].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(
                icmpv6_checksum(Ipv6Addr::UNSPECIFIED, destination, &invalid[54..]),
                0
            );
            assert!(parse_solicitation(&invalid).is_none());
        }
    }

    #[test]
    fn rate_limit_warning_is_emitted_once_per_window() {
        let start = Instant::now();
        let mac = [0x02, 1, 2, 3, 4, 5];
        let mut limiter = NdpRateLimiter::new(start);
        for window in [start, start + RATE_WINDOW] {
            for _ in 0..RESPONSES_PER_MAC_PER_WINDOW {
                assert!(limiter.allow(mac, window));
                assert!(!limiter.take_warning());
            }
            for rejected in 0..512 {
                assert!(!limiter.allow(mac, window));
                assert_eq!(limiter.take_warning(), rejected == 0);
                assert!(!limiter.take_warning());
            }
        }
    }

    #[test]
    fn rate_limiter_is_bounded_and_resets() {
        let start = Instant::now();
        let mut limiter = NdpRateLimiter::new(start);
        let mac = [0x02, 1, 2, 3, 4, 5];
        for _ in 0..RESPONSES_PER_MAC_PER_WINDOW {
            assert!(limiter.allow(mac, start));
        }
        assert!(!limiter.allow(mac, start));
        assert!(limiter.take_warning());
        assert!(limiter.allow(mac, start + RATE_WINDOW));
        assert!(!limiter.take_warning());
    }
}

#[cfg(test)]
mod native_network_view_tests {
    use super::*;
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN/CAP_NET_RAW and ip; isolated netns"]
    fn native_ndp_bind_uses_calling_namespace_without_sysfs_remount() -> anyhow::Result<()> {
        std::thread::spawn(|| -> anyhow::Result<()> {
            // SAFETY: only this new disposable thread changes namespace.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let name = "qeli-view2";
            anyhow::ensure!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
            for args in [
                vec!["link", "add", name, "type", "dummy"],
                vec!["link", "set", name, "address", "02:12:34:56:78:9c"],
                vec!["link", "set", name, "addrgenmode", "none"],
                vec!["link", "set", name, "up"],
                vec!["-6", "addr", "add", "fe80::69/64", "dev", name, "nodad"],
                vec![
                    "-6",
                    "addr",
                    "add",
                    "2001:db8:69::1/64",
                    "dev",
                    name,
                    "nodad",
                ],
            ] {
                let output = crate::system_command::Command::new("ip")
                    .args(args)
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "ip fixture: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let proxy = runtime
                .block_on(start(
                    "native-view",
                    crate::config::server::Ipv6NdpProxyMode::Required,
                    Some(name),
                    &crate::config::server::Ipv6RoutingConfig::default(),
                ))?
                .expect("required NDP responder");
            anyhow::ensure!(proxy.ifindex > 0 && proxy.mac == [2, 0x12, 0x34, 0x56, 0x78, 0x9c]);
            anyhow::ensure!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
            anyhow::ensure!(assigned_source(proxy.ifindex)? == "fe80::69".parse::<Ipv6Addr>()?);
            anyhow::ensure!(
                selected_source(proxy.ifindex, "2001:db8:69::1")?
                    == "2001:db8:69::1".parse::<Ipv6Addr>()?
            );
            anyhow::ensure!(selected_source(proxy.ifindex, "2001:db8:69::99").is_err());
            let removed = crate::system_command::Command::new("ip")
                .args(["-6", "addr", "del", "2001:db8:69::1/64", "dev", name])
                .output()?;
            anyhow::ensure!(removed.status.success());
            anyhow::ensure!(selected_source(proxy.ifindex, "2001:db8:69::1").is_err());
            anyhow::ensure!(assigned_source(proxy.ifindex)? == "fe80::69".parse::<Ipv6Addr>()?);
            let group = solicited_node_multicast("2001:db8:69::f00d".parse()?);
            let group_hex: String = group.octets().iter().map(|b| format!("{b:02x}")).collect();
            update_membership(proxy.memberships.as_raw_fd(), proxy.ifindex, group, true)?;
            anyhow::ensure!(
                std::fs::read_to_string("/proc/thread-self/net/igmp6")?.contains(&group_hex)
            );
            drop(proxy);
            anyhow::ensure!(
                !std::fs::read_to_string("/proc/thread-self/net/igmp6")?.contains(&group_hex)
            );
            Ok(())
        })
        .join()
        .expect("native NDP view test panicked")
    }
}
