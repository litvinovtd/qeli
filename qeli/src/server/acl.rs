//! Per-user destination ACL — enforcement of `allowed_networks`.
//!
//! `allowed_networks` (per user, or inherited from the user's group) is documented
//! as "the CIDRs/IPs this user is allowed to reach through the tunnel; empty =
//! anywhere". It was surfaced in the config, the panel and the docs, but until now
//! **nothing in the data plane read it** — so it was a security control that
//! silently did nothing while sitting next to controls (`profiles`, `max_sessions`,
//! `data_limit_gb`, `expire_at`) that ARE enforced. This module closes that gap.
//!
//! The check runs on the client→server (egress) direction, immediately before a
//! decrypted inner packet is handed to the TUN — i.e. after AEAD/replay validation,
//! so only authenticated traffic is ever evaluated.

use std::collections::HashMap;

/// Strict source extraction shared with the data plane. Malformed lengths and extension
/// chains are not described as if they were valid packets.
pub fn packet_source(pkt: &[u8]) -> Option<std::net::IpAddr> {
    crate::protocol::ip::parse_ip_packet(pkt)
        .ok()
        .map(|meta| meta.source)
}

#[derive(Debug, Clone, Copy)]
enum Network {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl Network {
    fn parse(raw: &str) -> Option<Self> {
        let value = raw.trim();
        let (address, prefix_text) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| {
                (address.trim(), Some(prefix.trim()))
            });
        match address.parse::<std::net::IpAddr>().ok()? {
            std::net::IpAddr::V4(address) => {
                let prefix = prefix_text.map_or(Some(32), |value| value.parse::<u8>().ok())?;
                if prefix > 32 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Some(Self::V4 {
                    network: u32::from(address) & mask,
                    mask,
                })
            }
            std::net::IpAddr::V6(address) => {
                let prefix = prefix_text.map_or(Some(128), |value| value.parse::<u8>().ok())?;
                if prefix > 128 {
                    return None;
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Some(Self::V6 {
                    network: u128::from(address) & mask,
                    mask,
                })
            }
        }
    }

    fn contains(self, address: std::net::IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, mask }, std::net::IpAddr::V4(address)) => {
                u32::from(address) & mask == network
            }
            (Self::V6 { network, mask }, std::net::IpAddr::V6(address)) => {
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }

    fn family_is_active(self, has_ipv4: bool, has_ipv6: bool) -> bool {
        match self {
            Self::V4 { .. } => has_ipv4,
            Self::V6 { .. } => has_ipv6,
        }
    }
}

/// A compiled dual-stack destination allow-list.
///
/// An EMPTY list means UNRESTRICTED — that is the documented semantic of an empty
/// `allowed_networks`, and it also keeps the hot path free for the common case
/// (see [`DstAcl::is_unrestricted`], which callers use to skip the check entirely).
#[derive(Debug, Clone)]
pub struct DstAcl {
    nets: Vec<Network>,
    restricted: bool,
}

impl DstAcl {
    /// Compile CIDR/IP strings once (at session setup) into mask pairs.
    ///
    /// Accepts `10.0.0.0/8` and a bare `10.0.0.5` (treated as `/32`), matching what
    /// the docs and the panel's repeater offer. An unparseable entry is logged and
    /// SKIPPED rather than silently ignored — but note the fail-closed consequence:
    /// if EVERY non-empty entry is malformed the compiled list is empty while `restricted`
    /// remains true, so every destination is denied.
    /// Authoring-time validation in the panel is what keeps that from happening; the
    /// warning here is the operator's second line of defence.
    pub fn compile(cidrs: &[String], who: &str) -> Self {
        let mut nets = Vec::with_capacity(cidrs.len());
        let mut restricted = false;
        for raw in cidrs {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            restricted = true;
            let Some(network) = Network::parse(s) else {
                log::warn!(
                    "allowed_networks for {}: '{}' is not a valid IPv4/IPv6 CIDR/address — entry ignored",
                    who,
                    s
                );
                continue;
            };
            nets.push(network);
        }
        DstAcl { nets, restricted }
    }

    /// True when no restriction applies (empty list = "anywhere"). Callers check
    /// this first so an unrestricted session pays nothing per packet.
    pub fn is_unrestricted(&self) -> bool {
        !self.restricted
    }

    /// Number of compiled rules (for the log line at session setup). Deliberately not
    /// `len()`: this is a rule count, not a container length, and `is_unrestricted`
    /// already covers the emptiness question.
    pub fn rule_count(&self) -> usize {
        self.nets.len()
    }

    /// May this inner packet be forwarded? Checks the parsed IPv4 or IPv6 destination.
    ///
    /// FAIL-CLOSED on anything we cannot evaluate, including a malformed/truncated IP
    /// packet. Never call this without checking
    /// [`DstAcl::is_unrestricted`] first if you care about the fast path.
    pub fn allows_packet(&self, pkt: &[u8]) -> bool {
        if !self.restricted {
            return true;
        }
        let Ok(meta) = crate::protocol::ip::parse_ip_packet(pkt) else {
            return false;
        };
        self.nets
            .iter()
            .any(|network| network.contains(meta.destination))
    }
}

/// The effective destination ACL for a user: their own `allowed_networks`, else the
/// group's, else empty (= unrestricted). Mirrors `effective_bandwidth_limit` /
/// `effective_max_sessions`.
pub fn effective_allowed_networks(
    user: &crate::config::users::UserEntry,
    groups: &HashMap<String, crate::config::users::GroupTemplate>,
) -> Vec<String> {
    if !user.allowed_networks.is_empty() {
        return user.allowed_networks.clone();
    }
    if let Some(ref group_name) = user.group {
        if let Some(group) = groups.get(group_name) {
            if let Some(ref nets) = group.allowed_networks {
                return nets.clone();
            }
        }
    }
    Vec::new()
}

/// Which SOURCE addresses a session is allowed to send from.
///
/// The destination ACL above answers "where may this client go"; nothing answered
/// "who may it claim to be". Without that, an authenticated client could put any
/// address in bytes 12..16 and the server would forward it: that defeats
/// `client_to_client = false` (isolation drops a packet whose source is *another
/// client's* IP, so forging a non-client source walks straight past it), lets one
/// user impersonate another on anything that authorises by source IP, and poisons
/// every downstream log and flow record — traffic is billed to the real session
/// while everyone downstream sees the forged address.
///
/// Legitimate sources are the client's own tunnel IP plus any subnets routed
/// behind it (`client_subnets` / iroute), which is why this is per-session state
/// rather than a global check.
#[derive(Debug, Clone)]
pub struct SrcGuard {
    assigned: Vec<std::net::IpAddr>,
    nets: Vec<Network>,
}

impl SrcGuard {
    pub fn new(client_ip: std::net::Ipv4Addr, subnets: &[String], who: &str) -> Self {
        // Reuse the CIDR parser (and its warnings) from the destination ACL.
        let compiled = DstAcl::compile(subnets, who);
        Self {
            assigned: vec![std::net::IpAddr::V4(client_ip)],
            nets: compiled.nets,
        }
    }

    pub fn new_dual(assigned: &[std::net::IpAddr], subnets: &[String], who: &str) -> Self {
        let mut compiled = DstAcl::compile(subnets, who);
        let has_ipv4 = assigned.iter().any(std::net::IpAddr::is_ipv4);
        let has_ipv6 = assigned.iter().any(std::net::IpAddr::is_ipv6);
        // `client_subnets` extends the addresses a session may claim; it must never extend
        // the negotiated family mode itself. In particular, an IPv6-only lease plus an IPv4
        // iroute must not become a covert way to inject IPv4 into the server TUN.
        compiled
            .nets
            .retain(|network| network.family_is_active(has_ipv4, has_ipv6));
        Self {
            assigned: assigned.to_vec(),
            nets: compiled.nets,
        }
    }

    /// May this packet claim its source address?
    ///
    /// FAIL-CLOSED: anything that is not a judgeable IPv4/IPv6 packet is REFUSED, matching
    /// `DstAcl::allows_packet`.
    ///
    /// This used to `return true` for a short packet or any non-IPv4 version nibble, on the
    /// reasoning that "the tunnel's address pool is IPv4, so only an IPv4 source can
    /// impersonate another session". That is true about impersonation and beside the point
    /// about egress. The uplink (client -> TUN) checks the version nowhere else — the only
    /// `(pkt[0] >> 4) != 4` test is in the TUN -> client forwarder, i.e. the opposite
    /// direction — so an authenticated client could put an IPv6 packet with any source
    /// address it liked straight into the TUN. On a dual-stack host with
    /// `net.ipv6.conf.all.forwarding = 1` (ordinary for a VPS) that is spoofed IPv6 egress
    /// into whatever the server can reach, and qeli programs iptables only: `ip6tables` is
    /// never touched, so there is no NAT and no filter on that path at all.
    ///
    /// The parser now judges both families; refusing malformed input remains the correct
    /// default. (Audit 2026-08-04; dual-family update 2026-08-20.)
    pub fn allows_packet(&self, pkt: &[u8]) -> bool {
        let Ok(meta) = crate::protocol::ip::parse_ip_packet(pkt) else {
            return false;
        };
        if self.assigned.contains(&meta.source) {
            return true;
        }
        self.nets
            .iter()
            .any(|network| network.contains(meta.source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(v: &[&str]) -> DstAcl {
        DstAcl::compile(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "test")
    }

    /// An IPv4 packet with the given destination (20-byte minimal header).
    fn pkt(dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[16..20].copy_from_slice(&dst);
        p
    }

    fn pkt6(source: &str, destination: &str) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 59;
        packet[8..24].copy_from_slice(&source.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn empty_list_is_unrestricted() {
        let a = acl(&[]);
        assert!(a.is_unrestricted());
        assert!(a.allows_packet(&pkt([8, 8, 8, 8])));
    }

    #[test]
    fn configured_but_malformed_list_is_deny_all() {
        let a = acl(&["10.0.0.0/99", "not-an-address"]);
        assert!(!a.is_unrestricted());
        assert_eq!(a.rule_count(), 0);
        assert!(!a.allows_packet(&pkt([10, 0, 0, 1])));
    }

    #[test]
    fn cidr_matches_only_inside_the_network() {
        let a = acl(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(!a.is_unrestricted());
        assert!(a.allows_packet(&pkt([10, 1, 2, 3])));
        assert!(a.allows_packet(&pkt([192, 168, 1, 77])));
        assert!(!a.allows_packet(&pkt([192, 168, 2, 77]))); // neighbouring /24
        assert!(!a.allows_packet(&pkt([8, 8, 8, 8])));
    }

    #[test]
    fn bare_ip_is_a_host_route() {
        let a = acl(&["203.0.113.7"]);
        assert!(a.allows_packet(&pkt([203, 0, 113, 7])));
        assert!(!a.allows_packet(&pkt([203, 0, 113, 8])));
    }

    #[test]
    fn ipv6_destination_rules_are_family_strict() {
        let a = acl(&["2001:db8:100::/48"]);
        assert!(a.allows_packet(&pkt6("fd42::2", "2001:db8:100::77")));
        assert!(!a.allows_packet(&pkt6("fd42::2", "2001:db8:101::77")));
        assert!(!a.allows_packet(&pkt([10, 0, 0, 2])));
    }

    #[test]
    fn slash_zero_allows_everything() {
        let a = acl(&["0.0.0.0/0"]);
        assert!(!a.is_unrestricted()); // an explicit rule, not "no rule"
        assert!(a.allows_packet(&pkt([1, 2, 3, 4])));
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let a = acl(&["banana", "10.0.0.0/99", "10.0.0.0/8", ""]);
        assert_eq!(a.rule_count(), 1);
        assert!(a.allows_packet(&pkt([10, 0, 0, 1])));
        assert!(!a.allows_packet(&pkt([11, 0, 0, 1])));
    }

    #[test]
    fn fails_closed_on_unevaluatable_packets() {
        let a = acl(&["10.0.0.0/8"]);
        assert!(!a.allows_packet(&[])); // empty
        assert!(!a.allows_packet(&pkt([10, 0, 0, 1])[..19])); // truncated header
        let mut v6 = pkt([10, 0, 0, 1]);
        v6[0] = 0x60; // version 6
        assert!(!a.allows_packet(&v6));
        // ...but an UNRESTRICTED acl still passes them through untouched.
        assert!(acl(&[]).allows_packet(&v6));
    }

    /// Build a packet with an explicit SOURCE address (bytes 12..16).
    fn pkt_src(src: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p[12..16].copy_from_slice(&src);
        p
    }

    #[test]
    fn src_guard_accepts_own_ip_and_rejects_forgeries() {
        let g = SrcGuard::new("10.0.0.7".parse().unwrap(), &[], "alice");
        assert!(g.allows_packet(&pkt_src([10, 0, 0, 7])));
        // Another client's tunnel IP — the impersonation case.
        assert!(!g.allows_packet(&pkt_src([10, 0, 0, 8])));
        // A non-client source, which is what walks past client_to_client isolation.
        assert!(!g.allows_packet(&pkt_src([8, 8, 8, 8])));
    }

    #[test]
    fn src_guard_allows_subnets_routed_behind_the_client() {
        let g = SrcGuard::new(
            "10.0.0.7".parse().unwrap(),
            &["192.168.50.0/24".to_string()],
            "router1",
        );
        assert!(g.allows_packet(&pkt_src([192, 168, 50, 33])));
        assert!(!g.allows_packet(&pkt_src([192, 168, 51, 33])));
        assert!(g.allows_packet(&pkt_src([10, 0, 0, 7])));
    }

    #[test]
    fn dual_source_guard_accepts_both_assignments_and_ipv6_iroute() {
        let guard = SrcGuard::new_dual(
            &["10.0.0.7".parse().unwrap(), "fd42::7".parse().unwrap()],
            &["2001:db8:200::/56".to_string()],
            "router1",
        );
        assert!(guard.allows_packet(&pkt_src([10, 0, 0, 7])));
        assert!(guard.allows_packet(&pkt6("fd42::7", "2606:4700:4700::1111")));
        assert!(guard.allows_packet(&pkt6("2001:db8:200::33", "2606:4700:4700::1111")));
        assert!(!guard.allows_packet(&pkt6("2001:db8:201::33", "2606:4700:4700::1111")));
    }

    #[test]
    fn single_family_source_guard_cannot_be_extended_by_an_opposite_family_iroute() {
        let ipv4_only = SrcGuard::new_dual(
            &["10.0.0.7".parse().unwrap()],
            &["2001:db8:200::/56".to_string()],
            "router4",
        );
        assert!(!ipv4_only.allows_packet(&pkt6("2001:db8:200::33", "2606:4700:4700::1111")));

        let ipv6_only = SrcGuard::new_dual(
            &["fd42::7".parse().unwrap()],
            &["192.168.50.0/24".to_string()],
            "router6",
        );
        assert!(!ipv6_only.allows_packet(&pkt_src([192, 168, 50, 33])));
    }

    #[test]
    fn src_guard_refuses_what_it_cannot_judge() {
        // FAIL-CLOSED, matching DstAcl. This test used to assert the opposite — that a
        // non-IPv4 or short packet was passed through untouched — on the reasoning that only
        // an IPv4 source can impersonate a pool address. True about impersonation, wrong
        // about egress: the legacy IPv4-only constructor must not silently accept another
        // family it cannot judge. Dual/IPv6 sessions use `new_dual`, whose family-aware
        // source guard validates every assigned address and routed subnet.
        // (Audit 2026-08-04.)
        let g = SrcGuard::new("10.0.0.7".parse().unwrap(), &[], "alice");
        let mut v6 = pkt_src([10, 0, 0, 9]);
        v6[0] = 0x60;
        assert!(!g.allows_packet(&v6), "an IPv6 packet must be refused");
        assert!(
            !g.allows_packet(&pkt_src([10, 0, 0, 9])[..19]),
            "a packet too short to carry a source address must be refused"
        );
        assert!(!g.allows_packet(&[]), "an empty packet must be refused");
        // The ordinary IPv4 path is unchanged: our own address is still allowed.
        assert!(g.allows_packet(&pkt_src([10, 0, 0, 7])));
    }

    #[test]
    fn packet_source_describes_ipv4_ipv6_and_malformed_packets() {
        assert_eq!(
            packet_source(&pkt_src([10, 9, 2, 7])),
            Some("10.9.2.7".parse().unwrap())
        );

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 59;
        ipv6[8..24].copy_from_slice(
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        assert_eq!(packet_source(&ipv6), Some("2001:db8::7".parse().unwrap()));
        assert_eq!(packet_source(&ipv6[..39]), None);
        assert_eq!(packet_source(&[]), None);
    }
}
