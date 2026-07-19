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

/// A compiled destination allow-list: `(network, mask)` pairs in host byte order.
///
/// An EMPTY list means UNRESTRICTED — that is the documented semantic of an empty
/// `allowed_networks`, and it also keeps the hot path free for the common case
/// (see [`DstAcl::is_unrestricted`], which callers use to skip the check entirely).
#[derive(Debug, Clone, Default)]
pub struct DstAcl {
    nets: Vec<(u32, u32)>,
}

impl DstAcl {
    /// Compile CIDR/IP strings once (at session setup) into mask pairs.
    ///
    /// Accepts `10.0.0.0/8` and a bare `10.0.0.5` (treated as `/32`), matching what
    /// the docs and the panel's repeater offer. An unparseable entry is logged and
    /// SKIPPED rather than silently ignored — but note the fail-closed consequence:
    /// if EVERY entry is malformed the list ends up empty, which means unrestricted.
    /// Authoring-time validation in the panel is what keeps that from happening; the
    /// warning here is the operator's second line of defence.
    pub fn compile(cidrs: &[String], who: &str) -> Self {
        let mut nets = Vec::with_capacity(cidrs.len());
        for raw in cidrs {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            let (addr_s, prefix) = match s.split_once('/') {
                Some((a, p)) => match p.parse::<u8>() {
                    Ok(n) if n <= 32 => (a.trim(), n),
                    _ => {
                        log::warn!(
                            "allowed_networks for {}: '{}' has an invalid prefix — entry ignored",
                            who,
                            s
                        );
                        continue;
                    }
                },
                None => (s, 32u8),
            };
            let Ok(ip) = addr_s.parse::<std::net::Ipv4Addr>() else {
                log::warn!(
                    "allowed_networks for {}: '{}' is not a valid IPv4 CIDR/address — entry ignored",
                    who,
                    s
                );
                continue;
            };
            // `u32::MAX << 32` is UB-shaped (overflow); /0 is the whole space.
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            nets.push((u32::from(ip) & mask, mask));
        }
        DstAcl { nets }
    }

    /// True when no restriction applies (empty list = "anywhere"). Callers check
    /// this first so an unrestricted session pays nothing per packet.
    pub fn is_unrestricted(&self) -> bool {
        self.nets.is_empty()
    }

    /// Number of compiled rules (for the log line at session setup). Deliberately not
    /// `len()`: this is a rule count, not a container length, and `is_unrestricted`
    /// already covers the emptiness question.
    pub fn rule_count(&self) -> usize {
        self.nets.len()
    }

    /// May this inner packet be forwarded? Checks the IPv4 DESTINATION address.
    ///
    /// FAIL-CLOSED on anything we cannot evaluate: a truncated header, or a non-IPv4
    /// packet (the tunnel's pool is IPv4-only, so inner IPv6 is already blackholed
    /// downstream — dropping it here just makes that explicit instead of forwarding
    /// traffic an ACL was supposed to gate). Never call this without checking
    /// [`DstAcl::is_unrestricted`] first if you care about the fast path.
    pub fn allows_packet(&self, pkt: &[u8]) -> bool {
        if self.nets.is_empty() {
            return true;
        }
        // IPv4 header: version nibble == 4, dst address at bytes 16..20.
        if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
            return false;
        }
        let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        self.nets.iter().any(|(net, mask)| (dst & mask) == *net)
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
    ip: u32,
    /// `(network, mask)` for each subnet routed behind this client.
    nets: Vec<(u32, u32)>,
}

impl SrcGuard {
    pub fn new(client_ip: std::net::Ipv4Addr, subnets: &[String], who: &str) -> Self {
        // Reuse the CIDR parser (and its warnings) from the destination ACL.
        let compiled = DstAcl::compile(subnets, who);
        Self {
            ip: u32::from(client_ip),
            nets: compiled.nets,
        }
    }

    /// May this packet claim its source address?
    ///
    /// Only IPv4 is judged. Anything else — a short packet, or a non-IPv4 version
    /// nibble — is passed through untouched, exactly as before: this closes the
    /// IPv4 spoofing hole without changing the handling of any other traffic. The
    /// tunnel's address pool is IPv4, so an IPv4 source is the only thing that can
    /// impersonate another session.
    pub fn allows_packet(&self, pkt: &[u8]) -> bool {
        if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
            return true;
        }
        let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
        if src == self.ip {
            return true;
        }
        self.nets.iter().any(|(net, mask)| (src & mask) == *net)
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
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn empty_list_is_unrestricted() {
        let a = acl(&[]);
        assert!(a.is_unrestricted());
        assert!(a.allows_packet(&pkt([8, 8, 8, 8])));
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
    fn src_guard_leaves_non_ipv4_alone() {
        // Narrow by design: only IPv4 sources can impersonate a pool address, so
        // everything else keeps its previous handling rather than being dropped.
        let g = SrcGuard::new("10.0.0.7".parse().unwrap(), &[], "alice");
        let mut v6 = pkt_src([10, 0, 0, 9]);
        v6[0] = 0x60;
        assert!(g.allows_packet(&v6));
        assert!(g.allows_packet(&pkt_src([10, 0, 0, 9])[..19]));
    }
}
