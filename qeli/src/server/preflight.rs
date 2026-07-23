//! Pre-flight safety checks — run BEFORE the panel binds, the worker spawns or any
//! TUN comes up, so a config that would cut the operator off the box refuses to start
//! instead of taking the machine down.
//!
//! The check that motivated this module: a profile whose `tun.address` IS the host's
//! default gateway. Bringing that TUN up makes the gateway a LOCAL address, every
//! outbound packet dies in the tunnel, and the server drops off the network entirely —
//! SSH and ICMP included. The operator's only way back is the provider's console or a
//! reboot, and nothing in the log says why (from the box's point of view the start was
//! perfectly successful). The shipped single-profile example used `10.0.0.0/24`, which
//! is one of the most common VPS gateway subnets, so this was a loaded footgun.
//!
//! Design mirrors [`super::validate_profiles`]: the verdict logic is PURE — it takes a
//! [`HostNet`] snapshot rather than reading the system itself — so every case is
//! unit-testable without touching the host's networking, and `check-config` can reach
//! the exact same verdict a real start would.
//!
//! **Fails OPEN when the host state cannot be read** (no `ip` binary, unparseable
//! output). This is a guard against an operator mistake, not a security boundary: a
//! box we cannot introspect must still be able to start, so an unreadable state is a
//! loud warning, never a refusal. A collision we DID see, by contrast, is fatal — there
//! is no configuration in which overlapping the host's own addressing works.

use crate::config::server::ServerConfig;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::process::Command;

/// Snapshot of the host's IPv4 networking, as read from `ip`. Interface names are kept
/// so a collision can name the interface it hit (an operator fixes `net0` far faster
/// than "some interface").
#[derive(Debug, Default, Clone)]
pub struct HostNet {
    /// (interface, address) for every non-loopback IPv4 address on the host.
    pub addrs: Vec<(String, Ipv4Addr)>,
    /// Gateways of the default route(s) — the addresses that MUST stay reachable.
    pub gateways: Vec<Ipv4Addr>,
    /// (interface, destination) of every non-default route.
    pub routes: Vec<(String, Ipv4Net)>,
}

/// Do two CIDR blocks share any address? Two blocks overlap iff one contains the
/// other's network address (the smaller is then fully inside the larger).
fn overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// `255.255.255.0` → `24`. `None` for a malformed or non-contiguous mask (e.g.
/// `255.0.255.0`), which callers treat as "cannot judge" rather than as a collision.
fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let bits = u32::from(mask.trim().parse::<Ipv4Addr>().ok()?);
    let ones = bits.leading_ones();
    // Reject a mask whose set bits are not all leading (0xFF00FF00 & co).
    if bits.count_ones() != ones {
        return None;
    }
    Some(ones as u8)
}

/// Parse `ip -4 -o addr show`:
/// `2: net0    inet 62.60.248.39/32 brd 62.60.248.39 scope global net0`
pub fn parse_addr_lines(out: &str) -> Vec<(String, Ipv4Addr)> {
    let mut v = Vec::new();
    for line in out.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        // [0]="2:", [1]=ifname, then "inet <addr>/<prefix>".
        let (Some(ifname), Some(i)) = (t.get(1), t.iter().position(|&x| x == "inet")) else {
            continue;
        };
        let Some(cidr) = t.get(i + 1) else { continue };
        if let Ok(addr) = cidr.split('/').next().unwrap_or("").parse::<Ipv4Addr>() {
            if !addr.is_loopback() {
                v.push((ifname.trim_end_matches(':').to_string(), addr));
            }
        }
    }
    v
}

/// Parse `ip -4 route show`, splitting default routes (we want their gateway) from
/// ordinary ones (we want their destination prefix):
/// `default via 10.0.0.1 dev net0 onlink`
/// `10.9.0.0/24 dev vpn0 proto kernel scope link src 10.9.0.1`
/// `10.0.0.1 dev net0 scope link`   ← bare host route, implicitly /32
pub fn parse_route_lines(out: &str) -> (Vec<Ipv4Addr>, Vec<(String, Ipv4Net)>) {
    let (mut gws, mut routes) = (Vec::new(), Vec::new());
    for line in out.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        let Some(&first) = t.first() else { continue };
        let dev = t
            .iter()
            .position(|&x| x == "dev")
            .and_then(|i| t.get(i + 1))
            .map(|s| s.to_string())
            .unwrap_or_default();
        if first == "default" {
            if let Some(gw) = t
                .iter()
                .position(|&x| x == "via")
                .and_then(|i| t.get(i + 1))
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
            {
                gws.push(gw);
            }
            continue;
        }
        // A destination without a prefix is a /32 host route.
        let parsed = if first.contains('/') {
            first.parse::<Ipv4Net>().ok()
        } else {
            first
                .parse::<Ipv4Addr>()
                .ok()
                .and_then(|a| Ipv4Net::new(a, 32).ok())
        };
        if let Some(net) = parsed {
            routes.push((dev, net));
        }
    }
    (gws, routes)
}

/// Read the host's IPv4 state. `None` if `ip` is missing or fails — the caller then
/// skips the check with a warning rather than blocking startup (see module docs).
pub fn gather_host_net() -> Option<HostNet> {
    let addr_out = Command::new("ip").args(["-4", "-o", "addr", "show"]).output().ok()?;
    let route_out = Command::new("ip").args(["-4", "route", "show"]).output().ok()?;
    if !addr_out.status.success() || !route_out.status.success() {
        return None;
    }
    let (gateways, routes) = parse_route_lines(&String::from_utf8_lossy(&route_out.stdout));
    Some(HostNet {
        addrs: parse_addr_lines(&String::from_utf8_lossy(&addr_out.stdout)),
        gateways,
        routes,
    })
}

/// The verdict. PURE — no IO, so every branch is unit-testable.
///
/// Only ENABLED profiles are checked, matching `validate_profiles`: a disabled profile
/// is never brought up, so its addressing cannot collide with anything.
///
/// Interfaces qeli owns (any profile's `tun.name`) are excluded from the host side of
/// every comparison. Otherwise a restart would flag the profile's OWN leftover TUN from
/// the previous run as a collision and refuse to ever start again.
pub fn check(config: &ServerConfig, host: &HostNet) -> anyhow::Result<()> {
    let own_ifs: Vec<&str> = config
        .profiles
        .iter()
        .map(|p| p.tun.name.as_str())
        .collect();
    let is_own = |ifname: &str| own_ifs.iter().any(|o| *o == ifname);

    // Host addressing, minus anything on our own TUNs.
    let host_addrs: Vec<&(String, Ipv4Addr)> =
        host.addrs.iter().filter(|(i, _)| !is_own(i)).collect();
    let host_routes: Vec<&(String, Ipv4Net)> =
        host.routes.iter().filter(|(i, _)| !is_own(i)).collect();

    let mut pools: Vec<(&str, Ipv4Net)> = Vec::new();

    for p in config.profiles.iter().filter(|p| p.enabled) {
        let name = p.name.as_str();

        // ── tun.address ────────────────────────────────────────────────────────
        // Parsed leniently: a malformed address is validate_profiles' business, and
        // failing here would report the wrong problem.
        if let Ok(tun_addr) = p.tun.address.trim().parse::<Ipv4Addr>() {
            // THE lockout. The gateway must stay reachable through the physical link;
            // taking its address onto a TUN black-holes every outbound packet.
            if host.gateways.contains(&tun_addr) {
                anyhow::bail!(
                    "profile '{name}': tun.address {tun_addr} is this host's DEFAULT GATEWAY. \
                     Bringing the TUN up would make the gateway a local address and cut the \
                     server off the network (SSH and ping included). Move the tunnel to a free \
                     range, e.g. tun.address = 10.9.0.1 with pool.cidr = 10.9.0.0/24."
                );
            }
            if let Some((ifname, _)) = host_addrs.iter().find(|(_, a)| *a == tun_addr) {
                anyhow::bail!(
                    "profile '{name}': tun.address {tun_addr} is already assigned to interface \
                     '{ifname}'. Pick an address outside the host's own networks."
                );
            }
        }

        // ── pool.cidr ──────────────────────────────────────────────────────────
        let Ok(pool) = p.pool.cidr.trim().parse::<Ipv4Net>() else {
            continue; // malformed CIDR — validate_profiles reports it
        };

        // A pool covering the gateway hands a client the gateway's address and, via the
        // TUN's connected route, steals the host's return path just as fatally.
        if let Some(gw) = host.gateways.iter().find(|gw| pool.contains(*gw)) {
            anyhow::bail!(
                "profile '{name}': pool.cidr {pool} contains this host's DEFAULT GATEWAY {gw}. \
                 The tunnel's connected route would capture the host's own return path and cut \
                 the server off the network. Move the pool to a free range, e.g. 10.9.0.0/24."
            );
        }
        if let Some((ifname, a)) = host_addrs.iter().find(|(_, a)| pool.contains(a)) {
            anyhow::bail!(
                "profile '{name}': pool.cidr {pool} contains {a}, the address of interface \
                 '{ifname}'. A client would be handed the host's own address. Move the pool to \
                 a free range."
            );
        }

        // The tunnel subnet must not shadow a network the host already routes (a LAN, a
        // provider subnet, a peer VPN) — traffic to it would silently divert into the
        // tunnel. Default routes are handled above; here only concrete prefixes.
        if let Some((ifname, r)) = host_routes.iter().find(|(_, r)| overlaps(&pool, r)) {
            anyhow::bail!(
                "profile '{name}': pool.cidr {pool} overlaps the existing route {r} on interface \
                 '{ifname}'. Traffic to that network would be diverted into the tunnel. Move the \
                 pool to a range this host does not already route."
            );
        }

        // Two profiles sharing a pool hand the same tunnel IP to two clients on two
        // TUNs — the kernel then routes the return traffic to whichever came up last.
        if let Some((other, o)) = pools.iter().find(|(_, o)| overlaps(&pool, o)) {
            anyhow::bail!(
                "profile '{name}': pool.cidr {pool} overlaps profile '{other}' pool {o}. \
                 Give every profile its own range (10.9.0.0/24, 10.9.1.0/24, …)."
            );
        }
        pools.push((name, pool));

        // The TUN's own connected route is derived from address+netmask and can be wider
        // than the pool, so check it against the host's routes too.
        if let (Ok(tun_addr), Some(prefix)) = (
            p.tun.address.trim().parse::<Ipv4Addr>(),
            netmask_to_prefix(&p.tun.netmask),
        ) {
            if let Ok(tun_net) = Ipv4Net::new(tun_addr, prefix) {
                let tun_net = tun_net.trunc();
                if let Some((ifname, r)) = host_routes.iter().find(|(_, r)| overlaps(&tun_net, r)) {
                    anyhow::bail!(
                        "profile '{name}': the tunnel subnet {tun_net} (tun.address \
                         {tun_addr} / netmask {}) overlaps the existing route {r} on interface \
                         '{ifname}'. Traffic to that network would be diverted into the tunnel.",
                        p.tun.netmask
                    );
                }
            }
        }
    }
    Ok(())
}

/// Gather + check. The entry point callers use; see module docs for the fail-open rule.
pub fn run(config: &ServerConfig) -> anyhow::Result<()> {
    match gather_host_net() {
        Some(host) => check(config, &host),
        None => {
            log::warn!(
                "pre-flight: could not read the host's network state (`ip` missing or \
                 unreadable) — skipping the subnet-collision check. Verify by hand that \
                 tun.address / pool.cidr do not overlap this host's addresses, gateway or routes."
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::server::ServerConfig;

    /// Fixtures are built from INI, like the `validate_profiles` tests: the real parser
    /// fills every default, so a fixture cannot drift from what an operator's file
    /// actually produces.
    fn profile_ini(name: &str, port: u16, tun_if: &str, addr: &str, mask: &str, pool: &str) -> String {
        format!(
            "[profile:{name}]\n\
             bind.address = 0.0.0.0\n\
             bind.port = {port}\n\
             bind.transport = tcp\n\
             tun.name = {tun_if}\n\
             tun.address = {addr}\n\
             tun.netmask = {mask}\n\
             tun.mtu = 1400\n\
             pool.cidr = {pool}\n\
             obf.mode = fake-tls\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n"
        )
    }

    /// One profile named `tcp` on vpn0 — the shape of the shipped single-profile example.
    fn one(addr: &str, mask: &str, pool: &str) -> ServerConfig {
        cfg(&[profile_ini("tcp", 443, "vpn0", addr, mask, pool)])
    }

    fn cfg(profiles: &[String]) -> ServerConfig {
        crate::config::parse_server_config(&profiles.concat()).expect("fixture INI must parse")
    }

    /// The real lockout this module exists for, with the exact shape of the VPS that
    /// hit it: a /32 public address and an onlink gateway at 10.0.0.1, against the
    /// shipped example's 10.0.0.0/24 tunnel.
    fn vps_host() -> HostNet {
        let (gateways, routes) = parse_route_lines("default via 10.0.0.1 dev net0 onlink\n");
        HostNet {
            addrs: parse_addr_lines(
                "2: net0    inet 62.60.248.39/32 brd 62.60.248.39 scope global net0\n",
            ),
            gateways,
            routes,
        }
    }

    #[test]
    fn tun_address_equal_to_default_gateway_is_refused() {
        let c = one("10.0.0.1", "255.255.255.0", "10.0.0.0/24");
        let err = check(&c, &vps_host()).unwrap_err().to_string();
        assert!(err.contains("DEFAULT GATEWAY"), "got: {err}");
        assert!(err.contains("10.0.0.1"), "must name the address: {err}");
    }

    #[test]
    fn pool_containing_the_gateway_is_refused_even_when_tun_address_differs() {
        // tun.address is free, but the pool still swallows the gateway.
        let c = one("10.0.0.9", "255.255.255.0", "10.0.0.0/24");
        let err = check(&c, &vps_host()).unwrap_err().to_string();
        assert!(err.contains("DEFAULT GATEWAY"), "got: {err}");
    }

    #[test]
    fn free_range_passes_on_the_same_host() {
        // The documented fix must actually pass.
        let c = one("10.9.0.1", "255.255.255.0", "10.9.0.0/24");
        assert!(check(&c, &vps_host()).is_ok());
    }

    #[test]
    fn pool_containing_a_host_address_is_refused() {
        let c = one("62.60.248.1", "255.255.255.0", "62.60.248.0/24");
        let err = check(&c, &vps_host()).unwrap_err().to_string();
        assert!(err.contains("62.60.248.39"), "must name the address: {err}");
        assert!(err.contains("net0"), "must name the interface: {err}");
    }

    #[test]
    fn pool_overlapping_an_existing_lan_route_is_refused() {
        let (gateways, routes) = parse_route_lines(
            "default via 192.168.1.1 dev eth0\n192.168.50.0/24 dev eth1 proto kernel scope link\n",
        );
        let host = HostNet {
            addrs: parse_addr_lines("2: eth0    inet 192.168.1.10/24 scope global eth0\n"),
            gateways,
            routes,
        };
        let c = one("192.168.50.1", "255.255.255.0", "192.168.50.0/24");
        let err = check(&c, &host).unwrap_err().to_string();
        assert!(err.contains("192.168.50.0/24"), "got: {err}");
        assert!(err.contains("eth1"), "must name the interface: {err}");
    }

    #[test]
    fn two_profiles_with_overlapping_pools_are_refused() {
        let c = cfg(&[
            profile_ini("tcp", 443, "vpn0", "10.9.0.1", "255.255.255.0", "10.9.0.0/24"),
            profile_ini("udp", 8443, "vpn1", "10.9.0.1", "255.255.255.0", "10.9.0.0/24"),
        ]);
        let err = check(&c, &vps_host()).unwrap_err().to_string();
        assert!(err.contains("overlaps profile"), "got: {err}");
    }

    #[test]
    fn distinct_pools_across_profiles_pass() {
        let c = cfg(&[
            profile_ini("tcp", 443, "vpn0", "10.9.0.1", "255.255.255.0", "10.9.0.0/24"),
            profile_ini("udp", 8443, "vpn1", "10.9.1.1", "255.255.255.0", "10.9.1.0/24"),
        ]);
        assert!(check(&c, &vps_host()).is_ok());
    }

    #[test]
    fn own_leftover_tun_is_not_a_collision() {
        // A restart after an unclean stop: vpn0 still carries the profile's own address
        // and connected route. Flagging that would make the server permanently unstartable.
        let (gateways, mut routes) = parse_route_lines("default via 10.0.0.1 dev net0 onlink\n");
        let (_, own) = parse_route_lines("10.9.0.0/24 dev vpn0 proto kernel scope link\n");
        routes.extend(own);
        let mut addrs =
            parse_addr_lines("2: net0    inet 62.60.248.39/32 scope global net0\n");
        addrs.extend(parse_addr_lines(
            "3: vpn0    inet 10.9.0.1/24 scope global vpn0\n",
        ));
        let host = HostNet {
            addrs,
            gateways,
            routes,
        };
        let c = one("10.9.0.1", "255.255.255.0", "10.9.0.0/24");
        assert!(check(&c, &host).is_ok());
    }

    #[test]
    fn disabled_profile_is_not_checked() {
        let mut ini = profile_ini("tcp", 443, "vpn0", "10.0.0.1", "255.255.255.0", "10.0.0.0/24");
        ini.push_str("enabled = false\n");
        assert!(check(&cfg(&[ini]), &vps_host()).is_ok());
    }

    #[test]
    fn empty_host_state_never_blocks() {
        // Fail-open: nothing known about the host ⇒ nothing to collide with.
        let c = one("10.0.0.1", "255.255.255.0", "10.0.0.0/24");
        assert!(check(&c, &HostNet::default()).is_ok());
    }

    #[test]
    fn parses_onlink_default_and_bare_host_routes() {
        let (gws, routes) = parse_route_lines(
            "default via 10.0.0.1 dev net0 onlink\n\
             10.0.0.1 dev net0 scope link\n\
             10.9.0.0/24 dev vpn0 proto kernel scope link src 10.9.0.1\n",
        );
        assert_eq!(gws, vec!["10.0.0.1".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(routes.len(), 2);
        // A prefix-less destination is a /32 host route.
        assert_eq!(routes[0].1, "10.0.0.1/32".parse::<Ipv4Net>().unwrap());
        assert_eq!(routes[0].0, "net0");
    }

    #[test]
    fn skips_loopback_addresses() {
        let a = parse_addr_lines(
            "1: lo    inet 127.0.0.1/8 scope host lo\n\
             2: net0    inet 62.60.248.39/32 scope global net0\n",
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, "net0");
    }

    #[test]
    fn netmask_conversion_rejects_non_contiguous_masks() {
        assert_eq!(netmask_to_prefix("255.255.255.0"), Some(24));
        assert_eq!(netmask_to_prefix("255.255.0.0"), Some(16));
        assert_eq!(netmask_to_prefix("255.255.255.255"), Some(32));
        assert_eq!(netmask_to_prefix("255.0.255.0"), None);
        assert_eq!(netmask_to_prefix("not-a-mask"), None);
    }
}
