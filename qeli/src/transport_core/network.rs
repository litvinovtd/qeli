//! Platform-neutral construction of the network plan learned during authentication.
//!
//! The shared core decides what routes and DNS settings are safe. Platform adapters only
//! apply the resulting [`NetworkPlan`](super::NetworkPlan) and acknowledge that generation.

use crate::config::client::{ClientConfig, ClientDnsConfig};
use crate::config::{
    HeartbeatConfig, PaddingConfig, PushedObf, TrafficNormalizationConfig, TrafficShapingConfig,
};
use crate::transport_core::{
    NetworkAddress, NetworkAddressFamily, NetworkDns, NetworkFamilyMode, NetworkPlan, NetworkRoute,
};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) struct HandshakeNetwork<'a> {
    pub family_mode: NetworkFamilyMode,
    pub addresses: &'a [NetworkAddress],
    pub client_ip: &'a str,
    pub prefix: u8,
    pub tunnel_gateway: &'a str,
    pub dns_ip: &'a str,
    pub dns_port: &'a str,
    pub dns_servers: &'a [NetworkDns],
    pub routes_json: &'a str,
    pub mtu: i32,
    /// Optional platform-supplied resolvers used only when neither the profile nor the server
    /// supplied one. Production clients pass an empty list; the seam remains for embedders.
    pub fallback_dns_servers: &'a [String],
}

fn addresses_for_client_device(
    config: &ClientConfig,
    addresses: &[NetworkAddress],
) -> Vec<NetworkAddress> {
    let is_tap = config.tun.device_type.eq_ignore_ascii_case("tap");
    addresses
        .iter()
        .cloned()
        .map(|mut assigned| {
            // The server cannot infer the client's local interface kind: all qeli links carry
            // L3 IP records on the wire, while a Linux client may expose either an L3 TUN or
            // an emulated L2 TAP locally. Keep the authenticated pool prefix as the on-link
            // fact, but choose the assigned prefix from the device that will actually receive
            // it. TUN must use host routes to avoid ARP/NDP; TAP needs the pool prefix so local
            // neighbour discovery can reach the synthetic gateway.
            assigned.prefix_len = if is_tap {
                assigned.on_link_prefix_len
            } else {
                match assigned.family {
                    NetworkAddressFamily::Ipv4 => 32,
                    NetworkAddressFamily::Ipv6 => 128,
                }
            };
            assigned
        })
        .collect()
}

pub(crate) fn build_network_plan(
    config: &ClientConfig,
    generation: u64,
    network: &HandshakeNetwork<'_>,
) -> anyhow::Result<NetworkPlan> {
    let mtu = u16::try_from(network.mtu)
        .map_err(|_| anyhow::anyhow!("invalid tunnel MTU {}", network.mtu))?;
    let addresses = addresses_for_client_device(config, network.addresses);
    let full_tunnel = is_full_tunnel(config);
    let has_ipv6 = network
        .addresses
        .iter()
        .any(|address| address.family == NetworkAddressFamily::Ipv6);
    match config.routing.ipv6 {
        crate::config::client::ClientIpv6Policy::Off if has_ipv6 => {
            anyhow::bail!("server returned IPv6 although the client policy is ipv6=off")
        }
        crate::config::client::ClientIpv6Policy::Required if !has_ipv6 => {
            anyhow::bail!("server returned no IPv6 address although the client policy is required")
        }
        _ => {}
    }
    // A broad physical/LAN exclusion is safe because the negotiated on-link route is more
    // specific (for example 10/8 outside versus the tunnel's 10.8.0.0/24). An equal or more
    // specific exclusion containing the tunnel gateway is not: depending on the platform it
    // either wins by longest prefix or ties with installation-order semantics, making every
    // pushed/include route for that family unusable. Reject that contradictory plan once here
    // instead of letting each OS fail differently after authentication.
    for assigned in network.addresses {
        let Some(gateway_text) = assigned.gateway.as_deref() else {
            continue;
        };
        let gateway = gateway_text
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid tunnel gateway '{}'", gateway_text))?;
        for cidr in &config.routing.exclude {
            let excluded = cidr
                .parse::<ipnet::IpNet>()
                .map_err(|_| anyhow::anyhow!("invalid exclude route '{cidr}'"))?;
            if excluded.prefix_len() >= assigned.on_link_prefix_len && excluded.contains(&gateway) {
                anyhow::bail!(
                    "tunnel gateway '{}' is covered by exclude route '{}' at or above the on-link /{} prefix",
                    gateway_text,
                    cidr,
                    assigned.on_link_prefix_len
                );
            }
        }
    }
    let prefix = network
        .addresses
        .iter()
        .find(|address| address.address == network.client_ip)
        .map(|address| address.on_link_prefix_len)
        .unwrap_or_else(|| normalized_prefix(network.prefix));
    let tun_net = network
        .client_ip
        .parse::<Ipv4Addr>()
        .ok()
        .map(|address| (address, prefix_to_netmask(prefix)));
    // An empty v2 DNS array means "the server did not push a resolver", not "this is an
    // IPv4-only legacy handshake".  Basing the parser choice on that array made an IPv6-only
    // client reject its own configured IPv6 resolver whenever the server push was empty.
    // Retain the legacy projection only for a genuinely IPv4-only plan; v2/dual/IPv6 plans
    // must resolve DNS against the negotiated address families even when the pushed list is
    // empty.
    let legacy_ipv4_plan = network.family_mode == NetworkFamilyMode::Ipv4
        && network
            .addresses
            .iter()
            .all(|address| address.family == NetworkAddressFamily::Ipv4);
    let dns_servers = if network.dns_servers.is_empty() && legacy_ipv4_plan {
        planned_dns_servers(
            &config.dns,
            network.dns_ip,
            network.dns_port,
            tun_net,
            full_tunnel,
            network.fallback_dns_servers,
        )?
    } else {
        planned_dns_servers_v2(
            &config.dns,
            network.dns_servers,
            network.addresses,
            network.fallback_dns_servers,
        )?
    };
    if full_tunnel && config.dns.mode == "tunnel" && dns_servers.is_empty() {
        anyhow::bail!(
            "full-tunnel DNS is set to tunnel mode but no resolver is available; configure dns_servers, let the server push one, or set dns = off only when the platform manages DNS"
        );
    }
    // A resolver published in the NetworkPlan is an explicit promise that its traffic uses
    // the tunnel. A more-specific host route added below safely overrides broad LAN/user
    // exclusions, but an exact host exclusion has the same prefix and platform tie-breaking is
    // not portable (several adapters deliberately install the physical exclusion last). Reject
    // that irreconcilable request once in the shared core instead of leaking or black-holing DNS
    // differently on each OS.
    for dns in &dns_servers {
        let address = dns
            .address
            .parse::<IpAddr>()
            .map_err(|_| anyhow::anyhow!("invalid DNS server '{}'", dns.address))?;
        for cidr in &config.routing.exclude {
            let excluded = cidr
                .parse::<ipnet::IpNet>()
                .map_err(|_| anyhow::anyhow!("invalid exclude route '{cidr}'"))?;
            let host_prefix = if address.is_ipv4() { 32 } else { 128 };
            if excluded.prefix_len() == host_prefix && excluded.contains(&address) {
                anyhow::bail!(
                    "tunnel DNS server '{}' is covered by exclude route '{}'; remove the exclusion or choose a resolver outside it",
                    dns.address,
                    cidr
                );
            }
        }
    }

    let mut routes = planned_pushed_routes_for_addresses(network.routes_json, network.addresses)?;
    let pushed_routes = routes.iter().map(|route| route.cidr.clone()).collect();
    for cidr in &config.routing.include {
        if !route_family_is_active(cidr, network.addresses)? {
            continue;
        }
        routes.push(NetworkRoute {
            cidr: cidr.clone(),
            gateway: gateway_for_cidr(cidr, network.addresses)?.to_string(),
            metric: 100,
        });
    }
    if config.routing.route_local_networks
        && network
            .addresses
            .iter()
            .any(|address| address.family == NetworkAddressFamily::Ipv4)
    {
        let gateway = gateway_for_cidr("10.0.0.0/8", network.addresses)?.to_string();
        routes.extend(
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .into_iter()
                .map(|cidr| NetworkRoute {
                    cidr: cidr.to_string(),
                    gateway: gateway.clone(),
                    metric: 100,
                }),
        );
    }
    // A resolver gets an explicit host route in both routing modes. In split mode this makes
    // an off-subnet resolver reachable at all; in full mode it keeps broad physical/LAN
    // exclusions from diverting the DNS address. The exact /32 or /128 exclusion case was
    // rejected above because equal-prefix ordering is platform-specific.
    let mut protected_dns_routes = HashSet::new();
    for dns in &dns_servers {
        if let Ok(address) = dns.address.parse::<IpAddr>() {
            let cidr = format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 });
            protected_dns_routes.insert(NumericCidr::parse(&cidr)?);
            if !routes.iter().any(|route| route.cidr == cidr) {
                routes.push(NetworkRoute {
                    gateway: gateway_for_ip(address, network.addresses)?.to_string(),
                    cidr,
                    metric: 50,
                });
            }
        }
    }
    let routes = apply_route_exclusions(routes, &config.routing.exclude, &protected_dns_routes)?;

    Ok(NetworkPlan {
        generation,
        family_mode: network.family_mode,
        addresses,
        tunnel_address: network.client_ip.to_string(),
        prefix_len: prefix,
        mtu,
        tunnel_gateway: network.tunnel_gateway.to_string(),
        carrier_address: None,
        routes,
        pushed_routes,
        dns_servers,
        full_tunnel,
        kill_switch: config.routing.kill_switch && full_tunnel,
        allow_ipv4_leak: config.routing.allow_ipv4_leak,
        allow_ipv6_leak: config.routing.allow_ipv6_leak,
        max_streams: 1,
        adaptive: false,
        data_plane: Default::default(),
        connection_log: Vec::new(),
    })
}

fn gateway_for_ip(address: IpAddr, addresses: &[NetworkAddress]) -> anyhow::Result<&str> {
    addresses
        .iter()
        .find(|assigned| {
            matches!(
                (assigned.family, address),
                (NetworkAddressFamily::Ipv4, IpAddr::V4(_))
                    | (NetworkAddressFamily::Ipv6, IpAddr::V6(_))
            )
        })
        .and_then(|assigned| assigned.gateway.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no tunnel gateway for {} route",
                if address.is_ipv4() { "IPv4" } else { "IPv6" }
            )
        })
}

fn gateway_for_cidr<'a>(cidr: &str, addresses: &'a [NetworkAddress]) -> anyhow::Result<&'a str> {
    let address = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid route CIDR '{cidr}'"))?;
    gateway_for_ip(address, addresses)
}

fn route_family_is_active(cidr: &str, addresses: &[NetworkAddress]) -> anyhow::Result<bool> {
    let address = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid route CIDR '{cidr}'"))?;
    Ok(addresses.iter().any(|assigned| {
        matches!(
            (assigned.family, address),
            (NetworkAddressFamily::Ipv4, IpAddr::V4(_))
                | (NetworkAddressFamily::Ipv6, IpAddr::V6(_))
        )
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct NumericCidr {
    start: u128,
    prefix: u8,
    bits: u8,
}

impl NumericCidr {
    fn parse(cidr: &str) -> anyhow::Result<Self> {
        let network = cidr
            .parse::<ipnet::IpNet>()
            .map_err(|_| anyhow::anyhow!("invalid route CIDR '{cidr}'"))?;
        Ok(match network {
            ipnet::IpNet::V4(value) => Self {
                start: u128::from(u32::from(value.network())),
                prefix: value.prefix_len(),
                bits: 32,
            },
            ipnet::IpNet::V6(value) => Self {
                start: u128::from(value.network()),
                prefix: value.prefix_len(),
                bits: 128,
            },
        })
    }

    fn overlaps(self, other: Self) -> bool {
        if self.bits != other.bits {
            return false;
        }
        let common = self.prefix.min(other.prefix);
        common == 0
            || (self.start >> u32::from(self.bits - common))
                == (other.start >> u32::from(other.bits - common))
    }

    fn children(self) -> Option<[Self; 2]> {
        if self.prefix >= self.bits {
            return None;
        }
        let prefix = self.prefix + 1;
        let half = 1_u128 << u32::from(self.bits - prefix);
        Some([
            Self { prefix, ..self },
            Self {
                start: self.start | half,
                prefix,
                bits: self.bits,
            },
        ])
    }

    fn render(self) -> String {
        if self.bits == 32 {
            format!(
                "{}/{}",
                std::net::Ipv4Addr::from(self.start as u32),
                self.prefix
            )
        } else {
            format!("{}/{}", std::net::Ipv6Addr::from(self.start), self.prefix)
        }
    }
}

fn cidrs_cover(base: NumericCidr, candidates: &[NumericCidr]) -> bool {
    let overlapping: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.bits == base.bits && candidate.overlaps(base))
        .collect();
    if overlapping.is_empty() {
        return false;
    }
    if overlapping
        .iter()
        .any(|candidate| candidate.prefix <= base.prefix)
    {
        return true;
    }
    base.children().is_some_and(|children| {
        cidrs_cover(children[0], &overlapping) && cidrs_cover(children[1], &overlapping)
    })
}

fn routes_cover_address_family(routes: &[NetworkRoute], bits: u8) -> bool {
    let candidates: Vec<_> = routes
        .iter()
        .filter_map(|route| NumericCidr::parse(&route.cidr).ok())
        .filter(|route| route.bits == bits)
        .collect();
    cidrs_cover(
        NumericCidr {
            start: 0,
            prefix: 0,
            bits,
        },
        &candidates,
    )
}

fn subtract_one_cidr(
    base: NumericCidr,
    excluded: NumericCidr,
    output: &mut Vec<NumericCidr>,
) -> anyhow::Result<()> {
    if !base.overlaps(excluded) {
        output.push(base);
    } else if excluded.prefix <= base.prefix {
        // For two overlapping CIDRs, the broader/equal prefix covers the narrower one.
    } else if let Some(children) = base.children() {
        subtract_one_cidr(children[0], excluded, output)?;
        subtract_one_cidr(children[1], excluded, output)?;
    }
    if output.len() > super::MAX_ROUTES {
        anyhow::bail!(
            "route exclusions expand the NetworkPlan beyond {} routes",
            super::MAX_ROUTES
        );
    }
    Ok(())
}

fn cidr_minus_excludes(cidr: &str, excludes: &[NumericCidr]) -> anyhow::Result<Vec<NumericCidr>> {
    let base = NumericCidr::parse(cidr)?;
    let mut fragments = vec![base];
    for excluded in excludes
        .iter()
        .copied()
        .filter(|value| value.bits == base.bits)
    {
        let mut next = Vec::new();
        for fragment in fragments {
            subtract_one_cidr(fragment, excluded, &mut next)?;
        }
        fragments = next;
        if fragments.is_empty() {
            break;
        }
    }
    Ok(fragments)
}

/// Apply user route exclusions to the canonical plan itself, not only as a second physical
/// route. Without this, a more-specific pushed/include prefix beats a broader physical
/// exclusion under normal longest-prefix routing and silently re-enters the tunnel.
fn apply_route_exclusions(
    routes: Vec<NetworkRoute>,
    exclude_cidrs: &[String],
    protected_host_routes: &HashSet<NumericCidr>,
) -> anyhow::Result<Vec<NetworkRoute>> {
    let excludes = exclude_cidrs
        .iter()
        .map(|cidr| NumericCidr::parse(cidr))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut planned = Vec::new();
    for route in routes {
        let original = NumericCidr::parse(&route.cidr)?;
        let fragments = if protected_host_routes.contains(&original) {
            vec![original]
        } else {
            cidr_minus_excludes(&route.cidr, &excludes)?
        };
        if fragments.len() == 1 && fragments[0] == original {
            planned.push(route);
        } else {
            for fragment in fragments {
                planned.push(NetworkRoute {
                    cidr: fragment.render(),
                    gateway: route.gateway.clone(),
                    metric: route.metric,
                });
            }
        }
        if planned.len() > super::MAX_ROUTES {
            anyhow::bail!(
                "route exclusions expand the NetworkPlan beyond {} routes",
                super::MAX_ROUTES
            );
        }
    }
    Ok(planned)
}

fn planned_dns_servers_v2(
    config: &ClientDnsConfig,
    pushed: &[NetworkDns],
    addresses: &[NetworkAddress],
    platform_fallback: &[String],
) -> anyhow::Result<Vec<NetworkDns>> {
    if config.mode != "tunnel" {
        return Ok(Vec::new());
    }
    let candidates = if !config.servers.is_empty() {
        dns_list(&config.servers, "client", 53)?
    } else if !pushed.is_empty() {
        pushed.to_vec()
    } else if !platform_fallback.is_empty() {
        dns_list(platform_fallback, "platform fallback", 53)?
    } else {
        dns_list(&config.fallback_servers, "client fallback", 53)?
    };
    if candidates.len() > 8 {
        anyhow::bail!("network plan contains too many DNS servers");
    }
    for dns in &candidates {
        if dns.port == 0 {
            anyhow::bail!("invalid DNS server '{}:0'", dns.address);
        }
        let address: IpAddr = dns
            .address
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid DNS server '{}:{}'", dns.address, dns.port))?;
        gateway_for_ip(address, addresses).map_err(|_| {
            anyhow::anyhow!(
                "DNS server '{}' uses a family not present in the negotiated tunnel",
                dns.address
            )
        })?;
    }
    Ok(candidates)
}

/// Build the complete, sanitized post-authentication journal once in Rust. The GUI adapters
/// only display these lines and report the platform apply result, which keeps Android,
/// Windows, macOS and iOS at parity with the Linux client without exposing credentials.
#[allow(clippy::too_many_arguments)]
pub(crate) fn server_push_log_lines(
    config: &ClientConfig,
    plan: &NetworkPlan,
    pushed_mtu: i32,
    pushed_dns: &str,
    pushed_dns_port: &str,
    routes_json: &str,
    pushed_obfuscation: Option<&PushedObf>,
) -> Vec<String> {
    let received_routes = serde_json::from_str::<Vec<serde_json::Value>>(routes_json)
        .map(|routes| routes.len())
        .unwrap_or(0);
    let pushed_dns_display = if pushed_dns.is_empty() {
        "-".to_string()
    } else {
        format!("{}:{}", log_value(pushed_dns), log_value(pushed_dns_port))
    };
    let effective_dns = if plan.dns_servers.is_empty() {
        "system resolver unchanged".to_string()
    } else {
        plan.dns_servers
            .iter()
            .map(|dns| format!("{}:{}", dns.address, dns.port))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = vec![format!(
        "server push: ip={}/{} gw={} mtu={} dns={} routes={} obf={} streams={} adaptive={}",
        plan.tunnel_address,
        plan.prefix_len,
        plan.tunnel_gateway,
        if pushed_mtu > 0 {
            pushed_mtu.to_string()
        } else {
            "-".into()
        },
        pushed_dns_display,
        received_routes,
        if pushed_obfuscation.is_some() {
            "yes"
        } else {
            "-"
        },
        plan.max_streams,
        plan.adaptive,
    )];

    if pushed_mtu <= 0 {
        lines.push(format!(
            "server push: mtu not sent (older server) — using {}",
            plan.mtu
        ));
    } else if config.tun.mtu > 0 {
        lines.push(format!(
            "server push: mtu {} IGNORED — client mtu={} wins; using {}",
            pushed_mtu, config.tun.mtu, plan.mtu
        ));
    } else if i32::from(plan.mtu) != pushed_mtu {
        lines.push(format!(
            "server push: mtu {} accepted as the ceiling; path probe selected {}",
            pushed_mtu, plan.mtu
        ));
    } else {
        lines.push(format!(
            "server push: mtu {} ACCEPTED into NetworkPlan (client mtu=0/auto)",
            pushed_mtu
        ));
    }

    if pushed_dns.is_empty() {
        if plan.dns_servers.is_empty() {
            lines.push(
                "server push: no DNS sent — keeping the system resolver (server: set dns.push_servers, or enable dns.listen)"
                    .into(),
            );
        } else {
            lines.push(format!(
                "server push: no DNS sent — using configured/fallback resolver: {effective_dns}"
            ));
        }
    } else if config.leaves_resolver_alone() {
        lines.push(format!(
            "server push: DNS {} IGNORED — client dns={} leaves the system resolver unchanged",
            pushed_dns_display, config.dns.mode
        ));
    } else if !config.dns.servers.is_empty() {
        lines.push(format!(
            "server push: DNS {} IGNORED — client dns_servers override it; NetworkPlan uses {}",
            pushed_dns_display, effective_dns
        ));
    } else if plan
        .dns_servers
        .iter()
        .any(|dns| dns.address == pushed_dns && pushed_dns_port.parse::<u16>() == Ok(dns.port))
    {
        lines.push(format!(
            "server push: DNS {} ACCEPTED into NetworkPlan",
            pushed_dns_display
        ));
    } else {
        lines.push(format!(
            "server push: DNS {} REJECTED by routing policy; NetworkPlan uses {}",
            pushed_dns_display, effective_dns
        ));
    }

    if received_routes == 0 {
        lines.push(
            "server push: no routes sent — the server profile/user has no valid route entries"
                .into(),
        );
    } else {
        lines.push(format!(
            "server push: {} route(s) received; {} validated before client exclusions",
            received_routes,
            plan.pushed_routes.len()
        ));
        let excludes = config
            .routing
            .exclude
            .iter()
            .filter_map(|cidr| NumericCidr::parse(cidr).ok())
            .collect::<Vec<_>>();
        let protected_dns = plan
            .dns_servers
            .iter()
            .filter_map(|dns| {
                let address = dns.address.parse::<IpAddr>().ok()?;
                NumericCidr::parse(&format!(
                    "{address}/{}",
                    if address.is_ipv4() { 32 } else { 128 }
                ))
                .ok()
            })
            .collect::<HashSet<_>>();
        for cidr in &plan.pushed_routes {
            let original = NumericCidr::parse(cidr).ok();
            let fragments = original.and_then(|network| {
                if protected_dns.contains(&network) {
                    Some(vec![network])
                } else {
                    cidr_minus_excludes(cidr, &excludes).ok()
                }
            });
            let effective = original.and_then(|network| {
                plan.routes.iter().find(|route| {
                    NumericCidr::parse(&route.cidr).is_ok_and(|candidate| {
                        candidate.bits == network.bits
                            && candidate.prefix >= network.prefix
                            && candidate.overlaps(network)
                    })
                })
            });
            match (fragments.as_deref(), effective) {
                (Some([]), _) => lines.push(format!(
                    "server push: route {cidr} EXCLUDED by client routing policy"
                )),
                (Some([fragment]), Some(route)) if Some(*fragment) == original => {
                    lines.push(format!(
                        "server push: route {} ACCEPTED (gateway={} metric={})",
                        cidr, route.gateway, route.metric
                    ));
                }
                (Some(fragments), Some(route)) => lines.push(format!(
                    "server push: route {} PARTIALLY ACCEPTED as {} fragment(s) (gateway={} metric={})",
                    cidr,
                    fragments.len(),
                    route.gateway,
                    route.metric
                )),
                _ => lines.push(format!(
                    "server push: route {cidr} could not be correlated with the effective plan"
                )),
            }
        }
        if received_routes > plan.pushed_routes.len() {
            lines.push(format!(
                "server push: {} route(s) REJECTED (invalid CIDR/gateway or prefix broader than IPv4 /8 or IPv6 /3)",
                received_routes - plan.pushed_routes.len()
            ));
        }
    }

    match pushed_obfuscation {
        Some(obfuscation) => append_data_plane_lines(
            &mut lines,
            "server push",
            &obfuscation.padding,
            &obfuscation.heartbeat,
            &obfuscation.traffic_normalization,
            &obfuscation.traffic_shaping,
            "APPLIED",
        ),
        None => {
            lines.push(
                "server push: no obfuscation block sent — keeping client data-plane settings"
                    .into(),
            );
            append_data_plane_lines(
                &mut lines,
                "data plane effective",
                &config.obfuscation.padding,
                &config.obfuscation.heartbeat,
                &config.obfuscation.traffic_normalization,
                &config.obfuscation.traffic_shaping,
                "CLIENT",
            );
        }
    }
    lines.push(format!(
        "server push: multipath max_streams={} adaptive={}",
        plan.max_streams, plan.adaptive
    ));
    lines.push(format!(
        "NetworkPlan {}: mode={} address={}/{} gateway={} mtu={} dns=[{}] routes={} pushed_routes={} kill_switch={}",
        plan.generation,
        if plan.full_tunnel { "full" } else { "split" },
        plan.tunnel_address,
        plan.prefix_len,
        plan.tunnel_gateway,
        plan.mtu,
        effective_dns,
        plan.routes.len(),
        plan.pushed_routes.len(),
        plan.kill_switch,
    ));
    lines.into_iter().map(sanitize_log_line).collect()
}

fn append_data_plane_lines(
    lines: &mut Vec<String>,
    source: &str,
    padding: &PaddingConfig,
    heartbeat: &HeartbeatConfig,
    normalization: &TrafficNormalizationConfig,
    shaping: &TrafficShapingConfig,
    decision: &str,
) {
    lines.push(format!(
        "{source}: padding {decision} (enabled={} min={} max={} randomize={} probability={})",
        padding.enabled,
        padding.min_bytes,
        padding.max_bytes,
        padding.randomize,
        padding.probability
    ));
    lines.push(format!(
        "{source}: heartbeat {decision} (enabled={} interval_ms={} size={} jitter_ms={})",
        heartbeat.enabled, heartbeat.interval_ms, heartbeat.data_size_bytes, heartbeat.jitter_ms
    ));
    lines.push(format!(
        "{source}: normalization {decision} (enabled={} round_sizes={:?})",
        normalization.enabled, normalization.round_sizes
    ));
    lines.push(format!(
        "{source}: shaping {decision} (enabled={} gap_ms={}/{}/{} budget_Bps={} size={}-{} stealth={} stealth_Mbps={})",
        shaping.enabled,
        shaping.idle_gap_mean_ms,
        shaping.idle_gap_min_ms,
        shaping.idle_gap_max_ms,
        shaping.budget_bytes_per_sec,
        shaping.min_size,
        shaping.max_size,
        shaping.stealth,
        shaping.stealth_rate_mbps,
    ));
}

fn log_value(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(160)
        .collect()
}

fn sanitize_log_line(line: String) -> String {
    let mut clean = String::with_capacity(line.len().min(1_024));
    for character in line.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if clean.len() + character.len_utf8() > 1_024 {
            break;
        }
        clean.push(character);
    }
    clean
}

pub(crate) fn is_full_tunnel(config: &ClientConfig) -> bool {
    config.routing.add_default_gateway
        || matches!(config.routing.mode.as_str(), "full-tunnel" | "all")
}

fn normalized_prefix(prefix: u8) -> u8 {
    if (1..=32).contains(&prefix) {
        prefix
    } else {
        24
    }
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

/// Resolve the DNS part of a plan without changing platform state.
pub(crate) fn planned_dns_servers(
    config: &ClientDnsConfig,
    pushed_server: &str,
    pushed_port: &str,
    tun_net: Option<(Ipv4Addr, Ipv4Addr)>,
    full_tunnel: bool,
    platform_fallback: &[String],
) -> anyhow::Result<Vec<NetworkDns>> {
    if config.mode != "tunnel" {
        return Ok(Vec::new());
    }

    if !config.servers.is_empty() {
        return ipv4_dns_list(&config.servers, "client", 53);
    }

    if !pushed_server.is_empty() {
        let parsed = match pushed_server.parse::<IpAddr>() {
            Ok(IpAddr::V4(value)) if !pushed_server.starts_with('-') => IpAddr::V4(value),
            Ok(IpAddr::V6(_)) => anyhow::bail!(
                "IPv6 pushed DNS server '{pushed_server}' is unreachable in a legacy IPv4 tunnel"
            ),
            _ => return Ok(Vec::new()),
        };
        let port = pushed_port
            .parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid pushed DNS port '{pushed_port}'"))?;
        if port == 0 {
            anyhow::bail!("invalid pushed DNS port '0'");
        }
        let reachable = match (parsed, tun_net) {
            (IpAddr::V4(dns), Some((address, mask))) => {
                (u32::from(dns) & u32::from(mask)) == (u32::from(address) & u32::from(mask))
            }
            _ => false,
        };
        if full_tunnel || reachable {
            return Ok(vec![NetworkDns {
                address: pushed_server.to_string(),
                port,
            }]);
        }
    }

    if !platform_fallback.is_empty() {
        return ipv4_dns_list(platform_fallback, "platform fallback", 53);
    }
    ipv4_dns_list(&config.fallback_servers, "client fallback", 53)
}

fn ipv4_dns_list(addresses: &[String], source: &str, port: u16) -> anyhow::Result<Vec<NetworkDns>> {
    let servers = dns_list(addresses, source, port)?;
    if let Some(server) = servers.iter().find(|server| {
        server
            .address
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6())
    }) {
        anyhow::bail!(
            "IPv6 {source} DNS server '{}' is unreachable in a legacy IPv4 tunnel",
            server.address
        );
    }
    Ok(servers)
}

fn dns_list(addresses: &[String], source: &str, port: u16) -> anyhow::Result<Vec<NetworkDns>> {
    addresses
        .iter()
        .map(|address| {
            address
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid {source} DNS server '{address}'"))?;
            Ok(NetworkDns {
                address: address.clone(),
                port,
            })
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct PushedRoute {
    cidr: String,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
}

pub(crate) fn pushed_route_prefix_is_allowed(address: IpAddr, prefix: u8) -> bool {
    prefix >= if address.is_ipv4() { 8 } else { 3 }
}

/// Parse and validate server-pushed routes before they cross the platform boundary.
pub(crate) fn planned_pushed_routes(
    routes_json: &str,
    default_gateway: &str,
) -> anyhow::Result<Vec<NetworkRoute>> {
    let gateway: IpAddr = default_gateway
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid default tunnel gateway '{default_gateway}'"))?;
    let (family, max_prefix) = if gateway.is_ipv4() {
        (NetworkAddressFamily::Ipv4, 32)
    } else {
        (NetworkAddressFamily::Ipv6, 128)
    };
    planned_pushed_routes_for_addresses(
        routes_json,
        &[NetworkAddress {
            family,
            address: default_gateway.to_string(),
            prefix_len: max_prefix,
            on_link_prefix_len: max_prefix,
            gateway: Some(default_gateway.to_string()),
        }],
    )
}

pub(crate) fn planned_pushed_routes_for_addresses(
    routes_json: &str,
    addresses: &[NetworkAddress],
) -> anyhow::Result<Vec<NetworkRoute>> {
    let trimmed = routes_json.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Ok(Vec::new());
    }
    let routes: Vec<PushedRoute> = serde_json::from_str(trimmed)
        .map_err(|error| anyhow::anyhow!("failed to parse pushed routes: {error}"))?;
    let mut planned = Vec::with_capacity(routes.len());
    for route in routes {
        let route_address = match route
            .cidr
            .split_once('/')
            .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        {
            Some(address) => address,
            None => continue,
        };
        if !addresses.iter().any(|assigned| {
            matches!(
                (assigned.family, route_address),
                (NetworkAddressFamily::Ipv4, IpAddr::V4(_))
                    | (NetworkAddressFamily::Ipv6, IpAddr::V6(_))
            )
        }) {
            continue;
        }
        let gateway = match route.gateway.as_deref() {
            Some(gateway) => gateway,
            None => gateway_for_ip(route_address, addresses)?,
        };
        if !crate::util::is_valid_cidr(&route.cidr) || !crate::util::is_valid_gateway(gateway) {
            continue;
        }
        let gateway_address: IpAddr = match gateway.parse() {
            Ok(address) => address,
            Err(_) => continue,
        };
        if route_address.is_ipv4() != gateway_address.is_ipv4() {
            continue;
        }
        let prefix = route
            .cidr
            .rsplit_once('/')
            .and_then(|(_, prefix)| prefix.parse::<u8>().ok())
            .unwrap_or(if route_address.is_ipv4() { 32 } else { 128 });
        // Reject only routes broader than the public/global aggregate for their family. The
        // previous shared /8 floor accidentally discarded valid IPv6 aggregates such as ULA
        // fc00::/7 and global-unicast 2000::/3.
        if !pushed_route_prefix_is_allowed(route_address, prefix) {
            continue;
        }
        planned.push(NetworkRoute {
            cidr: route.cidr,
            gateway: gateway.to_string(),
            metric: route.metric.unwrap_or(100),
        });
    }
    for (bits, family) in [(32, "IPv4"), (128, "IPv6")] {
        if routes_cover_address_family(&planned, bits) {
            anyhow::bail!(
                "server-pushed routes collectively cover the entire {family} address space; only the local client may enable full-tunnel mode"
            );
        }
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_addresses() -> Vec<NetworkAddress> {
        vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv4,
            address: "10.8.0.2".into(),
            prefix_len: 24,
            on_link_prefix_len: 24,
            gateway: Some("10.8.0.1".into()),
        }]
    }

    #[test]
    fn assigned_prefix_follows_the_client_device_not_the_server_device() {
        let server_tun_addresses = vec![
            NetworkAddress {
                family: NetworkAddressFamily::Ipv4,
                address: "10.8.0.2".into(),
                prefix_len: 32,
                on_link_prefix_len: 24,
                gateway: Some("10.8.0.1".into()),
            },
            NetworkAddress {
                family: NetworkAddressFamily::Ipv6,
                address: "fd71:e1::2".into(),
                prefix_len: 128,
                on_link_prefix_len: 64,
                gateway: Some("fd71:e1::1".into()),
            },
        ];
        let mut tap = ClientConfig::default();
        tap.tun.device_type = "tap".into();
        let tap_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Dual,
            addresses: &server_tun_addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let tap_plan = build_network_plan(&tap, 1, &tap_network).unwrap();
        assert_eq!(tap_plan.addresses[0].prefix_len, 24);
        assert_eq!(tap_plan.addresses[1].prefix_len, 64);

        let server_tap_addresses = tap_plan.addresses;
        let mut tun = ClientConfig::default();
        tun.tun.device_type = "tun".into();
        let tun_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Dual,
            addresses: &server_tap_addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let tun_plan = build_network_plan(&tun, 2, &tun_network).unwrap();
        assert_eq!(tun_plan.addresses[0].prefix_len, 32);
        assert_eq!(tun_plan.addresses[1].prefix_len, 128);
        assert_eq!(tun_plan.addresses[0].on_link_prefix_len, 24);
        assert_eq!(tun_plan.addresses[1].on_link_prefix_len, 64);
    }

    #[test]
    fn rejects_unreachable_pushed_dns_but_keeps_client_dns() {
        let mut dns = ClientDnsConfig {
            mode: "tunnel".into(),
            ..ClientDnsConfig::default()
        };
        let subnet = Some((
            "10.8.0.2".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        ));
        assert!(
            planned_dns_servers(&dns, "203.0.113.53", "53", subnet, false, &[])
                .unwrap()
                .is_empty()
        );
        dns.servers.push("203.0.113.53".into());
        assert_eq!(
            planned_dns_servers(&dns, "10.8.0.1", "53", subnet, false, &[])
                .unwrap()
                .first()
                .unwrap()
                .address,
            "203.0.113.53"
        );
    }

    #[test]
    fn platform_fallback_is_used_only_after_an_unusable_push() {
        let dns = ClientDnsConfig {
            mode: "tunnel".into(),
            ..ClientDnsConfig::default()
        };
        let fallback = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        let planned = planned_dns_servers(&dns, "", "53", None, true, &fallback).unwrap();
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[1].address, "8.8.8.8");

        let pushed = planned_dns_servers(&dns, "10.8.0.1", "5353", None, true, &fallback).unwrap();
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].port, 5353);

        let disabled = ClientDnsConfig {
            mode: "off".into(),
            ..ClientDnsConfig::default()
        };
        assert!(
            planned_dns_servers(&disabled, "", "53", None, true, &fallback)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn legacy_ipv4_plan_rejects_unreachable_ipv6_dns() {
        let mut dns = ClientDnsConfig {
            mode: "tunnel".into(),
            ..ClientDnsConfig::default()
        };
        dns.servers.push("2001:4860:4860::8888".into());
        let error = planned_dns_servers(&dns, "", "53", None, true, &[]).unwrap_err();
        assert!(error.to_string().contains("legacy IPv4 tunnel"));

        dns.servers.clear();
        let error =
            planned_dns_servers(&dns, "2001:4860:4860::8888", "53", None, true, &[]).unwrap_err();
        assert!(error.to_string().contains("legacy IPv4 tunnel"));

        let fallback = vec!["2001:4860:4860::8888".into()];
        let error = planned_dns_servers(&dns, "", "53", None, true, &fallback).unwrap_err();
        assert!(error.to_string().contains("legacy IPv4 tunnel"));
    }

    #[test]
    fn filters_hostile_pushed_routes() {
        let routes = planned_pushed_routes(
            r#"[{"cidr":"10.20.0.0/16","metric":42},{"cidr":"0.0.0.0/0"},{"cidr":"bad"}]"#,
            "10.8.0.1",
        )
        .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cidr, "10.20.0.0/16");
        assert_eq!(routes[0].metric, 42);
    }

    #[test]
    fn rejects_composite_default_routes() {
        let ipv4 = serde_json::to_string(
            &(0u16..=255)
                .map(|octet| serde_json::json!({ "cidr": format!("{octet}.0.0.0/8") }))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let error = planned_pushed_routes(&ipv4, "10.8.0.1").unwrap_err();
        assert!(error.to_string().contains("entire IPv4"), "{error}");

        let ipv6 = r#"[
            {"cidr":"::/3"},{"cidr":"2000::/3"},{"cidr":"4000::/3"},{"cidr":"6000::/3"},
            {"cidr":"8000::/3"},{"cidr":"a000::/3"},{"cidr":"c000::/3"},{"cidr":"e000::/3"}
        ]"#;
        let error = planned_pushed_routes(ipv6, "fd71:e1::1").unwrap_err();
        assert!(error.to_string().contains("entire IPv6"), "{error}");
    }

    #[test]
    fn pushed_routes_are_filtered_to_the_negotiated_families() {
        let routes_json = r#"[
            {"cidr":"10.20.0.0/16","gateway":"10.8.0.1"},
            {"cidr":"2001:db8:20::/64","gateway":"fd71:e1::1"}
        ]"#;
        let ipv4 = planned_pushed_routes_for_addresses(routes_json, &ipv4_addresses()).unwrap();
        assert_eq!(ipv4.len(), 1);
        assert_eq!(ipv4[0].cidr, "10.20.0.0/16");

        let ipv6_addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd71:e1::1".into()),
        }];
        let ipv6 = planned_pushed_routes_for_addresses(routes_json, &ipv6_addresses).unwrap();
        assert_eq!(ipv6.len(), 1);
        assert_eq!(ipv6[0].cidr, "2001:db8:20::/64");
    }

    #[test]
    fn pushed_route_breadth_policy_is_family_aware() {
        let ipv6_addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd71:e1::1".into()),
        }];
        let routes = planned_pushed_routes_for_addresses(
            r#"[
                {"cidr":"fc00::/7"},
                {"cidr":"2000::/3"},
                {"cidr":"::/2"},
                {"cidr":"10.0.0.0/7"}
            ]"#,
            &ipv6_addresses,
        )
        .unwrap();
        assert_eq!(
            routes
                .iter()
                .map(|route| route.cidr.as_str())
                .collect::<Vec<_>>(),
            ["fc00::/7", "2000::/3"]
        );
    }

    #[test]
    fn ipv6_only_plan_ignores_ipv4_route_local_without_mixed_gateway() {
        let mut config = ClientConfig::default();
        config.routing.route_local_networks = true;
        let addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd71:e1::1".into()),
        }];
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv6,
            addresses: &addresses,
            client_ip: "fd71:e1::2",
            prefix: 128,
            tunnel_gateway: "fd71:e1::1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 7, &network).unwrap();
        assert!(plan.routes.iter().all(|route| !route.cidr.contains('.')));
    }

    #[test]
    fn network_plan_keeps_server_routes_distinct_from_client_routes() {
        let mut config = ClientConfig::default();
        config.routing.include.push("192.0.2.0/24".into());
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: r#"[{"cidr":"10.20.0.0/16"}]"#,
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 7, &network).unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.pushed_routes, ["10.20.0.0/16"]);
    }

    #[test]
    fn split_tunnel_dns_gets_an_explicit_host_route() {
        let mut config = ClientConfig::default();
        config.dns.mode = "tunnel".into();
        config.dns.servers.push("203.0.113.53".into());
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 7, &network).unwrap();
        assert!(plan
            .routes
            .iter()
            .any(|route| { route.cidr == "203.0.113.53/32" && route.gateway == "10.8.0.1" }));
    }

    #[test]
    fn network_plan_rejects_an_excluded_tunnel_dns_server_in_both_families() {
        let mut ipv4_config = ClientConfig::default();
        ipv4_config.dns.mode = "tunnel".into();
        ipv4_config.dns.servers.push("203.0.113.53".into());
        ipv4_config.routing.exclude.push("203.0.113.53/32".into());
        let ipv4_addresses = ipv4_addresses();
        let ipv4_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &ipv4_addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let error = build_network_plan(&ipv4_config, 7, &ipv4_network).unwrap_err();
        assert!(error.to_string().contains("covered by exclude route"));

        let mut ipv6_config = ClientConfig::default();
        ipv6_config.dns.mode = "tunnel".into();
        ipv6_config.dns.servers.push("2001:db8:53::1".into());
        ipv6_config
            .routing
            .exclude
            .push("2001:db8:53::1/128".into());
        let ipv6_addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd71:e1::1".into()),
        }];
        let ipv6_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv6,
            addresses: &ipv6_addresses,
            client_ip: "fd71:e1::2",
            prefix: 128,
            tunnel_gateway: "fd71:e1::1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let error = build_network_plan(&ipv6_config, 8, &ipv6_network).unwrap_err();
        assert!(
            error.to_string().contains("covered by exclude route"),
            "{error}"
        );
    }

    #[test]
    fn exclusions_cannot_override_the_negotiated_tunnel_gateway() {
        let ipv4_addresses = ipv4_addresses();
        let ipv4_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &ipv4_addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let mut broad_ipv4 = ClientConfig::default();
        broad_ipv4.routing.exclude.push("10.0.0.0/8".into());
        assert!(build_network_plan(&broad_ipv4, 1, &ipv4_network).is_ok());
        for exclusion in ["10.8.0.0/24", "10.8.0.1/32"] {
            let mut config = ClientConfig::default();
            config.routing.exclude.push(exclusion.into());
            let error = build_network_plan(&config, 2, &ipv4_network).unwrap_err();
            assert!(error.to_string().contains("tunnel gateway"), "{error}");
        }

        let ipv6_addresses = vec![NetworkAddress {
            family: NetworkAddressFamily::Ipv6,
            address: "fd71:e1::2".into(),
            prefix_len: 128,
            on_link_prefix_len: 64,
            gateway: Some("fd71:e1::1".into()),
        }];
        let ipv6_network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv6,
            addresses: &ipv6_addresses,
            client_ip: "fd71:e1::2",
            prefix: 128,
            tunnel_gateway: "fd71:e1::1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let mut broad_ipv6 = ClientConfig::default();
        broad_ipv6.routing.exclude.push("fc00::/7".into());
        assert!(build_network_plan(&broad_ipv6, 3, &ipv6_network).is_ok());
        for exclusion in ["fd71:e1::/64", "fd71:e1::1/128"] {
            let mut config = ClientConfig::default();
            config.routing.exclude.push(exclusion.into());
            let error = build_network_plan(&config, 4, &ipv6_network).unwrap_err();
            assert!(error.to_string().contains("tunnel gateway"), "{error}");
        }
    }

    #[test]
    fn broad_exclude_keeps_tunnel_dns_on_a_more_specific_host_route() {
        let mut config = ClientConfig::default();
        config.dns.mode = "tunnel".into();
        config.dns.servers.push("203.0.113.53".into());
        config.routing.exclude.push("203.0.113.0/24".into());
        config.routing.mode = "full-tunnel".into();
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 9, &network).unwrap();
        assert!(plan
            .routes
            .iter()
            .any(|route| route.cidr == "203.0.113.53/32" && route.metric == 50));
    }

    #[test]
    fn plan_exactly_subtracts_broader_ipv4_and_ipv6_routes() {
        let mut config = ClientConfig::default();
        config.dns.mode = "off".into();
        config.routing.include.push("10.0.0.0/8".into());
        config.routing.exclude.push("10.1.0.0/16".into());
        config.routing.include.push("2001:db8::/32".into());
        config.routing.exclude.push("2001:db8:53::/48".into());
        let addresses = vec![
            NetworkAddress {
                family: NetworkAddressFamily::Ipv4,
                address: "10.8.0.2".into(),
                prefix_len: 32,
                on_link_prefix_len: 24,
                gateway: Some("10.8.0.1".into()),
            },
            NetworkAddress {
                family: NetworkAddressFamily::Ipv6,
                address: "fd71:e1::2".into(),
                prefix_len: 128,
                on_link_prefix_len: 64,
                gateway: Some("fd71:e1::1".into()),
            },
        ];
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Dual,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 10, &network).unwrap();
        let excluded_v4 = NumericCidr::parse("10.1.0.0/16").unwrap();
        let excluded_v6 = NumericCidr::parse("2001:db8:53::/48").unwrap();
        assert_eq!(plan.routes.len(), 24);
        assert!(plan.routes.iter().all(|route| {
            let value = NumericCidr::parse(&route.cidr).unwrap();
            !value.overlaps(excluded_v4) && !value.overlaps(excluded_v6)
        }));
        for allowed in [
            "10.0.1.1/32",
            "10.2.0.1/32",
            "2001:db8:52::1/128",
            "2001:db8:54::1/128",
        ] {
            let host = NumericCidr::parse(allowed).unwrap();
            assert!(plan
                .routes
                .iter()
                .any(|route| NumericCidr::parse(&route.cidr).unwrap().overlaps(host)));
        }
    }

    #[test]
    fn a_fully_excluded_route_is_absent_but_pushed_provenance_is_retained() {
        let mut config = ClientConfig::default();
        config.dns.mode = "off".into();
        config.routing.exclude.push("10.0.0.0/8".into());
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: r#"[{"cidr":"10.20.0.0/16"}]"#,
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 11, &network).unwrap();
        assert!(plan.routes.is_empty());
        assert_eq!(plan.pushed_routes, ["10.20.0.0/16"]);
    }

    #[test]
    fn full_tunnel_refuses_tunnel_dns_without_a_resolver() {
        let mut config = ClientConfig::default();
        config.dns.mode = "tunnel".into();
        config.routing.mode = "full-tunnel".into();
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            dns_servers: &[],
            routes_json: "[]",
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        assert!(build_network_plan(&config, 7, &network).is_err());
    }

    #[test]
    fn server_push_journal_covers_every_negotiated_group_and_rejection() {
        let mut config = ClientConfig::default();
        config.dns.mode = "tunnel".into();
        config.tun.mtu = 0;
        let routes = r#"[{"cidr":"10.20.0.0/16","metric":42},{"cidr":"0.0.0.0/0"}]"#;
        let addresses = ipv4_addresses();
        let network = HandshakeNetwork {
            family_mode: NetworkFamilyMode::Ipv4,
            addresses: &addresses,
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "10.8.0.1",
            dns_port: "53",
            dns_servers: &[],
            routes_json: routes,
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let mut plan = build_network_plan(&config, 7, &network).unwrap();
        plan.max_streams = 4;
        plan.adaptive = true;
        let pushed = PushedObf::default();
        let lines = server_push_log_lines(
            &config,
            &plan,
            1400,
            "10.8.0.1",
            "53",
            routes,
            Some(&pushed),
        );

        for expected in [
            "server push: ip=10.8.0.2/24",
            "mtu 1400 ACCEPTED",
            "DNS 10.8.0.1:53 ACCEPTED",
            "route 10.20.0.0/16 ACCEPTED",
            "1 route(s) REJECTED",
            "padding APPLIED",
            "heartbeat APPLIED",
            "normalization APPLIED",
            "shaping APPLIED",
            "multipath max_streams=4 adaptive=true",
            "NetworkPlan 7:",
        ] {
            assert!(
                lines.iter().any(|line| line.contains(expected)),
                "missing {expected:?} in {lines:#?}"
            );
        }
        assert!(lines.iter().all(|line| line.len() <= 1_024));
    }
}
