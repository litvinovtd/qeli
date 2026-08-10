//! Platform-neutral construction of the network plan learned during authentication.
//!
//! The shared core decides what routes and DNS settings are safe. Platform adapters only
//! apply the resulting [`NetworkPlan`](super::NetworkPlan) and acknowledge that generation.

use crate::config::client::{ClientConfig, ClientDnsConfig};
use crate::config::{
    HeartbeatConfig, PaddingConfig, PushedObf, TrafficNormalizationConfig, TrafficShapingConfig,
};
use crate::transport_core::{NetworkDns, NetworkPlan, NetworkRoute};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) struct HandshakeNetwork<'a> {
    pub client_ip: &'a str,
    pub prefix: u8,
    pub tunnel_gateway: &'a str,
    pub dns_ip: &'a str,
    pub dns_port: &'a str,
    pub routes_json: &'a str,
    pub mtu: i32,
    /// Optional platform-supplied resolvers used only when neither the profile nor the server
    /// supplied one. Production clients pass an empty list; the seam remains for embedders.
    pub fallback_dns_servers: &'a [String],
}

pub(crate) fn build_network_plan(
    config: &ClientConfig,
    generation: u64,
    network: &HandshakeNetwork<'_>,
) -> anyhow::Result<NetworkPlan> {
    let mtu = u16::try_from(network.mtu)
        .map_err(|_| anyhow::anyhow!("invalid tunnel MTU {}", network.mtu))?;
    let full_tunnel = is_full_tunnel(config);
    let prefix = normalized_prefix(network.prefix);
    let tun_net = network
        .client_ip
        .parse::<Ipv4Addr>()
        .ok()
        .map(|address| (address, prefix_to_netmask(prefix)));
    let dns_servers = planned_dns_servers(
        &config.dns,
        network.dns_ip,
        network.dns_port,
        tun_net,
        full_tunnel,
        network.fallback_dns_servers,
    )?;

    let mut routes = planned_pushed_routes(network.routes_json, network.tunnel_gateway)?;
    let pushed_routes = routes.iter().map(|route| route.cidr.clone()).collect();
    routes.extend(config.routing.include.iter().map(|cidr| NetworkRoute {
        cidr: cidr.clone(),
        gateway: network.tunnel_gateway.to_string(),
        metric: 100,
    }));
    if config.routing.route_local_networks {
        routes.extend(
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                .into_iter()
                .map(|cidr| NetworkRoute {
                    cidr: cidr.to_string(),
                    gateway: network.tunnel_gateway.to_string(),
                    metric: 100,
                }),
        );
    }
    routes.extend(
        config
            .routing
            .custom_routes
            .iter()
            .map(|route| NetworkRoute {
                cidr: route.dest.clone(),
                gateway: route.via.clone(),
                metric: route.metric,
            }),
    );

    Ok(NetworkPlan {
        generation,
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
        max_streams: 1,
        adaptive: false,
        data_plane: Default::default(),
        connection_log: Vec::new(),
    })
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
            "server push: {} route(s) received; {} accepted into NetworkPlan",
            received_routes,
            plan.pushed_routes.len()
        ));
        for (index, cidr) in plan.pushed_routes.iter().enumerate() {
            if let Some(route) = plan.routes.get(index) {
                lines.push(format!(
                    "server push: route {} ACCEPTED (gateway={} metric={})",
                    cidr, route.gateway, route.metric
                ));
            }
        }
        if received_routes > plan.pushed_routes.len() {
            lines.push(format!(
                "server push: {} route(s) REJECTED (invalid CIDR/gateway or prefix broader than /8)",
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
        return dns_list(&config.servers, "client", 53);
    }

    if !pushed_server.is_empty() {
        let parsed = match pushed_server.parse::<IpAddr>() {
            Ok(value) if !pushed_server.starts_with('-') => value,
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
        return dns_list(platform_fallback, "platform fallback", 53);
    }
    dns_list(&config.fallback_servers, "client fallback", 53)
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

/// Parse and validate server-pushed routes before they cross the platform boundary.
pub(crate) fn planned_pushed_routes(
    routes_json: &str,
    default_gateway: &str,
) -> anyhow::Result<Vec<NetworkRoute>> {
    let trimmed = routes_json.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Ok(Vec::new());
    }
    let routes: Vec<PushedRoute> = serde_json::from_str(trimmed)
        .map_err(|error| anyhow::anyhow!("failed to parse pushed routes: {error}"))?;
    let mut planned = Vec::with_capacity(routes.len());
    for route in routes {
        let gateway = route.gateway.as_deref().unwrap_or(default_gateway);
        if !crate::util::is_valid_cidr(&route.cidr) || !crate::util::is_valid_gateway(gateway) {
            continue;
        }
        let prefix = route
            .cidr
            .rsplit_once('/')
            .and_then(|(_, prefix)| prefix.parse::<u8>().ok())
            .unwrap_or(32);
        if prefix < 8 {
            continue;
        }
        planned.push(NetworkRoute {
            cidr: route.cidr,
            gateway: gateway.to_string(),
            metric: route.metric.unwrap_or(100),
        });
    }
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn network_plan_keeps_server_routes_distinct_from_client_routes() {
        let mut config = ClientConfig::default();
        config.routing.include.push("192.0.2.0/24".into());
        let network = HandshakeNetwork {
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "",
            dns_port: "53",
            routes_json: r#"[{"cidr":"10.20.0.0/16"}]"#,
            mtu: 1400,
            fallback_dns_servers: &[],
        };
        let plan = build_network_plan(&config, 7, &network).unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.pushed_routes, ["10.20.0.0/16"]);
    }

    #[test]
    fn server_push_journal_covers_every_negotiated_group_and_rejection() {
        let mut config = ClientConfig::default();
        config.dns.mode = "tunnel".into();
        config.tun.mtu = 0;
        let routes = r#"[{"cidr":"10.20.0.0/16","metric":42},{"cidr":"0.0.0.0/0"}]"#;
        let network = HandshakeNetwork {
            client_ip: "10.8.0.2",
            prefix: 24,
            tunnel_gateway: "10.8.0.1",
            dns_ip: "10.8.0.1",
            dns_port: "53",
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
