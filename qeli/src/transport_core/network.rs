//! Platform-neutral construction of the network plan learned during authentication.
//!
//! The shared core decides what routes and DNS settings are safe. Platform adapters only
//! apply the resulting [`NetworkPlan`](super::NetworkPlan) and acknowledge that generation.

use crate::config::client::{ClientConfig, ClientDnsConfig};
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
    /// Platform policy fallback used only when neither the profile nor the server supplied
    /// a resolver. Android preserves its established public fallback through this seam.
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
        routes,
        dns_servers,
        full_tunnel,
        kill_switch: config.routing.kill_switch && full_tunnel,
        max_streams: 1,
        adaptive: false,
    })
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
}
