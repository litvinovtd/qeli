use crate::config::client::ClientRoutingConfig;

pub fn setup_routes(
    config: &ClientRoutingConfig,
    gateway: &str,
    ifname: &str,
    server_addr: &str,
) -> anyhow::Result<()> {
    // Install a default route via the tunnel only when explicitly requested.
    // (Previously this also fired when `include` was empty, which silently
    // hijacked the host's default route — and could black-hole SSH.)
    if config.add_default_gateway || config.mode == "full-tunnel" || config.mode == "all" {
        let via_output = std::process::Command::new("ip")
            .args(["route", "get", server_addr])
            .output()?;

        let via_str = String::from_utf8_lossy(&via_output.stdout);
        let mut physical_gw = None;
        let mut physical_via = None;
        for part in via_str.split_whitespace() {
            if part == "via" {
                physical_via = Some(true);
            } else if physical_via.take() == Some(true) {
                physical_gw = Some(part.to_string());
                break;
            }
        }

        if let Some(gw) = &physical_gw {
            let output = std::process::Command::new("ip")
                .args(["route", "add", server_addr, "via", gw])
                .output()?;
            if output.status.success() {
                log::info!("Added bypass route: {} via {}", server_addr, gw);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    log::warn!("Failed to add bypass route for {}: {}", server_addr, stderr);
                }
            }
        }

        // Override the host default via the tunnel with the two-halves trick
        // (`0.0.0.0/1` + `128.0.0.0/1`): each is MORE SPECIFIC than any `/0`
        // default, so the tunnel wins regardless of the physical default's metric,
        // without deleting it (the server-bypass `/32` above keeps the encrypted
        // path to the server on the physical gateway, and the connected `/24` keeps
        // tunnel-internal traffic local). A single `default … metric 100` would lose
        // to the common metric-0 physical default and silently fail to tunnel.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let output = std::process::Command::new("ip")
                .args(["route", "add", half, "via", gateway, "dev", ifname])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    log::warn!("Failed to add full-tunnel route {}: {}", half, stderr);
                }
            }
        }
    }

    for subnet in &config.include {
        let output = std::process::Command::new("ip")
            .args(["route", "add", subnet, "via", gateway, "dev", ifname])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                log::warn!("Failed to add route {}: {}", subnet, stderr);
            }
        }
    }

    for subnet in &config.exclude {
        let _ = std::process::Command::new("ip")
            .args(["route", "del", subnet, "dev", ifname])
            .output();
    }

    for route in &config.custom_routes {
        let output = std::process::Command::new("ip")
            .args([
                "route",
                "add",
                &route.dest,
                "via",
                &route.via,
                "metric",
                &route.metric.to_string(),
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                log::warn!("Failed to add custom route {}: {}", route.dest, stderr);
            }
        }
    }

    Ok(())
}

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PushedRoute {
    cidr: String,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    metric: Option<u32>,
}

/// Route private/local networks through the tunnel, gated by
/// `routing.route_local_networks`. When enabled, applies the server-pushed
/// networks AND the RFC1918 private ranges so LAN resources behind the server
/// are reachable. When disabled, does nothing (local traffic stays off-tunnel
/// and pushed networks are ignored).
pub fn apply_local_networks(
    routing: &ClientRoutingConfig,
    routes_json: &str,
    ifname: &str,
    gateway: &str,
) {
    if !routing.route_local_networks {
        return;
    }
    // Specific local subnets the server advertised.
    apply_pushed_routes(routes_json, ifname, gateway);
    // Broad RFC1918 ranges so any private destination also tunnels.
    for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
        let output = std::process::Command::new("ip")
            .args([
                "route", "add", cidr, "via", gateway, "dev", ifname, "metric", "100",
            ])
            .output();
        if let Ok(o) = output {
            if !o.status.success() {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    log::warn!("Failed to route local net {}: {}", cidr, stderr.trim());
                }
            }
        }
    }
    log::info!(
        "Routing local networks (RFC1918 + {} pushed) through the tunnel",
        routes_json.matches("cidr").count()
    );
}

pub fn apply_pushed_routes(routes_json: &str, ifname: &str, default_gateway: &str) {
    let trimmed = routes_json.trim();
    if trimmed == "[]" || trimmed.is_empty() {
        return;
    }

    let routes: Vec<PushedRoute> = match serde_json::from_str(trimmed) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Failed to parse pushed routes: {}", e);
            return;
        }
    };

    for route in &routes {
        let gateway = route.gateway.as_deref().unwrap_or(default_gateway);
        let metric = route.metric.unwrap_or(100);

        // A malicious server could push a bogus/hostile CIDR or gateway that
        // ends up as an argument to `ip route add`. Validate both as real IP
        // values (and reject any option-looking string) before use; skip+log
        // anything that does not parse.
        if !is_valid_cidr(&route.cidr) {
            log::warn!("Ignoring pushed route with invalid CIDR: {}", route.cidr);
            continue;
        }
        if !is_valid_gateway(gateway) {
            log::warn!(
                "Ignoring pushed route {} with invalid gateway: {}",
                route.cidr,
                gateway
            );
            continue;
        }

        let output = std::process::Command::new("ip")
            .args([
                "route",
                "add",
                &route.cidr,
                "via",
                gateway,
                "dev",
                ifname,
                "metric",
                &metric.to_string(),
            ])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                log::info!(
                    "Pushed route applied: {} via {} dev {} metric {}",
                    route.cidr,
                    gateway,
                    ifname,
                    metric
                );
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                if !stderr.contains("File exists") {
                    log::warn!("Pushed route {} failed: {}", route.cidr, stderr.trim());
                }
            }
            Err(e) => log::warn!("Pushed route {} error: {}", route.cidr, e),
        }
    }
}

/// Validate a server-pushed CIDR (`ADDR/PREFIX`) using only std::net: the
/// address must parse as an `IpAddr` and the prefix must be a decimal length in
/// range for the family. Also rejects anything that could be read as an `ip`
/// option (leading `-`).
fn is_valid_cidr(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(len) = prefix.parse::<u8>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    len <= max
}

/// Validate a server-pushed gateway: must parse as a bare `IpAddr` and must not
/// look like an `ip` option (leading `-`).
fn is_valid_gateway(s: &str) -> bool {
    !s.starts_with('-') && s.parse::<std::net::IpAddr>().is_ok()
}

pub fn cleanup_routes(ifname: &str, server_addr: &str) -> anyhow::Result<()> {
    let _ = std::process::Command::new("ip")
        .args(["route", "del", server_addr])
        .output();
    std::process::Command::new("ip")
        .args(["route", "flush", "dev", ifname])
        .output()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_valid_cidr, is_valid_gateway};

    #[test]
    fn pushed_cidr_validation() {
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("fd00::/64"));
        assert!(is_valid_cidr("2001:db8::/32"));

        assert!(!is_valid_cidr("10.0.0.0")); // no prefix
        assert!(!is_valid_cidr("10.0.0.0/33")); // v4 prefix too large
        assert!(!is_valid_cidr("fd00::/129")); // v6 prefix too large
        assert!(!is_valid_cidr("not-an-ip/24"));
        assert!(!is_valid_cidr("-10.0.0.0/8")); // option-looking
        assert!(!is_valid_cidr("10.0.0.0/8 dev eth0")); // injected args
    }

    #[test]
    fn pushed_gateway_validation() {
        assert!(is_valid_gateway("10.0.0.1"));
        assert!(is_valid_gateway("fe80::1"));

        assert!(!is_valid_gateway("-1.2.3.4"));
        assert!(!is_valid_gateway("10.0.0.1/24"));
        assert!(!is_valid_gateway("gateway"));
        assert!(!is_valid_gateway("10.0.0.1 metric 0"));
    }
}
