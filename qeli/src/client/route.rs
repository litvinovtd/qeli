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
    // Physical default gateway toward the server. Used both to pin the server-bypass
    // /32 (full-tunnel) and to route EXCLUDED subnets around the tunnel below.
    let physical_gw = default_gateway(server_addr);

    if config.add_default_gateway || config.mode == "full-tunnel" || config.mode == "all" {
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

    // Exclude: carve specific subnets OUT of the tunnel. Adding a more-specific route
    // via the PHYSICAL gateway beats the `0.0.0.0/1`+`128.0.0.0/1` full-tunnel halves,
    // so exclusion works even in full-tunnel (a plain `route del ... dev tun` is a no-op
    // there — the subnet has no dedicated tun route to remove). Falls back to the delete
    // when the physical gateway is unknown (split-tunnel, where the subnet only exists on
    // tun if `include` added it). Removed on disconnect by cleanup_routes.
    for subnet in &config.exclude {
        if !is_valid_cidr(subnet) {
            log::warn!("skipping invalid exclude subnet: {}", subnet);
            continue;
        }
        if let Some(gw) = &physical_gw {
            let output = std::process::Command::new("ip")
                .args(["route", "add", subnet, "via", gw])
                .output();
            if let Ok(o) = output {
                if !o.status.success() {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if !stderr.contains("File exists") {
                        log::warn!("Failed to add exclude bypass {}: {}", subnet, stderr);
                    }
                }
            }
        } else {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", subnet, "dev", ifname])
                .output();
        }
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

/// Apply the subnets the server advertised, plus — only when
/// `routing.route_local_networks` is on — the broad RFC1918 ranges.
///
/// The two are deliberately NOT gated together. A server-pushed route is a
/// *specific* CIDR an admin explicitly configured (`route = …` on the profile,
/// or a per-user route), so it is always honoured — exactly like OpenVPN's
/// `push "route …"`. Every pushed value is validated in `apply_pushed_routes`
/// before it reaches `ip`, so a hostile server still cannot smuggle anything.
/// `route_local_networks` gates only the *blanket* 10/8 + 172.16/12 +
/// 192.168/16 pull, which stays off by default because it would hijack the
/// client's OWN LAN (printers, NAS, local router).
///
/// Until 0.7.12 the pushed routes sat behind the same flag, so a correctly
/// configured `route =` was silently dropped on every default client.
pub fn apply_local_networks(
    routing: &ClientRoutingConfig,
    routes_json: &str,
    ifname: &str,
    gateway: &str,
) {
    // Specific subnets the server advertised — always honoured.
    apply_pushed_routes(routes_json, ifname, gateway);
    if !routing.route_local_networks {
        return;
    }
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
    log::info!("Routing local networks (RFC1918 blanket) through the tunnel");
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

        // Report the route EXACTLY as it arrived, BEFORE we touch it, so the log answers
        // "what did the server actually send?" on its own. NB: the server resolves the
        // defaults itself (`gateway` falls back to the profile's tun address and `metric`
        // to 100 in build_auth_ok), so every pushed route carries both fields — we cannot
        // tell an admin-set gateway from a server-defaulted one, and must not pretend to.
        log::info!(
            "pushed route received: {} gateway={} metric={}",
            if route.cidr.is_empty() {
                "<empty>"
            } else {
                &route.cidr
            },
            gateway,
            metric,
        );

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
                    // Name the gateway: the usual cause is a next hop that is NOT reachable on
                    // the tunnel subnet ("Nexthop has invalid gateway"), which Linux refuses.
                    // The desktop/mobile clients route interface-scoped and quietly accept such
                    // a route, so the server side can look "fine" while Linux clients drop it.
                    log::warn!(
                        "pushed route {} via {} NOT applied: {} — the next hop must be reachable \
                         on the tunnel subnet; drop `gateway=` from the server's `route =` line to \
                         use the tunnel gateway ({}) instead",
                        route.cidr,
                        gateway,
                        stderr.trim(),
                        default_gateway
                    );
                }
            }
            Err(e) => log::warn!("pushed route {} error: {}", route.cidr, e),
        }
    }
}

/// Validate a server-pushed CIDR — shared with the config parser and the panel
/// API so the same rule rejects a bad route wherever it is authored.
fn is_valid_cidr(s: &str) -> bool {
    crate::util::is_valid_cidr(s)
}

/// Validate a server-pushed gateway: a bare `IpAddr`, never a subnet.
fn is_valid_gateway(s: &str) -> bool {
    crate::util::is_valid_gateway(s)
}

/// The physical default gateway used to reach `server_addr` (parsed from
/// `ip route get`). `None` if it can't be determined (e.g. an on-link server).
fn default_gateway(server_addr: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", server_addr])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut saw_via = false;
    for part in s.split_whitespace() {
        if part == "via" {
            saw_via = true;
        } else if saw_via {
            return Some(part.to_string());
        }
    }
    None
}

pub fn cleanup_routes(ifname: &str, server_addr: &str, exclude: &[String]) -> anyhow::Result<()> {
    let _ = std::process::Command::new("ip")
        .args(["route", "del", server_addr])
        .output();
    // Remove the exclude bypass routes we added on the PHYSICAL interface — the
    // `flush dev tun` below only clears tun routes, so these would otherwise linger and
    // could black-hole the subnet if the gateway changes on the next network.
    for subnet in exclude {
        if is_valid_cidr(subnet) {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", subnet])
                .output();
        }
    }
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
