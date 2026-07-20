use crate::config::client::ClientRoutingConfig;

/// Routes this process actually CREATED on the physical interface, so cleanup removes
/// only those.
///
/// Cleanup used to `ip route del` the server address, every `exclude` subnet and the IPv6
/// blackholes unconditionally — but setup treats an existing route as a benign no-op
/// ("File exists"), so those are exactly the cases where the route was someone else's:
/// an operator's static bypass, a route another VPN put there, a blackhole the host had.
/// Disconnecting then deleted it and left the host worse than it found it, with nothing
/// said. Record on successful creation, delete only what is recorded.
static CREATED_ROUTES: std::sync::Mutex<Vec<Vec<String>>> = std::sync::Mutex::new(Vec::new());

fn note_created(args: &[&str]) {
    if let Ok(mut g) = CREATED_ROUTES.lock() {
        g.push(args.iter().map(|s| s.to_string()).collect());
    }
}

/// Take the journal, leaving it empty (cleanup runs once per connection).
fn take_created() -> Vec<Vec<String>> {
    CREATED_ROUTES
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default()
}

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
                note_created(&["route", "del", server_addr]);
                log::info!("Added bypass route: {} via {}", server_addr, gw);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    // Fatal in full tunnel: without the bypass the encrypted path to the
                    // server would itself be routed into the tunnel we are building.
                    anyhow::bail!(
                        "full tunnel: could not pin the server bypass route for {} via {}: {}",
                        server_addr,
                        gw,
                        stderr.trim()
                    );
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
        //
        // Both halves are load-bearing and failure here is FATAL. Logging and carrying on
        // meant losing one half silently exposed half of the IPv4 space — and losing both
        // exposed everything — while the UI still said "connected, full tunnel". A refused
        // connection is the honest outcome; the caller tears down and retries.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let output = std::process::Command::new("ip")
                .args(["route", "add", half, "via", gateway, "dev", ifname])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "full tunnel: could not install route {} via {} dev {}: {} — refusing \
                         to run with a partial default route (traffic would leak)",
                        half,
                        gateway,
                        ifname,
                        stderr.trim()
                    );
                }
            }
        }
        // Verify against the FIB rather than trusting the exit status. The kill-switch
        // already re-checks every rule it installs because the iptables-nft wrapper can
        // report success while silently doing nothing; `ip route` deserves the same
        // distrust, and here a false success is a full-traffic leak.
        for half in ["0.0.0.0/1", "128.0.0.0/1"] {
            let shown = std::process::Command::new("ip")
                .args(["route", "show", half])
                .output()?;
            let text = String::from_utf8_lossy(&shown.stdout);
            if !text.contains(ifname) {
                anyhow::bail!(
                    "full tunnel: route {} is not in the routing table on {} after being added \
                     (saw {:?}) — refusing to run with a partial default route",
                    half,
                    ifname,
                    text.trim()
                );
            }
        }

        // IPv6. The halves above are IPv4-only, so in full tunnel every IPv6 destination
        // kept using the physical interface — the mode promises to carry all traffic and
        // quietly did not. qeli does not tunnel IPv6 yet, so the honest options are to
        // leak or to block; block, matching the kill-switch's existing fail-closed
        // contract, and let `allow_ipv6_leak` be the explicit opt-out it already is.
        if !config.allow_ipv6_leak {
            let mut blocked = 0;
            for half in ["::/1", "8000::/1"] {
                let out = std::process::Command::new("ip")
                    .args(["-6", "route", "add", "blackhole", half])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        note_created(&["-6", "route", "del", "blackhole", half]);
                        blocked += 1;
                    }
                    Ok(o) => {
                        let e = String::from_utf8_lossy(&o.stderr);
                        if e.contains("File exists") {
                            // Pre-existing: counts as blocked, but is not ours to remove.
                            blocked += 1;
                        } else {
                            log::warn!(
                                "full tunnel: could not blackhole IPv6 {}: {}",
                                half,
                                e.trim()
                            );
                        }
                    }
                    Err(e) => log::warn!("full tunnel: `ip -6 route` unavailable ({}) ", e),
                }
            }
            if blocked == 2 {
                log::info!(
                    "full tunnel: IPv6 blackholed (qeli tunnels IPv4 only; set \
                     allow_ipv6_leak = true to let IPv6 use the physical interface instead)"
                );
            } else {
                log::warn!(
                    "full tunnel: IPv6 is NOT fully blocked — traffic to IPv6 destinations may \
                     bypass the tunnel. Enable the kill-switch, or disable IPv6 on this host."
                );
            }
        }
    }

    // `include` is the split-tunnel counterpart of the halves above: the operator named
    // exactly which subnets must go through the tunnel, so a route that failed to install
    // is that subnet leaking in the clear. Fatal for the same reason.
    for subnet in &config.include {
        let output = std::process::Command::new("ip")
            .args(["route", "add", subnet, "via", gateway, "dev", ifname])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                anyhow::bail!(
                    "could not route included subnet {} through the tunnel ({} dev {}): {} — \
                     refusing to run, as that subnet would leave unencrypted",
                    subnet,
                    gateway,
                    ifname,
                    stderr.trim()
                );
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
                if o.status.success() {
                    note_created(&["route", "del", subnet]);
                } else {
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

pub fn cleanup_routes(ifname: &str, _server_addr: &str, _exclude: &[String]) -> anyhow::Result<()> {
    // Only the routes this process put on the PHYSICAL interface (server bypass, exclude
    // bypasses, IPv6 blackholes) — see CREATED_ROUTES. Anything that was already there
    // when we started stays; it was not ours to remove.
    for args in take_created() {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = std::process::Command::new("ip").args(&argv).output();
    }
    // The tun device's own routes go with the device, so flushing by interface can only
    // ever touch ours.
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

// ── fault injection: does the routing layer actually fail CLOSED? ────────────
//
// Everything below drives `setup_routes` / `cleanup_routes` with a FAKE `ip` on PATH.
// That is the point: the interesting behaviour here is "we ran a command and interpreted
// its result", and the failures that matter are the ones where the command did NOT work —
// which a healthy machine will not produce on demand. With a shim these tests need no
// root, no TUN and no network, because nothing real is ever configured.
//
// The shim records every invocation, so a test can assert not just the outcome but
// exactly WHICH commands ran. That is how "cleanup removes only what it created" is
// checked — something no amount of end-to-end testing on a healthy box would reveal.
#[cfg(all(test, target_os = "linux"))]
mod fault_injection {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};

    /// `PATH` is process-global, so shimmed tests must not overlap.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Shim {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        old_path: String,
    }

    impl Shim {
        /// `fail_on` — argument-line substrings that make the fake `ip` exit non-zero
        /// with `stderr_text`. Everything else succeeds.
        fn new(tag: &str, fail_on: &[&str], stderr_text: &str) -> Shim {
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-shim-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("case \"$*\" in\n");
            for cond in fail_on {
                script.push_str(&format!(
                    "  *\"{cond}\"*) echo '{stderr_text}' >&2; exit 2;;\n"
                ));
            }
            // `route get` must answer with a gateway and `route show` with a device, or
            // setup_routes cannot get as far as the behaviour under test.
            script.push_str(
                "  *\"route get\"*) echo '1.2.3.4 via 10.0.0.254 dev eth0 src 10.0.0.5'; exit 0;;\n",
            );
            script.push_str("  *\"route show\"*) echo 'shown dev qtest'; exit 0;;\n");
            script.push_str("esac\nexit 0\n");

            let bin = dir.join("ip");
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            // The ownership journal is process-global and deliberately SURVIVES a failed
            // setup (those routes were created and still need removing later). Across
            // tests that means one scenario inherits another's entries, so start clean.
            let _ = take_created();

            let old_path = std::env::var("PATH").unwrap_or_default();
            std::env::set_var("PATH", format!("{}:{}", dir.display(), old_path));
            Shim {
                dir,
                _guard: guard,
                old_path,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Shim {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.old_path);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn full_tunnel() -> ClientRoutingConfig {
        ClientRoutingConfig {
            add_default_gateway: true,
            // The IPv6 leg has its own behaviour; keep these focused on IPv4 routing.
            allow_ipv6_leak: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_failed_full_tunnel_half_refuses_the_connection() {
        // The regression this exists for: losing one /1 half used to be a warn the client
        // carried on from, so half of IPv4 left in the clear while the UI said "full
        // tunnel".
        let _shim = Shim::new(
            "half",
            &["route add 128.0.0.0/1"],
            "RTNETLINK answers: permission denied",
        );
        let err = setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("128.0.0.0/1") && msg.contains("refusing"),
            "a half-installed default route must refuse, got: {msg}"
        );
    }

    #[test]
    fn a_route_that_lies_about_success_is_caught_by_the_fib_check() {
        // iptables-nft taught us a zero exit code is not proof; `ip route add` gets the
        // same distrust. Here every add "succeeds" but the table shows a different device.
        let _shim = Shim::new("fib", &[], "");
        let err = setup_routes(&full_tunnel(), "10.0.0.1", "other0", "1.2.3.4").unwrap_err();
        assert!(
            err.to_string().contains("not in the routing table"),
            "expected the FIB verification to fire, got: {err}"
        );
    }

    #[test]
    fn a_failed_include_subnet_refuses_rather_than_leaking_it() {
        let cfg = ClientRoutingConfig {
            include: vec!["192.0.2.0/24".to_string()],
            ..Default::default()
        };
        let _shim = Shim::new(
            "incl",
            &["route add 192.0.2.0/24"],
            "RTNETLINK answers: network unreachable",
        );
        let err = setup_routes(&cfg, "10.0.0.1", "qtest", "1.2.3.4").unwrap_err();
        assert!(
            err.to_string().contains("192.0.2.0/24"),
            "an include route that did not install must refuse, got: {err}"
        );
    }

    #[test]
    fn a_failed_exclude_is_only_a_warning() {
        // Deliberately NOT fatal: a failed exclude leaves that subnet INSIDE the tunnel,
        // which is fail-closed. This test exists so nobody "tightens" it later.
        let cfg = ClientRoutingConfig {
            exclude: vec!["198.51.100.0/24".to_string()],
            ..Default::default()
        };
        let _shim = Shim::new(
            "excl",
            &["route add 198.51.100.0/24"],
            "RTNETLINK answers: no such device",
        );
        assert!(
            setup_routes(&cfg, "10.0.0.1", "qtest", "1.2.3.4").is_ok(),
            "a failed exclude bypass must not break the connection"
        );
    }

    #[test]
    fn cleanup_removes_the_bypass_route_we_created() {
        let shim = Shim::new("own", &[], "");
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();
        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();
        let calls = shim.calls();
        assert!(
            calls.contains("route del 1.2.3.4"),
            "a bypass route WE added must be removed on cleanup:\n{calls}"
        );
    }

    #[test]
    fn cleanup_leaves_a_pre_existing_route_alone() {
        // Setup treats an existing route as a benign no-op, so "File exists" means the
        // route was someone ELSE's — an operator's static bypass, another VPN's. Cleanup
        // used to delete it anyway, leaving the host worse than it found it.
        let shim = Shim::new(
            "preexist",
            &["route add 1.2.3.4"],
            "RTNETLINK answers: File exists",
        );
        setup_routes(&full_tunnel(), "10.0.0.1", "qtest", "1.2.3.4").unwrap();
        cleanup_routes("qtest", "1.2.3.4", &[]).unwrap();
        let calls = shim.calls();
        assert!(
            !calls.contains("route del 1.2.3.4"),
            "a route that already existed is not ours to delete:\n{calls}"
        );
    }
}
