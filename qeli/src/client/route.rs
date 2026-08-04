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

/// Did WE install the route this undo-command would remove?
///
/// The journal records the undo command for everything qeli adds, so asking whether an
/// undo is already queued answers "is this route ours". Used before any delete that is
/// not paired with an add of our own. (Audit 2026-07-27, R6.)
fn created_by_us(args: &[&str]) -> bool {
    CREATED_ROUTES
        .lock()
        .map(|g| g.iter().any(|e| e.iter().eq(args.iter().copied())))
        .unwrap_or(false)
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
        } else if let Some(dev) = physical_dev_for(server_addr).filter(|d| d != ifname) {
            // ON-LINK server (no gateway — same subnet, reached directly). The old code
            // pinned the bypass ONLY when a gateway existed, so here it did nothing, and the
            // `0.0.0.0/1`+`128.0.0.0/1` halves below then captured the encrypted carrier to
            // the server INTO the tunnel it carries — an immediate deadlock. Pin a scoped
            // `/32` on the physical dev instead: more specific than the halves, so the
            // carrier stays off the tunnel. (on-link bypass)
            let output = std::process::Command::new("ip")
                .args(["route", "add", server_addr, "dev", &dev, "scope", "link"])
                .output()?;
            if output.status.success() {
                note_created(&["route", "del", server_addr]);
                log::info!("Added on-link bypass route: {} dev {}", server_addr, dev);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "full tunnel: could not pin the on-link server bypass route for {} \
                         dev {}: {} — without it the encrypted path to the server loops into \
                         the tunnel",
                        server_addr,
                        dev,
                        stderr.trim()
                    );
                }
            }
        } else {
            // Neither a gateway nor a usable physical dev: we cannot keep the carrier off
            // the tunnel, so a full tunnel would deadlock. Fail loudly rather than build a
            // tunnel that cannot pass its own carrier traffic.
            anyhow::bail!(
                "full tunnel: could not determine how to reach the server {} on the physical \
                 network (no gateway and no usable interface) — refusing to build a tunnel \
                 whose own encrypted path would loop back into it",
                server_addr
            );
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
                            // Pre-existing — but a route to ::/1 is not necessarily a
                            // BLACKHOLE. Verify before counting it as blocked, or a plain
                            // pre-existing route makes us report IPv6 as blocked while it
                            // leaks out the physical interface.
                            match existing_route_satisfies(true, half, "blackhole") {
                                Some(true) => blocked += 1, // genuinely blocked, not ours to remove
                                Some(false) => log::warn!(
                                    "full tunnel: {} already has a NON-blackhole route — IPv6                                      traffic to it will BYPASS the tunnel",
                                    half
                                ),
                                None => log::warn!(
                                    "full tunnel: {} exists but could not be verified as a                                      blackhole — assuming IPv6 is NOT blocked",
                                    half
                                ),
                            }
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
            // `File exists` was accepted as success — but this branch exists precisely
            // because an un-tunnelled `include` subnet leaves in the clear, and a
            // pre-existing route to it may point anywhere (a LAN gateway, another VPN).
            // Swallowing it defeated the very check whose comment calls it fatal. Verify
            // the existing route uses OUR interface; bail with the same reasoning if not.
            let dev = format!("dev {ifname}");
            match existing_route_satisfies(false, subnet, &dev) {
                Some(true) => {}
                Some(false) => anyhow::bail!(
                    "included subnet {} already has a route that does NOT use {} — it would \
                     leave unencrypted. Remove the conflicting route (`ip route show {}`) or \
                     drop it from `include`.",
                    subnet,
                    ifname,
                    subnet
                ),
                None => anyhow::bail!(
                    "included subnet {} already has a route, but it could not be verified as \
                     going through {} — refusing to run rather than assume it is tunnelled.",
                    subnet,
                    ifname
                ),
            }
        }
    }

    // Exclude: carve specific subnets OUT of the tunnel. Adding a more-specific route
    // via the PHYSICAL gateway beats the `0.0.0.0/1`+`128.0.0.0/1` full-tunnel halves,
    // so exclusion works even in full-tunnel (a plain `route del ... dev tun` is a no-op
    // there — the subnet has no dedicated tun route to remove). Falls back to the delete
    // when the physical gateway is unknown (split-tunnel, where the subnet only exists on
    // tun if `include` added it). Removed on disconnect by cleanup_routes.
    // A kill-switch + exclude combination is fail-closed but silently non-functional: the
    // kill-switch's terminal DROP blocks everything not going out `tun` or to the server, so
    // an excluded subnet is BLACKHOLED rather than routed direct. That is safe (no leak) but
    // confusing — the user set exclude and sees the destination unreachable with no reason.
    // Say so once. (L4)
    if config.kill_switch && !config.exclude.is_empty() {
        log::warn!(
            "exclude + kill_switch: {} excluded subnet(s) will be BLACKHOLED, not sent direct — \
             the kill-switch blocks all non-tunnel egress. Disable the kill-switch if you need \
             these to reach the physical network.",
            config.exclude.len()
        );
    }
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
            // No physical gateway to route around the tunnel, so the best we can do is
            // stop sending this subnet INTO the tunnel — but only if the route through
            // the tunnel is ours.
            //
            // This used to delete unconditionally and journal nothing, which breaks the
            // rule the whole module is built on ("delete only what we created", see the
            // header): with `dev_attach`, the tun is owned by an external manager that may
            // have installed this very route, and `cleanup_routes` restores only what is
            // in the journal — so the route was gone for good once qeli exited. Deleting
            // only routes we added keeps the invariant; anything else is left alone and
            // reported, because silently not-excluding is worse than saying so.
            // (Audit 2026-07-27, R6.)
            if created_by_us(&["route", "del", subnet]) {
                let _ = std::process::Command::new("ip")
                    .args(["route", "del", subnet, "dev", ifname])
                    .output();
            } else {
                log::warn!(
                    "exclude {}: no physical gateway is known and the tunnel route for it \
                     was not installed by qeli — leaving it untouched (deleting a route we \
                     did not create could not be undone on disconnect). Traffic to this \
                     subnet keeps using the tunnel.",
                    subnet
                );
            }
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

        if output.status.success() {
            // Journal the deletion like every OTHER route type. custom_routes were the
            // only ones NOT recorded via note_created: when `via` is a PHYSICAL gateway
            // (a legitimate use — steer a subnet independently of the tunnel), the route
            // resolves onto the physical interface, so cleanup's `ip route flush dev <tun>`
            // never removes it and neither does the (empty) journal — leaving a stale route
            // on the host after disconnect that blackholes the subnet if that gateway later
            // changes. Match on `dest via via` so we delete exactly this route. (M4)
            note_created(&["route", "del", &route.dest, "via", &route.via]);
        } else {
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
                } else {
                    // A route already exists — but pointing where? A pre-existing
                    // `10.0.0.0/8 via <LAN gw>` is the normal case on a router, and
                    // swallowing it made the "routing local networks through the tunnel"
                    // line below a lie for that range.
                    let dev = format!("dev {ifname}");
                    match existing_route_satisfies(false, cidr, &dev) {
                        Some(true) => {}
                        Some(false) => log::warn!(
                            "local net {} already has a route that does NOT use {} — it will                              NOT go through the tunnel",
                            cidr,
                            ifname
                        ),
                        None => log::warn!(
                            "local net {} already has a route that could not be verified — it                              may not go through the tunnel",
                            cidr
                        ),
                    }
                }
            }
        }
    }
    log::info!("Routing local networks (RFC1918 blanket) through the tunnel");
}

/// Does the route the kernel ALREADY has for `cidr` satisfy what we wanted?
///
/// `ip route add` answers `File exists` for any pre-existing route to that prefix — it says
/// nothing about where that route points. Treating it as success (which every call site
/// did) meant a stale `10.0.0.0/8 via 192.168.1.1` counted as "routed through the tunnel",
/// and a plain `::/1` counted as "IPv6 blackholed". Both then logged success while the
/// traffic went straight out the physical interface. So: ask what is actually installed and
/// check it contains `want` (`dev <tun>` for a tunnelled prefix, `blackhole` for a blocked
/// one).
///
/// `None` = could not tell (no `ip`, unparsable output); the caller warns rather than
/// silently assuming either way.
fn existing_route_satisfies(v6: bool, cidr: &str, want: &str) -> Option<bool> {
    let mut args: Vec<&str> = Vec::new();
    if v6 {
        args.push("-6");
    }
    args.extend_from_slice(&["route", "show", cidr]);
    let out = std::process::Command::new("ip").args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return None;
    }
    Some(text.contains(want))
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
        // The SERVER must not get to decide that this client is full-tunnel.
        //
        // `is_valid_cidr` accepts any prefix length 0..=32, and `apply_pushed_routes` runs
        // unconditionally — before the `routing.route_local_networks` check and on both the
        // TCP and UDP paths — so a split-tunnel client (the default: `gateway = false`)
        // applied whatever the server sent. Pushing `0.0.0.0/1` + `128.0.0.0/1` captures all
        // traffic while being MORE SPECIFIC than any physical default route, so it wins
        // regardless of metric; `0.0.0.0/0 metric 0` beats a NetworkManager default at 100.
        // Either way the user asked for split-tunnel and silently got everything routed to
        // the server, with no bypass /32 for the server address (setup_routes only adds that
        // in full-tunnel mode).
        //
        // Pushing a /8 or narrower is the legitimate site-to-site case this feature exists
        // for and stays allowed. A route wide enough to redefine the client's default is a
        // policy decision that belongs to the user, not to the peer.
        // (Audit 2026-08-04.)
        const MIN_PUSHED_PREFIX: u8 = 8;
        let prefix = route
            .cidr
            .rsplit_once('/')
            .and_then(|(_, p)| p.parse::<u8>().ok())
            .unwrap_or(32);
        if prefix < MIN_PUSHED_PREFIX {
            log::warn!(
                "REFUSING pushed route {}: a /{} covers the whole default route, and a server                  may not turn a split-tunnel client into a full-tunnel one. Set                  'routing.mode = full-tunnel' locally if that is what you want.",
                route.cidr,
                prefix
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
                    // LEAK-marked (L3): a pushed route that fails to install means that
                    // subnet is NOT in the tunnel. In split-tunnel there is no kill-switch
                    // (should_engage requires full-tunnel), so it goes out the physical
                    // interface in the clear while auth still reports a working tunnel.
                    // Kept as warn, not fatal: this mirrors OpenVPN's best-effort
                    // `push "route"`, and making it fatal would let a broken/hostile server
                    // config deny the client service. The wording now names it as a leak.
                    log::warn!(
                        "LEAK: pushed route {} via {} NOT applied: {} — traffic to this subnet \
                         will use the PHYSICAL interface UNENCRYPTED. The next hop must be \
                         reachable on the tunnel subnet; drop `gateway=` from the server's \
                         `route =` line to use the tunnel gateway ({}) instead",
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

/// The physical interface `server_addr` is reached on, parsed from the `dev` field of
/// `ip route get`. This is what a gateway-less (ON-LINK) server has instead of a `via`:
/// same subnet as the client, reached directly. (on-link bypass)
fn physical_dev_for(server_addr: &str) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", server_addr])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut saw_dev = false;
    for part in s.split_whitespace() {
        if part == "dev" {
            saw_dev = true;
        } else if saw_dev {
            // Never our own tunnel device — if `ip route get` already resolves the server
            // through the tun (a stale route from a previous run), pinning it there is the
            // exact loop we are trying to prevent.
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
