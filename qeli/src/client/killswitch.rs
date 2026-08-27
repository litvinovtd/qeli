//! Firewall kill-switch (Linux / **`iptables` CLI only** — never `nft` or `ufw`,
//! to keep the whole project on a single firewall backend, same as `server/nat.rs`).
//!
//! While engaged, ALL egress is dropped except: loopback, traffic out the VPN tun
//! device, DHCP (physical-link renew), DNS (so a hostname server can be resolved —
//! see the trade-off below), and traffic to the VPN server's resolved IP(s). So
//! when the tunnel drops, nothing of substance leaks onto the physical interface
//! during the reconnect window — closing the classic "real IP exposed between
//! reconnects" hole.
//!
//! Implemented as a dedicated `QELI_KS` chain in the `filter` table, jumped to from
//! the top of `OUTPUT`; the chain ends in a terminal `DROP`, so it has the effect of
//! a drop policy without touching the host's global `OUTPUT` policy. IPv4 goes
//! through `iptables`, IPv6 through `ip6tables` (the old nftables `inet` table covered
//! both families at once; iptables is per-family, so we program both).
//!
//! Because the modern `iptables-nft` wrapper can return success while silently
//! no-op'ing, we VERIFY every rule with `iptables -C` rather than trusting the exit
//! code (same lesson as `server/nat.rs`).
//!
//! DNS TRADE-OFF: port 53 is allowed so the client can resolve a *hostname* server
//! address (otherwise the very first connect — which re-resolves the name with the
//! drop policy active — would fail). It is allowed **only to the resolvers this host is
//! configured to use**, never to an arbitrary destination: a blanket `--dport 53` rule let
//! every application's queries egress in cleartext on the physical link for as long as the
//! tunnel was down, and to a server of the querier's choosing — the metadata leak this
//! module exists to prevent. Fails CLOSED: with no non-loopback resolver readable, no
//! port-53 rule is installed and reconnects run off the allow-listed server IPs. The
//! residual leak is an application querying those same resolvers; use an IP server address
//! to avoid even that. (Windows and macOS scope this identically.)
//!
//! FAIL-SAFE LIFECYCLE — this is the whole point, read carefully:
//!   * [`engage`] installs the `QELI_KS` chain + OUTPUT jump and is idempotent (it
//!     tears down any existing copy first, then rebuilds). It is installed ONCE,
//!     before the connect loop, and deliberately stays up across every reconnect.
//!   * [`disengage`] removes the chain and is called only on a CLEAN stop
//!     (user disconnect / SIGINT / SIGTERM / loop exit).
//!   * A crashed run (SIGKILL / panic / power loss) leaves the chain in place — the
//!     machine stays locked (no leak) until qeli runs again, which `engage`
//!     replaces it. To unlock without reconnecting:
//!     `sudo iptables -D OUTPUT -j QELI_KS; sudo iptables -F QELI_KS; sudo iptables -X QELI_KS`
//!     (and the same with `ip6tables`).
//!
//! Only meaningful in full-tunnel mode (in split-tunnel the dropped "everything
//! else" is exactly the traffic that is supposed to go direct), so the caller
//! gates on that.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::Command;

/// Dedicated chain (in the `filter` table) holding the kill-switch ruleset.
/// Chain name for THIS instance.
///
/// It used to be one global `QELI_KS`. Every instance therefore built, and tore down,
/// the same chain: starting a second client wiped the first one's rules (its tun and
/// server IP were no longer allow-listed, so its traffic began hitting the DROP), and
/// whichever instance stopped first removed the chain out from under the other, leaving
/// it running with no kill-switch at all and nothing said about it. The tun interface
/// name is already unique per instance — that is what `dev=` is for — so key the chain
/// on it. iptables allows 28 characters; `QELI_KS_` (8) plus an IFNAMSIZ name (≤15) fits.
fn chain_for(tun_if: &str) -> String {
    format!("QELI_KS_{tun_if}")
}

/// The pre-per-instance chain name. Only removed on engage, to clean up after an
/// upgrade from a build that used one shared chain.
const LEGACY_CHAIN: &str = "QELI_KS";

/// Resolve `server_addr:port` to the set of IPs the kill-switch must allow through
/// (so the tunnel can (re)connect). Returns string IPs (v4 and v6).
fn resolve_ips(server_addr: &str, server_port: u16) -> Vec<String> {
    // A bare IP resolves to itself; a hostname resolves via the system resolver
    // (which still works here — we resolve BEFORE engaging the drop policy).
    match (server_addr, server_port).to_socket_addrs() {
        Ok(addrs) => {
            let mut ips: Vec<String> = addrs.map(|sa| sa.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            ips
        }
        Err(_) => Vec::new(),
    }
}

/// Locate an iptables-family binary (`iptables` / `ip6tables`). `None` = not present.
/// Checks the usual sbin locations first (cheap, no exec), then a PATH probe — same
/// approach as `server::nat::iptables_path` (duplicated because the server module is
/// `cfg`-excluded from the client/.so builds).
pub(crate) fn ipt_path(bin: &str) -> Option<String> {
    // Explicit override, searched first: `QELI_IPT_DIR=/opt/sbin`. Useful where the
    // binaries live off the usual paths (a stripped container, a router with its own
    // prefix), and it is also the seam the fault-injection tests use — the absolute-path
    // probe below deliberately ignores PATH, so without this there is no way to stand a
    // stub in front of iptables and check that a rule which fails to install is caught.
    if let Ok(dir) = std::env::var("QELI_IPT_DIR") {
        if !dir.is_empty() {
            let p = format!("{}/{bin}", dir.trim_end_matches('/'));
            if Path::new(&p).exists() {
                return Some(p);
            }
        }
    }
    for dir in ["/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"] {
        let p = format!("{dir}{bin}");
        if Path::new(&p).exists() {
            return Some(p);
        }
    }
    if Command::new(bin)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Some(bin.to_string());
    }
    None
}

pub(crate) fn ipv6_available() -> bool {
    ipt_path("ip6tables").is_some()
}

pub(crate) fn ipt(path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(path).args(args).output()
}

/// Is `<bin> -C <args>` satisfied? The only reliable presence check across the
/// legacy/nft backends — the exit code of `-A`/`-I` lies on a chain the nft wrapper
/// considers incompatible.
pub(crate) fn present(path: &str, args: &[&str]) -> bool {
    ipt(path, args).map(|o| o.status.success()).unwrap_or(false)
}

fn expected_qeli_chain<'a>(args: &'a [&'a str]) -> Option<&'a str> {
    let candidate = args
        .windows(2)
        .find_map(|pair| (pair[0] == "-j").then_some(pair[1]))
        .or_else(|| {
            if args.first() == Some(&"-S") {
                args.get(1).copied()
            } else {
                None
            }
        });
    candidate.filter(|chain| *chain == LEGACY_CHAIN || chain.starts_with("QELI_KS_"))
}

fn absent_check(
    status: &std::process::ExitStatus,
    stderr: &str,
    expected_chain: Option<&str>,
) -> bool {
    if status.code() == Some(1) {
        return true;
    }
    let stderr = stderr.to_ascii_lowercase();
    if stderr.contains("no chain/target/match by that name")
        || stderr.contains("does a matching rule exist")
        || stderr.contains("rule does not exist")
    {
        return true;
    }
    expected_chain.is_some_and(|chain| {
        let chain = chain.to_ascii_lowercase();
        stderr.contains(&chain)
            && ((stderr.contains("couldn't load target")
                && stderr.contains("no such file or directory"))
                // iptables-nft reports a missing jump target with status 2, not the
                // conventional status 1. Scope this phrase to the expected QELI chain so
                // unrelated nft parser/backend failures remain fatal.
                || (stderr.contains("chain") && stderr.contains("does not exist")))
    })
}

/// Presence check for teardown paths, where "absent" and "could not inspect the
/// firewall" must not collapse into the same `false` result.
pub(crate) fn present_checked(path: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = ipt(path, args)
        .map_err(|error| anyhow::anyhow!("cannot run {path} {}: {error}", args.join(" ")))?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if absent_check(&output.status, &stderr, expected_qeli_chain(args)) {
        Ok(false)
    } else {
        anyhow::bail!(
            "{path} {} failed with {}: {}",
            args.join(" "),
            output.status,
            stderr.trim()
        )
    }
}

/// True for a syntactically valid Linux interface name (≤ IFNAMSIZ-1 = 15,
/// `[A-Za-z0-9_-]`). `tun_if` is passed to iptables as a single argv argument (not a
/// shell string), but we still validate it — defence-in-depth (H-3).
pub(crate) fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Does the dedicated chain still exist? Unlike the hot-path helper, this distinguishes
/// a genuinely absent chain from an inspection failure.
fn chain_exists(path: &str, chain: &str) -> anyhow::Result<bool> {
    let output = ipt(path, &["-S", chain])
        .map_err(|error| anyhow::anyhow!("cannot run {path} -S {chain}: {error}"))?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if absent_check(&output.status, &stderr, Some(chain)) {
        Ok(false)
    } else {
        anyhow::bail!(
            "{path} -S {chain} failed with {}: {}",
            output.status,
            stderr.trim()
        )
    }
}

fn teardown_family(path: &str, chain: &str) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Remove the jump(s) first — a chain cannot be deleted while referenced. FORWARD is
    // only ever hooked in gateway mode, but unhook it unconditionally: a crash between
    // engage and disengage must not leave a dangling reference that blocks cleanup.
    for hook in ["OUTPUT", "FORWARD"] {
        for _ in 0..8 {
            match present_checked(path, &["-C", hook, "-j", chain]) {
                Ok(true) => {
                    if let Err(error) = ipt(path, &["-D", hook, "-j", chain]) {
                        errors.push(format!("cannot remove {hook} jump to {chain}: {error}"));
                        break;
                    }
                }
                Ok(false) => break,
                Err(error) => {
                    errors.push(error.to_string());
                    break;
                }
            }
        }
        match present_checked(path, &["-C", hook, "-j", chain]) {
            Ok(true) => errors.push(format!(
                "{path}: {hook} still jumps to {chain} after 8 deletion attempts"
            )),
            Ok(false) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }

    match chain_exists(path, chain) {
        Ok(true) => {
            let _ = ipt(path, &["-F", chain]);
            let _ = ipt(path, &["-X", chain]);
            match chain_exists(path, chain) {
                Ok(true) => errors.push(format!("{path}: chain {chain} still exists")),
                Ok(false) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }
        Ok(false) => {}
        Err(error) => errors.push(error.to_string()),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("firewall teardown failed: {}", errors.join("; "))
    }
}

/// The resolvers this host actually uses, for the kill-switch's port-53 allowance.
///
/// Read BEFORE the tunnel's own DNS override is applied (engage runs ahead of the connect
/// loop), so these are the operator's real upstreams.
///
/// Loopback entries are skipped deliberately: a `127.0.0.53` stub is already reachable via
/// the `-o lo` ACCEPT, and allowing it would grant nothing. What matters in that setup is
/// where systemd-resolved forwards to, and that list lives in its own resolv.conf — which is
/// why it is read first.
/// Is this address a resolver worth opening a hole for? Same rule as the Windows and macOS
/// clients, so the three platforms agree on what counts as an upstream.
///
/// Loopback is excluded because a stub is reachable through the `lo` ACCEPT regardless, and
/// treating it as "we have a resolver" would hide that the real upstreams are unknown — the
/// decision this feeds is precisely "allow port 53 to these" versus the fail-closed "block
/// physical DNS entirely". Link-local, the deprecated `fec0::/10` site-local range and IPv4
/// APIPA are phantoms in the same way: Windows in particular reports `fec0:0:0:ffff::1/2/3`
/// on nearly every IPv6 interface even though nothing routes there.
fn usable_resolver(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        // `is_unicast_link_local` is stable; site-local (fec0::/10) has no stable predicate,
        // so match the prefix directly.
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            !v6.is_unicast_link_local() && (seg & 0xffc0) != 0xfec0
        }
    }
}

fn system_resolvers() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                    if usable_resolver(&ip) {
                        let s = ip.to_string();
                        if !out.contains(&s) {
                            out.push(s);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Build the `QELI_KS` chain on one family and hook it at the top of OUTPUT.
/// `allow_ips` are the server addresses of THIS family to let through.
fn engage_family(
    path: &str,
    tun_if: &str,
    allow_ips: &[String],
    guard_forward: bool,
) -> anyhow::Result<()> {
    let chain = &chain_for(tun_if);
    teardown_family(path, chain).map_err(|error| {
        anyhow::anyhow!("kill-switch: cannot clear the previous {chain} ruleset: {error}")
    })?; // clean slate (leftover from a crash, or OUR own live one)
         // Upgrade path: a build before per-instance chains left a shared `QELI_KS` behind,
         // and nothing else will ever remove it.
    if present_checked(path, &["-C", "OUTPUT", "-j", LEGACY_CHAIN])? {
        log::info!("removing the legacy shared kill-switch chain {LEGACY_CHAIN}");
        teardown_family(path, LEGACY_CHAIN).map_err(|error| {
            anyhow::anyhow!(
                "kill-switch: cannot remove legacy shared chain {LEGACY_CHAIN}: {error}"
            )
        })?;
    }
    let _ = ipt(path, &["-N", chain]); // create chain (ignore "already exists")

    // Append a rule to the chain and confirm it actually landed.
    let add = |rule: &[&str]| -> bool {
        let mut a: Vec<&str> = vec!["-A", chain];
        a.extend_from_slice(rule);
        let _ = ipt(path, &a); // exit code is unreliable — verify below
        let mut c: Vec<&str> = vec!["-C", chain];
        c.extend_from_slice(rule);
        present(path, &c)
    };

    // The ACCEPT rules are as load-bearing as the DROP: their return value used to be
    // discarded, so a chain that failed to allow the tun (or the server address) still
    // got its terminal DROP and its OUTPUT hook — locking the host out of the very
    // tunnel the kill-switch exists to protect, and reporting success. Verify each.
    let mut missing: Vec<String> = Vec::new();
    let mut require = |rule: &[&str]| {
        if !add(rule) {
            missing.push(rule.join(" "));
        }
    };
    require(&["-o", "lo", "-j", "ACCEPT"]);
    require(&["-o", tun_if, "-j", "ACCEPT"]);
    if guard_forward {
        // The same user chain is hooked into FORWARD in router mode. Replies and
        // server-initiated site-to-site traffic enter from the tunnel and leave toward
        // the LAN, so `-o <tun>` alone would drop the return half of every forwarded
        // connection. OUTPUT never has this input interface, therefore the rule is inert
        // on the host-local hook and precise on FORWARD.
        require(&["-i", tun_if, "-j", "ACCEPT"]);
    }
    // DHCP client → server, so the physical lease can renew while locked.
    require(&["-p", "udp", "--dport", "67", "-j", "ACCEPT"]);
    // DNS, so a hostname server can be (re)resolved during a reconnect — but scoped to the
    // resolvers this host actually uses, never `--dport 53` to any destination.
    //
    // The blanket rule let EVERY application's DNS queries egress in cleartext on the
    // physical interface for as long as the tunnel was down: precisely the metadata leak the
    // kill-switch exists to prevent, and wide open to a resolver of the querier's choosing.
    // Windows and macOS were narrowed to the configured resolvers in the client audit; Linux
    // kept the original rule, so the strictest of the three platforms was in fact the
    // leakiest. Fails CLOSED to match them: with no resolver readable no port-53 rule is
    // installed at all, and the reconnect still works off the server IPs allowed below.
    // Residual (accepted, same as the other platforms): an application querying those same
    // resolvers still leaks its own query.
    // Family of THIS pass, taken from the binary's file name rather than a substring of the
    // whole path (a directory could contain a '6' and silently invert the filter).
    let is_v6 = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().starts_with("ip6"))
        .unwrap_or(false);
    let resolvers: Vec<String> = system_resolvers()
        .into_iter()
        .filter(|r| r.parse::<IpAddr>().map(|ip| ip.is_ipv6()) == Ok(is_v6))
        .collect();
    for r in &resolvers {
        require(&[
            "-p",
            "udp",
            "-d",
            r.as_str(),
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ]);
        require(&[
            "-p",
            "tcp",
            "-d",
            r.as_str(),
            "--dport",
            "53",
            "-j",
            "ACCEPT",
        ]);
    }
    if resolvers.is_empty() {
        log::info!(
            "kill-switch ({path}): no non-loopback resolver configured — port 53 stays \
             blocked while the tunnel is down; reconnects use the allow-listed server IP(s)"
        );
    }
    for ip in allow_ips {
        require(&["-d", ip.as_str(), "-j", "ACCEPT"]);
    }
    if !missing.is_empty() {
        let cleanup = teardown_family(path, chain)
            .err()
            .map(|error| format!("; rollback also failed: {error}"))
            .unwrap_or_default();
        anyhow::bail!(
            "kill-switch: could not install {} allow rule(s) in {chain} ({}) — refusing to              arm a chain that would block the tunnel itself{}",
            missing.len(),
            missing.join("; "),
            cleanup
        );
    }
    // Terminal DROP — everything not explicitly allowed above. This is the rule that
    // makes it a kill-switch, so its presence is mandatory.
    if !add(&["-j", "DROP"]) {
        let cleanup = teardown_family(path, chain)
            .err()
            .map(|error| format!("; rollback also failed: {error}"))
            .unwrap_or_default();
        anyhow::bail!("could not install the DROP rule in chain {chain}{cleanup}");
    }

    // Hook the chain at the top of OUTPUT — added LAST, so the chain is already
    // complete the instant it becomes reachable (no partial-block window).
    if !present(path, &["-C", "OUTPUT", "-j", chain]) {
        let _ = ipt(path, &["-I", "OUTPUT", "1", "-j", chain]);
    }
    if !present(path, &["-C", "OUTPUT", "-j", chain]) {
        let cleanup = teardown_family(path, chain)
            .err()
            .map(|error| format!("; rollback also failed: {error}"))
            .unwrap_or_default();
        anyhow::bail!("could not hook chain {chain} into OUTPUT{cleanup}");
    }

    // Gateway mode routes OTHER hosts' traffic, and routed packets never traverse
    // OUTPUT — only FORWARD. So an OUTPUT-only kill-switch protected this host while
    // leaving the LAN behind it unprotected: during a reconnect the tunnel routes are
    // gone, the box falls back to its physical default, and the LAN's traffic egresses
    // in the clear through a chain that never saw it. Hook the same chain into FORWARD,
    // but ONLY when qeli is actually acting as a gateway — on a plain client the box may
    // be routing something unrelated, and hijacking its FORWARD chain is not ours to do.
    if guard_forward {
        if !present(path, &["-C", "FORWARD", "-j", chain]) {
            let _ = ipt(path, &["-I", "FORWARD", "1", "-j", chain]);
        }
        if !present(path, &["-C", "FORWARD", "-j", chain]) {
            let cleanup = teardown_family(path, chain)
                .err()
                .map(|error| format!("; rollback also failed: {error}"))
                .unwrap_or_default();
            anyhow::bail!(
                "could not hook chain {chain} into FORWARD — refusing to run a gateway whose \
                 routed LAN traffic would not be covered by the kill-switch{cleanup}"
            );
        }
    }
    Ok(())
}

/// Best-effort probe: does this host have a globally-scoped IPv6 address on any
/// non-loopback interface? If so, an unprotected IPv6 leg is a real leak rather than
/// harmless-on-a-v4-only-box. Reads `/proc/net/if_inet6`, whose columns are
/// `addr ifindex prefixlen scope flags devname`; the scope is hex and `00` == global.
/// Returns false when the file is absent/unreadable (no evidence of IPv6 → don't block).
fn host_has_global_ipv6() -> bool {
    let Ok(txt) = std::fs::read_to_string("/proc/net/if_inet6") else {
        return false;
    };
    txt.lines().any(|line| {
        let mut cols = line.split_whitespace();
        let scope = cols.nth(3); // 0-based: addr(0) ifindex(1) prefixlen(2) scope(3)
        let devname = cols.nth(1); // remaining: flags(4) devname(5)
        scope == Some("00") && devname != Some("lo")
    })
}

/// Engage the kill-switch: allow only loopback, `tun_if`, DHCP, DNS, and the server
/// IP(s). Idempotent — rebuilds the `QELI_KS` chain on both families. Each family fails
/// closed when the host has usable egress but its firewall cannot be armed, unless the
/// matching `allow_ipv*_leak` escape hatch was explicitly enabled.
pub fn engage(
    server_addr: &str,
    server_port: u16,
    tun_if: &str,
    allow_ipv4_leak: bool,
    allow_ipv6_leak: bool,
    // True when qeli routes a LAN through the tunnel (gateway/forward mode). Routed
    // packets bypass OUTPUT entirely, so the chain must also cover FORWARD.
    guard_forward: bool,
) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("kill-switch: invalid TUN interface name {tun_if:?}");
    }
    let chain = chain_for(tun_if);
    let ips = resolve_ips(server_addr, server_port);
    if ips.is_empty() {
        anyhow::bail!(
            "kill-switch NOT engaged: cannot resolve server '{}' to an IP to allow through \
             (refusing to lock the host out with no path to the server)",
            server_addr
        );
    }

    // Split the allowed server IPs by family — iptables is v4, ip6tables is v6.
    // Re-format from a parsed IpAddr so only a canonical address literal reaches the
    // command line, even if resolution ever yields an odd string (H-3).
    let mut v4: Vec<String> = Vec::new();
    let mut v6: Vec<String> = Vec::new();
    for ip in &ips {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => v4.push(a.to_string()),
            Ok(IpAddr::V6(a)) => v6.push(a.to_string()),
            Err(_) => {}
        }
    }

    // IPv4 and IPv6 are independent. Requiring iptables unconditionally made a genuine
    // IPv6-only host fail before connecting even though it had no IPv4 path to leak over;
    // ignoring a missing tool on a dual-stack host would be the opposite (false security).
    // Protect a family whenever its firewall is available, and otherwise use the same
    // evidence + explicit escape-hatch rule for both families.
    let v4_path = ipt_path("iptables");
    let v4_protected = match v4_path.as_deref() {
        Some(path) => match engage_family(path, tun_if, &v4, guard_forward) {
            Ok(()) => true,
            Err(error) => {
                log::warn!("kill-switch: IPv4 leg not engaged ({error})");
                false
            }
        },
        None => false,
    };
    if !v4_protected {
        if host_has_ipv4_default_route() && !allow_ipv4_leak {
            anyhow::bail!(
                "kill-switch: this host has IPv4 egress but iptables is unavailable or could not be programmed, so IPv4 egress can't be locked — refusing to engage a leaking kill-switch. Install iptables, remove the IPv4 default route, or set allow_ipv4_leak = true to connect and accept the IPv4 leak."
            );
        }
        log::warn!(
            "kill-switch: IPv4 egress is NOT restricted (no IPv4 default route detected, or allow_ipv4_leak is set)"
        );
    }

    // IPv6 leg. Program ip6tables where present; where it's missing (or programming
    // fails) the host would leak over v6 while the switch reports ENGAGED — a false
    // sense of security. So on a host that actually HAS global IPv6, fail closed
    // (matching the v4 "refuse to run unprotected" contract) unless the operator has
    // opted into the leak.
    let v6_protected = match ipt_path("ip6tables") {
        Some(v6_path) => match engage_family(&v6_path, tun_if, &v6, guard_forward) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("kill-switch: IPv6 leg not engaged ({e})");
                false
            }
        },
        None => false,
    };
    if !v6_protected {
        if host_has_global_ipv6() && !allow_ipv6_leak {
            // Roll back the v4 leg we may have armed so a refusal leaves the host exactly
            // as it was — not half-locked to a server the client will never reach.
            if v4_protected {
                if let Some(path) = v4_path.as_deref() {
                    if let Err(rollback) = teardown_family(path, &chain_for(tun_if)) {
                        anyhow::bail!(
                            "kill-switch: IPv6 protection is unavailable and rollback of the \
                             already-installed IPv4 leg also failed: {rollback}. Manual firewall \
                             cleanup may be required before retrying"
                        );
                    }
                }
            }
            anyhow::bail!(
                "kill-switch: this host has global IPv6 but ip6tables is unavailable, so IPv6 \
                 egress can't be locked — refusing to engage a leaking kill-switch. Install \
                 ip6tables, use an IPv4-only host, or set allow_ipv6_leak = true to \
                 connect and accept the IPv6 leak."
            );
        }
        log::warn!(
            "kill-switch: IPv6 egress is NOT restricted (no global IPv6 detected on this host, \
             or allow_ipv6_leak is set)"
        );
    }

    log::warn!(
        "Kill-switch ENGAGED (iptables chain {chain}): egress restricted to lo, {tun_if}, DHCP, \
         DNS and {}. It stays up across reconnects and is removed only on a clean stop; a crash \
         leaves it (no leak) — clear manually with \
         `sudo iptables -D OUTPUT -j {chain}; sudo iptables -F {chain}; sudo iptables -X {chain}` \
         (and the same with ip6tables).",
        ips.join(", ")
    );
    Ok(())
}

/// Best-effort evidence that the host can send ordinary IPv4 traffic. `iproute2` is a
/// required Linux client dependency and the default route is the relevant leak path; a
/// link-local or tunnel-only address without a default is harmless here.
fn host_has_ipv4_default_route() -> bool {
    std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .map(|output| output.status.success() && !output.stdout.is_empty())
        .unwrap_or(false)
}

/// Re-resolve the server hostname and ADD any newly-seen server IP(s) to the live
/// kill-switch chain, inserted before the terminal DROP — WITHOUT tearing the chain
/// down. So a DDNS / round-robin server whose address rotates mid-session can still
/// be reconnected to, with NO leak window (unlike re-calling [`engage`], which
/// briefly removes the OUTPUT jump). Idempotent: never removes the DROP or existing
/// allows, and is a no-op when the chain isn't installed. Inspection or rule-update
/// failures are returned to the caller. Call it before each reconnect attempt.
pub fn refresh_server_ips(server_addr: &str, server_port: u16, tun_if: &str) -> anyhow::Result<()> {
    let chain = chain_for(tun_if);
    let ips = resolve_ips(server_addr, server_port);
    if ips.is_empty() {
        return Ok(());
    }
    let mut errors = Vec::new();
    for (bin, want_v6) in [("iptables", false), ("ip6tables", true)] {
        let Some(path) = ipt_path(bin) else {
            continue;
        };
        // Only touch a chain we actually installed (kill-switch engaged).
        match present_checked(&path, &["-C", "OUTPUT", "-j", chain.as_str()]) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        }
        for ip in &ips {
            let canon = match ip.parse::<IpAddr>() {
                Ok(p) if p.is_ipv6() == want_v6 => p.to_string(),
                _ => continue,
            };
            let rule = ["-d", canon.as_str(), "-j", "ACCEPT"];
            let mut check: Vec<&str> = vec!["-C", chain.as_str()];
            check.extend_from_slice(&rule);
            if present(&path, &check) {
                continue; // already allowed
            }
            // Insert at the top so it precedes the terminal DROP (appending would
            // land AFTER the DROP and never match).
            let mut add: Vec<&str> = vec!["-I", chain.as_str(), "1"];
            add.extend_from_slice(&rule);
            let add_error = ipt(&path, &add).err();
            match present_checked(&path, &check) {
                Ok(true) => {
                    log::info!("kill-switch: allowed new server IP {canon} (address rotated)")
                }
                Ok(false) => errors.push(format!(
                    "{path}: new server IP {canon} was not added{}",
                    add_error
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                )),
                Err(error) => errors.push(error.to_string()),
            }
        }

        // Now withdraw allowances for addresses the server NO LONGER resolves to.
        //
        // Add-only was deliberate ("no leak window"), and the ordering above preserves
        // that: new addresses are inserted BEFORE anything is removed, so there is never
        // a moment where the current server is unreachable. What add-only also did was
        // accumulate — a DDNS or round-robin name on a long-lived client with a flapping
        // link collected every address it had ever seen, each an ACCEPT straight past the
        // tunnel. Those hosts are not ours any more, and with cloud addressing one of them
        // may now belong to somebody else entirely; the chain also grew linearly, and it
        // is consulted per packet. (Audit 2026-07-27, R3.)
        let current: Vec<String> = ips
            .iter()
            .filter_map(|ip| match ip.parse::<IpAddr>() {
                Ok(p) if p.is_ipv6() == want_v6 => Some(p.to_string()),
                _ => None,
            })
            .collect();
        if current.is_empty() {
            // Resolution produced nothing for this family — keep what is there rather
            // than stripping the client's only path to the server.
            continue;
        }
        let stale_addresses = match live_server_allows(&path, &chain) {
            Ok(addresses) => addresses,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        for stale in stale_addresses {
            if current.iter().any(|c| c == &stale) {
                continue;
            }
            let rule = ["-d", stale.as_str(), "-j", "ACCEPT"];
            let mut del: Vec<&str> = vec!["-D", chain.as_str()];
            del.extend_from_slice(&rule);
            let delete_error = ipt(&path, &del).err();
            let mut check: Vec<&str> = vec!["-C", chain.as_str()];
            check.extend_from_slice(&rule);
            match present_checked(&path, &check) {
                Ok(false) => {
                    log::info!("kill-switch: withdrew stale server IP {stale} (no longer resolves)")
                }
                Ok(true) => errors.push(format!(
                    "{path}: stale server IP {stale} remains allowed{}",
                    delete_error
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                )),
                Err(error) => errors.push(error.to_string()),
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "kill-switch server-address refresh failed: {}",
            errors.join("; ")
        )
    }
}

/// Destination addresses currently allowed by plain `-d <ip> -j ACCEPT` rules in `chain`.
///
/// Deliberately narrow: it matches only the shape `refresh_server_ips` and `engage` use
/// for server addresses, so the loopback / tun / DHCP / DNS allowances — which have
/// interface or port matchers — are never returned and can never be withdrawn.
fn live_server_allows(path: &str, chain: &str) -> anyhow::Result<Vec<String>> {
    let out = std::process::Command::new(path)
        .args(["-S", chain])
        .output()
        .map_err(|error| anyhow::anyhow!("cannot inspect {path} chain {chain}: {error}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "cannot inspect {path} chain {chain}: {} ({})",
            String::from_utf8_lossy(&out.stderr).trim(),
            out.status
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let t: Vec<&str> = line.split_whitespace().collect();
            // `-A <chain> -d <cidr> -j ACCEPT` and nothing else.
            if t.len() == 6 && t[0] == "-A" && t[2] == "-d" && t[4] == "-j" && t[5] == "ACCEPT" {
                // iptables -S prints a /32 (or /128) suffix; strip it back to a bare IP.
                let addr = t[3].split('/').next().unwrap_or(t[3]);
                addr.parse::<IpAddr>().ok().map(|p| p.to_string())
            } else {
                None
            }
        })
        .collect())
}

/// Remove the kill-switch chain on both families. Called only on a clean stop. A missing
/// chain is an idempotent success; an inaccessible or still-referenced chain is an error.
pub fn disengage(tun_if: &str) -> anyhow::Result<()> {
    let chain = chain_for(tun_if);
    let mut errors = Vec::new();
    if let Some(p) = ipt_path("iptables") {
        if let Err(error) = teardown_family(&p, &chain) {
            errors.push(error.to_string());
        }
    } else {
        errors.push(format!(
            "kill-switch cleanup: `iptables` is unavailable, so {chain} cannot be removed"
        ));
    }
    if let Some(p) = ipt_path("ip6tables") {
        if let Err(error) = teardown_family(&p, &chain) {
            errors.push(error.to_string());
        }
    }
    if !errors.is_empty() {
        anyhow::bail!("kill-switch cleanup failed: {}", errors.join("; "))
    }
    log::info!("Kill-switch disengaged (iptables chain {chain} removed)");
    Ok(())
}

/// True when the kill-switch should run for this config: explicitly enabled AND
/// full-tunnel (in split-tunnel, dropping all other egress would break the traffic
/// that is meant to go direct).
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.kill_switch
        && (routing.add_default_gateway || routing.mode == "full-tunnel" || routing.mode == "all")
}

// ── fault injection: does the kill-switch refuse to arm when a rule is missing? ──
//
// The module already distrusts exit codes and verifies every rule with `-C`, precisely
// because the iptables-nft wrapper can report success while doing nothing. These tests
// exercise that distrust from the other side: a stub `iptables` whose `-C` fails for one
// chosen rule reproduces exactly "the rule did not land", which is impossible to arrange
// on a working host and is the case where the old code armed a chain anyway.
//
// Reached through `QELI_IPT_DIR`, because `ipt_path` looks at absolute paths before PATH.
#[cfg(all(test, target_os = "linux"))]
mod fault_injection {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};

    /// The override is an env var, i.e. process-global — keep these serialized.
    static SERIAL: Mutex<()> = Mutex::new(());

    struct Ipt {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        had: Option<String>,
    }

    impl Ipt {
        /// `check_fails_on` — substrings of a `-C` invocation that should report the rule
        /// as ABSENT. Everything else (including every `-A`/`-I`) succeeds, so this is
        /// "the command claimed success but the rule is not there".
        fn new(tag: &str, check_fails_on: &[&str]) -> Ipt {
            Self::new_inner(tag, check_fails_on, false)
        }

        fn stuck(tag: &str) -> Ipt {
            Self::new_inner(tag, &[], true)
        }

        fn new_inner(tag: &str, check_fails_on: &[&str], stuck: bool) -> Ipt {
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-ipt-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("state=\"$0.state\"\nout=\"$0.output\"\nfwd=\"$0.forward\"\n");
            script.push_str("if [ \"$1\" = \"-C\" ]; then\n  case \"$*\" in\n");
            for cond in check_fails_on {
                script.push_str(&format!("    *\"{cond}\"*) exit 1;;\n"));
            }
            script.push_str(
                "  esac\n\
                 case \"$*\" in\n\
                   *\"-C OUTPUT \"*) [ -f \"$out\" ] && exit 0 || exit 1;;\n\
                   *\"-C FORWARD \"*) [ -f \"$fwd\" ] && exit 0 || exit 1;;\n\
                 esac\n\
                 [ -f \"$state\" ] && exit 0 || exit 1\n\
                 fi\n\
                 if [ \"$1\" = \"-N\" ]; then touch \"$state\"; exit 0; fi\n\
                 if [ \"$1\" = \"-I\" ]; then\n\
                   [ \"$2\" = \"OUTPUT\" ] && touch \"$out\"\n\
                   [ \"$2\" = \"FORWARD\" ] && touch \"$fwd\"\n\
                   exit 0\n\
                 fi\n",
            );
            if stuck {
                script.push_str("if [ \"$1\" = \"-D\" ] || [ \"$1\" = \"-X\" ]; then exit 0; fi\n");
            } else {
                script.push_str(
                    "if [ \"$1\" = \"-D\" ]; then\n\
                       [ \"$2\" = \"OUTPUT\" ] && rm -f \"$out\"\n\
                       [ \"$2\" = \"FORWARD\" ] && rm -f \"$fwd\"\n\
                       exit 0\n\
                     fi\n\
                     if [ \"$1\" = \"-X\" ]; then rm -f \"$state\" \"$out\" \"$fwd\"; exit 0; fi\n",
                );
            }
            script.push_str(
                "if [ \"$1\" = \"-S\" ]; then\n\
                   [ -f \"$state\" ] && exit 0\n\
                   echo 'iptables: No chain/target/match by that name.' >&2\n\
                   exit 1\n\
                 fi\n\
                 exit 0\n",
            );

            for bin in ["iptables", "ip6tables"] {
                let p = dir.join(bin);
                let mut f = std::fs::File::create(&p).unwrap();
                f.write_all(script.as_bytes()).unwrap();
                drop(f);
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let had = std::env::var("QELI_IPT_DIR").ok();
            std::env::set_var("QELI_IPT_DIR", dir.to_string_lossy().to_string());
            Ipt {
                dir,
                _guard: guard,
                had,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Ipt {
        fn drop(&mut self) {
            match &self.had {
                Some(v) => std::env::set_var("QELI_IPT_DIR", v),
                None => std::env::remove_var("QELI_IPT_DIR"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // An IP literal so `resolve_ips` needs no DNS; allow_ipv6_leak keeps the v6 leg from
    // failing closed on a host that happens to have global IPv6.
    fn engage_test(ipt: &Ipt, tun_if: &str, guard_forward: bool) -> anyhow::Result<()> {
        let path = ipt.dir.join("iptables");
        let path = path.to_string_lossy().into_owned();
        engage_family(&path, tun_if, &["203.0.113.7".to_string()], guard_forward)
    }

    #[test]
    fn iptables_legacy_missing_qeli_target_is_absent_not_fatal() {
        use std::os::unix::process::ExitStatusExt;

        let status = std::process::ExitStatus::from_raw(2 << 8);
        let stderr = "iptables v1.8.9 (legacy): Couldn't load target \
                      'QELI_KS_qtest':No such file or directory";
        assert!(absent_check(&status, stderr, Some("QELI_KS_qtest")));
        assert!(!absent_check(&status, stderr, Some("QELI_KS_other")));

        let nft_stderr = "iptables v1.8.11 (nf_tables): Chain 'QELI_KS_qtest' does not exist";
        assert!(absent_check(&status, nft_stderr, Some("QELI_KS_qtest")));
        assert!(!absent_check(&status, nft_stderr, Some("QELI_KS_other")));

        let unrelated = "iptables v1.8.9 (legacy): Couldn't load match \
                         'owner':No such file or directory";
        assert!(!absent_check(&status, unrelated, Some("QELI_KS_qtest")));
        assert_eq!(
            expected_qeli_chain(&["-C", "OUTPUT", "-j", "QELI_KS_qtest"]),
            Some("QELI_KS_qtest")
        );
        assert_eq!(expected_qeli_chain(&["-C", "OUTPUT", "-j", "MARK"]), None);
    }

    /// The port-53 allowance must be scoped to real upstream resolvers.
    ///
    /// Guards the two properties the narrowing depends on: a loopback stub is NOT returned
    /// (it is already covered by the `-o lo` ACCEPT, and allowing it grants nothing, while
    /// treating it as "we have a resolver" would hide that the real upstreams are unknown),
    /// and systemd-resolved's own resolv.conf — where the actual upstreams live when the stub
    /// is in use — is read as well.
    #[test]
    fn resolver_parsing_skips_loopback_and_dedupes() {
        fn parse(text: &str) -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for line in text.lines() {
                if let Some(rest) = line.trim().strip_prefix("nameserver") {
                    if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                        if !ip.is_loopback() {
                            let s = ip.to_string();
                            if !out.contains(&s) {
                                out.push(s);
                            }
                        }
                    }
                }
            }
            out
        }

        // The systemd-resolved shape: the stub in /etc/resolv.conf carries no useful
        // destination, so nothing is allowed on its account.
        assert!(parse("nameserver 127.0.0.53\noptions edns0\n").is_empty());

        // Ordinary resolv.conf, with a duplicate and a comment.
        assert_eq!(
            parse(
                "# comment\nnameserver 192.168.1.1\nnameserver 1.1.1.1\nnameserver 192.168.1.1\n"
            ),
            vec!["192.168.1.1".to_string(), "1.1.1.1".to_string()]
        );

        // Malformed lines must not become rules.
        assert!(parse("nameserver\nnameserver not-an-ip\nsearch lan\n").is_empty());
    }

    /// Phantom resolver addresses must not count as "we have an upstream".
    ///
    /// Windows lists `fec0:0:0:ffff::1/2/3` on nearly every IPv6 interface; nothing routes
    /// there. Letting them through does not leak, but it flips the decision away from the
    /// fail-closed branch on a host whose only listed servers are phantoms — real queries
    /// stay blocked while the log claims DNS was allowed.
    #[test]
    fn phantom_resolver_addresses_are_not_upstreams() {
        for bad in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "fe80::1",          // link-local
            "fec0:0:0:ffff::1", // Windows' deprecated site-local default
            "fec0:0:0:ffff::3",
            "169.254.1.1", // APIPA
            "224.0.0.251", // multicast
        ] {
            assert!(
                !usable_resolver(&bad.parse::<IpAddr>().unwrap()),
                "{bad} must not be treated as an upstream resolver"
            );
        }
        for good in [
            "192.168.50.1",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "fd00::53",
        ] {
            assert!(
                usable_resolver(&good.parse::<IpAddr>().unwrap()),
                "{good} must be treated as an upstream resolver"
            );
        }
    }

    #[test]
    fn an_allow_rule_that_did_not_install_refuses_to_arm() {
        // The rule that lets traffic OUT THE TUNNEL. Arming a chain without it would cut
        // the host off from the very tunnel the kill-switch exists to protect — and the
        // old code did exactly that, because only the DROP was verified.
        let ipt = Ipt::new("allow", &["-o qtest -j ACCEPT"]);
        let err = engage_test(&ipt, "qtest", false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("allow rule") && msg.contains("refusing"),
            "a missing ACCEPT must refuse to arm, got: {msg}"
        );
        assert!(
            ipt.calls().contains("-X QELI_KS_qtest"),
            "the half-built chain must be torn down again:\n{}",
            ipt.calls()
        );
    }

    #[test]
    fn a_missing_drop_rule_refuses_to_arm() {
        // Without the terminal DROP the chain is not a kill-switch at all.
        let ipt = Ipt::new("drop", &["-j DROP"]);
        let err = engage_test(&ipt, "qtest", false).unwrap_err();
        assert!(
            err.to_string().contains("DROP"),
            "expected the DROP check to fire, got: {err}"
        );
    }

    #[test]
    fn a_chain_that_never_gets_hooked_refuses_to_arm() {
        // A perfect chain nothing jumps to blocks nothing.
        let ipt = Ipt::new("hook", &["-C OUTPUT -j QELI_KS_qtest"]);
        let err = engage_test(&ipt, "qtest", false).unwrap_err();
        assert!(
            err.to_string().contains("OUTPUT"),
            "expected the OUTPUT hook check to fire, got: {err}"
        );
    }

    #[test]
    fn gateway_mode_refuses_when_the_forward_hook_is_missing() {
        // Routed LAN traffic never traverses OUTPUT, so in gateway mode the FORWARD hook
        // is what protects the network behind the client. Missing it is not a warning.
        let ipt = Ipt::new("fwd", &["-C FORWARD -j QELI_KS_qtest"]);
        let err = engage_test(&ipt, "qtest", true).unwrap_err();
        assert!(
            err.to_string().contains("FORWARD"),
            "a gateway whose forwarded traffic is uncovered must refuse, got: {err}"
        );
    }

    #[test]
    fn gateway_mode_allows_both_directions_of_tunnel_forwarding() {
        let ipt = Ipt::new("fwd-bidirectional", &[]);
        engage_test(&ipt, "qtest", true).expect("arm");
        let calls = ipt.calls();
        assert!(
            calls.contains("-A QELI_KS_qtest -o qtest -j ACCEPT")
                && calls.contains("-A QELI_KS_qtest -i qtest -j ACCEPT"),
            "FORWARD protection must pass both LAN→TUN and TUN→LAN halves:\n{calls}"
        );
    }

    #[test]
    fn the_chain_is_named_per_instance_and_forward_is_opt_in() {
        let ipt = Ipt::new("ok", &[]);
        engage_test(&ipt, "qtest", false).expect("a healthy iptables must arm");
        let calls = ipt.calls();
        assert!(
            calls.contains("-N QELI_KS_qtest"),
            "the chain must be keyed on the interface (two instances must not share one):\n{calls}"
        );
        assert!(
            !calls.contains("-I FORWARD"),
            "a plain client must not hijack the host's FORWARD chain:\n{calls}"
        );
    }

    #[test]
    fn disengage_unhooks_both_chains_it_may_have_installed() {
        let ipt = Ipt::new("off", &[]);
        engage_test(&ipt, "qtest", true).expect("arm");
        disengage("qtest").expect("a healthy firewall must be removed");
        let calls = ipt.calls();
        assert!(
            calls.contains("-D OUTPUT -j QELI_KS_qtest")
                && calls.contains("-D FORWARD -j QELI_KS_qtest"),
            "teardown must unhook FORWARD as well — a dangling reference blocks chain \
             deletion after a crash:\n{calls}"
        );
    }

    #[test]
    fn disengage_reports_a_chain_that_remains_installed() {
        let ipt = Ipt::stuck("stuck");
        engage_test(&ipt, "qtest", false).expect("arm");
        let error = disengage("qtest").unwrap_err();
        assert!(
            error.to_string().contains("still"),
            "a lying delete command must not produce clean-stop success: {error}"
        );
    }
}
