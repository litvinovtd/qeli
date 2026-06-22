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
//! drop policy active — would fail). The residual leak is only DNS metadata on the
//! physical link while the tunnel is down; the actual data plane (your traffic and
//! real IP to arbitrary sites) stays fully blocked. Use an IP server address to
//! avoid even that.
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
const CHAIN: &str = "QELI_KS";

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
fn ipt_path(bin: &str) -> Option<String> {
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

fn ipt(path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(path).args(args).output()
}

/// Is `<bin> -C <args>` satisfied? The only reliable presence check across the
/// legacy/nft backends — the exit code of `-A`/`-I` lies on a chain the nft wrapper
/// considers incompatible.
fn present(path: &str, args: &[&str]) -> bool {
    ipt(path, args).map(|o| o.status.success()).unwrap_or(false)
}

/// True for a syntactically valid Linux interface name (≤ IFNAMSIZ-1 = 15,
/// `[A-Za-z0-9_-]`). `tun_if` is passed to iptables as a single argv argument (not a
/// shell string), but we still validate it — defence-in-depth (H-3).
fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Tear down our chain on one family (idempotent; ignores an absent chain/jump).
fn teardown_family(path: &str) {
    // Remove the OUTPUT jump(s) first — a chain cannot be deleted while referenced.
    for _ in 0..8 {
        if present(path, &["-C", "OUTPUT", "-j", CHAIN]) {
            let _ = ipt(path, &["-D", "OUTPUT", "-j", CHAIN]);
        } else {
            break;
        }
    }
    let _ = ipt(path, &["-F", CHAIN]);
    let _ = ipt(path, &["-X", CHAIN]);
}

/// Build the `QELI_KS` chain on one family and hook it at the top of OUTPUT.
/// `allow_ips` are the server addresses of THIS family to let through.
fn engage_family(path: &str, tun_if: &str, allow_ips: &[String]) -> anyhow::Result<()> {
    teardown_family(path); // clean slate (leftover from a crash, or a live one)
    let _ = ipt(path, &["-N", CHAIN]); // create chain (ignore "already exists")

    // Append a rule to the chain and confirm it actually landed.
    let add = |rule: &[&str]| -> bool {
        let mut a: Vec<&str> = vec!["-A", CHAIN];
        a.extend_from_slice(rule);
        let _ = ipt(path, &a); // exit code is unreliable — verify below
        let mut c: Vec<&str> = vec!["-C", CHAIN];
        c.extend_from_slice(rule);
        present(path, &c)
    };

    add(&["-o", "lo", "-j", "ACCEPT"]);
    add(&["-o", tun_if, "-j", "ACCEPT"]);
    // DHCP client → server, so the physical lease can renew while locked.
    add(&["-p", "udp", "--dport", "67", "-j", "ACCEPT"]);
    // DNS, so a hostname server can be (re)resolved during a reconnect (the data
    // plane stays blocked; only DNS metadata can transit — see module docs).
    add(&["-p", "udp", "--dport", "53", "-j", "ACCEPT"]);
    add(&["-p", "tcp", "--dport", "53", "-j", "ACCEPT"]);
    for ip in allow_ips {
        add(&["-d", ip.as_str(), "-j", "ACCEPT"]);
    }
    // Terminal DROP — everything not explicitly allowed above. This is the rule that
    // makes it a kill-switch, so its presence is mandatory.
    if !add(&["-j", "DROP"]) {
        teardown_family(path);
        anyhow::bail!("could not install the DROP rule in chain {CHAIN}");
    }

    // Hook the chain at the top of OUTPUT — added LAST, so the chain is already
    // complete the instant it becomes reachable (no partial-block window).
    if !present(path, &["-C", "OUTPUT", "-j", CHAIN]) {
        let _ = ipt(path, &["-I", "OUTPUT", "1", "-j", CHAIN]);
    }
    if !present(path, &["-C", "OUTPUT", "-j", CHAIN]) {
        teardown_family(path);
        anyhow::bail!("could not hook chain {CHAIN} into OUTPUT");
    }
    Ok(())
}

/// Engage the kill-switch: allow only loopback, `tun_if`, DHCP, DNS, and the server
/// IP(s). Idempotent — rebuilds the `QELI_KS` chain on both families.
pub fn engage(server_addr: &str, server_port: u16, tun_if: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("kill-switch: invalid TUN interface name {tun_if:?}");
    }
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

    // IPv4 leg is mandatory: without it we can't promise the real IP stays hidden.
    let v4_path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("kill-switch: `iptables` is not installed (apt install iptables)")
    })?;
    engage_family(&v4_path, tun_if, &v4)?;

    // IPv6 leg is best-effort: block v6 too where `ip6tables` exists; if it is missing
    // we warn (a v6-capable host could otherwise leak over v6 — prefer an IPv4 server
    // address, or install ip6tables).
    match ipt_path("ip6tables") {
        Some(v6_path) => {
            if let Err(e) = engage_family(&v6_path, tun_if, &v6) {
                log::warn!(
                    "kill-switch: IPv6 leg not engaged ({e}); IPv6 egress is NOT restricted"
                );
            }
        }
        None => log::warn!(
            "kill-switch: ip6tables not found — IPv6 egress is NOT restricted \
             (harmless if this host has no IPv6)"
        ),
    }

    log::warn!(
        "Kill-switch ENGAGED (iptables chain {CHAIN}): egress restricted to lo, {tun_if}, DHCP, \
         DNS and {}. It stays up across reconnects and is removed only on a clean stop; a crash \
         leaves it (no leak) — clear manually with \
         `sudo iptables -D OUTPUT -j {CHAIN}; sudo iptables -F {CHAIN}; sudo iptables -X {CHAIN}` \
         (and the same with ip6tables).",
        ips.join(", ")
    );
    Ok(())
}

/// Remove the kill-switch chain on both families. Called only on a CLEAN stop.
/// Best-effort: a missing chain (never engaged / already cleared) is not an error.
pub fn disengage() {
    if let Some(p) = ipt_path("iptables") {
        teardown_family(&p);
    }
    if let Some(p) = ipt_path("ip6tables") {
        teardown_family(&p);
    }
    log::info!("Kill-switch disengaged (iptables chain {CHAIN} removed if present)");
}

/// True when the kill-switch should run for this config: explicitly enabled AND
/// full-tunnel (in split-tunnel, dropping all other egress would break the traffic
/// that is meant to go direct).
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.kill_switch
        && (routing.add_default_gateway || routing.mode == "full-tunnel" || routing.mode == "all")
}
