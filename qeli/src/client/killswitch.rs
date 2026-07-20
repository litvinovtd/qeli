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

pub(crate) fn ipt(path: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new(path).args(args).output()
}

/// Is `<bin> -C <args>` satisfied? The only reliable presence check across the
/// legacy/nft backends — the exit code of `-A`/`-I` lies on a chain the nft wrapper
/// considers incompatible.
pub(crate) fn present(path: &str, args: &[&str]) -> bool {
    ipt(path, args).map(|o| o.status.success()).unwrap_or(false)
}

/// True for a syntactically valid Linux interface name (≤ IFNAMSIZ-1 = 15,
/// `[A-Za-z0-9_-]`). `tun_if` is passed to iptables as a single argv argument (not a
/// shell string), but we still validate it — defence-in-depth (H-3).
pub(crate) fn valid_ifname(s: &str) -> bool {
    (1..=15).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Tear down our chain on one family (idempotent; ignores an absent chain/jump).
fn teardown_family(path: &str, chain: &str) {
    // Remove the jump(s) first — a chain cannot be deleted while referenced. FORWARD is
    // only ever hooked in gateway mode, but unhook it unconditionally: a crash between
    // engage and disengage must not leave a dangling reference that blocks cleanup.
    for hook in ["OUTPUT", "FORWARD"] {
        for _ in 0..8 {
            if present(path, &["-C", hook, "-j", chain]) {
                let _ = ipt(path, &["-D", hook, "-j", chain]);
            } else {
                break;
            }
        }
    }
    let _ = ipt(path, &["-F", chain]);
    let _ = ipt(path, &["-X", chain]);
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
    teardown_family(path, chain); // clean slate (leftover from a crash, or OUR own live one)
                                  // Upgrade path: a build before per-instance chains left a shared `QELI_KS` behind,
                                  // and nothing else will ever remove it.
    if present(path, &["-C", "OUTPUT", "-j", LEGACY_CHAIN]) {
        log::info!("removing the legacy shared kill-switch chain {LEGACY_CHAIN}");
        teardown_family(path, LEGACY_CHAIN);
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
    // DHCP client → server, so the physical lease can renew while locked.
    require(&["-p", "udp", "--dport", "67", "-j", "ACCEPT"]);
    // DNS, so a hostname server can be (re)resolved during a reconnect (the data
    // plane stays blocked; only DNS metadata can transit — see module docs).
    require(&["-p", "udp", "--dport", "53", "-j", "ACCEPT"]);
    require(&["-p", "tcp", "--dport", "53", "-j", "ACCEPT"]);
    for ip in allow_ips {
        require(&["-d", ip.as_str(), "-j", "ACCEPT"]);
    }
    if !missing.is_empty() {
        teardown_family(path, chain);
        anyhow::bail!(
            "kill-switch: could not install {} allow rule(s) in {chain} ({}) — refusing to              arm a chain that would block the tunnel itself",
            missing.len(),
            missing.join("; ")
        );
    }
    // Terminal DROP — everything not explicitly allowed above. This is the rule that
    // makes it a kill-switch, so its presence is mandatory.
    if !add(&["-j", "DROP"]) {
        teardown_family(path, chain);
        anyhow::bail!("could not install the DROP rule in chain {chain}");
    }

    // Hook the chain at the top of OUTPUT — added LAST, so the chain is already
    // complete the instant it becomes reachable (no partial-block window).
    if !present(path, &["-C", "OUTPUT", "-j", chain]) {
        let _ = ipt(path, &["-I", "OUTPUT", "1", "-j", chain]);
    }
    if !present(path, &["-C", "OUTPUT", "-j", chain]) {
        teardown_family(path, chain);
        anyhow::bail!("could not hook chain {chain} into OUTPUT");
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
            teardown_family(path, chain);
            anyhow::bail!(
                "could not hook chain {chain} into FORWARD — refusing to run a gateway whose \
                 routed LAN traffic would not be covered by the kill-switch"
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
/// IP(s). Idempotent — rebuilds the `QELI_KS` chain on both families. Fails closed on
/// the IPv6 leg (unless `allow_ipv6_leak`) — see the IPv6 block below.
pub fn engage(
    server_addr: &str,
    server_port: u16,
    tun_if: &str,
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

    // IPv4 leg is mandatory: without it we can't promise the real IP stays hidden.
    let v4_path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("kill-switch: `iptables` is not installed (apt install iptables)")
    })?;
    engage_family(&v4_path, tun_if, &v4, guard_forward)?;

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
            // Roll back the v4 leg we just armed so a refusal leaves the host exactly as
            // it was — not half-locked to a server the client will never reach.
            teardown_family(&v4_path, &chain_for(tun_if));
            anyhow::bail!(
                "kill-switch: this host has global IPv6 but ip6tables is unavailable, so IPv6 \
                 egress can't be locked — refusing to engage a leaking kill-switch. Install \
                 ip6tables, use an IPv4-only host, or set routing.allow_ipv6_leak = true to \
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

/// Re-resolve the server hostname and ADD any newly-seen server IP(s) to the live
/// kill-switch chain, inserted before the terminal DROP — WITHOUT tearing the chain
/// down. So a DDNS / round-robin server whose address rotates mid-session can still
/// be reconnected to, with NO leak window (unlike re-calling [`engage`], which
/// briefly removes the OUTPUT jump). Best-effort + idempotent: never removes the
/// DROP or existing allows, and is a no-op when the chain isn't installed. Call it
/// before each reconnect attempt.
pub fn refresh_server_ips(server_addr: &str, server_port: u16, tun_if: &str) {
    let chain = chain_for(tun_if);
    let ips = resolve_ips(server_addr, server_port);
    if ips.is_empty() {
        return;
    }
    for (bin, want_v6) in [("iptables", false), ("ip6tables", true)] {
        let Some(path) = ipt_path(bin) else {
            continue;
        };
        // Only touch a chain we actually installed (kill-switch engaged).
        if !present(&path, &["-C", "OUTPUT", "-j", chain.as_str()]) {
            continue;
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
            let _ = ipt(&path, &add);
            log::info!("kill-switch: allowed new server IP {canon} (address rotated)");
        }
    }
}

/// Remove the kill-switch chain on both families. Called only on a CLEAN stop.
/// Best-effort: a missing chain (never engaged / already cleared) is not an error.
pub fn disengage(tun_if: &str) {
    let chain = chain_for(tun_if);
    if let Some(p) = ipt_path("iptables") {
        teardown_family(&p, &chain);
    }
    if let Some(p) = ipt_path("ip6tables") {
        teardown_family(&p, &chain);
    }
    log::info!("Kill-switch disengaged (iptables chain {chain} removed if present)");
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
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-ipt-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("if [ \"$1\" = \"-C\" ]; then\n  case \"$*\" in\n");
            for cond in check_fails_on {
                script.push_str(&format!("    *\"{cond}\"*) exit 1;;\n"));
            }
            // A `-C` with no match means "present": engage's own teardown-first step then
            // sees a chain to remove, which is the normal idempotent path.
            script.push_str("  esac\n  exit 0\nfi\nexit 0\n");

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
        let _ = ipt;
        engage("203.0.113.7", 443, tun_if, true, guard_forward)
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
        disengage("qtest");
        let calls = ipt.calls();
        assert!(
            calls.contains("-D OUTPUT -j QELI_KS_qtest")
                && calls.contains("-D FORWARD -j QELI_KS_qtest"),
            "teardown must unhook FORWARD as well — a dangling reference blocks chain \
             deletion after a crash:\n{calls}"
        );
    }
}
