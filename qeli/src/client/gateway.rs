//! Gateway / router NAT (Linux / **`iptables` CLI only**, same backend as
//! `server/nat.rs` and the kill-switch).
//!
//! When `routing.gateway_nat = true`, a client acting as a router programs the
//! firewall so a LAN *behind* it reaches the internet through the tunnel, without
//! any manual `iptables`:
//!   * `net.ipv4.ip_forward = 1` (+ relaxed `rp_filter` for the asymmetric
//!     LAN↔tun path);
//!   * `MASQUERADE` everything (or just `lan_subnet`) out the tun device — so the
//!     LAN's private source becomes the tunnel IP the server's own NAT understands;
//!   * a `FORWARD` accept both ways and a TCP **MSS-clamp** (without it the pings
//!     pass but TCP/HTTPS stalls — the tunnel MTU is below 1500).
//!
//! All rules carry a `qeli-gw-nat` comment, are verified with `iptables -C`
//! (the `iptables-nft` wrapper lies via exit codes — same lesson as the
//! kill-switch and `server/nat.rs`), and are idempotent.
//!
//! LIFECYCLE: the active IPv4/IPv6 halves are installed after the authenticated
//! NetworkPlan creates the TUN and are re-verified on reconnect (the rules are by
//! interface name, so a recreated `tun` can reuse them). [`disengage`] removes them on
//! a clean stop. A crash leaves them in place (fail-safe) — clear manually with the
//! commands logged on engage.

use super::killswitch::{ipt, ipt_path, present, present_checked, valid_ifname};

/// Comment tag on every rule we own, so teardown removes exactly ours.
const TAG: &str = "qeli-gw-nat";

/// Best-effort write to a `/proc/sys` knob. Returns whether the write succeeded
/// (a missing/read-only path in a restricted container yields `false`). Callers verify
/// load-bearing forwarding knobs and fail closed when their effective value is wrong.
fn write_sysctl_raw(path: &str, val: &str) -> bool {
    std::fs::write(path, val).is_ok()
}

fn set_sysctl(path: &str, val: &str) -> bool {
    // A read-only container may already have the required value. In that case
    // no write (and no later restoration) is necessary.
    if std::fs::read_to_string(path).is_ok_and(|current| current.trim() == val) {
        return true;
    }
    // Record the host's PRIOR value before overwriting it. Doing this inside the writer
    // makes the ordering structural: the previous code snapshotted separately, after the
    // writes had already happened, so it captured our own values and `disengage` then
    // "restored" ip_forward=1 / rp_filter=0 — permanently turning a workstation into a
    // router with anti-spoofing disabled. With the snapshot bound to the write, that
    // mistake is no longer expressible.
    remember_prior(path);
    std::fs::write(path, val).is_ok()
}

/// First-write-wins snapshot of one knob. Called only from [`set_sysctl`]; a reconnect
/// re-enters `engage` and must NOT overwrite the pristine value with our own.
fn remember_prior(path: &str) {
    let Ok(current) = std::fs::read_to_string(path) else {
        return; // knob absent (container / older kernel) — nothing to restore later
    };
    let mut g = PRIOR_SYSCTLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let prior = g.get_or_insert_with(Vec::new);
    if !prior.iter().any(|(p, _)| p == path) {
        prior.push((path.to_string(), current.trim().to_string()));
    }
}

/// Should the gateway firewall run for this config? True for NAT (`gateway_nat`) OR
/// pure L3 forwarding (`forward`, #13). [`engage`]'s `masquerade` arg picks which.
pub fn should_engage(routing: &crate::config::client::ClientRoutingConfig) -> bool {
    routing.gateway_nat || routing.forward
}

pub fn ipv6_available() -> bool {
    ipt_path("ip6tables").is_some()
}

// ── exit-node (this client is an internet EXIT for other tunnel clients) ──────
//
// The MIRROR of `gateway_nat`. gateway_nat masquerades a LAN *behind* this client OUT
// THE TUN (into the tunnel); exit_node masquerades traffic that arrived FROM the tunnel
// OUT THE PHYSICAL WAN (into this host's own internet). Chain:
//   consumer client --tunnel--> server --(client_to_client)--> THIS client --WAN--> net
// so remote clients reach the internet under THIS host's public IP (e.g. a grey/NAT'd
// residential line). The server side of the chain is `client_to_client` on the profile
// plus the exit user's `client_subnet` (0.0.0.0/0) — see the server config; this module
// is only the last hop's forward+NAT.
//
// Scoping is by PACKET MARK, not by source subnet: the pool CIDR is not known until
// after auth, but exit rules install as soon as the authenticated NetworkPlan creates the
// TUN. We mark
// packets forwarded tun->wan in mangle/FORWARD and MASQUERADE only those in
// nat/POSTROUTING — so locally-generated traffic (OUTPUT->POSTROUTING, never marked) is
// left alone, and no pool knowledge is needed. The nfmark persists FORWARD->POSTROUTING
// on the same skb. Masked (`0x51/0x51`) so it coexists with any other fwmark user.
const EXIT_TAG: &str = "qeli-exit-node";
const EXIT_MARK: &str = "0x51/0x51";

/// Every WAN used across reconnects. A physical-path change can select a new interface
/// while tagged rules on the previous one remain; remembering only the latest leaked them.
static EXIT_WANS_V4: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static EXIT_WANS_V6: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn remember_exit_wan(store: &std::sync::Mutex<Vec<String>>, wan: &str) {
    let mut wans = store.lock().unwrap_or_else(|error| error.into_inner());
    if !wans.iter().any(|existing| existing == wan) {
        wans.push(wan.to_string());
    }
}

/// Extract the token following `dev` in an `ip route` line.
fn dev_token(s: &str) -> Option<String> {
    let toks: Vec<&str> = s.split_whitespace().collect();
    toks.iter()
        .position(|&t| t == "dev")
        .and_then(|i| toks.get(i + 1))
        .map(|s| s.to_string())
}

/// Detect the WAN (default-route) interface. `None` if there is no default route — an
/// exit node with no internet path has nothing to share.
///
/// Asks the ROUTING TABLE for the default route first, and only falls back to probing a
/// well-known address. The probe alone was wrong on any host that routes that specific
/// address differently — a Pi-hole or corporate resolver at 1.1.1.1 reached over a
/// management interface, or a blackhole entry for it. `MASQUERADE` and the `MARK` rule
/// were then installed on the WRONG interface: tunnel traffic left with a private source
/// address, the return path was a black hole, and the log still said "Exit-node engaged".
/// (Audit 2026-07-27, R4.)
fn detect_wan() -> Option<String> {
    // 1. The default route itself. `ip route show default` prints e.g.
    //    "default via 10.0.0.1 dev eth0 proto dhcp metric 100"; with several defaults the
    //    first line is the lowest-metric one, which is what the kernel would pick.
    if let Ok(out) = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(dev) = s.lines().find_map(dev_token) {
                return Some(dev);
            }
        }
    }
    // 2. Fallback: ask the kernel which interface it would use for a public address.
    //    Kept because it also resolves policy-routing setups that `show default` misses.
    let out = std::process::Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // "1.1.1.1 via 10.0.0.1 dev eth0 src ..." — the token after "dev".
    dev_token(&String::from_utf8_lossy(&out.stdout))
}

/// IPv6 counterpart of [`detect_wan`]. The WAN may differ by family, so reusing the
/// IPv4 interface silently breaks multi-uplink and IPv6-over-a-different-provider hosts.
fn detect_wan_ipv6() -> Option<String> {
    if let Ok(out) = std::process::Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(device) = text.lines().find_map(dev_token) {
                return Some(device);
            }
        }
    }
    let out = std::process::Command::new("ip")
        .args(["-6", "route", "get", "2606:4700:4700::1111"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    dev_token(&String::from_utf8_lossy(&out.stdout))
}

fn policy_output_accepts_forward(output: &str) -> bool {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    lines.next().is_some_and(|line| {
        line.split_whitespace().collect::<Vec<_>>().as_slice() == ["-P", "FORWARD", "ACCEPT"]
    }) && lines.next().is_none()
}

/// A missing explicit qeli accept is safe only when the built-in FORWARD chain is empty and
/// accepts unmatched packets. An earlier explicit DROP/jump makes default ACCEPT insufficient.
/// Previously every router path merely warned and returned
/// success even under `-P FORWARD DROP`, so the authenticated NetworkPlan was ACKed while
/// all forwarded traffic was deterministically black-holed.
fn forward_policy_accepts(path: &str) -> bool {
    ipt(path, &["-t", "filter", "-S", "FORWARD"])
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            policy_output_accepts_forward(&String::from_utf8_lossy(&output.stdout))
        })
}

fn forward_insert_position(kill_switch_hooked: bool) -> &'static str {
    if kill_switch_hooked {
        "2"
    } else {
        "1"
    }
}

fn policy_output_has_first_forward_jump(output: &str, target: &str) -> bool {
    output
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.starts_with(&["-A", "FORWARD"]))
        .is_some_and(|fields| fields.as_slice() == ["-A", "FORWARD", "-j", target])
}

fn kill_switch_hook_is_first(path: &str, chain: &str) -> bool {
    ipt(path, &["-t", "filter", "-S", "FORWARD"])
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            policy_output_has_first_forward_jump(&String::from_utf8_lossy(&output.stdout), chain)
        })
}

/// Install one managed rule and verify it. Narrow filter/FORWARD permits must precede host
/// DROP rules, but an active qeli kill-switch jump remains first so reconnect traffic still
/// fails closed. NAT and mangle rules retain append semantics.
fn ensure_rule(path: &str, tun_if: &str, table: &str, chain: &str, rule: &[&str]) -> bool {
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    if !present(path, &check) {
        let insert = table == "filter" && chain == "FORWARD";
        let mut add: Vec<&str> = vec!["-t", table, if insert { "-I" } else { "-A" }, chain];
        let kill_switch_chain = format!("QELI_KS_{tun_if}");
        if insert {
            let hooked = present(path, &["-C", "FORWARD", "-j", kill_switch_chain.as_str()]);
            if hooked && !kill_switch_hook_is_first(path, &kill_switch_chain) {
                log::error!(
                    "qeli kill-switch jump {kill_switch_chain} is not the first FORWARD rule; \
                     refusing to insert a router permit ahead of it"
                );
                return false;
            }
            add.push(forward_insert_position(hooked));
        }
        add.extend_from_slice(rule);
        let _ = ipt(path, &add);
    }
    present(path, &check)
}

fn exit_mark_rule<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        tun_if,
        "-o",
        wan_if,
        "-j",
        "MARK",
        "--set-xmark",
        EXIT_MARK,
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_masq_rule(wan_if: &str) -> Vec<&str> {
    vec![
        "-o",
        wan_if,
        "-m",
        "mark",
        "--mark",
        EXIT_MARK,
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_fwd_out<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        tun_if,
        "-o",
        wan_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

fn exit_fwd_in<'a>(tun_if: &'a str, wan_if: &'a str) -> Vec<&'a str> {
    vec![
        "-i",
        wan_if,
        "-o",
        tun_if,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

/// MSS-clamp SYNs entering the small-MTU tunnel (the SYN-ACK returning to the consumer).
/// The consumer's own forward SYN already carries a small MSS from its own tun clamp, so
/// this side covers the return leg — without it TCP/HTTPS through the exit stalls.
fn exit_mss(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

/// Program this host as an internet exit for other tunnel clients: `ip_forward`, a
/// MASQUERADE of tun-forwarded traffic out the WAN, a FORWARD accept both ways, and an
/// MSS-clamp. Idempotent; installs by interface name so it survives reconnects (rules
/// stay while the tun is recreated), and is removed on a clean stop by [`disengage_exit`].
/// Relax `rp_filter` on the tunnel interface, once it EXISTS.
///
/// Historically `engage` / `engage_exit` ran before the connect loop, i.e. before
/// `setup_tunnel` created the TUN — so their per-interface write to
/// `/proc/sys/net/ipv4/conf/<tun>/rp_filter` hit a path that did not exist yet,
/// `remember_prior` bailed on the read, the write failed and `set_sysctl` returned false
/// into a discarded result. The knob was therefore never applied.
///
/// That matters because the kernel evaluates reverse-path filtering as
/// `max(conf/all, conf/<incoming-iface>)`: setting `conf/all` to 0 does not help while
/// the tun inherits `conf/default` = 1, which is the norm on many distributions. Strict
/// RPF on the tun then drops exactly the asymmetric paths gateway-NAT and exit-node
/// exist to carry, while the log cheerfully reported the feature engaged.
///
/// Called from `setup_tunnel` after the interface is up, on every connect.
/// (Audit 2026-07-27, R1.)
pub fn apply_tun_rp_filter(tun_if: &str) {
    if !set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0") {
        log::warn!(
            "could not relax rp_filter on {tun_if} — asymmetric paths (gateway-NAT /              exit-node) may be dropped by reverse-path filtering"
        );
    }
}

pub fn engage_exit(tun_if: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node: invalid TUN interface name {tun_if:?}");
    }
    let wan = detect_wan().ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node: no default route found — cannot determine the WAN interface to NAT \
             out of. An exit node needs its own working internet path to share."
        )
    })?;
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node: detected WAN interface name {wan:?} is invalid");
    }
    // Publish the exact interface before the first fallible/mutating step. If a
    // later rule or sysctl fails, the caller's rollback must not depend on the
    // default route still being detectable at teardown time.
    *EXIT_WAN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(wan.clone());
    let path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("exit-node: `iptables` is not installed (apt install iptables)")
    })?;

    // ip_forward is load-bearing (same as gateway_nat); rp_filter relaxed for the
    // asymmetric tun<->wan path. Each snapshots its prior value (remember_prior) so
    // disengage restores it — these are HOST-wide knobs, not ours to leave changed.
    let forwarding_path = "/proc/sys/net/ipv4/ip_forward";
    let forwarding_enabled = matches!(
        std::fs::read_to_string(forwarding_path),
        Ok(value) if value.trim() == "1"
    ) || (set_sysctl(forwarding_path, "1")
        && matches!(
            std::fs::read_to_string(forwarding_path),
            Ok(value) if value.trim() == "1"
        ));
    if !forwarding_enabled {
        anyhow::bail!(
            "exit-node: could not enable net.ipv4.ip_forward; refusing to advertise a black-holed IPv4 exit"
        );
    }
    set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{wan}/rp_filter"), "0");

    // Record the target before the first stateful rule is attempted. An iptables failure can
    // leave the MARK rule installed while the later MASQUERADE verification fails; teardown
    // must still know which WAN that partial rule names, including after a roaming event.
    remember_exit_wan(&EXIT_WANS_V4, &wan);

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(&path, tun_if, table, chain, rule)
    };

    // MARK + MASQUERADE are both essential — without either, tunnel traffic reaches the
    // WAN with a private source and the return path is black-holed.
    if !ensure("mangle", "FORWARD", &exit_mark_rule(tun_if, &wan)) {
        anyhow::bail!("exit-node: could not install the tun->wan MARK rule (mangle FORWARD)");
    }
    if !ensure("nat", "POSTROUTING", &exit_masq_rule(&wan)) {
        anyhow::bail!("exit-node: could not install MASQUERADE out {wan} (nat POSTROUTING)");
    }
    // FORWARD accepts are conditional — only an empty chain with policy ACCEPT makes them
    // redundant; on iptables-nft hosts the legacy filter chain can be incompatible.
    let fwd_ok = ensure("filter", "FORWARD", &exit_fwd_out(tun_if, &wan))
        & ensure("filter", "FORWARD", &exit_fwd_in(tun_if, &wan));
    let mss_ok = ensure("mangle", "FORWARD", &exit_mss(tun_if));

    if !fwd_ok {
        if !forward_policy_accepts(&path) {
            anyhow::bail!(
                "exit-node: FORWARD accept rules are absent and the chain is not empty/ACCEPT"
            );
        }
        log::warn!(
            "exit-node: FORWARD accept rules not installed (legacy/nft filter conflict?) — \
             relying on an empty FORWARD chain with policy ACCEPT. If you tighten it, permit \
             {tun_if}<->{wan} yourself."
        );
    }
    if !mss_ok {
        log::warn!(
            "exit-node: TCP MSS clamp could not be verified; correct Path-MTU Discovery is \
             required for forwarded TCP through {tun_if}"
        );
    }
    log::warn!(
        "Exit-node engaged: MASQUERADE tunnel traffic out {wan} (+forward +mss-clamp, \
         ip_forward=1). Remote clients now reach the internet under THIS host's IP. The \
         server must set client_to_client + this user's client_subnet = 0.0.0.0/0. Stays up \
         across reconnects, removed on a clean stop; a crash leaves it — clear rules tagged \
         `{EXIT_TAG}`."
    );
    Ok(())
}

/// Add the IPv6 half of an exit node after authentication negotiated an IPv6 address.
/// This is deliberately separate from [`engage_exit`]: IPv4 and IPv6 may use different
/// WAN interfaces, and an `ipv6 = auto` client must not require `ip6tables` when the
/// server ultimately assigns IPv4 only.
pub fn engage_exit_ipv6(tun_if: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node IPv6: invalid TUN interface name {tun_if:?}");
    }
    let wan = detect_wan_ipv6().ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6: no IPv6 default route found — cannot determine the IPv6 WAN"
        )
    })?;
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node IPv6: detected WAN interface name {wan:?} is invalid");
    }
    let path = ipt_path("ip6tables").ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6 requires `ip6tables`; refusing a negotiated IPv6 plan that would black-hole forwarded traffic"
        )
    })?;

    // Enabling IPv6 forwarding normally disables acceptance of Router Advertisements.
    // Preserve the physical WAN's RA-derived default by selecting router+host mode before
    // the host-wide switch, exactly as the IPv6 gateway path does.
    set_sysctl(&format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"), "2");
    let forwarding_path = "/proc/sys/net/ipv6/conf/all/forwarding";
    let forwarding_enabled = matches!(
        std::fs::read_to_string(forwarding_path),
        Ok(value) if value.trim() == "1"
    ) || (set_sysctl(forwarding_path, "1")
        && matches!(
            std::fs::read_to_string(forwarding_path),
            Ok(value) if value.trim() == "1"
        ));
    if !forwarding_enabled {
        anyhow::bail!(
            "exit-node IPv6: could not enable net.ipv6.conf.all.forwarding; refusing a black-holed IPv6 exit"
        );
    }
    // Forwarding can invalidate an RA-learned default unless accept_ra=2 actually took
    // effect. Re-resolve after the sysctl transition and program the interface the kernel
    // will really use, rather than claiming success with a stale pre-transition choice.
    let wan = detect_wan_ipv6().ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6: the IPv6 default route disappeared after enabling forwarding (check accept_ra=2)"
        )
    })?;
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node IPv6: post-forwarding WAN name {wan:?} is invalid");
    }
    set_sysctl(&format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"), "2");

    // See the IPv4 path above: remember the WAN before a partially successful rule batch
    // can return an error, otherwise a subsequent path change makes that batch unreachable
    // to clean teardown.
    remember_exit_wan(&EXIT_WANS_V6, &wan);

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(&path, tun_if, table, chain, rule)
    };

    if !ensure("mangle", "FORWARD", &exit_mark_rule(tun_if, &wan)) {
        anyhow::bail!("exit-node IPv6: could not install the tun->WAN MARK rule");
    }
    if !ensure("nat", "POSTROUTING", &exit_masq_rule(&wan)) {
        anyhow::bail!("exit-node IPv6: could not install NAT66 MASQUERADE out {wan}");
    }
    let forward_ok = ensure("filter", "FORWARD", &exit_fwd_out(tun_if, &wan))
        & ensure("filter", "FORWARD", &exit_fwd_in(tun_if, &wan));
    let mss_ok = ensure("mangle", "FORWARD", &exit_mss(tun_if));
    if !forward_ok {
        if !forward_policy_accepts(&path) {
            anyhow::bail!(
                "exit-node IPv6: FORWARD rules are absent and the chain is not empty/ACCEPT"
            );
        }
        log::warn!(
            "exit-node IPv6: FORWARD rules could not be verified; relying on an empty FORWARD chain with policy ACCEPT for {tun_if}<->{wan}"
        );
    }
    if !mss_ok {
        log::warn!(
            "exit-node IPv6: TCP MSS clamp could not be installed; ICMPv6 Packet Too Big must work along the complete path"
        );
    }
    log::warn!(
        "Exit-node IPv6 engaged: NAT66 tunnel traffic out {wan} (+forward, forwarding=1). \
         The server-side exit user also needs client_subnet = ::/0."
    );
    Ok(())
}

/// Remove every `qeli-exit-node` rule. Best-effort; a missing rule is not an error.
fn remove_exit_rules(tun_if: &str) {
    let remove_family = |binary: &str, wans: Vec<String>| {
        let Some(path) = ipt_path(binary) else {
            return;
        };
        if wans.is_empty() {
            log::warn!(
                "exit-node: {binary} WAN interface unknown at teardown — leftover rules tagged `{EXIT_TAG}` may remain"
            );
            return;
        }
        let drop_rule = |table: &str, chain: &str, rule: &[&str]| {
            let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
            check.extend_from_slice(rule);
            for _ in 0..8 {
                if present(&path, &check) {
                    let mut delete: Vec<&str> = vec!["-t", table, "-D", chain];
                    delete.extend_from_slice(rule);
                    let _ = ipt(&path, &delete);
                } else {
                    break;
                }
            }
        };
        for wan in wans {
            drop_rule("mangle", "FORWARD", &exit_mark_rule(tun_if, &wan));
            drop_rule("nat", "POSTROUTING", &exit_masq_rule(&wan));
            drop_rule("filter", "FORWARD", &exit_fwd_out(tun_if, &wan));
            drop_rule("filter", "FORWARD", &exit_fwd_in(tun_if, &wan));
            // WAN-independent; the first pass drains every tagged copy.
            drop_rule("mangle", "FORWARD", &exit_mss(tun_if));
            log::info!("Exit-node {binary} rules disengaged (WAN {wan})");
        }
        anyhow::bail!(
            "exit-node: WAN interface unknown at teardown — rules tagged `{EXIT_TAG}` may remain{}",
            if errors.is_empty() {
                String::new()
            } else {
                format!("; {}", errors.join("; "))
            }
        );
    };

    let mut wans_v4 = std::mem::take(
        &mut *EXIT_WANS_V4
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    );
    let mut wans_v6 = std::mem::take(
        &mut *EXIT_WANS_V6
            .lock()
            .unwrap_or_else(|error| error.into_inner()),
    );
    if wans_v4.is_empty() {
        wans_v4.extend(detect_wan());
    }
    if wans_v6.is_empty() {
        wans_v6.extend(detect_wan_ipv6());
    }
    remove_family("iptables", wans_v4);
    remove_family("ip6tables", wans_v6);
}

pub fn disengage_exit(tun_if: &str) {
    remove_exit_rules(tun_if);
    restore_sysctls(tun_if);
}

/// The MASQUERADE rule body (optionally restricted to a source subnet), tagged.
fn masq_rule<'a>(tun_if: &'a str, lan_subnet: &'a str) -> Vec<&'a str> {
    let mut r: Vec<&str> = Vec::new();
    if !lan_subnet.is_empty() {
        r.extend_from_slice(&["-s", lan_subnet]);
    }
    r.extend_from_slice(&[
        "-o",
        tun_if,
        "-j",
        "MASQUERADE",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]);
    r
}

fn fwd_out(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

fn fwd_in(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

/// Unrestricted inbound FORWARD accept (routing mode, #13): unlike [`fwd_in`], NEW
/// connections from the far side INTO the LAN are permitted — site-to-site is bidirectional,
/// there is no NAT state to gate on.
fn fwd_in_open(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-j",
        "ACCEPT",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

fn mss(tun_if: &str) -> Vec<&str> {
    vec![
        "-o",
        tun_if,
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--clamp-mss-to-pmtu",
        "-m",
        "comment",
        "--comment",
        TAG,
    ]
}

/// Program `ip_forward` + a FORWARD accept + MSS-clamp so a LAN behind the client is
/// reachable through `tun_if`. With `masquerade = true` (`gateway_nat`) it also MASQUERADEs
/// the LAN out the tun (internet egress); with `masquerade = false` (`forward`, #13) there is
/// NO NAT — real source IPs are preserved (site-to-site routing) and the inbound accept is
/// unrestricted so the far side can initiate to the LAN. Idempotent. Empty `lan_subnet`
/// masquerades everything leaving the tun.
pub fn engage(tun_if: &str, lan_subnet: &str, masquerade: bool) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway-nat: invalid TUN interface name {tun_if:?}");
    }
    let path = ipt_path("iptables").ok_or_else(|| {
        anyhow::anyhow!("gateway-nat: `iptables` is not installed (apt install iptables)")
    })?;

    // Forwarding + relaxed reverse-path filter (the LAN↔tun path is asymmetric).
    // Verify the effective value: accepting a firewall plan while forwarding remains off
    // advertises a working router but deterministically black-holes every LAN packet.
    let forwarding_path = "/proc/sys/net/ipv4/ip_forward";
    let forwarding_enabled = matches!(
        std::fs::read_to_string(forwarding_path),
        Ok(value) if value.trim() == "1"
    ) || (set_sysctl(forwarding_path, "1")
        && matches!(
            std::fs::read_to_string(forwarding_path),
            Ok(value) if value.trim() == "1"
        ));
    if !forwarding_enabled {
        anyhow::bail!(
            "gateway-nat: could not enable net.ipv4.ip_forward; refusing a router plan that would black-hole LAN traffic"
        );
    }
    // rp_filter stays best-effort (relaxing it only avoids drops on the asymmetric path).
    set_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
    set_sysctl(&format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"), "0");
    // (Each set_sysctl snapshots the prior value itself — see remember_prior. These are
    // HOST-wide knobs: leaving ip_forward on turns a workstation into a router after the
    // VPN stops, and a relaxed rp_filter keeps an anti-spoofing check disabled — neither
    // is ours to change permanently.)

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(&path, tun_if, table, chain, rule)
    };

    // MASQUERADE only in NAT mode (essential there — the LAN can't reach the internet
    // without it). Routing mode (#13) preserves real source IPs, so no MASQUERADE.
    if masquerade && !ensure("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet)) {
        anyhow::bail!("gateway-nat: could not install MASQUERADE on {tun_if}");
    }
    // FORWARD accept is conditional: on `iptables-nft` hosts the legacy `filter` FORWARD
    // chain can be incompatible (same as `server/nat.rs`); only an empty chain whose policy
    // is ACCEPT makes the rules redundant. Inbound is ESTABLISHED-only under NAT
    // (return traffic) but UNRESTRICTED for routing (the far side may initiate to the LAN).
    let fwd_ok = ensure("filter", "FORWARD", &fwd_out(tun_if))
        & if masquerade {
            ensure("filter", "FORWARD", &fwd_in(tun_if))
        } else {
            ensure("filter", "FORWARD", &fwd_in_open(tun_if))
        };
    let mss_ok = ensure("mangle", "FORWARD", &mss(tun_if));

    if !fwd_ok {
        if !forward_policy_accepts(&path) {
            anyhow::bail!(
                "gateway: FORWARD accept rules are absent and the chain is not empty/ACCEPT"
            );
        }
        log::warn!(
            "gateway: FORWARD accept rules not installed (legacy/nft filter conflict?) — \
             relying on an empty FORWARD chain with policy ACCEPT. If you tighten it, permit \
             {tun_if}<->LAN yourself."
        );
    }
    if !mss_ok {
        log::warn!(
            "gateway: TCP MSS clamp could not be verified; correct Path-MTU Discovery is \
             required for forwarded TCP through {tun_if}"
        );
    }
    if masquerade {
        log::warn!(
            "Gateway-NAT engaged: MASQUERADE {} out {tun_if} (+forward +mss-clamp, ip_forward=1). \
             Stays up across reconnects, removed on a clean stop; a crash leaves it — clear \
             rules tagged `{TAG}`.",
            if lan_subnet.is_empty() {
                "all".to_string()
            } else {
                format!("-s {lan_subnet}")
            }
        );
    } else {
        log::warn!(
            "Gateway forwarding engaged: routing tun<->LAN through {tun_if} WITHOUT NAT \
             (+mss-clamp, ip_forward=1). The far side needs a route back to this LAN (the \
             server's client_subnets for this user). Removed on a clean stop; a crash leaves \
             it — clear rules tagged `{TAG}`."
        );
    }
    Ok(())
}

/// Add the IPv6 half of gateway forwarding after authentication has returned an IPv6
/// NetworkPlan. Delaying this half until the plan is known lets an `ipv6 = auto` client
/// keep working with an IPv4-only server without requiring ip6tables, while a negotiated
/// dual/IPv6 plan still fails closed if the router cannot actually forward that family.
pub fn engage_ipv6(tun_if: &str, lan_subnet_ipv6: &str, masquerade: bool) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway IPv6: invalid TUN interface name {tun_if:?}");
    }
    let path = ipt_path("ip6tables").ok_or_else(|| {
        anyhow::anyhow!(
            "gateway IPv6 requires `ip6tables`; refusing a negotiated IPv6 plan that would not forward LAN traffic"
        )
    })?;

    // Linux stops accepting Router Advertisements when forwarding is enabled unless
    // accept_ra=2. Preserve native outer IPv6 on the default-route interface before
    // flipping the host-wide forwarding bit, and restore both values on clean teardown.
    let ipv6_wan_before = detect_wan_ipv6().filter(|interface| valid_ifname(interface));
    if let Some(wan) = &ipv6_wan_before {
        set_sysctl(&format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"), "2");
    }
    let forwarding_path = "/proc/sys/net/ipv6/conf/all/forwarding";
    let forwarding_enabled = matches!(
        std::fs::read_to_string(forwarding_path),
        Ok(value) if value.trim() == "1"
    ) || (set_sysctl(forwarding_path, "1")
        && matches!(
            std::fs::read_to_string(forwarding_path),
            Ok(value) if value.trim() == "1"
        ));
    if !forwarding_enabled {
        anyhow::bail!(
            "gateway IPv6 could not enable net.ipv6.conf.all.forwarding; LAN IPv6 would be black-holed"
        );
    }
    // If the host had native IPv6 before the transition, it must still have a default
    // afterwards. Otherwise this router may advertise a working dual-stack tunnel while
    // its own outer IPv6 carrier (or any locally routed IPv6) has just been removed by the
    // kernel's forwarding/RA interaction. A static/no-IPv6 host legitimately has no default,
    // so only enforce this invariant when one existed before the write.
    if ipv6_wan_before.is_some() {
        let ipv6_wan_after = detect_wan_ipv6().ok_or_else(|| {
            anyhow::anyhow!(
                "gateway IPv6: the IPv6 default route disappeared after enabling forwarding (check accept_ra=2)"
            )
        })?;
        if !valid_ifname(&ipv6_wan_after) {
            anyhow::bail!("gateway IPv6: post-forwarding WAN name {ipv6_wan_after:?} is invalid");
        }
        // Policy routing or a simultaneous roaming event may have selected a different
        // interface. Preserve RA acceptance on the path the kernel actually retained.
        set_sysctl(
            &format!("/proc/sys/net/ipv6/conf/{ipv6_wan_after}/accept_ra"),
            "2",
        );
    }

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(&path, tun_if, table, chain, rule)
    };

    if masquerade && !ensure("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet_ipv6)) {
        anyhow::bail!("gateway IPv6 could not install MASQUERADE on {tun_if}");
    }
    let forward_ok = ensure("filter", "FORWARD", &fwd_out(tun_if))
        & if masquerade {
            ensure("filter", "FORWARD", &fwd_in(tun_if))
        } else {
            ensure("filter", "FORWARD", &fwd_in_open(tun_if))
        };
    let mss_ok = ensure("mangle", "FORWARD", &mss(tun_if));
    if !forward_ok {
        if !forward_policy_accepts(&path) {
            anyhow::bail!(
                "gateway IPv6: FORWARD rules are absent and the chain is not empty/ACCEPT"
            );
        }
        log::warn!(
            "gateway IPv6: FORWARD rules could not be verified; relying on an empty FORWARD chain with policy ACCEPT for {tun_if}<->LAN"
        );
    }
    if !mss_ok {
        log::warn!(
            "gateway IPv6: TCP MSS clamp could not be installed; correct ICMPv6 Packet Too Big handling is now required along the complete path"
        );
    }
    log::warn!(
        "Gateway IPv6 engaged on {tun_if} ({}{}, forwarding=1).",
        if masquerade { "NAT66" } else { "routed" },
        if lan_subnet_ipv6.is_empty() {
            String::new()
        } else {
            format!(", source {lan_subnet_ipv6}")
        }
    );
    Ok(())
}

/// Remove every `qeli-gw-nat` rule for `tun_if`/`lan_subnet`. Best-effort; a
/// missing rule is not an error. Called only on a clean stop.
fn remove_gateway_rules(tun_if: &str, lan_subnet: &str, lan_subnet_ipv6: &str) {
    // Tear the families down independently. An IPv6-only router may legitimately have
    // ip6tables without the IPv4 binary; the old early return leaked all NAT66/FORWARD
    // rules in that setup.
    if let Some(path) = ipt_path("iptables") {
        let drop = |table: &str, chain: &str, rule: &[&str]| {
            let mut c: Vec<&str> = vec!["-t", table, "-C", chain];
            c.extend_from_slice(rule);
            for _ in 0..8 {
                if present(&path, &c) {
                    let mut d: Vec<&str> = vec!["-t", table, "-D", chain];
                    d.extend_from_slice(rule);
                    let _ = ipt(&path, &d);
                } else {
                    break;
                }
            }
        };
        drop("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet));
        drop("filter", "FORWARD", &fwd_out(tun_if));
        drop("filter", "FORWARD", &fwd_in(tun_if));
        drop("filter", "FORWARD", &fwd_in_open(tun_if));
        drop("mangle", "FORWARD", &mss(tun_if));
    }
    if let Some(ipv6_path) = ipt_path("ip6tables") {
        let drop_ipv6 = |table: &str, chain: &str, rule: &[&str]| {
            let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
            check.extend_from_slice(rule);
            for _ in 0..8 {
                if present(&ipv6_path, &check) {
                    let mut delete: Vec<&str> = vec!["-t", table, "-D", chain];
                    delete.extend_from_slice(rule);
                    let _ = ipt(&ipv6_path, &delete);
                } else {
                    break;
                }
            }
        };
        drop_ipv6("nat", "POSTROUTING", &masq_rule(tun_if, lan_subnet_ipv6));
        drop_ipv6("filter", "FORWARD", &fwd_out(tun_if));
        drop_ipv6("filter", "FORWARD", &fwd_in(tun_if));
        drop_ipv6("filter", "FORWARD", &fwd_in_open(tun_if));
        drop_ipv6("mangle", "FORWARD", &mss(tun_if));
    }
    log::info!("Gateway-NAT disengaged on {tun_if}");
    Ok(())
}

pub fn disengage(tun_if: &str, lan_subnet: &str, lan_subnet_ipv6: &str) {
    remove_gateway_rules(tun_if, lan_subnet, lan_subnet_ipv6);
    restore_sysctls(tun_if);
}

/// Tear down a complete client router plan atomically. Firewall permits/NAT are removed
/// for every enabled feature before host-wide forwarding, rp_filter and accept_ra values
/// are restored. This is used for both a clean process stop and a rejected NetworkPlan.
pub fn disengage_plan(
    tun_if: &str,
    lan_subnet: &str,
    lan_subnet_ipv6: &str,
    gateway_enabled: bool,
    exit_enabled: bool,
) {
    if gateway_enabled {
        remove_gateway_rules(tun_if, lan_subnet, lan_subnet_ipv6);
    }
    if exit_enabled {
        remove_exit_rules(tun_if);
    }
    if gateway_enabled || exit_enabled {
        restore_sysctls(tun_if);
    }
}

/// Host sysctl values as they were before `engage` touched them, so `disengage` can put
/// them back. Recorded per path by [`remember_prior`] on the first write (a reconnect
/// re-enters `engage` and must not overwrite the pristine values with our own); a knob we
/// could not read is simply not recorded, since there is nothing to restore.
static PRIOR_SYSCTLS: std::sync::Mutex<Option<Vec<(String, String)>>> = std::sync::Mutex::new(None);

fn restore_sysctls() -> anyhow::Result<()> {
    let mut g = PRIOR_SYSCTLS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(prior) = g.take() else {
        return Ok(());
    };
    let mut failed = Vec::new();
    for (path, value) in prior {
        // RAW write: going through set_sysctl would re-record the value we are about to
        // replace (i.e. our own), so the next engage would treat it as the pristine one.
        if !write_sysctl_raw(&path, &value) {
            failed.push((path, value));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        let detail = failed
            .iter()
            .map(|(path, value)| format!("{path}={value:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        // Keep the failed entries so another in-process cleanup attempt can retry them.
        *g = Some(failed);
        anyhow::bail!("could not restore host sysctl value(s): {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        forward_insert_position, policy_output_accepts_forward,
        policy_output_has_first_forward_jump,
    };

    #[test]
    fn forward_permit_stays_behind_the_qeli_kill_switch_only() {
        assert_eq!(forward_insert_position(false), "1");
        assert_eq!(forward_insert_position(true), "2");
    }

    #[test]
    fn kill_switch_jump_must_really_be_the_first_forward_rule() {
        assert!(policy_output_has_first_forward_jump(
            "-P FORWARD DROP\n-A FORWARD -j QELI_KS_tun0\n-A FORWARD -j DROP\n",
            "QELI_KS_tun0",
        ));
        assert!(!policy_output_has_first_forward_jump(
            "-P FORWARD DROP\n-A FORWARD -j HOST_POLICY\n-A FORWARD -j QELI_KS_tun0\n",
            "QELI_KS_tun0",
        ));
    }

    #[test]
    fn forward_policy_parser_requires_the_exact_builtin_accept_policy() {
        assert!(policy_output_accepts_forward("-P FORWARD ACCEPT\n"));
        assert!(!policy_output_accepts_forward(
            "-P FORWARD DROP\n-A FORWARD -j ACCEPT\n"
        ));
        assert!(!policy_output_accepts_forward(
            "-N FORWARDING\n-P FORWARDING ACCEPT\n"
        ));
        assert!(!policy_output_accepts_forward(
            "-P FORWARD ACCEPT\n-A FORWARD -j DROP\n"
        ));
    }
}
