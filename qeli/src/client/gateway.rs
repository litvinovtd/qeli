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
//! NetworkPlan creates the TUN. The generation owns them until cleanup, which runs
//! before its original TUN descriptor closes. A full reconnect installs a new plan;
//! roaming within one generation retains old WAN rules until cleanup. Ownership is
//! in memory; a crash can leave rules behind. Inspect
//! the tagged rules for this interface/subnet before manual recovery.

#[cfg(all(target_os = "linux", feature = "client"))]
use super::killswitch::{expected_qeli_chain, ipt_path, ipt_path_with, valid_ifname};
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
use crate::client_killswitch::{expected_qeli_chain, ipt_path, ipt_path_with, valid_ifname};

#[path = "gateway/host.rs"]
mod host;

#[path = "gateway/wan.rs"]
mod wan;
use crate::network_default_route::DefaultDevice;
use wan::{detect_wan, detect_wan_ipv6, select_wan_ipv6};

#[path = "gateway/identity.rs"]
mod identity;
use identity::Context;
#[path = "gateway/budget.rs"]
mod budget;
use budget::Budget;

#[cfg(all(target_os = "linux", feature = "client"))]
use super::route::RouteOwner;
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
use crate::client_route::RouteOwner;

pub(crate) fn bind_owner(owner: &RouteOwner) -> anyhow::Result<()> {
    identity::bind(owner)
}

pub(crate) fn disengage_owned(owner: &RouteOwner) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    if !identity::matches(owner)? {
        return Ok(());
    }
    disengage_locked(owner.interface(), budget)
}

/// Comment tag on every rule we own, so teardown removes exactly ours.
const TAG: &str = "qeli-gw-nat";

/// Acquire a host sysctl for one TUN-scoped router plan. This registers ownership even
/// when the knob already has the requested value, so sibling profiles cannot restore it.
fn managed_sysctl(ctx: &Context, path: &str, val: &str, tun_if: &str) -> bool {
    ctx.acquire(path, val, tun_if)
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
// on the same skb. The mask `0x51/0x51` preserves unrelated bits, but its selected
// bits are reserved for Qeli exit traffic and must not be reused by other marking.
const EXIT_TAG: &str = "qeli-exit-node";
const EXIT_MARK: &str = "0x51/0x51";

/// Every WAN used by each TUN within one NetworkPlan generation. A daemon may run ordinary and exit-node
/// client profiles in the same process; keying by TUN keeps one profile's roaming COMMIT
/// from installing exit rules for another profile. Keeping every WAN per TUN lets clean
/// teardown remove old+new rules after a physical-path change.
type ExitWansByTun = std::collections::BTreeMap<String, Vec<String>>;
static EXIT_WANS_V4: std::sync::Mutex<ExitWansByTun> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
static EXIT_WANS_V6: std::sync::Mutex<ExitWansByTun> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());
// Serialize each public router operation, including sysctl release, so cleanup cannot
// forget a concurrent acquisition. This is not a transaction around the entire NetworkPlan.
static ROUTER_OPERATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn router_operation(budget: Budget) -> std::io::Result<std::sync::MutexGuard<'static, ()>> {
    budget.lock(&ROUTER_OPERATION)
}

#[derive(Default)]
struct GatewayScope {
    ipv4: std::collections::BTreeSet<String>,
    ipv6: std::collections::BTreeSet<String>,
}
static GATEWAY_SCOPES: std::sync::Mutex<std::collections::BTreeMap<String, GatewayScope>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

fn remember_gateway(tun_if: &str, subnet: &str, ipv6: bool) {
    let mut scopes = GATEWAY_SCOPES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let scope = scopes.entry(tun_if.to_owned()).or_default();
    let subnets = if ipv6 {
        &mut scope.ipv6
    } else {
        &mut scope.ipv4
    };
    subnets.insert(subnet.to_owned());
}

fn remember_exit_wan(store: &std::sync::Mutex<ExitWansByTun>, tun_if: &str, wan: &str) {
    let mut by_tun = store.lock().unwrap_or_else(|error| error.into_inner());
    let wans = by_tun.entry(tun_if.to_string()).or_default();
    if !wans.iter().any(|existing| existing == wan) {
        wans.push(wan.to_string());
    }
}

fn exit_wans_for(store: &std::sync::Mutex<ExitWansByTun>, tun_if: &str) -> Vec<String> {
    store
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(tun_if)
        .cloned()
        .unwrap_or_default()
}

fn forget_exit_tun(store: &std::sync::Mutex<ExitWansByTun>, tun_if: &str) {
    store
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(tun_if);
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
fn forward_policy_accepts(ctx: &Context, path: &str) -> bool {
    ctx.ipt(path, &["-t", "filter", "-S", "FORWARD"])
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            std::str::from_utf8(&output.stdout).is_ok_and(policy_output_accepts_forward)
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

fn kill_switch_hook_is_first(ctx: &Context, path: &str, chain: &str) -> bool {
    ctx.ipt(path, &["-t", "filter", "-S", "FORWARD"])
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| {
            std::str::from_utf8(&output.stdout)
                .is_ok_and(|text| policy_output_has_first_forward_jump(text, chain))
        })
}

/// Return the guard's one-based position only when every preceding rule
/// either drops packets or can ACCEPT solely from a different input interface.
/// Other Qeli exit profiles may have their own guards and permits ahead of ours.
fn exit_drop_position_in_output(
    text: &str,
    rule: &[&str],
    tun_if: &str,
    hooked: bool,
) -> Option<usize> {
    // An exit profile never arms the kill-switch FORWARD hook. Its chain can
    // ACCEPT tunnel ingress before this guard, so it cannot be skipped safely.
    if hooked {
        return None;
    }
    let literal = format!("-A FORWARD {}", rule.join(" "));
    // iptables -S canonicalizes the comment matcher before the DROP target.
    let canonical = format!(
        "-A FORWARD {} -m comment --comment {} -j DROP",
        rule[..rule.len() - 6].join(" "),
        rule[rule.len() - 1]
    );
    // xtables quotes comments containing ':' (notably our cleanup lockdown tag).
    let canonical_quoted = format!(
        "-A FORWARD {} -m comment --comment \"{}\" -j DROP",
        rule[..rule.len() - 6].join(" "),
        rule[rule.len() - 1]
    );
    for (index, line) in text
        .lines()
        .filter(|line| line.starts_with("-A FORWARD "))
        .enumerate()
    {
        if line == literal || line == canonical || line == canonical_quoted {
            return Some(index + 1);
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let jump = fields
            .windows(2)
            .find(|pair| pair[0] == "-j")
            .map(|pair| pair[1]);
        if matches!(jump, Some("DROP" | "REJECT")) {
            continue;
        }
        let input = fields
            .windows(2)
            .find(|pair| pair[0] == "-i")
            .map(|pair| pair[1]);
        let negated_input = fields
            .windows(3)
            .any(|part| part[0] == "!" && part[1] == "-i" || part[0] == "-i" && part[1] == "!");
        let input_excludes_tun = input.is_some_and(|interface| {
            interface != "*"
                && interface != tun_if
                && !interface
                    .strip_suffix('+')
                    .is_some_and(|prefix| tun_if.starts_with(prefix))
        });
        if jump == Some("ACCEPT") && input_excludes_tun && !negated_input {
            continue;
        }
        return None;
    }
    None
}

fn exit_drop_position(
    ctx: &Context,
    path: &str,
    rule: &[&str],
    tun_if: &str,
    hooked: bool,
) -> Option<usize> {
    ctx.ipt(path, &["-t", "filter", "-S", "FORWARD"])
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| exit_drop_position_in_output(&text, rule, tun_if, hooked))
}

/// Install one managed rule and verify it. Narrow filter/FORWARD permits must precede host
/// DROP rules, but an active qeli kill-switch jump remains first so reconnect traffic still
/// fails closed. NAT and mangle rules retain append semantics.
fn ensure_rule(
    ctx: &Context,
    path: &str,
    tun_if: &str,
    table: &str,
    chain: &str,
    rule: &[&str],
) -> bool {
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    let exists = match ctx.present(path, &check) {
        Ok(exists) => exists,
        Err(error) => {
            log::error!("cannot inspect router rule before installation: {error}");
            return false;
        }
    };
    let insert = table == "filter" && chain == "FORWARD";
    let kill_switch_chain = format!("QELI_KS_{tun_if}");
    let hooked = if insert {
        match ctx.present(path, &["-C", "FORWARD", "-j", kill_switch_chain.as_str()]) {
            Ok(hooked) => hooked,
            Err(error) => {
                log::error!("cannot inspect router kill-switch protection: {error}");
                return false;
            }
        }
    } else {
        false
    };
    // Reconnect may reuse an existing permit, but never one ahead of our protection.
    if hooked && !kill_switch_hook_is_first(ctx, path, &kill_switch_chain) {
        log::error!(
            "qeli kill-switch jump {kill_switch_chain} is not the first FORWARD rule; \
             refusing to install or reuse a router permit ahead of it"
        );
        return false;
    }
    let exit_permit = insert && rule.contains(&EXIT_TAG) && rule.contains(&"ACCEPT");
    let guard_position = if exit_permit {
        let position = exit_drop_position(ctx, path, &exit_unmarked_drop(tun_if), tun_if, hooked);
        if position.is_none() {
            log::error!("exit-node unmarked egress guard is missing or bypassed");
            return false;
        }
        position
    } else {
        None
    };
    let own_drop = insert
        && (rule == exit_unmarked_drop(tun_if).as_slice()
            || rule == exit_lockdown_drop(tun_if).as_slice());
    if hooked && (exit_permit || own_drop) {
        log::error!("exit-node cannot protect {tun_if}: an existing kill-switch FORWARD hook may ACCEPT this TUN before the guard");
        return false;
    }
    if !exists {
        let mut add: Vec<&str> = vec!["-t", table, if insert { "-I" } else { "-A" }, chain];
        let position = guard_position
            .map(|index| (index + 1).to_string())
            .unwrap_or_else(|| forward_insert_position(hooked).to_string());
        if insert {
            add.push(position.as_str());
        }
        add.extend_from_slice(rule);
        let _ = ctx.ipt(path, &add);
    }
    match ctx.present(path, &check) {
        Ok(true) if own_drop => exit_drop_position(ctx, path, rule, tun_if, hooked).is_some(),
        Ok(present) => present,
        Err(error) => {
            log::error!("cannot verify installed router rule: {error}");
            false
        }
    }
}

/// Drop traffic from an exit TUN unless a Qeli WAN-specific mangle rule marked it.
fn exit_unmarked_drop(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-m",
        "mark",
        "!",
        "--mark",
        EXIT_MARK,
        "-j",
        "DROP",
        "-m",
        "comment",
        "--comment",
        EXIT_TAG,
    ]
}

/// Teardown first blocks every packet from this TUN, including packets that
/// were already marked before MARK/NAT removal. A failed cleanup keeps it.
fn exit_lockdown_drop(tun_if: &str) -> Vec<&str> {
    vec![
        "-i",
        tun_if,
        "-j",
        "DROP",
        "-m",
        "comment",
        "--comment",
        "qeli-exit-node:lockdown",
    ]
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

// The match may be identical on a shared WAN, but each TUN owns a distinct rule.
// Including the TUN in the exact comment lets another process keep its own NAT rule
// without an in-memory reference count. Old unsuffixed rules are not ours to claim.
fn exit_masq_tag(tun_if: &str) -> String {
    format!("{EXIT_TAG}:{tun_if}")
}

fn exit_masq_rule<'a>(wan_if: &'a str, tag: &'a str) -> Vec<&'a str> {
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
        tag,
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

/// Relax `rp_filter` on the tunnel interface, once it EXISTS.
///
/// Historically `engage` / `engage_exit` ran before the connect loop, i.e. before
/// `setup_tunnel` created the TUN — so their per-interface write to
/// `/proc/sys/net/ipv4/conf/<tun>/rp_filter` hit a path that did not exist yet,
/// the old snapshot helper bailed on the read and the per-interface write failed
/// into a discarded result. The knob was therefore never applied.
///
/// That matters because the kernel evaluates reverse-path filtering as
/// `max(conf/all, conf/<incoming-iface>)`: setting `conf/all` to 0 does not help while
/// the tun inherits `conf/default` = 1, which is the norm on many distributions. Strict
/// RPF on the tun then drops exactly the asymmetric paths gateway-NAT and exit-node
/// exist to carry, while the log cheerfully reported the feature engaged.
///
/// Called from `setup_tunnel` after the interface exists; for an owned exit TUN
/// this runs before link-up so its forwarding guard is ready first.
/// (Audit 2026-07-27, R1.)
pub fn apply_tun_rp_filter(tun_if: &str) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"),
        "0",
        tun_if,
    ) {
        log::warn!(
            "could not relax rp_filter on {tun_if} — asymmetric paths (gateway-NAT /              exit-node) may be dropped by reverse-path filtering"
        );
    }
    ctx.finish()
}

pub fn engage_exit(tun_if: &str) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node: invalid TUN interface name {tun_if:?}");
    }
    let wan = detect_wan(ctx).ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node: no unique default WAN found — cannot determine the interface to NAT \
             out of. An exit node needs its own working internet path to share."
        )
    })?;
    engage_exit_on(ctx, tun_if, &wan)
}

/// Add the IPv4 exit-node rules for one exact authenticated physical path. Existing
/// rules for the previous WAN deliberately remain until clean teardown: keeping old+new
/// is fail-safe while in-flight forwarded flows drain, and [`remove_exit_rules`] already
/// remembers every interface that this process touched.
fn engage_exit_on(ctx: &Context, tun_if: &str, wan: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node: invalid TUN interface name {tun_if:?}");
    }
    if wan == tun_if {
        anyhow::bail!("exit-node: the exit TUN {tun_if} cannot be its own WAN");
    }
    if !valid_ifname(wan) {
        anyhow::bail!("exit-node: detected WAN interface name {wan:?} is invalid");
    }
    let path = ctx.path("iptables")?.ok_or_else(|| {
        anyhow::anyhow!("exit-node: `iptables` is not installed (apt install iptables)")
    })?;

    // Install the fail-closed guard before forwarding, MARK or NAT can admit packets.
    // Record ownership first so every partial setup is cleaned with this generation.
    remember_exit_wan(&EXIT_WANS_V4, tun_if, wan);
    if !ensure_rule(
        ctx,
        &path,
        tun_if,
        "filter",
        "FORWARD",
        &exit_unmarked_drop(tun_if),
    ) {
        anyhow::bail!("exit-node: could not install unmarked tun egress DROP guard");
    }
    // ip_forward is load-bearing (same as gateway_nat); rp_filter relaxed for the
    // asymmetric tun<->wan path. The cross-process owner journal restores the pristine
    // values only after the last client plan releases them.
    let forwarding_path = "/proc/sys/net/ipv4/ip_forward";
    let forwarding_enabled = managed_sysctl(ctx, forwarding_path, "1", tun_if)
        && matches!(
            ctx.read(forwarding_path),
            Ok(value) if value.trim() == "1"
        );
    if !forwarding_enabled {
        anyhow::bail!(
            "exit-node: could not enable net.ipv4.ip_forward; refusing to advertise a black-holed IPv4 exit"
        );
    }
    managed_sysctl(ctx, "/proc/sys/net/ipv4/conf/all/rp_filter", "0", tun_if);
    managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"),
        "0",
        tun_if,
    );
    managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv4/conf/{wan}/rp_filter"),
        "0",
        tun_if,
    );

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(ctx, &path, tun_if, table, chain, rule)
    };

    // MARK + MASQUERADE are both essential — without either, tunnel traffic reaches the
    // WAN with a private source and the return path is black-holed.
    if !ensure(
        "nat",
        "POSTROUTING",
        &exit_masq_rule(wan, &exit_masq_tag(tun_if)),
    ) {
        anyhow::bail!("exit-node: could not install MASQUERADE out {wan} (nat POSTROUTING)");
    }
    if !ensure("mangle", "FORWARD", &exit_mark_rule(tun_if, wan)) {
        anyhow::bail!("exit-node: could not install the tun->wan MARK rule (mangle FORWARD)");
    }
    // The guard makes empty-chain ACCEPT fallback impossible: explicit narrow
    // permits must follow it for every selected WAN.
    let fwd_ok = ensure("filter", "FORWARD", &exit_fwd_out(tun_if, wan))
        & ensure("filter", "FORWARD", &exit_fwd_in(tun_if, wan));
    let mss_ok = ensure("mangle", "FORWARD", &exit_mss(tun_if));
    if !fwd_ok {
        anyhow::bail!("exit-node: could not verify guarded FORWARD accepts for {tun_if}<->{wan}");
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
         server must set client_to_client + this user's client_subnet = 0.0.0.0/0. Removed \
         before this generation releases its TUN; a crash leaves rules tagged \
         `{EXIT_TAG}`."
    );
    ctx.finish()
}

/// Add the IPv6 half of an exit node after authentication negotiated an IPv6 address.
/// This is deliberately separate from [`engage_exit`]: IPv4 and IPv6 may use different
/// WAN interfaces, and an `ipv6 = auto` client must not require `ip6tables` when the
/// server ultimately assigns IPv4 only.
pub fn engage_exit_ipv6(tun_if: &str) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node IPv6: invalid TUN interface name {tun_if:?}");
    }
    let wan = detect_wan_ipv6(ctx).ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6: no unique IPv6 default WAN found — cannot determine the IPv6 WAN"
        )
    })?;
    engage_exit_ipv6_on(ctx, tun_if, &wan)
}

/// IPv6 counterpart of [`engage_exit_on`]. The exact candidate interface is retained
/// across the forwarding transition; if Router Advertisement handling moves the default
/// elsewhere, the authenticated candidate is stale and COMMIT must fail closed.
fn engage_exit_ipv6_on(ctx: &Context, tun_if: &str, requested_wan: &str) -> anyhow::Result<()> {
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node IPv6: invalid TUN interface name {tun_if:?}");
    }
    let wan = requested_wan.to_string();
    if wan == tun_if {
        anyhow::bail!("exit-node IPv6: the exit TUN {tun_if} cannot be its own WAN");
    }
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node IPv6: detected WAN interface name {wan:?} is invalid");
    }
    let path = ctx.path("ip6tables")?.ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6 requires `ip6tables`; refusing a negotiated IPv6 plan that would black-hole forwarded traffic"
        )
    })?;

    // Guard the TUN before forwarding or a partial rule batch can pass un-NATed packets.
    remember_exit_wan(&EXIT_WANS_V6, tun_if, &wan);
    if !ensure_rule(
        ctx,
        &path,
        tun_if,
        "filter",
        "FORWARD",
        &exit_unmarked_drop(tun_if),
    ) {
        anyhow::bail!("exit-node IPv6: could not install unmarked tun egress DROP guard");
    }

    // Enabling IPv6 forwarding normally disables acceptance of Router Advertisements.
    // Preserve the physical WAN's RA-derived default by selecting router+host mode before
    // the host-wide switch, exactly as the IPv6 gateway path does.
    managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"),
        "2",
        tun_if,
    );
    let forwarding_path = "/proc/sys/net/ipv6/conf/all/forwarding";
    let forwarding_enabled = managed_sysctl(ctx, forwarding_path, "1", tun_if)
        && matches!(
            ctx.read(forwarding_path),
            Ok(value) if value.trim() == "1"
        );
    if !forwarding_enabled {
        anyhow::bail!(
            "exit-node IPv6: could not enable net.ipv6.conf.all.forwarding; refusing a black-holed IPv6 exit"
        );
    }
    // Forwarding can invalidate an RA-learned default unless accept_ra=2 actually took
    // effect. Re-resolve after the sysctl transition and program the interface the kernel
    // will really use, rather than claiming success with a stale pre-transition choice.
    let wan = detect_wan_ipv6(ctx).ok_or_else(|| {
        anyhow::anyhow!(
            "exit-node IPv6: the IPv6 default route disappeared after enabling forwarding (check accept_ra=2)"
        )
    })?;
    if wan != requested_wan {
        anyhow::bail!(
            "exit-node IPv6: authenticated candidate WAN {requested_wan} is no longer the active IPv6 default ({wan})"
        );
    }
    if wan == tun_if {
        anyhow::bail!("exit-node IPv6: the exit TUN {tun_if} cannot be its own WAN");
    }
    if !valid_ifname(&wan) {
        anyhow::bail!("exit-node IPv6: post-forwarding WAN name {wan:?} is invalid");
    }
    managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"),
        "2",
        tun_if,
    );

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(ctx, &path, tun_if, table, chain, rule)
    };

    if !ensure(
        "nat",
        "POSTROUTING",
        &exit_masq_rule(&wan, &exit_masq_tag(tun_if)),
    ) {
        anyhow::bail!("exit-node IPv6: could not install NAT66 MASQUERADE out {wan}");
    }
    if !ensure("mangle", "FORWARD", &exit_mark_rule(tun_if, &wan)) {
        anyhow::bail!("exit-node IPv6: could not install the tun->WAN MARK rule");
    }
    let forward_ok = ensure("filter", "FORWARD", &exit_fwd_out(tun_if, &wan))
        & ensure("filter", "FORWARD", &exit_fwd_in(tun_if, &wan));
    let mss_ok = ensure("mangle", "FORWARD", &exit_mss(tun_if));
    if !forward_ok {
        anyhow::bail!(
            "exit-node IPv6: could not verify guarded FORWARD accepts for {tun_if}<->{wan}"
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
    ctx.finish()
}

/// Read the WANs selected for this active exit plan without changing firewall state.
/// The monitor compares snapshots and retries a failed refresh: recorded WAN names
/// alone cannot prove success because ownership is recorded before rule installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExitWanSnapshot {
    ipv4: Option<String>,
    ipv6: Option<String>,
}

pub(super) fn exit_wan_snapshot_if_active(tun_if: &str) -> anyhow::Result<Option<ExitWanSnapshot>> {
    if exit_wans_for(&EXIT_WANS_V4, tun_if).is_empty()
        && exit_wans_for(&EXIT_WANS_V6, tun_if).is_empty()
    {
        return Ok(None);
    }
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let ipv4_active = !exit_wans_for(&EXIT_WANS_V4, tun_if).is_empty();
    let ipv6_active = !exit_wans_for(&EXIT_WANS_V6, tun_if).is_empty();
    if !ipv4_active && !ipv6_active {
        return Ok(None);
    }
    let context = Context::forward(tun_if, budget)?;
    let ipv4 = if ipv4_active {
        Some(detect_wan(&context).ok_or_else(|| {
            anyhow::anyhow!("exit-node monitor: no unique IPv4 default WAN remains")
        })?)
    } else {
        None
    };
    let ipv6 = if ipv6_active {
        Some(detect_wan_ipv6(&context).ok_or_else(|| {
            anyhow::anyhow!("exit-node monitor: no unique IPv6 default WAN remains")
        })?)
    } else {
        None
    };
    context.finish()?;
    Ok(Some(ExitWanSnapshot { ipv4, ipv6 }))
}

/// Refresh WAN-dependent exit-node state at platform COMMIT or on a physical WAN change.
///
/// The initial authenticated NetworkPlan records which inner families were actually
/// enabled for this exact TUN. A normal profile therefore returns before validating its
/// interface name or touching the host, even when another profile in the same daemon is an
/// exit node. IPv4 and IPv6 defaults are resolved independently: the qeli carrier interface
/// is not necessarily either exit WAN, and dual-stack hosts may use different uplinks.
///
/// Rules for the old WAN are intentionally not removed here. Removing them before transport
/// changes could break in-flight flows; removing them at COMMIT would make platform rollback
/// lossy. They are narrow `-i/-o` rules, harmless once that interface is no longer selected,
/// and remembered-WAN cleanup removes them before this generation releases its TUN.
pub fn refresh_exit_paths_if_active(tun_if: &str) -> anyhow::Result<()> {
    // Ordinary clients must not wait for another profile's router commands. Recheck
    // active families under the operation lock below in case cleanup wins the race.
    if exit_wans_for(&EXIT_WANS_V4, tun_if).is_empty()
        && exit_wans_for(&EXIT_WANS_V6, tun_if).is_empty()
    {
        return Ok(());
    }
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let ipv4_active = !exit_wans_for(&EXIT_WANS_V4, tun_if).is_empty();
    let ipv6_active = !exit_wans_for(&EXIT_WANS_V6, tun_if).is_empty();
    if !ipv4_active && !ipv6_active {
        return Ok(());
    }
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !valid_ifname(tun_if) {
        anyhow::bail!("exit-node roaming TUN interface {tun_if:?} is invalid");
    }
    if ipv4_active {
        let wan = detect_wan(ctx).ok_or_else(|| {
            anyhow::anyhow!(
                "exit-node roaming: no unique IPv4 default WAN remains at platform COMMIT"
            )
        })?;
        engage_exit_on(ctx, tun_if, &wan)?;
        if detect_wan(ctx).as_deref() != Some(wan.as_str()) {
            anyhow::bail!("exit-node roaming: IPv4 default route changed while refreshing {wan}");
        }
    }
    if ipv6_active {
        let wan = detect_wan_ipv6(ctx).ok_or_else(|| {
            anyhow::anyhow!(
                "exit-node roaming: no unique IPv6 default WAN remains at platform COMMIT"
            )
        })?;
        engage_exit_ipv6_on(ctx, tun_if, &wan)?;
        if detect_wan_ipv6(ctx).as_deref() != Some(wan.as_str()) {
            anyhow::bail!("exit-node roaming: IPv6 default route changed while refreshing {wan}");
        }
    }
    ctx.finish()
}

fn remove_rule(
    ctx: &Context,
    path: &str,
    table: &str,
    chain: &str,
    rule: &[&str],
) -> anyhow::Result<()> {
    let mut check: Vec<&str> = vec!["-t", table, "-C", chain];
    check.extend_from_slice(rule);
    for _ in 0..8 {
        if !ctx.present(path, &check)? {
            return Ok(());
        }
        let mut delete: Vec<&str> = vec!["-t", table, "-D", chain];
        delete.extend_from_slice(rule);
        ctx.ipt(path, &delete).map_err(|error| {
            anyhow::anyhow!(
                "cannot run {} {} while removing qeli firewall state: {}",
                path,
                delete.join(" "),
                error
            )
        })?;
    }
    if ctx.present(path, &check)? {
        anyhow::bail!(
            "{} rule remains after 8 deletion attempts: {}",
            table,
            rule.join(" ")
        );
    }
    Ok(())
}

/// Remove every exit-node rule from both families. WANs are retained until their family
/// has been confirmed clean so a second cleanup attempt can recover from a transient tool
/// failure or a physical-path change.
fn remove_exit_rules(ctx: &Context, tun_if: &str) -> anyhow::Result<()> {
    fn remove_family(
        ctx: &Context,
        binary: &str,
        tun_if: &str,
        remembered: &[String],
    ) -> anyhow::Result<()> {
        // Current routes do not establish ownership. An unstarted/already-clean family
        // must not discover and delete rules on another profile's WAN.
        if remembered.is_empty() {
            return Ok(());
        }
        let Some(path) = ctx.path(binary)? else {
            anyhow::bail!(
                "exit-node cleanup: `{binary}` is unavailable; rules tagged `{EXIT_TAG}` may remain"
            );
        };
        if !ensure_rule(
            ctx,
            &path,
            tun_if,
            "filter",
            "FORWARD",
            &exit_lockdown_drop(tun_if),
        ) {
            anyhow::bail!(
                "exit-node cleanup: cannot install TUN lockdown before removing {binary} rules"
            );
        }
        let mut errors = Vec::new();
        for wan in remembered {
            for result in [
                remove_rule(
                    ctx,
                    &path,
                    "mangle",
                    "FORWARD",
                    &exit_mark_rule(tun_if, wan),
                ),
                remove_rule(
                    ctx,
                    &path,
                    "nat",
                    "POSTROUTING",
                    &exit_masq_rule(wan, &exit_masq_tag(tun_if)),
                ),
                remove_rule(ctx, &path, "filter", "FORWARD", &exit_fwd_out(tun_if, wan)),
                remove_rule(ctx, &path, "filter", "FORWARD", &exit_fwd_in(tun_if, wan)),
                remove_rule(ctx, &path, "mangle", "FORWARD", &exit_mss(tun_if)),
            ] {
                if let Err(error) = result {
                    errors.push(format!("{binary}/{wan}: {error}"));
                }
            }
        }
        // Keep the guard after any partial cleanup failure, including MARK/NAT
        // deletion failures. Removing it last prevents an un-NATed fallback.
        if errors.is_empty() {
            if let Err(error) =
                remove_rule(ctx, &path, "filter", "FORWARD", &exit_unmarked_drop(tun_if))
            {
                errors.push(format!("{binary}/guard: {error}"));
            }
        }
        if errors.is_empty() {
            if let Err(error) =
                remove_rule(ctx, &path, "filter", "FORWARD", &exit_lockdown_drop(tun_if))
            {
                errors.push(format!("{binary}/lockdown: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("{}", errors.join("; "))
        }
    }

    let wans_v4 = exit_wans_for(&EXIT_WANS_V4, tun_if);
    let wans_v6 = exit_wans_for(&EXIT_WANS_V6, tun_if);
    let v4 = remove_family(ctx, "iptables", tun_if, &wans_v4);
    let v6 = remove_family(ctx, "ip6tables", tun_if, &wans_v6);
    if v4.is_ok() {
        forget_exit_tun(&EXIT_WANS_V4, tun_if);
    }
    if v6.is_ok() {
        forget_exit_tun(&EXIT_WANS_V6, tun_if);
    }
    match (v4, v6) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(v4), Err(v6)) => anyhow::bail!("IPv4 cleanup: {v4}; IPv6 cleanup: {v6}"),
    }
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
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway-nat: invalid TUN interface name {tun_if:?}");
    }
    let path = ctx.path("iptables")?.ok_or_else(|| {
        anyhow::anyhow!("gateway-nat: `iptables` is not installed (apt install iptables)")
    })?;
    // Mark before the first host mutation so rollback also covers a partially applied plan.
    remember_gateway(tun_if, lan_subnet, false);

    // Forwarding + relaxed reverse-path filter (the LAN↔tun path is asymmetric).
    // Verify the effective value: accepting a firewall plan while forwarding remains off
    // advertises a working router but deterministically black-holes every LAN packet.
    let forwarding_path = "/proc/sys/net/ipv4/ip_forward";
    let forwarding_enabled = managed_sysctl(ctx, forwarding_path, "1", tun_if)
        && matches!(
            ctx.read(forwarding_path),
            Ok(value) if value.trim() == "1"
        );
    if !forwarding_enabled {
        anyhow::bail!(
            "gateway-nat: could not enable net.ipv4.ip_forward; refusing a router plan that would black-hole LAN traffic"
        );
    }
    // rp_filter stays best-effort (relaxing it only avoids drops on the asymmetric path).
    managed_sysctl(ctx, "/proc/sys/net/ipv4/conf/all/rp_filter", "0", tun_if);
    managed_sysctl(
        ctx,
        &format!("/proc/sys/net/ipv4/conf/{tun_if}/rp_filter"),
        "0",
        tun_if,
    );
    // These are HOST-wide knobs: leaving ip_forward on turns a workstation into a router
    // after the VPN stops, and relaxed rp_filter leaves anti-spoofing disabled. The shared
    // owner journal restores both only after every client profile has released them.

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(ctx, &path, tun_if, table, chain, rule)
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
        if !forward_policy_accepts(ctx, &path) {
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
             Removed before this generation releases its TUN; a crash leaves rules tagged \
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
             server's client_subnets for this user). Removed before TUN release; a crash leaves \
             it — clear rules tagged `{TAG}`."
        );
    }
    ctx.finish()
}

/// Add the IPv6 half of gateway forwarding after authentication has returned an IPv6
/// NetworkPlan. Delaying this half until the plan is known lets an `ipv6 = auto` client
/// keep working with an IPv4-only server without requiring ip6tables, while a negotiated
/// dual/IPv6 plan still fails closed if the router cannot actually forward that family.
pub fn engage_ipv6(tun_if: &str, lan_subnet_ipv6: &str, masquerade: bool) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    let context = Context::forward(tun_if, budget)?;
    let ctx = &context;
    if !valid_ifname(tun_if) {
        anyhow::bail!("gateway IPv6: invalid TUN interface name {tun_if:?}");
    }
    let path = ctx.path("ip6tables")?.ok_or_else(|| {
        anyhow::anyhow!(
            "gateway IPv6 requires `ip6tables`; refusing a negotiated IPv6 plan that would not forward LAN traffic"
        )
    })?;
    // Linux stops accepting Router Advertisements when forwarding is enabled unless
    // accept_ra=2. Preserve native outer IPv6 on the default-route interface before
    // flipping the host-wide forwarding bit, and restore both values on clean teardown.
    let ipv6_wan_before = match select_wan_ipv6(ctx) {
        DefaultDevice::Selected(interface) if valid_ifname(&interface) => Some(interface),
        DefaultDevice::Ambiguous => {
            anyhow::bail!("gateway IPv6: multiple preferred default WAN interfaces; set one preferred route before enabling forwarding")
        }
        _ => None,
    };
    remember_gateway(tun_if, lan_subnet_ipv6, true);
    if let Some(wan) = &ipv6_wan_before {
        managed_sysctl(
            ctx,
            &format!("/proc/sys/net/ipv6/conf/{wan}/accept_ra"),
            "2",
            tun_if,
        );
    }
    let forwarding_path = "/proc/sys/net/ipv6/conf/all/forwarding";
    let forwarding_enabled = managed_sysctl(ctx, forwarding_path, "1", tun_if)
        && matches!(
            ctx.read(forwarding_path),
            Ok(value) if value.trim() == "1"
        );
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
        let ipv6_wan_after = match select_wan_ipv6(ctx) {
            DefaultDevice::Selected(interface) => interface,
            DefaultDevice::Ambiguous => {
                anyhow::bail!(
                    "gateway IPv6: default WAN became ambiguous after enabling forwarding"
                )
            }
            DefaultDevice::Missing => {
                anyhow::bail!("gateway IPv6: the IPv6 default route disappeared after enabling forwarding (check accept_ra=2)")
            }
        };
        if !valid_ifname(&ipv6_wan_after) {
            anyhow::bail!("gateway IPv6: post-forwarding WAN name {ipv6_wan_after:?} is invalid");
        }
        // Policy routing or a simultaneous roaming event may have selected a different
        // interface. Preserve RA acceptance on the path the kernel actually retained.
        managed_sysctl(
            ctx,
            &format!("/proc/sys/net/ipv6/conf/{ipv6_wan_after}/accept_ra"),
            "2",
            tun_if,
        );
    }

    let ensure = |table: &str, chain: &str, rule: &[&str]| -> bool {
        ensure_rule(ctx, &path, tun_if, table, chain, rule)
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
        if !forward_policy_accepts(ctx, &path) {
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
    ctx.finish()
}

/// Remove rules using the saved installation selectors, independently for each TUN
/// and family. Keep failed families (including all old subnets) available for retry.
/// The caller holds ROUTER_OPERATION through subsequent sysctl release.
fn remove_gateway_rules(ctx: &Context, tun_if: &str) -> anyhow::Result<()> {
    fn remove_family(
        ctx: &Context,
        binary: &str,
        tun_if: &str,
        subnets: &mut std::collections::BTreeSet<String>,
    ) -> anyhow::Result<()> {
        if subnets.is_empty() {
            return Ok(());
        }
        let path = ctx.path(binary)?.ok_or_else(|| {
            anyhow::anyhow!("'{binary}' is unavailable; gateway rules on {tun_if} may remain")
        })?;
        let mut errors = Vec::new();
        for subnet in subnets.iter() {
            if let Err(error) =
                remove_rule(ctx, &path, "nat", "POSTROUTING", &masq_rule(tun_if, subnet))
            {
                errors.push(error.to_string());
            }
        }
        for result in [
            remove_rule(ctx, &path, "filter", "FORWARD", &fwd_out(tun_if)),
            remove_rule(ctx, &path, "filter", "FORWARD", &fwd_in(tun_if)),
            remove_rule(ctx, &path, "filter", "FORWARD", &fwd_in_open(tun_if)),
            remove_rule(ctx, &path, "mangle", "FORWARD", &mss(tun_if)),
        ] {
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            subnets.clear();
            Ok(())
        } else {
            anyhow::bail!("{}", errors.join("; "))
        }
    }

    let mut scopes = GATEWAY_SCOPES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(scope) = scopes.get_mut(tun_if) else {
        return Ok(());
    };
    let mut errors = Vec::new();
    if let Err(error) = remove_family(ctx, "iptables", tun_if, &mut scope.ipv4) {
        errors.push(format!("IPv4: {error}"));
    }
    if let Err(error) = remove_family(ctx, "ip6tables", tun_if, &mut scope.ipv6) {
        errors.push(format!("IPv6: {error}"));
    }
    if errors.is_empty() {
        scopes.remove(tun_if);
        log::info!("Gateway forwarding rules disengaged on {tun_if}");
        Ok(())
    } else {
        anyhow::bail!("gateway cleanup failed: {}", errors.join("; "))
    }
}

/// Attempt every recorded router cleanup, then release this scope's sysctl ownership.
/// Failures are aggregated and failed rule records retained for retry. This is used for
/// both a clean process stop and a rejected NetworkPlan; kernel changes are not atomic.
pub fn disengage_plan(tun_if: &str) -> anyhow::Result<()> {
    let budget = Budget::new();
    let _operation = router_operation(budget)?;
    disengage_locked(tun_if, budget)
}

fn disengage_locked(tun_if: &str, budget: Budget) -> anyhow::Result<()> {
    let Some(context) = Context::cleanup(tun_if, budget)? else {
        return Ok(());
    };
    let ctx = &context;
    let mut errors = Vec::new();
    // Actual recorded ownership, not the current config, determines cleanup targets.
    for result in [
        remove_gateway_rules(ctx, tun_if),
        remove_exit_rules(ctx, tun_if),
        restore_sysctls(ctx, tun_if),
    ] {
        if let Err(error) = result {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        ctx.finish()?;
        if !GATEWAY_SCOPES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(tun_if)
            && exit_wans_for(&EXIT_WANS_V4, tun_if).is_empty()
            && exit_wans_for(&EXIT_WANS_V6, tun_if).is_empty()
        {
            identity::forget(tun_if);
        }
        Ok(())
    } else {
        anyhow::bail!("router-plan cleanup failed: {}", errors.join("; "))
    }
}

fn restore_sysctls(ctx: &Context, tun_if: &str) -> anyhow::Result<()> {
    ctx.release(tun_if)
}

#[cfg(test)]
mod tests {
    use super::{
        exit_drop_position_in_output, exit_lockdown_drop, exit_unmarked_drop, exit_wans_for,
        forget_exit_tun, forward_insert_position, policy_output_accepts_forward,
        policy_output_has_first_forward_jump, refresh_exit_paths_if_active, remember_exit_wan,
        ExitWansByTun,
    };

    #[test]
    fn forward_permit_stays_behind_the_qeli_kill_switch_only() {
        assert_eq!(forward_insert_position(false), "1");
        assert_eq!(forward_insert_position(true), "2");
    }

    #[test]
    fn real_iptables_guard_inventory_requires_priority() {
        let real = "-P FORWARD ACCEPT\n-A FORWARD -i ex_a -m mark ! --mark 0x51/0x51 -m comment --comment qeli-exit-node -j DROP\n";
        let guard = exit_unmarked_drop("ex_a");
        assert_eq!(
            exit_drop_position_in_output(real, &guard, "ex_a", false),
            Some(1)
        );
        let hooked = format!("-P FORWARD ACCEPT\n-A FORWARD -j QELI_KS_ex_a\n{real}");
        assert_eq!(
            exit_drop_position_in_output(&hooked, &guard, "ex_a", true),
            None
        );
        let bypass = format!("-P FORWARD ACCEPT\n-A FORWARD -i ex_a -j ACCEPT\n{real}");
        assert_eq!(
            exit_drop_position_in_output(&bypass, &guard, "ex_a", false),
            None
        );
        let wildcard = format!("-P FORWARD ACCEPT\n-A FORWARD -i ex+ -j ACCEPT\n{real}");
        assert_eq!(
            exit_drop_position_in_output(&wildcard, &guard, "ex_a", false),
            None
        );
        let other = format!(
            "-P FORWARD ACCEPT\n-A FORWARD -i ex_b -j DROP\n-A FORWARD -i ex_b -o wan0 -j ACCEPT\n{real}"
        );
        assert_eq!(
            exit_drop_position_in_output(&other, &guard, "ex_a", false),
            Some(3)
        );
    }

    #[test]
    fn quoted_lockdown_tag_is_recognized_ahead_of_exit_permits() {
        let lockdown = exit_lockdown_drop("ex_a");
        let real = "-P FORWARD ACCEPT\n-A FORWARD -i ex_a -m comment --comment \"qeli-exit-node:lockdown\" -j DROP\n-A FORWARD -i ex_a -o wan1 -j ACCEPT\n";
        assert_eq!(
            exit_drop_position_in_output(real, &lockdown, "ex_a", false),
            Some(1)
        );
        let bypass = format!("-P FORWARD ACCEPT\n-A FORWARD -i ex_a -j ACCEPT\n{real}");
        assert_eq!(
            exit_drop_position_in_output(&bypass, &lockdown, "ex_a", false),
            None
        );
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

    #[test]
    fn inactive_exit_node_path_refresh_is_a_strict_noop() {
        // LinuxPathController invokes the refresh for every committed path. A normal
        // client must neither validate the synthetic names nor execute a host command.
        assert!(refresh_exit_paths_if_active("not/a/tun").is_ok());
    }

    #[test]
    fn exit_wan_ownership_is_scoped_to_the_exact_tun() {
        let store = std::sync::Mutex::new(ExitWansByTun::new());
        remember_exit_wan(&store, "exit0", "wan-a");
        remember_exit_wan(&store, "exit0", "wan-b");
        remember_exit_wan(&store, "exit0", "wan-b");

        assert_eq!(exit_wans_for(&store, "exit0"), ["wan-a", "wan-b"]);
        assert!(exit_wans_for(&store, "ordinary0").is_empty());

        forget_exit_tun(&store, "ordinary0");
        assert_eq!(exit_wans_for(&store, "exit0"), ["wan-a", "wan-b"]);
        forget_exit_tun(&store, "exit0");
        assert!(exit_wans_for(&store, "exit0").is_empty());
    }
}

#[cfg(test)]
#[path = "gateway/rollback_tests.rs"]
mod rollback_tests;
