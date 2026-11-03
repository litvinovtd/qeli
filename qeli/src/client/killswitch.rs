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
//! Implemented as a dedicated `QELI_KS_<tun>` chain in the `filter` table, jumped to from
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
//!   * [`prepare_engage`] pins the calling network namespace; its returned mutation installs `QELI_KS_<tun>` + OUTPUT jump and is idempotent (it
//!     rebuilds existing rules under temporary DROP guards). It is installed ONCE,
//!     before the connect loop, and deliberately stays up across every reconnect.
//!   * [`disengage`] removes the chain and is called only on a CLEAN stop
//!     (user disconnect / SIGINT / SIGTERM / loop exit).
//!   * A crashed run (SIGKILL / panic / power loss) leaves the chain in place — the
//!     machine stays locked (no leak) until qeli runs again, whose prepared setup
//!     replaces it. A failed rebuild retains exact `qeli-ks-rebuild:<tun>` DROP guards
//!     until a successful retry or explicit clean stop. To unlock without reconnecting:
//!     use the exact per-TUN chain shown in the log, in its original network namespace.
//!     Remove its OUTPUT/FORWARD jumps before flushing/deleting that exact chain.
//!     Repeat for `ip6tables` when IPv6 was programmed; preserve unrelated chains.
//!
//! Only meaningful in full-tunnel mode (in split-tunnel the dropped "everything
//! else" is exactly the traffic that is supposed to go direct), so the caller
//! gates on that.

use crate::firewall_check::{present as checked_presence, Query};
use crate::system_command::Command;
use std::net::IpAddr;
use std::path::Path;

#[path = "killswitch/admission.rs"]
mod admission;
#[path = "killswitch/ownership.rs"]
pub(crate) mod ownership;
#[path = "killswitch/rebuild.rs"]
mod rebuild;
use ownership::Context;
#[path = "killswitch/ipv6_state.rs"]
pub(crate) mod ipv6_state;

// Serializes individual firewall operations. The Linux client also holds a
// namespace lease for its whole session, before DNS recovery and the first engage.
// Old binaries and external administrators do not participate in that lease.
static OPERATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
// Timing fixtures must control who waits for OPERATION; unrelated fixtures are not contenders.
#[cfg(all(test, target_os = "linux"))]
static BUDGET_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
fn operation() -> std::sync::MutexGuard<'static, ()> {
    OPERATION.lock().unwrap_or_else(|error| error.into_inner())
}

const OPERATION_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Copy)]
struct Budget {
    until: std::time::Instant,
    operation: &'static str,
}
impl Budget {
    fn remaining(self) -> std::io::Result<std::time::Duration> {
        crate::operation_budget::limit(self.until)
            .checked_duration_since(std::time::Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "kill-switch {} deadline expired; ownership retained for retry",
                        self.operation
                    ),
                )
            })
    }
    fn lock(self, lock: &std::sync::Mutex<()>) -> std::io::Result<std::sync::MutexGuard<'_, ()>> {
        loop {
            self.remaining()?;
            let acquired = match lock.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(guard) = acquired {
                self.remaining()?;
                return Ok(guard);
            }
            std::thread::sleep(self.remaining()?.min(std::time::Duration::from_millis(10)));
        }
    }
}

/// Dedicated chain (in the `filter` table) holding the kill-switch ruleset.
/// Chain name for THIS instance.
///
/// It used to be one global `QELI_KS`. Every instance therefore built, and tore down,
/// the same chain: starting a second client wiped the first one's rules (its tun and
/// server IP were no longer allow-listed, so its traffic began hitting the DROP), and
/// whichever instance stopped first removed the chain out from under the other, leaving
/// it running with no kill-switch at all and nothing said about it. The tun interface
/// name is already unique per instance — that is what `dev=` is for — so key the chain
/// on it. This scopes cleanup, not packet policy: two terminal-DROP chains still
/// conflict in OUTPUT/FORWARD, so admission permits only one TUN's kill-switch.
/// iptables allows 28 characters; `QELI_KS_` (8) plus an IFNAMSIZ name (≤15) fits.
fn chain_for(tun_if: &str) -> String {
    format!("QELI_KS_{tun_if}")
}

/// The pre-per-instance chain name. Its owner is unknown; admission preserves it
/// for explicit administrator recovery rather than treating it as this TUN's chain.
const LEGACY_CHAIN: &str = "QELI_KS";

/// Resolve `server_addr:port` to the set of IPs the kill-switch must allow through
/// (so the tunnel can (re)connect). Returns string IPs (v4 and v6).
async fn resolve_ips(
    server_addr: &str,
    server_port: u16,
    until: std::time::Instant,
) -> std::io::Result<Vec<String>> {
    match crate::transport_core::resolver::lookup(
        server_addr,
        server_port,
        tokio::time::Instant::from_std(until),
    )
    .await
    {
        Ok(addrs) => {
            let mut ips: Vec<String> = addrs.into_iter().map(|sa| sa.ip().to_string()).collect();
            ips.sort();
            ips.dedup();
            Ok(ips)
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Err(error),
        // A failed ordinary refresh keeps old allowances while checking the barrier.
        Err(_) => Ok(Vec::new()),
    }
}

/// Locate an iptables-family binary (`iptables` / `ip6tables`). `None` = not present.
/// Checks the usual sbin locations first (cheap, no exec), then a PATH probe — same
/// approach as `server::nat::iptables_path` (duplicated because the server module is
/// `cfg`-excluded from the client/.so builds).
pub(crate) fn ipt_path(bin: &str) -> Option<String> {
    ipt_path_with(bin, |program| ipt(program, &["--version"]))
}

pub(crate) fn ipt_path_with(
    bin: &str,
    probe: impl FnOnce(&str) -> std::io::Result<std::process::Output>,
) -> Option<String> {
    #[cfg(test)]
    if let Some(path) = ownership::test_support::path(bin) {
        return path;
    }
    // A positively disabled module has no IPv6 firewall to own or clean up.
    // Missing/denied/malformed evidence does not bypass filter admission.
    if bin == "ip6tables" && ipv6_state::globally_disabled() {
        return None;
    }
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
    if probe(bin).map(|o| o.status.success()).unwrap_or(false) {
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

pub(crate) fn expected_qeli_chain<'a>(args: &'a [&'a str]) -> Option<&'a str> {
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

/// Presence check for guarded setup and teardown, where "absent" and "could not inspect the
/// firewall" must not collapse into the same `false` result.
#[cfg(test)]
pub(crate) fn present_checked(path: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = ipt(path, args)
        .map_err(|error| anyhow::anyhow!("cannot run {path} {}: {error}", args.join(" ")))?;
    checked_presence(
        &output,
        Query::Rule {
            missing_target: expected_qeli_chain(args),
        },
    )
    .map_err(|error| anyhow::anyhow!("{path} {}: {error}", args.join(" ")))
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
fn chain_exists(context: &Context, path: &str, chain: &str) -> anyhow::Result<bool> {
    let output = context
        .ipt(path, &["-S", chain])
        .map_err(|error| anyhow::anyhow!("cannot run {path} -S {chain}: {error}"))?;
    checked_presence(&output, Query::Chain(chain))
        .map_err(|error| anyhow::anyhow!("{path} -S {chain}: {error}"))
}

fn teardown_family(context: &Context, path: &str, chain: &str) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Remove the jump(s) first — a chain cannot be deleted while referenced. FORWARD is
    // only ever hooked in gateway mode, but unhook it unconditionally: a crash between
    // engage and disengage must not leave a dangling reference that blocks cleanup.
    for hook in ["OUTPUT", "FORWARD"] {
        for _ in 0..8 {
            match context.present_checked(path, &["-C", hook, "-j", chain]) {
                Ok(true) => {
                    if let Err(error) = context.ipt(path, &["-D", hook, "-j", chain]) {
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
        match context.present_checked(path, &["-C", hook, "-j", chain]) {
            Ok(true) => errors.push(format!(
                "{path}: {hook} still jumps to {chain} after 8 deletion attempts"
            )),
            Ok(false) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }

    // Flushing a chain that may still be referenced would remove its DROP barrier.
    // Failure/unknown unhook results retain the exact chain for explicit recovery.
    if !errors.is_empty() {
        anyhow::bail!(
            "firewall unhook failed; chain retained: {}",
            errors.join("; ")
        );
    }

    match chain_exists(context, path, chain) {
        Ok(true) => {
            let _ = context.ipt(path, &["-F", chain]);
            let _ = context.ipt(path, &["-X", chain]);
            match chain_exists(context, path, chain) {
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

async fn system_resolvers(until: std::time::Instant) -> std::io::Result<Vec<String>> {
    Ok(
        crate::transport_core::resolver::system_upstreams(tokio::time::Instant::from_std(until))
            .await?
            .into_iter()
            .map(|address| address.ip())
            .filter(usable_resolver)
            .map(|ip| ip.to_string())
            .collect(),
    )
}

struct Rollback<'a> {
    context: &'a Context,
    budget: std::cell::OnceCell<Budget>,
    limit: std::time::Duration,
    failure: std::cell::RefCell<Option<String>>,
}
impl<'a> Rollback<'a> {
    fn new(context: &'a Context, limit: std::time::Duration) -> Self {
        Self {
            context,
            budget: std::cell::OnceCell::new(),
            limit,
            failure: std::cell::RefCell::new(None),
        }
    }
    fn family(&self, path: &str, chain: &str) -> anyhow::Result<()> {
        let budget = *self.budget.get_or_init(|| Budget {
            until: std::time::Instant::now() + self.limit,
            operation: "setup rollback",
        });
        let recovery = self.context.clone().with_budget(budget);
        let result = teardown_family(&recovery, path, chain);
        if let Err(error) = &result {
            self.failure
                .borrow_mut()
                .get_or_insert_with(|| error.to_string());
        }
        result
    }
    fn check(&self) -> anyhow::Result<()> {
        if let Some(error) = self.failure.borrow().as_ref() {
            anyhow::bail!("kill-switch setup rollback failed: {error}");
        }
        Ok(())
    }
}

/// Build the `QELI_KS` chain on one family and hook it at the top of OUTPUT.
/// `allow_ips` are the server addresses of THIS family to let through.
fn engage_family(
    context: &Context,
    rollback: &Rollback<'_>,
    path: &str,
    tun_if: &str,
    allow_ips: &[String],
    resolvers: &[String],
    guard_forward: bool,
) -> anyhow::Result<()> {
    let chain = &chain_for(tun_if);
    teardown_family(context, path, chain).map_err(|error| {
        anyhow::anyhow!("kill-switch: cannot clear the previous {chain} ruleset: {error}")
    })?; // Rebuild only this exact TUN's chain; admission has rejected other owners.
    let _ = context.ipt(path, &["-N", chain]); // create chain (ignore "already exists")

    // Append a rule to the chain and confirm it actually landed.
    let add = |rule: &[&str]| -> bool {
        let mut a: Vec<&str> = vec!["-A", chain];
        a.extend_from_slice(rule);
        let _ = context.ipt(path, &a); // exit code is unreliable — verify below
        let mut c: Vec<&str> = vec!["-C", chain];
        c.extend_from_slice(rule);
        context.present(path, &c)
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
    let resolvers: Vec<&String> = resolvers
        .iter()
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
        let cleanup = rollback
            .family(path, chain)
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
        let cleanup = rollback
            .family(path, chain)
            .err()
            .map(|error| format!("; rollback also failed: {error}"))
            .unwrap_or_default();
        anyhow::bail!("could not install the DROP rule in chain {chain}{cleanup}");
    }

    // Hook the chain at the top of OUTPUT — added LAST, so the chain is already
    // complete the instant it becomes reachable (no partial-block window).
    if !context.present(path, &["-C", "OUTPUT", "-j", chain]) {
        let _ = context.ipt(path, &["-I", "OUTPUT", "1", "-j", chain]);
    }
    if !context.present(path, &["-C", "OUTPUT", "-j", chain]) {
        let cleanup = rollback
            .family(path, chain)
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
        if !context.present(path, &["-C", "FORWARD", "-j", chain]) {
            let _ = context.ipt(path, &["-I", "FORWARD", "1", "-j", chain]);
        }
        if !context.present(path, &["-C", "FORWARD", "-j", chain]) {
            let cleanup = rollback
                .family(path, chain)
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

/// Prepare a kill-switch mutation: allow only loopback, `tun_if`, DHCP, DNS, and the server
/// IP(s). Idempotent — rebuilds the `QELI_KS` chain on both families. Each family fails
/// closed when the host has usable egress but its firewall cannot be armed, unless the
/// matching `allow_ipv*_leak` escape hatch was explicitly enabled.
pub(crate) async fn prepare_engage(
    server_addr: &str,
    server_port: u16,
    tun_if: &str,
    allow_ipv4_leak: bool,
    allow_ipv6_leak: bool,
    // True when qeli routes a LAN through the tunnel (gateway/forward mode). Routed
    // packets bypass OUTPUT entirely, so the chain must also cover FORWARD.
    guard_forward: bool,
) -> anyhow::Result<impl FnOnce() -> anyhow::Result<()> + Send + 'static> {
    let until = std::time::Instant::now() + OPERATION_BUDGET;
    let context = setup_context(tun_if, until)?;
    let ips = resolve_ips(server_addr, server_port, until).await?;
    // Read once, before any family is changed; cancellation cannot strand a partial chain.
    let resolvers = system_resolvers(until).await?;
    let server_addr = server_addr.to_owned();
    let tun_if = tun_if.to_owned();
    Ok(move || {
        engage_prepared(
            Setup {
                server_addr: &server_addr,
                tun_if: &tun_if,
                allow_ipv4_leak,
                allow_ipv6_leak,
                guard_forward,
            },
            context,
            until,
            OPERATION_BUDGET,
            ips,
            resolvers,
        )
    })
}

struct Setup<'a> {
    server_addr: &'a str,
    tun_if: &'a str,
    allow_ipv4_leak: bool,
    allow_ipv6_leak: bool,
    guard_forward: bool,
}

fn setup_context(tun_if: &str, until: std::time::Instant) -> anyhow::Result<Context> {
    anyhow::ensure!(
        valid_ifname(tun_if),
        "kill-switch: invalid TUN interface name {tun_if:?}"
    );
    let budget = Budget {
        until,
        operation: "setup",
    };
    budget.remaining()?;
    let context = Context::prepare(tun_if)?.with_budget(budget);
    context.check_budget()?;
    Ok(context)
}

#[cfg(test)]
fn engage_until(
    setup: Setup<'_>,
    until: std::time::Instant,
    rollback_limit: std::time::Duration,
    resolve: impl FnOnce() -> Vec<String>,
) -> anyhow::Result<()> {
    let context = setup_context(setup.tun_if, until)?;
    let ips = resolve();
    engage_prepared(setup, context, until, rollback_limit, ips, Vec::new())
}

fn engage_prepared(
    setup: Setup<'_>,
    context: Context,
    until: std::time::Instant,
    rollback_limit: std::time::Duration,
    ips: Vec<String>,
    resolvers: Vec<String>,
) -> anyhow::Result<()> {
    let Setup {
        server_addr,
        tun_if,
        allow_ipv4_leak,
        allow_ipv6_leak,
        guard_forward,
    } = setup;
    let budget = Budget {
        until,
        operation: "setup",
    };
    context.check()?;
    context.check_budget()?;
    let chain = chain_for(tun_if);
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
    let _operation = budget.lock(&OPERATION)?;
    context.check()?;
    context.check_budget()?;
    let rollback = Rollback::new(&context, rollback_limit);
    let mut attempted = Vec::new();
    let mut guarded = Vec::new();
    let result = (|| -> anyhow::Result<()> {
        let v4_path = ipt_path_with("iptables", |bin| context.ipt(bin, &["--version"]));
        context.check()?;
        context.check_budget()?;
        let v6_path = ipt_path_with("ip6tables", |bin| context.ipt(bin, &["--version"]));
        context.check()?;
        context.check_budget()?;
        // Inspect both available families before changing either one. A conflict is
        // host-wide policy incompatibility, not permission to use a leak escape hatch.
        for path in [v4_path.as_deref(), v6_path.as_deref()]
            .into_iter()
            .flatten()
        {
            admission::check(&context, path, &chain)?;
        }
        context.check_budget()?;
        context.bind(tun_if)?;
        context.check_budget()?;
        // Preserve crash leftovers before touching either family's ordinary chain.
        // Admission/guard failures do not authorize rollback of an inherited chain.
        for (ipv6, path) in [(false, v4_path.as_deref()), (true, v6_path.as_deref())] {
            if let Some(path) = path {
                context.remember(ipv6, path)?;
                if rebuild::arm(&context, path, tun_if, guard_forward)? {
                    guarded.push((ipv6, path.to_owned()));
                }
            }
        }
        let v4_protected = match v4_path.as_deref() {
            Some(path) => {
                attempted.push((false, path.to_owned()));
                match engage_family(
                    &context,
                    &rollback,
                    path,
                    tun_if,
                    &v4,
                    &resolvers,
                    guard_forward,
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        log::warn!("kill-switch: IPv4 leg not engaged ({error})");
                        false
                    }
                }
            }
            None => false,
        };
        context.check()?;
        context.check_budget()?;
        rollback.check()?;
        context.protected(false, v4_protected, guard_forward);
        if !v4_protected {
            anyhow::ensure!(
                !guarded.iter().any(|(ipv6, _)| !ipv6),
                "IPv4 kill-switch rebuild failed; prior protection retained by recovery guard"
            );
            // A missing default route is only a snapshot; DHCP or the administrator
            // can add one later without another kill-switch admission.
            let needs_protection = !allow_ipv4_leak;
            context.check()?;
            context.check_budget()?;
            if needs_protection {
                anyhow::bail!(
                "kill-switch: IPv4 can become active, but iptables is unavailable or could not be programmed — refusing to engage a leaking kill-switch. Install/fix iptables or set allow_ipv4_leak = true to connect and accept the IPv4 leak."
            );
            }
            log::warn!("kill-switch: IPv4 egress is NOT restricted (allow_ipv4_leak is set)");
        }

        // IPv6 leg. Program ip6tables where present; where it's missing (or programming
        // fails) a currently IPv4-only host can acquire global IPv6 later. An empty
        // address inventory is only a snapshot and cannot authorize an unprotected
        // lifetime. Only a globally disabled IPv6 module or an explicit leak override
        // permits this leg to remain unprotected.
        let v6_protected = match v6_path.as_deref() {
            Some(v6_path) => {
                attempted.push((true, v6_path.to_owned()));
                match engage_family(
                    &context,
                    &rollback,
                    v6_path,
                    tun_if,
                    &v6,
                    &resolvers,
                    guard_forward,
                ) {
                    Ok(()) => true,
                    Err(e) => {
                        log::warn!("kill-switch: IPv6 leg not engaged ({e})");
                        false
                    }
                }
            }
            None => false,
        };
        context.check()?;
        context.check_budget()?;
        rollback.check()?;
        context.protected(true, v6_protected, guard_forward);
        if !v6_protected {
            anyhow::ensure!(
                !guarded.iter().any(|(ipv6, _)| *ipv6),
                "IPv6 kill-switch rebuild failed; prior protection retained by recovery guard"
            );
            let needs_protection = !allow_ipv6_leak && !ipv6_state::globally_disabled();
            context.check()?;
            context.check_budget()?;
            if needs_protection {
                // Roll back the v4 leg we may have armed so a refusal leaves the host exactly
                // as it was — not half-locked to a server the client will never reach.
                if v4_protected {
                    if let Some(path) = v4_path.as_deref() {
                        if let Err(rollback) = rollback.family(path, &chain_for(tun_if)) {
                            anyhow::bail!(
                                "kill-switch: IPv6 protection is unavailable and rollback of the \
                             already-installed IPv4 leg also failed: {rollback}. Manual firewall \
                             cleanup may be required before retrying"
                            );
                        }
                    }
                }
                anyhow::bail!(
                "kill-switch: IPv6 can become active, but ip6tables is unavailable or could not be programmed — refusing to engage a leaking kill-switch. Install/fix ip6tables, disable IPv6 globally, or set allow_ipv6_leak = true to connect and accept the IPv6 leak."
            );
            }
            log::warn!(
            "kill-switch: IPv6 egress is NOT restricted (IPv6 module disabled or allow_ipv6_leak is set)"
        );
        }

        context.check()?;
        context.check_budget()?;
        Ok(())
    })();
    if let Err(error) = result {
        if !attempted.is_empty() {
            let mut failures = Vec::new();
            for (ipv6, path) in attempted {
                match rollback.family(&path, &chain) {
                    Ok(()) => context.protected(ipv6, false, guard_forward),
                    Err(failure) => failures.push(failure.to_string()),
                }
            }
            if !failures.is_empty() {
                return Err(error.context(format!(
                    "kill-switch setup rollback incomplete; ownership retained: {}",
                    failures.join("; "),
                )));
            }
        }
        return Err(error);
    }
    // Commit is separate from rollback: if retiring a guard fails, leave all
    // completed chains in place, including families whose guard is already gone.
    for (_, path) in &guarded {
        rebuild::clear(&context, path, tun_if)?;
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
/// be reconnected to without rebuilding the protection. Re-applying [`prepare_engage`] uses
/// temporary DROP guards and can interrupt availability. Idempotent: never removes the DROP or existing
/// removes stale server allowances only after adding the current ones. A previously
/// armed family must still have its hooks and DROP. Inspection or update errors stop
/// reconnect; the retained rules require recovery. Call it before each attempt.
pub(crate) async fn prepare_refresh(
    server_addr: &str,
    server_port: u16,
    tun_if: &str,
) -> anyhow::Result<impl FnOnce() -> anyhow::Result<()> + Send + 'static> {
    let until = std::time::Instant::now() + OPERATION_BUDGET;
    let context = refresh_context(tun_if, until)?;
    let ips = if context.is_some() {
        resolve_ips(server_addr, server_port, until).await?
    } else {
        Vec::new()
    };
    let tun_if = tun_if.to_owned();
    Ok(move || match context {
        Some(context) => refresh_prepared(&tun_if, until, context, ips),
        None => Ok(()),
    })
}

fn refresh_context(tun_if: &str, until: std::time::Instant) -> anyhow::Result<Option<Context>> {
    anyhow::ensure!(valid_ifname(tun_if), "invalid kill-switch interface name");
    let Some(context) = Context::lookup(tun_if, false)? else {
        return Ok(None);
    };
    let budget = Budget {
        until,
        operation: "server-address refresh",
    };
    let context = context.with_budget(budget);
    context.check_budget()?;
    Ok(Some(context))
}

#[cfg(test)]
fn refresh_until(
    tun_if: &str,
    until: std::time::Instant,
    resolve: impl FnOnce() -> Vec<String>,
) -> anyhow::Result<()> {
    let Some(context) = refresh_context(tun_if, until)? else {
        return Ok(());
    };
    let ips = resolve();
    refresh_prepared(tun_if, until, context, ips)
}

fn refresh_prepared(
    tun_if: &str,
    until: std::time::Instant,
    context: Context,
    ips: Vec<String>,
) -> anyhow::Result<()> {
    let budget = Budget {
        until,
        operation: "server-address refresh",
    };
    context.check()?;
    context.check_budget()?;
    let chain = chain_for(tun_if);
    let _operation = budget.lock(&OPERATION)?;
    context.confirm(tun_if)?;
    context.check_budget()?;
    let mut errors = Vec::new();
    for (want_v6, family) in context.paths() {
        if !family.protected {
            continue;
        }
        let path = family.path;
        // Reconnect may not silently accept removal of the original protection.
        let mut intact = true;
        let mut mandatory = vec![
            vec!["-C", "OUTPUT", "-j", chain.as_str()],
            vec!["-C", chain.as_str(), "-j", "DROP"],
        ];
        if family.guard_forward {
            mandatory.push(vec!["-C", "FORWARD", "-j", chain.as_str()]);
        }
        for rule in mandatory {
            match context.present_checked(&path, &rule) {
                Ok(true) => {}
                Ok(false) => {
                    errors.push(format!(
                        "{path}: kill-switch protection disappeared: {}",
                        rule.join(" ")
                    ));
                    intact = false;
                }
                Err(error) => {
                    errors.push(error.to_string());
                    intact = false;
                }
            }
        }
        if !intact || ips.is_empty() {
            continue;
        }
        let errors_before_add = errors.len();
        for ip in &ips {
            let canon = match ip.parse::<IpAddr>() {
                Ok(p) if p.is_ipv6() == want_v6 => p.to_string(),
                _ => continue,
            };
            let rule = ["-d", canon.as_str(), "-j", "ACCEPT"];
            let mut check: Vec<&str> = vec!["-C", chain.as_str()];
            check.extend_from_slice(&rule);
            match context.present_checked(&path, &check) {
                Ok(true) => continue, // already allowed
                Ok(false) => {}
                Err(error) => {
                    // Unknown is not absence: do not add a rule or retire the old path.
                    errors.push(error.to_string());
                    continue;
                }
            }
            // Insert at the top so it precedes the terminal DROP (appending would
            // land AFTER the DROP and never match).
            let mut add: Vec<&str> = vec!["-I", chain.as_str(), "1"];
            add.extend_from_slice(&rule);
            let add_error = context.ipt(&path, &add).err();
            match context.present_checked(&path, &check) {
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

        // Preserve the previous carrier path if any replacement was not verified.
        if errors.len() != errors_before_add {
            continue;
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
        let stale_addresses = match live_server_allows(&context, &path, &chain) {
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
            let delete_error = context.ipt(&path, &del).err();
            let mut check: Vec<&str> = vec!["-C", chain.as_str()];
            check.extend_from_slice(&rule);
            match context.present_checked(&path, &check) {
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
    context.check()?;
    context.check_budget()?;
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
fn live_server_allows(context: &Context, path: &str, chain: &str) -> anyhow::Result<Vec<String>> {
    let out = context
        .ipt(path, &["-S", chain])
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
/// Without an in-process owner there is no authority to remove a same-name chain.
pub fn disengage(tun_if: &str) -> anyhow::Result<()> {
    disengage_until(tun_if, std::time::Instant::now() + OPERATION_BUDGET)
}

fn disengage_until(tun_if: &str, until: std::time::Instant) -> anyhow::Result<()> {
    anyhow::ensure!(valid_ifname(tun_if), "invalid kill-switch interface name");
    let budget = Budget {
        until,
        operation: "cleanup",
    };
    let _operation = budget.lock(&OPERATION)?;
    let Some(context) = Context::lookup(tun_if, true)? else {
        return Ok(());
    };
    // One budget includes admission and both families. It belongs to this attempt,
    // not to the retained owner: a later explicit cleanup receives a fresh budget.
    let context = context.with_budget(budget);
    context.check_budget()?;
    let chain = chain_for(tun_if);
    let mut errors = Vec::new();
    for (_, family) in context.paths() {
        match teardown_family(&context, &family.path, &chain) {
            Ok(()) => {
                if let Err(error) = rebuild::clear(&context, &family.path, tun_if) {
                    errors.push(error.to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    context.check()?;
    if !errors.is_empty() {
        anyhow::bail!("kill-switch cleanup failed: {}", errors.join("; "))
    }
    context.check_budget()?;
    context.forget(tun_if)?;
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
        let context = Context::fixture();
        engage_family(
            &context,
            &Rollback::new(&context, OPERATION_BUDGET),
            &path,
            tun_if,
            &["203.0.113.7".to_string()],
            &[],
            guard_forward,
        )
    }

    #[test]
    fn failed_inspection_keeps_teardown_failed_without_flushing_chains() {
        let fixture = Ipt::new("cleanup-query-error", &[]);
        let path = fixture.dir.join("iptables");
        std::fs::write(&path, format!(
            "#!/bin/sh\necho \"$*\" >> \"{}\"\necho 'iptables: Permission denied (you must be root)' >&2\nexit 1\n",
            fixture.dir.join("calls.log").display(),
        )).unwrap();
        let error = teardown_family(&Context::fixture(), path.to_str().unwrap(), "QELI_KS_qtest")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Permission denied"), "{error}");
        let calls = fixture.calls();
        assert!(calls.contains("-C OUTPUT"));
        assert!(calls.contains("-C FORWARD"));
        assert!(!calls.contains("-S QELI_KS_qtest"));
        assert!(
            !calls.contains("-D ") && !calls.contains("-F ") && !calls.contains("-X "),
            "{calls}"
        );
    }

    #[test]
    fn only_qeli_jump_targets_allow_missing_chain_diagnostics() {
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

    // These two tests install through the per-family helper, so explicitly bind
    // its fake rules to a live namespace before exercising public cleanup.
    fn bind_cleanup_fixture(ipt: &Ipt) {
        let _operation = operation();
        let context = Context::prepare("qtest").unwrap();
        context.bind("qtest").unwrap();
        context
            .remember(false, ipt.dir.join("iptables").to_str().unwrap())
            .unwrap();
    }

    #[test]
    fn disengage_unhooks_both_chains_it_may_have_installed() {
        let ipt = Ipt::new("off", &[]);
        bind_cleanup_fixture(&ipt);
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
        bind_cleanup_fixture(&ipt);
        engage_test(&ipt, "qtest", false).expect("arm");
        let error = disengage("qtest").unwrap_err();
        assert!(
            error.to_string().contains("still"),
            "a lying delete command must not produce clean-stop success: {error}"
        );
        assert!(
            !ipt.calls().contains("-F "),
            "referenced chain must retain its DROP"
        );
        // The synthetic kernel is about to be discarded with its temporary directory.
        Context::lookup("qtest", true)
            .unwrap()
            .unwrap()
            .forget("qtest")
            .unwrap();
    }
}

#[cfg(test)]
#[path = "killswitch/command_bounds_tests.rs"]
mod command_bounds_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "killswitch/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "killswitch/cleanup_budget_tests.rs"]
mod cleanup_budget_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "killswitch/refresh_budget_tests.rs"]
mod refresh_budget_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "killswitch/setup_budget_tests.rs"]
mod setup_budget_tests;
