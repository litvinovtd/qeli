use crate::config::client::ClientRoutingConfig;
use crate::system_command::Command;
#[cfg(feature = "experimental-roaming")]
use crate::transport_core::path::PreparedPathCandidate;
use crate::transport_core::{NetworkAddressFamily, NetworkPlan};
#[cfg(test)]
use crate::util::is_valid_cidr;
use ipnet::Ipv4Net;
use std::net::IpAddr;

#[path = "route/ownership.rs"]
mod ownership;
#[cfg(target_os = "linux")]
use crate::network_namespace as identity;
use ownership::{delete_spec, route_matches_spec};
#[path = "route/budget.rs"]
mod budget;
#[path = "route/journal.rs"]
mod journal;
#[path = "route/persistent.rs"]
mod persistent;
#[cfg(all(test, feature = "experimental-roaming"))]
use journal::created_by_us_owned;
use journal::forget_created_owned;
#[cfg(test)]
use journal::note_created;
#[cfg(any(test, feature = "experimental-roaming"))]
use journal::recorded_undo;
#[cfg(all(target_os = "linux", feature = "client"))]
pub(crate) use journal::recover_stale;
#[cfg(test)]
use journal::take_created;
pub(crate) use journal::RouteOwner;
#[cfg(feature = "experimental-roaming")]
pub(crate) use journal::RouteScope;
use journal::{
    created_records, ensure_unclaimed, note_created_owned, note_pending, reconcile_pending,
};

#[cfg(test)]
thread_local! {
    static TEST_OWNER: std::cell::RefCell<Option<RouteOwner>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn test_owner() -> RouteOwner {
    TEST_OWNER.with(|slot| slot.borrow().as_ref().expect("route fixture owner").clone())
}
#[cfg(test)]
fn reset_test_owner() {
    TEST_OWNER.with(|slot| *slot.borrow_mut() = None);
    journal::reset_tests();
    TEST_OWNER.with(|slot| *slot.borrow_mut() = Some(RouteOwner::test_new("qtest", 7).unwrap()));
}

// Keep the route transaction's command boundary injectable without changing process PATH.
fn route_command_output(args: &[String]) -> std::io::Result<std::process::Output> {
    let until = budget::deadline();
    budget::check_until(until)?;
    let run = || {
        #[cfg(all(test, feature = "experimental-roaming"))]
        if let Some(output) = candidate_outcome_tests::command_output(args) {
            return output;
        }
        Command::new("ip").args(args).output_until(until)
    };
    let result = run();
    budget::check_until(until)?;
    result
}

#[cfg(all(test, feature = "experimental-roaming"))]
#[path = "route/candidate_outcome_tests.rs"]
mod candidate_outcome_tests;

#[cfg(test)]
pub(crate) static ROUTE_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// The two /1 routes capture the default IPv6 route without replacing ::/0, but they do not
// beat physical aggregate routes commonly present on hosts (notably 2000::/3 and fc00::/7).
// Install the same more-specific guards as the Windows and macOS adapters. Connected LAN
// routes remain more specific by design; route_local/exclude policy decides their treatment.
const IPV6_CAPTURE_PREFIXES: &[&str] = &["::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7"];
const FULL_TUNNEL_ROUTE_METRIC: u32 = 1;

fn full_tunnel_prefixes(family: NetworkAddressFamily) -> &'static [&'static str] {
    match family {
        NetworkAddressFamily::Ipv4 => &["0.0.0.0/1", "128.0.0.0/1"],
        NetworkAddressFamily::Ipv6 => IPV6_CAPTURE_PREFIXES,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PhysicalPath {
    gateway: Option<String>,
    device: String,
}

/// Sanitized physical carrier facts exported to client lifecycle hooks. This is a snapshot
/// from `ip route get` after the authenticated tunnel plan has been installed; it contains
/// no credentials or socket/session material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HookPhysicalPath {
    pub gateway: Option<String>,
    pub device: String,
    pub source: Option<String>,
}

fn family_flag(ipv6: bool) -> Option<&'static str> {
    ipv6.then_some("-6")
}

fn physical_path_query(
    owner: &RouteOwner,
    destination: IpAddr,
    tunnel_if: &str,
    source: Option<IpAddr>,
    output_interface: Option<&str>,
) -> Option<PhysicalPath> {
    let mut args = Vec::<String>::new();
    if let Some(flag) = family_flag(destination.is_ipv6()) {
        args.push(flag.to_string());
    }
    args.extend([
        "route".to_string(),
        "get".to_string(),
        destination.to_string(),
    ]);
    if let Some(source) = source {
        if source.is_ipv4() != destination.is_ipv4() {
            return None;
        }
        args.extend(["from".to_string(), source.to_string()]);
    }
    if let Some(interface) = output_interface {
        args.extend(["oif".to_string(), interface.to_string()]);
    }
    let output = owner.command_output(&args, true).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.lines().next()?.split_whitespace().collect();
    let gateway = fields
        .windows(2)
        .find(|pair| pair[0] == "via")
        .map(|pair| pair[1].to_string());
    let device = fields
        .windows(2)
        .find(|pair| pair[0] == "dev")
        .map(|pair| pair[1].to_string())?;
    (device != tunnel_if).then_some(PhysicalPath { gateway, device })
}

fn physical_path_for(
    owner: &RouteOwner,
    destination: IpAddr,
    source: Option<IpAddr>,
) -> Option<PhysicalPath> {
    physical_path_query(owner, destination, owner.interface(), source, None)
}

/// Resolve the actual non-tunnel carrier interface, next hop and selected source address for
/// hook diagnostics. Kept separate from `PhysicalPath`: routing safety comparisons intentionally
/// compare only the gateway/device pair and must not change when a kernel chooses another valid
/// source address on the same uplink.
pub(crate) fn hook_physical_path_for(
    destination: IpAddr,
    tunnel_if: &str,
    source: Option<IpAddr>,
) -> Option<HookPhysicalPath> {
    let mut command = Command::new("ip");
    if let Some(flag) = family_flag(destination.is_ipv6()) {
        command.args([flag]);
    }
    command.args(["route", "get", &destination.to_string()]);
    if let Some(source) = source {
        if source.is_ipv4() != destination.is_ipv4() {
            return None;
        }
        command.args(["from", &source.to_string()]);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = text.lines().next()?.split_whitespace().collect();
    let value_after = |name: &str| {
        fields
            .windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].to_string())
    };
    let device = value_after("dev")?;
    if device == tunnel_if {
        return None;
    }
    Some(HookPhysicalPath {
        gateway: value_after("via"),
        device,
        source: value_after("src"),
    })
}

#[cfg(feature = "experimental-roaming")]
fn physical_path_for_interface(
    owner: &RouteOwner,
    destination: IpAddr,
    source: IpAddr,
    output_interface: &str,
) -> Option<PhysicalPath> {
    let path = physical_path_query(
        owner,
        destination,
        owner.interface(),
        Some(source),
        Some(output_interface),
    )?;
    (path.device == output_interface).then_some(path)
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxCandidateRoute {
    pub remote: IpAddr,
    pub source: IpAddr,
    pub gateway: Option<String>,
    pub interface: String,
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, Clone)]
pub(crate) struct LinuxPreparedPathRoutes {
    pub generation: u64,
    pub candidate_id: u64,
    owner: RouteScope,
    pub routes: Vec<LinuxCandidateRoute>,
    tunnel_interface: String,
}

/// Resolve every candidate carrier through the exact interface/source pair reported by the
/// platform. PREPARE is deliberately read-only: the bound candidate socket can prove the new
/// path before COMMIT replaces any qeli-owned host route.
#[cfg(all(feature = "experimental-roaming", target_os = "linux"))]
pub(crate) fn prepare_candidate_path_routes(
    candidate: &PreparedPathCandidate,
    owner: &RouteOwner,
) -> anyhow::Result<LinuxPreparedPathRoutes> {
    let interface_index = candidate
        .update
        .interface_index
        .ok_or_else(|| anyhow::anyhow!("Linux candidate path requires an interface index"))?;
    let interface = crate::transport_core::carrier::linux_interface_name(interface_index)?
        .into_string()
        .map_err(|_| anyhow::anyhow!("candidate interface name is not valid UTF-8"))?;
    prepare_candidate_path_routes_on(candidate, owner, &interface)
}

#[cfg(feature = "experimental-roaming")]
fn prepare_candidate_path_routes_on(
    candidate: &PreparedPathCandidate,
    owner: &RouteOwner,
    interface: &str,
) -> anyhow::Result<LinuxPreparedPathRoutes> {
    let _operation = owner.operation()?;
    owner.verify_plan()?;
    if candidate.update.generation != owner.generation() {
        anyhow::bail!("candidate generation does not match route owner");
    }
    let tunnel_if = owner.interface();
    if interface.is_empty() || interface == tunnel_if {
        anyhow::bail!("candidate interface must be a non-tunnel interface");
    }
    let local_addresses = candidate
        .update
        .local_addresses
        .iter()
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid validated candidate source '{value}'"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut routes = Vec::new();
    for remote in candidate.update.compatible_resolved_addresses() {
        let source = local_addresses
            .iter()
            .copied()
            .find(|source| source.is_ipv4() == remote.is_ipv4())
            .ok_or_else(|| {
                anyhow::anyhow!("candidate path has no source address for carrier {remote}")
            })?;
        let path =
            physical_path_for_interface(owner, remote, source, interface).ok_or_else(|| {
                anyhow::anyhow!(
                    "candidate carrier {remote} has no route from {source} through {interface}"
                )
            })?;
        routes.push(LinuxCandidateRoute {
            remote,
            source,
            gateway: path.gateway,
            interface: path.device,
        });
    }
    if routes.is_empty() {
        anyhow::bail!("candidate path has no compatible carrier route");
    }
    Ok(LinuxPreparedPathRoutes {
        generation: candidate.update.generation,
        candidate_id: candidate.candidate_id,
        owner: owner.scope(),
        routes,
        tunnel_interface: tunnel_if.to_string(),
    })
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
enum CandidateRouteMutation {
    None,
    Add {
        undo: Vec<String>,
        journal_was_present: bool,
    },
    Replace {
        previous: Vec<String>,
        previous_undo: Vec<String>,
    },
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
struct CandidateRouteStep {
    route: LinuxCandidateRoute,
    mutation: CandidateRouteMutation,
}

#[cfg(feature = "experimental-roaming")]
fn carrier_route_undo(remote: IpAddr) -> Vec<String> {
    let mut args = Vec::new();
    if remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "del".to_string(), remote.to_string()]);
    args
}

#[cfg(feature = "experimental-roaming")]
fn candidate_route_command(action: &str, route: &LinuxCandidateRoute) -> Vec<String> {
    let mut args = Vec::new();
    if route.remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        action.to_string(),
        route.remote.to_string(),
    ]);
    if let Some(gateway) = &route.gateway {
        args.extend([
            "via".to_string(),
            gateway.clone(),
            "dev".to_string(),
            route.interface.clone(),
        ]);
    } else {
        args.extend([
            "dev".to_string(),
            route.interface.clone(),
            "scope".to_string(),
            "link".to_string(),
        ]);
    }
    args.extend(["src".to_string(), route.source.to_string()]);
    args
}

#[cfg(feature = "experimental-roaming")]
fn exact_route_tokens(
    owner: &RouteOwner,
    remote: IpAddr,
    needs_tunnel: bool,
) -> anyhow::Result<Option<Vec<String>>> {
    let mut args = Vec::<String>::new();
    if remote.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend(["route".to_string(), "show".to_string(), remote.to_string()]);
    let output = owner.command_output(&args, needs_tunnel)?;
    if !output.status.success() {
        anyhow::bail!(
            "could not inspect existing carrier route {remote}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    ownership::parse_route_snapshot(&remote.to_string(), &output.stdout)
}

/// A failed command may have reached the kernel before its result was lost. Only an
/// unchanged snapshot proves this step reversible. Do not undo an unproven add or replace:
/// the route may belong to a concurrent operator. Unknown state stops the generation.
#[cfg(feature = "experimental-roaming")]
fn verify_failed_route_unchanged(
    owner: &RouteOwner,
    remote: IpAddr,
    previous: Option<&[String]>,
) -> anyhow::Result<()> {
    let current = exact_route_tokens(owner, remote, false)?;
    if current.as_deref() != previous {
        anyhow::bail!("failed route mutation for {remote} did not preserve the previous route");
    }
    owner.cancel_intent(&carrier_route_undo(remote))?;
    Ok(())
}

#[cfg(feature = "experimental-roaming")]
fn candidate_route_expected_tokens(route: &LinuxCandidateRoute) -> Vec<String> {
    let mut expected = vec![format!("dev {}", route.interface)];
    if let Some(gateway) = &route.gateway {
        expected.push(format!("via {gateway}"));
    }
    expected
}

#[cfg(feature = "experimental-roaming")]
fn run_ip_owned(owner: &RouteOwner, args: &[String], description: &str) -> anyhow::Result<()> {
    let output = owner.command_output(args, true)?;
    if output.status.success() {
        let spec = delete_spec(args);
        let current =
            ownership::recorded_route_with(&spec, &|raw| owner.command_output(raw, false))?;
        anyhow::ensure!(
            current
                .as_ref()
                .is_some_and(|row| route_matches_spec(&spec, row)),
            "{description}: successful command did not establish the requested route"
        );
        return Ok(());
    }
    anyhow::bail!(
        "{description}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(feature = "experimental-roaming")]
fn rollback_candidate_route_steps(
    owner: &RouteOwner,
    applied: &[CandidateRouteStep],
) -> Vec<String> {
    let mut errors = Vec::new();
    for step in applied.iter().rev() {
        match &step.mutation {
            CandidateRouteMutation::None => {}
            CandidateRouteMutation::Add {
                undo,
                journal_was_present,
            } => match ownership::remove_recorded_route_with(undo, &|args| {
                owner.command_output(args, false)
            }) {
                Ok(removed) => {
                    if !journal_was_present {
                        if let Err(error) = forget_created_owned(owner, undo) {
                            errors.push(error.to_string());
                        }
                    }
                    if !removed {
                        errors.push("candidate route ownership changed during rollback".into());
                    }
                }
                Err(error) => errors.push(error.to_string()),
            },
            CandidateRouteMutation::Replace {
                previous,
                previous_undo,
            } => {
                let expected = delete_spec(&candidate_route_command("add", &step.route));
                if let Err(error) = restore_carrier_snapshot(
                    owner,
                    step.route.remote,
                    previous,
                    previous_undo,
                    Some(&expected),
                ) {
                    errors.push(error.to_string());
                }
            }
        }
    }
    errors
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug)]
struct RetiredCarrierRoute {
    remote: IpAddr,
    undo: Vec<String>,
    previous: Vec<String>,
}

#[cfg(feature = "experimental-roaming")]
fn restore_retired_carrier_routes(
    owner: &RouteOwner,
    retired: &[RetiredCarrierRoute],
) -> Vec<String> {
    let mut errors = Vec::new();
    for route in retired.iter().rev() {
        if let Err(error) =
            restore_carrier_snapshot(owner, route.remote, &route.previous, &route.undo, None)
        {
            errors.push(error.to_string());
        }
    }
    errors
}

fn completion_detail(result: &std::io::Result<std::process::Output>) -> String {
    match result {
        Ok(output) if output.status.success() => {
            "command succeeded but postcondition was not met".into()
        }
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
        Err(error) => error.to_string(),
    }
}

/// Restore only into an absent destination or over our observed candidate. Command status
/// is not evidence of restoration: re-read the complete validated pre-transaction snapshot.
#[cfg(feature = "experimental-roaming")]
fn restore_carrier_snapshot(
    owner: &RouteOwner,
    remote: IpAddr,
    previous: &[String],
    previous_undo: &[String],
    replace_if: Option<&[String]>,
) -> anyhow::Result<()> {
    let current = exact_route_tokens(owner, remote, false)?;
    if current.as_deref() == Some(previous) {
        note_created_owned(owner, previous_undo.to_vec())?;
        return Ok(());
    }
    let action = match current {
        None => "add",
        Some(current) if replace_if.is_some_and(|spec| route_matches_spec(spec, &current)) => {
            "replace"
        }
        Some(_) => {
            forget_created_owned(owner, previous_undo)?;
            anyhow::bail!("carrier route {remote} ownership changed before restoration");
        }
    };
    let mut restore = Vec::new();
    if remote.is_ipv6() {
        restore.push("-6".to_string());
    }
    restore.extend(["route".to_string(), action.to_string()]);
    restore.extend_from_slice(previous);
    let completion = owner.command_output(&restore, false);
    let current = exact_route_tokens(owner, remote, false).map_err(|error| {
        note_pending(owner, previous_undo.to_vec());
        anyhow::anyhow!("could not verify restored carrier route {remote}: {error}")
    })?;
    if current.as_deref() == Some(previous) {
        note_created_owned(owner, previous_undo.to_vec())?;
        return Ok(());
    }
    if current.is_some() {
        note_pending(owner, previous_undo.to_vec());
    }
    // Keep the previous proven journal entry, if any. Do not claim a restore that was
    // not observed, and do not rewrite an unexpected current route to force a match.
    anyhow::bail!(
        "could not restore carrier route {remote}: snapshot differs; {}",
        completion_detail(&completion)
    )
}

#[cfg(feature = "experimental-roaming")]
fn retire_carrier_route(owner: &RouteOwner, route: &RetiredCarrierRoute) -> anyhow::Result<()> {
    if exact_route_tokens(owner, route.remote, true)?.as_ref() != Some(&route.previous) {
        forget_created_owned(owner, &route.undo)?;
        anyhow::bail!("carrier route {} changed before retirement", route.remote);
    }
    let completion = owner.command_output(&route.undo, true);
    match exact_route_tokens(owner, route.remote, true)? {
        None => Ok(()),
        Some(current) => {
            if current != route.previous {
                forget_created_owned(owner, &route.undo)?;
            }
            anyhow::bail!(
                "carrier route {} remains after retirement; {}",
                route.remote,
                completion_detail(&completion)
            )
        }
    }
}

#[cfg(feature = "experimental-roaming")]
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct RouteCommitStateUnknown(String);

#[cfg(feature = "experimental-roaming")]
impl RouteCommitStateUnknown {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[cfg(feature = "experimental-roaming")]
impl LinuxPreparedPathRoutes {
    /// Serialize with this process's setup/cleanup, reject known conflicts before mutation,
    /// and verify applied routes through the ordinary FIB. Failure attempts reverse-order
    /// restoration; an unverified result is fatal for this generation. Kernel/operator
    /// changes are not locked by this process-local transaction.
    #[cfg(test)]
    pub(crate) fn commit(&self, previous_carriers: &[IpAddr]) -> anyhow::Result<()> {
        self.commit_with(previous_carriers, || Ok(()))
    }

    pub(crate) fn commit_with(
        &self,
        previous_carriers: &[IpAddr],
        refresh_platform: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let lease = self.owner.upgrade()?;
        let owner = &lease;
        let _operation = owner.operation().map_err(|error| {
            if owner.identity_failed() || owner.journal_failed() {
                anyhow::Error::new(RouteCommitStateUnknown::new(format!(
                    "route owner identity or journal lost before path commit: {error}"
                )))
            } else {
                error
            }
        })?;
        let result = owner
            .verify_plan()
            .and_then(|()| self.commit_locked(owner, previous_carriers, refresh_platform));
        if owner.identity_failed() || owner.journal_failed() {
            return Err(RouteCommitStateUnknown::new(format!(
                "route owner identity or journal lost during path commit: {}",
                result
                    .err()
                    .map_or_else(|| "final identity check failed".into(), |e| e.to_string())
            ))
            .into());
        }
        if result
            .as_ref()
            .err()
            .is_some_and(|error| error.downcast_ref::<RouteCommitStateUnknown>().is_some())
        {
            owner.stop_admission();
        }
        result
    }

    fn commit_locked(
        &self,
        owner: &RouteOwner,
        previous_carriers: &[IpAddr],
        refresh_platform: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        if self.generation != owner.generation() || self.tunnel_interface != owner.interface() {
            anyhow::bail!("prepared path does not match route owner");
        }
        for route in &self.routes {
            ensure_unclaimed(owner, &carrier_route_undo(route.remote))?;
        }
        // The Linux gateway refresh must not run before this owner's lifetime check
        // or race cleanup through a gap between validation and route commit.
        let refreshed = refresh_platform();
        owner.verify_plan()?;
        refreshed?;

        let desired = self
            .routes
            .iter()
            .map(|route| route.remote)
            .collect::<Vec<_>>();
        let mut retire = Vec::new();
        for remote in previous_carriers.iter().copied() {
            if desired.contains(&remote) {
                continue;
            }
            let key = carrier_route_undo(remote);
            let Some(undo) = recorded_undo(owner, &key) else {
                continue;
            };
            match exact_route_tokens(owner, remote, true)? {
                Some(previous) if route_matches_spec(&undo, &previous) => {
                    retire.push(RetiredCarrierRoute {
                        remote,
                        undo,
                        previous,
                    })
                }
                Some(_) | None => forget_created_owned(owner, &undo)?,
            }
        }
        let mut steps = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            let key = carrier_route_undo(route.remote);
            let recorded = recorded_undo(owner, &key);
            let existing = exact_route_tokens(owner, route.remote, true)?;
            let owned = recorded
                .as_ref()
                .zip(existing.as_ref())
                .is_some_and(|(undo, current)| route_matches_spec(undo, current));
            if recorded.is_some() && !owned {
                forget_created_owned(owner, &key)?;
            }
            let undo = delete_spec(&candidate_route_command("add", route));
            let expected = candidate_route_expected_tokens(route);
            let mutation = match existing {
                Some(previous) if owned => CandidateRouteMutation::Replace {
                    previous,
                    previous_undo: recorded.expect("matched ownership"),
                },
                Some(previous)
                    if route_output_satisfies_all(
                        &previous.join(" "),
                        &expected.iter().map(String::as_str).collect::<Vec<_>>(),
                    ) =>
                {
                    CandidateRouteMutation::None
                }
                Some(_) => {
                    anyhow::bail!(
                        "candidate carrier {} conflicts with an operator-owned route",
                        route.remote
                    )
                }
                None => CandidateRouteMutation::Add {
                    undo,
                    journal_was_present: owned,
                },
            };
            steps.push(CandidateRouteStep {
                route: route.clone(),
                mutation,
            });
        }

        let mut applied = Vec::with_capacity(steps.len());
        for step in steps {
            let result = match &step.mutation {
                CandidateRouteMutation::None => Ok(()),
                CandidateRouteMutation::Add {
                    undo,
                    journal_was_present,
                } => {
                    let args = candidate_route_command("add", &step.route);
                    run_ip_owned(owner, &args, "could not add candidate carrier route").and_then(
                        |()| {
                            if !journal_was_present {
                                note_created_owned(owner, undo.clone())?;
                            }
                            Ok(())
                        },
                    )
                }
                CandidateRouteMutation::Replace { .. } => {
                    let args = candidate_route_command("replace", &step.route);
                    run_ip_owned(owner, &args, "could not replace qeli-owned carrier route")
                        .and_then(|()| note_created_owned(owner, delete_spec(&args)))
                }
            };
            if let Err(error) = result {
                let _rollback = budget::rollback();
                let mut rollback_errors = rollback_candidate_route_steps(owner, &applied);
                let previous = match &step.mutation {
                    CandidateRouteMutation::Replace { previous, .. } => Some(previous.as_slice()),
                    CandidateRouteMutation::Add { .. } | CandidateRouteMutation::None => None,
                };
                if let Err(verification) =
                    verify_failed_route_unchanged(owner, step.route.remote, previous)
                {
                    note_pending(
                        owner,
                        delete_spec(&candidate_route_command("add", &step.route)),
                    );
                    rollback_errors.push(verification.to_string());
                }
                if rollback_errors.is_empty() {
                    return Err(error);
                }
                return Err(RouteCommitStateUnknown::new(format!(
                    "{error}; candidate route rollback failed: {}",
                    rollback_errors.join("; ")
                ))
                .into());
            }
            applied.push(step);

            let route = &applied.last().expect("applied step is present").route;
            let expected = PhysicalPath {
                gateway: route.gateway.clone(),
                device: route.interface.clone(),
            };
            let actual = physical_path_for(owner, route.remote, Some(route.source));
            if actual.as_ref() != Some(&expected) {
                let _rollback = budget::rollback();
                let rollback_errors = rollback_candidate_route_steps(owner, &applied);
                let mut message = format!(
                    "candidate carrier {} failed post-commit FIB verification",
                    route.remote
                );
                if !rollback_errors.is_empty() {
                    message.push_str("; candidate route rollback failed: ");
                    message.push_str(&rollback_errors.join("; "));
                    return Err(RouteCommitStateUnknown::new(message).into());
                }
                anyhow::bail!(message);
            }
        }

        let mut retired = Vec::with_capacity(retire.len());
        for route in retire {
            match retire_carrier_route(owner, &route) {
                Ok(()) => {
                    forget_created_owned(owner, &route.undo)?;
                    // Even a lost/negative command result is a completed retirement when
                    // absence is verified. Include it in rollback if a later route fails.
                    retired.push(route);
                }
                Err(error) => {
                    let _rollback = budget::rollback();
                    let mut rollback_errors = restore_retired_carrier_routes(owner, &retired);
                    rollback_errors.extend(rollback_candidate_route_steps(owner, &applied));
                    if let Err(verification) =
                        verify_failed_route_unchanged(owner, route.remote, Some(&route.previous))
                    {
                        note_pending(owner, route.undo.clone());
                        rollback_errors.push(verification.to_string());
                    }
                    if rollback_errors.is_empty() {
                        anyhow::bail!("could not retire previous carrier route: {error}");
                    }
                    return Err(RouteCommitStateUnknown::new(format!(
                        "could not retire previous carrier route: {error}; route rollback failed: {}",
                        rollback_errors.join("; ")
                    )).into());
                }
            }
        }
        if let Err(error) = owner.verify_plan() {
            let _rollback = budget::rollback();
            let mut errors = restore_retired_carrier_routes(owner, &retired);
            errors.extend(rollback_candidate_route_steps(owner, &applied));
            if errors.is_empty() {
                return Err(error);
            }
            return Err(RouteCommitStateUnknown::new(format!(
                "{error}; final route rollback: {}",
                errors.join("; ")
            ))
            .into());
        }
        Ok(())
    }
}

fn add_tunnel_route(
    owner: &RouteOwner,
    cidr: &str,
    gateway: &str,
    metric: u32,
    is_tap: bool,
) -> anyhow::Result<()> {
    if !crate::util::is_valid_cidr(cidr) {
        anyhow::bail!("invalid network-plan route '{cidr}'");
    }
    let destination = cidr
        .split_once('/')
        .and_then(|(address, _)| address.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid network-plan route '{cidr}'"))?;
    let gateway_ip = gateway
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid network-plan gateway '{gateway}'"))?;
    if destination.is_ipv4() != gateway_ip.is_ipv4() {
        anyhow::bail!("route {cidr} and gateway {gateway} use different families");
    }
    let ipv6 = destination.is_ipv6();
    // An L3 TUN is point-to-point for BOTH families. NetworkPlan v2 deliberately assigns
    // host prefixes (/32 and /128), so `via <gateway>` would require ARP/NDP reachability
    // that does not exist and Linux rejects the IPv4 next hop as invalid. A direct device
    // route sends the inner packet to qeli without neighbour discovery. TAP is real L2 and
    // retains the gateway route.
    let args = tunnel_route_args(ipv6, cidr, gateway, owner.interface(), metric, is_tap);
    install_initial_route(owner, &args)
}

fn tunnel_route_args(
    ipv6: bool,
    cidr: &str,
    gateway: &str,
    ifname: &str,
    metric: u32,
    is_tap: bool,
) -> Vec<String> {
    // Linux maps an IPv6 add with metric 0 to IP6_RT_PRIO_USER (1024).
    // Record the effective priority so verification and deletion use the same identity.
    let metric = if ipv6 && metric == 0 { 1024 } else { metric };
    let mut args = Vec::with_capacity(10);
    if let Some(flag) = family_flag(ipv6) {
        args.push(flag.to_string());
    }
    args.extend(["route".into(), "add".into(), cidr.into()]);
    if is_tap {
        args.extend(["via".into(), gateway.into()]);
    }
    args.extend([
        "dev".into(),
        ifname.into(),
        "metric".into(),
        metric.to_string(),
    ]);
    args
}

fn is_rfc1918_prefix(cidr: &Ipv4Net) -> bool {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        .into_iter()
        .map(|value| value.parse::<Ipv4Net>().expect("built-in RFC1918 CIDR"))
        .any(|root| {
            root.prefix_len() <= cidr.prefix_len()
                && root.contains(&cidr.network())
                && root.contains(&cidr.broadcast())
        })
}

/// A directly connected route is more-specific than the broad RFC1918 NetworkPlan routes.
/// Split it into two child prefixes instead of deleting/replacing the operator-owned route;
/// longest-prefix matching then sends the entire LAN through Qeli while local host routes
/// and later, more-specific exclusions keep their ordinary precedence.
fn route_local_capture_cidrs(
    connected: &[Ipv4Net],
    exclude_cidrs: &[String],
) -> anyhow::Result<Vec<String>> {
    let excludes = exclude_cidrs
        .iter()
        .filter_map(|value| value.parse::<Ipv4Net>().ok())
        .collect::<Vec<_>>();
    let mut captures = std::collections::BTreeSet::new();
    for cidr in connected {
        if cidr.prefix_len() >= 32 || !is_rfc1918_prefix(cidr) {
            continue;
        }
        let child_prefix = cidr.prefix_len() + 1;
        let first_network = cidr.network();
        let second_network =
            std::net::Ipv4Addr::from(u32::from(first_network) | (1u32 << (32 - child_prefix)));
        for network in [first_network, second_network] {
            let child = Ipv4Net::new(network, child_prefix)?;
            if excludes.iter().any(|exclude| {
                exclude.prefix_len() <= child.prefix_len()
                    && exclude.contains(&child.network())
                    && exclude.contains(&child.broadcast())
            }) {
                continue;
            }
            captures.insert((u32::from(child.network()), child.prefix_len()));
        }
    }
    Ok(captures
        .into_iter()
        .map(|(network, prefix)| format!("{}/{}", std::net::Ipv4Addr::from(network), prefix))
        .collect())
}

fn connected_rfc1918_prefixes(owner: &RouteOwner) -> anyhow::Result<Vec<Ipv4Net>> {
    owner.verify_plan()?;
    let ifname = owner.interface();
    let output = owner.command_output(
        &["-4", "-o", "address", "show", "up", "scope", "global"].map(String::from),
        true,
    )?;
    if !output.status.success() {
        anyhow::bail!(
            "could not enumerate connected IPv4 networks for route_local: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|error| {
        anyhow::anyhow!("invalid connected IPv4 address snapshot for route_local: {error}")
    })?;
    let mut prefixes = std::collections::BTreeSet::new();
    for (line_number, line) in text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let index = fields
            .first()
            .and_then(|s| s.strip_suffix(':'))
            .and_then(|s| s.parse::<u32>().ok());
        let device = fields
            .get(1)
            .and_then(|value| value.split('@').next())
            .filter(|s| !s.is_empty());
        let cidr = fields
            .get(3)
            .and_then(|value| value.parse::<Ipv4Net>().ok());
        if index.is_none_or(|index| index == 0)
            || fields.get(2) != Some(&"inet")
            || device.is_none()
            || cidr.is_none()
        {
            anyhow::bail!(
                "invalid connected IPv4 address snapshot for route_local at line {}",
                line_number + 1
            );
        }
        let device = device.expect("validated device");
        let cidr = cidr.expect("validated IPv4 address");
        if device == ifname {
            continue;
        }
        let canonical = Ipv4Net::new(cidr.network(), cidr.prefix_len())?;
        if is_rfc1918_prefix(&canonical) {
            prefixes.insert((u32::from(canonical.network()), canonical.prefix_len()));
        }
    }
    prefixes
        .into_iter()
        .map(|(network, prefix)| {
            Ipv4Net::new(std::net::Ipv4Addr::from(network), prefix).map_err(Into::into)
        })
        .collect()
}
fn connected_tunnel_cidr(address: IpAddr, prefix: u8) -> anyhow::Result<String> {
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv4Addr::from(u32::from(address) & mask),
                prefix
            ))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            Ok(format!(
                "{}/{}",
                std::net::Ipv6Addr::from(u128::from(address) & mask),
                prefix
            ))
        }
        _ => anyhow::bail!("invalid on-link prefix {prefix} for tunnel address {address}"),
    }
}

/// Shared initial route installation for physical bypasses, blackholes and TUN/TAP.
/// A pre-existing matching snapshot is borrowed,
/// never claimed. After an attempted add, only a successful result AND matching snapshot
/// grant ownership; a lost result reserves any possible leftover without delete authority.
fn install_initial_route(owner: &RouteOwner, args: &[String]) -> anyhow::Result<()> {
    let undo = delete_spec(args);
    ensure_unclaimed(owner, &undo)?;
    if let Some(previous) =
        ownership::recorded_route_with(&undo, &|raw| owner.command_output(raw, true))?
    {
        if ownership::route_satisfies_spec(&undo, &previous) {
            return Ok(());
        }
        anyhow::bail!(
            "initial route conflicts with an existing route: ip {}",
            args.join(" ")
        );
    }
    let completion = owner.command_output(args, true);
    let observed = ownership::recorded_route_with(&undo, &|raw| owner.command_output(raw, true));
    match &observed {
        Ok(Some(current))
            if completion.as_ref().is_ok_and(|o| o.status.success())
                && route_matches_spec(&undo, current) =>
        {
            note_created_owned(owner, undo)?;
            return Ok(());
        }
        Ok(None) => owner.cancel_intent(&undo)?, // Proven absence retires durable intent.
        Ok(Some(_)) | Err(_) => note_pending(owner, undo),
    }
    let detail = match observed {
        Ok(None) => "route is absent after initial add".to_string(),
        Ok(Some(_)) => {
            "initial add outcome is not proven; destination remains reserved".to_string()
        }
        Err(error) => format!("could not verify initial route: {error}"),
    };
    anyhow::bail!(
        "ip {}: {detail}; {}",
        args.join(" "),
        completion_detail(&completion)
    )
}

fn add_blackhole_half(owner: &RouteOwner, cidr: &str) -> anyhow::Result<()> {
    let ipv6 = cidr.contains(':');
    let mut args: Vec<String> = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend([
        "route".into(),
        "add".into(),
        "blackhole".into(),
        cidr.into(),
    ]);
    install_initial_route(owner, &args)
}

fn pin_carrier_route(
    owner: &RouteOwner,
    carrier: IpAddr,
    path: &PhysicalPath,
) -> anyhow::Result<()> {
    let ipv6 = carrier.is_ipv6();
    let destination = carrier.to_string();
    let mut args: Vec<String> = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend(["route".into(), "add".into(), destination.clone()]);
    if let Some(gateway) = &path.gateway {
        // Keep the route on the exact interface returned by `ip route get`. The same
        // gateway address can legitimately exist on two links of a multi-homed host.
        args.extend([
            "via".into(),
            gateway.clone(),
            "dev".into(),
            path.device.clone(),
        ]);
    } else {
        args.extend([
            "dev".into(),
            path.device.clone(),
            "scope".into(),
            "link".into(),
        ]);
    }

    install_initial_route(owner, &args)
}

/// Apply the already validated, generation-scoped dual-family network plan on Linux.
/// Every requested family is handled symmetrically; an inactive family is blocked only for
/// full-tunnel mode and only when its explicit leak escape hatch is disabled.
pub(crate) fn setup_network_plan_routes(
    owner: &RouteOwner,
    config: &ClientRoutingConfig,
    plan: &NetworkPlan,
    carrier_addresses: &[IpAddr],
    carrier_local_address: Option<IpAddr>,
    is_tap: bool,
) -> anyhow::Result<()> {
    let _operation = owner.operation()?;
    owner.verify_plan()?;
    if plan.generation != owner.generation() {
        anyhow::bail!("network plan generation does not match route owner");
    }
    let ifname = owner.interface();
    if carrier_addresses.is_empty() {
        anyhow::bail!("network plan has no resolved carrier address to preserve");
    }
    let mut seen_carriers = std::collections::HashSet::new();
    let carrier_paths: Vec<(IpAddr, Option<PhysicalPath>)> = carrier_addresses
        .iter()
        .copied()
        .filter(|address| seen_carriers.insert(*address))
        .map(|address| {
            (
                address,
                physical_path_for(owner, address, carrier_local_address),
            )
        })
        .collect();

    let exclude_paths: Vec<(String, IpAddr, Option<PhysicalPath>)> = config
        .exclude
        .iter()
        .filter_map(|cidr| {
            let address = cidr
                .split_once('/')
                .map(|(address, _)| address)
                .unwrap_or(cidr)
                .parse::<IpAddr>()
                .ok()?;
            Some((
                cidr.clone(),
                address,
                physical_path_for(owner, address, None),
            ))
        })
        .collect();

    let route_local_captures = if config.route_local_networks
        && plan
            .addresses
            .iter()
            .any(|address| address.family == NetworkAddressFamily::Ipv4)
    {
        route_local_capture_cidrs(&connected_rfc1918_prefixes(owner)?, &config.exclude)?
    } else {
        Vec::new()
    };

    // NetworkPlan v2 assigns host prefixes to an L3 TUN to prevent ARP/NDP. Install the
    // negotiated pool prefix explicitly so the server gateway, tunnel DNS and peer/client
    // addresses remain reachable in split-tunnel mode. Android already did this in its
    // Builder; without the equivalent Linux route only full-tunnel defaults happened to
    // cover the pool.
    for assigned in &plan.addresses {
        if assigned.on_link_prefix_len >= assigned.prefix_len {
            continue;
        }
        let address = assigned.address.parse::<IpAddr>().map_err(|_| {
            anyhow::anyhow!("invalid network-plan tunnel address '{}'", assigned.address)
        })?;
        let cidr = connected_tunnel_cidr(address, assigned.on_link_prefix_len)?;
        let gateway = assigned.gateway.as_deref().unwrap_or(&assigned.address);
        add_tunnel_route(owner, &cidr, gateway, 0, is_tap)?;
    }

    if plan.full_tunnel {
        for (carrier, path) in &carrier_paths {
            let path = path.as_ref().ok_or_else(|| {
                anyhow::anyhow!("full tunnel cannot determine a physical path to carrier {carrier}")
            })?;
            pin_carrier_route(owner, *carrier, path)?;
        }

        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        for address in &plan.addresses {
            match address.family {
                NetworkAddressFamily::Ipv4 => has_ipv4 = true,
                NetworkAddressFamily::Ipv6 => has_ipv6 = true,
            }
            let gateway = address.gateway.as_deref().ok_or_else(|| {
                anyhow::anyhow!("full tunnel address '{}' has no gateway", address.address)
            })?;
            for &prefix in full_tunnel_prefixes(address.family) {
                add_tunnel_route(owner, prefix, gateway, FULL_TUNNEL_ROUTE_METRIC, is_tap)?;
            }
        }
        if !has_ipv4 && !config.allow_ipv4_leak {
            add_blackhole_half(owner, "0.0.0.0/1")?;
            add_blackhole_half(owner, "128.0.0.0/1")?;
        }
        if !has_ipv6 && !config.allow_ipv6_leak {
            for &prefix in IPV6_CAPTURE_PREFIXES {
                add_blackhole_half(owner, prefix)?;
            }
        }
    }

    for route in &plan.routes {
        add_tunnel_route(owner, &route.cidr, &route.gateway, route.metric, is_tap)?;
    }

    if !route_local_captures.is_empty() {
        let address = plan
            .addresses
            .iter()
            .find(|address| address.family == NetworkAddressFamily::Ipv4)
            .ok_or_else(|| anyhow::anyhow!("route_local has no IPv4 tunnel address"))?;
        let gateway = address.gateway.as_deref().unwrap_or(&address.address);
        for cidr in &route_local_captures {
            add_tunnel_route(owner, cidr, gateway, 0, is_tap)?;
        }
        log::info!(
            "route_local: installed {} connected-prefix override route(s) without replacing physical routes",
            route_local_captures.len()
        );
    }

    if config.kill_switch && !config.exclude.is_empty() {
        log::warn!("exclude + kill_switch: excluded networks are fail-closed by the firewall");
    }
    for (cidr, address, path) in exclude_paths {
        let Some(path) = path else {
            anyhow::bail!("exclude {cidr}: no physical route is known");
        };
        let ipv6 = address.is_ipv6();
        let PhysicalPath { gateway, device } = path;
        let mut args: Vec<String> = Vec::new();
        if ipv6 {
            args.push("-6".into());
        }
        args.extend(["route".into(), "add".into(), cidr.clone()]);
        if let Some(gateway) = &gateway {
            // Pin the interface as well as the next hop. The same gateway (especially an
            // IPv6 link-local one) may exist on several uplinks of a multi-homed host.
            args.extend(["via".into(), gateway.clone(), "dev".into(), device.clone()]);
        } else {
            args.extend(["dev".into(), device.clone(), "scope".into(), "link".into()]);
        }
        install_initial_route(owner, &args)?;
    }
    if plan.full_tunnel {
        // `ip route add` success is not the final truth when source-policy rules or several
        // tables are present. Ask the FIB again after the /1 capture routes exist and require
        // every carrier to retain the exact physical path resolved before capture.
        for (carrier, expected) in carrier_paths {
            let expected = expected.ok_or_else(|| {
                anyhow::anyhow!("full tunnel has no pre-capture physical path to {carrier}")
            })?;
            let actual = physical_path_for(owner, carrier, carrier_local_address)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "full tunnel carrier {carrier} resolves through {ifname} or has no route after capture"
                    )
                })?;
            if actual != expected {
                anyhow::bail!(
                    "full tunnel carrier {carrier} changed physical path after capture: expected {:?}, got {:?}",
                    expected,
                    actual
                );
            }
        }
    }
    owner.verify_plan()
}

/// Did WE install the route this undo-command would remove?
///
/// The journal records the undo command for everything qeli adds, so asking whether an
/// undo is already queued answers "is this route ours". Used before any delete that is
/// not paired with an add of our own. (Audit 2026-07-27, R6.)
#[cfg(test)]
fn created_by_us(owner: &RouteOwner, args: &[&str]) -> bool {
    recorded_undo(
        owner,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .is_some()
}

/// Legacy IPv4 route applicator retained for its fault-injection regression suite.
/// Production connections use [`setup_network_plan_routes`], which is dual-family.
#[cfg(test)]
pub(crate) fn setup_routes(
    owner: &RouteOwner,
    config: &ClientRoutingConfig,
    gateway: &str,
    ifname: &str,
    server_addr: &str,
) -> anyhow::Result<()> {
    let _operation = owner.operation()?;
    // Install a default route via the tunnel only when explicitly requested.
    // (Previously this also fired when `include` was empty, which silently
    // hijacked the host's default route — and could black-hole SSH.)
    // Physical default gateway toward the server. Used both to pin the server-bypass
    // /32 (full-tunnel) and to route EXCLUDED subnets around the tunnel below.
    let physical_gw = default_gateway(server_addr);

    if config.add_default_gateway || config.mode == "full-tunnel" || config.mode == "all" {
        if let Some(gw) = &physical_gw {
            let output = Command::new("ip")
                .args(["route", "add", server_addr, "via", gw])
                .output()?;
            if output.status.success() {
                note_created(owner, &["route", "del", server_addr, "via", gw]);
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
            let output = Command::new("ip")
                .args(["route", "add", server_addr, "dev", &dev, "scope", "link"])
                .output()?;
            if output.status.success() {
                note_created(
                    owner,
                    &["route", "del", server_addr, "dev", &dev, "scope", "link"],
                );
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
            let output = Command::new("ip")
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
            let shown = Command::new("ip").args(["route", "show", half]).output()?;
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

        // This legacy applicator has only an IPv4 gateway, so it cannot tunnel IPv6.
        // Block rather than leak, matching the current NetworkPlan path's fail-closed
        // contract, and let `allow_ipv6_leak` remain the explicit opt-out.
        if !config.allow_ipv6_leak {
            let mut blocked = 0;
            for &half in IPV6_CAPTURE_PREFIXES {
                let out = Command::new("ip")
                    .args(["-6", "route", "add", "blackhole", half])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        note_created(owner, &["-6", "route", "del", "blackhole", half]);
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
            if blocked == IPV6_CAPTURE_PREFIXES.len() {
                log::info!(
                    "legacy IPv4 route plan: IPv6 blackholed (set \
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
        let output = Command::new("ip")
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
            let output = Command::new("ip")
                .args(["route", "add", subnet, "via", gw])
                .output();
            if let Ok(o) = output {
                if o.status.success() {
                    note_created(owner, &["route", "del", subnet, "via", gw]);
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
            if created_by_us(owner, &["route", "del", subnet]) {
                let _ = Command::new("ip")
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

    Ok(())
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
#[cfg(test)]
fn existing_route_satisfies(v6: bool, cidr: &str, want: &str) -> Option<bool> {
    existing_route_satisfies_all(v6, cidr, &[want])
}

#[cfg(test)]
fn existing_route_satisfies_all(v6: bool, cidr: &str, wants: &[&str]) -> Option<bool> {
    let mut args: Vec<&str> = Vec::new();
    if v6 {
        args.push("-6");
    }
    args.extend_from_slice(&["route", "show", cidr]);
    let out = Command::new("ip").args(&args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return None;
    }
    Some(route_output_satisfies_all(&text, wants))
}

/// Require every expected token sequence on one concrete route. Substring matching made
/// `dev eth0` accept `dev eth01`, and searching the complete multi-line output could combine
/// a gateway from one route with an interface from another.
#[cfg(any(test, feature = "experimental-roaming"))]
fn route_output_satisfies_all(output: &str, wants: &[&str]) -> bool {
    output.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        wants.iter().all(|want| {
            let expected: Vec<&str> = want.split_whitespace().collect();
            !expected.is_empty()
                && fields
                    .windows(expected.len())
                    .any(|window| window == expected.as_slice())
        })
    })
}

/// The physical default gateway used to reach `server_addr` (parsed from
/// `ip route get`). `None` if it can't be determined (e.g. an on-link server).
#[cfg(test)]
fn default_gateway(server_addr: &str) -> Option<String> {
    let out = Command::new("ip")
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
#[cfg(test)]
fn physical_dev_for(server_addr: &str) -> Option<String> {
    let out = Command::new("ip")
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

#[cfg(test)]
fn cleanup_routes(owner: &RouteOwner) -> anyhow::Result<()> {
    cleanup_routes_with_checks(owner, || Ok(()), || Ok(()))
}

#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub(crate) fn cleanup_routes_for_tun(
    owner: &RouteOwner,
    tun: &crate::tun::iface::TunInterface,
) -> anyhow::Result<()> {
    cleanup_routes_with_checks(owner, || owner.verify_namespace(), || owner.verify_tun(tun))
}

// Each command needs fresh evidence, including queries whose result can release a
// reservation. Checks are not atomic with iproute2; privileged external races remain.
fn cleanup_routes_with_checks(
    owner: &RouteOwner,
    namespace: impl Fn() -> anyhow::Result<()>,
    tunnel: impl Fn() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let _operation = owner.cleanup_operation()?;
    let ifname = owner.interface();
    let command = |args: &[String], needs_tunnel: bool| {
        namespace().map_err(std::io::Error::other)?;
        owner.verify_durable().map_err(std::io::Error::other)?;
        if needs_tunnel {
            tunnel().map_err(std::io::Error::other)?;
        }
        route_command_output(args)
    };
    let is_tunnel = |spec: &[String]| {
        spec.windows(2)
            .any(|pair| pair[0] == "dev" && pair[1] == ifname)
    };
    // Physical bypasses remain independently removable if the original namespace is
    // proven. A lost/renamed TUN must not authorize commands on a replacement name.
    let mut errors = Vec::new();
    for args in created_records(owner) {
        match ownership::remove_recorded_route_with(&args, &|raw| command(raw, is_tunnel(&args))) {
            Ok(removed) => {
                if !removed {
                    log::info!(
                        "owned route changed; preserving replacement: ip {}",
                        args.join(" ")
                    );
                }
                if let Err(error) = forget_created_owned(owner, &args) {
                    errors.push(error.to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }

    let errors_before_flush = errors.len();

    // The interface belongs to this owner. Verify each family independently, including
    // when completion was lost; an error in one family must not skip the other.
    for ipv6 in [false, true] {
        let mut args = Vec::new();
        if ipv6 {
            args.push("-6".to_string());
        }
        args.extend(["route", "flush", "dev", ifname].map(str::to_string));
        let completion = command(&args, true);
        if let Err(error) =
            ownership::verify_interface_routes_absent_with(ifname, ipv6, &|raw| command(raw, true))
        {
            errors.push(format!(
                "ip {}: {error}; {}",
                args.join(" "),
                completion_detail(&completion)
            ));
        }
    }

    let interface_flushed = errors.len() == errors_before_flush;
    // Pending never grants a destination delete. The independently owned interface can
    // still be flushed; reconcile afterwards so its now-absent routes release reservations.
    errors.extend(reconcile_pending(owner, |spec| {
        ownership::recorded_route_with(spec, &|raw| command(raw, is_tunnel(spec)))
    }));
    if let Err(error) = budget::check() {
        errors.push(error.to_string());
    }
    if let Err(error) = owner.reconcile_durable() {
        errors.push(error.to_string());
    }
    owner.cleanup_result(!errors.is_empty(), interface_flushed);
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("route cleanup failed: {}", errors.join("; "))
    }
}

#[cfg(all(test, target_os = "linux"))]
fn route_is_already_absent(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    [
        "no such process",
        "no such device",
        "cannot find device",
        "does not exist",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        connected_tunnel_cidr, full_tunnel_prefixes, route_local_capture_cidrs,
        route_output_satisfies_all, tunnel_route_args, IPV6_CAPTURE_PREFIXES,
    };
    use crate::transport_core::network::planned_pushed_routes;
    use crate::util::{is_valid_cidr, is_valid_gateway};
    use std::net::IpAddr;

    #[test]
    fn network_plan_tun_routes_are_direct_for_both_families() {
        assert_eq!(
            tunnel_route_args(false, "0.0.0.0/1", "10.9.0.1", "qeli0", 100, false),
            ["route", "add", "0.0.0.0/1", "dev", "qeli0", "metric", "100"]
        );
        assert_eq!(
            tunnel_route_args(true, "2001:db8::/32", "fd71:e1::1", "qeli0", 7, false),
            [
                "-6",
                "route",
                "add",
                "2001:db8::/32",
                "dev",
                "qeli0",
                "metric",
                "7"
            ]
        );
        assert_eq!(
            tunnel_route_args(false, "10.20.0.0/16", "10.9.0.1", "tap0", 9, true),
            [
                "route",
                "add",
                "10.20.0.0/16",
                "via",
                "10.9.0.1",
                "dev",
                "tap0",
                "metric",
                "9"
            ]
        );
    }

    #[test]
    fn ipv6_capture_routes_override_global_and_ula_physical_aggregates() {
        assert_eq!(
            full_tunnel_prefixes(super::NetworkAddressFamily::Ipv6),
            IPV6_CAPTURE_PREFIXES
        );
        assert_eq!(
            IPV6_CAPTURE_PREFIXES,
            &["::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7"]
        );
    }

    #[test]
    fn connected_tunnel_prefix_is_canonical_for_ipv4_and_ipv6() {
        assert_eq!(
            connected_tunnel_cidr("10.9.0.27".parse::<IpAddr>().unwrap(), 24).unwrap(),
            "10.9.0.0/24"
        );
        assert_eq!(
            connected_tunnel_cidr("fd71:e1:20::beef".parse::<IpAddr>().unwrap(), 64).unwrap(),
            "fd71:e1:20::/64"
        );
        assert!(connected_tunnel_cidr("10.9.0.27".parse().unwrap(), 64).is_err());
    }

    #[test]
    fn route_local_overrides_connected_rfc1918_without_replacing_operator_routes() {
        let connected = [
            "192.168.1.27/24".parse::<ipnet::Ipv4Net>().unwrap(),
            "10.8.1.4/16".parse::<ipnet::Ipv4Net>().unwrap(),
            "203.0.113.4/24".parse::<ipnet::Ipv4Net>().unwrap(),
            "10.9.0.7/32".parse::<ipnet::Ipv4Net>().unwrap(),
        ];
        assert_eq!(
            route_local_capture_cidrs(&connected, &[]).unwrap(),
            [
                "10.8.0.0/17",
                "10.8.128.0/17",
                "192.168.1.0/25",
                "192.168.1.128/25",
            ]
        );
        assert_eq!(
            route_local_capture_cidrs(
                &connected[0..1],
                &["192.168.1.0/25".into(), "192.168.1.192/26".into()],
            )
            .unwrap(),
            ["192.168.1.128/25"]
        );
    }
    #[test]
    fn existing_route_match_is_token_exact_and_stays_on_one_route() {
        assert!(route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth0 metric 5\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
        assert!(!route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth01 metric 5\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
        assert!(!route_output_satisfies_all(
            "192.0.2.10 via 10.0.0.1 dev eth1\n192.0.2.10 via 10.0.0.2 dev eth0\n",
            &["via 10.0.0.1", "dev eth0"]
        ));
    }

    #[test]
    fn pushed_route_plan_preserves_gateway_and_metric_after_policy_filtering() {
        let json = r#"[
            {"cidr":"192.0.2.0/24","gateway":"10.0.0.9","metric":7},
            {"cidr":"0.0.0.0/1","gateway":"10.0.0.1","metric":1},
            {"cidr":"not-a-route","gateway":"10.0.0.1"}
        ]"#;
        let routes = planned_pushed_routes(json, "10.0.0.1").unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].cidr, "192.0.2.0/24");
        assert_eq!(routes[0].gateway, "10.0.0.9");
        assert_eq!(routes[0].metric, 7);
    }

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
    use std::sync::MutexGuard;

    // Share serialization with the transaction fixtures: both use the ownership journal.

    struct Shim {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        old_path: String,
    }

    impl Shim {
        /// `fail_on` — argument-line substrings that make the fake `ip` exit non-zero
        /// with `stderr_text`. Everything else succeeds.
        fn new(tag: &str, fail_on: &[&str], stderr_text: &str) -> Shim {
            Self::new_with_route_show(tag, fail_on, stderr_text, Some("shown dev qtest"))
        }

        #[cfg(feature = "experimental-roaming")]
        fn new_with_route_show_cases(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show_cases: &[(&str, Option<&str>)],
            route_show: Option<&str>,
        ) -> Shim {
            Self::build(tag, fail_on, stderr_text, route_show_cases, route_show)
        }

        fn new_with_route_show(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show: Option<&str>,
        ) -> Shim {
            Self::build(tag, fail_on, stderr_text, &[], route_show)
        }

        fn build(
            tag: &str,
            fail_on: &[&str],
            stderr_text: &str,
            route_show_cases: &[(&str, Option<&str>)],
            route_show: Option<&str>,
        ) -> Shim {
            let guard = ROUTE_TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-shim-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let state = dir.join("routes");
            std::fs::create_dir_all(&state).unwrap();
            for route in route_show
                .into_iter()
                .chain(route_show_cases.iter().filter_map(|(_, value)| *value))
            {
                let tokens = route.split_whitespace().collect::<Vec<_>>();
                let Some(destination) =
                    tokens.get(usize::from(tokens.first() == Some(&"blackhole")))
                else {
                    continue;
                };
                if destination.parse::<IpAddr>().is_ok()
                    || destination.parse::<ipnet::IpNet>().is_ok()
                {
                    let family = if destination.contains(':') { 6 } else { 4 };
                    let key = destination.replace(['/', ':'], "_");
                    std::fs::write(state.join(format!("{family}-{key}")), route).unwrap();
                }
            }
            let mut script = format!(
                r#"#!/bin/sh
echo "$@" >> '{log}'
original="$*"
family=4
if [ "$1" = "-6" ]; then family=6; shift; fi
destination="$3"
if [ "$3" = "blackhole" ] || [ "$3" = "exact" ]; then destination="$4"; fi
key=$(printf '%s' "$destination" | tr '/:' '__')
record='{state}/'"$family-$key"
route_state='{state}'
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "dev" ]; then
  for entry in "$route_state"/"$family-"*; do
    if [ -s "$entry" ]; then
      case " $(cat "$entry") " in
        *" dev $4 "*) cat "$entry"; printf '\n';;
      esac
    fi
  done
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "exact" ]; then
  if [ -f "$record" ]; then cat "$record"; fi
  exit 0
fi
# Carrier snapshots track mutable host state. Keep legacy subnet FIB stubs for lie tests.
case "$destination" in
  */*) ;;
  *) if [ "$1" = "route" ] && [ "$2" = "show" ] && [ -f "$record" ]; then
       cat "$record"
       exit 0
     fi;;
esac
case "$original" in
"#,
                log = log.display(),
                state = state.display(),
            );
            for cond in fail_on {
                // An "already absent" fixture models an actual absent route too.
                let absent = if route_is_already_absent(stderr_text) {
                    "if [ \"$2\" = \"del\" ]; then : > \"$record\"; fi; "
                } else {
                    ""
                };
                script.push_str(&format!(
                    "  *\"{cond}\"*) {absent}echo '{stderr_text}' >&2; exit 2;;\n"
                ));
            }
            script.push_str(
                "  *\"route get\"*) echo '1.2.3.4 via 10.0.0.254 dev eth0 src 10.0.0.5'; exit 0;;\n",
            );
            for (pattern, result) in route_show_cases {
                if let Some(result) = result {
                    script.push_str(&format!("  *\"{pattern}\"*) echo '{result}'; exit 0;;\n"));
                } else {
                    script.push_str(&format!("  *\"{pattern}\"*) exit 0;;\n"));
                }
            }
            if let Some(route_show) = route_show {
                script.push_str(&format!(
                    "  *\"route show\"*) echo '{route_show}'; exit 0;;\n"
                ));
            } else {
                script.push_str("  *\"route show\"*) exit 0;;\n");
            }
            script.push_str(
                r#"esac
if [ "$1" = "route" ]; then
  case "$2" in
    add|replace) shift 2; printf '%s\n' "$*" > "$record";;
    del) : > "$record";;
    flush)
      for entry in "$route_state"/"$family-"*; do
        if [ -s "$entry" ]; then
          case " $(cat "$entry") " in
            *" dev $4 "*) : > "$entry";;
          esac
        fi
      done;;
  esac
fi
exit 0
"#,
            );

            let bin = dir.join("ip");
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            // The ownership journal is process-global and deliberately SURVIVES a failed
            // setup (those routes were created and still need removing later). Across
            // tests that means one scenario inherits another's entries, so start clean.
            reset_test_owner();

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
        let err = setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "qtest",
            "1.2.3.4",
        )
        .unwrap_err();
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
        let err = setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "other0",
            "1.2.3.4",
        )
        .unwrap_err();
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
        let err = setup_routes(&test_owner(), &cfg, "10.0.0.1", "qtest", "1.2.3.4").unwrap_err();
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
            setup_routes(&test_owner(), &cfg, "10.0.0.1", "qtest", "1.2.3.4").is_ok(),
            "a failed exclude bypass must not break the connection"
        );
    }

    #[test]
    fn cleanup_removes_the_bypass_route_we_created() {
        let shim = Shim::new("own", &[], "");
        setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "qtest",
            "1.2.3.4",
        )
        .unwrap();
        cleanup_routes(&test_owner()).unwrap();
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
        setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "qtest",
            "1.2.3.4",
        )
        .unwrap();
        cleanup_routes(&test_owner()).unwrap();
        let calls = shim.calls();
        assert!(
            !calls.contains("route del 1.2.3.4"),
            "a route that already existed is not ours to delete:\n{calls}"
        );
    }

    #[test]
    fn cleanup_surfaces_failure_and_retains_ownership_for_retry() {
        let shim = Shim::new(
            "cleanup-fail",
            &["route del 1.2.3.4"],
            "RTNETLINK answers: Operation not permitted",
        );
        setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "qtest",
            "1.2.3.4",
        )
        .unwrap();

        let first = cleanup_routes(&test_owner()).unwrap_err();
        assert!(first.to_string().contains("Operation not permitted"));
        assert!(cleanup_routes(&test_owner()).is_err());

        let calls = shim.calls();
        assert_eq!(
            calls.matches("route del 1.2.3.4").count(),
            2,
            "a failed owned-route deletion must be retried:\n{calls}"
        );
    }

    #[test]
    fn cleanup_treats_an_already_absent_owned_route_as_success() {
        let shim = Shim::new(
            "cleanup-absent",
            &["route del 1.2.3.4"],
            "RTNETLINK answers: No such process",
        );
        setup_routes(
            &test_owner(),
            &full_tunnel(),
            "10.0.0.1",
            "qtest",
            "1.2.3.4",
        )
        .unwrap();

        cleanup_routes(&test_owner()).unwrap();
        cleanup_routes(&test_owner()).unwrap();

        let calls = shim.calls();
        assert_eq!(
            calls.matches("route del 1.2.3.4").count(),
            1,
            "an already absent route must leave the ownership journal:\n{calls}"
        );
    }

    #[test]
    fn cleanup_surfaces_a_failed_tun_route_flush() {
        let _shim = Shim::new_with_route_show(
            "cleanup-flush",
            &["route flush dev qtest"],
            "RTNETLINK answers: Operation not permitted",
            Some("10.88.0.0/24 dev qtest"),
        );

        let err = cleanup_routes(&test_owner()).unwrap_err();
        assert!(err.to_string().contains("route flush dev qtest"));
        assert!(err.to_string().contains("Operation not permitted"));
    }

    #[cfg(feature = "experimental-roaming")]
    fn prepared_candidate() -> PreparedPathCandidate {
        PreparedPathCandidate {
            candidate_id: 41,
            update: crate::transport_core::path::PathUpdate {
                generation: 7,
                update_id: 3,
                platform_path_id: "linux:eth0".to_string(),
                reason: crate::transport_core::path::PathUpdateReason::ManualProbe,
                network_token: None,
                interface_index: Some(2),
                local_addresses: vec!["192.0.2.10".to_string(), "2001:db8::10".to_string()],
                resolved_addresses: vec![
                    crate::transport_core::path::PathResolution {
                        address: "198.51.100.20".to_string(),
                        ttl_secs: 30,
                    },
                    crate::transport_core::path::PathResolution {
                        address: "2001:db8::20".to_string(),
                        ttl_secs: 30,
                    },
                ],
                flags: crate::transport_core::path::PathUpdateFlags::default(),
            },
        }
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_prepare_is_read_only_and_queries_exact_source_and_interface() {
        let shim = Shim::new("candidate-prepare", &[], "");
        let candidate = prepared_candidate();
        let prepared = prepare_candidate_path_routes_on(&candidate, &test_owner(), "eth0").unwrap();

        assert_eq!(prepared.generation, 7);
        assert_eq!(prepared.candidate_id, 41);
        assert_eq!(prepared.routes.len(), 2);
        assert_eq!(
            prepared.routes[0].remote,
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prepared.routes[0].source,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(prepared.routes[0].interface, "eth0");
        assert_eq!(prepared.routes[0].gateway.as_deref(), Some("10.0.0.254"));
        assert_eq!(
            prepared.routes[1].remote,
            "2001:db8::20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            prepared.routes[1].source,
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );

        let calls = shim.calls();
        assert!(calls.contains("route get 198.51.100.20 from 192.0.2.10 oif eth0"));
        assert!(calls.contains("-6 route get 2001:db8::20 from 2001:db8::10 oif eth0"));
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_prepare_rejects_tunnel_or_mismatched_fib_interface() {
        let _shim = Shim::new("candidate-wrong-interface", &[], "");
        let candidate = prepared_candidate();
        assert!(prepare_candidate_path_routes_on(
            &candidate,
            &RouteOwner::test_new("eth0", 7).unwrap(),
            "eth0"
        )
        .is_err());
        let error = prepare_candidate_path_routes_on(&candidate, &test_owner(), "wlan0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("through wlan0"));
    }

    #[cfg(feature = "experimental-roaming")]
    fn ipv4_candidate() -> PreparedPathCandidate {
        let mut candidate = prepared_candidate();
        candidate.update.local_addresses.truncate(1);
        candidate.update.resolved_addresses.truncate(1);
        candidate
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_adds_only_missing_routes_and_journals_ownership() {
        let shim = Shim::new_with_route_show("candidate-add", &[], "", None);
        let prepared =
            prepare_candidate_path_routes_on(&prepared_candidate(), &test_owner(), "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("route add 198.51.100.20 via 10.0.0.254 dev eth0 src 192.0.2.10"));
        assert!(
            calls.contains("-6 route add 2001:db8::20 via 10.0.0.254 dev eth0 src 2001:db8::10")
        );
        assert!(created_by_us_owned(
            &test_owner(),
            &carrier_route_undo("198.51.100.20".parse::<IpAddr>().unwrap())
        ));
        assert!(created_by_us_owned(
            &test_owner(),
            &carrier_route_undo("2001:db8::20".parse::<IpAddr>().unwrap())
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_rejects_operator_conflict_before_mutation() {
        let shim = Shim::new_with_route_show(
            "candidate-conflict",
            &[],
            "",
            Some("198.51.100.20 dev qtest"),
        );
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), &test_owner(), "eth0").unwrap();
        let error = prepared.commit(&[]).unwrap_err().to_string();
        assert!(error.contains("operator-owned"));

        let calls = shim.calls();
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_preserves_matching_operator_route_without_claiming_it() {
        let shim = Shim::new_with_route_show(
            "candidate-operator-match",
            &[],
            "",
            Some("198.51.100.20 via 10.0.0.254 dev eth0"),
        );
        let remote = "198.51.100.20".parse::<IpAddr>().unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), &test_owner(), "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        let calls = shim.calls();
        assert!(!calls.contains(" route add "));
        assert!(!calls.contains(" route replace "));
        assert!(!calls.contains(" route del "));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(remote)
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_replaces_only_a_qeli_owned_route() {
        let shim = Shim::new_with_route_show(
            "candidate-replace",
            &[],
            "",
            Some("198.51.100.20 via 192.0.2.1 dev old0"),
        );
        let remote = "198.51.100.20".parse::<IpAddr>().unwrap();
        note_created_owned(
            &test_owner(),
            [
                carrier_route_undo(remote),
                vec![
                    "via".into(),
                    "192.0.2.1".into(),
                    "dev".into(),
                    "old0".into(),
                ],
            ]
            .concat(),
        )
        .unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&ipv4_candidate(), &test_owner(), "eth0").unwrap();
        prepared.commit(&[]).unwrap();

        assert!(shim
            .calls()
            .contains("route replace 198.51.100.20 via 10.0.0.254 dev eth0 src 192.0.2.10"));
        assert!(created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(remote)
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn candidate_commit_rolls_back_prior_add_when_a_later_family_fails() {
        let shim = Shim::new_with_route_show(
            "candidate-rollback",
            &["-6 route add 2001:db8::20"],
            "RTNETLINK answers: network unreachable",
            None,
        );
        let first = "198.51.100.20".parse::<IpAddr>().unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&prepared_candidate(), &test_owner(), "eth0").unwrap();
        let error = prepared.commit(&[]).unwrap_err().to_string();
        assert!(error.contains("network unreachable"));

        let calls = shim.calls();
        assert!(calls.contains("route del 198.51.100.20"));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(first)
        ));
    }

    #[cfg(feature = "experimental-roaming")]
    fn ipv6_candidate() -> PreparedPathCandidate {
        let mut candidate = prepared_candidate();
        candidate.update.local_addresses.remove(0);
        candidate.update.resolved_addresses.remove(0);
        candidate
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn family_commit_retires_the_previous_qeli_owned_carrier() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-retire-family",
            &[],
            "",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev old0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        note_created_owned(
            &test_owner(),
            [
                carrier_route_undo(old),
                vec![
                    "via".into(),
                    "192.0.2.1".into(),
                    "dev".into(),
                    "old0".into(),
                    "src".into(),
                    "192.0.2.2".into(),
                ],
            ]
            .concat(),
        )
        .unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), &test_owner(), "eth0").unwrap();
        prepared.commit(&[old]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("-6 route add 2001:db8::20"));
        assert!(calls.contains("route del 198.51.100.20"));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(old)
        ));
        assert!(created_by_us_owned(&test_owner(), &carrier_route_undo(new)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn family_commit_does_not_retire_an_operator_owned_previous_carrier() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-keep-operator-family",
            &[],
            "",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev operator0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), &test_owner(), "eth0").unwrap();
        prepared.commit(&[old]).unwrap();

        let calls = shim.calls();
        assert!(calls.contains("-6 route add 2001:db8::20"));
        assert!(
            !calls.contains("route del 198.51.100.20"),
            "an operator-owned previous route must not be retired:\n{calls}"
        );
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(old)
        ));
        assert!(created_by_us_owned(&test_owner(), &carrier_route_undo(new)));
    }

    #[cfg(feature = "experimental-roaming")]
    #[test]
    fn failed_old_carrier_retirement_rolls_back_the_new_family() {
        let old = "198.51.100.20".parse::<IpAddr>().unwrap();
        let new = "2001:db8::20".parse::<IpAddr>().unwrap();
        let shim = Shim::new_with_route_show_cases(
            "candidate-retire-rollback",
            &["route del 198.51.100.20"],
            "RTNETLINK answers: operation not permitted",
            &[
                (
                    "route show 198.51.100.20",
                    Some("198.51.100.20 via 192.0.2.1 dev old0 src 192.0.2.2"),
                ),
                ("-6 route show 2001:db8::20", None),
            ],
            None,
        );
        note_created_owned(
            &test_owner(),
            [
                carrier_route_undo(old),
                vec![
                    "via".into(),
                    "192.0.2.1".into(),
                    "dev".into(),
                    "old0".into(),
                    "src".into(),
                    "192.0.2.2".into(),
                ],
            ]
            .concat(),
        )
        .unwrap();
        let prepared =
            prepare_candidate_path_routes_on(&ipv6_candidate(), &test_owner(), "eth0").unwrap();
        let error = prepared.commit(&[old]).unwrap_err().to_string();

        assert!(error.contains("could not retire previous carrier route"));
        assert!(shim.calls().contains("-6 route del 2001:db8::20"));
        assert!(created_by_us_owned(&test_owner(), &carrier_route_undo(old)));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(new)
        ));
    }
}

#[cfg(all(test, target_os = "linux", any(feature = "client", feature = "server")))]
#[path = "route/identity_linux_tests.rs"]
mod identity_linux_tests;
