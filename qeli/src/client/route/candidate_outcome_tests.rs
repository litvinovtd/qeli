use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use std::sync::{Arc, Mutex, MutexGuard};

type Executor = Box<dyn FnMut(&[String]) -> io::Result<Output>>;
thread_local! {
    static EXECUTOR: RefCell<Option<Executor>> = RefCell::new(None);
}

pub(super) fn command_output(args: &[String]) -> Option<io::Result<Output>> {
    EXECUTOR.with(|executor| executor.borrow_mut().as_mut().map(|run| run(args)))
}

fn output(success: bool, text: &str) -> io::Result<Output> {
    Ok(Output {
        status: ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: if success {
            text.as_bytes().to_vec()
        } else {
            Vec::new()
        },
        stderr: if success {
            Vec::new()
        } else {
            text.as_bytes().to_vec()
        },
    })
}

#[derive(Clone, Copy)]
enum Fault {
    Reject,
    ApplyThenFail,
    ApplyThenIo(io::ErrorKind),
    UnchangedIo,
    Unreadable,
    Ambiguous,
    Foreign,
}

struct Kernel {
    routes: BTreeMap<String, Vec<String>>,
    calls: Vec<Vec<String>>,
    fail: Option<(String, String, Fault)>,
    fired: bool,
    fail_rollback: bool,
    extra_snapshot: Option<String>,
    query_error: bool,
    flush_error: bool,
    post_delete_query_error: bool,
    lie_delete: Option<bool>,
    race_before_delete: Option<(String, Vec<String>)>,
    operator_change_on_failure: Option<(String, Vec<String>)>,
}
impl Kernel {
    fn run(&mut self, raw: &[String]) -> io::Result<Output> {
        self.calls.push(raw.to_vec());
        if raw == ["-o", "link", "show"] {
            return output(false, "fixture link inventory unavailable");
        }
        let args = if raw.first().is_some_and(|s| s == "-6") {
            &raw[1..]
        } else {
            raw
        };
        assert_eq!(args[0], "route");
        let verb = args[1].as_str();
        if verb == "flush" || (verb == "show" && args.get(2).is_some_and(|s| s == "dev")) {
            let ipv6 = raw[0] == "-6";
            let interface = &args[3];
            let matching = |route: &Vec<String>| {
                route.iter().any(|s| s.contains(':')) == ipv6
                    && route
                        .windows(2)
                        .any(|p| p[0] == "dev" && &p[1] == interface)
            };
            if verb == "flush" {
                if self.flush_error {
                    return output(false, "fixture flush result");
                }
                self.routes.retain(|_, route| !matching(route));
                return output(true, "");
            }
            if self.query_error {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            return output(
                true,
                &self
                    .routes
                    .values()
                    .filter(|r| matching(r))
                    .map(|r| r.join(" "))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        let remote = &args[if (verb == "show" && args[2] == "exact") || args[2] == "blackhole" {
            3
        } else {
            2
        }];
        if verb == "show" {
            if self.query_error {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let current = self
                .routes
                .get(remote)
                .map(|r| r.join(" "))
                .unwrap_or_default();
            if let Some(extra) = &self.extra_snapshot {
                return output(true, &format!("{current}\n{extra}"));
            }
            if self.fired && self.fail.as_ref().is_some_and(|(_, ip, _)| ip == remote) {
                match self.fail.as_ref().unwrap().2 {
                    Fault::Unreadable => return Err(io::ErrorKind::BrokenPipe.into()),
                    Fault::Ambiguous => {
                        return output(true, &format!("{current}\n{remote} dev other0"))
                    }
                    _ => {}
                }
            }
            return output(true, &current);
        }
        if verb == "get" {
            return output(
                true,
                &self.routes.get(remote).expect("FIB route exists").join(" "),
            );
        }
        assert!(matches!(verb, "add" | "replace" | "del"));
        let fail = !self.fired
            && self
                .fail
                .as_ref()
                .is_some_and(|(action, ip, _)| action == verb && ip == remote);
        if fail {
            self.fired = true;
            if let Some((ip, replacement)) = self.operator_change_on_failure.take() {
                self.routes.insert(ip, replacement);
            }
            match self.fail.as_ref().unwrap().2 {
                Fault::Reject | Fault::Unreadable | Fault::Ambiguous => {
                    return output(false, "fixture rejected")
                }
                Fault::UnchangedIo => return Err(io::ErrorKind::BrokenPipe.into()),
                Fault::Foreign => {
                    self.routes.insert(
                        remote.clone(),
                        vec![remote.clone(), "dev".into(), "operator0".into()],
                    );
                    return output(false, "fixture concurrent operator change");
                }
                _ => {}
            }
        } else if self.fired && self.fail_rollback && verb == "del" {
            return output(false, "fixture rollback failed");
        }
        if verb == "del" {
            if let Some(success) = self.lie_delete {
                return output(
                    success,
                    if success {
                        ""
                    } else {
                        "RTNETLINK answers: No such process"
                    },
                );
            }
            if self
                .race_before_delete
                .as_ref()
                .is_some_and(|(ip, _)| ip == remote)
            {
                let (ip, replacement) = self.race_before_delete.take().unwrap();
                self.routes.insert(ip, replacement);
            }
            if let Some(current) = self.routes.get(remote) {
                // Kernel-style selectors: IPv6 does not match preferred source on delete.
                for field in ["dev", "via", "metric", "proto", "src"] {
                    if field == "src" && raw[0] == "-6" {
                        continue;
                    }
                    if let Some(wanted) = args.windows(2).find(|p| p[0] == field) {
                        if !current.windows(2).any(|p| p == wanted) {
                            return output(false, "RTNETLINK answers: No such process");
                        }
                    }
                }
            }
            self.routes.remove(remote);
            if self.post_delete_query_error {
                self.query_error = true;
            }
        } else {
            if verb == "add" && self.routes.contains_key(remote) {
                return output(false, "RTNETLINK answers: File exists");
            }
            let mut installed = args[2..].to_vec();
            // The real IPv6 FIB ignores the scope supplied to a route add.
            if raw[0] == "-6" {
                if let Some(index) = installed.iter().position(|s| s == "scope") {
                    installed.drain(index..index + 2);
                }
            }
            self.routes.insert(remote.clone(), installed);
        }
        if fail {
            match self.fail.as_ref().unwrap().2 {
                Fault::ApplyThenIo(kind) => return Err(kind.into()),
                Fault::ApplyThenFail => return output(false, "fixture lost completion"),
                _ => unreachable!(),
            }
        }
        output(true, "")
    }
}

struct Fixture {
    kernel: Arc<Mutex<Kernel>>,
    _guard: MutexGuard<'static, ()>,
}
impl Fixture {
    fn new(routes: Vec<Vec<String>>, fail: Option<(&str, IpAddr, Fault)>) -> Self {
        let guard = ROUTE_TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        reset_test_owner();
        let kernel = Arc::new(Mutex::new(Kernel {
            routes: routes.into_iter().map(|r| (r[0].clone(), r)).collect(),
            calls: Vec::new(),
            fail: fail
                .map(|(action, remote, fault)| (action.to_string(), remote.to_string(), fault)),
            fired: false,
            fail_rollback: false,
            extra_snapshot: None,
            query_error: false,
            flush_error: false,
            post_delete_query_error: false,
            lie_delete: None,
            race_before_delete: None,
            operator_change_on_failure: None,
        }));
        let executor = kernel.clone();
        EXECUTOR.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(move |args| executor.lock().unwrap().run(args)));
        });
        Self {
            kernel,
            _guard: guard,
        }
    }
    fn mutations(&self) -> Vec<Vec<String>> {
        self.kernel
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|args| {
                args.iter()
                    .any(|s| matches!(s.as_str(), "add" | "replace" | "del"))
            })
            .cloned()
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        EXECUTOR.with(|slot| *slot.borrow_mut() = None);
        reset_test_owner();
    }
}

fn candidate(ipv6: bool) -> LinuxCandidateRoute {
    LinuxCandidateRoute {
        remote: if ipv6 {
            "2001:db8::20"
        } else {
            "198.51.100.20"
        }
        .parse()
        .unwrap(),
        source: if ipv6 { "2001:db8::10" } else { "192.0.2.10" }
            .parse()
            .unwrap(),
        gateway: Some(if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.into()),
        interface: "eth0".into(),
    }
}
fn previous(remote: IpAddr) -> Vec<String> {
    vec![
        remote.to_string(),
        "dev".into(),
        "old0".into(),
        "metric".into(),
        "7".into(),
    ]
}
fn plan(routes: Vec<LinuxCandidateRoute>) -> LinuxPreparedPathRoutes {
    LinuxPreparedPathRoutes {
        generation: 7,
        candidate_id: 41,
        owner: test_owner().scope(),
        routes,
        tunnel_interface: "qtest".into(),
    }
}
fn unknown(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RouteCommitStateUnknown>().is_some()
}

/// Run the real commit path. A retirement uses the opposite family's new carrier.
fn failed(action: &str, ipv6: bool, fault: Fault, expect_unknown: bool) {
    let current = candidate(ipv6);
    let target = current.remote;
    let old = previous(target);
    let mut initial = Vec::new();
    if action != "add" {
        initial.push(old.clone());
    }
    let fixture = Fixture::new(initial, Some((action, target, fault)));
    if action != "add" {
        seed_owned(target);
    }
    let prepared = plan(vec![if action == "del" {
        candidate(!ipv6)
    } else {
        current.clone()
    }]);
    let completed_retirement =
        action == "del" && matches!(fault, Fault::ApplyThenFail | Fault::ApplyThenIo(_));
    let outcome = prepared.commit(if action == "del" {
        std::slice::from_ref(&target)
    } else {
        &[]
    });
    if completed_retirement {
        assert!(!expect_unknown);
        outcome.unwrap();
    } else {
        let error = outcome.unwrap_err();
        assert_eq!(
            unknown(&error),
            expect_unknown,
            "{action} IPv6={ipv6}: {error}"
        );
    }
    assert!(fixture.kernel.lock().unwrap().fired);
    // An uncertain add cannot claim a prefix which a concurrent operator could have installed.
    assert_eq!(
        created_by_us_owned(&test_owner(), &carrier_route_undo(target)),
        action != "add"
            && !completed_retirement
            && !(action == "del" && matches!(fault, Fault::Foreign))
    );
    assert_eq!(
        fixture
            .mutations()
            .iter()
            .filter(|args| args.iter().any(|s| s == &target.to_string()))
            .count(),
        1,
        "do not blindly rewrite/delete the failed step"
    );
    let state = fixture.kernel.lock().unwrap();
    match fault {
        Fault::Reject | Fault::UnchangedIo | Fault::Unreadable | Fault::Ambiguous => {
            assert_eq!(
                state.routes.get(&target.to_string()),
                if action == "add" { None } else { Some(&old) }
            );
        }
        Fault::Foreign => assert_eq!(state.routes[&target.to_string()][2], "operator0"),
        Fault::ApplyThenFail | Fault::ApplyThenIo(_) => {
            if action == "del" {
                assert!(!state.routes.contains_key(&target.to_string()));
            } else {
                assert_eq!(
                    state.routes[&target.to_string()],
                    candidate_route_command("add", &current)[if ipv6 { 3 } else { 2 }..]
                );
            }
        }
    }
    if action == "del" {
        let added = candidate(!ipv6).remote;
        assert_eq!(
            state.routes.contains_key(&added.to_string()),
            completed_retirement,
            "new family remains only after verified retirement"
        );
        assert_eq!(
            created_by_us_owned(&test_owner(), &carrier_route_undo(added)),
            completed_retirement
        );
    }
}

#[test]
fn failed_add_that_changed_kernel_state_is_not_reversible() {
    for ipv6 in [false, true] {
        failed("add", ipv6, Fault::ApplyThenFail, true);
    }
}
#[test]
fn failed_replace_that_changed_kernel_state_is_not_reversible() {
    for ipv6 in [false, true] {
        failed("replace", ipv6, Fault::ApplyThenFail, true);
    }
}
#[test]
fn retirement_with_verified_absence_completes_despite_negative_status() {
    for ipv6 in [false, true] {
        failed("del", ipv6, Fault::ApplyThenFail, false);
    }
}
#[test]
fn lost_result_is_unknown_unless_retirement_absence_is_confirmed() {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::InvalidData,
        io::ErrorKind::BrokenPipe,
    ] {
        for action in ["add", "replace", "del"] {
            for ipv6 in [false, true] {
                failed(action, ipv6, Fault::ApplyThenIo(kind), action != "del");
            }
        }
    }
}
#[test]
fn rejected_command_with_unchanged_route_remains_reversible() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            failed(action, ipv6, Fault::Reject, false);
        }
    }
}
#[test]
fn io_error_with_confirmed_unchanged_route_remains_reversible() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            failed(action, ipv6, Fault::UnchangedIo, false);
        }
    }
}
#[test]
fn unavailable_verification_cannot_prove_reversible_rejection() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            failed(action, ipv6, Fault::Unreadable, true);
        }
    }
}
#[test]
fn multiple_routes_cannot_hide_a_changed_snapshot_behind_the_first_line() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            failed(action, ipv6, Fault::Ambiguous, true);
        }
    }
}
#[test]
fn concurrent_operator_route_is_not_claimed_or_blindly_undone() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            failed(action, ipv6, Fault::Foreign, true);
        }
    }
}
#[test]
fn earlier_success_is_rolled_back_when_later_mutation_outcome_is_unknown() {
    let first = candidate(false);
    let second = candidate(true);
    let fixture = Fixture::new(
        Vec::new(),
        Some(("add", second.remote, Fault::ApplyThenFail)),
    );
    let error = plan(vec![first.clone(), second.clone()])
        .commit(&[])
        .unwrap_err();
    assert!(unknown(&error), "{error}");
    let state = fixture.kernel.lock().unwrap();
    assert!(!state.routes.contains_key(&first.remote.to_string()));
    assert!(state.routes.contains_key(&second.remote.to_string()));
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(first.remote)
    ));
}
#[test]
fn earlier_rollback_failure_remains_unknown_even_when_current_step_is_unchanged() {
    let first = candidate(false);
    let second = candidate(true);
    let fixture = Fixture::new(Vec::new(), Some(("add", second.remote, Fault::Reject)));
    fixture.kernel.lock().unwrap().fail_rollback = true;
    let error = plan(vec![first.clone(), second.clone()])
        .commit(&[])
        .unwrap_err();
    assert!(unknown(&error), "{error}");
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(first.remote)
    ));
    let state = fixture.kernel.lock().unwrap();
    assert!(state.routes.contains_key(&first.remote.to_string()));
    assert!(!state.routes.contains_key(&second.remote.to_string()));
}
#[test]
fn successful_add_replace_and_retirement_keep_existing_contract() {
    for action in ["add", "replace", "del"] {
        for ipv6 in [false, true] {
            let route = candidate(ipv6);
            let fixture = Fixture::new(
                if action == "add" {
                    Vec::new()
                } else {
                    vec![previous(route.remote)]
                },
                None,
            );
            if action != "add" {
                seed_owned(route.remote);
            }
            let desired = if action == "del" {
                candidate(!ipv6)
            } else {
                route.clone()
            };
            plan(vec![desired.clone()])
                .commit(if action == "del" {
                    std::slice::from_ref(&route.remote)
                } else {
                    &[]
                })
                .unwrap();
            assert!(created_by_us_owned(
                &test_owner(),
                &carrier_route_undo(desired.remote)
            ));
            assert!(fixture.mutations().contains(&candidate_route_command(
                if action == "replace" {
                    "replace"
                } else {
                    "add"
                },
                &desired
            )));
            if action == "del" {
                assert!(!created_by_us_owned(
                    &test_owner(),
                    &carrier_route_undo(route.remote)
                ));
                assert!(!fixture
                    .kernel
                    .lock()
                    .unwrap()
                    .routes
                    .contains_key(&route.remote.to_string()));
            }
        }
    }
}
#[test]
fn operator_owned_match_and_conflict_do_not_mutate_or_claim_routes() {
    for matches in [false, true] {
        for ipv6 in [false, true] {
            let route = candidate(ipv6);
            let snapshot = if matches {
                candidate_route_command("add", &route)[if ipv6 { 3 } else { 2 }..].to_vec()
            } else {
                previous(route.remote)
            };
            let fixture = Fixture::new(vec![snapshot], None);
            let result = plan(vec![route.clone()]).commit(&[]);
            assert_eq!(result.is_ok(), matches);
            assert!(fixture.mutations().is_empty());
            assert!(!created_by_us_owned(
                &test_owner(),
                &carrier_route_undo(route.remote)
            ));
        }
    }
}

#[test]
fn ambiguous_initial_snapshot_rejects_before_any_mutation() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(vec![previous(route.remote)], None);
        seed_owned(route.remote);
        fixture.kernel.lock().unwrap().extra_snapshot =
            Some(format!("{} dev operator0", route.remote));
        let error = plan(vec![route.clone()]).commit(&[]).unwrap_err();
        assert!(!unknown(&error));
        assert!(error.to_string().contains("ambiguous"));
        assert!(fixture.mutations().is_empty());
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
            previous(route.remote)
        );
        assert!(created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
    }
}

#[test]
fn earlier_retirement_is_restored_when_later_verification_fails() {
    let first = candidate(false).remote;
    let second = candidate(true).remote;
    let mut new = candidate(false);
    new.remote = "203.0.113.20".parse().unwrap();
    let fixture = Fixture::new(
        vec![previous(first), previous(second)],
        Some(("del", second, Fault::Unreadable)),
    );
    seed_owned(first);
    seed_owned(second);
    let error = plan(vec![new.clone()])
        .commit(&[first, second])
        .unwrap_err();
    assert!(unknown(&error), "{error}");
    let state = fixture.kernel.lock().unwrap();
    assert_eq!(state.routes[&first.to_string()], previous(first));
    assert_eq!(state.routes[&second.to_string()], previous(second));
    assert!(!state.routes.contains_key(&new.remote.to_string()));
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(first)
    ));
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(second)
    ));
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(new.remote)
    ));
}

// Seed pre-existing ownership with selectors, just like successful production installation.
fn seed_owned(remote: IpAddr) {
    let snapshot = exact_route_tokens(&test_owner(), remote, true)
        .unwrap()
        .unwrap();
    let mut undo = carrier_route_undo(remote);
    undo.extend(snapshot.into_iter().skip(1));
    note_created_owned(&test_owner(), undo).unwrap();
}

fn install_owned(ipv6: bool) -> (Fixture, LinuxCandidateRoute) {
    let route = candidate(ipv6);
    let fixture = Fixture::new(Vec::new(), None);
    pin_carrier_route(
        &test_owner(),
        route.remote,
        &PhysicalPath {
            gateway: route.gateway.clone(),
            device: route.interface.clone(),
        },
    )
    .unwrap();
    (fixture, route)
}

#[test]
fn ownership_cleanup_removes_unchanged_route_for_both_families() {
    for ipv6 in [false, true] {
        let (fixture, route) = install_owned(ipv6);
        cleanup_routes(&test_owner()).unwrap();
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
        let calls = fixture.mutations();
        let deletion = calls
            .iter()
            .find(|args| args.iter().any(|s| s == "del"))
            .unwrap();
        assert!(deletion.windows(2).any(|p| p == ["dev", "eth0"]));
        assert!(deletion
            .windows(2)
            .any(|p| p[0] == "via" && p[1] == route.gateway.as_deref().unwrap()));
    }
}

#[test]
fn ownership_cleanup_preserves_operator_replacement() {
    for ipv6 in [false, true] {
        for field in ["dev", "via"] {
            let (fixture, route) = install_owned(ipv6);
            let key = route.remote.to_string();
            let replacement = {
                let mut state = fixture.kernel.lock().unwrap();
                let current = state.routes.get_mut(&key).unwrap();
                let index = current.iter().position(|s| s == field).unwrap() + 1;
                current[index] = if field == "dev" {
                    "operator0".into()
                } else if ipv6 {
                    "2001:db8::99".into()
                } else {
                    "192.0.2.99".into()
                };
                current.clone()
            };
            cleanup_routes(&test_owner()).unwrap();
            assert_eq!(fixture.kernel.lock().unwrap().routes[&key], replacement);
            assert_eq!(fixture.mutations().len(), 1, "only original add");
            assert!(!created_by_us_owned(
                &test_owner(),
                &carrier_route_undo(route.remote)
            ));
        }
    }
}

#[test]
fn ownership_delete_selectors_preserve_replacement_between_check_and_delete() {
    for ipv6 in [false, true] {
        let (fixture, route) = install_owned(ipv6);
        let replacement = vec![route.remote.to_string(), "dev".into(), "operator0".into()];
        fixture.kernel.lock().unwrap().race_before_delete =
            Some((route.remote.to_string(), replacement.clone()));
        cleanup_routes(&test_owner()).unwrap();
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
            replacement
        );
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
    }
}

#[test]
fn ownership_cleanup_verifies_success_and_absent_error_before_forgetting() {
    for status in [true, false] {
        let (fixture, route) = install_owned(false);
        fixture.kernel.lock().unwrap().lie_delete = Some(status);
        assert!(cleanup_routes(&test_owner()).is_err());
        assert!(created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
        assert!(fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
        fixture.kernel.lock().unwrap().lie_delete = None;
        cleanup_routes(&test_owner()).unwrap();
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
    }
}

#[test]
fn ownership_cleanup_accepts_confirmed_absence_after_lost_delete_result() {
    for ipv6 in [false, true] {
        let (fixture, route) = install_owned(ipv6);
        fixture.kernel.lock().unwrap().fail = Some((
            "del".into(),
            route.remote.to_string(),
            Fault::ApplyThenIo(io::ErrorKind::BrokenPipe),
        ));
        cleanup_routes(&test_owner()).unwrap();
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
        assert!(!created_by_us_owned(
            &test_owner(),
            &carrier_route_undo(route.remote)
        ));
    }
}

#[test]
fn ownership_cleanup_retains_unreadable_snapshot_without_deleting() {
    let (fixture, route) = install_owned(false);
    fixture.kernel.lock().unwrap().query_error = true;
    assert!(cleanup_routes(&test_owner()).is_err());
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
    assert_eq!(fixture.mutations().len(), 1);
    fixture.kernel.lock().unwrap().query_error = false;
    cleanup_routes(&test_owner()).unwrap();
}

#[test]
fn ownership_cleanup_retries_after_unreadable_delete_verification() {
    let (fixture, route) = install_owned(true);
    fixture.kernel.lock().unwrap().post_delete_query_error = true;
    assert!(cleanup_routes(&test_owner()).is_err());
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
    assert!(!fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&route.remote.to_string()));
    fixture.kernel.lock().unwrap().query_error = false;
    let calls = fixture.mutations().len();
    cleanup_routes(&test_owner()).unwrap();
    assert_eq!(
        fixture.mutations().len(),
        calls,
        "confirmed absence needs no repeated delete"
    );
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
}

#[test]
fn ownership_cleanup_retains_ambiguous_snapshot() {
    let (fixture, route) = install_owned(false);
    fixture.kernel.lock().unwrap().extra_snapshot = Some(format!("{} dev other0", route.remote));
    assert!(cleanup_routes(&test_owner()).is_err());
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
    assert_eq!(fixture.mutations().len(), 1);
}

#[test]
fn ownership_roaming_replaces_the_cleanup_selector_with_the_new_path() {
    let (fixture, mut route) = install_owned(false);
    route.interface = "wwan0".into();
    route.gateway = Some("192.0.2.99".into());
    plan(vec![route.clone()]).commit(&[]).unwrap();
    cleanup_routes(&test_owner()).unwrap();
    assert!(!fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&route.remote.to_string()));
    let calls = fixture.mutations();
    let last = calls.last().unwrap();
    assert!(last.windows(2).any(|p| p == ["dev", "wwan0"]));
    assert!(last.windows(2).any(|p| p == ["via", "192.0.2.99"]));
}

#[test]
fn ownership_stale_record_does_not_authorize_replacing_operator_route() {
    let (fixture, route) = install_owned(false);
    let replacement = vec![route.remote.to_string(), "dev".into(), "operator0".into()];
    fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .insert(route.remote.to_string(), replacement.clone());
    let result = plan(vec![route.clone()]).commit(&[]);
    assert!(result.is_err());
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
        replacement
    );
    assert_eq!(fixture.mutations().len(), 1);
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
}

#[test]
fn ownership_stale_record_does_not_authorize_retiring_operator_route() {
    let (fixture, old) = install_owned(false);
    let replacement = vec![old.remote.to_string(), "dev".into(), "operator0".into()];
    fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .insert(old.remote.to_string(), replacement.clone());
    plan(vec![candidate(true)]).commit(&[old.remote]).unwrap();
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&old.remote.to_string()],
        replacement
    );
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(old.remote)
    ));
}

#[test]
fn ownership_cleanup_handles_on_link_route_without_inventing_gateway() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(Vec::new(), None);
        pin_carrier_route(
            &test_owner(),
            route.remote,
            &PhysicalPath {
                gateway: None,
                device: "eth0".into(),
            },
        )
        .unwrap();
        cleanup_routes(&test_owner()).unwrap();
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
        assert!(!fixture
            .mutations()
            .last()
            .unwrap()
            .iter()
            .any(|s| s == "via"));
    }
}

#[test]
fn ownership_rollback_does_not_overwrite_operator_replacement() {
    let (fixture, mut first) = install_owned(false);
    let second = candidate(true);
    let replacement = vec![first.remote.to_string(), "dev".into(), "operator0".into()];
    {
        let mut state = fixture.kernel.lock().unwrap();
        state.fail = Some(("add".into(), second.remote.to_string(), Fault::Reject));
        state.operator_change_on_failure = Some((first.remote.to_string(), replacement.clone()));
    }
    first.interface = "wwan0".into();
    let error = plan(vec![first.clone(), second]).commit(&[]).unwrap_err();
    assert!(fixture.kernel.lock().unwrap().fired);
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&first.remote.to_string()],
        replacement
    );
    assert!(unknown(&error));
    assert!(!created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(first.remote)
    ));
}

#[test]
fn ownership_retirement_restore_does_not_overwrite_operator_replacement() {
    let (fixture, first) = install_owned(false);
    let second = candidate(true);
    pin_carrier_route(
        &test_owner(),
        second.remote,
        &PhysicalPath {
            gateway: second.gateway.clone(),
            device: second.interface.clone(),
        },
    )
    .unwrap();
    let mut next = candidate(false);
    next.remote = "203.0.113.20".parse().unwrap();
    let replacement = vec![first.remote.to_string(), "dev".into(), "operator0".into()];
    {
        let mut state = fixture.kernel.lock().unwrap();
        state.fail = Some(("del".into(), second.remote.to_string(), Fault::Reject));
        state.operator_change_on_failure = Some((first.remote.to_string(), replacement.clone()));
    }
    let error = plan(vec![next])
        .commit(&[first.remote, second.remote])
        .unwrap_err();
    assert!(fixture.kernel.lock().unwrap().fired);
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&first.remote.to_string()],
        replacement
    );
    assert!(unknown(&error));
}

#[test]
fn ownership_cleanup_preserves_changed_preferred_source_of_candidate() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(Vec::new(), None);
        plan(vec![route.clone()]).commit(&[]).unwrap();
        let replacement = {
            let mut state = fixture.kernel.lock().unwrap();
            let current = state.routes.get_mut(&route.remote.to_string()).unwrap();
            let index = current.iter().position(|s| s == "src").unwrap() + 1;
            current[index] = if ipv6 {
                "2001:db8::77".into()
            } else {
                "192.0.2.77".into()
            };
            current.clone()
        };
        cleanup_routes(&test_owner()).unwrap();
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
            replacement
        );
        assert_eq!(fixture.mutations().len(), 1);
    }
}

#[test]
fn ownership_cleanup_retains_malformed_snapshot_for_retry() {
    let (fixture, route) = install_owned(false);
    let original = fixture.kernel.lock().unwrap().routes[&route.remote.to_string()].clone();
    fixture.kernel.lock().unwrap().routes.insert(
        route.remote.to_string(),
        vec!["garbled".into(), "dev".into(), "eth0".into()],
    );
    assert!(cleanup_routes(&test_owner()).is_err());
    assert!(created_by_us_owned(
        &test_owner(),
        &carrier_route_undo(route.remote)
    ));
    assert_eq!(fixture.mutations().len(), 1);
    fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .insert(route.remote.to_string(), original);
    cleanup_routes(&test_owner()).unwrap();
}

#[test]
fn scope_cleanup_other_tunnel_does_not_delete_current_carrier() {
    let fixture = Fixture::new(Vec::new(), None);
    let route = candidate(false);
    plan(vec![route.clone()]).commit(&[]).unwrap();
    cleanup_routes(&RouteOwner::test_new("other-tun", 8).unwrap()).unwrap();
    assert!(fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&route.remote.to_string()));
}

#[test]
fn scope_stale_prepared_commit_after_cleanup_is_rejected() {
    let fixture = Fixture::new(Vec::new(), None);
    let prepared = plan(vec![candidate(false)]);
    cleanup_routes(&test_owner()).unwrap();
    let before = fixture.mutations().len();
    assert!(prepared.commit(&[]).is_err());
    assert_eq!(fixture.mutations().len(), before);
}

fn plan_for(owner: &RouteOwner, routes: Vec<LinuxCandidateRoute>) -> LinuxPreparedPathRoutes {
    LinuxPreparedPathRoutes {
        generation: owner.generation(),
        candidate_id: 41,
        owner: owner.scope(),
        routes,
        tunnel_interface: owner.interface().into(),
    }
}

#[test]
fn scope_two_owners_on_same_wan_clean_only_their_routes() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(Vec::new(), None);
        let first = test_owner();
        let second = RouteOwner::test_new("other-tun", 7).unwrap();
        let a = candidate(ipv6);
        let mut b = a.clone();
        b.remote = if ipv6 {
            "2001:db8::30"
        } else {
            "198.51.100.30"
        }
        .parse()
        .unwrap();
        plan_for(&first, vec![a.clone()]).commit(&[]).unwrap();
        plan_for(&second, vec![b.clone()]).commit(&[]).unwrap();
        cleanup_routes(&first).unwrap();
        {
            let state = fixture.kernel.lock().unwrap();
            assert!(!state.routes.contains_key(&a.remote.to_string()));
            assert!(state.routes.contains_key(&b.remote.to_string()));
            assert!(state
                .calls
                .iter()
                .filter(|c| c.iter().any(|s| s == "flush"))
                .all(|c| c.last().unwrap() == "qtest"));
        }
        assert!(recorded_undo(&second, &carrier_route_undo(b.remote)).is_some());
        cleanup_routes(&second).unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    }
}

#[test]
fn scope_other_owner_cannot_replace_or_borrow_managed_route() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(Vec::new(), None);
        let second = RouteOwner::test_new("other-tun", 7).unwrap();
        let route = candidate(ipv6);
        plan(vec![route.clone()]).commit(&[]).unwrap();
        let before = fixture.mutations();
        let error = plan_for(&second, vec![route.clone()])
            .commit(&[])
            .unwrap_err();
        assert!(error.to_string().contains("another Qeli owner"));
        assert!(pin_carrier_route(
            &second,
            route.remote,
            &PhysicalPath {
                gateway: route.gateway,
                device: route.interface,
            }
        )
        .is_err());
        assert_eq!(fixture.mutations(), before);
        cleanup_routes(&second).unwrap();
        assert!(fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&route.remote.to_string()));
    }
}

#[test]
fn scope_retirement_never_reads_another_owners_journal() {
    let fixture = Fixture::new(Vec::new(), None);
    let a = candidate(false);
    let b = candidate(true);
    let second = RouteOwner::test_new("other-tun", 8).unwrap();
    plan(vec![a.clone()]).commit(&[]).unwrap();
    plan_for(&second, vec![b.clone()])
        .commit(&[a.remote])
        .unwrap();
    let state = fixture.kernel.lock().unwrap();
    assert!(state.routes.contains_key(&a.remote.to_string()));
    assert!(state.routes.contains_key(&b.remote.to_string()));
    assert!(!state.calls.iter().any(|c| c.iter().any(|s| s == "del")));
}

#[test]
fn scope_cleanup_failure_does_not_steal_another_owners_retry() {
    let fixture = Fixture::new(Vec::new(), None);
    let a = candidate(false);
    let b = candidate(true);
    let second = RouteOwner::test_new("other-tun", 8).unwrap();
    plan(vec![a.clone()]).commit(&[]).unwrap();
    plan_for(&second, vec![b.clone()]).commit(&[]).unwrap();
    fixture.kernel.lock().unwrap().lie_delete = Some(true);
    assert!(cleanup_routes(&test_owner()).is_err());
    fixture.kernel.lock().unwrap().lie_delete = None;
    cleanup_routes(&second).unwrap();
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(a.remote)).is_some());
    assert!(fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&a.remote.to_string()));
    assert!(
        plan(vec![a.clone()]).commit(&[]).is_err(),
        "failed cleanup still closes admission"
    );
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn scope_same_interface_cannot_be_reused_while_old_guard_lives() {
    let _fixture = Fixture::new(Vec::new(), None);
    let old = RouteOwner::test_new("reused-tun", 9).unwrap();
    assert!(RouteOwner::test_new("reused-tun", 10).is_err());
    cleanup_routes(&old).unwrap();
    assert!(
        RouteOwner::test_new("reused-tun", 10).is_err(),
        "guard still protects TUN teardown"
    );
    drop(old);
    assert!(RouteOwner::test_new("reused-tun", 10).is_ok());
}

#[test]
fn scope_expired_candidate_cannot_target_reused_interface_and_generation() {
    let fixture = Fixture::new(Vec::new(), None);
    let old = RouteOwner::test_new("reused-tun", 9).unwrap();
    let stale = plan_for(&old, vec![candidate(false)]);
    stale.commit(&[]).unwrap();
    cleanup_routes(&old).unwrap();
    drop(old);
    let current = RouteOwner::test_new("reused-tun", 9).unwrap();
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(stale
        .commit(&[])
        .unwrap_err()
        .to_string()
        .contains("expired"));
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
    plan_for(&current, vec![candidate(true)])
        .commit(&[])
        .unwrap();
    cleanup_routes(&current).unwrap();
}

#[test]
fn scope_wrong_generation_is_rejected_before_any_command() {
    let fixture = Fixture::new(Vec::new(), None);
    let mut prepared = plan(vec![candidate(false)]);
    prepared.generation += 1;
    assert!(prepared.commit(&[]).is_err());
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
}

#[test]
fn scope_dropped_owner_with_residual_route_cannot_be_adopted() {
    let fixture = Fixture::new(Vec::new(), None);
    let old = RouteOwner::test_new("orphan-tun", 9).unwrap();
    let remote = candidate(false).remote;
    plan_for(&old, vec![candidate(false)]).commit(&[]).unwrap();
    drop(old);
    assert!(RouteOwner::test_new("orphan-tun", 10).is_err());
    assert!(plan(vec![candidate(false)]).commit(&[]).is_err());
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&remote.to_string()));
}

#[test]
fn scope_unconfirmed_flush_retains_reservation_until_retry_succeeds() {
    let fixture = Fixture::new(Vec::new(), None);
    let owner = RouteOwner::test_new("flush-tun", 9).unwrap();
    fixture.kernel.lock().unwrap().routes.insert(
        "10.88.0.0/24".into(),
        vec!["10.88.0.0/24".into(), "dev".into(), "flush-tun".into()],
    );
    fixture.kernel.lock().unwrap().flush_error = true;
    assert!(cleanup_routes(&owner).is_err());
    fixture.kernel.lock().unwrap().flush_error = false;
    cleanup_routes(&owner).unwrap();
    drop(owner);
    assert!(RouteOwner::test_new("flush-tun", 10).is_ok());
    let failed = RouteOwner::test_new("failed-flush-tun", 9).unwrap();
    fixture.kernel.lock().unwrap().routes.insert(
        "10.88.0.0/24".into(),
        vec![
            "10.88.0.0/24".into(),
            "dev".into(),
            "failed-flush-tun".into(),
        ],
    );
    fixture.kernel.lock().unwrap().flush_error = true;
    assert!(cleanup_routes(&failed).is_err());
    drop(failed);
    assert!(RouteOwner::test_new("failed-flush-tun", 10).is_err());
}

#[test]
fn scope_host_prefix_notation_cannot_bypass_another_owners_claim() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(Vec::new(), None);
        let other = RouteOwner::test_new("other-tun", 8).unwrap();
        let route = candidate(ipv6);
        let mut undo = delete_spec(&candidate_route_command("add", &route));
        let destination = if ipv6 { 3 } else { 2 };
        undo[destination] = format!("{}/{}", route.remote, if ipv6 { 128 } else { 32 });
        note_created_owned(&other, undo).unwrap();
        assert!(plan(vec![route]).commit(&[]).is_err());
        assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    }
}

#[test]
fn scope_blackhole_is_not_borrowed_from_another_owner() {
    for cidr in ["0.0.0.0/1", "::/1"] {
        let fixture = Fixture::new(Vec::new(), None);
        let other = RouteOwner::test_new("other-tun", 8).unwrap();
        add_blackhole_half(&test_owner(), cidr).unwrap();
        let before = fixture.mutations();
        assert!(add_blackhole_half(&other, cidr).is_err());
        assert_eq!(fixture.mutations(), before);
        cleanup_routes(&other).unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.contains_key(cidr));
        cleanup_routes(&test_owner()).unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    }
}

#[test]
fn scope_failed_candidate_rollback_preserves_other_owner() {
    let a = candidate(false);
    let mut b = a.clone();
    b.remote = "198.51.100.30".parse().unwrap();
    let failing = candidate(true);
    let fixture = Fixture::new(Vec::new(), Some(("add", failing.remote, Fault::Reject)));
    let second = RouteOwner::test_new("other-tun", 8).unwrap();
    plan(vec![a.clone()]).commit(&[]).unwrap();
    let error = plan_for(&second, vec![b.clone(), failing])
        .commit(&[])
        .unwrap_err();
    assert!(!unknown(&error));
    let state = fixture.kernel.lock().unwrap();
    assert!(state.routes.contains_key(&a.remote.to_string()));
    assert!(!state.routes.contains_key(&b.remote.to_string()));
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(a.remote)).is_some());
    assert!(recorded_undo(&second, &carrier_route_undo(b.remote)).is_none());
}

#[test]
fn scope_network_plan_exclude_cannot_borrow_another_owners_carrier() {
    let route = candidate(false);
    let fixture = Fixture::new(Vec::new(), None);
    plan(vec![route.clone()]).commit(&[]).unwrap();
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    let network = NetworkPlan {
        generation: 8,
        family_mode: crate::transport_core::NetworkFamilyMode::Ipv4,
        addresses: vec![crate::transport_core::NetworkAddress {
            family: NetworkAddressFamily::Ipv4,
            address: "10.20.0.2".into(),
            prefix_len: 24,
            on_link_prefix_len: 24,
            gateway: Some("10.20.0.1".into()),
        }],
        tunnel_address: "10.20.0.2".into(),
        prefix_len: 24,
        mtu: 1400,
        tunnel_gateway: "10.20.0.1".into(),
        carrier_address: None,
        routes: Vec::new(),
        pushed_routes: Vec::new(),
        dns_servers: Vec::new(),
        full_tunnel: false,
        kill_switch: false,
        allow_ipv4_leak: false,
        allow_ipv6_leak: false,
        max_streams: 1,
        adaptive: false,
        data_plane: Default::default(),
        connection_log: Vec::new(),
    };
    let config = ClientRoutingConfig {
        exclude: vec![format!("{}/32", route.remote)],
        ..Default::default()
    };
    let before = fixture.mutations();
    let error = setup_network_plan_routes(&other, &config, &network, &[route.remote], None, false)
        .unwrap_err();
    assert!(error.to_string().contains("another Qeli owner"), "{error}");
    assert_eq!(fixture.mutations(), before);
    cleanup_routes(&other).unwrap();
    assert!(fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&route.remote.to_string()));
}

#[test]
fn scope_cleanup_and_late_commit_serialize_across_threads() {
    use std::sync::mpsc;
    use std::time::Duration;
    let fixture = Fixture::new(Vec::new(), None);
    let route = candidate(false);
    let owner = test_owner();
    let stale = plan(vec![route.clone()]);
    stale.commit(&[]).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let kernel = fixture.kernel.clone();
    let cleanup = std::thread::spawn(move || {
        let mut gate = Some((entered_tx, release_rx));
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |args| {
                if args.iter().any(|s| s == "del") {
                    if let Some((entered, release)) = gate.take() {
                        entered.send(()).unwrap();
                        release
                            .recv_timeout(Duration::from_secs(5))
                            .expect("release cleanup fixture");
                    }
                }
                kernel.lock().unwrap().run(args)
            }))
        });
        let result = cleanup_routes(&owner);
        EXECUTOR.with(|slot| *slot.borrow_mut() = None);
        result
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let kernel = fixture.kernel.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let commit = std::thread::spawn(move || {
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |args| kernel.lock().unwrap().run(args)))
        });
        started_tx.send(()).unwrap();
        let result = stale.commit(&[]);
        EXECUTOR.with(|slot| *slot.borrow_mut() = None);
        result
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    release_tx.send(()).unwrap();
    cleanup.join().unwrap().unwrap();
    assert!(commit
        .join()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("stopped"));
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    assert_eq!(
        fixture
            .mutations()
            .iter()
            .filter(|c| c.iter().any(|s| s == "add"))
            .count(),
        1
    );
}

#[test]
fn scope_platform_refresh_runs_only_inside_a_live_route_commit() {
    use std::cell::Cell;
    let fixture = Fixture::new(Vec::new(), None);
    let prepared = plan(vec![candidate(false)]);
    let refreshes = Cell::new(0);
    prepared
        .commit_with(&[], || {
            assert!(fixture.mutations().is_empty());
            refreshes.set(refreshes.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(refreshes.get(), 1);
    cleanup_routes(&test_owner()).unwrap();
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(prepared
        .commit_with(&[], || {
            refreshes.set(refreshes.get() + 1);
            Ok(())
        })
        .is_err());
    assert_eq!(
        refreshes.get(),
        1,
        "late commit must not mutate the gateway first"
    );
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
}

#[path = "postcondition_tests.rs"]
mod postcondition_tests;

#[path = "setup_flush_tests.rs"]
mod setup_flush_tests;

#[path = "command_bounds_tests.rs"]
mod command_bounds_tests;

#[path = "tunnel_plan_tests.rs"]
mod tunnel_plan_tests;

#[path = "cleanup_identity_tests.rs"]
mod cleanup_identity_tests;

#[path = "setup_identity_tests.rs"]
mod setup_identity_tests;

#[path = "budget_tests.rs"]
mod budget_tests;

#[test]
fn ownership_cleanup_preserves_implicit_attribute_changes() {
    for ipv6 in [false, true] {
        for extra in [
            "proto static",
            "metric 71",
            "mtu 1300",
            if ipv6 {
                "src 2001:db8::99"
            } else {
                "src 192.0.2.99"
            },
        ] {
            let (fixture, route) = install_owned(ipv6);
            let key = route.remote.to_string();
            fixture
                .kernel
                .lock()
                .unwrap()
                .routes
                .get_mut(&key)
                .unwrap()
                .extend(extra.split_whitespace().map(str::to_string));
            let operator = fixture.kernel.lock().unwrap().routes[&key].clone();
            let before = fixture.mutations();
            cleanup_routes(&test_owner()).unwrap();
            assert_eq!(
                fixture.kernel.lock().unwrap().routes.get(&key),
                Some(&operator)
            );
            assert_eq!(
                fixture.mutations(),
                before,
                "no delete of operator replacement"
            );
            assert!(!created_by_us_owned(
                &test_owner(),
                &carrier_route_undo(route.remote)
            ));
        }
    }
}

#[test]
fn ownership_roaming_never_replaces_changed_implicit_protocol() {
    for ipv6 in [false, true] {
        let (fixture, mut route) = install_owned(ipv6);
        let key = route.remote.to_string();
        fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .get_mut(&key)
            .unwrap()
            .extend(["proto", "static"].map(str::to_string));
        let operator = fixture.kernel.lock().unwrap().routes[&key].clone();
        let before = fixture.mutations();
        route.interface = "new0".into();
        assert!(plan(vec![route]).commit(&[]).is_err());
        assert_eq!(fixture.mutations(), before);
        cleanup_routes(&test_owner()).unwrap();
        assert_eq!(
            fixture.kernel.lock().unwrap().routes.get(&key),
            Some(&operator)
        );
    }
}

#[test]
fn ownership_retirement_preserves_changed_implicit_protocol() {
    for ipv6 in [false, true] {
        let (fixture, route) = install_owned(ipv6);
        let key = route.remote.to_string();
        fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .get_mut(&key)
            .unwrap()
            .extend(["proto", "static"].map(str::to_string));
        let operator = fixture.kernel.lock().unwrap().routes[&key].clone();
        plan(vec![candidate(!ipv6)])
            .commit(&[route.remote])
            .unwrap();
        cleanup_routes(&test_owner()).unwrap();
        assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 1);
        assert_eq!(
            fixture.kernel.lock().unwrap().routes.get(&key),
            Some(&operator)
        );
    }
}

#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
#[test]
fn persistent_retirement_write_failure_is_terminal_and_cleanup_can_retry() {
    use std::os::unix::fs::PermissionsExt;
    let old = candidate(false);
    let fixture = Fixture::new(vec![previous(old.remote)], None);
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Directory(std::env::temp_dir().join(format!(
        "qeli-route-commit-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    )));
    std::fs::create_dir(&dir.0).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = test_owner();
    let session = super::persistent::native::Session::at(&dir.0, owner.interface()).unwrap();
    owner.test_attach_session(session);
    {
        let _operation = owner.operation().unwrap();
        seed_owned(old.remote);
    }
    let file = dir.0.join("client-routes.state");
    let saved = dir.0.join("saved.state");
    let broken_file = file.clone();
    let saved_file = saved.clone();
    let kernel = fixture.kernel.clone();
    let destination = old.remote.to_string();
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let did_fire = fired.clone();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let result = kernel.lock().unwrap().run(args);
            if args.get(1).is_some_and(|s| s == "del") && args.get(2) == Some(&destination) {
                std::fs::rename(&broken_file, &saved_file).unwrap();
                std::fs::create_dir(&broken_file).unwrap();
                did_fire.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            result
        }))
    });
    let error = plan(vec![candidate(true)])
        .commit(&[old.remote])
        .unwrap_err();
    assert!(fired.load(std::sync::atomic::Ordering::Relaxed));
    assert!(
        unknown(&error),
        "a journal failure after retiring the live path must stop this generation: {error}"
    );
    assert!(owner.journal_failed());
    assert!(owner.operation().is_err());
    assert!(cleanup_routes(&owner).is_err());
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&saved, &file).unwrap();
    cleanup_routes(&owner).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    let disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(disk["groups"].as_array().unwrap().len(), 0);
}

#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
#[test]
fn persistent_intent_write_failure_stops_admission_before_kernel_mutation() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(vec![], None);
    let dir = std::env::temp_dir().join(format!(
        "qeli-route-intent-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let owner = test_owner();
    let session = super::persistent::native::Session::at(&dir, owner.interface()).unwrap();
    owner.test_attach_session(session);
    let operation = owner.operation().unwrap();
    let file = dir.join("client-routes.state");
    std::fs::create_dir(&file).unwrap();
    let args = [
        "route",
        "add",
        "198.51.100.42",
        "via",
        "192.0.2.1",
        "dev",
        "wan0",
    ]
    .map(str::to_string);
    assert!(owner.command_output(&args, false).is_err());
    assert!(owner.journal_failed());
    assert!(
        fixture.mutations().is_empty(),
        "intent must be durable before the command"
    );
    drop(operation);
    assert!(
        owner.operation().is_err(),
        "failed intent closes forward admission"
    );
    std::fs::remove_dir(&file).unwrap();
    cleanup_routes(&owner).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
