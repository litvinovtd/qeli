//! Production transaction tests with one exact command's completion/observation faulted.
use super::*;

#[derive(Clone, Copy)]
enum SnapshotFault {
    Unreadable,
    Malformed,
    Ambiguous,
    InvalidUtf8,
}

enum Completion {
    NoEffect(bool),
    AppliedIo,
    AppliedError(&'static str),
    BadSnapshot(SnapshotFault),
    Changed(Vec<String>),
}

fn old_command(action: &str, remote: IpAddr) -> Vec<String> {
    let mut args = Vec::new();
    if remote.is_ipv6() {
        args.push("-6".into());
    }
    args.extend(["route".into(), action.into()]);
    args.extend(previous(remote));
    args
}

fn intercept(fixture: &Fixture, target: Vec<String>, completion: Completion, remote: IpAddr) {
    let kernel = fixture.kernel.clone();
    let mut fired = false;
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let mut state = kernel.lock().unwrap();
            if fired && args.iter().any(|s| s == "show") && args.last() == Some(&remote.to_string())
            {
                if let Completion::BadSnapshot(fault) = &completion {
                    state.calls.push(args.to_vec());
                    return match fault {
                        SnapshotFault::Unreadable => Err(io::ErrorKind::BrokenPipe.into()),
                        SnapshotFault::Malformed => output(true, "not-a-route dev old0"),
                        SnapshotFault::Ambiguous => output(
                            true,
                            &format!("{}\n{} dev other0", previous(remote).join(" "), remote),
                        ),
                        SnapshotFault::InvalidUtf8 => {
                            let mut result = output(true, "")?;
                            result.stdout = vec![0xff];
                            Ok(result)
                        }
                    };
                }
            }
            if !fired && args == target {
                fired = true;
                match &completion {
                    Completion::NoEffect(success) => {
                        state.calls.push(args.to_vec());
                        return output(
                            *success,
                            if *success {
                                ""
                            } else {
                                "RTNETLINK answers: No such process"
                            },
                        );
                    }
                    _ => {
                        state.run(args)?;
                    }
                }
                return match &completion {
                    Completion::AppliedIo => Err(io::ErrorKind::BrokenPipe.into()),
                    Completion::AppliedError(message) => output(false, message),
                    Completion::Changed(route) => {
                        state.routes.insert(remote.to_string(), route.clone());
                        output(true, "")
                    }
                    Completion::BadSnapshot(_) => output(true, ""),
                    Completion::NoEffect(_) => unreachable!(),
                };
            }
            state.run(args)
        }))
    });
}

fn rejected_replace(ipv6: bool, completion: Completion) -> (Fixture, IpAddr, anyhow::Error) {
    let first = candidate(ipv6);
    let later = candidate(!ipv6);
    let remote = first.remote;
    let fixture = Fixture::new(
        vec![previous(remote)],
        Some(("add", later.remote, Fault::Reject)),
    );
    seed_owned(remote);
    intercept(&fixture, old_command("replace", remote), completion, remote);
    let error = plan(vec![first, later]).commit(&[]).unwrap_err();
    (fixture, remote, error)
}

fn rejected_retirement(ipv6: bool, completion: Completion) -> (Fixture, IpAddr, anyhow::Error) {
    let first = candidate(ipv6).remote;
    let second = if ipv6 {
        "2001:db8::30"
    } else {
        "198.51.100.30"
    }
    .parse()
    .unwrap();
    let fixture = Fixture::new(
        vec![previous(first), previous(second)],
        Some(("del", second, Fault::Reject)),
    );
    seed_owned(first);
    seed_owned(second);
    intercept(&fixture, old_command("add", first), completion, first);
    let error = plan(vec![candidate(!ipv6)])
        .commit(&[first, second])
        .unwrap_err();
    (fixture, first, error)
}

fn assert_old_record(remote: IpAddr) {
    assert_eq!(
        recorded_undo(&test_owner(), &carrier_route_undo(remote)),
        Some(old_command("del", remote))
    );
}

#[test]
fn postcondition_retirement_lie_success_keeps_previous_route_and_rejects() {
    for ipv6 in [false, true] {
        let old = candidate(ipv6).remote;
        let new = candidate(!ipv6);
        let fixture = Fixture::new(vec![previous(old)], None);
        seed_owned(old);
        intercept(
            &fixture,
            old_command("del", old),
            Completion::NoEffect(true),
            old,
        );
        let error = plan(vec![new.clone()]).commit(&[old]).unwrap_err();
        assert!(!unknown(&error), "{error}");
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&old.to_string()],
            previous(old)
        );
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&new.remote.to_string()));
        assert_old_record(old);
    }
}

#[test]
fn postcondition_retirement_false_absent_error_is_not_success() {
    for ipv6 in [false, true] {
        let old = candidate(ipv6).remote;
        let fixture = Fixture::new(vec![previous(old)], None);
        seed_owned(old);
        intercept(
            &fixture,
            old_command("del", old),
            Completion::NoEffect(false),
            old,
        );
        let error = plan(vec![candidate(!ipv6)]).commit(&[old]).unwrap_err();
        assert!(!unknown(&error), "{error}");
        assert_old_record(old);
    }
}

#[test]
fn postcondition_retirement_lost_result_with_verified_absence_completes() {
    for ipv6 in [false, true] {
        let old = candidate(ipv6).remote;
        let new = candidate(!ipv6);
        let fixture = Fixture::new(vec![previous(old)], None);
        seed_owned(old);
        intercept(
            &fixture,
            old_command("del", old),
            Completion::AppliedIo,
            old,
        );
        plan(vec![new.clone()]).commit(&[old]).unwrap();
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&old.to_string()));
        assert!(fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&new.remote.to_string()));
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(old)).is_none());
    }
}

#[test]
fn postcondition_unreadable_retirement_remains_unknown_and_retains_record() {
    let old = candidate(false).remote;
    let fixture = Fixture::new(vec![previous(old)], None);
    seed_owned(old);
    intercept(
        &fixture,
        old_command("del", old),
        Completion::BadSnapshot(SnapshotFault::Unreadable),
        old,
    );
    let error = plan(vec![candidate(true)]).commit(&[old]).unwrap_err();
    assert!(unknown(&error), "{error}");
    assert_old_record(old);
}

#[test]
fn postcondition_retirement_preserves_concurrent_operator_replacement() {
    let old = candidate(false).remote;
    let fixture = Fixture::new(vec![previous(old)], None);
    seed_owned(old);
    let operator = vec![old.to_string(), "dev".into(), "operator0".into()];
    fixture.kernel.lock().unwrap().race_before_delete = Some((old.to_string(), operator.clone()));
    let error = plan(vec![candidate(true)]).commit(&[old]).unwrap_err();
    assert!(unknown(&error), "{error}");
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&old.to_string()],
        operator
    );
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(old)).is_none());
}

#[test]
fn postcondition_replace_rollback_lie_success_is_unknown_and_retryable() {
    for ipv6 in [false, true] {
        let (fixture, remote, error) = rejected_replace(ipv6, Completion::NoEffect(true));
        assert!(unknown(&error), "{error}");
        assert_eq!(
            recorded_undo(&test_owner(), &carrier_route_undo(remote)),
            Some(delete_spec(&candidate_route_command(
                "add",
                &candidate(ipv6)
            )))
        );
        cleanup_routes(&test_owner()).unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    }
}

#[test]
fn postcondition_replace_rollback_lost_result_accepts_verified_restoration() {
    for ipv6 in [false, true] {
        let (fixture, remote, error) = rejected_replace(ipv6, Completion::AppliedIo);
        assert!(!unknown(&error), "{error}");
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&remote.to_string()],
            previous(remote)
        );
        assert_old_record(remote);
    }
}

#[test]
fn postcondition_replace_rollback_rejects_unreadable_or_invalid_verification() {
    for fault in [
        SnapshotFault::Unreadable,
        SnapshotFault::Malformed,
        SnapshotFault::Ambiguous,
        SnapshotFault::InvalidUtf8,
    ] {
        let (_fixture, remote, error) = rejected_replace(false, Completion::BadSnapshot(fault));
        assert!(unknown(&error), "{error}");
        assert_ne!(
            recorded_undo(&test_owner(), &carrier_route_undo(remote)),
            Some(old_command("del", remote))
        );
    }
}

#[test]
fn postcondition_replace_rollback_does_not_claim_foreign_post_state() {
    let remote = candidate(false).remote;
    let operator = vec![remote.to_string(), "dev".into(), "operator0".into()];
    let (fixture, remote, error) = rejected_replace(false, Completion::Changed(operator.clone()));
    assert!(unknown(&error), "{error}");
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&remote.to_string()],
        operator
    );
    assert_ne!(
        recorded_undo(&test_owner(), &carrier_route_undo(remote)),
        Some(old_command("del", remote))
    );
}

#[test]
fn postcondition_retired_restore_lie_success_does_not_claim_missing_route() {
    for ipv6 in [false, true] {
        let (fixture, remote, error) = rejected_retirement(ipv6, Completion::NoEffect(true));
        assert!(unknown(&error), "{error}");
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&remote.to_string()));
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(remote)).is_none());
    }
}

#[test]
fn postcondition_retired_restore_lost_result_accepts_verified_restoration() {
    for ipv6 in [false, true] {
        let (fixture, remote, error) = rejected_retirement(ipv6, Completion::AppliedIo);
        assert!(!unknown(&error), "{error}");
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&remote.to_string()],
            previous(remote)
        );
        assert_old_record(remote);
    }
}

#[test]
fn postcondition_retired_restore_requires_readable_valid_verification() {
    for fault in [
        SnapshotFault::Unreadable,
        SnapshotFault::Malformed,
        SnapshotFault::Ambiguous,
        SnapshotFault::InvalidUtf8,
    ] {
        let (_fixture, remote, error) = rejected_retirement(true, Completion::BadSnapshot(fault));
        assert!(unknown(&error), "{error}");
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(remote)).is_none());
    }
}

#[test]
fn postcondition_retired_restore_does_not_claim_foreign_post_state() {
    let remote = candidate(true).remote;
    let operator = vec![remote.to_string(), "dev".into(), "operator0".into()];
    let (fixture, remote, error) = rejected_retirement(true, Completion::Changed(operator.clone()));
    assert!(unknown(&error), "{error}");
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&remote.to_string()],
        operator
    );
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(remote)).is_none());
}

#[test]
fn postcondition_absent_error_after_delete_is_included_in_later_rollback() {
    for ipv6 in [false, true] {
        let first = candidate(ipv6).remote;
        let second = if ipv6 {
            "2001:db8::30"
        } else {
            "198.51.100.30"
        }
        .parse()
        .unwrap();
        let fixture = Fixture::new(
            vec![previous(first), previous(second)],
            Some(("del", second, Fault::Reject)),
        );
        seed_owned(first);
        seed_owned(second);
        intercept(
            &fixture,
            old_command("del", first),
            Completion::AppliedError("RTNETLINK answers: No such process"),
            first,
        );
        let error = plan(vec![candidate(!ipv6)])
            .commit(&[first, second])
            .unwrap_err();
        assert!(!unknown(&error), "{error}");
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&first.to_string()],
            previous(first)
        );
        assert_old_record(first);
    }
}

#[test]
fn postcondition_disappeared_route_before_retirement_is_not_recreated() {
    let old = candidate(false).remote;
    let new = candidate(true);
    let fixture = Fixture::new(vec![previous(old)], None);
    seed_owned(old);
    let kernel = fixture.kernel.clone();
    let new_ip = new.remote.to_string();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let mut state = kernel.lock().unwrap();
            if args.iter().any(|s| s == "get") && args.iter().any(|s| s == &new_ip) {
                state.routes.remove(&old.to_string());
            }
            state.run(args)
        }))
    });
    let error = plan(vec![new]).commit(&[old]).unwrap_err();
    assert!(unknown(&error), "{error}");
    assert!(!fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&old.to_string()));
    assert!(!fixture
        .mutations()
        .iter()
        .any(|args| args.iter().any(|s| s == "add") && args.iter().any(|s| s == &old.to_string())));
}

#[test]
fn postcondition_malformed_matching_snapshot_is_not_accepted_before_mutation() {
    let route = candidate(false);
    let fixture = Fixture::new(
        vec![candidate_route_command("add", &route)[2..].to_vec()],
        None,
    );
    let kernel = fixture.kernel.clone();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            if args.iter().any(|s| s == "show") {
                kernel.lock().unwrap().calls.push(args.to_vec());
                return output(true, "not-a-route via 192.0.2.1 dev eth0");
            }
            kernel.lock().unwrap().run(args)
        }))
    });
    assert!(plan(vec![route]).commit(&[]).is_err());
    assert!(fixture.mutations().is_empty());
}

#[path = "pending_tests.rs"]
mod pending_tests;
