use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn initial(ipv6: bool) -> Vec<String> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend(
        [
            "route",
            "add",
            if ipv6 { "fd42::/64" } else { "10.42.0.0/16" },
            "dev",
            "qtest",
            "metric",
            "100",
        ]
        .map(str::to_string),
    );
    args
}
fn deny_tunnel() {
    test_owner().test_evidence().lock().unwrap().tunnel = false;
}
fn intercept_loss(fixture: &Fixture, on: &'static str, namespace: bool) {
    let kernel = fixture.kernel.clone();
    let evidence = test_owner().test_evidence();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let result = kernel.lock().unwrap().run(args);
            if args.iter().any(|s| s == on) {
                let mut state = evidence.lock().unwrap();
                if namespace {
                    state.namespace = false;
                } else {
                    state.tunnel = false;
                }
            }
            result
        }))
    });
}

#[test]
fn setup_identity_missing_tun_refuses_initial_query_and_add() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(vec![], None);
        deny_tunnel();
        assert!(install_initial_route(&test_owner(), &initial(ipv6)).is_err());
        assert!(fixture.kernel.lock().unwrap().calls.is_empty());
        assert!(test_owner().operation().is_err());
    }
}

#[test]
fn setup_identity_loss_after_prequery_refuses_add() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(vec![], None);
        intercept_loss(&fixture, "show", false);
        assert!(install_initial_route(&test_owner(), &initial(ipv6)).is_err());
        assert!(fixture.mutations().is_empty());
        assert!(test_owner().operation().is_err());
    }
}

#[test]
fn setup_identity_lost_postquery_never_claims_initial_route() {
    let fixture = Fixture::new(vec![], None);
    intercept_loss(&fixture, "add", true);
    let args = initial(false);
    assert!(install_initial_route(&test_owner(), &args).is_err());
    assert!(recorded_undo(&test_owner(), &delete_spec(&args)).is_none());
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    assert!(ensure_unclaimed(&other, &delete_spec(&args)).is_err());
}

#[test]
fn setup_identity_roaming_does_not_refresh_dead_tun() {
    let fixture = Fixture::new(vec![], None);
    let called = AtomicBool::new(false);
    deny_tunnel();
    let error = plan(vec![candidate(false)])
        .commit_with(&[], || {
            called.store(true, Ordering::Relaxed);
            Ok(())
        })
        .unwrap_err();
    assert!(unknown(&error));
    assert!(!called.load(Ordering::Relaxed));
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
}

#[test]
fn setup_identity_namespace_lost_in_refresh_refuses_routes() {
    let fixture = Fixture::new(vec![], None);
    let error = plan(vec![candidate(false)])
        .commit_with(&[], || {
            test_owner().test_evidence().lock().unwrap().namespace = false;
            Ok(())
        })
        .unwrap_err();
    assert!(unknown(&error));
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    assert!(test_owner().operation().is_err());
}

#[test]
fn setup_identity_lost_tun_after_candidate_add_rolls_back_physical_route() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(vec![], None);
        intercept_loss(&fixture, "add", false);
        let error = plan(vec![candidate(ipv6)]).commit(&[]).unwrap_err();
        assert!(unknown(&error));
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
        assert!(fixture
            .mutations()
            .iter()
            .any(|r| r.iter().any(|s| s == "del")));
        assert!(test_owner().operation().is_err());
    }
}

#[test]
fn setup_identity_lost_namespace_after_candidate_add_preserves_pending() {
    let fixture = Fixture::new(vec![], None);
    intercept_loss(&fixture, "add", true);
    let route = candidate(false);
    let error = plan(vec![route.clone()]).commit(&[]).unwrap_err();
    assert!(unknown(&error));
    assert_eq!(fixture.mutations().len(), 1);
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_none());
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    assert!(ensure_unclaimed(&other, &carrier_route_undo(route.remote)).is_err());
}

#[test]
fn setup_identity_namespace_mismatch_at_entry_is_terminal() {
    let fixture = Fixture::new(vec![], None);
    test_owner().test_evidence().lock().unwrap().namespace = false;
    let called = AtomicBool::new(false);
    let error = plan(vec![candidate(false)])
        .commit_with(&[], || {
            called.store(true, Ordering::Relaxed);
            Ok(())
        })
        .unwrap_err();
    assert!(unknown(&error));
    assert!(!called.load(Ordering::Relaxed));
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
}

#[test]
fn setup_identity_reappearing_tun_cannot_resume_rejected_generation() {
    let fixture = Fixture::new(vec![], None);
    deny_tunnel();
    assert!(test_owner().verify_plan().is_err());
    test_owner().test_evidence().lock().unwrap().tunnel = true;
    assert!(test_owner().verify_plan().is_err());
    assert!(test_owner().operation().is_err());
    assert!(plan(vec![candidate(false)]).commit(&[]).is_err());
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
}

#[test]
fn setup_identity_lost_tun_after_replace_restores_original_physical_route() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let old = previous(route.remote);
        let fixture = Fixture::new(vec![old.clone()], None);
        seed_owned(route.remote);
        intercept_loss(&fixture, "replace", false);
        let error = plan(vec![route.clone()]).commit(&[]).unwrap_err();
        assert!(unknown(&error));
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
            old
        );
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_some());
    }
}

#[test]
fn setup_identity_loss_during_last_fib_query_cannot_ack_commit() {
    let fixture = Fixture::new(vec![], None);
    intercept_loss(&fixture, "get", false);
    let error = plan(vec![candidate(false)]).commit(&[]).unwrap_err();
    assert!(unknown(&error));
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn setup_identity_healthy_initial_routes_still_claim_and_cleanup() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(vec![], None);
        let args = initial(ipv6);
        install_initial_route(&test_owner(), &args).unwrap();
        assert!(recorded_undo(&test_owner(), &delete_spec(&args)).is_some());
        assert!(!test_owner().identity_failed());
        cleanup_routes(&test_owner()).unwrap();
        assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    }
}

#[test]
fn setup_identity_healthy_borrowed_carrier_remains_unclaimed() {
    let route = candidate(false);
    let row = candidate_route_command("add", &route)[2..].to_vec();
    let fixture = Fixture::new(vec![row], None);
    plan(vec![route.clone()]).commit(&[]).unwrap();
    assert!(fixture.mutations().is_empty());
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_none());
    assert!(!test_owner().identity_failed());
}
