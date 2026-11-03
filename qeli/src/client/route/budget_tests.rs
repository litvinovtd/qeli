//! Transaction deadline tests against the route ownership model.
use super::*;
use std::time::{Duration, Instant};

fn exhaust_deadline() {
    std::thread::sleep(
        budget::deadline().saturating_duration_since(Instant::now()) + Duration::from_millis(5),
    );
}
fn shortly<T>(run: impl FnOnce() -> T) -> T {
    budget::with_deadline(Instant::now() + Duration::from_millis(80), run)
}

#[test]
fn route_budget_expired_admission_runs_no_commands_or_refresh() {
    let fixture = Fixture::new(vec![], None);
    let owner = test_owner();
    budget::with_deadline(Instant::now(), || {
        assert!(owner.operation().is_err());
        assert!(plan(vec![candidate(false)])
            .commit_with(&[], || panic!("expired refresh"))
            .is_err());
    });
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    assert!(
        owner.operation().is_ok(),
        "timeout alone does not invalidate an unchanged owner"
    );
}

#[test]
fn route_budget_busy_cleanup_stops_admission_and_preserves_retry() {
    let route = candidate(false);
    let old = previous(route.remote);
    let fixture = Fixture::new(vec![old], None);
    seed_owned(route.remote);
    fixture.kernel.lock().unwrap().calls.clear();
    let owner = test_owner();
    let held = owner.operation().unwrap();
    let started = Instant::now();
    let error = shortly(|| cleanup_routes(&owner)).unwrap_err();
    assert!(error.to_string().contains("deadline expired"));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    assert!(recorded_undo(&owner, &carrier_route_undo(route.remote)).is_some());
    drop(held);
    assert!(
        owner.operation().is_err(),
        "cleanup stopped late COMMIT before waiting"
    );
    cleanup_routes(&owner).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn route_budget_late_refresh_never_starts_route_queries_or_writes() {
    let fixture = Fixture::new(vec![], None);
    let result = shortly(|| {
        plan(vec![candidate(false)]).commit_with(&[], || {
            exhaust_deadline();
            Ok(())
        })
    });
    assert!(result.is_err());
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    assert!(test_owner().operation().is_ok());
}

#[test]
fn route_budget_late_add_keeps_pending_without_delete_authority() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(vec![], None);
        let kernel = fixture.kernel.clone();
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |args| {
                let result = kernel.lock().unwrap().run(args);
                if args.iter().any(|s| s == "add") {
                    exhaust_deadline();
                }
                result
            }))
        });
        let route = candidate(ipv6);
        let error = shortly(|| plan(vec![route.clone()]).commit(&[])).unwrap_err();
        assert!(unknown(&error));
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_none());
        assert!(test_owner().operation().is_err());
        assert!(cleanup_routes(&test_owner()).is_err());
        assert_eq!(
            fixture.mutations().len(),
            1,
            "pending is not permission to delete"
        );
        fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .remove(&route.remote.to_string());
        cleanup_routes(&test_owner()).unwrap();
    }
}

#[test]
fn route_budget_late_fib_rolls_back_with_one_fresh_deadline() {
    let fixture = Fixture::new(vec![], None);
    let kernel = fixture.kernel.clone();
    let mut forward_until = None;
    let mut rollback_until = None;
    let mut expired = false;
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let until = budget::deadline();
            if expired {
                assert!(until > forward_until.unwrap());
                assert_eq!(
                    *rollback_until.get_or_insert(until),
                    until,
                    "rollback shares one deadline"
                );
            } else {
                assert_eq!(
                    *forward_until.get_or_insert(until),
                    until,
                    "forward shares one deadline"
                );
            }
            let result = kernel.lock().unwrap().run(args);
            if args.iter().any(|s| s == "get") && !expired {
                exhaust_deadline();
                expired = true;
            }
            result
        }))
    });
    let error = shortly(|| plan(vec![candidate(false), candidate(true)]).commit(&[])).unwrap_err();
    assert!(
        !unknown(&error),
        "verified rollback leaves a known state: {error}"
    );
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    let writes = fixture.mutations();
    assert_eq!(
        writes.len(),
        2,
        "only first add and its rollback; no second-family add"
    );
    assert!(writes[1].iter().any(|s| s == "del"));
    assert!(test_owner().operation().is_ok());
}

#[test]
fn route_budget_cleanup_is_shared_across_routes_and_families() {
    let routes = [candidate(false), candidate(true)];
    let fixture = Fixture::new(routes.iter().map(|r| previous(r.remote)).collect(), None);
    for route in &routes {
        seed_owned(route.remote);
    }
    fixture.kernel.lock().unwrap().calls.clear();
    let kernel = fixture.kernel.clone();
    let mut delay = true;
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| {
            let result = kernel.lock().unwrap().run(args);
            if delay && args.iter().any(|s| s == "del") {
                delay = false;
                exhaust_deadline();
            }
            result
        }))
    });
    assert!(shortly(|| cleanup_routes(&test_owner())).is_err());
    assert_eq!(
        fixture.kernel.lock().unwrap().calls.len(),
        2,
        "no new child after the shared deadline"
    );
    for route in &routes {
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_some());
    }
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
    assert!(take_created(&test_owner()).is_empty());
}
