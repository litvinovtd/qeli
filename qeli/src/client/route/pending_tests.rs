//! Unknown results reserve a destination without granting permission to delete it.
use super::*;

#[test]
fn pending_unknown_add_cannot_report_clean_teardown() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(
            Vec::new(),
            Some((
                "add",
                route.remote,
                Fault::ApplyThenIo(io::ErrorKind::BrokenPipe),
            )),
        );
        assert!(unknown(&plan(vec![route.clone()]).commit(&[]).unwrap_err()));
        let before = fixture.mutations();
        assert!(
            cleanup_routes(&test_owner()).is_err(),
            "uncertain physical route must remain visible to cleanup"
        );
        assert_eq!(
            fixture.mutations(),
            before,
            "pending is not permission to delete"
        );
        assert!(recorded_undo(&test_owner(), &carrier_route_undo(route.remote)).is_none());
    }
}

#[test]
fn pending_unknown_add_cannot_be_borrowed_by_another_owner() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(
            Vec::new(),
            Some(("add", route.remote, Fault::ApplyThenFail)),
        );
        assert!(unknown(&plan(vec![route.clone()]).commit(&[]).unwrap_err()));
        let other = RouteOwner::test_new("other-tun", 9).unwrap();
        let before = fixture.kernel.lock().unwrap().calls.len();
        assert!(plan_for(&other, vec![route]).commit(&[]).is_err());
        assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
    }
}

#[test]
fn pending_unknown_add_survives_final_lease_drop() {
    let route = candidate(false);
    let fixture = Fixture::new(
        Vec::new(),
        Some(("add", route.remote, Fault::ApplyThenFail)),
    );
    let owner = RouteOwner::test_new("orphan-pending", 9).unwrap();
    let stale = plan_for(&owner, vec![route]);
    assert!(unknown(&stale.commit(&[]).unwrap_err()));
    drop(owner);
    assert!(RouteOwner::test_new("orphan-pending", 10).is_err());
    assert!(stale.commit(&[]).is_err());
    assert_eq!(fixture.mutations().len(), 1);
}

#[test]
fn pending_unknown_replace_cannot_be_forgotten_by_cleanup() {
    for ipv6 in [false, true] {
        let route = candidate(ipv6);
        let fixture = Fixture::new(
            vec![previous(route.remote)],
            Some(("replace", route.remote, Fault::ApplyThenFail)),
        );
        seed_owned(route.remote);
        assert!(unknown(&plan(vec![route.clone()]).commit(&[]).unwrap_err()));
        let before = fixture.mutations();
        assert!(cleanup_routes(&test_owner()).is_err());
        assert_eq!(fixture.mutations(), before);
        let other = RouteOwner::test_new("other-tun", 9).unwrap();
        assert!(plan_for(&other, vec![route]).commit(&[]).is_err());
    }
}

#[test]
fn pending_unreadable_restore_cannot_report_clean_teardown() {
    let (fixture, remote, error) =
        rejected_retirement(false, Completion::BadSnapshot(SnapshotFault::Unreadable));
    assert!(unknown(&error));
    let kernel = fixture.kernel.clone();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| kernel.lock().unwrap().run(args)))
    });
    assert!(
        cleanup_routes(&test_owner()).is_err(),
        "restoration was applied but never confirmed"
    );
    assert_eq!(
        fixture.kernel.lock().unwrap().routes[&remote.to_string()],
        previous(remote)
    );
    assert!(recorded_undo(&test_owner(), &carrier_route_undo(remote)).is_none());
}

#[test]
fn pending_unknown_result_immediately_closes_route_admission() {
    let route = candidate(false);
    let fixture = Fixture::new(
        Vec::new(),
        Some(("add", route.remote, Fault::ApplyThenFail)),
    );
    let prepared = plan(vec![route]);
    assert!(unknown(&prepared.commit(&[]).unwrap_err()));
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(prepared
        .commit_with(&[], || panic!("unknown owner must reject gateway refresh"))
        .is_err());
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
}

#[test]
fn pending_orphan_owned_record_releases_only_after_verified_absence() {
    let fixture = Fixture::new(Vec::new(), None);
    let owner = RouteOwner::test_new("orphan-recovery", 9).unwrap();
    let route = candidate(false);
    let stale = plan_for(&owner, vec![route.clone()]);
    stale.commit(&[]).unwrap();
    fixture.kernel.lock().unwrap().lie_delete = Some(true);
    assert!(cleanup_routes(&owner).is_err());
    drop(owner);
    let before = fixture.mutations();
    assert!(RouteOwner::test_new("orphan-recovery", 10).is_err());
    fixture.kernel.lock().unwrap().routes.clear();
    let recovered = RouteOwner::test_new("orphan-recovery", 9)
        .expect("absent leftover can release a stopped orphan");
    assert_eq!(fixture.mutations(), before, "orphan recheck is read-only");
    assert!(
        stale.commit(&[]).is_err(),
        "same generation cannot revive the old lease"
    );
    drop(recovered);
}

// Additional recovery controls, introduced after the baseline reproduction.
fn unknown_owner(ipv6: bool) -> (Fixture, RouteOwner, LinuxCandidateRoute) {
    let route = candidate(ipv6);
    let fixture = Fixture::new(
        Vec::new(),
        Some(("add", route.remote, Fault::ApplyThenFail)),
    );
    let owner = RouteOwner::test_new("pending-control", 9).unwrap();
    assert!(unknown(
        &plan_for(&owner, vec![route.clone()])
            .commit(&[])
            .unwrap_err()
    ));
    (fixture, owner, route)
}

#[test]
fn pending_live_retry_releases_absent_destination_without_reopening_owner() {
    for ipv6 in [false, true] {
        let (fixture, owner, route) = unknown_owner(ipv6);
        assert!(cleanup_routes(&owner).is_err());
        let before = fixture.mutations();
        fixture.kernel.lock().unwrap().routes.clear();
        cleanup_routes(&owner).unwrap();
        assert!(plan_for(&owner, vec![route]).commit(&[]).is_err());
        assert!(
            RouteOwner::test_new("pending-control", 10).is_err(),
            "live lease protects teardown"
        );
        assert_eq!(fixture.mutations(), before);
        drop(owner);
        RouteOwner::test_new("pending-control", 10).unwrap();
    }
}

#[test]
fn pending_orphan_unknown_add_can_release_after_external_removal() {
    for ipv6 in [false, true] {
        let (fixture, owner, route) = unknown_owner(ipv6);
        assert!(cleanup_routes(&owner).is_err());
        drop(owner);
        assert!(RouteOwner::test_new("pending-control", 10).is_err());
        let before = fixture.mutations();
        fixture.kernel.lock().unwrap().routes.clear();
        let recovered = RouteOwner::test_new("pending-control", 10).unwrap();
        assert_eq!(fixture.mutations(), before);
        assert!(recorded_undo(&recovered, &carrier_route_undo(route.remote)).is_none());
    }
}

#[test]
fn pending_cleanup_preserves_matching_and_foreign_routes_without_claiming() {
    for ipv6 in [false, true] {
        let (fixture, owner, route) = unknown_owner(ipv6);
        let replacement = vec![route.remote.to_string(), "dev".into(), "operator0".into()];
        fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .insert(route.remote.to_string(), replacement.clone());
        let before = fixture.mutations();
        assert!(cleanup_routes(&owner).is_err());
        assert_eq!(fixture.mutations(), before);
        assert!(recorded_undo(&owner, &carrier_route_undo(route.remote)).is_none());
        assert_eq!(
            fixture.kernel.lock().unwrap().routes[&route.remote.to_string()],
            replacement
        );
    }
}

#[test]
fn pending_orphan_invalid_queries_retain_reservation_until_valid_absence() {
    for fault in [
        SnapshotFault::Unreadable,
        SnapshotFault::Malformed,
        SnapshotFault::Ambiguous,
        SnapshotFault::InvalidUtf8,
    ] {
        let (fixture, owner, route) = unknown_owner(false);
        assert!(cleanup_routes(&owner).is_err());
        drop(owner);
        fixture.kernel.lock().unwrap().routes.clear();
        let kernel = fixture.kernel.clone();
        let destination = route.remote.to_string();
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |args| {
                if args.last() == Some(&destination) && args.iter().any(|s| s == "show") {
                    kernel.lock().unwrap().calls.push(args.to_vec());
                    return match fault {
                        SnapshotFault::Unreadable => Err(io::ErrorKind::BrokenPipe.into()),
                        SnapshotFault::Malformed => output(true, "not-a-route dev eth0"),
                        SnapshotFault::Ambiguous => output(
                            true,
                            &format!("{destination} dev eth0\n{destination} dev eth1"),
                        ),
                        SnapshotFault::InvalidUtf8 => {
                            let mut result = output(true, "")?;
                            result.stdout = vec![0xff];
                            Ok(result)
                        }
                    };
                }
                kernel.lock().unwrap().run(args)
            }))
        });
        let before = fixture.mutations();
        assert!(RouteOwner::test_new("pending-control", 10).is_err());
        assert_eq!(fixture.mutations(), before);
        let kernel = fixture.kernel.clone();
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |args| kernel.lock().unwrap().run(args)))
        });
        RouteOwner::test_new("pending-control", 10).unwrap();
    }
}

#[test]
fn pending_orphan_without_cleanup_does_not_release_even_if_route_disappeared() {
    let (fixture, owner, _) = unknown_owner(false);
    drop(owner);
    fixture.kernel.lock().unwrap().routes.clear();
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(RouteOwner::test_new("pending-control", 10).is_err());
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
}

#[test]
fn pending_orphan_failed_interface_flush_does_not_release() {
    let (fixture, owner, _) = unknown_owner(false);
    fixture.kernel.lock().unwrap().routes.insert(
        "10.88.0.0/24".into(),
        vec![
            "10.88.0.0/24".into(),
            "dev".into(),
            "pending-control".into(),
        ],
    );
    fixture.kernel.lock().unwrap().flush_error = true;
    assert!(cleanup_routes(&owner).is_err());
    drop(owner);
    fixture.kernel.lock().unwrap().routes.clear();
    fixture.kernel.lock().unwrap().flush_error = false;
    assert!(RouteOwner::test_new("pending-control", 10).is_err());
}

#[test]
fn pending_orphan_requires_empty_interface_routes_in_both_families() {
    for ipv6 in [false, true] {
        for bad in ["route remains", "query failed", "invalid utf8"] {
            let (fixture, owner, _) = unknown_owner(false);
            assert!(cleanup_routes(&owner).is_err());
            drop(owner);
            fixture.kernel.lock().unwrap().routes.clear();
            let mut target = Vec::new();
            if ipv6 {
                target.push("-6".to_string());
            }
            target.extend(["route", "show", "dev", "pending-control"].map(str::to_string));
            let kernel = fixture.kernel.clone();
            EXECUTOR.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |args| {
                    if args == target {
                        kernel.lock().unwrap().calls.push(args.to_vec());
                        return match bad {
                            "query failed" => output(false, "fixture query failure"),
                            "invalid utf8" => {
                                let mut result = output(true, "")?;
                                result.stdout = vec![0xff];
                                Ok(result)
                            }
                            _ => output(true, "10.0.0.0/24 dev pending-control"),
                        };
                    }
                    kernel.lock().unwrap().run(args)
                }))
            });
            let before = fixture.mutations();
            assert!(RouteOwner::test_new("pending-control", 10).is_err());
            assert_eq!(fixture.mutations(), before);
            let kernel = fixture.kernel.clone();
            EXECUTOR.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |args| kernel.lock().unwrap().run(args)))
            });
            RouteOwner::test_new("pending-control", 10).unwrap();
        }
    }
}

#[test]
fn pending_unchanged_rejection_does_not_reserve_or_close_owner() {
    let route = candidate(false);
    let fixture = Fixture::new(Vec::new(), Some(("add", route.remote, Fault::Reject)));
    let prepared = plan(vec![route]);
    assert!(!unknown(&prepared.commit(&[]).unwrap_err()));
    fixture.kernel.lock().unwrap().fail = None;
    prepared.commit(&[]).unwrap();
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn pending_orphan_does_not_release_partial_set_or_touch_other_owner() {
    let (fixture, owner, route) = unknown_owner(false);
    let other = RouteOwner::test_new("unrelated-tun", 1).unwrap();
    let other_route = candidate(true);
    plan_for(&other, vec![other_route.clone()])
        .commit(&[])
        .unwrap();
    assert!(cleanup_routes(&owner).is_err());
    drop(owner);
    let before = fixture.mutations();
    assert!(RouteOwner::test_new("pending-control", 10).is_err());
    assert_eq!(fixture.mutations(), before);
    fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .remove(&route.remote.to_string());
    RouteOwner::test_new("pending-control", 10).unwrap();
    assert!(fixture
        .kernel
        .lock()
        .unwrap()
        .routes
        .contains_key(&other_route.remote.to_string()));
    assert!(recorded_undo(&other, &carrier_route_undo(other_route.remote)).is_some());
}

#[test]
fn pending_failed_owned_rollback_also_closes_admission() {
    let first = candidate(false);
    let second = candidate(true);
    let fixture = Fixture::new(Vec::new(), Some(("add", second.remote, Fault::Reject)));
    fixture.kernel.lock().unwrap().fail_rollback = true;
    assert!(unknown(
        &plan(vec![first.clone(), second]).commit(&[]).unwrap_err()
    ));
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(plan(vec![first])
        .commit_with(&[], || panic!("failed rollback must close admission"))
        .is_err());
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
    fixture.kernel.lock().unwrap().fail_rollback = false;
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}
