use super::*;
use std::cell::Cell;

fn record(ipv6: bool, dev: &str) -> Vec<String> {
    let mut args = Vec::new();
    if ipv6 {
        args.push("-6".into());
    }
    args.extend(
        [
            "route",
            "del",
            if ipv6 {
                "2001:db8:42::/64"
            } else {
                "10.42.0.0/16"
            },
            "dev",
            dev,
        ]
        .map(str::to_string),
    );
    args
}
fn snapshot(spec: &[String]) -> Vec<String> {
    spec[2 + usize::from(spec[0] == "-6")..].to_vec()
}
fn denied() -> anyhow::Result<()> {
    anyhow::bail!("fixture identity unavailable")
}
fn allowed() -> anyhow::Result<()> {
    Ok(())
}
fn writes(fixture: &Fixture) -> Vec<Vec<String>> {
    fixture
        .kernel
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|args| args.iter().any(|s| matches!(s.as_str(), "del" | "flush")))
        .cloned()
        .collect()
}

#[test]
fn cleanup_identity_foreign_same_name_routes_survive() {
    for ipv6 in [false, true] {
        let spec = record(ipv6, "qtest");
        let fixture = Fixture::new(vec![snapshot(&spec)], None);
        note_created_owned(&test_owner(), spec.clone()).unwrap();
        assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
        assert!(writes(&fixture).is_empty());
        assert!(recorded_undo(&test_owner(), &spec).is_some());
        assert!(!fixture.kernel.lock().unwrap().routes.is_empty());
    }
}

#[test]
fn cleanup_identity_unjournalled_replacement_survives_flush() {
    let fixture = Fixture::new(
        vec![
            snapshot(&record(false, "qtest")),
            snapshot(&record(true, "qtest")),
        ],
        None,
    );
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
    assert!(writes(&fixture).is_empty());
    assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 2);
}

#[test]
fn cleanup_identity_physical_cleanup_continues_when_tun_is_lost() {
    for ipv6 in [false, true] {
        let tunnel = record(ipv6, "qtest");
        let mut physical = record(ipv6, "eth0");
        let destination = 2 + usize::from(ipv6);
        physical[destination] = if ipv6 {
            "2001:db8:43::/64"
        } else {
            "10.43.0.0/16"
        }
        .into();
        let fixture = Fixture::new(vec![snapshot(&tunnel), snapshot(&physical)], None);
        note_created_owned(&test_owner(), tunnel.clone()).unwrap();
        note_created_owned(&test_owner(), physical.clone()).unwrap();
        assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
        assert_eq!(writes(&fixture), vec![physical]);
        assert!(recorded_undo(&test_owner(), &tunnel).is_some());
    }
}

#[test]
fn cleanup_identity_foreign_namespace_blocks_all_commands() {
    let physical = record(false, "eth0");
    let fixture = Fixture::new(vec![snapshot(&physical)], None);
    note_created_owned(&test_owner(), physical.clone()).unwrap();
    assert!(cleanup_routes_with_checks(&test_owner(), denied, allowed).is_err());
    assert!(fixture.kernel.lock().unwrap().calls.is_empty());
    assert!(recorded_undo(&test_owner(), &physical).is_some());
}

#[test]
fn cleanup_identity_rechecked_between_snapshot_and_delete() {
    for ipv6 in [false, true] {
        let spec = record(ipv6, "qtest");
        let fixture = Fixture::new(vec![snapshot(&spec)], None);
        note_created_owned(&test_owner(), spec.clone()).unwrap();
        let checks = Cell::new(0);
        assert!(cleanup_routes_with_checks(&test_owner(), allowed, || {
            checks.set(checks.get() + 1);
            if checks.get() == 1 {
                Ok(())
            } else {
                denied()
            }
        })
        .is_err());
        assert!(writes(&fixture).is_empty());
        assert!(recorded_undo(&test_owner(), &spec).is_some());
    }
}

#[test]
fn cleanup_identity_rechecked_between_flush_families() {
    let fixture = Fixture::new(vec![], None);
    let checks = Cell::new(0);
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, || {
        checks.set(checks.get() + 1);
        if checks.get() <= 2 {
            Ok(())
        } else {
            denied()
        }
    })
    .is_err());
    assert_eq!(
        writes(&fixture),
        vec![vec!["route", "flush", "dev", "qtest"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()]
    );
}

#[test]
fn cleanup_identity_pending_preserved_when_tun_is_unverifiable() {
    let spec = record(false, "qtest");
    let fixture = Fixture::new(vec![], None);
    note_pending(&test_owner(), spec.clone());
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    assert!(ensure_unclaimed(&other, &spec).is_err());
    assert!(writes(&fixture).is_empty());
}

#[test]
fn cleanup_identity_verified_retry_releases_own_records() {
    let spec = record(false, "qtest");
    let fixture = Fixture::new(vec![snapshot(&spec)], None);
    note_created_owned(&test_owner(), spec.clone()).unwrap();
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
    cleanup_routes_with_checks(&test_owner(), allowed, allowed).unwrap();
    assert!(recorded_undo(&test_owner(), &spec).is_none());
    assert!(fixture.kernel.lock().unwrap().routes.is_empty());
}

#[test]
fn cleanup_identity_namespace_rechecked_before_physical_delete() {
    let spec = record(false, "eth0");
    let fixture = Fixture::new(vec![snapshot(&spec)], None);
    note_created_owned(&test_owner(), spec.clone()).unwrap();
    let checks = Cell::new(0);
    assert!(cleanup_routes_with_checks(
        &test_owner(),
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 1 {
                Ok(())
            } else {
                denied()
            }
        },
        allowed
    )
    .is_err());
    assert!(writes(&fixture).is_empty());
    assert!(recorded_undo(&test_owner(), &spec).is_some());
}

#[test]
fn cleanup_identity_lost_postcheck_keeps_record_until_verified_absence() {
    let spec = record(false, "qtest");
    let fixture = Fixture::new(vec![snapshot(&spec)], None);
    note_created_owned(&test_owner(), spec.clone()).unwrap();
    let checks = Cell::new(0);
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, || {
        checks.set(checks.get() + 1);
        if checks.get() <= 2 {
            Ok(())
        } else {
            denied()
        }
    })
    .is_err());
    assert_eq!(writes(&fixture), vec![spec.clone()]);
    assert!(recorded_undo(&test_owner(), &spec).is_some());
    cleanup_routes_with_checks(&test_owner(), allowed, allowed).unwrap();
    assert!(recorded_undo(&test_owner(), &spec).is_none());
}

#[test]
fn cleanup_identity_physical_pending_absence_is_independent() {
    let spec = record(false, "eth0");
    let fixture = Fixture::new(vec![], None);
    note_pending(&test_owner(), spec.clone());
    assert!(cleanup_routes_with_checks(&test_owner(), allowed, denied).is_err());
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    ensure_unclaimed(&other, &spec).unwrap();
    assert!(writes(&fixture).is_empty());
}

#[test]
fn cleanup_identity_failed_evidence_keeps_orphan_name_reserved() {
    let _fixture = Fixture::new(vec![], None);
    let owner = RouteOwner::test_new("orphan-tun", 8).unwrap();
    assert!(cleanup_routes_with_checks(&owner, allowed, denied).is_err());
    drop(owner);
    assert!(RouteOwner::test_new("orphan-tun", 9).is_err());
}

#[test]
fn cleanup_identity_borrowed_physical_route_is_preserved() {
    let spec = record(false, "eth0");
    let fixture = Fixture::new(vec![snapshot(&spec)], None);
    cleanup_routes_with_checks(&test_owner(), allowed, allowed).unwrap();
    assert!(fixture.mutations().is_empty());
    assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 1);
}
