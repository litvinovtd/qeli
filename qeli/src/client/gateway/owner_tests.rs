//! Actual RouteOwner retention with explicit synthetic TUN evidence.
use super::*;
#[cfg(all(target_os = "linux", feature = "client"))]
use crate::client::route;
#[cfg(not(all(target_os = "linux", feature = "client")))]
use crate::client_route as route;

#[test]
fn gateway_owner_unbound_production_owner_cannot_bind() {
    let _route_serial = route::ROUTE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    run(|kernel| {
        let owner = RouteOwner::new("gw_a", 10).unwrap();
        assert!(bind_owner(&owner).is_err());
        assert!(kernel.borrow().calls.is_empty());
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[test]
fn gateway_owner_reservation_survives_caller_until_verified_cleanup() {
    let _route_serial = route::ROUTE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    run(|kernel| {
        let owner = RouteOwner::test_new("gw_a", 10).unwrap();
        bind_owner(&owner).unwrap();
        engage_family("gw_a", false);
        drop(owner);
        assert!(RouteOwner::test_new("gw_a", 11).is_err());
        cleanup("gw_a").unwrap();
        assert!(kernel.borrow().leases.is_empty());
        let next = RouteOwner::test_new("gw_a", 11).unwrap();
        bind_owner(&next).unwrap();
        engage_family("gw_a", false);
        disengage_owned(&next).unwrap();
    });
}

#[test]
fn gateway_owner_failed_cleanup_pins_generation_and_namespace() {
    let _route_serial = route::ROUTE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    run(|kernel| {
        let owner = RouteOwner::test_new("gw_a", 10).unwrap();
        bind_owner(&owner).unwrap();
        engage_family("gw_a", false);
        let evidence = owner.test_evidence();
        evidence.lock().unwrap().namespace = false;
        let calls = kernel.borrow().calls.len();
        assert!(disengage_owned(&owner).is_err());
        assert_eq!(kernel.borrow().calls.len(), calls);
        drop(owner);
        assert!(RouteOwner::test_new("gw_a", 11).is_err());
        evidence.lock().unwrap().namespace = true;
        cleanup("gw_a").unwrap();
        assert!(RouteOwner::test_new("gw_a", 11).is_ok());
    });
}

#[test]
fn gateway_owner_stopped_route_generation_refuses_setup_but_can_clean() {
    let _route_serial = route::ROUTE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    run(|kernel| {
        let owner = RouteOwner::test_new("gw_a", 10).unwrap();
        bind_owner(&owner).unwrap();
        engage_family("gw_a", false);
        owner.stop_admission();
        let calls = kernel.borrow().calls.len();
        assert!(engage("gw_a", "", true).is_err());
        assert_eq!(kernel.borrow().calls.len(), calls);
        disengage_owned(&owner).unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(kernel.borrow().leases.is_empty());
    });
}
