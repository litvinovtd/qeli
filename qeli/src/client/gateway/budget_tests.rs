//! Public router entry points retain exact ownership when an operation runs out of time.
use super::*;
use budget::with_deadline;
use std::time::{Duration, Instant};

#[test]
fn gateway_expired_or_busy_admission_starts_no_host_io() {
    run(|kernel| {
        let expired = Instant::now();
        with_deadline(expired, || {
            assert!(engage("gw_a", "10.20.0.0/24", true).is_err());
            assert!(engage_ipv6("gw_a", "fd20::/64", true).is_err());
            assert!(engage_exit("gw_a").is_err());
            assert!(engage_exit_ipv6("gw_a").is_err());
            assert!(apply_tun_rp_filter("gw_a").is_err());
            assert!(disengage_plan("gw_a").is_err());
        });
        let held = router_operation(Budget::new()).unwrap();
        let start = Instant::now();
        with_deadline(start + Duration::from_millis(40), || {
            assert!(engage("gw_a", "10.20.0.0/24", true).is_err());
        });
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(held);
        assert!(kernel.borrow().calls.is_empty());
        assert!(kernel.borrow().leases.is_empty());
        engage("gw_a", "10.20.0.0/24", true).unwrap();
        cleanup("gw_a").unwrap();
    });
}

#[test]
fn gateway_setup_late_nat_ack_retains_partial_plan_for_fresh_rollback() {
    run(|kernel| {
        kernel.borrow_mut().delay_once = Some(("-A".into(), Duration::from_millis(120)));
        with_deadline(Instant::now() + Duration::from_millis(90), || {
            assert!(engage("gw_a", "10.20.0.0/24", true).is_err());
        });
        assert_eq!(kernel.borrow().count(false, "gw_a"), 1);
        assert!(!kernel.borrow().leases.is_empty());
        assert!(GATEWAY_SCOPES.lock().unwrap().contains_key("gw_a"));
        // A fresh attempt has a new deadline, despite the retained owner's failed setup.
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[test]
fn gateway_cleanup_deadline_is_shared_by_both_families_and_sysctls() {
    run(|kernel| {
        engage("gw_a", "10.20.0.0/24", true).unwrap();
        engage_ipv6("gw_a", "fd20::/64", true).unwrap();
        let v6_before = kernel.borrow().count(true, "gw_a");
        kernel.borrow_mut().delay_once = Some(("-D".into(), Duration::from_millis(120)));
        let commands_before = kernel.borrow().calls.len();
        with_deadline(Instant::now() + Duration::from_millis(90), || {
            assert!(cleanup("gw_a")
                .unwrap_err()
                .to_string()
                .contains("deadline expired"));
        });
        assert_eq!(kernel.borrow().count(true, "gw_a"), v6_before);
        assert!(kernel.borrow().releases.is_empty());
        // One presence check and one deletion; no later family gets a reset deadline.
        assert_eq!(
            kernel.borrow().calls[commands_before..]
                .iter()
                .filter(|args| args.as_slice() != ["--version"])
                .count(),
            2
        );
        assert!(GATEWAY_SCOPES.lock().unwrap().contains_key("gw_a"));
        cleanup("gw_a").unwrap();
        assert_eq!(kernel.borrow().count(true, "gw_a"), 0);
        assert_eq!(kernel.borrow().count(false, "gw_a"), 0);
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[test]
fn gateway_refresh_late_wan_query_never_starts_firewall_work() {
    run(|kernel| {
        kernel.borrow_mut().wans[0] = Some("wan0".into());
        engage_exit("gw_a").unwrap();
        kernel.borrow_mut().wans[0] = Some("wan1".into());
        kernel.borrow_mut().delay_once = Some(("default".into(), Duration::from_millis(120)));
        let mutations = kernel.borrow().mutations();
        with_deadline(Instant::now() + Duration::from_millis(90), || {
            assert!(refresh_exit_paths_if_active("gw_a").is_err());
        });
        assert_eq!(kernel.borrow().mutations(), mutations);
        assert_eq!(exit_wans_for(&EXIT_WANS_V4, "gw_a"), ["wan0"]);
        cleanup("gw_a").unwrap();
    });
}

#[test]
fn gateway_expired_context_refuses_sysctl_admission() {
    run(|kernel| {
        let context = Context::forward(
            "gw_a",
            Budget {
                until: Instant::now(),
            },
        )
        .err()
        .unwrap();
        assert!(context.to_string().contains("deadline expired"));
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[cfg(target_os = "linux")]
#[test]
fn gateway_real_command_is_killed_at_the_shared_deadline() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    identity::test_support::with_owners(|| {
        let started = Instant::now();
        let context = Context::forward(
            "gw_a",
            Budget {
                until: started + Duration::from_millis(120),
            },
        )
        .unwrap();
        assert!(context.ipt("/bin/sh", &["-c", "sleep 5"]).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    });
}
