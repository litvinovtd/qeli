//! Boundary fault injection: actual gateway entry points, isolated firewall/sysctl model.
use super::*;
fn lose(namespace: bool) {
    let state = identity::test_support::evidence("gw_a");
    let mut state = state.lock().unwrap();
    if namespace {
        state.namespace = false;
    } else {
        state.tunnel = false;
    }
}
fn recover() {
    let state = identity::test_support::evidence("gw_a");
    let mut state = state.lock().unwrap();
    state.namespace = true;
    state.tunnel = true;
}

#[test]
fn gateway_identity_missing_tun_blocks_every_setup_entry() {
    run(|kernel| {
        lose(false);
        assert!(engage("gw_a", "", true).is_err());
        assert!(engage_ipv6("gw_a", "", true).is_err());
        assert!(engage_exit("gw_a").is_err());
        assert!(engage_exit_ipv6("gw_a").is_err());
        assert!(apply_tun_rp_filter("gw_a").is_err());
        let kernel = kernel.borrow();
        assert!(kernel.calls.is_empty());
        assert!(kernel.leases.is_empty());
    });
}

#[test]
fn gateway_identity_loss_after_query_refuses_firewall_add() {
    for ipv6 in [false, true] {
        run(|kernel| {
            kernel.borrow_mut().lose_after_command = Some(("-C".into(), false));
            let result = if ipv6 {
                engage_ipv6("gw_a", "", true)
            } else {
                engage("gw_a", "", true)
            };
            assert!(result.is_err());
            assert_eq!(kernel.borrow().mutations(), 0);
            assert!(cleanup("gw_a").is_err());
            assert!(kernel.borrow().releases.is_empty());
            recover();
            cleanup("gw_a").unwrap();
        });
    }
}

#[test]
fn gateway_identity_loss_during_sysctl_stops_firewall() {
    for namespace in [false, true] {
        run(|kernel| {
            kernel.borrow_mut().lose_after_acquire = Some(namespace);
            assert!(engage("gw_a", "", true).is_err());
            assert_eq!(kernel.borrow().mutations(), 0);
            assert!(cleanup("gw_a").is_err());
            assert!(kernel.borrow().releases.is_empty());
            recover();
            cleanup("gw_a").unwrap();
        });
    }
}

#[test]
fn gateway_identity_best_effort_mss_cannot_hide_lost_tun() {
    run(|kernel| {
        kernel.borrow_mut().lose_after_command = Some(("TCPMSS".into(), false));
        assert!(engage("gw_a", "", true).is_err());
        assert!(kernel.borrow().count(false, "gw_a") > 0);
        recover();
        assert!(
            engage("gw_a", "", true).is_err(),
            "failed generation revived"
        );
        cleanup("gw_a").unwrap();
    });
}

#[test]
fn gateway_identity_roaming_loss_after_wan_query_blocks_new_rules() {
    run(|kernel| {
        kernel.borrow_mut().wans[0] = Some("wan0".into());
        engage_exit("gw_a").unwrap();
        let before = kernel.borrow().mutations();
        kernel.borrow_mut().wans[0] = Some("wan1".into());
        kernel.borrow_mut().lose_after_command = Some(("default".into(), true));
        assert!(refresh_exit_paths_if_active("gw_a").is_err());
        assert_eq!(kernel.borrow().mutations(), before);
        recover();
        disengage_plan("gw_a").unwrap();
    });
}

#[test]
fn gateway_identity_foreign_namespace_preserves_rules_and_sysctls() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_a", true);
        let rules = kernel.borrow().rules.clone();
        let calls = kernel.borrow().calls.len();
        lose(true);
        assert!(cleanup("gw_a").is_err());
        assert_eq!(kernel.borrow().calls.len(), calls);
        assert_eq!(kernel.borrow().rules, rules);
        assert!(kernel.borrow().releases.is_empty());
        recover();
        cleanup("gw_a").unwrap();
        assert_eq!(
            kernel.borrow().count(false, "gw_a") + kernel.borrow().count(true, "gw_a"),
            0
        );
    });
}

#[test]
fn gateway_identity_cleanup_rechecks_namespace_before_delete() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_a", true);
        let mutations = kernel.borrow().mutations();
        kernel.borrow_mut().lose_after_command = Some(("-C".into(), true));
        assert!(cleanup("gw_a").is_err());
        assert_eq!(kernel.borrow().mutations(), mutations);
        assert!(kernel.borrow().releases.is_empty());
        recover();
        cleanup("gw_a").unwrap();
    });
}

#[test]
fn gateway_identity_lost_tun_allows_rule_cleanup_but_retains_sysctls() {
    run(|kernel| {
        engage_family("gw_a", false);
        engage_family("gw_a", true);
        lose(false);
        assert!(cleanup("gw_a").is_err());
        assert_eq!(
            kernel.borrow().count(false, "gw_a") + kernel.borrow().count(true, "gw_a"),
            0
        );
        assert!(kernel.borrow().releases.is_empty());
        assert!(!kernel.borrow().leases.is_empty());
        recover();
        cleanup("gw_a").unwrap();
        assert!(kernel.borrow().leases.is_empty());
    });
}

#[test]
fn gateway_identity_namespace_loss_after_delete_retains_failed_family() {
    run(|kernel| {
        engage_family("gw_a", false);
        kernel.borrow_mut().lose_after_command = Some(("-D".into(), true));
        assert!(cleanup("gw_a").is_err());
        assert!(GATEWAY_SCOPES.lock().unwrap().contains_key("gw_a"));
        assert!(kernel.borrow().releases.is_empty());
        recover();
        cleanup("gw_a").unwrap();
        assert!(!GATEWAY_SCOPES.lock().unwrap().contains_key("gw_a"));
    });
}
