//! Shared-WAN ownership through the actual public exit-node entry points.
use super::*;

fn start(kernel: &Rc<RefCell<Kernel>>, tun: &str, wan: &str, ipv6: bool) {
    kernel.borrow_mut().wans[usize::from(ipv6)] = Some(wan.into());
    if ipv6 {
        engage_exit_ipv6(tun).unwrap();
    } else {
        engage_exit(tun).unwrap();
    }
}
fn stop(tun: &str) -> anyhow::Result<()> {
    disengage_plan(tun)
}
fn nat_count(kernel: &Rc<RefCell<Kernel>>, wan: &str, ipv6: bool) -> usize {
    kernel
        .borrow()
        .rules
        .get(&(ipv6, "nat".into(), "POSTROUTING".into()))
        .map(|rules| {
            rules
                .iter()
                .filter(|rule| {
                    rule.windows(2).any(|p| p == ["-o", wan])
                        && rule.iter().any(|s| s == "MASQUERADE")
                })
                .count()
        })
        .unwrap_or(0)
}
fn retained_tun(tun: &str, ipv6: bool) -> Vec<String> {
    exit_wans_for(if ipv6 { &EXIT_WANS_V6 } else { &EXIT_WANS_V4 }, tun)
}
fn shared_wan(ipv6: bool) {
    run(|k| {
        start(&k, "ex_a", "wan0", ipv6);
        start(&k, "ex_b", "wan0", ipv6);
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", ipv6), 1, "sibling lost its NAT");
        assert_eq!(k.borrow().count(ipv6, "ex_b"), 5);
        stop("ex_b").unwrap();
        assert_eq!(nat_count(&k, "wan0", ipv6), 0);
    });
}
#[test]
fn regression_shared_wan_ipv4_survives_sibling_stop() {
    shared_wan(false);
}
#[test]
fn regression_shared_wan_ipv6_survives_sibling_stop() {
    shared_wan(true);
}

#[test]
fn regression_unstarted_exit_cannot_remove_active_nat() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        stop("unused").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 1);
        stop("ex_a").unwrap();
    });
}
#[test]
fn regression_inactive_cleanup_never_discovers_or_inspects_wan() {
    run(|k| {
        k.borrow_mut().wans = [Some("wan0".into()), Some("wan6".into())];
        stop("unused").unwrap();
        assert!(
            k.borrow().calls.is_empty(),
            "no recorded firewall ownership"
        );
    });
}
#[test]
fn regression_clean_family_does_not_reappear_during_retry() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        start(&k, "ex_a", "wan6", true);
        k.borrow_mut().delete_fault = Some(false);
        assert!(stop("ex_a").is_err());
        start(&k, "ex_b", "wan6", true);
        k.borrow_mut().delete_fault = None;
        stop("ex_a").unwrap();
        assert_eq!(
            nat_count(&k, "wan6", true),
            1,
            "retry touched the already-clean family"
        );
        stop("ex_b").unwrap();
    });
}
#[test]
fn regression_roaming_cleanup_preserves_each_wan_sibling() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        start(&k, "ex_b", "wan0", false);
        start(&k, "ex_c", "wan1", false);
        k.borrow_mut().wans[0] = Some("wan1".into());
        refresh_exit_paths_if_active("ex_a").unwrap();
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 1);
        assert_eq!(nat_count(&k, "wan1", false), 1);
        stop("ex_b").unwrap();
        stop("ex_c").unwrap();
    });
}
#[test]
fn ipv6_roaming_rejects_wan_change_during_firewall_refresh() {
    run(|k| {
        start(&k, "ex_a", "wan0", true);
        k.borrow_mut().wans[1] = Some("wan1".into());
        k.borrow_mut().move_wan_after_command = Some(("TCPMSS".into(), "wan2".into()));
        let error = refresh_exit_paths_if_active("ex_a").unwrap_err();
        assert!(
            error.to_string().contains("IPv6 default route changed"),
            "{error:#}"
        );
        assert_eq!(retained_tun("ex_a", true), ["wan0", "wan1"]);
        assert_eq!(nat_count(&k, "wan1", true), 1);
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", true) + nat_count(&k, "wan1", true), 0);
    });
}

#[test]
fn regression_nat_rules_have_independent_tun_identity() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        start(&k, "ex_b", "wan0", false);
        assert_eq!(nat_count(&k, "wan0", false), 2);
        let state = k.borrow();
        let rules = &state.rules[&(false, "nat".into(), "POSTROUTING".into())];
        assert!(rules.iter().any(|r| r
            .windows(2)
            .any(|p| p == ["--comment", "qeli-exit-node:ex_a"])));
        assert!(rules.iter().any(|r| r
            .windows(2)
            .any(|p| p == ["--comment", "qeli-exit-node:ex_b"])));
    });
}
#[test]
fn different_wans_clean_independently() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        start(&k, "ex_b", "wan1", false);
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 0);
        assert_eq!(nat_count(&k, "wan1", false), 1);
        stop("ex_b").unwrap();
    });
}
#[test]
fn reconnect_deduplicates_each_tun_wan_rule() {
    run(|k| {
        for ipv6 in [false, true] {
            start(&k, "ex_a", "wan0", ipv6);
            start(&k, "ex_a", "wan0", ipv6);
            assert_eq!(nat_count(&k, "wan0", ipv6), 1);
            assert_eq!(retained_tun("ex_a", ipv6), ["wan0"]);
        }
        stop("ex_a").unwrap();
        assert!(k.borrow().leases.is_empty());
    });
}
#[test]
fn partial_exit_setup_remembers_mark_for_rollback() {
    run(|k| {
        k.borrow_mut().wans[0] = Some("wan0".into());
        k.borrow_mut().fail_nat_add = true;
        assert!(engage_exit("ex_a").is_err());
        assert_eq!(retained_tun("ex_a", false), ["wan0"]);
        assert_eq!(k.borrow().count(false, "ex_a"), 1);
        stop("ex_a").unwrap();
        assert_eq!(k.borrow().count(false, "ex_a"), 0);
        assert!(retained_tun("ex_a", false).is_empty());
        assert!(k.borrow().leases.is_empty());
    });
}
#[test]
fn cleanup_retry_remembers_original_wan_after_route_disappears() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        k.borrow_mut().fail_mark_delete = true;
        assert!(stop("ex_a").is_err());
        assert_eq!(retained_tun("ex_a", false), ["wan0"]);
        k.borrow_mut().wans[0] = None;
        k.borrow_mut().fail_mark_delete = false;
        stop("ex_a").unwrap();
        assert!(retained_tun("ex_a", false).is_empty());
        assert_eq!(k.borrow().count(false, "ex_a"), 0);
    });
}
#[test]
fn dual_stack_can_use_different_wans_and_restore_sysctls() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        start(&k, "ex_a", "wan6", true);
        stop("ex_a").unwrap();
        assert_eq!(
            nat_count(&k, "wan0", false) + nat_count(&k, "wan6", true),
            0
        );
        assert!(k.borrow().leases.is_empty());
    });
}

#[test]
fn distinct_process_nat_identity_is_preserved_without_local_owner() {
    run(|k| {
        let external = exit_masq_rule("wan0", "qeli-exit-node:external")
            .iter()
            .map(|s| s.to_string())
            .collect();
        k.borrow_mut()
            .rules
            .insert((false, "nat".into(), "POSTROUTING".into()), vec![external]);
        start(&k, "ex_a", "wan0", false);
        assert_eq!(nat_count(&k, "wan0", false), 2);
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 1);
        assert!(
            k.borrow().rules[&(false, "nat".into(), "POSTROUTING".into())][0]
                .contains(&"qeli-exit-node:external".to_string())
        );
    });
}
#[test]
fn legacy_unsuffixed_nat_is_preserved_for_explicit_recovery() {
    run(|k| {
        let legacy = exit_masq_rule("wan0", EXIT_TAG)
            .iter()
            .map(|s| s.to_string())
            .collect();
        k.borrow_mut()
            .rules
            .insert((false, "nat".into(), "POSTROUTING".into()), vec![legacy]);
        start(&k, "ex_a", "wan0", false);
        assert_eq!(nat_count(&k, "wan0", false), 2);
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 1);
        assert!(
            k.borrow().rules[&(false, "nat".into(), "POSTROUTING".into())][0]
                .contains(&EXIT_TAG.to_string())
        );
    });
}
#[test]
fn partial_nat_failure_does_not_borrow_or_remove_sibling_rule() {
    run(|k| {
        start(&k, "ex_b", "wan0", false);
        k.borrow_mut().fail_nat_add = true;
        assert!(engage_exit("ex_a").is_err());
        stop("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan0", false), 1);
        assert_eq!(k.borrow().count(false, "ex_b"), 5);
        stop("ex_b").unwrap();
    });
}
#[test]
fn unknown_cleanup_inspection_retains_exit_scope_for_retry() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        k.borrow_mut().query_fault = Some("iptables: backend unavailable");
        assert!(stop("ex_a").is_err());
        assert_eq!(retained_tun("ex_a", false), ["wan0"]);
        stop("ex_a").unwrap();
        assert!(retained_tun("ex_a", false).is_empty());
        assert_eq!(nat_count(&k, "wan0", false), 0);
    });
}

#[test]
fn exit_guard_stays_ahead_of_permits_across_wan_refresh() {
    for ipv6 in [false, true] {
        run(|k| {
            start(&k, "ex_a", "wan0", ipv6);
            let guard: Vec<String> = exit_unmarked_drop("ex_a")
                .into_iter()
                .map(str::to_owned)
                .collect();
            {
                let kernel = k.borrow();
                let rules = &kernel.rules[&(ipv6, "filter".into(), "FORWARD".into())];
                assert_eq!(rules.first(), Some(&guard));
            }
            k.borrow_mut().wans[usize::from(ipv6)] = Some("wan1".into());
            refresh_exit_paths_if_active("ex_a").unwrap();
            {
                let kernel = k.borrow();
                let rules = &kernel.rules[&(ipv6, "filter".into(), "FORWARD".into())];
                assert_eq!(rules.first(), Some(&guard));
            }
            stop("ex_a").unwrap();
            assert_eq!(k.borrow().count(ipv6, "ex_a"), 0);
        });
    }
}

#[test]
fn failed_exit_cleanup_keeps_full_tun_lockdown_until_retry() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        k.borrow_mut().fail_mark_delete = true;
        assert!(stop("ex_a").is_err());
        let lockdown: Vec<String> = exit_lockdown_drop("ex_a")
            .into_iter()
            .map(str::to_owned)
            .collect();
        {
            let kernel = k.borrow();
            let rules = &kernel.rules[&(false, "filter".into(), "FORWARD".into())];
            assert_eq!(rules.first(), Some(&lockdown));
        }
        k.borrow_mut().fail_mark_delete = false;
        stop("ex_a").unwrap();
        assert_eq!(k.borrow().count(false, "ex_a"), 0);
    });
}

#[test]
fn exit_guard_refuses_a_forward_kill_switch_hook_that_can_accept_tun_ingress() {
    run(|kernel| {
        kernel.borrow_mut().rules.insert(
            (false, "filter".into(), "FORWARD".into()),
            vec![vec!["-j".into(), "QELI_KS_ex_a".into()]],
        );
        kernel.borrow_mut().wans[0] = Some("wan0".into());
        assert!(engage_exit("ex_a").is_err());
        assert_eq!(kernel.borrow().mutations(), 0);
    });
}

#[test]
fn exit_wan_snapshot_tracks_a_separate_default_change() {
    run(|k| {
        assert!(exit_wan_snapshot_if_active("ex_a").unwrap().is_none());
        start(&k, "ex_a", "wan0", false);
        let initial = exit_wan_snapshot_if_active("ex_a").unwrap().unwrap();
        assert_eq!(initial.ipv4.as_deref(), Some("wan0"));
        assert_eq!(initial.ipv6, None);
        k.borrow_mut().wans[0] = Some("wan1".into());
        let changed = exit_wan_snapshot_if_active("ex_a").unwrap().unwrap();
        assert_eq!(changed.ipv4.as_deref(), Some("wan1"));
        assert_ne!(initial, changed);
        assert_eq!(nat_count(&k, "wan1", false), 0);
        refresh_exit_paths_if_active("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan1", false), 1);
        stop("ex_a").unwrap();
        assert!(exit_wan_snapshot_if_active("ex_a").unwrap().is_none());
    });
}

#[test]
fn partial_refresh_still_exposes_selected_wan_for_retry() {
    run(|k| {
        start(&k, "ex_a", "wan0", false);
        k.borrow_mut().wans[0] = Some("wan1".into());
        k.borrow_mut().fail_nat_add = true;
        assert!(refresh_exit_paths_if_active("ex_a").is_err());
        assert_eq!(retained_tun("ex_a", false), ["wan0", "wan1"]);
        assert_eq!(
            exit_wan_snapshot_if_active("ex_a")
                .unwrap()
                .unwrap()
                .ipv4
                .as_deref(),
            Some("wan1")
        );
        k.borrow_mut().fail_nat_add = false;
        refresh_exit_paths_if_active("ex_a").unwrap();
        assert_eq!(nat_count(&k, "wan1", false), 1);
        stop("ex_a").unwrap();
    });
}

#[test]
fn exit_rejects_its_own_tun_as_wan_before_mutating() {
    for ipv6 in [false, true] {
        run(|k| {
            let family = usize::from(ipv6);
            k.borrow_mut().wans[family] = Some("ex_a".into());
            let error = if ipv6 {
                engage_exit_ipv6("ex_a")
            } else {
                engage_exit("ex_a")
            }
            .unwrap_err();
            assert!(error.to_string().contains("cannot be its own WAN"));
            assert_eq!(k.borrow().mutations(), 0);
            assert!(retained_tun("ex_a", ipv6).is_empty());

            start(&k, "ex_a", "wan0", ipv6);
            let before = k.borrow().mutations();
            k.borrow_mut().wans[family] = Some("ex_a".into());
            assert!(refresh_exit_paths_if_active("ex_a")
                .unwrap_err()
                .to_string()
                .contains("cannot be its own WAN"));
            assert_eq!(k.borrow().mutations(), before);
            assert_eq!(retained_tun("ex_a", ipv6), ["wan0"]);
            stop("ex_a").unwrap();
        });
    }
}
