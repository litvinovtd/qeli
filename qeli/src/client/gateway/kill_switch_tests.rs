//! Public kill-switch admission must preserve an already protected profile.
use super::*;
#[cfg(all(target_os = "linux", feature = "client"))]
use crate::client::killswitch as ks;
#[cfg(all(test, not(all(target_os = "linux", feature = "client"))))]
use crate::client_killswitch as ks;

fn protect(tun: &str, addr: &str) -> anyhow::Result<()> {
    engage(addr, 443, tun, false, false, true)
}
fn seed(kernel: &mut Kernel, ipv6: bool, name: &str) {
    kernel.rules.insert(
        (ipv6, "filter".into(), name.into()),
        vec![vec!["-j".into(), "DROP".into()]],
    );
    kernel.rules.insert(
        (ipv6, "filter".into(), "OUTPUT".into()),
        vec![vec!["-j".into(), name.into()]],
    );
}
fn allow_egress(kernel: &Kernel, chain: &str, out: &str, dest: &str, depth: usize) -> bool {
    assert!(depth < 8);
    for rule in kernel
        .rules
        .get(&(false, "filter".into(), chain.into()))
        .into_iter()
        .flatten()
    {
        let value = |flag: &str| {
            rule.windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].as_str())
        };
        if value("-o").is_some_and(|x| x != out)
            || value("-i").is_some()
            || value("-d").is_some_and(|x| x != dest)
            || value("-p").is_some_and(|x| x != "tcp")
        {
            continue;
        }
        match value("-j") {
            Some("ACCEPT") => return true,
            Some("DROP") => return false,
            Some(target) if target.starts_with("QELI_KS") => {
                return allow_egress(kernel, target, out, dest, depth + 1)
            }
            _ => panic!("unsupported model verdict: {rule:?}"),
        }
    }
    false
}
#[test]
fn regression_second_kill_switch_preserves_first_profile() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        assert!(allow_egress(
            &k.borrow(),
            "OUTPUT",
            "wan0",
            "203.0.113.7",
            0
        ));
        let before = k.borrow().mutations();
        let result = protect("ks_b", "203.0.113.8");
        assert!(
            allow_egress(&k.borrow(), "OUTPUT", "wan0", "203.0.113.7", 0),
            "new terminal DROP blocks the first carrier"
        );
        assert!(
            result.is_err(),
            "incompatible host-wide policies must not both be accepted"
        );
        assert_eq!(k.borrow().mutations(), before);
    });
}
#[test]
fn regression_ipv6_conflict_is_checked_before_any_ipv4_mutation() {
    run(|k| {
        seed(&mut k.borrow_mut(), true, "QELI_KS_other");
        let before = k.borrow().rules.clone();
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
        assert_eq!(
            k.borrow()
                .rules
                .get(&(true, "filter".into(), "QELI_KS_other".into())),
            before.get(&(true, "filter".into(), "QELI_KS_other".into()))
        );
    });
}
#[test]
fn regression_unknown_inventory_does_not_authorize_installation() {
    run(|k| {
        k.borrow_mut().inventory_failure = Some(false);
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn regression_truncated_inventory_does_not_authorize_installation() {
    run(|k| {
        k.borrow_mut().inventory_override = Some((false, b"-P OUTPUT ACCEPT\n".to_vec()));
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn regression_legacy_chain_is_not_claimed_by_an_unrelated_profile() {
    run(|k| {
        seed(&mut k.borrow_mut(), false, "QELI_KS");
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
        assert!(k
            .borrow()
            .rules
            .contains_key(&(false, "filter".into(), "QELI_KS".into())));
    });
}
#[test]
fn regression_leak_override_does_not_bypass_ownership_conflict() {
    run(|k| {
        seed(&mut k.borrow_mut(), false, "QELI_KS_other");
        assert!(engage("203.0.113.7", 443, "ks_a", true, true, false).is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn own_profile_can_rebuild_its_chain() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        protect("ks_a", "203.0.113.7").unwrap();
        assert!(allow_egress(
            &k.borrow(),
            "OUTPUT",
            "wan0",
            "203.0.113.7",
            0
        ));
        ks::disengage("ks_a").unwrap();
        assert!(!k
            .borrow()
            .rules
            .keys()
            .any(|(_, _, name)| name == "QELI_KS_ks_a"));
    });
}
#[test]
fn independent_administrator_chain_does_not_conflict() {
    run(|k| {
        k.borrow_mut()
            .rules
            .insert((false, "filter".into(), "HOST_FIREWALL".into()), Vec::new());
        protect("ks_a", "203.0.113.7").unwrap();
        ks::disengage("ks_a").unwrap();
        assert!(k
            .borrow()
            .rules
            .contains_key(&(false, "filter".into(), "HOST_FIREWALL".into())));
    });
}

#[test]
fn non_utf8_inventory_refuses_without_mutation() {
    run(|k| {
        k.borrow_mut().inventory_override = Some((false, vec![0xff]));
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn malformed_or_duplicate_inventory_refuses_without_mutation() {
    let prefix = "-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P FORWARD DROP\n";
    for suffix in [
        "-N\n",
        "-P OUTPUT ACCEPT\n",
        "-N INPUT\n",
        "-A undeclared -j DROP\n",
    ] {
        run(|k| {
            k.borrow_mut().inventory_override =
                Some((false, format!("{prefix}{suffix}").into_bytes()));
            assert!(protect("ks_a", "203.0.113.7").is_err());
            assert_eq!(k.borrow().mutations(), 0);
        });
    }
}
#[test]
fn ipv6_inspection_error_refuses_before_any_ipv4_mutation() {
    run(|k| {
        k.borrow_mut().inventory_failure = Some(true);
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn unhooked_foreign_chain_requires_explicit_recovery() {
    run(|k| {
        k.borrow_mut()
            .rules
            .insert((false, "filter".into(), "QELI_KS_stale".into()), Vec::new());
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn another_profile_can_start_after_verified_cleanup() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        ks::disengage("ks_a").unwrap();
        protect("ks_b", "203.0.113.8").unwrap();
        assert!(allow_egress(
            &k.borrow(),
            "OUTPUT",
            "wan0",
            "203.0.113.8",
            0
        ));
        ks::disengage("ks_b").unwrap();
    });
}
#[test]
fn concurrent_public_start_admits_only_one_policy() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ks::ownership::test_support::clear();
    let kernel = std::sync::Arc::new(Mutex::new(Kernel::default()));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [("ks_a", "203.0.113.7"), ("ks_b", "203.0.113.8")]
        .into_iter()
        .map(|(tun, ip)| {
            let kernel = kernel.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                ks::ipv6_state::test_support::with_disabled(false, || {
                    with_commands(
                        move |cmd| Action::Reply(kernel.lock().unwrap().command(cmd)),
                        || {
                            barrier.wait();
                            ks::ownership::test_support::with_namespace(
                                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
                                || protect(tun, ip).is_ok(),
                            )
                        },
                    )
                })
            })
        })
        .collect();
    let successful: usize = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum();
    assert_eq!(successful, 1);
    let chains: Vec<_> = kernel
        .lock()
        .unwrap()
        .rules
        .keys()
        .filter(|(v6, _, name)| !*v6 && name.starts_with("QELI_KS_"))
        .cloned()
        .collect();
    assert_eq!(chains.len(), 1);
    ks::ownership::test_support::clear();
}

// Force IPv6 firewall installation to fail after IPv4 has been armed.
fn failed_ipv6(k: &Rc<RefCell<Kernel>>) {
    k.borrow_mut().fail_ipv6_drop = true;
}
fn assert_ipv4_removed(k: &Rc<RefCell<Kernel>>) {
    assert!(!k
        .borrow()
        .rules
        .contains_key(&(false, "filter".into(), "QELI_KS_ks_a".into())));
}
#[test]
fn regression_failed_ipv6_firewall_refuses_and_rolls_back_ipv4() {
    run(|k| {
        failed_ipv6(&k);
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_ipv4_removed(&k);
    });
}
#[test]
fn regression_ipv6_refusal_reports_failed_ipv4_rollback() {
    run(|k| {
        failed_ipv6(&k);
        k.borrow_mut().lie_delete = true;
        let error = protect("ks_a", "203.0.113.7").unwrap_err().to_string();
        assert!(error.contains("rollback"), "{error}");
        assert!(k
            .borrow()
            .rules
            .contains_key(&(false, "filter".into(), "QELI_KS_ks_a".into())));
    });
}
#[test]
fn regression_missing_ipv4_firewall_refuses_before_default_route_arrives() {
    run(|k| {
        let error =
            ks::ownership::test_support::with_paths([None, Some("model-ip6tables".into())], || {
                engage("2001:db8::7", 443, "ks_a", false, false, true)
                    .unwrap_err()
                    .to_string()
            });
        assert!(error.contains("IPv4 can become active"), "{error}");
        assert_eq!(k.borrow().mutations(), 0);
        assert!(
            !k.borrow()
                .calls
                .iter()
                .any(|args| args == &["-4", "route", "show", "default"]),
            "a route snapshot cannot prove lifetime safety"
        );
    });
}
#[test]
fn explicit_ipv4_leak_override_allows_missing_firewall() {
    run(|k| {
        ks::ownership::test_support::with_paths([None, Some("model-ip6tables".into())], || {
            engage("2001:db8::7", 443, "ks_a", true, false, true).unwrap()
        });
        assert!(k
            .borrow()
            .rules
            .contains_key(&(true, "filter".into(), "QELI_KS_ks_a".into())));
        ks::disengage("ks_a").unwrap();
    });
}

#[test]
fn regression_missing_ipv6_firewall_refuses_even_before_global_address_arrives() {
    run(|k| {
        let error =
            ks::ownership::test_support::with_paths([Some("model-iptables".into()), None], || {
                protect("ks_a", "203.0.113.7").unwrap_err().to_string()
            });
        assert!(error.contains("IPv6 can become active"), "{error}");
        assert_ipv4_removed(&k);
        assert!(
            !k.borrow()
                .calls
                .iter()
                .any(|args| args == &["-6", "address", "show", "scope", "global"]),
            "an address snapshot cannot prove lifetime safety"
        );
    });
}
#[test]
fn explicit_ipv6_leak_override_allows_missing_firewall() {
    run(|k| {
        ks::ownership::test_support::with_paths([Some("model-iptables".into()), None], || {
            engage("203.0.113.7", 443, "ks_a", false, true, true).unwrap()
        });
        assert!(k
            .borrow()
            .rules
            .contains_key(&(false, "filter".into(), "QELI_KS_ks_a".into())));
    });
}

#[test]
fn regression_module_disabled_allows_ipv4_without_ipv6_filter_inventory() {
    run(|k| {
        k.borrow_mut().inventory_failure = Some(true);
        ks::ipv6_state::test_support::with_disabled(true, || {
            protect("ks_a", "203.0.113.7").unwrap();
            assert!(allow_egress(
                &k.borrow(),
                "OUTPUT",
                "wan0",
                "203.0.113.7",
                0
            ));
        });
    });
}
#[test]
fn regression_module_disabled_lifecycle_never_touches_ipv6_tables() {
    run(|k| {
        ks::ipv6_state::test_support::with_disabled(true, || {
            protect("ks_a", "203.0.113.7").unwrap();
            refresh_server_ips("203.0.113.8", 443, "ks_a").unwrap();
            ks::disengage("ks_a").unwrap();
            assert!(!k.borrow().rules.keys().any(|(ipv6, _, _)| *ipv6));
        });
    });
}
#[test]
fn absent_disabled_evidence_keeps_inventory_failure_fatal() {
    run(|k| {
        k.borrow_mut().inventory_failure = Some(true);
        assert!(protect("ks_a", "203.0.113.7").is_err());
        assert_eq!(k.borrow().mutations(), 0);
    });
}
#[test]
fn module_disabled_does_not_bypass_ipv4_ownership_conflict() {
    run(|k| {
        seed(&mut k.borrow_mut(), false, "QELI_KS_other");
        ks::ipv6_state::test_support::with_disabled(true, || {
            assert!(protect("ks_a", "203.0.113.7").is_err());
            assert_eq!(k.borrow().mutations(), 0);
        });
    });
}
#[test]
fn module_disabled_does_not_bypass_unknown_ipv4_inventory() {
    run(|k| {
        k.borrow_mut().inventory_failure = Some(false);
        ks::ipv6_state::test_support::with_disabled(true, || {
            assert!(protect("ks_a", "203.0.113.7").is_err());
            assert_eq!(k.borrow().mutations(), 0);
        });
    });
}

#[test]
fn regression_kill_switch_namespace_change_preserves_foreign_chain() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        ks::ownership::test_support::set_namespace(2);
        let before = k.borrow().calls.len();
        assert!(refresh_server_ips("203.0.113.8", 443, "ks_a").is_err());
        assert!(ks::disengage("ks_a").is_err());
        assert!(engage("203.0.113.8", 443, "ks_a", true, true, false).is_err());
        assert_eq!(
            k.borrow().calls.len(),
            before,
            "no command in the wrong namespace"
        );
        ks::ownership::test_support::set_namespace(1);
        assert!(
            protect("ks_a", "203.0.113.7").is_err(),
            "identity loss remains sticky"
        );
        ks::disengage("ks_a").unwrap();
        protect("ks_a", "203.0.113.7").unwrap();
        ks::disengage("ks_a").unwrap();
    });
}
#[test]
fn regression_identity_loss_after_mutation_cannot_use_leak_override() {
    run(|k| {
        k.borrow_mut().lose_kill_namespace_after = Some("-N".into());
        assert!(engage("203.0.113.7", 443, "ks_a", true, true, false).is_err());
        assert_eq!(k.borrow().calls.last().unwrap()[0], "-N");
        let before = k.borrow().calls.len();
        assert!(ks::disengage("ks_a").is_err());
        assert_eq!(k.borrow().calls.len(), before);
        ks::ownership::test_support::set_namespace(1);
        ks::disengage("ks_a").unwrap();
        assert_ipv4_removed(&k);
    });
}
#[test]
fn regression_cleanup_identity_loss_retains_retry_authority() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        k.borrow_mut().lose_kill_namespace_after = Some("-D".into());
        assert!(ks::disengage("ks_a").is_err());
        assert_eq!(k.borrow().calls.last().unwrap()[0], "-D");
        ks::ownership::test_support::set_namespace(1);
        ks::disengage("ks_a").unwrap();
        assert_ipv4_removed(&k);
    });
}
#[test]
fn regression_refresh_identity_loss_stops_after_current_command() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        k.borrow_mut().lose_kill_namespace_after = Some("-I".into());
        assert!(refresh_server_ips("203.0.113.8", 443, "ks_a").is_err());
        assert_eq!(k.borrow().calls.last().unwrap()[0], "-I");
        ks::ownership::test_support::set_namespace(1);
        ks::disengage("ks_a").unwrap();
    });
}
#[test]
fn regression_cleanup_without_owner_preserves_same_name_rules() {
    run(|k| {
        seed(&mut k.borrow_mut(), false, "QELI_KS_ks_a");
        let before = k.borrow().rules.clone();
        ks::disengage("ks_a").unwrap();
        assert_eq!(k.borrow().rules, before);
        assert!(k.borrow().calls.is_empty());
    });
}
#[test]
fn regression_disappeared_ipv6_tool_is_not_successful_cleanup() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        k.borrow_mut().missing_firewall = Some(true);
        assert!(ks::disengage("ks_a").is_err());
        k.borrow_mut().missing_firewall = None;
        ks::disengage("ks_a").unwrap();
        assert!(!k
            .borrow()
            .rules
            .keys()
            .any(|(_, _, chain)| chain == "QELI_KS_ks_a"));
    });
}
#[test]
fn regression_cleanup_error_retains_owner_until_verified_retry() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        k.borrow_mut().lie_delete = true;
        assert!(ks::disengage("ks_a").is_err());
        k.borrow_mut().lie_delete = false;
        ks::disengage("ks_a").unwrap();
        assert_ipv4_removed(&k);
        let before = k.borrow().calls.len();
        ks::disengage("ks_a").unwrap();
        assert_eq!(k.borrow().calls.len(), before);
    });
}
#[test]
fn regression_reconnect_rejects_removed_output_forward_or_drop() {
    for (chain, rule) in [
        ("OUTPUT", vec!["-j", "QELI_KS_ks_a"]),
        ("FORWARD", vec!["-j", "QELI_KS_ks_a"]),
        ("QELI_KS_ks_a", vec!["-j", "DROP"]),
    ] {
        run(|k| {
            protect("ks_a", "203.0.113.7").unwrap();
            k.borrow_mut()
                .rules
                .get_mut(&(false, "filter".into(), chain.into()))
                .unwrap()
                .retain(|existing| existing != &rule);
            let before = k.borrow().mutations();
            assert!(refresh_server_ips("203.0.113.8", 443, "ks_a").is_err());
            // The intact IPv6 family has no new server address, so no mutations.
            assert_eq!(k.borrow().mutations(), before);
            ks::disengage("ks_a").unwrap();
        });
    }
}

#[test]
fn regression_refresh_failed_add_keeps_previous_server_allowance() {
    run(|k| {
        protect("ks_a", "203.0.113.7").unwrap();
        k.borrow_mut().lie_add = true;
        assert!(refresh_server_ips("203.0.113.8", 443, "ks_a").is_err());
        assert!(allow_egress(
            &k.borrow(),
            "OUTPUT",
            "wan0",
            "203.0.113.7",
            0
        ));
        k.borrow_mut().lie_add = false;
        ks::disengage("ks_a").unwrap();
    });
}

#[test]
fn regression_explicit_ipv6_only_cleanup_never_requires_unprogrammed_ipv4() {
    run(|k| {
        ks::ownership::test_support::with_paths([None, Some("model-ip6tables".into())], || {
            engage("2001:db8::7", 443, "ks_a", true, false, true).unwrap();
            refresh_server_ips("2001:db8::8", 443, "ks_a").unwrap();
            ks::disengage("ks_a").unwrap();
            assert!(k.borrow().rules.keys().all(|(ipv6, _, _)| *ipv6));
        });
    });
}

// Keep namespace and thread-local fault fixtures on their owning test thread.
fn engage(
    host: &str,
    port: u16,
    tun: &str,
    allow_ipv4_leak: bool,
    allow_ipv6_leak: bool,
    guard_forward: bool,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(ks::prepare_engage(
            host,
            port,
            tun,
            allow_ipv4_leak,
            allow_ipv6_leak,
            guard_forward,
        ))?()
}
fn refresh_server_ips(host: &str, port: u16, tun: &str) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(ks::prepare_refresh(host, port, tun))?()
}
