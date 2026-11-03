//! Setup, rollback and DNS redirect share operation budgets through real subprocesses.
use super::test_support::{budget, deadline, Fixture};
use super::*;
use std::time::Duration;

fn rule(f: &Fixture, proto: &str, filter: bool) -> Rule {
    Rule {
        table: if filter { "filter" } else { "nat" },
        chain: if filter { "FORWARD" } else { "PREROUTING" },
        args: vec![
            "-p".into(),
            proto.into(),
            "--comment".into(),
            tag(&f.profile),
            "-j".into(),
            "ACCEPT".into(),
        ],
        essential: true,
    }
}
fn install(f: &Fixture, proto: &str, b: Budget) -> anyhow::Result<bool> {
    install_rule(
        &f.profile,
        false,
        f.dir.join("iptables").to_str().unwrap(),
        &rule(f, proto, false),
        b,
    )
}

#[test]
fn setup_admission_never_runs_body_or_rollback_without_lock() {
    let f = Fixture::new();
    f.retain(false, "udp");
    f.run(|| {
        deadline(setup_operation(&f.profile, budget(0), || {
            panic!("expired body")
        }));
        let held = firewall_program_lock().lock().unwrap();
        deadline(setup_operation(&f.profile, budget(30), || {
            panic!("busy body")
        }));
        drop(held);
    });
    assert!(f.calls("iptables").is_empty());
    assert_eq!(f.retained(), [false]);
    f.cleanup();
}

#[test]
fn rule_registry_admission_refuses_untracked_mutation() {
    let f = Fixture::new();
    f.run(|| {
        let _fw = firewall_program_lock().lock().unwrap();
        let _registry = owned_rules().lock().unwrap();
        deadline(install(&f, "udp", budget(30)).map(|_| ()));
        assert!(f.calls("iptables").is_empty());
    });
}

#[test]
fn setup_rules_share_deadline_with_fresh_verified_rollback() {
    let f = Fixture::new();
    f.flag("iptables.insert-udp-delay", "0.25");
    f.flag("iptables.insert-tcp-delay", "0.45");
    f.run(|| {
        let b = budget(650);
        deadline(setup_operation(&f.profile, b, || {
            assert!(install(&f, "udp", b)?);
            assert!(install(&f, "tcp", b)?);
            Ok(())
        }));
    });
    assert!(!f.dir.join("iptables.PREROUTING.udp").exists());
    assert!(!f.dir.join("iptables.PREROUTING.tcp").exists());
    assert!(f.retained().is_empty());
    assert_eq!(
        f.calls("iptables")
            .lines()
            .filter(|l| l.contains("-D PREROUTING"))
            .count(),
        2
    );
}

#[test]
fn setup_queue_consumes_insertion_budget() {
    let f = Fixture::new();
    f.flag("iptables.insert-udp-delay", "0.45");
    let held = firewall_program_lock().lock().unwrap();
    let (sent, received) = std::sync::mpsc::channel();
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            f.run(|| {
                let b = budget(650);
                sent.send(()).unwrap();
                setup_operation(&f.profile, b, || {
                    install(&f, "udp", b)?;
                    install(&f, "tcp", b)?;
                    Ok(())
                })
            })
        });
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        worker.join().unwrap()
    });
    deadline(result);
    assert!(!f.calls("iptables").contains("-p tcp"));
    assert!(f.retained().is_empty());
}

#[test]
fn rollback_shares_deadline_across_families_and_retains_unconfirmed_removal() {
    let f = Fixture::new();
    f.retain(false, "udp");
    f.retain(true, "udp");
    f.flag("iptables.udp-delay", "0.45");
    f.flag("ip6tables.udp-delay", "0.45");
    f.run(|| {
        let _held = firewall_program_lock().lock().unwrap();
        deadline(rollback_setup_until(&f.profile, budget(650)));
    });
    assert_eq!(f.retained(), [true]);
    f.cleanup();
}

#[test]
fn incomplete_setup_rollback_is_reported_and_retained() {
    let f = Fixture::new();
    f.flag("iptables.insert-udp-delay", "0.4");
    f.flag("iptables.deny-udp", "1");
    f.run(|| {
        let b = budget(100);
        let error =
            setup_operation(&f.profile, b, || install(&f, "udp", b).map(|_| ())).unwrap_err();
        assert!(
            format!("{error:#}").contains("NAT rollback incomplete"),
            "{error:#}"
        );
    });
    assert_eq!(f.retained(), [false]);
    assert!(f.dir.join("iptables.PREROUTING.udp").exists());
    std::fs::remove_file(f.dir.join("iptables.deny-udp")).unwrap();
    f.cleanup();
    assert!(!f.dir.join("iptables.PREROUTING.udp").exists());
}

#[test]
fn expired_forward_inventory_cannot_insert_or_fall_back_to_accept() {
    let f = Fixture::new();
    f.flag("iptables.inventory-delay", "0.4");
    f.run(|| {
        let b = budget(100);
        deadline(setup_operation(&f.profile, b, || {
            install_rule(
                &f.profile,
                false,
                f.dir.join("iptables").to_str().unwrap(),
                &rule(&f, "udp", true),
                b,
            )
            .map(|_| ())
        }));
    });
    assert!(f.retained().is_empty());
    assert!(!f.calls("iptables").contains("-I FORWARD"));
}

#[test]
fn late_success_cannot_escape_setup_boundary() {
    let f = Fixture::new();
    f.run(|| {
        deadline(setup_operation(&f.profile, budget(30), || {
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        }))
    });
}

#[test]
fn redirects_share_transport_budget_for_both_families() {
    let f = Fixture::new();
    f.run(|| {
        for (bin, listen) in [("iptables", "192.0.2.1"), ("ip6tables", "2001:db8::1")] {
            f.flag(&format!("{bin}.insert-udp-delay"), "0.25");
            f.flag(&format!("{bin}.insert-tcp-delay"), "0.45");
            deadline(enable_dns_redirect_until(
                &f.profile,
                "vpn0",
                listen,
                5353,
                budget(650),
            ));
            assert!(!f.dir.join(format!("{bin}.PREROUTING.udp")).exists());
            assert!(!f.dir.join(format!("{bin}.PREROUTING.tcp")).exists());
        }
    });
    assert!(f.retained().is_empty());
}

#[test]
fn dns_input_time_consumes_redirect_budget() {
    let f = Fixture::new();
    f.run(|| {
        f.flag("iptables.insert-udp-delay", "0.2");
        f.flag("iptables.insert-tcp-delay", "0.2");
        let b = budget(650);
        let lease =
            enable_dns_input_until(&f.profile, "vpn0", "192.0.2.0/24", "192.0.2.1", 5353, b)
                .unwrap();
        f.flag("iptables.insert-udp-delay", "0.4");
        deadline(enable_dns_redirect_until(
            &f.profile,
            "vpn0",
            "192.0.2.1",
            5353,
            b,
        ));
        drop(lease);
        assert!(!f.dir.join("iptables.INPUT.udp").exists());
        assert!(!f.dir.join("iptables.INPUT.tcp").exists());
        assert!(!f.dir.join("iptables.PREROUTING.udp").exists());
    });
    assert!(f.retained().is_empty());
}
