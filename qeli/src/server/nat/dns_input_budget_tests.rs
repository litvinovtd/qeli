//! DNS INPUT lease deadlines use the shared private rule model, never the host firewall.
use super::test_support::{budget, deadline, Fixture};
use super::*;
use std::time::{Duration, Instant};

fn setup(f: &Fixture, ms: u64) -> anyhow::Result<DnsInputLease> {
    enable_dns_input_until(
        &f.profile,
        "vpn0",
        "192.0.2.0/24",
        "192.0.2.1",
        53,
        Budget::for_operation("DNS INPUT setup")
            .with_deadline(Instant::now() + Duration::from_millis(ms)),
    )
}
fn pending(f: &Fixture) -> bool {
    let mut seen = false;
    let _ = dns_input_registry()
        .lock()
        .unwrap()
        .retry(Some(&f.profile), |_| {
            seen = true;
            anyhow::bail!("inspect pending evidence")
        });
    seen
}

#[test]
fn cleanup_expiry_retires_before_firewall_and_registry_admission() {
    let f = Fixture::new();
    f.run(|| {
        for phase in 0..3 {
            let mut lease = f.dns_lease();
            let before = f.calls("iptables");
            if phase == 0 {
                deadline(lease.cleanup_until(budget(0)));
            } else if phase == 1 {
                let held = firewall_program_lock().lock().unwrap();
                deadline(lease.cleanup_until(budget(30)));
                drop(held);
            } else {
                let mut held = dns_input_registry().lock().unwrap();
                deadline(lease.cleanup_until(budget(30)));
                let mut retired = false;
                assert!(held
                    .retry(Some(&f.profile), |_| {
                        retired = true;
                        anyhow::bail!("pending")
                    })
                    .is_err());
                assert!(retired);
                drop(held);
            }
            assert!(
                pending(&f),
                "timed-out admission stranded an active generation"
            );
            assert_eq!(before, f.calls("iptables"));
            lease.cleanup_until(budget(2000)).unwrap();
            assert!(lease.owner.is_none());
        }
    });
}

#[test]
fn actual_drop_publishes_retirement_while_firewall_mutex_is_busy() {
    let f = Fixture::new();
    let lease = f.dns_lease();
    let held = firewall_program_lock().lock().unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| f.run(|| drop(lease)));
        let until = Instant::now() + Duration::from_secs(2);
        let seen = loop {
            if pending(&f) {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        let untouched = f.calls("iptables").is_empty();
        // Release before joining/asserting, including the counterfactual failure path.
        drop(held);
        worker.join().unwrap();
        assert!(seen, "Drop did not publish retirement before waiting");
        assert!(untouched);
    });
    assert!(!pending(&f));
    assert!(!f.dir.join("iptables.INPUT.udp").exists());
    assert!(!f.dir.join("iptables.INPUT.tcp").exists());
}

#[test]
fn lease_queue_consumes_command_budget_and_partial_cleanup_is_retryable() {
    let f = Fixture::new();
    f.run(|| {
        let mut lease = f.dns_lease();
        f.flag("iptables.udp-delay", "0.45");
        let held = firewall_program_lock().lock().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let (result, mut lease) = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                f.run(|| {
                    let b = budget(650);
                    sent.send(()).unwrap();
                    let result = lease.cleanup_until(b);
                    (result, lease)
                })
            });
            received.recv_timeout(Duration::from_secs(2)).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
            worker.join().unwrap()
        });
        deadline(result);
        assert!(pending(&f));
        assert!(!f.dir.join("iptables.INPUT.udp").exists());
        assert!(f.dir.join("iptables.INPUT.tcp").exists());
        assert!(!f.calls("iptables").contains("-p tcp"));
        lease.cleanup_until(budget(2000)).unwrap();
        assert!(!pending(&f));
    });
}

#[test]
fn setup_admission_expiry_does_not_reserve_or_mutate() {
    let f = Fixture::new();
    f.run(|| {
        deadline(setup(&f, 0).map(|_| ()));
        let held = firewall_program_lock().lock().unwrap();
        deadline(setup(&f, 30).map(|_| ()));
        drop(held);
        let held = dns_input_registry().lock().unwrap();
        deadline(setup(&f, 30).map(|_| ()));
        drop(held);
        assert!(f.calls("iptables").is_empty());
        dns_input_registry()
            .lock()
            .unwrap()
            .finish_shutdown(|_| panic!("unexpected reservation"))
            .unwrap();
    });
}

#[test]
fn setup_transports_share_deadline_and_rollback_has_fresh_budget() {
    let f = Fixture::new();
    f.run(|| {
        f.flag("iptables.insert-udp-delay", "0.25");
        f.flag("iptables.insert-tcp-delay", "0.45");
        let result = setup(&f, 650);
        assert!(result.is_err(), "setup renewed its deadline for TCP");
        deadline(result.map(|_| ()));
        let calls = f.calls("iptables");
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("-I INPUT"))
                .count(),
            2
        );
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("-D INPUT"))
                .count(),
            2
        );
        assert!(
            !f.dir.join("iptables.INPUT.udp").exists()
                && !f.dir.join("iptables.INPUT.tcp").exists()
        );
        assert!(!pending(&f));
    });
}

#[test]
fn pending_generation_cleanup_consumes_the_new_setup_budget() {
    let f = Fixture::new();
    f.retire_dns();
    f.run(|| {
        f.flag("iptables.udp-delay", "0.25");
        f.flag("iptables.tcp-delay", "0.15");
        f.flag("iptables.insert-udp-delay", "0.3");
        let result = setup(&f, 650);
        assert!(
            result.is_err(),
            "pending cleanup time was excluded from setup"
        );
        deadline(result.map(|_| ()));
        let calls = f.calls("iptables");
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("-I INPUT"))
                .count(),
            1
        );
        assert!(!f.dir.join("iptables.INPUT.udp").exists());
        assert!(!pending(&f));
    });
}

#[test]
fn failed_setup_rollback_retains_pending_owner_and_blocks_replacement() {
    let f = Fixture::new();
    f.run(|| {
        f.flag("iptables.insert-udp-delay", "0.4");
        f.flag("iptables.deny-udp", "1");
        deadline(setup(&f, 100).map(|_| ()));
        assert!(pending(&f));
        assert!(f.dir.join("iptables.INPUT.udp").exists());
        let inserts = f
            .calls("iptables")
            .lines()
            .filter(|line| line.contains("-I INPUT"))
            .count();
        assert!(setup(&f, 1000).is_err());
        assert_eq!(
            f.calls("iptables")
                .lines()
                .filter(|line| line.contains("-I INPUT"))
                .count(),
            inserts
        );
        std::fs::remove_file(f.dir.join("iptables.deny-udp")).unwrap();
        std::fs::remove_file(f.dir.join("iptables.insert-udp-delay")).unwrap();
        let mut current = setup(&f, 2000).unwrap();
        assert!(
            f.dir.join("iptables.INPUT.udp").exists() && f.dir.join("iptables.INPUT.tcp").exists()
        );
        current.cleanup_until(budget(2000)).unwrap();
        assert!(!pending(&f));
    });
}
