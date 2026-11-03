use super::*;
use std::cell::Cell;

fn rules(profile: &str) -> DnsInputRules {
    DnsInputRules::new(profile, "tun0", "10.42.0.0/24", "10.42.0.1", 53).unwrap()
}

fn no_pending(_: &DnsInputRules) -> anyhow::Result<()> {
    panic!("active ownership must never be passed to a pending cleanup callback")
}

#[test]
fn reservation_precedes_mutation_and_refuses_duplicate_live_owner() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    assert!(!registry.entries[&id].retired.load(Ordering::Acquire));
    let error = registry
        .begin(rules("edge"), no_pending)
        .unwrap_err()
        .to_string();
    assert!(error.contains("live owner"), "{error}");
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn failed_finish_retains_complete_evidence_for_later_retry() {
    let mut registry = DnsInputRegistry::default();
    let owned = rules("edge");
    let id = registry.begin(owned.clone(), no_pending).unwrap();
    registry
        .finish(id, |_| anyhow::bail!("tool disappeared"))
        .unwrap_err();
    assert!(registry.entries[&id].retired.load(Ordering::Acquire));
    assert_eq!(registry.entries[&id].rules, owned);
    registry
        .retry(Some("edge"), |_| anyhow::bail!("still unavailable"))
        .unwrap_err();
    assert_eq!(registry.entries[&id].rules, owned);
    registry
        .retry(Some("edge"), |spec| {
            assert_eq!(*spec, owned);
            Ok(())
        })
        .unwrap();
    assert!(registry.entries.is_empty());
}

#[test]
fn stale_lease_cannot_delete_replacement_after_successful_retry() {
    let mut registry = DnsInputRegistry::default();
    let old = registry.begin(rules("edge"), no_pending).unwrap();
    registry
        .finish(old, |_| anyhow::bail!("first cleanup failed"))
        .unwrap_err();
    let retried = Cell::new(false);
    let current = registry
        .begin(rules("edge"), |_| {
            retried.set(true);
            Ok(())
        })
        .unwrap();
    assert!(retried.get());
    assert_ne!(old, current);
    registry.finish(old, no_pending).unwrap();
    assert!(!registry.entries[&current].retired.load(Ordering::Acquire));
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn failed_pending_cleanup_blocks_new_generation_before_reservation() {
    let mut registry = DnsInputRegistry::default();
    let old = registry.begin(rules("edge"), no_pending).unwrap();
    registry
        .finish(old, |_| anyhow::bail!("failure"))
        .unwrap_err();
    let replacement =
        DnsInputRules::new("edge", "tun1", "10.43.0.0/24", "10.43.0.1", 5353).unwrap();
    let error = registry
        .begin(replacement, |_| anyhow::bail!("retry denied"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("retry denied"), "{error}");
    assert_eq!(registry.last_id, old.0);
    assert_eq!(registry.entries.len(), 1);
    assert_eq!(registry.entries[&old].rules, rules("edge"));
}

#[test]
fn profile_retry_does_not_touch_active_or_sibling_profile_permits() {
    let mut registry = DnsInputRegistry::default();
    let old = registry.begin(rules("edge"), no_pending).unwrap();
    let sibling = registry.begin(rules("edge2"), no_pending).unwrap();
    let active = registry
        .begin(
            DnsInputRules::new("edge", "tun0", "2001:db8::/64", "2001:db8::1", 53).unwrap(),
            no_pending,
        )
        .unwrap();
    for id in [old, sibling] {
        registry
            .finish(id, |_| anyhow::bail!("failure"))
            .unwrap_err();
    }
    registry
        .retry(Some("edge"), |spec| {
            assert_eq!(spec.profile, "edge");
            assert!(!spec.ipv6);
            Ok(())
        })
        .unwrap();
    assert!(!registry.entries.contains_key(&old));
    assert!(registry.entries[&sibling].retired.load(Ordering::Acquire));
    assert!(!registry.entries[&active].retired.load(Ordering::Acquire));
}

#[test]
fn retry_all_continues_after_failure_and_preserves_failed_entries() {
    let mut registry = DnsInputRegistry::default();
    let first = registry.begin(rules("first"), no_pending).unwrap();
    let second = registry.begin(rules("second"), no_pending).unwrap();
    let active = registry.begin(rules("active"), no_pending).unwrap();
    for id in [first, second] {
        registry
            .finish(id, |_| anyhow::bail!("failure"))
            .unwrap_err();
    }
    let mut seen = Vec::new();
    let error = registry
        .retry(None, |spec| {
            seen.push(spec.profile.clone());
            if spec.profile == "first" {
                anyhow::bail!("still failed");
            }
            Ok(())
        })
        .unwrap_err()
        .to_string();
    assert_eq!(seen, ["first", "second"]);
    assert!(error.contains("first: still failed"), "{error}");
    assert!(registry.entries[&first].retired.load(Ordering::Acquire));
    assert!(!registry.entries.contains_key(&second));
    assert!(!registry.entries[&active].retired.load(Ordering::Acquire));
}

#[test]
fn successful_finish_is_idempotent_and_releases_capacity() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    registry.finish(id, |_| Ok(())).unwrap();
    registry.finish(id, no_pending).unwrap();
    registry.retry(None, no_pending).unwrap();
    assert!(registry.entries.is_empty());
}

#[test]
fn panic_during_cleanup_leaves_retryable_evidence() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        registry
            .finish(id, |_| panic!("fixture cleanup panic"))
            .unwrap();
    }));
    assert!(unwind.is_err());
    assert!(registry.entries[&id].retired.load(Ordering::Acquire));
    registry.retry(None, |_| Ok(())).unwrap();
    assert!(registry.entries.is_empty());
}

#[test]
fn registry_limit_refuses_new_mutation_without_dropping_existing_evidence() {
    let mut registry = DnsInputRegistry::default();
    let mut first = None;
    for i in 0..MAX_TRACKED_RULESETS {
        let id = registry.begin(rules(&format!("p{i}")), no_pending).unwrap();
        first.get_or_insert(id);
    }
    let error = registry
        .begin(rules("overflow"), no_pending)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ownership limit"), "{error}");
    assert_eq!(registry.entries.len(), MAX_TRACKED_RULESETS);
    registry.finish(first.unwrap(), |_| Ok(())).unwrap();
    registry.begin(rules("overflow"), no_pending).unwrap();
    assert_eq!(registry.entries.len(), MAX_TRACKED_RULESETS);
}

#[test]
fn ownership_ids_never_wrap_or_reuse_an_old_generation() {
    let mut registry = DnsInputRegistry {
        last_id: u64::MAX - 1,
        ..Default::default()
    };
    let last = registry.begin(rules("edge"), no_pending).unwrap();
    assert_eq!(last.0, u64::MAX);
    registry.finish(last, |_| Ok(())).unwrap();
    assert!(registry
        .begin(rules("edge"), no_pending)
        .unwrap_err()
        .to_string()
        .contains("ids exhausted"));
    registry.finish(last, no_pending).unwrap();
    assert!(registry.entries.is_empty());
}

#[test]
fn rule_sets_preserve_family_protocol_and_exact_ownership_arguments() {
    for (pool, listen, ipv6) in [
        ("10.42.0.0/24", "10.42.0.1", false),
        ("2001:db8::/64", "2001:db8::1", true),
    ] {
        let spec = DnsInputRules::new("edge", "tun7", pool, listen, 5353).unwrap();
        assert_eq!(spec.ipv6, ipv6);
        for (proto, rule) in ["udp", "tcp"].into_iter().zip(&spec.rules) {
            assert_eq!(
                rule,
                &[
                    "-i",
                    "tun7",
                    "-s",
                    pool,
                    "-p",
                    proto,
                    "-d",
                    listen,
                    "--dport",
                    "5353",
                    "-m",
                    "comment",
                    "--comment",
                    "qeli-nat:edge",
                    "-j",
                    "ACCEPT",
                ]
            );
        }
    }
    assert!(DnsInputRules::new("edge", "tun0", "10.42.0.0/24", "invalid", 53).is_err());
}

#[test]
fn partial_udp_failure_retains_rules_for_real_exact_cleanup_retry() {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    let spec = rules("edge");
    let installed = std::cell::RefCell::new(spec.rules.to_vec());
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(spec.clone(), no_pending).unwrap();
    let fail_udp = Cell::new(true);
    let mut cleanup = |owned: &DnsInputRules| {
        assert_eq!(owned, &spec);
        crate::nat_cleanup::cleanup_exact_rules_with(
            "filter",
            "INPUT",
            ["udp", "tcp"]
                .into_iter()
                .zip(owned.rules.iter().map(Vec::as_slice)),
            |args| {
                assert_eq!(&args[..2], &["-t", "filter"]);
                assert_eq!(args[3], "INPUT");
                let found = installed
                    .borrow()
                    .iter()
                    .position(|rule| rule == &args[4..]);
                let code = match args[2] {
                    "-C" => u32::from(found.is_none()),
                    "-D" => {
                        if fail_udp.get() && args.contains(&"udp") {
                            return Err(std::io::Error::other("fixture UDP delete failure"));
                        }
                        installed.borrow_mut().remove(found.unwrap());
                        0
                    }
                    _ => panic!("exact DNS cleanup must not require a chain listing"),
                };
                #[cfg(unix)]
                let status = std::process::ExitStatus::from_raw((code as i32) << 8);
                #[cfg(windows)]
                let status = std::process::ExitStatus::from_raw(code);
                Ok(std::process::Output {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                })
            },
        )
    };
    assert!(registry
        .finish(id, &mut cleanup)
        .unwrap_err()
        .to_string()
        .contains("UDP delete failure"));
    assert!(registry.entries[&id].retired.load(Ordering::Acquire));
    assert_eq!(registry.entries[&id].rules, spec);
    assert_eq!(
        *installed.borrow(),
        vec![spec.rules[0].clone()],
        "TCP must be removed even when UDP fails"
    );
    fail_udp.set(false);
    registry.retry(Some("edge"), &mut cleanup).unwrap();
    assert!(registry.entries.is_empty());
    assert!(installed.borrow().is_empty());
}

#[test]
fn shutdown_retries_retired_rules_and_confirms_an_empty_registry() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    registry
        .finish(id, |_| anyhow::bail!("transient denial"))
        .unwrap_err();
    let calls = Cell::new(0);
    registry
        .finish_shutdown(|owned| {
            assert_eq!(owned, &rules("edge"));
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(registry.entries.is_empty());
    registry.finish_shutdown(no_pending).unwrap();
}

#[test]
fn shutdown_keeps_a_permanent_failure_retryable() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    registry
        .finish(id, |_| anyhow::bail!("denied"))
        .unwrap_err();
    let error = registry
        .finish_shutdown(|_| anyhow::bail!("tool unavailable"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("tool unavailable"), "{error}");
    assert!(registry.entries[&id].retired.load(Ordering::Acquire));
    assert_eq!(registry.entries[&id].rules, rules("edge"));
    registry.finish_shutdown(|_| Ok(())).unwrap();
}

#[test]
fn shutdown_reports_active_owners_without_deleting_their_rules() {
    let mut registry = DnsInputRegistry::default();
    let id = registry.begin(rules("edge"), no_pending).unwrap();
    let error = registry
        .finish_shutdown(no_pending)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("edge: DNS INPUT lease still active"),
        "{error}"
    );
    assert!(!registry.entries[&id].retired.load(Ordering::Acquire));
    registry.finish(id, |_| Ok(())).unwrap();
    registry.finish_shutdown(no_pending).unwrap();
}

#[test]
fn shutdown_reports_active_and_failed_retired_owners_and_cleans_the_rest() {
    let mut registry = DnsInputRegistry::default();
    let active = registry.begin(rules("active"), no_pending).unwrap();
    let failed = registry.begin(rules("failed"), no_pending).unwrap();
    let recovered = registry.begin(rules("recovered"), no_pending).unwrap();
    for id in [failed, recovered] {
        registry
            .finish(id, |_| anyhow::bail!("denied"))
            .unwrap_err();
    }
    let error = registry
        .finish_shutdown(|owned| {
            assert_ne!(owned.profile, "active");
            if owned.profile == "failed" {
                anyhow::bail!("persistent denial");
            }
            Ok(())
        })
        .unwrap_err()
        .to_string();
    assert!(error.contains("persistent denial"), "{error}");
    assert!(
        error.contains("active: DNS INPUT lease still active"),
        "{error}"
    );
    assert!(!registry.entries.contains_key(&recovered));
    assert!(!registry.entries[&active].retired.load(Ordering::Acquire));
    assert!(registry.entries[&failed].retired.load(Ordering::Acquire));
}

#[test]
fn owner_drop_retires_without_acquiring_the_registry_lock() {
    let mut registry = DnsInputRegistry::default();
    let owner = registry.begin_owned(rules("edge"), no_pending).unwrap();
    let id = owner.id();
    let lock = std::sync::Mutex::new(registry);
    let mut held = lock.lock().unwrap();
    std::thread::spawn(move || drop(owner)).join().unwrap();
    assert!(held.entries[&id].retired.load(Ordering::Acquire));
    held.retry(Some("edge"), |_| Ok(())).unwrap();
    assert!(held.entries.is_empty());
}

#[test]
fn dropped_old_owner_cannot_retire_a_replacement_generation() {
    let mut registry = DnsInputRegistry::default();
    let old = registry.begin_owned(rules("edge"), no_pending).unwrap();
    registry.finish(old.id(), |_| Ok(())).unwrap();
    let current = registry.begin_owned(rules("edge"), no_pending).unwrap();
    drop(old);
    assert!(!registry.entries[&current.id()]
        .retired
        .load(Ordering::Acquire));
    registry.retry(None, no_pending).unwrap();
    drop(current);
    registry.finish_shutdown(|_| Ok(())).unwrap();
}

#[test]
fn shutdown_reports_retirement_that_arrives_after_retry_snapshot() {
    let mut registry = DnsInputRegistry::default();
    let first = registry.begin_owned(rules("first"), no_pending).unwrap();
    let mut later = Some(registry.begin_owned(rules("later"), no_pending).unwrap());
    drop(first);
    let error = registry
        .finish_shutdown(|spec| {
            assert_eq!(spec.profile, "first");
            drop(later.take());
            Ok(())
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("cleanup still pending"),
        "{error}"
    );
    assert_eq!(registry.entries.len(), 1);
    registry.finish_shutdown(|_| Ok(())).unwrap();
    assert!(registry.entries.is_empty());
}

#[test]
fn reservation_refuses_retirement_arriving_during_pending_cleanup() {
    let mut registry = DnsInputRegistry::default();
    let first = registry.begin_owned(rules("edge"), no_pending).unwrap();
    let mut later = Some(
        registry
            .begin_owned(
                DnsInputRules::new("edge", "tun0", "2001:db8::/64", "2001:db8::1", 53).unwrap(),
                no_pending,
            )
            .unwrap(),
    );
    drop(first);
    let before = registry.last_id;
    let error = registry
        .begin_owned(rules("edge"), |_| {
            drop(later.take());
            Ok(())
        })
        .unwrap_err();
    assert!(
        error.to_string().contains("cleanup still pending"),
        "{error}"
    );
    assert_eq!(registry.last_id, before);
    let current = registry.begin_owned(rules("edge"), |_| Ok(())).unwrap();
    assert_eq!(registry.entries.len(), 1);
    drop(current);
    registry.finish_shutdown(|_| Ok(())).unwrap();
}
