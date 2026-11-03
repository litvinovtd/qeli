use super::*;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;

#[derive(Default)]
struct Journal {
    writes: Vec<(String, String, String)>,
    releases: Vec<String>,
    held: HashMap<String, HashSet<String>>,
    fail_at: Option<usize>,
    refuse_release: HashSet<String>,
}

impl Journal {
    fn acquire(&mut self, path: &str, value: &str, scope: &str) -> anyhow::Result<()> {
        self.writes.push((path.into(), value.into(), scope.into()));
        // Model a write that succeeds but whose verification fails afterwards.
        self.held
            .entry(scope.into())
            .or_default()
            .insert(path.into());
        if self.fail_at == Some(self.writes.len()) {
            anyhow::bail!("acquire fixture");
        }
        Ok(())
    }

    fn release(&mut self, scope: &str) -> anyhow::Result<()> {
        self.releases.push(scope.into());
        if self.refuse_release.contains(scope) {
            anyhow::bail!("rollback fixture");
        }
        self.held.remove(scope);
        Ok(())
    }
}

fn acquire(
    registry: &mut Registry,
    journal: &RefCell<Journal>,
    profile: &str,
    wan: Option<&str>,
    tun: &str,
) -> anyhow::Result<()> {
    registry.acquire(
        profile,
        wan,
        tun,
        |path, value, scope| journal.borrow_mut().acquire(path, value, scope),
        |scope| journal.borrow_mut().release(scope),
    )
}

fn finish(registry: &mut Registry, journal: &RefCell<Journal>) -> anyhow::Result<()> {
    crate::nat_cleanup::finish_owned_cleanup_with(
        || Ok(()),
        &registry.profiles(),
        |profile| registry.release(profile, |scope| journal.borrow_mut().release(scope)),
    )
}

#[test]
fn complete_acquire_preserves_ra_order_and_release_is_idempotent() {
    let journal = RefCell::new(Journal::default());
    let mut registry = Registry::default();
    acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0").unwrap();
    let scope = server_sysctl_scope("qeli0");
    assert_eq!(
        journal.borrow().writes,
        vec![
            (
                "/proc/sys/net/ipv6/conf/eth0/accept_ra".into(),
                "2".into(),
                scope.clone()
            ),
            (IPV6_FORWARDING_SYSCTL.into(), "1".into(), scope.clone()),
        ]
    );
    assert_eq!(registry.profiles(), ["p"]);
    finish(&mut registry, &journal).unwrap();
    finish(&mut registry, &journal).unwrap();
    registry
        .release("p", |_| panic!("already released"))
        .unwrap();
    assert!(registry.profiles().is_empty());
    assert!(journal.borrow().held.is_empty());
    assert_eq!(journal.borrow().releases, [scope]);
}

fn successful_rollback(fail_at: usize) {
    let journal = RefCell::new(Journal {
        fail_at: Some(fail_at),
        ..Default::default()
    });
    let mut registry = Registry::default();
    let error = acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0").unwrap_err();
    assert!(error.to_string().contains("acquire fixture"));
    assert_eq!(journal.borrow().writes.len(), fail_at);
    assert_eq!(journal.borrow().releases.len(), 1);
    assert!(journal.borrow().held.is_empty());
    assert!(registry.profiles().is_empty());
    finish(&mut registry, &journal).unwrap();
}

#[test]
fn first_acquire_failure_is_rolled_back() {
    successful_rollback(1);
}
#[test]
fn second_acquire_failure_is_rolled_back() {
    successful_rollback(2);
}

fn failed_rollback(fail_at: usize) {
    let scope = server_sysctl_scope("qeli0");
    let journal = RefCell::new(Journal {
        fail_at: Some(fail_at),
        refuse_release: HashSet::from([scope]),
        ..Default::default()
    });
    let mut registry = Registry::default();
    let error = acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("acquire fixture") && error.contains("rollback fixture"),
        "{error}"
    );
    assert_eq!(journal.borrow().writes.len(), fail_at);
    assert_eq!(registry.profiles(), ["p"]);
    let error = finish(&mut registry, &journal).unwrap_err().to_string();
    assert!(
        error.contains("IPv6 sysctls/p") && error.contains("rollback fixture"),
        "{error}"
    );
    assert_eq!(registry.profiles(), ["p"]);
    assert!(!journal.borrow().held.is_empty());
    journal.borrow_mut().refuse_release.clear();
    finish(&mut registry, &journal).unwrap();
    assert!(registry.profiles().is_empty());
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn first_acquire_and_rollback_failure_survive_until_final_retry() {
    failed_rollback(1);
}
#[test]
fn second_acquire_and_rollback_failure_survive_until_final_retry() {
    failed_rollback(2);
}

#[test]
fn kernel_route_mode_without_wan_only_acquires_forwarding() {
    let journal = RefCell::new(Journal::default());
    let mut registry = Registry::default();
    acquire(&mut registry, &journal, "p", None, "qeli0").unwrap();
    assert_eq!(
        journal.borrow().writes,
        vec![(
            IPV6_FORWARDING_SYSCTL.into(),
            "1".into(),
            server_sysctl_scope("qeli0")
        )]
    );
    finish(&mut registry, &journal).unwrap();
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn same_profile_can_reacquire_both_knobs_after_failed_rollback() {
    let journal = RefCell::new(Journal {
        fail_at: Some(2),
        refuse_release: HashSet::from([server_sysctl_scope("qeli0")]),
        ..Default::default()
    });
    let mut registry = Registry::default();
    assert!(acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0").is_err());
    acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0").unwrap();
    assert_eq!(
        journal.borrow().writes.len(),
        4,
        "both settings must be re-applied"
    );
    assert_eq!(registry.profiles(), ["p"]);
    journal.borrow_mut().refuse_release.clear();
    finish(&mut registry, &journal).unwrap();
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn changed_wan_or_scope_cannot_replace_pending_ownership() {
    let journal = RefCell::new(Journal {
        fail_at: Some(1),
        refuse_release: HashSet::from([server_sysctl_scope("qeli0")]),
        ..Default::default()
    });
    let mut registry = Registry::default();
    assert!(acquire(&mut registry, &journal, "p", Some("eth0"), "qeli0").is_err());
    for (wan, tun) in [
        (Some("eth1"), "qeli0"),
        (None, "qeli0"),
        (Some("eth0"), "qeli1"),
    ] {
        let error = acquire(&mut registry, &journal, "p", wan, tun)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already owns"), "{error}");
    }
    assert_eq!(journal.borrow().writes.len(), 1);
    assert_eq!(journal.borrow().releases.len(), 1);
    journal.borrow_mut().refuse_release.clear();
    finish(&mut registry, &journal).unwrap();
    assert_eq!(
        journal.borrow().releases.last(),
        Some(&server_sysctl_scope("qeli0"))
    );
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn invalid_wan_is_rejected_before_ownership_or_journal_mutation() {
    let journal = RefCell::new(Journal::default());
    let mut registry = Registry::default();
    for wan in [
        "",
        ".",
        "..",
        "../eth0",
        "a\\b",
        "bad name",
        "a\n",
        "a\0",
        "abcdefghijklmnop",
    ] {
        assert!(acquire(&mut registry, &journal, "p", Some(wan), "qeli0").is_err());
    }
    assert!(registry.profiles().is_empty());
    assert!(journal.borrow().writes.is_empty());
    assert!(journal.borrow().releases.is_empty());
}

#[test]
fn final_pass_drains_other_profiles_despite_dns_and_partial_lease_failure() {
    let journal = RefCell::new(Journal::default());
    let mut registry = Registry::default();
    acquire(&mut registry, &journal, "a", Some("eth0"), "qeli0").unwrap();
    journal.borrow_mut().fail_at = Some(4);
    journal
        .borrow_mut()
        .refuse_release
        .insert(server_sysctl_scope("qeli1"));
    assert!(acquire(&mut registry, &journal, "b", Some("eth1"), "qeli1").is_err());
    let dns_called = Cell::new(false);
    let error = crate::nat_cleanup::finish_owned_cleanup_with(
        || {
            dns_called.set(true);
            anyhow::bail!("DNS fixture");
        },
        &registry.profiles(),
        |profile| registry.release(profile, |scope| journal.borrow_mut().release(scope)),
    )
    .unwrap_err()
    .to_string();
    assert!(dns_called.get());
    assert!(
        error.contains("DNS fixture") && error.contains("IPv6 sysctls/b"),
        "{error}"
    );
    assert_eq!(registry.profiles(), ["b"]);
    assert!(!journal
        .borrow()
        .held
        .contains_key(&server_sysctl_scope("qeli0")));
    assert!(journal
        .borrow()
        .held
        .contains_key(&server_sysctl_scope("qeli1")));
    journal.borrow_mut().refuse_release.clear();
    finish(&mut registry, &journal).unwrap();
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn panic_after_first_mutation_keeps_scope_available_for_cleanup() {
    let journal = RefCell::new(Journal::default());
    let mut registry = Registry::default();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = registry.acquire(
            "p",
            Some("eth0"),
            "qeli0",
            |path, value, scope| {
                journal.borrow_mut().acquire(path, value, scope).unwrap();
                panic!("acquire panic fixture");
            },
            |_| panic!("ordinary rollback not reached during panic"),
        );
    }));
    assert!(panic.is_err());
    assert_eq!(registry.profiles(), ["p"]);
    finish(&mut registry, &journal).unwrap();
    assert!(journal.borrow().held.is_empty());
}

#[test]
fn server_sysctl_scope_is_bounded_and_unambiguous() {
    assert_eq!(server_sysctl_scope("qeli6"), "s-71656c6936");
    assert_ne!(server_sysctl_scope("qeli:6"), server_sysctl_scope("qeli6"));
    assert!(server_sysctl_scope("abcdefghijklmno").len() <= 32);
}
