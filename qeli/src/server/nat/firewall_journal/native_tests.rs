use super::*;
use crate::nat_firewall_journal::tests::rule;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qeli-firewall-state-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("server-firewall.state")
    }
    fn open(&self) -> Session {
        Session::at(&self.0).unwrap()
    }
    fn store(&self, s: &Session) -> Store {
        Store::decode(&std::fs::read(self.path()).unwrap(), &s.boot).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn applied_then_failed_mutation_is_durable_before_callback_and_recovered_after_reopen() {
    let f = Fixture::new();
    let mut s = f.open();
    let cookie = s.cookie;
    assert!(s
        .apply::<()>(&rule(false), Backend::Nft, until(), || {
            let store: Store = serde_json::from_slice(&std::fs::read(f.path())?)?;
            assert_eq!(store.rules(cookie), vec![rule(false)]);
            anyhow::bail!("lost mutation response");
        })
        .is_err());
    drop(s);
    let mut restarted = f.open();
    let mut calls = 0;
    restarted
        .recover(until(), |saved, backend| {
            assert_eq!(backend, Backend::Nft);
            assert_eq!(saved, &rule(false));
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert!(f.store(&restarted).rules(cookie).is_empty());
    assert!(f.0.join("server-firewall.state.lock").is_file());
}
#[test]
fn recovery_failure_retains_failed_rules_and_releases_verified_siblings() {
    let f = Fixture::new();
    let mut s = f.open();
    s.apply::<()>(&rule(false), Backend::Nft, until(), || Ok(()))
        .unwrap();
    s.apply::<()>(&rule(true), Backend::Nft, until(), || Ok(()))
        .unwrap();
    assert!(s
        .recover(until(), |r, _| if r.ipv6 {
            Ok(())
        } else {
            anyhow::bail!("denied")
        })
        .is_err());
    assert_eq!(f.store(&s).rules(s.cookie), vec![rule(false)]);
    s.recover(until(), |_, _| Ok(())).unwrap();
    assert!(f.store(&s).rules(s.cookie).is_empty());
}
#[test]
fn foreign_namespace_group_is_never_probed_or_discarded() {
    let f = Fixture::new();
    let mut s = f.open();
    let foreign = s.cookie.checked_add(1).unwrap();
    let mut store = Store::new(&s.boot);
    store.retain(foreign, rule(false), Backend::Nft).unwrap();
    std::fs::write(f.path(), store.encode().unwrap()).unwrap();
    s.recover(until(), |_, _| {
        panic!("foreign network must not run commands")
    })
    .unwrap();
    assert_eq!(f.store(&s).rules(foreign), vec![rule(false)]);
}
#[test]
fn malformed_or_untrusted_journal_never_reaches_kernel_mutation() {
    let f = Fixture::new();
    let mut s = f.open();
    std::fs::write(f.path(), b"broken").unwrap();
    assert!(s
        .apply::<()>(&rule(false), Backend::Nft, until(), || panic!(
            "corrupt state"
        ))
        .is_err());
    std::fs::remove_file(f.path()).unwrap();
    std::os::unix::fs::symlink(f.0.join("outside"), f.path()).unwrap();
    assert!(s
        .apply::<()>(&rule(false), Backend::Nft, until(), || panic!("symlink"))
        .is_err());
    assert!(!f.0.join("outside").exists());
}
#[test]
fn journal_lock_contention_uses_callers_deadline() {
    let f = Fixture::new();
    let mut s = f.open();
    let _lock = crate::util::FileLock::acquire_timeout_owned(
        f.path(),
        Duration::from_secs(1),
        s.directory.owner(),
    )
    .unwrap();
    let start = Instant::now();
    assert!(s
        .apply::<()>(
            &rule(false),
            Backend::Nft,
            start + Duration::from_millis(30),
            || panic!("locked")
        )
        .is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(!f.path().exists());
}
#[test]
fn failed_live_cleanup_keeps_exact_recovery_evidence() {
    let f = Fixture::new();
    let mut s = f.open();
    s.apply::<()>(&rule(false), Backend::Nft, until(), || Ok(()))
        .unwrap();
    assert!(s
        .remove(&rule(false), Backend::Nft, until(), || anyhow::bail!(
            "unknown check result"
        ))
        .is_err());
    assert_eq!(f.store(&s).rules(s.cookie), vec![rule(false)]);
    s.remove(&rule(false), Backend::Nft, until(), || Ok(()))
        .unwrap();
    assert!(f.store(&s).rules(s.cookie).is_empty());
}
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN; disposable network namespaces"]
fn namespace_change_is_sticky_and_never_replays_saved_commands() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let original = std::fs::File::open("/proc/thread-self/ns/net")?;
        let f = Fixture::new();
        let mut s = f.open();
        s.apply::<()>(&rule(false), Backend::Nft, until(), || Ok(()))
            .unwrap();
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        assert!(s
            .recover(until(), |_, _| panic!("namespace changed"))
            .is_err());
        anyhow::ensure!(unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) } == 0);
        assert!(s
            .recover(until(), |_, _| panic!("invalidated session"))
            .is_err());
        assert_eq!(f.store(&s).rules(s.cookie), vec![rule(false)]);
        Ok(())
    })
    .join()
    .unwrap()
}

#[test]
fn live_cleanup_with_wrong_backend_preserves_durable_evidence() {
    let f = Fixture::new();
    let mut s = f.open();
    s.apply(&rule(false), Backend::Nft, until(), || Ok(()))
        .unwrap();
    assert!(s
        .remove(&rule(false), Backend::Legacy, until(), || panic!(
            "wrong backend"
        ))
        .is_err());
    assert_eq!(f.store(&s).rules(s.cookie), vec![rule(false)]);
}
