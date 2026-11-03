//! Cooperative publication/application exclusion with the Keenetic wan.d hook.
//! The sibling directory is also acquired by lifecycle.sh using atomic mkdir.
//! Never share the lifecycle lock: start holds it while waiting for this writer.
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) struct PublicationLock(PathBuf);
impl PublicationLock {
    pub(super) fn acquire(path: &Path) -> io::Result<Self> {
        let mut sibling = path.as_os_str().to_os_string();
        sibling.push(".publish-lock");
        let sibling = PathBuf::from(sibling);
        let until = crate::operation_budget::limit(Instant::now() + crate::operation_budget::LIMIT);
        loop {
            crate::operation_budget::check_until(until)?;
            match DirBuilder::new().mode(0o700).create(&sibling) {
                Ok(()) => return Ok(Self(sibling)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    // A live hook can finish; an unknown/stale owner is never removed.
                    std::thread::sleep(
                        Duration::from_millis(20)
                            .min(until.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for PublicationLock {
    fn drop(&mut self) {
        // Non-empty/replaced directories are retained for administrator review.
        if let Err(error) = fs::remove_dir(&self.0) {
            log::warn!("network-plan publication lock release failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "qeli-plan-lock-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn plan(&self) -> PathBuf {
            self.0.join("plan")
        }
        fn lock(&self) -> PathBuf {
            self.0.join("plan.publish-lock")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn private_lock_is_released_on_unwind() {
        let f = Fixture::new();
        assert!(std::panic::catch_unwind(|| {
            let _lock = PublicationLock::acquire(&f.plan()).unwrap();
            assert_eq!(
                fs::metadata(f.lock()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            panic!("publication interrupted");
        })
        .is_err());
        assert!(!f.lock().exists());
    }
    #[test]
    fn publisher_waits_for_live_owner_then_acquires() {
        let f = Fixture::new();
        let owner = PublicationLock::acquire(&f.plan()).unwrap();
        let path = f.plan();
        let (tx, rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _scope =
                crate::operation_budget::Scope::enter(Instant::now() + Duration::from_secs(2));
            let _lock = PublicationLock::acquire(&path).unwrap();
            tx.send(()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(60)).is_err());
        drop(owner);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        thread.join().unwrap();
        assert!(!f.lock().exists());
    }
    #[test]
    fn stale_lock_times_out_without_removal() {
        let f = Fixture::new();
        fs::create_dir(f.lock()).unwrap();
        fs::write(f.lock().join("canary"), b"unknown owner").unwrap();
        let _scope =
            crate::operation_budget::Scope::enter(Instant::now() + Duration::from_millis(40));
        assert_eq!(
            PublicationLock::acquire(&f.plan()).err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(fs::read(f.lock().join("canary")).unwrap(), b"unknown owner");
    }
    #[test]
    fn expired_parent_budget_does_not_create_a_lock() {
        let f = Fixture::new();
        let _scope = crate::operation_budget::Scope::enter(Instant::now());
        assert_eq!(
            PublicationLock::acquire(&f.plan()).err().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!f.lock().exists());
    }
    #[test]
    fn non_directory_lock_is_not_replaced_and_unknown_contents_are_retained() {
        let f = Fixture::new();
        fs::write(f.lock(), b"foreign file").unwrap();
        {
            let _scope =
                crate::operation_budget::Scope::enter(Instant::now() + Duration::from_millis(40));
            assert_eq!(
                PublicationLock::acquire(&f.plan()).err().unwrap().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert_eq!(fs::read(f.lock()).unwrap(), b"foreign file");
        fs::remove_file(f.lock()).unwrap();
        let owner = PublicationLock::acquire(&f.plan()).unwrap();
        fs::write(f.lock().join("canary"), b"do not remove").unwrap();
        drop(owner);
        assert_eq!(fs::read(f.lock().join("canary")).unwrap(), b"do not remove");
    }
}
