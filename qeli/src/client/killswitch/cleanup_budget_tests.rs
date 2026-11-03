use super::*;
use std::time::{Duration, Instant};
fn cleanup_budget(until: Instant) -> Budget {
    Budget {
        until,
        operation: "cleanup",
    }
}

#[test]
fn cleanup_admission_rejects_expired_and_busy_locks() {
    let lock = std::sync::Mutex::new(());
    assert_eq!(
        cleanup_budget(Instant::now())
            .lock(&lock)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let held = lock.lock().unwrap();
    assert_eq!(
        cleanup_budget(Instant::now() + Duration::from_millis(25))
            .lock(&lock)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    drop(held);
    assert!(cleanup_budget(Instant::now() + Duration::from_secs(1))
        .lock(&lock)
        .is_ok());
}

#[test]
fn expired_cleanup_context_starts_no_more_commands() {
    crate::system_command::test_support::with_commands(
        |_| panic!("expired cleanup spawned a command"),
        || {
            let context = Context::fixture().with_budget(cleanup_budget(Instant::now()));
            assert_eq!(
                context
                    .ipt("fixture", &["-S", "QELI_KS_budget"])
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            assert!(teardown_family(&context, "fixture", "QELI_KS_budget").is_err());
        },
    );
}

#[test]
fn cleanup_rejects_an_acknowledgement_after_its_budget() {
    use crate::system_command::test_support::{with_commands, Action};
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    let until = Instant::now() + Duration::from_millis(40);
    with_commands(
        move |_| {
            std::thread::sleep(
                until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
            Action::Reply(Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }))
        },
        || {
            let context = Context::fixture().with_budget(cleanup_budget(until));
            assert_eq!(
                context
                    .ipt("fixture", &["-D", "OUTPUT", "-j", "QELI_KS_budget"])
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
        },
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    struct Fixture {
        dir: PathBuf,
        name: &'static str,
        _serial: std::sync::MutexGuard<'static, ()>,
    }
    impl Fixture {
        fn new(name: &'static str, scripts: [&str; 2]) -> Self {
            let serial = BUDGET_TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!(
                "qeli-ks-budget-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&dir).unwrap();
            let _operation = operation();
            // Real pinned namespace, but only private fixture executables: no firewall mutation.
            // Existing model tests clear fixture owners, so do not share their fake namespace.
            let context = Context::prepare(name).unwrap();
            context.bind(name).unwrap();
            for (index, script) in scripts.into_iter().enumerate() {
                let path = dir.join(if index == 0 { "iptables" } else { "ip6tables" });
                std::fs::write(&path, format!("#!/bin/sh\ncd '{}' || exit 17\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\n{script}\n", dir.display())).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                context
                    .remember(index == 1, path.to_str().unwrap())
                    .unwrap();
            }
            Self {
                dir,
                name,
                _serial: serial,
            }
        }
        fn retained(&self) {
            let context = Context::lookup(self.name, true)
                .unwrap()
                .expect("timed-out cleanup forgot its owner");
            assert_eq!(context.paths().len(), 2);
        }
        fn retry(&self) {
            std::fs::write(self.dir.join("retry"), b"1").unwrap();
            disengage(self.name).unwrap();
            assert!(Context::lookup(self.name, true).unwrap().is_none());
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _operation = operation();
            if let Ok(Some(context)) = Context::lookup(self.name, true) {
                let _ = context.forget(self.name);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn cleanup_families_share_one_budget_and_can_retry() {
        let absent = "echo 'iptables: No chain/target/match by that name.' >&2; exit 1";
        let v4 = format!("[ -e retry ] || sleep 0.03\n{absent}");
        let v6 = format!("[ -e retry ] || sleep 0.45\n{absent}");
        let f = Fixture::new("ks_budget_fam", [&v4, &v6]);
        let result = disengage_until(f.name, Instant::now() + Duration::from_millis(650));
        assert!(
            result.is_err(),
            "cleanup granted each family/command a fresh deadline"
        );
        let v4_calls = std::fs::read_to_string(f.dir.join("iptables.calls")).unwrap();
        let v6_calls = std::fs::read_to_string(f.dir.join("ip6tables.calls")).unwrap();
        assert!(
            v4_calls.ends_with(
                "-C FORWARD -m comment --comment qeli-ks-rebuild:ks_budget_fam -j DROP\n"
            ),
            "first family did not finish ordinary-chain and rebuild-guard cleanup: {v4_calls}"
        );
        assert_eq!(
            v6_calls.lines().count(),
            1,
            "commands continued after the shared deadline"
        );
        f.retained();
        f.retry();
    }

    #[test]
    fn cleanup_timeout_after_deletion_preserves_owner_for_verified_retry() {
        let script = r#"
case "$1" in
  -C) [ "$2" = OUTPUT ] && [ -e "$0.jump" ] && exit 0; exit 1;;
  -D) rm -f "$0.jump"; [ -e retry ] || sleep 1; exit 0;;
  -S) [ -e "$0.chain" ] && exit 0; echo 'iptables: No chain/target/match by that name.' >&2; exit 1;;
  -F) exit 0;;
  -X) rm -f "$0.chain"; exit 0;;
  *) exit 17;;
esac
"#;
        let f = Fixture::new("ks_budget_del", [script, script]);
        for bin in ["iptables", "ip6tables"] {
            for suffix in ["jump", "chain"] {
                std::fs::write(f.dir.join(format!("{bin}.{suffix}")), b"1").unwrap();
            }
        }
        assert!(disengage_until(f.name, Instant::now() + Duration::from_millis(350)).is_err());
        assert!(
            !f.dir.join("iptables.jump").exists(),
            "fixture did not apply the deletion before timeout"
        );
        assert!(
            f.dir.join("iptables.chain").exists(),
            "later mutation ran after timeout"
        );
        assert!(
            !f.dir.join("ip6tables.calls").exists(),
            "second family spawned after timeout"
        );
        f.retained();
        f.retry();
        for bin in ["iptables", "ip6tables"] {
            assert!(!f.dir.join(format!("{bin}.jump")).exists());
            assert!(!f.dir.join(format!("{bin}.chain")).exists());
        }
    }
}
