use super::*;
use std::os::unix::fs::PermissionsExt;
fn row(ipv6: bool, number: u32) -> Vec<String> {
    let text = if ipv6 {
        format!("-6 route del 2001:db8:99::{number} dev route-wan")
    } else {
        format!("route del 198.51.100.{number} dev route-wan")
    };
    text.split_whitespace().map(str::to_string).collect()
}
struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn directory() -> TestDirectory {
    let path = std::env::temp_dir().join(format!(
        "qeli-route-state-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    TestDirectory(path)
}

fn name() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "rj{:x}{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}
#[test]
fn route_journal_file_retains_pending_and_confirmed_with_private_mode() {
    let d = directory();
    let n = name();
    let s = Session::at(d.path(), &n).unwrap();
    let g = s.begin().unwrap();
    s.change(&row(false, 8), Change::Intent).unwrap();
    let file = d.path().join("client-routes.state");
    let disk = Store::decode(&std::fs::read(&file).unwrap(), &s.boot).unwrap();
    assert_eq!(disk.records(s.cookie, &n, true), [row(false, 8)]);
    assert!(disk.records(s.cookie, &n, false).is_empty());
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    s.change(&row(false, 8), Change::Confirm).unwrap();
    drop(g);
    drop(s);
    // Other tests may have forked while this CLOEXEC socket was live; their
    // children drop the inherited fd at exec. This test checks disk continuity,
    // not zero-latency rebind while a parallel child has not exec'd yet.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let next = loop {
        match Session::at(d.path(), &n) {
            Ok(next) => break next,
            Err(error)
                if error.to_string().contains("still live")
                    && std::time::Instant::now() < until =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(error) => panic!("route session did not reopen: {error}"),
        }
    };
    let _g = next.begin().unwrap();
    assert_eq!(
        next.read(|s| Ok(s.records(next.cookie, &n, false)))
            .unwrap(),
        [row(false, 8)]
    );
}
#[test]
fn route_journal_live_owner_cannot_be_reopened_with_another_directory() {
    let d = directory();
    let other = directory();
    let n = name();
    let _owner = Session::at(d.path(), &n).unwrap();
    assert!(Session::at(other.path(), &n).is_err());
}
#[test]
fn route_journal_other_tun_cannot_borrow_confirmed_or_pending_route() {
    let d = directory();
    let a = Session::at(d.path(), &name()).unwrap();
    let b = Session::at(d.path(), &name()).unwrap();
    for change in [Change::Intent, Change::Confirm] {
        {
            let _g = a.begin().unwrap();
            a.change(&row(false, 8), change).unwrap();
        }
        let _g = b.begin().unwrap();
        assert!(b.check_unclaimed(&row(false, 8)).is_err());
        assert!(b
            .before_command(
                &["route", "add", "198.51.100.8", "dev", "route-wan"].map(str::to_string)
            )
            .is_err());
    }
}
#[test]
fn route_journal_rejects_untrusted_files_and_directory_before_mutation() {
    let d = directory();
    let n = name();
    let s = Session::at(d.path(), &n).unwrap();
    {
        let _g = s.begin().unwrap();
        s.change(&row(false, 8), Change::Intent).unwrap();
    }
    let file = d.path().join("client-routes.state");
    let bytes = std::fs::read(&file).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(s.begin().is_err());
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&file, d.path().join("real.state")).unwrap();
    std::os::unix::fs::symlink("real.state", &file).unwrap();
    assert!(s.begin().is_err());
    std::fs::remove_file(&file).unwrap();
    std::fs::rename(d.path().join("real.state"), &file).unwrap();
    let _g = s.begin().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(s
        .before_command(&["route", "add", "198.51.100.9", "dev", "route-wan"].map(str::to_string))
        .is_err());
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(s.verify().is_err(), "lost context stays invalid");
}
#[test]
fn route_journal_lock_wait_obeys_operation_deadline_and_preserves_disk() {
    let d = directory();
    let s = Session::at(d.path(), &name()).unwrap();
    let file = d.path().join("client-routes.state");
    let _lock = crate::util::FileLock::acquire(&file).unwrap();
    static LOCK: Mutex<()> = Mutex::new(());
    let now = std::time::Instant::now();
    budget::with_deadline(now + std::time::Duration::from_millis(40), || {
        let _operation = budget::Operation::acquire(&LOCK).unwrap();
        assert!(s.begin().is_err());
    });
    assert!(now.elapsed() < std::time::Duration::from_secs(1));
    assert!(!file.exists());
}
#[test]
fn route_journal_failed_intent_write_cannot_confirm_a_physical_mutation() {
    let d = directory();
    let s = Session::at(d.path(), &name()).unwrap();
    let _g = s.begin().unwrap();
    // A directory at the file path makes atomic replacement fail even for root.
    std::fs::create_dir(d.path().join("client-routes.state")).unwrap();
    assert!(s
        .before_command(&["route", "add", "198.51.100.8", "dev", "route-wan"].map(str::to_string))
        .is_err());
    assert!(s.read(|s| Ok(s.groups.is_empty())).unwrap());
}
fn isolated(test: impl FnOnce() -> anyhow::Result<()> + Send + 'static) -> anyhow::Result<()> {
    std::thread::spawn(move || {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        test()
    })
    .join()
    .expect("route recovery native test panicked")
}
fn ip(args: &[String]) -> anyhow::Result<()> {
    let out = route_command_output(args)?;
    anyhow::ensure!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}
fn command(text: &str) -> anyhow::Result<()> {
    ip(&text
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>())
}
fn install(s: &Session, spec: &[String], confirm: bool) -> anyhow::Result<()> {
    let mut add = spec.to_vec();
    let action = usize::from(add[0] == "-6") + 1;
    add[action] = "add".into();
    s.before_command(&add)?;
    ip(&add)?;
    if confirm {
        s.change(spec, Change::Confirm)?;
    }
    Ok(())
}
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated network namespace"]
fn native_route_recovery_cleans_owned_preserves_changed_and_refuses_pending() -> anyhow::Result<()>
{
    isolated(|| {
        command("link set lo up")?;
        command("link add route-wan type dummy")?;
        command("link set route-wan up")?;
        let d = directory();
        let n = name();
        let s = Session::at(d.path(), &n)?;
        let g = s.begin()?;
        for ipv6 in [false, true] {
            install(&s, &row(ipv6, 8), true)?;
            install(&s, &row(ipv6, 9), true)?;
            let mut changed = row(ipv6, 9);
            changed[usize::from(ipv6) + 1] = "change".into();
            changed.extend(["proto", "static"].map(str::to_string));
            ip(&changed)?;
            install(&s, &row(ipv6, 10), false)?;
        }
        // A different network generation must remain byte-for-byte equivalent as a record.
        s.edit(|store| store.change(s.cookie + 1, &n, &row(false, 11), Change::Confirm))?;
        let cookie = s.cookie;
        drop(g);
        drop(s);
        let s = Session::at(d.path(), &n)?;
        let _g = s.begin()?;
        assert!(s.recover().is_err());
        for ipv6 in [false, true] {
            assert!(ownership::recorded_route(&row(ipv6, 8))?.is_none());
            assert!(ownership::recorded_route(&row(ipv6, 9))?
                .unwrap()
                .iter()
                .any(|s| s == "static"));
            assert!(ownership::recorded_route(&row(ipv6, 10))?.is_some());
            assert!(s
                .read(|store| Ok(store.records(cookie, &n, false)))
                .unwrap()
                .is_empty());
            ip(&row(ipv6, 10))?; // Explicit administrator resolution of unproven leftovers.
        }
        s.recover()?;
        assert!(s
            .read(|store| Ok(store.records(cookie, &n, true)))
            .unwrap()
            .is_empty());
        assert_eq!(
            s.read(|store| Ok(store.records(cookie + 1, &n, false)))?,
            [row(false, 11)]
        );
        Ok(())
    })
}
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated network namespace"]
fn native_route_recovery_refuses_live_interface_and_lost_namespace() -> anyhow::Result<()> {
    isolated(|| {
        command("link add route-wan type dummy")?;
        command("link set route-wan up")?;
        let d = directory();
        let s = Session::at(d.path(), "route-tun")?;
        let _g = s.begin()?;
        install(&s, &row(false, 8), true)?;
        command("link add route-tun type dummy")?;
        assert!(s.recover().is_err());
        assert!(ownership::recorded_route(&row(false, 8))?.is_some());
        command("link del route-tun")?;
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        assert!(s.recover().is_err());
        assert!(s
            .before_command(
                &["route", "add", "198.51.100.8", "dev", "route-wan"].map(str::to_string)
            )
            .is_err());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated network namespace"]
fn native_route_recovery_retains_failed_delete_and_cleans_other_family() -> anyhow::Result<()> {
    isolated(|| {
        use crate::system_command::test_support::{arguments, with_commands, Action};
        command("link add route-wan type dummy")?;
        command("link set route-wan up")?;
        let d = directory();
        let s = Session::at(d.path(), &name())?;
        let _g = s.begin()?;
        install(&s, &row(false, 8), true)?;
        install(&s, &row(true, 8), true)?;
        with_commands(
            |cmd| {
                assert_eq!(cmd.get_program(), "ip");
                let args = arguments(cmd);
                if args == row(false, 8) {
                    return Action::Reply(Err(std::io::ErrorKind::PermissionDenied.into()));
                }
                Action::Reply(std::process::Command::new("ip").args(args).output())
            },
            || assert!(s.recover().is_err()),
        );
        assert!(ownership::recorded_route(&row(false, 8))?.is_some());
        assert!(ownership::recorded_route(&row(true, 8))?.is_none());
        assert_eq!(
            s.read(|store| Ok(store.records(s.cookie, &s.interface, false)))?,
            [row(false, 8)]
        );
        s.recover()?;
        assert!(ownership::recorded_route(&row(false, 8))?.is_none());
        Ok(())
    })
}
