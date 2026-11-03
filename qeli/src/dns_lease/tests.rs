use super::*;
use std::cell::Cell;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "qeli-dns-lease-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(dir)
    }
    fn lease(&self) -> Lease {
        Lease::acquire(&self.0, link()).unwrap()
    }
    fn path(&self) -> PathBuf {
        link().path(&self.0)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scope() -> Scope {
    Scope {
        boot: "12345678-1234-1234-1234-123456789abc".into(),
        device: 4,
        inode: 17,
        network_cookie: 123,
    }
}
fn link() -> Link {
    Link {
        scope: scope(),
        index: 42,
        name: "qtest".into(),
    }
}
fn saved(f: &Fixture) -> Vec<u8> {
    std::fs::read(f.path()).unwrap()
}

#[test]
fn live_owner_cannot_be_overwritten_even_after_rename() {
    let f = Fixture::new();
    let lease = f.lease();
    assert_eq!(lease.link(), &link());
    let before = saved(&f);
    let mut renamed = link();
    renamed.name = "renamed".into();
    assert!(Lease::acquire(&f.0, renamed)
        .err()
        .unwrap()
        .to_string()
        .contains("active owner"));
    assert_eq!(saved(&f), before);
}
#[test]
fn index_and_namespace_isolate_owners_without_lossy_name_keys() {
    let f = Fixture::new();
    let _first = f.lease();
    let mut second = link();
    second.index += 1;
    second.name = "q+test".into();
    let _second = Lease::acquire(&f.0, second.clone()).unwrap();
    let mut third = second.clone();
    third.scope.inode += 1;
    let _third = Lease::acquire(&f.0, third.clone()).unwrap();
    assert_ne!(link().path(&f.0), second.path(&f.0));
    assert_ne!(second.path(&f.0), third.path(&f.0));
}
#[test]
fn legacy_marker_cannot_grant_or_be_replaced_by_new_ownership() {
    let f = Fixture::new();
    let old = f.0.join("dns-resolvectl-qtest");
    std::fs::write(&old, "qtest").unwrap();
    assert!(Lease::acquire(&f.0, link())
        .err()
        .unwrap()
        .to_string()
        .contains("legacy DNS marker"));
    assert_eq!(std::fs::read_to_string(old).unwrap(), "qtest");
    assert!(!f.path().exists());
}
#[test]
fn dropped_lease_leaves_recovery_evidence_and_blocks_blind_takeover() {
    let f = Fixture::new();
    drop(f.lease());
    let before = saved(&f);
    assert!(Lease::acquire(&f.0, link())
        .err()
        .unwrap()
        .to_string()
        .contains("unrecovered"));
    assert_eq!(saved(&f), before);
}
#[test]
fn cleanup_runs_once_then_releases_only_its_marker() {
    let f = Fixture::new();
    let mut lease = f.lease();
    let calls = Cell::new(0);
    lease
        .cleanup(|l| {
            assert_eq!(l, &link());
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
    lease.cleanup(|_| panic!("already retired")).unwrap();
    assert_eq!(calls.get(), 1);
    assert!(!f.path().exists());
    assert!(f.path().with_extension("lock").exists());
    drop(lease);
    let _next = f.lease();
}
#[test]
fn command_failures_keep_ownership_and_allow_only_owner_retry() {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::InvalidData,
        io::ErrorKind::NotFound,
        io::ErrorKind::Other,
    ] {
        let f = Fixture::new();
        let mut lease = f.lease();
        let before = saved(&f);
        assert!(lease
            .cleanup(|_| Err(io::Error::new(kind, "command fault").into()))
            .unwrap_err()
            .to_string()
            .contains("marker kept"));
        assert_eq!(saved(&f), before);
        assert!(Lease::acquire(&f.0, link()).is_err());
        lease.cleanup(|_| Ok(())).unwrap();
        assert!(!f.path().exists());
    }
}
#[test]
fn replaced_generation_is_never_reverted_or_retired() {
    let f = Fixture::new();
    let mut lease = f.lease();
    let mut replacement = lease.record.clone();
    replacement.token = "a".repeat(32);
    std::fs::write(f.path(), serde_json::to_vec(&replacement).unwrap()).unwrap();
    let before = saved(&f);
    assert!(lease
        .cleanup(|_| panic!("foreign generation must not be reverted"))
        .is_err());
    assert_eq!(saved(&f), before);
}
#[test]
fn marker_replacement_during_command_survives_retirement() {
    let f = Fixture::new();
    let mut lease = f.lease();
    let mut replacement = lease.record.clone();
    replacement.token = "b".repeat(32);
    let foreign = serde_json::to_vec(&replacement).unwrap();
    assert!(lease
        .cleanup(|_| {
            std::fs::write(f.path(), &foreign)?;
            Ok(())
        })
        .is_err());
    assert_eq!(saved(&f), foreign);
}
#[test]
fn missing_marker_does_not_authorize_revert() {
    let f = Fixture::new();
    let mut lease = f.lease();
    std::fs::remove_file(f.path()).unwrap();
    assert!(lease.cleanup(|_| panic!("missing marker")).is_err());
}
#[test]
fn malformed_and_oversized_markers_are_preserved() {
    for content in [
        Vec::new(),
        vec![0xff],
        b"qtest".to_vec(),
        vec![b'x'; MAX_MARKER as usize + 1],
    ] {
        let f = Fixture::new();
        std::fs::write(f.path(), &content).unwrap();
        assert!(Lease::acquire(&f.0, link()).is_err());
        assert_eq!(saved(&f), content);
    }
}
#[test]
fn invalid_record_version_token_or_path_is_rejected() {
    for field in ["version", "token", "path"] {
        let f = Fixture::new();
        let lease = f.lease();
        let mut record = lease.record.clone();
        drop(lease);
        match field {
            "version" => record.version = 3,
            "token" => record.token = "bad".into(),
            _ => record.link.index += 1,
        }
        let bytes = serde_json::to_vec(&record).unwrap();
        std::fs::write(f.path(), &bytes).unwrap();
        assert!(recover(&f.path(), &scope(), |_| panic!("invalid record")).is_err());
        assert_eq!(saved(&f), bytes);
    }
}
#[test]
fn changed_namespace_cannot_authorize_any_cleanup() {
    for field in ["boot", "device", "inode"] {
        let mut other = scope();
        match field {
            "boot" => other.boot = "a".repeat(36),
            "device" => other.device += 1,
            _ => other.inode += 1,
        }
        assert!(command_target(&link(), &other, Some(42)).is_err());
        assert!(command_target(&link(), &other, None).is_err());
    }
}
#[test]
fn same_index_with_renamed_original_still_uses_numeric_target() {
    assert_eq!(
        command_target(&link(), &scope(), Some(42)).unwrap(),
        Some(42)
    );
}
#[test]
fn detached_original_never_grants_authority_over_replacement() {
    let f = Fixture::new();
    let mut lease = f.lease();
    let calls = Cell::new(0);
    lease
        .cleanup(|l| {
            if command_target(l, &scope(), None)?.is_some() {
                calls.set(calls.get() + 1)
            };
            Ok(())
        })
        .unwrap();
    assert_eq!(calls.get(), 0);
    assert!(!f.path().exists());
}
#[test]
fn different_observed_index_preserves_marker_and_refuses_command() {
    let f = Fixture::new();
    let mut lease = f.lease();
    let before = saved(&f);
    assert!(lease
        .cleanup(|l| {
            command_target(l, &scope(), Some(43))?;
            panic!("replacement")
        })
        .is_err());
    assert_eq!(saved(&f), before);
}
#[test]
fn recovery_skips_active_lock_without_even_parsing_marker() {
    let f = Fixture::new();
    let _lease = f.lease();
    std::fs::write(f.path(), b"partial").unwrap();
    assert_eq!(
        recover(&f.path(), &scope(), |_| panic!("active owner")).unwrap(),
        Recovery::Busy
    );
}
#[test]
fn recovery_leaves_foreign_namespace_without_probing() {
    let f = Fixture::new();
    drop(f.lease());
    let before = saved(&f);
    let mut other = scope();
    other.inode += 1;
    assert_eq!(
        recover(&f.path(), &other, |_| panic!("foreign namespace")).unwrap(),
        Recovery::Foreign
    );
    assert_eq!(saved(&f), before);
}
#[test]
fn recovery_preserves_live_or_reused_index_without_revert() {
    let f = Fixture::new();
    drop(f.lease());
    let before = saved(&f);
    assert_eq!(
        recover(&f.path(), &scope(), |i| {
            assert_eq!(i, 42);
            Ok(true)
        })
        .unwrap(),
        Recovery::Live
    );
    assert_eq!(saved(&f), before);
}
#[test]
fn recovery_retires_absent_index_without_any_dns_command() {
    let f = Fixture::new();
    drop(f.lease());
    assert_eq!(
        recover(&f.path(), &scope(), |i| {
            assert_eq!(i, 42);
            Ok(false)
        })
        .unwrap(),
        Recovery::Retired
    );
    assert!(!f.path().exists());
    assert!(f.path().with_extension("lock").exists());
    assert_eq!(
        recover(&f.path(), &scope(), |_| panic!("absent marker")).unwrap(),
        Recovery::Absent
    );
}
#[test]
fn recovery_probe_error_keeps_exact_evidence() {
    let f = Fixture::new();
    drop(f.lease());
    let before = saved(&f);
    assert!(recover(&f.path(), &scope(), |_| anyhow::bail!("lookup denied")).is_err());
    assert_eq!(saved(&f), before);
}
#[test]
fn scan_excludes_sidecars_and_legacy_files() {
    assert!(is_marker("dns-link-v1-example.state"));
    for name in [
        "dns-link-v1-example.lock",
        "dns-resolvectl-qtest",
        "dns-backup.json",
        "dns-link-v1-state",
    ] {
        assert!(!is_marker(name));
    }
}
#[test]
fn invalid_link_identity_is_rejected_before_state_creation() {
    let f = Fixture::new();
    for which in 0..7 {
        let mut l = link();
        match which {
            0 => l.index = 0,
            1 => l.scope.inode = 0,
            2 => l.scope.boot = "invalid".into(),
            3 => l.name = "".into(),
            4 => l.name = "x".repeat(16),
            5 => l.name = "x/y".into(),
            _ => l.index = u32::MAX,
        }
        assert!(Lease::acquire(&f.0, l).is_err());
    }
    assert_eq!(std::fs::read_dir(&f.0).unwrap().count(), 0);
}
#[test]
fn directory_cannot_be_used_as_marker_or_retired() {
    let f = Fixture::new();
    let mut lease = f.lease();
    assert!(lease
        .cleanup(|_| {
            std::fs::remove_file(f.path())?;
            std::fs::create_dir(f.path())?;
            Ok(())
        })
        .is_err());
    assert!(f.path().is_dir());
}
#[cfg(unix)]
#[test]
fn fifo_lock_open_is_nonblocking_and_rejected() {
    use std::os::unix::ffi::OsStrExt;
    let f = Fixture::new();
    let path = f.path().with_extension("lock");
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    assert!(Lease::acquire(&f.0, link()).is_err());
    assert!(!f.path().exists());
}
#[cfg(unix)]
#[test]
fn marker_and_lock_symlinks_do_not_follow_external_files() {
    for lock in [false, true] {
        let f = Fixture::new();
        let external = f.0.join("external");
        std::fs::write(&external, "untouched").unwrap();
        let path = if lock {
            f.path().with_extension("lock")
        } else {
            f.path()
        };
        std::os::unix::fs::symlink(&external, &path).unwrap();
        assert!(Lease::acquire(&f.0, link()).is_err());
        assert_eq!(std::fs::read_to_string(external).unwrap(), "untouched");
    }
}
#[test]
fn separate_process_cannot_replace_live_dns_owner() {
    let f = Fixture::new();
    let _lease = f.lease();
    let before = saved(&f);
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "dns_lease::tests::child_refuses_live_owner",
            "--ignored",
        ])
        .env("QELI_DNS_LEASE_TEST_DIR", &f.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(saved(&f), before);
}
#[test]
#[ignore = "subprocess fixture, invoked only by separate_process_cannot_replace_live_dns_owner"]
fn child_refuses_live_owner() {
    let dir = PathBuf::from(std::env::var_os("QELI_DNS_LEASE_TEST_DIR").expect("parent fixture"));
    assert!(Lease::acquire(&dir, link())
        .err()
        .unwrap()
        .to_string()
        .contains("active owner"));
}

#[cfg(target_os = "linux")]
#[test]
fn state_directory_symlink_is_rejected_before_creating_evidence() {
    let f = Fixture::new();
    let alias = f.0.join("alias");
    std::os::unix::fs::symlink(&f.0, &alias).unwrap();
    let result = Lease::acquire(&alias, link());
    assert!(
        result.is_err(),
        "DNS ownership followed a directory symlink"
    );
    assert!(!f.path().exists());
}
#[cfg(target_os = "linux")]
#[test]
fn state_directory_writable_by_others_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        Lease::acquire(&f.0, link()).is_err(),
        "DNS ownership used a world-writable state directory"
    );
    assert!(!f.path().exists());
}
#[cfg(target_os = "linux")]
#[test]
fn state_directory_recovery_refuses_untrusted_marker_before_index_probe() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    drop(f.lease());
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
    let probed = Cell::new(false);
    let result = recover(&f.path(), &scope(), |_| {
        probed.set(true);
        Ok(false)
    });
    assert!(
        result.is_err(),
        "unsafe marker was accepted: {result:?}; index probed={}",
        probed.get()
    );
    assert!(!probed.get());
    assert!(f.path().exists());
}

#[test]
fn v2_cookie_distinguishes_reused_namespace_inode_without_probing_or_retiring() {
    let f = Fixture::new();
    drop(f.lease());
    let before = saved(&f);
    let mut other = scope();
    other.network_cookie += 1;
    assert_eq!(
        recover(&f.path(), &other, |_| panic!("foreign generation probe")).unwrap(),
        Recovery::Foreign
    );
    assert_eq!(saved(&f), before);
    assert!(command_target(&link(), &other, Some(link().index)).is_err());
    assert!(command_target(&link(), &other, None).is_err());
}
#[test]
fn v2_marker_name_carries_the_kernel_generation() {
    let f = Fixture::new();
    let mut other = link();
    other.scope.network_cookie += 1;
    let _a = f.lease();
    let _b = Lease::acquire(&f.0, other.clone()).unwrap();
    assert_ne!(f.path(), other.path(&f.0));
    assert!(f
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("dns-link-v2-"));
    assert_eq!(
        serde_json::from_slice::<Record>(&saved(&f))
            .unwrap()
            .version,
        2
    );
}
#[test]
fn cookie_zero_is_rejected_before_creating_state() {
    let f = Fixture::new();
    let mut bad = link();
    bad.scope.network_cookie = 0;
    assert!(Lease::acquire(&f.0, bad).is_err());
    assert_eq!(std::fs::read_dir(&f.0).unwrap().count(), 0);
}
#[test]
fn v1_evidence_is_preserved_and_cannot_be_adopted_on_matching_inode() {
    let f = Fixture::new();
    let l = link();
    let path = f.0.join(format!(
        "dns-link-v1-{}-{}-{}-{}.state",
        l.scope.boot, l.scope.device, l.scope.inode, l.index
    ));
    let bytes = br#"{"version":1,"legacy":"not sufficient to infer a namespace generation"}"#;
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        recover(&path, &scope(), |_| panic!("v1 is not authority")).unwrap(),
        Recovery::Legacy
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(Lease::acquire(&f.0, l)
        .err()
        .unwrap()
        .to_string()
        .contains("legacy DNS v1 marker"));
    assert!(!f.path().exists());
}
#[test]
fn marker_enumeration_recognizes_v2_and_retains_legacy_v1() {
    for name in ["dns-link-v1-example.state", "dns-link-v2-example.state"] {
        assert!(is_marker(name));
    }
    for name in [
        "dns-link-v2-example.lock",
        "unrelated.state",
        "dns-link-v3-example.state",
    ] {
        assert!(!is_marker(name));
    }
}
#[cfg(target_os = "linux")]
#[test]
fn moving_the_state_directory_never_retires_a_replacement_markers_inode() {
    let f = Fixture::new();
    let state = f.0.join("state");
    let moved = f.0.join("moved");
    let mut lease = Lease::acquire(&state, link()).unwrap();
    let name = lease.path.file_name().unwrap().to_owned();
    let bytes = std::fs::read(state.join(&name)).unwrap();
    std::fs::rename(&state, &moved).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join(&name), &bytes).unwrap();
    lease.cleanup(|_| Ok(())).unwrap();
    assert!(!moved.join(&name).exists());
    assert_eq!(std::fs::read(state.join(&name)).unwrap(), bytes);
}
#[cfg(target_os = "linux")]
#[test]
fn lost_directory_permissions_stop_revert_and_preserve_the_marker() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let mut lease = f.lease();
    let before = saved(&f);
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(lease.cleanup(|_| panic!("untrusted directory")).is_err());
    assert_eq!(saved(&f), before);
    std::fs::set_permissions(&f.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    lease.cleanup(|_| Ok(())).unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn unsafe_sidecar_permissions_are_rejected_before_marker_creation() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let path = f.path().with_extension("lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Lease::acquire(&f.0, link()).is_err());
    assert!(!f.path().exists());
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root; validates privileged DNS state owners"]
fn native_dns_state_refuses_foreign_marker_and_sidecar_owners() {
    use std::os::unix::ffi::OsStrExt;
    for lock in [false, true] {
        let f = Fixture::new();
        drop(f.lease());
        let path = if lock {
            f.path().with_extension("lock")
        } else {
            f.path()
        };
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 65534, 65534) }, 0);
        let before = saved(&f);
        assert!(recover(&f.path(), &scope(), |_| panic!("foreign owner")).is_err());
        assert_eq!(saved(&f), before);
    }
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root; validates delegated service directory ownership"]
fn native_root_dns_files_inherit_the_admitted_service_directory_owner() {
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
    let f = Fixture::new();
    let state = f.0.join("state");
    std::fs::create_dir(&state).unwrap();
    let path = std::ffi::CString::new(state.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
    let mut lease = Lease::acquire(&state, link()).unwrap();
    let marker = link().path(&state);
    for path in [marker.clone(), marker.with_extension("lock")] {
        let md = std::fs::metadata(path).unwrap();
        assert_eq!(md.uid(), 65534);
        assert_eq!(md.mode() & 0o777, 0o600);
    }
    lease.cleanup(|_| Ok(())).unwrap();
    assert!(!marker.exists());
}
