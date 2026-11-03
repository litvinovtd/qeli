//! Namespace regressions use real temporary journal files and isolated kernel I/O.
use super::*;
use host::test_support::{with_io, Operation};
use std::{cell::RefCell, io, rc::Rc};
const KNOB: &str = "/proc/sys/net/ipv4/ip_forward";
const BOOT: &str = "namespace-test-boot";

#[derive(Default)]
struct Kernel {
    net: u64,
    cookie: Option<u64>,
    cookie_error: Option<io::ErrorKind>,
    no_cookie: bool,
    pid_ns: u64,
    time_ns: Option<u64>,
    time_error: Option<io::ErrorKind>,
    inherited_proc: bool,
    writes: Vec<String>,
    values: BTreeMap<u64, String>,
    namespace_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    status: Option<Result<String, io::ErrorKind>>,
    probes: usize,
    switch_after_owner_read: Option<u64>,
    switch_after_knob_read: Option<u64>,
    switch_after_write: Option<u64>,
}
struct Fixture {
    path: PathBuf,
    kernel: Rc<RefCell<Kernel>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}
fn run(test: impl FnOnce(&Fixture)) {
    let dir = std::env::temp_dir().join(format!(
        "qeli-sysctl-ns-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let fixture = Fixture {
        path: dir.join("sysctls.state"),
        kernel: Rc::new(RefCell::new(Kernel {
            net: 10,
            pid_ns: 20,
            ..Kernel::default()
        })),
    };
    let kernel = fixture.kernel.clone();
    with_io(
        move |op| {
            let mut k = kernel.borrow_mut();
            match op {
                Operation::Target(path) => panic!("unexpected target {path}"),
                Operation::NetworkCookie => {
                    if let Some(error) = k.cookie_error {
                        return Err(error.into());
                    }
                    if k.no_cookie {
                        return Ok("unsupported".into());
                    }
                    Ok(k.cookie.unwrap_or(k.net + 1000).to_string())
                }
                Operation::Namespace(path) => {
                    if let Some(error) = k.namespace_error {
                        return Err(error.into());
                    }
                    Ok(format!(
                        "4:{}",
                        match path {
                            "/proc/thread-self/ns/net" => k.net,
                            "/proc/thread-self/ns/pid" => k.pid_ns,
                            "/proc/thread-self/ns/time" => {
                                if let Some(error) = k.time_error {
                                    return Err(error.into());
                                }
                                match k.time_ns {
                                    Some(id) => id,
                                    None => return Err(io::ErrorKind::NotFound.into()),
                                }
                            }
                            _ => panic!("unexpected namespace path {path}"),
                        }
                    ))
                }
                Operation::Read("/proc/self/status") => {
                    if let Some(status) = k.status.clone() {
                        return status.map_err(Into::into);
                    }
                    Ok(format!(
                        "Name: qeli\nNStgid: {}{}\n",
                        if k.inherited_proc { "1000 " } else { "" },
                        std::process::id()
                    ))
                }
                Operation::Read(path) if path == KNOB => {
                    let value = k
                        .values
                        .get(&k.net)
                        .cloned()
                        .unwrap_or_else(|| "1\n".into());
                    if let Some(net) = k.switch_after_knob_read.take() {
                        k.net = net;
                    }
                    Ok(value)
                }
                Operation::Read(path) => {
                    k.probes += 1;
                    if let Some(net) = k.switch_after_owner_read.take() {
                        k.net = net;
                    }
                    if path == format!("/proc/{}/stat", std::process::id()) {
                        let mut fields = vec!["0"; 20];
                        fields[0] = "S";
                        fields[19] = "100";
                        Ok(format!(
                            "{} (qeli) {}",
                            std::process::id(),
                            fields.join(" ")
                        ))
                    } else {
                        Err(io::ErrorKind::NotFound.into())
                    }
                }
                Operation::Write(_, value) => {
                    if let Some(error) = k.write_error {
                        return Err(error.into());
                    }
                    let net = k.net;
                    k.values.insert(net, value.into());
                    k.writes.push(value.into());
                    if let Some(net) = k.switch_after_write.take() {
                        k.net = net;
                    }
                    Ok(String::new())
                }
                Operation::ProcessExists(_) => {
                    k.probes += 1;
                    Ok("0".into())
                }
            }
        },
        || test(&fixture),
    );
}
// Execute the production transaction below the flock boundary with a unique temp file.
fn seed_owned(f: &Fixture) {
    with_journal(&f.path, BOOT, |tx, _| {
        tx.current_mut().entries.insert(
            KNOB.into(),
            ManagedSysctl {
                target: None,
                original: "0".into(),
                managed: "1".into(),
                owners: BTreeSet::from([format!("{}:100:edge", i32::MAX)]),
            },
        );
        tx.persist()
    })
    .unwrap();
}
fn recover_at(f: &Fixture) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, recover_in)
}
fn acquire_at(f: &Fixture, value: &str, scope: &str) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, |tx, unknown| {
        acquire_in(tx, &unknown, KNOB, value, scope)
    })
}
fn release_at(f: &Fixture, scope: &str) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, |tx, unknown| release_in(tx, unknown, scope))
}
fn legacy(f: &Fixture, boot: &str) -> Vec<u8> {
    let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"boot_id":boot,"entries":{KNOB:{"original":"0","managed":"1","owners":[]}}})).unwrap();
    std::fs::write(&f.path, &bytes).unwrap();
    bytes
}
#[test]
fn regression_foreign_network_does_not_restore_or_discard_saved_state() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().net = 11;
        recover_at(f).unwrap();
        assert!(
            f.kernel.borrow().writes.is_empty(),
            "foreign namespace must not restore a local knob"
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}
#[test]
fn regression_same_network_foreign_pid_namespace_refuses_before_pruning() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().pid_ns = 21;
        assert!(
            recover_at(f).is_err(),
            "foreign PID namespace is not evidence of dead owners"
        );
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}
#[test]
fn regression_inherited_procfs_view_is_rejected_before_creating_state() {
    run(|f| {
        f.kernel.borrow_mut().inherited_proc = true;
        assert!(
            recover_at(f).is_err(),
            "PID probes must use the procfs PID coordinate system"
        );
        assert!(!f.path.exists());
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn regression_legacy_same_boot_recovery_is_not_assigned_to_current_namespace() {
    run(|f| {
        let before = legacy(f, BOOT);
        assert!(
            recover_at(f).is_err(),
            "legacy namespace cannot be inferred even without owners"
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn previous_boot_legacy_state_is_not_replayed() {
    run(|f| {
        legacy(f, "previous-boot");
        recover_at(f).unwrap();
        assert!(!f.path.exists());
        assert!(f.kernel.borrow().writes.is_empty());
    });
}

#[test]
fn separate_networks_keep_independent_originals_and_release_independently() {
    run(|f| {
        f.kernel.borrow_mut().values.insert(10, "0".into());
        acquire_at(f, "1", "edge").unwrap();
        f.kernel.borrow_mut().net = 11;
        f.kernel.borrow_mut().values.insert(11, "2".into());
        acquire_at(f, "1", "edge").unwrap();
        let store = load(&f.path, BOOT).unwrap();
        assert_eq!(store.namespaces.len(), 2);
        assert_eq!(store.namespaces["4:10"].entries[KNOB].original, "0");
        assert_eq!(store.namespaces["4:11"].entries[KNOB].original, "2");
        release_at(f, "edge").unwrap();
        assert_eq!(f.kernel.borrow().values[&11], "2\n");
        assert_eq!(f.kernel.borrow().values[&10], "1\n");
        let store = load(&f.path, BOOT).unwrap();
        assert_eq!(store.namespaces.len(), 1);
        assert!(store.namespaces.contains_key("4:10"));
        f.kernel.borrow_mut().net = 10;
        release_at(f, "edge").unwrap();
        assert_eq!(f.kernel.borrow().values[&10], "0\n");
        assert!(!f.path.exists());
    });
}
#[test]
fn foreign_network_owners_are_never_probed_in_current_pid_namespace() {
    run(|f| {
        seed_owned(f);
        f.kernel.borrow_mut().net = 11;
        recover_at(f).unwrap();
        assert_eq!(f.kernel.borrow().probes, 0);
    });
}
#[test]
fn matching_namespaces_recover_confirmed_dead_owner() {
    run(|f| {
        seed_owned(f);
        recover_at(f).unwrap();
        assert_eq!(f.kernel.borrow().writes, ["0\n"]);
        assert!(!f.path.exists());
    });
}
#[test]
fn same_network_different_pid_namespace_cannot_acquire_or_release() {
    run(|f| {
        acquire_at(f, "1", "edge").unwrap();
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().pid_ns = 21;
        assert!(acquire_at(f, "1", "other")
            .unwrap_err()
            .to_string()
            .contains("PID namespace mismatch"));
        assert!(release_at(f, "edge").is_err());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn final_release_does_not_reserve_empty_network_group() {
    run(|f| {
        acquire_at(f, "1", "edge").unwrap();
        f.kernel.borrow_mut().net = 11;
        acquire_at(f, "1", "other").unwrap();
        f.kernel.borrow_mut().net = 10;
        release_at(f, "edge").unwrap();
        f.kernel.borrow_mut().pid_ns = 21;
        acquire_at(f, "1", "replacement").unwrap();
        let store = load(&f.path, BOOT).unwrap();
        assert_eq!(store.namespaces["4:10"].pid_namespace, "4:21");
        assert_eq!(store.namespaces["4:11"].pid_namespace, "4:20");
    });
}
#[test]
fn namespace_inspection_failure_preserves_existing_journal() {
    for error in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::NotFound,
        io::ErrorKind::Other,
    ] {
        run(|f| {
            seed_owned(f);
            let before = std::fs::read(&f.path).unwrap();
            f.kernel.borrow_mut().namespace_error = Some(error);
            assert!(recover_at(f).is_err());
            assert_eq!(std::fs::read(&f.path).unwrap(), before);
            assert!(f.kernel.borrow().writes.is_empty());
            assert_eq!(f.kernel.borrow().probes, 0);
        });
    }
}
#[test]
fn invalid_or_unreadable_procfs_status_cannot_admit_transaction() {
    let pid = std::process::id();
    for status in [
        Ok(String::new()),
        Ok("NStgid: 0".into()),
        Ok("NStgid: nope".into()),
        Ok(format!("NStgid: {pid}\nNStgid: {pid}")),
        Ok(format!("NStgid: {}", pid + 1)),
        Err(io::ErrorKind::PermissionDenied),
        Err(io::ErrorKind::NotFound),
    ] {
        run(|f| {
            f.kernel.borrow_mut().status = Some(status);
            assert!(acquire_at(f, "1", "edge").is_err());
            assert!(!f.path.exists());
            assert!(f.kernel.borrow().writes.is_empty());
        });
    }
}
#[test]
fn empty_legacy_journal_can_be_replaced_without_guessing_a_namespace() {
    run(|f| {
        std::fs::write(
            &f.path,
            format!(r#"{{"version":1,"boot_id":"{BOOT}","entries":{{}}}}"#),
        )
        .unwrap();
        acquire_at(f, "1", "edge").unwrap();
        let store = load(&f.path, BOOT).unwrap();
        assert_eq!(store.version, JOURNAL_VERSION);
        assert_eq!(store.namespaces["4:10"].pid_namespace, "4:20");
    });
}
#[test]
fn nonempty_legacy_acquire_and_release_keep_original_bytes() {
    run(|f| {
        let before = legacy(f, BOOT);
        assert!(acquire_at(f, "1", "edge")
            .unwrap_err()
            .to_string()
            .contains("legacy host sysctl journal"));
        assert!(release_at(f, "edge").is_err());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn previous_boot_namespaced_state_is_not_replayed_or_pid_checked() {
    run(|f| {
        seed_owned(f);
        let mut store = load(&f.path, BOOT).unwrap();
        store.boot_id = "previous-boot".into();
        persist(&f.path, &store).unwrap();
        f.kernel.borrow_mut().pid_ns = 21;
        recover_at(f).unwrap();
        assert!(!f.path.exists());
        assert_eq!(f.kernel.borrow().probes, 0);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn unsupported_version_is_not_discarded_even_from_previous_boot() {
    run(|f| {
        let before = br#"{"version":99,"boot_id":"previous-boot","namespaces":{}}"#;
        std::fs::write(&f.path, before).unwrap();
        assert!(recover_at(f)
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}
#[test]
fn corrupt_foreign_namespace_is_not_silently_overwritten() {
    run(|f| {
        seed_owned(f);
        let mut store = load(&f.path, BOOT).unwrap();
        store.namespaces.get_mut("4:10").unwrap().pid_namespace = "invalid".into();
        let before = serde_json::to_vec(&store).unwrap();
        std::fs::write(&f.path, &before).unwrap();
        f.kernel.borrow_mut().net = 11;
        assert!(acquire_at(f, "1", "edge").is_err());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn failed_oversized_persist_preserves_previous_journal() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        let mut store = load(&f.path, BOOT).unwrap();
        let mut entry = store.namespaces["4:10"].entries[KNOB].clone();
        entry.owners = (1..=256)
            .map(|pid| format!("{pid}:100:long-owner-scope-012345678901234"))
            .collect();
        for n in 0..32 {
            let mut journal = SysctlJournal::empty("4:20".into());
            journal.network_cookie = Some(1000 + n);
            journal.entries.insert(KNOB.into(), entry.clone());
            store.namespaces.insert(format!("4:{}", 100 + n), journal);
        }
        assert!(persist(&f.path, &store)
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}
#[test]
fn namespace_keys_are_canonical_device_and_inode_pairs() {
    for value in ["4:10", "0:1", "18446744073709551615:18446744073709551615"] {
        assert!(namespace::valid_identity(value));
    }
    for value in [
        "",
        "net:[10]",
        "4:0",
        "04:10",
        "4:010",
        "4:-1",
        "4:1:2",
        "4:18446744073709551616",
        "../net",
    ] {
        assert!(!namespace::valid_identity(value));
    }
}

#[test]
fn changed_or_hidden_time_namespace_cannot_reinterpret_process_start_times() {
    for other in [Some(31), None] {
        run(|f| {
            f.kernel.borrow_mut().time_ns = Some(30);
            seed_owned(f);
            let before = std::fs::read(&f.path).unwrap();
            f.kernel.borrow_mut().time_ns = other;
            assert!(recover_at(f)
                .unwrap_err()
                .to_string()
                .contains("time namespace mismatch"));
            assert_eq!(std::fs::read(&f.path).unwrap(), before);
            assert!(f.kernel.borrow().writes.is_empty());
            assert_eq!(f.kernel.borrow().probes, 0);
        });
    }
}
#[test]
fn unreadable_time_namespace_is_not_treated_as_unsupported_kernel() {
    run(|f| {
        f.kernel.borrow_mut().time_error = Some(io::ErrorKind::PermissionDenied);
        assert!(acquire_at(f, "1", "edge").is_err());
        assert!(!f.path.exists());
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn matching_time_namespace_allows_normal_recovery() {
    run(|f| {
        f.kernel.borrow_mut().time_ns = Some(30);
        seed_owned(f);
        recover_at(f).unwrap();
        assert!(!f.path.exists());
        assert_eq!(f.kernel.borrow().writes, ["0\n"]);
    });
}

#[test]
fn failed_acquire_persists_original_for_retry_without_losing_foreign_group() {
    run(|f| {
        acquire_at(f, "1", "foreign").unwrap();
        f.kernel.borrow_mut().net = 11;
        f.kernel.borrow_mut().values.insert(11, "0".into());
        f.kernel.borrow_mut().write_error = Some(io::ErrorKind::PermissionDenied);
        assert!(acquire_at(f, "1", "edge").is_err());
        let store = load(&f.path, BOOT).unwrap();
        assert!(store.namespaces.contains_key("4:10"));
        let entry = &store.namespaces["4:11"].entries[KNOB];
        assert_eq!(entry.original, "0");
        assert!(entry.owners.is_empty());
        f.kernel.borrow_mut().write_error = None;
        recover_at(f).unwrap();
        assert_eq!(load(&f.path, BOOT).unwrap().namespaces.len(), 1);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn failed_restore_is_reported_and_retained_until_retry_in_original_namespace() {
    run(|f| {
        f.kernel.borrow_mut().values.insert(10, "0".into());
        acquire_at(f, "1", "edge").unwrap();
        f.kernel.borrow_mut().write_error = Some(io::ErrorKind::PermissionDenied);
        assert!(release_at(f, "edge").is_err());
        let store = load(&f.path, BOOT).unwrap();
        assert!(store.namespaces["4:10"].entries[KNOB].owners.is_empty());
        assert!(recover_at(f)
            .unwrap_err()
            .to_string()
            .contains("could not restore stale"));
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().net = 11;
        recover_at(f).unwrap();
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        f.kernel.borrow_mut().net = 10;
        f.kernel.borrow_mut().write_error = None;
        recover_at(f).unwrap();
        assert!(!f.path.exists());
        assert_eq!(f.kernel.borrow().values[&10], "0\n");
    });
}

#[cfg(unix)]
#[test]
fn untrusted_journal_modes_cannot_authorize_stale_sysctl_restoration() {
    use std::os::unix::fs::PermissionsExt;
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            recover_at(f).is_err(),
            "a writable journal cannot authorize kernel restoration"
        );
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}

#[cfg(unix)]
#[test]
fn hardlinked_journal_cannot_authorize_stale_sysctl_restoration() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        let other = f.path.with_extension("other");
        std::fs::hard_link(&f.path, &other).unwrap();
        assert!(
            recover_at(f).is_err(),
            "a multiply-linked journal cannot authorize kernel restoration"
        );
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert_eq!(std::fs::read(other).unwrap(), before);
    });
}

#[test]
fn namespace_change_across_lock_wait_refuses_before_pruning_or_persisting() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        let admitted = namespace::current().unwrap();
        f.kernel.borrow_mut().net = 11;
        assert!(with_journal_context(&f.path, BOOT, admitted, recover_in).is_err());
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}

#[test]
fn local_journal_lock_has_a_deadline_without_stealing_ownership() {
    let lock = Mutex::new(());
    let held = lock.lock().unwrap();
    assert!(wait_local_lock(&lock, std::time::Instant::now()).is_err());
    drop(held);
    assert!(wait_local_lock(&lock, std::time::Instant::now()).is_ok());
}

#[test]
fn context_loss_during_owner_probe_cannot_prune_or_persist() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().switch_after_owner_read = Some(11);
        assert!(recover_at(f).is_err());
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(
            f.kernel.borrow().probes,
            1,
            "do not probe PID existence in the new context"
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        f.kernel.borrow_mut().net = 10;
        recover_at(f).unwrap();
        assert!(!f.path.exists());
    });
}

#[test]
fn context_loss_after_original_read_cannot_acquire_in_another_namespace() {
    run(|f| {
        f.kernel.borrow_mut().values.insert(10, "0".into());
        f.kernel.borrow_mut().switch_after_knob_read = Some(11);
        assert!(acquire_at(f, "1", "edge").is_err());
        assert!(f.kernel.borrow().writes.is_empty());
        assert!(
            !f.path.exists(),
            "an unverified original must not enter the journal"
        );
    });
}

#[test]
fn context_loss_before_restore_write_retains_the_original_journal() {
    run(|f| {
        f.kernel.borrow_mut().values.insert(10, "0".into());
        acquire_at(f, "1", "edge").unwrap();
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().writes.clear();
        f.kernel.borrow_mut().switch_after_knob_read = Some(11);
        assert!(release_at(f, "edge").is_err());
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        f.kernel.borrow_mut().net = 10;
        release_at(f, "edge").unwrap();
        assert_eq!(f.kernel.borrow().writes, ["0\n"]);
        assert!(!f.path.exists());
    });
}

#[test]
fn context_loss_after_write_preserves_evidence_and_poisoned_transaction_cannot_commit() {
    run(|f| {
        f.kernel.borrow_mut().values.insert(10, "0".into());
        f.kernel.borrow_mut().values.insert(11, "2".into());
        let result = with_journal(&f.path, BOOT, |tx, unknown| {
            f.kernel.borrow_mut().switch_after_write = Some(11);
            assert!(acquire_in(tx, &unknown, KNOB, "1", "edge").is_err());
            // Returning to the original namespace must not resurrect a transaction
            // whose verification failed after an actual mutation.
            f.kernel.borrow_mut().net = 10;
            tx.current_mut().entries.clear();
            tx.persist()
        });
        assert!(result.is_err());
        let store = load(&f.path, BOOT).unwrap();
        let entry = &store.namespaces["4:10"].entries[KNOB];
        assert_eq!(entry.original, "0");
        assert_eq!(entry.owners.len(), 1);
        assert_eq!(f.kernel.borrow().values[&10], "1\n");
        assert_eq!(f.kernel.borrow().values[&11], "2");
        release_at(f, "edge").unwrap();
        assert_eq!(f.kernel.borrow().values[&10], "0\n");
        assert!(!f.path.exists());
    });
}

#[test]
fn reused_namespace_inode_cannot_replay_original_or_prune_owners() {
    run(|f| {
        seed_owned(f);
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().cookie = Some(2020);
        for result in [
            recover_at(f),
            acquire_at(f, "1", "new"),
            release_at(f, "edge"),
        ] {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("generation mismatch"));
        }
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
        assert_eq!(f.kernel.borrow().probes, 0);
    });
}
#[test]
fn missing_or_unreadable_cookie_never_changes_owned_state() {
    for error in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
        run(|f| {
            seed_owned(f);
            let before = std::fs::read(&f.path).unwrap();
            f.kernel.borrow_mut().cookie_error = Some(error);
            assert!(recover_at(f).is_err());
            assert_eq!(std::fs::read(&f.path).unwrap(), before);
            assert!(f.kernel.borrow().writes.is_empty());
        });
    }
    run(|f| {
        f.kernel.borrow_mut().no_cookie = true;
        recover_at(f).unwrap();
        assert!(acquire_at(f, "1", "edge")
            .unwrap_err()
            .to_string()
            .contains("SO_NETNS_COOKIE"));
        assert!(!f.path.exists());
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn legacy_v3_same_boot_requires_verified_upgrade_without_replay() {
    run(|f| {
        seed_owned(f);
        let mut old: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&f.path).unwrap()).unwrap();
        old["version"] = 3.into();
        old["namespaces"]["4:10"]
            .as_object_mut()
            .unwrap()
            .remove("network_cookie");
        let before = serde_json::to_vec(&old).unwrap();
        std::fs::write(&f.path, &before).unwrap();
        assert!(recover_at(f).unwrap_err().to_string().contains("legacy v3"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
        assert!(decode_store(&before, "next-boot")
            .unwrap()
            .namespaces
            .is_empty());
    });
}
#[test]
fn invalid_v4_cookie_is_rejected_even_from_previous_boot() {
    run(|f| {
        seed_owned(f);
        let base: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&f.path).unwrap()).unwrap();
        for cookie in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!("1010"),
        ] {
            let mut value = base.clone();
            value["namespaces"]["4:10"]["network_cookie"] = cookie;
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(decode_store(&bytes, BOOT).is_err());
            assert!(decode_store(&bytes, "next-boot").is_err());
        }
    });
}
