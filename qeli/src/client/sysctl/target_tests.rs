//! Production journal algorithms with replaceable per-interface kernel objects.
use super::*;
use host::test_support::{with_io, Operation};
use std::{cell::RefCell, io, rc::Rc};
const LINK: &str = "/proc/sys/net/ipv6/conf/wan0/accept_ra";
const GLOBAL: &str = "/proc/sys/net/ipv4/ip_forward";
const BOOT: &str = "target-test-boot";
struct Kernel {
    object: Option<u64>,
    object_time: u64,
    value: String,
    global: String,
    owner_gone: bool,
    die_on_open: bool,
    replace_after_read: bool,
    writes: Vec<String>,
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
    let directory = std::env::temp_dir().join(format!(
        "qeli-target-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let f = Fixture {
        path: directory.join("sysctls.state"),
        kernel: Rc::new(RefCell::new(Kernel {
            object: Some(100),
            object_time: 1000,
            value: "1".into(),
            global: "0".into(),
            owner_gone: false,
            die_on_open: false,
            replace_after_read: false,
            writes: vec![],
        })),
    };
    let kernel = f.kernel.clone();
    with_io(
        move |op| {
            let mut k = kernel.borrow_mut();
            match op {
                Operation::NetworkCookie => Ok("1010".into()),
                Operation::Namespace(path) => match path {
                    "/proc/thread-self/ns/net" => Ok("4:10".into()),
                    "/proc/thread-self/ns/pid" => Ok("4:20".into()),
                    "/proc/thread-self/ns/time" => Err(io::ErrorKind::NotFound.into()),
                    _ => panic!("unexpected namespace {path}"),
                },
                Operation::Read("/proc/self/status") => {
                    Ok(format!("NStgid: {}", std::process::id()))
                }
                Operation::Read(path) if path.ends_with("/stat") => {
                    if k.owner_gone {
                        return Err(io::ErrorKind::NotFound.into());
                    }
                    let mut fields = vec!["0"; 20];
                    fields[0] = "S";
                    fields[19] = "100";
                    Ok(format!(
                        "{} (qeli) {}",
                        std::process::id(),
                        fields.join(" ")
                    ))
                }
                Operation::ProcessExists(_) => Ok(if k.owner_gone { "0" } else { "1" }.into()),
                Operation::Target(LINK) => {
                    if k.die_on_open {
                        k.die_on_open = false;
                        k.owner_gone = true;
                    }
                    k.object
                        .map(|id| format!("5:{id}:{}:1234", k.object_time))
                        .ok_or_else(|| io::ErrorKind::NotFound.into())
                }
                Operation::Read(LINK) => {
                    let old = k.value.clone();
                    if k.replace_after_read {
                        k.replace_after_read = false;
                        k.object = Some(101);
                        k.value = "2".into();
                    }
                    Ok(old)
                }
                Operation::Read(GLOBAL) => Ok(k.global.clone()),
                Operation::Write(path, value) if path == LINK || path == GLOBAL => {
                    k.writes.push(path.into());
                    if path == LINK {
                        k.value = value.trim().into();
                    } else {
                        k.global = value.trim().into();
                    }
                    Ok(String::new())
                }
                _ => panic!("unexpected target operation"),
            }
        },
        || test(&f),
    );
}
fn acquire(f: &Fixture, path: &str, value: &str, scope: &str) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, |tx, unknown| {
        acquire_in(tx, &unknown, path, value, scope)
    })
}
fn release(f: &Fixture, scope: &str) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, |tx, unknown| release_in(tx, unknown, scope))
}
fn recover(f: &Fixture) -> anyhow::Result<()> {
    with_journal(&f.path, BOOT, recover_in)
}
fn retained(f: &Fixture) {
    let store = load(&f.path, BOOT).unwrap();
    let entry = &store.namespaces["4:10"].entries[LINK];
    assert_eq!(entry.original, "1");
    assert_eq!(entry.managed, "2");
}
#[test]
fn original_descriptor_restores_only_after_last_scope_and_releases_cache() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        acquire(f, LINK, "2", "two").unwrap();
        assert_eq!(target::test_cache_len(), 1);
        release(f, "one").unwrap();
        assert_eq!(f.kernel.borrow().value, "2");
        release(f, "two").unwrap();
        assert_eq!(f.kernel.borrow().value, "1");
        assert!(!f.path.exists());
        assert_eq!(target::test_cache_len(), 0);
    });
}
#[test]
fn replaced_interface_is_never_restored_or_adopted_by_reacquisition() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        f.kernel.borrow_mut().writes.clear();
        f.kernel.borrow_mut().object = Some(101);
        assert!(release(f, "one").is_err());
        retained(f);
        assert!(acquire(f, LINK, "2", "two").is_err());
        retained(f);
        assert_eq!(f.kernel.borrow().value, "2");
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn renamed_or_removed_table_keeps_the_original_evidence() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        f.kernel.borrow_mut().writes.clear();
        f.kernel.borrow_mut().object = None;
        assert!(release(f, "one").is_err());
        retained(f);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn replacement_between_original_read_and_write_preserves_pending_original() {
    run(|f| {
        f.kernel.borrow_mut().replace_after_read = true;
        assert!(acquire(f, LINK, "2", "one").is_err());
        retained(f);
        assert_eq!(f.kernel.borrow().value, "2");
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn crash_without_descriptor_refuses_even_matching_inode_and_restores_unrelated_global() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        acquire(f, GLOBAL, "1", "one").unwrap();
        target::clear_test_cache();
        f.kernel.borrow_mut().owner_gone = true;
        f.kernel.borrow_mut().writes.clear();
        assert!(recover(f).is_err());
        retained(f);
        assert_eq!(f.kernel.borrow().value, "2");
        assert_eq!(f.kernel.borrow().global, "0");
        assert_eq!(f.kernel.borrow().writes, [GLOBAL]);
    });
}
#[test]
fn crashed_unchanged_lease_needs_no_interface_restore() {
    run(|f| {
        f.kernel.borrow_mut().value = "2".into();
        acquire(f, LINK, "2", "one").unwrap();
        target::clear_test_cache();
        f.kernel.borrow_mut().owner_gone = true;
        f.kernel.borrow_mut().object = None;
        recover(f).unwrap();
        assert!(!f.path.exists());
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
#[test]
fn new_process_may_join_only_while_original_descriptor_has_a_live_owner() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        // Model a separate process's registry while the original owner's descriptor remains held.
        let store = load(&f.path, BOOT).unwrap();
        let entry = &store.namespaces["4:10"].entries[LINK];
        let guard = namespace::Guard::new(namespace::current().unwrap())
            .unwrap()
            .with_journal_scope(&f.path);
        let original = target::resolve(LINK, entry.target.as_ref(), &guard, None).unwrap();
        target::clear_test_cache();
        acquire(f, LINK, "2", "two").unwrap();
        assert_eq!(
            load(&f.path, BOOT).unwrap().namespaces["4:10"].entries[LINK]
                .owners
                .len(),
            2
        );
        drop(original);
        release(f, "one").unwrap();
        release(f, "two").unwrap();
        assert_eq!(f.kernel.borrow().value, "1");
    });
}
#[test]
fn witness_dying_during_open_cannot_authorize_a_matching_numeric_inode() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        target::clear_test_cache();
        f.kernel.borrow_mut().die_on_open = true;
        let before = std::fs::read(&f.path).unwrap();
        assert!(acquire(f, LINK, "2", "two")
            .unwrap_err()
            .to_string()
            .contains("witness"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
    });
}
#[test]
fn v2_current_boot_is_preserved_but_empty_or_previous_boot_may_upgrade() {
    run(|f| {
        acquire(f, GLOBAL, "1", "one").unwrap();
        let mut store = load(&f.path, BOOT).unwrap();
        store.version = 2;
        let before = serde_json::to_vec(&store).unwrap();
        std::fs::write(&f.path, &before).unwrap();
        assert!(recover(f).unwrap_err().to_string().contains("legacy v2"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        store.boot_id = "previous-boot".into();
        assert!(decode_store(&serde_json::to_vec(&store).unwrap(), BOOT)
            .unwrap()
            .namespaces
            .is_empty());
        store.boot_id = BOOT.into();
        store.namespaces.clear();
        assert_eq!(
            decode_store(&serde_json::to_vec(&store).unwrap(), BOOT)
                .unwrap()
                .version,
            JOURNAL_VERSION
        );
    });
}
#[test]
fn per_interface_cache_is_bounded_and_validated_journal_can_release_unused_pins() {
    run(|f| {
        let guard = namespace::Guard::new(namespace::current().unwrap())
            .unwrap()
            .with_journal_scope(&f.path);
        for _ in 0..256 {
            target::capture(LINK, &guard).unwrap();
        }
        assert!(target::capture(LINK, &guard).is_err());
        assert_eq!(target::test_cache_len(), 256);
        recover(f).unwrap();
        assert_eq!(target::test_cache_len(), 0);
    });
}

#[test]
fn live_witness_cannot_admit_a_reused_inode_with_a_different_timestamp() {
    run(|f| {
        acquire(f, LINK, "2", "one").unwrap();
        target::clear_test_cache();
        f.kernel.borrow_mut().object_time += 1;
        let before = std::fs::read(&f.path).unwrap();
        f.kernel.borrow_mut().writes.clear();
        assert!(acquire(f, LINK, "2", "two")
            .unwrap_err()
            .to_string()
            .contains("object changed"));
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert!(f.kernel.borrow().writes.is_empty());
    });
}
