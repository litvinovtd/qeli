//! Exercise the real journal pruning/restoration algorithms with isolated host I/O.
use super::*;
use host::test_support::{with_io, Operation};
use std::{cell::RefCell, collections::BTreeMap, io, rc::Rc};

const KNOB: &str = "/proc/sys/net/ipv4/ip_forward";
const OWNER: &str = "42:100:edge";
#[derive(Default)]
struct Kernel {
    reads: BTreeMap<String, Result<String, io::ErrorKind>>,
    processes: BTreeMap<u32, Result<bool, io::ErrorKind>>,
    write_error: Option<io::ErrorKind>,
    writes: Vec<(String, String)>,
}
impl Kernel {
    fn command(&mut self, op: Operation<'_>) -> io::Result<String> {
        match op {
            Operation::Target(path) => panic!("unexpected target {path}"),
            Operation::NetworkCookie => Ok("1010".into()),
            Operation::Namespace(path) => match path {
                "/proc/thread-self/ns/net" => Ok("4:10".into()),
                "/proc/thread-self/ns/pid" => Ok("4:20".into()),
                "/proc/thread-self/ns/time" => Err(io::ErrorKind::NotFound.into()),
                _ => panic!("unexpected namespace {path}"),
            },
            Operation::Read("/proc/self/status") => Ok(format!("NStgid: {}\n", std::process::id())),
            Operation::Read(path) => self
                .reads
                .get(path)
                .cloned()
                .unwrap_or(Err(io::ErrorKind::NotFound))
                .map_err(Into::into),
            Operation::Write(path, value) => {
                if let Some(error) = self.write_error {
                    return Err(error.into());
                }
                self.writes.push((path.into(), value.into()));
                self.reads.insert(path.into(), Ok(value.into()));
                Ok(String::new())
            }
            Operation::ProcessExists(pid) => self
                .processes
                .get(&pid)
                .copied()
                .unwrap_or(Err(io::ErrorKind::Other))
                .map(|alive| u8::from(alive).to_string())
                .map_err(Into::into),
        }
    }
}
fn stat(pid: u32, start: &str) -> String {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = start;
    format!("{pid} (name with ) parentheses) {}", fields.join(" "))
}
fn journal(owned: bool) -> SysctlJournal {
    let mut journal = SysctlJournal::empty("4:20".into());
    journal.entries.insert(
        KNOB.into(),
        ManagedSysctl {
            target: None,
            original: "0".into(),
            managed: "1".into(),
            owners: if owned {
                BTreeSet::from([OWNER.into()])
            } else {
                BTreeSet::new()
            },
        },
    );
    journal
}
fn run(test: impl FnOnce(Rc<RefCell<Kernel>>)) {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    kernel
        .borrow_mut()
        .reads
        .insert(KNOB.into(), Ok("1\n".into()));
    let io = kernel.clone();
    with_io(move |op| io.borrow_mut().command(op), || test(kernel));
}
fn context() -> namespace::Guard {
    namespace::Guard::new(namespace::current().unwrap()).unwrap()
}
fn assert_retained(journal: &SysctlJournal, kernel: &Rc<RefCell<Kernel>>, owner: bool) {
    let entry = journal
        .entries
        .get(KNOB)
        .expect("recovery evidence must survive");
    assert_eq!(entry.original, "0");
    assert_eq!(entry.owners.contains(OWNER), owner);
    assert!(
        kernel.borrow().writes.is_empty(),
        "unknown owner must not trigger restore"
    );
}

#[test]
fn regression_unreadable_owner_is_retained_without_restoring_forwarding() {
    for error in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Other,
        io::ErrorKind::InvalidData,
    ] {
        run(|k| {
            k.borrow_mut()
                .reads
                .insert("/proc/42/stat".into(), Err(error));
            let mut j = journal(true);
            let _ = prune_dead_owners(&mut j, &context());
            assert_retained(&j, &k, true);
        });
    }
}
#[test]
fn regression_malformed_process_stat_is_not_a_dead_owner() {
    for value in ["truncated", "42 (bad) S 0", "42 (bad) S nope"] {
        run(|k| {
            k.borrow_mut()
                .reads
                .insert("/proc/42/stat".into(), Ok(value.into()));
            let mut j = journal(true);
            let _ = prune_dead_owners(&mut j, &context());
            assert_retained(&j, &k, true);
        });
    }
}
#[test]
fn regression_hidden_but_existing_process_is_not_pruned() {
    run(|k| {
        k.borrow_mut().processes.insert(42, Ok(true));
        let mut j = journal(true);
        let _ = prune_dead_owners(&mut j, &context());
        assert_retained(&j, &k, true);
    });
}
#[test]
fn regression_unknown_process_existence_is_not_pruned() {
    run(|k| {
        k.borrow_mut()
            .processes
            .insert(42, Err(io::ErrorKind::PermissionDenied));
        let mut j = journal(true);
        let _ = prune_dead_owners(&mut j, &context());
        assert_retained(&j, &k, true);
    });
}
#[test]
fn regression_failed_knob_inspection_preserves_ownerless_recovery() {
    for error in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
        run(|k| {
            k.borrow_mut().reads.insert(KNOB.into(), Err(error));
            let mut j = journal(false);
            let _ = prune_dead_owners(&mut j, &context());
            assert_retained(&j, &k, false);
        });
    }
}
#[test]
fn regression_empty_or_invalid_knob_is_not_an_administrator_change() {
    for value in ["", "   ", "garbled", "1\n2"] {
        run(|k| {
            k.borrow_mut().reads.insert(KNOB.into(), Ok(value.into()));
            let mut j = journal(false);
            let _ = prune_dead_owners(&mut j, &context());
            assert_retained(&j, &k, false);
        });
    }
}
#[test]
fn live_generation_with_complex_comm_keeps_forwarding() {
    run(|k| {
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Ok(stat(42, "100")));
        let mut j = journal(true);
        let _ = prune_dead_owners(&mut j, &context());
        assert_retained(&j, &k, true);
    });
}
#[test]
fn confirmed_pid_reuse_restores_unowned_value() {
    run(|k| {
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Ok(stat(42, "101")));
        let mut j = journal(true);
        let _ = prune_dead_owners(&mut j, &context());
        assert!(j.entries.is_empty());
        assert_eq!(k.borrow().writes, [(KNOB.into(), "0\n".into())]);
    });
}
#[test]
fn confirmed_missing_process_restores_unowned_value() {
    run(|k| {
        k.borrow_mut().processes.insert(42, Ok(false));
        let mut j = journal(true);
        let _ = prune_dead_owners(&mut j, &context());
        assert!(j.entries.is_empty());
        assert_eq!(k.borrow().writes.len(), 1);
    });
}
#[test]
fn administrator_change_is_preserved() {
    run(|k| {
        k.borrow_mut().reads.insert(KNOB.into(), Ok("2\n".into()));
        let mut j = journal(false);
        let _ = prune_dead_owners(&mut j, &context());
        assert!(j.entries.is_empty());
        assert!(k.borrow().writes.is_empty());
    });
}
#[test]
fn missing_interface_without_generation_evidence_retains_journal() {
    run(|k| {
        let path = "/proc/sys/net/ipv4/conf/edge/rp_filter";
        let mut j = journal(false);
        let entry = j.entries.remove(KNOB).unwrap();
        j.entries.insert(path.into(), entry);
        let _ = prune_dead_owners(&mut j, &context());
        assert!(j.entries.contains_key(path));
        assert!(k.borrow().writes.is_empty());
    });
}
#[test]
fn regression_missing_global_knob_is_not_completed_recovery() {
    run(|k| {
        k.borrow_mut().reads.remove(KNOB);
        let mut j = journal(false);
        let _ = prune_dead_owners(&mut j, &context());
        assert_retained(&j, &k, false);
    });
}
#[test]
fn uncertain_owner_is_reported_and_blocks_acquisition_policy() {
    run(|k| {
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Err(io::ErrorKind::PermissionDenied));
        let mut j = journal(true);
        let uncertain = prune_dead_owners(&mut j, &context());
        assert_eq!(uncertain.len(), 1);
        assert!(require_known_owners(&uncertain)
            .unwrap_err()
            .to_string()
            .contains("cannot verify"));
        assert_retained(&j, &k, true);
    });
}
#[test]
fn invalid_or_process_group_owner_ids_are_rejected() {
    for owner in [
        "0:100:edge",
        "4294967295:100:edge",
        "42::edge",
        "42:18446744073709551616:edge",
        "42:nope:edge",
        "42:100:bad:scope",
    ] {
        let mut j = journal(false);
        j.entries.get_mut(KNOB).unwrap().owners.insert(owner.into());
        assert!(validate(&j).is_err(), "{owner}");
    }
}
#[test]
fn mismatched_pid_in_stat_is_unknown_not_pid_reuse() {
    run(|k| {
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Ok(stat(43, "101")));
        let mut j = journal(true);
        assert!(!prune_dead_owners(&mut j, &context()).is_empty());
        assert_retained(&j, &k, true);
    });
}
#[test]
fn recovery_retries_after_owner_observation_becomes_available() {
    run(|k| {
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Err(io::ErrorKind::PermissionDenied));
        let mut j = journal(true);
        assert!(!prune_dead_owners(&mut j, &context()).is_empty());
        k.borrow_mut()
            .reads
            .insert("/proc/42/stat".into(), Ok(stat(42, "101")));
        assert!(prune_dead_owners(&mut j, &context()).is_empty());
        assert!(j.entries.is_empty());
        assert_eq!(k.borrow().writes.len(), 1);
    });
}
#[test]
fn own_release_preserves_uninspectable_coowner_and_reports_uncertainty() {
    run(|k| {
        let me = "99:200:own";
        k.borrow_mut()
            .reads
            .insert("/proc/99/stat".into(), Ok(stat(99, "200")));
        let mut j = journal(true);
        j.entries.get_mut(KNOB).unwrap().owners.insert(me.into());
        let uncertain = prune_dead_owners(&mut j, &context());
        assert_eq!(uncertain.len(), 1);
        assert!(!release_owner(&mut j, me, uncertain, &context()).is_empty());
        assert_eq!(j.entries[KNOB].owners, BTreeSet::from([OWNER.into()]));
        assert!(k.borrow().writes.is_empty());
    });
}
#[test]
fn unrelated_own_cleanup_continues_despite_unknown_foreign_owner() {
    run(|k| {
        let me = "99:200:own";
        let other = "/proc/sys/net/ipv6/conf/all/forwarding";
        k.borrow_mut()
            .reads
            .insert("/proc/99/stat".into(), Ok(stat(99, "200")));
        k.borrow_mut().reads.insert(other.into(), Ok("1\n".into()));
        let mut j = journal(true);
        j.entries.insert(
            other.into(),
            ManagedSysctl {
                target: None,
                original: "0".into(),
                managed: "1".into(),
                owners: BTreeSet::from([me.into()]),
            },
        );
        let uncertain = prune_dead_owners(&mut j, &context());
        assert!(!release_owner(&mut j, me, uncertain, &context()).is_empty());
        assert!(j.entries.contains_key(KNOB));
        assert!(!j.entries.contains_key(other));
        assert_eq!(k.borrow().writes, [(other.into(), "0\n".into())]);
    });
}
#[test]
fn failed_restore_write_keeps_pristine_value_for_retry() {
    run(|k| {
        k.borrow_mut().write_error = Some(io::ErrorKind::PermissionDenied);
        let mut j = journal(false);
        let _ = prune_dead_owners(&mut j, &context());
        assert_retained(&j, &k, false);
        k.borrow_mut().write_error = None;
        let _ = prune_dead_owners(&mut j, &context());
        assert!(j.entries.is_empty());
        assert_eq!(k.borrow().writes, [(KNOB.into(), "0\n".into())]);
    });
}
