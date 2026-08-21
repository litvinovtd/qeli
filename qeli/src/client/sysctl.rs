//! Cross-process ownership for Linux host-networking sysctls.
//!
//! Server profiles, standalone clients, and panel-managed outbound client processes may all
//! use the same host-wide forwarding knobs. A process-local "prior value" snapshot lets the
//! first component that stops restore a value still required by another one. The journal
//! below is locked across processes, records the pristine value before mutation, and
//! identifies an owner by PID + `/proc/<pid>/stat` start time + TUN scope so PID reuse and
//! same-process multi-profile operation are both handled. The journal follows the state
//! directory's ownership, so a manual root client cannot lock a later User=qeli service out.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const JOURNAL_VERSION: u8 = 1;
const JOURNAL_LIMIT: u64 = 128 * 1024;
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const JOURNAL_NAME: &str = "sysctls.state";

static IN_PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ManagedSysctl {
    original: String,
    managed: String,
    owners: BTreeSet<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SysctlJournal {
    version: u8,
    boot_id: String,
    entries: BTreeMap<String, ManagedSysctl>,
}

impl SysctlJournal {
    fn empty(boot_id: String) -> Self {
        Self {
            version: JOURNAL_VERSION,
            boot_id,
            entries: BTreeMap::new(),
        }
    }
}

fn journal_path() -> PathBuf {
    std::env::var_os("STATE_DIRECTORY")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/qeli"))
        .join(JOURNAL_NAME)
}

fn current_boot_id() -> anyhow::Result<String> {
    let value = std::fs::read_to_string(BOOT_ID_PATH)
        .map_err(|error| anyhow::anyhow!("cannot read {BOOT_ID_PATH}: {error}"))?;
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        anyhow::bail!("{BOOT_ID_PATH} contains an invalid boot identifier");
    }
    Ok(value.to_string())
}

fn process_start_time(pid: u32) -> anyhow::Result<String> {
    let path = format!("/proc/{pid}/stat");
    let stat = std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("cannot read {path}: {error}"))?;
    // `comm` is parenthesized and may itself contain spaces or `)`, so split after the last
    // closing parenthesis. The remaining fields start at field 3; starttime is field 22.
    let close = stat
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("{path} has no process-name terminator"))?;
    let start = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow::anyhow!("{path} has no start-time field"))?;
    if start.is_empty() || !start.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("{path} contains an invalid start-time field");
    }
    Ok(start.to_string())
}

fn owner_id(scope: &str) -> anyhow::Result<String> {
    if !valid_scope(scope) {
        anyhow::bail!("invalid sysctl owner scope {scope:?}");
    }
    let pid = std::process::id();
    Ok(format!("{pid}:{}:{scope}", process_start_time(pid)?))
}

fn owner_is_alive(owner: &str) -> bool {
    let mut parts = owner.splitn(3, ':');
    let Some(pid) = parts.next().and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    let Some(expected_start) = parts.next() else {
        return false;
    };
    parts.next().is_some_and(valid_scope)
        && process_start_time(pid).is_ok_and(|actual| actual == expected_start)
}

fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 32
        && !scope.contains('/')
        && !scope.contains('\\')
        && !scope.contains(':')
        && !scope
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && !name.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '/' | '\\' | ':')
        })
}

fn valid_sysctl_path(path: &str) -> bool {
    let fields: Vec<&str> = path
        .strip_prefix("/proc/sys/net/")
        .map(|suffix| suffix.split('/').collect())
        .unwrap_or_default();
    matches!(fields.as_slice(), ["ipv4", "ip_forward"])
        || matches!(fields.as_slice(), ["ipv4", "conf", interface, "rp_filter"] if valid_ifname(interface))
        || matches!(fields.as_slice(), ["ipv6", "conf", "all", "forwarding"])
        || matches!(fields.as_slice(), ["ipv6", "conf", interface, "accept_ra"] if valid_ifname(interface))
}

fn valid_value(value: &str) -> bool {
    matches!(value, "0" | "1" | "2")
}

fn validate(journal: &SysctlJournal) -> anyhow::Result<()> {
    if journal.version != JOURNAL_VERSION
        || journal.boot_id.is_empty()
        || journal.boot_id.len() > 128
        || journal.boot_id.chars().any(char::is_control)
        || journal.entries.len() > 256
    {
        anyhow::bail!("invalid host sysctl journal header");
    }
    for (path, entry) in &journal.entries {
        if !valid_sysctl_path(path)
            || !valid_value(&entry.original)
            || !valid_value(&entry.managed)
            || entry.owners.len() > 256
            || entry.owners.iter().any(|owner| {
                let mut parts = owner.splitn(3, ':');
                parts
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_none()
                    || !parts.next().is_some_and(|start| {
                        !start.is_empty() && start.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    || !parts.next().is_some_and(valid_scope)
            })
        {
            anyhow::bail!("invalid host sysctl journal entry for {path:?}");
        }
    }
    Ok(())
}

fn load(path: &Path, boot_id: &str) -> anyhow::Result<SysctlJournal> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SysctlJournal::empty(boot_id.to_string()));
        }
        Err(error) => anyhow::bail!("cannot inspect {}: {error}", path.display()),
    };
    if !metadata.file_type().is_file() || metadata.len() > JOURNAL_LIMIT {
        anyhow::bail!(
            "refusing invalid host sysctl journal {} (regular={}, size={})",
            path.display(),
            metadata.file_type().is_file(),
            metadata.len()
        );
    }
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
    let journal: SysctlJournal = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("cannot parse {}: {error}", path.display()))?;
    validate(&journal)?;
    if journal.boot_id == boot_id {
        Ok(journal)
    } else {
        // `/var/lib` survives a reboot, but the kernel has already reloaded its own sysctl
        // policy. Values from an earlier boot must never be replayed into the new one.
        Ok(SysctlJournal::empty(boot_id.to_string()))
    }
}

fn persist(path: &Path, journal: &SysctlJournal) -> anyhow::Result<()> {
    validate(journal)?;
    if journal.entries.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(anyhow::anyhow!("cannot remove {}: {error}", path.display())),
        };
    }
    let bytes = serde_json::to_vec(journal)?;
    crate::util::write_atomic_private(path, &bytes)
}

fn read_value(path: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .map_err(|error| anyhow::anyhow!("cannot read {path}: {error}"))
}

fn write_value(path: &str, value: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{value}\n"))
        .map_err(|error| anyhow::anyhow!("cannot write {path}={value}: {error}"))?;
    let actual = read_value(path)?;
    if actual != value {
        anyhow::bail!("{path} remained {actual} after writing {value}");
    }
    Ok(())
}

/// Restore only while the kernel still contains our managed value. An administrator's
/// deliberate change made while qeli was active wins and is never overwritten.
fn restore_if_owned(path: &str, entry: &ManagedSysctl) -> anyhow::Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    let current = read_value(path)?;
    if current != entry.managed || current == entry.original {
        if current != entry.managed {
            log::warn!(
                "host networking: not restoring {path} to {} because it was changed externally to {current}",
                entry.original
            );
        }
        return Ok(());
    }
    write_value(path, &entry.original)
}

fn prune_dead_owners(journal: &mut SysctlJournal) {
    for entry in journal.entries.values_mut() {
        entry.owners.retain(|owner| owner_is_alive(owner));
    }
    let empty: Vec<String> = journal
        .entries
        .iter()
        .filter(|(_, entry)| entry.owners.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    for path in empty {
        let restored = journal
            .entries
            .get(&path)
            .is_some_and(|entry| restore_if_owned(&path, entry).is_ok());
        if restored {
            journal.entries.remove(&path);
        } else {
            log::warn!(
                "host networking: stale owner cleanup could not restore {path}; keeping it for retry"
            );
        }
    }
}

fn with_locked_journal<T>(
    body: impl FnOnce(&Path, &mut SysctlJournal) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let _local = IN_PROCESS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = journal_path();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("host sysctl journal has no parent"))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| anyhow::anyhow!("cannot create {}: {error}", parent.display()))?;
    let _file_lock = crate::util::FileLock::acquire(&path)?;
    let boot_id = current_boot_id()?;
    let mut journal = load(&path, &boot_id)?;
    prune_dead_owners(&mut journal);
    // Commit stale-owner recovery independently from the requested operation. In particular,
    // a failed acquire must never be retried implicitly and persisted as a live owner.
    persist(&path, &journal)?;
    body(&path, &mut journal)
}

pub fn acquire_checked(path: &str, value: &str, scope: &str) -> anyhow::Result<()> {
    with_locked_journal(|journal_path, journal| {
        if !valid_sysctl_path(path) || !valid_value(value) {
            anyhow::bail!("refusing unmanaged sysctl request {path}={value:?}");
        }
        let owner = owner_id(scope)?;
        let current = read_value(path)?;
        if let Some(entry) = journal.entries.get_mut(path) {
            if entry.managed != value {
                anyhow::bail!(
                    "{path} is already managed as {} by another qeli client",
                    entry.managed
                );
            }
            entry.owners.insert(owner.clone());
        } else {
            journal.entries.insert(
                path.to_string(),
                ManagedSysctl {
                    original: current.clone(),
                    managed: value.to_string(),
                    owners: BTreeSet::from([owner.clone()]),
                },
            );
        }
        // Persist the pristine value and owner BEFORE changing the kernel. A SIGKILL after
        // the write can then be recovered by the next qeli client operation.
        persist(journal_path, journal)?;
        if current != value {
            if let Err(error) = write_value(path, value) {
                // The owner was made durable before the kernel write. Remove this failed
                // acquisition, but retain an empty entry until the next recovery pass: a
                // write followed by a failed verification may already have changed the knob.
                if let Some(entry) = journal.entries.get_mut(path) {
                    entry.owners.remove(&owner);
                }
                persist(journal_path, journal)?;
                return Err(error);
            }
        }
        Ok(())
    })
}

pub fn acquire(path: &str, value: &str, scope: &str) -> bool {
    let result = acquire_checked(path, value, scope);
    if let Err(error) = result {
        log::warn!("host networking: could not acquire {path}={value}: {error}");
        false
    } else {
        true
    }
}

pub fn release_scope(scope: &str) -> anyhow::Result<()> {
    with_locked_journal(|journal_path, journal| {
        let owner = owner_id(scope)?;
        for entry in journal.entries.values_mut() {
            entry.owners.remove(&owner);
        }
        let empty: Vec<String> = journal
            .entries
            .iter()
            .filter(|(_, entry)| entry.owners.is_empty())
            .map(|(path, _)| path.clone())
            .collect();
        let mut failures = Vec::new();
        for path in empty {
            let restored = match journal.entries.get(&path) {
                Some(entry) => restore_if_owned(&path, entry),
                None => continue,
            };
            match restored {
                Ok(()) => {
                    journal.entries.remove(&path);
                }
                Err(error) => failures.push(format!("{path}: {error}")),
            }
        }
        persist(journal_path, journal)?;
        if failures.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "could not restore host sysctl value(s): {}",
                failures.join(", ")
            )
        }
    })
}

/// Prune owners left by killed qeli processes and restore entries that no live component owns.
/// Called at server-worker startup; ordinary acquire/release operations perform the same pass.
#[cfg(feature = "server")]
pub fn recover() -> anyhow::Result<()> {
    with_locked_journal(|_, _| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::{valid_scope, valid_sysctl_path};

    #[test]
    fn journal_accepts_only_router_knobs_and_safe_scopes() {
        assert!(valid_sysctl_path("/proc/sys/net/ipv4/ip_forward"));
        assert!(valid_sysctl_path("/proc/sys/net/ipv6/conf/all/forwarding"));
        assert!(valid_sysctl_path("/proc/sys/net/ipv6/conf/eth0/accept_ra"));
        assert!(!valid_sysctl_path("/proc/sys/kernel/core_pattern"));
        assert!(!valid_sysctl_path(
            "/proc/sys/net/ipv4/conf/../../ip_forward/rp_filter"
        ));
        assert!(valid_scope("qeli0"));
        assert!(!valid_scope("../qeli0"));
        assert!(!valid_scope("qeli:0"));
    }
}
