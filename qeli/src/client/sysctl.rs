//! Cross-process ownership for Linux host-networking sysctls.
//!
//! Server profiles, standalone clients, and panel-managed outbound client processes may all
//! use the same host-wide forwarding knobs. A process-local "prior value" snapshot lets the
//! first component that stops restore a value still required by another one. The journal
//! below is locked across processes, records the pristine value before mutation, and
//! identifies an owner by PID + `/proc/<pid>/stat` start time + TUN scope so PID reuse and
//! same-process multi-profile operation are both handled. Network namespaces have separate
//! journal groups; each group requires the same PID namespace/procfs view. The journal follows the state
//! directory's ownership, so a manual root client cannot lock a later User=qeli service out.
//! Per-interface v3 entries additionally require a live held sysctl descriptor.
//! Loss of all live evidence retains the original for manual recovery instead of
//! applying a saved value to a potentially renamed or replaced interface.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[path = "sysctl/host.rs"]
mod host;
use crate::state_storage::{journal_file, state_dir};
#[path = "sysctl/namespace.rs"]
mod namespace;
#[path = "sysctl/target.rs"]
mod target;

const JOURNAL_VERSION: u8 = 4;
const JOURNAL_LIMIT: u64 = 128 * 1024;
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const JOURNAL_NAME: &str = "sysctls.state";

static IN_PROCESS_LOCK: Mutex<()> = Mutex::new(());
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

fn wait_local_lock(
    lock: &Mutex<()>,
    deadline: std::time::Instant,
) -> anyhow::Result<std::sync::MutexGuard<'_, ()>> {
    loop {
        match lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    anyhow::bail!("timed out waiting for the in-process host sysctl journal lock");
                }
                std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ManagedSysctl {
    original: String,
    managed: String,
    owners: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<target::Identity>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SysctlJournal {
    #[serde(default)]
    network_cookie: Option<u64>,
    pid_namespace: String,
    time_namespace: Option<String>,
    entries: BTreeMap<String, ManagedSysctl>,
}

impl SysctlJournal {
    fn empty(pid_namespace: String) -> Self {
        Self {
            network_cookie: None,
            pid_namespace,
            time_namespace: None,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalStore {
    version: u8,
    boot_id: String,
    namespaces: BTreeMap<String, SysctlJournal>,
}
impl JournalStore {
    fn empty(boot_id: String) -> Self {
        Self {
            version: JOURNAL_VERSION,
            boot_id,
            namespaces: BTreeMap::new(),
        }
    }

    fn select(&mut self, context: &namespace::Context) -> anyhow::Result<&mut SysctlJournal> {
        let journal = self
            .namespaces
            .entry(context.network.clone())
            .or_insert_with(|| {
                let mut journal = SysctlJournal::empty(context.pid.clone());
                journal.time_namespace = context.time.clone();
                journal.network_cookie = context.cookie;
                journal
            });
        if journal.network_cookie != context.cookie
            || (!journal.entries.is_empty() && context.cookie.is_none())
        {
            anyhow::bail!("host sysctl network namespace generation mismatch or unavailable SO_NETNS_COOKIE; keep sysctls.state and recover from the original namespace");
        }
        if journal.pid_namespace != context.pid {
            anyhow::bail!(
                "host sysctl PID namespace mismatch for network namespace {}: saved {}, current {}; keep sysctls.state and recover from the original PID namespace",
                context.network, journal.pid_namespace, context.pid
            );
        }
        if journal.time_namespace != context.time {
            anyhow::bail!(
                "host sysctl time namespace mismatch for network namespace {}; keep sysctls.state and recover from the original time namespace",
                context.network
            );
        }
        Ok(journal)
    }
}

struct JournalTransaction<'a> {
    path: &'a Path,
    store: JournalStore,
    network: String,
    context: namespace::Guard,
}
impl JournalTransaction<'_> {
    fn current(&self) -> &SysctlJournal {
        &self.store.namespaces[&self.network]
    }
    fn current_mut(&mut self) -> &mut SysctlJournal {
        self.store
            .namespaces
            .get_mut(&self.network)
            .expect("selected sysctl namespace")
    }
    fn persist(&self) -> anyhow::Result<()> {
        self.context.check()?;
        let result = persist(self.path, &self.store);
        self.context.check()?;
        result?;
        retain_targets(&self.store, self.context.scope());
        Ok(())
    }
}

fn journal_path() -> PathBuf {
    crate::state_storage::default_state_dir().join(JOURNAL_NAME)
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

fn process_start_time(pid: u32, context: &namespace::Guard) -> std::io::Result<String> {
    let path = format!("/proc/{pid}/stat");
    let stat = context.io(|| host::read(&path))?;
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path} contains an invalid process identity"),
        )
    };
    let (reported_pid, command) = stat.split_once(" (").ok_or_else(invalid)?;
    if reported_pid.parse::<u32>().ok() != Some(pid) || !command.contains(')') {
        return Err(invalid());
    }
    // `comm` is parenthesized and may itself contain spaces or `)`, so split after the last
    // closing parenthesis. The remaining fields start at field 3; starttime is field 22.
    let close = stat.rfind(')').ok_or_else(invalid)?;
    let start = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(invalid)?;
    if start.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || start.parse::<u64>().is_err()
    {
        return Err(invalid());
    }
    Ok(start.to_string())
}

fn owner_id(scope: &str, context: &namespace::Guard) -> anyhow::Result<String> {
    if !valid_scope(scope) {
        anyhow::bail!("invalid sysctl owner scope {scope:?}");
    }
    let pid = std::process::id();
    Ok(format!(
        "{pid}:{}:{scope}",
        process_start_time(pid, context)?
    ))
}

fn parse_owner(owner: &str) -> Option<(u32, &str)> {
    let mut parts = owner.splitn(3, ':');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let start = parts.next()?;
    if pid == 0
        || pid > i32::MAX as u32
        || start.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || start.parse::<u64>().is_err()
        || !parts.next().is_some_and(valid_scope)
    {
        return None;
    }
    Some((pid, start))
}

/// Only a different observed generation or confirmed process absence proves death.
/// NotFound alone can also mean an invisible process under procfs restrictions.
fn owner_is_alive(owner: &str, context: &namespace::Guard) -> anyhow::Result<bool> {
    let (pid, expected) = parse_owner(owner)
        .ok_or_else(|| anyhow::anyhow!("invalid sysctl owner identity {owner:?}"))?;
    match process_start_time(pid, context) {
        Ok(actual) => Ok(actual == expected),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !context.io(|| host::process_exists(pid))? {
                Ok(false)
            } else {
                anyhow::bail!("PID {pid} exists but its start time cannot be inspected");
            }
        }
        Err(error) => Err(anyhow::anyhow!(
            "cannot inspect PID {pid} start time: {error}"
        )),
    }
}

fn require_known_owners(uncertain: &[String]) -> anyhow::Result<()> {
    if !uncertain.is_empty() {
        anyhow::bail!(
            "cannot verify host sysctl owner(s): {}",
            uncertain.join("; ")
        );
    }
    Ok(())
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

fn per_interface(path: &str) -> bool {
    let fields: Vec<_> = path
        .strip_prefix("/proc/sys/net/")
        .unwrap_or_default()
        .split('/')
        .collect();
    matches!(fields.as_slice(), [_, "conf", interface, _] if !["all", "default"].contains(interface))
}

fn retain_targets(store: &JournalStore, scope: &Path) {
    target::retain(
        scope,
        store
            .namespaces
            .values()
            .flat_map(|j| j.entries.values())
            .filter_map(|entry| entry.target.as_ref().map(target::Identity::lease))
            .collect(),
    );
}

fn valid_value(value: &str) -> bool {
    matches!(value, "0" | "1" | "2")
}

fn valid_boot_id(boot_id: &str) -> bool {
    !boot_id.is_empty() && boot_id.len() <= 128 && !boot_id.chars().any(char::is_control)
}

fn validate_entries(entries: &BTreeMap<String, ManagedSysctl>) -> anyhow::Result<()> {
    if entries.len() > 256 {
        anyhow::bail!("too many host sysctl journal entries");
    }
    for (path, entry) in entries {
        if !valid_sysctl_path(path)
            || !valid_value(&entry.original)
            || !valid_value(&entry.managed)
            || entry.target.as_ref().is_some_and(|target| !target.valid())
            || entry.owners.len() > 256
            || entry
                .owners
                .iter()
                .any(|owner| parse_owner(owner).is_none())
        {
            anyhow::bail!("invalid host sysctl journal entry for {path:?}");
        }
    }
    Ok(())
}

fn validate(journal: &SysctlJournal) -> anyhow::Result<()> {
    if !namespace::valid_identity(&journal.pid_namespace) {
        anyhow::bail!("invalid host sysctl PID namespace identity");
    }
    if journal
        .time_namespace
        .as_ref()
        .is_some_and(|identity| !namespace::valid_identity(identity))
    {
        anyhow::bail!("invalid host sysctl time namespace identity");
    }
    validate_entries(&journal.entries)
}

fn validate_store(store: &JournalStore) -> anyhow::Result<()> {
    validate_store_schema(store, true)
}
fn validate_store_schema(store: &JournalStore, require_cookie: bool) -> anyhow::Result<()> {
    if store.version != JOURNAL_VERSION
        || !valid_boot_id(&store.boot_id)
        || store.namespaces.len() > 256
        || store
            .namespaces
            .values()
            .map(|journal| journal.entries.len())
            .sum::<usize>()
            > 256
    {
        anyhow::bail!("invalid host sysctl journal header");
    }
    let mut leases = BTreeSet::new();
    for (network, journal) in &store.namespaces {
        if !namespace::valid_identity(network) {
            anyhow::bail!("invalid host sysctl network namespace identity");
        }
        validate(journal)?;
        if journal.network_cookie == Some(0)
            || (require_cookie && !journal.entries.is_empty() && journal.network_cookie.is_none())
        {
            anyhow::bail!("host sysctl journal lacks a valid network namespace generation");
        }
        for (path, entry) in &journal.entries {
            if let Some(target) = &entry.target {
                if !leases.insert(target.lease()) {
                    anyhow::bail!("duplicate per-interface sysctl lease identity");
                }
            }
            if per_interface(path) != entry.target.is_some() {
                anyhow::bail!("missing or misplaced per-interface sysctl identity for {path}");
            }
        }
    }
    Ok(())
}

fn decode_store(bytes: &[u8], boot_id: &str) -> anyhow::Result<JournalStore> {
    #[derive(serde::Deserialize)]
    struct Header {
        version: u8,
    }
    let header: Header = serde_json::from_slice(bytes)?;
    if header.version == 1 {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LegacyJournal {
            version: u8,
            boot_id: String,
            entries: BTreeMap<String, ManagedSysctl>,
        }
        let old: LegacyJournal = serde_json::from_slice(bytes)?;
        if old.version != 1 || !valid_boot_id(&old.boot_id) {
            anyhow::bail!("invalid legacy host sysctl journal header");
        }
        validate_entries(&old.entries)?;
        if old.boot_id == boot_id && !old.entries.is_empty() {
            // Even a dead/ownerless legacy entry has no provable network namespace.
            // Never guess a namespace or lose its saved original value on upgrade.
            anyhow::bail!("legacy host sysctl journal has no namespace identity; keep sysctls.state and complete recovery with the previous version in its original namespaces before upgrading");
        }
        return Ok(JournalStore::empty(boot_id.to_string()));
    }
    if header.version == 2 {
        let old: JournalStore = serde_json::from_slice(bytes)?;
        if !valid_boot_id(&old.boot_id)
            || old.namespaces.len() > 256
            || old
                .namespaces
                .values()
                .map(|j| j.entries.len())
                .sum::<usize>()
                > 256
        {
            anyhow::bail!("invalid legacy host sysctl journal header");
        }
        for (network, journal) in &old.namespaces {
            if !namespace::valid_identity(network) {
                anyhow::bail!("invalid legacy host sysctl network namespace identity");
            }
            validate(journal)?;
        }
        if old.boot_id == boot_id && old.namespaces.values().any(|j| !j.entries.is_empty()) {
            anyhow::bail!("legacy v2 host sysctl journal lacks live descriptor ownership; keep sysctls.state and complete recovery before upgrading, or perform a planned host reboot");
        }
        return Ok(JournalStore::empty(boot_id.to_owned()));
    }
    if header.version == 3 {
        let mut old: JournalStore = serde_json::from_slice(bytes)?;
        old.version = JOURNAL_VERSION;
        validate_store_schema(&old, false)?;
        if old.boot_id == boot_id && old.namespaces.values().any(|j| !j.entries.is_empty()) {
            anyhow::bail!("legacy v3 host sysctl journal lacks durable namespace generation; keep sysctls.state and complete recovery before upgrading, or perform a planned host reboot");
        }
        return Ok(JournalStore::empty(boot_id.to_owned()));
    }
    if header.version != JOURNAL_VERSION {
        anyhow::bail!("unsupported host sysctl journal version {}", header.version);
    }
    let store: JournalStore = serde_json::from_slice(bytes)?;
    validate_store(&store)?;
    if store.boot_id == boot_id {
        Ok(store)
    } else {
        // A new boot has reloaded kernel policy; never replay an earlier boot's values.
        Ok(JournalStore::empty(boot_id.to_string()))
    }
}

fn load(path: &Path, boot_id: &str) -> anyhow::Result<JournalStore> {
    let opened = journal_file::Opened::open(path, JOURNAL_LIMIT)
        .map_err(|error| anyhow::anyhow!("cannot open {}: {error}", path.display()))?;
    let Some(opened) = opened else {
        return Ok(JournalStore::empty(boot_id.to_string()));
    };
    let bytes = opened
        .read()
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
    decode_store(&bytes, boot_id)
        .map_err(|error| anyhow::anyhow!("cannot load {}: {error}", path.display()))
}

fn persist(path: &Path, store: &JournalStore) -> anyhow::Result<()> {
    validate_store(store)?;
    // The selected empty group remains available to the transaction's acquire body,
    // but must not reserve a PID namespace on disk after its final lease is gone.
    let mut snapshot = store.clone();
    snapshot
        .namespaces
        .retain(|_, journal| !journal.entries.is_empty());
    if snapshot.namespaces.is_empty() {
        return crate::util::remove_file_synced(path)
            .map_err(|error| anyhow::anyhow!("cannot remove {}: {error}", path.display()));
    }
    let bytes = serde_json::to_vec(&snapshot)?;
    if bytes.len() as u64 > JOURNAL_LIMIT {
        anyhow::bail!("host sysctl journal exceeds its size limit");
    }
    crate::util::write_atomic_private(path, &bytes)
}

fn read_target_value(
    path: &str,
    target: Option<&target::Pin>,
    context: &namespace::Guard,
) -> std::io::Result<String> {
    let value = match target {
        Some(pin) => pin.read(context)?,
        None => context.io(|| host::read(path))?,
    }
    .trim()
    .to_string();
    if !valid_value(&value) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path} contains an invalid sysctl value"),
        ));
    }
    Ok(value)
}

fn write_value(
    path: &str,
    value: &str,
    target: Option<&target::Pin>,
    context: &namespace::Guard,
) -> anyhow::Result<()> {
    let bytes = format!("{value}\n");
    match target {
        Some(pin) => pin.write(&bytes, context),
        None => context.io(|| host::write(path, &bytes)),
    }
    .map_err(|error| anyhow::anyhow!("cannot write {path}={value}: {error}"))?;
    let actual = read_target_value(path, target, context)?;
    if actual != value {
        anyhow::bail!("{path} remained {actual} after writing {value}");
    }
    Ok(())
}

/// Restore only while the kernel still contains our managed value. An administrator's
/// deliberate change made while qeli was active wins and is never overwritten.
fn restore_if_owned(
    path: &str,
    entry: &ManagedSysctl,
    context: &namespace::Guard,
) -> anyhow::Result<()> {
    // If we never changed this value, no write or interface lookup is needed.
    if entry.original == entry.managed {
        return Ok(());
    }
    let target = if per_interface(path) {
        Some(target::resolve(path, entry.target.as_ref(), context, None)?)
    } else {
        None
    };
    // ENOENT from a held descriptor can mean a rename/unregistered sysctl table,
    // not just deletion. Preserve evidence rather than forgetting the original.
    let current = read_target_value(path, target.as_deref(), context)
        .map_err(|error| anyhow::anyhow!("cannot inspect saved sysctl {path}: {error}"))?;
    if current != entry.managed || current == entry.original {
        if current != entry.managed {
            log::warn!(
                "host networking: not restoring {path} to {} because it was changed externally to {current}",
                entry.original
            );
        }
        return Ok(());
    }
    write_value(path, &entry.original, target.as_deref(), context)
}

fn prune_dead_owners(journal: &mut SysctlJournal, context: &namespace::Guard) -> Vec<String> {
    let mut uncertain = Vec::new();
    for (path, entry) in &mut journal.entries {
        entry
            .owners
            .retain(|owner| match owner_is_alive(owner, context) {
                Ok(alive) => alive,
                Err(error) => {
                    let message = format!("{path}, owner {owner}: {error}");
                    log::warn!("host networking: retaining unverified owner: {message}");
                    uncertain.push(message);
                    true
                }
            });
    }
    let empty: Vec<String> = journal
        .entries
        .iter()
        .filter(|(_, entry)| entry.owners.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    for path in empty {
        match restore_if_owned(&path, &journal.entries[&path], context) {
            Ok(()) => { journal.entries.remove(&path); }
            Err(error) => log::warn!(
                "host networking: stale owner cleanup could not restore {path}: {error}; keeping it for retry"
            ),
        }
    }
    uncertain
}

fn with_locked_journal<T>(
    body: impl FnOnce(&mut JournalTransaction<'_>, Vec<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    let context = namespace::current()?;
    let _local = wait_local_lock(&IN_PROCESS_LOCK, deadline)?;
    let requested = journal_path();
    let parent = requested
        .parent()
        .ok_or_else(|| anyhow::anyhow!("host sysctl journal has no parent"))?;
    let directory = state_dir::Directory::open(parent).map_err(|error| {
        anyhow::anyhow!(
            "unsafe sysctl state directory {}: {error}",
            parent.display()
        )
    })?;
    // Every sidecar, snapshot, temporary file and rename is now relative to the
    // same held directory, even if the original pathname is moved or replaced.
    let path = directory.journal_path(JOURNAL_NAME)?;
    let _file_lock = crate::util::FileLock::acquire_timeout_owned(
        &path,
        deadline.saturating_duration_since(std::time::Instant::now()),
        directory.owner(),
    )?;
    directory.verify()?;
    let boot_id = current_boot_id()?;
    let result = with_journal_scope(&path, &requested, &boot_id, context, body);
    directory.verify()?;
    result
}

// Kept below the lock boundary so portable tests can exercise real journal I/O
// with isolated namespace/sysctl observations, without pretending to test flock.
#[cfg(test)]
fn with_journal<T>(
    path: &Path,
    boot_id: &str,
    body: impl FnOnce(&mut JournalTransaction<'_>, Vec<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    with_journal_context(path, boot_id, namespace::current()?, body)
}

#[cfg(test)]
fn with_journal_context<T>(
    path: &Path,
    boot_id: &str,
    context: namespace::Context,
    body: impl FnOnce(&mut JournalTransaction<'_>, Vec<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    with_journal_scope(path, path, boot_id, context, body)
}

fn with_journal_scope<T>(
    path: &Path,
    scope: &Path,
    boot_id: &str,
    context: namespace::Context,
    body: impl FnOnce(&mut JournalTransaction<'_>, Vec<String>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    if namespace::current()? != context {
        anyhow::bail!(
            "host sysctl namespace changed while waiting for journal locks; no recovery attempted"
        );
    }
    let guard = namespace::Guard::new(context)?.with_journal_scope(scope);
    let mut store = load(path, boot_id)?;
    guard.check()?;
    retain_targets(&store, scope);
    // Admission precedes pruning, kernel I/O and persistence. Foreign groups are
    // never probed: their PIDs and sysctl paths have meaning only in their namespace.
    store.select(guard.context())?;
    let mut transaction = JournalTransaction {
        path,
        store,
        network: guard.context().network.clone(),
        context: guard,
    };
    let uncertain = prune_dead_owners(
        transaction
            .store
            .namespaces
            .get_mut(&transaction.network)
            .expect("selected sysctl namespace"),
        &transaction.context,
    );
    transaction.persist()?;
    body(&mut transaction, uncertain)
}

pub fn acquire_checked(path: &str, value: &str, scope: &str) -> anyhow::Result<()> {
    with_locked_journal(|transaction, uncertain| {
        acquire_in(transaction, &uncertain, path, value, scope)
    })
}

fn acquire_in(
    transaction: &mut JournalTransaction<'_>,
    uncertain: &[String],
    path: &str,
    value: &str,
    scope: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        transaction.context.context().cookie.is_some(),
        "SO_NETNS_COOKIE is required for managed host sysctls; no sysctl was changed"
    );

    require_known_owners(uncertain)?;
    if !valid_sysctl_path(path) || !valid_value(value) {
        anyhow::bail!("refusing unmanaged sysctl request {path}={value:?}");
    }
    let owner = owner_id(scope, &transaction.context)?;
    let existing = transaction.current().entries.get(path).cloned();
    let (target_identity, target) = if per_interface(path) {
        if let Some(entry) = existing.as_ref() {
            let live_witness = || {
                for witness in &entry.owners {
                    if owner_is_alive(witness, &transaction.context)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            };
            let pin = target::resolve(
                path,
                entry.target.as_ref(),
                &transaction.context,
                Some(&live_witness),
            )?;
            (entry.target.clone(), Some(pin))
        } else {
            let (identity, pin) = target::capture(path, &transaction.context)?;
            (Some(identity), Some(pin))
        }
    } else {
        (None, None)
    };
    let current = read_target_value(path, target.as_deref(), &transaction.context)?;
    let journal = transaction.current_mut();
    let new_owner = if let Some(entry) = journal.entries.get_mut(path) {
        if entry.managed != value {
            anyhow::bail!(
                "{path} is already managed as {} by another qeli client",
                entry.managed
            );
        }
        entry.owners.insert(owner.clone())
    } else {
        journal.entries.insert(
            path.to_string(),
            ManagedSysctl {
                original: current.clone(),
                managed: value.to_string(),
                owners: BTreeSet::from([owner.clone()]),
                target: target_identity,
            },
        );
        true
    };
    // Persist the pristine value and owner BEFORE changing the kernel. A SIGKILL
    // retains recovery evidence. Per-interface replay additionally needs a live
    // descriptor witness; after the last witness dies it requires manual recovery.
    transaction.persist()?;
    if current != value {
        if let Err(error) = write_value(path, value, target.as_deref(), &transaction.context) {
            // Undo only ownership added by this call. A failed idempotent reacquire
            // must not discard an earlier successful lease of the same live component.
            // Retain empty entries: write verification may fail after changing the knob.
            if new_owner {
                transaction
                    .current_mut()
                    .entries
                    .get_mut(path)
                    .expect("acquired sysctl entry")
                    .owners
                    .remove(&owner);
            }
            transaction.persist()?;
            return Err(error);
        }
    }
    Ok(())
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

fn release_owner(
    journal: &mut SysctlJournal,
    owner: &str,
    mut failures: Vec<String>,
    context: &namespace::Guard,
) -> Vec<String> {
    for entry in journal.entries.values_mut() {
        entry.owners.remove(owner);
    }
    let empty: Vec<String> = journal
        .entries
        .iter()
        .filter(|(_, entry)| entry.owners.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    for path in empty {
        match restore_if_owned(&path, &journal.entries[&path], context) {
            Ok(()) => {
                journal.entries.remove(&path);
            }
            Err(error) => failures.push(format!("{path}: {error}")),
        }
    }
    failures
}

pub fn release_scope(scope: &str) -> anyhow::Result<()> {
    with_locked_journal(|transaction, uncertain| release_in(transaction, uncertain, scope))
}

fn release_in(
    transaction: &mut JournalTransaction<'_>,
    uncertain: Vec<String>,
    scope: &str,
) -> anyhow::Result<()> {
    let owner = owner_id(scope, &transaction.context)?;
    // Release our known identity even when another owner is uninspectable.
    // Its records remain, unrelated cleanup continues, and uncertainty is reported.
    let failures = release_owner(
        transaction
            .store
            .namespaces
            .get_mut(&transaction.network)
            .expect("selected sysctl namespace"),
        &owner,
        uncertain,
        &transaction.context,
    );
    transaction.persist()?;
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "could not restore host sysctl value(s): {}",
            failures.join(", ")
        );
    }
}

/// Prune owners left by killed qeli processes and restore entries that no live component owns.
/// Called at server-worker startup; ordinary acquire/release operations perform the same pass.
#[cfg(feature = "server")]
pub fn recover() -> anyhow::Result<()> {
    with_locked_journal(recover_in)
}

#[cfg(any(test, feature = "server"))]
fn recover_in(
    transaction: &mut JournalTransaction<'_>,
    uncertain: Vec<String>,
) -> anyhow::Result<()> {
    require_known_owners(&uncertain)?;
    // The locked pre-pass already attempted every stale entry and persisted any
    // failures for retry. Live owners are expected; ownerless entries are not success.
    let unresolved: Vec<&str> = transaction
        .current()
        .entries
        .iter()
        .filter(|(_, entry)| entry.owners.is_empty())
        .map(|(path, _)| path.as_str())
        .collect();
    if !unresolved.is_empty() {
        anyhow::bail!(
            "could not restore stale host sysctl value(s): {}",
            unresolved.join(", ")
        );
    }
    Ok(())
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

#[cfg(test)]
#[path = "sysctl/ownership_tests.rs"]
mod ownership_tests;

#[cfg(test)]
#[path = "sysctl/namespace_tests.rs"]
mod namespace_tests;

#[cfg(test)]
#[path = "sysctl/target_tests.rs"]
mod target_tests;
