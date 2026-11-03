//! A journal group belongs to one network namespace and one PID coordinate system.
use super::host;

#[derive(Clone)]
pub(super) struct Context {
    pub network: String,
    pub cookie: Option<u64>,
    pub pid: String,
    pub time: Option<String>,
    // Capture before waiting for either journal lock and retain through final I/O.
    // Strings alone can be reused after the last namespace reference disappears.
    _pins: std::sync::Arc<Vec<host::NamespacePin>>,
}

impl PartialEq for Context {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network
            && self.cookie == other.cookie
            && self.pid == other.pid
            && self.time == other.time
    }
}
impl Eq for Context {}

pub(super) fn valid_identity(value: &str) -> bool {
    let Some((device, inode)) = value.split_once(':') else {
        return false;
    };
    match (device.parse::<u64>(), inode.parse::<u64>()) {
        (Ok(device), Ok(inode)) => inode != 0 && value == format!("{device}:{inode}"),
        _ => false,
    }
}

fn require_local_procfs(status: &str, process: u32) -> anyhow::Result<()> {
    // NStgid is ordered from the PID namespace of this procfs mount inward.
    // A single value equal to getpid proves that numeric /proc/<pid> lookups and
    // kill(pid, 0) use the same coordinate system. An inherited ancestor mount
    // can otherwise inspect or signal-probe an unrelated process with the same PID.
    let mut fields = status
        .lines()
        .filter_map(|line| line.strip_prefix("NStgid:"));
    let values: Vec<&str> = fields
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if fields.next().is_some()
        || values.len() != 1
        || values[0].parse::<u32>().ok() != Some(process)
        || process == 0
    {
        anyhow::bail!("host sysctl procfs PID namespace mismatch or unavailable NStgid; mount procfs for the current PID namespace");
    }
    Ok(())
}

pub(super) fn current() -> anyhow::Result<Context> {
    let status = host::read("/proc/self/status").map_err(|error| {
        anyhow::anyhow!("cannot verify host sysctl procfs PID namespace: {error}")
    })?;
    require_local_procfs(&status, std::process::id())?;
    // setns affects the calling thread, so /proc/self/ns/net is insufficient.
    let network_pin = host::pin_namespace("/proc/thread-self/ns/net")?;
    let network = network_pin.identity.clone();
    let cookie = host::network_cookie()?;
    let pid_pin = host::pin_namespace("/proc/thread-self/ns/pid")?;
    let pid = pid_pin.identity.clone();
    let mut pins = vec![network_pin, pid_pin];
    // Linux with no CONFIG_TIME_NS does not expose ns/time. Any other error is
    // uncertainty. A present/absent or changed identity never matches a saved group.
    let time = match host::pin_namespace("/proc/thread-self/ns/time") {
        Ok(pin) => {
            let identity = pin.identity.clone();
            pins.push(pin);
            Some(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if !valid_identity(&network)
        || !valid_identity(&pid)
        || time
            .as_ref()
            .is_some_and(|identity| !valid_identity(identity))
    {
        anyhow::bail!("invalid current host sysctl namespace identity");
    }
    Ok(Context {
        network,
        cookie,
        pid,
        time,
        _pins: std::sync::Arc::new(pins),
    })
}

/// A transaction becomes unusable after any observed context loss, even if a later
/// callback returns to the original namespace. Never persist a partly reinterpreted journal.
pub(super) struct Guard {
    expected: Context,
    failed: std::cell::Cell<bool>,
    scope: std::path::PathBuf,
}

impl Guard {
    pub(super) fn new(expected: Context) -> anyhow::Result<Self> {
        let guard = Self {
            expected,
            failed: std::cell::Cell::new(false),
            scope: std::path::PathBuf::new(),
        };
        guard.check()?;
        Ok(guard)
    }

    pub(super) fn with_journal_scope(mut self, scope: &std::path::Path) -> Self {
        self.scope = scope.to_owned();
        self
    }

    pub(super) fn scope(&self) -> &std::path::Path {
        &self.scope
    }

    pub(super) fn context(&self) -> &Context {
        &self.expected
    }

    pub(super) fn check(&self) -> anyhow::Result<()> {
        if self.failed.get() {
            anyhow::bail!("host sysctl transaction lost its namespace context; keep the journal and retry from the original namespaces");
        }
        let result = current().and_then(|actual| {
            if actual == self.expected {
                Ok(())
            } else {
                anyhow::bail!("host sysctl namespace changed during the journal transaction")
            }
        });
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    pub(super) fn io<T>(
        &self,
        operation: impl FnOnce() -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let check = || {
            self.check()
                .map_err(|error| std::io::Error::other(error.to_string()))
        };
        check()?;
        let result = operation();
        // A failed read can coincide with a namespace change. Context loss takes
        // precedence over NotFound, which otherwise authorizes owner/interface removal.
        check()?;
        result
    }
}
