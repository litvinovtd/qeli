//! Outbound client tunnels driven by the web panel: this box can dial OUT to other
//! qeli servers (a "client" role alongside, or instead of, the server role).
//!
//! Profiles are stored as `/etc/qeli/clients/<name>.conf` — the same flat-INI a
//! `qeli://` link expands into. Connecting spawns `qeli client -c <file>` as a child
//! process (it inherits the supervisor's `CAP_NET_ADMIN`, so it can bring up its TUN
//! and routes); disconnecting sends it SIGTERM so it restores DNS/routes and exits.
//! Each tunnel's stdout/stderr is captured to `/var/log/qeli/client-<name>.log` for
//! the panel's status view. `kill_on_drop` is a safety net if the supervisor dies.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const CLIENTS_DIR: &str = "/etc/qeli/clients";

/// Per-process handle for a running tunnel.
pub struct ClientManager {
    /// profile name -> running child. Absent = not connected.
    running: Mutex<HashMap<String, Arc<Mutex<Child>>>>,
    /// Closes admission and preserves the first shutdown deadline across cancelled waiters.
    shutdown_deadline: std::sync::OnceLock<tokio::time::Instant>,
    shutdown_failures: std::sync::Mutex<crate::server_shutdown::Failures>,
    shutdown_waiter: Mutex<()>,
}

impl Default for ClientManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientManager {
    pub fn new() -> Self {
        ClientManager {
            running: Mutex::new(HashMap::new()),
            shutdown_deadline: std::sync::OnceLock::new(),
            shutdown_failures: std::sync::Mutex::new(Default::default()),
            shutdown_waiter: Mutex::new(()),
        }
    }

    /// Validate a profile name: a single path segment of `[A-Za-z0-9._-]`, so it
    /// can't escape CLIENTS_DIR or inject shell/path tricks.
    pub fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 64
            && name != "."
            && name != ".."
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    }

    pub fn profile_path(name: &str) -> String {
        format!("{CLIENTS_DIR}/{name}.conf")
    }

    pub fn log_path(name: &str) -> String {
        format!("/var/log/qeli/client-{name}.log")
    }

    /// Private machine-readable diagnostics written by the spawned client. Keep the file
    /// beside the configured control socket so a non-root/custom-runtime installation uses
    /// one writable runtime directory for all panel IPC instead of falling back to /var/run.
    pub fn status_path(name: &str) -> String {
        let control = crate::server::control::control_socket_path();
        let dir = std::path::Path::new(&control)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/var/run/qeli"));
        dir.join(format!("client-{name}.status.json"))
            .to_string_lossy()
            .to_string()
    }

    /// Names of all stored client profiles (files in CLIENTS_DIR ending in `.conf`).
    pub fn list_profiles() -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(CLIENTS_DIR) {
            for e in rd.flatten() {
                if let Some(n) = e.file_name().to_str().and_then(|f| f.strip_suffix(".conf")) {
                    if Self::valid_name(n) {
                        out.push(n.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Does this profile carry `autostart = true` in its `[qeli]` section? Reads the
    /// file fresh (the panel rewrites it on every save), so it reflects the on-disk
    /// truth — a hand-edited file works exactly the same as a panel toggle.
    pub fn profile_autostarts(name: &str) -> bool {
        Self::profile_autostarts_file(std::path::Path::new(&Self::profile_path(name)))
    }

    fn profile_autostarts_file(path: &std::path::Path) -> bool {
        crate::config_source::load_bounded(path, crate::transport_core::MAX_CONFIG_BYTES as u64)
            .ok()
            .map(|snapshot| snapshot.into_parts().0)
            .and_then(|s| crate::config::parse_client_config_strict(&s).ok())
            .map(|c| c.autostart)
            .unwrap_or(false)
    }

    /// Names of profiles flagged for autostart.
    pub fn autostart_names() -> Vec<String> {
        Self::list_profiles()
            .into_iter()
            .filter(|n| Self::profile_autostarts(n))
            .collect()
    }

    /// Connect every autostart-flagged profile (best-effort) — called once the
    /// supervisor is up. A client tunnel dials a REMOTE server, so it doesn't depend
    /// on the local server profiles being up; failures are logged, not fatal.
    pub async fn start_autostart(&self) {
        for name in Self::autostart_names() {
            match self.connect(&name).await {
                Ok(()) => log::info!("autostart: client tunnel '{name}' connecting"),
                Err(e) => log::warn!("autostart: client tunnel '{name}' failed: {e}"),
            }
        }
    }

    /// Is this profile's tunnel currently up? (Reaps the child if it has exited.)
    pub async fn is_running(&self, name: &str) -> bool {
        let mut map = self.running.lock().await;
        match map.get_mut(name) {
            Some(child) => match child.try_lock().map(|mut child| child.try_wait()) {
                Ok(Ok(Some(_))) => {
                    map.remove(name); // exited — drop the dead handle
                    false
                }
                Ok(Ok(None)) => true, // still running
                _ => true,
            },
            None => false,
        }
    }

    /// Bring up the tunnel for `name`. No-op if already connected.
    pub async fn connect(&self, name: &str) -> anyhow::Result<()> {
        self.check_admission()?;
        if !Self::valid_name(name) {
            anyhow::bail!("invalid client profile name");
        }
        let path = Self::profile_path(name);
        if !std::path::Path::new(&path).exists() {
            anyhow::bail!("client profile '{name}' does not exist");
        }
        // Hold the running lock across the "already up?" check AND the insert below, so two
        // concurrent connect() calls (panel + autostart, or a double-click) can't both see
        // "not running" and spawn two `qeli client` processes fighting over the same TUN.
        let mut running = self.running.lock().await;
        self.check_admission()?;
        if let Some(child) = running.get_mut(name) {
            match child.try_lock().map(|mut child| child.try_wait()) {
                Ok(Ok(Some(_))) => {
                    running.remove(name); // exited — respawn below
                }
                _ => return Ok(()), // still running (or unknown) — no-op
            }
        }
        let exe = std::env::current_exe()
            .map_err(|e| anyhow::anyhow!("cannot resolve current_exe: {e}"))?;
        let log = Self::log_path(name);
        // Ensure the log directory exists — the server may log to journald/stderr and
        // never create /var/log/qeli, in which case opening the client log (and thus
        // starting the tunnel) failed with "No such file or directory" and the panel
        // showed neither a connection nor a log.
        if let Some(dir) = std::path::Path::new(&log).parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("cannot create client log dir {}: {e}", dir.display())
            })?;
        }
        // APPEND, not truncate. Truncating destroyed the evidence at the worst possible
        // moment: a tunnel dies, the operator opens the panel and presses "Connect", and
        // the log explaining WHY it died is wiped before it can be read. Keeping history
        // costs a bounded amount of disk — trim from the front when the file has grown
        // past the cap, so an old log cannot fill the partition either.
        // (Audit 2026-07-27, S5.)
        const CLIENT_LOG_MAX_BYTES: u64 = 4 * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(&log) {
            if meta.len() > CLIENT_LOG_MAX_BYTES {
                // Keep the most recent half; a client log is read tail-first anyway.
                if let Ok(existing) = std::fs::read(&log) {
                    let keep_from = existing.len().saturating_sub(existing.len() / 2);
                    // Resume at a line boundary so the first retained line isn't a fragment.
                    let cut = existing[keep_from..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map(|i| keep_from + i + 1)
                        .unwrap_or(keep_from);
                    let _ = std::fs::write(&log, &existing[cut..]);
                }
            }
        }
        let logfile = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .map_err(|e| anyhow::anyhow!("cannot open client log {log}: {e}"))?;
        let errfile = logfile
            .try_clone()
            .map_err(|e| anyhow::anyhow!("cannot dup client log fd: {e}"))?;
        // Never attribute the previous process's negotiated plan to a fresh attempt. The new
        // child publishes `created` immediately after strict config parsing succeeds.
        let status = Self::status_path(name);
        match std::fs::remove_file(&status) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!(
                "cannot remove stale client status {} before starting '{}': {}",
                status,
                name,
                error
            ),
        }
        let child = Command::new(&exe)
            .arg("client")
            .arg("-c")
            .arg(&path)
            // Logs remain the human audit trail; this bounded sidecar is the stable contract
            // consumed by the panel. It contains no credentials or transport keys.
            .env("QELI_CLIENT_STATUS", Self::status_path(name))
            .env("QELI_CLIENT_PROFILE", name)
            .stdin(Stdio::null())
            .stdout(Stdio::from(logfile))
            .stderr(Stdio::from(errfile))
            .kill_on_drop(true) // safety net: don't orphan the tunnel if we drop
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start client '{name}': {e}"))?;
        log::info!("Client tunnel '{name}' started (pid {:?})", child.id());
        running.insert(name.to_string(), Arc::new(Mutex::new(child)));
        Ok(())
    }

    fn check_admission(&self) -> anyhow::Result<()> {
        if self.shutdown_deadline.get().is_some() {
            anyhow::bail!("client manager is shutting down; new tunnels are not admitted");
        }
        Ok(())
    }

    /// Keep the original Child in the registry through wait and cancellation. A concurrent
    /// Connect cannot replace a tunnel whose DNS/routes may still be undergoing cleanup.
    pub async fn disconnect(&self, name: &str) -> anyhow::Result<()> {
        let deadline = self
            .shutdown_deadline
            .get()
            .copied()
            .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_secs(5));
        let Some(owned) = self.running.lock().await.get(name).cloned() else {
            return Ok(());
        };
        let mut child = owned.lock().await;
        let result = stop_client(name, &mut child, deadline).await;
        if child.id().is_none() {
            let mut running = self.running.lock().await;
            if running
                .get(name)
                .is_some_and(|current| Arc::ptr_eq(current, &owned))
            {
                running.remove(name);
            }
        }
        result
    }

    /// Signal every owned tunnel, sharing one grace period including registry admission.
    /// Cancelled waiters keep the Child handles and original deadline for a later retry.
    pub async fn shutdown_all(&self) -> anyhow::Result<()> {
        self.shutdown_with_grace(std::time::Duration::from_secs(5))
            .await
    }

    /// Close Connect/autostart immediately when the supervisor begins stopping its worker.
    /// This is synchronous so admission cannot remain open while that child is awaited.
    pub(crate) fn request_shutdown(&self) {
        self.request_shutdown_with_grace(std::time::Duration::from_secs(5));
    }

    fn request_shutdown_with_grace(&self, grace: std::time::Duration) -> tokio::time::Instant {
        *self
            .shutdown_deadline
            .get_or_init(|| tokio::time::Instant::now() + grace)
    }

    async fn shutdown_with_grace(&self, grace: std::time::Duration) -> anyhow::Result<()> {
        let deadline = self.request_shutdown_with_grace(grace);
        let _waiter = self.shutdown_waiter.lock().await;
        let owned: Vec<_> = self
            .running
            .lock()
            .await
            .iter()
            .map(|(name, child)| (name.clone(), child.clone()))
            .collect();
        let mut pending: Vec<_> = owned
            .iter()
            .map(|(name, owned)| {
                let stop = async {
                    let mut child = owned.lock().await;
                    let result = stop_client(name, &mut child, deadline).await;
                    if child.id().is_none() {
                        let mut running = self.running.lock().await;
                        if running
                            .get(name)
                            .is_some_and(|current| Arc::ptr_eq(current, owned))
                        {
                            running.remove(name);
                        }
                    }
                    result
                };
                (name, Some(Box::pin(stop)))
            })
            .collect();
        // Poll all borrowed children before waiting. No detached task owns a handle,
        // so dropping this waiter cannot release or lose the running registry entries.
        std::future::poll_fn(|cx| {
            use std::future::Future;
            for (name, waiting) in &mut pending {
                if let Some(future) = waiting {
                    if let std::task::Poll::Ready(result) = future.as_mut().poll(cx) {
                        self.shutdown_failures
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .record(name, result);
                        *waiting = None;
                    }
                }
            }
            if pending.iter().all(|(_, waiting)| waiting.is_none()) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        drop(pending);
        self.shutdown_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .result()
    }
}

async fn stop_client(
    name: &str,
    child: &mut Child,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    // Reap first; never signal an exited child's numeric PID after it may be reused.
    if child.try_wait()?.is_none() {
        if let Some(pid) = child.id() {
            if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    anyhow::bail!("cannot signal client tunnel '{name}': {error}");
                }
            }
        }
    }
    let status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(result) => result?,
        Err(_) => {
            child.start_kill()?;
            child.wait().await?;
            anyhow::bail!("client tunnel '{name}' exceeded shutdown grace; forced termination cannot confirm cleanup");
        }
    };
    if !status.success() {
        anyhow::bail!("client tunnel '{name}' exited with {status}; cleanup was not confirmed");
    }
    log::info!("Client tunnel '{name}' stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ClientManager;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::{Child, Command};

    async fn ready_child(script: &str) -> Child {
        let mut child = Command::new("sh")
            .args(["-c", script])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            BufReader::new(child.stdout.take().unwrap()).read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(line.trim(), "ready");
        child
    }

    #[tokio::test]
    async fn shutdown_signals_all_children_with_one_grace_and_reports_forced_kill() {
        let manager = ClientManager::new();
        for name in ["one", "two", "three"] {
            let child = ready_child("trap '' TERM; echo ready; exec sleep 30").await;
            manager
                .running
                .lock()
                .await
                .insert(name.into(), Arc::new(Mutex::new(child)));
        }
        let started = tokio::time::Instant::now();
        let error = manager
            .shutdown_with_grace(Duration::from_millis(150))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "sequential grace: {:?}",
            started.elapsed()
        );
        for name in ["one", "two", "three"] {
            assert!(error.contains(name), "{error}");
        }
        assert!(error.contains("forced termination"));
        assert!(manager.running.lock().await.is_empty());
        assert!(manager
            .connect("not-present")
            .await
            .unwrap_err()
            .to_string()
            .contains("shutting down"));
    }

    #[tokio::test]
    async fn disconnect_cancellation_keeps_child_owned_and_prevents_replacement() {
        let manager = ClientManager::new();
        let child = ready_child("trap '' TERM; echo ready; exec sleep 30").await;
        let pid = child.id();
        manager
            .running
            .lock()
            .await
            .insert("one".into(), Arc::new(Mutex::new(child)));
        let stopping = tokio::time::timeout(Duration::from_millis(20), manager.disconnect("one"));
        let observe = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(10), manager.is_running("one"))
                    .await
                    .unwrap()
            );
        };
        let (cancelled, ()) = tokio::join!(stopping, observe);
        assert!(cancelled.is_err());
        let owned = manager.running.lock().await.get("one").unwrap().clone();
        assert_eq!(owned.lock().await.id(), pid);
        manager
            .shutdown_with_grace(Duration::ZERO)
            .await
            .unwrap_err();
        assert!(manager.running.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cancelled_shutdown_preserves_deadline_and_already_observed_errors() {
        let manager = ClientManager::new();
        let mut failed = ready_child("echo ready; exit 7").await;
        failed.wait().await.unwrap();
        let pending = ready_child("trap '' TERM; echo ready; exec sleep 30").await;
        manager.running.lock().await.extend([
            ("failed".into(), Arc::new(Mutex::new(failed))),
            ("pending".into(), Arc::new(Mutex::new(pending))),
        ]);
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            manager.shutdown_with_grace(Duration::from_millis(100))
        )
        .await
        .is_err());
        let deadline = *manager.shutdown_deadline.get().unwrap();
        assert!(manager
            .shutdown_failures
            .lock()
            .unwrap()
            .result()
            .unwrap_err()
            .to_string()
            .contains("failed"));
        tokio::time::sleep_until(deadline).await;
        let error = manager
            .shutdown_with_grace(Duration::from_secs(10))
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(manager.shutdown_deadline.get(), Some(&deadline));
        assert!(
            error.contains("failed") && error.contains("pending"),
            "{error}"
        );
        assert!(manager.running.lock().await.is_empty());
    }

    #[tokio::test]
    async fn clean_signal_exit_allows_successful_shutdown() {
        let manager = ClientManager::new();
        let child =
            ready_child("trap 'exit 0' TERM; echo ready; while :; do sleep 0.02; done").await;
        manager
            .running
            .lock()
            .await
            .insert("clean".into(), Arc::new(Mutex::new(child)));
        manager.shutdown_all().await.unwrap();
        manager.shutdown_all().await.unwrap();
        assert!(manager.running.lock().await.is_empty());
    }

    #[tokio::test]
    async fn shutdown_closes_admission_before_registry_wait_and_keeps_that_deadline() {
        let manager = ClientManager::new();
        let registry = manager.running.lock().await;
        assert!(tokio::time::timeout(
            Duration::from_millis(10),
            manager.shutdown_with_grace(Duration::from_millis(10))
        )
        .await
        .is_err());
        let deadline = *manager.shutdown_deadline.get().unwrap();
        assert!(manager
            .connect("not-present")
            .await
            .unwrap_err()
            .to_string()
            .contains("shutting down"));
        drop(registry);
        manager.shutdown_all().await.unwrap();
        assert_eq!(manager.shutdown_deadline.get(), Some(&deadline));
    }

    #[test]
    fn autostart_reads_bounded_client_ini() {
        let path = std::env::temp_dir().join(format!(
            "qeli-autostart-{}-{}.conf",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, "[qeli]\nserver = host:443\nautostart = true\n").unwrap();
        assert!(ClientManager::profile_autostarts_file(&path));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(crate::transport_core::MAX_CONFIG_BYTES as u64 + 1)
            .unwrap();
        assert!(!ClientManager::profile_autostarts_file(&path));
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn supervisor_stop_reaps_clients_while_worker_is_still_waiting() {
        let manager = ClientManager::new();
        let child = ready_child("trap '' TERM; echo ready; exec sleep 30").await;
        manager
            .running
            .lock()
            .await
            .insert("one".into(), Arc::new(Mutex::new(child)));
        let (release_worker, worker_wait) = tokio::sync::oneshot::channel();
        let (clients_done, clients_wait) = tokio::sync::oneshot::channel();
        let stopping_manager = &manager;
        let mut coordinator = Box::pin(crate::server_shutdown::coordinate(
            |stopping| async move {
                // Same order as the supervisor's signal future: close admission,
                // announce stop, then continue owning and waiting for the worker.
                stopping_manager.request_shutdown_with_grace(Duration::from_millis(100));
                let _ = stopping.send(true);
                worker_wait.await.unwrap();
                Err::<(), _>(anyhow::anyhow!("worker failure fixture"))
            },
            || async {
                let result = manager.shutdown_all().await;
                let _ = clients_done.send(());
                result
            },
        ));
        tokio::select! {
            result = &mut coordinator => panic!("returned before worker exit: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), clients_wait) => result.unwrap().unwrap(),
        }
        assert!(
            manager.running.lock().await.is_empty(),
            "clients were left running until worker exit"
        );
        assert!(manager
            .connect("not-present")
            .await
            .unwrap_err()
            .to_string()
            .contains("shutting down"));
        release_worker.send(()).unwrap();
        let (worker, clients) = coordinator.await;
        let mut failures = crate::server_shutdown::Failures::default();
        failures.record("worker", worker);
        failures.record("outbound clients", clients);
        let message = failures.result().unwrap_err().to_string();
        assert!(
            message.contains("worker failure fixture") && message.contains("forced termination"),
            "{message}"
        );
    }
}
