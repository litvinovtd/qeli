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
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

pub const CLIENTS_DIR: &str = "/etc/qeli/clients";

/// Per-process handle for a running tunnel.
pub struct ClientManager {
    /// profile name -> running child. Absent = not connected.
    running: Mutex<HashMap<String, Child>>,
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
        std::fs::read_to_string(Self::profile_path(name))
            .ok()
            .and_then(|s| crate::config::format::IniDoc::parse(&s).ok())
            .and_then(|d| crate::config::client::ClientConfig::from_ini(&d).ok())
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
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => {
                    map.remove(name); // exited — drop the dead handle
                    false
                }
                Ok(None) => true, // still running
                Err(_) => true,
            },
            None => false,
        }
    }

    /// Bring up the tunnel for `name`. No-op if already connected.
    pub async fn connect(&self, name: &str) -> anyhow::Result<()> {
        if !Self::valid_name(name) {
            anyhow::bail!("invalid client profile name");
        }
        let path = Self::profile_path(name);
        if !std::path::Path::new(&path).exists() {
            anyhow::bail!("client profile '{name}' does not exist");
        }
        if self.is_running(name).await {
            return Ok(()); // already up
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
        let logfile = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log)
            .map_err(|e| anyhow::anyhow!("cannot open client log {log}: {e}"))?;
        let errfile = logfile
            .try_clone()
            .map_err(|e| anyhow::anyhow!("cannot dup client log fd: {e}"))?;
        let child = Command::new(&exe)
            .arg("client")
            .arg("-c")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(logfile))
            .stderr(Stdio::from(errfile))
            .kill_on_drop(true) // safety net: don't orphan the tunnel if we drop
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start client '{name}': {e}"))?;
        log::info!("Client tunnel '{name}' started (pid {:?})", child.id());
        self.running.lock().await.insert(name.to_string(), child);
        Ok(())
    }

    /// Tear down the tunnel for `name` (SIGTERM → graceful DNS/route restore, then
    /// reap; SIGKILL if it doesn't exit in time). No-op if not connected.
    pub async fn disconnect(&self, name: &str) -> anyhow::Result<()> {
        let mut child = match self.running.lock().await.remove(name) {
            Some(c) => c,
            None => return Ok(()),
        };
        if let Some(pid) = child.id() {
            // SIGTERM so the client restores /etc/resolv.conf + routes before exit.
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
        // Give it a moment to clean up; force-kill if it overstays.
        let waited = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
        if waited.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        log::info!("Client tunnel '{name}' stopped");
        Ok(())
    }

    /// SIGTERM every running tunnel (best-effort) — called on supervisor shutdown.
    pub async fn shutdown_all(&self) {
        let names: Vec<String> = self.running.lock().await.keys().cloned().collect();
        for n in names {
            let _ = self.disconnect(&n).await;
        }
    }
}
