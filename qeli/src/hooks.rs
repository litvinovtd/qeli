//! Lifecycle hooks (`post_up` / `post_down`) — a configured shell command run at
//! tunnel start and clean stop, on both the client and the server.
//!
//! **SECURITY.** A hook runs an arbitrary command as the process user (typically
//! root). It is therefore honoured ONLY from a *trusted* local config file:
//!  * [`config_is_trusted`] refuses to run hooks when the config file is group- or
//!    world-writable (anyone who can edit it would otherwise run code as us);
//!  * the web panel / API must NEVER write these fields (see `web/api/config.rs`),
//!    so a panel compromise can't turn into remote code execution.
//!
//! A failing hook logs a warning but does not abort the tunnel. Each hook has a
//! hard timeout (the child is killed on drop), so a hung command can't wedge
//! startup or shutdown.

#[cfg(target_os = "linux")]
use std::time::Duration;

/// Hard timeout for a single hook invocation.
#[cfg(target_os = "linux")]
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Reject hooks from a config file others can write (privilege-escalation guard).
/// `Ok(())` = safe to run hooks; `Err(reason)` = refuse. Non-Linux: always `Ok`
/// (hooks are a Linux-only feature).
#[cfg(target_os = "linux")]
pub fn config_is_trusted(path: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).map_err(|e| format!("cannot stat config '{path}': {e}"))?;
    // Group- or world-writable (0o022) means a non-owner could inject a hook.
    if md.mode() & 0o022 != 0 {
        return Err(format!(
            "config '{path}' is group/world-writable (mode {:o}); refusing to run hooks — `chmod 600 {path}`",
            md.mode() & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn config_is_trusted(_path: &str) -> Result<(), String> {
    Ok(())
}

/// Run a hook command via `/bin/sh -c`, with the given environment, a hard
/// timeout, and captured output. Best-effort: failures are logged, never fatal.
/// No-op on a blank command or on non-Linux targets.
#[cfg(target_os = "linux")]
pub async fn run(label: &str, cmd: &str, env: &[(&str, String)]) {
    if cmd.trim().is_empty() {
        return;
    }
    log::info!("hook[{label}]: running");
    let mut c = tokio::process::Command::new("/bin/sh");
    c.arg("-c").arg(cmd).kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    match tokio::time::timeout(HOOK_TIMEOUT, c.output()).await {
        Ok(Ok(o)) => {
            let so = String::from_utf8_lossy(&o.stdout);
            let se = String::from_utf8_lossy(&o.stderr);
            let tail = format!("{} {}", so.trim(), se.trim());
            if o.status.success() {
                if tail.trim().is_empty() {
                    log::info!("hook[{label}]: ok");
                } else {
                    log::info!("hook[{label}]: ok — {}", tail.trim());
                }
            } else {
                log::warn!("hook[{label}]: exited {} — {}", o.status, tail.trim());
            }
        }
        Ok(Err(e)) => log::warn!("hook[{label}]: failed to spawn /bin/sh: {e}"),
        Err(_) => log::warn!(
            "hook[{label}]: timed out after {}s — killed",
            HOOK_TIMEOUT.as_secs()
        ),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_label: &str, _cmd: &str, _env: &[(&str, String)]) {}
