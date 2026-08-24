use crate::server::web::auth::{self, AuthError};
use crate::server::{ServerState, WorkerCmd};
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Apply config changes by restarting the data-plane worker process. The
/// supervisor — and with it the web panel and this very request — keep running,
/// so the panel never goes down: only the VPN profiles (TUN, listeners, DNS,
/// DHCP) are torn down by the OS as the old worker exits and recreated by a
/// fresh worker. The panel JS just polls /api/status until clients reappear.
pub async fn restart(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    // Re-check the exact on-disk config immediately before touching the healthy worker.  Saves
    // already preflight, but the file can also be edited by hand between save and restart.
    // Refusing here preserves the currently-working VPN instead of killing it and only then
    // discovering that the replacement would collide with the host's LAN/default gateway.
    let _config_write_guard = state.config_write_lock.lock().await;
    let config = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(format!("restart refused: {error}")))),
    };
    if let Err(error) = crate::server::validate_profiles(&config) {
        return Ok(Json(super::err_json(format!(
            "restart refused: server config is invalid: {error}"
        ))));
    }
    if let Err(error) = super::effective_users(&config) {
        return Ok(Json(super::err_json(format!(
            "restart refused: profile reservations conflict with users: {error}"
        ))));
    }
    if let Err(error) = crate::server::preflight::run(&config) {
        return Ok(Json(super::err_json(format!(
            "restart refused: server config conflicts with host networking: {error}"
        ))));
    }
    match &state.worker_tx {
        Some(tx) => {
            if tx.send(WorkerCmd::Restart).await.is_err() {
                return Ok(Json(super::err_json(
                    "supervisor is not accepting commands",
                )));
            }
            Ok(Json(json!({"ok": true, "message": "worker restarting"})))
        }
        None => Ok(Json(super::err_json(
            "server is not running under a supervisor",
        ))),
    }
}

/// FULL process restart via systemd — needed for changes the worker restart can't apply
/// (the panel's own socket: `web.bind` / `web.port` / `web.tls*` / `web.enabled`). The panel
/// session survives when `web.persist_session_key` is on (the default).
///
/// Before firing, we PRE-FLIGHT so a restart that cannot work fails *loudly* with an
/// actionable message instead of a fire-and-forget that logs an error nobody reads (the
/// panel used to report success regardless — the change then simply never applied).
/// Rejected up-front: no systemd (a container or a hand-run process), a missing `systemctl`,
/// or a non-root service that polkit actually refuses to authorise. We ask polkit instead of
/// checking `/etc/polkit-1/rules.d/49-qeli.rules`: on Ubuntu that directory is commonly mode
/// 0750 root:polkitd, so `Path::exists()` from the `qeli` service user returns false even when
/// the installed rule is valid and systemd accepts the restart.
/// Only when the pre-flight passes do we schedule the real restart (returned FIRST, the
/// `systemctl restart` runs ~0.8 s later so the browser gets the reply before we're replaced).
/// Outcome of the last DETACHED restart, when it failed.
///
/// The reply to `full_restart` is necessarily sent BEFORE the restart runs — systemd
/// replaces this process, so there is no later moment to answer from. That made every
/// outcome look like `ok: true`, including the ones where `systemctl` refused and the
/// server kept running the old config; the failure reached the journal only.
///
/// This closes the loop without changing that design: on SUCCESS the process is replaced
/// and this cell dies with it (the panel reconnecting IS the success signal), while on
/// FAILURE the process survives, so the message persists and `/api/status` reports it on
/// the panel's next poll. (S-18)
static LAST_RESTART_FAILURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn record_restart_failure(msg: String) {
    if let Ok(mut g) = LAST_RESTART_FAILURE.lock() {
        *g = Some(msg);
    }
}

/// The pending restart-failure message, if the last requested restart never happened.
pub fn last_restart_failure() -> Option<String> {
    LAST_RESTART_FAILURE.lock().ok().and_then(|g| g.clone())
}

pub async fn full_restart(_guard: auth::AuthGuard) -> Result<Json<Value>, AuthError> {
    // A fresh attempt supersedes any stale failure from a previous one.
    if let Ok(mut g) = LAST_RESTART_FAILURE.lock() {
        *g = None;
    }
    let unit = detect_systemd_unit().unwrap_or_else(|| "qeli.service".to_string());

    match restart_capability(&unit).await {
        RestartReady::Ok => {
            let unit_bg = unit.clone();
            tokio::spawn(async move {
                // Let the HTTP response flush before systemd stops us.
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                match tokio::process::Command::new("systemctl")
                    .args(["restart", &unit_bg])
                    .status()
                    .await
                {
                    Ok(s) if s.success() => {} // being replaced — nothing more to do
                    Ok(s) => {
                        log::error!("full-restart: `systemctl restart {unit_bg}` exited with {s}");
                        record_restart_failure(format!(
                            "`systemctl restart {unit_bg}` exited with {s} — the server is still \
                             running the OLD configuration. Restart it manually."
                        ));
                    }
                    Err(e) => {
                        log::error!(
                            "full-restart: could not run systemctl ({e}) — run \
                             `systemctl restart {unit_bg}` manually"
                        );
                        record_restart_failure(format!(
                            "could not run systemctl ({e}) — the server is still running the OLD \
                             configuration. Run `systemctl restart {unit_bg}` manually."
                        ));
                    }
                }
            });
            Ok(Json(json!({
                "ok": true,
                "unit": unit,
                "message": "full restart requested — the panel will reconnect in a few seconds"
            })))
        }
        RestartReady::PolkitDenied { unit, user } => Ok(Json(json!({
            "ok": false,
            "kind": "polkit_missing",
            "unit": unit,
            "user": user,
            "install_cmd": "sudo qeli install-polkit",
            "error": format!(
                "The panel runs as '{user}', and polkit did not authorise it to restart {unit}. \
                 The rule may be missing, invalid, or target a different service user/unit. \
                 Install or refresh it as root — run `sudo qeli install-polkit --user {user} \
                 --unit {unit}` — then click Apply & Restart again. Verify independently with: \
                 `sudo -u {user} systemctl restart {unit}`. To apply changes right now: \
                 `sudo systemctl restart {unit}`."
            ),
        }))),
        RestartReady::NoSystemd { container } => Ok(Json(json!({
            "ok": false,
            "kind": "no_systemd",
            "container": container,
            "unit": unit,
            "error": if container {
                "This server runs inside a container — systemctl is not available here, so \
                 \"Apply & Restart\" cannot restart the process. Profile / data-plane changes apply \
                 with the in-process worker restart. To change the panel socket \
                 (web.bind / web.port / web.tls / web.enabled), recreate the container \
                 (e.g. `docker restart <name>`) after saving."
                    .to_string()
            } else {
                "Not running under systemd — the panel cannot restart the process itself. Profile / \
                 data-plane changes apply with the worker restart; for panel-socket changes restart \
                 the qeli process the way you started it."
                    .to_string()
            },
        }))),
        RestartReady::NoSystemctl => Ok(Json(json!({
            "ok": false,
            "kind": "no_systemctl",
            "unit": unit,
            "error": format!(
                "`systemctl` is not installed, so \"Apply & Restart\" cannot restart {unit}. \
                 Restart the qeli process the way your init system does; profile / data-plane \
                 changes can be applied with the worker restart."
            ),
        }))),
    }
}

/// Whether a full (systemd) restart from the panel can actually succeed — so `full_restart`
/// can return a precise, actionable reason instead of silently failing.
enum RestartReady {
    /// systemd present and we may manage the unit (root, or polkit authorises it).
    Ok,
    /// Not under systemd — a container (docker/podman/lxc) or a hand-run process.
    NoSystemd { container: bool },
    /// `systemctl` binary absent.
    NoSystemctl,
    /// systemd + non-root user, and polkit denied managing this unit.
    PolkitDenied { unit: String, user: String },
}

async fn restart_capability(unit: &str) -> RestartReady {
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        // The canonical sd_booted() check: this directory exists iff booted under systemd.
        return RestartReady::NoSystemd {
            container: in_container(),
        };
    }
    if !["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        return RestartReady::NoSystemctl;
    }
    // Root manages units directly. For an unprivileged service, ask polkit about the
    // exact action and unit instead of trying to stat its root-only rules directory.
    if unsafe { libc::geteuid() } == 0 {
        return RestartReady::Ok;
    }

    match polkit_restart_authorization(unit).await {
        PolkitAuthorization::Authorized => RestartReady::Ok,
        PolkitAuthorization::Denied => RestartReady::PolkitDenied {
            unit: unit.to_string(),
            user: effective_username(),
        },
        PolkitAuthorization::Unknown => {
            // `pkcheck` is optional and its own operational failure says nothing about
            // whether systemd will authorise the real request. Do not recreate the old
            // false-negative with a different probe: let systemctl make the authoritative
            // decision. A failure is retained by LAST_RESTART_FAILURE and shown by status.
            log::warn!(
                "full-restart: could not preflight polkit authorization for {unit}; \
                 deferring the authorization decision to systemctl"
            );
            RestartReady::Ok
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolkitAuthorization {
    Authorized,
    Denied,
    Unknown,
}

fn classify_pkcheck_exit(code: Option<i32>) -> PolkitAuthorization {
    match code {
        Some(0) => PolkitAuthorization::Authorized,
        // pkcheck documents 1 as an outright denial, 2 as authorization unavailable
        // without an authentication agent / user interaction, and 3 as a dismissed
        // authentication request. A headless system service cannot proceed in any of
        // those cases. 126/127 mean the probe itself was malformed or failed.
        Some(1..=3) => PolkitAuthorization::Denied,
        _ => PolkitAuthorization::Unknown,
    }
}

fn pkcheck_process_subject(stat: &str, pid: u32, uid: u32) -> Option<String> {
    // /proc/<pid>/stat field 22 is the process start time. The command in field 2 is
    // parenthesized and may contain spaces or ')', so split only after its final ')'.
    // Starting at field 3 (`state`), starttime is token index 19.
    let after_command = stat.rsplit_once(')')?.1;
    let start_time = after_command.split_whitespace().nth(19)?;
    Some(format!("{pid},{start_time},{uid}"))
}

/// Ask polkit whether this exact qeli process may manage this exact systemd unit.
/// No user interaction is requested: the service has no terminal or authentication agent.
async fn polkit_restart_authorization(unit: &str) -> PolkitAuthorization {
    let Some(pkcheck) = ["/usr/bin/pkcheck", "/bin/pkcheck"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
    else {
        return PolkitAuthorization::Unknown;
    };

    // The full pid,start-time,uid form avoids the PID-reuse race explicitly warned about
    // in pkcheck(1). If procfs is unexpectedly unavailable, treat the probe as unknown and
    // let the real systemctl request decide instead of falling back to the racy short form.
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return PolkitAuthorization::Unknown;
    };
    let Some(subject) =
        pkcheck_process_subject(&stat, std::process::id(), unsafe { libc::geteuid() })
    else {
        return PolkitAuthorization::Unknown;
    };
    let mut command = tokio::process::Command::new(pkcheck);
    command
        .args([
            "--action-id",
            "org.freedesktop.systemd1.manage-units",
            "--process",
            &subject,
            "--detail",
            "unit",
            unit,
            "--detail",
            "verb",
            "restart",
        ])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let check = command.status();
    match tokio::time::timeout(std::time::Duration::from_secs(3), check).await {
        Ok(Ok(status)) => classify_pkcheck_exit(status.code()),
        Ok(Err(error)) => {
            log::warn!("full-restart: could not execute {pkcheck}: {error}");
            PolkitAuthorization::Unknown
        }
        Err(_) => {
            log::warn!("full-restart: {pkcheck} timed out while checking {unit}");
            PolkitAuthorization::Unknown
        }
    }
}

/// Best-effort container detection: the Docker/Podman marker files, or a container manager
/// in PID 1's cgroup. (Under systemd this is normally false; kept for LXC-system-container
/// edge cases where /run/systemd/system exists but systemctl still cannot reach the host.)
fn in_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup")
        .map(|s| {
            s.contains("docker")
                || s.contains("containerd")
                || s.contains("/lxc")
                || s.contains("libpod")
        })
        .unwrap_or(false)
}

/// getpwuid(geteuid()).pw_name — the user this process runs as (the polkit rule's subject).
/// Falls back to the numeric euid if the lookup fails.
fn effective_username() -> String {
    unsafe {
        let uid = libc::geteuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

/// Best-effort: this process's own systemd unit from its cgroup, so the restart targets the
/// right unit whatever it is named (`qeli.service`, `qeli-server.service`, …). `None` when not
/// run under systemd (caller falls back to `qeli.service`).
fn detect_systemd_unit() -> Option<String> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // e.g. "0::/system.slice/qeli.service" → the last `*.service` path component.
    cg.lines()
        .filter_map(|l| l.rsplit('/').next())
        .find(|c| c.ends_with(".service"))
        .map(|c| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::{classify_pkcheck_exit, pkcheck_process_subject, PolkitAuthorization};

    #[test]
    fn pkcheck_exit_status_is_interpreted_without_false_denials() {
        assert_eq!(
            classify_pkcheck_exit(Some(0)),
            PolkitAuthorization::Authorized
        );
        assert_eq!(classify_pkcheck_exit(Some(1)), PolkitAuthorization::Denied);
        assert_eq!(classify_pkcheck_exit(Some(2)), PolkitAuthorization::Denied);
        assert_eq!(classify_pkcheck_exit(Some(3)), PolkitAuthorization::Denied);
        assert_eq!(
            classify_pkcheck_exit(Some(126)),
            PolkitAuthorization::Unknown
        );
        assert_eq!(
            classify_pkcheck_exit(Some(127)),
            PolkitAuthorization::Unknown
        );
        assert_eq!(classify_pkcheck_exit(None), PolkitAuthorization::Unknown);
    }

    #[test]
    fn pkcheck_subject_uses_pid_start_time_and_uid() {
        let stat = "4242 (qeli ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
        assert_eq!(
            pkcheck_process_subject(stat, 4242, 991),
            Some("4242,987654,991".to_string())
        );
    }
}
