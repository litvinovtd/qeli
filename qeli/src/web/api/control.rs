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
/// or a non-root service with no polkit rule (`49-qeli.rules`) — which is every non-.deb
/// install; there we tell the operator to run `sudo qeli install-polkit`.
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

    match restart_capability(&unit) {
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
        RestartReady::MissingPolkit { unit, user } => Ok(Json(json!({
            "ok": false,
            "kind": "polkit_missing",
            "unit": unit,
            "user": user,
            "install_cmd": "sudo qeli install-polkit",
            "error": format!(
                "The panel runs as '{user}' and is not allowed to restart {unit}: the polkit rule \
                 that authorises it is not installed (this build was not installed from the .deb \
                 package, which ships it). Install it once as root — run `sudo qeli install-polkit` \
                 on the server — then click Apply & Restart again. To apply changes right now: \
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
    /// systemd present and we may manage the unit (root, or the polkit rule is installed).
    Ok,
    /// Not under systemd — a container (docker/podman/lxc) or a hand-run process.
    NoSystemd { container: bool },
    /// `systemctl` binary absent.
    NoSystemctl,
    /// systemd + non-root user, but the polkit rule authorising `user` → `unit` is missing.
    MissingPolkit { unit: String, user: String },
}

fn restart_capability(unit: &str) -> RestartReady {
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
    // Root manages units directly; a non-root service needs the polkit rule.
    if unsafe { libc::geteuid() } == 0 || polkit_rule_installed() {
        return RestartReady::Ok;
    }
    RestartReady::MissingPolkit {
        unit: unit.to_string(),
        user: effective_username(),
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

/// The shipped rule (`.deb`) or an `install-polkit`-written one both land here.
fn polkit_rule_installed() -> bool {
    std::path::Path::new("/etc/polkit-1/rules.d/49-qeli.rules").exists()
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
