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
/// session survives when `web.persist_session_key` is on (the default). The HTTP response is
/// returned FIRST; the actual `systemctl restart` runs ~0.8 s later so the browser gets the
/// reply before this process is replaced. Requires permission to manage the unit: a root
/// service works directly; a non-root `User=qeli` service needs the shipped polkit rule
/// (`49-qeli.rules`). On failure the operator is told to run the command manually.
pub async fn full_restart(_guard: auth::AuthGuard) -> Result<Json<Value>, AuthError> {
    let unit = detect_systemd_unit().unwrap_or_else(|| "qeli.service".to_string());
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
            Ok(s) => log::error!("full-restart: `systemctl restart {unit_bg}` exited with {s}"),
            Err(e) => log::error!(
                "full-restart: could not run systemctl ({e}) — run `systemctl restart {unit_bg}` \
                 manually, or (non-root service) install the polkit rule 49-qeli.rules"
            ),
        }
    });
    Ok(Json(json!({
        "ok": true,
        "unit": unit,
        "message": "full restart requested — the panel will reconnect in a few seconds"
    })))
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
