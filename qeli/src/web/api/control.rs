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
