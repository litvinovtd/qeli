use crate::server::web::auth::{self, AuthError};
use crate::server::{ServerState, WorkerCmd};
use axum::extract::State;
use axum::http::HeaderMap;
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
    headers: HeaderMap,
) -> Result<Json<Value>, AuthError> {
    auth::check_auth(&headers, &state.config.web)?;

    match &state.worker_tx {
        Some(tx) => {
            if tx.send(WorkerCmd::Restart).await.is_err() {
                return Ok(Json(
                    json!({"ok": false, "error": "supervisor is not accepting commands"}),
                ));
            }
            Ok(Json(json!({"ok": true, "message": "worker restarting"})))
        }
        None => Ok(Json(
            json!({"ok": false, "error": "server is not running under a supervisor"}),
        )),
    }
}
