use crate::server::web::auth::{self, AuthError};
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::Value;
use std::sync::Arc;

/// Latest host + tunnel snapshot: CPU/RAM/load/disk/uptime, the worker process's
/// own CPU/RSS, host NIC throughput, socket counts, and the live tunnel rate.
/// Served straight from the supervisor's 1 Hz sampler — no per-request /proc work.
pub async fn get_system(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    Ok(Json(state.metrics.latest_json().await))
}

/// Throughput / CPU / mem history ring buffer (1 s resolution, last 5 min) that
/// the dashboard renders as the live network-load chart.
pub async fn get_metrics(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    Ok(Json(state.metrics.history_json().await))
}
