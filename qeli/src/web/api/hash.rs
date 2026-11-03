use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

/// Share the verification budget; reject overload before queueing memory-hard work.
pub(super) async fn bounded_hash(password: String) -> Result<String, String> {
    if password.is_empty() || password.len() > 1024 {
        return Err("password must contain 1..1024 bytes".into());
    }
    let permit = crate::server::argon2_gate()
        .try_acquire()
        .map_err(|_| "password hashing busy; retry later".to_string())?;
    crate::server::run_argon2(permit, move || {
        crate::crypto::hash_password(password.as_bytes()).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("hash task failed: {e}"))?
}

pub async fn hash_password(
    State(_state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Json(body): Json<Value>,
) -> Json<Value> {
    let password = match body["password"].as_str() {
        Some("") => return Json(json!({ "ok": false, "error": "password field required" })),
        // Cap the input before the memory-hard hash so an authenticated admin can't
        // submit a huge string and burn CPU/RAM.
        Some(p) if p.len() > 1024 => {
            return Json(json!({ "ok": false, "error": "password too long (max 1024 bytes)" }))
        }
        Some(p) => p.to_string(),
        None => return Json(json!({ "ok": false, "error": "password field required" })),
    };

    match bounded_hash(password).await {
        Ok(hash) => Json(json!({ "ok": true, "hash": hash })),
        Err(e) => Json(json!({ "ok": false, "error": e })),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn admin_hash_rejects_oversize_and_busy_before_dispatch() {
        assert!(super::bounded_hash(String::new()).await.is_err());
        assert!(super::bounded_hash("x".repeat(1025)).await.is_err());
        let capacity = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(2, 8) as u32;
        let permits = crate::server::argon2_gate()
            .acquire_many(capacity)
            .await
            .unwrap();
        assert!(super::bounded_hash("valid password".into())
            .await
            .unwrap_err()
            .contains("busy"));
        drop(permits);
    }
}
