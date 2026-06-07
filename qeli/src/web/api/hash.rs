use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn hash_password(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    if let Err(e) = auth::check_auth(&headers, &state.config.web) {
        return e.1;
    }

    let password = match body["password"].as_str() {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return Json(json!({ "ok": false, "error": "password field required" })),
    };

    let result = tokio::task::spawn_blocking(move || {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        let hasher = argon2::Argon2::default();
        hasher
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(hash)) => Json(json!({ "ok": true, "hash": hash })),
        Ok(Err(e)) => Json(json!({ "ok": false, "error": e })),
        Err(e) => Json(json!({ "ok": false, "error": format!("task error: {}", e) })),
    }
}
