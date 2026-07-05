use super::paths::{validate_in_whitelist, ALLOWED_LOG_DIRS};
use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct LogsQuery {
    #[serde(default = "default_lines")]
    lines: usize,
    #[serde(default)]
    filter: Option<String>,
}

fn default_lines() -> usize {
    200
}

/// Read at most the last `cap` bytes of a file as (lossy) UTF-8, dropping a partial
/// first line — so a multi-GB log isn't slurped whole for a tail view.
fn read_tail(path: &std::path::Path, cap: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(cap);
    if start > 0 {
        f.seek(SeekFrom::Start(start))?;
    }
    let mut bytes = Vec::new();
    f.take(cap).read_to_end(&mut bytes)?;
    let s = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if start > 0 {
        s.split_once('\n').map(|(_, r)| r.to_string()).unwrap_or(s)
    } else {
        s
    })
}

pub async fn get_logs(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Query(q): Query<LogsQuery>,
) -> Json<Value> {
    let log_path = state.config.logging.file.clone();
    let filter = q.filter.clone();
    let max_lines = q.lines.min(2000);

    let path_display = log_path.as_deref().unwrap_or("").to_string();

    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
        let path = match &log_path {
            Some(p) if !p.is_empty() => p.clone(),
            _ => {
                return Ok(vec![
                    "[logging.file not configured — logs go to stderr/journald]".to_string(),
                    "[Use: journalctl -u qeli -n 200 --no-pager]".to_string(),
                ])
            }
        };

        // Resolve and verify the path lives inside the log whitelist; an
        // attacker who can edit the running config must not be able to read
        // arbitrary files (e.g. /etc/shadow) via /api/logs.
        let canon = validate_in_whitelist(&path, ALLOWED_LOG_DIRS)
            .map_err(|e| anyhow::anyhow!("log path rejected: {}", e))?;

        // Read only the last ~4 MiB so a multi-GB log isn't slurped whole for a tail
        // view (we return at most 2000 lines). A filter therefore matches within the
        // recent window — the intent of a log viewer.
        let content = read_tail(&canon, 4 * 1024 * 1024)
            .map_err(|e| anyhow::anyhow!("Cannot read {}: {}", canon.display(), e))?;

        // Lower-case the filter ONCE, not once per log line (the old code re-lowered the
        // filter on every line of a potentially large log).
        let filter_lc = filter.as_ref().map(|f| f.to_lowercase());
        let lines: Vec<String> = content
            .lines()
            .filter(|l| match &filter_lc {
                Some(f) => l.to_lowercase().contains(f),
                None => true,
            })
            .rev()
            .take(max_lines)
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        Ok(lines)
    })
    .await;

    match result {
        Ok(Ok(lines)) => Json(json!({
            "ok": true,
            "path": path_display,
            "count": lines.len(),
            "lines": lines,
        })),
        Ok(Err(e)) => Json(json!({ "ok": false, "error": e.to_string(), "lines": [] })),
        Err(e) => Json(json!({ "ok": false, "error": format!("task error: {}", e), "lines": [] })),
    }
}
