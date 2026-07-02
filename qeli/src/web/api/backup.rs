use crate::server::web::auth::{self, AuthError};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Stream a gzip tarball of `/etc/qeli` (config + users file + identity keys) for
/// off-box backup. Authed-admin only; a GET so the browser downloads it straight
/// to disk carrying the session cookie. Restore = extract it back into `/etc`
/// (`tar xzf qeli-backup-*.tar.gz -C /etc`) and restart.
pub async fn download_backup(_guard: auth::AuthGuard) -> Result<Response, AuthError> {
    let out = tokio::task::spawn_blocking(|| {
        // `--ignore-failed-read`: the panel runs as the `qeli` user and some items
        // under /etc/qeli (e.g. root-owned client-links/, mode 0700) are unreadable
        // to it — skip those rather than abort, so the restore-critical files
        // (server config, users, identity keys) still get backed up.
        // `--xattrs`: preserve extended attributes so a restore keeps them.
        std::process::Command::new("tar")
            .args([
                "czf",
                "-",
                "--ignore-failed-read",
                "--xattrs",
                "-C",
                "/etc",
                "qeli",
            ])
            .output()
    })
    .await;

    // tar exits non-zero (1/2) when it skipped unreadable files, yet still produces
    // a valid archive — accept any non-empty gzip stream (magic 1f 8b).
    let is_gzip = |b: &[u8]| b.len() > 2 && b[0] == 0x1f && b[1] == 0x8b;
    let o = match out {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("tar spawn error: {e}"),
            )
                .into_response())
        }
        Err(e) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("task error: {e}"),
            )
                .into_response())
        }
    };
    if !is_gzip(&o.stdout) {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("tar failed: {}", String::from_utf8_lossy(&o.stderr)),
        )
            .into_response());
    }
    // `--ignore-failed-read` silently drops files the qeli user can't read. That is
    // fine for the root-owned client-links/, but if it drops the IDENTITY KEYS
    // (root-owned 0600) the archive looks successful yet restores a server with a
    // DIFFERENT identity — every client would need re-pinning. tar names any file it
    // skipped on stderr (success is silent), so a mention of qeli/identity means the
    // keys are missing: refuse rather than hand out a broken backup.
    let stderr = String::from_utf8_lossy(&o.stderr);
    if stderr.contains("qeli/identity") {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "backup aborted: the server identity key(s) under /etc/qeli/identity were \
                 unreadable and would be MISSING from the archive (a restore would change the \
                 server identity and break every pinned client). Fix the permissions \
                 (`chown -R qeli:qeli /etc/qeli/identity`) or take the backup as root. \
                 tar: {}",
                stderr.trim()
            ),
        )
            .into_response());
    }
    let bytes = o.stdout;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fname = format!("qeli-backup-{ts}.tar.gz");
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// Restore `/etc/qeli` from an uploaded backup `.tar.gz` (the file produced by
/// `download_backup`). The body is the raw gzip. Before extracting it validates
/// the archive is a gzip whose entries ALL live under `qeli/` (no absolute paths
/// or `..` traversal), then snapshots the current directory to a pre-restore
/// archive so the change is reversible. The worker must be restarted to apply.
pub async fn restore_backup(
    _guard: auth::AuthGuard,
    body: Bytes,
) -> Result<Json<Value>, AuthError> {
    let result = tokio::task::spawn_blocking(move || restore_blocking(&body)).await;
    Ok(Json(match result {
        Ok(Ok(msg)) => {
            // Notify (Tier-3): a successful restore changed /etc/qeli on disk.
            tokio::spawn(async {
                crate::server::notify::fire(
                    crate::server::notify::Event::Restore,
                    "config restored from an uploaded backup",
                )
                .await;
            });
            json!({ "ok": true, "message": msg })
        }
        Ok(Err(e)) => json!({ "ok": false, "error": e }),
        Err(e) => json!({ "ok": false, "error": format!("task error: {e}") }),
    }))
}

fn restore_blocking(data: &[u8]) -> Result<String, String> {
    if data.len() < 3 || data[0] != 0x1f || data[1] != 0x8b {
        return Err("not a gzip archive".into());
    }
    let tmp = "/etc/qeli/.restore-upload.tgz";
    std::fs::write(tmp, data).map_err(|e| format!("write temp file: {e}"))?;
    let cleanup = || {
        let _ = std::fs::remove_file(tmp);
    };

    // List entries and refuse anything not safely contained under `qeli/`.
    let listing = match std::process::Command::new("tar")
        .args(["tzvf", tmp])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            cleanup();
            return Err(format!(
                "not a valid tar.gz: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        Err(e) => {
            cleanup();
            return Err(format!("tar list failed: {e}"));
        }
    };
    let mut count = 0usize;
    for line in String::from_utf8_lossy(&listing).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // `tar tzvf` prefixes each entry with its type flag. Refuse anything that is
        // not a regular file ('-') or directory ('d'): a symlink / hardlink / device
        // entry is a classic tar-extraction escape (write THROUGH a link pointing
        // outside qeli/), which the path check below cannot stop on its own.
        let ftype = line.chars().next().unwrap_or(' ');
        if ftype != '-' && ftype != 'd' {
            cleanup();
            return Err(
                "refused: archive contains a symlink/hardlink/special entry \
                 (only regular files and directories are allowed)"
                    .into(),
            );
        }
        // For a regular file / directory the path is the last whitespace field
        // (no `-> target` suffix, since symlinks are already rejected above).
        let p = line.split_whitespace().last().unwrap_or("");
        if p.is_empty()
            || p.starts_with('/')
            || p.contains("..")
            || !(p == "qeli" || p.starts_with("qeli/"))
        {
            cleanup();
            return Err(format!(
                "refused: archive contains an unexpected path '{p}' (entries must be under qeli/)"
            ));
        }
        count += 1;
    }
    if count == 0 {
        cleanup();
        return Err("archive is empty".into());
    }

    // Snapshot the current state so a bad restore is reversible.
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bak = format!("/etc/qeli/.pre-restore-{ts}.tgz");
    let _ = std::process::Command::new("tar")
        .args([
            "czf",
            &bak,
            "--ignore-failed-read",
            "--xattrs",
            "-C",
            "/etc",
            "qeli",
        ])
        .output();
    // The snapshot holds identity keys + user hashes — keep it admin-only, and
    // rotate old ones so repeated restores don't grow /etc/qeli without bound.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
    }
    prune_pre_restore_snapshots(5);

    let ex = std::process::Command::new("tar")
        .args(["xzf", tmp, "--xattrs", "-C", "/etc"])
        .output();
    cleanup();
    match ex {
        Ok(o) if o.status.success() => Ok(format!(
            "restored {count} file(s) into /etc/qeli (pre-restore backup saved to {bak}). \
             Restart the server to apply."
        )),
        Ok(o) => Err(format!(
            "extract failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("tar extract spawn failed: {e}")),
    }
}

/// Keep only the `keep` newest `.pre-restore-*.tgz` snapshots in /etc/qeli so
/// repeated restores don't grow the config dir without bound. The timestamp is
/// embedded in the name (unix seconds), so lexicographic sort == chronological.
fn prune_pre_restore_snapshots(keep: usize) {
    let mut snaps: Vec<std::path::PathBuf> = match std::fs::read_dir("/etc/qeli") {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(".pre-restore-") && n.ends_with(".tgz"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => return,
    };
    if snaps.len() <= keep {
        return;
    }
    snaps.sort();
    let remove_n = snaps.len() - keep;
    for p in snaps.into_iter().take(remove_n) {
        let _ = std::fs::remove_file(p);
    }
}
