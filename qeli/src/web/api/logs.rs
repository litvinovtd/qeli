use super::paths::{validate_in_whitelist, ALLOWED_LOG_DIRS};
use crate::server::web::auth;
use crate::server::ServerState;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

static LOG_READS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
const MAX_FILTER_BYTES: usize = 1024;

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

/// Open the canonical whitelist result component by component. NOFOLLOW on only
/// the final name would still allow a swapped ancestor to redirect the read.
fn open_canonical_log(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
        path::Component,
    };
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid log path");
    if !path.is_absolute() {
        return Err(invalid());
    }
    let names: Vec<_> = path
        .components()
        .filter(|c| *c != Component::RootDir)
        .collect();
    if names.is_empty() {
        return Err(invalid());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for (i, component) in names.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if i + 1 < names.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: the live parent fd and one NUL-terminated component are owned here.
        let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned fd; from_raw_fd takes it exactly once.
        file = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log must be a regular file",
        ));
    }
    Ok(file)
}

/// Read a bounded tail from the admitted descriptor, preserving a complete first
/// line if the window starts exactly at its boundary. Rotation cannot redirect it.
fn read_tail(mut file: std::fs::File, cap: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    if cap == 0 {
        return Ok(String::new());
    }
    let start = file.metadata()?.len().saturating_sub(cap);
    let partial = if start > 0 {
        file.seek(SeekFrom::Start(start - 1))?;
        let mut previous = [0];
        if file.read(&mut previous)? == 0 {
            return Ok(String::new());
        }
        previous[0] != b'\n'
    } else {
        false
    };
    let mut bytes = Vec::new();
    file.take(cap).read_to_end(&mut bytes)?;
    let content = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if partial {
        content
            .split_once('\n')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_default()
    } else {
        content
    })
}

async fn run_read(
    gate: &'static tokio::sync::Semaphore,
    read: impl FnOnce() -> anyhow::Result<Vec<String>> + Send + 'static,
) -> anyhow::Result<Vec<String>> {
    let permit = gate
        .try_acquire()
        .map_err(|_| anyhow::anyhow!("log reader is busy; retry the request"))?;
    // Admission belongs to the blocking work, including after HTTP cancellation.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    })
    .await?
}

pub async fn get_logs(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
    Query(q): Query<LogsQuery>,
) -> Json<Value> {
    if q.filter
        .as_ref()
        .is_some_and(|filter| filter.len() > MAX_FILTER_BYTES)
    {
        return Json(json!({"ok": false, "error": "log filter exceeds 1024 bytes", "lines": []}));
    }
    let config = match super::current_server_config(&state).await {
        Ok(config) => config,
        Err(error) => return Json(super::err_json(error)),
    };
    let log_path = config.logging.file.clone();
    let filter = q.filter;
    let max_lines = q.lines.min(2000);

    let path_display = log_path.as_deref().unwrap_or("").to_string();

    let result = run_read(&LOG_READS, move || -> anyhow::Result<Vec<String>> {
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
        let content = open_canonical_log(&canon)
            .and_then(|file| read_tail(file, 4 * 1024 * 1024))
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
        Ok(lines) => Json(json!({
            "ok": true,
            "path": path_display,
            "count": lines.len(),
            "lines": lines,
        })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string(), "lines": [] })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf, sync::mpsc, time::Duration};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-log-read-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
        fn canonical(&self, path: &std::path::Path) -> PathBuf {
            validate_in_whitelist(path.to_str().unwrap(), &[self.0.to_str().unwrap()]).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn tail_keeps_boundary_lines_and_drops_incomplete_first_line() {
        let dir = Fixture::new();
        let path = dir.0.join("log");
        fs::write(&path, b"old\nfirst\nlast\n").unwrap();
        for (cap, expected) in [
            (11, "first\nlast\n"),
            (9, "last\n"),
            (0, ""),
            (100, "old\nfirst\nlast\n"),
        ] {
            assert_eq!(
                read_tail(open_canonical_log(&path).unwrap(), cap).unwrap(),
                expected
            );
        }
        fs::write(&path, b"single long unfinished line").unwrap();
        assert_eq!(
            read_tail(open_canonical_log(&path).unwrap(), 5).unwrap(),
            ""
        );
        fs::write(&path, [b'a', b'\n', 0xff, b'\n']).unwrap();
        assert_eq!(
            read_tail(open_canonical_log(&path).unwrap(), 100).unwrap(),
            "a\n\u{fffd}\n"
        );
    }

    #[test]
    fn replaced_leaf_and_parent_symlinks_cannot_escape_whitelist() {
        use std::os::unix::fs::symlink;
        let dir = Fixture::new();
        let outside = Fixture::new();
        let secret = outside.0.join("log");
        fs::write(&secret, "outside-secret").unwrap();
        let leaf = dir.0.join("log");
        fs::write(&leaf, "admitted").unwrap();
        let canon = dir.canonical(&leaf);
        fs::remove_file(&leaf).unwrap();
        symlink(&secret, &leaf).unwrap();
        assert!(open_canonical_log(&canon).is_err());
        assert!(validate_in_whitelist(leaf.to_str().unwrap(), &[dir.0.to_str().unwrap()]).is_err());
        let parent = dir.0.join("nested");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("log");
        fs::write(&path, "admitted").unwrap();
        let canon = dir.canonical(&path);
        fs::rename(&parent, dir.0.join("old-nested")).unwrap();
        symlink(&outside.0, &parent).unwrap();
        assert!(open_canonical_log(&canon).is_err());
        assert_eq!(fs::read_to_string(secret).unwrap(), "outside-secret");
    }

    #[test]
    fn fifo_swap_is_rejected_without_a_writer_and_rotation_keeps_open_inode() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let dir = Fixture::new();
        let path = dir.0.join("log");
        fs::write(&path, "old\n").unwrap();
        let canon = dir.canonical(&path);
        let file = open_canonical_log(&canon).unwrap();
        fs::rename(&path, dir.0.join("rotated")).unwrap();
        fs::write(&path, "new\n").unwrap();
        assert_eq!(read_tail(file, 100).unwrap(), "old\n");
        fs::remove_file(&path).unwrap();
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(open_canonical_log(&canon).is_err()).unwrap();
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        if result.is_err() {
            // Unblock a regressed open before failing the test.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path);
        }
        worker.join().unwrap();
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn cancelled_http_read_retains_admission_until_io_finishes() {
        let gate = Box::leak(Box::new(tokio::sync::Semaphore::new(1)));
        let (start, started) = tokio::sync::oneshot::channel();
        let (release, released) = mpsc::channel();
        let caller = tokio::spawn(run_read(gate, move || {
            let _ = start.send(());
            released.recv().unwrap();
            Ok(vec!["done".into()])
        }));
        started.await.unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let error = run_read(gate, || panic!("read bypassed admission"))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("busy"));
        assert_eq!(gate.available_permits(), 0);
        release.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(2), gate.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(
            run_read(gate, || Ok(vec!["next".into()])).await.unwrap(),
            vec!["next"]
        );
    }
    #[tokio::test]
    async fn actual_log_route_auth_filter_limit_and_current_ini_errors() {
        use axum::{
            body::{to_bytes, Body},
            http::{Request, StatusCode},
            routing::get,
            Router,
        };
        use tower::ServiceExt;
        let dir = Fixture::new();
        let path = dir.0.join("server.ini");
        let config = crate::config::server::ServerConfig::default();
        fs::write(&path, "[logging]\n[profile:fixture]\n").unwrap();
        let state = crate::server::test_api_state(config, &path);
        let app = Router::new()
            .route("/logs", get(get_logs))
            .with_state(state.clone());
        let request = |uri: String| Request::builder().uri(uri).body(Body::empty()).unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request("/logs".into()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        state.live_web.write().await.insecure_no_auth = true;
        let response = app
            .clone()
            .oneshot(request(format!("/logs?filter={}", "x".repeat(1025))))
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "log filter exceeds 1024 bytes");
        let response = app
            .clone()
            .oneshot(request(format!("/logs?filter={}", "x".repeat(1024))))
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(value["ok"], true, "{value}");
        assert_eq!(value["count"], 2);
        let outside = dir.0.join("outside-log");
        fs::write(&outside, "private-marker").unwrap();
        fs::write(
            &path,
            format!(
                "[logging]\nfile = {}\n[profile:fixture]\n",
                outside.display()
            ),
        )
        .unwrap();
        let response = app.oneshot(request("/logs".into())).await.unwrap();
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["ok"], false);
        assert!(value["error"].as_str().unwrap().contains("outside allowed"));
        assert!(!String::from_utf8_lossy(&body).contains("private-marker"));
    }
}
