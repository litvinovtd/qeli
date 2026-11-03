use crate::server::web::auth::{self, AuthError};
use crate::server::{ServerState, WorkerCmd};
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

fn validate_restart_candidate(
    config: &crate::config::server::ServerConfig,
    preflight: impl FnOnce(&crate::config::server::ServerConfig) -> anyhow::Result<()>,
) -> Result<(), String> {
    crate::server::validate_profiles(config)
        .map_err(|error| format!("restart refused: server config is invalid: {error}"))?;
    super::effective_users(config)
        .map_err(|error| format!("restart refused: users configuration is invalid: {error}"))?;
    preflight(config).map_err(|error| {
        format!("restart refused: server config conflicts with host networking: {error}")
    })
}

/// A full process restart replaces the working panel as well as the VPN worker.
/// Check panel admission and the existing TLS material before stopping either.
fn validate_full_restart_panel(config: &crate::config::server::ServerConfig) -> Result<(), String> {
    super::config::validate_web_auth_for_save(&config.web)
        .map_err(|error| format!("restart refused: {error}"))?;
    crate::web::tls::check_config_files(&config.web)
        .map_err(|error| format!("restart refused: panel TLS: {error}"))?;
    Ok(())
}

/// Restart preflight must use one config snapshot for both values and file-path trust.
async fn current_restart_config(
    state: &Arc<ServerState>,
) -> Result<crate::config::server::ServerConfig, String> {
    let Some(path) = state.config_path.lock().await.clone() else {
        return Ok(state.config.clone());
    };
    let source = crate::server::read_config_source(&path)
        .map_err(|error| format!("cannot read current server config '{path}': {error}"))?;
    let (config, findings) = crate::config::parse_server_config_reporting(source.text())
        .map_err(|error| format!("cannot parse current server config '{path}': {error}"))?;
    if !findings.is_empty() {
        return Err(format!(
            "current server config '{path}' has {} unreadable or ambiguous value(s): {}",
            findings.len(),
            findings.join("; ")
        ));
    }
    source
        .validate_users_file_trust(&config)
        .map_err(|error| error.to_string())?;
    source
        .validate_tls_paths_trust(&config)
        .map_err(|error| error.to_string())?;
    for profile in &config.profiles {
        source
            .validate_identity_key_trust(profile)
            .map_err(|error| error.to_string())?;
    }
    Ok(config)
}

async fn preflight_restart(
    state: &Arc<ServerState>,
) -> Result<tokio::sync::OwnedMutexGuard<()>, String> {
    let (guard, observed) = super::preflight::lock(state, false).await?;
    let config = current_restart_config(state)
        .await
        .map_err(|error| format!("restart refused: {error}"))?;
    validate_restart_candidate(&config, |config| observed.check(config))?;
    validate_full_restart_panel(&config)?;
    Ok(guard)
}

/// Apply config changes by restarting the data-plane worker process. The
/// supervisor — and with it the web panel and this very request — keep running,
/// so the panel never goes down: only the VPN profiles (TUN, listeners, DNS,
/// DHCP) are torn down by the OS as the old worker exits and recreated by a
/// fresh worker. The panel JS just polls /api/status until clients reappear.
pub async fn restart(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    // Re-check the exact on-disk config immediately before touching the healthy worker.  Saves
    // already preflight, but the file can also be edited by hand between save and restart.
    // Refusing here preserves the currently-working VPN instead of killing it and only then
    // discovering that the replacement would collide with the host's LAN/default gateway.
    let (_config_write_guard, observed) = match super::preflight::lock(&state, false).await {
        Ok(value) => value,
        Err(error) => return Ok(Json(super::err_json(error))),
    };
    let config = match current_restart_config(&state).await {
        Ok(config) => config,
        Err(error) => return Ok(Json(super::err_json(format!("restart refused: {error}")))),
    };
    if super::config::needs_full_restart_for_config(&state.config, &config) {
        return Ok(Json(json!({
            "ok": false,
            "kind": "full_restart_required",
            "error": "A startup-only setting changed (panel listener, session-key source, auth.users_file or logging settings); a worker restart cannot apply it. Restart the full qeli process.",
        })));
    }
    if let Err(error) = validate_restart_candidate(&config, |config| observed.check(config)) {
        return Ok(Json(super::err_json(error)));
    }
    match &state.worker_tx {
        Some(tx) => {
            if tx.try_send(WorkerCmd::Restart).is_err() {
                return Ok(Json(super::err_json(
                    "supervisor command queue is busy or closed; retry the restart",
                )));
            }
            Ok(Json(json!({"ok": true, "message": "worker restarting"})))
        }
        None => Ok(Json(super::err_json(
            "server is not running under a supervisor",
        ))),
    }
}

/// FULL process restart via systemd — needed for startup-only settings the worker
/// cannot apply (panel listener, session-key source, auth.users_file and logging). The panel
/// session survives when `web.persist_session_key` is on (the default).
///
/// Before firing, we PRE-FLIGHT so a restart that cannot work fails *loudly* with an
/// actionable message instead of a fire-and-forget that logs an error nobody reads (the
/// panel used to report success regardless — the change then simply never applied).
/// Rejected up-front: no systemd (a container or a hand-run process), a missing `systemctl`,
/// or a non-root service that polkit actually refuses to authorise. We ask polkit instead of
/// checking `/etc/polkit-1/rules.d/49-qeli.rules`: on Ubuntu that directory is commonly mode
/// 0750 root:polkitd, so `Path::exists()` from the `qeli` service user returns false even when
/// the installed rule is valid and systemd accepts the restart.
/// Only when the pre-flight passes do we schedule the real restart (returned FIRST, the
/// `systemctl restart` runs ~0.8 s later so the browser gets the reply before we're replaced).
/// Outcome of the last DETACHED restart, when it failed.
///
/// The reply to `full_restart` is necessarily sent BEFORE the restart runs — systemd
/// replaces this process, so there is no later moment to answer from. That made every
/// outcome look like `ok: true`, including the ones where `systemctl` refused and the
/// server kept running the old config; the failure reached the journal only.
///
/// This closes the loop without changing that design: on SUCCESS the process is replaced
/// and this cell dies with it (the panel reconnecting IS the success signal), while on
/// FAILURE the process survives, so the message persists and `/api/status` reports it on
/// the panel's next poll. (S-18)
static LAST_RESTART_FAILURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn record_restart_failure(msg: String) {
    if let Ok(mut g) = LAST_RESTART_FAILURE.lock() {
        *g = Some(msg);
    }
}

/// The pending restart-failure message, if the last requested restart never happened.
pub fn last_restart_failure() -> Option<String> {
    LAST_RESTART_FAILURE.lock().ok().and_then(|g| g.clone())
}

pub async fn full_restart(
    State(state): State<Arc<ServerState>>,
    _guard: auth::AuthGuard,
) -> Result<Json<Value>, AuthError> {
    match preflight_restart(&state).await {
        Ok(guard) => drop(guard),
        Err(error) => return Ok(Json(super::err_json(error))),
    }
    // A fresh attempt supersedes any stale failure from a previous one.
    if let Ok(mut g) = LAST_RESTART_FAILURE.lock() {
        *g = None;
    }
    let unit = detect_systemd_unit().unwrap_or_else(|| "qeli.service".to_string());

    match restart_capability(&unit).await {
        RestartReady::Ok => {
            let unit_bg = unit.clone();
            let state_bg = state.clone();
            tokio::spawn(async move {
                // Let the HTTP response flush before systemd stops us.
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                // A config edit or network change during the response delay must not kill
                // the healthy process. Keep writes excluded through command dispatch.
                let _write_guard = match preflight_restart(&state_bg).await {
                    Ok(guard) => guard,
                    Err(error) => {
                        log::error!("full-restart: {error}");
                        record_restart_failure(error);
                        return;
                    }
                };
                match crate::hook_process::run_output(
                    tokio::process::Command::new("systemctl").args(["restart", &unit_bg]),
                    tokio::time::Instant::now() + std::time::Duration::from_secs(15),
                    64 * 1024,
                )
                .await
                .map(|output| output.status)
                {
                    Ok(s) if s.success() => {} // being replaced — nothing more to do
                    Ok(s) => {
                        log::error!("full-restart: `systemctl restart {unit_bg}` exited with {s}");
                        record_restart_failure(format!(
                            "`systemctl restart {unit_bg}` exited with {s} — the server is still \
                             running the OLD configuration. Restart it manually."
                        ));
                    }
                    Err(e) => {
                        log::error!(
                            "full-restart: systemctl result unknown ({e}); check {unit_bg} before retrying"
                        );
                        record_restart_failure(format!(
                            "could not confirm `systemctl restart {unit_bg}` ({e}). The request may \
                             already be queued in systemd; check the service status and journal before retrying."
                        ));
                    }
                }
            });
            Ok(Json(json!({
                "ok": true,
                "unit": unit,
                "message": "full restart requested — the panel will reconnect in a few seconds"
            })))
        }
        RestartReady::PolkitDenied { unit, user } => Ok(Json(json!({
            "ok": false,
            "kind": "polkit_missing",
            "unit": unit,
            "user": user,
            "install_cmd": "sudo qeli install-polkit",
            "error": format!(
                "The panel runs as '{user}', and polkit did not authorise it to restart {unit}. \
                 The rule may be missing, invalid, or target a different service user/unit. \
                 Install or refresh it as root — run `sudo qeli install-polkit --user {user} \
                 --unit {unit}` — then click Apply & Restart again. Verify independently with: \
                 `sudo -u {user} systemctl restart {unit}`. To apply changes right now: \
                 `sudo systemctl restart {unit}`."
            ),
        }))),
        RestartReady::NoSystemd { container } => Ok(Json(json!({
            "ok": false,
            "kind": "no_systemd",
            "container": container,
            "unit": unit,
            "error": if container {
                "This server runs inside a container — systemctl is not available here, so \
                 \"Apply & Restart\" cannot restart the process. Profile / data-plane changes apply \
                 with the in-process worker restart. To change startup-only settings \
                 (panel listener, session-key source, auth.users_file or logging settings), recreate the \
                 container (e.g. `docker restart <name>`) after saving."
                    .to_string()
            } else {
                "Not running under systemd — the panel cannot restart the process itself. Profile / \
                 data-plane changes apply with the worker restart; for startup-only settings \
                 restart the qeli process the way you started it."
                    .to_string()
            },
        }))),
        RestartReady::NoSystemctl => Ok(Json(json!({
            "ok": false,
            "kind": "no_systemctl",
            "unit": unit,
            "error": format!(
                "`systemctl` is not installed, so \"Apply & Restart\" cannot restart {unit}. \
                 Restart the qeli process the way your init system does; profile / data-plane \
                 changes can be applied with the worker restart."
            ),
        }))),
    }
}

/// Whether a full (systemd) restart from the panel can actually succeed — so `full_restart`
/// can return a precise, actionable reason instead of silently failing.
enum RestartReady {
    /// systemd present and we may manage the unit (root, or polkit authorises it).
    Ok,
    /// Not under systemd — a container (docker/podman/lxc) or a hand-run process.
    NoSystemd { container: bool },
    /// `systemctl` binary absent.
    NoSystemctl,
    /// systemd + non-root user, and polkit denied managing this unit.
    PolkitDenied { unit: String, user: String },
}

async fn restart_capability(unit: &str) -> RestartReady {
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        // The canonical sd_booted() check: this directory exists iff booted under systemd.
        return RestartReady::NoSystemd {
            container: in_container(),
        };
    }
    if !["/usr/bin/systemctl", "/bin/systemctl"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        return RestartReady::NoSystemctl;
    }
    // Root manages units directly. For an unprivileged service, ask polkit about the
    // exact action and unit instead of trying to stat its root-only rules directory.
    if unsafe { libc::geteuid() } == 0 {
        return RestartReady::Ok;
    }

    match polkit_restart_authorization(unit).await {
        PolkitAuthorization::Authorized => RestartReady::Ok,
        PolkitAuthorization::Denied => RestartReady::PolkitDenied {
            unit: unit.to_string(),
            user: effective_username(),
        },
        PolkitAuthorization::Unknown => {
            // `pkcheck` is optional and its own operational failure says nothing about
            // whether systemd will authorise the real request. Do not recreate the old
            // false-negative with a different probe: let systemctl make the authoritative
            // decision. A failure is retained by LAST_RESTART_FAILURE and shown by status.
            log::warn!(
                "full-restart: could not preflight polkit authorization for {unit}; \
                 deferring the authorization decision to systemctl"
            );
            RestartReady::Ok
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolkitAuthorization {
    Authorized,
    Denied,
    Unknown,
}

fn classify_pkcheck_exit(code: Option<i32>) -> PolkitAuthorization {
    match code {
        Some(0) => PolkitAuthorization::Authorized,
        // pkcheck documents 1 as an outright denial, 2 as authorization unavailable
        // without an authentication agent / user interaction, and 3 as a dismissed
        // authentication request. A headless system service cannot proceed in any of
        // those cases. 126/127 mean the probe itself was malformed or failed.
        Some(1..=3) => PolkitAuthorization::Denied,
        _ => PolkitAuthorization::Unknown,
    }
}

fn pkcheck_process_subject(stat: &str, pid: u32, uid: u32) -> Option<String> {
    // /proc/<pid>/stat field 22 is the process start time. The command in field 2 is
    // parenthesized and may contain spaces or ')', so split only after its final ')'.
    // Starting at field 3 (`state`), starttime is token index 19.
    let after_command = stat.rsplit_once(')')?.1;
    let start_time = after_command.split_whitespace().nth(19)?;
    Some(format!("{pid},{start_time},{uid}"))
}

/// Ask polkit whether this exact qeli process may manage this exact systemd unit.
/// No user interaction is requested: the service has no terminal or authentication agent.
async fn polkit_restart_authorization(unit: &str) -> PolkitAuthorization {
    let Some(pkcheck) = ["/usr/bin/pkcheck", "/bin/pkcheck"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
    else {
        return PolkitAuthorization::Unknown;
    };

    // The full pid,start-time,uid form avoids the PID-reuse race explicitly warned about
    // in pkcheck(1). If procfs is unexpectedly unavailable, treat the probe as unknown and
    // let the real systemctl request decide instead of falling back to the racy short form.
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return PolkitAuthorization::Unknown;
    };
    let Some(subject) =
        pkcheck_process_subject(&stat, std::process::id(), unsafe { libc::geteuid() })
    else {
        return PolkitAuthorization::Unknown;
    };
    let mut command = tokio::process::Command::new(pkcheck);
    command
        .args([
            "--action-id",
            "org.freedesktop.systemd1.manage-units",
            "--process",
            &subject,
            "--detail",
            "unit",
            unit,
            "--detail",
            "verb",
            "restart",
        ])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let check = command.status();
    match tokio::time::timeout(std::time::Duration::from_secs(3), check).await {
        Ok(Ok(status)) => classify_pkcheck_exit(status.code()),
        Ok(Err(error)) => {
            log::warn!("full-restart: could not execute {pkcheck}: {error}");
            PolkitAuthorization::Unknown
        }
        Err(_) => {
            log::warn!("full-restart: {pkcheck} timed out while checking {unit}");
            PolkitAuthorization::Unknown
        }
    }
}

/// Best-effort container detection: the Docker/Podman marker files, or a container manager
/// in PID 1's cgroup. (Under systemd this is normally false; kept for LXC-system-container
/// edge cases where /run/systemd/system exists but systemctl still cannot reach the host.)
fn in_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup")
        .map(|s| {
            s.contains("docker")
                || s.contains("containerd")
                || s.contains("/lxc")
                || s.contains("libpod")
        })
        .unwrap_or(false)
}

/// getpwuid(geteuid()).pw_name — the user this process runs as (the polkit rule's subject).
/// Falls back to the numeric euid if the lookup fails.
fn effective_username() -> String {
    unsafe {
        let uid = libc::geteuid();
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            return uid.to_string();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

/// Best-effort: this process's own systemd unit from its cgroup, so the restart targets the
/// right unit whatever it is named (`qeli.service`, `qeli-server.service`, …). `None` when not
/// run under systemd (caller falls back to `qeli.service`).
fn detect_systemd_unit() -> Option<String> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // e.g. "0::/system.slice/qeli.service" → the last `*.service` path component.
    cg.lines()
        .filter_map(|l| l.rsplit('/').next())
        .find(|c| c.ends_with(".service"))
        .map(|c| c.to_string())
}

#[cfg(test)]
mod tests {
    use super::{classify_pkcheck_exit, pkcheck_process_subject, PolkitAuthorization};

    #[test]
    fn pkcheck_exit_status_is_interpreted_without_false_denials() {
        assert_eq!(
            classify_pkcheck_exit(Some(0)),
            PolkitAuthorization::Authorized
        );
        assert_eq!(classify_pkcheck_exit(Some(1)), PolkitAuthorization::Denied);
        assert_eq!(classify_pkcheck_exit(Some(2)), PolkitAuthorization::Denied);
        assert_eq!(classify_pkcheck_exit(Some(3)), PolkitAuthorization::Denied);
        assert_eq!(
            classify_pkcheck_exit(Some(126)),
            PolkitAuthorization::Unknown
        );
        assert_eq!(
            classify_pkcheck_exit(Some(127)),
            PolkitAuthorization::Unknown
        );
        assert_eq!(classify_pkcheck_exit(None), PolkitAuthorization::Unknown);
    }

    #[test]
    fn pkcheck_subject_uses_pid_start_time_and_uid() {
        let stat = "4242 (qeli ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
        assert_eq!(
            pkcheck_process_subject(stat, 4242, 991),
            Some("4242,987654,991".to_string())
        );
    }
}

#[cfg(test)]
mod restart_validation_tests {
    use super::*;
    #[tokio::test]
    async fn full_restart_refuses_invalid_disk_config_before_systemd_dispatch() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-full-restart-validation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.conf");
        std::fs::write(&path, "not valid INI").unwrap();
        let state =
            crate::server::test_api_state(crate::config::server::ServerConfig::default(), &path);
        let response = full_restart(State(state), auth::AuthGuard).await.unwrap().0;
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("restart refused"),
            "{response}"
        );
        assert!(response.get("unit").is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn full_restart_refuses_untrusted_custom_users_path_before_dispatch() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "qeli-full-restart-users-trust-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.conf");
        let mut candidate = crate::config::server::ServerConfig::default();
        candidate
            .profiles
            .push(crate::config::server::ProfileConfig::baseline());
        let users = dir.join("other-users.conf");
        candidate.auth.users_file = users.to_string_lossy().into_owned();
        std::fs::write(&path, candidate.to_ini_string()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let state =
            crate::server::test_api_state(crate::config::server::ServerConfig::default(), &path);
        let response = full_restart(State(state), auth::AuthGuard).await.unwrap().0;
        assert_eq!(response["ok"], false, "{response}");
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("auth.users_file"),
            "{response}"
        );
        assert!(response.get("unit").is_none());
        assert!(!users.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn worker_restart_refuses_changed_users_file_before_dispatch() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-worker-restart-users-path-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("server.conf");
        let mut startup = crate::config::server::ServerConfig::default();
        startup
            .profiles
            .push(crate::config::server::ProfileConfig::baseline());
        let mut candidate = startup.clone();
        candidate.auth.users_file = dir.join("other-users.conf").to_string_lossy().into_owned();
        std::fs::write(&path, candidate.to_ini_string()).unwrap();
        let state = crate::server::test_api_state(startup, &path);
        let response = restart(State(state), auth::AuthGuard).await.unwrap().0;
        assert_eq!(response["kind"], "full_restart_required", "{response}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn full_restart_refuses_a_panel_that_cannot_start() {
        let mut config = crate::config::server::ServerConfig::default();
        config.web.enabled = true;
        let error = validate_full_restart_panel(&config).unwrap_err();
        assert!(error.contains("web.password_hash"), "{error}");

        config.web.insecure_no_auth = true;
        config.web.tls = true;
        let dir = std::env::temp_dir().join(format!(
            "qeli-full-restart-tls-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, b"not a certificate").unwrap();
        std::fs::write(&key, b"not a private key").unwrap();
        config.web.tls_cert = cert.to_string_lossy().into_owned();
        config.web.tls_key = key.to_string_lossy().into_owned();
        let error = validate_full_restart_panel(&config).unwrap_err();
        assert!(error.contains("panel TLS"), "{error}");
        assert!(error.contains("no certificates"), "{error}");
        assert_eq!(std::fs::read(&cert).unwrap(), b"not a certificate");

        config.web.enabled = false;
        validate_full_restart_panel(&config).expect("disabled panel ignores dormant TLS files");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restart_requires_valid_profiles_users_and_host_networking() {
        let empty = crate::config::server::ServerConfig::default();
        let error = validate_restart_candidate(&empty, |_| {
            panic!("must reject empty config before host preflight")
        })
        .unwrap_err();
        assert!(error.contains("no profiles defined"), "{error}");
        let mut config = crate::config::parse_server_config("[profile:p]\nbind.port=443\ntun.name=vpn0\ntun.address=10.0.0.1\npool.cidr=10.0.0.0/24\n").unwrap();
        let path =
            std::env::temp_dir().join(format!("qeli-restart-users-{}.conf", std::process::id()));
        config.auth.users_file = path.to_string_lossy().into_owned();
        std::fs::write(&path, "").unwrap();
        assert!(validate_restart_candidate(&config, |_| Ok(())).is_ok());
        let error =
            validate_restart_candidate(&config, |_| anyhow::bail!("fixture host collision"))
                .unwrap_err();
        assert!(error.contains("fixture host collision"), "{error}");
        std::fs::write(
            &path,
            "[user:alice]\npassword_hash=fixture\ngroup=missing\n",
        )
        .unwrap();
        let error =
            validate_restart_candidate(&config, |_| panic!("must reject users first")).unwrap_err();
        assert!(error.contains("group 'missing'"), "{error}");
        config.profiles[0].bind.port = 0;
        let error = validate_restart_candidate(&config, |_| panic!("must reject config first"))
            .unwrap_err();
        assert!(error.contains("server config is invalid"), "{error}");
        std::fs::remove_file(path).unwrap();
    }
}
