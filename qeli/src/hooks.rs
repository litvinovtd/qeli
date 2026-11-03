//! Lifecycle hooks (`post_up` / `post_down`) — a configured shell command run at
//! tunnel start and clean stop, on both the client and the server.
//!
//! **SECURITY.** A hook runs an arbitrary command as the process user (typically
//! root). It is therefore honoured ONLY from a *trusted* local config file:
//!  * the runtime config loader checks the owner/mode of the SAME opened file that
//!    supplies the parsed bytes; an untrusted snapshot never gains command permission
//!    from a later replacement of its pathname;
//!  * the web panel / API must NEVER write these fields (see `web/api/config.rs`),
//!    so a panel compromise can't turn into remote code execution.
//!
//! A failing hook logs a warning but does not abort the tunnel. Each hook has a
//! 30-second execution/output deadline. Linux timeout/cancellation kills the isolated
//! process group; bounded streaming tails prevent noisy hooks from exhausting memory.

#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
#[path = "hooks/worker.rs"]
mod worker;

/// Hard timeout for a single hook invocation.
#[cfg(target_os = "linux")]
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Filesystem paths a hook command would actually execute: the first token, plus — when
/// that token is a known interpreter — the script it is told to run.
///
/// Used for two purposes that must agree: the world-writable warning below, and the
/// restore vetting in `web/api/backup.rs`, which refuses to overwrite a script an existing
/// hook points at. Not cfg-gated: the restore path needs it on every build.
pub fn script_paths(cmd: &str) -> Vec<String> {
    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "python", "python2", "python3",
        "perl", "ruby", "node", "lua", "php", "awk",
    ];
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    let mut out: Vec<String> = Vec::new();
    let Some(&first) = toks.first() else {
        return out;
    };
    out.push(first.to_string());
    let base = first.rsplit('/').next().unwrap_or(first);
    if INTERPRETERS.contains(&base) {
        // First non-flag argument is the script path. `-c` takes inline code rather than a
        // file, so stop there instead of treating a fragment of shell as a path.
        let mut i = 1;
        while i < toks.len() && toks[i].starts_with('-') {
            if toks[i] == "-c" {
                return out;
            }
            i += 1;
        }
        if let Some(&script) = toks.get(i) {
            if !script.starts_with('-') {
                out.push(script.to_string());
            }
        }
    }
    out
}

/// Result of one lifecycle-hook invocation. Callers currently treat hooks as best-effort,
/// but the typed result keeps tests and future policy code from parsing log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Skipped,
    Success,
    ExitFailure,
    SpawnFailure,
    IoFailure,
    TimedOut,
}

#[cfg(target_os = "linux")]
struct HookContextFile {
    path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl HookContextFile {
    fn create(contents: &str) -> std::io::Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        // NetworkPlan is already bounded (routes/DNS/log lines). Keep a second defensive
        // ceiling here because this file is generated immediately before a privileged hook.
        const MAX_CONTEXT_BYTES: usize = 1024 * 1024;
        if contents.len() > MAX_CONTEXT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("hook context exceeds {MAX_CONTEXT_BYTES} bytes"),
            ));
        }

        for _ in 0..16 {
            let path = std::path::PathBuf::from(format!(
                "/tmp/qeli-hook-{}-{:016x}.json",
                std::process::id(),
                rand::random::<u64>()
            ));
            let opened = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path);
            match opened {
                Ok(mut file) => {
                    let context = Self { path };
                    // `context` removes the partially-written private file if either write fails.
                    file.write_all(contents.as_bytes())
                        .and_then(|_| file.write_all(b"\n"))?;
                    return Ok(context);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique hook context file",
        ))
    }
}

#[cfg(target_os = "linux")]
impl Drop for HookContextFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                log::warn!("hook context cleanup '{}': {error}", self.path.display());
            }
        }
    }
}

/// Run a hook through `/bin/sh -c` with an environment snapshot, optional positional
/// parameters and an optional JSON context document.
///
/// Positional parameters are installed as shell `$1`, `$2`, ... without concatenating them
/// into the command string. A script command can forward them with `"$@"`. The JSON file is
/// mode 0600, exists only while the hook runs, and is exposed through both
/// `QELI_CONTEXT_FILE` and the compatibility name `QELI_NETWORK_PLAN_FILE`.
#[cfg(target_os = "linux")]
pub async fn run_with_context(
    label: &str,
    cmd: &str,
    env: &[(String, String)],
    positional_arguments: &[String],
    context_json: Option<&str>,
) -> HookStatus {
    if cmd.trim().is_empty() {
        return HookStatus::Skipped;
    }
    let label = label.to_owned();
    let worker_label = label.clone();
    let cmd = cmd.to_owned();
    let env = env.to_vec();
    let arguments = positional_arguments.to_vec();
    let context = context_json.map(str::to_owned);
    match worker::run(move |stop| async move {
        run_owned(
            &worker_label,
            &cmd,
            &env,
            &arguments,
            context.as_deref(),
            stop,
        )
        .await
    })
    .await
    {
        Ok(status) => status,
        Err(error) => {
            log::warn!("hook[{label}]: worker failed: {error}");
            HookStatus::IoFailure
        }
    }
}

#[cfg(target_os = "linux")]
async fn run_owned(
    label: &str,
    cmd: &str,
    env: &[(String, String)],
    positional_arguments: &[String],
    context_json: Option<&str>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> HookStatus {
    if !matches!(
        stop.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ) {
        return HookStatus::Skipped;
    }
    // Best-effort warning: callers authorize the loaded config snapshot, but the
    // SCRIPT it points to is not. If the command is a bare path to an existing
    // world-writable file, a local non-owner could swap its contents -- flag it.
    {
        use std::os::unix::fs::MetadataExt;
        // The first token AND, when it is a known interpreter, the script it runs:
        // `bash /opt/hook.sh` used to stat only `bash` -- a root-owned system binary that is
        // never world-writable -- so the file that actually executes went unexamined.
        for path in script_paths(cmd) {
            if let Ok(md) = std::fs::metadata(&path) {
                if md.is_file() && md.mode() & 0o002 != 0 {
                    log::warn!(
                        "hook[{label}]: script '{path}' is world-writable (mode {:o}) -- a local user could alter what runs as root",
                        md.mode() & 0o777
                    );
                }
            }
        }
    }

    let context_file = match context_json {
        Some(json) => match HookContextFile::create(json) {
            Ok(file) => Some(file),
            Err(error) => {
                log::warn!("hook[{label}]: could not create the JSON context file: {error}");
                None
            }
        },
        None => None,
    };

    log::info!("hook[{label}]: running");
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(cmd)
        // POSIX sh assigns the first word after the command to $0. A stable synthetic $0
        // means the first real value is always $1 (interface) rather than disappearing.
        .arg("qeli-hook")
        .args(positional_arguments);
    for (key, value) in env {
        command.env(key, value);
    }
    let context_path = context_file
        .as_ref()
        .map(|file| file.path.to_string_lossy().into_owned())
        .unwrap_or_default();
    command
        .env("QELI_CONTEXT_FILE", &context_path)
        .env("QELI_NETWORK_PLAN_FILE", &context_path);

    match crate::hook_process::run_cancellable(command, HOOK_TIMEOUT, async {
        let _ = stop.await;
    })
    .await
    {
        Ok(None) => HookStatus::Skipped,
        Ok(Some(output)) => {
            let tail = output.logged_output();
            if output.timed_out {
                log::warn!("hook[{label}]: timed out after {}s -- process group termination requested; leader reaped -- {tail}", HOOK_TIMEOUT.as_secs());
                HookStatus::TimedOut
            } else if output.status.success() {
                if tail.is_empty() {
                    log::info!("hook[{label}]: ok");
                } else {
                    log::info!("hook[{label}]: ok -- {tail}");
                }
                HookStatus::Success
            } else {
                log::warn!("hook[{label}]: exited {} -- {tail}", output.status);
                HookStatus::ExitFailure
            }
        }
        Err(crate::hook_process::RunError::Spawn(error)) => {
            log::warn!("hook[{label}]: failed to spawn /bin/sh: {error}");
            HookStatus::SpawnFailure
        }
        Err(crate::hook_process::RunError::Io(error)) => {
            log::warn!("hook[{label}]: process I/O or cleanup failed: {error}");
            HookStatus::IoFailure
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_with_context(
    _label: &str,
    _cmd: &str,
    _env: &[(String, String)],
    _positional_arguments: &[String],
    _context_json: Option<&str>,
) -> HookStatus {
    HookStatus::Skipped
}

/// Compatibility wrapper used by server hooks. Client hooks use [`run_with_context`] to add
/// the complete authenticated NetworkPlan and lifecycle metadata.
pub async fn run(label: &str, cmd: &str, env: &[(&str, String)]) -> HookStatus {
    let owned = env
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect::<Vec<_>>();
    run_with_context(label, cmd, &owned, &[], None).await
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn context_file_is_private_and_removed_on_drop() {
        let path = {
            let context = HookContextFile::create(r#"{"hook_api":1}"#).unwrap();
            let metadata = std::fs::metadata(&context.path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                std::fs::read_to_string(&context.path).unwrap(),
                "{\"hook_api\":1}\n"
            );
            context.path.clone()
        };
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn context_and_positional_parameters_reach_the_shell_without_interpolation() {
        let environment = vec![
            ("QELI_IFNAME".to_string(), "vpn9".to_string()),
            ("QELI_GATEWAY".to_string(), "10.9.0.1".to_string()),
        ];
        let arguments = vec!["vpn9".to_string(), "10.9.0.1".to_string()];
        let command = concat!(
            "test \"$1\" = \"$QELI_IFNAME\" && ",
            "test \"$2\" = \"$QELI_GATEWAY\" && ",
            "test -r \"$QELI_CONTEXT_FILE\" && ",
            "test \"$QELI_CONTEXT_FILE\" = \"$QELI_NETWORK_PLAN_FILE\" && ",
            "grep -q '\"hook_api\":1' \"$QELI_CONTEXT_FILE\""
        );
        assert_eq!(
            run_with_context(
                "test",
                command,
                &environment,
                &arguments,
                Some(r#"{"hook_api":1}"#),
            )
            .await,
            HookStatus::Success
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "hooks/io_tests.rs"]
mod io_tests;
