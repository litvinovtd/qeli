//! Lifecycle hooks (`post_up` / `post_down`) — a configured shell command run at
//! tunnel start and clean stop, on both the client and the server.
//!
//! **SECURITY.** A hook runs an arbitrary command as the process user (typically
//! root). It is therefore honoured ONLY from a *trusted* local config file:
//!  * [`config_is_trusted`] refuses to run hooks when the config file is group- or
//!    world-writable (anyone who can edit it would otherwise run code as us);
//!  * the web panel / API must NEVER write these fields (see `web/api/config.rs`),
//!    so a panel compromise can't turn into remote code execution.
//!
//! A failing hook logs a warning but does not abort the tunnel. Each hook has a
//! hard timeout (the child is killed on drop), so a hung command can't wedge
//! startup or shutdown.

#[cfg(target_os = "linux")]
use std::time::Duration;

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

/// Reject hooks from a config file others can write (privilege-escalation guard).
/// `Ok(())` = safe to run hooks; `Err(reason)` = refuse. Non-Linux: always `Ok`
/// (hooks are a Linux-only feature).
#[cfg(target_os = "linux")]
pub fn config_is_trusted(path: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // Judge the file we can actually OPEN, and refuse a symlink outright.
    //
    // This used to be `std::fs::metadata(path)` — a lookup by NAME, following symlinks, and
    // a SECOND trip to the filesystem: the config contents were read (and the hook strings
    // parsed out of them) well before this ran. Anything that could swap the path between
    // those two calls decided what root executed. The window is not theoretical — the
    // scenario the comment below describes, a machine-generated config in a directory the
    // service account can write, is exactly where a rename loop wins: put your own file
    // there with `post_up = curl … | sh`, wait for the read, put the root-owned 0600
    // original back before the stat.
    //
    // Opening with O_NOFOLLOW and stat'ing THAT descriptor removes the second lookup and
    // the symlink. A truly race-free design would read the contents from this same fd; that
    // is a larger change to the config loader, and closing the symlink + double-lookup holes
    // is the part that matters most. (Audit 2026-08-04.)
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("cannot open config '{path}' for trust check: {e}"))?;
    let md = f
        .metadata()
        .map_err(|e| format!("cannot stat config '{path}': {e}"))?;
    if !md.is_file() {
        return Err(format!(
            "config '{path}' is not a regular file; refusing to run hooks"
        ));
    }
    // Group- or world-writable (0o022) means a non-owner could inject a hook.
    if md.mode() & 0o022 != 0 {
        return Err(format!(
            "config '{path}' is group/world-writable (mode {:o}); refusing to run hooks — `chmod 600 {path}`",
            md.mode() & 0o777
        ));
    }
    // Mode alone is not trust. A hook runs as THIS process (root under systemd/procd),
    // so a config owned by anyone else is a config someone else can rewrite at will —
    // 0600 owned by an unprivileged account passes the check above and still hands
    // that account root. This matters for machine-generated configs in particular:
    // the OpenWrt init script renders /var/run/qeli/client.conf at 0600, and the only
    // thing that makes it trustworthy is that root wrote it.
    let uid = unsafe { libc::geteuid() };
    if md.uid() != uid && md.uid() != 0 {
        return Err(format!(
            "config '{path}' is owned by uid {} (we run as {}); refusing to run hooks — \
             a config we do not own can be rewritten by someone else",
            md.uid(),
            uid
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn config_is_trusted(_path: &str) -> Result<(), String> {
    Ok(())
}

/// Result of one lifecycle-hook invocation. Callers currently treat hooks as best-effort,
/// but the typed result keeps tests and future policy code from parsing log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookStatus {
    Skipped,
    Success,
    ExitFailure,
    SpawnFailure,
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

#[cfg(target_os = "linux")]
fn logged_output(stdout: &[u8], stderr: &[u8]) -> String {
    // A hook is trusted code, but an accidentally noisy command must not emit an unbounded
    // single log record. Keep the tail, where shell diagnostics normally live.
    const MAX_LOG_BYTES: usize = 16 * 1024;
    let joined = [stdout, b" ", stderr].concat();
    let truncated = joined.len() > MAX_LOG_BYTES;
    let kept = if truncated {
        &joined[joined.len() - MAX_LOG_BYTES..]
    } else {
        &joined
    };
    let text = String::from_utf8_lossy(kept).trim().to_string();
    if truncated {
        format!("[output truncated to last {MAX_LOG_BYTES} bytes] {text}")
    } else {
        text
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
    // Best-effort warning: the config file is verified 0600 (config_is_trusted), but the
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
        .args(positional_arguments)
        .kill_on_drop(true);
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

    match tokio::time::timeout(HOOK_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => {
            let tail = logged_output(&output.stdout, &output.stderr);
            if output.status.success() {
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
        Ok(Err(error)) => {
            log::warn!("hook[{label}]: failed to spawn /bin/sh: {error}");
            HookStatus::SpawnFailure
        }
        Err(_) => {
            log::warn!(
                "hook[{label}]: timed out after {}s -- killed",
                HOOK_TIMEOUT.as_secs()
            );
            HookStatus::TimedOut
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
