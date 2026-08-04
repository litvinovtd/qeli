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

/// Run a hook command via `/bin/sh -c`, with the given environment, a hard
/// timeout, and captured output. Best-effort: failures are logged, never fatal.
/// No-op on a blank command or on non-Linux targets.
#[cfg(target_os = "linux")]
pub async fn run(label: &str, cmd: &str, env: &[(&str, String)]) {
    if cmd.trim().is_empty() {
        return;
    }
    // Best-effort warning: the config file is verified 0600 (config_is_trusted), but the
    // SCRIPT it points to is not. If the command is a bare path to an existing
    // world-writable file, a local non-owner could swap its contents — flag it.
    {
        use std::os::unix::fs::MetadataExt;
        // The first token AND, when it is a known interpreter, the script it runs:
        // `bash /opt/hook.sh` used to stat only `bash` — a root-owned system binary that is
        // never world-writable — so the file that actually executes went unexamined, which
        // is exactly the case this warning exists for. (S-11)
        for path in script_paths(cmd) {
            if let Ok(md) = std::fs::metadata(&path) {
                if md.is_file() && md.mode() & 0o002 != 0 {
                    log::warn!(
                        "hook[{label}]: script '{path}' is world-writable (mode {:o}) — a local user could alter what runs as root",
                        md.mode() & 0o777
                    );
                }
            }
        }
    }
    log::info!("hook[{label}]: running");
    let mut c = tokio::process::Command::new("/bin/sh");
    c.arg("-c").arg(cmd).kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    match tokio::time::timeout(HOOK_TIMEOUT, c.output()).await {
        Ok(Ok(o)) => {
            let so = String::from_utf8_lossy(&o.stdout);
            let se = String::from_utf8_lossy(&o.stderr);
            let tail = format!("{} {}", so.trim(), se.trim());
            if o.status.success() {
                if tail.trim().is_empty() {
                    log::info!("hook[{label}]: ok");
                } else {
                    log::info!("hook[{label}]: ok — {}", tail.trim());
                }
            } else {
                log::warn!("hook[{label}]: exited {} — {}", o.status, tail.trim());
            }
        }
        Ok(Err(e)) => log::warn!("hook[{label}]: failed to spawn /bin/sh: {e}"),
        Err(_) => log::warn!(
            "hook[{label}]: timed out after {}s — killed",
            HOOK_TIMEOUT.as_secs()
        ),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_label: &str, _cmd: &str, _env: &[(&str, String)]) {}
