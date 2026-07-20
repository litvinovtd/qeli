//! Client DNS management with crash-safe restore.
//!
//! The hard requirement: *never* leave the system pointing at the tunnel
//! resolver after the tunnel is gone. The previous implementation broke in
//! four ways — it re-backed-up its own generated file on reconnect (losing the
//! real original), it `rename`d the backup away (so a second restore was a
//! no-op), it clobbered the `/etc/resolv.conf` symlink that systemd-resolved /
//! NetworkManager rely on, and it did nothing on SIGKILL/crash.
//!
//! Algorithm:
//!   * The original `/etc/resolv.conf` state (symlink target, file content, or
//!     absence) is captured **once** into a persistent backup under
//!     `/var/lib/qeli`. Capture is idempotent: if a backup already exists, or
//!     the current file is already ours, we do not overwrite the saved original.
//!   * `restore` rebuilds the exact original — recreating the symlink if it was
//!     one — and only deletes the backup after a successful restore.
//!   * `recover_stale` runs at startup and repairs leftovers from a previous
//!     crashed run, which is what makes the scheme robust against SIGKILL.
//!   * A SIGINT/SIGTERM handler (installed in client/mod.rs) calls `restore`
//!     before exit so `systemctl stop` is clean too.

use crate::config::client::ClientDnsConfig;
use serde::{Deserialize, Serialize};
use std::path::Path;

const RESOLV_PATH: &str = "/etc/resolv.conf";
const STATE_DIR: &str = "/var/lib/qeli";
const BACKUP_PATH: &str = "/var/lib/qeli/dns-backup.json";
/// Records the interface a `resolvectl` config was applied to, so it can be
/// reverted even on a later run.
const RESOLVECTL_MARK: &str = "/var/lib/qeli/dns-resolvectl";
const MARKER: &str = "# Managed by qeli VPN — original saved in /var/lib/qeli/dns-backup.json";

/// Snapshot of `/etc/resolv.conf` before qeli touched it.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct DnsBackup {
    /// "symlink" | "file" | "absent" | "managed-no-original"
    kind: String,
    /// Link target for `kind == "symlink"`.
    target: Option<String>,
    /// File content for `kind == "file"`.
    content: Option<String>,
    /// Unix permission bits for `kind == "file"`.
    mode: Option<u32>,
}

pub fn setup_dns_for_interface(
    config: &ClientDnsConfig,
    dns_server: &str,
    dns_port: &str,
    ifname: &str,
) -> anyhow::Result<()> {
    if config.mode != "tunnel" {
        return Ok(());
    }

    // Empty pushed DNS (the server's in-tunnel proxy is disabled) → fall back to
    // the client's own configured resolvers, so names still resolve instead of
    // pointing at a dead pushed address.
    let fallback;
    let dns_server = if dns_server.is_empty() {
        fallback = config
            .servers
            .first()
            .or_else(|| config.fallback_servers.first())
            .cloned()
            .unwrap_or_else(|| "1.1.1.1".to_string());
        log::info!("server pushed no DNS — using client resolver {}", fallback);
        fallback.as_str()
    } else {
        dns_server
    };

    // The DNS address is server-pushed (auth-OK JSON) and is written verbatim
    // into resolv.conf / handed to `resolvectl`. A malicious server could push
    // a bogus or option-looking value, so require a bare IP address before use;
    // on reject, leave the existing resolver untouched (safe no-op).
    if dns_server.starts_with('-') || dns_server.parse::<std::net::IpAddr>().is_err() {
        log::warn!("Ignoring invalid pushed DNS server: {}", dns_server);
        return Ok(());
    }

    let dns_addr = if dns_port == "53" {
        dns_server.to_string()
    } else {
        format!("{}#{}", dns_server, dns_port)
    };

    // Preferred path: systemd-resolved — but ONLY when it is actually the system
    // resolver (resolv.conf → stub). Otherwise `resolvectl dns` "succeeds" yet has
    // no effect (glibc reads real nameservers straight from resolv.conf), silently
    // leaking DNS; there we skip it and edit resolv.conf below instead. Per-link
    // config is auto-dropped when the tun is deleted, so it is inherently safe; we
    // still record the interface so `restore` can revert explicitly.
    if resolved_is_active() && try_resolvectl(config, ifname, &dns_addr) {
        log::info!("DNS set via resolvectl on {}: {}", ifname, dns_addr);
        let _ = ensure_state_dir();
        let _ = std::fs::write(RESOLVECTL_MARK, ifname);
        return Ok(());
    }

    log::warn!("resolvectl unavailable, falling back to /etc/resolv.conf");
    ensure_state_dir()?;
    capture_original(Path::new(RESOLV_PATH), Path::new(BACKUP_PATH), MARKER)?;
    write_managed_resolv(
        Path::new(RESOLV_PATH),
        dns_server,
        &config.search_domains,
        MARKER,
    )?;
    log::info!(
        "DNS set to {} (original saved at {})",
        dns_server,
        BACKUP_PATH
    );
    Ok(())
}

/// Restore DNS to its pre-tunnel state. Safe to call repeatedly and even when
/// nothing was changed (it becomes a no-op).
pub fn restore_dns() {
    // 1. Revert any resolvectl per-link config.
    if let Ok(ifname) = std::fs::read_to_string(RESOLVECTL_MARK) {
        let ifname = ifname.trim();
        if !ifname.is_empty() {
            let reverted = std::process::Command::new("resolvectl")
                .args(["revert", ifname])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if reverted {
                log::info!("Reverted resolvectl config on {}", ifname);
                let _ = std::fs::remove_file(RESOLVECTL_MARK);
            } else {
                // Keep the marker: dropping it discarded the only record that this link
                // still carries our DNS config, so nothing would ever retry — matching
                // how a failed resolv.conf restore keeps its backup.
                log::error!(
                    "Failed to revert resolvectl on {} — the tunnel's DNS may still be                      configured on that link; marker kept at {} for a later retry",
                    ifname,
                    RESOLVECTL_MARK
                );
            }
        } else {
            let _ = std::fs::remove_file(RESOLVECTL_MARK);
        }
    }

    // 2. Restore /etc/resolv.conf from the persistent backup.
    let backup = Path::new(BACKUP_PATH);
    if backup.exists() {
        match restore_resolv(Path::new(RESOLV_PATH), backup) {
            Ok(()) => {
                let _ = std::fs::remove_file(backup);
                log::info!("Restored /etc/resolv.conf to its original state");
            }
            Err(e) => {
                // Keep the backup so a later restore (or recover_stale) can retry.
                log::error!(
                    "Failed to restore /etc/resolv.conf: {} (backup kept at {})",
                    e,
                    BACKUP_PATH
                );
            }
        }
    }
}

/// Repair leftover state from a previous run that died without restoring
/// (SIGKILL, power loss, panic). Call once at client startup. If a backup or
/// resolvectl marker exists, the previous run did not clean up — restore now.
pub fn recover_stale() {
    let has_backup = Path::new(BACKUP_PATH).exists();
    let has_mark = Path::new(RESOLVECTL_MARK).exists();
    if has_backup || has_mark {
        log::warn!("Found stale DNS state from a previous run — restoring before connecting");
        restore_dns();
    }
}

// ── resolvectl ────────────────────────────────────────────────────────────

/// Is systemd-resolved actually the system resolver? Its per-link DNS only takes
/// effect if the box resolves THROUGH it — i.e. `/etc/resolv.conf` points at the
/// stub (`127.0.0.53`) or systemd's run dir. On a box where systemd-resolved is
/// merely installed (so `resolvectl` exists and returns success) but resolv.conf
/// lists real nameservers or is managed by something else, `resolvectl dns` is a
/// silent no-op and the tunnel's pushed DNS is ignored (a leak). When this returns
/// false we fall back to editing resolv.conf, which always takes effect.
fn resolved_is_active() -> bool {
    if let Ok(target) = std::fs::read_link(RESOLV_PATH) {
        let t = target.to_string_lossy();
        if t.contains("systemd/resolve") || t.contains("stub-resolv.conf") {
            return true;
        }
    }
    std::fs::read_to_string(RESOLV_PATH)
        .map(|c| c.contains("127.0.0.53"))
        .unwrap_or(false)
}

fn try_resolvectl(config: &ClientDnsConfig, ifname: &str, dns_addr: &str) -> bool {
    let ok = std::process::Command::new("resolvectl")
        .args(["dns", ifname, dns_addr])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        return false;
    }

    // Routing domains decide which queries go to this link. `~.` is the
    // catch-all that sends *all* DNS through the tunnel (full-tunnel mode).
    let mut domains: Vec<String> = config.search_domains.clone();
    if config.redirect_all {
        domains.push("~.".to_string());
    }
    if !domains.is_empty() {
        // The routing domains decide WHICH queries take this link — with `~.` they are
        // the difference between "all DNS goes through the tunnel" and "almost none does".
        // The result used to be discarded and the caller told the whole thing succeeded,
        // so a failure here meant queries kept going to the physical resolver while the
        // log said DNS was set: a silent leak in exactly the mode that exists to prevent
        // one. Report it, so the caller falls back to editing resolv.conf.
        let ok = std::process::Command::new("resolvectl")
            .args(["domain", ifname])
            .args(&domains)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            log::warn!(
                "resolvectl set the DNS server on {} but REFUSED the routing domains ({}) —                  queries would keep using the physical resolver; reverting and falling back                  to /etc/resolv.conf",
                ifname,
                domains.join(" ")
            );
            let _ = std::process::Command::new("resolvectl")
                .args(["revert", ifname])
                .output();
            return false;
        }
    }
    true
}

// ── /etc/resolv.conf capture & restore (pure file logic, path-injectable) ───

fn ensure_state_dir() -> anyhow::Result<()> {
    std::fs::create_dir_all(STATE_DIR)
        .map_err(|e| anyhow::anyhow!("cannot create state dir {}: {}", STATE_DIR, e))
}

/// Capture the current resolv.conf state into `backup`, exactly once.
///
/// Idempotent: if `backup` already exists we keep the previously-saved
/// original. If the current file is already ours (contains `marker`) but no
/// backup exists, we record `managed-no-original` so restore falls back to a
/// working public resolver rather than leaving a dangling tunnel address.
fn capture_original(resolv: &Path, backup: &Path, marker: &str) -> anyhow::Result<()> {
    if backup.exists() {
        return Ok(());
    }

    let snapshot = match std::fs::symlink_metadata(resolv) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = std::fs::read_link(resolv)
                .map_err(|e| anyhow::anyhow!("read_link {}: {}", resolv.display(), e))?;
            DnsBackup {
                kind: "symlink".into(),
                target: Some(target.to_string_lossy().into_owned()),
                content: None,
                mode: None,
            }
        }
        Ok(_meta) => {
            let content = std::fs::read_to_string(resolv).unwrap_or_default();
            if content.contains(marker) {
                // Our own file with no saved original — corrupted prior state.
                DnsBackup {
                    kind: "managed-no-original".into(),
                    target: None,
                    content: None,
                    mode: None,
                }
            } else {
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(resolv)
                        .ok()
                        .map(|m| m.permissions().mode())
                };
                #[cfg(not(unix))]
                let mode = None;
                DnsBackup {
                    kind: "file".into(),
                    target: None,
                    content: Some(content),
                    mode,
                }
            }
        }
        Err(_) => DnsBackup {
            kind: "absent".into(),
            target: None,
            content: None,
            mode: None,
        },
    };

    let json = serde_json::to_string(&snapshot)?;
    write_atomic(backup, json.as_bytes())?;
    Ok(())
}

/// Rebuild `/etc/resolv.conf` exactly as captured in `backup`.
fn restore_resolv(resolv: &Path, backup: &Path) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(backup)?;
    let snap: DnsBackup = serde_json::from_str(&json)?;

    match snap.kind.as_str() {
        "symlink" => {
            let target = snap
                .target
                .ok_or_else(|| anyhow::anyhow!("symlink backup without target"))?;
            // Remove whatever is there now (our regular file) then recreate the link.
            let _ = std::fs::remove_file(resolv);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, resolv)
                .map_err(|e| anyhow::anyhow!("recreate symlink -> {}: {}", target, e))?;
            Ok(())
        }
        "file" => {
            let content = snap.content.unwrap_or_default();
            write_atomic(resolv, content.as_bytes())?;
            #[cfg(unix)]
            if let Some(mode) = snap.mode {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(resolv, std::fs::Permissions::from_mode(mode));
            }
            Ok(())
        }
        "absent" => {
            // There was no resolv.conf before us; remove ours if still present.
            if resolv.exists() {
                let _ = std::fs::remove_file(resolv);
            }
            Ok(())
        }
        "managed-no-original" => {
            // We never knew the original. Leave a working public resolver
            // rather than a dead tunnel address.
            let content =
                "# Restored by qeli (original unknown)\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n";
            write_atomic(resolv, content.as_bytes())?;
            Ok(())
        }
        other => Err(anyhow::anyhow!("unknown backup kind: {}", other)),
    }
}

fn write_managed_resolv(
    resolv: &Path,
    dns_server: &str,
    search: &[String],
    marker: &str,
) -> anyhow::Result<()> {
    let mut content = String::new();
    content.push_str(marker);
    content.push('\n');
    content.push_str(&format!("nameserver {}\n", dns_server));
    if !search.is_empty() {
        content.push_str(&format!("search {}\n", search.join(" ")));
    }
    write_atomic(resolv, content.as_bytes())
}

/// Write a file atomically (tmp in the same dir, then rename). Thin wrapper over
/// [`crate::util::write_atomic`] — the single shared implementation (also used by
/// the server's config/users/key writes), which on Unix uses `O_EXCL` +
/// `O_NOFOLLOW` against symlink pre-planting (H-5) and preserves the target's
/// mode. Replacing a symlink with the renamed regular file is intentional —
/// `restore_resolv` recreates the link from the backup.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    crate::util::write_atomic(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Unique temp workspace per test.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "qeli-dns-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap()
    }

    #[test]
    fn capture_and_restore_regular_file() {
        let t = Tmp::new("file");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        std::fs::write(&resolv, "nameserver 192.168.1.1\n").unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        assert!(read(&resolv).contains("10.0.0.1"));
        assert!(read(&resolv).contains(MARKER));

        restore_resolv(&resolv, &backup).unwrap();
        assert_eq!(read(&resolv), "nameserver 192.168.1.1\n");
    }

    #[test]
    fn capture_is_idempotent_across_reconnects() {
        // The core bug: a second setup must NOT overwrite the saved original
        // with our generated file.
        let t = Tmp::new("reconnect");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        std::fs::write(&resolv, "nameserver 9.9.9.9\n").unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        // Reconnect: setup runs again while resolv.conf is already ours.
        capture_original(&resolv, &backup, MARKER).unwrap();

        restore_resolv(&resolv, &backup).unwrap();
        assert_eq!(
            read(&resolv),
            "nameserver 9.9.9.9\n",
            "original must survive reconnect"
        );
    }

    #[test]
    #[cfg(unix)]
    fn capture_and_restore_symlink() {
        let t = Tmp::new("symlink");
        let resolv = t.path("resolv.conf");
        let real = t.path("stub-resolv.conf");
        std::fs::write(&real, "nameserver 127.0.0.53\n").unwrap();
        std::os::unix::fs::symlink(&real, &resolv).unwrap();

        capture_original(&resolv, &t.path("backup.json"), MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        // Our write replaced the symlink with a regular file.
        assert!(!std::fs::symlink_metadata(&resolv)
            .unwrap()
            .file_type()
            .is_symlink());

        restore_resolv(&resolv, &t.path("backup.json")).unwrap();
        let meta = std::fs::symlink_metadata(&resolv).unwrap();
        assert!(meta.file_type().is_symlink(), "symlink must be recreated");
        assert_eq!(std::fs::read_link(&resolv).unwrap(), real);
    }

    #[test]
    fn absent_original_is_removed_on_restore() {
        let t = Tmp::new("absent");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        // No resolv.conf exists yet.
        capture_original(&resolv, &backup, MARKER).unwrap();
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();
        assert!(resolv.exists());

        restore_resolv(&resolv, &backup).unwrap();
        assert!(
            !resolv.exists(),
            "file we created must be removed when there was no original"
        );
    }

    #[test]
    fn managed_file_without_backup_restores_to_public_resolver() {
        // Simulates a crashed prior run: resolv.conf is ours, backup is gone.
        let t = Tmp::new("orphan");
        let resolv = t.path("resolv.conf");
        let backup = t.path("backup.json");
        write_managed_resolv(&resolv, "10.0.0.1", &[], MARKER).unwrap();

        capture_original(&resolv, &backup, MARKER).unwrap();
        let snap: DnsBackup = serde_json::from_str(&read(&backup)).unwrap();
        assert_eq!(snap.kind, "managed-no-original");

        restore_resolv(&resolv, &backup).unwrap();
        let restored = read(&resolv);
        assert!(
            restored.contains("1.1.1.1"),
            "must leave a working resolver, not the dead tunnel IP"
        );
        assert!(!restored.contains("10.0.0.1"));
    }
}

// ── fault injection: a PARTIAL resolvectl failure must not read as success ───
//
// `resolvectl dns` and `resolvectl domain` are two calls, and only the pair does what
// the mode promises: the server address decides WHERE queries go, the routing domains
// decide WHICH queries take that link. With `~.` the domains are the difference between
// "all DNS goes through the tunnel" and "almost none does" — so a failure of the second
// call while the first succeeded is a silent DNS leak, reported as a working tunnel.
//
// Only reproducible by making the command fail on demand, hence the stub on PATH.
#[cfg(all(test, target_os = "linux"))]
mod fault_injection {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, MutexGuard};

    static SERIAL: Mutex<()> = Mutex::new(());

    struct Resolvectl {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
        old_path: String,
    }

    impl Resolvectl {
        fn new(tag: &str, fail_on: &[&str]) -> Resolvectl {
            let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
            let dir = std::env::temp_dir().join(format!("qeli-rslv-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let log = dir.join("calls.log");

            let mut script = String::from("#!/bin/sh\n");
            script.push_str(&format!("echo \"$@\" >> {}\n", log.display()));
            script.push_str("case \"$*\" in\n");
            for cond in fail_on {
                script.push_str(&format!("  *\"{cond}\"*) exit 1;;\n"));
            }
            script.push_str("esac\nexit 0\n");

            let bin = dir.join("resolvectl");
            let mut f = std::fs::File::create(&bin).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            drop(f);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

            let old_path = std::env::var("PATH").unwrap_or_default();
            std::env::set_var("PATH", format!("{}:{}", dir.display(), old_path));
            Resolvectl {
                dir,
                _guard: guard,
                old_path,
            }
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
    }

    impl Drop for Resolvectl {
        fn drop(&mut self) {
            std::env::set_var("PATH", &self.old_path);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Full-tunnel DNS: the `~.` catch-all is what makes every query take the link.
    fn redirect_all() -> ClientDnsConfig {
        ClientDnsConfig {
            redirect_all: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_refused_routing_domain_is_not_reported_as_success() {
        // `dns` lands, `domain` does not. The old code discarded the second result and
        // returned true, so the caller logged "DNS set" and never fell back — while every
        // query kept going to the physical resolver.
        let rc = Resolvectl::new("domain", &["domain qtest"]);
        assert!(
            !try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"),
            "a failed routing-domain call must report failure so the caller falls back"
        );
        assert!(
            rc.calls().contains("revert qtest"),
            "the half-applied link config must be reverted, not left behind:\n{}",
            rc.calls()
        );
    }

    #[test]
    fn a_working_resolvectl_reports_success_and_sets_both() {
        let rc = Resolvectl::new("ok", &[]);
        assert!(try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"));
        let calls = rc.calls();
        assert!(
            calls.contains("dns qtest 10.0.0.1") && calls.contains("domain qtest"),
            "both halves must be applied:\n{calls}"
        );
        assert!(
            !calls.contains("revert"),
            "nothing to revert on the success path:\n{calls}"
        );
    }

    #[test]
    fn a_refused_dns_call_fails_before_touching_domains() {
        // The first call failing is the ordinary "resolved is not really in charge" case:
        // report it and let the caller edit resolv.conf instead.
        let rc = Resolvectl::new("dns", &["dns qtest"]);
        assert!(!try_resolvectl(&redirect_all(), "qtest", "10.0.0.1"));
        assert!(
            !rc.calls().contains("domain qtest"),
            "no point setting routing domains on a link whose server was refused:\n{}",
            rc.calls()
        );
    }
}
