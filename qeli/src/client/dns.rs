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

    let dns_addr = if dns_port == "53" {
        dns_server.to_string()
    } else {
        format!("{}#{}", dns_server, dns_port)
    };

    // Preferred path: systemd-resolved. Per-link config is automatically
    // dropped when the tun interface is deleted, so it is inherently safe; we
    // still record the interface so `restore` can revert explicitly.
    if try_resolvectl(config, ifname, &dns_addr) {
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
            let _ = std::process::Command::new("resolvectl")
                .args(["revert", ifname])
                .output();
            log::info!("Reverted resolvectl config on {}", ifname);
        }
        let _ = std::fs::remove_file(RESOLVECTL_MARK);
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
        let _ = std::process::Command::new("resolvectl")
            .args(["domain", ifname])
            .args(&domains)
            .output();
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

/// Write a file atomically (tmp in the same dir, then rename). Replacing a
/// symlink with the renamed regular file is intentional — `restore_resolv`
/// recreates the link from the backup.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("resolv.conf");
    // We run as root writing into /etc, so a *predictable* temp name
    // (`.resolv.conf.qeli-tmp`) plus a symlink-following `std::fs::write` let a
    // local attacker pre-plant a symlink and redirect the write to an arbitrary
    // file (H-5). Defend with an UNPREDICTABLE name + `O_EXCL` (create_new, fails
    // on any pre-existing entry incl. a symlink) + `O_NOFOLLOW` (never traverse a
    // symlink as the final component). Retry on the rare random-name clash.
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..8 {
        let mut rnd = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".{stem}.qeli-tmp-{suffix}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
        {
            Ok(mut f) => {
                f.write_all(bytes)
                    .and_then(|()| f.sync_all())
                    .map_err(|e| anyhow::anyhow!("write {}: {}", tmp.display(), e))?;
                drop(f);
                return std::fs::rename(&tmp, path).map_err(|e| {
                    let _ = std::fs::remove_file(&tmp);
                    anyhow::anyhow!("rename {} -> {}: {}", tmp.display(), path.display(), e)
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                return Err(anyhow::anyhow!("create temp in {}: {}", dir.display(), e));
            }
        }
    }
    Err(anyhow::anyhow!(
        "could not create a fresh temp file in {}: {:?}",
        dir.display(),
        last_err
    ))
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
