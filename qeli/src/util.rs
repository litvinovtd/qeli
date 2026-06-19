//! Small cross-platform utilities shared across the crate.

use std::path::Path;

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
/// PERMISSIONS: a temp+rename creates a NEW inode, which would otherwise drop the
/// target's mode to the umask default — a regression for files that must stay
/// `0600` (the users DB holds every password hash). So when the target already
/// exists its Unix mode is copied onto the temp before the rename, matching
/// `std::fs::write`'s behaviour of leaving an existing file's permissions intact.
pub fn write_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> anyhow::Result<()> {
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
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rnd);
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = dir.join(format!(".{stem}.qeli-tmp-{suffix}"));

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        match opts.open(&tmp) {
            Ok(mut f) => {
                // Preserve the existing target's mode (don't silently widen a 0600
                // secrets file to the umask default on rename).
                #[cfg(unix)]
                if let Ok(meta) = std::fs::metadata(path) {
                    let _ = f.set_permissions(meta.permissions());
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
}
