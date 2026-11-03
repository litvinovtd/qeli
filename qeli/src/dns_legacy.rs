//! Legacy global DNS snapshots have no namespace, boot or resolver ownership witness.
//! Their presence requires administrator recovery, never automatic filesystem replay.
use std::path::Path;

// The caller pins and verifies the state directory. Inspect entries without opening
// their contents: a dangling symlink, FIFO, directory, empty or corrupt file is still
// legacy evidence. A stable lock sidecar alone does not prove pending recovery.
pub(crate) fn require_absent(directory: &Path) -> anyhow::Result<()> {
    for name in ["dns-backup.json", "dns-holders"] {
        match std::fs::symlink_metadata(directory.join(name)) {
            Ok(_) => anyhow::bail!(
                "legacy global DNS state {name} has no namespace or resolver ownership; \
                 administrator recovery required; /etc/resolv.conf and legacy state left unchanged"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => anyhow::bail!("cannot inspect legacy global DNS state {name}: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-legacy-dns-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn refused(dir: &Directory) {
        let error = require_absent(&dir.0).unwrap_err().to_string();
        assert!(
            error.contains("legacy global DNS state") && error.contains("administrator recovery"),
            "{error}"
        );
    }
    #[test]
    fn absent_legacy_state_and_a_stable_lock_sidecar_allow_startup() {
        let dir = Directory::new();
        require_absent(&dir.0).unwrap();
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        std::fs::write(dir.path("dns-holders.lock"), b"stable lock").unwrap();
        require_absent(&dir.0).unwrap();
        assert_eq!(
            std::fs::read(dir.path("dns-holders.lock")).unwrap(),
            b"stable lock"
        );
    }
    #[test]
    fn every_snapshot_kind_and_invalid_payload_remain_untouched() {
        let dir = Directory::new();
        for content in [
            r#"{"kind":"file","content":"old resolver"}"#,
            r#"{"kind":"symlink","target":"foreign-resolver"}"#,
            r#"{"kind":"absent"}"#,
            r#"{"kind":"managed-no-original"}"#,
            "",
            "{truncated",
            "unknown legacy format",
        ] {
            std::fs::write(dir.path("dns-backup.json"), content).unwrap();
            refused(&dir);
            assert_eq!(
                std::fs::read_to_string(dir.path("dns-backup.json")).unwrap(),
                content
            );
            assert!(!dir.path("dns-holders.lock").exists());
        }
    }
    #[test]
    fn holder_only_is_not_pruned_by_current_pid_visibility() {
        let dir = Directory::new();
        for content in [
            "".to_owned(),
            "2147483647\n".into(),
            format!("{}\n", std::process::id()),
            "invalid PID".into(),
        ] {
            std::fs::write(dir.path("dns-holders"), &content).unwrap();
            refused(&dir);
            assert_eq!(
                std::fs::read_to_string(dir.path("dns-holders")).unwrap(),
                content
            );
            assert!(!dir.path("dns-holders.lock").exists());
        }
    }
    #[test]
    fn directories_at_either_legacy_name_are_not_absence() {
        for name in ["dns-backup.json", "dns-holders"] {
            let dir = Directory::new();
            let entry = dir.path(name);
            std::fs::create_dir(&entry).unwrap();
            std::fs::write(entry.join("evidence"), "retained").unwrap();
            refused(&dir);
            assert_eq!(std::fs::read(entry.join("evidence")).unwrap(), b"retained");
        }
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed_even_when_dangling() {
        for name in ["dns-backup.json", "dns-holders"] {
            let dir = Directory::new();
            let entry = dir.path(name);
            std::os::unix::fs::symlink("missing-target", &entry).unwrap();
            refused(&dir);
            assert_eq!(
                std::fs::read_link(&entry).unwrap(),
                Path::new("missing-target")
            );
            std::fs::write(dir.path("missing-target"), "unchanged").unwrap();
            refused(&dir);
            assert_eq!(
                std::fs::read(dir.path("missing-target")).unwrap(),
                b"unchanged"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn fifo_legacy_state_is_refused_without_reading() {
        use std::os::unix::ffi::OsStrExt;
        let dir = Directory::new();
        let path = dir.path("dns-backup.json");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        refused(&dir);
        use std::os::unix::fs::FileTypeExt;
        assert!(std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_fifo());
    }
    #[cfg(unix)]
    #[test]
    fn failed_metadata_inspection_does_not_mean_absent() {
        let dir = Directory::new();
        let file = dir.path("not-a-directory");
        std::fs::write(&file, "untouched").unwrap();
        assert!(require_absent(&file)
            .unwrap_err()
            .to_string()
            .contains("cannot inspect"));
        assert_eq!(std::fs::read(file).unwrap(), b"untouched");
    }
}
