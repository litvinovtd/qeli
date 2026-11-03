use super::*;

#[test]
fn device_reads_only_the_existing_id_prefix() {
    struct Prefix {
        used: bool,
    }
    impl Read for Prefix {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            assert!(!self.used, "must not inspect the suffix");
            assert_eq!(out.len(), crate::protocol::DEVICE_ID_LEN);
            out.fill(19);
            self.used = true;
            Ok(out.len())
        }
    }
    assert_eq!(
        read_device_prefix(Prefix { used: false }).unwrap(),
        Some([19; crate::protocol::DEVICE_ID_LEN])
    );
}
#[test]
fn device_short_zero_and_read_errors_remain_distinct() {
    assert_eq!(read_device_prefix(&[1u8][..]).unwrap(), None);
    assert_eq!(
        read_device_prefix(&[0u8; crate::protocol::DEVICE_ID_LEN][..]).unwrap(),
        None
    );
    struct Failed;
    impl Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture I/O failure"))
        }
    }
    assert!(read_device_prefix(Failed).is_err());
}
#[test]
fn known_hosts_requires_utf8_in_the_whole_snapshot() {
    assert!(read_known_hosts(&[b'#', b'\n', 0xff][..])
        .unwrap_err()
        .to_string()
        .contains("UTF-8"));
}
#[test]
fn known_hosts_exact_limit_and_infinite_input_are_bounded() {
    assert_eq!(
        read_known_hosts(io::repeat(b'#').take(MAX_KNOWN_HOSTS as u64))
            .unwrap()
            .len(),
        MAX_KNOWN_HOSTS
    );
    let error = read_known_hosts(io::repeat(b'x')).unwrap_err();
    assert!(error.to_string().contains("1 MiB"));
}
#[test]
fn every_matching_pin_is_checked_including_conflicting_duplicates() {
    let a = "aa".repeat(32);
    let b = "bb".repeat(32);
    assert!(check_pin(
        &format!("# comment\nh:443 {}\nh:443 {a}\n", a.to_uppercase()),
        "h:443",
        &a
    )
    .unwrap());
    for text in [
        format!("h:443 {a}\nh:443 {b}\n"),
        format!("h:443 {b}\nh:443 {a}\n"),
    ] {
        assert!(check_pin(&text, "h:443", &a)
            .unwrap_err()
            .to_string()
            .contains("MISMATCH"));
    }
}
#[test]
fn malformed_matching_pin_cannot_become_first_trust() {
    for row in ["h:443", "h:443 ", "h:443 abc", "h:443 not-a-key"] {
        assert!(check_pin(row, "h:443", &"aa".repeat(32)).is_err());
    }
    assert!(!check_pin(
        "legacy unrelated record\n# comment",
        "h:443",
        &"aa".repeat(32)
    )
    .unwrap());
}

#[cfg(target_os = "linux")]
pub(crate) struct Directory(std::path::PathBuf);
#[cfg(target_os = "linux")]
impl Directory {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qeli-identity-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}
#[cfg(target_os = "linux")]
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    fn dir() -> Directory {
        Directory::new()
    }
    #[test]
    fn sparse_device_suffix_is_not_read_or_rewritten() {
        use std::io::Write;
        let dir = dir();
        let path = dir.path().join("id");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[17; crate::protocol::DEVICE_ID_LEN]).unwrap();
        f.set_len(1 << 34).unwrap();
        drop(f);
        let before = std::fs::metadata(&path).unwrap();
        assert_eq!(
            device_id_at(path.to_str().unwrap()),
            [17; crate::protocol::DEVICE_ID_LEN]
        );
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!((before.ino(), before.len()), (after.ino(), after.len()));
        assert!(!dir.path().join("id.lock").exists());
    }
    #[test]
    fn fifo_device_is_preserved_and_never_waits_for_a_writer() {
        let dir = dir();
        let path = dir.path().join("id");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let before = std::fs::metadata(&path).unwrap();
        let started = std::time::Instant::now();
        assert_ne!(
            device_id_at(path.to_str().unwrap()),
            [0; crate::protocol::DEVICE_ID_LEN]
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let after = std::fs::metadata(&path).unwrap();
        assert!(after.file_type().is_fifo());
        assert_eq!(before.ino(), after.ino());
        assert!(!dir.path().join("id.lock").exists());
    }
    #[test]
    fn device_lock_timeout_does_not_replace_an_owners_file() {
        let dir = dir();
        let path = dir.path().join("id");
        let lock = crate::util::FileLock::acquire(&path).unwrap();
        let id = device_id_with_wait(&path, Duration::from_millis(30));
        assert_ne!(id, [0; crate::protocol::DEVICE_ID_LEN]);
        assert!(!path.exists());
        drop(lock);
        let durable = device_id_at(path.to_str().unwrap());
        assert_eq!(device_id_at(path.to_str().unwrap()), durable);
    }
    #[test]
    fn corrupted_or_oversized_store_is_unchanged_even_with_unpinned_opt_in() {
        let dir = dir();
        let path = dir.path().join("known_hosts");
        for bytes in [vec![0xff], vec![b'#'; MAX_KNOWN_HOSTS + 1]] {
            std::fs::write(&path, &bytes).unwrap();
            for allow in [false, true] {
                assert!(trust_on_first_use_at(
                    path.to_str().unwrap(),
                    "h:443",
                    &"aa".repeat(32),
                    allow
                )
                .is_err());
            }
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(!dir.path().join("known_hosts.lock").exists());
        }
    }
    #[test]
    fn adding_a_pin_preserves_unterminated_record_and_private_mode() {
        let dir = dir();
        let path = dir.path().join("known_hosts");
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        std::fs::write(&path, format!("# operator\na:443 {a}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        trust_on_first_use_at(path.to_str().unwrap(), "b:443", &b, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# operator\na:443 {a}\nb:443 {b}\n")
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        trust_on_first_use_at(path.to_str().unwrap(), "a:443", &a, false).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn persistence_escape_hatch_still_applies_to_missing_unwritable_store() {
        let path = format!("/proc/qeli-missing-known-hosts-{}", std::process::id());
        assert!(trust_on_first_use_at(&path, "h:443", &"aa".repeat(32), false).is_err());
        assert!(trust_on_first_use_at(&path, "h:443", &"aa".repeat(32), true).is_ok());
    }
}
