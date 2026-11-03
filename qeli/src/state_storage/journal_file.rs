//! Bounded journal snapshots: validate and read the same descriptor.
use crate::config_source::Stamp;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    path::Path,
};

pub(crate) struct Opened {
    file: File,
    stamp: Stamp,
    limit: u64,
}

impl Opened {
    pub(crate) fn open(path: &Path, limit: u64) -> io::Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        #[cfg(not(unix))]
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::other("privileged journal must not be a symlink"))
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(io::Error::other(
                "privileged journal must be a regular file within its size limit",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let parent_metadata = std::fs::metadata(parent)?;
            if !parent_metadata.is_dir()
                || parent_metadata.mode() & 0o022 != 0
                || (metadata.uid() != 0 && metadata.uid() != parent_metadata.uid())
            {
                return Err(io::Error::other(
                    "privileged journal owner or parent permissions are untrusted",
                ));
            }
            if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::other(
                    "privileged journal must be single-link and not group/world-writable",
                ));
            }
        }
        Ok(Some(Self {
            file,
            stamp: Stamp::of(&metadata),
            limit,
        }))
    }

    pub(crate) fn read(mut self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.file
            .by_ref()
            .take(self.limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.limit {
            return Err(io::Error::other(
                "privileged journal grew beyond its size limit",
            ));
        }
        let metadata = self.file.metadata()?;
        if self.stamp != Stamp::of(&metadata) || bytes.len() as u64 != metadata.len() {
            return Err(io::Error::other("privileged journal changed while reading"));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "qeli-sysctl-file-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("sysctls.state")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn exact_limit_reads_full_snapshot_and_oversize_is_rejected() {
        let f = Fixture::new();
        assert!(Opened::open(&f.path(), 4).unwrap().is_none());
        std::fs::write(f.path(), b"1234").unwrap();
        assert_eq!(
            Opened::open(&f.path(), 4).unwrap().unwrap().read().unwrap(),
            b"1234"
        );
        std::fs::write(f.path(), b"12345").unwrap();
        assert!(Opened::open(&f.path(), 4).is_err());
    }
    #[test]
    fn growth_after_open_is_never_an_unbounded_or_partial_successful_read() {
        let f = Fixture::new();
        std::fs::write(f.path(), b"1234").unwrap();
        let opened = Opened::open(&f.path(), 8).unwrap().unwrap();
        std::fs::write(f.path(), vec![b'x'; 1024 * 1024]).unwrap();
        assert!(opened.read().is_err());
    }
    #[test]
    fn truncation_after_open_is_rejected_even_if_the_prefix_could_parse() {
        let f = Fixture::new();
        std::fs::write(f.path(), b"{}  ").unwrap();
        let opened = Opened::open(&f.path(), 8).unwrap().unwrap();
        std::fs::write(f.path(), b"{}").unwrap();
        assert!(opened.read().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn pathname_replacement_cannot_switch_the_opened_snapshot() {
        let f = Fixture::new();
        std::fs::write(f.path(), b"old").unwrap();
        let opened = Opened::open(&f.path(), 8).unwrap().unwrap();
        std::fs::rename(f.path(), f.0.join("old")).unwrap();
        std::fs::write(f.path(), b"new").unwrap();
        // Rename changes ctime on Linux: either retain the opened bytes or refuse the change.
        if let Ok(bytes) = opened.read() {
            assert_eq!(bytes, b"old");
        }
        assert_eq!(std::fs::read(f.path()).unwrap(), b"new");
    }
    #[cfg(unix)]
    #[test]
    fn symlink_and_hardlink_never_authorize_a_journal_read() {
        let f = Fixture::new();
        let outside = f.0.join("outside");
        std::fs::write(&outside, b"original").unwrap();
        std::os::unix::fs::symlink(&outside, f.path()).unwrap();
        assert!(Opened::open(&f.path(), 100).is_err());
        std::fs::remove_file(f.path()).unwrap();
        std::fs::hard_link(&outside, f.path()).unwrap();
        assert!(Opened::open(&f.path(), 100).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"original");
    }
    #[cfg(unix)]
    #[test]
    fn fifo_open_does_not_wait_for_a_writer_and_unsafe_mode_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let path = std::ffi::CString::new(f.path().as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        assert!(Opened::open(&f.path(), 100).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        std::fs::remove_file(f.path()).unwrap();
        std::fs::write(f.path(), b"{}").unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Opened::open(&f.path(), 100).is_err());
    }
}
