//! Lifetime and directory durability for same-directory atomic publication.
use std::{
    io,
    path::{Path, PathBuf},
};

pub(super) struct Parent {
    #[cfg(unix)]
    directory: std::fs::File,
}
impl Parent {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            Ok(Self {
                directory: std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                    .open(path)?,
            })
        }
        #[cfg(not(unix))]
        {
            if !std::fs::metadata(path)?.is_dir() {
                return Err(io::Error::other("atomic write parent is not a directory"));
            }
            Ok(Self {})
        }
    }
    pub(super) fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.directory.sync_all()
        }
        // Windows directory flush has a different contract. Retain the existing
        // file-sync/rename behavior here; do not claim Unix directory durability.
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

pub(super) struct Pending(Option<PathBuf>);
impl Pending {
    pub(super) fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }
    pub(super) fn published(&mut self) {
        self.0 = None;
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            if let Err(error) = std::fs::remove_file(path) {
                if error.kind() != io::ErrorKind::NotFound {
                    log::warn!(
                        "could not remove incomplete atomic-write file {}: {error}",
                        path.display()
                    );
                }
            }
        }
    }
}

#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
pub(crate) fn remove_if_exists(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = Parent::open(dir)?;
    remove_with_sync(path, || parent.sync())
}
#[cfg(any(
    test,
    all(target_os = "linux", any(feature = "client", feature = "server"))
))]
fn remove_with_sync(path: &Path, sync: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    // Retry the directory sync even if a previous failed attempt already unlinked it.
    sync().map_err(|error| {
        io::Error::other(format!(
            "removed {} but cannot sync its directory: {error}; persistence is uncertain",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_retry_syncs_even_after_the_name_is_absent() {
        let dir = std::env::temp_dir().join(format!(
            "qeli-remove-sync-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("state");
        std::fs::write(&path, b"state").unwrap();
        let error = remove_with_sync(&path, || {
            Err(io::Error::other("injected directory I/O failure"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("persistence is uncertain"));
        assert!(!path.exists());
        let called = std::cell::Cell::new(false);
        remove_with_sync(&path, || {
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert!(called.get());
        std::fs::remove_dir(dir).unwrap();
    }
}
