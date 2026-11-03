//! Hold the trusted directory while every marker/sidecar operation addresses it by fd.
#[cfg(unix)]
use std::io;
use std::{
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
};

pub(crate) struct Directory {
    #[cfg(target_os = "linux")]
    owner: crate::state_storage::state_dir::Directory,
    path: PathBuf,
}
impl Directory {
    pub(crate) fn open(path: &Path) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let owner = crate::state_storage::state_dir::Directory::open(path)?;
            let path = owner
                .journal_path("dns-link.state")?
                .parent()
                .expect("anchored directory")
                .to_owned();
            Ok(Self { owner, path })
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No production DNS adapter on these platforms. Portable file/lock tests
            // still exercise the same marker protocol without pretending to test openat.
            Ok(Self {
                path: path.to_owned(),
            })
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn existing(path: &Path) -> anyhow::Result<Option<Self>> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Self::open(path).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(all(target_os = "linux", feature = "client"))]
    pub(crate) fn refuse_legacy_global(&self) -> anyhow::Result<()> {
        self.verify()?;
        crate::dns_legacy::require_absent(&self.path)?;
        self.verify()
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn entries(&self) -> anyhow::Result<std::fs::ReadDir> {
        self.verify()?;
        Ok(std::fs::read_dir(&self.path)?)
    }
    pub(super) fn verify(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        self.owner.verify()?;
        Ok(())
    }
    pub(super) fn sync(&self) -> anyhow::Result<()> {
        self.verify()?;
        #[cfg(unix)]
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
    fn validate_lock(&self, file: &File, path: &Path) -> anyhow::Result<()> {
        self.verify()?;
        #[cfg(not(unix))]
        let _ = path;
        let opened = file.metadata()?;
        anyhow::ensure!(opened.is_file(), "DNS lock must be a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let named = std::fs::symlink_metadata(path)?;
            let parent = std::fs::metadata(&self.path)?;
            anyhow::ensure!(
                opened.nlink() == 1
                    && opened.mode() & 0o022 == 0
                    && (opened.uid() == 0 || opened.uid() == parent.uid()),
                "untrusted DNS lock owner or permissions"
            );
            anyhow::ensure!(
                !named.file_type().is_symlink()
                    && (opened.dev(), opened.ino()) == (named.dev(), named.ino()),
                "DNS lock was replaced"
            );
        }
        Ok(())
    }
    // A stable sidecar is deliberately retained after marker retirement. Hold its
    // lock for the lease lifetime; a second process cannot adopt a live generation.
    pub(super) fn try_lock(&self, path: &Path) -> anyhow::Result<Option<File>> {
        self.verify()?;
        let path = path.with_extension("lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        }
        let file = options.open(&path)?;
        self.validate_lock(&file, &path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(error) => return Err(anyhow::anyhow!("cannot lock DNS ownership state: {error}")),
        }
        self.validate_lock(&file, &path)?;
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
            let target = std::fs::metadata(&self.path)?;
            let current = file.metadata()?;
            if current.uid() != target.uid() || current.gid() != target.gid() {
                // The directory's admitted owner is also the writer of future generations.
                anyhow::ensure!(
                    unsafe { libc::fchown(file.as_raw_fd(), target.uid(), target.gid()) } == 0,
                    "cannot hand DNS lock to state directory owner: {}",
                    io::Error::last_os_error()
                );
            }
        }
        self.sync()?;
        Ok(Some(file))
    }
}
