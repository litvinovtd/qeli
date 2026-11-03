//! Lifetime lease for the local administrative socket. Never unlink another listener.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::net::UnixListener;

pub(super) struct ControlSocket {
    pub(super) listener: Option<UnixListener>,
    path: PathBuf,
    identity: (u64, u64),
    // Keep the sidecar inode permanently: unlinking a flock file splits the lock domain.
    _lease: File,
}

fn identity(meta: &std::fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

impl ControlSocket {
    pub(super) fn bind(path: &Path) -> anyhow::Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let meta = std::fs::symlink_metadata(parent)?;
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            meta.is_dir() && meta.uid() == uid && meta.mode() & 0o777 == 0o700,
            "control socket directory {} must be a real private directory owned by uid {uid} (0700); choose a dedicated directory, for example /tmp/qeli-{uid}/control.sock",
            parent.display()
        );
        // Resolve /var/run -> /run, then reject ancestors that another uid could
        // use to replace the private directory. Sticky /tmp is allowed; arbitrary
        // world-writable non-sticky directories are not.
        let parent = parent.canonicalize()?;
        for ancestor in parent.ancestors().skip(1) {
            let meta = std::fs::metadata(ancestor)?;
            anyhow::ensure!(
                (meta.uid() == uid || meta.uid() == 0)
                    && (meta.mode() & 0o022 == 0 || meta.mode() & libc::S_ISVTX != 0),
                "unsafe control socket ancestor {}",
                ancestor.display()
            );
        }
        let path = parent.join(
            path.file_name()
                .ok_or_else(|| anyhow::anyhow!("control socket requires a file name"))?,
        );
        let mut lease_path = path.as_os_str().to_os_string();
        lease_path.push(".lock");
        let lease = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(lease_path)?;
        let meta = lease.metadata()?;
        anyhow::ensure!(
            meta.is_file() && meta.nlink() == 1 && meta.uid() == uid,
            "control socket lock must be a regular single-link file owned by uid {uid}"
        );
        if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            anyhow::bail!(
                "control socket {} is already owned: {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                anyhow::ensure!(
                    meta.file_type().is_socket() && meta.uid() == uid,
                    "refusing to replace non-socket or foreign path {}",
                    path.display()
                );
                // Nonblocking connect also treats a full accept backlog as live. Only
                // ECONNREFUSED proves a stale socket; permission/other errors preserve it.
                let probe =
                    socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
                probe.set_nonblocking(true)?;
                let address = socket2::SockAddr::unix(&path)?;
                match probe.connect(&address) {
                    Err(error) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {
                        anyhow::ensure!(
                            identity(&std::fs::symlink_metadata(&path)?) == identity(&meta),
                            "control socket changed while checking stale path"
                        );
                        std::fs::remove_file(&path)?;
                    }
                    _ => anyhow::bail!(
                        "control socket {} has a listener or cannot be safely reclaimed",
                        path.display()
                    ),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&path)?;
        let meta = std::fs::symlink_metadata(&path)?;
        let owned = Self {
            listener: Some(listener),
            path,
            identity: identity(&meta),
            _lease: lease,
        };
        // The private directory gates access even before chmod, independently of umask.
        std::fs::set_permissions(&owned.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(owned)
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|meta| meta.file_type().is_socket() && identity(&meta) == self.identity)
        {
            if let Err(error) = std::fs::remove_file(&self.path) {
                log::warn!(
                    "Cannot remove owned control socket {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "qeli-control-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn socket(&self) -> PathBuf {
            self.0.join("control.sock")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn concurrent_bind_preserves_owner_and_drop_releases_path() {
        let dir = Fixture::new();
        let path = dir.socket();
        let first = ControlSocket::bind(&path).unwrap();
        let original = identity(&std::fs::symlink_metadata(&path).unwrap());
        assert!(ControlSocket::bind(&path).is_err());
        assert_eq!(
            identity(&std::fs::symlink_metadata(&path).unwrap()),
            original
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let peer = tokio::net::UnixStream::connect(&path).await.unwrap();
        let _accepted = first.listener.as_ref().unwrap().accept().await.unwrap();
        drop(peer);
        drop(first);
        assert!(!path.exists());
        assert!(ControlSocket::bind(&path).is_ok());
    }

    #[tokio::test]
    async fn preserves_foreign_live_listener_without_lease() {
        let dir = Fixture::new();
        let path = dir.socket();
        let _listener = UnixListener::bind(&path).unwrap();
        let original = identity(&std::fs::symlink_metadata(&path).unwrap());
        assert!(ControlSocket::bind(&path).is_err());
        assert_eq!(
            identity(&std::fs::symlink_metadata(&path).unwrap()),
            original
        );
    }

    #[tokio::test]
    async fn reclaims_stale_socket_and_creates_private_parent() {
        let dir = Fixture::new();
        let path = dir.socket();
        drop(UnixListener::bind(&path).unwrap());
        assert!(ControlSocket::bind(&path).is_ok());
        let nested = dir.0.join("new/control.sock");
        let _listener = ControlSocket::bind(&nested).unwrap();
        assert_eq!(
            std::fs::metadata(nested.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
    }

    #[tokio::test]
    async fn refuses_shared_parent_without_chmod() {
        let dir = Fixture::new();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ControlSocket::bind(&dir.socket()).is_err());
        assert_eq!(std::fs::metadata(&dir.0).unwrap().mode() & 0o777, 0o755);
    }

    #[tokio::test]
    async fn preserves_regular_file_and_symlink() {
        let dir = Fixture::new();
        let path = dir.socket();
        std::fs::write(&path, b"keep").unwrap();
        assert!(ControlSocket::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        let target = dir.0.join("target");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ControlSocket::bind(&path).is_err());
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(target).unwrap(), b"target");
    }

    #[tokio::test]
    async fn drop_preserves_replacement_path() {
        let dir = Fixture::new();
        let path = dir.socket();
        let first = ControlSocket::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(first);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }

    #[tokio::test]
    async fn refuses_symlink_directory_and_lock() {
        let dir = Fixture::new();
        let link = dir.0.join("linked");
        std::os::unix::fs::symlink(&dir.0, &link).unwrap();
        assert!(ControlSocket::bind(&link.join("control.sock")).is_err());
        let target = dir.0.join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.0.join("control.sock.lock")).unwrap();
        assert!(ControlSocket::bind(&dir.socket()).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"keep");
    }
    #[tokio::test]
    async fn refuses_untrusted_writable_ancestor() {
        let dir = Fixture::new();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ControlSocket::bind(&dir.0.join("private/control.sock")).is_err());
        assert!(!dir.0.join("private/control.sock").exists());
    }
}
