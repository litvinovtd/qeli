//! Resolve state storage without following directory symlinks, then address it by fd.
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
struct Node {
    owner: u32,
    mode: u32,
}
struct Policy {
    caller: u32,
    delegated: Option<u32>,
}
impl Policy {
    fn check(&mut self, node: Node, parent: Option<Node>, final_dir: bool) -> anyhow::Result<()> {
        let sticky_root = node.owner == 0 && node.mode & 0o1000 != 0;
        anyhow::ensure!(
            node.mode & 0o022 == 0 || (!final_dir && sticky_root),
            "privileged state directory must not be group/world-writable"
        );
        if parent.is_some_and(|p| p.mode & 0o022 != 0) {
            // A root invocation must not adopt a foreign user's pre-planted child
            // of /tmp merely because the child's own permissions look private.
            anyhow::ensure!(
                node.owner == 0 || node.owner == self.caller,
                "foreign privileged state directory beneath a writable ancestor"
            );
        }
        if node.owner != 0 && node.owner != self.caller && self.delegated != Some(node.owner) {
            anyhow::ensure!(
                self.delegated.is_none()
                    && parent.is_some_and(|p| p.owner == 0 && p.mode & 0o022 == 0),
                "untrusted privileged state directory owner {}",
                node.owner
            );
            // /var/lib/qeli is deliberately assigned to the packaged service user
            // by root. Preserve that authority for a root CLI sharing its journal.
            self.delegated = Some(node.owner);
        }
        Ok(())
    }
}

pub(crate) struct Directory {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    owner: u32,
}
impl Directory {
    #[cfg(target_os = "linux")]
    pub(crate) fn open(path: &Path) -> anyhow::Result<Self> {
        use std::{
            ffi::CString,
            os::{
                fd::{AsRawFd, FromRawFd},
                unix::{
                    ffi::OsStrExt,
                    fs::{MetadataExt, OpenOptionsExt},
                },
            },
            path::Component,
        };
        anyhow::ensure!(
            path.is_absolute(),
            "privileged state directory must be absolute"
        );
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => (),
                Component::Normal(name) => names.push(CString::new(name.as_bytes())?),
                _ => anyhow::bail!("privileged state directory must not contain parent traversal"),
            }
        }
        anyhow::ensure!(
            !names.is_empty() && names.len() <= 64,
            "invalid privileged state directory depth"
        );
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let node = |file: &std::fs::File| -> std::io::Result<Node> {
            let md = file.metadata()?;
            Ok(Node {
                owner: md.uid(),
                mode: md.mode(),
            })
        };
        let mut current = node(&file)?;
        // SAFETY: no pointers, no side effects.
        let mut policy = Policy {
            caller: unsafe { libc::geteuid() },
            delegated: None,
        };
        policy.check(current, None, false)?;
        for (i, name) in names.iter().enumerate() {
            let open = || {
                // SAFETY: parent fd and NUL-terminated single component remain live.
                let fd = unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
                }
            };
            let child = match open() {
                Ok(child) => child,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Already admitted the parent before any filesystem mutation.
                    if unsafe { libc::mkdirat(file.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        let error = std::io::Error::last_os_error();
                        if error.kind() != std::io::ErrorKind::AlreadyExists {
                            return Err(error.into());
                        }
                    }
                    file.sync_all()?;
                    open()?
                }
                Err(error) => return Err(error.into()),
            };
            let next = node(&child)?;
            policy.check(next, Some(current), i + 1 == names.len())?;
            file = child;
            current = next;
        }
        Ok(Self {
            file,
            owner: current.owner,
        })
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(_path: &Path) -> anyhow::Result<Self> {
        anyhow::bail!("host sysctl state directories require Linux")
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn journal_path(&self, name: &str) -> anyhow::Result<PathBuf> {
        use std::os::fd::AsRawFd;
        anyhow::ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
                && name != "."
                && name != "..",
            "invalid state file name"
        );
        Ok(PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.file.as_raw_fd(),
            name
        )))
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn journal_path(&self, _name: &str) -> anyhow::Result<PathBuf> {
        unreachable!()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn owner(&self) -> u32 {
        self.owner
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn owner(&self) -> u32 {
        unreachable!()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let md = self.file.metadata()?;
        anyhow::ensure!(
            md.uid() == self.owner && md.mode() & 0o022 == 0,
            "privileged state directory ownership or permissions changed"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_service_owner_requires_protected_root_delegation() {
        let root = Node {
            owner: 0,
            mode: 0o755,
        };
        let service = Node {
            owner: 997,
            mode: 0o750,
        };
        let mut p = Policy {
            caller: 0,
            delegated: None,
        };
        p.check(service, Some(root), true).unwrap();
        p.check(service, Some(service), true).unwrap();
        assert!(p
            .check(
                Node {
                    owner: 998,
                    mode: 0o700
                },
                Some(service),
                true
            )
            .is_err());
        let mut p = Policy {
            caller: 0,
            delegated: None,
        };
        assert!(p
            .check(
                service,
                Some(Node {
                    owner: 0,
                    mode: 0o1777
                }),
                true
            )
            .is_err());
    }
    #[test]
    fn writable_leaf_and_nonsticky_writable_ancestors_are_never_trusted() {
        for mode in [0o777, 0o770, 0o1777] {
            assert!(Policy {
                caller: 7,
                delegated: None
            }
            .check(Node { owner: 7, mode }, None, true)
            .is_err());
        }
        assert!(Policy {
            caller: 0,
            delegated: None
        }
        .check(
            Node {
                owner: 0,
                mode: 0o777
            },
            None,
            false
        )
        .is_err());
        let mut p = Policy {
            caller: 7,
            delegated: None,
        };
        let tmp = Node {
            owner: 0,
            mode: 0o1777,
        };
        p.check(tmp, None, false).unwrap();
        p.check(
            Node {
                owner: 7,
                mode: 0o700,
            },
            Some(tmp),
            true,
        )
        .unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "state_dir_tests.rs"]
mod native_tests;
