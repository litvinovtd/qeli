//! Injectable process/sysctl I/O. Host regressions never read or modify real procfs.
use std::io;
pub(super) fn read(path: &str) -> io::Result<String> {
    #[cfg(test)]
    {
        test_support::call(test_support::Operation::Read(path))
    }
    #[cfg(not(test))]
    {
        std::fs::read_to_string(path)
    }
}
pub(super) fn write(path: &str, value: &str) -> io::Result<()> {
    #[cfg(test)]
    {
        test_support::call(test_support::Operation::Write(path, value)).map(|_| ())
    }
    #[cfg(not(test))]
    {
        std::fs::write(path, value)
    }
}
pub(super) fn process_exists(pid: u32) -> io::Result<bool> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid process ID",
        ));
    }
    #[cfg(test)]
    {
        test_support::call(test_support::Operation::ProcessExists(pid)).map(|value| value == "1")
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        // Signal 0 performs an existence/permission check; it delivers no signal.
        // SAFETY: pid is a positive representable process ID, not a process group.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(error),
        }
    }
}
/// Keep the namespace alive while its dev/inode identity authorizes a transaction.
/// Test backends carry only the synthetic identity and never touch host procfs.
pub(super) struct NamespacePin {
    pub(super) identity: String,
    #[cfg(target_os = "linux")]
    _file: Option<std::fs::File>,
}

pub(super) fn pin_namespace(path: &str) -> io::Result<NamespacePin> {
    #[cfg(test)]
    {
        let identity = test_support::call(test_support::Operation::Namespace(path))?;
        Ok(NamespacePin {
            identity,
            #[cfg(target_os = "linux")]
            _file: None,
        })
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        live_pin_namespace(path)
    }
}

#[cfg(target_os = "linux")]
fn live_pin_namespace(path: &str) -> io::Result<NamespacePin> {
    use std::os::unix::fs::MetadataExt;
    // File::open follows the procfs link and uses CLOEXEC. Obtain identity from
    // that same held fd, never from a second pathname lookup.
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    Ok(NamespacePin {
        identity: format!("{}:{}", metadata.dev(), metadata.ino()),
        _file: Some(file),
    })
}
#[cfg(test)]
pub(super) mod test_support {
    use std::{cell::RefCell, io};
    pub(crate) enum Operation<'a> {
        Read(&'a str),
        Namespace(&'a str),
        NetworkCookie,
        Target(&'a str),
        Write(&'a str, &'a str),
        ProcessExists(u32),
    }
    type Handler = Box<dyn FnMut(Operation<'_>) -> io::Result<String>>;
    thread_local! {
        static BACKEND: RefCell<Option<Handler>> = RefCell::new(None);
    }
    pub(super) fn call(operation: Operation<'_>) -> io::Result<String> {
        BACKEND.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .expect("sysctl host tests require isolated I/O")(operation)
        })
    }
    pub(crate) fn with_io<T>(
        handler: impl FnMut(Operation<'_>) -> io::Result<String> + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BACKEND.with(|slot| *slot.borrow_mut() = None);
                super::super::target::clear_test_cache();
            }
        }
        BACKEND.with(|slot| {
            assert!(slot.borrow().is_none(), "nested sysctl I/O override");
            *slot.borrow_mut() = Some(Box::new(handler));
        });
        let _reset = Reset;
        run()
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN; isolated thread-owned network namespaces"]
fn native_namespace_pin_survives_last_member_and_closes_on_drop() -> anyhow::Result<()> {
    use std::os::fd::AsRawFd;
    std::thread::spawn(|| -> anyhow::Result<()> {
        // SAFETY: only this disposable thread enters new namespaces.
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let pin = live_pin_namespace("/proc/thread-self/ns/net")?;
        let fd = pin._file.as_ref().unwrap().as_raw_fd();
        // No other process/thread lives in the first namespace after this call.
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let replacement = live_pin_namespace("/proc/thread-self/ns/net")?;
        anyhow::ensure!(pin.identity != replacement.identity);
        anyhow::ensure!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
        // The held namespace still exists and is usable, not merely a saved number.
        anyhow::ensure!(unsafe { libc::setns(fd, libc::CLONE_NEWNET) } == 0);
        anyhow::ensure!(live_pin_namespace("/proc/thread-self/ns/net")?.identity == pin.identity);
        let replacement_fd = replacement._file.as_ref().unwrap().as_raw_fd();
        anyhow::ensure!(unsafe { libc::setns(replacement_fd, libc::CLONE_NEWNET) } == 0);
        drop(pin);
        // This test runs alone; no intervening descriptor allocation can reuse fd.
        anyhow::ensure!(unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1);
        anyhow::ensure!(io::Error::last_os_error().raw_os_error() == Some(libc::EBADF));
        Ok(())
    })
    .join()
    .expect("namespace pin test panicked")
}

#[cfg(test)]
pub(super) fn target_identity(path: &str) -> io::Result<String> {
    test_support::call(test_support::Operation::Target(path))
}

/// A boot-local kernel generation independent of recyclable nsfs inode numbers.
/// No connect/bind or network traffic; the socket is closed before returning.
pub(super) fn network_cookie() -> io::Result<Option<u64>> {
    #[cfg(test)]
    {
        let value = test_support::call(test_support::Operation::NetworkCookie)?;
        if value == "unsupported" {
            Ok(None)
        } else {
            value
                .parse::<u64>()
                .ok()
                .filter(|v| *v != 0)
                .map(Some)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid network namespace cookie",
                    )
                })
        }
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        live_network_cookie()
    }
}

#[cfg(target_os = "linux")]
fn live_network_cookie() -> io::Result<Option<u64>> {
    crate::network_namespace::cookie()
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN and SO_NETNS_COOKIE; isolated namespaces"]
fn native_network_cookie_is_stable_and_distinguishes_new_namespaces() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: only this disposable thread changes network namespaces.
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let first = live_pin_namespace("/proc/thread-self/ns/net")?;
        let original =
            live_network_cookie()?.ok_or_else(|| anyhow::anyhow!("SO_NETNS_COOKIE unavailable"))?;
        anyhow::ensure!(live_network_cookie()? == Some(original));
        anyhow::ensure!(unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0);
        let next =
            live_network_cookie()?.ok_or_else(|| anyhow::anyhow!("SO_NETNS_COOKIE unavailable"))?;
        anyhow::ensure!(original != next);
        anyhow::ensure!(
            unsafe {
                libc::setns(
                    first._file.as_ref().unwrap().as_raw_fd(),
                    libc::CLONE_NEWNET,
                )
            } == 0
        );
        anyhow::ensure!(live_network_cookie()? == Some(original));
        Ok(())
    })
    .join()
    .expect("namespace cookie thread panicked")
}
