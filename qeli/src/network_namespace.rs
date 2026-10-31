//! Live namespace evidence. Holding the descriptor prevents namespace identity reuse
//! while this route owner (or its unresolved orphan reservation) exists.
use std::os::unix::fs::MetadataExt;
use std::{fs::File, io};

#[derive(Debug)]
pub(crate) enum Namespace {
    Pinned(File),
    // This is not a fabricated namespace inode/cookie. The kernel has exactly one
    // network context for this boot; only the client may opt into this evidence.
    #[cfg(any(test, feature = "client"))]
    SingleNetwork(String),
}
impl Namespace {
    pub(crate) fn capture() -> anyhow::Result<Self> {
        Ok(Self::Pinned(open_thread_namespace("net")?))
    }
    #[cfg(any(test, feature = "client"))]
    pub(crate) fn capture_client() -> anyhow::Result<Self> {
        match open_thread_namespace("net") {
            Ok(file) => Ok(Self::Pinned(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let boot = single_network_boot()?;
                Ok(Self::SingleNetwork(boot))
            }
            Err(error) => Err(error.into()),
        }
    }
    #[cfg(any(test, feature = "client"))]
    pub(crate) fn is_single_network(&self) -> bool {
        matches!(self, Self::SingleNetwork(_))
    }
    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        match self {
            Self::Pinned(file) => {
                let expected = file.metadata()?;
                let actual = open_thread_namespace("net")?.metadata()?;
                anyhow::ensure!(
                    (expected.dev(), expected.ino()) == (actual.dev(), actual.ino()),
                    "network namespace changed; refusing network commands"
                );
            }
            #[cfg(any(test, feature = "client"))]
            Self::SingleNetwork(boot) => {
                anyhow::ensure!(
                    boot == &single_network_boot()?,
                    "single-network boot changed"
                );
            }
        }
        Ok(())
    }
}

/// Unlike /proc/self/ns, both paths identify the CALLING THREAD after setns.
pub(crate) fn open_thread_namespace(name: &str) -> io::Result<File> {
    match File::open(format!("/proc/thread-self/ns/{name}")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // SAFETY: gettid has no arguments and no side effects.
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            File::open(format!("/proc/self/task/{tid}/ns/{name}"))
        }
        result => result,
    }
}

#[cfg(any(test, feature = "client"))]
fn boot_id() -> anyhow::Result<String> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    anyhow::ensure!(
        boot.len() == 36
            && boot.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            }),
        "invalid kernel boot_id"
    );
    Ok(boot.to_owned())
}

#[cfg(any(test, feature = "client"))]
fn accepts_single_network(seccomp: Option<u32>, probe_errno: Option<i32>) -> bool {
    // Missing procfs entries, EPERM, ENOSYS, hidden namespaces or a seccomp-made
    // EINVAL are NOT evidence. Linux returns EINVAL for disabled CONFIG_NET_NS.
    seccomp.is_none_or(|mode| mode == 0) && probe_errno == Some(libc::EINVAL)
}

#[cfg(any(test, feature = "client"))]
fn prove_single_network() -> anyhow::Result<()> {
    let probe = std::thread::Builder::new().name("qeli-netns-probe".into()).spawn(|| -> anyhow::Result<()> {
        let status = std::fs::read_to_string("/proc/thread-self/status")
            .or_else(|_| {
                // SAFETY: gettid only obtains the current thread ID.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                std::fs::read_to_string(format!("/proc/self/task/{tid}/status"))
            })?;
        let seccomp = status.lines().find_map(|line| line.strip_prefix("Seccomp:"))
            .map(|value| value.trim().parse::<u32>()).transpose()?;
        anyhow::ensure!(seccomp.is_none_or(|mode| mode == 0),
            "network namespace support cannot be determined under seccomp");
        // A procfs bind-over can hide ns/net. Probe the kernel on a disposable
        // thread, never on a transaction/application thread. A successful unshare
        // affects this thread only and is immediately discarded on return.
        // SAFETY: CLONE_NEWNET does not change shared filesystem/FD/process state.
        let result = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        let errno = (result < 0).then(|| io::Error::last_os_error().raw_os_error()).flatten();
        anyhow::ensure!(accepts_single_network(seccomp, errno),
            "ns/net is unavailable but absence of CONFIG_NET_NS could not be proven (unshare errno {errno:?}); refusing unscoped network changes");
        Ok(())
    })?;
    probe
        .join()
        .map_err(|_| anyhow::anyhow!("network namespace capability probe panicked"))??;
    Ok(())
}

#[cfg(any(test, feature = "client"))]
fn single_network_boot() -> anyhow::Result<String> {
    // Only positive kernel evidence is cached. Kernel configuration cannot change
    // without a reboot; procfs absence and boot identity are still checked each time.
    static VERIFIED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    match open_thread_namespace("net") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("network namespaces are available; singleton evidence is invalid"),
    }
    let boot = boot_id()?;
    if let Some(expected) = VERIFIED.get() {
        anyhow::ensure!(expected == &boot, "kernel boot identity changed");
    } else {
        prove_single_network()?;
        let _ = VERIFIED.set(boot.clone());
        anyhow::ensure!(
            VERIFIED.get() == Some(&boot),
            "kernel boot identity changed"
        );
        log::warn!("Client compatibility mode: kernel has no network namespaces; routes remain boot-scoped, DNS must be managed by the router (dns=off), host sysctls are read-only");
    }
    Ok(boot)
}

/// Kernel generation identifier; unlike nsfs inode numbers it is not recycled in a boot.
pub(crate) fn cookie() -> io::Result<Option<u64>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: fixed socket arguments; ownership of a successful fd is transferred once.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut cookie = 0u64;
    let mut length = std::mem::size_of_val(&cookie) as libc::socklen_t;
    // SAFETY: both output pointers are valid with the supplied buffer size.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&mut cookie as *mut u64).cast(),
            &mut length,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Ok(None);
        }
        return Err(error);
    }
    if length as usize != std::mem::size_of_val(&cookie) || cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SO_NETNS_COOKIE response",
        ));
    }
    Ok(Some(cookie))
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    #[test]
    fn singleton_requires_positive_kernel_evidence_not_an_access_error() {
        assert!(accepts_single_network(Some(0), Some(libc::EINVAL)));
        assert!(accepts_single_network(None, Some(libc::EINVAL)));
        for errno in [
            None,
            Some(libc::EPERM),
            Some(libc::ENOSYS),
            Some(libc::EACCES),
        ] {
            assert!(!accepts_single_network(Some(0), errno));
        }
        assert!(!accepts_single_network(Some(2), Some(libc::EINVAL)));
        assert!(!accepts_single_network(Some(1), Some(libc::EINVAL)));
    }
    #[test]
    fn current_namespace_uses_thread_scoped_evidence() -> anyhow::Result<()> {
        let namespace = Namespace::capture()?;
        assert!(!namespace.is_single_network());
        namespace.verify()
    }
}
