//! Live namespace evidence. Holding the descriptor prevents namespace identity reuse
//! while this route owner (or its unresolved orphan reservation) exists.
use std::os::unix::fs::MetadataExt;
use std::{fs::File, io};

#[derive(Debug)]
pub(crate) struct Namespace(File);
impl Namespace {
    pub(crate) fn capture() -> anyhow::Result<Self> {
        Ok(Self(File::open("/proc/thread-self/ns/net")?))
    }
    pub(crate) fn verify(&self) -> anyhow::Result<()> {
        let expected = self.0.metadata()?;
        let actual = std::fs::metadata("/proc/thread-self/ns/net")?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
            anyhow::bail!("network namespace changed; refusing network commands");
        }
        Ok(())
    }
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
