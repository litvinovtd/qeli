//! Query the calling namespace through a socket, never an inherited sysfs mount.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

struct Query(OwnedFd);
impl Query {
    fn open() -> io::Result<Self> {
        // SAFETY: no pointers; a successful call returns one owned descriptor.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: ownership of the fresh descriptor is transferred exactly once.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
    fn request(&self, name: &str, request: libc::c_ulong) -> io::Result<libc::ifreq> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        // SAFETY: zero is a valid initial representation of the name/union storage.
        let mut value: libc::ifreq = unsafe { std::mem::zeroed() };
        for (to, from) in value.ifr_name.iter_mut().zip(name.bytes()) {
            *to = from as libc::c_char;
        }
        // SAFETY: initialized ifreq remains live and writable for the ioctl; the
        // platform libc supplies the layout and ioctl request type (glibc/musl).
        if unsafe { libc::ioctl(self.0.as_raw_fd(), request as _, &mut value) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }
    fn index(&self, name: &str) -> io::Result<u32> {
        let result = self.request(name, libc::SIOCGIFINDEX as _)?;
        // SAFETY: a successful SIOCGIFINDEX initialized this union member.
        let index = unsafe { result.ifr_ifru.ifru_ifindex };
        if index <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid interface index",
            ));
        }
        Ok(index as u32)
    }
}

/// Only an explicit ENODEV means absent; permission/socket/protocol errors are unknown.
pub(crate) fn index(name: &str) -> io::Result<Option<u32>> {
    match Query::open()?.index(name) {
        Ok(index) => Ok(Some(index)),
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Observe both fields through one socket pinned to the same namespace. The second
/// index query detects ordinary rename/replacement during observation; it does not
/// make a subsequent operation atomic against privileged external link changes.
pub(crate) fn ethernet(name: &str) -> io::Result<(u32, [u8; 6])> {
    let query = Query::open()?;
    let index = query.index(name)?;
    let result = query.request(name, libc::SIOCGIFHWADDR as _)?;
    // SAFETY: successful SIOCGIFHWADDR initialized this union member.
    let address = unsafe { result.ifr_ifru.ifru_hwaddr };
    if address.sa_family != libc::ARPHRD_ETHER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "interface '{name}' is not Ethernet-compatible (ARPHRD {})",
                address.sa_family
            ),
        ));
    }
    let mac = std::array::from_fn(|i| address.sa_data[i] as u8);
    if query.index(name)? != index {
        return Err(io::Error::other(format!(
            "interface '{name}' changed during observation"
        )));
    }
    Ok((index, mac))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_names_never_alias_another_interface() {
        for name in ["", "abcdefghijklmnop", "lo\0other"] {
            assert_eq!(index(name).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }
    #[test]
    fn non_ethernet_link_is_not_interpreted_as_a_mac() {
        assert!(index("lo").unwrap().is_some());
        assert_eq!(
            ethernet("lo").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and ip; isolated netns"]
    fn native_interface_queries_ignore_inherited_sysfs() -> anyhow::Result<()> {
        std::thread::spawn(|| -> anyhow::Result<()> {
            // SAFETY: only this disposable thread changes namespace.
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            let name = "qeli-view0";
            anyhow::ensure!(
                !std::path::Path::new(&format!("/sys/class/net/{name}")).exists(),
                "fixture requires inherited sysfs without test link"
            );
            for args in [
                vec!["link", "add", name, "type", "dummy"],
                vec!["link", "set", name, "address", "02:12:34:56:78:9a"],
            ] {
                let output = crate::system_command::Command::new("ip")
                    .args(args)
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "ip fixture: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let (observed_index, mac) = ethernet(name)?;
            anyhow::ensure!(Some(observed_index) == index(name)?);
            anyhow::ensure!(mac == [2, 0x12, 0x34, 0x56, 0x78, 0x9a]);
            anyhow::ensure!(!std::path::Path::new(&format!("/sys/class/net/{name}")).exists());
            let output = crate::system_command::Command::new("ip")
                .args(["link", "del", name])
                .output()?;
            anyhow::ensure!(output.status.success());
            anyhow::ensure!(index(name)?.is_none());
            Ok(())
        })
        .join()
        .expect("native interface test panicked")
    }
}
