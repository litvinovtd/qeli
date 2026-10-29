// Device-introspection fields are kept as API surface even when one path does not read them.
#![allow(dead_code)]
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

// Запрос ioctl TUNSETIFF. Кодировка `_IOW` на MIPS отличается от asm-generic
// (x86/arm/arm64), поэтому ЗНАЧЕНИЕ арк-специфично (0x800454ca против 0x400454ca).
// ТИП запроса тоже зависит от платформы (`c_ulong` на glibc, `c_int` на musl) —
// кастуем `as _` на месте вызова (см. ниже).
#[cfg(any(target_arch = "mips", target_arch = "mips64"))]
const TUNSETIFF: libc::c_ulong = 0x800454ca;
#[cfg(not(any(target_arch = "mips", target_arch = "mips64")))]
const TUNSETIFF: libc::c_ulong = 0x400454ca;
pub use super::open::DeviceType;
use super::open::{self, OpenMode, QueueIoctl};

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    ifr_pad: [u8; 22],
}

pub struct TunInterface {
    pub fd: File,
    pub name: String,
    pub mtu: i32,
}

struct QueueDescriptor<'a>(&'a File);

impl QueueIoctl for QueueDescriptor<'_> {
    fn set_creation_index(&mut self, index: u32) -> io::Result<()> {
        // SAFETY: ioctl reads one initialized u32 and self.0 owns the live TUN fd.
        let result = unsafe { libc::ioctl(self.0.as_raw_fd(), libc::TUNSETIFINDEX as _, &index) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_interface(&mut self, name: &str, flags: i16) -> io::Result<String> {
        let mut ifr = IfReq {
            ifr_name: [0u8; 16],
            ifr_flags: flags,
            ifr_pad: [0u8; 22],
        };
        let name_bytes = name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 15);
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        let ret = unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                TUNSETIFF as _,
                &mut ifr as *mut _ as *mut libc::c_void,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let actual_name = std::str::from_utf8(&ifr.ifr_name)
            .unwrap_or(name)
            .trim_end_matches('\0')
            .to_string();
        Ok(actual_name)
    }
}

impl TunInterface {
    pub fn create(name: &str, mtu: i32) -> io::Result<Self> {
        Self::create_device(name, mtu, DeviceType::Tun)
    }

    pub fn create_tap(name: &str, mtu: i32) -> io::Result<Self> {
        Self::create_device(name, mtu, DeviceType::Tap)
    }

    /// Attach one fd to an externally-owned TUN/TAP without guessing its queue mode from
    /// the configured name. Linux requires IFF_MULTI_QUEUE to match the existing device;
    /// TUNSETIFF otherwise fails with EINVAL. qeli's packet pump also requires IFF_NO_PI.
    pub fn attach(name: &str, mtu: i32, device_type: DeviceType) -> io::Result<Self> {
        let index = Self::verify_sysfs_index(name)?;
        let flags_path = format!("/sys/class/net/{name}/tun_flags");
        let flags_text = std::fs::read_to_string(&flags_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not inspect existing TUN/TAP '{name}' via {flags_path}: {error}"),
            )
        })?;
        let observed = open::parse_tun_flags(&flags_text)?;
        let flags = open::attachment_flags(name, device_type, observed)?;
        if Self::verify_sysfs_index(name)? != index {
            return Err(io::Error::other(format!(
                "existing TUN/TAP '{name}' changed while inspecting sysfs"
            )));
        }
        Self::open_device(name, mtu, flags)
    }

    /// sysfs can remain mounted from another network namespace after setns/unshare.
    /// An index mismatch proves its tun_flags belong to a different link. Matching
    /// indexes alone do not prove identity across namespaces (indexes can be reused).
    fn verify_sysfs_index(name: &str) -> io::Result<u32> {
        let current = open::interface_index(name)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("TUN/TAP '{name}' does not exist"),
            )
        })?;
        let path = format!("/sys/class/net/{name}/ifindex");
        let text = std::fs::read_to_string(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not inspect existing TUN/TAP '{name}' via {path}: {error}"),
            )
        })?;
        let mounted = text.trim().parse::<u32>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TUN/TAP ifindex in {path}: {error}"),
            )
        })?;
        if current != mounted {
            return Err(io::Error::other(format!(
                "TUN/TAP '{name}' has index {current} in the current network namespace but index {mounted} in sysfs; refusing foreign tun_flags"
            )));
        }
        Ok(current)
    }

    fn create_device(name: &str, mtu: i32, device_type: DeviceType) -> io::Result<Self> {
        Self::open_device(name, mtu, open::flags(device_type, false, OpenMode::Create))
    }

    /// Create `n` multi-queue fds attached to ONE device `name`. The first fd
    /// creates the interface; the rest add queues. All carry `IFF_MULTI_QUEUE`.
    /// `n` is clamped to >= 1. Every returned `TunInterface` must stay open to keep
    /// the device alive (a non-persistent device dies when its last queue closes).
    pub fn create_multiqueue(
        name: &str,
        mtu: i32,
        device_type: DeviceType,
        n: usize,
    ) -> io::Result<Vec<Self>> {
        open::create_queues(
            name,
            device_type,
            n,
            |name, flags| Self::open_device(name, mtu, flags),
            |queue| queue.name.as_str(),
        )
    }

    /// Open one queue using the shared create/attach policy. IFF_TUN_EXCL makes
    /// creation reject a device that appeared after the caller's existence check.
    fn open_device(name: &str, mtu: i32, flags: i16) -> io::Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let actual_name = open::configure_queue(&mut QueueDescriptor(&fd), name, flags)?;
        Ok(TunInterface {
            fd,
            name: actual_name,
            mtu,
        })
    }

    pub fn set_address(ifname: &str, address: &str, prefix: u8) -> io::Result<()> {
        let address_family = address.parse::<std::net::IpAddr>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid IP address '{address}': {error}"),
            )
        })?;
        let max_prefix = if address_family.is_ipv4() { 32 } else { 128 };
        if prefix == 0 || prefix > max_prefix {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid {} prefix /{prefix}",
                    if address_family.is_ipv4() {
                        "IPv4"
                    } else {
                        "IPv6"
                    }
                ),
            ));
        }
        let output = crate::system_command::Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{}/{}", address, prefix),
                "dev",
                ifname,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                return Err(io::Error::other(stderr.to_string()));
            }
        }
        Ok(())
    }

    pub fn set_up(ifname: &str, mtu: i32) -> io::Result<()> {
        let output = crate::system_command::Command::new("ip")
            .args(["link", "set", "dev", ifname, "up", "mtu", &mtu.to_string()])
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(())
    }

    pub fn set_mac(ifname: &str, mac: [u8; 6]) -> io::Result<()> {
        let address = mac
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let output = crate::system_command::Command::new("ip")
            .args(["link", "set", "dev", ifname, "address", &address])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(())
    }

    pub fn set_queue_len(ifname: &str, len: u32) -> io::Result<()> {
        Self::set_queue_len_impl(ifname, len, true)
    }

    /// Client policy must not report a configured queue if the kernel rejected it.
    pub fn set_queue_len_strict(ifname: &str, len: u32) -> io::Result<()> {
        Self::set_queue_len_impl(ifname, len, false)
    }

    fn set_queue_len_impl(ifname: &str, len: u32, allow_unsupported: bool) -> io::Result<()> {
        let output = crate::system_command::Command::new("ip")
            .args(["link", "set", "dev", ifname, "txqueuelen", &len.to_string()])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !allow_unsupported || !stderr.contains("Operation not supported") {
                return Err(io::Error::other(stderr.to_string()));
            }
        }
        Ok(())
    }

    /// Observe the device attached to this descriptor, including a renamed interface.
    /// None means the original was externally unregistered; never resolve its saved name.
    #[cfg(any(test, feature = "client"))]
    fn attached_name(&self) -> io::Result<Option<String>> {
        let mut ifr = IfReq {
            ifr_name: [0; 16],
            ifr_flags: 0,
            ifr_pad: [0; 22],
        };
        // SAFETY: the descriptor is owned, and ifr provides the complete writable ifreq.
        if unsafe { libc::ioctl(self.as_raw_fd(), libc::TUNGETIFF as _, &mut ifr) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADFD) {
                return Ok(None);
            }
            return Err(error);
        }
        let name = std::ffi::CStr::from_bytes_until_nul(&ifr.ifr_name)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            .to_str()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(Some(name.to_string()))
    }

    #[cfg(any(test, feature = "client"))]
    fn require_attached_namespace(&self) -> io::Result<bool> {
        use std::os::unix::{fs::MetadataExt, io::FromRawFd};
        let context =
            crate::network_namespace::Namespace::capture_client().map_err(io::Error::other)?;
        if context.is_single_network() {
            // Older router kernels also lack TUNGETDEVNETNS. Kernel-proven
            // absence of NET_NS means a live TUN cannot belong to another one.
            // attached_name still uses TUNGETIFF on the ORIGINAL descriptor.
            context.verify().map_err(io::Error::other)?;
            return Ok(true);
        }
        // SAFETY: this ioctl returns a newly owned namespace fd on success.
        let fd = unsafe { libc::ioctl(self.as_raw_fd(), libc::TUNGETDEVNETNS as _) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADFD) {
                return Ok(false);
            }
            return Err(io::Error::new(
                error.kind(),
                format!("cannot verify TUN namespace with TUNGETDEVNETNS: {error}"),
            ));
        }
        // SAFETY: the successful ioctl transferred this new fd, released on every exit.
        let namespace = unsafe { File::from_raw_fd(fd) };
        let original = namespace.metadata()?;
        let current = crate::network_namespace::open_thread_namespace("net")?.metadata()?;
        if (original.dev(), original.ino()) != (current.dev(), current.ino()) {
            return Err(io::Error::other(
                "TUN belongs to a different network namespace",
            ));
        }
        Ok(true)
    }

    #[cfg(any(test, feature = "client"))]
    pub(crate) fn attached_link(&self) -> io::Result<Option<(String, u32)>> {
        if !self.require_attached_namespace()? {
            return Ok(None);
        }
        let Some(name) = self.attached_name()? else {
            return Ok(None);
        };
        let index = open::interface_index(&name)?;
        let Some(after) = self.attached_name()? else {
            return Ok(None);
        };
        if !self.require_attached_namespace()? {
            return Ok(None);
        }
        if name != after || index.is_none() {
            return Err(io::Error::other("TUN identity changed during observation"));
        }
        Ok(Some((name, index.expect("checked above"))))
    }

    pub fn set_nonblocking(&self) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let ret =
            unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Read for TunInterface {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }
}

impl Write for TunInterface {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
}

impl AsRawFd for TunInterface {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
#[path = "attach_linux_tests.rs"]
mod linux_tests;
