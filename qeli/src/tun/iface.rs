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
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
// Allow several independent fds (queues) to attach to one device; the kernel then
// RSS-distributes packets across them so the data plane can read/write the TUN
// from multiple cores in parallel (Linux IFF_MULTI_QUEUE).
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    ifr_pad: [u8; 22],
}

#[derive(Clone, Copy, PartialEq)]
pub enum DeviceType {
    Tun,
    Tap,
}

pub struct TunInterface {
    pub fd: File,
    pub name: String,
    pub mtu: i32,
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
        let flags_path = format!("/sys/class/net/{name}/tun_flags");
        let flags_text = std::fs::read_to_string(&flags_path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("could not inspect existing TUN/TAP '{name}' via {flags_path}: {error}"),
            )
        })?;
        let flags = parse_tun_flags(&flags_text)?;
        let expected_kind = match device_type {
            DeviceType::Tun => IFF_TUN,
            DeviceType::Tap => IFF_TAP,
        };
        let actual_kind = flags & (IFF_TUN | IFF_TAP);
        if actual_kind != expected_kind {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "existing interface '{name}' has tun_flags {:#x}, which does not match device_type = {}",
                    flags,
                    if device_type == DeviceType::Tap { "tap" } else { "tun" }
                ),
            ));
        }
        if flags & IFF_NO_PI == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "existing interface '{name}' includes a packet-information header; qeli dev_attach requires IFF_NO_PI"
                ),
            ));
        }
        Self::open_device(name, mtu, device_type, flags & IFF_MULTI_QUEUE != 0)
    }

    fn create_device(name: &str, mtu: i32, device_type: DeviceType) -> io::Result<Self> {
        Self::open_device(name, mtu, device_type, false)
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
        let n = n.max(1);
        let mut queues = Vec::with_capacity(n);
        for _ in 0..n {
            queues.push(Self::open_device(name, mtu, device_type, true)?);
        }
        Ok(queues)
    }

    /// Open a single TUN/TAP queue fd. With `multiqueue`, sets `IFF_MULTI_QUEUE` so
    /// several fds can attach to the same named device.
    fn open_device(
        name: &str,
        mtu: i32,
        device_type: DeviceType,
        multiqueue: bool,
    ) -> io::Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut flags = match device_type {
            DeviceType::Tun => IFF_TUN | IFF_NO_PI,
            DeviceType::Tap => IFF_TAP | IFF_NO_PI,
        };
        if multiqueue {
            flags |= IFF_MULTI_QUEUE;
        }

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
                fd.as_raw_fd(),
                // `as _`: тип запроса — c_ulong (glibc) или c_int (musl).
                TUNSETIFF as _,
                &ifr as *const _ as *const libc::c_void,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_name = std::str::from_utf8(&ifr.ifr_name)
            .unwrap_or(name)
            .trim_end_matches('\0')
            .to_string();

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
        let output = std::process::Command::new("ip")
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
        let output = std::process::Command::new("ip")
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
        let output = std::process::Command::new("ip")
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
        let output = std::process::Command::new("ip")
            .args(["link", "set", "dev", ifname, "txqueuelen", &len.to_string()])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Operation not supported") {
                return Err(io::Error::other(stderr.to_string()));
            }
        }
        Ok(())
    }

    pub fn delete(ifname: &str) -> io::Result<()> {
        // Try both tuntap modes, each with and without `multi_queue`. The device is exactly
        // one combination, and the name prefix doesn't reliably tell us which (a TAP may be
        // named "vpn0", a TUN "tap0"). The matching form removes it; the others no-op with
        // "No such device". This stays scoped to tuntap, so a same-named non-tuntap interface
        // (WireGuard / ethernet) is never touched.
        //
        // The `multi_queue` variants are why this is a four-way loop rather than the original
        // two: `ip tuntap del` reconstructs the interface flags and calls TUNSETIFF, so
        // deleting an IFF_MULTI_QUEUE device WITHOUT that flag fails with a bare
        // `ioctl(TUNSETIFF): Invalid argument`. Every server profile creates a multi-queue
        // device (`create_multiqueue`, queues default to one per core), so this function could
        // not delete the devices this codebase actually makes — silently, because both call
        // sites used `.ok()`. That left a stale interface behind whenever a profile stopped or
        // failed to start, and made the "delete any leftover first" step at profile start a
        // no-op. Verified on the lab: plain del → EINVAL and the device survives; with
        // `multi_queue` → removed. (Audit 2026-08-01, §5.)
        let mut hard_err = None;
        for mode in ["tun", "tap"] {
            for mq in [true, false] {
                let mut args = vec!["tuntap", "del", "mode", mode];
                if mq {
                    args.push("multi_queue");
                }
                args.extend(["name", ifname]);
                let output = std::process::Command::new("ip").args(&args).output()?;
                if output.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("No such device") || stderr.contains("does not exist") {
                    continue; // wrong mode/queueing for this device, or it's already gone
                }
                hard_err = Some(stderr.to_string());
            }
        }
        // Nothing deleted it: either it was absent (fine) or one form failed for a real reason
        // (busy/permission) — surface that.
        match hard_err {
            Some(e) => Err(io::Error::other(e)),
            None => Ok(()),
        }
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

fn parse_tun_flags(value: &str) -> io::Result<libc::c_short> {
    let value = value.trim();
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse::<u16>()
    }
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid tun_flags value '{value}': {error}"),
        )
    })?;
    Ok(parsed as libc::c_short)
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
mod tests {
    use super::*;

    #[test]
    fn tun_flags_parser_accepts_kernel_hex_and_decimal_forms() {
        assert_eq!(
            parse_tun_flags("0x1102\n").unwrap(),
            IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE
        );
        assert_eq!(parse_tun_flags("4097").unwrap(), IFF_TUN | IFF_NO_PI);
        assert!(parse_tun_flags("not-flags").is_err());
    }
}
