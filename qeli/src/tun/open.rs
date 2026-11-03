//! Shared Linux TUN/TAP opening policy, independent of ioctl transport.
use std::io;
pub(super) const IFF_TUN: i16 = 0x0001;
pub(super) const IFF_TAP: i16 = 0x0002;
pub(super) const IFF_NO_PI: i16 = 0x1000;
pub(super) const IFF_MULTI_QUEUE: i16 = 0x0100;
const IFF_TUN_EXCL: i16 = 0x8000u16 as i16;
const IFF_NAPI: i16 = 0x0010;
const IFF_NAPI_FRAGS: i16 = 0x0020;
const IFF_PERSIST: i16 = 0x0800;
const IFF_ONE_QUEUE: i16 = 0x2000;
const IFF_VNET_HDR: i16 = 0x4000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Tun,
    Tap,
}
#[derive(Clone, Copy)]
pub(super) enum OpenMode {
    Create,
    Attach,
}
pub(super) fn flags(kind: DeviceType, multiqueue: bool, mode: OpenMode) -> i16 {
    let mut flags = match kind {
        DeviceType::Tun => IFF_TUN,
        DeviceType::Tap => IFF_TAP,
    } | IFF_NO_PI;
    if multiqueue {
        flags |= IFF_MULTI_QUEUE;
    }
    if matches!(mode, OpenMode::Create) {
        flags |= IFF_TUN_EXCL;
    }
    flags
}
/// First queue creates exclusively; subsequent queues use the name returned by it.
/// Dropping the vector on any later error closes all queues already acquired.
pub(super) fn create_queues<T>(
    name: &str,
    kind: DeviceType,
    count: usize,
    mut open: impl FnMut(&str, i16) -> io::Result<T>,
    name_of: impl Fn(&T) -> &str,
) -> io::Result<Vec<T>> {
    let count = count.max(1);
    let mut queues = Vec::with_capacity(count);
    queues.push(open(name, flags(kind, true, OpenMode::Create))?);
    for _ in 1..count {
        queues.push(open(
            name_of(&queues[0]),
            flags(kind, true, OpenMode::Attach),
        )?);
    }
    Ok(queues)
}

/// Query the calling thread's network namespace, without relying on a sysfs mount.
#[cfg(all(target_os = "linux", any(feature = "client", feature = "server")))]
pub(crate) use crate::network_interface::index as interface_index;

#[cfg(test)]
#[path = "open_tests.rs"]
mod tests;

/// Linux ioctl transport for one newly opened queue descriptor.
pub(super) trait QueueIoctl {
    fn set_creation_index(&mut self, index: u32) -> io::Result<()>;
    fn set_interface(&mut self, name: &str, flags: i16) -> io::Result<String>;
}
pub(super) fn configure_queue(
    ioctl: &mut impl QueueIoctl,
    name: &str,
    flags: i16,
) -> io::Result<String> {
    if flags & IFF_TUN_EXCL == 0 {
        // TUNSETIFF has no attach-only flag. TUNSETIFINDEX affects only its CREATE
        // branch, so request Linux's permanently occupied loopback index there.
        // An existing device ignores this index; an absent one cannot register.
        // The newly opened TUN fd pins its network namespace, including loopback.
        // See Linux include/net/flow.h (LOOPBACK_IFINDEX), loopback_net_init(),
        // tun_set_iff() and register_netdevice(). Never fall back if the guard fails.
        ioctl.set_creation_index(1).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot prohibit TUN creation while attaching '{name}': {error}"),
            )
        })?;
    }
    ioctl.set_interface(name, flags)
}
pub(super) fn attachment_flags(name: &str, kind: DeviceType, observed: i16) -> io::Result<i16> {
    let expected = match kind {
        DeviceType::Tun => IFF_TUN,
        DeviceType::Tap => IFF_TAP,
    };
    if observed & (IFF_TUN | IFF_TAP) != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("existing interface '{name}' does not match device_type"),
        ));
    }
    if observed & IFF_NO_PI == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("existing interface '{name}' includes a packet-information header; qeli dev_attach requires IFF_NO_PI")));
    }
    if observed & IFF_VNET_HDR != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("existing interface '{name}' uses IFF_VNET_HDR; qeli dev_attach requires packets without a virtio header")));
    }
    let supported = IFF_TUN
        | IFF_TAP
        | IFF_NO_PI
        | IFF_MULTI_QUEUE
        | IFF_ONE_QUEUE
        | IFF_NAPI
        | IFF_NAPI_FRAGS
        | IFF_PERSIST;
    if observed & !supported != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("existing interface '{name}' has unsupported tun_flags {:#x}; refusing to reset its features", observed as u16)));
    }
    // The first attachment can rewrite TUN_FEATURES. Preserve every accepted feature;
    // IFF_PERSIST is read-only here and must not become a persistence-changing ioctl.
    Ok(observed & !IFF_PERSIST)
}
#[cfg(test)]
#[path = "attach_tests.rs"]
mod attach_tests;

pub(super) fn parse_tun_flags(value: &str) -> io::Result<i16> {
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
    Ok(parsed as i16)
}

#[cfg(test)]
mod parser_tests {
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
