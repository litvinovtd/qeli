use super::*;
use std::cell::RefCell;
#[derive(Default)]
struct Kernel {
    exists: bool,
    creations: usize,
    opens: usize,
    flags: i16,
    index_error: Option<io::ErrorKind>,
    events: Vec<&'static str>,
}
struct Descriptor<'a> {
    kernel: &'a RefCell<Kernel>,
    creation_index: u32,
}
impl QueueIoctl for Descriptor<'_> {
    fn set_creation_index(&mut self, index: u32) -> io::Result<()> {
        let mut kernel = self.kernel.borrow_mut();
        kernel.events.push("set-index");
        if let Some(error) = kernel.index_error {
            return Err(error.into());
        }
        self.creation_index = index;
        Ok(())
    }
    fn set_interface(&mut self, name: &str, flags: i16) -> io::Result<String> {
        let mut kernel = self.kernel.borrow_mut();
        kernel.events.push("set-iff");
        if kernel.exists && flags as u16 & 0x8000 != 0 {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if !kernel.exists {
            // Loopback keeps index 1 occupied in this namespace. A requested
            // creation index cannot be allocated a second time.
            if self.creation_index == 1 {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            kernel.creations += 1;
            kernel.exists = true;
        }
        kernel.opens += 1;
        // First attachment can rewrite the device feature flags.
        kernel.flags = flags;
        Ok(name.to_string())
    }
}
fn queue(kernel: &RefCell<Kernel>, name: &str, flags: i16) -> io::Result<String> {
    configure_queue(
        &mut Descriptor {
            kernel,
            creation_index: 0,
        },
        name,
        flags,
    )
}
fn borrow(kernel: &RefCell<Kernel>, kind: DeviceType, observed: i16) -> io::Result<String> {
    queue(kernel, "vpn0", attachment_flags("vpn0", kind, observed)?)
}
#[test]
fn regression_missing_attach_never_creates_device() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        for mq in [false, true] {
            let kernel = RefCell::new(Kernel::default());
            assert!(borrow(&kernel, kind, flags(kind, mq, OpenMode::Attach)).is_err());
            assert_eq!(kernel.borrow().creations, 0);
            assert!(!kernel.borrow().exists);
        }
    }
}
#[test]
fn regression_later_queue_disappearance_never_creates_replacement() {
    let kernel = RefCell::new(Kernel::default());
    let result = create_queues(
        "vpn0",
        DeviceType::Tun,
        3,
        |name, flags| {
            if kernel.borrow().opens == 1 {
                kernel.borrow_mut().exists = false;
            }
            queue(&kernel, name, flags)
        },
        |name| name.as_str(),
    );
    assert!(result.is_err());
    assert_eq!(kernel.borrow().creations, 1);
    assert_eq!(kernel.borrow().opens, 1);
}
#[test]
fn regression_creation_guard_failure_never_reaches_attachment() {
    for error in [
        io::ErrorKind::Unsupported,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Other,
    ] {
        let kernel = RefCell::new(Kernel {
            exists: true,
            index_error: Some(error),
            ..Kernel::default()
        });
        assert!(queue(
            &kernel,
            "vpn0",
            flags(DeviceType::Tun, true, OpenMode::Attach)
        )
        .is_err());
        assert_eq!(kernel.borrow().opens, 0);
        assert!(!kernel.borrow().events.contains(&"set-iff"));
    }
}
#[test]
fn regression_vnet_header_device_is_rejected_before_opening() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        for mq in [false, true] {
            let observed = flags(kind, mq, OpenMode::Attach) | 0x4000;
            let kernel = RefCell::new(Kernel {
                exists: true,
                flags: observed,
                ..Kernel::default()
            });
            assert!(borrow(&kernel, kind, observed).is_err());
            assert_eq!(kernel.borrow().flags, observed);
            assert!(kernel.borrow().events.is_empty());
        }
    }
}
#[test]
fn regression_attach_preserves_existing_features() {
    for extra in [0x2000, 0x0010, 0x0030] {
        let observed = flags(DeviceType::Tap, true, OpenMode::Attach) | extra;
        let kernel = RefCell::new(Kernel {
            exists: true,
            flags: observed,
            ..Kernel::default()
        });
        borrow(&kernel, DeviceType::Tap, observed).unwrap();
        assert_eq!(kernel.borrow().flags, observed);
    }
}
#[test]
fn regression_unknown_device_features_are_not_silently_cleared() {
    let observed = flags(DeviceType::Tun, false, OpenMode::Attach) | 0x0040;
    let kernel = RefCell::new(Kernel {
        exists: true,
        flags: observed,
        ..Kernel::default()
    });
    assert!(borrow(&kernel, DeviceType::Tun, observed).is_err());
    assert!(kernel.borrow().events.is_empty());
    assert_eq!(kernel.borrow().flags, observed);
}
#[test]
fn compatible_existing_tun_and_tap_still_attach() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        for mq in [false, true] {
            let observed = flags(kind, mq, OpenMode::Attach);
            let kernel = RefCell::new(Kernel {
                exists: true,
                flags: observed,
                ..Kernel::default()
            });
            assert_eq!(borrow(&kernel, kind, observed).unwrap(), "vpn0");
            assert_eq!(kernel.borrow().creations, 0);
            assert_eq!(kernel.borrow().opens, 1);
        }
    }
}
#[test]
fn exclusive_create_still_creates_one_device() {
    let kernel = RefCell::new(Kernel::default());
    queue(
        &kernel,
        "vpn0",
        flags(DeviceType::Tun, false, OpenMode::Create),
    )
    .unwrap();
    assert_eq!(kernel.borrow().creations, 1);
}
#[test]
fn mismatched_kind_and_packet_information_header_are_refused() {
    for observed in [IFF_TAP | IFF_NO_PI, IFF_TUN, IFF_TUN | IFF_TAP | IFF_NO_PI] {
        assert!(attachment_flags("vpn0", DeviceType::Tun, observed).is_err());
    }
}
#[test]
fn multiqueue_create_keeps_one_device() {
    let kernel = RefCell::new(Kernel::default());
    let result = create_queues(
        "vpn0",
        DeviceType::Tun,
        3,
        |name, flags| queue(&kernel, name, flags),
        |name| name.as_str(),
    )
    .unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(kernel.borrow().creations, 1);
    assert_eq!(kernel.borrow().opens, 3);
}

#[test]
fn guard_is_installed_before_every_attach_ioctl() {
    let kernel = RefCell::new(Kernel {
        exists: true,
        ..Kernel::default()
    });
    queue(
        &kernel,
        "vpn0",
        flags(DeviceType::Tun, false, OpenMode::Attach),
    )
    .unwrap();
    assert_eq!(kernel.borrow().events, ["set-index", "set-iff"]);
}
#[test]
fn exclusive_creation_does_not_require_attach_guard_support() {
    let kernel = RefCell::new(Kernel {
        index_error: Some(io::ErrorKind::Unsupported),
        ..Kernel::default()
    });
    queue(
        &kernel,
        "vpn0",
        flags(DeviceType::Tap, true, OpenMode::Create),
    )
    .unwrap();
    assert_eq!(kernel.borrow().events, ["set-iff"]);
}
#[test]
fn guard_failure_prevents_replacement_even_when_target_is_absent() {
    let kernel = RefCell::new(Kernel {
        index_error: Some(io::ErrorKind::PermissionDenied),
        ..Kernel::default()
    });
    let error = queue(
        &kernel,
        "vpn0",
        flags(DeviceType::Tun, true, OpenMode::Attach),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("cannot prohibit TUN creation"));
    assert_eq!(kernel.borrow().creations, 0);
}
#[test]
fn guard_on_later_queue_stops_multiqueue_at_first_failure() {
    let kernel = RefCell::new(Kernel {
        index_error: Some(io::ErrorKind::Unsupported),
        ..Kernel::default()
    });
    assert!(create_queues(
        "vpn0",
        DeviceType::Tun,
        3,
        |name, flags| queue(&kernel, name, flags),
        |name| name.as_str()
    )
    .is_err());
    assert_eq!(kernel.borrow().opens, 1);
    assert_eq!(kernel.borrow().events, ["set-iff", "set-index"]);
}
#[test]
fn persistence_bit_is_not_replayed_as_a_create_or_control_flag() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        let expected = flags(kind, true, OpenMode::Attach) | 0x2000;
        assert_eq!(
            attachment_flags("vpn0", kind, expected | 0x0800).unwrap(),
            expected
        );
    }
}
#[test]
fn unsupported_or_exclusive_metadata_cannot_bypass_attach_guard() {
    for bit in [0x0004u16, 0x0040, 0x0200, 0x0400, 0x8000] {
        let observed = flags(DeviceType::Tun, true, OpenMode::Attach) | bit as i16;
        assert!(attachment_flags("vpn0", DeviceType::Tun, observed).is_err());
    }
}
#[test]
fn malformed_flags_fail_before_any_kernel_operation() {
    for text in ["", "-1", "65536", "0x10000", "0x", "0x1101 trailing"] {
        assert!(parse_tun_flags(text).is_err(), "{text}");
    }
}
#[test]
fn compatible_feature_combinations_are_preserved_in_single_and_multi_queue() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        for mq in [false, true] {
            let observed = flags(kind, mq, OpenMode::Attach) | 0x2000 | 0x0010;
            let kernel = RefCell::new(Kernel {
                exists: true,
                ..Kernel::default()
            });
            borrow(&kernel, kind, observed | 0x0800).unwrap();
            assert_eq!(kernel.borrow().flags, observed);
            assert_eq!(kernel.borrow().creations, 0);
        }
    }
}
