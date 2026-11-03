use super::*;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
#[derive(Default)]
struct Kernel {
    devices: BTreeMap<String, usize>,
    calls: Vec<(String, i16)>,
    fail_at: Option<usize>,
    next: usize,
}
struct Queue {
    name: String,
    kernel: Rc<RefCell<Kernel>>,
}
impl Drop for Queue {
    fn drop(&mut self) {
        let mut kernel = self.kernel.borrow_mut();
        let count = kernel.devices.get_mut(&self.name).unwrap();
        *count -= 1;
        if *count == 0 {
            kernel.devices.remove(&self.name);
        }
    }
}
fn open(kernel: &Rc<RefCell<Kernel>>, requested: &str, flags: i16) -> io::Result<Queue> {
    let mut k = kernel.borrow_mut();
    k.calls.push((requested.into(), flags));
    if k.fail_at == Some(k.calls.len()) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let name = if requested.contains("%d") {
        let n = k.next;
        k.next += 1;
        requested.replace("%d", &n.to_string())
    } else {
        requested.into()
    };
    // Kernel TUNSETIFF rejects an existing name when bit 0x8000 is present.
    if k.devices.contains_key(&name) && flags as u16 & 0x8000 != 0 {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    *k.devices.entry(name.clone()).or_default() += 1;
    Ok(Queue {
        name,
        kernel: kernel.clone(),
    })
}
#[test]
fn regression_create_refuses_existing_device_for_tun_and_tap() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        let kernel = Rc::new(RefCell::new(Kernel::default()));
        kernel.borrow_mut().devices.insert("vpn0".into(), 1);
        let result = open(&kernel, "vpn0", flags(kind, false, OpenMode::Create));
        assert!(
            result.is_err(),
            "create must not borrow a foreign persistent device"
        );
        assert_eq!(kernel.borrow().devices["vpn0"], 1);
    }
}
#[test]
fn regression_multiqueue_first_open_refuses_a_racing_foreign_device() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    kernel.borrow_mut().devices.insert("vpn0".into(), 1);
    let result = create_queues(
        "vpn0",
        DeviceType::Tun,
        3,
        |name, flags| open(&kernel, name, flags),
        |q| &q.name,
    );
    assert!(result.is_err());
    assert_eq!(kernel.borrow().devices["vpn0"], 1);
    assert_eq!(kernel.borrow().calls.len(), 1);
}
#[test]
fn regression_additional_queues_use_the_first_resolved_device_name() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    let queues = create_queues(
        "tun%d",
        DeviceType::Tun,
        3,
        |name, flags| open(&kernel, name, flags),
        |q| &q.name,
    )
    .unwrap();
    assert_eq!(kernel.borrow().devices.len(), 1);
    assert!(queues.iter().all(|q| q.name == queues[0].name));
}
#[test]
fn explicit_attach_keeps_external_ownership() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    kernel.borrow_mut().devices.insert("vpn0".into(), 1);
    let queue = open(
        &kernel,
        "vpn0",
        flags(DeviceType::Tun, true, OpenMode::Attach),
    )
    .unwrap();
    assert_eq!(kernel.borrow().devices["vpn0"], 2);
    drop(queue);
    assert_eq!(kernel.borrow().devices["vpn0"], 1);
}
#[test]
fn partial_queue_failure_releases_every_new_descriptor() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    kernel.borrow_mut().fail_at = Some(3);
    assert!(create_queues(
        "vpn0",
        DeviceType::Tap,
        4,
        |name, flags| open(&kernel, name, flags),
        |q| &q.name
    )
    .is_err());
    assert!(kernel.borrow().devices.is_empty());
}

#[test]
fn additional_queues_attach_without_repeating_exclusive_create() {
    for kind in [DeviceType::Tun, DeviceType::Tap] {
        let kernel = Rc::new(RefCell::new(Kernel::default()));
        let queues = create_queues(
            "vpn0",
            kind,
            3,
            |name, flags| open(&kernel, name, flags),
            |q| &q.name,
        )
        .unwrap();
        let calls = kernel.borrow().calls.clone();
        assert_ne!(calls[0].1 as u16 & 0x8000, 0);
        assert!(calls[1..]
            .iter()
            .all(|(_, flags)| *flags as u16 & 0x8000 == 0));
        assert!(calls
            .iter()
            .all(|(_, flags)| flags & IFF_MULTI_QUEUE != 0 && flags & IFF_NO_PI != 0));
        assert_eq!(kernel.borrow().devices["vpn0"], 3);
        drop(queues);
        assert!(kernel.borrow().devices.is_empty());
    }
}
#[test]
fn zero_requested_queues_still_creates_one_owned_device() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    let queues = create_queues(
        "vpn0",
        DeviceType::Tun,
        0,
        |name, flags| open(&kernel, name, flags),
        |q| &q.name,
    )
    .unwrap();
    assert_eq!(queues.len(), 1);
    assert_eq!(kernel.borrow().calls.len(), 1);
}
#[test]
fn failed_first_open_never_attempts_attachment() {
    let kernel = Rc::new(RefCell::new(Kernel::default()));
    kernel.borrow_mut().fail_at = Some(1);
    assert!(create_queues(
        "vpn0",
        DeviceType::Tun,
        4,
        |name, flags| open(&kernel, name, flags),
        |q| &q.name
    )
    .is_err());
    assert_eq!(kernel.borrow().calls.len(), 1);
    assert!(kernel.borrow().devices.is_empty());
}
#[test]
fn explicit_attach_and_create_preserve_device_type_and_packet_format() {
    for (kind, bit) in [(DeviceType::Tun, 1), (DeviceType::Tap, 2)] {
        for mode in [OpenMode::Create, OpenMode::Attach] {
            let value = flags(kind, false, mode);
            assert_eq!(value & 3, bit);
            assert_ne!(value & IFF_NO_PI, 0);
            assert_eq!(value & IFF_MULTI_QUEUE, 0);
        }
    }
}
