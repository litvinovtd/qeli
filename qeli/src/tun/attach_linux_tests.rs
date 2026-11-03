//! Opt-in real ioctl checks. Every test enters a private network namespace on
//! a disposable OS thread before opening or creating any TUN/TAP.
use super::*;

#[test]
fn client_queue_policy_is_strict_without_changing_server_compatibility() {
    use crate::system_command::test_support::{arguments, with_commands, Action};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    for strict in [false, true] {
        for (success, stderr) in [
            (true, ""),
            (false, "Operation not supported"),
            (false, "Operation not permitted"),
        ] {
            with_commands(
                move |command| {
                    assert_eq!(command.get_program(), "ip");
                    assert_eq!(
                        arguments(command),
                        ["link", "set", "dev", "vpn0", "txqueuelen", "1000"]
                    );
                    Action::Reply(Ok(Output {
                        status: ExitStatus::from_raw(if success { 0 } else { 256 }),
                        stdout: vec![],
                        stderr: stderr.as_bytes().to_vec(),
                    }))
                },
                || {
                    let result = if strict {
                        TunInterface::set_queue_len_strict("vpn0", 1000)
                    } else {
                        TunInterface::set_queue_len("vpn0", 1000)
                    };
                    assert_eq!(
                        result.is_ok(),
                        success || !strict && stderr == "Operation not supported"
                    );
                },
            );
        }
    }
}

fn isolated(test: fn() -> io::Result<()>) -> io::Result<()> {
    std::thread::spawn(move || {
        // SAFETY: only this fresh thread changes its network namespace. No descriptor
        // or network mutation is attempted unless isolation succeeded.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        test()
    })
    .join()
    .expect("isolated TUN test thread panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn owned_queue_policy_changes_kernel_txqlen() -> io::Result<()> {
    isolated(|| {
        let tun = TunInterface::create("qeli-queue0", 1400)?;
        for length in [500, 1000, 2000] {
            TunInterface::set_queue_len_strict(&tun.name, length)?;
            let output = std::process::Command::new("ip")
                .args(["-j", "link", "show", "dev", &tun.name])
                .output()?;
            assert!(output.status.success());
            let interfaces: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(interfaces[0]["txqlen"], serde_json::json!(length));
        }
        assert!(TunInterface::set_queue_len_strict("qeli-missing0", 1000).is_err());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn missing_attach_never_registers_tun_or_tap() -> io::Result<()> {
    isolated(|| {
        // Prove device access and creation privileges before testing a refusal.
        // Otherwise a missing /dev/net/tun could make this test pass vacuously.
        drop(TunInterface::create("qeli-probe", 1400)?);
        for kind in [DeviceType::Tun, DeviceType::Tap] {
            for mq in [false, true] {
                let name = "qeli-audit0";
                assert_eq!(open::interface_index(name)?, None);
                assert!(TunInterface::open_device(
                    name,
                    1400,
                    open::flags(kind, mq, OpenMode::Attach)
                )
                .is_err());
                assert_eq!(open::interface_index(name)?, None);
            }
        }
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn attachment_guard_keeps_existing_device_and_releases_only_its_fd() -> io::Result<()> {
    isolated(|| {
        for kind in [DeviceType::Tun, DeviceType::Tap] {
            let name = "qeli-audit0";
            let owner =
                TunInterface::open_device(name, 1400, open::flags(kind, true, OpenMode::Create))?;
            let index = open::interface_index(name)?.expect("created device must exist");
            let borrower =
                TunInterface::open_device(name, 1400, open::flags(kind, true, OpenMode::Attach))?;
            assert_eq!(open::interface_index(name)?, Some(index));
            drop(borrower);
            assert_eq!(open::interface_index(name)?, Some(index));
            drop(owner);
            assert_eq!(open::interface_index(name)?, None);
        }
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn multiqueue_creation_uses_one_device_and_last_fd_releases_it() -> io::Result<()> {
    isolated(|| {
        for kind in [DeviceType::Tun, DeviceType::Tap] {
            let queues = TunInterface::create_multiqueue("qeli-audit%d", 1400, kind, 3)?;
            let name = queues[0].name.clone();
            let index = open::interface_index(&name)?.expect("created device must exist");
            assert!(queues.iter().all(|queue| queue.name == name));
            let mut queues = queues.into_iter();
            drop(queues.next());
            assert_eq!(open::interface_index(&name)?, Some(index));
            drop(queues);
            assert_eq!(open::interface_index(&name)?, None);
        }
        Ok(())
    })
}

// Mutation helpers below are called only inside isolated(), after unshare succeeds.
fn ip_link(args: &[&str]) -> io::Result<()> {
    let output = crate::system_command::Command::new("ip")
        .args(["link"])
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(())
}

fn persistent(tun: &TunInterface) -> io::Result<()> {
    // SAFETY: tun owns an attached descriptor; this ioctl takes an integer argument.
    if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETPERSIST as _, 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, /dev/net/tun and ip; isolated netns"]
fn closing_renamed_device_preserves_persistent_replacement() -> io::Result<()> {
    isolated(|| {
        for kind in [DeviceType::Tun, DeviceType::Tap] {
            let name = if kind == DeviceType::Tun {
                "qeli-tun"
            } else {
                "qeli-tap"
            };
            let original =
                TunInterface::open_device(name, 1400, open::flags(kind, true, OpenMode::Create))?;
            ip_link(&["set", "dev", name, "name", "qeli-moved"])?;
            let original_index = open::interface_index("qeli-moved")?.expect("renamed device");
            assert_eq!(
                original.attached_link()?,
                Some(("qeli-moved".to_string(), original_index))
            );
            let replacement =
                TunInterface::open_device(name, 1400, open::flags(kind, true, OpenMode::Create))?;
            persistent(&replacement)?;
            let index = open::interface_index(name)?.expect("replacement must exist");
            drop(original);
            assert_eq!(open::interface_index("qeli-moved")?, None);
            drop(replacement);
            // A name-based ip tuntap del would have cleared this device's persistence.
            assert_eq!(open::interface_index(name)?, Some(index));
        }
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, /dev/net/tun and ip; isolated netns"]
fn closing_detached_queues_preserves_persistent_replacement() -> io::Result<()> {
    isolated(|| {
        let name = "qeli-audit0";
        let original = TunInterface::create_multiqueue(name, 1400, DeviceType::Tun, 3)?;
        ip_link(&["del", "dev", name])?;
        for queue in &original {
            assert_eq!(queue.attached_link()?, None);
        }
        assert_eq!(open::interface_index(name)?, None);
        let replacement = TunInterface::create_multiqueue(name, 1400, DeviceType::Tun, 2)?;
        persistent(&replacement[0])?;
        let index = open::interface_index(name)?.expect("replacement must exist");
        drop(original);
        drop(replacement);
        assert_eq!(open::interface_index(name)?, Some(index));
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn duplicate_workers_close_before_original_descriptor_releases_name() -> io::Result<()> {
    isolated(|| {
        let name = "qeli-audit0";
        let mut owner = TunInterface::create_multiqueue(name, 1400, DeviceType::Tun, 3)?;
        let readers: Vec<_> = owner
            .iter()
            .map(|queue| queue.fd.try_clone())
            .collect::<io::Result<_>>()?;
        let writers: Vec<_> = owner
            .iter()
            .map(|queue| queue.fd.try_clone())
            .collect::<io::Result<_>>()?;
        owner.truncate(1);
        let index = open::interface_index(name)?.expect("created device must exist");
        drop(readers);
        drop(writers);
        assert_eq!(open::interface_index(name)?, Some(index));
        // A competing generation must still be refused throughout host cleanup.
        assert!(TunInterface::create(name, 1400).is_err());
        drop(owner);
        assert_eq!(open::interface_index(name)?, None);
        drop(TunInterface::create(name, 1400)?);
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and /dev/net/tun; isolated netns"]
fn descriptor_namespace_mismatch_does_not_resolve_same_name() -> io::Result<()> {
    isolated(|| {
        let name = "qeli-audit0";
        let original = TunInterface::create(name, 1400)?;
        let index = open::interface_index(name)?.expect("created original");
        // This already-isolated disposable thread enters another private namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let replacement = TunInterface::create(name, 1400)?;
        assert_eq!(open::interface_index(name)?, Some(index));
        assert!(original.attached_link().is_err());
        assert_eq!(
            replacement.attached_link()?,
            Some((name.to_string(), index))
        );
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, /dev/net/tun and ip; isolated mount/net namespaces"]
fn inherited_sysfs_same_name_different_index_is_rejected() -> io::Result<()> {
    std::thread::spawn(|| {
        // Both namespace mutations are confined to this disposable thread. Prevent
        // mount propagation before replacing /sys with this namespace's sysfs.
        if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let private = unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                (libc::MS_PRIVATE | libc::MS_REC) as _,
                std::ptr::null(),
            )
        };
        if private != 0 {
            return Err(io::Error::last_os_error());
        }
        let mounted = unsafe {
            libc::mount(
                c"sysfs".as_ptr(),
                c"/sys".as_ptr(),
                c"sysfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if mounted != 0 {
            return Err(io::Error::last_os_error());
        }
        let name = "qeli-audit0";
        let _old_owner = TunInterface::create_multiqueue(name, 1400, DeviceType::Tun, 1)?;
        drop(TunInterface::attach(name, 1400, DeviceType::Tun)?);
        let foreign_index: u32 = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        ip_link(&["add", "qeli-pad", "type", "dummy"])?;
        let _current_owner = TunInterface::create_multiqueue(name, 1400, DeviceType::Tun, 1)?;
        let current_index = open::interface_index(name)?.expect("current TUN exists");
        assert_ne!(current_index, foreign_index);
        let error = TunInterface::attach(name, 1400, DeviceType::Tun)
            .err()
            .expect("foreign sysfs flags must be rejected before TUNSETIFF");
        assert!(
            error.to_string().contains("refusing foreign tun_flags"),
            "{error}"
        );
        assert_eq!(open::interface_index(name)?, Some(current_index));
        Ok(())
    })
    .join()
    .expect("isolated TUN test thread panicked")
}
