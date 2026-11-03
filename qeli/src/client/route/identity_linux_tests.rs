//! Native regressions: no network mutation until a disposable thread has entered
//! a fresh network namespace. Missing privileges/tools are errors, never skips.
use super::*;
use crate::tun::iface::TunInterface;
use std::os::fd::AsRawFd;

fn isolated(test: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    let _serial = ROUTE_TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    journal::reset_tests();
    let result = std::thread::spawn(move || {
        // SAFETY: affects only this newly created test thread.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        test()
    })
    .join()
    .expect("route identity test panicked");
    journal::reset_tests();
    result
}
fn ip(args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("ip").args(args).output()?;
    anyhow::ensure!(
        output.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn dummy(name: &str) -> anyhow::Result<()> {
    ip(&["link", "add", name, "type", "dummy"])?;
    ip(&["link", "set", name, "up"])?;
    Ok(())
}
fn add_owned(owner: &RouteOwner, prefix: &str, dev: &str) -> anyhow::Result<()> {
    ip(&["route", "add", prefix, "dev", dev])?;
    note_created_owned(
        owner,
        ["route", "del", prefix, "dev", dev]
            .map(str::to_string)
            .to_vec(),
    )
    .unwrap();
    Ok(())
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_cleanup_rename_preserves_replacement_and_cleans_physical_bypass() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        ip(&["link", "set", owner.interface(), "up"])?;
        add_owned(&owner, "10.41.0.0/16", owner.interface())?;
        dummy("qeli-physical")?;
        add_owned(&owner, "10.42.0.0/16", "qeli-physical")?;
        ip(&["link", "set", owner.interface(), "down"])?;
        ip(&["link", "set", owner.interface(), "name", "qeli-renamed"])?;
        // NETDEV_DOWN may have flushed the original route before rename. Seed and
        // verify the protected route again, so absence after cleanup cannot be blamed
        // on fixture setup and the test actually exercises preservation.
        ip(&["link", "set", "qeli-renamed", "up"])?;
        ip(&["route", "replace", "10.41.0.0/16", "dev", "qeli-renamed"])?;
        assert!(ip(&["route", "show", "exact", "10.41.0.0/16"])?.contains("qeli-renamed"));
        dummy(owner.interface())?;
        ip(&["route", "add", "10.43.0.0/16", "dev", owner.interface()])?;
        assert!(cleanup_routes_for_tun(&owner, &tun).is_err());
        assert!(ip(&["route", "show", "exact", "10.42.0.0/16"])?
            .trim()
            .is_empty());
        assert!(ip(&["route", "show", "exact", "10.43.0.0/16"])?.contains("qeli-audit0"));
        assert!(ip(&["route", "show", "exact", "10.41.0.0/16"])?.contains("qeli-renamed"));
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_cleanup_deleted_original_does_not_delete_same_name_route() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        ip(&["link", "set", owner.interface(), "up"])?;
        add_owned(&owner, "10.41.0.0/16", owner.interface())?;
        ip(&["link", "del", owner.interface()])?;
        dummy(owner.interface())?;
        ip(&["route", "add", "10.41.0.0/16", "dev", owner.interface()])?;
        assert!(cleanup_routes_for_tun(&owner, &tun).is_err());
        assert!(ip(&["route", "show", "exact", "10.41.0.0/16"])?.contains("qeli-audit0"));
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_cleanup_namespace_change_preserves_foreign_physical_route() -> anyhow::Result<()> {
    isolated(|| {
        let original_namespace = std::fs::File::open("/proc/thread-self/ns/net")?;
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        assert!(owner.bind_tun(&tun).is_err(), "an owner cannot be rebound");
        dummy("qeli-physical")?;
        add_owned(&owner, "10.42.0.0/16", "qeli-physical")?;
        // SAFETY: still the disposable isolated test thread.
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dummy("qeli-physical")?;
        ip(&["route", "add", "10.42.0.0/16", "dev", "qeli-physical"])?;
        assert!(cleanup_routes_for_tun(&owner, &tun).is_err());
        assert!(ip(&["route", "show", "exact", "10.42.0.0/16"])?.contains("qeli-physical"));
        // SAFETY: return only to the private namespace held by our own descriptor.
        if unsafe { libc::setns(original_namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        cleanup_routes_for_tun(&owner, &tun)?;
        assert!(ip(&["route", "show", "exact", "10.42.0.0/16"])?
            .trim()
            .is_empty());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_setup_rejects_renamed_tun_before_route_add() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        ip(&["link", "set", owner.interface(), "name", "qeli-renamed"])?;
        dummy(owner.interface())?;
        let args = ["route", "add", "10.41.0.0/16", "dev", owner.interface()].map(str::to_string);
        assert!(install_initial_route(&owner, &args).is_err());
        assert!(owner.identity_failed());
        assert!(ip(&["route", "show", "exact", "10.41.0.0/16"])?
            .trim()
            .is_empty());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_route_scope_does_not_keep_original_tun_alive() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        owner.verify_plan()?;
        let name = std::ffi::CString::new(owner.interface())?;
        drop(tun);
        // SAFETY: name is a valid terminated interface name; this is a read-only lookup.
        assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 0);
        dummy(owner.interface())?;
        assert!(owner.verify_plan().is_err());
        assert!(owner.identity_failed());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_unbound_route_owner_has_no_setup_authority() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        dummy(owner.interface())?;
        assert!(owner.verify_plan().is_err());
        let args = ["route", "add", "10.41.0.0/16", "dev", owner.interface()].map(str::to_string);
        assert!(install_initial_route(&owner, &args).is_err());
        assert!(ip(&["route", "show", "exact", "10.41.0.0/16"])?
            .trim()
            .is_empty());
        Ok(())
    })
}

#[cfg(feature = "experimental-roaming")]
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_roaming_namespace_change_in_callback_is_terminal() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        let plan = LinuxPreparedPathRoutes {
            generation: 1,
            candidate_id: 1,
            owner: owner.scope(),
            tunnel_interface: owner.interface().into(),
            routes: vec![LinuxCandidateRoute {
                remote: "198.51.100.7".parse()?,
                source: "192.0.2.10".parse()?,
                gateway: None,
                interface: "qeli-physical".into(),
            }],
        };
        let error = plan
            .commit_with(&[], || {
                // SAFETY: only the disposable isolated test thread changes namespace.
                if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                dummy("qeli-physical")?;
                ip(&["address", "add", "192.0.2.10/24", "dev", "qeli-physical"])?;
                Ok(())
            })
            .unwrap_err();
        assert!(error.downcast_ref::<RouteCommitStateUnknown>().is_some());
        assert!(owner.identity_failed());
        assert!(ip(&["route", "show", "exact", "198.51.100.7/32"])?
            .trim()
            .is_empty());
        Ok(())
    })
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip and /dev/net/tun; isolated netns"]
fn native_cleanup_preserves_operator_route_attribute_changes() -> anyhow::Result<()> {
    isolated(|| {
        let owner = RouteOwner::new("qeli-audit0", 1)?;
        let tun = std::sync::Arc::new(TunInterface::create(owner.interface(), 1400)?);
        owner.bind_tun(&tun)?;
        ip(&["link", "set", owner.interface(), "up"])?;
        dummy("qeli-physical")?;
        ip(&["addr", "add", "192.0.2.2/24", "dev", "qeli-physical"])?;
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:1::2/64",
            "dev",
            "qeli-physical",
            "nodad",
        ])?;
        let mut preserved = Vec::new();
        let mut controls = Vec::new();
        for ipv6 in [false, true] {
            let extras = [
                "proto static",
                "metric 71",
                if ipv6 {
                    "src 2001:db8:1::2"
                } else {
                    "src 192.0.2.2"
                },
                "mtu 1300",
            ];
            for (index, extra) in extras.iter().enumerate() {
                let destination = if ipv6 {
                    format!("2001:db8:2::{}", index + 10)
                } else {
                    format!("198.51.100.{}", index + 10)
                };
                let mut add: Vec<String> = if ipv6 { vec!["-6".into()] } else { Vec::new() };
                add.extend(
                    ["route", "add", &destination, "dev", "qeli-physical"].map(str::to_string),
                );
                install_initial_route(&owner, &add)?;
                let mut changed = add.clone();
                // Metric changes are a different FIB entry. Remove and re-add, as an
                // administrator replacing that path would; other selectors stay identical.
                if extra.starts_with("metric") {
                    ip(&delete_spec(&add)
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>())?;
                } else {
                    changed[usize::from(ipv6) + 1] = "change".into();
                }
                changed.extend(extra.split_whitespace().map(str::to_string));
                ip(&changed.iter().map(String::as_str).collect::<Vec<_>>())?;
                let mut query = if ipv6 {
                    vec!["-6".to_string()]
                } else {
                    Vec::new()
                };
                query.extend(["route", "show", "exact", &destination].map(str::to_string));
                let before = ip(&query.iter().map(String::as_str).collect::<Vec<_>>())?;
                assert!(!before.trim().is_empty());
                preserved.push((query, before));
            }
            let destination = if ipv6 {
                "2001:db8:2::99"
            } else {
                "198.51.100.99"
            };
            let mut add = if ipv6 {
                vec!["-6".to_string()]
            } else {
                Vec::new()
            };
            add.extend(["route", "add", destination, "dev", "qeli-physical"].map(str::to_string));
            install_initial_route(&owner, &add)?;
            controls.push(delete_spec(&add));
            let cidr = if ipv6 { "8000::/1" } else { "0.0.0.0/1" };
            add_blackhole_half(&owner, cidr)?;
            let mut change = if ipv6 {
                vec!["-6".to_string()]
            } else {
                Vec::new()
            };
            change.extend(
                ["route", "change", "blackhole", cidr, "proto", "static"].map(str::to_string),
            );
            ip(&change.iter().map(String::as_str).collect::<Vec<_>>())?;
            let mut query = if ipv6 {
                vec!["-6".to_string()]
            } else {
                Vec::new()
            };
            query.extend(["route", "show", "exact", cidr].map(str::to_string));
            let before = ip(&query.iter().map(String::as_str).collect::<Vec<_>>())?;
            preserved.push((query, before));
        }
        cleanup_routes_for_tun(&owner, &tun)?;
        let mut lost = Vec::new();
        for (query, before) in preserved {
            let after = ip(&query.iter().map(String::as_str).collect::<Vec<_>>())?;
            if before != after {
                lost.push(format!(
                    "{}: before={before:?}, after={after:?}",
                    query.join(" ")
                ));
            }
        }
        for record in controls {
            assert!(ownership::recorded_route(&record)?.is_none());
        }
        assert!(
            lost.is_empty(),
            "operator replacements were changed: {}",
            lost.join("; ")
        );
        Ok(())
    })
}
