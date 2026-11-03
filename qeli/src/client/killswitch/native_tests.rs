//! Explicit privileged tests. Every mutation follows CLONE_NEWNET in a new thread.
use super::*;
use std::os::fd::AsRawFd;

fn new_namespace() -> anyhow::Result<()> {
    // SAFETY: caller is a disposable test thread, never an application worker.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn command(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program).args(args).output()?;
    anyhow::ensure!(
        output.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn tools() -> anyhow::Result<[String; 2]> {
    Ok([
        ipt_path("iptables").ok_or_else(|| anyhow::anyhow!("iptables required"))?,
        ipt_path("ip6tables").ok_or_else(|| anyhow::anyhow!("ip6tables required"))?,
    ])
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and iptables/ip6tables; isolated netns"]
fn native_kill_switch_namespace_change_preserves_foreign_rules() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        new_namespace()?;
        let original = std::fs::File::open("/proc/thread-self/ns/net")?;
        let paths = tools()?;
        let tun = "ks_native0";
        let chain = chain_for(tun);
        engage("203.0.113.7", 443, tun, false, false, true)?;
        for path in &paths {
            anyhow::ensure!(present_checked(path, &["-C", "OUTPUT", "-j", &chain])?);
        }
        new_namespace()?;
        for path in &paths {
            command(path, &["-N", &chain])?;
            command(path, &["-A", &chain, "-m", "comment", "--comment", "foreign-sentinel", "-j", "DROP"])?;
            command(path, &["-I", "OUTPUT", "-j", &chain])?;
        }
        // Exercise the public entry points, not just a namespace comparison helper.
        let refresh = refresh_server_ips("203.0.113.8", 443, tun);
        let cleanup = disengage(tun);
        let restart = engage("203.0.113.8", 443, tun, true, true, false);
        let preserved = paths.iter().all(|path| {
            present_checked(path, &["-C", &chain, "-m", "comment", "--comment", "foreign-sentinel", "-j", "DROP"]).unwrap_or(false)
        });
        // SAFETY: return this same disposable thread to its still-open original netns.
        if unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) } != 0 { return Err(std::io::Error::last_os_error().into()); }
        disengage(tun)?;
        anyhow::ensure!(refresh.is_err() && cleanup.is_err() && restart.is_err() && preserved,
            "foreign namespace touched: refresh={refresh:?}, cleanup={cleanup:?}, restart={restart:?}, preserved={preserved}");
        for path in &paths { anyhow::ensure!(!chain_exists(&Context::fixture(), path, &chain)?); }
        Ok(())
    }).join().expect("native kill-switch namespace test panicked")
}

fn packets(
    path: &str,
    chain: &str,
    target: &str,
    destination: Option<&str>,
) -> anyhow::Result<u64> {
    let text = command(path, &["-n", "-v", "-x", "-L", chain])?;
    let mut count = 0;
    let mut matched = false;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 3
            && fields[2] == target
            && destination.is_none_or(|address| fields.contains(&address))
        {
            count += fields[0].parse::<u64>()?;
            matched = true;
        }
    }
    anyhow::ensure!(
        matched,
        "counter rule missing: {target} {destination:?}: {text}"
    );
    Ok(count)
}
fn probe(address: &str, ipv6: bool) -> anyhow::Result<()> {
    // No peer exists on the dummy WAN: an echo may fail, but filter counters must move.
    let output = Command::new("ping")
        .args([
            if ipv6 { "-6" } else { "-4" },
            "-n",
            "-c",
            "1",
            "-W",
            "1",
            address,
        ])
        .output()?;
    anyhow::ensure!(
        matches!(output.status.code(), Some(0 | 1)),
        "ping fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip, ping and iptables/ip6tables; isolated netns"]
fn native_late_ipv4_route_stays_behind_existing_kill_switch() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        new_namespace()?;
        command("ip", &["link", "set", "lo", "up"])?;
        command("ip", &["link", "add", "wan0", "type", "dummy"])?;
        command("ip", &["link", "set", "wan0", "up"])?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                "wan0",
                "nodad",
            ],
        )?;
        command("ip", &["-6", "route", "add", "default", "dev", "wan0"])?;
        anyhow::ensure!(
            command("ip", &["-4", "route", "show", "default"])?.is_empty(),
            "fixture must start without an IPv4 default route"
        );
        let paths = tools()?;
        let tun = "ks_latev4";
        let chain = chain_for(tun);
        engage("2001:db8::7", 443, tun, false, false, true)?;
        anyhow::ensure!(present_checked(&paths[0], &["-C", "OUTPUT", "-j", &chain])?);
        command("ip", &["addr", "add", "192.0.2.1/24", "dev", "wan0"])?;
        command("ip", &["route", "add", "default", "dev", "wan0"])?;
        probe("203.0.113.9", false)?;
        anyhow::ensure!(
            packets(&paths[0], &chain, "DROP", None)? > 0,
            "late IPv4 default route bypassed the existing kill switch"
        );
        disengage(tun)?;
        Ok(())
    })
    .join()
    .expect("native late-IPv4 test thread panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip, ping and iptables/ip6tables; isolated netns"]
fn native_late_ipv6_address_stays_behind_existing_kill_switch() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        new_namespace()?;
        command("ip", &["link", "set", "lo", "up"])?;
        command("ip", &["link", "add", "wan0", "type", "dummy"])?;
        command("ip", &["link", "set", "wan0", "up"])?;
        command("ip", &["addr", "add", "192.0.2.1/24", "dev", "wan0"])?;
        command("ip", &["route", "add", "default", "dev", "wan0"])?;
        anyhow::ensure!(
            command("ip", &["-6", "address", "show", "scope", "global"])?.is_empty(),
            "fixture must start without global IPv6"
        );
        let paths = tools()?;
        let tun = "ks_latev6";
        let chain = chain_for(tun);
        engage("203.0.113.7", 443, tun, false, false, true)?;
        anyhow::ensure!(present_checked(&paths[1], &["-C", "OUTPUT", "-j", &chain])?);
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                "wan0",
                "nodad",
            ],
        )?;
        command("ip", &["-6", "route", "add", "default", "dev", "wan0"])?;
        probe("2001:db8:1::9", true)?;
        anyhow::ensure!(
            packets(&paths[1], &chain, "DROP", None)? > 0,
            "late IPv6 address bypassed the existing kill switch"
        );
        disengage(tun)?;
        Ok(())
    })
    .join()
    .expect("native late-IPv6 test thread panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN, ip, ping and iptables/ip6tables; isolated netns"]
fn native_kill_switch_packets_stay_blocked_across_tun_reconnect() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        new_namespace()?;
        command("ip", &["link", "set", "lo", "up"])?;
        command("ip", &["link", "add", "wan0", "type", "dummy"])?;
        command("ip", &["link", "set", "wan0", "up"])?;
        command("ip", &["addr", "add", "192.0.2.1/24", "dev", "wan0"])?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                "wan0",
                "nodad",
            ],
        )?;
        command("ip", &["route", "add", "default", "dev", "wan0"])?;
        command("ip", &["-6", "route", "add", "default", "dev", "wan0"])?;
        let paths = tools()?;
        let tun = "ks_native1";
        let chain = chain_for(tun);
        for (ipv6, path, old, new, blocked) in [
            (
                false,
                &paths[0],
                "203.0.113.7",
                "203.0.113.8",
                "203.0.113.9",
            ),
            (
                true,
                &paths[1],
                "2001:db8:1::7",
                "2001:db8:1::8",
                "2001:db8:1::9",
            ),
        ] {
            engage(old, 443, tun, false, false, true)?;
            probe(old, ipv6)?;
            anyhow::ensure!(
                packets(path, &chain, "ACCEPT", Some(old))? > 0,
                "server path blocked"
            );
            probe(blocked, ipv6)?;
            let drops = packets(path, &chain, "DROP", None)?;
            anyhow::ensure!(drops > 0, "unapproved WAN traffic not dropped");
            command("ip", &["link", "add", tun, "type", "dummy"])?;
            command("ip", &["link", "set", tun, "up"])?;
            command("ip", &["link", "del", tun])?;
            refresh_server_ips(new, 443, tun)?;
            anyhow::ensure!(!present_checked(
                path,
                &["-C", &chain, "-d", old, "-j", "ACCEPT"]
            )?);
            probe(new, ipv6)?;
            anyhow::ensure!(packets(path, &chain, "ACCEPT", Some(new))? > 0);
            probe(blocked, ipv6)?;
            anyhow::ensure!(
                packets(path, &chain, "DROP", None)? > drops,
                "reconnect opened WAN egress"
            );
            disengage(tun)?;
            for path in &paths {
                anyhow::ensure!(!chain_exists(&Context::fixture(), path, &chain)?);
            }
        }
        Ok(())
    })
    .join()
    .expect("native kill-switch packet test panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and real dual-stack iptables; isolated netns"]
fn native_kill_switch_failed_restart_preserves_packet_barrier() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        use crate::system_command::test_support::{arguments, with_commands, Action};
        use std::os::unix::process::ExitStatusExt;
        new_namespace()?;
        command("ip", &["link", "set", "lo", "up"])?;
        command("ip", &["link", "add", "wan0", "type", "dummy"])?;
        command("ip", &["link", "set", "wan0", "up"])?;
        command("ip", &["addr", "add", "192.0.2.1/24", "dev", "wan0"])?;
        command(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                "wan0",
                "nodad",
            ],
        )?;
        command("ip", &["route", "add", "default", "dev", "wan0"])?;
        command("ip", &["-6", "route", "add", "default", "dev", "wan0"])?;
        let paths = tools()?;
        let tun = "ks_crash0";
        let chain = chain_for(tun);
        for path in &paths {
            command(
                path,
                &[
                    "-A",
                    "OUTPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "audit-wan-sentinel",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
        engage("203.0.113.7", 443, tun, false, false, true)?;
        // Simulate losing all process-local authority while retaining the kernel rules.
        Context::lookup(tun, true)?
            .expect("initial owner")
            .forget(tun)?;
        let packets = || -> anyhow::Result<Vec<u64>> {
            paths
                .iter()
                .map(|path| packets(path, "OUTPUT", "ACCEPT", None))
                .collect()
        };
        let before = packets()?;
        let injected = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = injected.clone();
        let failed = with_commands(
            move |cmd| {
                let args = arguments(cmd);
                let reject = cmd.get_program().to_string_lossy().ends_with("ip6tables")
                    && args == ["-A", &chain, "-j", "DROP"];
                let output = if reject {
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(1 << 8),
                        stdout: vec![],
                        stderr: b"injected DROP failure".to_vec(),
                    })
                } else {
                    std::process::Command::new(cmd.get_program())
                        .args(cmd.get_args())
                        .output()
                };
                // Real UDP packets after each firewall mutation sample the complete rebuild,
                // including its rollback, instead of only checking the final ruleset.
                if args
                    .first()
                    .is_some_and(|a| ["-N", "-A", "-I", "-D", "-F", "-X"].contains(&a.as_str()))
                {
                    for (local, target) in [
                        ("0.0.0.0:0", "203.0.113.9:43889"),
                        ("[::]:0", "[2001:db8:1::9]:43889"),
                    ] {
                        let socket = std::net::UdpSocket::bind(local).expect("bind packet probe");
                        let _ = socket.send_to(b"restart-barrier", target);
                    }
                }
                Action::Reply(output)
            },
            || engage("203.0.113.8", 443, tun, false, false, true),
        );
        let after = packets()?;
        let injected = injected.load(std::sync::atomic::Ordering::Relaxed);
        disengage(tun)?;
        anyhow::ensure!(
            failed.is_err() && injected > 0,
            "fault did not exercise setup failure: {failed:?}, injected={injected}"
        );
        anyhow::ensure!(
            before == after,
            "restart/rollback exposed WAN egress: before={before:?}, after={after:?}"
        );
        Ok(())
    })
    .join()
    .expect("native restart test panicked")
}

#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN/CAP_NET_ADMIN and real dual-stack iptables; isolated netns"]
fn native_kill_switch_rebuild_guard_failures_retry_without_unlocking() -> anyhow::Result<()> {
    std::thread::spawn(|| -> anyhow::Result<()> {
        use crate::system_command::test_support::{arguments, with_commands, Action};
        use std::os::unix::process::ExitStatusExt;
        new_namespace()?;
        let paths = tools()?;
        let tun = "ks_crash1";
        let chain = chain_for(tun);
        let comment = format!("qeli-ks-rebuild:{tun}");
        let snapshot = || -> anyhow::Result<Vec<String>> {
            paths
                .iter()
                .map(|p| command(p, &["-t", "filter", "-S"]))
                .collect()
        };
        let intact = || -> anyhow::Result<()> {
            for p in &paths {
                for args in [
                    vec!["-C", "OUTPUT", "-j", &chain],
                    vec!["-C", "FORWARD", "-j", &chain],
                    vec!["-C", &chain, "-j", "DROP"],
                ] {
                    anyhow::ensure!(
                        present_checked(p, &args)?,
                        "ordinary protection lost: {p} {args:?}"
                    );
                }
            }
            Ok(())
        };
        let guard = |p: &str, hook: &str| {
            present_checked(
                p,
                &[
                    "-C",
                    hook,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )
        };
        for p in &paths {
            command(p, &["-N", "OPERATOR_SENTINEL"])?;
            command(p, &["-A", "OPERATOR_SENTINEL", "-j", "RETURN"])?;
        }
        engage("203.0.113.7", 443, tun, false, false, true)?;
        // Guard insertion can report success without changing the kernel. It must
        // fail before either family's inherited ordinary protection is removed.
        let result = with_commands(
            |cmd| {
                let args = arguments(cmd);
                let reject = cmd.get_program().to_string_lossy().ends_with("ip6tables")
                    && args.first().is_some_and(|x| x == "-I")
                    && args.iter().any(|x| x.starts_with("qeli-ks-rebuild:"));
                let output = if reject {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(0),
                        stdout: vec![],
                        stderr: vec![],
                    })
                } else {
                    std::process::Command::new(cmd.get_program())
                        .args(cmd.get_args())
                        .output()
                };
                Action::Reply(output)
            },
            || engage("203.0.113.8", 443, tun, true, true, true),
        );
        anyhow::ensure!(result.is_err(), "no-op guard insertion was accepted");
        intact()?;
        anyhow::ensure!(guard(&paths[0], "OUTPUT")? && !guard(&paths[1], "OUTPUT")?);
        // Failure retiring the second family's guard must not roll back already
        // committed ordinary protection after the first guard has been retired.
        let result = with_commands(
            |cmd| {
                let args = arguments(cmd);
                let reject = cmd.get_program().to_string_lossy().ends_with("ip6tables")
                    && args.first().is_some_and(|x| x == "-D")
                    && args.iter().any(|x| x.starts_with("qeli-ks-rebuild:"));
                let output = if reject {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(1 << 8),
                        stdout: vec![],
                        stderr: b"injected guard delete failure".to_vec(),
                    })
                } else {
                    std::process::Command::new(cmd.get_program())
                        .args(cmd.get_args())
                        .output()
                };
                Action::Reply(output)
            },
            || engage("203.0.113.8", 443, tun, true, true, true),
        );
        anyhow::ensure!(result.is_err(), "failed guard retirement was accepted");
        intact()?;
        anyhow::ensure!(!guard(&paths[0], "OUTPUT")? && guard(&paths[1], "OUTPUT")?);
        // Explicit leak exceptions cannot unlock a failed replacement of previously
        // armed protection. Rollback leaves only guards; model another process loss.
        let result = with_commands(
            |cmd| {
                let args = arguments(cmd);
                let reject = cmd.get_program().to_string_lossy().ends_with("ip6tables")
                    && args.first().is_some_and(|x| x == "-A")
                    && args.last().is_some_and(|x| x == "DROP");
                let output = if reject {
                    Ok(std::process::Output {
                        status: std::process::ExitStatus::from_raw(1 << 8),
                        stdout: vec![],
                        stderr: b"injected DROP failure".to_vec(),
                    })
                } else {
                    std::process::Command::new(cmd.get_program())
                        .args(cmd.get_args())
                        .output()
                };
                Action::Reply(output)
            },
            || engage("203.0.113.8", 443, tun, true, true, true),
        );
        anyhow::ensure!(result.is_err(), "leak flags bypassed rebuild failure");
        for p in &paths {
            anyhow::ensure!(guard(p, "OUTPUT")? && guard(p, "FORWARD")?);
            anyhow::ensure!(!chain_exists(&Context::fixture(), p, &chain)?);
        }
        Context::lookup(tun, true)?
            .expect("retained owner")
            .forget(tun)?;
        let before = snapshot()?;
        anyhow::ensure!(engage("203.0.113.8", 443, "ks_foreign", true, true, true).is_err());
        anyhow::ensure!(
            before == snapshot()?,
            "foreign TUN changed recovery-only protection"
        );
        engage("203.0.113.8", 443, tun, false, false, true)?;
        intact()?;
        for p in &paths {
            anyhow::ensure!(!guard(p, "OUTPUT")? && !guard(p, "FORWARD")?);
        }
        disengage(tun)?;
        for p in &paths {
            anyhow::ensure!(!chain_exists(&Context::fixture(), p, &chain)?);
            anyhow::ensure!(!guard(p, "OUTPUT")? && !guard(p, "FORWARD")?);
            anyhow::ensure!(present_checked(
                p,
                &["-C", "OPERATOR_SENTINEL", "-j", "RETURN"]
            )?);
        }
        Ok(())
    })
    .join()
    .expect("native rebuild recovery test panicked")
}

fn engage(
    host: &str,
    port: u16,
    tun: &str,
    v4: bool,
    v6: bool,
    forward: bool,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(super::prepare_engage(host, port, tun, v4, v6, forward))?()
}
fn refresh_server_ips(host: &str, port: u16, tun: &str) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(super::prepare_refresh(host, port, tun))?()
}
