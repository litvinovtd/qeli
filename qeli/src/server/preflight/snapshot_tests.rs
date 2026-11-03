use super::*;
use std::io;
use std::process::{ExitStatus, Output};

fn output(success: bool, stdout: &str) -> Output {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        ExitStatus::from_raw(if success { 0 } else { 17 << 8 })
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        ExitStatus::from_raw(if success { 0 } else { 17 })
    };
    Output {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

const OBSERVATIONS: [&str; 4] = [
    "1: lo inet 127.0.0.1/8 scope host lo\n2: eth0@if7 inet 192.0.2.10/24 scope global eth0\n",
    "default via 192.0.2.1 dev eth0\n192.0.2.0/24 dev eth0\n",
    "1: lo inet6 ::1/128 scope host\n2: eth0@if7 inet6 2001:db8::10/64 scope global\n2: eth0 inet6 2001:db8::11/64 scope global tentative\n",
    "default via fe80::1 dev eth0\n2001:db8::/64 dev eth0\n",
];

fn failure(kind: Option<io::ErrorKind>, index: usize) -> io::Result<Output> {
    match kind {
        Some(kind) => Err(io::Error::new(kind, "probe fixture failure")),
        // A failed command may still return plausible text: it is not a valid observation.
        None => Ok(output(false, OBSERVATIONS[index])),
    }
}

#[test]
fn ipv4_probe_failures_leave_the_snapshot_unavailable() {
    for failed in 0..2 {
        for kind in [
            Some(io::ErrorKind::TimedOut),
            Some(io::ErrorKind::InvalidData),
            Some(io::ErrorKind::NotFound),
            None,
        ] {
            let mut index = 0;
            let host = gather_host_net_with(|_| {
                let current = index;
                index += 1;
                assert!(current < 2, "failed IPv4 must not continue to IPv6");
                if current == failed {
                    failure(kind, current)
                } else {
                    Ok(output(true, OBSERVATIONS[current]))
                }
            });
            assert!(host.is_none(), "probe {failed}, failure {kind:?}");
        }
    }
}

#[test]
fn ipv6_probe_failures_preserve_other_observations_independently() {
    for failed in [vec![2], vec![3], vec![2, 3]] {
        for kind in [
            Some(io::ErrorKind::TimedOut),
            Some(io::ErrorKind::InvalidData),
            None,
        ] {
            let mut index = 0;
            let host = gather_host_net_with(|_| {
                let current = index;
                index += 1;
                if failed.contains(&current) {
                    failure(kind, current)
                } else {
                    Ok(output(true, OBSERVATIONS[current]))
                }
            })
            .expect("unavailable IPv6 must preserve the IPv4 snapshot");
            assert_eq!(index, 4, "a failed address probe must not skip routes");
            assert_eq!(host.addrs.len(), 1);
            assert_eq!(
                host.gateways,
                vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
            );
            assert_eq!(host.routes.len(), 1);
            assert_eq!(host.ipv6_addrs.is_empty(), failed.contains(&2));
            assert_eq!(host.ipv6_egress_addrs.is_empty(), failed.contains(&2));
            assert_eq!(host.ipv6_gateways.is_empty(), failed.contains(&3));
            assert_eq!(host.ipv6_default_interfaces.is_empty(), failed.contains(&3));
            assert_eq!(host.ipv6_routes.is_empty(), failed.contains(&3));
        }
    }
}

#[test]
fn successful_snapshot_keeps_collision_and_egress_observations_distinct() {
    let mut calls = Vec::new();
    let host = gather_host_net_with(|args| {
        let index = calls.len();
        calls.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
        Ok(output(true, OBSERVATIONS[index]))
    })
    .unwrap();
    assert_eq!(
        calls,
        vec![
            vec!["-4", "-o", "addr", "show"],
            vec!["-4", "route", "show"],
            vec!["-6", "-o", "addr", "show"],
            vec!["-6", "route", "show"],
        ]
    );
    assert_eq!(
        host.addrs,
        vec![("eth0".into(), "192.0.2.10".parse().unwrap())]
    );
    assert_eq!(
        host.ipv6_addrs.len(),
        2,
        "tentative addresses still collide"
    );
    assert_eq!(
        host.ipv6_egress_addrs,
        vec![("eth0".into(), "2001:db8::10".parse().unwrap())]
    );
    assert_eq!(
        host.ipv6_gateways,
        vec!["fe80::1".parse::<Ipv6Addr>().unwrap()]
    );
    assert_eq!(host.ipv6_default_interfaces, vec!["eth0"]);
    assert_eq!(
        host.ipv6_routes,
        vec![("eth0".into(), "2001:db8::/64".parse().unwrap())]
    );
}

#[test]
fn successful_empty_output_is_an_observation_not_a_command_failure() {
    let host = gather_host_net_with(|_| Ok(output(true, ""))).unwrap();
    assert!(host.addrs.is_empty());
    assert!(host.gateways.is_empty());
    assert!(host.routes.is_empty());
    assert!(host.ipv6_addrs.is_empty());
    assert!(host.ipv6_egress_addrs.is_empty());
    assert!(host.ipv6_gateways.is_empty());
    assert!(host.ipv6_default_interfaces.is_empty());
    assert!(host.ipv6_routes.is_empty());
}

#[tokio::test]
async fn async_snapshot_preserves_sync_failure_policy_and_collision_data() {
    for failed in [None, Some(0), Some(1), Some(2), Some(3)] {
        for kind in [
            None,
            Some(io::ErrorKind::TimedOut),
            Some(io::ErrorKind::NotFound),
        ] {
            let mut index = 0;
            let asynchronous = gather_host_net_async_with(|_| {
                let current = index;
                index += 1;
                std::future::ready(if failed == Some(current) {
                    failure(kind, current)
                } else {
                    Ok(output(true, OBSERVATIONS[current]))
                })
            })
            .await;
            let async_calls = index;
            index = 0;
            let synchronous = gather_host_net_with(|_| {
                let current = index;
                index += 1;
                if failed == Some(current) {
                    failure(kind, current)
                } else {
                    Ok(output(true, OBSERVATIONS[current]))
                }
            });
            assert_eq!(index, async_calls);
            assert_eq!(format!("{asynchronous:?}"), format!("{synchronous:?}"));
        }
    }
}

// Run only in an isolated child executable, with optional loopback lifetime witness.
#[test]
fn probe_fixture() {
    use std::io::{Read, Write};
    let Ok(index) = std::env::var("QELI_PREFLIGHT_FIXTURE_INDEX") else {
        return;
    };
    let index: usize = index.parse().unwrap();
    if let Ok(address) = std::env::var("QELI_PREFLIGHT_FIXTURE_WITNESS") {
        let mut peer = std::net::TcpStream::connect(address).unwrap();
        peer.write_all(b"ready").unwrap();
        let _ = peer.read(&mut [0]);
    }
    // libtest's --nocapture label has no newline. Keep the observations on
    // separate lines, as they are in the real ip command's stdout.
    std::io::stdout().write_all(b"\n").unwrap();
    std::io::stdout()
        .write_all(OBSERVATIONS[index].as_bytes())
        .unwrap();
    std::io::stdout().flush().unwrap();
    std::process::exit(0);
}

fn fixture(index: usize, witness: Option<std::net::SocketAddr>) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    let module = module_path!().split_once("::").unwrap().1;
    command.args([
        "--exact",
        &format!("{module}::probe_fixture"),
        "--nocapture",
    ]);
    command.env("QELI_PREFLIGHT_FIXTURE_INDEX", index.to_string());
    if let Some(witness) = witness {
        command.env("QELI_PREFLIGHT_FIXTURE_WITNESS", witness.to_string());
    }
    command
}

#[tokio::test]
async fn asynchronous_probe_leaves_executor_responsive_and_cancellation_stops_child() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    let task = tokio::spawn(gather_host_net_async_commands(until, move |_| {
        fixture(0, Some(address))
    }));
    let (mut peer, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut ready = [0; 5];
    peer.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert!(
        !task.is_finished(),
        "preflight must still be pending on the child"
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let result = tokio::time::timeout(Duration::from_secs(3), peer.read(&mut [0]))
        .await
        .unwrap();
    assert!(
        matches!(result, Ok(0))
            || result.is_err_and(|error| matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ))
    );
}

#[tokio::test]
async fn later_ipv6_probes_share_one_deadline_and_keep_observed_ipv4() {
    use std::time::Duration;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let start = tokio::time::Instant::now();
    let until = start + Duration::from_secs(2);
    let mut index = 0;
    let host = gather_host_net_async_commands(until, move |_| {
        let current = index;
        index += 1;
        fixture(current, (current >= 2).then_some(address))
    })
    .await
    .expect("IPv6 timeout must not discard observed IPv4");
    assert_eq!(
        host.gateways,
        vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
    );
    assert!(host.ipv6_addrs.is_empty());
    assert!(host.ipv6_routes.is_empty());
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "deadline renewed for the next probe"
    );
}
