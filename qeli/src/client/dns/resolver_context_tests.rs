use super::*;
use crate::system_command::test_support::{arguments, with_commands, Action};
use std::{
    cell::RefCell,
    os::linux::net::SocketAddrExt,
    os::unix::{
        net::{SocketAddr, UnixListener},
        process::ExitStatusExt,
    },
    process::{ExitStatus, Output},
    rc::Rc,
};

#[derive(Default)]
struct State {
    owner: u32,
    new_bus: bool,
    malformed_pid: bool,
    until: Option<Instant>,
    methods: Vec<String>,
    writes: Vec<Vec<String>>,
}
fn reply(text: String) -> Action {
    Action::Reply(Ok(Output {
        status: ExitStatus::from_raw(0),
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }))
}
fn fixture<T>(run: impl FnOnce(String, Rc<RefCell<State>>) -> T) -> T {
    let name = format!(
        "qeli-resolver-context-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let listener =
        UnixListener::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
    listener.set_nonblocking(true).unwrap();
    struct Peer {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            self.thread.take().unwrap().join().unwrap();
        }
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = stop.clone();
    let _peer = Peer {
        stop,
        thread: Some(std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut buf = [0; 128];
                        if stream.read(&mut buf).is_ok() {
                            let _ = stream.write_all(b"OK abcdef0123456789abcdef0123456789\r\n");
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        })),
    };
    let address = format!("unix:abstract={name}");
    let state = Rc::new(RefCell::new(State::default()));
    let model = state.clone();
    let expected = format!("{address},guid=abcdef0123456789abcdef0123456789");
    with_commands(
        move |command| {
            let args = arguments(command);
            let mut s = model.borrow_mut();
            assert!(args.iter().any(|a| a == &format!("--address={expected}")));
            assert!(args.iter().any(|a| a == "--auto-start=no"));
            if args[4] != "org.freedesktop.DBus" {
                assert_eq!(
                    args[4],
                    format!(":1.{}", s.owner + 1),
                    "mutations must name the captured unique owner"
                );
                s.writes.push(args[7..].to_vec());
                return reply(String::new());
            }
            let method = args[7].as_str();
            s.methods.push(method.into());
            if let Some(until) = s.until.take() {
                std::thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
                );
            }
            reply(match method {
                "GetId" => format!(
                    "s \"{}123456789abcdef0123456789abcdef\"",
                    if s.new_bus { "1" } else { "0" }
                ),
                "GetNameOwner" => format!("s \":1.{}\"", s.owner + 1),
                "GetConnectionUnixProcessID" => format!(
                    "u {}",
                    if s.malformed_pid {
                        0
                    } else {
                        std::process::id()
                    }
                ),
                _ => panic!("unexpected bus method {args:?}"),
            })
        },
        || run(address, state),
    )
}
fn until() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn resolver_context_address_parser_refuses_ambiguous_endpoints() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(
        endpoint(DEFAULT_BUS).unwrap(),
        PathBuf::from("/run/dbus/system_bus_socket")
    );
    assert_eq!(
        endpoint("unix:path=/tmp/test%20bus,guid=0123456789abcdef0123456789abcdef").unwrap(),
        PathBuf::from("/tmp/test bus")
    );
    assert_eq!(
        endpoint("unix:abstract=test.bus")
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"\0test.bus"
    );
    for address in [
        "",
        "tcp:host=localhost",
        "unix:path=relative",
        "unix:path=",
        "unix:path=/a,path=/b",
        "unix:path=/a;unix:path=/b",
        "unix:path=/a%00b",
        "unix:path=/a%GG",
        "unix:abstract=",
        "unix:guid=abc",
        "unix:path=/a,guid=bad",
    ] {
        assert!(endpoint(address).is_err(), "{address}");
    }
}
#[test]
fn resolver_context_setup_and_revert_pin_verified_bus() {
    fixture(|address, state| {
        let context = Context::capture_at(address, until()).unwrap();
        let dns = crate::config::client::ClientDnsConfig {
            mode: "tunnel".into(),
            ..Default::default()
        };
        super::super::apply_link_dns(
            &dns,
            || Ok("42".into()),
            &["192.0.2.53".into()],
            until(),
            Some(&context),
        )
        .unwrap();
        super::super::revert_link_with("42", Some(&context), until()).unwrap();
        assert_eq!(state.borrow().writes.len(), 3);
        assert_eq!(
            state.borrow().writes[0],
            [
                "SetLinkDNS",
                "ia(iay)",
                "42",
                "1",
                "2",
                "4",
                "192",
                "0",
                "2",
                "53"
            ]
        );
        assert_eq!(state.borrow().writes[2], ["RevertLink", "i", "42"]);
    });
}
#[test]
fn resolver_context_replaced_service_never_receives_mutation_or_revert() {
    fixture(|address, state| {
        let context = Context::capture_at(address, until()).unwrap();
        state.borrow_mut().owner += 1;
        assert!(super::super::apply_link_dns(
            &Default::default(),
            || Ok("42".into()),
            &["192.0.2.53".into()],
            until(),
            Some(&context)
        )
        .is_err());
        assert!(super::super::revert_link_with("42", Some(&context), until()).is_err());
        assert!(state.borrow().writes.is_empty());
    });
}
#[test]
fn resolver_context_bus_replacement_invalidates_saved_context() {
    fixture(|address, state| {
        let context = Context::capture_at(address, until()).unwrap();
        state.borrow_mut().new_bus = true;
        assert!(context.verify(until()).is_err());
        assert!(state.borrow().writes.is_empty());
    });
}
#[test]
fn resolver_context_late_probe_stops_following_queries() {
    fixture(|address, state| {
        let until = Instant::now() + Duration::from_millis(50);
        state.borrow_mut().until = Some(until);
        assert!(Context::capture_at(address, until).is_err());
        assert_eq!(state.borrow().methods, ["GetId"]);
        assert!(state.borrow().writes.is_empty());
    });
}
#[test]
fn resolver_context_expired_admission_never_connects_to_bus() {
    let error = Context::capture_at("invalid address".into(), Instant::now())
        .err()
        .unwrap();
    assert!(error.to_string().contains("deadline expired"));
}
#[test]
fn resolver_context_invalid_service_pid_is_refused() {
    fixture(|address, state| {
        state.borrow_mut().malformed_pid = true;
        assert!(Context::capture_at(address, until()).is_err());
        assert!(state.borrow().writes.is_empty());
    });
}
#[test]
#[ignore = "requires Linux CAP_SYS_ADMIN; changes only a disposable thread network namespace"]
fn native_resolver_context_refuses_other_service_network() {
    std::thread::spawn(|| {
        // SAFETY: fresh disposable thread, no runtime or shared network mutations.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        fixture(|address, state| {
            // D-Bus reports the process leader's PID, whose namespace is the parent.
            let error = Context::capture_at(address, until())
                .err()
                .expect("foreign resolver must be refused");
            assert!(
                error.to_string().contains("different network namespace"),
                "{error}"
            );
            assert!(state.borrow().writes.is_empty());
        });
    })
    .join()
    .unwrap();
}

// Invoked only inside a private bus/resolved/mount/net/PID fixture, never by the
// generic privileged sweep. The required address is deliberately not a default bus.
#[test]
#[ignore = "child fixture: requires QELI_RESOLVER_TEST_BUS and isolated real resolved"]
fn resolver_service_child() -> anyhow::Result<()> {
    let address = std::env::var("QELI_RESOLVER_TEST_BUS")?;
    let context = Context::capture_at(address.clone(), until())?;
    let config = crate::config::client::ClientDnsConfig {
        mode: "tunnel".into(),
        ..Default::default()
    };
    super::super::apply_link_dns(
        &config,
        || Ok("2".into()),
        &["192.0.2.53".into()],
        until(),
        Some(&context),
    )?;
    let output = super::super::resolver_command(Some(&context))
        .args(["dns", "2"])
        .output()?;
    anyhow::ensure!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("192.0.2.53")
    );
    std::thread::spawn(move || {
        // SAFETY: fresh disposable test thread, no persistent namespace change.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNET) }, 0);
        let error = Context::capture_at(address, until())
            .err()
            .expect("foreign namespace capture must fail");
        assert!(
            error.to_string().contains("different network namespace"),
            "{error}"
        );
    })
    .join()
    .unwrap();
    // Extended typed API carries a port, not a TLS server name after '#'.
    super::super::apply_link_dns(
        &config,
        || Ok("2".into()),
        &["192.0.2.53#5353".into()],
        until(),
        Some(&context),
    )?;
    let output = super::super::resolver_command(Some(&context))
        .args(["dns", "2"])
        .output()?;
    anyhow::ensure!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("192.0.2.53:5353"),
        "custom DNS port readback: {:?}",
        output
    );
    // Authentication must refuse a different bus GUID before a method is delivered.
    let bad_address = format!(
        "{},guid=11111111111111111111111111111111",
        context.address().split(",guid=").next().unwrap()
    );
    let rejected = call(&bad_address, "GetId", &[], until());
    anyhow::ensure!(
        rejected.is_err(),
        "busctl accepted a different bus instance"
    );
    println!("REAL_RESOLVER_DEFAULT_AND_CUSTOM_PORT_AND_BUS_GUID_PASS");
    super::super::revert_link_with("2", Some(&context), until())?;
    let output = super::super::resolver_command(Some(&context))
        .args(["dns", "2"])
        .output()?;
    anyhow::ensure!(
        output.status.success() && !String::from_utf8_lossy(&output.stdout).contains("192.0.2.53")
    );
    Ok(())
}

#[test]
fn resolver_context_nonstandard_dns_port_is_a_port_not_a_server_name() {
    let (method, signature, args) = payload(
        "dns",
        42,
        &["192.0.2.53#5353".into(), "2001:db8::53".into()],
    )
    .unwrap();
    assert_eq!((method, signature), ("SetLinkDNSEx", "ia(iayqs)"));
    assert_eq!(
        &args[..10],
        ["42", "2", "2", "4", "192", "0", "2", "53", "5353", ""]
    );
    assert_eq!(&args[10..12], ["10", "16"]);
    assert_eq!(&args[28..], ["53", ""]);
    for bad in ["192.0.2.53#0", "192.0.2.53#65536", "bad#53"] {
        assert!(payload("dns", 42, &[bad.into()]).is_err());
    }
}

#[test]
fn resolver_context_authentication_guid_is_pinned_separately_from_bus_id() {
    fixture(|address, _| {
        let context = Context::capture_at(address.clone(), until()).unwrap();
        assert!(context
            .address()
            .ends_with(",guid=abcdef0123456789abcdef0123456789"));
        assert_ne!(context.snapshot.bus_id, "abcdef0123456789abcdef0123456789");
        assert!(Context::capture_at(
            format!("{address},guid=11111111111111111111111111111111"),
            until()
        )
        .is_err());
    });
}

#[test]
fn resolver_context_authentication_rejects_invalid_or_oversized_replies() {
    for reply in [
        b"REJECTED EXTERNAL\r\n".as_slice(),
        b"OK 00000000000000000000000000000000\r\n",
        b"OK bad\r\n",
        &[b'x'; 129],
    ] {
        let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.write_all(reply).unwrap();
        assert!(authentication_guid(&client.into(), until()).is_err());
    }
}
#[test]
fn resolver_context_authentication_deadline_bounds_silent_peer() {
    let (client, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let start = Instant::now();
    assert!(authentication_guid(&client.into(), start + Duration::from_millis(30)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
}
