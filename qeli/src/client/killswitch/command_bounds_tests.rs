//! Host-safe integration of the firewall helpers and the real bounded collector.
use super::*;
use crate::system_command::test_support::{arguments, with_commands, Action};
use std::io;

fn ipt_probe(mode: &'static str, expected: io::ErrorKind) {
    with_commands(
        move |command| {
            assert_eq!(command.get_program(), "qeli-test-iptables");
            assert_eq!(arguments(command), ["-C", "OUTPUT", "-j", "QELI_KS_qtest"]);
            Action::Probe { mode }
        },
        || {
            let result = ipt(
                "qeli-test-iptables",
                &["-C", "OUTPUT", "-j", "QELI_KS_qtest"],
            );
            assert!(matches!(result, Err(ref error) if error.kind() == expected));
        },
    );
}
#[test]
fn command_bounds_iptables_deadline_rejects_late_success() {
    ipt_probe("slow", io::ErrorKind::TimedOut);
}
#[test]
fn command_bounds_iptables_overflow_is_an_error() {
    ipt_probe("bytes", io::ErrorKind::InvalidData);
}
#[test]
fn command_bounds_firewall_queries_never_claim_absence_on_limit() {
    for mode in ["slow", "bytes"] {
        with_commands(
            move |command| {
                assert_eq!(command.get_program(), "qeli-test-iptables");
                Action::Probe { mode }
            },
            || {
                assert!(present_checked(
                    "qeli-test-iptables",
                    &["-C", "OUTPUT", "-j", "QELI_KS_qtest"]
                )
                .is_err());
                assert!(
                    chain_exists(&Context::fixture(), "qeli-test-iptables", "QELI_KS_qtest")
                        .is_err()
                );
            },
        );
    }
}
#[test]
fn command_bounds_teardown_does_not_flush_uninspectable_chain() {
    for mode in ["slow", "bytes"] {
        with_commands(
            move |command| {
                assert_eq!(command.get_program(), "qeli-test-iptables");
                assert!(
                    matches!(arguments(command)[0].as_str(), "-C" | "-S"),
                    "no blind firewall mutation"
                );
                Action::Probe { mode }
            },
            || {
                assert!(
                    teardown_family(&Context::fixture(), "qeli-test-iptables", "QELI_KS_qtest")
                        .is_err()
                )
            },
        );
    }
}
#[test]
fn command_bounds_server_allow_inventory_rejects_partial_output() {
    for mode in ["slow", "bytes"] {
        with_commands(
            move |command| {
                assert_eq!(command.get_program(), "qeli-test-iptables");
                assert_eq!(arguments(command), ["-S", "QELI_KS_qtest"]);
                Action::Probe { mode }
            },
            || {
                assert!(live_server_allows(
                    &Context::fixture(),
                    "qeli-test-iptables",
                    "QELI_KS_qtest"
                )
                .is_err())
            },
        );
    }
}
#[test]
fn command_bounds_firewall_preserves_complete_success_and_nonzero_exit() {
    for (mode, success) in [("stdin", true), ("fail", false)] {
        with_commands(
            move |_| Action::Probe { mode },
            || {
                let result = ipt("qeli-test-iptables", &["--version"]).unwrap();
                assert_eq!(result.status.success(), success);
                if !success {
                    assert_eq!(result.status.code(), Some(17));
                    assert_eq!(result.stderr, b"expected command failure");
                }
            },
        );
    }
}

#[test]
fn teardown_preserves_referenced_chain_when_jump_deletion_does_not_work() {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};
    for hook in ["OUTPUT", "FORWARD"] {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        with_commands(
            move |command| {
                let args = arguments(command);
                observed.lock().unwrap().push(args.clone());
                assert!(
                    matches!(args[0].as_str(), "-C" | "-D"),
                    "no flush/delete of referenced chain: {args:?}"
                );
                let present = args[1] == hook;
                Action::Reply(Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(if present {
                        0
                    } else {
                        if cfg!(unix) {
                            256
                        } else {
                            1
                        }
                    }),
                    stdout: vec![],
                    stderr: if present {
                        vec![]
                    } else {
                        b"Bad rule (does a matching rule exist in that chain?).".to_vec()
                    },
                }))
            },
            || {
                let error =
                    teardown_family(&Context::fixture(), "fixture", "QELI_KS_qtest").unwrap_err();
                assert!(error.to_string().contains("chain retained"));
            },
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|a| a[0] == "-D").count(), 8);
    }
}

#[test]
fn teardown_preserves_chain_if_hook_inventory_is_unknown_even_when_chain_is_readable() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let inspected = Arc::new(AtomicUsize::new(0));
    let calls = inspected.clone();
    with_commands(
        move |command| {
            let args = arguments(command);
            assert_eq!(
                args[0], "-C",
                "unknown hook state must not authorize chain flushing: {args:?}"
            );
            calls.fetch_add(1, Ordering::Relaxed);
            Action::Reply(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hook inspection refused",
            )))
        },
        || {
            let error =
                teardown_family(&Context::fixture(), "fixture", "QELI_KS_qtest").unwrap_err();
            assert!(error.to_string().contains("chain retained"));
        },
    );
    assert_eq!(inspected.load(Ordering::Relaxed), 4);
}
