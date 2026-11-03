//! Bounded real child completion combined with the route ownership/state model.
use super::*;
use crate::system_command::test_support::{arguments, with_commands, Action};
use std::sync::atomic::{AtomicBool, Ordering};

fn direct_probe(mode: &'static str, expected: io::ErrorKind) {
    let _serial = ROUTE_TEST_SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    with_commands(
        move |command| {
            assert_eq!(command.get_program(), "ip");
            assert_eq!(
                arguments(command),
                ["-6", "route", "show", "exact", "2001:db8::20"]
            );
            Action::Probe { mode }
        },
        || {
            let result = route_command_output(
                &["-6", "route", "show", "exact", "2001:db8::20"].map(String::from),
            );
            assert!(matches!(result, Err(ref error) if error.kind() == expected));
        },
    );
}
#[test]
fn command_bounds_route_deadline_rejects_late_success() {
    direct_probe("slow", io::ErrorKind::TimedOut);
}
#[test]
fn command_bounds_route_overflow_never_reaches_parser() {
    direct_probe("bytes", io::ErrorKind::InvalidData);
}

fn setup_probe(mode: &'static str, ipv6: bool, before: bool) {
    let fixture = Fixture::new(Vec::new(), None);
    // Use the production ip -> Command boundary, bypassing the older model-only seam.
    EXECUTOR.with(|slot| *slot.borrow_mut() = None);
    let kernel = fixture.kernel.clone();
    let target = if ipv6 {
        "2001:db8::/32"
    } else {
        "198.51.100.0/24"
    };
    let fired = Arc::new(AtomicBool::new(false));
    let observed = fired.clone();
    with_commands(
        move |command| {
            assert_eq!(command.get_program(), "ip");
            let raw = arguments(command);
            let args = if raw[0] == "-6" { &raw[1..] } else { &raw[..] };
            let inject = args[1] == if before { "show" } else { "add" }
                && !observed.swap(true, Ordering::SeqCst);
            let mut state = kernel.lock().unwrap();
            if inject {
                if before {
                    state.calls.push(raw);
                } else {
                    assert!(state.run(&raw).unwrap().status.success());
                }
                return Action::Probe { mode };
            }
            Action::Reply(state.run(&raw))
        },
        || {
            assert!(add_blackhole_half(&test_owner(), target).is_err());
            assert!(fired.load(Ordering::SeqCst));
            assert!(
                take_created(&test_owner()).is_empty(),
                "no ownership from an unknown add"
            );
            if before {
                assert!(
                    fixture.mutations().is_empty(),
                    "failed pre-query must prevent writes"
                );
                cleanup_routes(&test_owner()).unwrap();
            } else {
                let mutations = fixture.mutations();
                assert!(
                    cleanup_routes(&test_owner()).is_err(),
                    "pending cannot become absent"
                );
                assert_eq!(
                    fixture.mutations(),
                    mutations,
                    "pending is not delete authority"
                );
                assert!(
                    test_owner().operation().is_err(),
                    "public operation admission stays closed"
                );
                assert_eq!(fixture.mutations(), mutations);
                fixture.kernel.lock().unwrap().routes.remove(target);
                cleanup_routes(&test_owner()).unwrap();
            }
        },
    );
}
#[test]
fn command_bounds_applied_add_timeout_keeps_pending() {
    for ipv6 in [false, true] {
        setup_probe("slow", ipv6, false);
    }
}
#[test]
fn command_bounds_applied_add_overflow_keeps_pending() {
    for ipv6 in [false, true] {
        setup_probe("bytes", ipv6, false);
    }
}
#[test]
fn command_bounds_prequery_timeout_prevents_mutation() {
    for ipv6 in [false, true] {
        setup_probe("slow", ipv6, true);
    }
}
#[test]
fn command_bounds_prequery_overflow_prevents_mutation() {
    for ipv6 in [false, true] {
        setup_probe("bytes", ipv6, true);
    }
}

fn flush_probe(mode: &'static str, query: bool) {
    for ipv6 in [false, true] {
        let route = vec![
            if ipv6 { "fd88::/64" } else { "10.88.0.0/24" }.into(),
            "dev".into(),
            "qtest".into(),
        ];
        let fixture = Fixture::new(vec![route], None);
        EXECUTOR.with(|slot| *slot.borrow_mut() = None);
        let kernel = fixture.kernel.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let observed = fired.clone();
        with_commands(
            move |command| {
                assert_eq!(command.get_program(), "ip");
                let raw = arguments(command);
                let family = raw[0] == "-6";
                let args = if family { &raw[1..] } else { &raw[..] };
                let selected = args
                    == [
                        "route",
                        if query { "show" } else { "flush" },
                        "dev",
                        "qtest",
                    ];
                let mut state = kernel.lock().unwrap();
                if family == ipv6 && selected && !observed.swap(true, Ordering::SeqCst) {
                    assert!(state.run(&raw).unwrap().status.success());
                    return Action::Probe { mode };
                }
                Action::Reply(state.run(&raw))
            },
            || {
                let first = cleanup_routes(&test_owner());
                assert!(fired.load(Ordering::SeqCst));
                assert_eq!(
                    first.is_err(),
                    query,
                    "postcondition, not completion, determines flush outcome"
                );
                let state = fixture.kernel.lock().unwrap();
                for family in [false, true] {
                    assert!(state
                        .calls
                        .iter()
                        .any(|raw| raw.contains(&"flush".into()) && (raw[0] == "-6") == family));
                }
                drop(state);
                cleanup_routes(&test_owner()).unwrap();
            },
        );
    }
}
#[test]
fn command_bounds_applied_flush_timeout_can_be_verified() {
    flush_probe("slow", false);
}
#[test]
fn command_bounds_applied_flush_overflow_can_be_verified() {
    flush_probe("bytes", false);
}
#[test]
fn command_bounds_flush_query_timeout_requires_retry() {
    flush_probe("slow", true);
}
#[test]
fn command_bounds_flush_query_overflow_requires_retry() {
    flush_probe("bytes", true);
}

#[test]
fn command_bounds_hook_discovery_uses_bounded_command() {
    for mode in ["slow", "bytes"] {
        with_commands(
            move |command| {
                assert_eq!(command.get_program(), "ip");
                assert_eq!(
                    arguments(command),
                    ["-6", "route", "get", "2001:db8::20", "from", "2001:db8::10"]
                );
                Action::Probe { mode }
            },
            || {
                assert!(hook_physical_path_for(
                    "2001:db8::20".parse().unwrap(),
                    "qtest",
                    Some("2001:db8::10".parse().unwrap())
                )
                .is_none())
            },
        );
    }
}
