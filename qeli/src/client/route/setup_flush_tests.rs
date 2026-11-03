//! Initial setup and interface cleanup use the real production command boundary.
use super::*;

#[derive(Clone, Copy)]
enum SetupKind {
    Carrier,
    Exclude,
    Blackhole,
}
impl SetupKind {
    fn destination(self, ipv6: bool) -> String {
        match self {
            Self::Carrier | Self::Exclude => candidate(ipv6).remote.to_string(),
            Self::Blackhole => if ipv6 {
                "2001:db8::/32"
            } else {
                "198.51.100.0/24"
            }
            .into(),
        }
    }
    fn run(self, ipv6: bool) -> anyhow::Result<()> {
        let route = candidate(ipv6);
        match self {
            Self::Carrier => pin_carrier_route(
                &test_owner(),
                route.remote,
                &PhysicalPath {
                    gateway: route.gateway,
                    device: route.interface,
                },
            ),
            Self::Blackhole => add_blackhole_half(&test_owner(), &self.destination(ipv6)),
            Self::Exclude => {
                let network = NetworkPlan {
                    generation: 7,
                    family_mode: crate::transport_core::NetworkFamilyMode::Ipv4,
                    addresses: Vec::new(),
                    tunnel_address: "10.20.0.2".into(),
                    prefix_len: 24,
                    mtu: 1400,
                    tunnel_gateway: "10.20.0.1".into(),
                    carrier_address: None,
                    routes: Vec::new(),
                    pushed_routes: Vec::new(),
                    dns_servers: Vec::new(),
                    full_tunnel: false,
                    kill_switch: false,
                    allow_ipv4_leak: false,
                    allow_ipv6_leak: false,
                    max_streams: 1,
                    adaptive: false,
                    data_plane: Default::default(),
                    connection_log: Vec::new(),
                };
                setup_network_plan_routes(
                    &test_owner(),
                    &ClientRoutingConfig {
                        exclude: vec![self.destination(ipv6)],
                        ..Default::default()
                    },
                    &network,
                    &[route.remote],
                    None,
                    false,
                )
            }
        }
    }
}
#[derive(Clone, Copy)]
enum AddFault {
    Success,
    AppliedExists,
    AppliedIo,
    AppliedError,
    LieSuccess,
    PostQueryError,
    PreQueryError,
}
fn setup_fixture(kind: SetupKind, ipv6: bool, fault: AddFault) -> Fixture {
    let fixture = Fixture::new(Vec::new(), None);
    let kernel = fixture.kernel.clone();
    let destination = kind.destination(ipv6);
    let mut wrote = false;
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |raw| {
            let args = if raw[0] == "-6" { &raw[1..] } else { raw };
            let mut state = kernel.lock().unwrap();
            if args[1] == "get" {
                state.calls.push(raw.to_vec());
                return output(
                    true,
                    &format!(
                        "{} via {} dev eth0",
                        args[2],
                        if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                    ),
                );
            }
            if args[1] == "show"
                && args.last() == Some(&destination)
                && (matches!(fault, AddFault::PreQueryError)
                    || (wrote && matches!(fault, AddFault::PostQueryError)))
            {
                state.calls.push(raw.to_vec());
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if args[1] == "add" && args.iter().any(|s| s == &destination) {
                wrote = true;
                if matches!(fault, AddFault::LieSuccess) {
                    state.calls.push(raw.to_vec());
                    return output(true, "");
                }
                state.run(raw)?;
                return match fault {
                    AddFault::AppliedIo => Err(io::ErrorKind::BrokenPipe.into()),
                    AddFault::AppliedError => output(false, "fixture lost result"),
                    AddFault::AppliedExists => output(false, "RTNETLINK answers: File exists"),
                    _ => output(true, ""),
                };
            }
            state.run(raw)
        }))
    });
    fixture
}
fn reset_executor(fixture: &Fixture) {
    let kernel = fixture.kernel.clone();
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |args| kernel.lock().unwrap().run(args)))
    });
}
fn kinds() -> [SetupKind; 3] {
    [SetupKind::Carrier, SetupKind::Exclude, SetupKind::Blackhole]
}

#[test]
fn setup_flush_unknown_initial_add_remains_reserved() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            for fault in [AddFault::AppliedIo, AddFault::AppliedError] {
                let fixture = setup_fixture(kind, ipv6, fault);
                assert!(kind.run(ipv6).is_err());
                reset_executor(&fixture);
                let before = fixture.mutations();
                assert!(
                    cleanup_routes(&test_owner()).is_err(),
                    "unknown setup add cannot become a clean teardown"
                );
                assert_eq!(
                    fixture.mutations(),
                    before,
                    "pending must not authorize delete"
                );
            }
        }
    }
}
#[test]
fn setup_flush_initial_add_lie_success_is_rejected_without_claim() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::LieSuccess);
            assert!(
                kind.run(ipv6).is_err(),
                "missing route cannot be a successful setup"
            );
            assert!(take_created(&test_owner()).is_empty());
            reset_executor(&fixture);
            cleanup_routes(&test_owner()).unwrap();
        }
    }
}
#[test]
fn setup_flush_unreadable_post_snapshot_does_not_claim_initial_add() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::PostQueryError);
            assert!(kind.run(ipv6).is_err());
            assert!(
                take_created(&test_owner()).is_empty(),
                "no proof of the applied route"
            );
            reset_executor(&fixture);
            assert!(cleanup_routes(&test_owner()).is_err());
        }
    }
}
#[test]
fn setup_flush_unreadable_pre_snapshot_prevents_initial_mutation() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::PreQueryError);
            assert!(kind.run(ipv6).is_err());
            assert!(fixture.mutations().is_empty());
        }
    }
}

#[derive(Clone, Copy)]
enum FlushFault {
    LieSuccess,
    FalseAbsent,
    AppliedIo,
    AppliedError,
    QueryError,
}
fn tun_route(ipv6: bool, interface: &str) -> Vec<String> {
    vec![
        if ipv6 { "fd88::/64" } else { "10.88.0.0/24" }.into(),
        "dev".into(),
        interface.into(),
    ]
}
fn flush_fixture(ipv6: bool, fault: FlushFault) -> Fixture {
    let fixture = Fixture::new(
        vec![
            tun_route(ipv6, "qtest"),
            tun_route(!ipv6, "qtest"),
            tun_route(ipv6, "other-tun"),
        ],
        None,
    );
    // The simple model indexes by prefix, so keep the other interface on a separate prefix.
    {
        let mut state = fixture.kernel.lock().unwrap();
        state
            .routes
            .insert("other".into(), tun_route(ipv6, "other-tun"));
        let target = tun_route(ipv6, "qtest");
        state.routes.insert(target[0].clone(), target);
    }
    let kernel = fixture.kernel.clone();
    let mut fired = false;
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |raw| {
            let family = raw[0] == "-6";
            let args = if family { &raw[1..] } else { raw };
            let mut state = kernel.lock().unwrap();
            if family == ipv6 && args == ["route", "flush", "dev", "qtest"] {
                fired = true;
                if matches!(fault, FlushFault::LieSuccess | FlushFault::FalseAbsent) {
                    state.calls.push(raw.to_vec());
                    return output(
                        matches!(fault, FlushFault::LieSuccess),
                        "Cannot find device \"qtest\"",
                    );
                }
                state.run(raw)?;
                return match fault {
                    FlushFault::AppliedIo => Err(io::ErrorKind::BrokenPipe.into()),
                    FlushFault::AppliedError => output(false, "fixture completion lost"),
                    _ => output(true, ""),
                };
            }
            if family == ipv6
                && fired
                && args == ["route", "show", "dev", "qtest"]
                && matches!(fault, FlushFault::QueryError)
            {
                state.calls.push(raw.to_vec());
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            state.run(raw)
        }))
    });
    fixture
}
#[test]
fn setup_flush_lie_success_retains_owner_until_verified_retry() {
    for ipv6 in [false, true] {
        let fixture = flush_fixture(ipv6, FlushFault::LieSuccess);
        assert!(cleanup_routes(&test_owner()).is_err());
        assert!(!fixture
            .kernel
            .lock()
            .unwrap()
            .routes
            .contains_key(&tun_route(!ipv6, "qtest")[0]));
        reset_executor(&fixture);
        cleanup_routes(&test_owner()).unwrap();
        assert_eq!(
            fixture.kernel.lock().unwrap().routes.len(),
            1,
            "other interface must survive"
        );
    }
}
#[test]
fn setup_flush_false_absent_diagnostic_is_not_proof() {
    for ipv6 in [false, true] {
        let _fixture = flush_fixture(ipv6, FlushFault::FalseAbsent);
        assert!(cleanup_routes(&test_owner()).is_err());
    }
}
#[test]
fn setup_flush_lost_result_with_verified_absence_completes() {
    for ipv6 in [false, true] {
        for fault in [FlushFault::AppliedIo, FlushFault::AppliedError] {
            let fixture = flush_fixture(ipv6, fault);
            cleanup_routes(&test_owner()).unwrap();
            assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 1);
        }
    }
}
#[test]
fn setup_flush_unreadable_post_query_retains_cleanup_failure() {
    for ipv6 in [false, true] {
        let fixture = flush_fixture(ipv6, FlushFault::QueryError);
        assert!(cleanup_routes(&test_owner()).is_err());
        reset_executor(&fixture);
        cleanup_routes(&test_owner()).unwrap();
    }
}

// Additional controls added after the eight baseline failures.
fn setup_snapshot(kind: SetupKind, ipv6: bool) -> Vec<String> {
    let destination = kind.destination(ipv6);
    if matches!(kind, SetupKind::Blackhole) {
        vec!["blackhole".into(), destination]
    } else {
        vec![
            destination,
            "via".into(),
            if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.into(),
            "dev".into(),
            "eth0".into(),
        ]
    }
}
#[test]
fn setup_flush_successful_initial_routes_are_owned_and_removed() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::Success);
            kind.run(ipv6).unwrap();
            assert_eq!(fixture.mutations().len(), 1);
            cleanup_routes(&test_owner()).unwrap();
            assert!(fixture.kernel.lock().unwrap().routes.is_empty());
        }
    }
}
#[test]
fn setup_flush_matching_external_route_is_borrowed_without_mutation() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::Success);
            fixture
                .kernel
                .lock()
                .unwrap()
                .routes
                .insert(kind.destination(ipv6), setup_snapshot(kind, ipv6));
            kind.run(ipv6).unwrap();
            cleanup_routes(&test_owner()).unwrap();
            assert!(fixture.mutations().is_empty());
            assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 1);
        }
    }
}
#[test]
fn setup_flush_conflicting_external_route_is_preserved_before_add() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::Success);
            let foreign = vec![kind.destination(ipv6), "dev".into(), "operator0".into()];
            fixture
                .kernel
                .lock()
                .unwrap()
                .routes
                .insert(kind.destination(ipv6), foreign.clone());
            assert!(kind.run(ipv6).is_err());
            cleanup_routes(&test_owner()).unwrap();
            assert!(fixture.mutations().is_empty());
            assert_eq!(
                fixture.kernel.lock().unwrap().routes[&kind.destination(ipv6)],
                foreign
            );
        }
    }
}
#[test]
fn setup_flush_file_exists_after_initial_absence_is_not_borrowed() {
    for kind in kinds() {
        for ipv6 in [false, true] {
            let fixture = setup_fixture(kind, ipv6, AddFault::AppliedExists);
            assert!(kind.run(ipv6).is_err());
            assert!(take_created(&test_owner()).is_empty());
            reset_executor(&fixture);
            let before = fixture.mutations();
            assert!(cleanup_routes(&test_owner()).is_err());
            assert_eq!(fixture.mutations(), before);
        }
    }
}
#[test]
fn setup_flush_invalid_snapshots_never_grant_initial_ownership() {
    for after in [false, true] {
        for bad in ["wrong destination", "ambiguous", "invalid utf8"] {
            let fixture = Fixture::new(Vec::new(), None);
            let route = candidate(false);
            let kernel = fixture.kernel.clone();
            let mut wrote = false;
            EXECUTOR.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |args| {
                    let mut state = kernel.lock().unwrap();
                    if args.iter().any(|s| s == "add") {
                        wrote = true;
                    }
                    if args.iter().any(|s| s == "show")
                        && args.last().is_some_and(|s| s == "198.51.100.20")
                        && (!after || wrote)
                    {
                        state.calls.push(args.to_vec());
                        return match bad {
                            "wrong destination" => {
                                output(true, "203.0.113.9 via 192.0.2.1 dev eth0")
                            }
                            "ambiguous" => output(
                                true,
                                "198.51.100.20 via 192.0.2.1 dev eth0\n198.51.100.20 dev other0",
                            ),
                            _ => {
                                let mut out = output(true, "")?;
                                out.stdout = vec![0xff];
                                Ok(out)
                            }
                        };
                    }
                    state.run(args)
                }))
            });
            assert!(pin_carrier_route(
                &test_owner(),
                route.remote,
                &PhysicalPath {
                    gateway: route.gateway,
                    device: route.interface
                }
            )
            .is_err());
            assert!(take_created(&test_owner()).is_empty());
            assert_eq!(fixture.mutations().len(), usize::from(after));
        }
    }
}
#[test]
fn setup_flush_on_link_request_does_not_accept_gateway_route() {
    let route = candidate(false);
    let fixture = Fixture::new(vec![setup_snapshot(SetupKind::Carrier, false)], None);
    assert!(pin_carrier_route(
        &test_owner(),
        route.remote,
        &PhysicalPath {
            gateway: None,
            device: "eth0".into()
        }
    )
    .is_err());
    assert!(fixture.mutations().is_empty());
    cleanup_routes(&test_owner()).unwrap();
    assert_eq!(fixture.kernel.lock().unwrap().routes.len(), 1);
}
#[test]
fn setup_flush_pending_setup_closes_owner_and_blocks_another_owner() {
    let fixture = setup_fixture(SetupKind::Carrier, false, AddFault::AppliedIo);
    assert!(SetupKind::Carrier.run(false).is_err());
    let other = RouteOwner::test_new("other-tun", 8).unwrap();
    let before = fixture.kernel.lock().unwrap().calls.len();
    assert!(plan(vec![candidate(false)]).commit(&[]).is_err());
    assert!(plan_for(&other, vec![candidate(false)])
        .commit(&[])
        .is_err());
    assert_eq!(fixture.kernel.lock().unwrap().calls.len(), before);
}

fn missing_interface_fixture(link_result: io::Result<Output>) -> Fixture {
    let fixture = Fixture::new(Vec::new(), None);
    let kernel = fixture.kernel.clone();
    let result = match link_result {
        Ok(out) => Ok((out.status, out.stdout, out.stderr)),
        Err(err) => Err(err.kind()),
    };
    EXECUTOR.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |raw| {
            if raw == ["-o", "link", "show"] {
                kernel.lock().unwrap().calls.push(raw.to_vec());
                return match &result {
                    Ok((status, stdout, stderr)) => Ok(Output {
                        status: *status,
                        stdout: stdout.clone(),
                        stderr: stderr.clone(),
                    }),
                    Err(kind) => Err((*kind).into()),
                };
            }
            let args = if raw[0] == "-6" { &raw[1..] } else { raw };
            kernel.lock().unwrap().calls.push(raw.to_vec());
            assert!(
                args == ["route", "flush", "dev", "qtest"]
                    || args == ["route", "show", "dev", "qtest"]
            );
            output(false, "Cannot find device \"qtest\"")
        }))
    });
    fixture
}
#[test]
fn setup_flush_missing_interface_is_confirmed_by_link_inventory() {
    let fixture = missing_interface_fixture(output(
        true,
        "1: lo: <LOOPBACK> mtu 65536\n2: qtest-other@if7: <UP> mtu 1400",
    ));
    cleanup_routes(&test_owner()).unwrap();
    cleanup_routes(&test_owner()).unwrap();
    assert!(fixture.mutations().is_empty());
    assert_eq!(
        fixture
            .kernel
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.iter().any(|s| s == "flush"))
            .count(),
        4
    );
}
#[test]
fn setup_flush_query_failure_with_existing_interface_is_not_absence() {
    for name in ["qtest", "qtest@if9"] {
        let fixture =
            missing_interface_fixture(output(true, &format!("1: lo: <UP>\n2: {name}: <UP>")));
        assert!(cleanup_routes(&test_owner()).is_err());
        assert_eq!(
            fixture
                .kernel
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|c| c.iter().any(|s| s == "flush"))
                .count(),
            2
        );
    }
}
#[test]
fn setup_flush_invalid_link_inventory_does_not_release_reservation() {
    let mut utf8 = output(true, "").unwrap();
    utf8.stdout = vec![0xff];
    for result in [
        output(true, "garbled"),
        output(true, "0: eth0: <UP>"),
        output(true, "2: : <UP>"),
        output(false, "denied"),
        Err(io::ErrorKind::BrokenPipe.into()),
        Ok(utf8),
    ] {
        let _fixture = missing_interface_fixture(result);
        assert!(cleanup_routes(&test_owner()).is_err());
    }
}
#[test]
fn setup_flush_invalid_utf8_after_flush_is_not_empty_snapshot() {
    for ipv6 in [false, true] {
        let fixture = Fixture::new(Vec::new(), None);
        let kernel = fixture.kernel.clone();
        EXECUTOR.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |raw| {
                let args = if raw[0] == "-6" { &raw[1..] } else { raw };
                if (raw[0] == "-6") == ipv6 && args == ["route", "show", "dev", "qtest"] {
                    kernel.lock().unwrap().calls.push(raw.to_vec());
                    let mut result = output(true, "")?;
                    result.stdout = vec![0xff];
                    return Ok(result);
                }
                kernel.lock().unwrap().run(raw)
            }))
        });
        assert!(cleanup_routes(&test_owner()).is_err());
    }
}
#[test]
fn setup_flush_failed_command_on_already_empty_interface_is_complete() {
    let fixture = Fixture::new(Vec::new(), None);
    fixture.kernel.lock().unwrap().flush_error = true;
    cleanup_routes(&test_owner()).unwrap();
}
