//! Production NetworkPlan route application against an isolated kernel state model.
use super::*;
use crate::system_command::test_support::{arguments, with_commands, Action};
use crate::transport_core::{NetworkAddress, NetworkFamilyMode, NetworkRoute};

#[derive(Clone, Copy)]
enum Origin {
    Connected,
    Configured,
    Capture,
    Local,
}
#[derive(Clone, Copy)]
enum Failure {
    None,
    Lie,
    PreQuery,
    PostQuery,
    Lost,
    Foreign,
    Inventory(&'static [u8]),
}

struct Case {
    config: ClientRoutingConfig,
    network: NetworkPlan,
    target: String,
    ipv6: bool,
    tap: bool,
}
impl Case {
    fn new(origin: Origin, ipv6: bool, tap: bool) -> Self {
        let address = if ipv6 { "fd20::2" } else { "10.20.0.2" };
        let gateway = if ipv6 { "fd20::1" } else { "10.20.0.1" };
        let bits = if ipv6 { 128 } else { 32 };
        let target = match origin {
            Origin::Connected => {
                if ipv6 {
                    "fd20::/64"
                } else {
                    "10.20.0.0/24"
                }
            }
            Origin::Configured => {
                if ipv6 {
                    "fd22::/64"
                } else {
                    "172.22.0.0/16"
                }
            }
            Origin::Capture => {
                if ipv6 {
                    "::/1"
                } else {
                    "0.0.0.0/1"
                }
            }
            Origin::Local => "10.88.0.0/25",
        }
        .to_string();
        let routes = if matches!(origin, Origin::Configured) {
            vec![NetworkRoute {
                cidr: target.clone(),
                gateway: gateway.into(),
                metric: 100,
            }]
        } else {
            Vec::new()
        };
        Self {
            config: ClientRoutingConfig {
                route_local_networks: matches!(origin, Origin::Local),
                allow_ipv4_leak: true,
                allow_ipv6_leak: true,
                ..Default::default()
            },
            network: NetworkPlan {
                generation: 7,
                family_mode: if ipv6 {
                    NetworkFamilyMode::Ipv6
                } else {
                    NetworkFamilyMode::Ipv4
                },
                addresses: vec![NetworkAddress {
                    family: if ipv6 {
                        NetworkAddressFamily::Ipv6
                    } else {
                        NetworkAddressFamily::Ipv4
                    },
                    address: address.into(),
                    prefix_len: bits,
                    on_link_prefix_len: if matches!(origin, Origin::Connected) {
                        if ipv6 {
                            64
                        } else {
                            24
                        }
                    } else {
                        bits
                    },
                    gateway: Some(gateway.into()),
                }],
                tunnel_address: address.into(),
                prefix_len: bits,
                mtu: 1400,
                tunnel_gateway: gateway.into(),
                carrier_address: None,
                routes,
                pushed_routes: Vec::new(),
                dns_servers: Vec::new(),
                full_tunnel: matches!(origin, Origin::Capture),
                kill_switch: false,
                allow_ipv4_leak: true,
                allow_ipv6_leak: true,
                max_streams: 1,
                adaptive: false,
                data_plane: Default::default(),
                connection_log: Vec::new(),
            },
            target,
            ipv6,
            tap,
        }
    }
    fn run(&self) -> anyhow::Result<()> {
        setup_network_plan_routes(
            &test_owner(),
            &self.config,
            &self.network,
            &[candidate(self.ipv6).remote],
            None,
            self.tap,
        )
    }
    fn row(&self, metric: u32) -> Vec<String> {
        let mut row = vec![self.target.clone()];
        if self.tap {
            row.extend(["via".into(), self.network.tunnel_gateway.clone()]);
        }
        row.extend([
            "dev".into(),
            "qtest".into(),
            "metric".into(),
            metric.to_string(),
        ]);
        row
    }
}

fn fixture_run<T>(
    case: &Case,
    existing: Option<Vec<String>>,
    failure: Failure,
    run: impl FnOnce(&Fixture) -> T,
) -> T {
    // A pre-existing physical carrier avoids unrelated mutations in full-tunnel tests.
    let carrier = candidate(case.ipv6);
    let mut initial = vec![vec![
        carrier.remote.to_string(),
        "via".into(),
        carrier.gateway.unwrap(),
        "dev".into(),
        "eth0".into(),
    ]];
    if let Some(row) = existing {
        initial.push(row);
    }
    let fixture = Fixture::new(initial, None);
    EXECUTOR.with(|slot| *slot.borrow_mut() = None);
    let kernel = fixture.kernel.clone();
    let target = case.target.clone();
    let mut wrote = false;
    with_commands(
        move |command| {
            assert_eq!(
                command.get_program(),
                "ip",
                "no host command may escape this fixture"
            );
            let raw = arguments(command);
            if raw == ["-4", "-o", "address", "show", "up", "scope", "global"] {
                kernel.lock().unwrap().calls.push(raw);
                if let Failure::Inventory(bytes) = failure {
                    let mut result = output(true, "").unwrap();
                    result.stdout = bytes.to_vec();
                    return Action::Reply(Ok(result));
                }
                return Action::Reply(output(
                    true,
                    "2: eth0 inet 10.88.0.3/24 scope global eth0\n",
                ));
            }
            let ipv6 = raw[0] == "-6";
            let args = if ipv6 { &raw[1..] } else { &raw[..] };
            let verb = args[1].as_str();
            let selected = args.iter().any(|arg| arg == &target);
            let mut state = kernel.lock().unwrap();
            if verb == "get" {
                state.calls.push(raw.clone());
                return Action::Reply(output(
                    true,
                    &format!(
                        "{} via {} dev eth0",
                        args[2],
                        if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                    ),
                ));
            }
            if selected
                && verb == "show"
                && (matches!(failure, Failure::PreQuery)
                    || (wrote && matches!(failure, Failure::PostQuery)))
            {
                state.calls.push(raw);
                return Action::Reply(Err(io::ErrorKind::TimedOut.into()));
            }
            if selected && verb == "add" {
                wrote = true;
                if matches!(failure, Failure::Lie) {
                    state.calls.push(raw);
                    return Action::Reply(output(true, ""));
                }
                let result = state.run(&raw);
                if matches!(failure, Failure::Foreign) {
                    state.routes.insert(
                        target.clone(),
                        vec![
                            target.clone(),
                            "dev".into(),
                            "operator0".into(),
                            "metric".into(),
                            "77".into(),
                        ],
                    );
                }
                if matches!(failure, Failure::Lost | Failure::Foreign) {
                    return Action::Reply(Err(io::ErrorKind::TimedOut.into()));
                }
                return Action::Reply(result);
            }
            let mut result = state.run(&raw);
            if verb == "show" {
                if let Ok(ref mut output) = result {
                    // Model actual display defaults without changing route identity in state.
                    let text = String::from_utf8(output.stdout.clone()).unwrap();
                    let text = if ipv6 {
                        text.replace("metric 0", "metric 1024")
                    } else {
                        text.replace(" metric 0", "")
                    };
                    let text = text
                        .replace("0.0.0.0/0 ", "default ")
                        .replace("::/0 ", "default ");
                    output.stdout = text.into_bytes();
                }
            }
            Action::Reply(result)
        },
        || run(&fixture),
    )
}
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for ipv6 in [false, true] {
        for origin in [Origin::Connected, Origin::Configured, Origin::Capture] {
            cases.push(Case::new(origin, ipv6, false));
        }
        cases.push(Case::new(Origin::Configured, ipv6, true));
    }
    cases.push(Case::new(Origin::Local, false, false));
    cases
}

#[test]
fn tunnel_plan_lie_success_is_rejected_for_every_origin() {
    for case in cases() {
        fixture_run(&case, None, Failure::Lie, |_| {
            assert!(case.run().is_err(), "missing {} accepted", case.target)
        });
    }
}
#[test]
fn tunnel_plan_existing_metric_conflict_is_rejected() {
    for ipv6 in [false, true] {
        for tap in [false, true] {
            let case = Case::new(Origin::Configured, ipv6, tap);
            fixture_run(&case, Some(case.row(99)), Failure::None, |fixture| {
                assert!(case.run().is_err(), "wrong metric accepted");
                assert!(
                    fixture.mutations().is_empty(),
                    "conflict must be checked before add"
                );
            });
        }
    }
}
#[test]
fn tunnel_plan_direct_tun_does_not_borrow_a_gateway_route() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        let mut row = case.row(100);
        row.extend(["via".into(), case.network.tunnel_gateway.clone()]);
        fixture_run(&case, Some(row), Failure::None, |_| {
            assert!(case.run().is_err())
        });
    }
}
#[test]
fn tunnel_plan_failed_prequery_prevents_writes() {
    for case in cases() {
        fixture_run(&case, None, Failure::PreQuery, |fixture| {
            assert!(case.run().is_err());
            assert!(fixture.mutations().is_empty());
        });
    }
}
#[test]
fn tunnel_plan_failed_postquery_closes_admission() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        fixture_run(&case, None, Failure::PostQuery, |_| {
            assert!(case.run().is_err());
            assert!(take_created(&test_owner()).is_empty());
            assert!(test_owner().operation().is_err());
        });
    }
}
#[test]
fn tunnel_plan_lost_add_keeps_reservation_without_delete_authority() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        fixture_run(&case, None, Failure::Lost, |_| {
            assert!(case.run().is_err());
            assert!(take_created(&test_owner()).is_empty());
            assert!(test_owner().operation().is_err());
            let other = RouteOwner::test_new("other-tun", 8).unwrap();
            let spec = delete_spec(&tunnel_route_args(
                ipv6,
                &case.target,
                &case.network.tunnel_gateway,
                "other-tun",
                100,
                false,
            ));
            assert!(ensure_unclaimed(&other, &spec).is_err());
        });
    }
}
#[test]
fn tunnel_plan_success_records_verified_route_selector() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        fixture_run(&case, None, Failure::None, |_| {
            case.run().unwrap();
            let spec = delete_spec(&tunnel_route_args(
                ipv6,
                &case.target,
                &case.network.tunnel_gateway,
                "qtest",
                100,
                false,
            ));
            assert_eq!(recorded_undo(&test_owner(), &spec), Some(spec));
        });
    }
}
#[test]
fn tunnel_plan_invalid_prefix_never_reaches_mutation() {
    let mut case = Case::new(Origin::Configured, false, false);
    case.target = "172.22.0.0/99".into();
    case.network.routes[0].cidr = case.target.clone();
    fixture_run(&case, None, Failure::None, |fixture| {
        assert!(case.run().is_err());
        assert!(fixture.mutations().is_empty());
    });
}

#[test]
fn tunnel_plan_valid_origins_install_and_cleanup_with_display_defaults() {
    for case in cases() {
        fixture_run(&case, None, Failure::None, |fixture| {
            case.run().unwrap();
            cleanup_routes(&test_owner()).unwrap();
            let state = fixture.kernel.lock().unwrap();
            assert!(!state.routes.contains_key(&case.target));
            assert!(
                state
                    .routes
                    .contains_key(&candidate(case.ipv6).remote.to_string()),
                "borrowed physical carrier preserved"
            );
        });
    }
}
#[test]
fn tunnel_plan_matching_route_is_borrowed_without_add_or_claim() {
    for ipv6 in [false, true] {
        for tap in [false, true] {
            let case = Case::new(Origin::Configured, ipv6, tap);
            fixture_run(&case, Some(case.row(100)), Failure::None, |fixture| {
                case.run().unwrap();
                assert!(fixture.mutations().is_empty());
                assert!(take_created(&test_owner()).is_empty());
                // This TUN belongs to this owner, independently of individual route claims.
                cleanup_routes(&test_owner()).unwrap();
                assert!(!fixture
                    .kernel
                    .lock()
                    .unwrap()
                    .routes
                    .contains_key(&case.target));
            });
        }
    }
}
#[test]
fn tunnel_plan_lost_tun_add_reconciles_after_owned_interface_flush() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        fixture_run(&case, None, Failure::Lost, |fixture| {
            assert!(case.run().is_err());
            cleanup_routes(&test_owner()).unwrap();
            assert!(!fixture
                .kernel
                .lock()
                .unwrap()
                .routes
                .contains_key(&case.target));
            assert!(!fixture
                .mutations()
                .iter()
                .any(|cmd| cmd.iter().any(|a| a == "del")));
            let other = RouteOwner::test_new("other-tun", 8).unwrap();
            let spec = delete_spec(&tunnel_route_args(
                ipv6,
                &case.target,
                &case.network.tunnel_gateway,
                "other-tun",
                100,
                false,
            ));
            ensure_unclaimed(&other, &spec).unwrap();
        });
    }
}
#[test]
fn tunnel_plan_unknown_foreign_route_survives_interface_flush() {
    for ipv6 in [false, true] {
        let case = Case::new(Origin::Configured, ipv6, false);
        fixture_run(&case, None, Failure::Foreign, |fixture| {
            assert!(case.run().is_err());
            assert!(cleanup_routes(&test_owner()).is_err());
            let state = fixture.kernel.lock().unwrap();
            assert!(state.routes[&case.target].iter().any(|s| s == "operator0"));
            assert!(!state.calls.iter().any(|cmd| cmd.iter().any(|s| s == "del")));
        });
    }
}
#[test]
fn tunnel_plan_default_route_snapshot_is_supported_for_both_families() {
    for ipv6 in [false, true] {
        let mut case = Case::new(Origin::Configured, ipv6, false);
        case.target = if ipv6 { "::/0" } else { "0.0.0.0/0" }.into();
        case.network.routes[0].cidr = case.target.clone();
        fixture_run(&case, None, Failure::None, |_| {
            case.run().unwrap();
            cleanup_routes(&test_owner()).unwrap();
        });
    }
}
#[test]
fn tunnel_plan_metric_zero_uses_kernel_effective_identity() {
    for ipv6 in [false, true] {
        let mut case = Case::new(Origin::Configured, ipv6, false);
        case.network.routes[0].metric = 0;
        fixture_run(&case, None, Failure::None, |fixture| {
            case.run().unwrap();
            let routes = take_created(&test_owner());
            assert_eq!(routes.len(), 1);
            assert!(routes[0]
                .windows(2)
                .any(|p| p == ["metric", if ipv6 { "1024" } else { "0" }]));
            note_created_owned(&test_owner(), routes[0].clone()).unwrap();
            cleanup_routes(&test_owner()).unwrap();
            assert!(!fixture
                .kernel
                .lock()
                .unwrap()
                .routes
                .contains_key(&case.target));
        });
    }
}
#[test]
fn tunnel_plan_does_not_mutate_another_live_owners_route() {
    let case = Case::new(Origin::Configured, false, false);
    fixture_run(&case, Some(case.row(100)), Failure::None, |fixture| {
        let other = RouteOwner::test_new("other-tun", 8).unwrap();
        note_created_owned(
            &other,
            delete_spec(&tunnel_route_args(
                false,
                &case.target,
                &case.network.tunnel_gateway,
                "qtest",
                100,
                false,
            )),
        )
        .unwrap();
        assert!(case.run().is_err());
        assert!(fixture.mutations().is_empty());
    });
}
#[test]
fn tunnel_plan_partial_failure_retains_earlier_verified_routes_for_cleanup() {
    let mut case = Case::new(Origin::Configured, false, false);
    let first = "172.21.0.0/16";
    case.network.routes.insert(
        0,
        NetworkRoute {
            cidr: first.into(),
            gateway: "10.20.0.1".into(),
            metric: 100,
        },
    );
    fixture_run(&case, None, Failure::Lie, |fixture| {
        assert!(case.run().is_err());
        assert!(fixture.kernel.lock().unwrap().routes.contains_key(first));
        cleanup_routes(&test_owner()).unwrap();
        assert!(!fixture.kernel.lock().unwrap().routes.contains_key(first));
    });
}
#[test]
fn tunnel_plan_pushed_routes_use_shared_policy_before_installation() {
    let mut case = Case::new(Origin::Configured, false, false);
    case.network.routes = crate::transport_core::network::planned_pushed_routes(
        r#"[{"cidr":"172.22.0.0/16","metric":7},{"cidr":"0.0.0.0/1"},{"cidr":"bad"}]"#,
        "10.20.0.1",
    )
    .unwrap();
    assert_eq!(case.network.routes.len(), 1);
    fixture_run(&case, None, Failure::None, |fixture| {
        case.run().unwrap();
        let state = fixture.kernel.lock().unwrap();
        assert!(state.routes[&case.target]
            .windows(2)
            .any(|p| p == ["metric", "7"]));
        assert!(!state.routes.contains_key("0.0.0.0/1"));
    });
}
#[test]
fn tunnel_plan_gateway_and_noncanonical_prefix_validation_prevent_writes() {
    for (cidr, gateway) in [("172.22.0.0/16", "fd20::1"), ("172.22.1.9/16", "10.20.0.1")] {
        let mut case = Case::new(Origin::Configured, false, false);
        case.network.routes[0].cidr = cidr.into();
        case.network.routes[0].gateway = gateway.into();
        fixture_run(&case, None, Failure::None, |fixture| {
            assert!(case.run().is_err());
            assert!(fixture.mutations().is_empty());
        });
    }
}
#[test]
fn tunnel_plan_invalid_inventory_rejects_malformed_rows_before_mutation() {
    for bytes in [
        &b"garbage\n"[..],
        &b"0: eth0 inet 10.88.0.3/24 scope global\n"[..],
        &b"2: eth0 inet 10.88.0.3/99 scope global\n"[..],
        &b"2: eth0 inet6 fd20::2/64 scope global\n"[..],
        &b"2: eth0 inet 10.88.0.3/24 scope global\ntruncated\n"[..],
    ] {
        let case = Case::new(Origin::Local, false, false);
        fixture_run(&case, None, Failure::Inventory(bytes), |fixture| {
            assert!(case.run().is_err(), "malformed address inventory accepted");
            assert!(fixture.mutations().is_empty());
        });
    }
}
#[test]
fn tunnel_plan_invalid_inventory_rejects_non_utf8_before_mutation() {
    let case = Case::new(Origin::Local, false, false);
    fixture_run(
        &case,
        None,
        Failure::Inventory(b"2: eth0 inet 10.88.0.3/24 scope global \xff"),
        |fixture| {
            assert!(case.run().is_err(), "lossy address inventory accepted");
            assert!(fixture.mutations().is_empty());
        },
    );
}

#[test]
fn tunnel_plan_inventory_accepts_multiple_addresses_and_ignores_owned_tun() {
    let case = Case::new(Origin::Local, false, false);
    let inventory=b"\n2: eth0@if3 inet 10.88.0.3/24 brd 10.88.0.255 scope global eth0\\ valid_lft forever preferred_lft forever\n2: eth0@if3 inet 10.88.0.4/24 scope global secondary eth0\n3: qtest inet 10.99.0.2/24 scope global qtest\n4: eth1 inet 192.0.2.4/24 scope global eth1\n";
    fixture_run(&case, None, Failure::Inventory(inventory), |fixture| {
        case.run().unwrap();
        let state = fixture.kernel.lock().unwrap();
        assert!(state.routes.contains_key("10.88.0.0/25"));
        assert!(state.routes.contains_key("10.88.0.128/25"));
        assert!(!state.routes.contains_key("10.99.0.0/25"));
        assert!(!state.routes.contains_key("192.0.2.0/25"));
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|raw| raw.iter().any(|s| s == "add"))
                .count(),
            2
        );
    });
}
#[test]
fn tunnel_plan_empty_inventory_needs_no_local_overrides() {
    let case = Case::new(Origin::Local, false, false);
    fixture_run(&case, None, Failure::Inventory(b""), |fixture| {
        case.run().unwrap();
        assert!(fixture.mutations().is_empty());
    });
}

#[test]
fn tunnel_plan_metric_omission_does_not_accept_a_truncated_metric_or_wrong_destination() {
    for ipv6 in [false, true] {
        let cidr = if ipv6 { "fd22::/64" } else { "172.22.0.0/16" };
        let spec = delete_spec(&tunnel_route_args(ipv6, cidr, "unused", "qtest", 0, false));
        for (suffix, expected) in [
            ("", !ipv6),
            (" metric", false),
            (" metric 77", false),
            (" metric 0", !ipv6),
            (" metric 1024", ipv6),
        ] {
            let row = format!("{cidr} dev qtest{suffix}")
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            assert_eq!(route_matches_spec(&spec, &row), expected);
        }
        let row = "default dev qtest metric 1024"
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(!route_matches_spec(&spec, &row));
    }
}
