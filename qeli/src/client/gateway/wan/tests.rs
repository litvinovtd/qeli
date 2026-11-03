use super::*;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

fn output(success: bool, stdout: &str) -> io::Result<Output> {
    Ok(Output {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    })
}

fn expected_queries(ipv6: bool) -> [&'static [&'static str]; 2] {
    if ipv6 {
        [
            &["-6", "route", "show", "default"],
            &["-6", "route", "get", "2606:4700:4700::1111"],
        ]
    } else {
        [&["route", "show", "default"], &["route", "get", "1.1.1.1"]]
    }
}

#[test]
fn default_route_wins_without_route_get_for_each_family() {
    for ipv6 in [false, true] {
        let mut calls = 0;
        let wan = detect_wan_with(ipv6, |args| {
            calls += 1;
            assert_eq!(args, expected_queries(ipv6)[0]);
            output(
                true,
                "unreachable default\ndefault via 192.0.2.1 dev eth0 metric 100\ndefault dev eth1",
            )
        });
        assert_eq!(wan.as_deref(), Some("eth1"));
        assert_eq!(calls, 1);
    }
}

#[test]
fn failed_default_query_falls_back_for_each_family() {
    for ipv6 in [false, true] {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::InvalidData,
            io::ErrorKind::NotFound,
        ] {
            let mut calls = 0;
            let wan = detect_wan_with(ipv6, |args| {
                assert_eq!(args, expected_queries(ipv6)[calls]);
                calls += 1;
                if calls == 1 {
                    Err(io::Error::from(kind))
                } else {
                    output(true, "1.1.1.1 via 192.0.2.1 dev eth1 src 192.0.2.2")
                }
            });
            assert_eq!(wan.as_deref(), Some("eth1"));
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn unusable_default_output_falls_back_for_each_family() {
    for ipv6 in [false, true] {
        for (success, data) in [
            (false, "default dev rejected0"),
            (true, ""),
            (true, "unreachable default"),
            (true, "default dev"),
        ] {
            let mut calls = 0;
            let wan = detect_wan_with(ipv6, |args| {
                assert_eq!(args, expected_queries(ipv6)[calls]);
                calls += 1;
                if calls == 1 {
                    output(success, data)
                } else {
                    output(true, "destination dev eth1")
                }
            });
            assert_eq!(wan.as_deref(), Some("eth1"));
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn failed_route_get_does_not_invent_a_wan() {
    for ipv6 in [false, true] {
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::InvalidData,
            io::ErrorKind::NotFound,
        ] {
            let mut calls = 0;
            let wan = detect_wan_with(ipv6, |args| {
                assert_eq!(args, expected_queries(ipv6)[calls]);
                calls += 1;
                if calls == 1 {
                    output(true, "")
                } else {
                    Err(io::Error::from(kind))
                }
            });
            assert_eq!(wan, None);
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn unusable_route_get_output_does_not_invent_a_wan() {
    for ipv6 in [false, true] {
        for (success, data) in [
            (false, "destination dev rejected0"),
            (true, ""),
            (true, "unreachable"),
            (true, "destination dev"),
        ] {
            let mut calls = 0;
            let wan = detect_wan_with(ipv6, |args| {
                assert_eq!(args, expected_queries(ipv6)[calls]);
                calls += 1;
                if calls == 1 {
                    output(true, "")
                } else {
                    output(success, data)
                }
            });
            assert_eq!(wan, None);
            assert_eq!(calls, 2);
        }
    }
}

#[test]
fn default_route_uses_lowest_metric_instead_of_output_order() {
    for ipv6 in [false, true] {
        let mut calls = 0;
        let wan = detect_wan_with(ipv6, |args| {
            assert_eq!(args, expected_queries(ipv6)[0]);
            calls += 1;
            output(
                true,
                "default via 192.0.2.1 dev slow metric 600\ndefault via 198.51.100.1 dev fast metric 50",
            )
        });
        assert_eq!(wan.as_deref(), Some("fast"));
        assert_eq!(calls, 1);
    }
}

#[test]
fn malformed_default_metric_cannot_take_priority_over_valid_route() {
    for ipv6 in [false, true] {
        let wan = detect_wan_with(ipv6, |_| {
            output(
                true,
                "default dev invalid metric nonsense\ndefault dev valid metric 10",
            )
        });
        assert_eq!(wan.as_deref(), Some("valid"));
    }
}

#[test]
fn multipath_default_refuses_destination_specific_fallback() {
    for ipv6 in [false, true] {
        let mut calls = 0;
        let wan = detect_wan_with(ipv6, |args| {
            assert_eq!(args, expected_queries(ipv6)[0]);
            calls += 1;
            let routes = if ipv6 {
                "default metric 1024 pref medium\n\tnexthop via 2001:db8:1::1 dev wan0 weight 1\n\tnexthop via 2001:db8:2::1 dev wan1 weight 1"
            } else {
                "default \n\tnexthop via 198.51.100.1 dev wan0 weight 1 \n\tnexthop via 192.0.2.1 dev wan1 weight 1"
            };
            output(true, routes)
        });
        assert_eq!(wan, None);
        assert_eq!(calls, 1, "route-get must not bless one ECMP hash bucket");
    }
}

#[test]
fn equal_best_metrics_across_wans_are_ambiguous() {
    for ipv6 in [false, true] {
        let mut calls = 0;
        let wan = detect_wan_with(ipv6, |args| {
            assert_eq!(args, expected_queries(ipv6)[0]);
            calls += 1;
            output(
                true,
                "default via 198.51.100.1 dev wan0 metric 100\ndefault via 192.0.2.1 dev wan1 metric 100",
            )
        });
        assert_eq!(wan, None);
        assert_eq!(calls, 1);
    }
}

#[test]
fn lower_metric_single_wan_beats_higher_metric_multipath() {
    for ipv6 in [false, true] {
        let mut calls = 0;
        let wan = detect_wan_with(ipv6, |args| {
            assert_eq!(args, expected_queries(ipv6)[0]);
            calls += 1;
            output(
                true,
                "default dev fast metric 50\ndefault metric 600\n\tnexthop via 198.51.100.1 dev slow0 weight 1\n\tnexthop via 192.0.2.1 dev slow1 weight 1",
            )
        });
        assert_eq!(wan.as_deref(), Some("fast"));
        assert_eq!(calls, 1);
    }
}

#[test]
fn equal_best_routes_on_the_same_device_remain_supported() {
    for ipv6 in [false, true] {
        let wan = detect_wan_with(ipv6, |_| {
            output(
                true,
                "default via 198.51.100.1 dev wan0 metric 100\ndefault via 198.51.100.3 dev wan0 metric 100",
            )
        });
        assert_eq!(wan.as_deref(), Some("wan0"));
    }
}
