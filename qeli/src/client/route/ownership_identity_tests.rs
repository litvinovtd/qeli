use super::*;

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_string).collect()
}
fn spec(ipv6: bool) -> Vec<String> {
    words(if ipv6 {
        "-6 route del 2001:db8:2::8 via 2001:db8:1::1 dev wan0"
    } else {
        "route del 198.51.100.8 via 192.0.2.1 dev wan0"
    })
}
fn current(ipv6: bool, extra: &str) -> Vec<String> {
    let mut result = spec(ipv6)[if ipv6 { 3 } else { 2 }..].to_vec();
    result.extend(words(extra));
    result
}

#[test]
fn defaults_match_real_kernel_snapshots() {
    for ipv6 in [false, true] {
        let extra = if ipv6 { "metric 1024 pref medium" } else { "" };
        assert!(route_matches_spec(&spec(ipv6), &current(ipv6, extra)));
        assert!(route_matches_spec(
            &spec(ipv6),
            &current(ipv6, "proto boot linkdown")
        ));
        assert!(route_matches_spec(&spec(ipv6), &current(ipv6, "proto 3")));
    }
    assert!(route_matches_spec(
        &words("route del 198.51.100.0/24 dev wan0"),
        &words("198.51.100.0/24 dev wan0 scope link")
    ));
    assert!(route_matches_spec(
        &words("-6 route del 2001:db8::/64 dev wan0 scope link"),
        &words("2001:db8::/64 dev wan0 metric 1024 pref medium")
    ));
    assert!(route_matches_spec(
        &words("route del blackhole 0.0.0.0/1"),
        &words("blackhole 0.0.0.0/1")
    ));
    assert!(route_matches_spec(
        &words("-6 route del blackhole 8000::/1"),
        &words("blackhole 8000::/1 dev lo metric 1024 pref medium")
    ));
}

#[test]
fn ownership_rejects_changed_implicit_protocol() {
    for ipv6 in [false, true] {
        for protocol in ["static", "kernel", "dhcp", "42"] {
            assert!(!route_matches_spec(
                &spec(ipv6),
                &current(ipv6, &format!("proto {protocol}"))
            ));
        }
    }
}
#[test]
fn ownership_rejects_changed_implicit_priority() {
    for ipv6 in [false, true] {
        assert!(!route_matches_spec(
            &spec(ipv6),
            &current(ipv6, "metric 71")
        ));
    }
}
#[test]
fn ownership_rejects_added_preferred_source() {
    for ipv6 in [false, true] {
        let source = if ipv6 { "2001:db8:1::2" } else { "192.0.2.2" };
        assert!(!route_matches_spec(
            &spec(ipv6),
            &current(ipv6, &format!("src {source}"))
        ));
    }
}
#[test]
fn ownership_rejects_changed_scope_and_preference() {
    assert!(!route_matches_spec(
        &spec(false),
        &current(false, "scope link")
    ));
    assert!(!route_matches_spec(
        &spec(true),
        &current(true, "pref high")
    ));
}
#[test]
fn ownership_rejects_extra_or_ambiguous_route_attributes() {
    for ipv6 in [false, true] {
        for extra in [
            "mtu 1300",
            "advmss 1200",
            "onlink",
            "nhid 7",
            "nexthop dev wan0 weight 1 nexthop dev wan1 weight 1",
            "dev wan1",
            "metric",
            "proto boot proto static",
        ] {
            assert!(
                !route_matches_spec(&spec(ipv6), &current(ipv6, extra)),
                "{ipv6}: {extra}"
            );
        }
    }
}
#[test]
fn changed_blackholes_are_not_owned() {
    for (record, snapshot) in [
        (
            "route del blackhole 0.0.0.0/1",
            "blackhole 0.0.0.0/1 proto static",
        ),
        (
            "-6 route del blackhole 8000::/1",
            "blackhole 8000::/1 dev lo metric 99 pref medium",
        ),
    ] {
        assert!(!route_matches_spec(&words(record), &words(snapshot)));
    }
}
#[test]
fn operator_route_can_be_usable_without_delete_authority() {
    for ipv6 in [false, true] {
        let route = current(ipv6, "proto static metric 71");
        assert!(route_satisfies_spec(&spec(ipv6), &route));
        assert!(!route_matches_spec(&spec(ipv6), &route));
    }
}
