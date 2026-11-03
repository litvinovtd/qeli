//! Regression checks through the production INI entry points (audit Q01).
use qeli_core::config::{parse_server_config_reporting, users::UsersDb};

fn accepted(source: &str) -> qeli_core::config::server::ServerConfig {
    let (cfg, findings) = parse_server_config_reporting(source).expect("parse failed");
    assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    cfg
}

fn rejected(source: &str) -> bool {
    match parse_server_config_reporting(source) {
        Err(_) => true,
        Ok((_, findings)) => !findings.is_empty(),
    }
}

fn assert_rejected_cases(cases: &[String]) {
    let accepted: Vec<_> = cases.iter().filter(|source| !rejected(source)).collect();
    assert!(
        accepted.is_empty(),
        "invalid configs accepted without findings: {accepted:#?}"
    );
}

#[test]
fn invalid_profile_routes_produce_findings() {
    assert_rejected_cases(
        &[
            "",
            "nonsense",
            "10.0.0.0/33",
            "gateway=10.0.0.1",
            "10.0.0.0/8 gateway=10.0.0.1/24",
            "10.0.0.0/8 gateway=fd00::1",
        ]
        .map(|route| format!("[profile:test]\nroute = {route}\n")),
    );
}

#[test]
fn route_option_typos_and_duplicates_are_rejected() {
    assert_rejected_cases(
        &[
            "10.0.0.0/8 metric=no",
            "10.0.0.0/8 metric=-1",
            "10.0.0.0/8 metric=4294967296",
            "10.0.0.0/8 metirc=7",
            "10.0.0.0/8 extra",
            "10.0.0.0/8 gateway=10.0.0.1 gateway=10.0.0.2",
            "10.0.0.0/8 metric=1 metric=2",
            "10.0.0.0/8 cidr=192.168.0.0/16",
            "10.0.0.0/8 notdesc=hidden",
            "10.0.0.0/8 gateway=10.0.0.1desc=hidden",
        ]
        .map(|route| format!("[profile:test]\nroute = {route}\n")),
    );
}

#[test]
fn user_routes_share_strict_option_validation() {
    for route in [
        "10.0.0.0/8 metric=no",
        "10.0.0.0/8 metirc=7",
        "10.0.0.0/8 metric=1 metric=2",
        "10.0.0.0/8 desc=unsupported",
        "10.0.0.0/8 desc=",
    ] {
        let user = format!("[user:alice]\nroute = {route}\n");
        assert!(
            rejected(&format!("[profile:test]\n{user}")),
            "inline: {route}"
        );
        assert!(
            UsersDb::parse_strict(&user, "audit-users.conf").is_err(),
            "external: {route}"
        );
    }
}

#[test]
fn route_options_and_profile_descriptions_round_trip() {
    let source = "[profile:test]\nroute = cidr=10.0.0.0/8 gateway=10.0.0.1 metric=0 desc=Office LAN (a=b)\nroute = fd00::/64 gateway=fd00::1 metric=4294967295\n[user:alice]\nroute = 192.168.0.0/16 metric=50\n";
    let first = accepted(source);
    let route = &first.profiles[0].routing.advertised_routes[0];
    assert_eq!(route.description.as_deref(), Some("Office LAN (a=b)"));
    assert_eq!(route.metric, Some(0));
    assert_eq!(first.profiles[0].routing.advertised_routes.len(), 2);
    let second = accepted(&first.to_ini_string());
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(second).unwrap()
    );
}

#[test]
fn malformed_and_duplicate_singleton_sections_are_rejected() {
    assert_rejected_cases(
        &[
            "[auth:main]",
            "[web:main]",
            "[logging:main]",
            "[auth:]",
            "[auth]\n[auth]",
            "[web]\n[web]",
            "[logging]\n[logging]",
            "[unknown]",
            "[profiel:test]",
            "[]",
        ]
        .map(|header| format!("[profile:test]\n{header}\n")),
    );
}

#[test]
fn dynamic_map_keys_must_be_unique_and_nonempty() {
    assert_rejected_cases(&[
        "[profile:test]\npool.reservation.alice=10.9.0.2\npool.reservation.alice=10.9.0.3\n",
        "[profile:test]\npool.ipv6.reservation.alice=fd00::2\npool.ipv6.reservation.alice=fd00::3\n",
        "[profile:test]\npool.reservation.=10.9.0.2\n",
        "[profile:test]\npool.ipv6.reservation.=fd00::2\n",
        "[profile:test]\n[user:alice]\nmetadata.note=one\nmetadata.note=two\n",
        "[profile:test]\n[user:alice]\nmetadata.=no-key\n",
    ].map(str::to_string));
}

#[test]
fn repeated_profile_lists_merge_in_source_order() {
    let cfg = accepted("[profile:test]\npool.exclude=10.9.0.2\npool.exclude=10.9.0.3,10.9.0.4\npool.ipv6.exclude=fd00::2\npool.ipv6.exclude=fd00::3\ndns.upstream=1.1.1.1\ndns.upstream=8.8.8.8\ndns.blocklist=ads.example\ndns.blocklist=other.example\ndns.push_servers=1.1.1.1\ndns.push_servers=8.8.8.8\nobf.tls.reality_proxy.short_ids=0123456789abcdef\nobf.tls.reality_proxy.short_ids=fedcba9876543210\nobf.traffic_normalization.round_sizes=512\nobf.traffic_normalization.round_sizes=1024,1500\n");
    let p = &cfg.profiles[0];
    assert_eq!(p.pool.exclude, ["10.9.0.2", "10.9.0.3", "10.9.0.4"]);
    assert_eq!(p.pool.ipv6.exclude, ["fd00::2", "fd00::3"]);
    assert_eq!(p.dns.upstream, ["1.1.1.1", "8.8.8.8"]);
    assert_eq!(p.dns.blocklist, ["ads.example", "other.example"]);
    assert_eq!(p.dns.push_servers, ["1.1.1.1", "8.8.8.8"]);
    assert_eq!(p.obfuscation.tls.reality_proxy.short_ids.len(), 2);
    assert_eq!(
        p.obfuscation.traffic_normalization.round_sizes,
        [512, 1024, 1500]
    );
}

#[test]
fn repeated_web_and_group_lists_are_accepted() {
    let cfg = accepted("[profile:test]\n[web]\nallowed_ips=127.0.0.1\nallowed_ips=::1\nallowed_origins=https://one.example\nallowed_origins=https://two.example\ntrusted_proxies=127.0.0.1\ntrusted_proxies=::1\n[group:staff]\nallowed_networks=10.0.0.0/8\nallowed_networks=192.168.0.0/16\n");
    assert_eq!(cfg.web.allowed_ips, ["127.0.0.1", "::1"]);
    assert_eq!(cfg.web.allowed_origins.len(), 2);
    assert_eq!(cfg.web.trusted_proxies.len(), 2);
    assert_eq!(
        cfg.auth.groups["staff"]
            .allowed_networks
            .as_ref()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn missing_and_explicit_empty_lists_remain_distinct() {
    let default = accepted("[profile:test]\n[group:staff]\n");
    let clear = accepted("[profile:test]\ndns.upstream=\nobf.traffic_normalization.round_sizes=\n[group:staff]\nallowed_networks=\n");
    assert!(!default.profiles[0].dns.upstream.is_empty());
    assert!(clear.profiles[0].dns.upstream.is_empty());
    assert!(clear.profiles[0]
        .obfuscation
        .traffic_normalization
        .round_sizes
        .is_empty());
    assert_eq!(default.auth.groups["staff"].allowed_networks, None);
    assert_eq!(clear.auth.groups["staff"].allowed_networks, Some(vec![]));
}

#[test]
fn malformed_numeric_list_members_produce_findings() {
    assert_rejected_cases(
        &[
            "512,no,1500",
            "512,-1",
            "512,999999999999999999999999999999",
        ]
        .map(|sizes| format!("[profile:test]\nobf.traffic_normalization.round_sizes={sizes}\n")),
    );
}

#[test]
fn independent_parses_do_not_share_findings() {
    std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..32)
            .map(|i| {
                scope.spawn(move || {
                    let source = if i % 2 == 0 {
                        "[profile:test]\nroute=invalid\n"
                    } else {
                        "[profile:test]\nroute=10.0.0.0/8\n"
                    };
                    assert_eq!(rejected(source), i % 2 == 0);
                })
            })
            .collect();
        for job in jobs {
            job.join().unwrap();
        }
    });
}

#[test]
fn ordinary_server_parser_does_not_discard_findings() {
    // Quick Start and CLI mutations use this entry point before rewriting INI.
    for entry in [
        "route=invalid",
        "route=10.0.0.0/8 metric=no",
        "enabled=maybe",
        "enabled=true\nunknown=1",
        "pool.reservation.=10.9.0.2",
    ] {
        let source = format!("[profile:test]\n{entry}\n");
        assert!(
            qeli_core::config::parse_server_config(&source).is_err(),
            "accepted {entry}"
        );
    }
}
