//! Current all-key coverage fixture; generated data is outside production src/.
use qeli_core::config::parse_server_config_reporting;

#[test]
fn generated_server_fixture_round_trips_every_field() {
    let input = include_str!("../../test/fixtures/roundtrip_fixture_server.ini");
    let (original, findings) = parse_server_config_reporting(input).unwrap();
    assert!(
        findings.is_empty(),
        "unexpected input findings: {findings:?}"
    );
    let serialized = original.to_ini_string();
    let (restored, findings) = parse_server_config_reporting(&serialized).unwrap();
    assert!(
        findings.is_empty(),
        "unexpected output findings: {findings:?}"
    );
    assert_eq!(
        serde_json::to_value(&original).unwrap(),
        serde_json::to_value(&restored).unwrap(),
        "server INI round-trip dropped or altered a field"
    );
    for profile in &restored.profiles {
        assert_eq!(profile.routing.ipv6.ndp_proxy_source, "fe80::1234");
        assert!(profile.routing.ipv6.ndp_proxy_router);
        assert!(profile.routing.ipv6.ndp_proxy_override);
        assert_eq!(profile.routing.ipv6.ndp_proxy_announce_interval_secs, 45);
        assert_eq!(
            profile.obfuscation.ws_host.as_deref(),
            Some("front.example")
        );
    }
    assert_eq!(restored.profiles.len(), 2);
}
