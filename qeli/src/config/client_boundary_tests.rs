#[test]
fn shared_ip_and_socket_buffer_boundaries() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../conformance/config-boundary.json")).unwrap();
    let defaults =
        crate::config::parse_client_config_strict("[qeli]\nserver=fixture.invalid:443\n").unwrap();
    assert_eq!(defaults.server.protocol, "tcp");
    assert_eq!(defaults.obfuscation.mode, "fake-tls");
    for case in corpus["cases"].as_array().unwrap() {
        let ini = format!(
            "{}{}",
            corpus["base"].as_str().unwrap(),
            case["ini"].as_str().unwrap()
        );
        let result = crate::config::parse_client_config_strict(&ini).and_then(|cfg| cfg.validate());
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {result:?}",
            case["name"]
        );
    }
}
