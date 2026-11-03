use qeli_core::config::editor;
use serde_json::{json, Value};
fn call(mut request: Value) -> Value {
    request["version"] = json!(1);
    serde_json::from_slice(&editor::request(&serde_json::to_vec(&request).unwrap())).unwrap()
}
fn ok(request: Value) -> Value {
    let r = call(request);
    assert_eq!(r["ok"], true, "{r}");
    r["result"].clone()
}
const BASE: &str = "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = secret\n";
#[test]
fn native_schema_has_all_84_profile_fields() {
    let r = ok(json!({"op":"schema"}));
    assert_eq!(
        r["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| !v["key"].as_str().unwrap().starts_with("logging."))
            .count(),
        84
    );
}
#[test]
fn draft_roundtrip_preserves_absence_and_explicit_empty() {
    let source = format!("{BASE}dns_servers =\nrecv_buffer_size = 0\npost_up =\n");
    let r = ok(json!({"op":"import","source":source}));
    let text = ok(json!({"op":"export","source":r["source"],"values":r["values"]}))["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("dns_servers ="));
    assert!(text.contains("recv_buffer_size = 0"));
    assert!(!text.contains("padding ="));
    assert!(text.contains("post_up ="));
}
#[test]
fn unknown_fields_and_invalid_scalars_survive_edit() {
    let source = format!("{BASE}future_field = keep\nmtu = broken\n");
    let r = ok(json!({"op":"import","source":source}));
    assert_eq!(r["diagnostics"].as_array().unwrap().len(), 2);
    let export = ok(json!({"op":"export","source":r["source"],"values":{"user":"bob"}}));
    let text = export["text"].as_str().unwrap();
    assert!(text.contains("future_field = keep"));
    assert!(text.contains("mtu = broken"));
    assert_eq!(call(json!({"op":"validate","source":text}))["ok"], false);
}
#[test]
fn duplicate_endpoint_remains_a_refusal_after_projection() {
    let r = ok(json!({"op":"import","source":format!("{BASE}server = other.example.com:8443\n")}));
    assert_eq!(
        call(json!({"op":"validate","source":r["source"],"values":r["values"]}))["ok"],
        false
    );
}
#[test]
fn patch_can_repair_an_invalid_value_to_its_displayed_default() {
    let r = ok(json!({"op":"import","source":format!("{BASE}mtu = broken\n")}));
    assert_eq!(
        call(json!({"op":"validate","source":r["source"],"values":r["values"],"patch":{"mtu":0}}))
            ["ok"],
        true
    );
}
#[test]
fn repeated_lists_remain_ordered() {
    let s=format!("{BASE}route_file = first\nroute_file = second\ninclude = 10.0.0.0/8\ninclude = 192.0.2.0/24\n");
    let r = ok(json!({"op":"import","source":s}));
    assert_eq!(r["values"]["route_file"], json!(["first", "second"]));
    assert_eq!(
        r["values"]["include"],
        json!(["10.0.0.0/8", "192.0.2.0/24"])
    );
    ok(json!({"op":"validate","source":r["source"]}));
}
#[test]
fn invalid_list_members_are_not_silently_dropped() {
    for tail in [
        "include = 10.0.0.0/8,,192.0.2.0/24",
        "exclude = 10.0.0.1/8",
        "dns_servers = 1.1.1.1,,",
    ] {
        assert_eq!(
            call(json!({"op":"validate","source":format!("{BASE}{tail}\n")}))["ok"],
            false,
            "{tail}"
        );
    }
}
#[test]
fn runtime_defaults_are_explicit_and_equal_to_document_values() {
    let r = ok(json!({"op":"runtime","source":BASE}));
    let cfg = qeli_core::config::client::ClientConfig::from_ini(
        &qeli_core::config::format::IniDoc::parse(r["text"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(cfg.routing.add_default_gateway);
    assert_eq!(cfg.obfuscation.padding.min_bytes, 0);
    assert_eq!(cfg.obfuscation.padding.max_bytes, 255);
    assert_eq!(cfg.obfuscation.heartbeat.jitter_ms, 2000);
}
#[test]
fn legacy_dns_is_migrated_without_replacing_explicit_empty_servers() {
    let r = ok(json!({"op":"import","source":format!("{BASE}dns = 1.1.1.1\ndns_servers =\n")}));
    assert_eq!(r["values"]["dns"], "tunnel");
    assert_eq!(r["values"]["dns_servers"], json!([]));
}
#[test]
fn malformed_pin_never_becomes_tofu() {
    assert_eq!(
        call(json!({"op":"validate","source":format!("{BASE}key = {}z\n","a".repeat(64))}))["ok"],
        false
    );
}
#[test]
fn request_and_source_limits_are_enforced() {
    assert_eq!(
        call(json!({"op":"import","source":"x".repeat(256*1024+1)}))["ok"],
        false
    );
    let r: Value =
        serde_json::from_slice(&editor::request(&vec![b' '; editor::MAX_REQUEST + 1])).unwrap();
    assert_eq!(r["ok"], false);
}
#[test]
fn service_version_is_required() {
    let r: Value = serde_json::from_slice(&editor::request(br#"{"op":"schema"}"#)).unwrap();
    assert_eq!(r["ok"], false);
}
#[test]
fn numeric_and_boolean_typos_are_still_visible_after_export() {
    for field in ["mtu = typo", "reconnect = typo", "jc = -0"] {
        let r = ok(json!({"op":"import","source":format!("{BASE}{field}\n")}));
        let e = ok(json!({"op":"export","source":r["source"],"values":r["values"]}));
        assert!(e["text"].as_str().unwrap().contains(field));
        assert_eq!(
            call(json!({"op":"runtime","source":e["text"]}))["ok"],
            false
        );
    }
}
#[test]
fn policy_uses_bounded_native_cidr_subtraction() {
    let r = ok(
        json!({"op":"policy","operation":"subtract","data":{"cidr":"10.0.0.0/8","excludes":["10.0.0.0/9"]}}),
    );
    assert_eq!(r["value"], json!(["10.128.0.0/9"]));
}
#[test]
fn reconnect_arithmetic_saturates_and_never_exceeds_cap() {
    let r = ok(
        json!({"op":"policy","operation":"backoff","data":{"attempt":i64::MAX,"base":i64::MAX,"cap":60000}}),
    );
    assert_eq!(r["value"], 60000);
}
#[test]
fn parse_and_export_do_not_run_password_commands() {
    let s = format!("{BASE}password_command = DO_NOT_EXECUTE\n");
    let r = ok(json!({"op":"runtime","source":s}));
    assert!(r["text"].as_str().unwrap().contains("DO_NOT_EXECUTE"));
}
#[cfg(feature = "transport-core-ffi")]
#[test]
fn ffi_sizes_and_caller_buffers_are_checked() {
    use qeli_core::transport_core::ffi::qeli_config_request;
    let input = br#"{"version":1,"op":"schema"}"#;
    let mut size = 0;
    unsafe {
        assert_eq!(
            qeli_config_request(
                input.as_ptr(),
                input.len(),
                std::ptr::null_mut(),
                0,
                &mut size
            ),
            -6
        );
        assert!(size > 0);
        let mut out = vec![0; size];
        assert_eq!(
            qeli_config_request(
                input.as_ptr(),
                input.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut size
            ),
            0
        );
        assert_eq!(serde_json::from_slice::<Value>(&out).unwrap()["ok"], true);
        assert_eq!(
            qeli_config_request(std::ptr::null(), 0, out.as_mut_ptr(), out.len(), &mut size),
            -1
        );
    }
}

#[test]
fn encoded_credentials_cannot_inject_ini_lines() {
    for uri in [
        "qeli://u:p%0Aevil@vpn.example:443",
        "qeli://u:p@vpn.example:443#label%0Aevil",
        "qeli://u:p@vpn.example:443?sni=host%0Dfake",
    ] {
        assert_eq!(call(json!({"op":"import","source":uri}))["ok"], false);
    }
}

#[test]
fn form_can_explicitly_repair_a_bad_port_and_a_defaulted_scalar() {
    let d = ok(json!({"op":"import","source":"[qeli]\nserver = vpn.example:bad\nmtu = broken\n"}));
    ok(json!({"op":"validate","source":d["source"],"values":d["values"],"unresolved":[]}));
}
#[test]
fn negative_model_port_never_silently_falls_back() {
    assert_eq!(
        call(json!({"op":"validate","values":{"$host":"vpn.example","$port":-1}}))["ok"],
        false
    );
}

#[test]
fn explicit_patch_does_not_require_a_model_overlay() {
    let r = ok(json!({"op":"export","source":BASE,"patch":{"mtu":1280}}));
    assert!(r["text"].as_str().unwrap().contains("mtu = 1280"));
}
#[test]
fn routing_controls_have_one_effective_gateway() {
    for mode in ["full-tunnel", "all", "FULL-TUNNEL"] {
        let r = ok(
            json!({"op":"runtime","source":BASE,"values":{"gateway":false,"$routing_mode":mode}}),
        );
        assert!(r["text"].as_str().unwrap().contains("gateway = true"));
    }
    let r = ok(
        json!({"op":"runtime","source":BASE,"values":{"gateway":false,"$routing_mode":"split-tunnel"}}),
    );
    assert!(r["text"].as_str().unwrap().contains("gateway = false"));
}
#[test]
fn schema_defaults_are_valid_in_a_new_form() {
    let r = ok(json!({"op":"import","source":BASE}));
    // All default scalars include metric=0 (OS default); carried hooks/paths stay absent.
    let mut values = r["values"].clone();
    for key in [
        "server",
        "dev",
        "device_type",
        "password_file",
        "password_command",
        "post_up",
        "post_down",
        "lan_subnet",
        "lan_subnet_ipv6",
    ] {
        values.as_object_mut().unwrap().remove(key);
    }
    ok(json!({"op":"validate","values":values}));
}

#[test]
fn ios_projection_preserves_the_document_and_excludes_unsupported_firewall_requirement() {
    let source = format!("{BASE}kill_switch = true\n");
    let saved = ok(json!({"op":"export","platform":"ios","source":source}));
    assert!(saved["text"]
        .as_str()
        .unwrap()
        .contains("kill_switch = true"));
    let runtime = ok(json!({"op":"runtime","platform":"ios","source":source}));
    assert!(!runtime["text"].as_str().unwrap().contains("kill_switch ="));
}
#[test]
fn policy_route_files_normalize_and_report_exact_line() {
    let result = ok(
        json!({"op":"policy","operation":"route_file","data":{"lines":["# comment","route 10.4.9.7 255.255.0.0","10.4.0.0/16","route-ipv6 2001:db8::8/64"],"offset":512,"source":"routes.txt"}}),
    );
    assert_eq!(result["value"], json!(["10.4.0.0/16", "2001:db8::/64"]));
    let bad = call(
        json!({"op":"policy","operation":"route_file","data":{"lines":["# comment","route 10.0.0.0 255.0.255.0"],"offset":512,"source":"routes.txt"}}),
    );
    assert_eq!(bad["ok"], false);
    assert!(bad["error"].as_str().unwrap().contains("routes.txt:514"));
}
#[test]
fn an_exclusion_away_from_the_gateway_does_not_override_its_route() {
    assert_eq!(
        ok(
            json!({"op":"policy","operation":"on_link","data":{"cidr":"192.168.1.0/25","gateway":"192.168.1.254","prefix":24}})
        )["value"],
        false
    );
}
#[test]
fn attempt_counter_can_exhaust_the_largest_configured_retry_budget() {
    assert_eq!(
        ok(json!({"op":"policy","operation":"next_attempt","data":{"attempt":i32::MAX}}))["value"],
        i64::from(i32::MAX) + 1
    );
}

#[test]
fn empty_per_app_selection_cannot_become_an_unrestricted_tunnel() {
    for mode in ["include", "exclude"] {
        assert_eq!(
            call(json!({"op":"validate","source":format!("{BASE}apps_mode = {mode}\n")}))["ok"],
            false
        );
    }
}

#[test]
fn edits_cannot_create_a_document_that_import_would_refuse_by_size() {
    assert_eq!(
        call(json!({"op":"export","source":BASE,"patch":{"name":"x".repeat(256*1024)}}))["ok"],
        false
    );
}

#[test]
fn reconnect_does_not_reward_short_or_never_established_sessions() {
    for (established, forced, elapsed, expected) in [
        (true, false, 500, 4),
        (true, false, 30000, 0),
        (false, false, 30000, 4),
        (true, true, 500, 0),
        (false, true, 500, 3),
    ] {
        assert_eq!(
            ok(
                json!({"op":"policy","operation":"next_attempt","data":{"attempt":3,"established":established,"forced":forced,"connected_ms":elapsed}})
            )["value"],
            expected
        );
    }
}

#[test]
fn malformed_overlay_envelopes_are_not_ignored() {
    for (key, value) in [
        ("source", json!(42)),
        ("values", json!([])),
        ("patch", json!(true)),
        ("unresolved", json!([123])),
    ] {
        let mut request = json!({"op":"export","source":BASE});
        request[key] = value;
        assert_eq!(call(request)["ok"], false, "{key}");
    }
}

#[test]
fn unmodeled_defaults_match_runtime_without_materializing_automatic_overrides() {
    let imported = ok(json!({"op":"import","source":BASE}));
    let config = editor::parse_runtime(BASE).unwrap();
    assert_eq!(
        imported["values"]["recv_buffer_size"],
        config.performance.recv_buffer_size
    );
    assert_eq!(
        imported["values"]["reality_split_delay"],
        config.obfuscation.reality_split_delay_ms
    );
    assert_eq!(imported["values"]["lan_subnet"], config.routing.lan_subnet);
    let runtime = ok(json!({"op":"runtime","source":BASE}));
    let text = runtime["text"].as_str().unwrap();
    assert!(!text.contains("recv_buffer_size ="));
    assert!(
        editor::parse_runtime(text)
            .unwrap()
            .performance
            .recv_buffer_auto
    );
    assert!(
        !editor::parse_runtime(&format!("{BASE}recv_buffer_size = 0\n"))
            .unwrap()
            .performance
            .recv_buffer_auto
    );
}

#[test]
fn raw_carried_scalars_cannot_launder_duplicate_keys() {
    for (key, first, second) in [
        ("autostart", "true", "false"),
        ("recv_buffer_size", "4194304", "0"),
        ("reality_split_delay", "broken", "100"),
    ] {
        let source = format!("{BASE}{key} = {first}\n{key} = {second}\n");
        let values = json!({key:first, "user":"edited"});
        let exported = ok(json!({"op":"export","source":source,"values":values}));
        let saved = ok(json!({"op":"import","source":exported["text"]}));
        assert_eq!(saved["raw"][key].as_array().unwrap().len(), 2, "{key}");
        assert_eq!(
            call(json!({"op":"validate","source":source,"values":values}))["ok"],
            false,
            "{key}"
        );
    }
}
#[test]
fn reconnect_ini_values_reach_the_headless_runtime_and_survive_serialization() {
    let source=format!("{BASE}reconnect = false\nreconnect_retries = 7\nreconnect_base_delay = 3\nreconnect_max_delay = 25\n");
    let cfg = editor::parse_runtime(&source).unwrap();
    for c in [&cfg, &editor::parse_runtime(&cfg.to_ini_string()).unwrap()] {
        assert!(!c.server.reconnect.enabled);
        assert_eq!(c.server.reconnect.max_retries, 7);
        assert_eq!(c.server.reconnect.base_delay_secs, 3);
        assert_eq!(c.server.reconnect.max_delay_secs, 25);
    }
}

#[test]
fn reconnect_budget_and_delay_have_independent_bounds() {
    // Settling caps only the delay; the fourth failure must still exceed a budget of three.
    let exhausted = ok(json!({"op":"policy","operation":"retry_decision","data":{
        "enabled":true,"max_retries":3,"attempt":4,"settling_cap":3,"elapsed_ms":5000}}));
    assert_eq!(exhausted["value"]["reason"], "retry_limit");
    assert_eq!(exhausted["value"]["delay_ms"], 0);
    let settling = ok(json!({"op":"policy","operation":"retry_decision","data":{
        "attempt":10,"settling_cap":3,"elapsed_ms":5000,"reduction":0}}));
    assert!(settling["value"]["reason"].is_null());
    assert_eq!(settling["value"]["attempt"], 10);
    assert_eq!(settling["value"]["delay_ms"], 4000);
}

#[test]
fn reconnect_budget_scenarios_match_every_client() {
    for limit in [0, 1, 3, i64::from(i32::MAX)] {
        for attempt in [limit, limit + 1] {
            let result = ok(json!({"op":"policy","operation":"retry_decision","data":{
                "max_retries":limit,"attempt":attempt,"elapsed_ms":30000}}));
            assert_eq!(result["value"]["reason"].is_null(), attempt <= limit);
        }
    }
    for attempt in [0, 1, 200] {
        let disabled = ok(json!({"op":"policy","operation":"retry_decision","data":{
            "enabled":false,"attempt":attempt}}));
        assert_eq!(disabled["value"]["reason"], "disabled");
        let unlimited = ok(json!({"op":"policy","operation":"retry_decision","data":{
            "max_retries":-1,"attempt":attempt}}));
        assert!(unlimited["value"]["reason"].is_null());
    }
}

#[test]
fn slow_handshake_cannot_reset_a_short_connected_session() {
    let next = ok(json!({"op":"policy","operation":"next_attempt","data":{
        "attempt":2,"established":true,"connected_ms":200,"elapsed_ms":45000}}));
    assert_eq!(next["value"], 3);
    // A stable session resets on either a clean close or an error; no exit-status input is used.
    let stable = ok(json!({"op":"policy","operation":"next_attempt","data":{
        "attempt":2,"established":true,"connected_ms":30000}}));
    assert_eq!(stable["value"], 0);
}

#[test]
fn reconnect_floor_throttles_short_forced_cycles_without_delaying_stable_sessions() {
    for (attempt, elapsed, reduction, expected) in [
        (0, 200, 0, 1300),
        (1, 100, 200, 1400),
        (0, 30000, 0, 0),
        (2, 30000, 400, 1600),
    ] {
        let result = ok(json!({"op":"policy","operation":"retry_decision","data":{
            "attempt":attempt,"elapsed_ms":elapsed,"reduction":reduction}}));
        assert_eq!(result["value"]["delay_ms"], expected);
    }
}

#[test]
fn carrier_restoration_skips_backoff_but_preserves_budget_and_floor() {
    for (attempt, reason, delay) in [(3, Value::Null, 1300), (4, json!("retry_limit"), 0)] {
        let result = ok(json!({"op":"policy","operation":"retry_decision","data":{
            "attempt":attempt,"max_retries":3,"elapsed_ms":200,"carrier_restored":true}}));
        assert_eq!(result["value"]["attempt"], attempt);
        assert_eq!(result["value"]["reason"], reason);
        assert_eq!(result["value"]["delay_ms"], delay);
    }
}

#[test]
fn audit_boundary_control_characters_are_never_silently_removed() {
    for tail in [
        "pass = sec\u{7}ret",
        "gatewa\u{7}y = false",
        "[log\u{7}ging]\nlevel = debug",
        "pass = secret\u{85}",
        "pass = secret\u{b}",
    ] {
        assert_eq!(
            call(json!({"op":"import","source":format!("{BASE}{tail}\n")}))["ok"],
            false,
            "{tail:?}"
        );
    }
    for op in ["export", "validate", "runtime"] {
        for overlay in ["values", "patch"] {
            let mut request = json!({"op":op,"source":BASE});
            request[overlay] = json!({"pass":"sec\u{7}ret"});
            assert_eq!(call(request)["ok"], false, "{op}/{overlay}");
        }
    }
}

#[test]
fn audit_boundary_edit_identifiers_cannot_disappear_or_change_after_save() {
    for key in [
        "#future",
        ";future",
        "gateway ",
        " gateway",
        "gatewa\t y",
        ".name",
        "qeli:other.name",
    ] {
        assert_eq!(
            call(json!({"op":"export","source":BASE,"patch":{key:"false"}}))["ok"],
            false,
            "{key:?}"
        );
    }
}

#[test]
fn audit_boundary_legacy_dns_duplicates_survive_open_save_and_refuse_activation() {
    let imported =
        ok(json!({"op":"import","source":format!("{BASE}dns = 1.1.1.1\ndns = 8.8.8.8\n")}));
    let exported =
        ok(json!({"op":"export","source":imported["source"],"values":imported["values"]}));
    assert_eq!(
        call(json!({"op":"validate","source":exported["text"]}))["ok"],
        false
    );
    let reopened = ok(json!({"op":"import","source":exported["text"]}));
    assert_eq!(reopened["raw"]["dns"], json!(["1.1.1.1", "8.8.8.8"]));
}

#[test]
fn audit_boundary_bom_does_not_bypass_uri_validation() {
    let invalid = "qeli://u:p@vpn.example.com:443?proto=udp&mode=reality-tls";
    for prefix in ["", "\u{feff}", " \t\u{feff}"] {
        assert_eq!(
            call(json!({"op":"import","source":format!("{prefix}{invalid}")}))["ok"],
            false
        );
    }
    let valid = "qeli://u:p@vpn.example.com:443";
    for prefix in ["", "\u{feff}", " \t\u{feff}"] {
        assert_eq!(
            call(json!({"op":"import","source":format!("{prefix}{valid}")}))["ok"],
            true
        );
    }
}

#[test]
fn audit_redaction_covers_patch_uppercase_ini_and_uri_credentials() {
    for secret in ["xy", "fixture-private-secret"] {
        let requests = [
            json!({"op":"validate","source":BASE,"patch":{"pass":secret,"mode":secret}}),
            json!({"op":"validate","source":format!("[qeli]\nserver=host:443\nPASS={secret}\nmode={secret}\n")}),
            json!({"op":"import","source":format!("qeli://u:{secret}@host:443?mode={secret}")}),
        ];
        for request in requests {
            let response = call(request);
            assert_eq!(response["ok"], false);
            let message = response["error"].as_str().unwrap();
            assert!(!message.contains(secret), "credential disclosed: {message}");
            assert!(
                message.contains("[redacted]"),
                "missing redaction: {message}"
            );
        }
    }
}

#[test]
fn audit_dns_migration_preserves_invalid_resolver_lists_and_refreshes_raw() {
    let imported = ok(
        json!({"op":"import","source":format!("{BASE}dns = 1.1.1.1\ndns_servers = 8.8.8.8,,\n")}),
    );
    assert_eq!(
        call(json!({"op":"validate","source":imported["source"]}))["ok"],
        false
    );
    let valid = ok(json!({"op":"import","source":format!("{BASE}dns = 1.1.1.1\n")}));
    let again = ok(json!({"op":"import","source":valid["source"]}));
    assert_eq!(valid["raw"], again["raw"]);
}

#[test]
fn audit_schema_names_cannot_alias_a_different_ini_section() {
    for key in ["logging.level", "logging.file", "logging.time_format"] {
        let source = format!("{BASE}{key} = info\n");
        let draft = ok(json!({"op":"import","source":source}));
        assert_eq!(
            call(json!({"op":"validate","source":draft["source"]}))["ok"],
            false,
            "{key}"
        );
        let exported = ok(json!({"op":"export","source":draft["source"],"values":draft["values"]}));
        assert_eq!(
            call(json!({"op":"validate","source":exported["text"]}))["ok"],
            false,
            "{key} after save"
        );
    }
}

#[test]
fn audit_uri_controls_cannot_change_endpoint_transport_or_pin() {
    let mut accepted = Vec::new();
    for uri in [
        "qeli://u:p@exa\u{7}mple.com:443".to_string(),
        "qeli://u:p@host:443?proto=t%07cp".to_string(),
        "qeli://u:p@host:443?mode=fake-%07tls".to_string(),
        format!("qeli://u:p@host:443?key={}{}", "0".repeat(64), "%07"),
        "qeli://u:p@host:443?rsid=ab%07cd".to_string(),
    ] {
        if call(json!({"op":"import","source":uri}))["ok"] == true {
            accepted.push(uri);
        }
    }
    assert!(
        accepted.is_empty(),
        "silently normalized URIs: {accepted:?}"
    );
}

#[test]
fn runtime_audit_malformed_zero_pins_never_become_tofu() {
    for length in [1, 2, 32, 63, 65, 128] {
        let pin = "0".repeat(length);
        let source = format!("{BASE}key = {pin}\n");
        assert_eq!(
            call(json!({"op":"validate","source":source}))["ok"],
            false,
            "INI {length}"
        );
        assert_eq!(
            call(json!({"op":"import","source":format!("qeli://u:p@host:443?key={pin}")}))["ok"],
            false,
            "URI {length}"
        );
    }
    for pin in [String::new(), "0".repeat(64), "a".repeat(64)] {
        ok(json!({"op":"validate","source":format!("{BASE}key = {pin}\n")}));
        ok(json!({"op":"import","source":format!("qeli://u:p@host:443?key={pin}")}));
    }
}

#[test]
fn runtime_audit_invalid_hosts_cannot_reach_runtime_or_share() {
    for host in [
        "exa mple.com",
        "evil@host",
        "host/path",
        "host?query",
        "host#label",
        "host[",
        "-host",
        "host..example",
    ] {
        let source = format!("[qeli]\nserver = {host}:443\n");
        for op in ["validate", "runtime", "uri"] {
            assert_eq!(
                call(json!({"op":op,"source":source}))["ok"],
                false,
                "{op} {host}"
            );
        }
        let draft = ok(json!({"op":"import","source":source}));
        let saved = ok(json!({"op":"export","source":draft["source"],"values":draft["values"]}));
        assert_eq!(
            call(json!({"op":"validate","source":saved["text"]}))["ok"],
            false,
            "saved {host}"
        );
    }
    for host in [
        "vpn_example",
        "localhost",
        "xn--e1afmkfd.xn--p1ai",
        "vpn.example.",
        "192.0.2.1",
        "[2001:db8::1]",
    ] {
        ok(json!({"op":"validate","source":format!("[qeli]\nserver = {host}:443\n")}));
        ok(json!({"op":"import","source":format!("qeli://u:p@{host}:443")}));
    }
}

#[test]
fn runtime_audit_partial_edits_do_not_repair_an_unsupplied_port() {
    for endpoint in ["host:wrong", "host:0", "host"] {
        let source = format!("[qeli]\nserver = {endpoint}\n");
        let saved =
            ok(json!({"op":"export","source":source,"values":{"user":"bob"},"unresolved":[]}));
        assert_eq!(
            call(json!({"op":"validate","source":saved["text"]}))["ok"],
            false,
            "{endpoint}"
        );
        assert!(saved["text"].as_str().unwrap().contains(endpoint));
        ok(json!({"op":"validate","source":source,"values":{"$port":443},"unresolved":[]}));
    }
}

#[test]
fn runtime_audit_explicit_device_uses_shared_document_rules() {
    for source in [
        "[QELI]\nSERVER=host:443\nDEV=vpn42\n",
        "\u{feff}[qeli]\nserver=host:443\ndev=vpn42\ndns=1.1.1.1\n",
    ] {
        assert_eq!(
            editor::explicit_device(source).unwrap().as_deref(),
            Some("vpn42")
        );
    }
    for tail in ["", "DEV=\n"] {
        assert_eq!(
            editor::explicit_device(&format!("{BASE}{tail}")).unwrap(),
            None
        );
    }
    assert!(editor::explicit_device(&format!("{BASE}dev=vpn1\nDEV=vpn2\n")).is_err());
}

#[test]
fn policy_subtract_counts_final_routes_and_retains_the_real_limit() {
    for (cidr, host_base, host_prefix) in [
        ("198.18.0.0/22", "198.18", 32),
        ("2001:db8::/118", "2001:db8::", 128),
    ] {
        let hosts: Vec<String> = (0..2)
            .flat_map(|parity| (parity..1024).step_by(2))
            .map(|n| {
                if host_prefix == 32 {
                    format!("{host_base}.{}.{}/{host_prefix}", n / 256, n % 256)
                } else {
                    format!("{host_base}{n:x}/{host_prefix}")
                }
            })
            .collect();
        assert_eq!(
            ok(json!({"op":"policy","operation":"subtract","data":{"cidr":cidr,"excludes":hosts}}))
                ["value"],
            json!([])
        );
        assert_eq!(
            call(
                json!({"op":"policy","operation":"subtract","data":{"cidr":cidr,"excludes":&hosts[..512]}})
            )["ok"],
            false
        );
    }
}

#[test]
fn share_requires_a_portable_inline_password() {
    for source in [
        "[qeli]\nserver = vpn.example.com:443\nuser = alice\n",
        "[qeli]\nserver = vpn.example.com:443\nuser = alice\npassword_file = /tmp/qeli-secret\n",
        "[qeli]\nserver = vpn.example.com:443\nuser = alice\npassword_command = secret-tool lookup service qeli\n",
    ] {
        ok(json!({"op":"validate","source":source}));
        let denied = call(json!({"op":"uri","source":source}));
        assert_eq!(denied["ok"], false, "{denied}");
        assert!(denied["error"].as_str().unwrap().contains("inline pass"));
    }
    let source = "[qeli]\nserver = vpn.example.com:443\nuser = alice\npass = secret\npassword_file = /tmp/qeli-secret\n";
    let uri = ok(json!({"op":"uri","source":source}))["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(uri.starts_with("qeli://alice:secret@vpn.example.com:443"));
    ok(json!({"op":"import","source":uri}));
}

#[test]
fn every_schema_field_survives_runtime_projection() {
    let schema = ok(json!({"op":"schema"}));
    let fields = schema["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 87);
    for field in fields {
        let key = field["key"].as_str().unwrap();
        let kind = field["kind"].as_str().unwrap();
        let value = match key {
            "server" => "other.example.com:8443".to_string(),
            "name" => "Example".to_string(),
            "proto" => "udp".to_string(),
            "user" => "bob".to_string(),
            "pass" => "otherpass".to_string(),
            "key" => "ab".repeat(32),
            "mode" => "plain".to_string(),
            "front" => "none".to_string(),
            "sni" => "example.com".to_string(),
            "reality_sid" => "0123456789abcdef".to_string(),
            "mtu" => "1400".to_string(),
            "dns" => "system".to_string(),
            "dns_servers" => "1.1.1.1".to_string(),
            "apps_mode" => "include".to_string(),
            "apps" => "com.example.app".to_string(),
            "route_file" => "rules.txt".to_string(),
            "local" => "192.0.2.3".to_string(),
            "lport" => "12345".to_string(),
            "dev" => "vpn1".to_string(),
            "device_type" => "tun".to_string(),
            "lan_subnet" => "192.168.1.0/24".to_string(),
            "lan_subnet_ipv6" => "2001:db8::/64".to_string(),
            "post_up" | "post_down" | "password_command" => "true".to_string(),
            "password_file" => "/tmp/qeli-pw".to_string(),
            "reality_split" => "1,2".to_string(),
            "ipv6" | "roaming" => "off".to_string(),
            "logging.level" => "debug".to_string(),
            "logging.file" => "/tmp/qeli.log".to_string(),
            "logging.time_format" => "utc".to_string(),
            "include" => "10.0.0.0/8".to_string(),
            "exclude" => "192.0.2.0/24".to_string(),
            _ => match kind {
                "bool" => (field["default"] != "true").to_string(),
                "int" => {
                    (field["default"].as_str().unwrap().parse::<i64>().unwrap() + 1).to_string()
                }
                "list" | "lines" => "10.0.0.0/8".to_string(),
                _ => "sample".to_string(),
            },
        };
        let mut source = String::from("[qeli]\n");
        for (base_key, base_value) in [
            ("server", "vpn.example.com:443"),
            ("user", "alice"),
            ("pass", "secret"),
        ] {
            if key != base_key {
                source.push_str(&format!("{base_key} = {base_value}\n"));
            }
        }
        if key == "exit_node" {
            source.push_str("gateway = false\n");
        }
        if key == "apps_mode" {
            source.push_str("apps = com.example.app\n");
        }
        if let Some(logging_key) = key.strip_prefix("logging.") {
            source.push_str(&format!("[logging]\n{logging_key} = {value}\n"));
        } else {
            source.push_str(&format!("{key} = {value}\n"));
        }
        let imported = ok(json!({"op":"import","source":source}));
        let runtime = ok(json!({"op":"runtime","source":source}));
        let again = ok(json!({"op":"import","source":runtime["text"]}));
        assert_eq!(imported["values"], again["values"], "field {key}");
    }
}

#[test]
fn bounded_ini_mutations_keep_values_and_raw_entries_across_export() {
    let keys = [
        "mode",
        "proto",
        "mtu",
        "dns",
        "dns_servers",
        "include",
        "apps",
        "apps_mode",
        "gateway",
        "allow_ipv4_leak",
        "route_file",
        "logging.level",
        "future_key",
        "pass",
    ];
    let values = [
        "",
        "true",
        "false",
        "0",
        "1",
        "bad",
        "1.1.1.1",
        "a,b",
        " a ",
        "\"a;b\"",
        "a\\\"b",
        "snowman",
        "x\tq",
        "\"quoted\"",
        "10.0.0.0/8",
    ];
    let mut state = 192486_u64;
    let mut pick = |len: usize| {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        ((state >> 32) as usize) % len
    };
    for case in 0..1000 {
        let mut source = String::from(BASE);
        for _ in 0..pick(6) {
            source.push_str(&format!(
                "{} = {}\n",
                keys[pick(keys.len())],
                values[pick(values.len())]
            ));
        }
        if case % 7 == 0 {
            source.push_str(&format!(
                "[logging]\nlevel = {}\n",
                values[pick(values.len())]
            ));
        }
        let first = ok(json!({"op":"import","source":source}));
        let saved = ok(json!({"op":"export","source":first["source"]}));
        let again = ok(json!({"op":"import","source":saved["text"]}));
        assert_eq!(first["values"], again["values"], "case {case}");
        assert_eq!(first["raw"], again["raw"], "case {case}");
    }
}
