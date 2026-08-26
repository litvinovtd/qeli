//! Guard for `qeli check-config`: every key present in a shipped example config
//! must be READ by `from_ini`. An unread key is exactly what check-config reports
//! as "a key that nothing reads — check the spelling", and what a web-panel save
//! silently drops on round-trip. A shipped example must therefore never contain
//! one. This exercises the REAL files the `.deb` installs (not a hand-kept fixture
//! that can drift from them) — the scenario an operator actually runs check-config
//! against — so a newly added config parameter that the parser forgets to read
//! (like the historical `update_check` regression) fails CI here.

use qeli::config::client::ClientConfig;
use qeli::config::format::IniDoc;
#[cfg(target_os = "linux")]
use qeli::config::server::ServerConfig;
use qeli::config::users::UsersDb;

const VALID_TEST_PIN: &str = "0900000000000000000000000000000000000000000000000000000000000000";

fn materialize_client_template(text: &str) -> String {
    text.lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("key = ") {
                format!("key = {VALID_TEST_PIN}")
            } else if trimmed == "# reality_sid = <hex>" {
                "reality_sid = 0123456789abcdef".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(target_os = "linux")]
#[test]
fn shipped_server_examples_have_no_unread_keys() {
    // The server examples the .deb installs. `server.conf` is the exhaustive
    // single-profile reference (every server key); the multiprofile one exercises
    // repeated [profile:*] sections and the IPv6 example is the runnable dual-stack
    // deployment template. None carries GUI-only or retired keys, so the unread set
    // must be exactly empty.
    for (name, text) in [
        ("server.conf", include_str!("../config/server.conf")),
        (
            "server-multiprofile.conf",
            include_str!("../config/server-multiprofile.conf"),
        ),
        (
            "server-ipv6.conf",
            include_str!("../config/server-ipv6.conf"),
        ),
        // The maximum-obfuscation reference was shipped and never tested. It is the one an
        // operator on a hostile network copies, and it exercises the REALITY combination
        // (fake-tls + reality_proxy + real_tls) that none of the others do.
        // (Audit 2026-08-03, P2.)
        (
            "server-maxobf.conf",
            include_str!("../config/server-maxobf.conf"),
        ),
    ] {
        let doc = IniDoc::parse(text).unwrap_or_else(|e| panic!("{name}: parse error: {e}"));
        let cfg = ServerConfig::from_ini(&doc).unwrap_or_else(|e| panic!("{name}: from_ini: {e}"));
        // Parsing is not starting. `from_ini` only says the file is well-formed; every rule
        // about whether a profile can actually RUN — reality_proxy without short_ids, plain or
        // reality-tls on UDP, a zero max_clients, a too-long tun name — lives in
        // `validate_profiles`, and the test never called it. A shipped example that parses and
        // then refuses to boot is the worst kind of green CI, because the example is exactly
        // what an operator copies. (Audit 2026-08-03, P3.)
        qeli::server::validate_profiles(&cfg)
            .unwrap_or_else(|e| panic!("{name}: would refuse to start: {e}"));
        // Also consume any inline [user:*] / [group:*] the example might carry, so
        // their keys are not counted as unread.
        let _ = UsersDb::from_ini(&doc);
        let unread = doc.unread_keys();
        assert!(
            unread.is_empty(),
            "{name}: {} key(s) check-config would flag as typos (from_ini never reads them): {:?}",
            unread.len(),
            unread
        );
    }
}

#[test]
fn every_shipped_server_profile_spells_out_the_balanced_recordizer_block() {
    const KEYS: &[&str] = &[
        "obf.recordizer.policy",
        "obf.recordizer.batch.delay_min_ms",
        "obf.recordizer.batch.delay_max_ms",
        "obf.recordizer.batch.max_packets",
        "obf.recordizer.batch.max_queue_bytes",
        "obf.recordizer.record.max_payload_bytes",
        "obf.recordizer.record.small_min_ratio",
        "obf.recordizer.record.small_max_ratio",
        "obf.recordizer.record.full_probability",
        "obf.recordizer.fragment.enabled",
        "obf.recordizer.fragment.reassembly_timeout_ms",
        "obf.recordizer.fragment.max_inflight_packets",
        "obf.recordizer.fragment.max_reassembly_bytes",
        "obf.recordizer.fragment.max_fragments_per_packet",
    ];

    for (name, text) in [
        ("server.conf", include_str!("../config/server.conf")),
        (
            "server-multiprofile.conf",
            include_str!("../config/server-multiprofile.conf"),
        ),
        (
            "server-ipv6.conf",
            include_str!("../config/server-ipv6.conf"),
        ),
        (
            "server-maxobf.conf",
            include_str!("../config/server-maxobf.conf"),
        ),
        (
            "release/reality-tls/server-reality.conf",
            include_str!("../../release/reality-tls/server-reality.conf"),
        ),
    ] {
        let doc = IniDoc::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        let mut count = 0usize;
        for profile in doc.sections_of("profile") {
            count += 1;
            for key in KEYS {
                assert!(
                    profile.entries.iter().any(|(present, _)| present == key),
                    "{name} {} is missing explicit {key}",
                    profile.header()
                );
            }
            let policy = profile
                .entries
                .iter()
                .find(|(key, _)| key == "obf.recordizer.policy")
                .map(|(_, value)| value.as_str());
            assert_eq!(policy, Some("prefer"), "{name} {}", profile.header());
        }
        assert!(count > 0, "{name} contains no server profile");
    }
}

#[test]
fn every_shipped_server_profile_is_explicit_dual_stack_with_a_unique_ula() {
    let mut all_prefixes = std::collections::HashSet::new();

    for (name, text) in [
        ("server.conf", include_str!("../config/server.conf")),
        (
            "server-multiprofile.conf",
            include_str!("../config/server-multiprofile.conf"),
        ),
        (
            "server-ipv6.conf",
            include_str!("../config/server-ipv6.conf"),
        ),
        (
            "server-maxobf.conf",
            include_str!("../config/server-maxobf.conf"),
        ),
        (
            "release/reality-tls/server-reality.conf",
            include_str!("../../release/reality-tls/server-reality.conf"),
        ),
    ] {
        let doc = IniDoc::parse(text).unwrap_or_else(|error| panic!("{name}: {error}"));
        let mut count = 0usize;
        for profile in doc.sections_of("profile") {
            count += 1;
            let entries: std::collections::HashMap<&str, &str> = profile
                .entries
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let header = profile.header();
            assert_eq!(entries.get("tun.ip_mode").copied(), Some("dual"), "{name} {header}");
            assert_eq!(
                entries.get("routing.nat.enabled").copied(),
                Some("true"),
                "{name} {header}"
            );
            assert_eq!(
                entries.get("routing.ipv6.mode").copied(),
                Some("nat66"),
                "{name} {header}"
            );
            for key in ["tun.ipv6_address", "pool.ipv6.cidr", "dns.listen_ipv6"] {
                assert!(entries.contains_key(key), "{name} {header} is missing {key}");
            }
            let prefix = entries["pool.ipv6.cidr"];
            assert!(
                prefix.starts_with("fd") && prefix.ends_with("/64"),
                "{name} {header} must use an RFC4193 locally assigned /64, got {prefix}"
            );
            assert!(
                all_prefixes.insert(prefix.to_owned()),
                "{name} {header} reuses ULA subnet {prefix}"
            );
        }
        assert!(count > 0, "{name} contains no server profile");
    }
}

/// The REALITY template must keep FAILING until its placeholder is replaced.
///
/// `release/reality-tls/server-reality.conf` ships `REPLACE_WITH_OWN_SHORT_ID` on purpose —
/// a short_id is a per-deployment secret and a shared one is no secret. That makes it the one
/// example that must not validate, and the reason it cannot simply join the loop above. Pinned
/// so the day someone "fixes" the template by filling in a value, this says why not.
/// (Audit 2026-08-03, P2.)
#[cfg(target_os = "linux")]
#[test]
fn the_reality_template_refuses_its_own_placeholder() {
    let text = include_str!("../../release/reality-tls/server-reality.conf");
    let doc = IniDoc::parse(text).expect("reality template parse error");
    let err = ServerConfig::from_ini(&doc)
        .and_then(|cfg| qeli::server::validate_profiles(&cfg))
        .expect_err("the placeholder short_id must not validate");
    let msg = err.to_string();
    assert!(
        msg.contains("short_ids"),
        "the refusal must point at the short_id placeholder, got: {msg}"
    );
}

#[test]
fn shipped_client_examples_have_no_unexpected_unread_keys() {
    // The client example legitimately carries a few keys that only the Windows /
    // macOS GUI clients implement (this Rust client does not read them) —
    // check-config whitelists exactly these, so the test does too. Anything ELSE
    // left unread would be a real check-config false-positive on a shipped file.
    // Taken FROM the real allowlist rather than copied beside it. The copy here had drifted:
    // it still held the original six names while the shipped list had grown to twenty-two, so
    // the test enforced a rule stricter than the tool it is supposed to mirror — and a comment
    // asking a human to keep two lists in sync is what let that happen. (Audit 2026-08-03, P3.)
    for (name, text) in [
        ("client.conf", include_str!("../config/client.conf")),
        (
            "client-reality.conf",
            include_str!("../config/client-reality.conf"),
        ),
        (
            "client-maxobf.conf",
            include_str!("../config/client-maxobf.conf"),
        ),
    ] {
        let doc = IniDoc::parse(text).unwrap_or_else(|e| panic!("{name}: parse error: {e}"));
        let cfg =
            ClientConfig::from_ini(&doc).unwrap_or_else(|e| panic!("{name}: from_ini failed: {e}"));
        // The ordinary example must be runnable as-is. REALITY examples deliberately cannot
        // be: a repository-wide server key would defeat pinning, so both carry a deployment
        // placeholder. Assert that the refusal is specifically the missing/placeholder pin;
        // this still exercises all other pair/range rules without blessing a fake shared key.
        if name == "client.conf" {
            cfg.validate()
                .unwrap_or_else(|e| panic!("{name}: would refuse to start: {e}"));
        } else {
            let error = cfg
                .validate()
                .expect_err("a shipped REALITY template must require its deployment key")
                .to_string();
            assert!(
                error.contains("key"),
                "{name}: placeholder refusal must point at the pinned key, got: {error}"
            );
        }

        // Placeholder rejection alone is not proof that the rest of a REALITY template
        // works. Substitute a valid public pin and run the complete pair/range validator.
        let materialized = materialize_client_template(text);
        let materialized_doc = IniDoc::parse(&materialized)
            .unwrap_or_else(|e| panic!("{name}: materialized parse error: {e}"));
        let materialized_cfg = ClientConfig::from_ini(&materialized_doc)
            .unwrap_or_else(|e| panic!("{name}: materialized from_ini failed: {e}"));
        materialized_cfg
            .validate()
            .unwrap_or_else(|e| panic!("{name}: materialized template would refuse to start: {e}"));

        let unexpected: Vec<_> = doc
            .unread_keys()
            .into_iter()
            .filter(|(_, key)| !qeli::config::GUI_ONLY_CLIENT_KEYS.contains(key))
            .collect();
        assert!(
            unexpected.is_empty(),
            "{name}: {} key(s) check-config would flag as typos: {:?}",
            unexpected.len(),
            unexpected
        );
    }
}

#[test]
fn release_client_templates_validate_after_documented_materialization() {
    for (name, text) in [
        (
            "release/reality-tls/client-reality.conf",
            include_str!("../../release/reality-tls/client-reality.conf"),
        ),
        (
            "release/keenetic/client.conf.example",
            include_str!("../../release/keenetic/client.conf.example"),
        ),
        (
            "release/keenetic/opkgtun/client.conf.example",
            include_str!("../../release/keenetic/opkgtun/client.conf.example"),
        ),
    ] {
        let materialized = materialize_client_template(text)
            .replace("YOUR_SERVER_HOST", "vpn.example.com")
            .replace("YOUR_USERNAME", "client1")
            .replace("YOUR_PASSWORD", "changeme")
            .replace("YOUR_SERVER_PUBKEY_HEX", VALID_TEST_PIN)
            .replace("YOUR_SHORT_ID_HEX", "0123456789abcdef");
        let doc = IniDoc::parse(&materialized)
            .unwrap_or_else(|e| panic!("{name}: materialized parse error: {e}"));
        let cfg = ClientConfig::from_ini(&doc)
            .unwrap_or_else(|e| panic!("{name}: materialized from_ini failed: {e}"));
        cfg.validate()
            .unwrap_or_else(|e| panic!("{name}: materialized template would refuse to start: {e}"));
        let unexpected: Vec<_> = doc
            .unread_keys()
            .into_iter()
            .filter(|(_, key)| !qeli::config::GUI_ONLY_CLIENT_KEYS.contains(key))
            .collect();
        assert!(
            unexpected.is_empty(),
            "{name}: materialized template has unread keys: {unexpected:?}"
        );
    }
}

#[test]
fn shipped_users_example_has_no_unread_keys() {
    let text = include_str!("../config/users.conf");
    let doc = IniDoc::parse(text).expect("users.conf parse error");
    let _ = UsersDb::from_ini(&doc);
    let unread = doc.unread_keys();
    assert!(unread.is_empty(), "users.conf has unread keys: {unread:?}");
}
