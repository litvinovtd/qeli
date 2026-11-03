#![no_main]
//! Exercise the shared runtime parser, document-service envelope and qeli:// decoder.
//! Imported profiles eventually reach these boundaries; malformed input must return
//! an error, never panic or loop.
use libfuzzer_sys::fuzz_target;
use qeli_core::config::{parse_client_config, parse_client_config_strict, share::ClientLink};

const MAX_STRUCTURED_INPUT: usize = 8 * 1024;

fn check_ini_round_trip(source: &str) {
    if let Ok(parsed) = parse_client_config(source) {
        let canonical = parsed.to_ini_string();
        let reparsed = parse_client_config_strict(&canonical)
            .expect("serialized valid client config must pass strict parsing");
        assert_eq!(reparsed.to_ini_string(), canonical);
    }
}

fn check_link_round_trip(uri: &str) {
    if let Ok(parsed) = ClientLink::from_uri(uri) {
        let canonical = parsed.to_uri();
        let reparsed =
            ClientLink::from_uri(&canonical).expect("serialized valid share link must parse");
        assert_eq!(reparsed.to_uri(), canonical);
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = qeli_core::config::editor::request(data);
    if data.len() <= MAX_STRUCTURED_INPUT {
        check_ini_round_trip(&text);
        check_link_round_trip(&text);

        // Reach successful branches on every run, even with an initially empty corpus.
        let byte = |index| data.get(index).copied().unwrap_or_default();
        let host = if byte(0) & 1 == 0 {
            "vpn.example.com"
        } else {
            "[2001:db8::1]"
        };
        let port = 1024 + u16::from(byte(1));
        let proto = if byte(2) & 1 == 0 { "tcp" } else { "udp" };
        let roaming = ["off", "auto", "required"][usize::from(byte(3) % 3)];
        let ini = format!(
            "[qeli]\nserver = {host}:{port}\nproto = {proto}\nuser = u{}\npass = p{}\nroaming = {roaming}\nbind_static = false\n",
            byte(4), byte(5)
        );
        check_ini_round_trip(&ini);

        let uri = format!(
            "qeli://u{}:p%25%3A{}@{host}:{port}?proto={proto}&mode=fake-tls&roaming={roaming}#label%20{}",
            byte(4), byte(5), byte(6)
        );
        let parsed = ClientLink::from_uri(&uri).expect("structured share link must parse");
        assert_eq!(parsed.user, format!("u{}", byte(4)));
        assert_eq!(parsed.pass, format!("p%:{}", byte(5)));
        assert_eq!(parsed.port, port);
        assert_eq!(parsed.roaming, roaming);
        check_link_round_trip(&uri);
    } else {
        let _ = parse_client_config(&text);
        let _ = ClientLink::from_uri(&text);
    }
});
