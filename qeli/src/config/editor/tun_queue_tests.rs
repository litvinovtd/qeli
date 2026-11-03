use super::*;

const BASE: &str = "[qeli]\nserver = h:443\nuser = u\npass = p\nbind_static = false\n";

#[test]
fn tun_queue_editor_round_trip_stays_in_qeli_section() {
    for value in [
        500,
        1000,
        2000,
        super::super::client::CLIENT_TUN_TX_QUEUE_LEN_MAX,
    ] {
        let source = format!("{BASE}tun.tx_queue_len = {value}\n");
        let document = parse(&source).unwrap();
        validate(&document).unwrap();
        assert_eq!(document.values["tun.tx_queue_len"], json!(value));
        let serialized = materialize(&document).unwrap().to_string();
        assert!(serialized.contains(&format!("tun.tx_queue_len = {value}")));
        assert!(!serialized.contains("[tun]"));
        let config = parse_runtime(&serialized).unwrap();
        assert_eq!(config.tun.tx_queue_len, Some(value));
    }
    let omitted = parse_runtime(BASE).unwrap();
    assert_eq!(omitted.tun.tx_queue_len, None);
    assert_eq!(omitted.tun.owned_linux_tx_queue_len(), Some(1000));
}

#[test]
fn tun_queue_editor_patch_uses_literal_key_and_rejects_invalid_values() {
    let mut document = parse(BASE).unwrap();
    set(&mut document.doc, "tun.tx_queue_len", &json!(500)).unwrap();
    let document = inspect(document.doc.clone()).unwrap();
    validate(&document).unwrap();
    assert_eq!(document.values["tun.tx_queue_len"], json!(500));
    for value in ["0", "32768", "65535", "65536", "-1", "1.5", "auto", ""] {
        let source = format!("{BASE}tun.tx_queue_len = {value}\n");
        assert!(parse_runtime(&source).is_err(), "invalid value {value}");
    }
    assert!(parse_runtime(&format!("{BASE}[tun]\ntx_queue_len = 500\n")).is_err());
    assert!(parse_runtime(&format!("{BASE}logging.level = info\n")).is_err());
}
