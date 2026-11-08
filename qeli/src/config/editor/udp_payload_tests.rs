use super::*;
const BASE: &str = "[qeli]\nserver=h:443\nuser=u\npass=p\nbind_static=false\n";

#[test]
fn manual_udp_payload_defaults_and_round_trips_on_every_transport() {
    let automatic = parse_runtime(BASE).unwrap();
    assert_eq!(automatic.tun.udp_payload_size, 0);
    assert!(automatic.tun.udp_probing_enabled());
    assert_eq!(automatic.tun.manual_udp_payload_size(), None);
    for proto in ["udp", "tcp"] {
        for size in [0, 548, 1232, 1472, 8972, 65507] {
            for probing in [true, false] {
                let source = format!(
                    "{BASE}proto={proto}\nudp_payload_size={size}\nmtu_probe={probing}\nmtu=1400\n"
                );
                let doc = parse(&source).unwrap();
                validate(&doc).unwrap();
                assert_eq!(doc.values["udp_payload_size"], json!(size));
                let serialized = materialize(&doc).unwrap().to_string();
                let cfg = parse_runtime(&serialized).unwrap();
                assert_eq!(cfg.tun.udp_payload_size, size);
                assert_eq!(cfg.tun.mtu, 1400);
                assert_eq!(cfg.tun.udp_probing_enabled(), probing && size == 0);
                assert_eq!(
                    cfg.tun.manual_udp_payload_size(),
                    (size != 0).then_some(size as usize)
                );
                let canonical = cfg.to_ini_string();
                assert_eq!(
                    parse_runtime(&canonical).unwrap().tun.udp_payload_size,
                    size
                );
            }
        }
    }
}

#[test]
fn manual_udp_payload_rejects_invalid_input_without_turning_it_into_auto() {
    for raw in [
        "-1",
        "1",
        "547",
        "65508",
        "65535",
        "4294967296",
        "1.5",
        "auto",
        "",
        "oops",
    ] {
        assert!(
            parse_runtime(&format!("{BASE}udp_payload_size={raw}\n")).is_err(),
            "accepted {raw:?}"
        );
    }
    let mut doc = parse(BASE).unwrap();
    set(&mut doc.doc, "udp_payload_size", &json!(1472)).unwrap();
    let doc = inspect(doc.doc.clone()).unwrap();
    validate(&doc).unwrap();
    assert_eq!(
        parse_runtime(&materialize(&doc).unwrap().to_string())
            .unwrap()
            .tun
            .udp_payload_size,
        1472
    );
}
