use super::*;

pub(super) fn rule(ipv6: bool) -> Rule {
    Rule {
        ipv6,
        table: "filter".into(),
        chain: "INPUT".into(),
        args: [
            "-i",
            "qeli0",
            "-m",
            "comment",
            "--comment",
            "qeli-nat:edge",
            "-j",
            "ACCEPT",
        ]
        .map(str::to_owned)
        .to_vec(),
    }
}
#[test]
fn namespaces_and_families_keep_independent_exact_specs() {
    let mut s = Store::new("boot");
    s.retain(11, rule(false), Backend::Nft).unwrap();
    s.retain(11, rule(true), Backend::Nft).unwrap();
    s.retain(22, rule(false), Backend::Nft).unwrap();
    let mut s = Store::decode(&s.encode().unwrap(), "boot").unwrap();
    s.forget(11, &rule(false));
    assert_eq!(s.rules(11), vec![rule(true)]);
    assert_eq!(s.rules(22), vec![rule(false)]);
}
#[test]
fn previous_boot_cannot_supply_recovery_commands() {
    let mut s = Store::new("boot");
    s.retain(11, rule(false), Backend::Nft).unwrap();
    assert!(Store::decode(&s.encode().unwrap(), "new boot")
        .unwrap()
        .rules(11)
        .is_empty());
}
#[test]
fn unknown_versions_and_corrupt_state_are_retained_as_errors() {
    for input in [
        br#"{"version":2,"boot":"boot","namespaces":{}}"#.as_slice(),
        b"{}",
        b"partial",
    ] {
        assert!(Store::decode(input, "boot").is_err());
    }
}
#[test]
fn kernel_generation_is_mandatory_and_not_an_inode_alias() {
    let mut s = Store::new("boot");
    assert!(s.retain(0, rule(false), Backend::Nft).is_err());
    let mut s = Store::new("boot");
    s.retain(11, rule(false), Backend::Nft).unwrap();
    assert!(s.rules(12).is_empty());
}
#[test]
fn foreign_comments_and_command_switches_are_never_replayed() {
    let r = rule(false);
    for addition in [
        vec!["-F"],
        vec!["--table", "raw"],
        vec!["--modprobe", "/bad"],
        vec!["-j", "OTHER"],
        vec!["--comment", "qeli-nat:other"],
    ] {
        let mut bad = r.clone();
        bad.args.extend(addition.into_iter().map(str::to_owned));
        assert!(validate_rule(&bad).is_err());
    }
    let mut bad = r;
    bad.args[5] = "operator".into();
    assert!(validate_rule(&bad).is_err());
}
#[test]
fn nat44_guard_journal_accepts_only_generated_iprange_form() {
    let mut owned = Rule {
        ipv6: false,
        table: "filter".into(),
        chain: "FORWARD".into(),
        args: [
            "-i",
            "qeli0",
            "!",
            "-o",
            "wan0",
            "-m",
            "iprange",
            "!",
            "--dst-range",
            "10.0.0.0-10.255.255.255",
            "-m",
            "iprange",
            "!",
            "--dst-range",
            "172.16.0.0-172.31.255.255",
            "-m",
            "iprange",
            "!",
            "--dst-range",
            "192.168.0.0-192.168.255.255",
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            "qeli-nat:edge",
        ]
        .map(str::to_owned)
        .to_vec(),
    };
    let mut interface_named_iprange = rule(false);
    interface_named_iprange.args[1] = "iprange".into();
    validate_rule(&interface_named_iprange).unwrap();
    validate_rule(&owned).unwrap();
    let mut store = Store::new("boot");
    store.retain(11, owned.clone(), Backend::Nft).unwrap();
    assert_eq!(
        Store::decode(&store.encode().unwrap(), "boot")
            .unwrap()
            .rules(11),
        vec![owned.clone()]
    );
    owned.args[9] = "0.0.0.0-255.255.255.255".into();
    assert!(validate_rule(&owned).is_err());
    owned.args[9] = "10.0.0.0-10.255.255.255".into();
    owned.args[7] = "-d".into();
    assert!(validate_rule(&owned).is_err());
    owned.args[7] = "!".into();
    owned.ipv6 = true;
    assert!(validate_rule(&owned).is_err());
}

#[test]
fn configured_profile_names_are_preserved_verbatim() {
    for name in [
        "edge.eu",
        "日本語",
        "client@example.com",
        "edge home",
        "--odd",
    ] {
        let mut r = rule(false);
        r.args[5] = format!("qeli-nat:{name}");
        validate_rule(&r).unwrap();
    }
}
#[test]
fn capacity_cannot_be_evaded_by_another_namespace() {
    let mut s = Store::new("boot");
    for cookie in 1..=MAX_NAMESPACES as u64 {
        s.retain(cookie, rule(false), Backend::Nft).unwrap();
    }
    assert!(s.retain(99, rule(false), Backend::Nft).is_err());
}
#[test]
fn persisted_rules_are_deduplicated_and_input_size_is_bounded() {
    let mut s = Store::new("boot");
    for _ in 0..3 {
        s.retain(11, rule(false), Backend::Nft).unwrap();
    }
    assert_eq!(s.rules(11).len(), 1);
    assert!(Store::decode(&vec![b' '; LIMIT as usize + 1], "boot").is_err());
}

#[test]
fn backend_identity_distinguishes_nft_legacy_and_unknown_tools() {
    for text in [
        "iptables v1.8.11 (nf_tables)\n",
        "ip6tables v1.8.11 (nf_tables)",
    ] {
        assert_eq!(Backend::parse(text.as_bytes()).unwrap(), Backend::Nft);
    }
    for text in ["iptables v1.8.11 (legacy)", "iptables v1.6.2"] {
        assert_eq!(Backend::parse(text.as_bytes()).unwrap(), Backend::Legacy);
    }
    for text in ["nftables v1.8.11", "iptables v1.8.11 (future)", "unknown"] {
        assert!(Backend::parse(text.as_bytes()).is_err());
    }
}
#[test]
fn an_existing_family_cannot_silently_change_backend() {
    let mut s = Store::new("boot");
    s.retain(1, rule(false), Backend::Nft).unwrap();
    assert!(s.retain(1, rule(false), Backend::Legacy).is_err());
    s.retain(1, rule(true), Backend::Legacy).unwrap();
    assert_eq!(s.backend(1, false), Some(Backend::Nft));
}
