use super::*;
fn spec() -> Vec<String> {
    "route del 198.51.100.8 via 192.0.2.1 dev wan0"
        .split_whitespace()
        .map(str::to_string)
        .collect()
}
#[test]
fn route_intent_does_not_grant_delete_authority() {
    let mut s = Store::new("boot");
    let r = spec();
    s.change(7, "vpn0", &r, Change::Intent).unwrap();
    let s = Store::decode(&s.encode().unwrap(), "boot").unwrap();
    assert!(s.records(7, "vpn0", false).is_empty());
    assert_eq!(s.records(7, "vpn0", true), [r]);
}
#[test]
fn route_confirmation_replaces_pending_and_survives_roundtrip() {
    let mut s = Store::new("boot");
    let r = spec();
    s.change(7, "vpn0", &r, Change::Intent).unwrap();
    s.change(7, "vpn0", &r, Change::Confirm).unwrap();
    let s = Store::decode(&s.encode().unwrap(), "boot").unwrap();
    assert_eq!(s.records(7, "vpn0", false), [r]);
    assert!(s.records(7, "vpn0", true).is_empty());
}
#[test]
fn route_replacement_intent_keeps_previous_known_selector() {
    let mut s = Store::new("boot");
    let r = spec();
    let mut next = r.clone();
    *next.last_mut().unwrap() = "wan1".into();
    s.change(7, "vpn0", &r, Change::Confirm).unwrap();
    s.change(7, "vpn0", &next, Change::Intent).unwrap();
    assert_eq!(s.records(7, "vpn0", false), [r]);
    assert_eq!(s.records(7, "vpn0", true), [next.clone()]);
    s.change(7, "vpn0", &next, Change::Confirm).unwrap();
    assert_eq!(s.records(7, "vpn0", false), [next]);
    assert!(s.records(7, "vpn0", true).is_empty());
}
#[test]
fn route_scope_is_boot_cookie_and_exact_interface() {
    let mut s = Store::new("boot");
    s.change(7, "vpn0", &spec(), Change::Confirm).unwrap();
    assert!(s.records(8, "vpn0", false).is_empty());
    assert!(s.records(7, "vpn1", false).is_empty());
    assert!(Store::decode(&s.encode().unwrap(), "next-boot")
        .unwrap()
        .groups
        .is_empty());
}
#[test]
fn foreign_route_claims_block_borrowing_including_unknown_intents() {
    for change in [Change::Intent, Change::Confirm] {
        let mut s = Store::new("boot");
        let r = spec();
        s.change(7, "vpn0", &r, change).unwrap();
        assert!(s.check_unclaimed(7, "vpn1", &r).is_err());
        assert!(s.check_unclaimed(8, "vpn1", &r).is_ok());
        let mut host = r.clone();
        host[2] += "/32";
        assert!(s.check_unclaimed(7, "vpn1", &host).is_err());
    }
}
#[test]
fn journal_forgetting_owned_never_promotes_or_forgets_unknown_intent() {
    let mut s = Store::new("boot");
    let r = spec();
    s.change(7, "vpn0", &r, Change::Confirm).unwrap();
    s.change(7, "vpn0", &r, Change::Intent).unwrap();
    s.change(7, "vpn0", &r, Change::ForgetOwned).unwrap();
    assert_eq!(s.records(7, "vpn0", true), std::slice::from_ref(&r));
    s.change(7, "vpn0", &r[..3], Change::ForgetPending).unwrap();
    assert!(s.groups.is_empty());
}
#[test]
fn recovery_grammar_refuses_arbitrary_commands_and_wrong_families() {
    for row in [
        "route flush table main",
        "route del default dev wan0",
        "route del 198.51.100.8 table local dev wan0",
        "route del 198.51.100.8 dev wan0 proto static",
        "-6 route del 198.51.100.8 dev wan0",
        "route del 198.51.100.8 via ::1 dev wan0",
        "route del 198.51.100.8 dev wan0 dev wan1",
        "route del 198.51.100.8",
        "route del blackhole",
        "route del 198.51.100.8 dev wan0 metric",
        "route del 198.51.100.8 nexthop dev wan0",
    ] {
        assert!(
            validate_spec(
                &row.split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            )
            .is_err(),
            "{row}"
        );
    }
}
#[test]
fn supported_physical_specifications_roundtrip() {
    for row in [
        "route del 198.51.100.8 dev wan0 scope link",
        "-6 route del 2001:db8::1 via 2001:db8::2 dev wan0 src 2001:db8::3 metric 1024 pref medium",
        "route del blackhole 0.0.0.0/1",
        "-6 route del blackhole 8000::/1",
    ] {
        let mut s = Store::new("boot");
        let r = row
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        s.change(7, "vpn0", &r, Change::Intent).unwrap();
        Store::decode(&s.encode().unwrap(), "boot").unwrap();
    }
}
#[test]
fn malformed_or_old_version_journal_is_not_reset_even_after_reboot() {
    for bytes in [
        br#"{"version":2,"boot":"old","groups":[]}"#.as_slice(),
        b"{",
        br#"{"version":1,"boot":"old","groups":[],"extra":true}"#,
    ] {
        assert!(Store::decode(bytes, "new").is_err());
    }
}
#[test]
fn journal_rejects_tun_entries_duplicate_owner_and_zero_cookie() {
    let mut s = Store::new("boot");
    s.change(7, "vpn0", &spec(), Change::Confirm).unwrap();
    s.groups.push(s.groups[0].clone());
    assert!(s.encode().is_err());
    s.groups.pop();
    s.groups[0].cookie = 0;
    assert!(s.encode().is_err());
    s.groups[0].cookie = 7;
    *s.groups[0].owned[0].last_mut().unwrap() = "vpn0".into();
    assert!(s.encode().is_err());
}
#[test]
fn journal_bounds_bytes_groups_and_records() {
    assert!(Store::decode(&vec![b' '; LIMIT as usize + 1], "boot").is_err());
    let mut s = Store::new("boot");
    s.change(7, "vpn0", &spec(), Change::Confirm).unwrap();
    s.groups[0].pending = vec![spec(); MAX_RECORDS];
    assert!(s.encode().is_err());
    s.groups[0].pending.clear();
    s.groups = vec![s.groups[0].clone(); MAX_GROUPS + 1];
    assert!(s.encode().is_err());
}
