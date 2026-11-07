use super::*;
#[test]
fn existing_installations_default_to_external_and_accept_old_empty_config() {
    let p: Policy = serde_json::from_str("{}").unwrap();
    p.validate().unwrap();
    assert_eq!(p.components.routing, Owner::External);
    assert_eq!(p.components.firewall, Owner::External);
}
#[test]
fn refuses_unknown_fields_instead_of_ignoring_misspelt_policy() {
    assert!(serde_json::from_str::<Policy>(r#"{"component":{"routing":"client"}}"#).is_err());
    assert!(serde_json::from_str::<Policy>(r#"{"components":{"route":"client"}}"#).is_err());
}
#[test]
fn does_not_enable_half_a_killswitch_or_accept_default_source_prefix() {
    let mut p = Policy::default();
    p.components.firewall = Owner::Client;
    assert!(p.validate().is_err());
    p.components.firewall = Owner::External;
    p.networks.push(Network {
        device: "br-test".into(),
        subnets: vec!["0.0.0.0/0".into()],
        policy: NetworkPolicy::VpnOnly,
    });
    assert!(p.validate().is_err());
}
#[test]
fn rejects_ambiguous_networks_device_injection_and_unsafe_paths() {
    for device in ["lo", "eth0;id", "../eth0", "eth0\n", "abcdefghijklmnop"] {
        assert!(interface(device).is_err());
    }
    let mut p = Policy::default();
    p.networks = vec![
        Network {
            device: "br-a".into(),
            subnets: vec!["192.168.7.0/24".into()],
            policy: NetworkPolicy::Direct,
        },
        Network {
            device: "br-b".into(),
            subnets: vec!["192.168.7.0/25".into()],
            policy: NetworkPolicy::Direct,
        },
    ];
    assert!(p.validate().is_err());
    p.networks.clear();
    p.state_directory = "/tmp/../etc".into();
    assert!(p.validate().is_err());
}
