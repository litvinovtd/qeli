//! Local trust-store names, not wire/session identifiers. TCP and UDP may use
//! the same host and port with different per-profile static identities.

pub(crate) fn endpoint_id(protocol: &str, host: &str, port: u16) -> String {
    format!(
        "{}://{}",
        protocol.to_ascii_lowercase(),
        crate::util::join_host_port(host, port)
    )
}

/// Legacy releases used unbracketed `host:port`, without the carrier protocol.
/// This is only a migration fallback; a qualified pin always takes precedence.
#[cfg(any(test, all(target_os = "linux", feature = "client")))]
pub(crate) fn legacy_id(server_id: &str) -> Option<String> {
    let endpoint = server_id
        .strip_prefix("tcp://")
        .or_else(|| server_id.strip_prefix("udp://"))?;
    if let Some(ipv6) = endpoint.strip_prefix('[') {
        let (host, port) = ipv6.split_once("]:")?;
        Some(format!("{host}:{port}"))
    } else {
        Some(endpoint.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_numeric_port_is_a_different_identity_for_tcp_and_udp() {
        for host in ["vpn.example", "192.0.2.1", "2001:db8::1"] {
            let tcp = endpoint_id("tcp", host, 443);
            let udp = endpoint_id("udp", host, 443);
            assert_ne!(tcp, udp);
            assert_eq!(legacy_id(&tcp), Some(format!("{host}:443")));
            assert_eq!(legacy_id(&udp), legacy_id(&tcp));
        }
        assert_eq!(
            endpoint_id("UDP", "2001:db8::1", 443),
            "udp://[2001:db8::1]:443"
        );
        assert_eq!(endpoint_id("tcp", "[::1]", 8443), "tcp://[::1]:8443");
        assert_eq!(legacy_id("vpn.example:443"), None);
        assert_eq!(legacy_id("https://vpn.example:443"), None);
    }
}
