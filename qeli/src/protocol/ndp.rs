//! Neighbor discovery belongs to the local Wintun link, not the routed VPN.
//! In particular Windows can emit NS with a zero-length link-layer option on
//! its MAC-less adapter. Never serialize those local control frames as user data.

pub(crate) fn is_local_control(packet: &[u8]) -> bool {
    // Ordinary data takes a constant-time fast path; only link-local control
    // candidates need the bounded IPv6 extension-header parser.
    if packet.first().map(|byte| byte >> 4) != Some(6) || packet.get(7) != Some(&255) {
        return false;
    }
    let Ok(meta) = super::ip::parse_ip_packet(packet) else {
        return false;
    };
    if meta.protocol != 58 {
        return false;
    }
    let Some(offset) = meta.l4_offset else {
        return false;
    };
    matches!(packet.get(offset), Some(133..=137)) && packet.get(offset + 1) == Some(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(kind: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 66];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&26u16.to_be_bytes());
        packet[6] = 58;
        packet[7] = 255;
        packet[8..24].copy_from_slice(
            &"2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[24..40].copy_from_slice(
            &"ff02::1:ff00:1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        packet[40] = kind;
        packet[64..].copy_from_slice(&[1, 0]); // issue #69's malformed SLLA option
        packet
    }

    #[test]
    fn windows_zero_length_ns_is_local_but_ip_payload_is_unchanged() {
        let ns = packet(135);
        for kind in 133..=137 {
            assert!(is_local_control(&packet(kind)));
        }
        for kind in [1, 2, 3, 4, 128, 129] {
            assert!(
                !is_local_control(&packet(kind)),
                "ICMPv6 type {kind} must reach the VPN"
            );
        }
        let mut ordinary = ns.clone();
        ordinary[7] = 64;
        assert!(!is_local_control(&ordinary));
        ordinary[6] = 17;
        assert!(!is_local_control(&ordinary));
        assert!(!is_local_control(&ns[..41]));
        let mut bad_code = ns.clone();
        bad_code[41] = 1;
        assert!(!is_local_control(&bad_code));
        let mut extension = ns.clone();
        extension[6] = 0; // hop-by-hop header before ICMPv6
        extension[4..6].copy_from_slice(&34u16.to_be_bytes());
        extension.splice(40..40, [58, 0, 0, 0, 0, 0, 0, 0]);
        assert!(is_local_control(&extension));
    }
}
