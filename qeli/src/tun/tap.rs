const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xdd];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];

#[derive(Debug, Clone, Copy)]
pub struct TapGateway {
    pub mac: [u8; 6],
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub ipv6_prefix_len: u8,
}

fn packet_ethertype(packet: &[u8]) -> Option<[u8; 2]> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(ETHERTYPE_IPV4),
        Some(6) if packet.len() >= 40 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

pub fn strip_ethernet_header(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let packet = &frame[ETHERNET_HEADER_LEN..];
    let expected = packet_ethertype(packet)?;
    (frame[12..14] == expected).then_some(packet)
}

pub fn prepend_ethernet_header(
    ip_packet: &[u8],
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
) -> Option<Vec<u8>> {
    let ethertype = packet_ethertype(ip_packet)?;
    let destination = destination_mac_for_ip(ip_packet).unwrap_or(*dst_mac);
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + ip_packet.len());
    frame.extend_from_slice(&destination);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ethertype);
    frame.extend_from_slice(ip_packet);
    Some(frame)
}

pub fn destination_mac_for_ip(packet: &[u8]) -> Option<[u8; 6]> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 && (224..=239).contains(&packet[16]) => {
            Some([0x01, 0x00, 0x5e, packet[17] & 0x7f, packet[18], packet[19]])
        }
        Some(6) if packet.len() >= 40 && packet[24] == 0xff => {
            Some([0x33, 0x33, packet[36], packet[37], packet[38], packet[39]])
        }
        _ => None,
    }
}

/// Answer the neighbour-control frames emitted by a client TAP locally. The assigned
/// addresses and routes are static, but Linux still resolves the L2 gateway and may send
/// Router Solicitation. These frames are link-local control traffic and must not enter the
/// encrypted L3 data plane.
pub fn client_tap_control_reply(frame: &[u8], gateway: TapGateway) -> Option<Vec<u8>> {
    if let Some(target) = arp_request_target(frame) {
        return (Some(target) == gateway.ipv4).then(|| arp_reply(frame, gateway.mac, target));
    }
    if let Some(target) = neighbor_solicitation_target(frame) {
        return (Some(target) == gateway.ipv6)
            .then(|| neighbor_advertisement(frame, gateway.mac, target));
    }
    if is_router_solicitation(frame) {
        return gateway.ipv6.map(|address| {
            router_advertisement(frame, gateway.mac, address, gateway.ipv6_prefix_len)
        });
    }
    None
}

/// Answer a server TAP's attempt to resolve a client address. The session map remains the
/// authority for forwarding: replying only lets the kernel emit the IP packet, and the
/// normal exact-address/iroute lookup still drops traffic for an unassigned target.
pub fn server_tap_control_reply(
    frame: &[u8],
    server_ipv4: Option<std::net::Ipv4Addr>,
    server_ipv6: Option<std::net::Ipv6Addr>,
) -> Option<Vec<u8>> {
    if let Some(target) = arp_request_target(frame) {
        if Some(target) == server_ipv4 {
            return None;
        }
        return Some(arp_reply(
            frame,
            mac_from_ip(std::net::IpAddr::V4(target)),
            target,
        ));
    }
    if let Some(target) = neighbor_solicitation_target(frame) {
        if Some(target) == server_ipv6 {
            return None;
        }
        return Some(neighbor_advertisement(
            frame,
            mac_from_ip(std::net::IpAddr::V6(target)),
            target,
        ));
    }
    None
}

fn arp_request_target(frame: &[u8]) -> Option<std::net::Ipv4Addr> {
    if frame.len() < 42
        || frame[12..14] != ETHERTYPE_ARP
        || frame[14..16] != [0, 1]
        || frame[16..18] != ETHERTYPE_IPV4
        || frame[18] != 6
        || frame[19] != 4
        || frame[20..22] != [0, 1]
    {
        return None;
    }
    Some(std::net::Ipv4Addr::new(
        frame[38], frame[39], frame[40], frame[41],
    ))
}

fn arp_reply(frame: &[u8], responder_mac: [u8; 6], target: std::net::Ipv4Addr) -> Vec<u8> {
    let mut reply = vec![0u8; 42];
    reply[..6].copy_from_slice(&frame[6..12]);
    reply[6..12].copy_from_slice(&responder_mac);
    reply[12..14].copy_from_slice(&ETHERTYPE_ARP);
    reply[14..20].copy_from_slice(&[0, 1, 0x08, 0, 6, 4]);
    reply[20..22].copy_from_slice(&[0, 2]);
    reply[22..28].copy_from_slice(&responder_mac);
    reply[28..32].copy_from_slice(&target.octets());
    reply[32..38].copy_from_slice(&frame[6..12]);
    reply[38..42].copy_from_slice(&frame[28..32]);
    reply
}

fn neighbor_solicitation_target(frame: &[u8]) -> Option<std::net::Ipv6Addr> {
    if frame.len() < 78
        || frame[12..14] != ETHERTYPE_IPV6
        || frame[14] >> 4 != 6
        || frame[20] != 58
        || frame[21] != 255
        || frame[54] != 135
        || frame[55] != 0
    {
        return None;
    }
    let target = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&frame[62..78]).ok()?);
    (!target.is_unspecified() && !target.is_multicast()).then_some(target)
}

fn is_router_solicitation(frame: &[u8]) -> bool {
    frame.len() >= 62
        && frame[12..14] == ETHERTYPE_IPV6
        && frame[14] >> 4 == 6
        && frame[20] == 58
        && frame[21] == 255
        && frame[54] == 133
        && frame[55] == 0
}

fn neighbor_advertisement(
    request: &[u8],
    responder_mac: [u8; 6],
    target: std::net::Ipv6Addr,
) -> Vec<u8> {
    let source = std::net::Ipv6Addr::from(target.octets());
    let requester = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&request[22..38]).unwrap());
    let dad = requester.is_unspecified();
    let destination = if dad {
        "ff02::1".parse::<std::net::Ipv6Addr>().unwrap()
    } else {
        requester
    };
    let destination_mac = if dad {
        [0x33, 0x33, 0, 0, 0, 1]
    } else {
        <[u8; 6]>::try_from(&request[6..12]).unwrap()
    };
    let mut reply = vec![0u8; 14 + 40 + 32];
    reply[..6].copy_from_slice(&destination_mac);
    reply[6..12].copy_from_slice(&responder_mac);
    reply[12..14].copy_from_slice(&ETHERTYPE_IPV6);
    write_ipv6_header(&mut reply[14..54], source, destination, 32);
    reply[54] = 136;
    reply[58..62]
        .copy_from_slice(&(if dad { 0x2000_0000u32 } else { 0x6000_0000u32 }).to_be_bytes());
    reply[62..78].copy_from_slice(&target.octets());
    reply[78] = 2; // Target Link-Layer Address
    reply[79] = 1;
    reply[80..86].copy_from_slice(&responder_mac);
    write_icmpv6_checksum(&mut reply, 14, 54);
    reply
}

fn router_advertisement(
    request: &[u8],
    gateway_mac: [u8; 6],
    gateway_address: std::net::Ipv6Addr,
    prefix_len: u8,
) -> Vec<u8> {
    let requester = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&request[22..38]).unwrap());
    let destination = if requester.is_unspecified() {
        "ff02::1".parse::<std::net::Ipv6Addr>().unwrap()
    } else {
        requester
    };
    let destination_mac = destination_mac_for_ipv6(destination)
        .unwrap_or_else(|| <[u8; 6]>::try_from(&request[6..12]).unwrap());
    let source = link_local_from_mac(gateway_mac);
    let mut reply = vec![0u8; 14 + 40 + 56];
    reply[..6].copy_from_slice(&destination_mac);
    reply[6..12].copy_from_slice(&gateway_mac);
    reply[12..14].copy_from_slice(&ETHERTYPE_IPV6);
    write_ipv6_header(&mut reply[14..54], source, destination, 56);
    reply[54] = 134;
    reply[58] = 64; // Cur Hop Limit
    reply[60..62].copy_from_slice(&1800u16.to_be_bytes());
    reply[70] = 1; // Source Link-Layer Address
    reply[71] = 1;
    reply[72..78].copy_from_slice(&gateway_mac);
    reply[78] = 3; // Prefix Information
    reply[79] = 4;
    reply[80] = prefix_len.min(128);
    reply[81] = 0x80; // L=1, A=0: assigned AuthOK address only, no arbitrary SLAAC
    reply[82..86].copy_from_slice(&3600u32.to_be_bytes());
    reply[86..90].copy_from_slice(&1800u32.to_be_bytes());
    let mut prefix = gateway_address.octets();
    mask_ipv6_prefix(&mut prefix, prefix_len.min(128));
    reply[94..110].copy_from_slice(&prefix);
    write_icmpv6_checksum(&mut reply, 14, 54);
    reply
}

fn write_ipv6_header(
    header: &mut [u8],
    source: std::net::Ipv6Addr,
    destination: std::net::Ipv6Addr,
    payload_len: u16,
) {
    header[0] = 0x60;
    header[4..6].copy_from_slice(&payload_len.to_be_bytes());
    header[6] = 58;
    header[7] = 255;
    header[8..24].copy_from_slice(&source.octets());
    header[24..40].copy_from_slice(&destination.octets());
}

fn destination_mac_for_ipv6(address: std::net::Ipv6Addr) -> Option<[u8; 6]> {
    let bytes = address.octets();
    address
        .is_multicast()
        .then_some([0x33, 0x33, bytes[12], bytes[13], bytes[14], bytes[15]])
}

fn link_local_from_mac(mac: [u8; 6]) -> std::net::Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8] = mac[0] ^ 0x02;
    bytes[9] = mac[1];
    bytes[10] = mac[2];
    bytes[11] = 0xff;
    bytes[12] = 0xfe;
    bytes[13] = mac[3];
    bytes[14] = mac[4];
    bytes[15] = mac[5];
    std::net::Ipv6Addr::from(bytes)
}

fn mask_ipv6_prefix(address: &mut [u8; 16], prefix_len: u8) {
    let full = usize::from(prefix_len / 8);
    let rem = prefix_len % 8;
    if rem != 0 && full < address.len() {
        address[full] &= 0xff << (8 - rem);
    }
    let zero_from = full + usize::from(rem != 0);
    address[zero_from..].fill(0);
}

fn write_icmpv6_checksum(packet: &mut [u8], ipv6_offset: usize, icmp_offset: usize) {
    packet[icmp_offset + 2..icmp_offset + 4].fill(0);
    let payload_len = packet.len() - icmp_offset;
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            sum += if chunk.len() == 2 {
                u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
            } else {
                u32::from(chunk[0]) << 8
            };
        }
    };
    add(&packet[ipv6_offset + 8..ipv6_offset + 40]);
    add(&(payload_len as u32).to_be_bytes());
    add(&[0, 0, 0, 58]);
    add(&packet[icmp_offset..]);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&(!(sum as u16)).to_be_bytes());
}

/// Stable locally-administered TAP address derived from the complete assigned inner
/// address. A 40-bit FNV projection avoids the old IPv4-octet/IPv6-tail alias where
/// unrelated prefixes could receive the same MAC. It is not an identity or secret.
pub fn mac_from_ip(address: std::net::IpAddr) -> [u8; 6] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut add = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    };
    match address {
        std::net::IpAddr::V4(address) => address.octets().into_iter().for_each(&mut add),
        std::net::IpAddr::V6(address) => address.octets().into_iter().for_each(&mut add),
    }
    let encoded = hash.to_be_bytes();
    let mut mac = [
        0x02, encoded[3], encoded[4], encoded[5], encoded[6], encoded[7],
    ];
    if mac == [0x02, 0, 0, 0, 0, 1] {
        mac[5] ^= 0x80;
    }
    mac
}

pub fn is_tap_mode(device_type: &str) -> bool {
    device_type.eq_ignore_ascii_case("tap")
}

pub fn tap_interface_name(config_name: &str, device_type: &str) -> String {
    if is_tap_mode(device_type) && !config_name.starts_with("tap") {
        let suffix = config_name
            .trim_start_matches("tun")
            .trim_start_matches("vpn")
            .trim_start_matches("tap");
        format!("tap{}", suffix)
    } else {
        config_name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_frames_round_trip_with_matching_ethertypes() {
        let v4 = [0x45; 20];
        let v6 = [0x60; 40];
        let dst = [2, 0, 0, 0, 0, 1];
        let src = [2, 0, 0, 0, 0, 2];
        for (packet, ethertype) in [(&v4[..], ETHERTYPE_IPV4), (&v6[..], ETHERTYPE_IPV6)] {
            let frame = prepend_ethernet_header(packet, &dst, &src).unwrap();
            assert_eq!(frame[12..14], ethertype);
            assert_eq!(strip_ethernet_header(&frame), Some(packet));
        }
    }

    #[test]
    fn mismatched_or_non_ip_frames_are_rejected() {
        let mut frame = prepend_ethernet_header(&[0x45; 20], &[0; 6], &[0; 6]).unwrap();
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV6);
        assert!(strip_ethernet_header(&frame).is_none());
        assert!(prepend_ethernet_header(&[0; 40], &[0; 6], &[0; 6]).is_none());
    }

    #[test]
    fn multicast_mac_mapping_and_full_address_mac_are_family_correct() {
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[24..40].copy_from_slice(
            &"ff02::1:ff00:1234"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        assert_eq!(
            destination_mac_for_ip(&v6),
            Some([0x33, 0x33, 0xff, 0x00, 0x12, 0x34])
        );
        assert_ne!(
            mac_from_ip("2001:db8:1::10".parse().unwrap()),
            mac_from_ip("2001:db8:2::10".parse().unwrap())
        );
    }

    #[test]
    fn client_answers_arp_ndp_and_router_solicitation_locally() {
        let client_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let gateway = TapGateway {
            mac: [0x02, 0, 0, 0, 0, 1],
            ipv4: Some("10.9.0.1".parse().unwrap()),
            ipv6: Some("fd71:e1:1234:1::1".parse().unwrap()),
            ipv6_prefix_len: 64,
        };

        let mut arp = vec![0u8; 42];
        arp[..6].fill(0xff);
        arp[6..12].copy_from_slice(&client_mac);
        arp[12..22].copy_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1]);
        arp[22..28].copy_from_slice(&client_mac);
        arp[28..32].copy_from_slice(&[10, 9, 0, 2]);
        arp[38..42].copy_from_slice(&[10, 9, 0, 1]);
        let arp_reply = client_tap_control_reply(&arp, gateway).unwrap();
        assert_eq!(&arp_reply[..6], &client_mac);
        assert_eq!(&arp_reply[6..12], &gateway.mac);
        assert_eq!(&arp_reply[20..22], &[0, 2]);
        assert_eq!(&arp_reply[28..32], &[10, 9, 0, 1]);

        let source: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
        let target = gateway.ipv6.unwrap();
        let mut ns = vec![0u8; 14 + 40 + 32];
        ns[..6].copy_from_slice(&[0x33, 0x33, 0xff, 0, 0, 1]);
        ns[6..12].copy_from_slice(&client_mac);
        ns[12..14].copy_from_slice(&ETHERTYPE_IPV6);
        write_ipv6_header(
            &mut ns[14..54],
            source,
            "ff02::1:ff00:1".parse().unwrap(),
            32,
        );
        ns[54] = 135;
        ns[62..78].copy_from_slice(&target.octets());
        let na = client_tap_control_reply(&ns, gateway).unwrap();
        assert_eq!(na[54], 136);
        assert_eq!(&na[62..78], &target.octets());
        assert_eq!(&na[80..86], &gateway.mac);

        let mut rs = vec![0u8; 14 + 40 + 8];
        rs[..6].copy_from_slice(&[0x33, 0x33, 0, 0, 0, 2]);
        rs[6..12].copy_from_slice(&client_mac);
        rs[12..14].copy_from_slice(&ETHERTYPE_IPV6);
        write_ipv6_header(&mut rs[14..54], source, "ff02::2".parse().unwrap(), 8);
        rs[54] = 133;
        let ra = client_tap_control_reply(&rs, gateway).unwrap();
        assert_eq!(ra[54], 134);
        assert_eq!(ra[80], 64);
        assert_eq!(
            ra[81] & 0x40,
            0,
            "RA must not authorize arbitrary SLAAC addresses"
        );
        assert_eq!(
            &ra[94..110],
            &"fd71:e1:1234:1::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[test]
    fn server_answers_only_client_neighbor_targets() {
        let server = "fd71::1".parse().unwrap();
        let client: std::net::Ipv6Addr = "fd71::50".parse().unwrap();
        let mut ns = vec![0u8; 14 + 40 + 24];
        ns[12..14].copy_from_slice(&ETHERTYPE_IPV6);
        write_ipv6_header(
            &mut ns[14..54],
            server,
            "ff02::1:ff00:50".parse().unwrap(),
            24,
        );
        ns[54] = 135;
        ns[62..78].copy_from_slice(&client.octets());
        assert!(server_tap_control_reply(&ns, None, Some(server)).is_some());
        ns[62..78].copy_from_slice(&server.octets());
        assert!(server_tap_control_reply(&ns, None, Some(server)).is_none());
    }
}
