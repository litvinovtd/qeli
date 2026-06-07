const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

pub fn strip_ethernet_header(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN + 20 {
        return None;
    }
    let ethertype = &frame[12..14];
    if ethertype == ETHERTYPE_IPV4 {
        Some(&frame[ETHERNET_HEADER_LEN..])
    } else {
        None
    }
}

pub fn prepend_ethernet_header(ip_packet: &[u8], dst_mac: &[u8; 6], src_mac: &[u8; 6]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + ip_packet.len());
    frame.extend_from_slice(dst_mac);
    frame.extend_from_slice(src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4);
    frame.extend_from_slice(ip_packet);
    frame
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

pub fn generate_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac[0] = 0x02;
    mac[1] = 0x00;
    let rng = rand::random::<u32>();
    mac[2] = (rng >> 24) as u8;
    mac[3] = ((rng >> 16) & 0xff) as u8;
    mac[4] = ((rng >> 8) & 0xff) as u8;
    mac[5] = (rng & 0xff) as u8;
    mac
}
