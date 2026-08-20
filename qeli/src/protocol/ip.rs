//! Bounded parser for untrusted inner IPv4 and IPv6 datagrams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const MAX_EXTENSION_HEADERS: usize = 8;
const MAX_EXTENSION_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentInfo {
    pub id: u32,
    pub offset: u16,
    pub more: bool,
    /// Protocol value carried by the fragmentation header itself.
    ///
    /// For IPv4 this is the base header's Protocol field. For IPv6 it is the Fragment
    /// Header's Next Header value, which is identical in every fragment even when fragment
    /// zero contains additional extension headers that later fragments cannot parse.
    pub protocol: u8,
}

impl FragmentInfo {
    pub const fn is_fragmented(self) -> bool {
        self.offset != 0 || self.more
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacketMeta {
    pub version: IpVersion,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub l4_offset: Option<usize>,
    pub fragment: Option<FragmentInfo>,
    pub packet_len: usize,
}

impl IpPacketMeta {
    pub fn ports(self, packet: &[u8]) -> Option<(u16, u16)> {
        if !matches!(self.protocol, 6 | 17) {
            return None;
        }
        let offset = self.l4_offset?;
        let bytes = packet.get(offset..offset + 4)?;
        Some((
            u16::from_be_bytes([bytes[0], bytes[1]]),
            u16::from_be_bytes([bytes[2], bytes[3]]),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IpPacketError {
    #[error("empty IP packet")]
    Empty,
    #[error("unsupported IP version {0}")]
    UnsupportedVersion(u8),
    #[error("truncated IP header")]
    TruncatedHeader,
    #[error("invalid IPv4 header length")]
    InvalidIpv4HeaderLength,
    #[error("declared IP length does not match record length")]
    LengthMismatch,
    #[error("IPv6 jumbograms are not supported")]
    Ipv6Jumbogram,
    #[error("truncated IPv6 extension header")]
    TruncatedExtension,
    #[error("IPv6 extension chain exceeds parser limits")]
    ExtensionLimit,
    #[error("duplicate IPv6 fragment header")]
    DuplicateFragmentHeader,
}

pub fn parse_ip_packet(packet: &[u8]) -> Result<IpPacketMeta, IpPacketError> {
    let first = *packet.first().ok_or(IpPacketError::Empty)?;
    match first >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        version => Err(IpPacketError::UnsupportedVersion(version)),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<IpPacketMeta, IpPacketError> {
    if packet.len() < IPV4_MIN_HEADER {
        return Err(IpPacketError::TruncatedHeader);
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER || ihl > packet.len() {
        return Err(IpPacketError::InvalidIpv4HeaderLength);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || total_len != packet.len() {
        return Err(IpPacketError::LengthMismatch);
    }
    let flags_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let fragment = FragmentInfo {
        id: u32::from(u16::from_be_bytes([packet[4], packet[5]])),
        offset: flags_offset & 0x1fff,
        more: flags_offset & 0x2000 != 0,
        protocol: packet[9],
    };
    let fragmented = fragment.is_fragmented();
    Ok(IpPacketMeta {
        version: IpVersion::V4,
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        protocol: packet[9],
        l4_offset: (!fragmented || fragment.offset == 0).then_some(ihl),
        fragment: fragmented.then_some(fragment),
        packet_len: total_len,
    })
}

fn parse_ipv6(packet: &[u8]) -> Result<IpPacketMeta, IpPacketError> {
    if packet.len() < IPV6_HEADER {
        return Err(IpPacketError::TruncatedHeader);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len == 0 && packet.len() != IPV6_HEADER {
        return Err(IpPacketError::Ipv6Jumbogram);
    }
    let total_len = IPV6_HEADER
        .checked_add(payload_len)
        .ok_or(IpPacketError::LengthMismatch)?;
    if total_len != packet.len() {
        return Err(IpPacketError::LengthMismatch);
    }
    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("checked IPv6 header"),
    ));
    let destination = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("checked IPv6 header"),
    ));
    let mut next = packet[6];
    let mut offset = IPV6_HEADER;
    let mut extension_count = 0usize;
    let mut extension_bytes = 0usize;
    let mut fragment = None;

    loop {
        let extension_len = match next {
            0 | 43 | 60 => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(IpPacketError::TruncatedExtension)?;
                usize::from(header[1])
                    .checked_add(1)
                    .and_then(|units| units.checked_mul(8))
                    .ok_or(IpPacketError::ExtensionLimit)?
            }
            44 => {
                if fragment.is_some() {
                    return Err(IpPacketError::DuplicateFragmentHeader);
                }
                8
            }
            51 => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(IpPacketError::TruncatedExtension)?;
                usize::from(header[1])
                    .checked_add(2)
                    .and_then(|units| units.checked_mul(4))
                    .ok_or(IpPacketError::ExtensionLimit)?
            }
            _ => break,
        };
        extension_count += 1;
        extension_bytes = extension_bytes
            .checked_add(extension_len)
            .ok_or(IpPacketError::ExtensionLimit)?;
        if extension_count > MAX_EXTENSION_HEADERS || extension_bytes > MAX_EXTENSION_BYTES {
            return Err(IpPacketError::ExtensionLimit);
        }
        let header = packet
            .get(offset..offset + extension_len)
            .ok_or(IpPacketError::TruncatedExtension)?;
        let current = next;
        next = header[0];
        if current == 44 {
            let wire = u16::from_be_bytes([header[2], header[3]]);
            fragment = Some(FragmentInfo {
                id: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                offset: wire >> 3,
                more: wire & 1 != 0,
                protocol: header[0],
            });
        }
        offset += extension_len;
        // Extension headers after the Fragment Header are part of the fragmentable
        // payload. Only fragment zero is guaranteed to begin with them; a later fragment
        // can start in the middle of that header or the L4 payload. Preserve the Fragment
        // Header's Next Header value as `protocol`, but never parse arbitrary later-fragment
        // bytes as another extension chain.
        if current == 44 && fragment.is_some_and(|fragment| fragment.offset != 0) {
            break;
        }
    }

    let carries_l4 = fragment.is_none_or(|fragment| fragment.offset == 0);
    Ok(IpPacketMeta {
        version: IpVersion::V6,
        source,
        destination,
        protocol: next,
        l4_offset: carries_l4.then_some(offset),
        fragment,
        packet_len: total_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp() -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(28u16).to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        packet[20..24].copy_from_slice(&[0x04, 0xd2, 0x00, 0x35]);
        packet
    }

    fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"fd42::2".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"fd42::1".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn parses_ipv4_lengths_and_ports() {
        let packet = ipv4_udp();
        let meta = parse_ip_packet(&packet).unwrap();
        assert_eq!(meta.version, IpVersion::V4);
        assert_eq!(meta.ports(&packet), Some((1234, 53)));
        let mut trailing = packet.clone();
        trailing.push(0);
        assert_eq!(
            parse_ip_packet(&trailing),
            Err(IpPacketError::LengthMismatch)
        );
    }

    #[test]
    fn parses_ipv6_udp_and_extension_chain() {
        let udp = [0x04, 0xd2, 0x00, 0x35, 0, 8, 0, 0];
        let packet = ipv6(17, &udp);
        let meta = parse_ip_packet(&packet).unwrap();
        assert_eq!(meta.ports(&packet), Some((1234, 53)));
        let mut payload = vec![0u8; 8];
        payload[0] = 17;
        payload.extend_from_slice(&udp);
        let with_extension = ipv6(60, &payload);
        let meta = parse_ip_packet(&with_extension).unwrap();
        assert_eq!(meta.l4_offset, Some(48));
        assert_eq!(meta.ports(&with_extension), Some((1234, 53)));
    }

    #[test]
    fn ipv6_fragments_hide_nonfirst_ports() {
        let mut first = vec![0u8; 16];
        first[0] = 17;
        first[3] = 1;
        first[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        first[8..12].copy_from_slice(&[0x04, 0xd2, 0x00, 0x35]);
        let first = ipv6(44, &first);
        assert_eq!(
            parse_ip_packet(&first).unwrap().ports(&first),
            Some((1234, 53))
        );

        let mut later = vec![0u8; 16];
        later[0] = 17;
        later[2..4].copy_from_slice(&(1u16 << 3).to_be_bytes());
        later[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let later = ipv6(44, &later);
        let meta = parse_ip_packet(&later).unwrap();
        assert_eq!(meta.l4_offset, None);
        assert_eq!(meta.ports(&later), None);
    }

    #[test]
    fn nonfirst_ipv6_fragment_does_not_parse_fragmentable_extension_bytes() {
        let mut later = vec![0u8; 16];
        later[0] = 60; // Destination Options follows Fragment in the original packet.
        later[2..4].copy_from_slice(&(1u16 << 3).to_be_bytes());
        later[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        // The remaining bytes are an arbitrary later slice of the fragmentable part, not
        // necessarily the start of the Destination Options header.
        let later = ipv6(44, &later);
        let meta = parse_ip_packet(&later).unwrap();
        assert_eq!(meta.protocol, 60);
        assert_eq!(meta.l4_offset, None);
        assert_eq!(meta.fragment.unwrap().offset, 1);
    }

    #[test]
    fn rejects_jumbogram_truncation_and_unbounded_chain() {
        let mut jumbo = vec![0u8; 41];
        jumbo[0] = 0x60;
        assert_eq!(parse_ip_packet(&jumbo), Err(IpPacketError::Ipv6Jumbogram));
        assert_eq!(
            parse_ip_packet(&ipv6(60, &[17])),
            Err(IpPacketError::TruncatedExtension)
        );
        let mut headers = vec![0u8; 9 * 8];
        for index in 0..9 {
            headers[index * 8] = if index == 8 { 17 } else { 60 };
        }
        assert_eq!(
            parse_ip_packet(&ipv6(60, &headers)),
            Err(IpPacketError::ExtensionLimit)
        );
    }

    #[test]
    fn accepts_an_empty_ipv6_packet_with_no_next_header() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[6] = 59;
        assert_eq!(parse_ip_packet(&packet).unwrap().packet_len, 40);
    }
}
