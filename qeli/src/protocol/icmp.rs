//! ICMPv4 "Fragmentation Needed" generation, for the downlink path-MTU signal.
//!
//! The server forwards packets from its TUN into a client's tunnel. Those packets were
//! sized by the *origin*, which discovered the path MTU up to the server's TUN — it knows
//! nothing about the narrower leg from the server to the client. When a client's real path
//! MTU is smaller than the profile's `tun.mtu`, oversized packets are handed to the
//! transport and dropped somewhere on the way, with no signal to anyone: the classic
//! black hole where a connection establishes and then stalls on the first big transfer.
//!
//! A router in that position does not drop silently — it answers the origin with ICMP
//! Destination Unreachable / Fragmentation Needed (type 3, code 4, RFC 792) carrying the
//! next-hop MTU (RFC 1191), which is how path-MTU discovery is *supposed* to converge.
//! That is what this builds, so the server behaves like the router it is.
//!
//! IPv4 uses Fragmentation Needed when DF is set and may otherwise be fragmented by the
//! forwarder. IPv6 routers never fragment: the sibling below emits ICMPv6 Packet Too Big and
//! lets the origin retry at the advertised MTU.

/// ICMP Destination Unreachable.
const ICMP_DEST_UNREACH: u8 = 3;
/// Code 4: fragmentation needed and DF set.
const ICMP_FRAG_NEEDED: u8 = 4;
/// Differentiated-services value Linux uses for ICMP errors (CS6 — internetwork control).
const ICMP_ERR_TOS: u8 = 0xC0;
/// IPv4 `protocol` value for ICMP.
const IP_PROTO_ICMP: u8 = 1;
/// IPv4 header without options.
const IPV4_HDR_LEN: usize = 20;
/// ICMP header: type(1) + code(1) + checksum(2) + unused(2) + next-hop MTU(2).
const ICMP_HDR_LEN: usize = 8;
/// Bytes of the offending datagram quoted back after its IP header. RFC 792's minimum;
/// enough for the origin to match the error to a socket (ports live in the first 4).
const QUOTED_PAYLOAD: usize = 8;

/// ICMP types that are ERRORS (RFC 1122 §3.2.2). Everything else — Echo, Timestamp, Address
/// Mask, Router Discovery — is a query, and a router owes a query the same Fragmentation
/// Needed it owes any other oversized DF datagram.
const ICMP_ERROR_TYPES: [u8; 5] = [
    3,  // Destination Unreachable
    4,  // Source Quench (deprecated, still an error)
    5,  // Redirect
    11, // Time Exceeded
    12, // Parameter Problem
];

/// True when `pkt` (an IPv4 datagram whose header is `ihl` bytes) carries an ICMP **error**.
///
/// Fails CLOSED: a datagram too short to hold an ICMP type byte is treated as an error, so a
/// truncated or malicious packet suppresses our reply rather than provoking one.
fn icmp_is_error(pkt: &[u8], ihl: usize) -> bool {
    match pkt.get(ihl) {
        Some(&t) => ICMP_ERROR_TYPES.contains(&t),
        None => true,
    }
}

/// The standard internet checksum (RFC 1071): one's complement of the one's-complement
/// sum of 16-bit big-endian words, with a trailing odd byte zero-padded.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// True if `pkt` is an IPv4 packet with the Don't Fragment bit set.
///
/// DF decides which half of PMTUD applies: with DF set a router must not fragment and
/// must report back, which is the case every modern stack (and all of QUIC) relies on.
#[inline]
pub fn has_df(pkt: &[u8]) -> bool {
    pkt.len() >= IPV4_HDR_LEN && (pkt[0] >> 4) == 4 && (pkt[6] & 0x40) != 0
}

/// The IPv4 header a NON-FIRST fragment should carry: the fixed 20 bytes plus only those
/// options whose "copied" flag (the option type's high bit) is set, padded with EOL to a
/// 4-byte boundary so IHL stays expressible.
///
/// RFC 791 §3.1 splits options into two classes for exactly this reason. Something like Record
/// Route or Timestamp is meaningful only where it was recorded, so it belongs on the first
/// fragment alone; Router Alert must be seen by every hop and is copied. Getting this wrong is
/// not cosmetic — a router that copies a Record Route into all fragments produces a datagram
/// whose reassembled options differ from what was sent.
///
/// Returns `None` on a malformed option list: a length byte of 0 or 1 for a multi-byte option,
/// or one that runs past the header. Refusing there is right — the packet is already invalid,
/// and guessing a repair would forward something the sender never wrote.
fn later_fragment_header(hdr: &[u8]) -> Option<Vec<u8>> {
    if hdr.len() < IPV4_HDR_LEN {
        return None;
    }
    let mut out = hdr[..IPV4_HDR_LEN].to_vec();
    let mut i = IPV4_HDR_LEN;
    while i < hdr.len() {
        let opt = hdr[i];
        let kind = opt & 0x1F;
        let copied = opt & 0x80 != 0;
        // EOL ends the list; NOP is a single padding byte.
        if kind == 0 {
            break;
        }
        if kind == 1 {
            if copied {
                out.push(opt);
            }
            i += 1;
            continue;
        }
        // Every other option is type-length-value, with the length covering type and length.
        let len = *hdr.get(i + 1)? as usize;
        if len < 2 || i + len > hdr.len() {
            return None;
        }
        if copied {
            out.extend_from_slice(&hdr[i..i + len]);
        }
        i += len;
    }
    // IHL counts 32-bit words, so pad with EOL until the header is a whole number of them.
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    if out.len() > 60 {
        return None; // IHL maxes out at 15 words
    }
    out[0] = (out[0] & 0xF0) | ((out.len() / 4) as u8);
    Some(out)
}

/// Split an oversized IPv4 datagram into fragments that each fit `mtu` (RFC 791 §3.2).
///
/// The other half of being a router. With DF set we answer [`frag_needed`] and drop; without
/// DF the sender is entitled to expect fragmentation instead, and qeli forwards in userspace
/// so the kernel never gets the chance to do it. Those packets were simply dropped with a
/// debug line — a black hole for exactly the traffic that told us it did not want one.
///
/// Returns `None` (caller falls back to dropping) when the packet must not or cannot be
/// fragmented here:
///   * not IPv4, or the header is malformed / longer than what arrived;
///   * DF is set — fragmenting then would violate the sender's explicit instruction;
///   * it already fits `mtu`;
///   * `mtu` leaves no room for even one 8-byte payload unit;
///   * the option list is malformed (a length that runs past the header, or a zero length).
///
/// Options ARE handled, per RFC 791 §3.1: each option's high bit says whether it is copied
/// into every fragment or only the first, so the first fragment keeps the header verbatim and
/// later fragments carry just the copied options, padded to a 4-byte boundary. This used to
/// refuse outright — "safer than a half-right implementation" — which meant an oversized
/// non-DF packet with any option at all (Record Route, a timestamp, router alert) was dropped
/// instead of forwarded, silently, on exactly the path where the sender had said it wanted
/// fragmentation. (Audit 2026-07-30 #10; options implemented 2026-08-01, §P3.)
pub fn fragment_ipv4(pkt: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if pkt.len() < IPV4_HDR_LEN || (pkt[0] >> 4) != 4 || has_df(pkt) {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HDR_LEN || ihl > pkt.len() {
        return None;
    }
    // Header for fragments AFTER the first: only options whose copied bit is set survive.
    // Built up front so a malformed option list refuses the whole packet rather than being
    // discovered halfway through emitting fragments.
    let later_hdr = later_fragment_header(&pkt[..ihl])?;
    let later_ihl = later_hdr.len();
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    // A header CLAIMING more bytes than arrived is a truncated (or lying) datagram, and it must
    // not be re-fragmented. Clamping the length silently produced fragments whose headers
    // described a complete datagram while carrying only the bytes that happened to be present:
    // the receiver would then reassemble a short packet as if it were whole, and MF/offset
    // would say nothing was missing. Refuse and let the caller drop it — the same treatment as
    // a declared length below the header. (Audit 2026-08-01, §11.)
    if total_len > pkt.len() || total_len < ihl {
        return None;
    }
    let payload = &pkt[ihl..total_len];
    if pkt.len() <= mtu {
        return None;
    }
    // A header whose declared total_len is <= its own IHL leaves no payload, and the loop below
    // would then produce ZERO fragments. `Some(vec![])` reads to the caller as "fragmented
    // successfully", so it forwarded nothing, counted no drop, and the packet vanished with no
    // trace anywhere. Refuse instead, and let the caller drop and count it.
    // (Audit 2026-07-31, §9.)
    if payload.is_empty() {
        return None;
    }
    // Every fragment but the last must carry a multiple of 8 bytes (the offset field counts
    // 8-byte units), so round the per-fragment payload DOWN. Sized against the LARGER of the
    // two headers: the first fragment keeps every option, later ones only the copied ones, and
    // using one budget for both keeps the offset arithmetic in whole units.
    let hdr_budget = ihl.max(later_ihl);
    let per_frag = (mtu.saturating_sub(hdr_budget)) & !7usize;
    if per_frag == 0 {
        return None;
    }

    // Preserve where this datagram already sat in a larger one: it may itself be a fragment.
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let base_offset = (flags_frag & 0x1FFF) as usize;
    let orig_mf = (flags_frag & 0x2000) != 0;

    // The last piece's offset must still FIT the 13-bit field. `base_offset + sent/8` was
    // masked with `& 0x1FFF` when written, so a datagram already far into a larger one wrapped
    // around to a low offset instead of overflowing — producing fragments that a receiver
    // reassembles OVER the beginning of the packet. That is a rewrite of data the sender never
    // asked for, so refuse the whole thing rather than emit it. (Audit 2026-08-01, §11.)
    const MAX_FRAG_OFFSET_UNITS: usize = 0x1FFF;
    let last_offset_units = base_offset + (payload.len().saturating_sub(1)) / 8;
    if last_offset_units > MAX_FRAG_OFFSET_UNITS {
        return None;
    }

    let mut out = Vec::with_capacity(payload.len().div_ceil(per_frag));
    let mut sent = 0usize;
    while sent < payload.len() {
        let take = per_frag.min(payload.len() - sent);
        let is_last = sent + take == payload.len();
        // MF stays set on the final piece when the ORIGINAL was itself a non-final fragment.
        let more = !is_last || orig_mf;

        // The FIRST fragment carries the header as it arrived; later ones carry only the
        // options marked copied (RFC 791 §3.1), which is what makes a Record Route or a
        // timestamp option behave the way the sender expects.
        let hdr: &[u8] = if sent == 0 { &pkt[..ihl] } else { &later_hdr };
        let this_ihl = hdr.len();

        let mut frag = Vec::with_capacity(this_ihl + take);
        frag.extend_from_slice(hdr);
        frag[2..4].copy_from_slice(&((this_ihl + take) as u16).to_be_bytes());
        let offset_units = base_offset + sent / 8;
        let mut ff = (offset_units as u16) & 0x1FFF;
        if more {
            ff |= 0x2000;
        }
        frag[6..8].copy_from_slice(&ff.to_be_bytes());
        // Header changed, so the header checksum must be recomputed over the header alone.
        frag[10] = 0;
        frag[11] = 0;
        let ck = checksum(&frag[..this_ihl]);
        frag[10..12].copy_from_slice(&ck.to_be_bytes());
        frag.extend_from_slice(&payload[sent..sent + take]);
        out.push(frag);
        sent += take;
    }
    Some(out)
}

/// Build an ICMP "Fragmentation Needed" for `offender`, announcing `next_hop_mtu`.
///
/// `router_ip` is the address the error appears to come from — the server's TUN address,
/// i.e. the hop that could not forward. The result is a complete IPv4 packet ready to be
/// written back into the TUN, where the host stack routes it to the origin.
///
/// Returns `None` when `offender` is not a forwardable IPv4 packet, or when its own source
/// address is unusable as a destination (unspecified / multicast / broadcast) — answering
/// those would emit traffic nobody asked for.
pub fn frag_needed(
    offender: &[u8],
    router_ip: std::net::Ipv4Addr,
    next_hop_mtu: u16,
) -> Option<Vec<u8>> {
    if offender.len() < IPV4_HDR_LEN || (offender[0] >> 4) != 4 {
        return None;
    }
    // Quote the offender's real header length (it may carry options), bounded by what
    // actually arrived so a truncated read cannot make us index past the end.
    let ihl = ((offender[0] & 0x0F) as usize) * 4;
    if ihl < IPV4_HDR_LEN || ihl > offender.len() {
        return None;
    }
    let quote_len = (ihl + QUOTED_PAYLOAD).min(offender.len());

    let dst = std::net::Ipv4Addr::new(offender[12], offender[13], offender[14], offender[15]);
    if dst.is_unspecified() || dst.is_multicast() || dst.is_broadcast() {
        return None;
    }
    // Never answer an ICMP *error* with another ICMP error (RFC 1122 §3.2.2): two hosts could
    // otherwise trade errors forever, and it also stops our own error coming back at us.
    //
    // Only errors, though. An earlier version rejected every ICMP packet, which silently broke
    // the one command an operator reaches for to test this: `ping -s 1500 -M do` sends an Echo
    // Request — a QUERY, not an error — and RFC 1191 §3 requires a router to answer an oversized
    // DF datagram with Fragmentation Needed whatever it carries. Suppressing that made PMTUD
    // look broken in exactly the diagnostic that proves it works.
    if offender[9] == IP_PROTO_ICMP && icmp_is_error(offender, ihl) {
        return None;
    }

    let total = IPV4_HDR_LEN + ICMP_HDR_LEN + quote_len;
    let mut out = vec![0u8; total];

    // ── IPv4 header ──────────────────────────────────────────────────────────
    out[0] = 0x45; // version 4, IHL 5 (no options)
    out[1] = ICMP_ERR_TOS;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // Identification 0 and no fragment flags: this packet is small and never fragmented.
    out[8] = 64; // TTL
    out[9] = IP_PROTO_ICMP;
    out[12..16].copy_from_slice(&router_ip.octets());
    out[16..20].copy_from_slice(&dst.octets());
    let ip_ck = checksum(&out[..IPV4_HDR_LEN]);
    out[10..12].copy_from_slice(&ip_ck.to_be_bytes());

    // ── ICMP ─────────────────────────────────────────────────────────────────
    let icmp = IPV4_HDR_LEN;
    out[icmp] = ICMP_DEST_UNREACH;
    out[icmp + 1] = ICMP_FRAG_NEEDED;
    // out[icmp + 4..icmp + 6] stays zero (unused)
    out[icmp + 6..icmp + 8].copy_from_slice(&next_hop_mtu.to_be_bytes());
    out[icmp + ICMP_HDR_LEN..].copy_from_slice(&offender[..quote_len]);
    let icmp_ck = checksum(&out[icmp..]);
    out[icmp + 2..icmp + 4].copy_from_slice(&icmp_ck.to_be_bytes());

    Some(out)
}

/// Build an ICMPv6 Packet Too Big response (RFC 4443 section 3.2).
///
/// The result is a complete IPv6 packet ready for the server TUN. The quoted offender is
/// capped so the error itself fits the IPv6 minimum MTU (1280 bytes). ICMPv6 errors never
/// trigger another ICMPv6 error.
pub fn packet_too_big_v6(
    offender: &[u8],
    router_ip: std::net::Ipv6Addr,
    next_hop_mtu: u32,
) -> Option<Vec<u8>> {
    const IPV6_HEADER: usize = 40;
    const ICMPV6_HEADER: usize = 8;
    const IPPROTO_ICMPV6: u8 = 58;
    const ICMPV6_PACKET_TOO_BIG: u8 = 2;
    const IPV6_MIN_MTU: usize = 1280;

    // Be defensive even though the server forwarder already applies this floor before it
    // compares packet length.  No caller of this public helper may emit an invalid sub-1280
    // ICMPv6 next-hop MTU if it is ever reused elsewhere.
    let next_hop_mtu = next_hop_mtu.max(IPV6_MIN_MTU as u32);

    if router_ip.is_unspecified() || router_ip.is_multicast() {
        return None;
    }
    let meta = crate::protocol::ip::parse_ip_packet(offender).ok()?;
    if meta.version != crate::protocol::ip::IpVersion::V6 {
        return None;
    }
    let std::net::IpAddr::V6(destination) = meta.source else {
        return None;
    };
    if destination.is_unspecified() || destination.is_multicast() {
        return None;
    }
    if meta.protocol == IPPROTO_ICMPV6 {
        let icmp_type = *offender.get(meta.l4_offset?)?;
        if icmp_type < 128 {
            return None;
        }
    }

    let quote_len = offender
        .len()
        .min(IPV6_MIN_MTU - IPV6_HEADER - ICMPV6_HEADER);
    let payload_len = ICMPV6_HEADER + quote_len;
    let mut out = vec![0u8; IPV6_HEADER + payload_len];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out[6] = IPPROTO_ICMPV6;
    out[7] = 64;
    out[8..24].copy_from_slice(&router_ip.octets());
    out[24..40].copy_from_slice(&destination.octets());

    let icmp = IPV6_HEADER;
    out[icmp] = ICMPV6_PACKET_TOO_BIG;
    out[icmp + 1] = 0;
    out[icmp + 4..icmp + 8].copy_from_slice(&next_hop_mtu.to_be_bytes());
    out[icmp + ICMPV6_HEADER..].copy_from_slice(&offender[..quote_len]);

    let mut pseudo = Vec::with_capacity(40 + payload_len);
    pseudo.extend_from_slice(&router_ip.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(payload_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
    pseudo.extend_from_slice(&out[icmp..]);
    let icmp_checksum = checksum(&pseudo);
    out[icmp + 2..icmp + 4].copy_from_slice(&icmp_checksum.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn tcp_packet_v6(payload: usize, next_header: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    fn icmpv6_checksum_valid(packet: &[u8]) -> bool {
        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let mut pseudo = Vec::with_capacity(40 + payload_len);
        pseudo.extend_from_slice(&packet[8..24]);
        pseudo.extend_from_slice(&packet[24..40]);
        pseudo.extend_from_slice(&(payload_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&packet[40..40 + payload_len]);
        checksum(&pseudo) == 0
    }

    #[test]
    fn packet_too_big_v6_is_well_formed_and_bounded() {
        let offender = tcp_packet_v6(2_000, 6);
        let router: Ipv6Addr = "fd42:7165:6c69::1".parse().unwrap();
        let reply = packet_too_big_v6(&offender, router, 1280).expect("builds");

        assert_eq!(
            reply.len(),
            1280,
            "ICMPv6 error must fit the minimum IPv6 MTU"
        );
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(reply[6], 58);
        assert_eq!(reply[7], 64);
        assert_eq!(&reply[8..24], &router.octets());
        assert_eq!(&reply[24..40], &offender[8..24]);
        assert_eq!(reply[40], 2, "Packet Too Big type");
        assert_eq!(reply[41], 0);
        assert_eq!(u32::from_be_bytes(reply[44..48].try_into().unwrap()), 1280);
        assert_eq!(&reply[48..], &offender[..1232]);
        assert_eq!(
            u16::from_be_bytes([reply[4], reply[5]]) as usize,
            reply.len() - 40
        );
        assert!(icmpv6_checksum_valid(&reply));
    }

    #[test]
    fn packet_too_big_v6_answers_queries_but_not_icmpv6_errors() {
        let router: Ipv6Addr = "fd42:7165:6c69::1".parse().unwrap();
        let mut echo = tcp_packet_v6(64, 58);
        echo[40] = 128;
        assert!(packet_too_big_v6(&echo, router, 1280).is_some());

        for error_type in [1u8, 2, 3, 4, 100, 127] {
            let mut error = tcp_packet_v6(64, 58);
            error[40] = error_type;
            assert!(
                packet_too_big_v6(&error, router, 1280).is_none(),
                "must not answer ICMPv6 error type {error_type}"
            );
        }
    }

    #[test]
    fn packet_too_big_v6_refuses_invalid_endpoints_and_non_ipv6() {
        let offender = tcp_packet_v6(64, 17);
        let router: Ipv6Addr = "fd42:7165:6c69::1".parse().unwrap();
        assert!(packet_too_big_v6(&offender, Ipv6Addr::UNSPECIFIED, 1280).is_none());
        assert!(packet_too_big_v6(&offender, "ff02::1".parse().unwrap(), 1280).is_none());

        let mut bad_source = offender.clone();
        bad_source[8..24].fill(0);
        assert!(packet_too_big_v6(&bad_source, router, 1280).is_none());
        assert!(packet_too_big_v6(&tcp_packet(64, true), router, 1280).is_none());
        assert!(packet_too_big_v6(&[0x60, 0, 0], router, 1280).is_none());
    }

    #[test]
    fn packet_too_big_v6_never_advertises_a_subminimum_mtu() {
        let offender = tcp_packet_v6(2_000, 6);
        let router: Ipv6Addr = "fd42:7165:6c69::1".parse().unwrap();
        let reply = packet_too_big_v6(&offender, router, 576).expect("builds");
        assert_eq!(u32::from_be_bytes(reply[44..48].try_into().unwrap()), 1280);
    }

    /// A TCP packet from 203.0.113.9 to 10.8.0.2, DF set, `payload` bytes past the header.
    fn tcp_packet(payload: usize, df: bool) -> Vec<u8> {
        let mut p = vec![0u8; IPV4_HDR_LEN + payload];
        p[0] = 0x45;
        let total = (IPV4_HDR_LEN + payload) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        if df {
            p[6] = 0x40;
        }
        p[8] = 64;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 9).octets());
        p[16..20].copy_from_slice(&Ipv4Addr::new(10, 8, 0, 2).octets());
        // Ports, so the quoted bytes are recognisable.
        p[20..24].copy_from_slice(&[0x01, 0xBB, 0xC0, 0x01]);
        p
    }

    /// A receiver validates a checksum by summing the region and expecting all-ones.
    fn checksum_valid(region: &[u8]) -> bool {
        checksum(region) == 0
    }

    /// Reassemble fragments the way a receiver does, so the test asserts the property that
    /// matters (the original bytes come back) rather than a byte pattern I chose.
    fn reassemble(frags: &[Vec<u8>]) -> (Vec<u8>, bool) {
        let mut out = vec![0u8; 0];
        let mut last_mf = false;
        for f in frags {
            let ihl = ((f[0] & 0x0F) as usize) * 4;
            let ff = u16::from_be_bytes([f[6], f[7]]);
            let off = (ff & 0x1FFF) as usize * 8;
            last_mf = (ff & 0x2000) != 0;
            let total = u16::from_be_bytes([f[2], f[3]]) as usize;
            assert_eq!(total, f.len(), "total-length field must match the buffer");
            assert!(checksum(&f[..ihl]) == 0, "header checksum must verify");
            if out.len() < off + (f.len() - ihl) {
                out.resize(off + (f.len() - ihl), 0);
            }
            out[off..off + f.len() - ihl].copy_from_slice(&f[ihl..]);
        }
        (out, last_mf)
    }

    /// Without DF the sender expects fragmentation, and qeli forwards in userspace so the
    /// kernel never does it: those packets used to be dropped outright. (Audit 2026-07-30, #10.)
    #[test]
    fn non_df_oversized_packets_are_fragmented_losslessly() {
        // NOTE: `tcp_packet` takes a PAYLOAD size, so each datagram is 20 bytes longer.
        for (payload_len, mtu) in [
            (1400usize, 1280usize),
            (3000, 576),
            (1281, 1280),
            (9000, 1400),
        ] {
            let pkt = tcp_packet(payload_len, false); // DF clear
            let frags = fragment_ipv4(&pkt, mtu).expect("a non-DF oversized packet must fragment");
            assert!(
                frags.len() > 1,
                "payload={payload_len} mtu={mtu}: expected several fragments"
            );
            for f in &frags {
                assert!(
                    f.len() <= mtu,
                    "a fragment ({} B) must fit the MTU {mtu}",
                    f.len()
                );
            }
            // Every fragment but the last carries a multiple of 8 payload bytes.
            for f in &frags[..frags.len() - 1] {
                assert_eq!(
                    (f.len() - IPV4_HDR_LEN) % 8,
                    0,
                    "non-final payload must be 8-aligned"
                );
                assert!(
                    u16::from_be_bytes([f[6], f[7]]) & 0x2000 != 0,
                    "MF must be set"
                );
            }
            let (body, mf) = reassemble(&frags);
            assert!(!mf, "the last fragment of a whole datagram must clear MF");
            assert_eq!(
                body,
                &pkt[IPV4_HDR_LEN..],
                "payload must survive the round trip"
            );
        }
    }

    /// The cases that must fall back to dropping rather than produce a wrong packet.
    #[test]
    fn fragmentation_refuses_what_it_must_not_touch() {
        let router_mtu = 1280;
        // DF set: fragmenting would violate the sender's explicit instruction.
        assert!(fragment_ipv4(&tcp_packet(1400, true), router_mtu).is_none());
        // Already fits.
        assert!(fragment_ipv4(&tcp_packet(1000, false), router_mtu).is_none());
        // An MTU too small to hold even one 8-byte unit past the header.
        assert!(fragment_ipv4(&tcp_packet(1400, false), IPV4_HDR_LEN + 4).is_none());
        // Not IPv4.
        let mut v6 = vec![0u8; 1400];
        v6[0] = 0x60;
        assert!(fragment_ipv4(&v6, router_mtu).is_none());
        // A header claiming options that are not really there (IHL 6 over a 20-byte header
        // whose bytes 20..24 are the TCP ports) is malformed — bytes 20/21 read as an option
        // type and a nonsense length. Refusing is right; guessing a repair would forward
        // something the sender never wrote.
        let mut lying = tcp_packet(1400, false);
        lying[0] = 0x46; // IHL 6, but the option bytes are actually TCP ports
        assert!(fragment_ipv4(&lying, router_mtu).is_none());

        // A malformed header claiming no payload must refuse, not report success with zero
        // fragments — the caller would then forward nothing AND count no drop.
        let mut empty = tcp_packet(1400, false);
        empty[2..4].copy_from_slice(&(IPV4_HDR_LEN as u16).to_be_bytes());
        assert!(fragment_ipv4(&empty, router_mtu).is_none());

        // A header claiming MORE bytes than arrived is truncated (or lying). This used to be
        // clamped, which produced fragments whose headers described a complete datagram while
        // carrying only the bytes that happened to be present — the receiver then reassembled
        // a short packet as if it were whole, with MF/offset saying nothing was missing.
        // (Audit 2026-08-01, §11.)
        let mut lying_len = tcp_packet(1400, false);
        lying_len[2..4].copy_from_slice(&9000u16.to_be_bytes());
        assert!(fragment_ipv4(&lying_len, router_mtu).is_none());

        // A datagram already so far into a larger one that our last piece would not fit the
        // 13-bit offset field. The offset was masked with `& 0x1FFF` on write, so it WRAPPED
        // to a low value and the receiver reassembled those bytes over the start of the packet.
        let mut near_max = tcp_packet(1400, false);
        // offset = 8188 units (of a 8191 maximum): 1400 bytes needs 175 more units.
        near_max[6..8].copy_from_slice(&8188u16.to_be_bytes());
        assert!(fragment_ipv4(&near_max, router_mtu).is_none());
    }

    /// A header with OPTIONS fragments, and the copied bit decides which options travel.
    ///
    /// This used to refuse outright, so an oversized non-DF packet carrying any option at all
    /// was dropped rather than forwarded — silently, on exactly the path where the sender had
    /// said it wanted fragmentation. RFC 791 §3.1: the first fragment keeps the header as it
    /// arrived, later fragments carry only options whose type has the high bit set.
    /// (Audit 2026-08-01, §P3.)
    #[test]
    fn options_are_copied_per_their_copied_bit() {
        // Build a 1400-byte-payload packet whose header carries two options:
        // Router Alert (0x94, copied, 4 bytes) and Record Route (0x07, NOT copied, 8 bytes).
        let base = tcp_packet(1400, false);
        let opts: [u8; 12] = [
            0x94, 0x04, 0x00, 0x00, // Router Alert — copied
            0x07, 0x07, 0x04, 0, 0, 0, 0,    // Record Route — not copied
            0x00, // EOL pad to 12 bytes
        ];
        let ihl = IPV4_HDR_LEN + opts.len();
        let mut pkt = Vec::with_capacity(ihl + 1400);
        pkt.extend_from_slice(&base[..IPV4_HDR_LEN]);
        pkt.extend_from_slice(&opts);
        pkt.extend_from_slice(&base[IPV4_HDR_LEN..]);
        pkt[0] = 0x40 | ((ihl / 4) as u8);
        pkt[2..4].copy_from_slice(&((ihl + 1400) as u16).to_be_bytes());

        let frags = fragment_ipv4(&pkt, 576).expect("a packet with options must fragment");
        assert!(frags.len() > 1);

        // First fragment: the header exactly as it arrived, options and all.
        let first_ihl = ((frags[0][0] & 0x0F) as usize) * 4;
        assert_eq!(first_ihl, ihl, "the first fragment keeps every option");
        assert_eq!(&frags[0][IPV4_HDR_LEN..first_ihl], &opts[..]);

        // Later fragments: Router Alert survives, Record Route does not.
        let later_ihl = ((frags[1][0] & 0x0F) as usize) * 4;
        assert!(later_ihl < ihl, "the non-copied option must be dropped");
        let later_opts = &frags[1][IPV4_HDR_LEN..later_ihl];
        assert_eq!(
            &later_opts[..4],
            &[0x94, 0x04, 0x00, 0x00],
            "Router Alert is copied"
        );
        assert!(
            !later_opts.contains(&0x07),
            "Record Route must not be copied"
        );

        // Every fragment must still be a valid, in-budget datagram.
        for f in &frags {
            let fi = ((f[0] & 0x0F) as usize) * 4;
            assert!(f.len() <= 576, "fragment overruns the MTU: {}", f.len());
            assert_eq!(checksum(&f[..fi]), 0, "header checksum must verify");
            assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, f.len());
        }

        // ...and the payload reassembles byte-for-byte, in order and without gaps.
        let mut out = Vec::new();
        for f in &frags {
            let fi = ((f[0] & 0x0F) as usize) * 4;
            let off = ((u16::from_be_bytes([f[6], f[7]]) & 0x1FFF) as usize) * 8;
            assert_eq!(off, out.len(), "fragment offsets must be contiguous");
            out.extend_from_slice(&f[fi..]);
        }
        assert_eq!(
            out,
            pkt[ihl..],
            "the reassembled payload must match the original"
        );
    }

    /// A datagram that is ALREADY a fragment keeps its place: offsets continue from where it
    /// sat, and MF stays set on our last piece because more of the original is still to come.
    #[test]
    fn fragmenting_an_existing_fragment_preserves_its_offset_and_mf() {
        let mut pkt = tcp_packet(1400, false);
        // offset = 100 units (800 B) into the original, MF set (more follows).
        pkt[6..8].copy_from_slice(&(0x2000u16 | 100).to_be_bytes());
        let frags = fragment_ipv4(&pkt, 576).expect("must fragment");
        let first = u16::from_be_bytes([frags[0][6], frags[0][7]]);
        assert_eq!(
            first & 0x1FFF,
            100,
            "the first piece keeps the original offset"
        );
        let last = u16::from_be_bytes([frags[frags.len() - 1][6], frags[frags.len() - 1][7]]);
        assert!(
            last & 0x2000 != 0,
            "MF must stay set — the original was not the final fragment"
        );
    }

    /// Build an ICMP datagram of `total` bytes carrying ICMP `icmp_type`, DF set.
    fn icmp_packet(total: usize, icmp_type: u8) -> Vec<u8> {
        let mut p = tcp_packet(total, true);
        p[9] = IP_PROTO_ICMP;
        p[IPV4_HDR_LEN] = icmp_type;
        p
    }

    /// RFC 1122 §3.2.2 bars answering an ICMP **error**; it says nothing about queries, and
    /// RFC 1191 §3 requires Fragmentation Needed for ANY oversized DF datagram. Suppressing
    /// the reply to an Echo Request broke `ping -s 1500 -M do` — the exact command used to
    /// prove PMTUD works.
    #[test]
    fn oversized_df_echo_gets_an_answer_but_icmp_errors_do_not() {
        let router = Ipv4Addr::new(10, 8, 0, 1);

        // Queries MUST be answered.
        for query in [0u8, 8, 13, 14, 17, 18] {
            assert!(
                frag_needed(&icmp_packet(1400, query), router, 1280).is_some(),
                "ICMP type {query} is a query and must get Fragmentation Needed"
            );
        }
        // Errors MUST NOT be — otherwise two hosts trade errors forever.
        for err in ICMP_ERROR_TYPES {
            assert!(
                frag_needed(&icmp_packet(1400, err), router, 1280).is_none(),
                "ICMP type {err} is an error and must not be answered with one"
            );
        }
        // Non-ICMP is unaffected.
        assert!(frag_needed(&tcp_packet(1400, true), router, 1280).is_some());
    }

    /// A datagram too short to hold an ICMP type byte must fail CLOSED (no reply), not index
    /// past the end — the offender is attacker-supplied.
    #[test]
    fn truncated_icmp_is_treated_as_an_error() {
        let mut p = tcp_packet(IPV4_HDR_LEN, true);
        p[9] = IP_PROTO_ICMP;
        p.truncate(IPV4_HDR_LEN);
        assert!(frag_needed(&p, Ipv4Addr::new(10, 8, 0, 1), 1280).is_none());
    }

    #[test]
    fn frag_needed_is_a_well_formed_icmp_error() {
        let offender = tcp_packet(1400, true);
        let icmp = frag_needed(&offender, Ipv4Addr::new(10, 8, 0, 1), 1280).expect("builds");

        assert_eq!(
            icmp.len(),
            IPV4_HDR_LEN + ICMP_HDR_LEN + IPV4_HDR_LEN + QUOTED_PAYLOAD
        );
        assert_eq!(icmp[0], 0x45);
        assert_eq!(icmp[9], 1, "protocol must be ICMP");
        assert_eq!(
            u16::from_be_bytes([icmp[2], icmp[3]]) as usize,
            icmp.len(),
            "total length must match the buffer"
        );
        // Addresses: from the router, back to the original SOURCE.
        assert_eq!(&icmp[12..16], &Ipv4Addr::new(10, 8, 0, 1).octets());
        assert_eq!(&icmp[16..20], &Ipv4Addr::new(203, 0, 113, 9).octets());

        // Type/code/next-hop MTU.
        assert_eq!(icmp[20], 3);
        assert_eq!(icmp[21], 4);
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1280);

        // Both checksums must verify the way a real stack verifies them.
        assert!(checksum_valid(&icmp[..IPV4_HDR_LEN]), "IPv4 checksum");
        assert!(checksum_valid(&icmp[IPV4_HDR_LEN..]), "ICMP checksum");

        // The quote lets the origin match the error to its socket: header + 8 bytes,
        // which covers the ports.
        let quote = &icmp[IPV4_HDR_LEN + ICMP_HDR_LEN..];
        assert_eq!(quote, &offender[..IPV4_HDR_LEN + QUOTED_PAYLOAD]);
        assert_eq!(&quote[20..24], &[0x01, 0xBB, 0xC0, 0x01]);
    }

    #[test]
    fn df_detection() {
        assert!(has_df(&tcp_packet(100, true)));
        assert!(!has_df(&tcp_packet(100, false)));
        assert!(!has_df(&[]), "a short buffer is not a DF packet");
    }

    #[test]
    fn refuses_what_must_not_be_answered() {
        // Not IPv4.
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert!(frag_needed(&v6, Ipv4Addr::new(10, 8, 0, 1), 1280).is_none());
        // Too short to hold a header.
        assert!(frag_needed(&[0x45, 0, 0, 4], Ipv4Addr::new(10, 8, 0, 1), 1280).is_none());

        // An ICMP ERROR: answering an error with an error can loop (RFC 1122 §3.2.2). The type
        // byte must be set explicitly — this used to reuse `tcp_packet`, whose first port byte
        // (0x01) landed in the type field and happens to be an unassigned type, so the case
        // passed only while the code rejected every ICMP packet regardless of type. Queries are
        // the other half of the rule and are covered by
        // `oversized_df_echo_gets_an_answer_but_icmp_errors_do_not`.
        let mut icmp_in = tcp_packet(100, true);
        icmp_in[9] = IP_PROTO_ICMP;
        icmp_in[IPV4_HDR_LEN] = ICMP_DEST_UNREACH;
        assert!(frag_needed(&icmp_in, Ipv4Addr::new(10, 8, 0, 1), 1280).is_none());

        // Sources we must not send traffic to.
        for src in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            let mut p = tcp_packet(100, true);
            p[12..16].copy_from_slice(&src.octets());
            assert!(
                frag_needed(&p, Ipv4Addr::new(10, 8, 0, 1), 1280).is_none(),
                "must not answer {src}"
            );
        }
    }

    /// A header carrying options must be quoted at its real length, and a header whose
    /// declared IHL exceeds what arrived must be refused rather than read past the end.
    #[test]
    fn header_options_and_lying_ihl() {
        let mut with_opts = tcp_packet(100, true);
        with_opts[0] = 0x46; // IHL 6 → 24-byte header
        let icmp = frag_needed(&with_opts, Ipv4Addr::new(10, 8, 0, 1), 1300).expect("builds");
        assert_eq!(
            icmp.len(),
            IPV4_HDR_LEN + ICMP_HDR_LEN + 24 + QUOTED_PAYLOAD
        );
        assert!(checksum_valid(&icmp[IPV4_HDR_LEN..]));

        let mut liar = vec![0u8; IPV4_HDR_LEN + 2];
        liar[0] = 0x4F; // IHL 15 → 60 bytes, but only 22 arrived
        liar[9] = 6;
        liar[12..16].copy_from_slice(&Ipv4Addr::new(203, 0, 113, 9).octets());
        assert!(frag_needed(&liar, Ipv4Addr::new(10, 8, 0, 1), 1280).is_none());
    }

    /// A tiny offender is quoted whole — `min` must clamp to what arrived, not pad.
    #[test]
    fn short_offender_is_quoted_whole() {
        let mut small = vec![0u8; IPV4_HDR_LEN + 3];
        small[0] = 0x45;
        small[9] = 17; // UDP
        small[12..16].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 7).octets());
        small[16..20].copy_from_slice(&Ipv4Addr::new(10, 8, 0, 2).octets());
        let icmp = frag_needed(&small, Ipv4Addr::new(10, 8, 0, 1), 1280).expect("builds");
        assert_eq!(icmp.len(), IPV4_HDR_LEN + ICMP_HDR_LEN + small.len());
        assert!(checksum_valid(&icmp[..IPV4_HDR_LEN]));
        assert!(checksum_valid(&icmp[IPV4_HDR_LEN..]));
    }

    #[test]
    fn checksum_matches_a_known_vector() {
        // RFC 1071 §3 worked example.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
        // An odd-length buffer pads with a zero byte rather than reading out of bounds.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2]),
            checksum(&[0x00, 0x01, 0xf2, 0x00])
        );
    }
}
