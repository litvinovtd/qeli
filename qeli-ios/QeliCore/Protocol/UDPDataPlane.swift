import Foundation
@testable import QeliIOS

/// UDP-specific packet policy kept separate from the Network Extension loop so
/// loss/corruption behavior is explicit and unit-testable.
enum UDPDataPlane {
    /// Android currently forwards IPv4 packets only. Unsupported or empty TUN
    /// packets are skipped without consuming an encryption sequence number.
    static func encodeUplink(_ packet: Data, encoder: PacketCodec, mtu: Int) throws -> Data? {
        guard packet.first.map({ $0 >> 4 == 4 }) == true else { return nil }
        return try encoder.encryptCapped(packet, maxInnerAndPadding: max(0, mtu))
    }

    /// A bad UDP datagram is independent of the next one, so authentication,
    /// replay and truncation failures are packet loss rather than tunnel-fatal errors.
    static func decodeDownlink(_ record: Data, decoder: PacketCodec) -> Data? {
        guard let plaintext = try? decoder.decrypt(record), !plaintext.isEmpty else { return nil }
        return plaintext
    }

    /// Server-pushed cover sizes must remain below the probed datagram ceiling.
    static func cappedCoverPadding(_ requested: Int, mtu: Int) -> Int {
        min(max(requested, 0), max(0, mtu - 60))
    }
}

struct UDPPathMTUProbePolicy: Equatable, Sendable {
    /// IPv6 minimum PATH MTU (RFC 8200 §5) — the narrowest path we must serve.
    static let pathFloor = 1_280
    static let recordOverhead = 48
    /// Smallest tunnel MTU worth probing at all, below which a tunnel is not useful.
    static let absoluteFloor = 576
    /// Worst case in this codebase: obfs seal (13) + QUIC short header (9) + UDP (8) + IPv6 (40).
    /// Used when a caller has no codec to ask; see ``UDPDatagramCodec/outerOverhead``.
    static let worstCaseOuterOverhead = 13 + 9 + 8 + 40

    let ceiling: Int
    /// Everything a probe for a candidate tunnel MTU adds on the wire beyond the MTU itself:
    /// our record overhead plus the obfs/QUIC/UDP/IP headers.
    let outerOverhead: Int

    init(ceiling: Int, outerOverhead: Int = Self.recordOverhead + Self.worstCaseOuterOverhead) {
        self.ceiling = ceiling
        self.outerOverhead = outerOverhead
    }

    /// The largest tunnel MTU whose probe datagram still fits a 1280-byte path.
    var floor: Int {
        min(max(Self.pathFloor - outerOverhead, Self.absoluteFloor), max(ceiling, Self.absoluteFloor))
    }

    /// Rungs in TUNNEL (inner) MTU units, highest first.
    ///
    /// The floor is DERIVED from the overhead, not hard-coded to 1280. That confusion was the
    /// #12 defect: rungs are INNER MTUs while 1280 is an OUTER path MTU, so a lowest rung of
    /// 1280 asked a 1280-byte path for 1280 + overhead bytes. Every rung then failed on exactly
    /// the narrow paths probing exists for, the probe reported nothing, and the caller fell back
    /// to the pushed MTU with fragmentation switched back on.
    var candidates: [Int] {
        let low = floor
        // The jumbo rungs (12000..1500) exist because the ceiling stopped being an Ethernet
        // number. While it was 1500 the next rung down was 1360 and the gap was 140 bytes; once
        // the ceiling became record-sized the same ladder went straight to 1360, so a path
        // that carries 9000 — an ordinary jumbo LAN, which is exactly who configures a large
        // MTU — was certified at 1360 and lost ~85% of its frame. These cost nothing on a
        // normal path: they are all above a 1500 ceiling and the filter drops them.
        //
        // The set is a COMPROMISE, not an exact answer: probing fixed rungs certifies the
        // best rung that FITS, not the path's real maximum, so a 7000-byte path lands on 6000.
        // Closing that needs a binary search between the highest failing rung and the best
        // passing one — worth doing, and deliberately not smuggled in here, since it changes
        // the probe's control flow in all four ports.
        // (Audit 2026-08-01, §8.)
        return [ceiling, 12_000, 9_000, 6_000, 4_000, 2_500, 2_000, 1_500, 1_360, 1_320, 1_280, 1_200, low]
            .filter { $0 >= low && $0 <= ceiling }
            .reduce(into: [Int]()) { values, candidate in
                if !values.contains(candidate) { values.append(candidate) }
            }
            .sorted(by: >)
    }

    /// Stop refining once the bracket is this narrow — chasing the last few dozen bytes is not
    /// worth a round trip, and the threshold also bounds the loop for a wide gap. Same value in
    /// Rust, C# and Kotlin.
    static let refineStepBytes = 256

    /// Hard cap on refinement probes, so a pathological bracket cannot stretch the handshake.
    static let refineMaxProbes = 5

    /// Next size to try between a rung known to WORK (`lo`) and one known to FAIL (`hi`), or
    /// `nil` when the bracket is narrow enough to stop.
    ///
    /// The coarse ladder certifies the best rung that FITS, not the path's maximum: with rungs
    /// at 9000 and 6000 an 8999-byte path was pinned to 6000 and threw away a third of every
    /// frame. A ladder can only ever land on its own numbers, so adding rungs moves the loss
    /// around instead of removing it — the bracket has to be searched. (Audit 2026-08-01, §8.)
    static func refineStep(lo: Int, hi: Int) -> Int? {
        hi - lo <= refineStepBytes ? nil : lo + (hi - lo) / 2
    }

    func outerProbeSize(for tunnelMTU: Int) -> Int {
        let (value, overflow) = tunnelMTU.addingReportingOverflow(Self.recordOverhead)
        return overflow ? Int.max : value
    }

    func accepts(_ event: UDPDatagramEvent, id: Int) -> Bool {
        guard case .mtuProbeAck(let receivedID, _) = event else { return false }
        return receivedID == (id & 0xffff)
    }
}
