import Foundation

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
    static let minimumTunnelMTU = 1_280
    static let recordOverhead = 48

    let ceiling: Int

    var candidates: [Int] {
        guard ceiling >= Self.minimumTunnelMTU else { return [] }
        return [ceiling, 1_360, 1_320, Self.minimumTunnelMTU]
            .filter { $0 >= Self.minimumTunnelMTU && $0 <= ceiling }
            .reduce(into: [Int]()) { values, candidate in
                if !values.contains(candidate) { values.append(candidate) }
            }
            .sorted(by: >)
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
