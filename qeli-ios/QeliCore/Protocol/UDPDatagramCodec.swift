import Foundation
import Security

enum UDPDatagramEvent: Equatable {
    case records([Data])
    case fragmentPending
    case junk
    case mtuProbe(id: Int, outerSize: Int)
    case mtuProbeAck(id: Int, outerSize: Int)
}

/// Applies the Qeli UDP outer layers in their wire order and slices received
/// datagrams back into complete TLS-shaped records.
///
/// Send: ClientHello fragmentation -> QUIC mask -> stateless obfs.
/// Receive: stateless obfs -> QUIC mask -> fragment reassembly -> record slicing.
final class UDPDatagramCodec: @unchecked Sendable {
    let quicEnabled: Bool
    let connectionID: Data
    let obfsKey: Data?

    private let sendLock = NSLock()
    private let receiveLock = NSLock()
    private var packetNumber: UInt32
    private var reassembler = UDPFragmentation.Reassembler()

    convenience init(config: VPNConfig) throws {
        let isObfs = config.wireMode.caseInsensitiveCompare("obfs") == .orderedSame
        if isObfs && config.obfsKey.isEmpty { throw UDPDatagramCodecError.emptyObfsKey }
        try self.init(
            quicEnabled: config.quicEnabled,
            connectionID: config.quicEnabled ? QUICMask.connectionID() : Data(repeating: 0, count: 4),
            obfsKey: isObfs ? ObfsDatagramCipher.deriveKey(config.obfsKey) : nil
        )
    }

    init(
        quicEnabled: Bool,
        connectionID: Data,
        obfsKey: Data? = nil,
        initialPacketNumber: UInt32 = 0
    ) throws {
        guard connectionID.count == 4 else { throw UDPDatagramCodecError.invalidConnectionID }
        if let obfsKey, obfsKey.count != 32 {
            throw UDPDatagramCodecError.invalidObfsKeyLength(obfsKey.count)
        }
        self.quicEnabled = quicEnabled
        self.connectionID = connectionID
        self.obfsKey = obfsKey
        self.packetNumber = initialPacketNumber
    }

    /// Encodes one Qeli record. A long-header ClientHello is fragmented before
    /// masking so no fragment exceeds Qeli's mobile-safe 1200-byte chunk.
    func encode(record: Data, longHeader: Bool = false) throws -> [Data] {
        let pieces = longHeader
            ? try UDPFragmentation.fragment(messageID: UDPFragmentation.clientHello, message: record)
            : [record]
        return try sendLock.withLock {
            try pieces.map { try encodeLocked(payload: $0, longHeader: longHeader) }
        }
    }

    /// Encodes a control payload without handshake fragmentation (for MTU probes).
    func encodePayload(_ payload: Data, longHeader: Bool) throws -> Data {
        try sendLock.withLock { try encodeLocked(payload: payload, longHeader: longHeader) }
    }

    /// AmneziaWG-style polymorphic preamble. Each decoy uses the same QUIC/obfs
    /// layers as the following ClientHello and remains below the UDP fragment limit.
    func encodeAWGJunkPreamble(count: Int, minimumSize: Int, maximumSize: Int) throws -> [Data] {
        let boundedCount = min(max(count, 0), 128)
        let boundedMaximum = min(max(maximumSize, 0), 1_400)
        let boundedMinimum = min(max(minimumSize, 0), boundedMaximum)
        return try sendLock.withLock {
            try (0..<boundedCount).map { _ in
                let requested = boundedMinimum < boundedMaximum
                    ? Int.random(in: boundedMinimum...boundedMaximum)
                    : boundedMinimum
                let bodyLength = min(max(requested, 1), UDPFragmentation.maxChunk)
                let junk = try Self.junkDatagram(bodyLength: bodyLength)
                return try encodeLocked(payload: junk, longHeader: true)
            }
        }
    }

    /// Removes obfs and QUIC but intentionally leaves Qeli fragment/control framing.
    /// Useful for path-MTU probing before the record data plane starts.
    func decodePayload(_ datagram: Data) throws -> Data {
        var payload = datagram
        if let obfsKey { payload = try ObfsDatagramCipher.open(payload, key: obfsKey) }
        if quicEnabled {
            guard let unwrapped = QUICMask.unwrap(payload) else { throw UDPDatagramCodecError.invalidQUICPacket }
            payload = Data(unwrapped)
        }
        return payload
    }

    /// Consumes one complete UDP datagram. Malformed input is reported to the
    /// caller, which should drop it (UDP corruption must not desynchronise a tunnel).
    func ingest(datagram: Data) throws -> UDPDatagramEvent {
        let payload = try decodePayload(datagram)
        if UDPFragmentation.isJunk(payload) { return .junk }
        if UDPFragmentation.isMTUProbe(payload), let value = UDPFragmentation.parseMTUProbe(payload) {
            return .mtuProbe(id: value.id, outerSize: value.outerSize)
        }
        if UDPFragmentation.isMTUProbeAck(payload), let value = UDPFragmentation.parseMTUProbe(payload) {
            return .mtuProbeAck(id: value.id, outerSize: value.outerSize)
        }

        return try receiveLock.withLock {
            if UDPFragmentation.isFragment(payload) {
                do {
                    guard let full = try reassembler.push(payload) else { return .fragmentPending }
                    reassembler = UDPFragmentation.Reassembler()
                    return .records(try Self.sliceTLSRecords(full))
                } catch {
                    // A new handshake/retransmit must not inherit poisoned fragment state.
                    reassembler = UDPFragmentation.Reassembler()
                    throw error
                }
            }
            reassembler = UDPFragmentation.Reassembler()
            return .records(try Self.sliceTLSRecords(payload))
        }
    }

    private func encodeLocked(payload: Data, longHeader: Bool) throws -> Data {
        let masked: Data
        if quicEnabled {
            if longHeader {
                masked = try QUICMask.wrapLong(
                    payload,
                    connectionID: connectionID,
                    packetNumber: takePacketNumber(),
                    packetType: 0x02
                )
            } else {
                masked = try QUICMask.wrapShort(
                    payload,
                    connectionID: connectionID,
                    packetNumber: takePacketNumber()
                )
            }
        } else {
            masked = payload
        }
        if let obfsKey { return try ObfsDatagramCipher.seal(masked, key: obfsKey) }
        return masked
    }

    /// Called only while `sendLock` is held.
    private func takePacketNumber() -> UInt32 {
        let value = packetNumber
        packetNumber &+= 1
        return value
    }

    private static func sliceTLSRecords(_ payload: Data) throws -> [Data] {
        var records: [Data] = []
        var offset = 0
        while offset < payload.count {
            guard payload.count - offset >= PacketCodec.tlsHeaderSize else {
                throw UDPDatagramCodecError.truncatedRecordHeader(payload.count - offset)
            }
            let length = (Int(payload[offset + 3]) << 8) | Int(payload[offset + 4])
            let end = offset + PacketCodec.tlsHeaderSize + length
            guard length <= PacketCodec.maxRecordSize, end <= payload.count else {
                throw UDPDatagramCodecError.truncatedRecord(declared: length, available: payload.count - offset - 5)
            }
            records.append(Data(payload[offset..<end]))
            offset = end
        }
        guard !records.isEmpty else { throw UDPDatagramCodecError.emptyPayload }
        return records
    }

    private static func junkDatagram(bodyLength: Int) throws -> Data {
        var body = Data(count: bodyLength)
        let status = body.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bodyLength, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw UDPDatagramCodecError.randomFailure(status) }
        return Data(UDPFragmentation.magic + [UDPFragmentation.junk, 0, 1]) + body
    }
}

enum UDPDatagramCodecError: LocalizedError, Equatable {
    case emptyObfsKey
    case invalidObfsKeyLength(Int)
    case invalidConnectionID
    case invalidQUICPacket
    case emptyPayload
    case truncatedRecordHeader(Int)
    case truncatedRecord(declared: Int, available: Int)
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .emptyObfsKey: return "UDP obfs mode requires a non-empty obfs_key."
        case .invalidObfsKeyLength(let count): return "UDP obfs key is \(count) bytes; expected 32."
        case .invalidConnectionID: return "QUIC masking requires a four-byte connection ID."
        case .invalidQUICPacket: return "Malformed QUIC-masked UDP datagram."
        case .emptyPayload: return "UDP datagram has no Qeli records."
        case .truncatedRecordHeader(let count): return "UDP datagram ends with a \(count)-byte record header."
        case .truncatedRecord(let declared, let available):
            return "UDP record declares \(declared) bytes but only \(available) are available."
        case .randomFailure(let status): return "Secure random generator failed (\(status))."
        }
    }
}
