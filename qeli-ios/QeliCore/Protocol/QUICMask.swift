import Foundation
import Security
@testable import QeliIOS

enum QUICMask {
    /// Bytes ``wrapShort(_:connectionID:packetNumber:)`` emits ahead of the payload: flags(1) +
    /// connection id(4) + packet number(4). This is the DATA-plane header; the handshake uses
    /// the longer long-header form. The path-MTU probe budgets for it.
    static let shortHeaderMin = 1 + 4 + 4

    static func connectionID() throws -> Data {
        var value = Data(count: 4)
        let status = value.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 4, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw QUICMaskError.randomFailure(status) }
        return value
    }

    static func wrapLong(
        _ payload: Data,
        connectionID: Data,
        packetNumber: UInt32
    ) throws -> Data {
        guard connectionID.count == 4 else { throw QUICMaskError.invalidConnectionID }
        var output = Data([0xc3])
        output.appendBigEndian(UInt32(1))
        output.append(4)
        output.append(connectionID)
        output.append(0)
        try appendVarint(0, to: &output)                        // Token Length varint = 0
        try appendVarint(UInt64(4 + payload.count), to: &output) // pn(4) + payload
        output.appendBigEndian(packetNumber)
        output.append(payload)
        return output
    }

    static func wrapShort(_ payload: Data, connectionID: Data, packetNumber: UInt32) throws -> Data {
        guard connectionID.count == 4 else { throw QUICMaskError.invalidConnectionID }
        var output = Data([0x43])
        output.append(connectionID)
        output.appendBigEndian(packetNumber)
        output.append(payload)
        return output
    }

    static func unwrap(_ packet: Data) -> Data? {
        guard let first = packet.first else { return nil }
        return first & 0x80 != 0 ? unwrapLong(packet) : unwrapShort(packet)
    }

    private static func unwrapLong(_ packet: Data) -> Data? {
        guard packet.count >= 17,
              packet[0] == 0xc3 || packet[0] == 0xe3,
              packet[1] == 0, packet[2] == 0, packet[3] == 0, packet[4] == 1 else {
            return nil
        }
        var offset = 5
        let destinationLength = Int(packet[offset]); offset += 1
        guard destinationLength == 4, offset + destinationLength <= packet.count else { return nil }
        offset += destinationLength
        guard offset < packet.count else { return nil }
        let sourceLength = Int(packet[offset]); offset += 1
        guard sourceLength == 0,
              let tokenLength = readVarint(packet, offset: &offset), tokenLength == 0,
              let declaredLength = readVarint(packet, offset: &offset),
              declaredLength >= 4, declaredLength == UInt64(packet.count - offset) else { return nil }
        offset += 4
        return packet.dropFirst(offset)
    }

    private static func unwrapShort(_ packet: Data) -> Data? {
        guard packet.count >= 9 else { return nil }
        guard packet[0] == 0x43 else { return nil }
        let offset = 1 + 4 + 4
        guard offset <= packet.count else { return nil }
        return packet.dropFirst(offset)
    }

    private static func readVarint(_ data: Data, offset: inout Int) -> UInt64? {
        guard offset < data.count else { return nil }
        let first = data[offset]
        let length = 1 << Int(first >> 6)
        guard offset + length <= data.count else { return nil }
        var value = UInt64(first & 0x3f)
        if length > 1 {
            for index in 1..<length { value = (value << 8) | UInt64(data[offset + index]) }
        }
        offset += length
        return value
    }
}

enum QUICMaskError: Error {
    case invalidConnectionID
    case randomFailure(OSStatus)
    case varintOutOfRange(UInt64)
}

/// Append a QUIC variable-length integer in its SHORTEST form (RFC 9000 §16), mirroring
/// `quic.rs::push_varint`.
///
/// This port used to emit the Length field as a fixed 2-byte varint with a silent
/// `& 0x3fff` truncation. Two problems. The truncation is the "unreachable now, corrupt
/// later" class Rust fixed in audit 2026-07-27 (F5). More immediately, every real QUIC stack
/// encodes minimally, so a datagram whose Length is padded to two bytes when one would do is
/// a static per-packet deviation from genuine QUIC — and reading as genuine QUIC is the
/// entire purpose of the mask. (Audit 2026-08-04.)
private func appendVarint(_ value: UInt64, to output: inout Data) throws {
    switch value {
    case ..<0x40:
        output.append(UInt8(value))
    case ..<0x4000:
        output.append(UInt8(0x40 | (value >> 8)))
        output.append(UInt8(value & 0xff))
    case ..<0x4000_0000:
        output.append(UInt8(0x80 | (value >> 24)))
        output.append(UInt8((value >> 16) & 0xff))
        output.append(UInt8((value >> 8) & 0xff))
        output.append(UInt8(value & 0xff))
    default:
        // Rust returns false here and the caller fails the wrap; silently truncating is
        // what this code used to do and is exactly what must not happen.
        throw QUICMaskError.varintOutOfRange(value)
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt32) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}
