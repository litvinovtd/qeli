import Foundation
import Security

enum QUICMask {
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
        packetNumber: UInt32,
        packetType: UInt8
    ) throws -> Data {
        guard connectionID.count == 4 else { throw QUICMaskError.invalidConnectionID }
        var output = Data([0xc0 | ((packetType & 0x03) << 4) | 0x03])
        output.appendBigEndian(UInt32(1))
        output.append(4)
        output.append(connectionID)
        output.append(0)
        output.append(0)
        let length = (4 + payload.count) & 0x3fff
        output.append(UInt8(0x40 | (length >> 8)))
        output.append(UInt8(length & 0xff))
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
        guard packet.count >= 12 else { return nil }
        let packetNumberLength = Int(packet[0] & 0x03) + 1
        var offset = 5
        let destinationLength = Int(packet[offset]); offset += 1
        guard offset + destinationLength <= packet.count else { return nil }
        offset += destinationLength
        guard offset < packet.count else { return nil }
        let sourceLength = Int(packet[offset]); offset += 1
        guard offset + sourceLength <= packet.count else { return nil }
        offset += sourceLength
        guard let tokenLength = readVarint(packet, offset: &offset),
              tokenLength <= UInt64(packet.count - offset) else { return nil }
        offset += Int(tokenLength)
        guard readVarint(packet, offset: &offset) != nil,
              offset + packetNumberLength <= packet.count else { return nil }
        offset += packetNumberLength
        return packet.dropFirst(offset)
    }

    private static func unwrapShort(_ packet: Data) -> Data? {
        guard packet.count >= 9 else { return nil }
        let packetNumberLength = min(Int(packet[0] & 0x03) + 1, 4)
        let offset = 1 + 4 + packetNumberLength
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
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt32) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}

