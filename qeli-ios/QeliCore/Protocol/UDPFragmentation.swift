import Foundation
import Security

enum UDPFragmentation {
    static let magic: [UInt8] = [0xf0, 0x9b, 0x71]
    static let headerLength = 6
    static let maxChunk = 1_200
    static let maxFragments = 24
    static let clientHello: UInt8 = 1
    static let serverHello: UInt8 = 2
    static let junk: UInt8 = 3
    static let mtuProbe: UInt8 = 4
    static let mtuProbeAck: UInt8 = 5
    static let probeBodyLength = 4

    static func isFragment(_ data: Data) -> Bool {
        data.count >= headerLength && Array(data.prefix(3)) == magic
    }

    static func isJunk(_ data: Data) -> Bool { isFragment(data) && data[3] == junk }
    static func isMTUProbe(_ data: Data) -> Bool {
        isFragment(data) && data[3] == mtuProbe && data.count >= headerLength + probeBodyLength
    }
    static func isMTUProbeAck(_ data: Data) -> Bool {
        isFragment(data) && data[3] == mtuProbeAck && data.count >= headerLength + probeBodyLength
    }

    static func parseMTUProbe(_ data: Data) -> (id: Int, outerSize: Int)? {
        guard data.count >= headerLength + probeBodyLength else { return nil }
        let id = Int(data[headerLength]) | (Int(data[headerLength + 1]) << 8)
        let size = Int(data[headerLength + 2]) | (Int(data[headerLength + 3]) << 8)
        return (id, size)
    }

    static func mtuProbeDatagram(id: Int, outerSize: Int) throws -> Data? {
        let minimum = headerLength + probeBodyLength
        guard (minimum...65_535).contains(outerSize) else { return nil }
        var data = Data(repeating: 0, count: outerSize)
        writeHeader(&data, messageID: mtuProbe, index: 0, count: 1)
        writeProbeBody(&data, id: id, outerSize: outerSize)
        if outerSize > minimum {
            let paddingLength = outerSize - minimum
            var padding = Data(count: paddingLength)
            let status = padding.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, paddingLength, $0.baseAddress!)
            }
            guard status == errSecSuccess else { throw UDPFragmentationError.randomFailure(status) }
            data.replaceSubrange(minimum..<outerSize, with: padding)
        }
        return data
    }

    static func mtuProbeAckDatagram(id: Int, outerSize: Int) -> Data {
        var data = Data(repeating: 0, count: headerLength + probeBodyLength)
        writeHeader(&data, messageID: mtuProbeAck, index: 0, count: 1)
        writeProbeBody(&data, id: id, outerSize: outerSize)
        return data
    }

    static func fragment(messageID: UInt8, message: Data) throws -> [Data] {
        let count = max(1, (message.count + maxChunk - 1) / maxChunk)
        guard count <= maxFragments else { throw UDPFragmentationError.tooManyFragments(count) }
        return (0..<count).map { index in
            let start = index * maxChunk
            let end = min(message.count, start + maxChunk)
            var fragment = Data(magic + [messageID, UInt8(index), UInt8(count)])
            if start < end { fragment.append(message[start..<end]) }
            return fragment
        }
    }

    final class Reassembler {
        private var messageID: UInt8?
        private var expectedCount = 0
        private var parts: [Data?] = []

        func push(_ data: Data) throws -> Data? {
            guard UDPFragmentation.isFragment(data) else { throw UDPFragmentationError.notFragment }
            let incomingID = data[3]
            let index = Int(data[4])
            let count = Int(data[5])
            guard (1...UDPFragmentation.maxFragments).contains(count) else {
                throw UDPFragmentationError.invalidCount
            }
            guard index < count else { throw UDPFragmentationError.invalidIndex }
            guard data.count - UDPFragmentation.headerLength <= UDPFragmentation.maxChunk else {
                throw UDPFragmentationError.chunkTooLarge
            }
            if messageID == nil {
                messageID = incomingID
                expectedCount = count
                parts = Array(repeating: nil, count: count)
            } else if messageID != incomingID || expectedCount != count {
                throw UDPFragmentationError.inconsistentMessage
            }
            if parts[index] == nil { parts[index] = data.dropFirst(UDPFragmentation.headerLength) }
            guard parts.allSatisfy({ $0 != nil }) else { return nil }
            return parts.compactMap { $0 }.reduce(into: Data()) { $0.append($1) }
        }
    }

    private static func writeHeader(_ data: inout Data, messageID: UInt8, index: UInt8, count: UInt8) {
        data[0] = magic[0]; data[1] = magic[1]; data[2] = magic[2]
        data[3] = messageID; data[4] = index; data[5] = count
    }

    private static func writeProbeBody(_ data: inout Data, id: Int, outerSize: Int) {
        data[headerLength] = UInt8(id & 0xff)
        data[headerLength + 1] = UInt8((id >> 8) & 0xff)
        data[headerLength + 2] = UInt8(outerSize & 0xff)
        data[headerLength + 3] = UInt8((outerSize >> 8) & 0xff)
    }
}

enum UDPFragmentationError: Error {
    case notFragment, invalidCount, invalidIndex, chunkTooLarge, inconsistentMessage
    case tooManyFragments(Int)
    case randomFailure(OSStatus)
}
