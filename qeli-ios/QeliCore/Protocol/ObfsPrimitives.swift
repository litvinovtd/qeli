import CryptoKit
import Foundation
import Security

/// Wire-compatible primitives for `qeli/src/protocol/obfs.rs`.
enum QeliObfs {
    static let nonceLength = 12
    static let webSocketMaximumPayload = 16_384
    static let webSocketMaximumReadPayload = 1 << 20
    static let awgJunkCountLimit = 128
    static let awgJunkLengthLimit = 1_400

    /// SHA256("qeli-obfs-key-v1" || UTF8(psk)).
    static func deriveKey(_ preSharedKey: String) -> Data {
        var input = Data("qeli-obfs-key-v1".utf8)
        input.append(Data(preSharedKey.utf8))
        return Data(SHA256.hash(data: input))
    }

    /// Stateless UDP form: QUIC-shaped flag || nonce || ChaCha20(payload).
    static func datagramSeal(key: Data, payload: Data) throws -> Data {
        let nonce = try secureRandom(count: nonceLength)
        let flag = UInt8(0x40) | ((try secureRandom(count: 1))[0] & 0x3f)
        var stream = try QeliChaCha20Keystream(key: key, nonce: nonce)
        return Data([flag]) + nonce + stream.xor(payload)
    }

    static func datagramOpen(key: Data, datagram: Data) throws -> Data? {
        guard datagram.count >= 1 + nonceLength else { return nil }
        let nonceStart = datagram.index(after: datagram.startIndex)
        let nonceEnd = datagram.index(nonceStart, offsetBy: nonceLength)
        let nonce = Data(datagram[nonceStart..<nonceEnd])
        var stream = try QeliChaCha20Keystream(key: key, nonce: nonce)
        return stream.xor(Data(datagram[nonceEnd...]))
    }

    /// One client-to-server RFC 6455 binary frame with a caller-provided mask.
    static func webSocketBinaryFrame(payload: Data, mask: Data) throws -> Data {
        guard mask.count == 4 else { throw QeliObfsError.invalidWebSocketMask }
        var output = Data([0x82])
        appendWebSocketLength(payload.count, masked: true, to: &output)
        output.append(mask)
        for (offset, byte) in payload.enumerated() {
            output.append(byte ^ mask[mask.index(mask.startIndex, offsetBy: offset % 4)])
        }
        return output
    }

    /// Android/Rust writer chunks one logical write into <= 16 KiB masked frames.
    static func webSocketFrames(payload: Data) throws -> Data {
        var output = Data()
        var offset = 0
        repeat {
            let count = min(webSocketMaximumPayload, payload.count - offset)
            let start = payload.index(payload.startIndex, offsetBy: offset)
            let end = payload.index(start, offsetBy: count)
            let chunk = Data(payload[start..<end])
            output.append(try webSocketBinaryFrame(payload: chunk, mask: secureRandom(count: 4)))
            offset += count
        } while offset < payload.count
        return output
    }

    static func secureRandom(count: Int) throws -> Data {
        guard count >= 0 else { throw QeliObfsError.invalidRandomLength }
        guard count > 0 else { return Data() }
        var output = Data(count: count)
        let status = output.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw QeliObfsError.randomFailure(status) }
        return output
    }

    private static func appendWebSocketLength(_ length: Int, masked: Bool, to output: inout Data) {
        let mask: UInt8 = masked ? 0x80 : 0
        if length <= 125 {
            output.append(mask | UInt8(length))
        } else if length <= 65_535 {
            output.append(mask | 126)
            output.append(UInt8((length >> 8) & 0xff))
            output.append(UInt8(length & 0xff))
        } else {
            output.append(mask | 127)
            let value = UInt64(length)
            for shift in stride(from: 56, through: 0, by: -8) {
                output.append(UInt8((value >> UInt64(shift)) & 0xff))
            }
        }
    }
}

/// Stateful IETF ChaCha20 stream, counter=0, continuous across `xor` calls.
struct QeliChaCha20Keystream {
    private let key: [UInt8]
    private let nonce: [UInt8]
    private var counter: UInt32 = 0
    private var block: [UInt8] = []
    private var blockOffset = 0

    init(key: Data, nonce: Data) throws {
        guard key.count == 32 else { throw QeliObfsError.invalidKeyLength(key.count) }
        guard nonce.count == QeliObfs.nonceLength else {
            throw QeliObfsError.invalidNonceLength(nonce.count)
        }
        self.key = Array(key)
        self.nonce = Array(nonce)
    }

    mutating func xor(_ data: Data) -> Data {
        var output = Data(capacity: data.count)
        for byte in data {
            if blockOffset >= block.count {
                block = Self.makeBlock(key: key, counter: counter, nonce: nonce)
                counter &+= 1
                blockOffset = 0
            }
            output.append(byte ^ block[blockOffset])
            blockOffset += 1
        }
        return output
    }

    static func block(key: Data, counter: UInt32, nonce: Data) throws -> Data {
        guard key.count == 32 else { throw QeliObfsError.invalidKeyLength(key.count) }
        guard nonce.count == QeliObfs.nonceLength else {
            throw QeliObfsError.invalidNonceLength(nonce.count)
        }
        return Data(makeBlock(key: Array(key), counter: counter, nonce: Array(nonce)))
    }

    private static func makeBlock(key: [UInt8], counter: UInt32, nonce: [UInt8]) -> [UInt8] {
        var state: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]
        for offset in stride(from: 0, to: 32, by: 4) { state.append(littleEndian(key, offset)) }
        state.append(counter)
        for offset in stride(from: 0, to: 12, by: 4) { state.append(littleEndian(nonce, offset)) }

        var working = state
        for _ in 0..<10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }

        var output: [UInt8] = []
        output.reserveCapacity(64)
        for index in 0..<16 {
            let word = working[index] &+ state[index]
            output += [UInt8(word & 0xff), UInt8((word >> 8) & 0xff),
                       UInt8((word >> 16) & 0xff), UInt8((word >> 24) & 0xff)]
        }
        return output
    }

    private static func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]; state[d] = rotateLeft(state[d] ^ state[a], by: 16)
        state[c] = state[c] &+ state[d]; state[b] = rotateLeft(state[b] ^ state[c], by: 12)
        state[a] = state[a] &+ state[b]; state[d] = rotateLeft(state[d] ^ state[a], by: 8)
        state[c] = state[c] &+ state[d]; state[b] = rotateLeft(state[b] ^ state[c], by: 7)
    }

    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    private static func littleEndian(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8) |
        (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
    }
}

enum QeliObfsError: LocalizedError, Equatable {
    case invalidKeyLength(Int)
    case invalidNonceLength(Int)
    case invalidWebSocketMask
    case invalidRandomLength
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let count): return "Obfs key must be 32 bytes, got \(count)."
        case .invalidNonceLength(let count): return "Obfs nonce must be 12 bytes, got \(count)."
        case .invalidWebSocketMask: return "WebSocket mask must be four bytes."
        case .invalidRandomLength: return "Random byte count cannot be negative."
        case .randomFailure(let status): return "Secure random generation failed (\(status))."
        }
    }
}
