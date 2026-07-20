import CryptoKit
import Foundation
import Security

/// Stateless UDP obfuscation used by Qeli's `obfs` wire mode.
///
/// Wire format: `quic-shaped flag(1) || nonce(12) || ChaCha20(payload)`.
/// This deliberately uses unauthenticated ChaCha20, rather than ChaChaPoly: the
/// encrypted Qeli record inside the datagram already provides authentication and
/// replay protection. Keeping the outer transform stateless preserves UDP loss and
/// reordering semantics and is byte-compatible with the Rust and Android clients.
enum ObfsDatagramCipher {
    static let nonceLength = 12
    static let flagLength = 1

    static func deriveKey(_ preSharedKey: String) -> Data {
        var material = Data("qeli-obfs-key-v1".utf8)
        material.append(Data(preSharedKey.utf8))
        return Data(SHA256.hash(data: material))
    }

    static func seal(_ payload: Data, key: Data) throws -> Data {
        let nonce = try secureRandom(count: nonceLength)
        let randomFlag = try secureRandom(count: 1)[0] & 0x3f
        var result = Data([0x40 | randomFlag])
        result.append(nonce)
        result.append(try ChaCha20Stream.xor(payload, key: key, nonce: nonce))
        return result
    }

    /// Deterministic form used by interoperability tests and packet captures.
    static func seal(_ payload: Data, key: Data, nonce: Data, flag: UInt8) throws -> Data {
        guard nonce.count == nonceLength else { throw ObfsDatagramError.invalidNonceLength(nonce.count) }
        var result = Data([0x40 | (flag & 0x3f)])
        result.append(nonce)
        result.append(try ChaCha20Stream.xor(payload, key: key, nonce: nonce))
        return result
    }

    static func open(_ datagram: Data, key: Data) throws -> Data {
        guard datagram.count >= flagLength + nonceLength else {
            throw ObfsDatagramError.truncatedDatagram(datagram.count)
        }
        let nonceStart = datagram.index(after: datagram.startIndex)
        let nonceEnd = datagram.index(nonceStart, offsetBy: nonceLength)
        let nonce = Data(datagram[nonceStart..<nonceEnd])
        return try ChaCha20Stream.xor(Data(datagram[nonceEnd...]), key: key, nonce: nonce)
    }

    private static func secureRandom(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw ObfsDatagramError.randomFailure(status) }
        return data
    }
}

enum ObfsDatagramError: LocalizedError, Equatable {
    case invalidKeyLength(Int)
    case invalidNonceLength(Int)
    case truncatedDatagram(Int)
    case counterExhausted
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let count): return "UDP obfs key is \(count) bytes; expected 32."
        case .invalidNonceLength(let count): return "UDP obfs nonce is \(count) bytes; expected 12."
        case .truncatedDatagram(let count): return "UDP obfs datagram is truncated (\(count) bytes)."
        case .counterExhausted: return "UDP obfs ChaCha20 counter exhausted."
        case .randomFailure(let status): return "Secure random generator failed (\(status))."
        }
    }
}

/// RFC 8439 ChaCha20 with the IETF 96-bit nonce and an initial counter of zero.
private enum ChaCha20Stream {
    private static let constants: [UInt32] = [
        0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574
    ]

    static func xor(_ input: Data, key: Data, nonce: Data) throws -> Data {
        guard key.count == 32 else { throw ObfsDatagramError.invalidKeyLength(key.count) }
        guard nonce.count == 12 else { throw ObfsDatagramError.invalidNonceLength(nonce.count) }

        let keyBytes = [UInt8](key)
        let nonceBytes = [UInt8](nonce)
        let source = [UInt8](input)
        var destination = Array(repeating: UInt8(0), count: source.count)
        let keyWords = stride(from: 0, to: 32, by: 4).map { littleEndianWord(keyBytes, at: $0) }
        let nonceWords = stride(from: 0, to: 12, by: 4).map { littleEndianWord(nonceBytes, at: $0) }

        var blockCounter: UInt32 = 0
        var offset = 0
        while offset < source.count {
            let stream = block(keyWords: keyWords, nonceWords: nonceWords, counter: blockCounter)
            let count = min(64, source.count - offset)
            for index in 0..<count { destination[offset + index] = source[offset + index] ^ stream[index] }
            offset += count
            if offset < source.count {
                guard blockCounter != UInt32.max else { throw ObfsDatagramError.counterExhausted }
                blockCounter &+= 1
            }
        }
        return Data(destination)
    }

    private static func block(keyWords: [UInt32], nonceWords: [UInt32], counter: UInt32) -> [UInt8] {
        let initial = constants + keyWords + [counter] + nonceWords
        var working = initial
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
            let value = working[index] &+ initial[index]
            output.append(UInt8(value & 0xff))
            output.append(UInt8((value >> 8) & 0xff))
            output.append(UInt8((value >> 16) & 0xff))
            output.append(UInt8((value >> 24) & 0xff))
        }
        return output
    }

    private static func quarterRound(
        _ state: inout [UInt32], _ ai: Int, _ bi: Int, _ ci: Int, _ di: Int
    ) {
        var a = state[ai], b = state[bi], c = state[ci], d = state[di]
        a &+= b; d ^= a; d = rotateLeft(d, by: 16)
        c &+= d; b ^= c; b = rotateLeft(b, by: 12)
        a &+= b; d ^= a; d = rotateLeft(d, by: 8)
        c &+= d; b ^= c; b = rotateLeft(b, by: 7)
        state[ai] = a; state[bi] = b; state[ci] = c; state[di] = d
    }

    private static func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }

    private static func littleEndianWord(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}
