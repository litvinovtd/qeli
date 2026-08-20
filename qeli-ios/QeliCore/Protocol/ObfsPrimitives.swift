import CryptoKit
import Foundation
import Security
@testable import QeliIOS

/// Wire-compatible primitives for `qeli/src/protocol/obfs.rs`.
enum QeliObfs {
    static let nonceLength = 12
    static let webSocketMaximumPayload = 16_384
    /// Same as the write cap, matching Rust and C#.
    ///
    /// This was 1 MiB — 64x the reference. The WS frame header rides OVER ChaCha20 (only the
    /// payload is enciphered), so the 2...9 length bytes are chosen by anyone on the path,
    /// and this is the pre-authentication phase: an MITM rewriting the length to 0x100000
    /// made the extension allocate a megabyte and block until it was filled, repeatable on
    /// every reconnect. A legitimate qeli server never emits a frame above
    /// `webSocketMaximumPayload`, so 16385...1048576 was pure attack surface.
    /// (Audit 2026-08-04.)
    static let webSocketMaximumReadPayload = webSocketMaximumPayload
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
        return Data([flag]) + nonce + (try stream.xor(payload))
    }

    static func datagramOpen(key: Data, datagram: Data) throws -> Data? {
        guard datagram.count >= 1 + nonceLength else { return nil }
        let nonceStart = datagram.index(after: datagram.startIndex)
        let nonceEnd = datagram.index(nonceStart, offsetBy: nonceLength)
        let nonce = Data(datagram[nonceStart..<nonceEnd])
        var stream = try QeliChaCha20Keystream(key: key, nonce: nonce)
        return try stream.xor(Data(datagram[nonceEnd...]))
    }

    /// The WebSocket endpoint path, derived from the obfs PSK. Byte-identical to Rust
    /// `ws::derive_path` and to the Kotlin/C# ports: the first 18 bytes of
    /// HKDF-SHA256(ikm=key, salt=empty, info="qeli-ws-path-v1"), url-safe base64 (24 chars,
    /// no padding), prefixed with '/'.
    ///
    /// Replaces the per-connection RANDOM path. The server used to upgrade on ANY
    /// request-target, so a correct Upgrade to /aZ8k2Qx came back `101` — which a server
    /// presenting itself as nginx never does for a location nobody configured. A fresh
    /// random path per connection was independently wrong: a real WebSocket service has one
    /// stable endpoint, not a stream of never-repeating targets. 24 chars keep the
    /// request-line's printable run well past the 20-byte FET exemption threshold, which is
    /// what the random path was also buying. (Audit 2026-08-04, M-06.)
    static func webSocketPath(key: Data) -> String {
        let raw = hkdfExpand(ikm: key, info: Data("qeli-ws-path-v1".utf8), count: 18)
        // 18 bytes → exactly 24 base64 chars, so there is never any '=' to strip.
        let b64 = raw.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        return "/" + b64
    }

    /// HKDF-SHA256 (RFC 5869) with an all-zero salt: extract then expand.
    private static func hkdfExpand(ikm: Data, info: Data, count: Int) -> Data {
        let prk = HMAC<SHA256>.authenticationCode(
            for: ikm, using: SymmetricKey(data: Data(repeating: 0, count: 32)))
        let prkKey = SymmetricKey(data: Data(prk))
        var output = Data()
        var block = Data()
        var counter: UInt8 = 1
        while output.count < count {
            var message = block
            message.append(info)
            message.append(counter)
            block = Data(HMAC<SHA256>.authenticationCode(for: message, using: prkKey))
            output.append(block.prefix(count - output.count))
            counter += 1
        }
        return output
    }

    /// One client-to-server RFC 6455 control frame (FIN=1, `opcode`). RFC 6455 §5.5 caps a
    /// control payload at 125 bytes and forbids fragmenting it, so an over-long echo is
    /// truncated rather than emitted illegally.
    static func webSocketControlFrame(opcode: UInt8, payload: Data, mask: Data) throws -> Data {
        guard mask.count == 4 else { throw QeliObfsError.invalidWebSocketMask }
        let body = Data(payload.prefix(125))
        var output = Data([0x80 | (opcode & 0x0f), UInt8(0x80 | body.count)])
        output.append(mask)
        for (offset, byte) in body.enumerated() {
            output.append(byte ^ mask[mask.index(mask.startIndex, offsetBy: offset % 4)])
        }
        return output
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

    /// Throws once the 2^32 block counter is exhausted rather than wrapping.
    ///
    /// `counter &+= 1` silently wrapped to 0, restarting the keystream from the first
    /// block under the SAME (key, nonce). Two ciphertexts then share keystream and XOR to
    /// the plaintexts — a total loss of confidentiality for that stream, reached after
    /// 2^32 × 64 B = 256 GiB in one direction on a long-lived obfs-TCP session. Every
    /// other implementation already refuses: the Rust core (`protocol/obfs.rs`), the
    /// Android client, and the OTHER Swift ChaCha20 in this very module
    /// (`ObfsDatagramCipher`, which throws `counterExhausted`). This one was the outlier.
    /// (Audit 2026-07-27, F6.)
    mutating func xor(_ data: Data) throws -> Data {
        var output = Data(capacity: data.count)
        for byte in data {
            if blockOffset >= block.count {
                block = Self.makeBlock(key: key, counter: counter, nonce: nonce)
                guard counter != UInt32.max else { throw QeliObfsError.counterExhausted }
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
    /// The ChaCha20 block counter reached 2^32; continuing would reuse keystream.
    case counterExhausted

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let count): return "Obfs key must be 32 bytes, got \(count)."
        case .invalidNonceLength(let count): return "Obfs nonce must be 12 bytes, got \(count)."
        case .counterExhausted:
            return "Obfs keystream exhausted (2^32 blocks) — the session must be renegotiated."
        case .invalidWebSocketMask: return "WebSocket mask must be four bytes."
        case .invalidRandomLength: return "Random byte count cannot be negative."
        case .randomFailure(let status): return "Secure random generation failed (\(status))."
        }
    }
}
