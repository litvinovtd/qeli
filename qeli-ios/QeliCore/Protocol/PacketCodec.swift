import Foundation
import Security
import CryptoKit
@testable import Qeli

final class PacketCodec: @unchecked Sendable {
    static let tlsHeaderSize = 5
    static let nonceSize = 12
    static let tagSize = 16
    static let counterSize = 8
    static let replayWindow = 2_048
    static let replayWords = replayWindow / 64
    static let applicationData: UInt8 = 0x17
    static let maxRecordSize = 16_384 + nonceSize + tagSize + counterSize + 256

    private let cipher: PacketCipher
    private let rawFraming: Bool
    private let lock = NSLock()
    private var paddingEnabled: Bool
    private var paddingMin: Int
    private var paddingMax: Int
    private var counter: UInt64 = 0
    private var replayHighest: UInt64?
    private var replayBits = Array(repeating: UInt64(0), count: replayWords)
    // M6: per-instance nonce seed (4B) + PRP key (32B). The nonce goes on the wire and the peer
    // never inverts the PRP (it reads the nonce off the wire), so these are local randomness that
    // need NOT match the peer's — they only make (seed‖counter) unique per key, which a monotonic
    // counter + fresh per-session key guarantee.
    private let nonceSeed: Data
    private let noncePrpKey: Data

    init(
        cipher: PacketCipher,
        paddingEnabled: Bool = true,
        paddingMin: Int = 0,
        paddingMax: Int = 255,
        rawFraming: Bool = false
    ) {
        self.cipher = cipher
        self.paddingEnabled = paddingEnabled
        self.paddingMin = paddingMin
        self.paddingMax = paddingMax
        self.rawFraming = rawFraming
        self.nonceSeed = Self.secureRandom(4)
        self.noncePrpKey = Self.secureRandom(32)
    }

    var headerSize: Int { rawFraming ? 2 : Self.tlsHeaderSize }

    func setPadding(enabled: Bool, minimum: Int, maximum: Int) {
        lock.withLock {
            paddingEnabled = enabled
            paddingMin = minimum
            paddingMax = maximum
        }
    }

    func encrypt(_ plaintext: Data) throws -> Data {
        let padding = lock.withLock { () -> Int in
            guard paddingEnabled else { return 0 }
            let low = min(max(paddingMin, 0), 65_535)
            let high = min(max(paddingMax, low), 65_535)
            return high > low ? Int.random(in: low...high) : low
        }
        return try encrypt(plaintext, explicitPadding: padding)
    }

    func encryptCapped(_ plaintext: Data, maxInnerAndPadding: Int) throws -> Data {
        let padding = lock.withLock { () -> Int in
            guard paddingEnabled else { return 0 }
            let room = max(0, maxInnerAndPadding - plaintext.count)
            let low = min(max(paddingMin, 0), room)
            let high = min(max(paddingMax, low), room)
            return high > low ? Int.random(in: low...high) : low
        }
        return try encrypt(plaintext, explicitPadding: padding)
    }

    func encrypt(_ plaintext: Data, explicitPadding: Int) throws -> Data {
        let sequence = try lock.withLock { () throws -> UInt64 in
            guard counter < UInt64(Int64.max - 1_000) else { throw PacketCodecError.counterExhausted }
            defer { counter += 1 }
            return counter
        }
        let paddingLength = min(max(explicitPadding, 0), 65_535)
        // Counter-derived, collision-free, DPI-opaque nonce (was a random 96-bit value, which
        // carries a birthday-bound collision risk the Rust core eliminates). (client-audit M6)
        let nonce = nonceFor(sequence)
        let padding = try Self.randomData(count: paddingLength)
        var inner = Data()
        inner.reserveCapacity(Self.counterSize + plaintext.count + paddingLength + 2)
        inner.appendBigEndian(sequence)
        inner.append(plaintext)
        inner.append(padding)
        inner.append(UInt8((paddingLength >> 8) & 0xff))
        inner.append(UInt8(paddingLength & 0xff))

        let encrypted = try cipher.encrypt(inner, nonce: nonce)
        let payloadLength = nonce.count + encrypted.count
        guard payloadLength <= Self.maxRecordSize, payloadLength <= 65_535 else {
            throw PacketCodecError.recordTooLarge(payloadLength)
        }
        var record = Data()
        record.reserveCapacity(headerSize + payloadLength)
        if rawFraming {
            record.append(UInt8((payloadLength >> 8) & 0xff))
            record.append(UInt8(payloadLength & 0xff))
        } else {
            record.append(contentsOf: [
                Self.applicationData, 0x03, 0x03,
                UInt8((payloadLength >> 8) & 0xff), UInt8(payloadLength & 0xff)
            ])
        }
        record.append(nonce)
        record.append(encrypted)
        return record
    }

    func decrypt(_ packet: Data) throws -> Data {
        let minimum = headerSize + Self.nonceSize + Self.tagSize + Self.counterSize + 2
        guard packet.count >= minimum else { throw PacketCodecError.packetTooShort(packet.count) }
        if !rawFraming, packet[0] != Self.applicationData {
            throw PacketCodecError.wrongContentType(packet[0])
        }
        // The legacy_record_version too, not just the content type. Every record we EMIT
        // carries 0x03 0x03, and a real TLS 1.3 peer emits nothing else on an established
        // connection — so accepting other bytes made the masking framing looser than the thing
        // it imitates, for no gain. (Audit 2026-08-03, P3.)
        if !rawFraming, packet[1] != 0x03 || packet[2] != 0x03 {
            throw PacketCodecError.wrongContentType(packet[1])
        }
        let payloadLength = rawFraming
            ? (Int(packet[0]) << 8) | Int(packet[1])
            : (Int(packet[3]) << 8) | Int(packet[4])
        guard payloadLength <= Self.maxRecordSize else { throw PacketCodecError.recordTooLarge(payloadLength) }
        guard payloadLength >= Self.nonceSize + Self.tagSize + Self.counterSize + 2,
              headerSize + payloadLength == packet.count else {
            throw PacketCodecError.recordLengthMismatch(
                declared: payloadLength,
                available: packet.count - headerSize
            )
        }
        let nonceRange = headerSize..<(headerSize + Self.nonceSize)
        let encryptedRange = (headerSize + Self.nonceSize)..<(headerSize + payloadLength)
        let decrypted = try cipher.decrypt(packet[encryptedRange], nonce: packet[nonceRange])
        guard decrypted.count >= Self.counterSize + 2 else { throw PacketCodecError.truncatedPlaintext }

        let sequence = decrypted.prefix(Self.counterSize).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        let paddingLength = (Int(decrypted[decrypted.count - 2]) << 8) | Int(decrypted[decrypted.count - 1])
        guard Self.counterSize + paddingLength + 2 <= decrypted.count else {
            throw PacketCodecError.invalidPadding(paddingLength)
        }
        // Authenticate and validate the complete record before mutating replay state.
        // Otherwise a malformed packet could consume a fresh sequence number and make
        // a later canonical packet with that sequence look like a replay.
        try lock.withLock {
            guard acceptCounter(sequence) else { throw PacketCodecError.replay(sequence) }
        }
        let dataEnd = decrypted.count - paddingLength - 2
        return decrypted[Self.counterSize..<dataEnd]
    }

    /// True if `sequence` is fresh (not a replay / not too old); records it as seen.
    /// `internal` so the shared replay-window fixture (`conformance/replay-window.json`)
    /// can drive it directly — the window is pure state, and going through `decrypt`
    /// would need a valid record per sequence number.
    func acceptCounter(_ sequence: UInt64) -> Bool {
        guard let highest = replayHighest else {
            replayHighest = sequence
            replayBits[0] = 1
            return true
        }
        if sequence > highest {
            let advance = sequence - highest
            if advance >= UInt64(Self.replayWindow) {
                replayBits = Array(repeating: 0, count: Self.replayWords)
            } else {
                shiftWindow(Int(advance))
            }
            replayHighest = sequence
            replayBits[0] |= 1
            return true
        }
        let distance = highest - sequence
        guard distance < UInt64(Self.replayWindow) else { return false }
        let word = Int(distance / 64)
        let mask = UInt64(1) << UInt64(distance % 64)
        guard replayBits[word] & mask == 0 else { return false }
        replayBits[word] |= mask
        return true
    }

    private func shiftWindow(_ bits: Int) {
        let words = bits / 64
        let offset = bits % 64
        if offset == 0 {
            for index in stride(from: Self.replayWords - 1, through: 0, by: -1) {
                replayBits[index] = index >= words ? replayBits[index - words] : 0
            }
        } else {
            for index in stride(from: Self.replayWords - 1, through: 0, by: -1) {
                let low = index >= words ? replayBits[index - words] << UInt64(offset) : 0
                let high = index > words ? replayBits[index - words - 1] >> UInt64(64 - offset) : 0
                replayBits[index] = low | high
            }
        }
    }

    // ── M6: counter-derived data-plane nonce (mirrors Rust packet.rs / C# PacketCodec) ──
    /// Build the 96-bit wire nonce for `counter` as PRP(seed(4) ‖ counter_be(8)). A balanced
    /// Feistel network is bijective for any round function, so distinct (seed,counter) inputs —
    /// counter is monotonic — always map to distinct nonces (no AEAD reuse), while the on-wire
    /// value no longer increments by 1 (no visible-counter DPI tell).
    private func nonceFor(_ counter: UInt64) -> Data {
        Self.prpNonce(key: noncePrpKey, raw: Self.rawNonce(seed: nonceSeed, counter: counter))
    }

    /// The pre-permutation nonce input: seed(4) ‖ counter big-endian(8). Split out of
    /// `nonceFor` so the whole derivation is checkable against the shared fixture
    /// (`conformance/prp-nonce.json`) without constructing a codec.
    static func rawNonce(seed: Data, counter: UInt64) -> Data {
        var raw = Data()
        raw.reserveCapacity(nonceSize)
        raw.append(seed)               // 4 bytes
        raw.appendBigEndian(counter)   // 8 bytes
        return raw
    }

    /// 96-bit balanced Feistel permutation, 4 rounds; round fn = SHA256(key‖round‖half)[..6].
    /// Byte-for-byte identical to Rust `packet.rs prp_nonce` (not required for interop — the peer
    /// reads the nonce straight off the wire — but kept identical for auditability).
    static func prpNonce(key: Data, raw: Data) -> Data {
        let bytes = [UInt8](raw)
        var l = Array(bytes[0..<6])
        var r = Array(bytes[6..<12])
        for round in UInt8(0)..<UInt8(4) {
            let f = prpRound(key: key, round: round, half: r)
            var nr = [UInt8](repeating: 0, count: 6)
            for i in 0..<6 { nr[i] = l[i] ^ f[i] }
            l = r
            r = nr
        }
        return Data(l + r)
    }

    private static func prpRound(key: Data, round: UInt8, half: [UInt8]) -> [UInt8] {
        var input = Data()
        input.append(key)
        input.append(round)
        input.append(contentsOf: half)
        let digest = SHA256.hash(data: input)
        return Array(digest.prefix(6))
    }

    /// Non-throwing secure random for the init-time nonce seed / PRP key. SecRandomCopyBytes
    /// effectively never fails on iOS; the fallback only guarantees distinct per-instance
    /// material (nonce uniqueness needs distinct seeds, not CSPRNG-grade for this field).
    private static func secureRandom(_ count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        if status != errSecSuccess {
            for i in 0..<count { data[i] = UInt8.random(in: 0...255) }
        }
        return data
    }

    private static func randomData(count: Int) throws -> Data {
        if count == 0 { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw PacketCodecError.randomFailure(status) }
        return data
    }
}

enum PacketCodecError: LocalizedError {
    case counterExhausted
    case packetTooShort(Int)
    case wrongContentType(UInt8)
    case recordTooLarge(Int)
    case recordLengthMismatch(declared: Int, available: Int)
    case truncatedPlaintext
    case invalidPadding(Int)
    case replay(UInt64)
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .counterExhausted: return "Packet counter exhausted; reconnect required."
        case .packetTooShort(let count): return "Packet is too short (\(count) bytes)."
        case .wrongContentType(let value): return "Unexpected TLS content type \(value)."
        case .recordTooLarge(let count): return "Record payload is too large (\(count) bytes)."
        case .recordLengthMismatch(let declared, let available):
            return "Record length mismatch (declared \(declared), available \(available))."
        case .truncatedPlaintext: return "Decrypted packet is truncated."
        case .invalidPadding(let count): return "Invalid packet padding length \(count)."
        case .replay(let sequence): return "Replay detected for packet \(sequence)."
        case .randomFailure(let status): return "Secure random generator failed (\(status))."
        }
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt64) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}
