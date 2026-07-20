import Foundation
import Security

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
        let nonce = try Self.randomData(count: Self.nonceSize)
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
        let payloadLength = rawFraming
            ? (Int(packet[0]) << 8) | Int(packet[1])
            : (Int(packet[3]) << 8) | Int(packet[4])
        guard payloadLength <= Self.maxRecordSize else { throw PacketCodecError.recordTooLarge(payloadLength) }
        guard payloadLength >= Self.nonceSize + Self.tagSize + Self.counterSize + 2,
              headerSize + payloadLength <= packet.count else {
            throw PacketCodecError.truncatedRecord
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

    private func acceptCounter(_ sequence: UInt64) -> Bool {
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
    case truncatedRecord
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
        case .truncatedRecord: return "Record is truncated."
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
