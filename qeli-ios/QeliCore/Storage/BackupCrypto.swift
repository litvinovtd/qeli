import CryptoKit
import Foundation
import Security

enum BackupCrypto {
    static let magic = "QELI-ENC-1"
    static let iterations = 210_000
    private static let maximumAcceptedIterations = 1_000_000
    private static let saltLength = 16
    private static let nonceLength = 12

    static func isEncrypted(_ data: Data) -> Bool {
        data.starts(with: Data(magic.utf8))
    }

    static func encrypt(_ plaintext: Data, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw BackupCryptoError.passphraseRequired }
        let salt = try randomData(count: saltLength)
        let nonceData = try randomData(count: nonceLength)
        let rawKey = pbkdf2SHA256(
            password: Data(passphrase.utf8),
            salt: salt,
            iterations: iterations,
            outputLength: 32
        )
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: rawKey), nonce: nonce)
        let ciphertextAndTag = sealed.ciphertext + sealed.tag
        let envelope = [
            magic,
            String(iterations),
            salt.base64EncodedString(),
            nonceData.base64EncodedString(),
            ciphertextAndTag.base64EncodedString()
        ].joined(separator: "\n")
        return Data(envelope.utf8)
    }

    static func decrypt(_ envelope: Data, passphrase: String) throws -> Data {
        guard !passphrase.isEmpty else { throw BackupCryptoError.passphraseRequired }
        guard let text = String(data: envelope, encoding: .utf8) else {
            throw BackupCryptoError.invalidEnvelope
        }
        let lines = text.components(separatedBy: "\n")
        guard lines.count >= 5,
              lines[0] == magic,
              let rounds = Int(lines[1]), (1...maximumAcceptedIterations).contains(rounds),
              let salt = Data(base64Encoded: lines[2]), salt.count == saltLength,
              let nonceData = Data(base64Encoded: lines[3]), nonceData.count == nonceLength,
              let ciphertextAndTag = Data(base64Encoded: lines[4]), ciphertextAndTag.count >= 16 else {
            throw BackupCryptoError.invalidEnvelope
        }
        let key = pbkdf2SHA256(
            password: Data(passphrase.utf8),
            salt: salt,
            iterations: rounds,
            outputLength: 32
        )
        let split = ciphertextAndTag.count - 16
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonceData),
            ciphertext: ciphertextAndTag.prefix(split),
            tag: ciphertextAndTag.suffix(16)
        )
        do {
            return try AES.GCM.open(box, using: SymmetricKey(data: key))
        } catch {
            throw BackupCryptoError.authenticationFailed
        }
    }

    /// PBKDF2-HMAC-SHA256 implemented with CryptoKit so the backup envelope remains
    /// byte-compatible with Android without adding a binary CommonCrypto dependency.
    static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        outputLength: Int
    ) -> Data {
        precondition(iterations > 0 && outputLength > 0)
        let key = SymmetricKey(data: password)
        let digestLength = SHA256.byteCount
        let blockCount = (outputLength + digestLength - 1) / digestLength
        var result = Data()
        result.reserveCapacity(blockCount * digestLength)

        for block in 1...blockCount {
            var blockIndex = UInt32(block).bigEndian
            var initial = salt
            withUnsafeBytes(of: &blockIndex) { initial.append(contentsOf: $0) }
            var u = Data(HMAC<SHA256>.authenticationCode(for: initial, using: key))
            var accumulator = u
            if iterations > 1 {
                for _ in 2...iterations {
                    u = Data(HMAC<SHA256>.authenticationCode(for: u, using: key))
                    accumulator.xorInPlace(with: u)
                }
            }
            result.append(accumulator)
        }
        return result.prefix(outputLength)
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw BackupCryptoError.randomFailure(status) }
        return data
    }
}

enum BackupCryptoError: LocalizedError {
    case passphraseRequired
    case invalidEnvelope
    case authenticationFailed
    case randomFailure(OSStatus)

    var errorDescription: String? {
        switch self {
        case .passphraseRequired: return "Passphrase required."
        case .invalidEnvelope: return "Not an encrypted Qeli backup."
        case .authenticationFailed: return "Wrong passphrase or corrupt backup."
        case .randomFailure(let status): return "Secure random generator failed (\(status))."
        }
    }
}

private extension Data {
    mutating func xorInPlace(with other: Data) {
        precondition(count == other.count)
        let byteCount = count
        withUnsafeMutableBytes { destination in
            other.withUnsafeBytes { source in
                guard let dst = destination.bindMemory(to: UInt8.self).baseAddress,
                      let src = source.bindMemory(to: UInt8.self).baseAddress else { return }
                for index in 0..<byteCount { dst[index] ^= src[index] }
            }
        }
    }
}
