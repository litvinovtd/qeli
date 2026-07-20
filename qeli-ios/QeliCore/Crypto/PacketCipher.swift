import CryptoKit
import Foundation

struct PacketCipher: Sendable {
    static let nonceSize = 12
    static let tagSize = 16
    private let key: SymmetricKey

    init(key: Data) throws {
        guard key.count == 32 else { throw PacketCipherError.invalidKeyLength(key.count) }
        self.key = SymmetricKey(data: key)
    }

    func encrypt(_ plaintext: Data, nonce: Data) throws -> Data {
        guard nonce.count == Self.nonceSize else { throw PacketCipherError.invalidNonce }
        let sealed = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: ChaChaPoly.Nonce(data: nonce)
        )
        return sealed.ciphertext + sealed.tag
    }

    func decrypt(_ ciphertextAndTag: Data, nonce: Data) throws -> Data {
        guard nonce.count == Self.nonceSize else { throw PacketCipherError.invalidNonce }
        guard ciphertextAndTag.count >= Self.tagSize else { throw PacketCipherError.truncatedCiphertext }
        let split = ciphertextAndTag.count - Self.tagSize
        let box = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertextAndTag.prefix(split),
            tag: ciphertextAndTag.suffix(Self.tagSize)
        )
        return try ChaChaPoly.open(box, using: key)
    }
}

enum PacketCipherError: LocalizedError {
    case invalidKeyLength(Int)
    case invalidNonce
    case truncatedCiphertext

    var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let count): return "ChaCha20-Poly1305 key is \(count) bytes; expected 32."
        case .invalidNonce: return "ChaCha20-Poly1305 nonce must be 12 bytes."
        case .truncatedCiphertext: return "Ciphertext does not contain an authentication tag."
        }
    }
}

