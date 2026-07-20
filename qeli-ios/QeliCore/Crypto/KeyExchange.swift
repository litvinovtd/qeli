import CryptoKit
import Foundation

struct X25519KeyPair: Sendable {
    private let privateKey: Curve25519.KeyAgreement.PrivateKey

    init() { privateKey = Curve25519.KeyAgreement.PrivateKey() }

    var publicKey: Data { privateKey.publicKey.rawRepresentation }

    func sharedSecret(peerPublicKey: Data) throws -> Data {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        return secret.withUnsafeBytes { Data($0) }
    }
}

