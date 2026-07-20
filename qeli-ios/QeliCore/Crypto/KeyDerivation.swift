import CryptoKit
import Foundation

enum KeyDerivation {
    static func handshakeTranscript(_ records: [Data]) -> Data {
        var hash = SHA256()
        for record in records { hash.update(data: record) }
        return Data(hash.finalize())
    }

    static func serverAuthenticationProof(
        staticShared: Data,
        ephemeralShared: Data,
        transcriptHash: Data
    ) -> Data {
        let prk = hmac(key: staticShared, data: ephemeralShared)
        return expand(
            pseudorandomKey: prk,
            info: Data("vpn-server-auth-proof-v2".utf8) + transcriptHash,
            length: 32
        )
    }

    static func clientKeyProof(
        staticShared: Data,
        ephemeralShared: Data,
        transcriptHash: Data
    ) -> Data {
        let prk = hmac(key: staticShared, data: ephemeralShared)
        return expand(
            pseudorandomKey: prk,
            info: Data("vpn-client-key-proof-v1".utf8) + transcriptHash,
            length: 32
        )
    }

    static func classicKeys(sharedSecret: Data) -> (serverToClient: Data, clientToServer: Data) {
        directionalKeys(salt: "qeli-key-derivation-v1", inputKeyMaterial: sharedSecret)
    }

    static func hybridKeys(
        x25519Shared: Data,
        mlkemShared: Data
    ) -> (serverToClient: Data, clientToServer: Data) {
        directionalKeys(
            salt: "qeli-key-derivation-v2-hybrid",
            inputKeyMaterial: x25519Shared + mlkemShared
        )
    }

    static func boundClassicKeys(
        ephemeralShared: Data,
        staticShared: Data
    ) -> (serverToClient: Data, clientToServer: Data) {
        directionalKeys(
            salt: "qeli-key-derivation-v1-static-bound",
            inputKeyMaterial: ephemeralShared + staticShared
        )
    }

    static func boundHybridKeys(
        x25519Shared: Data,
        mlkemShared: Data,
        staticShared: Data
    ) -> (serverToClient: Data, clientToServer: Data) {
        directionalKeys(
            salt: "qeli-key-derivation-v2-hybrid-static-bound",
            inputKeyMaterial: x25519Shared + mlkemShared + staticShared
        )
    }

    private static func directionalKeys(
        salt: String,
        inputKeyMaterial: Data
    ) -> (serverToClient: Data, clientToServer: Data) {
        let prk = hmac(key: Data(salt.utf8), data: inputKeyMaterial)
        return (
            expand(pseudorandomKey: prk, info: Data("server-to-client-enc-key".utf8), length: 32),
            expand(pseudorandomKey: prk, info: Data("client-to-server-enc-key".utf8), length: 32)
        )
    }

    static func hmac(key: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    static func expand(pseudorandomKey: Data, info: Data, length: Int) -> Data {
        precondition(length > 0 && length <= 255 * SHA256.byteCount)
        let key = SymmetricKey(data: pseudorandomKey)
        var result = Data()
        var previous = Data()
        var index: UInt8 = 1
        while result.count < length {
            let input = previous + info + Data([index])
            previous = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            result.append(previous)
            index &+= 1
        }
        return result.prefix(length)
    }
}

