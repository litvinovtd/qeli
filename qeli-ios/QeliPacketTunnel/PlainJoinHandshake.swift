import Foundation

struct PlainJoinHandshakeResult {
    var encoder: PacketCodec
    var decoder: PacketCodec
    var reader: StreamRecordReader
}

enum PlainJoinHandshake {
    private static let magic = Data("QELIJOIN".utf8)
    private static let tokenLength = 16

    static func run(
        transport: QeliTransport,
        config: VPNConfig,
        token: Data,
        streamIndex: Int,
        sharedStore: SharedTunnelStore
    ) async throws -> PlainJoinHandshakeResult {
        guard !config.isUDP else { throw PlainJoinHandshakeError.tcpRequired }
        guard token.count == tokenLength else {
            throw PlainJoinHandshakeError.invalidTokenLength(token.count)
        }
        guard (1...255).contains(streamIndex) else {
            throw PlainJoinHandshakeError.invalidStreamIndex(streamIndex)
        }

        let reader = StreamRecordReader(transport: transport)
        let keyPair = X25519KeyPair()
        try await transport.send(keyPair.publicKey)
        let serverEphemeralPublicKey = try await reader.readExactly(32)
        let transcriptHash = KeyDerivation.handshakeTranscript([
            keyPair.publicKey,
            serverEphemeralPublicKey
        ])
        let ephemeralShared = try keyPair.sharedSecret(peerPublicKey: serverEphemeralPublicKey)

        let directional: (serverToClient: Data, clientToServer: Data)
        if config.bindStaticToSession {
            guard let pinned = try config.serverPublicKeyData(), !pinned.allSatisfy({ $0 == 0 }) else {
                throw PlainHandshakeError.staticBindingNeedsPinnedKey
            }
            let staticShared = try keyPair.sharedSecret(peerPublicKey: pinned)
            directional = KeyDerivation.boundClassicKeys(
                ephemeralShared: ephemeralShared,
                staticShared: staticShared
            )
        } else {
            directional = KeyDerivation.classicKeys(sharedSecret: ephemeralShared)
        }

        let encoder = PacketCodec(
            cipher: try PacketCipher(key: directional.clientToServer),
            paddingEnabled: config.paddingEnabled,
            paddingMin: config.paddingMin,
            paddingMax: config.paddingMax,
            rawFraming: true
        )
        let decoder = PacketCodec(
            cipher: try PacketCipher(key: directional.serverToClient),
            rawFraming: true
        )

        let serverAuthenticationRecord = try await reader.readRawRecord()
        let serverAuthentication = try decoder.decrypt(serverAuthenticationRecord)
        _ = try PlainHandshake.verifyServer(
            message: serverAuthentication,
            keyPair: keyPair,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash,
            config: config,
            endpoint: "\(config.serverAddress):\(config.port)"
        )

        var join = magic
        join.append(token)
        join.append(UInt8(streamIndex))
        try await transport.send(encoder.encrypt(join))

        let acknowledgementRecord = try await reader.readRawRecord()
        let acknowledgement = try decoder.decrypt(acknowledgementRecord)
        guard acknowledgement == Data("JOINOK".utf8) else {
            throw PlainJoinHandshakeError.rejected
        }
        sharedStore.appendLog("Bonded plain stream #\(streamIndex) authenticated")
        return PlainJoinHandshakeResult(encoder: encoder, decoder: decoder, reader: reader)
    }
}

enum PlainJoinHandshakeError: LocalizedError {
    case tcpRequired
    case invalidTokenLength(Int)
    case invalidStreamIndex(Int)
    case rejected

    var errorDescription: String? {
        switch self {
        case .tcpRequired:
            return "Plain JOIN requires TCP."
        case .invalidTokenLength(let count):
            return "The multipath JOIN token must be 16 bytes, got \(count)."
        case .invalidStreamIndex(let index):
            return "The multipath stream index is invalid: \(index)."
        case .rejected:
            return "The server rejected the multipath JOIN request."
        }
    }
}
