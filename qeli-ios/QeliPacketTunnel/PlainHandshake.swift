import Foundation

struct PlainHandshakeResult {
    var config: VPNConfig
    var session: TunnelSessionConfiguration
    var encoder: PacketCodec
    var decoder: PacketCodec
    var reader: StreamRecordReader
}

enum PlainHandshake {
    static func run(
        transport: QeliTransport,
        config inputConfig: VPNConfig,
        sharedStore: SharedTunnelStore
    ) async throws -> PlainHandshakeResult {
        guard !inputConfig.isUDP else { throw PlainHandshakeError.tcpRequired }
        let reader = StreamRecordReader(transport: transport)
        let keyPair = X25519KeyPair()

        try await transport.send(keyPair.publicKey)
        let serverEphemeralPublicKey = try await reader.readExactly(32)
        let transcriptHash = KeyDerivation.handshakeTranscript([keyPair.publicKey, serverEphemeralPublicKey])
        let ephemeralShared = try keyPair.sharedSecret(peerPublicKey: serverEphemeralPublicKey)

        let directional: (serverToClient: Data, clientToServer: Data)
        if inputConfig.bindStaticToSession {
            guard let pinned = try inputConfig.serverPublicKeyData(), !pinned.allSatisfy({ $0 == 0 }) else {
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
            paddingEnabled: inputConfig.paddingEnabled,
            paddingMin: inputConfig.paddingMin,
            paddingMax: inputConfig.paddingMax,
            rawFraming: true
        )
        let decoder = PacketCodec(
            cipher: try PacketCipher(key: directional.serverToClient),
            rawFraming: true
        )

        let serverAuthenticationRecord = try await reader.readRawRecord()
        let serverAuthentication = try decoder.decrypt(serverAuthenticationRecord)
        let staticShared = try verifyServer(
            message: serverAuthentication,
            keyPair: keyPair,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash,
            config: inputConfig,
            endpoint: "\(inputConfig.serverAddress):\(inputConfig.port)"
        )
        sharedStore.appendLog("Server identity verified [OK] (plain)")

        let clientProof = KeyDerivation.clientKeyProof(
            staticShared: staticShared,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash
        )
        let deviceID = try SecureIdentityStore().deviceID()
        var clientAuthentication = clientProof
        clientAuthentication.append(0)
        clientAuthentication.append(deviceID)
        clientAuthentication.append(Data("\(inputConfig.username):\(inputConfig.password)".utf8))
        let encryptedClientAuthentication = try encoder.encrypt(clientAuthentication)
        try await transport.send(encryptedClientAuthentication)

        let responseRecord = try await reader.readRawRecord()
        let response = try decoder.decrypt(responseRecord)
        guard let responseString = String(data: response, encoding: .utf8), responseString.hasPrefix("OK:") else {
            throw PlainHandshakeError.authenticationFailed(String(data: response, encoding: .utf8) ?? "invalid response")
        }
        let parsed = try parseOK(String(responseString.dropFirst(3)), inputConfig: inputConfig)
        encoder.setPadding(
            enabled: parsed.config.paddingEnabled,
            minimum: parsed.config.paddingMin,
            maximum: parsed.config.paddingMax
        )
        sharedStore.appendLog("Auth OK, IP \(parsed.session.clientAddress)")
        return PlainHandshakeResult(
            config: parsed.config,
            session: parsed.session,
            encoder: encoder,
            decoder: decoder,
            reader: reader
        )
    }

    static func verifyServer(
        message: Data,
        keyPair: X25519KeyPair,
        ephemeralShared: Data,
        transcriptHash: Data,
        config: VPNConfig,
        endpoint: String
    ) throws -> Data {
        let explicitPin = try config.serverPublicKeyData()
        let identities = SecureIdentityStore()
        let staticPublicKey: Data
        let receivedProof: Data
        var shouldRemember = false

        if message.count >= 64 {
            staticPublicKey = Data(message.prefix(32))
            receivedProof = Data(message[32..<64])
            if let explicitPin {
                guard timingSafeEqual(explicitPin, staticPublicKey) else {
                    throw PlainHandshakeError.serverKeyMismatch
                }
            } else if let remembered = try identities.knownHostKey(endpoint: endpoint) {
                guard timingSafeEqual(remembered, staticPublicKey) else {
                    throw PlainHandshakeError.serverKeyMismatch
                }
            } else {
                shouldRemember = true
            }
        } else if message.count >= 32 {
            guard let explicitPin else { throw PlainHandshakeError.proofOnlyNeedsPinnedKey }
            staticPublicKey = explicitPin
            receivedProof = Data(message.prefix(32))
        } else {
            throw PlainHandshakeError.serverProofTooShort
        }

        let staticShared = try keyPair.sharedSecret(peerPublicKey: staticPublicKey)
        let expected = KeyDerivation.serverAuthenticationProof(
            staticShared: staticShared,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash
        )
        guard timingSafeEqual(receivedProof, expected) else {
            throw PlainHandshakeError.invalidServerProof
        }
        if shouldRemember { try identities.rememberHostKey(staticPublicKey, endpoint: endpoint) }
        return staticShared
    }

    private static func parseOK(
        _ jsonText: String,
        inputConfig: VPNConfig
    ) throws -> (config: VPNConfig, session: TunnelSessionConfiguration) {
        guard let data = jsonText.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let clientAddress = root["client_ip"] as? String,
              !clientAddress.isEmpty else {
            throw PlainHandshakeError.invalidOKResponse
        }
        let number: (String, Int) -> Int = { key, fallback in
            (root[key] as? NSNumber)?.intValue ?? fallback
        }
        let prefix = (1...32).contains(number("prefix", 24)) ? number("prefix", 24) : 24
        let pushedMTU = (576...9_000).contains(number("mtu", 0)) ? number("mtu", 0) : 0
        let dns = (root["dns"] as? String).flatMap { $0.isEmpty ? nil : $0 }.map { [$0] } ?? []
        let routes = (root["routes"] as? [[String: Any]])?.compactMap { $0["cidr"] as? String } ?? []

        var config = inputConfig
        config.mtu = inputConfig.mtu > 0 ? inputConfig.mtu : (pushedMTU > 0 ? pushedMTU : 1_400)
        if let obfuscation = root["obfuscation"] as? [String: Any] {
            if let padding = obfuscation["padding"] as? [String: Any] {
                config.paddingEnabled = (padding["enabled"] as? NSNumber)?.boolValue ?? true
                config.paddingMin = (padding["min_bytes"] as? NSNumber)?.intValue ?? 0
                config.paddingMax = (padding["max_bytes"] as? NSNumber)?.intValue ?? 255
            }
            if let heartbeat = obfuscation["heartbeat"] as? [String: Any] {
                config.heartbeatEnabled = (heartbeat["enabled"] as? NSNumber)?.boolValue ?? true
                config.heartbeatIntervalMilliseconds = (heartbeat["interval_ms"] as? NSNumber)?.intValue ?? 15_000
                config.heartbeatJitterMilliseconds = (heartbeat["jitter_ms"] as? NSNumber)?.intValue ?? 2_000
            }
            if let shaping = obfuscation["traffic_shaping"] as? [String: Any] {
                config.shapingEnabled = (shaping["enabled"] as? NSNumber)?.boolValue ?? false
                config.shapingGapMeanMilliseconds = (shaping["idle_gap_mean_ms"] as? NSNumber)?.intValue ?? 700
                config.shapingGapMinMilliseconds = (shaping["idle_gap_min_ms"] as? NSNumber)?.intValue ?? 40
                config.shapingGapMaxMilliseconds = (shaping["idle_gap_max_ms"] as? NSNumber)?.intValue ?? 6_000
                config.shapingBudgetBytesPerSecond = (shaping["budget_bytes_per_sec"] as? NSNumber)?.intValue ?? 16_384
                config.shapingMinSize = (shaping["min_size"] as? NSNumber)?.intValue ?? 64
                config.shapingMaxSize = (shaping["max_size"] as? NSNumber)?.intValue ?? 1_024
                config.shapingStealth = (shaping["stealth"] as? NSNumber)?.boolValue ?? false
                config.shapingStealthRateMbps = (shaping["stealth_rate_mbps"] as? NSNumber)?.intValue ?? 2
            }
        }
        let sessionToken = (root["session_token"] as? String) ?? ""
        let maxStreams = sessionToken.isEmpty ? 1 : min(max(number("max_streams", 1), 1), 64)
        let multipathAdaptive = (root["multipath_adaptive"] as? NSNumber)?.boolValue ?? false
        return (
            config,
            TunnelSessionConfiguration(
                clientAddress: clientAddress,
                prefixLength: prefix,
                pushedDNS: dns,
                pushedRoutes: routes,
                mtu: config.mtu,
                sessionToken: sessionToken,
                maxStreams: maxStreams,
                multipathAdaptive: multipathAdaptive
            )
        )
    }

    static func timingSafeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }
}

actor StreamRecordReader {
    private let transport: QeliTransport
    private var buffer = Data()

    init(transport: QeliTransport) { self.transport = transport }

    func readExactly(_ length: Int) async throws -> Data {
        while buffer.count < length {
            try Task.checkCancellation()
            let chunk = try await transport.receive(maximumLength: max(4_096, length - buffer.count))
            if chunk.isEmpty { continue }
            buffer.append(chunk)
        }
        let result = Data(buffer.prefix(length))
        buffer.removeFirst(length)
        return result
    }

    func readRawRecord() async throws -> Data {
        let header = try await readExactly(2)
        let length = (Int(header[0]) << 8) | Int(header[1])
        guard length >= PacketCodec.nonceSize + PacketCodec.tagSize + PacketCodec.counterSize + 2,
              length <= PacketCodec.maxRecordSize else {
            throw PlainHandshakeError.invalidRecordLength(length)
        }
        return header + (try await readExactly(length))
    }
}

extension VPNConfig {
    func serverPublicKeyData() throws -> Data? {
        guard let serverPublicKeyHex, !serverPublicKeyHex.isEmpty else { return nil }
        let clean = serverPublicKeyHex.filter { !$0.isWhitespace && $0 != ":" && $0 != "-" }
        guard clean.count == 64, clean.allSatisfy(\.isHexDigit) else {
            throw PlainHandshakeError.invalidPinnedKey
        }
        var result = Data(); result.reserveCapacity(32)
        var index = clean.startIndex
        for _ in 0..<32 {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(String(clean[index..<next]), radix: 16) else {
                throw PlainHandshakeError.invalidPinnedKey
            }
            result.append(byte); index = next
        }
        return result
    }
}

enum PlainHandshakeError: LocalizedError {
    case tcpRequired
    case staticBindingNeedsPinnedKey
    case invalidPinnedKey
    case serverKeyMismatch
    case proofOnlyNeedsPinnedKey
    case serverProofTooShort
    case invalidServerProof
    case authenticationFailed(String)
    case invalidOKResponse
    case invalidRecordLength(Int)

    var errorDescription: String? {
        switch self {
        case .tcpRequired: return "Plain mode currently requires TCP."
        case .staticBindingNeedsPinnedKey: return "bind_static is enabled; add the 64-hex server key or set bind_static = false."
        case .invalidPinnedKey: return "The pinned server key must contain exactly 64 hexadecimal characters."
        case .serverKeyMismatch: return "Server key mismatch — possible MITM or deliberate key rotation."
        case .proofOnlyNeedsPinnedKey: return "The server sent a proof-only identity message but this profile has no pinned key."
        case .serverProofTooShort: return "The server identity proof is too short."
        case .invalidServerProof: return "The server identity proof is invalid."
        case .authenticationFailed(let value): return "Authentication failed: \(value)"
        case .invalidOKResponse: return "The server returned an invalid OK response."
        case .invalidRecordLength(let length): return "Invalid raw record length \(length)."
        }
    }
}
