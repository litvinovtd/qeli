import Foundation

struct MaskedSessionMetadata: Sendable, Equatable {
    var sessionToken: Data
    var maxStreams: Int
    var adaptive: Bool
}

struct MaskedHandshakeResult {
    var config: VPNConfig
    var session: TunnelSessionConfiguration
    var encoder: PacketCodec
    var decoder: PacketCodec
    var recordTransport: any QeliRecordTransport
    var metadata: MaskedSessionMetadata
}

struct MaskedJoinResult {
    var encoder: PacketCodec
    var decoder: PacketCodec
    var recordTransport: any QeliRecordTransport
}

/// Selects the TCP mask, then runs the shared hybrid fake-TLS handshake.
enum MaskedModeHandshake {
    /// `transport` must already be connected. UDP callers should use the
    /// `recordTransport` overload with their datagram/fragment adapter.
    static func run(
        transport: QeliTransport,
        config: VPNConfig,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedHandshakeResult {
        let records = try await makeRecordTransport(transport: transport, config: config)
        return try await run(recordTransport: records, config: config, sharedStore: sharedStore)
    }

    /// Shared TCP/UDP hybrid handshake. A UDP adapter observes `longHeader=true`
    /// for ClientHello fragmentation and applies its own retransmission policy.
    static func run(
        recordTransport: any QeliRecordTransport,
        config: VPNConfig,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedHandshakeResult {
        try await FakeTLSHandshake.run(
            recordTransport: recordTransport,
            config: config,
            sharedStore: sharedStore
        )
    }

    /// Establish a masked secondary transport and present a 16-byte JOIN token.
    static func runJoin(
        transport: QeliTransport,
        config: VPNConfig,
        token: Data,
        index: Int,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedJoinResult {
        let records = try await makeRecordTransport(transport: transport, config: config)
        return try await runJoin(
            recordTransport: records,
            config: config,
            token: token,
            index: index,
            sharedStore: sharedStore
        )
    }

    static func runJoin(
        recordTransport: any QeliRecordTransport,
        config: VPNConfig,
        token: Data,
        index: Int,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedJoinResult {
        try await FakeTLSHandshake.runJoin(
            recordTransport: recordTransport,
            config: config,
            token: token,
            index: index,
            sharedStore: sharedStore
        )
    }

    private static func makeRecordTransport(
        transport: QeliTransport,
        config: VPNConfig
    ) async throws -> any QeliRecordTransport {
        switch config.wireMode.lowercased() {
        case "obfs":
            return try await ObfuscatedRecordTransport.establish(over: transport, config: config)
        case "reality-tls":
            return try await RealityRecordTransport.establish(over: transport, config: config)
        case "fake-tls", "faketls", "tls":
            guard !config.isUDP else { throw MaskedHandshakeError.udpAdapterRequired }
            return TLSRecordTransport(underlyingTransport: transport)
        default:
            throw MaskedHandshakeError.unsupportedWireMode(config.wireMode)
        }
    }
}

private enum FakeTLSHandshake {
    static func run(
        recordTransport: any QeliRecordTransport,
        config inputConfig: VPNConfig,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedHandshakeResult {
        let clock = ContinuousClock()
        let handshakeDeadline = clock.now.advanced(by: .seconds(max(1, inputConfig.connectionTimeoutSeconds)))
        let exchange = try await exchangeKeys(
            recordTransport: recordTransport,
            config: inputConfig,
            padToMinimum: inputConfig.isUDP ? 1_200 : 0,
            handshakeDeadline: handshakeDeadline
        )

        _ = try await recordTransport.receiveRecord() // positional NewSessionTicket
        let serverProofRecord = try await recordTransport.receiveRecord()
        let serverProof = try exchange.decoder.decrypt(serverProofRecord)
        let staticShared = try verifyServer(
            message: serverProof,
            keyPair: exchange.keyPair,
            ephemeralShared: exchange.ephemeralShared,
            transcriptHash: exchange.transcriptHash,
            config: inputConfig
        )
        sharedStore.appendLog("Server identity verified [OK] (\(inputConfig.wireMode))")

        let proof = KeyDerivation.clientKeyProof(
            staticShared: staticShared,
            ephemeralShared: exchange.ephemeralShared,
            transcriptHash: exchange.transcriptHash
        )
        var authentication = proof
        authentication.append(0)
        authentication.append(try SecureIdentityStore().deviceID())
        authentication.append(Data("\(inputConfig.username):\(inputConfig.password)".utf8))
        let authenticationRecord = try exchange.encoder.encrypt(authentication)
        try await recordTransport.sendRecord(authenticationRecord)

        let responseRecord = try await receiveHandshakeLeg(
            from: recordTransport,
            resending: authenticationRecord,
            longHeader: false,
            deadline: handshakeDeadline,
            expected: "AuthOK"
        )
        let response = try exchange.decoder.decrypt(responseRecord)
        guard let responseText = String(data: response, encoding: .utf8), responseText.hasPrefix("OK:") else {
            throw MaskedHandshakeError.authenticationFailed(String(data: response, encoding: .utf8) ?? "invalid response")
        }
        let parsed = try parseOK(String(responseText.dropFirst(3)), inputConfig: inputConfig)
        exchange.encoder.setPadding(
            enabled: parsed.config.paddingEnabled,
            minimum: parsed.config.paddingMin,
            maximum: parsed.config.paddingMax
        )
        sharedStore.appendLog("Auth OK, IP \(parsed.session.clientAddress)")
        return MaskedHandshakeResult(
            config: parsed.config,
            session: parsed.session,
            encoder: exchange.encoder,
            decoder: exchange.decoder,
            recordTransport: recordTransport,
            metadata: parsed.metadata
        )
    }

    static func runJoin(
        recordTransport: any QeliRecordTransport,
        config: VPNConfig,
        token: Data,
        index: Int,
        sharedStore: SharedTunnelStore
    ) async throws -> MaskedJoinResult {
        guard token.count == 16 else { throw MaskedHandshakeError.invalidJoinTokenLength(token.count) }
        guard (0...255).contains(index) else { throw MaskedHandshakeError.invalidStreamIndex(index) }
        let exchange = try await exchangeKeys(
            recordTransport: recordTransport,
            config: config,
            padToMinimum: 0,
            handshakeDeadline: nil
        )
        _ = try await recordTransport.receiveRecord() // positional NewSessionTicket
        let proofRecord = try await recordTransport.receiveRecord()
        let proof = try exchange.decoder.decrypt(proofRecord)
        _ = try verifyServer(
            message: proof,
            keyPair: exchange.keyPair,
            ephemeralShared: exchange.ephemeralShared,
            transcriptHash: exchange.transcriptHash,
            config: config
        )

        var join = Data("QELIJOIN".utf8)
        join.append(token)
        join.append(UInt8(index))
        let joinRecord = try exchange.encoder.encrypt(join)
        try await recordTransport.sendRecord(joinRecord)
        let acknowledgementRecord = try await recordTransport.receiveRecord()
        let acknowledgement = try exchange.decoder.decrypt(acknowledgementRecord)
        guard acknowledgement == Data("JOINOK".utf8) else { throw MaskedHandshakeError.joinRejected }
        sharedStore.appendLog("Multipath stream #\(index) joined")
        return MaskedJoinResult(
            encoder: exchange.encoder,
            decoder: exchange.decoder,
            recordTransport: recordTransport
        )
    }

    private static func exchangeKeys(
        recordTransport: any QeliRecordTransport,
        config: VPNConfig,
        padToMinimum: Int,
        handshakeDeadline: ContinuousClock.Instant?
    ) async throws -> HybridExchange {
        guard QeliNativeCore.isAvailable else { throw QeliNativeError.unavailable }
        let keyPair = X25519KeyPair()
        let mlkem = try MLKEMContext()
        guard mlkem.encapsulationKey.count == 1_184 else {
            throw MaskedHandshakeError.invalidMLKEMEncapsulationKey(mlkem.encapsulationKey.count)
        }
        let sni = try MaskedWireValueParser.sni(for: config)
        let clientHello = try QeliNativeCore.fakeTLSClientHello(
            x25519PublicKey: keyPair.publicKey,
            mlkemEncapsulationKey: mlkem.encapsulationKey,
            sni: sni,
            padToMinimum: padToMinimum
        )
        guard !clientHello.isEmpty else { throw MaskedHandshakeError.emptyClientHello }
        try await recordTransport.sendRecord(clientHello, longHeader: true)

        let serverHelloRecord: Data
        if let handshakeDeadline {
            serverHelloRecord = try await receiveHandshakeLeg(
                from: recordTransport,
                resending: clientHello,
                longHeader: true,
                deadline: handshakeDeadline,
                expected: "ServerHello"
            )
        } else {
            serverHelloRecord = try await recordTransport.receiveRecord()
        }
        let serverHello = try parseHybridServerHello(serverHelloRecord)
        var certificateRecord = try await recordTransport.receiveRecord()
        if isChangeCipherSpec(certificateRecord) {
            certificateRecord = try await recordTransport.receiveRecord()
        }
        let finishedRecord = try await recordTransport.receiveRecord()

        let ephemeralShared = try keyPair.sharedSecret(peerPublicKey: serverHello.serverX25519)
        let mlkemShared = try mlkem.decapsulate(serverHello.ciphertext)
        guard mlkemShared.count == 32 else {
            throw MaskedHandshakeError.invalidMLKEMSharedSecret(mlkemShared.count)
        }
        let directional: (serverToClient: Data, clientToServer: Data)
        if config.bindStaticToSession {
            guard let keyText = config.serverPublicKeyHex else {
                throw MaskedHandshakeError.staticBindingNeedsPinnedKey
            }
            let pinned = try MaskedWireValueParser.hex32(keyText)
            guard pinned.contains(where: { $0 != 0 }) else {
                throw MaskedHandshakeError.staticBindingNeedsPinnedKey
            }
            let staticShared = try keyPair.sharedSecret(peerPublicKey: pinned)
            directional = KeyDerivation.boundHybridKeys(
                x25519Shared: ephemeralShared,
                mlkemShared: mlkemShared,
                staticShared: staticShared
            )
        } else {
            directional = KeyDerivation.hybridKeys(
                x25519Shared: ephemeralShared,
                mlkemShared: mlkemShared
            )
        }

        let encoder = PacketCodec(
            cipher: try PacketCipher(key: directional.clientToServer),
            paddingEnabled: config.paddingEnabled,
            paddingMin: config.paddingMin,
            paddingMax: config.paddingMax
        )
        let decoder = PacketCodec(cipher: try PacketCipher(key: directional.serverToClient))
        let transcriptHash = KeyDerivation.handshakeTranscript([
            clientHello, serverHelloRecord, certificateRecord, finishedRecord
        ])
        return HybridExchange(
            keyPair: keyPair,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash,
            encoder: encoder,
            decoder: decoder
        )
    }

    private static func receiveHandshakeLeg(
        from recordTransport: any QeliRecordTransport,
        resending record: Data,
        longHeader: Bool,
        deadline: ContinuousClock.Instant,
        expected: String
    ) async throws -> Data {
        guard ContinuousClock().now < deadline else { throw MaskedHandshakeError.handshakeTimedOut(expected) }
        if let retransmitting = recordTransport as? any QeliHandshakeRetransmittingRecordTransport {
            return try await retransmitting.receiveHandshakeRecord(
                resending: record,
                longHeader: longHeader,
                deadline: deadline,
                expected: expected
            )
        }
        return try await recordTransport.receiveRecord()
    }

    private static func verifyServer(
        message: Data,
        keyPair: X25519KeyPair,
        ephemeralShared: Data,
        transcriptHash: Data,
        config: VPNConfig
    ) throws -> Data {
        let pinned = try config.serverPublicKeyHex.map { try MaskedWireValueParser.hex32($0) }
        let identities = SecureIdentityStore()
        let endpoint = "\(config.serverAddress):\(config.port)"
        let staticPublicKey: Data
        let receivedProof: Data
        var rememberOnSuccess = false

        if message.count >= 64 {
            staticPublicKey = Data(message.prefix(32))
            receivedProof = Data(message.dropFirst(32).prefix(32))
            if let pinned {
                guard timingSafeEqual(pinned, staticPublicKey) else { throw MaskedHandshakeError.serverKeyMismatch }
            } else if let remembered = try identities.knownHostKey(endpoint: endpoint) {
                guard timingSafeEqual(remembered, staticPublicKey) else { throw MaskedHandshakeError.serverKeyMismatch }
            } else {
                rememberOnSuccess = true
            }
        } else if message.count >= 32 {
            guard let pinned else { throw MaskedHandshakeError.proofOnlyNeedsPinnedKey }
            staticPublicKey = pinned
            receivedProof = Data(message.prefix(32))
        } else {
            throw MaskedHandshakeError.serverProofTooShort(message.count)
        }

        let staticShared = try keyPair.sharedSecret(peerPublicKey: staticPublicKey)
        let expected = KeyDerivation.serverAuthenticationProof(
            staticShared: staticShared,
            ephemeralShared: ephemeralShared,
            transcriptHash: transcriptHash
        )
        guard timingSafeEqual(receivedProof, expected) else { throw MaskedHandshakeError.invalidServerProof }
        if rememberOnSuccess { try identities.rememberHostKey(staticPublicKey, endpoint: endpoint) }
        return staticShared
    }

    private static func parseHybridServerHello(_ record: Data) throws -> HybridServerHello {
        let bytes = Array(record)
        guard bytes.count >= 5, bytes[0] == 0x16 else { throw MaskedHandshakeError.invalidServerHello }
        let recordLength = (Int(bytes[3]) << 8) | Int(bytes[4])
        guard bytes.count == 5 + recordLength else { throw MaskedHandshakeError.invalidServerHello }
        let inner = Array(bytes[5...])
        guard inner.count >= 43, inner[0] == 0x02 else { throw MaskedHandshakeError.invalidServerHello }
        let bodyLength = (Int(inner[1]) << 16) | (Int(inner[2]) << 8) | Int(inner[3])
        guard bodyLength >= 43, inner.count >= 4 + bodyLength else { throw MaskedHandshakeError.invalidServerHello }
        var position = 4 + 2 + 32
        guard position < inner.count else { throw MaskedHandshakeError.invalidServerHello }
        let sessionIDLength = Int(inner[position])
        position += 1 + sessionIDLength + 2 + 1
        guard position + 2 <= inner.count else { throw MaskedHandshakeError.invalidServerHello }
        let extensionsLength = (Int(inner[position]) << 8) | Int(inner[position + 1])
        position += 2
        let extensionsEnd = position + extensionsLength
        guard extensionsEnd <= inner.count else { throw MaskedHandshakeError.invalidServerHello }

        while position + 4 <= extensionsEnd {
            let type = (Int(inner[position]) << 8) | Int(inner[position + 1])
            let length = (Int(inner[position + 2]) << 8) | Int(inner[position + 3])
            position += 4
            guard position + length <= extensionsEnd else { throw MaskedHandshakeError.invalidServerHello }
            if type == 0x0033, length >= 6 {
                let sharesLength = (Int(inner[position]) << 8) | Int(inner[position + 1])
                let group = (Int(inner[position + 2]) << 8) | Int(inner[position + 3])
                let keyLength = (Int(inner[position + 4]) << 8) | Int(inner[position + 5])
                if group == 0x11ec,
                   keyLength == 1_120,
                   sharesLength >= 4 + keyLength,
                   6 + keyLength <= length {
                    let keyStart = position + 6
                    return HybridServerHello(
                        ciphertext: Data(inner[keyStart..<(keyStart + 1_088)]),
                        serverX25519: Data(inner[(keyStart + 1_088)..<(keyStart + 1_120)])
                    )
                }
            }
            position += length
        }
        throw MaskedHandshakeError.hybridShareMissing
    }

    private static func isChangeCipherSpec(_ record: Data) -> Bool {
        record == Data([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
    }

    private static func parseOK(
        _ jsonText: String,
        inputConfig: VPNConfig
    ) throws -> (config: VPNConfig, session: TunnelSessionConfiguration, metadata: MaskedSessionMetadata) {
        guard let data = jsonText.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let clientAddress = root["client_ip"] as? String,
              !clientAddress.isEmpty else { throw MaskedHandshakeError.invalidOKResponse }

        func integer(_ key: String, _ fallback: Int) -> Int {
            (root[key] as? NSNumber)?.intValue ?? fallback
        }
        let requestedPrefix = integer("prefix", 24)
        let prefix = (1...32).contains(requestedPrefix) ? requestedPrefix : 24
        let requestedMTU = integer("mtu", 0)
        let pushedMTU = (576...9_000).contains(requestedMTU) ? requestedMTU : 0
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

        let tokenText = root["session_token"] as? String ?? ""
        let token = decodeSessionToken(tokenText)
        let metadata = MaskedSessionMetadata(
            sessionToken: token,
            maxStreams: min(max(integer("max_streams", 1), 1), 64),
            adaptive: (root["multipath_adaptive"] as? NSNumber)?.boolValue ?? false
        )
        return (
            config,
            TunnelSessionConfiguration(
                clientAddress: clientAddress,
                prefixLength: prefix,
                pushedDNS: dns,
                pushedRoutes: routes,
                mtu: config.mtu
            ),
            metadata
        )
    }

    private static func decodeSessionToken(_ text: String) -> Data {
        guard text.count == 32, text.allSatisfy(\.isHexDigit) else { return Data() }
        var output = Data(); output.reserveCapacity(16)
        var index = text.startIndex
        for _ in 0..<16 {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(String(text[index..<next]), radix: 16) else { return Data() }
            output.append(byte); index = next
        }
        return output
    }

    private static func timingSafeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) { difference |= left ^ right }
        return difference == 0
    }
}

private struct HybridExchange {
    var keyPair: X25519KeyPair
    var ephemeralShared: Data
    var transcriptHash: Data
    var encoder: PacketCodec
    var decoder: PacketCodec
}

private struct HybridServerHello {
    var ciphertext: Data
    var serverX25519: Data
}

enum MaskedHandshakeError: LocalizedError {
    case unsupportedWireMode(String)
    case udpAdapterRequired
    case invalidMLKEMEncapsulationKey(Int)
    case invalidMLKEMSharedSecret(Int)
    case emptyClientHello
    case invalidServerHello
    case hybridShareMissing
    case staticBindingNeedsPinnedKey
    case serverKeyMismatch
    case proofOnlyNeedsPinnedKey
    case serverProofTooShort(Int)
    case invalidServerProof
    case authenticationFailed(String)
    case invalidOKResponse
    case invalidJoinTokenLength(Int)
    case invalidStreamIndex(Int)
    case joinRejected
    case handshakeTimedOut(String)

    var errorDescription: String? {
        switch self {
        case .unsupportedWireMode(let mode): return "Unsupported masked wire mode: \(mode)."
        case .udpAdapterRequired: return "UDP fake-TLS requires a QeliRecordTransport datagram adapter."
        case .invalidMLKEMEncapsulationKey(let count): return "ML-KEM encapsulation key has invalid length \(count)."
        case .invalidMLKEMSharedSecret(let count): return "ML-KEM shared secret has invalid length \(count)."
        case .emptyClientHello: return "The native core returned an empty fake-TLS ClientHello."
        case .invalidServerHello: return "The server returned an invalid fake-TLS ServerHello."
        case .hybridShareMissing: return "The server did not return an X25519MLKEM768 key share."
        case .staticBindingNeedsPinnedKey: return "bind_static requires a non-zero pinned server key."
        case .serverKeyMismatch: return "Server key mismatch — possible MITM or deliberate key rotation."
        case .proofOnlyNeedsPinnedKey: return "The server sent proof-only identity without a pinned key."
        case .serverProofTooShort(let count): return "The server identity proof is too short (\(count) bytes)."
        case .invalidServerProof: return "The server identity proof is invalid."
        case .authenticationFailed(let value): return "Authentication failed: \(value)"
        case .invalidOKResponse: return "The server returned an invalid OK response."
        case .invalidJoinTokenLength(let count): return "JOIN token must be 16 bytes, got \(count)."
        case .invalidStreamIndex(let index): return "JOIN stream index is outside UInt8: \(index)."
        case .joinRejected: return "The server rejected the multipath JOIN."
        case .handshakeTimedOut(let expected): return "Qeli handshake timed out waiting for \(expected)."
        }
    }
}
