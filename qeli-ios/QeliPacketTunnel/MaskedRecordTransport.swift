import Foundation

/// The decoy hosts a bare-IP endpoint borrows, so a fake-TLS ClientHello and a
/// WebSocket-fronted request both look like traffic to a large, unremarkable site.
///
/// ONE list, mirroring the Rust canon (`protocol/tls.rs DEFAULT_SNI_POOL`). The SNI picker and
/// the WebSocket Host pool used to carry DIFFERENT sets — four names in one, five in the other
/// — so a client could front a request as amazon.com while never offering it as an SNI. Both
/// are observable, and disagreeing between them is a fingerprint of its own.
/// (Audit 2026-07-31.)
let defaultSNIPool = [
    "www.cloudflare.com", "www.google.com", "www.microsoft.com",
    "www.apple.com", "www.amazon.com"
]

/// Whole-record I/O used by the hybrid Qeli handshake and data plane.
/// Implementations accept concurrent TX and RX; all TX calls are serialized.
protocol QeliRecordTransport: AnyObject {
    var underlyingTransport: QeliTransport { get }
    func sendRecord(_ record: Data, longHeader: Bool) async throws
    func receiveRecord() async throws -> Data
    func cancel()
}

extension QeliRecordTransport {
    func sendRecord(_ record: Data) async throws {
        try await sendRecord(record, longHeader: false)
    }
}

/// Implemented by the UDP adapter. The initial send has already happened; this
/// method waits in jittered rounds and re-sends the exact same inner record until
/// a response arrives or the shared handshake deadline expires.
protocol QeliHandshakeRetransmittingRecordTransport: QeliRecordTransport {
    func receiveHandshakeRecord(
        resending record: Data,
        longHeader: Bool,
        deadline: ContinuousClock.Instant,
        expected: String
    ) async throws -> Data
}

/// Direct TLS-record-shaped Qeli records over a TCP byte stream.
actor TLSRecordTransport: QeliRecordTransport {
    nonisolated let underlyingTransport: QeliTransport
    private let input: RawTransportByteStream
    private let transmitGate = AsyncWireGate()

    init(underlyingTransport: QeliTransport) {
        self.underlyingTransport = underlyingTransport
        input = RawTransportByteStream(transport: underlyingTransport)
    }

    func sendRecord(_ record: Data, longHeader: Bool) async throws {
        await transmitGate.acquire()
        do {
            try Task.checkCancellation()
            try await underlyingTransport.send(record)
            await transmitGate.release()
        } catch {
            await transmitGate.release()
            throw error
        }
    }

    func receiveRecord() async throws -> Data {
        try await input.readTLSRecord()
    }

    nonisolated func cancel() { underlyingTransport.cancel() }
}

/// TCP obfs mode: optional HTTP/WebSocket front, bidirectional AWG junk,
/// clear nonce exchange, then a continuous ChaCha20 stream in each direction.
actor ObfuscatedRecordTransport: QeliRecordTransport {
    nonisolated let underlyingTransport: QeliTransport
    private let input: RawTransportByteStream
    private let webSocketInput: WebSocketInboundBuffer?
    private let transmitGate = AsyncWireGate()
    private var writeStream: QeliChaCha20Keystream
    private var readStream: QeliChaCha20Keystream

    private init(
        underlyingTransport: QeliTransport,
        input: RawTransportByteStream,
        webSocketInput: WebSocketInboundBuffer?,
        writeStream: QeliChaCha20Keystream,
        readStream: QeliChaCha20Keystream
    ) {
        self.underlyingTransport = underlyingTransport
        self.input = input
        self.webSocketInput = webSocketInput
        self.writeStream = writeStream
        self.readStream = readStream
    }

    /// The underlying transport must already be connected.
    static func establish(over transport: QeliTransport, config: VPNConfig) async throws -> ObfuscatedRecordTransport {
        guard !config.isUDP else { throw MaskedTransportError.obfsTCPRequired }
        guard !config.obfsKey.isEmpty else { throw MaskedTransportError.emptyObfsKey }

        let input = RawTransportByteStream(transport: transport)
        let fronted = config.obfsFronting.caseInsensitiveCompare("websocket") == .orderedSame
        if fronted {
            try await transport.send(makeWebSocketRequest(
                key: QeliObfs.deriveKey(config.obfsKey), host: webSocketHost(for: config)))
            let head = try await input.readHTTPHead(maximumLength: 4_096)
            guard head.hasPrefix("HTTP/1.1 101") else {
                throw MaskedTransportError.webSocketUpgradeRejected
            }
        }
        let webSocketInput = fronted ? WebSocketInboundBuffer(input: input) : nil

        let junkCount = config.awgEnabled
            ? min(max(config.awgJunkCount, 0), QeliObfs.awgJunkCountLimit)
            : 0
        if junkCount > 0 {
            let minimum = min(max(config.awgJunkMin, 1), QeliObfs.awgJunkLengthLimit)
            let maximum = min(max(config.awgJunkMax, minimum), QeliObfs.awgJunkLengthLimit)
            for _ in 0..<junkCount {
                let length = try secureUniform(in: minimum...maximum)
                let body = try QeliObfs.secureRandom(count: length)
                if fronted {
                    try await transport.send(QeliObfs.webSocketFrames(payload: body))
                } else {
                    var record = Data([UInt8((length >> 8) & 0xff), UInt8(length & 0xff)])
                    record.append(body)
                    try await transport.send(record)
                }
            }
            for _ in 0..<junkCount {
                if let webSocketInput {
                    try await webSocketInput.discardOneFrame()
                } else {
                    let header = try await input.readExactly(2)
                    let length = (Int(header[0]) << 8) | Int(header[1])
                    guard length <= QeliObfs.awgJunkLengthLimit else {
                        throw MaskedTransportError.junkRecordTooLarge(length)
                    }
                    _ = try await input.readExactly(length)
                }
            }
        }

        let localNonce = try QeliObfs.secureRandom(count: QeliObfs.nonceLength)
        if fronted {
            try await transport.send(QeliObfs.webSocketFrames(payload: localNonce))
        } else {
            try await transport.send(localNonce)
        }
        let peerNonce: Data
        if let webSocketInput {
            peerNonce = try await webSocketInput.readExactly(QeliObfs.nonceLength)
        } else {
            peerNonce = try await input.readExactly(QeliObfs.nonceLength)
        }

        let key = QeliObfs.deriveKey(config.obfsKey)
        return try ObfuscatedRecordTransport(
            underlyingTransport: transport,
            input: input,
            webSocketInput: webSocketInput,
            writeStream: QeliChaCha20Keystream(key: key, nonce: localNonce),
            readStream: QeliChaCha20Keystream(key: key, nonce: peerNonce)
        )
    }

    func sendRecord(_ record: Data, longHeader: Bool) async throws {
        await transmitGate.acquire()
        do {
            try Task.checkCancellation()
            let ciphertext = try writeStream.xor(record)
            let wire: Data
            if let webSocketInput {
                // Owed Pongs ride out in front of the data — see `drainControlFrames`.
                let owed = try await webSocketInput.drainControlFrames()
                wire = owed + (try QeliObfs.webSocketFrames(payload: ciphertext))
            } else { wire = ciphertext }
            try await underlyingTransport.send(wire)
            await transmitGate.release()
        } catch {
            await transmitGate.release()
            throw error
        }
    }

    func receiveRecord() async throws -> Data {
        let header = try await receivePlainExactly(5)
        let length = try tlsPayloadLength(header)
        return header + (try await receivePlainExactly(length))
    }

    nonisolated func cancel() { underlyingTransport.cancel() }

    private func receivePlainExactly(_ count: Int) async throws -> Data {
        let ciphertext: Data
        if let webSocketInput {
            ciphertext = try await webSocketInput.readExactly(count)
        } else {
            ciphertext = try await input.readExactly(count)
        }
        return try readStream.xor(ciphertext)
    }
}

/// Genuine outer TLS 1.3 (REALITY) carrying inner fake-TLS Qeli records.
actor RealityRecordTransport: QeliRecordTransport {
    nonisolated let underlyingTransport: QeliTransport
    private let client: RealTLSClient
    private let transmitGate = AsyncWireGate()
    private var plaintextBuffer = Data()

    private init(underlyingTransport: QeliTransport, client: RealTLSClient) {
        self.underlyingTransport = underlyingTransport
        self.client = client
    }

    /// The underlying TCP transport must already be connected.
    static func establish(over transport: QeliTransport, config: VPNConfig) async throws -> RealityRecordTransport {
        guard !config.isUDP else { throw MaskedTransportError.realityTCPRequired }
        guard let keyText = config.serverPublicKeyHex else { throw MaskedTransportError.realityNeedsPinnedKey }
        let key = try MaskedWireValueParser.hex32(keyText)
        guard let shortIDText = config.realityShortID else { throw MaskedTransportError.realityNeedsShortID }
        let shortID = MaskedWireValueParser.realityShortID(shortIDText)
        let sni = try MaskedWireValueParser.sni(for: config)
        let client = try RealTLSClient(realityPublicKey: key, shortID: shortID, sni: sni)

        try await transport.send(client.clientHello)
        while true {
            try Task.checkCancellation()
            let bytes = try await transport.receive(maximumLength: 65_535)
            guard !bytes.isEmpty else { continue }
            switch try client.receiveHandshake(bytes) {
            case .needsMore:
                continue
            case .established(let finalFlight):
                if !finalFlight.isEmpty { try await transport.send(finalFlight) }
                return RealityRecordTransport(underlyingTransport: transport, client: client)
            }
        }
    }

    func sendRecord(_ record: Data, longHeader: Bool) async throws {
        await transmitGate.acquire()
        do {
            try Task.checkCancellation()
            // Actor isolation prevents seal/open from touching the native handle together.
            let outerRecord = try client.seal(record)
            try await underlyingTransport.send(outerRecord)
            await transmitGate.release()
        } catch {
            await transmitGate.release()
            throw error
        }
    }

    func receiveRecord() async throws -> Data {
        while true {
            if plaintextBuffer.count >= 5 {
                let length = try tlsPayloadLength(Data(plaintextBuffer.prefix(5)))
                let total = 5 + length
                if plaintextBuffer.count >= total {
                    let record = Data(plaintextBuffer.prefix(total))
                    plaintextBuffer.removeFirst(total)
                    return record
                }
            }
            try Task.checkCancellation()
            let wire = try await underlyingTransport.receive(maximumLength: 65_535)
            if wire.isEmpty { continue }
            // The native sans-IO core buffers split outer records internally.
            let plaintext = try client.open(wire)
            if !plaintext.isEmpty { plaintextBuffer.append(plaintext) }
        }
    }

    nonisolated func cancel() { underlyingTransport.cancel() }
}

actor RawTransportByteStream {
    private let transport: QeliTransport
    private var buffer = Data()

    init(transport: QeliTransport) { self.transport = transport }

    func readExactly(_ count: Int) async throws -> Data {
        guard count >= 0 else { throw MaskedTransportError.invalidReadLength(count) }
        while buffer.count < count {
            try Task.checkCancellation()
            let chunk = try await transport.receive(maximumLength: max(4_096, count - buffer.count))
            if !chunk.isEmpty { buffer.append(chunk) }
        }
        let value = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return value
    }

    func readTLSRecord() async throws -> Data {
        let header = try await readExactly(5)
        let length = try tlsPayloadLength(header)
        return header + (try await readExactly(length))
    }

    func readHTTPHead(maximumLength: Int) async throws -> String {
        var head = Data()
        var window: UInt32 = 0
        while true {
            let oneByte = try await readExactly(1)
            let byte = oneByte[0]
            head.append(byte)
            window = (window << 8) | UInt32(byte)
            if head.count >= 4, window == 0x0d0a_0d0a {
                guard let value = String(data: head, encoding: .ascii) else {
                    throw MaskedTransportError.invalidHTTPResponse
                }
                return value
            }
            guard head.count <= maximumLength else { throw MaskedTransportError.httpHeadTooLarge }
        }
    }
}

actor WebSocketInboundBuffer {
    private let input: RawTransportByteStream
    private var pending = Data()

    /// Control frames owed to the peer as (opcode, payload), queued by the read path and
    /// drained by the write path. Mirrors Rust's `WsReframer::control_out`.
    private var controlOut: [(UInt8, Data)] = []

    init(input: RawTransportByteStream) { self.input = input }

    func readExactly(_ count: Int) async throws -> Data {
        while pending.count < count { try await decodeOneFrame() }
        let value = Data(pending.prefix(count))
        pending.removeFirst(count)
        return value
    }

    func discardOneFrame() async throws {
        guard pending.isEmpty else { throw MaskedTransportError.junkAfterBufferedData }
        try await decodeOneFrame()
        pending.removeAll(keepingCapacity: false)
    }

    private func decodeOneFrame() async throws {
        let firstData = try await input.readExactly(1)
        let first = firstData[0]
        let opcode = first & 0x0f
        let secondData = try await input.readExactly(1)
        let second = secondData[0]
        let masked = (second & 0x80) != 0
        var length = UInt64(second & 0x7f)
        if length == 126 {
            let extended = try await input.readExactly(2)
            length = (UInt64(extended[0]) << 8) | UInt64(extended[1])
        } else if length == 127 {
            let extended = try await input.readExactly(8)
            length = extended.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }
        guard length <= UInt64(QeliObfs.webSocketMaximumReadPayload) else {
            throw MaskedTransportError.webSocketPayloadTooLarge(length)
        }
        let mask: Data?
        if masked { mask = try await input.readExactly(4) }
        else { mask = nil }
        var payload = try await input.readExactly(Int(length))
        if let mask {
            for index in payload.indices {
                let offset = payload.distance(from: payload.startIndex, to: index)
                let maskIndex = mask.index(mask.startIndex, offsetBy: offset % 4)
                payload[index] = payload[index] ^ mask[maskIndex]
            }
        }
        if opcode == 0 || opcode == 2 { pending.append(payload) }
        // RFC 6455 §5.5.2: a Ping MUST be answered with a Pong echoing its payload. This
        // port used to drop Pings silently. WS-fronting exists to survive WebSocket-aware
        // middleboxes, and a keepalive Ping is exactly what such a middlebox sends — an
        // endpoint that never Pongs is the anomaly it looks for. Rust has replied since
        // audit 2026-07-27 (E3); the ports had not. (Audit 2026-08-04.)
        //
        // The reply is queued, not written here: draining it on the write path keeps every
        // socket write on one task, which is why Rust queues them too.
        if opcode == 0x9, controlOut.count < Self.maximumControlOut {
            controlOut.append((0xA, payload))
        }
    }

    /// Hard cap on the owed-reply queue. The peer chooses how many Pings to send and the
    /// queue only drains when WE write, so an unbounded list is a memory-growth primitive
    /// for an on-path attacker. Past the cap we simply stop owing replies.
    private static let maximumControlOut = 8

    /// Take the owed control frames, already encoded as masked client->server frames, and
    /// clear the queue.
    func drainControlFrames() throws -> Data {
        guard !controlOut.isEmpty else { return Data() }
        var output = Data()
        for (opcode, payload) in controlOut {
            output.append(try QeliObfs.webSocketControlFrame(
                opcode: opcode, payload: payload, mask: QeliObfs.secureRandom(count: 4)))
        }
        controlOut.removeAll(keepingCapacity: false)
        return output
    }
}

private actor AsyncWireGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !held { held = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        if waiters.isEmpty { held = false }
        else { waiters.removeFirst().resume() }
    }
}

enum MaskedWireValueParser {
    static func hex32(_ text: String) throws -> Data {
        let clean = text.filter(\.isHexDigit)
        guard clean.count == 64 else { throw MaskedTransportError.invalidPinnedKey }
        return try decodeHexPairs(clean)
    }

    /// Matches `short_id_from_hex`: take up to eight complete pairs, then zero-pad.
    static func realityShortID(_ text: String) -> Data {
        let clean = text.filter(\.isHexDigit)
        var output = Data(repeating: 0, count: 8)
        var source = clean.startIndex
        for destination in 0..<8 {
            guard source < clean.endIndex else { break }
            let next = clean.index(source, offsetBy: 2, limitedBy: clean.endIndex) ?? clean.endIndex
            guard clean.distance(from: source, to: next) == 2,
                  let byte = UInt8(String(clean[source..<next]), radix: 16) else { break }
            output[destination] = byte
            source = next
        }
        return output
    }

    static func sni(for config: VPNConfig) throws -> String {
        if let configured = config.sni { return configured }
        let address = config.serverAddress
        let components = address.split(separator: ".", omittingEmptySubsequences: false)
        let isIPv4 = components.count == 4 && components.allSatisfy {
            (1...3).contains($0.count) && $0.allSatisfy(\.isNumber)
        }
        guard isIPv4 else { return address }
        // ONE list, shared with the WebSocket Host pool — see `defaultSNIPool`.
        let pool = defaultSNIPool
        return pool[try secureUniform(in: 0...(pool.count - 1))]
    }

    private static func decodeHexPairs(_ text: String) throws -> Data {
        var output = Data(); output.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(String(text[index..<next]), radix: 16) else {
                throw MaskedTransportError.invalidPinnedKey
            }
            output.append(byte)
            index = next
        }
        return output
    }
}

private func tlsPayloadLength(_ header: Data) throws -> Int {
    guard header.count == 5 else { throw MaskedTransportError.invalidTLSHeader }
    let length = (Int(header[3]) << 8) | Int(header[4])
    guard length <= 65_535 else { throw MaskedTransportError.invalidTLSRecordLength(length) }
    return length
}

private func secureUniform(in range: ClosedRange<Int>) throws -> Int {
    guard range.lowerBound <= range.upperBound else { throw MaskedTransportError.invalidRandomRange }
    let width = UInt64(range.upperBound - range.lowerBound) + 1
    var value: UInt64 = 0
    repeat {
        value = try QeliObfs.secureRandom(count: 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    } while value >= UInt64.max - (UInt64.max % width)
    return range.lowerBound + Int(value % width)
}

/// The `Host:` value for the obfs WebSocket Upgrade, with the same precedence the fake-TLS
/// SNI uses: an explicit `obfuscation.sni` wins, else the connect hostname, else nil (a
/// random decoy) when dialling a bare IP — so the cleartext header agrees with where the
/// packets actually go instead of naming an unrelated CDN. Rust has done this since audit
/// 2026-07-27 (E2); this port had not. (Audit 2026-08-04, M-08.)
private func webSocketHost(for config: VPNConfig) -> String? {
    if let sni = config.sni, !sni.isEmpty { return sni }
    return VPNConfig.isIPLiteral(config.serverAddress) ? nil : config.serverAddress
}

private func makeWebSocketRequest(key obfsKey: Data, host: String?) throws -> Data {
    let hosts = defaultSNIPool
    let agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    ]
    let path = QeliObfs.webSocketPath(key: obfsKey)
    let key = try QeliObfs.secureRandom(count: 16).base64EncodedString()
    let host = (host?.isEmpty == false) ? host! : hosts[try secureUniform(in: 0...(hosts.count - 1))]
    let agent = agents[try secureUniform(in: 0...(agents.count - 1))]
    let request = "GET \(path) HTTP/1.1\r\n" +
        "Host: \(host)\r\n" +
        "User-Agent: \(agent)\r\n" +
        "Accept: */*\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        "Sec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\n\r\n"
    guard let bytes = request.data(using: .ascii) else { throw MaskedTransportError.invalidHTTPRequest }
    return bytes
}

enum MaskedTransportError: LocalizedError {
    case obfsTCPRequired
    case realityTCPRequired
    case emptyObfsKey
    case realityNeedsPinnedKey
    case realityNeedsShortID
    case invalidPinnedKey
    case webSocketUpgradeRejected
    case invalidHTTPResponse
    case invalidHTTPRequest
    case httpHeadTooLarge
    case webSocketPayloadTooLarge(UInt64)
    case junkRecordTooLarge(Int)
    case junkAfterBufferedData
    case invalidReadLength(Int)
    case invalidTLSHeader
    case invalidTLSRecordLength(Int)
    case invalidRandomRange

    var errorDescription: String? {
        switch self {
        case .obfsTCPRequired: return "Streaming obfs transport requires TCP."
        case .realityTCPRequired: return "REALITY transport requires TCP."
        case .emptyObfsKey: return "Obfs mode requires a non-empty obfs_key."
        case .realityNeedsPinnedKey: return "REALITY requires auth.server_public_key."
        case .realityNeedsShortID: return "REALITY requires reality_sid."
        case .invalidPinnedKey: return "The server key must contain exactly 64 hexadecimal characters."
        case .webSocketUpgradeRejected: return "The obfs server did not accept the WebSocket upgrade."
        case .invalidHTTPResponse: return "The obfs WebSocket response is not ASCII."
        case .invalidHTTPRequest: return "The obfs WebSocket request could not be encoded."
        case .httpHeadTooLarge: return "The obfs WebSocket response header exceeds 4096 bytes."
        case .webSocketPayloadTooLarge(let count): return "Obfs WebSocket payload is too large (\(count) bytes)."
        case .junkRecordTooLarge(let count): return "Obfs AWG junk record is too large (\(count) bytes)."
        case .junkAfterBufferedData: return "Obfs AWG junk arrived after tunnel data."
        case .invalidReadLength(let count): return "Invalid stream read length \(count)."
        case .invalidTLSHeader: return "The Qeli TLS-shaped record header is invalid."
        case .invalidTLSRecordLength(let count): return "The Qeli TLS-shaped record length is invalid (\(count))."
        case .invalidRandomRange: return "Invalid secure-random range."
        }
    }
}
