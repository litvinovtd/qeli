import Foundation

enum QeliNativeError: LocalizedError {
    case unavailable
    case invalidInput(String)
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .unavailable: return "The Qeli iOS native core has not been linked."
        case .invalidInput(let message): return message
        case .operationFailed(let operation): return "Native Qeli operation failed: \(operation)."
        }
    }
}

#if canImport(QeliNative)
import QeliNative

enum QeliNativeCore {
    static let isAvailable = true

    static func udpProbe(config: String, timeoutMilliseconds: UInt32) throws -> UInt64 {
        try QeliNativeTransport.requireCompatible()
        var bytes = Array(config.utf8)
        defer { bytes.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) } }
        var latency: UInt64 = 0
        let status = bytes.withUnsafeBytes { raw in
            qeli_client_udp_probe(
                raw.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                timeoutMilliseconds,
                &latency
            )
        }
        guard status == 0 else { throw QeliNativeError.operationFailed("UDP probe (\(status))") }
        return latency
    }

    static func fakeTLSClientHello(
        x25519PublicKey: Data,
        mlkemEncapsulationKey: Data,
        sni: String,
        padToMinimum: Int
    ) throws -> Data {
        guard x25519PublicKey.count == 32 else {
            throw QeliNativeError.invalidInput("X25519 public key must be 32 bytes.")
        }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status: Int32 = x25519PublicKey.withUnsafeBytes { xBytes in
            mlkemEncapsulationKey.withUnsafeBytes { mlBytes in
                sni.withCString { sniPointer in
                    qeli_build_faketls_clienthello(
                        xBytes.bindMemory(to: UInt8.self).baseAddress,
                        mlBytes.bindMemory(to: UInt8.self).baseAddress,
                        mlkemEncapsulationKey.count,
                        sniPointer,
                        max(0, padToMinimum),
                        &output,
                        &outputLength
                    )
                }
            }
        }
        guard status == 0 else { throw QeliNativeError.operationFailed("fake ClientHello") }
        return takeBuffer(output, length: outputLength)
    }

    fileprivate static func takeBuffer(_ pointer: UnsafeMutablePointer<UInt8>?, length: Int) -> Data {
        guard let pointer, length > 0 else { return Data() }
        let value = Data(bytes: pointer, count: length)
        qeli_realtls_buf_free(pointer, length)
        return value
    }
}

final class MLKEMContext {
    private var handle: UnsafeMutableRawPointer?
    let encapsulationKey: Data

    init() throws {
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        handle = qeli_mlkem_keygen(&output, &outputLength)
        guard handle != nil else { throw QeliNativeError.operationFailed("ML-KEM key generation") }
        encapsulationKey = QeliNativeCore.takeBuffer(output, length: outputLength)
    }

    deinit { if let handle { qeli_mlkem_free(handle) } }

    func decapsulate(_ ciphertext: Data) throws -> Data {
        guard let handle else { throw QeliNativeError.operationFailed("ML-KEM context is closed") }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status = ciphertext.withUnsafeBytes { bytes in
            qeli_mlkem_decapsulate(
                handle,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                ciphertext.count,
                &output,
                &outputLength
            )
        }
        guard status == 0 else { throw QeliNativeError.operationFailed("ML-KEM decapsulation") }
        return QeliNativeCore.takeBuffer(output, length: outputLength)
    }
}

final class RealTLSClient {
    enum Progress { case needsMore, established(Data) }
    private var handle: UnsafeMutableRawPointer?
    let clientHello: Data

    init(realityPublicKey: Data, shortID: Data, sni: String) throws {
        guard realityPublicKey.count == 32 else {
            throw QeliNativeError.invalidInput("REALITY public key must be 32 bytes.")
        }
        guard shortID.count == 8 else {
            throw QeliNativeError.invalidInput("REALITY short ID must be 8 bytes.")
        }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        handle = realityPublicKey.withUnsafeBytes { keyBytes in
            shortID.withUnsafeBytes { shortBytes in
                sni.withCString { sniPointer in
                    qeli_realtls_new(
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        shortBytes.bindMemory(to: UInt8.self).baseAddress,
                        sniPointer,
                        &output,
                        &outputLength
                    )
                }
            }
        }
        guard handle != nil else { throw QeliNativeError.operationFailed("REALITY initialization") }
        clientHello = QeliNativeCore.takeBuffer(output, length: outputLength)
    }

    deinit { if let handle { qeli_realtls_free(handle) } }

    func receiveHandshake(_ data: Data) throws -> Progress {
        let (status, output) = try call(data, function: qeli_realtls_recv)
        switch status {
        case 0: return .needsMore
        case 1: return .established(output)
        default: throw QeliNativeError.operationFailed("REALITY handshake")
        }
    }

    func seal(_ plaintext: Data) throws -> Data {
        let (status, output) = try call(plaintext, function: qeli_realtls_seal)
        guard status == 0 else { throw QeliNativeError.operationFailed("REALITY seal") }
        return output
    }

    func open(_ records: Data) throws -> Data {
        let (status, output) = try call(records, function: qeli_realtls_open)
        guard status == 0 else { throw QeliNativeError.operationFailed("REALITY open") }
        return output
    }

    private func call(
        _ input: Data,
        function: (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> Int32
    ) throws -> (Int32, Data) {
        guard let handle else { throw QeliNativeError.operationFailed("REALITY context is closed") }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status = input.withUnsafeBytes { bytes in
            function(
                handle,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                input.count,
                &output,
                &outputLength
            )
        }
        return (status, QeliNativeCore.takeBuffer(output, length: outputLength))
    }
}

struct QeliTransportEvent: Sendable {
    let kind: UInt32
    let state: UInt32
    let sequence: UInt64
    let planGeneration: UInt64
    let errorCode: Int32
    let payload: String
}

struct QeliTransportStats: Sendable {
    let state: UInt32
    let txPackets: UInt64
    let txBytes: UInt64
    let rxPackets: UInt64
    let rxBytes: UInt64
    let reconnects: UInt64
    let uptimeMilliseconds: UInt64
    let udpKernelDrops: UInt64
    let udpInternalDrops: UInt64
    let udpBufferGrows: UInt64
    let udpRecvBufferBytes: UInt64
}

/// Thin owner of the whole-client C ABI. Rust owns the transport and every wire byte; this
/// object only moves lifecycle events and bounded packet batches across NetworkExtension.
final class QeliNativeTransport: @unchecked Sendable {
    static let abiVersion: UInt32 = 0x0001_000a
    static let platformRoutes: UInt64 = 1 << 0
    static let platformDNS: UInt64 = 1 << 1
    static let platformPacketBatch: UInt64 = 1 << 4
    static let platformServerIdentity: UInt64 = 1 << 6
    static let platformCapabilities = platformRoutes | platformDNS | platformPacketBatch
        | platformServerIdentity
    static let coreNativeDataPlane: UInt64 = 1 << 8
    static let corePacketIO: UInt64 = 1 << 9
    static let coreUDPDiagnostic: UInt64 = 1 << 10
    static let maxPacketBytes = 65_535
    static let maxBatchPackets = 64
    static let batchBytes = 256 * 1024
    static let maxEventPayload = 256 * 1024

    private let handle: UInt64
    private let eventLock = NSLock()
    private let uplinkLock = NSLock()
    private let downlinkLock = NSLock()
    private var eventPayload = [UInt8](repeating: 0, count: maxEventPayload)
    private var uplinkBytes = [UInt8]()
    private var uplinkLengths = [UInt32]()
    private var downlinkBytes = [UInt8](repeating: 0, count: batchBytes)
    private var downlinkLengths = [UInt32](repeating: 0, count: maxBatchPackets)

    static func requireCompatible() throws {
        let actual = qeli_client_abi_version()
        guard actual >> 16 == abiVersion >> 16,
              actual & 0xffff >= abiVersion & 0xffff else {
            throw QeliNativeError.operationFailed(
                String(format: "transport ABI 0x%08x (need 0x%08x)", actual, abiVersion)
            )
        }
        let required = coreNativeDataPlane | corePacketIO | coreUDPDiagnostic
        let capabilities = qeli_client_core_capabilities()
        guard capabilities & required == required else {
            throw QeliNativeError.operationFailed(
                String(format: "transport capabilities 0x%llx (need 0x%llx)", capabilities, required)
            )
        }
    }

    init(config: String) throws {
        try Self.requireCompatible()
        var bytes = Array(config.utf8)
        defer { bytes.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) } }
        var value: UInt64 = 0
        let status = bytes.withUnsafeBytes { raw in
            qeli_client_new(
                raw.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                Self.platformCapabilities,
                128,
                &value
            )
        }
        guard status == 0, value != 0 else {
            throw QeliNativeError.operationFailed("transport create (\(status))")
        }
        handle = value
        uplinkBytes.reserveCapacity(Self.batchBytes)
        uplinkLengths.reserveCapacity(Self.maxBatchPackets)
    }

    deinit { _ = qeli_client_free(handle) }

    func setDeviceID(_ value: Data) throws {
        let status = value.withUnsafeBytes { raw in
            qeli_client_set_device_id(
                handle,
                raw.bindMemory(to: UInt8.self).baseAddress,
                value.count
            )
        }
        try check(status, "set device id")
    }

    func start() throws { try check(qeli_client_start(handle), "start") }

    func run(runtimeInput: String = "{}") -> Int32 {
        let input = Data(runtimeInput.utf8)
        return input.withUnsafeBytes { raw in
            qeli_client_run(handle, raw.bindMemory(to: UInt8.self).baseAddress, input.count)
        }
    }

    func stop() { _ = qeli_client_stop(handle) }

    func pollEvent() throws -> QeliTransportEvent? {
        try eventLock.withLock {
            var event = qeli_client_event_t()
            event.struct_size = UInt32(MemoryLayout<qeli_client_event_t>.size)
            event.abi_version = Self.abiVersion
            var payloadLength = 0
            let payloadCapacity = eventPayload.count
            let status = eventPayload.withUnsafeMutableBytes { raw in
                qeli_client_poll_event(
                    handle,
                    &event,
                    raw.bindMemory(to: UInt8.self).baseAddress,
                    payloadCapacity,
                    &payloadLength
                )
            }
            if status == 1 { return nil }
            try check(status, "poll event")
            guard payloadLength <= eventPayload.count else {
                throw QeliNativeError.operationFailed("event payload overflow")
            }
            let payload = String(decoding: eventPayload.prefix(payloadLength), as: UTF8.self)
            return QeliTransportEvent(
                kind: event.kind,
                state: event.state,
                sequence: event.sequence,
                planGeneration: event.plan_generation,
                errorCode: event.error_code,
                payload: payload
            )
        }
    }

    func networkPlanResult(generation: UInt64, accepted: Bool, reason: String = "") throws {
        try resultWithReason(reason) { pointer, length in
            qeli_client_network_plan_result(
                handle, generation, accepted ? 0 : -1, pointer, length
            )
        }
    }

    func serverIdentityResult(sequence: UInt64, accepted: Bool, reason: String = "") throws {
        try resultWithReason(reason) { pointer, length in
            qeli_client_server_identity_result(
                handle, sequence, accepted ? 0 : -1, pointer, length
            )
        }
    }

    /// Push at most one ABI batch and return the accepted packet prefix.
    func pushPackets(_ packets: ArraySlice<Data>, generation: UInt64) throws -> Int {
        try uplinkLock.withLock {
            uplinkBytes.removeAll(keepingCapacity: true)
            uplinkLengths.removeAll(keepingCapacity: true)
            for packet in packets.prefix(Self.maxBatchPackets) {
                // Returning an accepted PREFIX is part of the packet-seam contract. Skipping
                // an invalid element here would make the caller advance past a different
                // packet and could loop forever when the first packet is too large.
                guard !packet.isEmpty, packet.count <= Self.maxPacketBytes else {
                    throw QeliNativeError.invalidInput("invalid uplink packet size \(packet.count)")
                }
                guard uplinkBytes.count + packet.count <= Self.batchBytes else { break }
                uplinkLengths.append(UInt32(packet.count))
                uplinkBytes.append(contentsOf: packet)
            }
            guard !uplinkLengths.isEmpty else { return 0 }
            var accepted = 0
            let byteCount = uplinkBytes.count
            let packetCount = uplinkLengths.count
            let status = uplinkBytes.withUnsafeBytes { packetRaw in
                uplinkLengths.withUnsafeBytes { lengthRaw in
                    qeli_client_tun_push(
                        handle,
                        generation,
                        packetRaw.bindMemory(to: UInt8.self).baseAddress,
                        byteCount,
                        lengthRaw.bindMemory(to: UInt32.self).baseAddress,
                        packetCount,
                        &accepted
                    )
                }
            }
            if status != 0 && status != 1 { try check(status, "push packets") }
            return accepted
        }
    }

    func pullPackets(generation: UInt64) throws -> [Data] {
        try downlinkLock.withLock {
            var packetCount = 0
            var byteCount = 0
            let packetCapacity = downlinkBytes.count
            let lengthCapacity = downlinkLengths.count
            let status = downlinkBytes.withUnsafeMutableBytes { packetRaw in
                downlinkLengths.withUnsafeMutableBytes { lengthRaw in
                    qeli_client_tun_pull(
                        handle,
                        generation,
                        packetRaw.bindMemory(to: UInt8.self).baseAddress,
                        packetCapacity,
                        lengthRaw.bindMemory(to: UInt32.self).baseAddress,
                        lengthCapacity,
                        &packetCount,
                        &byteCount
                    )
                }
            }
            if status == 1 { return [] }
            try check(status, "pull packets")
            guard packetCount <= downlinkLengths.count, byteCount <= downlinkBytes.count else {
                throw QeliNativeError.operationFailed("packet batch overflow")
            }
            var output: [Data] = []
            output.reserveCapacity(packetCount)
            var offset = 0
            for index in 0..<packetCount {
                let length = Int(downlinkLengths[index])
                guard length > 0, offset + length <= byteCount else {
                    throw QeliNativeError.operationFailed("invalid packet batch")
                }
                output.append(Data(downlinkBytes[offset..<(offset + length)]))
                offset += length
            }
            return output
        }
    }

    func stats() throws -> QeliTransportStats {
        var value = qeli_client_stats_t()
        value.struct_size = UInt32(MemoryLayout<qeli_client_stats_t>.size)
        value.abi_version = Self.abiVersion
        try check(qeli_client_stats(handle, &value), "stats")
        return QeliTransportStats(
            state: value.state,
            txPackets: value.tx_packets,
            txBytes: value.tx_bytes,
            rxPackets: value.rx_packets,
            rxBytes: value.rx_bytes,
            reconnects: value.reconnects,
            uptimeMilliseconds: value.uptime_ms,
            udpKernelDrops: value.udp_kernel_drops,
            udpInternalDrops: value.udp_internal_drops,
            udpBufferGrows: value.udp_buffer_grows,
            udpRecvBufferBytes: value.udp_recv_buffer_bytes
        )
    }

    /// `QELI_CLIENT_STALE_REQUEST`: the generation this answer belonged to is gone.
    private static let staleRequest: Int32 = -11

    private func resultWithReason(
        _ reason: String,
        call: (UnsafePointer<UInt8>?, Int) -> Int32
    ) throws {
        let bytes = Data(reason.utf8)
        let status = bytes.withUnsafeBytes { raw in
            call(raw.bindMemory(to: UInt8.self).baseAddress, bytes.count)
        }
        // A stale answer is the normal outcome of a network change: the link dropped and the
        // generation was cancelled while we were still applying the settings. It is not a
        // failure of this attempt, and treating it as one aborted a reconnect that had
        // otherwise succeeded.
        guard status != Self.staleRequest else { return }
        try check(status, "platform result")
    }

    private func check(_ status: Int32, _ operation: String) throws {
        guard status == 0 else {
            throw QeliNativeError.operationFailed("\(operation) (\(status))")
        }
    }
}

#elseif QELI_NATIVE_REQUIRED

#error("QeliNative is required by the Packet Tunnel target. Run 'sh build_native.sh' before generating the Xcode project.")

#else

enum QeliNativeCore {
    static let isAvailable = false

    static func udpProbe(config: String, timeoutMilliseconds: UInt32) throws -> UInt64 {
        throw QeliNativeError.unavailable
    }

    static func fakeTLSClientHello(
        x25519PublicKey: Data,
        mlkemEncapsulationKey: Data,
        sni: String,
        padToMinimum: Int
    ) throws -> Data {
        throw QeliNativeError.unavailable
    }
}

final class MLKEMContext {
    let encapsulationKey = Data()
    init() throws { throw QeliNativeError.unavailable }
    func decapsulate(_ ciphertext: Data) throws -> Data { throw QeliNativeError.unavailable }
}

final class RealTLSClient {
    enum Progress { case needsMore, established(Data) }
    let clientHello = Data()
    init(realityPublicKey: Data, shortID: Data, sni: String) throws { throw QeliNativeError.unavailable }
    func receiveHandshake(_ data: Data) throws -> Progress { throw QeliNativeError.unavailable }
    func seal(_ plaintext: Data) throws -> Data { throw QeliNativeError.unavailable }
    func open(_ records: Data) throws -> Data { throw QeliNativeError.unavailable }
}

#endif
