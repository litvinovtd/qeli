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

}

struct QeliTransportEvent: Sendable {
    let kind: UInt32
    let state: UInt32
    let payloadFormat: UInt32
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
    let roamAttempts: UInt64
    let roamSuccesses: UInt64
    let roamFailures: UInt64
    let roamReconnectFallbacks: UInt64
    let roamCandidates: UInt64
    let lastRoamLatencyMilliseconds: UInt64
}

/// Thin owner of the whole-client C ABI. Rust owns the transport and every wire byte; this
/// object only moves lifecycle events and bounded packet batches across NetworkExtension.
enum QeliPathCommandOutcome: Int32, Sendable {
    case accepted = 0
    case rejected = 1
    case platformStateUnknown = 2
}

final class QeliNativeTransport: @unchecked Sendable {
    static let abiVersion: UInt32 = 0x0001_000b
    // ABI 1.14 is the first path-transaction revision that can report an incomplete platform
    // rollback separately from a clean rejection. Older cores stay on full reconnect.
    static let pathTransactionsABIVersion: UInt32 = 0x0001_000e
    static let pathRefreshABIVersion: UInt32 = 0x0001_000d
    static let platformRoutes: UInt64 = 1 << 0
    static let platformDNS: UInt64 = 1 << 1
    static let platformPacketBatch: UInt64 = 1 << 4
    static let platformServerIdentity: UInt64 = 1 << 6
    static let platformIPv6Tun: UInt64 = 1 << 8
    static let platformIPv6Routes: UInt64 = 1 << 9
    static let platformIPv6DNS: UInt64 = 1 << 10
    static let platformPathTransactions: UInt64 = 1 << 12
    static let platformPathSocketBinding: UInt64 = 1 << 13
    static let platformPathRefresh: UInt64 = 1 << 14
    static let basePlatformCapabilities = platformRoutes | platformDNS | platformPacketBatch
        | platformServerIdentity | platformIPv6Tun | platformIPv6Routes | platformIPv6DNS
    static let coreNativeDataPlane: UInt64 = 1 << 8
    static let corePacketIO: UInt64 = 1 << 9
    static let coreUDPDiagnostic: UInt64 = 1 << 10
    static let corePathTransactions: UInt64 = 1 << 13
    static let corePathRefreshEvents: UInt64 = 1 << 14
    static let maxPacketBytes = 65_535
    static let maxBatchPackets = 64
    static let batchBytes = 256 * 1024
    static let maxEventPayload = 256 * 1024

    private let handle: UInt64
    let pathTransactionsEnabled: Bool
    let pathRefreshEnabled: Bool
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

    init(config: String, roamingEnabled: Bool = false) throws {
        try Self.requireCompatible()
        let actualABI = qeli_client_abi_version()
        let coreCapabilities = qeli_client_core_capabilities()
        let transactions = roamingEnabled
            && actualABI >= Self.pathTransactionsABIVersion
            && coreCapabilities & Self.corePathTransactions != 0
        let refresh = transactions
            && actualABI >= Self.pathRefreshABIVersion
            && coreCapabilities & Self.corePathRefreshEvents != 0
        var platformCapabilities = Self.basePlatformCapabilities
        if transactions {
            platformCapabilities |= Self.platformPathTransactions | Self.platformPathSocketBinding
        }
        if refresh { platformCapabilities |= Self.platformPathRefresh }
        var bytes = Array(config.utf8)
        defer { bytes.withUnsafeMutableBufferPointer { $0.initialize(repeating: 0) } }
        var value: UInt64 = 0
        let status = bytes.withUnsafeBytes { raw in
            qeli_client_new(
                raw.bindMemory(to: UInt8.self).baseAddress,
                bytes.count,
                platformCapabilities,
                128,
                &value
            )
        }
        guard status == 0, value != 0 else {
            throw QeliNativeError.operationFailed("transport create (\(status))")
        }
        handle = value
        pathTransactionsEnabled = transactions
        pathRefreshEnabled = refresh
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
                payloadFormat: event.payload_format,
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

    func pathUpdate(_ update: QeliPathUpdate) throws -> UInt64 {
        guard pathTransactionsEnabled else {
            throw QeliNativeError.operationFailed("path transactions are not enabled")
        }
        let data = try QeliRoamingPath.encode(update)
        var candidateID: UInt64 = 0
        let status = data.withUnsafeBytes { raw in
            qeli_client_path_update(
                handle, raw.bindMemory(to: UInt8.self).baseAddress, data.count, &candidateID
            )
        }
        try check(status, "path update")
        guard candidateID != 0 else {
            throw QeliNativeError.operationFailed("path update returned no candidate")
        }
        return candidateID
    }

    func pathCommandResult(
        event: QeliTransportEvent,
        command: QeliPathCommand,
        outcome: QeliPathCommandOutcome,
        reason: String = ""
    ) throws {
        guard event.kind == QeliRoamingPath.pathCommandEvent,
              event.sequence != 0,
              event.planGeneration == command.generation else {
            throw QeliNativeError.invalidInput("path command result correlation mismatch")
        }
        try resultWithReason(reason) { pointer, length in
            qeli_client_path_command_result(
                handle, command.generation, command.candidateID, event.sequence,
                outcome.rawValue, pointer, length
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
            udpRecvBufferBytes: value.udp_recv_buffer_bytes,
            roamAttempts: value.roam_attempts,
            roamSuccesses: value.roam_successes,
            roamFailures: value.roam_failures,
            roamReconnectFallbacks: value.roam_reconnect_fallbacks,
            roamCandidates: value.roam_candidates,
            lastRoamLatencyMilliseconds: value.last_roam_latency_ms
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

    static func udpProbe(config: String, timeoutMilliseconds: UInt32) throws -> UInt64 {
        throw QeliNativeError.unavailable
    }

}

#endif
