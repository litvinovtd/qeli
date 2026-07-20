import Foundation
import Network
import Dispatch

actor PlainRecordTransport: QeliRecordTransport {
    nonisolated let underlyingTransport: QeliTransport
    private let reader: StreamRecordReader

    init(underlyingTransport: QeliTransport, reader: StreamRecordReader) {
        self.underlyingTransport = underlyingTransport
        self.reader = reader
    }

    func sendRecord(_ record: Data, longHeader: Bool) async throws {
        try Task.checkCancellation()
        try await underlyingTransport.send(record)
    }

    func receiveRecord() async throws -> Data {
        try await reader.readRawRecord()
    }

    nonisolated func cancel() { underlyingTransport.cancel() }
}

actor TunnelRecordSender {
    private let records: any QeliRecordTransport
    private let encoder: PacketCodec
    private let isUDP: Bool
    private var mtu: Int
    private let uplinkShaper: TrafficShaper

    init(
        records: any QeliRecordTransport,
        encoder: PacketCodec,
        config: VPNConfig
    ) {
        self.records = records
        self.encoder = encoder
        isUDP = config.isUDP
        mtu = max(576, config.mtu > 0 ? config.mtu : 1_400)
        uplinkShaper = TrafficShaper(config: config)
    }

    /// Returns false for packet families intentionally not carried by Qeli.
    func sendUserPacket(_ packet: Data) async throws -> Bool {
        guard packet.first.map({ $0 >> 4 == 4 }) == true else { return false }
        let record: Data
        if isUDP {
            guard let encoded = try UDPDataPlane.encodeUplink(packet, encoder: encoder, mtu: mtu) else {
                return false
            }
            record = encoded
        } else {
            record = try encoder.encrypt(packet)
        }
        try await records.sendRecord(record)
        if !isUDP {
            try await fillStealthPacingWindow(forPayloadBytes: packet.count)
        }
        return true
    }

    func sendHeartbeat(_ emission: HeartbeatEmission) async throws {
        let record: Data
        switch emission {
        case .heartbeat:
            record = try encoder.encrypt(Data())
        case .paddedCover(let requested):
            let padding = isUDP
                ? UDPDataPlane.cappedCoverPadding(requested, mtu: mtu)
                : max(0, requested)
            record = try encoder.encrypt(Data(), explicitPadding: padding)
        }
        try await records.sendRecord(record)
    }

    func updateMTU(_ value: Int) {
        mtu = max(576, value)
    }

    /// Android-compatible TCP stealth pacing: the user packet leaves immediately,
    /// then small encrypted cover records fill the rate-cap window at 4...18 ms
    /// jittered steps. The actor serialises this with user traffic and heartbeat.
    private func fillStealthPacingWindow(forPayloadBytes bytes: Int) async throws {
        var remaining = uplinkShaper.stealthDelayMilliseconds(for: bytes)
        while remaining > 6 {
            try Task.checkCancellation()
            let coverSize = uplinkShaper.nextSize()
            if uplinkShaper.trySpend(coverSize) {
                let cover = try encoder.encrypt(Data(), explicitPadding: coverSize)
                try await records.sendRecord(cover)
            }
            let step = min(remaining, Int.random(in: 4...18))
            try await Task.sleep(nanoseconds: UInt64(step) * 1_000_000)
            remaining -= step
        }
    }
}

final class TunnelStreamRuntime: @unchecked Sendable {
    let index: Int
    let records: any QeliRecordTransport
    let decoder: PacketCodec
    let sender: TunnelRecordSender
    let heartbeat: HeartbeatScheduler
    let isUDP: Bool

    private let lock = NSLock()
    private var dead = false
    private var downlinkTask: Task<Void, Never>?

    init(
        index: Int,
        records: any QeliRecordTransport,
        encoder: PacketCodec,
        decoder: PacketCodec,
        config: VPNConfig
    ) {
        self.index = index
        self.records = records
        self.decoder = decoder
        sender = TunnelRecordSender(records: records, encoder: encoder, config: config)
        heartbeat = HeartbeatScheduler(config: config, isUDP: config.isUDP)
        isUDP = config.isUDP
    }

    var isDead: Bool { lock.withLock { dead } }

    @discardableResult
    func markDead() -> Bool {
        lock.withLock {
            guard !dead else { return false }
            dead = true
            return true
        }
    }

    func retainDownlink(_ task: Task<Void, Never>) {
        let keep = lock.withLock { () -> Bool in
            guard !dead else { return false }
            downlinkTask = task
            return true
        }
        if !keep { task.cancel() }
    }

    /// Installs callbacks and starts keepalive tasks atomically with respect to
    /// `cancel()`. This prevents a stop racing between pool installation and
    /// activation from resurrecting tasks on an already-dead stream.
    func begin(
        pathUpdate: @escaping @Sendable (NWPath) -> Void,
        sendHeartbeat: @escaping HeartbeatScheduler.SendOperation,
        onHeartbeatFailure: @escaping HeartbeatScheduler.FailureOperation
    ) -> Bool {
        lock.withLock {
            guard !dead else { return false }
            records.underlyingTransport.setPathUpdateHandler(pathUpdate)
            heartbeat.start(send: sendHeartbeat, onFailure: onHeartbeatFailure)
            return true
        }
    }

    func cancel() {
        let task = lock.withLock { () -> Task<Void, Never>? in
            dead = true
            defer { downlinkTask = nil }
            return downlinkTask
        }
        heartbeat.stop()
        task?.cancel()
        records.cancel()
    }
}

private struct RuntimeFailure: @unchecked Sendable {
    let error: Error
}

final class RuntimeFailureSignal: @unchecked Sendable {
    private let lock = NSLock()
    private let stream: AsyncStream<RuntimeFailure>
    private let continuation: AsyncStream<RuntimeFailure>.Continuation
    private var finished = false

    init() {
        var captured: AsyncStream<RuntimeFailure>.Continuation!
        stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { captured = $0 }
        continuation = captured
    }

    func signal(_ error: Error) {
        let shouldSignal = lock.withLock { () -> Bool in
            guard !finished else { return false }
            finished = true
            return true
        }
        guard shouldSignal else { return }
        continuation.yield(RuntimeFailure(error: error))
        continuation.finish()
    }

    func next() async -> Error? {
        var iterator = stream.makeAsyncIterator()
        return await iterator.next()?.error
    }

    func cancel() { signal(CancellationError()) }
}

final class TunnelStreamPool: @unchecked Sendable {
    let config: VPNConfig
    let session: TunnelSessionConfiguration
    let multipath: MultipathSession?
    let scheduler: MultipathScheduler
    let failure = RuntimeFailureSignal()
    let attemptStartedAt: Date
    let trafficBaseline: UInt64

    private let lock = NSLock()
    private var streams: [Int: TunnelStreamRuntime] = [:]
    private var cancelled = false
    private var managementTask: Task<Void, Never>?
    private var livenessTask: Task<Void, Never>?
    private var lastReceiveNanoseconds = DispatchTime.now().uptimeNanoseconds
    private var lastUserUplinkNanoseconds = DispatchTime.now().uptimeNanoseconds

    init(
        primary: TunnelStreamRuntime,
        config: VPNConfig,
        session: TunnelSessionConfiguration,
        multipath: MultipathSession?,
        attemptStartedAt: Date,
        trafficBaseline: UInt64
    ) {
        self.config = config
        self.session = session
        self.multipath = multipath
        scheduler = MultipathScheduler(
            maximumStreams: multipath?.maximumStreams ?? 1,
            adaptive: multipath?.adaptive ?? false
        )
        self.attemptStartedAt = attemptStartedAt
        self.trafficBaseline = trafficBaseline
        streams[primary.index] = primary
    }

    var streamCount: Int { lock.withLock { streams.count } }

    var hasSatisfiedPath: Bool {
        lock.withLock {
            streams.values.contains {
                $0.records.underlyingTransport.currentPath?.status == .satisfied
            }
        }
    }

    func stream(index: Int) -> TunnelStreamRuntime? { lock.withLock { streams[index] } }

    func selectStream() -> TunnelStreamRuntime? {
        lock.withLock {
            guard !cancelled,
                  let index = scheduler.selectStream(from: Array(streams.keys)) else { return nil }
            return streams[index]
        }
    }

    /// Android treats bonded streams as one logical session for receive
    /// liveness. Refresh every stream watchdog when any authenticated downlink or
    /// real TUN uplink succeeds, so a quiet secondary is not discarded while the
    /// rest of the bond is healthy.
    func markReceived() {
        let values = lock.withLock { () -> [TunnelStreamRuntime] in
            lastReceiveNanoseconds = DispatchTime.now().uptimeNanoseconds
            return Array(streams.values)
        }
        values.forEach { $0.heartbeat.markReceived() }
    }

    func markUserUplink() {
        let values = lock.withLock { () -> [TunnelStreamRuntime] in
            lastUserUplinkNanoseconds = DispatchTime.now().uptimeNanoseconds
            return Array(streams.values)
        }
        values.forEach { $0.heartbeat.markUserUplink() }
    }

    @discardableResult
    func add(_ stream: TunnelStreamRuntime) -> Bool {
        let added = lock.withLock { () -> Bool in
            guard !cancelled, streams[stream.index] == nil else { return false }
            streams[stream.index] = stream
            return true
        }
        if added { scheduler.markJoined(index: stream.index) }
        else { stream.cancel() }
        return added
    }

    func lose(_ stream: TunnelStreamRuntime, error: Error) {
        guard stream.markDead() else { return }
        let last = lock.withLock { () -> Bool in
            guard let current = streams[stream.index], current === stream else { return false }
            streams.removeValue(forKey: stream.index)
            return !cancelled && streams.isEmpty
        }
        _ = scheduler.markDead(index: stream.index)
        stream.cancel()
        if last { failure.signal(error) }
    }

    func retainManagementTask(_ task: Task<Void, Never>) {
        let keep = lock.withLock { () -> Bool in
            guard !cancelled else { return false }
            managementTask = task
            return true
        }
        if !keep { task.cancel() }
    }

    /// Multipath Android parity: the bond keeps a global liveness watchdog even
    /// when fixed heartbeats and cover shaping are disabled.
    func startMultipathLivenessIfNeeded() {
        guard (multipath?.maximumStreams ?? 1) > 1 else { return }
        let task = lock.withLock { () -> Task<Void, Never>? in
            guard !cancelled, livenessTask == nil else { return nil }
            let now = DispatchTime.now().uptimeNanoseconds
            lastReceiveNanoseconds = now
            lastUserUplinkNanoseconds = now
            let task = Task<Void, Never> { [weak self] in
                await self?.runMultipathLiveness()
            }
            livenessTask = task
            return task
        }
        if lock.withLock({ cancelled }) { task?.cancel() }
    }

    func cancel() {
        let values = lock.withLock {
            () -> ([TunnelStreamRuntime], Task<Void, Never>?, Task<Void, Never>?) in
            guard !cancelled else { return ([], nil, nil) }
            cancelled = true
            let value = (Array(streams.values), managementTask, livenessTask)
            streams.removeAll()
            managementTask = nil
            livenessTask = nil
            return value
        }
        failure.cancel()
        values.1?.cancel()
        values.2?.cancel()
        values.0.forEach { $0.cancel() }
    }

    func forceFailure(_ error: Error) { failure.signal(error) }

    var elapsedSinceAttemptStartedMilliseconds: Int {
        max(0, Int(Date().timeIntervalSince(attemptStartedAt) * 1_000))
    }

    private func runMultipathLiveness() async {
        let policy = HeartbeatPolicy(config: config, isUDP: false)
        while !Task.isCancelled {
            do { try await Task.sleep(nanoseconds: 3_000_000_000) }
            catch { return }
            let now = DispatchTime.now().uptimeNanoseconds
            let elapsed = lock.withLock {
                (
                    Self.milliseconds(from: lastReceiveNanoseconds, to: now),
                    Self.milliseconds(from: lastUserUplinkNanoseconds, to: now),
                    cancelled
                )
            }
            guard !elapsed.2 else { return }
            if let error = policy.livenessFailure(
                millisecondsSinceReceive: elapsed.0,
                millisecondsSinceUserUplink: elapsed.1
            ) {
                failure.signal(error)
                return
            }
        }
    }

    private static func milliseconds(from start: UInt64, to end: UInt64) -> Int {
        guard end >= start else { return 0 }
        let value = (end - start) / 1_000_000
        return value > UInt64(Int.max) ? Int.max : Int(value)
    }
}

struct EstablishedTunnelRuntime: @unchecked Sendable {
    var config: VPNConfig
    var session: TunnelSessionConfiguration
    var primary: TunnelStreamRuntime
    var multipath: MultipathSession?
    var attemptStartedAt: Date
}
