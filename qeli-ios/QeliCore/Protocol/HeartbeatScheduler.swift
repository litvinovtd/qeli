import Dispatch
import Foundation

enum HeartbeatEmission: Equatable, Sendable {
    case heartbeat
    case paddedCover(Int)
}

enum HeartbeatLivenessFailure: LocalizedError, Equatable, Sendable {
    case uplinkActiveWithoutDownlink
    case serverSilent(milliseconds: Int)
    case transportWriteFailed(String)

    var errorDescription: String? {
        switch self {
        case .uplinkActiveWithoutDownlink: return "Uplink is active but no downlink arrived for more than 8 seconds."
        case .serverSilent(let milliseconds): return "No data from the server for more than \(milliseconds / 1_000) seconds."
        case .transportWriteFailed(let message): return "Heartbeat transport write failed: \(message)"
        }
    }
}

/// Pure heartbeat/liveness calculations shared by the scheduler and tests.
struct HeartbeatPolicy: Equatable, Sendable {
    let enabled: Bool
    let intervalMilliseconds: Int
    let jitterMilliseconds: Int
    let isUDP: Bool

    init(config: VPNConfig, isUDP: Bool) {
        enabled = config.heartbeatEnabled && config.heartbeatIntervalMilliseconds > 0
        intervalMilliseconds = max(0, config.heartbeatIntervalMilliseconds)
        jitterMilliseconds = max(0, config.heartbeatJitterMilliseconds)
        self.isUDP = isUDP
    }

    var receiveDeadAfterMilliseconds: Int {
        max(Self.saturatingMultiply(intervalMilliseconds, by: 3), 30_000)
    }

    /// `randomFraction` is in 0..<1 and makes the symmetric jitter deterministic in tests.
    func nextDelayMilliseconds(randomFraction: Double) -> Int {
        let fraction = min(max(randomFraction, 0), 0.999_999_999)
        let width = Self.saturatingMultiply(jitterMilliseconds, by: 2)
        let offset = width > 0 ? Int(Double(width) * fraction) - jitterMilliseconds : 0
        let (sum, overflow) = intervalMilliseconds.addingReportingOverflow(offset)
        return max(1_000, overflow ? Int.max : sum)
    }

    func livenessFailure(
        millisecondsSinceReceive: Int,
        millisecondsSinceUserUplink: Int
    ) -> HeartbeatLivenessFailure? {
        if millisecondsSinceUserUplink < 2_000 && millisecondsSinceReceive > 8_000 {
            return .uplinkActiveWithoutDownlink
        }
        if millisecondsSinceReceive > receiveDeadAfterMilliseconds {
            return .serverSilent(milliseconds: receiveDeadAfterMilliseconds)
        }
        return nil
    }

    private static func saturatingMultiply(_ value: Int, by multiplier: Int) -> Int {
        let (result, overflow) = value.multipliedReportingOverflow(by: multiplier)
        return overflow ? Int.max : result
    }
}

/// Runs fixed heartbeats or Poisson traffic-shaping cover and independently
/// watches receive liveness. Call `markReceived` for every authenticated inbound
/// record and `markUserUplink` only for real TUN packets (not keepalives/cover).
final class HeartbeatScheduler: @unchecked Sendable {
    typealias SendOperation = @Sendable (HeartbeatEmission) async throws -> Void
    typealias FailureOperation = @Sendable (HeartbeatLivenessFailure) -> Void

    let policy: HeartbeatPolicy

    private let shaper: TrafficShaper
    private let lock = NSLock()
    private var running = false
    private var failureDelivered = false
    private var emissionTask: Task<Void, Never>?
    private var livenessTask: Task<Void, Never>?
    private var lastReceiveNanoseconds = DispatchTime.now().uptimeNanoseconds
    private var lastUserUplinkNanoseconds = DispatchTime.now().uptimeNanoseconds

    init(config: VPNConfig, isUDP: Bool) {
        policy = HeartbeatPolicy(config: config, isUDP: isUDP)
        shaper = TrafficShaper(config: config)
    }

    func markReceived() {
        lock.withLock { lastReceiveNanoseconds = DispatchTime.now().uptimeNanoseconds }
    }

    func markUserUplink() {
        lock.withLock { lastUserUplinkNanoseconds = DispatchTime.now().uptimeNanoseconds }
    }

    func start(send: @escaping SendOperation, onFailure: @escaping FailureOperation) {
        let shouldStart = lock.withLock { () -> Bool in
            guard !running else { return false }
            running = true
            failureDelivered = false
            let now = DispatchTime.now().uptimeNanoseconds
            lastReceiveNanoseconds = now
            lastUserUplinkNanoseconds = now
            return true
        }
        guard shouldStart else { return }

        let emitter = Task<Void, Never> { [weak self] in
            await self?.runEmitter(send: send, onFailure: onFailure)
        }
        let watcher = Task<Void, Never> { [weak self] in
            await self?.runLivenessWatcher(onFailure: onFailure)
        }
        let retained = lock.withLock { () -> Bool in
            guard running else { return false }
            emissionTask = emitter
            livenessTask = watcher
            return true
        }
        if !retained { emitter.cancel(); watcher.cancel() }
    }

    func stop() {
        let tasks = lock.withLock { () -> (Task<Void, Never>?, Task<Void, Never>?) in
            running = false
            defer { emissionTask = nil; livenessTask = nil }
            return (emissionTask, livenessTask)
        }
        tasks.0?.cancel()
        tasks.1?.cancel()
    }

    private func runEmitter(send: @escaping SendOperation, onFailure: @escaping FailureOperation) async {
        guard shaper.enabled || policy.enabled else { return }
        while isRunning && !Task.isCancelled {
            let wait = shaper.enabled
                ? max(1, shaper.nextGapMilliseconds())
                : policy.nextDelayMilliseconds(randomFraction: Double.random(in: 0..<1))
            do { try await Task.sleep(nanoseconds: Self.nanoseconds(milliseconds: wait)) }
            catch { return }
            guard isRunning && !Task.isCancelled else { return }

            let emission: HeartbeatEmission
            if shaper.enabled {
                let size = shaper.nextSize()
                guard shaper.trySpend(size) else { continue }
                emission = .paddedCover(size)
            } else {
                emission = .heartbeat
            }
            do {
                try await send(emission)
            } catch {
                // Datagram send errors have normal packet-loss semantics. Receive
                // liveness decides whether the path is actually dead.
                if policy.isUDP { continue }
                deliver(.transportWriteFailed(error.localizedDescription), to: onFailure)
                return
            }
        }
    }

    private func runLivenessWatcher(onFailure: @escaping FailureOperation) async {
        // Match Android single-stream TCP semantics: when both heartbeat and
        // shaping are explicitly off, a blocking TCP read has no idle watchdog.
        // UDP still needs an independent watcher because datagram loss is non-fatal.
        guard policy.isUDP || policy.enabled || shaper.enabled else { return }
        while isRunning && !Task.isCancelled {
            do { try await Task.sleep(nanoseconds: 3_000_000_000) }
            catch { return }
            guard let failure = currentLivenessFailure() else { continue }
            deliver(failure, to: onFailure)
            return
        }
    }

    private var isRunning: Bool { lock.withLock { running } }

    private func currentLivenessFailure() -> HeartbeatLivenessFailure? {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = lock.withLock {
            (
                Self.milliseconds(from: lastReceiveNanoseconds, to: now),
                Self.milliseconds(from: lastUserUplinkNanoseconds, to: now)
            )
        }
        return policy.livenessFailure(
            millisecondsSinceReceive: elapsed.0,
            millisecondsSinceUserUplink: elapsed.1
        )
    }

    private func deliver(_ failure: HeartbeatLivenessFailure, to callback: FailureOperation) {
        let result = lock.withLock {
            () -> (Bool, Task<Void, Never>?, Task<Void, Never>?) in
            guard running, !failureDelivered else { return (false, nil, nil) }
            failureDelivered = true
            running = false
            defer { emissionTask = nil; livenessTask = nil }
            return (true, emissionTask, livenessTask)
        }
        guard result.0 else { return }
        callback(failure)
        result.1?.cancel()
        result.2?.cancel()
    }

    private static func milliseconds(from start: UInt64, to end: UInt64) -> Int {
        guard end >= start else { return 0 }
        let value = (end - start) / 1_000_000
        return value > UInt64(Int.max) ? Int.max : Int(value)
    }

    private static func nanoseconds(milliseconds: Int) -> UInt64 {
        let upperBound = Int(UInt64.max / 1_000_000)
        return UInt64(min(max(milliseconds, 0), upperBound)) * 1_000_000
    }
}
