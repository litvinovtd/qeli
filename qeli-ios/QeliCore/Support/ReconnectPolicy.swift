import Foundation

enum ReconnectStopReason: Equatable, Sendable {
    case disabled
    case retryLimitReached
}

enum ReconnectDecision: Equatable, Sendable {
    case retry(attempt: Int, afterMilliseconds: Int)
    case stop(ReconnectStopReason)
}

/// Thin lifecycle adapter for the shared Rust reconnect policy. The platform owns
/// cancellation and carrier waiting; the core owns retry budgets and delay calculation.
struct ReconnectPolicy: Equatable, Sendable {
    /// Largest millisecond value that can be converted to Task.sleep nanoseconds.
    static let maximumSleepMilliseconds = Int(UInt64.max / 1_000_000)

    let enabled: Bool
    let maximumRetries: Int
    let baseDelayMilliseconds: Int
    let maximumDelayMilliseconds: Int

    init(config: VPNConfig) {
        enabled = config.reconnectEnabled
        maximumRetries = config.reconnectMaxRetries
        baseDelayMilliseconds = Self.secondsToMilliseconds(max(0, config.reconnectBaseDelaySeconds))
        maximumDelayMilliseconds = min(
            Self.maximumSleepMilliseconds,
            max(1_000, Self.secondsToMilliseconds(max(0, config.reconnectMaxDelaySeconds)))
        )
    }

    init(
        enabled: Bool = true,
        maximumRetries: Int = -1,
        baseDelayMilliseconds: Int = 1_000,
        maximumDelayMilliseconds: Int = 60_000
    ) {
        self.enabled = enabled
        self.maximumRetries = maximumRetries
        self.baseDelayMilliseconds = max(0, baseDelayMilliseconds)
        self.maximumDelayMilliseconds = min(
            Self.maximumSleepMilliseconds,
            max(1_000, maximumDelayMilliseconds)
        )
    }

    /// - Parameters:
    ///   - failureCount: Consecutive unstable attempts,
    ///     including the latest failure. Zero follows a stable established session.
    ///   - millisecondsSinceAttemptStarted: Elapsed time since the prior attempt began.
    func decision(
        failureCount: Int,
        millisecondsSinceAttemptStarted: Int,
        carrierRestored: Bool = false
    ) throws -> ReconnectDecision {
        let result = try ConfigCore.policy("retry_decision", [
            "enabled": enabled, "max_retries": maximumRetries, "attempt": failureCount,
            "base": baseDelayMilliseconds, "cap": maximumDelayMilliseconds,
            "elapsed_ms": millisecondsSinceAttemptStarted, "carrier_restored": carrierRestored
        ])["value"] as! [String: Any]
        if let reason = result["reason"] as? String {
            return .stop(reason == "disabled" ? .disabled : .retryLimitReached)
        }
        return .retry(attempt: result["attempt"] as! Int, afterMilliseconds: result["delay_ms"] as! Int)
    }

    func delayMilliseconds(forAttempt attempt: Int) throws -> Int {
        try ConfigCore.policy("backoff",["attempt":attempt,"base":baseDelayMilliseconds,"cap":maximumDelayMilliseconds])["value"] as! Int
    }
    func jitteredDelayMilliseconds(forAttempt attempt: Int, reductionForTesting: Int? = nil) throws -> Int {
        var data: [String:Any] = ["scheduled":try delayMilliseconds(forAttempt:attempt)]
        if let reductionForTesting { data["reduction"]=reductionForTesting }
        return try ConfigCore.policy("jitter",data)["value"] as! Int
    }
    func nextFailureCount(previous: Int, sessionWasEstablished: Bool, connectedMilliseconds: Int, forced: Bool = false) throws -> Int {
        try ConfigCore.policy("next_attempt",["attempt":previous,"established":sessionWasEstablished,"connected_ms":connectedMilliseconds,"forced":forced])["value"] as! Int
    }

    private static func secondsToMilliseconds(_ seconds: Int) -> Int {
        let (value, overflow) = seconds.multipliedReportingOverflow(by: 1_000)
        return overflow ? Int.max : value
    }
}
