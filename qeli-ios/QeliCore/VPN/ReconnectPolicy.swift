import Foundation

enum ReconnectStopReason: Equatable, Sendable {
    case disabled
    case retryLimitReached
}

enum ReconnectDecision: Equatable, Sendable {
    case retry(attempt: Int, afterMilliseconds: Int)
    case stop(ReconnectStopReason)
}

/// Android-derived exponential reconnect policy with a floor between the
/// *start* of consecutive attempts. The floor also throttles a tunnel that reaches
/// connected state and then drops immediately (where exponential backoff resets).
/// Unlike an Android edge-case, `enabled = false` is honored after an established
/// session drops as well as after a pre-establishment failure.
struct ReconnectPolicy: Equatable, Sendable {
    static let minimumInterAttemptMilliseconds = 1_500
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
    ///   - failureCount: Consecutive failures before reaching connected state,
    ///     including the latest failure. Pass zero when an established session drops.
    ///   - millisecondsSinceAttemptStarted: Elapsed time since the prior attempt began.
    func decision(
        failureCount: Int,
        millisecondsSinceAttemptStarted: Int
    ) -> ReconnectDecision {
        guard enabled else { return .stop(.disabled) }
        let attempt = max(0, failureCount)
        if attempt > 0, maximumRetries >= 0, attempt > maximumRetries {
            return .stop(.retryLimitReached)
        }
        let interAttemptRemainder = max(
            0,
            Self.minimumInterAttemptMilliseconds - max(0, millisecondsSinceAttemptStarted)
        )
        let backoff = attempt == 0 ? 0 : delayMilliseconds(forAttempt: attempt)
        return .retry(attempt: attempt, afterMilliseconds: max(interAttemptRemainder, backoff))
    }

    func delayMilliseconds(forAttempt attempt: Int) -> Int {
        guard attempt > 0 else { return 0 }
        let exponent = min(max(attempt - 1, 0), 7)
        let multiplier = min(1 << exponent, 100)
        let (raw, overflow) = baseDelayMilliseconds.multipliedReportingOverflow(by: multiplier)
        let safeRaw = overflow ? Int.max : raw
        return max(1_000, min(safeRaw, maximumDelayMilliseconds))
    }

    /// Backoff escalates only across failures that never reached connected state.
    func nextFailureCount(previous: Int, sessionWasEstablished: Bool) -> Int {
        guard !sessionWasEstablished else { return 0 }
        let value = max(previous, 0)
        return value == Int.max ? Int.max : value + 1
    }

    private static func secondsToMilliseconds(_ seconds: Int) -> Int {
        let (value, overflow) = seconds.multipliedReportingOverflow(by: 1_000)
        return overflow ? Int.max : value
    }
}
