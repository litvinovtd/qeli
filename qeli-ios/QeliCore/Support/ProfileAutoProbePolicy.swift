import Foundation

/// Mirrors Android's opt-in, bounded foreground polling policy. No iOS background task is
/// requested: entering the background or starting a tunnel revokes automatic work.
enum ProfileAutoProbePolicy {
    static let defaultEnabled = false
    static let defaultIntervalSeconds = 30
    static let minimumIntervalSeconds = 10
    static let maximumIntervalSeconds = 3_600
    static let sweepCooldown: TimeInterval = 10

    static func clampIntervalSeconds(_ value: Int) -> Int {
        min(maximumIntervalSeconds, max(minimumIntervalSeconds, value))
    }

    static func canStartSweep(
        enabled: Bool,
        foreground: Bool,
        tunnelBusy: Bool,
        systemDisconnected: Bool,
        now: TimeInterval,
        lastSweep: TimeInterval?
    ) -> Bool {
        guard enabled, foreground, !tunnelBusy, systemDisconnected else { return false }
        guard let lastSweep else { return true }
        let elapsed = now - lastSweep
        return elapsed < 0 || elapsed >= sweepCooldown
    }
}
