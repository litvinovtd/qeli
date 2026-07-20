import Dispatch
import Foundation

final class TrafficShaper: @unchecked Sendable {
    let enabled: Bool
    let stealth: Bool
    private let gapMeanMilliseconds: Int
    private let gapMinimumMilliseconds: Int
    private let gapMaximumMilliseconds: Int
    private let budgetBytesPerSecond: Int
    private let minimumSize: Int
    private let maximumSize: Int
    private let stealthBitsPerSecond: Double
    private let lock = NSLock()
    private var tokens: Double
    private var lastRefill = DispatchTime.now().uptimeNanoseconds
    private var rateTokens = 0.0
    private var lastRateRefill = DispatchTime.now().uptimeNanoseconds

    init(config: VPNConfig) {
        budgetBytesPerSecond = config.shapingBudgetBytesPerSecond
        enabled = config.shapingEnabled && config.shapingBudgetBytesPerSecond > 0
        stealth = enabled && config.shapingStealth && !config.isUDP
        gapMeanMilliseconds = max(1, config.shapingGapMeanMilliseconds)
        gapMinimumMilliseconds = max(0, config.shapingGapMinMilliseconds)
        gapMaximumMilliseconds = max(config.shapingGapMinMilliseconds, config.shapingGapMaxMilliseconds)
        minimumSize = max(0, config.shapingMinSize)
        maximumSize = max(config.shapingMinSize, config.shapingMaxSize)
        stealthBitsPerSecond = Double(max(1, config.shapingStealthRateMbps)) * 1_000_000
        tokens = Double(max(0, config.shapingBudgetBytesPerSecond))
    }

    func nextGapMilliseconds() -> Int {
        let sample = -Double(gapMeanMilliseconds) * log(max(1e-12, 1 - Double.random(in: 0..<1)))
        return min(max(Int(sample), gapMinimumMilliseconds), gapMaximumMilliseconds)
    }

    func nextSize() -> Int {
        maximumSize > minimumSize ? Int.random(in: minimumSize...maximumSize) : minimumSize
    }

    func trySpend(_ bytes: Int) -> Bool {
        lock.withLock {
            let now = DispatchTime.now().uptimeNanoseconds
            let elapsed = Double(now - lastRefill) / 1_000_000_000
            lastRefill = now
            tokens = min(tokens + elapsed * Double(budgetBytesPerSecond), Double(budgetBytesPerSecond))
            guard tokens >= Double(bytes) else { return false }
            tokens -= Double(bytes)
            return true
        }
    }

    func stealthDelayMilliseconds(for bytes: Int) -> Int {
        guard stealth else { return 0 }
        return lock.withLock {
            let now = DispatchTime.now().uptimeNanoseconds
            let elapsed = Double(now - lastRateRefill) / 1_000_000_000
            lastRateRefill = now
            rateTokens = min(rateTokens + elapsed * stealthBitsPerSecond, stealthBitsPerSecond)
            rateTokens -= Double(bytes * 8)
            guard rateTokens < 0 else { return 0 }
            return min(1_000, Int((-rateTokens / stealthBitsPerSecond) * 1_000))
        }
    }
}
