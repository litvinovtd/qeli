import Foundation

struct MultipathSession: Equatable, Sendable {
    let token: Data
    let maximumStreams: Int
    let adaptive: Bool

    init(sessionTokenHex: String, maximumStreams: Int, adaptive: Bool) throws {
        token = try JoinHandshake.parseToken(sessionTokenHex)
        self.maximumStreams = min(max(maximumStreams, 1), MultipathScheduler.maximumBondedStreams)
        self.adaptive = adaptive
    }
}

enum JoinHandshake {
    static let magic = Data("QELIJOIN".utf8)
    static let tokenLength = 16
    static let acknowledgement = Data("JOINOK".utf8)

    static func buildPayload(token: Data, streamIndex: Int) throws -> Data {
        guard token.count == tokenLength else { throw JoinHandshakeError.invalidTokenLength(token.count) }
        guard (1...255).contains(streamIndex) else { throw JoinHandshakeError.invalidStreamIndex(streamIndex) }
        return magic + token + Data([UInt8(streamIndex)])
    }

    static func validateAcknowledgement(_ plaintext: Data) throws {
        guard plaintext == acknowledgement else {
            throw JoinHandshakeError.rejected(String(data: plaintext, encoding: .utf8) ?? "invalid response")
        }
    }

    static func parseToken(_ hexadecimal: String) throws -> Data {
        let clean = hexadecimal.filter { !$0.isWhitespace && $0 != ":" && $0 != "-" }
        guard clean.count == tokenLength * 2, clean.allSatisfy(\.isHexDigit) else {
            throw JoinHandshakeError.invalidToken
        }
        var result = Data(); result.reserveCapacity(tokenLength)
        var index = clean.startIndex
        for _ in 0..<tokenLength {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(String(clean[index..<next]), radix: 16) else {
                throw JoinHandshakeError.invalidToken
            }
            result.append(byte)
            index = next
        }
        return result
    }
}

enum JoinHandshakeError: LocalizedError, Equatable {
    case invalidToken
    case invalidTokenLength(Int)
    case invalidStreamIndex(Int)
    case rejected(String)

    var errorDescription: String? {
        switch self {
        case .invalidToken: return "Multipath session token must contain exactly 32 hexadecimal characters."
        case .invalidTokenLength(let count): return "Multipath JOIN token is \(count) bytes; expected 16."
        case .invalidStreamIndex(let index): return "Multipath secondary stream index \(index) is outside 1...255."
        case .rejected(let response): return "Multipath JOIN was rejected: \(response)"
        }
    }
}

enum MultipathRampDecision: Equatable, Sendable {
    case hold(rateBytesPerSecond: UInt64)
    case openStream(index: Int, rateBytesPerSecond: UInt64)
    case plateau(rateBytesPerSecond: UInt64)
    case targetReached
}

/// Tracks bonded stream rotation and Android's adaptive ramp heuristic. Stream
/// objects and sockets remain owned by the tunnel engine; this type only makes
/// deterministic scheduling decisions.
final class MultipathScheduler: @unchecked Sendable {
    static let maximumBondedStreams = 8
    static let adaptiveSampleMilliseconds = 3_000
    static let adaptiveLoadThresholdBytesPerSecond: UInt64 = 250_000

    let targetStreamCount: Int
    let adaptive: Bool

    private let lock = NSLock()
    private var liveIndexes: Set<Int> = [0]
    private var roundRobinCounter: UInt64 = 0
    private var lastTotalBytes: UInt64 = 0
    private var bestRate: UInt64 = 0
    private var nextAdaptiveIndex = 1
    private var pendingAdaptiveIndex: Int?

    init(maximumStreams: Int, adaptive: Bool) {
        targetStreamCount = min(max(maximumStreams, 1), Self.maximumBondedStreams)
        self.adaptive = adaptive
    }

    convenience init(session: MultipathSession) {
        self.init(maximumStreams: session.maximumStreams, adaptive: session.adaptive)
    }

    /// Secondary streams to open immediately in fixed mode. The primary is index 0.
    var initialSecondaryIndexes: [Int] {
        adaptive || targetStreamCount <= 1 ? [] : Array(1..<targetStreamCount)
    }

    var liveStreamIndexes: [Int] { lock.withLock { liveIndexes.sorted() } }

    func markJoined(index: Int) {
        lock.withLock {
            guard (0..<targetStreamCount).contains(index) else { return }
            liveIndexes.insert(index)
            if pendingAdaptiveIndex == index { pendingAdaptiveIndex = nil }
            nextAdaptiveIndex = max(nextAdaptiveIndex, index + 1)
        }
    }

    /// Returns true when the logical tunnel lost its final stream.
    @discardableResult
    func markDead(index: Int) -> Bool {
        lock.withLock {
            liveIndexes.remove(index)
            if pendingAdaptiveIndex == index { pendingAdaptiveIndex = nil }
            return liveIndexes.isEmpty
        }
    }

    func markJoinFailed(index: Int) {
        lock.withLock {
            if pendingAdaptiveIndex == index { pendingAdaptiveIndex = nil }
        }
    }

    /// Round-robins over a caller-provided live snapshot, matching Android's
    /// single-uplink multipath loop.
    func selectStream(from indexes: [Int]) -> Int? {
        guard !indexes.isEmpty else { return nil }
        return lock.withLock {
            let ordered = indexes.sorted()
            let selected = ordered[Int(roundRobinCounter % UInt64(ordered.count))]
            roundRobinCounter &+= 1
            return selected
        }
    }

    func selectStream() -> Int? { selectStream(from: liveStreamIndexes) }

    /// Samples combined upload+download bytes. When load exceeds ~2 Mbps, adaptive
    /// mode grows while each new stream improves throughput by more than 10%.
    func observeThroughput(
        totalBytes: UInt64,
        intervalMilliseconds: Int = adaptiveSampleMilliseconds
    ) -> MultipathRampDecision {
        lock.withLock {
            let delta = totalBytes >= lastTotalBytes ? totalBytes - lastTotalBytes : totalBytes
            lastTotalBytes = totalBytes
            let interval = UInt64(max(1, intervalMilliseconds))
            let (scaled, overflow) = delta.multipliedReportingOverflow(by: 1_000)
            let rate = (overflow ? UInt64.max : scaled) / interval

            guard adaptive else { return .hold(rateBytesPerSecond: rate) }
            guard liveIndexes.count < targetStreamCount else { return .targetReached }
            guard pendingAdaptiveIndex == nil else { return .hold(rateBytesPerSecond: rate) }

            let increment = bestRate / 10
            let (threshold, thresholdOverflow) = bestRate.addingReportingOverflow(increment)
            let improvementThreshold = thresholdOverflow ? UInt64.max : threshold
            let improving = rate > improvementThreshold
            if rate > bestRate { bestRate = rate }
            guard rate > Self.adaptiveLoadThresholdBytesPerSecond else {
                return .hold(rateBytesPerSecond: rate)
            }
            if liveIndexes.count > 1, !improving {
                return .plateau(rateBytesPerSecond: rate)
            }

            while nextAdaptiveIndex < targetStreamCount, liveIndexes.contains(nextAdaptiveIndex) {
                nextAdaptiveIndex += 1
            }
            guard nextAdaptiveIndex < targetStreamCount else { return .targetReached }
            pendingAdaptiveIndex = nextAdaptiveIndex
            return .openStream(index: nextAdaptiveIndex, rateBytesPerSecond: rate)
        }
    }
}
