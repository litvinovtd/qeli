import XCTest
@testable import Qeli

final class HeartbeatReconnectTests: XCTestCase {
    func testSymmetricHeartbeatJitterAndLiveness() {
        var config = VPNConfig(serverAddress: "example.com", port: 443)
        config.heartbeatIntervalMilliseconds = 15_000
        config.heartbeatJitterMilliseconds = 2_000
        let policy = HeartbeatPolicy(config: config, isUDP: true)

        XCTAssertEqual(policy.nextDelayMilliseconds(randomFraction: 0), 13_000)
        XCTAssertEqual(policy.nextDelayMilliseconds(randomFraction: 0.5), 15_000)
        XCTAssertEqual(policy.receiveDeadAfterMilliseconds, 45_000)
        XCTAssertEqual(
            policy.livenessFailure(millisecondsSinceReceive: 8_001, millisecondsSinceUserUplink: 1_999),
            .uplinkActiveWithoutDownlink
        )
        XCTAssertEqual(
            policy.livenessFailure(millisecondsSinceReceive: 45_001, millisecondsSinceUserUplink: 5_000),
            .serverSilent(milliseconds: 45_000)
        )
    }

    /// A server with heartbeat AND shaping off is silent by design; treating that silence as
    /// a dead session reconnected a healthy idle tunnel roughly every 30 s. The uplink-active
    /// check must keep firing regardless — it only triggers while we are sending.
    /// (Audit 2026-07-29, #10.)
    func testSilenceIsNotAFailureWhenTheServerOwesNothing() {
        var config = VPNConfig(serverAddress: "example.com", port: 443)
        config.heartbeatIntervalMilliseconds = 15_000
        let policy = HeartbeatPolicy(config: config, isUDP: true)

        XCTAssertNil(
            policy.livenessFailure(
                millisecondsSinceReceive: 45_001,
                millisecondsSinceUserUplink: 5_000,
                expectServerData: false
            )
        )
        XCTAssertEqual(
            policy.livenessFailure(
                millisecondsSinceReceive: 45_001,
                millisecondsSinceUserUplink: 5_000,
                expectServerData: true
            ),
            .serverSilent(milliseconds: 45_000)
        )
        // Our own uplink going unanswered is a real failure either way.
        XCTAssertEqual(
            policy.livenessFailure(
                millisecondsSinceReceive: 8_001,
                millisecondsSinceUserUplink: 1_999,
                expectServerData: false
            ),
            .uplinkActiveWithoutDownlink
        )
    }

    func testReconnectExponentialBackoffAndCaps() {
        let policy = ReconnectPolicy(
            maximumRetries: -1,
            baseDelayMilliseconds: 1_000,
            maximumDelayMilliseconds: 60_000
        )
        XCTAssertEqual(
            (1...8).map { policy.delayMilliseconds(forAttempt: $0) },
            [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]
        )
        XCTAssertEqual(
            policy.jitteredDelayMilliseconds(forAttempt: 2, reductionForTesting: 0), 2_000
        )
        XCTAssertEqual(
            policy.jitteredDelayMilliseconds(forAttempt: 2, reductionForTesting: 400), 1_600
        )
        XCTAssertEqual(
            policy.decision(failureCount: 0, millisecondsSinceAttemptStarted: 200),
            .retry(attempt: 0, afterMilliseconds: 1_300)
        )
        XCTAssertEqual(
            policy.decision(failureCount: 1, millisecondsSinceAttemptStarted: 100),
            .retry(attempt: 1, afterMilliseconds: 1_400)
        )
    }

    func testReconnectStopConditions() {
        XCTAssertEqual(
            ReconnectPolicy(enabled: false).decision(failureCount: 1, millisecondsSinceAttemptStarted: 2_000),
            .stop(.disabled)
        )
        XCTAssertEqual(
            ReconnectPolicy(maximumRetries: 2).decision(failureCount: 3, millisecondsSinceAttemptStarted: 2_000),
            .stop(.retryLimitReached)
        )
    }
}
