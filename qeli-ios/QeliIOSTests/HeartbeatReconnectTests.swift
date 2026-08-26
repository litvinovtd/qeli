import XCTest
@testable import Qeli

final class HeartbeatReconnectTests: XCTestCase {

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
