import XCTest
@testable import Qeli

final class HeartbeatReconnectTests: XCTestCase {

    func testReconnectExponentialBackoffAndCaps() throws {
        let policy = ReconnectPolicy(
            maximumRetries: -1,
            baseDelayMilliseconds: 1_000,
            maximumDelayMilliseconds: 60_000
        )
        XCTAssertEqual(
            try (1...8).map { try policy.delayMilliseconds(forAttempt: $0) },
            [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]
        )
        XCTAssertEqual(
            try policy.jitteredDelayMilliseconds(forAttempt: 2, reductionForTesting: 0), 2_000
        )
        XCTAssertEqual(
            try policy.jitteredDelayMilliseconds(forAttempt: 2, reductionForTesting: 400), 1_600
        )
        XCTAssertEqual(
            try policy.decision(failureCount: 0, millisecondsSinceAttemptStarted: 200),
            .retry(attempt: 0, afterMilliseconds: 1_300)
        )
        XCTAssertEqual(
            try policy.decision(failureCount: 1, millisecondsSinceAttemptStarted: 100),
            .retry(attempt: 1, afterMilliseconds: 1_400)
        )
    }

    func testShortEstablishedSessionStillEscalatesBackoff() throws {
        let policy = ReconnectPolicy()
        XCTAssertEqual(try policy.nextFailureCount(previous: 3, sessionWasEstablished: true, connectedMilliseconds: 500), 4)
        XCTAssertEqual(try policy.nextFailureCount(previous: 3, sessionWasEstablished: true, connectedMilliseconds: 30_000), 0)
    }

    func testReconnectStopConditions() throws {
        XCTAssertEqual(
            try ReconnectPolicy(enabled: false).decision(failureCount: 1, millisecondsSinceAttemptStarted: 2_000),
            .stop(.disabled)
        )
        XCTAssertEqual(
            try ReconnectPolicy(maximumRetries: 2).decision(failureCount: 3, millisecondsSinceAttemptStarted: 2_000),
            .stop(.retryLimitReached)
        )
    }
    func testInitialDNSFailureRespectsDisabledAndFiniteRetryBudgets() throws {
        let policies = [ReconnectPolicy(enabled: false), ReconnectPolicy(maximumRetries: 0),
                        ReconnectPolicy(maximumRetries: 2)]
        for (index, policy) in policies.enumerated() {
            let firstFailure = try policy.nextFailureCount(
                previous: 0, sessionWasEstablished: false, connectedMilliseconds: 0)
            XCTAssertEqual(firstFailure, 1)
            let firstDecision = try policy.decision(
                failureCount: firstFailure, millisecondsSinceAttemptStarted: 5_000)
            if index == 0 { XCTAssertEqual(firstDecision, .stop(.disabled)) }
            else if index == 1 { XCTAssertEqual(firstDecision, .stop(.retryLimitReached)) }
            else {
                guard case .retry(attempt: 1, afterMilliseconds: _) = firstDecision else {
                    return XCTFail("The first failed lookup must enter the existing retry loop")
                }
                XCTAssertEqual(try policy.decision(
                    failureCount: 3, millisecondsSinceAttemptStarted: 5_000),
                    .stop(.retryLimitReached))
            }
        }
    }

    func testStableSessionAndForcedCycleBudget() throws {
        let policy = ReconnectPolicy(maximumRetries: 0)
        XCTAssertEqual(try policy.nextFailureCount(previous: 2, sessionWasEstablished: true,
            connectedMilliseconds: 200, forced: true), 0)
        XCTAssertEqual(try policy.decision(failureCount: 0, millisecondsSinceAttemptStarted: 30_000),
            .retry(attempt: 0, afterMilliseconds: 0))
        XCTAssertEqual(try policy.decision(failureCount: 1, millisecondsSinceAttemptStarted: 30_000),
            .stop(.retryLimitReached))
        XCTAssertEqual(try policy.nextFailureCount(previous: Int(Int32.max), sessionWasEstablished: false,
            connectedMilliseconds: 0), Int(Int32.max) + 1)
    }

}
