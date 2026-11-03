import XCTest
@testable import Qeli

final class ProviderSnapshotResponseGateTests: XCTestCase {
    func testLateReplyCannotReplaceANewerAcceptedSnapshot() {
        var gate = ProviderSnapshotResponseGate()
        let old = gate.issue()
        let new = gate.issue()
        XCTAssertTrue(gate.accept(new))
        XCTAssertFalse(gate.accept(old))
        XCTAssertFalse(gate.accept(new))
    }

    func testPendingNewerRequestDoesNotStarveAnOlderValidResponse() {
        var gate = ProviderSnapshotResponseGate()
        let old = gate.issue()
        let new = gate.issue()
        XCTAssertTrue(gate.accept(old))
        XCTAssertTrue(gate.accept(new))
    }

    func testStopAndAutomaticRestartRejectRepliesFromPreviousEpoch() {
        var gate = ProviderSnapshotResponseGate()
        let old = gate.issue()
        gate.invalidate()
        let current = gate.issue()
        XCTAssertFalse(gate.accept(old))
        XCTAssertTrue(gate.accept(current))
        gate.invalidate()
        XCTAssertFalse(gate.accept(current))
        let restarted = gate.issue()
        XCTAssertTrue(gate.accept(restarted))
    }

    func testOnlyOneUnfinishedPollIsAdmittedPerEpoch() throws {
        var gate = ProviderSnapshotResponseGate()
        let token = try XCTUnwrap(gate.beginPolling())
        XCTAssertNil(gate.beginPolling())
        XCTAssertTrue(gate.finishPolling(token))
        XCTAssertNotNil(gate.beginPolling())
    }

    func testLatePollCannotReleaseTheNextEpochsOutstandingPoll() throws {
        var gate = ProviderSnapshotResponseGate()
        let old = try XCTUnwrap(gate.beginPolling())
        gate.invalidate()
        let current = try XCTUnwrap(gate.beginPolling())
        XCTAssertFalse(gate.finishPolling(old))
        XCTAssertNil(gate.beginPolling())
        XCTAssertTrue(gate.finishPolling(current))
    }

    func testDuplicateCompletionCannotReleaseANewerPoll() throws {
        var gate = ProviderSnapshotResponseGate()
        let old = try XCTUnwrap(gate.beginPolling())
        XCTAssertTrue(gate.finishPolling(old))
        let current = try XCTUnwrap(gate.beginPolling())
        XCTAssertFalse(gate.finishPolling(old))
        XCTAssertNil(gate.beginPolling())
        XCTAssertTrue(gate.finishPolling(current))
    }

    func testRequestOwnershipSurvivesOtherRequestsButNotStatusTransition() {
        var gate = ProviderSnapshotResponseGate()
        let settings = gate.issue()
        _ = gate.issue()
        XCTAssertTrue(gate.isCurrent(settings))
        gate.invalidate()
        XCTAssertFalse(gate.isCurrent(settings))
    }

}
