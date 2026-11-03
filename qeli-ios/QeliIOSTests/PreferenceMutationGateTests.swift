import Foundation
import XCTest
@testable import Qeli

@MainActor
final class PreferenceMutationGateTests: XCTestCase {
    private enum FixtureError: Error { case waiterDidNotQueue }

    private func waitForQueue(_ gate: PreferenceMutationGate, count: Int) async throws {
        for _ in 0..<1000 {
            if gate.queuedOperationCount == count { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        throw FixtureError.waiterDidNotQueue
    }

    func testCancelledBeforeAdmissionDoesNotRunPreferenceMutation() async throws {
        let gate = PreferenceMutationGate()
        var mutated = false
        let cancelled = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await gate.withLock { mutated = true }
        }
        do { try await cancelled.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        XCTAssertFalse(mutated)
        try await gate.withLock { mutated = true }
        XCTAssertTrue(mutated)
    }

    func testCancelledQueuedMutationWaitsForOwnerAndNeverRunsBody() async throws {
        let gate = PreferenceMutationGate()
        let release = AsyncResultCompletion<Void>()
        let entered = AsyncResultCompletion<Void>()
        defer { release.finish(.success(())) }
        let first = Task {
            try await gate.withLock {
                entered.finish(.success(()))
                let result = await withCheckedContinuation { release.park($0) }
                try result.get()
            }
        }
        let admission = await withCheckedContinuation { entered.park($0) }
        try admission.get()
        var mutated = false
        let cancelled = Task { try await gate.withLock { mutated = true } }
        try await waitForQueue(gate, count: 1)
        cancelled.cancel()
        // Cancellation cannot unlock the owner's still-pending OS preference callback.
        XCTAssertEqual(gate.queuedOperationCount, 1)
        release.finish(.success(()))
        try await first.value
        do { try await cancelled.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        XCTAssertFalse(mutated)
        try await gate.withLock { mutated = true }
        XCTAssertTrue(mutated)
    }

    func testSuspendedTransactionSerializesRefreshAndReadsLatestPolicyAtAdmission() async throws {
        let gate = PreferenceMutationGate()
        let release = AsyncResultCompletion<Void>()
        let entered = AsyncResultCompletion<Void>()
        defer { release.finish(.success(())) }
        var policy = "old"
        var applied: [String] = []
        let first = Task {
            try await gate.withLock {
                applied.append(policy)
                entered.finish(.success(()))
                let result = await withCheckedContinuation { release.park($0) }
                try result.get()
            }
        }
        let admission = await withCheckedContinuation { entered.park($0) }
        try admission.get()
        let second = Task { try await gate.withLock { applied.append(policy) } }
        try await waitForQueue(gate, count: 1)
        policy = "new"
        XCTAssertEqual(applied, ["old"])
        release.finish(.success(()))
        try await first.value
        try await second.value
        XCTAssertEqual(applied, ["old", "new"])
    }
}
