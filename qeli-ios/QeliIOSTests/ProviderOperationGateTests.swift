import Foundation
import XCTest
@testable import Qeli

final class ProviderOperationGateTests: XCTestCase {
    private enum FixtureError: Error { case waiterDidNotQueue }

    private func waitForQueue(_ gate: ProviderOperationGate, count: Int) async throws {
        for _ in 0..<1000 {
            if await gate.queuedOperationCount == count { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        throw FixtureError.waiterDidNotQueue
    }

    func testFIFOLeaseOwnershipSurvivesDelayedOSCompletion() async throws {
        let gate = ProviderOperationGate()
        let first = try await gate.acquire()
        let second = Task { try await gate.acquire() }
        try await waitForQueue(gate, count: 1)
        let third = Task { try await gate.acquire() }
        try await waitForQueue(gate, count: 2)
        await gate.release(first)
        let secondLease = try await second.value
        XCTAssertNotEqual(first, secondLease)
        let pending = await gate.queuedOperationCount
        XCTAssertEqual(pending, 1)
        await gate.release(secondLease)
        let thirdLease = try await third.value
        XCTAssertNotEqual(secondLease, thirdLease)
        await gate.release(thirdLease)
    }

    func testTimedOutWaiterDoesNotReleaseTheOSOperation() async throws {
        let gate = ProviderOperationGate()
        let held = try await gate.acquire()
        do {
            _ = try await gate.acquire(timeoutNanoseconds: 10_000_000)
            XCTFail("Expected timeout")
        } catch ProviderOperationGate.GateError.timedOut {}
        let next = Task { try await gate.acquire() }
        try await waitForQueue(gate, count: 1)
        await gate.release(held)
        let lease = try await next.value
        await gate.release(lease)
    }

    func testCancelledWaiterDoesNotReleaseTheOSOperation() async throws {
        let gate = ProviderOperationGate()
        let held = try await gate.acquire()
        let cancelled = Task { try await gate.acquire() }
        try await waitForQueue(gate, count: 1)
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        try await waitForQueue(gate, count: 0)
        let next = Task { try await gate.acquire() }
        try await waitForQueue(gate, count: 1)
        await gate.release(held)
        let lease = try await next.value
        await gate.release(lease)
    }

    func testDuplicateOldReleaseCannotUnlockANewerLease() async throws {
        let gate = ProviderOperationGate()
        let old = try await gate.acquire()
        await gate.release(old)
        let current = try await gate.acquire()
        await gate.release(old)
        do {
            _ = try await gate.acquire(timeoutNanoseconds: 10_000_000)
            XCTFail("A stale callback unlocked the current operation")
        } catch ProviderOperationGate.GateError.timedOut {}
        await gate.release(current)
        let final = try await gate.acquire()
        await gate.release(final)
    }

    func testZeroBudgetCannotAdmitEvenAnIdleOperation() async {
        let gate = ProviderOperationGate()
        do { _ = try await gate.acquire(timeoutNanoseconds: 0); XCTFail("Expected timeout") }
        catch ProviderOperationGate.GateError.timedOut {}
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testCancellationBeforeAcquisitionDoesNotConsumeAdmission() async throws {
        let gate = ProviderOperationGate()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await gate.acquire()
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        let lease = try await gate.acquire()
        await gate.release(lease)
    }
}
