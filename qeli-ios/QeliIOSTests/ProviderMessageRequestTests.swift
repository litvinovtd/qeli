import Foundation
import XCTest
@testable import Qeli

@MainActor
final class ProviderMessageRequestTests: XCTestCase {
    private enum FixtureError: Error { case sendFailed }

    func testSynchronousAndDuplicateRepliesKeepTheFirstResult() async throws {
        let data = try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { reply in
            reply(Data("ok".utf8))
            reply(nil)
        }
        XCTAssertEqual(data, Data("ok".utf8))
    }

    func testSendFailurePreservesItsError() async {
        do {
            _ = try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { _ in
                throw FixtureError.sendFailed
            }
            XCTFail("Expected send failure")
        } catch FixtureError.sendFailed {}
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testNilReplyIsReturnedForCallerValidation() async throws {
        let data = try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { $0(nil) }
        XCTAssertNil(data)
    }

    func testMissingReplyTimesOutAndLateReplyCannotCompleteAnotherRequest() async throws {
        var lateReply: ((Data?) -> Void)?
        do {
            _ = try await ProviderMessageRequest.send(timeoutNanoseconds: 10_000_000) { lateReply = $0 }
            XCTFail("Expected timeout")
        } catch ProviderMessageRequest.RequestError.timedOut {}
        lateReply?(Data("old".utf8))
        let current = try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { $0(Data("new".utf8)) }
        XCTAssertEqual(current, Data("new".utf8))
    }

    func testZeroBudgetDoesNotIssueTheMessage() async {
        var issued = false
        do {
            _ = try await ProviderMessageRequest.send(timeoutNanoseconds: 0) { _ in issued = true }
            XCTFail("Expected timeout")
        } catch ProviderMessageRequest.RequestError.timedOut {}
        catch { XCTFail("Unexpected error: \(error)") }
        XCTAssertFalse(issued)
    }

    func testCancellationBeforeRequestDoesNotIssueTheMessage() async throws {
        var issued = false
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { _ in issued = true }
        }
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        XCTAssertFalse(issued)
    }

    func testCancellationOfIssuedRequestRejectsItsLateReply() async throws {
        let entered = AsyncResultCompletion<Void>()
        var lateReply: ((Data?) -> Void)?
        let task = Task {
            try await ProviderMessageRequest.send(timeoutNanoseconds: 1_000_000_000) { reply in
                lateReply = reply
                entered.finish(.success(()))
            }
        }
        let admission = await withCheckedContinuation { entered.park($0) }
        try admission.get()
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch is CancellationError {}
        lateReply?(Data("ok".utf8))
    }
}
