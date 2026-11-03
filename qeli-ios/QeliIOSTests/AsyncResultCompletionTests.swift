import XCTest
@testable import Qeli

final class AsyncResultCompletionTests: XCTestCase {
    private enum FixtureError: Error { case expected }

    func testCancellationBeforeParkKeepsItsOriginalOutcome() async {
        let completion = AsyncResultCompletion<Int>()
        completion.finish(.failure(CancellationError()))
        let result = await withCheckedContinuation { completion.park($0) }
        do { _ = try result.get(); XCTFail("Expected cancellation") }
        catch is CancellationError {}
        catch { XCTFail("Outcome was relabelled: \(error)") }
    }

    func testSuccessBeforeParkIsNotRelabelledAsTimeout() async throws {
        let completion = AsyncResultCompletion<Int>()
        completion.finish(.success(7))
        let result = await withCheckedContinuation { completion.park($0) }
        XCTAssertEqual(try result.get(), 7)
    }

    func testFailureBeforeParkAndDuplicateFinishPreserveFirstOutcome() async {
        let completion = AsyncResultCompletion<Int>()
        completion.finish(.failure(FixtureError.expected))
        completion.finish(.success(8))
        let result = await withCheckedContinuation { completion.park($0) }
        do { _ = try result.get(); XCTFail("Expected fixture error") }
        catch FixtureError.expected {}
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testParkThenMultipleFinishesResumesOnlyOnce() async throws {
        let completion = AsyncResultCompletion<Int>()
        let result = await withCheckedContinuation {
            completion.park($0)
            completion.finish(.success(9))
            completion.finish(.failure(FixtureError.expected))
        }
        XCTAssertEqual(try result.get(), 9)
    }
}
