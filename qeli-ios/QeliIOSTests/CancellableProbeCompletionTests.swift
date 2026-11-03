import XCTest
@testable import Qeli

final class CancellableProbeCompletionTests: XCTestCase {
    private enum FixtureError: Error { case expected }

    func testCancelBeforeParkPreventsResourceStartAndCleansOnce() async {
        var cleaned = 0
        var started = false
        let completion = CancellableProbeCompletion<Int> { cleaned += 1 }
        completion.finish(.failure(CancellationError()))
        completion.start { started = true }
        completion.finish(.success(1))
        let result = await withCheckedContinuation { completion.park($0) }
        do { _ = try result.get(); XCTFail("Expected cancellation") }
        catch is CancellationError {}
        catch { XCTFail("Unexpected error: \(error)") }
        XCTAssertFalse(started)
        XCTAssertEqual(cleaned, 1)
    }

    func testSynchronousCompletionInsideStartAllowsCleanupReentry() async throws {
        var cleaned = 0
        var starts = 0
        let completion = CancellableProbeCompletion<Int> { cleaned += 1 }
        completion.start {
            starts += 1
            completion.finish(.success(7))
        }
        completion.start { starts += 1 }
        let result = await withCheckedContinuation { completion.park($0) }
        XCTAssertEqual(try result.get(), 7)
        XCTAssertEqual(starts, 1)
        XCTAssertEqual(cleaned, 1)
    }

    func testParkedFailureReleasesResourceCaptureBeforeResumption() async {
        final class Resource {}
        var resource: Resource? = Resource()
        weak var observed = resource
        let completion = CancellableProbeCompletion<Int> { [owned = resource!] in _ = owned }
        resource = nil
        XCTAssertNotNil(observed)
        let result = await withCheckedContinuation {
            completion.park($0)
            completion.finish(.failure(FixtureError.expected))
        }
        XCTAssertNil(observed)
        do { _ = try result.get(); XCTFail("Expected failure") }
        catch FixtureError.expected {}
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testTimeoutAndLateSuccessHaveOneCleanupAndOutcome() async {
        var cleaned = 0
        let completion = CancellableProbeCompletion<Int> { cleaned += 1 }
        completion.start {}
        let result = await withCheckedContinuation {
            completion.park($0)
            completion.finish(.failure(FixtureError.expected))
            completion.finish(.success(8))
        }
        XCTAssertEqual(cleaned, 1)
        do { _ = try result.get(); XCTFail("Expected timeout fixture") }
        catch FixtureError.expected {}
        catch { XCTFail("Unexpected error: \(error)") }
    }
}
