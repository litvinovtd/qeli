import XCTest
@testable import Qeli

final class InitialCarrierResolutionTests: XCTestCase {
    private enum ResolverError: Error { case offline }

    func testSuccessfulInitialLookupRetainsEveryCandidate() async throws {
        let result = try await InitialCarrierResolution.capture {
            ["192.0.2.1", "2001:db8::1"]
        }
        XCTAssertEqual(result.addresses, ["192.0.2.1", "2001:db8::1"])
        XCTAssertNil(result.failure)
    }

    func testTransientInitialFailureBecomesPendingRetry() async throws {
        let result = try await InitialCarrierResolution.capture { throw ResolverError.offline }
        XCTAssertTrue(result.addresses.isEmpty)
        XCTAssertTrue(result.failure is ResolverError)
    }

    func testCancelledLookupCannotBecomeRetryableFailure() async {
        do {
            _ = try await InitialCarrierResolution.capture { throw CancellationError() }
            XCTFail("Cancellation must escape initial lookup")
        } catch is CancellationError { }
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testTaskCancellationWinsOverLateResolverResult() async {
        for resolverFails in [false, true] {
            let task = Task {
                try await InitialCarrierResolution.capture {
                    withUnsafeCurrentTask { $0?.cancel() }
                    if resolverFails { throw ResolverError.offline }
                    return ["192.0.2.1"]
                }
            }
            do {
                _ = try await task.value
                XCTFail("A late resolver result must not restart a stopped tunnel")
            } catch is CancellationError { }
            catch { XCTFail("Unexpected error: \(error)") }
        }
    }

    func testColdRetryBypassesSystemDNSBehindBootstrap() async throws {
        var systemCalls = 0
        var scopedCalls = 0
        let result = try await InitialCarrierResolution.resolveRetry(
            lastKnown: [],
            system: { systemCalls += 1; throw ResolverError.offline },
            scoped: { scopedCalls += 1; return ["2001:db8::2"] })
        XCTAssertEqual(result, ["2001:db8::2"])
        XCTAssertEqual(systemCalls, 0)
        XCTAssertEqual(scopedCalls, 1)
    }

    func testWarmRetryPreservesCompleteDNSAnswerSet() async throws {
        let result = try await InitialCarrierResolution.resolveRetry(
            lastKnown: ["192.0.2.1"],
            system: { ["192.0.2.2", "2001:db8::2"] },
            scoped: { XCTFail("Warm refresh should retain address rotation"); return [] })
        XCTAssertEqual(result, ["192.0.2.2", "2001:db8::2"])
    }

    func testCancelledColdRetryDiscardsItsLateCandidate() async {
        let task = Task {
            try await InitialCarrierResolution.resolveRetry(
                lastKnown: [], system: { [] }, scoped: {
                    withUnsafeCurrentTask { $0?.cancel() }
                    return ["192.0.2.2"]
                })
        }
        do {
            _ = try await task.value
            XCTFail("A cancelled retry must not launch a replacement transport")
        } catch is CancellationError { }
        catch { XCTFail("Unexpected error: \(error)") }
    }

    func testColdRetryFailurePropagatesToExistingRetryBudget() async {
        do {
            _ = try await InitialCarrierResolution.resolveRetry(
                lastKnown: [], system: { XCTFail("Unscoped DNS must stay unused"); return [] },
                scoped: { throw ResolverError.offline })
            XCTFail("The supervisor must account for the failed retry")
        } catch is ResolverError { }
        catch { XCTFail("Unexpected error: \(error)") }
    }
}
