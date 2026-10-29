import XCTest
@testable import Qeli

final class IOSRoamingObservationPolicyTests: XCTestCase {
    func testFirstUsableObservationEstablishesBaseline() {
        XCTAssertEqual(action(previous: nil, current: "wifi", lost: false), .establishBaseline)
    }

    func testDuplicateCallbackPreservesPendingCandidate() {
        XCTAssertEqual(action(previous: "wifi", current: "cellular", lost: false), .submit)
        // The controller records the target signature before its debounce completes.
        // KEEP must leave that task and its revision alive when a duplicate arrives.
        XCTAssertEqual(action(previous: "cellular", current: "cellular", lost: false), .keep)
    }

    func testLossThenSameNetworkRequiresFreshCandidate() {
        XCTAssertEqual(action(previous: "wifi", current: "wifi", lost: true), .submit)
        XCTAssertEqual(action(previous: "wifi", current: "cellular", lost: true), .submit)
        // A loss before the first monitor callback must not suppress recovery either.
        XCTAssertEqual(action(previous: nil, current: "wifi", lost: true), .submit)
    }

    func testRecoveredPathDuplicateDoesNotCancelRecoveryOrRearmFallback() {
        XCTAssertEqual(action(previous: "wifi", current: "wifi", lost: true), .submit)
        // SUBMIT clears waitingForReplacement and advances the observation revision,
        // invalidating a late loss timer; the next identical callback is a no-op.
        XCTAssertEqual(action(previous: "wifi", current: "wifi", lost: false), .keep)
    }

    func testNewPathSupersedesPendingCandidate() {
        XCTAssertEqual(action(previous: "cellular", current: "wifi", lost: false), .submit)
    }

    private func action(
        previous: String?, current: String, lost: Bool
    ) -> IOSRoamingObservationPolicy.Action {
        IOSRoamingObservationPolicy.usablePathAction(
            previousSignature: previous, signature: current, waitingForReplacement: lost)
    }
}
