import Foundation
import XCTest
@testable import Qeli

final class TunnelProfileSelectionTests: XCTestCase {
    func testExplicitRequestWinsEvenWhenConfiguredProfileIsDifferent() {
        let requested = UUID()
        let configured = UUID()
        XCTAssertEqual(
            TunnelProfileSelection.resolve(requested: requested.uuidString as NSString, configured: configured.uuidString),
            requested
        )
    }

    func testMalformedExplicitRequestDoesNotFallBackToConfiguredProfile() {
        let configured = UUID().uuidString
        for raw in ["", "not-a-uuid", NSNumber(value: 1), NSNull()] as [Any] {
            XCTAssertNil(TunnelProfileSelection.resolve(requested: raw, configured: configured))
        }
    }

    func testAutomaticLaunchUsesOnlyValidPersistedSelection() {
        let configured = UUID()
        XCTAssertEqual(TunnelProfileSelection.resolve(requested: nil, configured: configured.uuidString), configured)
        for raw in ["", "not-a-uuid", NSNumber(value: 1), NSNull()] as [Any] {
            XCTAssertNil(TunnelProfileSelection.resolve(requested: nil, configured: raw))
        }
        XCTAssertNil(TunnelProfileSelection.resolve(requested: nil, configured: nil))
    }

    func testStaleExplicitUUIDIsNotReplacedByAnotherConfiguredUUID() {
        let removedProfile = UUID()
        let configuredProfile = UUID()
        let selected = TunnelProfileSelection.resolve(
            requested: removedProfile.uuidString, configured: configuredProfile.uuidString
        )
        let availableProfileIDs = [configuredProfile]
        XCTAssertEqual(selected, removedProfile)
        XCTAssertFalse(availableProfileIDs.contains(where: { $0 == selected }))
    }
}
