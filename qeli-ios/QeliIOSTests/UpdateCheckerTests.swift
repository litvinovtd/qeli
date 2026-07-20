import XCTest
@testable import Qeli

final class UpdateCheckerTests: XCTestCase {
    func testVersionNormalizationAndNumericComparison() {
        XCTAssertEqual(UpdateChecker.normalize(" v0.7.12-beta+5 "), "0.7.12")
        XCTAssertTrue(UpdateChecker.isNewer("0.10.0", than: "0.9.9"))
        XCTAssertFalse(UpdateChecker.isNewer("v0.7.12", than: "0.7.12+715"))
        XCTAssertFalse(UpdateChecker.isNewer("0.7.11", than: "0.7.12"))
    }
}
