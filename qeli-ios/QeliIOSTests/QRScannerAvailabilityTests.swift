import XCTest
@testable import Qeli

@MainActor
final class QRScannerAvailabilityTests: XCTestCase {
    func testRuntimeCameraRestrictionReplacesPreviewOnce() {
        let scanner = QRCameraViewController(locale: Locale(identifier: "en"), onCode: { _ in
            XCTFail("unavailability must not import a profile")
        })
        // Invalidating before loading the view also proves no authorization or capture
        // can start from a late UIKit load after shutdown. No camera is used by this test.
        XCTAssertFalse(scanner.isViewLoaded)
        scanner.cameraBecameUnavailable()
        XCTAssertEqual(scanner.children.count, 1)
        scanner.cameraBecameUnavailable()
        XCTAssertEqual(scanner.children.count, 1)
        scanner.shutdown()
        XCTAssertEqual(scanner.children.count, 1)
    }
}
