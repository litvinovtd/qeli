import XCTest
@testable import Qeli

final class QRScannerDeliveryGateTests: XCTestCase {
    func testDuplicateFramesDeliverOnlyOneCode() {
        var gate = QRScannerDeliveryGate()
        XCTAssertEqual(gate.consume("qeli://first"), "qeli://first")
        XCTAssertNil(gate.consume("qeli://first"))
        XCTAssertNil(gate.consume("qeli://second"))
        XCTAssertFalse(gate.acceptsCallbacks)
    }

    func testUnrelatedCodeDoesNotConsumeScanner() {
        var gate = QRScannerDeliveryGate()
        XCTAssertNil(gate.consume("https://example.invalid"))
        XCTAssertTrue(gate.acceptsCallbacks)
        XCTAssertEqual(gate.consume("qeli://profile"), "qeli://profile")
    }

    func testOversizedPayloadIsBoundedWithoutBlockingNextScan() {
        var gate = QRScannerDeliveryGate()
        XCTAssertNil(gate.consume("qeli://" + String(repeating: "x", count: QRScannerDeliveryGate.maximumPayloadBytes)))
        XCTAssertTrue(gate.acceptsCallbacks)
        XCTAssertEqual(gate.consume("qeli://profile"), "qeli://profile")
    }

    func testDismissalRejectsLatePermissionAndQueuedCodeCallbacks() {
        var capture = QRScannerDeliveryGate()
        var ui = QRScannerDeliveryGate()
        let pending = capture.consume("qeli://profile")
        ui.stop()
        XCTAssertFalse(ui.acceptsCallbacks)
        XCTAssertNil(ui.consume(pending!))
    }

    func testStoppedCaptureCannotDeliverOrRestart() {
        var gate = QRScannerDeliveryGate()
        gate.stop()
        gate.stop()
        XCTAssertFalse(gate.acceptsCallbacks)
        XCTAssertNil(gate.consume("qeli://profile"))
    }
}
