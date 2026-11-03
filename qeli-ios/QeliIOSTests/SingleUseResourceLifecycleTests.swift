import XCTest
@testable import Qeli

final class SingleUseResourceLifecycleTests: XCTestCase {
    func testStopBeforeStartRejectsAResumedOldStart() {
        var lifecycle = SingleUseResourceLifecycle()
        XCTAssertFalse(lifecycle.stop())
        XCTAssertFalse(lifecycle.start())
        XCTAssertFalse(lifecycle.active)
    }

    func testRepeatedStartDoesNotStartTheResourceTwice() {
        var lifecycle = SingleUseResourceLifecycle()
        XCTAssertTrue(lifecycle.start())
        XCTAssertFalse(lifecycle.start())
        XCTAssertTrue(lifecycle.active)
    }

    func testStopAfterStartCancelsExactlyOnceAndPermanentlyClosesIt() {
        var lifecycle = SingleUseResourceLifecycle()
        XCTAssertTrue(lifecycle.start())
        XCTAssertTrue(lifecycle.stop())
        XCTAssertFalse(lifecycle.stop())
        XCTAssertFalse(lifecycle.start())
        XCTAssertFalse(lifecycle.active)
    }
}
