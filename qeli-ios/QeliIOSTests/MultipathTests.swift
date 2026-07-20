import XCTest
@testable import Qeli

final class MultipathTests: XCTestCase {
    func testJoinPayloadAndAcknowledgement() throws {
        let token = try JoinHandshake.parseToken("00112233445566778899aabbccddeeff")
        let payload = try JoinHandshake.buildPayload(token: token, streamIndex: 3)
        XCTAssertEqual(payload.prefix(8), Data("QELIJOIN".utf8))
        XCTAssertEqual(payload.count, 25)
        XCTAssertEqual(payload.last, 3)
        XCTAssertNoThrow(try JoinHandshake.validateAcknowledgement(Data("JOINOK".utf8)))
        XCTAssertThrowsError(try JoinHandshake.validateAcknowledgement(Data("NO".utf8)))
    }

    func testFixedSchedulerRoundRobinsLiveStreams() {
        let scheduler = MultipathScheduler(maximumStreams: 4, adaptive: false)
        XCTAssertEqual(scheduler.initialSecondaryIndexes, [1, 2, 3])
        scheduler.markJoined(index: 1)
        scheduler.markJoined(index: 2)
        XCTAssertEqual((0..<5).compactMap { _ in scheduler.selectStream() }, [0, 1, 2, 0, 1])
        XCTAssertFalse(scheduler.markDead(index: 1))
        XCTAssertFalse(scheduler.markDead(index: 0))
        XCTAssertTrue(scheduler.markDead(index: 2))
    }

    func testAdaptiveSchedulerRampsThenDetectsPlateau() {
        let scheduler = MultipathScheduler(maximumStreams: 3, adaptive: true)
        XCTAssertEqual(
            scheduler.observeThroughput(totalBytes: 900_003),
            .openStream(index: 1, rateBytesPerSecond: 300_001)
        )
        scheduler.markJoined(index: 1)
        XCTAssertEqual(
            scheduler.observeThroughput(totalBytes: 1_710_003),
            .plateau(rateBytesPerSecond: 270_000)
        )
    }
}
