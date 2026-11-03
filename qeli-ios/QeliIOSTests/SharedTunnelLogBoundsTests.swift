import Foundation
import XCTest
@testable import Qeli

final class SharedTunnelLogBoundsTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var store: SharedTunnelStore!

    override func setUp() {
        super.setUp()
        suite = "qeli.log.tests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        store = SharedTunnelStore(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
        store = nil
        defaults = nil
        super.tearDown()
    }

    func testUnicodeMessageIsBoundedWithoutBreakingScalars() {
        store.appendLog(String(repeating: "🛰", count: 4_000))
        let lines = store.logLines()
        XCTAssertEqual(lines.count, 1)
        XCTAssertLessThanOrEqual(lines[0].message.utf8.count, SharedTunnelStore.maximumLogMessageBytes)
        XCTAssertFalse(lines[0].message.contains("\u{fffd}"))
        XCTAssertTrue(lines[0].message.hasSuffix("[truncated]"))
    }

    func testEscapedMessagesRespectEncodedArchiveBudgetAndKeepLatest() {
        for index in 0..<80 {
            store.appendLog("\(index):" + String(repeating: "\u{0000}", count: 4_000))
        }
        let lines = store.logLines()
        XCTAssertFalse(lines.isEmpty)
        XCTAssertLessThan(lines.count, 80)
        XCTAssertTrue(lines.last!.message.hasPrefix("79:"))
        XCTAssertLessThanOrEqual(defaults.data(forKey: "tunnel.log.v1")!.count, SharedTunnelStore.maximumLogArchiveBytes)
    }

    func testOversizedLegacyArchiveIsRejectedAndNextAppendRepairsIt() {
        defaults.set(Data(repeating: 0, count: SharedTunnelStore.maximumLogArchiveBytes + 1), forKey: "tunnel.log.v1")
        XCTAssertTrue(store.logLines().isEmpty)
        store.appendLog("recovered")
        XCTAssertEqual(store.logLines().map(\.message), ["recovered"])
        XCTAssertLessThanOrEqual(defaults.data(forKey: "tunnel.log.v1")!.count, SharedTunnelStore.maximumLogArchiveBytes)
    }

    func testCountWindowRetainsNewestWithoutChangingTheirIdentity() throws {
        let lines = (0..<510).map { TunnelLogLine(message: String($0)) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        defaults.set(try encoder.encode(lines), forKey: "tunnel.log.v1")
        let current = store.logLines()
        XCTAssertEqual(current.count, SharedTunnelStore.maximumLogLines)
        XCTAssertEqual(current.first?.message, "10")
        XCTAssertEqual(current.last?.id, lines.last?.id)
        store.appendLog("last")
        XCTAssertEqual(store.logLines().last?.message, "last")
        XCTAssertEqual(store.logLines().count, SharedTunnelStore.maximumLogLines)
    }
}
