import Foundation
import XCTest
@testable import Qeli

final class DiagnosticReportTests: XCTestCase {
    func testExportClassifiesMessagesWithoutCopyingSecretsOrAddresses() throws {
        let secret = "user=alice password=never-export-me vpn.private.example 192.0.2.43"
        let events = [
            DiagnosticEvent(message: "ERROR: handshake failed \(secret)", sessionID: "abcd1234", date: Date(timeIntervalSince1970: 123)),
            DiagnosticEvent(message: secret, sessionID: secret, date: Date())
        ]
        let data = try DiagnosticReport(events: events, sessionID: secret, kind: .current).data()
        let text = String(decoding: data, as: UTF8.self)
        for value in ["alice", "never-export-me", "vpn.private.example", "192.0.2.43", "password"] {
            XCTAssertFalse(text.contains(value))
        }
        let report = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(report["raw_messages_included"] as? Bool, false)
        XCTAssertTrue(report["carrier_metrics"] is NSNull)
        XCTAssertEqual(report["carrier_metrics_status"] as? String, "unavailable")
        XCTAssertEqual(report["session_id"] as? String, "")
        XCTAssertEqual(events[0].event, .handshake)
        XCTAssertEqual(events[0].timestampMS, 123_000)
    }

    func testRecognizesIOSFailureReasonsAndUnknownMessagesStayUnknown() {
        let messages: [(String, DiagnosticEvent.Reason)] = [
            ("Native generation failed: something private", .nativeGenerationFailed),
            ("ERROR: SERVER KEY MISMATCH", .permissionOrSecurityRejection),
            ("iOS physical path lost — waiting for a replacement carrier", .physicalNetworkLost),
            ("No usable physical network; reconnect parked", .noUsableNetwork),
            ("KICK: arbitrary server text", .serverTerminatedSession),
            ("unrecognized arbitrary server text", .unspecified)
        ]
        for (message, expected) in messages {
            XCTAssertEqual(DiagnosticEvent(message: message, sessionID: "abc12345", date: Date()).reasonCode, expected)
        }
    }

    func testBoundedReportsKeepMostRecentEventsAndSanitizeSessionIDs() throws {
        var events = (0..<600).map {
            DiagnosticEvent(message: "connected", sessionID: "abc12345", date: Date(timeIntervalSince1970: Double($0)))
        }
        events[599].sessionID = "untrusted-network-name"
        let report = DiagnosticReport(events: events, sessionID: "abc12345", kind: .current)
        XCTAssertEqual(report.events.count, DiagnosticReport.maximumEvents)
        XCTAssertEqual(report.events.first?.timestampMS, 100_000)
        XCTAssertEqual(report.events.last?.sessionID, "")
        XCTAssertLessThanOrEqual(try report.data().count, DiagnosticReport.maximumBytes)
        XCTAssertEqual(try JSONDecoder().decode(DiagnosticReport.self, from: report.data()), report)
    }

    func testNonFiniteAndOutOfRangeDatesCannotTrapOrExportUnexpectedNumbers() {
        for value in [Double.nan, Double.infinity, -1, Double.greatestFiniteMagnitude] {
            XCTAssertEqual(DiagnosticReport.timestamp(Date(timeIntervalSince1970: value)), 0)
        }
    }
}
