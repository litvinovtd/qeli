import Foundation
import XCTest
@testable import Qeli

final class DiagnosticJournalStoreTests: XCTestCase {
    private var directory: URL!
    private var store: DiagnosticJournalStore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("qeli-diagnostics-\(UUID().uuidString)", isDirectory: true)
        store = DiagnosticJournalStore(directory: directory)
    }

    override func tearDownWithError() throws {
        if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
        store = nil
    }

    private func currentEvents(_ journal: DiagnosticJournalStore? = nil) throws -> [DiagnosticEvent] {
        try JSONDecoder().decode(DiagnosticReport.self, from: (journal ?? store).report(lastError: false).validatedData()).events
    }

    func testLastErrorRequiresBothPersistedOptInAndCurrentConsent() throws {
        try store.append("ERROR: handshake failed", sessionID: "abc12345")
        try store.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: true)
        XCTAssertThrowsError(try store.report(lastError: true))
        try store.setRetainLastErrorReport(true)
        try store.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: false)
        XCTAssertThrowsError(try store.report(lastError: true))
        try store.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: true)
        let report = try store.report(lastError: true)
        XCTAssertEqual(report.defaultFilename, "qeli-last-error.json")
        XCTAssertEqual(try JSONDecoder().decode(DiagnosticReport.self, from: report.validatedData()).kind, .terminalError)
        XCTAssertEqual(try currentEvents().count, 1)
    }

    func testLastErrorSurvivesNormalDisconnectAndStoreRecreation() throws {
        try store.setRetainLastErrorReport(true)
        try store.append("ERROR: timed out", sessionID: "abc12345")
        try store.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: true)
        let saved = try store.report(lastError: true).data
        try store.finish(sessionID: "def12345", clear: true, terminalError: false, retentionAllowed: true)
        let reopened = DiagnosticJournalStore(directory: directory)
        XCTAssertTrue(try currentEvents(reopened).isEmpty)
        XCTAssertEqual(try reopened.report(lastError: true).validatedData(), saved)
    }

    func testClearAndOptOutInvalidatePreparedExportsAndRemoveSavedError() throws {
        try store.setRetainLastErrorReport(true)
        try store.append("ERROR: private message", sessionID: "abc12345")
        try store.finish(sessionID: "abc12345", clear: false, terminalError: true, retentionAllowed: true)
        let current = try store.report(lastError: false)
        let saved = try store.report(lastError: true)
        try store.setRetainLastErrorReport(false)
        XCTAssertThrowsError(try current.validatedData())
        XCTAssertThrowsError(try saved.validatedData())
        XCTAssertThrowsError(try store.report(lastError: true))
        let beforeClear = try store.report(lastError: false)
        try store.clear()
        XCTAssertThrowsError(try beforeClear.validatedData())
        XCTAssertTrue(try currentEvents().isEmpty)
    }

    func testTwoWritersRetainEachOthersEventsAndArchiveNeverContainsFreeText() throws {
        let other = DiagnosticJournalStore(directory: directory)
        let secret = "never-persist-this-host.example"
        for _ in 0..<30 {
            try store.append("ERROR: \(secret)", sessionID: "abc12345")
            try other.append("connected \(secret)", sessionID: "def12345")
        }
        XCTAssertEqual(try currentEvents().count, 60)
        let bytes = try Data(contentsOf: directory.appendingPathComponent("journal.json"))
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains(secret))
    }

    func testUnavailableMetricsAreExplicitAndClearRemovesTheirTimestamp() throws {
        try store.updateCarrierDiagnostics(nil, date: Date(timeIntervalSince1970: 42), preserveLastOnUnavailable: true)
        let report = try JSONDecoder().decode(DiagnosticReport.self, from: store.report(lastError: false).validatedData())
        XCTAssertNil(report.carrierMetrics)
        XCTAssertNil(report.carrierMetricsCapturedAtMS)
        XCTAssertEqual(report.carrierMetricsUnavailableAtMS, 42_000)
        try store.clear()
        let cleared = try JSONDecoder().decode(DiagnosticReport.self, from: store.report(lastError: false).validatedData())
        XCTAssertNil(cleared.carrierMetricsUnavailableAtMS)
    }

    func testConcurrentWritersDoNotLoseJournalEntries() async throws {
        let first = DiagnosticJournalStore(directory: directory)
        let second = DiagnosticJournalStore(directory: directory)
        let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { tasks in
            for index in 0..<50 {
                tasks.addTask {
                    do {
                        try (index.isMultiple(of: 2) ? first : second).append("connected", sessionID: "abc12345")
                        return true
                    } catch { return false }
                }
            }
            var count = 0
            for await success in tasks { if success { count += 1 } }
            return count
        }
        XCTAssertEqual(successes, 50)
        XCTAssertEqual(try currentEvents().count, 50)
    }

    func testOversizedArchiveIsRejectedAndClearRepairsIt() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(repeating: 0, count: DiagnosticJournalStore.maximumArchiveBytes + 1)
            .write(to: directory.appendingPathComponent("journal.json"))
        XCTAssertThrowsError(try store.report(lastError: false))
        try store.clear()
        try store.append("recovered", sessionID: "abc12345")
        XCTAssertEqual(try currentEvents().count, 1)
    }

    func testSharedLogCaptureSealsOldWritersAndClearRemovesBothHistories() throws {
        let suite = "qeli.diagnostic.integration.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        let shared = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        try shared.setRetainLastErrorReport(true)
        shared.appendLog("ERROR: handshake failed")
        shared.finishLogSession(clear: true, terminalError: true)
        shared.appendLog("late callback")
        XCTAssertEqual(try currentEvents().count, 1)
        XCTAssertNoThrow(try shared.diagnosticReport(lastError: true))
        try shared.clearDiagnostics()
        XCTAssertTrue(shared.logLines().isEmpty)
        XCTAssertTrue(try currentEvents().isEmpty)
        XCTAssertThrowsError(try shared.diagnosticReport(lastError: true))
    }

    func testPreparedLastErrorChecksRevokedConsentBeforeJournalCleanupCompletes() throws {
        let suite = "qeli.diagnostic.revocation.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        let shared = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        try shared.setRetainLastErrorReport(true)
        shared.appendLog("ERROR: handshake failed")
        shared.finishLogSession(clear: false, terminalError: true)
        let saved = try shared.diagnosticReport(lastError: true)
        let current = try shared.diagnosticReport(lastError: false)
        let archiveURL = directory.appendingPathComponent("journal.json")
        let before = try Data(contentsOf: archiveURL)

        // This is also the exact persistent state after an I/O failure during cleanup:
        // AppModel has saved false, but the archive and its revision remain unchanged.
        defaults.set(Data(#"{"retainLastErrorReport":false}"#.utf8), forKey: "app.settings.v1")
        XCTAssertEqual(try Data(contentsOf: archiveURL), before)
        XCTAssertThrowsError(try saved.validatedData())
        XCTAssertThrowsError(try shared.diagnosticReport(lastError: true))
        XCTAssertNoThrow(try current.validatedData())
    }

    func testNewOptInCannotReviveErrorWhosePreviousRemovalDidNotComplete() throws {
        let suite = "qeli.diagnostic.reenable.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        let shared = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        try shared.setRetainLastErrorReport(true)
        shared.appendLog("ERROR: timed out")
        shared.finishLogSession(clear: false, terminalError: true)
        let saved = try shared.diagnosticReport(lastError: true)

        // Ordinary initialization preserves the valid prior capture.
        try shared.setRetainLastErrorReport(true)
        XCTAssertNoThrow(try saved.validatedData())
        defaults.set(Data(#"{"retainLastErrorReport":false}"#.utf8), forKey: "app.settings.v1")
        // Re-enable in AppModel's order: initialize storage, then persist true.
        try shared.setRetainLastErrorReport(true)
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        XCTAssertThrowsError(try saved.validatedData())
        XCTAssertThrowsError(try shared.diagnosticReport(lastError: true))
        let next = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        next.appendLog("ERROR: new connection failed")
        next.finishLogSession(clear: false, terminalError: true)
        XCTAssertNoThrow(try next.diagnosticReport(lastError: true).validatedData())
    }

    func testClearRepairsCorruptArchiveWithoutSilentlyLosingCurrentOptIn() throws {
        let suite = "qeli.diagnostic.repair.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        let shared = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        try shared.setRetainLastErrorReport(true)
        try Data("corrupt".utf8).write(to: directory.appendingPathComponent("journal.json"))
        try shared.clearDiagnostics()
        shared.appendLog("ERROR: connection failed after repair")
        shared.finishLogSession(clear: false, terminalError: true)
        XCTAssertNoThrow(try shared.diagnosticReport(lastError: true).validatedData())
        defaults.set(Data(#"{"retainLastErrorReport":false}"#.utf8), forKey: "app.settings.v1")
        try Data("corrupt".utf8).write(to: directory.appendingPathComponent("journal.json"))
        try shared.clearDiagnostics()
        XCTAssertThrowsError(try store.report(lastError: true))
    }

    func testRetentionRequiresAJSONBooleanRatherThanNumericOrStringConsent() throws {
        let suite = "qeli.diagnostic.strict-consent.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(Data(#"{"retainLastErrorReport":true}"#.utf8), forKey: "app.settings.v1")
        let shared = SharedTunnelStore(suiteName: suite, diagnosticJournal: store)
        try shared.setRetainLastErrorReport(true)
        shared.appendLog("ERROR: handshake failed")
        shared.finishLogSession(clear: false, terminalError: true)
        let prepared = try shared.diagnosticReport(lastError: true)
        for invalid in ["1", "0", "\"true\"", "null", "false"] {
            defaults.set(Data("{\"retainLastErrorReport\":\(invalid)}".utf8), forKey: "app.settings.v1")
            XCTAssertThrowsError(try shared.diagnosticReport(lastError: true), invalid)
            XCTAssertThrowsError(try prepared.validatedData(), invalid)
        }
        defaults.set(Data("{}".utf8), forKey: "app.settings.v1")
        XCTAssertThrowsError(try prepared.validatedData())
        defaults.removeObject(forKey: "app.settings.v1")
        XCTAssertThrowsError(try prepared.validatedData())
    }
}
