import Foundation
import XCTest
@testable import Qeli

final class CarrierDiagnosticsTests: XCTestCase {
    static func row(id: Int64 = 1, finished: Int64 = 0, pending: Int64 = 1, activity: String = "active") -> [String: Any] {
        var row: [String: Any] = [:]
        for key in CarrierDiagnosticsSnapshot.Carrier.counterNames { row[key] = Int64(0) }
        for key in CarrierDiagnosticsSnapshot.Carrier.ageNames { row[key] = NSNull() }
        row["carrier_id"] = id
        row["accepted_packets"] = pending > 0 ? 1 : 0
        row["pending_packets"] = pending
        row["local_finished_bytes"] = finished
        row["closed"] = false
        row["accounting_supported"] = true
        row["activity"] = activity
        row["progress_boundary"] = "carrier_io_acceptance"
        return row
    }

    static func object(runID: Int64 = 1, elapsed: Int64 = 1_000, rows: [[String: Any]]? = nil) -> [String: Any] {
        [
            "schema": 1, "scope": "tcp_uplink", "completion": "local_write_flush_not_peer_ack",
            "age_semantics": "queue_wait_sample_and_pending_episode", "progress_timestamps": "sampled",
            "payloads": "queued_tunnel_payloads_including_control", "supported": true,
            "runtime_available": true, "finished": false, "run_id": runID,
            "elapsed_ms": elapsed, "omitted_carriers": 0, "carriers": rows ?? [row()]
        ]
    }

    static func data(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: .sortedKeys) }

    static func snapshot(runID: Int64 = 1, elapsed: Int64 = 1_000, rows: [[String: Any]]? = nil) throws -> CarrierDiagnosticsSnapshot {
        try XCTUnwrap(CarrierDiagnosticsSnapshot.parse(data(object(runID: runID, elapsed: elapsed, rows: rows))))
    }

    func testAllowedNumericProjectionStripsEveryUnknownField() throws {
        var row = Self.row()
        row["remote_address"] = "private-vpn.example"
        var object = Self.object(rows: [row])
        object["username"] = "never-export-user"
        let snapshot = try XCTUnwrap(CarrierDiagnosticsSnapshot.parse(Self.data(object)))
        let safe = try JSONEncoder().encode(snapshot)
        let text = String(decoding: safe, as: UTF8.self)
        XCTAssertFalse(text.contains("private-vpn.example"))
        XCTAssertFalse(text.contains("never-export-user"))
        XCTAssertFalse(text.contains("remote_address"))
        XCTAssertEqual(try JSONDecoder().decode(CarrierDiagnosticsSnapshot.self, from: safe), snapshot)
        XCTAssertEqual(snapshot.carriers.first?.counter("carrier_id"), 1)
        XCTAssertNil(snapshot.carriers.first?.age("last_queue_wait_ms"))
    }

    func testRejectsBooleansStringsFractionsNegativesAndOverflowAsCounters() throws {
        let invalidCounters: [Any] = [true, "1", -1, 1.5]
        for invalid in invalidCounters {
            var object = Self.object()
            object["run_id"] = invalid
            XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(object)))
            var row = Self.row()
            row["queued_bytes"] = invalid
            XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(Self.object(rows: [row]))))
        }
        let original = String(decoding: try Self.data(Self.object()), as: UTF8.self)
        XCTAssertTrue(original.contains("\"run_id\":1"))
        for invalid in ["1.0", "1e0", "18446744073709551615"] {
            let changed = original.replacingOccurrences(of: "\"run_id\":1", with: "\"run_id\":\(invalid)")
            XCTAssertNil(CarrierDiagnosticsSnapshot.parse(Data(changed.utf8)), invalid)
        }
    }

    func testRejectsUnexpectedLabelsDuplicateCarriersMissingFieldsAndOversize() throws {
        var object = Self.object()
        object["scope"] = "other-scope"
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(object)))
        object = Self.object()
        object["supported"] = 1
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(object)))
        var row = Self.row(activity: "unknown-host.example")
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(Self.object(rows: [row]))))
        row = Self.row()
        row.removeValue(forKey: "last_queue_wait_ms")
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(Self.object(rows: [row]))))
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(Self.object(rows: [Self.row(), Self.row()]))))
        XCTAssertNil(try CarrierDiagnosticsSnapshot.parse(Self.data(Self.object(rows: (1...33).map { Self.row(id: Int64($0)) }))))
        XCTAssertNil(CarrierDiagnosticsSnapshot.parse(Data(repeating: 0, count: CarrierDiagnosticsSnapshot.maximumBytes + 1)))
    }

    func testSamplerUsesMonotonicTimeAndDoesNotReplayFrozenOrBackwardsSamples() throws {
        let sampler = CarrierDiagnosticsSampler()
        XCTAssertTrue(sampler.sample(try Self.snapshot()).lines[0].contains("local_Bps=unavailable"))
        let next = try Self.snapshot(elapsed: 2_000, rows: [Self.row(finished: 1_000)])
        XCTAssertTrue(sampler.sample(next).lines[0].contains("local_Bps=1000"))
        XCTAssertTrue(sampler.sample(next).lines.isEmpty)
        let older = try Self.snapshot(elapsed: 1_500, rows: [Self.row(finished: 2_000)])
        let ignored = sampler.sample(older)
        XCTAssertTrue(ignored.lines.isEmpty)
        XCTAssertEqual(ignored.snapshot, next)
        let newRun = try Self.snapshot(runID: 2, elapsed: 50, rows: [Self.row(finished: 10)])
        XCTAssertTrue(sampler.sample(newRun).lines[0].contains("local_Bps=unavailable"))
        XCTAssertNil(sampler.sample(nil).snapshot)
        XCTAssertTrue(sampler.sample(newRun).lines[0].contains("local_Bps=unavailable"))
    }

    func testSamplerLimitsLinesAndPrioritizesDegradedCarriers() throws {
        let rows = (1...8).map { id -> [String: Any] in
            var row = Self.row(id: Int64(id), activity: id == 8 ? "degraded" : "active")
            row["backlog_episode_ms"] = id * 10
            return row
        }
        let result = CarrierDiagnosticsSampler().sample(try Self.snapshot(rows: rows))
        XCTAssertEqual(result.lines.count, 3)
        XCTAssertTrue(result.lines[0].hasPrefix("TCP carrier 8 "))
        XCTAssertTrue(result.lines[2].contains("8 active/changed, 1 degraded"))
        XCTAssertFalse(result.lines.joined().contains("peer delivery"))
    }

    func testIdleAndPreviouslyClosedCarriersDoNotSpamAndHugeRatesCannotTrap() throws {
        let sampler = CarrierDiagnosticsSampler()
        XCTAssertTrue(sampler.sample(try Self.snapshot(rows: [Self.row(pending: 0, activity: "idle")])).lines.isEmpty)
        var closed = Self.row(pending: 0, activity: "closed")
        closed["closed"] = true
        XCTAssertEqual(sampler.sample(try Self.snapshot(elapsed: 2_000, rows: [closed])).lines.count, 1)
        XCTAssertTrue(sampler.sample(try Self.snapshot(elapsed: 3_000, rows: [closed])).lines.isEmpty)
        _ = sampler.sample(try Self.snapshot(runID: 2, elapsed: 1))
        let huge = sampler.sample(try Self.snapshot(runID: 2, elapsed: 2, rows: [Self.row(finished: Int64.max)]))
        XCTAssertTrue(huge.lines[0].contains("local_Bps=\(Int64.max)"))
    }

    func testJournalKeepsTimestampedLastKnownMetricsThroughUnavailableTerminalRead() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("qeli-carrier-journal-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = DiagnosticJournalStore(directory: directory)
        let snapshot = try Self.snapshot()
        try journal.setRetainLastErrorReport(true)
        try journal.updateCarrierDiagnostics(snapshot, date: Date(timeIntervalSince1970: 10))
        try journal.updateCarrierDiagnostics(nil, date: Date(timeIntervalSince1970: 12), preserveLastOnUnavailable: true)
        try journal.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: true)
        let report = try JSONDecoder().decode(DiagnosticReport.self, from: journal.report(lastError: true).validatedData())
        XCTAssertEqual(report.carrierMetrics, snapshot)
        XCTAssertEqual(report.carrierMetricsCapturedAtMS, 10_000)
        XCTAssertEqual(report.carrierMetricsUnavailableAtMS, 12_000)
        try journal.updateCarrierDiagnostics(nil, preserveLastOnUnavailable: false)
        let current = try JSONDecoder().decode(DiagnosticReport.self, from: journal.report(lastError: false).validatedData())
        XCTAssertNil(current.carrierMetrics)
        XCTAssertNil(current.carrierMetricsCapturedAtMS)
    }

    func testMetricPollingDoesNotRewriteJournalAndNormalStopRemovesOnlyCurrentMetrics() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("qeli-metric-persistence-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = DiagnosticJournalStore(directory: directory)
        try journal.setRetainLastErrorReport(true)
        try journal.append("connected", sessionID: "abc12345")
        let journalURL = directory.appendingPathComponent("journal.json")
        let metricsURL = directory.appendingPathComponent("carrier-metrics.json")
        let before = try Data(contentsOf: journalURL)
        try journal.updateCarrierDiagnostics(Self.snapshot(), date: Date(timeIntervalSince1970: 10))
        try journal.updateCarrierDiagnostics(Self.snapshot(elapsed: 2_000), date: Date(timeIntervalSince1970: 11))
        XCTAssertEqual(try Data(contentsOf: journalURL), before)
        try journal.finish(sessionID: "abc12345", clear: true, terminalError: true, retentionAllowed: true)
        let saved = try journal.report(lastError: true).data
        try journal.finish(sessionID: "def12345", clear: true, terminalError: false, retentionAllowed: true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: metricsURL.path))
        XCTAssertEqual(try journal.report(lastError: true).data, saved)
        let current = try JSONDecoder().decode(DiagnosticReport.self, from: journal.report(lastError: false).data)
        XCTAssertNil(current.carrierMetrics)
        XCTAssertTrue(current.events.isEmpty)
    }

    func testCorruptOrOversizedMetricsFailClosedAndClearRepairsThem() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("qeli-corrupt-metrics-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = DiagnosticJournalStore(directory: directory)
        try journal.append("connected", sessionID: "abc12345")
        let metricsURL = directory.appendingPathComponent("carrier-metrics.json")
        for corrupt in [Data("not-json".utf8), Data(repeating: 0, count: DiagnosticJournalStore.maximumMetricsBytes + 1)] {
            try corrupt.write(to: metricsURL)
            XCTAssertThrowsError(try journal.report(lastError: false))
            try journal.clear()
            XCTAssertFalse(FileManager.default.fileExists(atPath: metricsURL.path))
            XCTAssertNoThrow(try journal.report(lastError: false))
        }
        try Data("not-json".utf8).write(to: metricsURL)
        try journal.updateCarrierDiagnostics(Self.snapshot())
        XCTAssertNoThrow(try journal.report(lastError: false))
    }

    func testAbsentMetricsAreUnavailableAndSavedErrorCaptureIsIndependent() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("qeli-missing-metrics-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let journal = DiagnosticJournalStore(directory: directory)
        try journal.setRetainLastErrorReport(true)
        let original = try Self.snapshot()
        try journal.updateCarrierDiagnostics(original)
        try journal.finish(sessionID: "abc12345", clear: false, terminalError: true, retentionAllowed: true)
        try FileManager.default.removeItem(at: directory.appendingPathComponent("carrier-metrics.json"))
        let current = try JSONDecoder().decode(DiagnosticReport.self, from: journal.report(lastError: false).data)
        let saved = try JSONDecoder().decode(DiagnosticReport.self, from: journal.report(lastError: true).data)
        XCTAssertNil(current.carrierMetrics)
        XCTAssertEqual(saved.carrierMetrics, original)
        try journal.setRetainLastErrorReport(false)
        XCTAssertThrowsError(try journal.report(lastError: true))
    }
}
