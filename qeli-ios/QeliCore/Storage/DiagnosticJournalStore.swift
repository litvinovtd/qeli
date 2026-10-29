import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum DiagnosticJournalError: LocalizedError {
    case unavailable, invalidArchive, noLastError, changed
    var errorDescription: String? {
        switch self {
        case .unavailable: return "Diagnostic storage is unavailable."
        case .invalidArchive: return "The diagnostic archive is invalid or too large. Use Clear to remove it."
        case .noLastError: return "No saved error report is available."
        case .changed: return "Diagnostic data changed while the export was open. Prepare a new report."
        }
    }
}

struct DiagnosticReportExport: Sendable {
    let data: Data
    let defaultFilename: String
    private let store: DiagnosticJournalStore
    private let revision: UUID
    private let retentionAllowed: (@Sendable () -> Bool)?

    fileprivate init(
        data: Data, lastError: Bool, store: DiagnosticJournalStore, revision: UUID,
        retentionAllowed: (@Sendable () -> Bool)?
    ) {
        self.data = data
        defaultFilename = lastError ? "qeli-last-error.json" : "qeli-diagnostics.json"
        self.store = store
        self.revision = revision
        self.retentionAllowed = lastError ? retentionAllowed : nil
    }

    /// Recheck whenever SwiftUI materializes the FileDocument. The system owns any bytes
    /// already handed to its exporter; local Clear cannot recall an external copy.
    func validatedData() throws -> Data {
        // The app persists revoked consent before disk cleanup. Recheck it even if a
        // failed journal replacement left the archive's old revision intact.
        guard retentionAllowed?() != false else { throw DiagnosticJournalError.noLastError }
        try store.validate(revision: revision)
        return data
    }
}

/// Only bounded, classified metadata reaches this file. File locking serializes app and
/// packet-provider writers; an atomic replacement prevents partially written archives.
final class DiagnosticJournalStore: @unchecked Sendable {
    static let maximumArchiveBytes = 1024 * 1024
    static let maximumMetricsBytes = 128 * 1024
    private static let processLock = NSLock()
    private let directory: URL
    private var archiveURL: URL { directory.appendingPathComponent("journal.json") }
    private var metricsURL: URL { directory.appendingPathComponent("carrier-metrics.json") }

    private struct Archive: Codable {
        var schema = 1
        var revision = UUID()
        var events: [DiagnosticEvent] = []
        var retainLastErrorReport = false
        var lastError: DiagnosticReport?
    }

    private struct Metrics: Codable {
        var snapshot: CarrierDiagnosticsSnapshot?
        var capturedAtMS: Int64?
        var unavailableAtMS: Int64?
    }

    init(directory: URL) { self.directory = directory }

    static func appGroupStore() -> DiagnosticJournalStore? {
        #if os(iOS) || os(macOS)
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppConstants.appGroupIdentifier
        ) else { return nil }
        return DiagnosticJournalStore(directory: container.appendingPathComponent("Library/Application Support/QeliDiagnostics", isDirectory: true))
        #else
        return nil
        #endif
    }

    func append(_ message: String, sessionID: String, date: Date = Date()) throws {
        let event = DiagnosticEvent(message: message, sessionID: sessionID, date: date)
        try locked {
            var archive = try read()
            archive.events.append(event)
            if archive.events.count > DiagnosticReport.maximumEvents {
                archive.events.removeFirst(archive.events.count - DiagnosticReport.maximumEvents)
            }
            try write(archive)
        }
    }

    func setRetainLastErrorReport(_ enabled: Bool, discardSavedError: Bool = false) throws {
        try locked {
            var archive = try read()
            guard archive.retainLastErrorReport != enabled || (!enabled && archive.lastError != nil)
                    || discardSavedError else { return }
            archive.retainLastErrorReport = enabled
            if !enabled || discardSavedError { archive.lastError = nil }
            archive.revision = UUID()
            try write(archive)
        }
    }

    func updateCarrierDiagnostics(
        _ snapshot: CarrierDiagnosticsSnapshot?, date: Date = Date(), preserveLastOnUnavailable: Bool = false
    ) throws {
        try locked {
            var metrics = snapshot == nil && preserveLastOnUnavailable ? try readMetrics() : Metrics()
            if let snapshot {
                metrics.snapshot = snapshot
                metrics.capturedAtMS = DiagnosticReport.timestamp(date)
                metrics.unavailableAtMS = nil
            } else {
                if !preserveLastOnUnavailable {
                    metrics.snapshot = nil
                    metrics.capturedAtMS = nil
                }
                metrics.unavailableAtMS = DiagnosticReport.timestamp(date)
            }
            // Frequent counter sampling must not rewrite the event history and saved report.
            try write(metrics, to: metricsURL, maximumBytes: Self.maximumMetricsBytes)
        }
    }

    func finish(sessionID: String, clear: Bool, terminalError: Bool, retentionAllowed: Bool) throws {
        try locked {
            var archive = try read()
            if terminalError, retentionAllowed, archive.retainLastErrorReport {
                archive.lastError = try makeReport(archive, sessionID: sessionID, kind: .terminalError)
                archive.revision = UUID()
            }
            // Match the raw log policy: terminal failures keep their current history.
            if clear && !terminalError {
                archive.events = []
                archive.revision = UUID()
            }
            try write(archive)
            if clear && !terminalError { try removeMetrics() }
        }
    }

    func clear(retentionAllowed: Bool? = nil) throws {
        try locked {
            // Clear must also recover a corrupt archive; no untrusted report survives it.
            var archive = (try? read()) ?? Archive()
            // A corrupt archive has no trustworthy consent bit. The app's current
            // preference restores it so Clear does not silently disable an active opt-in.
            if let retentionAllowed { archive.retainLastErrorReport = retentionAllowed }
            archive.events = []
            archive.lastError = nil
            archive.revision = UUID()
            try write(archive)
            try removeMetrics()
        }
    }

    func report(
        lastError: Bool, retentionAllowed: (@Sendable () -> Bool)? = nil
    ) throws -> DiagnosticReportExport {
        try locked {
            let archive = try read()
            let report: DiagnosticReport
            if lastError {
                guard retentionAllowed?() != false, archive.retainLastErrorReport,
                      let saved = archive.lastError else {
                    throw DiagnosticJournalError.noLastError
                }
                report = saved
            } else {
                report = try makeReport(archive, sessionID: archive.events.last?.sessionID ?? "", kind: .current)
            }
            // An empty, previously unused store needs a stable revision for the exporter.
            if !FileManager.default.fileExists(atPath: archiveURL.path) { try write(archive) }
            return DiagnosticReportExport(
                data: try report.data(), lastError: lastError, store: self,
                revision: archive.revision, retentionAllowed: retentionAllowed)
        }
    }

    fileprivate func validate(revision: UUID) throws {
        try locked {
            guard try read().revision == revision else { throw DiagnosticJournalError.changed }
        }
    }

    private func makeReport(_ archive: Archive, sessionID: String, kind: DiagnosticReport.Kind) throws -> DiagnosticReport {
        let metrics = try readMetrics()
        return DiagnosticReport(
            events: archive.events, sessionID: sessionID, kind: kind,
            carrierMetrics: metrics.snapshot, carrierMetricsCapturedAtMS: metrics.capturedAtMS,
            carrierMetricsUnavailableAtMS: metrics.unavailableAtMS
        )
    }

    private func read() throws -> Archive {
        guard let data = try readData(from: archiveURL, maximumBytes: Self.maximumArchiveBytes) else { return Archive() }
        let archive = try JSONDecoder().decode(Archive.self, from: data)
        guard archive.schema == 1, archive.events.count <= DiagnosticReport.maximumEvents else {
            throw DiagnosticJournalError.invalidArchive
        }
        return archive
    }

    private func write(_ archive: Archive) throws {
        try write(archive, to: archiveURL, maximumBytes: Self.maximumArchiveBytes)
    }

    private func readMetrics() throws -> Metrics {
        guard let data = try readData(from: metricsURL, maximumBytes: Self.maximumMetricsBytes) else { return Metrics() }
        return try JSONDecoder().decode(Metrics.self, from: data)
    }

    private func removeMetrics() throws {
        if FileManager.default.fileExists(atPath: metricsURL.path) { try FileManager.default.removeItem(at: metricsURL) }
    }

    private func readData(from url: URL, maximumBytes: Int) throws -> Data? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max
        guard size <= maximumBytes else { throw DiagnosticJournalError.invalidArchive }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else { throw DiagnosticJournalError.invalidArchive }
        return data
    }

    private func write<T: Encodable>(_ value: T, to url: URL, maximumBytes: Int) throws {
        let data = try JSONEncoder().encode(value)
        guard data.count <= maximumBytes else { throw DiagnosticJournalError.invalidArchive }
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try data.write(to: url, options: .atomic)
        #endif
    }

    private func locked<T>(_ operation: () throws -> T) throws -> T {
        Self.processLock.lock()
        defer { Self.processLock.unlock() }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        #if os(iOS) || os(macOS)
        var directory = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try directory.setResourceValues(values)
        #endif
        let descriptor = open(directory.appendingPathComponent("journal.lock").path, O_CREAT | O_RDWR, mode_t(0o600))
        guard descriptor >= 0 else { throw DiagnosticJournalError.unavailable }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw DiagnosticJournalError.unavailable }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try operation()
    }
}
