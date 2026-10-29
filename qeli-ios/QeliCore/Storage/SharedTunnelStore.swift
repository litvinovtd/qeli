import Foundation

final class SharedTunnelStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let lock = NSLock()
    private let diagnostics: DiagnosticJournalStore?
    private let diagnosticSessionID = String(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(8)).lowercased()
    private var logSessionClosed = false
    private let snapshotKey = "tunnel.snapshot.v1"
    private let logKey = "tunnel.log.v1"
    static let maximumLogLines = 500
    static let maximumLogMessageBytes = 4 * 1024
    static let maximumLogArchiveBytes = 1024 * 1024

    init(suiteName: String? = AppConstants.appGroupIdentifier, diagnosticJournal: DiagnosticJournalStore? = nil) {
        defaults = suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
        diagnostics = diagnosticJournal ?? (suiteName == AppConstants.appGroupIdentifier
            ? DiagnosticJournalStore.appGroupStore() : nil)
    }

    func snapshot() -> TunnelSnapshot {
        lock.withLock {
            guard let data = defaults.data(forKey: snapshotKey),
                  let value = try? JSONDecoder.shared.decode(TunnelSnapshot.self, from: data) else {
                return TunnelSnapshot()
            }
            return value
        }
    }

    func save(_ snapshot: TunnelSnapshot) {
        lock.withLock {
            guard let data = try? JSONEncoder.shared.encode(snapshot) else { return }
            defaults.set(data, forKey: snapshotKey)
        }
    }

    func logLines() -> [TunnelLogLine] {
        lock.withLock { readLogLines() }
    }

    private func readLogLines() -> [TunnelLogLine] {
        guard let data = defaults.data(forKey: logKey),
              data.count <= Self.maximumLogArchiveBytes,
              let lines = try? JSONDecoder.shared.decode([TunnelLogLine].self, from: data) else {
            return []
        }
        return lines.suffix(Self.maximumLogLines).map { line in
            var line = line
            line.message = Self.boundedLogMessage(line.message)
            return line
        }
    }

    private static func boundedLogMessage(_ message: String) -> String {
        guard message.utf8.count > maximumLogMessageBytes else { return message }
        let suffix = "… [truncated]"
        var bytes = Array(message.utf8.prefix(maximumLogMessageBytes - suffix.utf8.count))
        // Never split a UTF-8 scalar at the byte budget boundary.
        while String(bytes: bytes, encoding: .utf8) == nil { bytes.removeLast() }
        return String(decoding: bytes, as: UTF8.self) + suffix
    }

    func appendLog(_ message: String, date: Date = Date()) {
        lock.withLock {
            guard !logSessionClosed else { return }
            try? diagnostics?.append(message, sessionID: diagnosticSessionID, date: date)
            var lines = readLogLines()
            lines.append(TunnelLogLine(date: date, message: Self.boundedLogMessage(message)))
            if lines.count > Self.maximumLogLines { lines.removeFirst(lines.count - Self.maximumLogLines) }
            // Escaped control characters can expand sixfold in JSON. Bound actual encoded
            // bytes, retaining a recent suffix, rather than estimating message byte totals.
            while let data = try? JSONEncoder.shared.encode(lines) {
                if data.count <= Self.maximumLogArchiveBytes {
                    defaults.set(data, forKey: logKey)
                    return
                }
                guard lines.count > 1 else { return }
                lines.removeFirst(max(1, lines.count / 4))
            }
        }
    }

    func clearLog() {
        // Compatibility for existing internal callers. The UI uses the throwing variant
        // below so a failed disk cleanup is visible instead of claiming deletion succeeded.
        try? clearDiagnostics()
    }

    func clearDiagnostics() throws {
        try lock.withLock {
            try diagnostics?.clear(retentionAllowed: retentionAllowedBySettings)
            defaults.removeObject(forKey: logKey)
        }
    }

    func setRetainLastErrorReport(_ enabled: Bool) throws {
        guard let diagnostics else {
            if enabled { throw DiagnosticJournalError.unavailable }
            return
        }
        // A new opt-in must not revive a report whose earlier deletion failed. During
        // normal app startup the persisted setting is already true, so preserve it.
        try diagnostics.setRetainLastErrorReport(
            enabled, discardSavedError: enabled && !retentionAllowedBySettings)
    }

    func diagnosticReport(lastError: Bool) throws -> DiagnosticReportExport {
        guard let diagnostics else { throw DiagnosticJournalError.unavailable }
        if lastError && !retentionAllowedBySettings { throw DiagnosticJournalError.noLastError }
        return try diagnostics.report(lastError: lastError, retentionAllowed: { [self] in
            retentionAllowedBySettings
        })
    }

    func updateCarrierDiagnostics(
        _ snapshot: CarrierDiagnosticsSnapshot?, date: Date = Date(), preserveLastOnUnavailable: Bool = false
    ) {
        lock.withLock {
            guard !logSessionClosed else { return }
            try? diagnostics?.updateCarrierDiagnostics(
                snapshot, date: date, preserveLastOnUnavailable: preserveLastOnUnavailable
            )
        }
    }

    /// Read only the opt-in bit, keeping this shared/widget source independent of the
    /// complete app settings model. The app persists `false` before attempting cleanup.
    private struct RetentionConsent: Decodable {
        let retainLastErrorReport: Bool?
    }

    private var retentionAllowedBySettings: Bool {
        guard let data = defaults.data(forKey: "app.settings.v1"),
              let consent = try? JSONDecoder().decode(RetentionConsent.self, from: data) else { return false }
        // Decoding Bool rejects numeric 1, which NSNumber's conditional Bool cast accepts.
        return consent.retainLastErrorReport == true
    }

    /// Each provider start owns a separate store instance. Seal that writer even when
    /// retaining history: delayed callbacks from an old engine must not write into the
    /// next session. Repeated completion must not erase a newer session's journal.
    func finishLogSession(clear: Bool, terminalError: Bool = false) {
        lock.withLock {
            guard !logSessionClosed else { return }
            logSessionClosed = true
            try? diagnostics?.finish(
                sessionID: diagnosticSessionID, clear: clear, terminalError: terminalError,
                retentionAllowed: retentionAllowedBySettings
            )
            // Keep startup/authentication/transport failures available after the alert closes.
            if clear && !terminalError { defaults.removeObject(forKey: logKey) }
        }
    }
}

private extension JSONEncoder {
    static var shared: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }
}

private extension JSONDecoder {
    static var shared: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}

