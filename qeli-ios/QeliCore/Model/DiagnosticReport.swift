import Foundation

/// A diagnostic report never copies free text. Unknown messages become `other`.
struct DiagnosticEvent: Codable, Equatable, Sendable {
    enum Category: String, Codable, Sendable {
        case carrierHealth = "carrier_health", session, recovery
        case physicalNetwork = "physical_network", dns, pathMTU = "path_mtu"
        case handshake, tunnel, connectionState = "connection_state", timeout, error, other
    }
    enum Reason: String, Codable, Sendable {
        case nativeGenerationFailed = "native_generation_failed"
        case reconnectDisabled = "reconnect_disabled", retryBudgetExhausted = "retry_budget_exhausted"
        case serverTerminatedSession = "server_terminated_session"
        case permissionOrSecurityRejection = "permission_or_security_rejection"
        case carrierDNSEmpty = "carrier_dns_empty", dnsLookupFailed = "dns_lookup_failed"
        case operationTimedOut = "operation_timed_out", physicalNetworkLost = "physical_network_lost"
        case noUsableNetwork = "no_usable_network", linkMTUChanged = "link_mtu_changed"
        case userDisconnect = "user_disconnect", transportClosedCleanly = "transport_closed_cleanly"
        case unspecified
    }
    enum Level: String, Codable, Sendable { case info, error }

    var timestampMS: Int64
    var sessionID: String
    var level: Level
    var event: Category
    var reasonCode: Reason

    enum CodingKeys: String, CodingKey {
        case timestampMS = "timestamp_ms", sessionID = "session_id", level, event
        case reasonCode = "reason_code"
    }

    init(message: String, sessionID: String, date: Date) {
        timestampMS = DiagnosticReport.timestamp(date)
        self.sessionID = DiagnosticReport.safeSession(sessionID)
        let value = String(decoding: message.utf8.prefix(4096), as: UTF8.self).lowercased()
        level = value.hasPrefix("error") || value.contains("failed") ? .error : .info
        if value.hasPrefix("carrier diagnostics") || value.hasPrefix("tcp carrier ") { event = .carrierHealth }
        else if value.hasPrefix("session ") || value.hasPrefix("=== vpn session ") { event = .session }
        else if value.contains("reconnect") || value.hasPrefix("retry") { event = .recovery }
        else if value.contains("network") || value.contains("carrier") { event = .physicalNetwork }
        else if value.contains("dns") || value.contains("resolve") { event = .dns }
        else if value.contains("mtu") { event = .pathMTU }
        else if value.contains("handshake") { event = .handshake }
        else if value.contains("tun") || value.contains("route") { event = .tunnel }
        else if value.contains("connected") || value.contains("disconnect") { event = .connectionState }
        else if value.contains("timeout") || value.contains("timed out") { event = .timeout }
        else if value.contains("error") || value.contains("fail") { event = .error }
        else { event = .other }

        if value.contains("native generation failed") || value.contains("native transport generation failed") { reasonCode = .nativeGenerationFailed }
        else if value.contains("reconnect is disabled") { reasonCode = .reconnectDisabled }
        else if value.contains("max reconnect retries") { reasonCode = .retryBudgetExhausted }
        else if value.hasPrefix("kick:") || value.contains("session terminated by server") { reasonCode = .serverTerminatedSession }
        else if value.contains("server key mismatch") || value.contains("permission denied") || value.contains("required entitlements") { reasonCode = .permissionOrSecurityRejection }
        else if value.contains("has no ipv4 or ipv6 carrier address") { reasonCode = .carrierDNSEmpty }
        else if value.contains("dns refresh failed") { reasonCode = .dnsLookupFailed }
        else if value.contains("timed out") || value.contains("timeout") { reasonCode = .operationTimedOut }
        else if value.contains("physical path lost") || value.contains("network lost") { reasonCode = .physicalNetworkLost }
        else if value.contains("no usable") && value.contains("network") { reasonCode = .noUsableNetwork }
        else if value.contains("link mtu changed") { reasonCode = .linkMTUChanged }
        else if value.contains("user disconnect") { reasonCode = .userDisconnect }
        else if value.contains("connection closed cleanly") { reasonCode = .transportClosedCleanly }
        else { reasonCode = .unspecified }
    }
}

struct DiagnosticReport: Codable, Equatable, Sendable {
    enum Kind: String, Codable, Sendable { case current, terminalError = "terminal_error" }
    static let maximumEvents = 500
    static let maximumBytes = 256 * 1024
    var capturedAtMS: Int64
    var sessionID: String
    var kind: Kind
    var events: [DiagnosticEvent]
    var carrierMetrics: CarrierDiagnosticsSnapshot?
    var carrierMetricsCapturedAtMS: Int64?
    var carrierMetricsUnavailableAtMS: Int64?

    init(
        events: [DiagnosticEvent], sessionID: String, kind: Kind, date: Date = Date(),
        carrierMetrics: CarrierDiagnosticsSnapshot? = nil,
        carrierMetricsCapturedAtMS: Int64? = nil, carrierMetricsUnavailableAtMS: Int64? = nil
    ) {
        capturedAtMS = Self.timestamp(date)
        self.sessionID = Self.safeSession(sessionID)
        self.kind = kind
        self.carrierMetrics = carrierMetrics
        self.carrierMetricsCapturedAtMS = carrierMetricsCapturedAtMS
        self.carrierMetricsUnavailableAtMS = carrierMetricsUnavailableAtMS
        self.events = events.suffix(Self.maximumEvents).map { event in
            var safe = event
            safe.sessionID = Self.safeSession(event.sessionID)
            return safe
        }
    }

    enum CodingKeys: String, CodingKey {
        case schema, app, kind, capturedAtMS = "captured_at_ms", sessionID = "session_id", events
        case rawMessagesIncluded = "raw_messages_included", carrierMetrics = "carrier_metrics"
        case carrierMetricsStatus = "carrier_metrics_status"
        case carrierMetricsCapturedAtMS = "carrier_metrics_captured_at_ms"
        case carrierMetricsUnavailableAtMS = "carrier_metrics_latest_read_unavailable_at_ms"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(1, forKey: .schema)
        try container.encode("qeli-ios", forKey: .app)
        try container.encode(kind, forKey: .kind)
        try container.encode(capturedAtMS, forKey: .capturedAtMS)
        try container.encode(Self.safeSession(sessionID), forKey: .sessionID)
        try container.encode(Array(events.suffix(Self.maximumEvents)), forKey: .events)
        try container.encode(false, forKey: .rawMessagesIncluded)
        // The type's strict decoder admits only known numeric counters and protocol labels.
        // Unknown counters stay unknown, never zero observations.
        try container.encode(carrierMetrics, forKey: .carrierMetrics)
        try container.encode(carrierMetrics == nil ? "unavailable" : "available", forKey: .carrierMetricsStatus)
        try container.encode(carrierMetricsCapturedAtMS, forKey: .carrierMetricsCapturedAtMS)
        try container.encode(carrierMetricsUnavailableAtMS, forKey: .carrierMetricsUnavailableAtMS)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard try container.decode(Int.self, forKey: .schema) == 1,
              try container.decode(String.self, forKey: .app) == "qeli-ios",
              try container.decode(Bool.self, forKey: .rawMessagesIncluded) == false else {
            throw DiagnosticJournalError.invalidArchive
        }
        capturedAtMS = try container.decode(Int64.self, forKey: .capturedAtMS)
        sessionID = Self.safeSession(try container.decode(String.self, forKey: .sessionID))
        kind = try container.decode(Kind.self, forKey: .kind)
        carrierMetrics = try container.decodeIfPresent(CarrierDiagnosticsSnapshot.self, forKey: .carrierMetrics)
        carrierMetricsCapturedAtMS = try container.decodeIfPresent(Int64.self, forKey: .carrierMetricsCapturedAtMS)
        carrierMetricsUnavailableAtMS = try container.decodeIfPresent(Int64.self, forKey: .carrierMetricsUnavailableAtMS)
        events = Array(try container.decode([DiagnosticEvent].self, forKey: .events).suffix(Self.maximumEvents))
        for index in events.indices { events[index].sessionID = Self.safeSession(events[index].sessionID) }
    }

    func data() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumBytes else { throw DiagnosticJournalError.invalidArchive }
        return data
    }

    static func safeSession(_ value: String) -> String {
        value.utf8.count == 8 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } ? value : ""
    }

    static func timestamp(_ date: Date) -> Int64 {
        let value = date.timeIntervalSince1970 * 1000
        guard value.isFinite, value >= 0, value < Double(Int64.max) else { return 0 }
        return Int64(value)
    }
}
