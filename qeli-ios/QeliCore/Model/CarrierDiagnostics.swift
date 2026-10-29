import CoreFoundation
import Foundation

/// An allowlisted projection of the native TCP uplink snapshot. Every label is a constant
/// or enum; neither network addresses nor arbitrary native strings are retained.
struct CarrierDiagnosticsSnapshot: Codable, Equatable, Sendable {
    static let maximumBytes = 64 * 1024
    static let maximumCarriers = 32
    let supported: Bool
    let runtimeAvailable: Bool
    let finished: Bool
    let runID: Int64
    let elapsedMS: Int64
    let omittedCarriers: Int64
    let carriers: [Carrier]

    struct Carrier: Codable, Equatable, Sendable {
        enum Activity: String, Codable, Sendable { case idle, active, degraded, closed }
        static let counterNames = [
            "carrier_id", "logical_slot", "accepted_packets", "accepted_bytes",
            "local_finished_packets", "local_finished_bytes", "cancelled_packets", "cancelled_bytes",
            "rejected_packets", "rejected_bytes", "queue_full_drops_packets", "queue_full_drops_bytes",
            "queued_packets", "queued_bytes", "in_flight_packets", "in_flight_bytes",
            "pending_packets", "pending_bytes", "max_queue_wait_ms", "write_progress_bytes"
        ]
        static let ageNames = [
            "backlog_episode_ms", "oldest_in_flight_ms", "last_queue_wait_ms",
            "last_local_finish_ago_ms", "last_write_progress_ago_ms", "pending_no_write_progress_ms"
        ]
        private let counters: [String: Int64]
        private let ages: [String: Int64]
        let closed: Bool
        let accountingSupported: Bool
        let activity: Activity

        func counter(_ name: String) -> Int64 { counters[name] ?? 0 }
        func age(_ name: String) -> Int64? { ages[name] }

        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: Key.self)
            var counters: [String: Int64] = [:]
            for name in Self.counterNames { counters[name] = try values.nonnegative(name) }
            var ages: [String: Int64] = [:]
            for name in Self.ageNames {
                guard values.contains(Key(name)) else { throw DiagnosticJournalError.invalidArchive }
                if try !values.decodeNil(forKey: Key(name)) { ages[name] = try values.nonnegative(name) }
            }
            self.counters = counters
            self.ages = ages
            closed = try values.decode(Bool.self, forKey: Key("closed"))
            accountingSupported = try values.decode(Bool.self, forKey: Key("accounting_supported"))
            activity = try values.decode(Activity.self, forKey: Key("activity"))
            guard try values.decode(String.self, forKey: Key("progress_boundary")) == "carrier_io_acceptance" else {
                throw DiagnosticJournalError.invalidArchive
            }
        }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: Key.self)
            for name in Self.counterNames { try values.encode(counter(name), forKey: Key(name)) }
            for name in Self.ageNames { try values.encode(age(name), forKey: Key(name)) }
            try values.encode(closed, forKey: Key("closed"))
            try values.encode(accountingSupported, forKey: Key("accounting_supported"))
            try values.encode(activity, forKey: Key("activity"))
            try values.encode("carrier_io_acceptance", forKey: Key("progress_boundary"))
        }
    }

    private static let labels = [
        "scope": "tcp_uplink", "completion": "local_write_flush_not_peer_ack",
        "age_semantics": "queue_wait_sample_and_pending_episode", "progress_timestamps": "sampled",
        "payloads": "queued_tunnel_payloads_including_control"
    ]

    /// JSONDecoder accepts an integer-valued floating token for Int64. Check the original
    /// NSNumber representation first, so native floats, booleans and overflowing UInt64s
    /// cannot masquerade as counters. Unknown fields are discarded by our encoder.
    static func parse(_ data: Data) -> Self? {
        guard data.count <= maximumBytes,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              strictInteger(object["schema"]) == 1,
              let rows = object["carriers"] as? [[String: Any]], rows.count <= maximumCarriers else { return nil }
        for name in ["run_id", "elapsed_ms", "omitted_carriers"] {
            guard strictInteger(object[name]) != nil else { return nil }
        }
        for name in ["supported", "runtime_available", "finished"] {
            guard strictBoolean(object[name]) else { return nil }
        }
        for row in rows {
            for name in Carrier.counterNames { guard strictInteger(row[name]) != nil else { return nil } }
            for name in Carrier.ageNames {
                guard row[name] is NSNull || strictInteger(row[name]) != nil else { return nil }
            }
            for name in ["closed", "accounting_supported"] {
                guard strictBoolean(row[name]) else { return nil }
            }
        }
        guard let result = try? JSONDecoder().decode(Self.self, from: data),
              let safeData = try? JSONEncoder().encode(result), safeData.count <= maximumBytes else { return nil }
        return result
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: Key.self)
        guard try values.nonnegative("schema") == 1 else { throw DiagnosticJournalError.invalidArchive }
        for (name, expected) in Self.labels {
            guard try values.decode(String.self, forKey: Key(name)) == expected else { throw DiagnosticJournalError.invalidArchive }
        }
        supported = try values.decode(Bool.self, forKey: Key("supported"))
        runtimeAvailable = try values.decode(Bool.self, forKey: Key("runtime_available"))
        finished = try values.decode(Bool.self, forKey: Key("finished"))
        runID = try values.nonnegative("run_id")
        elapsedMS = try values.nonnegative("elapsed_ms")
        omittedCarriers = try values.nonnegative("omitted_carriers")
        carriers = try values.decode([Carrier].self, forKey: Key("carriers"))
        guard carriers.count <= Self.maximumCarriers,
              Set(carriers.map { $0.counter("carrier_id") }).count == carriers.count else {
            throw DiagnosticJournalError.invalidArchive
        }
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: Key.self)
        try values.encode(1, forKey: Key("schema"))
        for (name, constant) in Self.labels { try values.encode(constant, forKey: Key(name)) }
        try values.encode(supported, forKey: Key("supported"))
        try values.encode(runtimeAvailable, forKey: Key("runtime_available"))
        try values.encode(finished, forKey: Key("finished"))
        try values.encode(runID, forKey: Key("run_id"))
        try values.encode(elapsedMS, forKey: Key("elapsed_ms"))
        try values.encode(omittedCarriers, forKey: Key("omitted_carriers"))
        try values.encode(carriers, forKey: Key("carriers"))
    }

    private static func strictInteger(_ raw: Any?) -> Int64? {
        guard let number = raw as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              !["f", "d"].contains(String(cString: number.objCType)),
              let result = Int64(number.stringValue), result >= 0 else { return nil }
        return result
    }

    private static func strictBoolean(_ raw: Any?) -> Bool {
        guard let number = raw as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }
}

private struct Key: CodingKey {
    let stringValue: String
    let intValue: Int? = nil
    init(_ value: String) { stringValue = value }
    init?(stringValue: String) { self.init(stringValue) }
    init?(intValue: Int) { return nil }
}

private extension KeyedDecodingContainer where Key == CarrierDiagnosticsKey {
    func nonnegative(_ name: String) throws -> Int64 {
        let value = try decode(Int64.self, forKey: Key(name))
        guard value >= 0 else { throw DiagnosticJournalError.invalidArchive }
        return value
    }
}

// A distinct alias avoids the generic container's `Key` shadowing the concrete CodingKey.
private typealias CarrierDiagnosticsKey = Key
