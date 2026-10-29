import Foundation

/// One bounded previous sample, measured using the native monotonic elapsed clock.
final class CarrierDiagnosticsSampler: @unchecked Sendable {
    private struct Previous {
        let finishedBytes: Int64
        let accepted: Int64
        let dropped: Int64
        let closed: Bool
    }
    private let lock = NSLock()
    private var runID: Int64?
    private var elapsedMS: Int64 = 0
    private var previous: [Int64: Previous] = [:]
    private var lastSnapshot: CarrierDiagnosticsSnapshot?

    func sample(_ snapshot: CarrierDiagnosticsSnapshot?) -> (snapshot: CarrierDiagnosticsSnapshot?, lines: [String]) {
        lock.withLock {
            guard let snapshot else {
                runID = nil
                previous = [:]
                lastSnapshot = nil
                return (nil, [])
            }
            if snapshot.runID == runID,
               snapshot.elapsedMS < elapsedMS || (snapshot.elapsedMS == elapsedMS && snapshot == lastSnapshot) {
                return (lastSnapshot, [])
            }
            let sameRun = snapshot.runID == runID
            let deltaMS = sameRun ? snapshot.elapsedMS - elapsedMS : 0
            var next: [Int64: Previous] = [:]
            var candidates: [(CarrierDiagnosticsSnapshot.Carrier, Previous?)] = []
            for row in snapshot.carriers {
                let id = row.counter("carrier_id")
                let state = Previous(
                    finishedBytes: row.counter("local_finished_bytes"), accepted: row.counter("accepted_packets"),
                    dropped: row.counter("queue_full_drops_packets"), closed: row.closed
                )
                let before = sameRun ? previous[id] : nil
                next[id] = state
                let changed = before.map {
                    state.finishedBytes != $0.finishedBytes || state.accepted != $0.accepted
                        || state.dropped != $0.dropped || state.closed != $0.closed
                } ?? (state.accepted > 0 || state.dropped > 0)
                if (row.counter("pending_packets") > 0 || changed) && (!state.closed || before?.closed != true) {
                    candidates.append((row, before))
                }
            }
            candidates.sort {
                if ($0.0.activity == .degraded) != ($1.0.activity == .degraded) { return $0.0.activity == .degraded }
                return ($0.0.age("backlog_episode_ms") ?? 0) > ($1.0.age("backlog_episode_ms") ?? 0)
            }
            let limit = candidates.count > 3 ? 2 : 3
            var lines = candidates.prefix(limit).map { row, before -> String in
                let finished = row.counter("local_finished_bytes")
                let rate: String
                if let before, deltaMS > 0, finished >= before.finishedBytes {
                    let value = Double(finished - before.finishedBytes) * 1000 / Double(deltaMS)
                    rate = String(value >= Double(Int64.max) ? Int64.max : Int64(value))
                } else { rate = "unavailable" }
                func age(_ name: String) -> String { row.age(name).map(String.init) ?? "none" }
                return "TCP carrier \(row.counter("carrier_id")) slot=\(row.counter("logical_slot")) "
                    + "state=\(row.activity.rawValue) accounting=\(row.accountingSupported) "
                    + "queued=\(row.counter("queued_packets"))/\(row.counter("queued_bytes"))B "
                    + "in_flight=\(row.counter("in_flight_packets"))/\(row.counter("in_flight_bytes"))B "
                    + "backlog_episode_ms=\(age("backlog_episode_ms")) in_flight_ms=\(age("oldest_in_flight_ms")) "
                    + "queue_wait_ms=\(age("last_queue_wait_ms")) full_drops=\(row.counter("queue_full_drops_packets")) "
                    + "local_finished=\(row.counter("local_finished_packets"))/\(finished)B local_Bps=\(rate) "
                    + "sampled_no_write_progress_ms=\(age("pending_no_write_progress_ms")) "
                    + "(includes queued control; local completion, not peer ACK)"
            }
            if candidates.count > limit {
                let degraded = candidates.filter { $0.0.activity == .degraded }.count
                lines.append("TCP carrier diagnostics: \(candidates.count) active/changed, \(degraded) degraded; full bounded snapshot is included in diagnostic export")
            }
            runID = snapshot.runID
            elapsedMS = snapshot.elapsedMS
            previous = next
            lastSnapshot = snapshot
            return (snapshot, lines)
        }
    }
}
