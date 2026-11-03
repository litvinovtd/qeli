package com.qeli

import org.json.JSONArray
import org.json.JSONObject

internal data class CarrierDiagnosticsSample(val snapshot: String?, val lines: List<String>)

/** Only numeric counters and known protocol labels cross into the incident report. */
internal object CarrierDiagnostics {
    const val MAX_BYTES = 64 * 1024
    const val MAX_CARRIERS = 32
    private val counters = listOf(
        "carrier_id", "logical_slot", "accepted_packets", "accepted_bytes",
        "local_finished_packets", "local_finished_bytes", "cancelled_packets", "cancelled_bytes",
        "rejected_packets", "rejected_bytes", "queue_full_drops_packets", "queue_full_drops_bytes",
        "queued_packets", "queued_bytes", "in_flight_packets", "in_flight_bytes",
        "pending_packets", "pending_bytes", "max_queue_wait_ms", "write_progress_bytes",
    )
    private val ages = listOf(
        "backlog_episode_ms", "oldest_in_flight_ms", "last_queue_wait_ms",
        "last_local_finish_ago_ms", "last_write_progress_ago_ms", "pending_no_write_progress_ms",
    )

    fun sanitize(raw: String?): String? {
        if (raw == null || raw.length > MAX_BYTES || raw.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return null
        return runCatching {
            val input = JSONObject(raw)
            require(input.getInt("schema") == 1 && input.getString("scope") == "tcp_uplink")
            require(input.getString("completion") == "local_write_flush_not_peer_ack")
            val output = JSONObject()
                .put("schema", 1)
                .put("scope", "tcp_uplink")
                .put("completion", "local_write_flush_not_peer_ack")
            for ((key, expected) in mapOf(
                "age_semantics" to "queue_wait_sample_and_pending_episode",
                "progress_timestamps" to "sampled",
                "payloads" to "queued_tunnel_payloads_including_control",
            )) {
                require(input.getString(key) == expected)
                output.put(key, expected)
            }
            for (key in listOf("supported", "runtime_available", "finished")) {
                output.put(key, boolean(input, key))
            }
            for (key in listOf("run_id", "elapsed_ms", "omitted_carriers")) {
                output.put(key, number(input, key))
            }
            val rows = input.getJSONArray("carriers")
            require(rows.length() <= MAX_CARRIERS)
            val cleanRows = JSONArray()
            val seen = HashSet<Long>()
            for (index in 0 until rows.length()) {
                val row = rows.getJSONObject(index)
                val clean = JSONObject()
                for (key in counters) clean.put(key, number(row, key))
                require(seen.add(clean.getLong("carrier_id")))
                for (key in ages) {
                    clean.put(key, if (row.isNull(key)) JSONObject.NULL else number(row, key))
                }
                for (key in listOf("closed", "accounting_supported")) clean.put(key, boolean(row, key))
                val activity = row.getString("activity")
                require(activity in setOf("idle", "active", "degraded", "closed"))
                require(row.getString("progress_boundary") == "carrier_io_acceptance")
                clean.put("activity", activity).put("progress_boundary", "carrier_io_acceptance")
                cleanRows.put(clean)
            }
            output.put("carriers", cleanRows).toString().also {
                require(it.toByteArray(Charsets.UTF_8).size <= MAX_BYTES)
            }
        }.getOrNull()
    }

    private fun boolean(value: JSONObject, key: String): Boolean =
        (value.get(key) as? Boolean) ?: error("invalid diagnostic boolean")

    private fun number(value: JSONObject, key: String): Long {
        val field = value.get(key)
        // Native integers must remain integers. Never accept free text, floating point,
        // negatives, or wrap an out-of-range unsigned counter into a signed value.
        require(field is Int || field is Long)
        return (field as Number).toLong().also { require(it >= 0) }
    }
}

/** One bounded sample history; uses the native monotonic clock, never GUI polling intervals. */
internal class CarrierDiagnosticsSampler {
    private data class Previous(val finishedBytes: Long, val accepted: Long, val dropped: Long, val closed: Boolean)
    private var runId: Long? = null
    private var elapsedMs = 0L
    private var previous = emptyMap<Long, Previous>()
    private var lastSnapshot: String? = null

    @Synchronized
    fun sample(raw: String?): CarrierDiagnosticsSample {
        val clean = CarrierDiagnostics.sanitize(raw)
        if (clean == null) {
            runId = null
            previous = emptyMap()
            lastSnapshot = null
            return CarrierDiagnosticsSample(null, emptyList())
        }
        val snapshot = JSONObject(clean)
        val currentRun = snapshot.getLong("run_id")
        val now = snapshot.getLong("elapsed_ms")
        if (currentRun == runId && (now < elapsedMs || (now == elapsedMs && clean == lastSnapshot))) {
            // A frozen terminal sample or repeated poll is not a new observation. Do not
            // invent a zero-rate point, replay closed events, or move the sample clock back.
            return CarrierDiagnosticsSample(lastSnapshot, emptyList())
        }
        val sameRun = currentRun == runId
        val deltaMs = if (sameRun) now - elapsedMs else 0L
        val rows = snapshot.getJSONArray("carriers")
        val next = HashMap<Long, Previous>(rows.length())
        val candidates = ArrayList<Pair<JSONObject, Previous?>>(rows.length())
        for (index in 0 until rows.length()) {
            val row = rows.getJSONObject(index)
            val id = row.getLong("carrier_id")
            val state = Previous(
                row.getLong("local_finished_bytes"), row.getLong("accepted_packets"),
                row.getLong("queue_full_drops_packets"), row.getBoolean("closed"),
            )
            val before = if (sameRun) previous[id] else null
            next[id] = state
            val hasActivity = row.getLong("pending_packets") > 0 ||
                (before != null && state != before) ||
                (before == null && (state.accepted > 0 || state.dropped > 0))
            if (hasActivity && (!state.closed || before?.closed != true)) candidates += row to before
        }
        candidates.sortWith(compareByDescending<Pair<JSONObject, Previous?>> { it.first.getString("activity") == "degraded" }
            .thenByDescending { it.first.optLong("backlog_episode_ms", 0) })
        val limit = if (candidates.size > 3) 2 else 3
        val lines = candidates.take(limit).map { (row, before) ->
            val finished = row.getLong("local_finished_bytes")
            val rate = if (before != null && deltaMs > 0 && finished >= before.finishedBytes) {
                ((finished - before.finishedBytes).toDouble() * 1000.0 / deltaMs).toLong().toString()
            } else "unavailable"
            fun age(key: String): String = if (row.isNull(key)) "none" else row.getLong(key).toString()
            "TCP carrier ${row.getLong("carrier_id")} slot=${row.getLong("logical_slot")} " +
                "state=${row.getString("activity")} accounting=${row.getBoolean("accounting_supported")} " +
                "queued=${row.getLong("queued_packets")}/${row.getLong("queued_bytes")}B " +
                "in_flight=${row.getLong("in_flight_packets")}/${row.getLong("in_flight_bytes")}B " +
                "backlog_episode_ms=${age("backlog_episode_ms")} in_flight_ms=${age("oldest_in_flight_ms")} " +
                "queue_wait_ms=${age("last_queue_wait_ms")} full_drops=${row.getLong("queue_full_drops_packets")} " +
                "local_finished=${row.getLong("local_finished_packets")}/${finished}B local_Bps=$rate " +
                "sampled_no_write_progress_ms=${age("pending_no_write_progress_ms")} " +
                "(includes queued control; local completion, not peer ACK)"
        }.toMutableList()
        if (candidates.size > limit) {
            lines += "TCP carrier diagnostics: ${candidates.size} active/changed, " +
                "${candidates.count { it.first.getString("activity") == "degraded" }} degraded; " +
                "full bounded snapshot is included in diagnostic export"
        }
        runId = currentRun
        elapsedMs = now
        previous = next
        lastSnapshot = clean
        return CarrierDiagnosticsSample(clean, lines)
    }
}
