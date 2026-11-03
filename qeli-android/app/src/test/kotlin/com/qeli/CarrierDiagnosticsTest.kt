package com.qeli

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CarrierDiagnosticsTest {
    private fun snapshot(elapsed: Long, finished: Long, run: Long = 1): JSONObject {
        val row = JSONObject("""{
            "carrier_id":1,"logical_slot":0,"closed":false,"activity":"active",
            "accounting_supported":true,"progress_boundary":"carrier_io_acceptance",
            "accepted_packets":2,"accepted_bytes":2000,"local_finished_packets":1,
            "local_finished_bytes":0,"cancelled_packets":0,"cancelled_bytes":0,
            "rejected_packets":0,"rejected_bytes":0,"queue_full_drops_packets":0,
            "queue_full_drops_bytes":0,"queued_packets":1,"queued_bytes":1000,
            "in_flight_packets":0,"in_flight_bytes":0,"pending_packets":1,
            "pending_bytes":1000,"max_queue_wait_ms":10,"write_progress_bytes":100,
            "backlog_episode_ms":10,"oldest_in_flight_ms":null,"last_queue_wait_ms":10,
            "last_local_finish_ago_ms":10,"last_write_progress_ago_ms":5,
            "pending_no_write_progress_ms":5
        }""").put("local_finished_bytes", finished)
        return JSONObject().put("schema", 1).put("supported", true)
            .put("runtime_available", true).put("finished", false).put("scope", "tcp_uplink")
            .put("completion", "local_write_flush_not_peer_ack").put("run_id", run)
            .put("age_semantics", "queue_wait_sample_and_pending_episode")
            .put("progress_timestamps", "sampled")
            .put("payloads", "queued_tunnel_payloads_including_control")
            .put("elapsed_ms", elapsed).put("omitted_carriers", 0).put("carriers", JSONArray().put(row))
    }

    @Test
    fun `report drops free text and rejects noninteger counters`() {
        val input = snapshot(1000, 1000).put("profile", "secret configuration")
        input.getJSONArray("carriers").getJSONObject(0).put("endpoint", "private.example")
        val cleaned = CarrierDiagnostics.sanitize(input.toString())!!
        assertFalse(cleaned.contains("secret"))
        assertFalse(cleaned.contains("private.example"))
        input.getJSONArray("carriers").getJSONObject(0).put("accepted_bytes", "password=secret")
        assertNull(CarrierDiagnostics.sanitize(input.toString()))
    }

    @Test
    fun `repeated source sample does not invent rate or replay terminal events`() {
        val sampler = CarrierDiagnosticsSampler()
        sampler.sample(snapshot(1000, 1000).toString())
        assertTrue(sampler.sample(snapshot(1000, 1000).toString()).lines.isEmpty())
        val next = sampler.sample(snapshot(3000, 3000).toString())
        assertTrue(next.lines.single().contains("local_Bps=1000"))
        val closed = snapshot(4000, 3000).apply {
            put("finished", true).put("runtime_available", false)
            getJSONArray("carriers").getJSONObject(0).put("closed", true).put("activity", "closed")
        }
        assertTrue(sampler.sample(closed.toString()).lines.isNotEmpty())
        assertTrue(sampler.sample(closed.toString()).lines.isEmpty())
    }

    @Test
    fun `new generation never computes throughput from its predecessor`() {
        val sampler = CarrierDiagnosticsSampler()
        sampler.sample(snapshot(1000, 100000).toString())
        val next = sampler.sample(snapshot(2000, 1000, run = 2).toString())
        assertTrue(next.lines.single().contains("local_Bps=unavailable"))
    }

    @Test
    fun `terminal transition in the same millisecond is retained without a rate`() {
        val sampler = CarrierDiagnosticsSampler()
        sampler.sample(snapshot(1000, 1000).toString())
        val terminal = snapshot(1000, 1000).apply {
            put("finished", true).put("runtime_available", false)
            getJSONArray("carriers").getJSONObject(0).put("closed", true).put("activity", "closed")
        }
        val result = sampler.sample(terminal.toString())
        assertTrue(JSONObject(result.snapshot!!).getBoolean("finished"))
        assertTrue(result.lines.single().contains("local_Bps=unavailable"))
    }

    @Test
    fun `carrier count and negative ages are bounded`() {
        val input = snapshot(1000, 1000)
        val rows = input.getJSONArray("carriers")
        repeat(32) { rows.put(JSONObject(rows.getJSONObject(0).toString()).put("carrier_id", it + 2)) }
        assertNull(CarrierDiagnostics.sanitize(input.toString()))
        val negative = snapshot(1000, 1000)
        negative.getJSONArray("carriers").getJSONObject(0).put("oldest_in_flight_ms", -1)
        assertNull(CarrierDiagnostics.sanitize(negative.toString()))
    }
}
