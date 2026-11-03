package com.qeli

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DiagnosticReportCodecTest {
    @Test fun `arbitrary input secrets never become report text`() {
        val secrets = listOf("qeli://secret-profile", "password=secret-password", "obfs_key=deadbeef",
            "private_key=PRIVATE", "secret=SECRET", "token=TOKEN", "-----BEGIN PRIVATE KEY-----",
            "config parse error: quoted 'user secret input'", "c2VjcmV0LWJhc2U2NA==")
        val report = DiagnosticReportCodec.encode(secrets.map { DiagnosticLogStore.entry(it, "aabbccdd", "error") },
            "aabbccdd", "terminal_error", null, null, 0, 0)
        secrets.forEach { assertFalse(report.contains(it)) }
        val parsed = JSONObject(report)
        assertFalse(parsed.getBoolean("raw_messages_included"))
        assertEquals(secrets.size, parsed.getJSONArray("events").length())
    }

    @Test fun `known failures retain useful structured reason without arbitrary suffix`() {
        val message = "ERR: [IllegalStateException] native transport generation failed (rc=-17) password=secret"
        val report = JSONObject(DiagnosticReportCodec.encode(listOf(DiagnosticLogStore.entry(message, "aabbccdd")),
            "aabbccdd", "current", null, null, 2, 1))
        val event = report.getJSONArray("events").getJSONObject(0)
        assertEquals("native_generation_failed", event.getString("reason_code"))
        assertEquals(-17, event.getInt("native_return_code"))
        assertFalse(report.toString().contains("password"))
        assertEquals("carrier_health", DiagnosticReportCodec.category("TCP carrier 3: pending=4"))
    }
}
