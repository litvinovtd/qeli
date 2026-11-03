package com.qeli

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** JNI contract exercised against the freshly built shared core. */
class ReconnectPolicyTest {
    @Test fun slowHandshakeDoesNotMakeAShortSessionStable() {
        val next = ConfigCore.policy("next_attempt", JSONObject()
            .put("attempt", 3).put("established", true)
            .put("connected_ms", 200).put("elapsed_ms", 45_000)).getLong("value")
        assertEquals(4L, next)
    }

    @Test fun settlingDoesNotEraseFiniteBudget() {
        val result = ConfigCore.policy("retry_decision", JSONObject()
            .put("attempt", 4).put("max_retries", 3).put("settling_cap", 3)).getJSONObject("value")
        assertEquals("retry_limit", result.getString("reason"))
        assertEquals(0L, result.getLong("delay_ms"))
    }

    @Test fun disabledStopsEvenAStableSession() {
        val result = ConfigCore.policy("retry_decision", JSONObject()
            .put("attempt", 0).put("enabled", false)).getJSONObject("value")
        assertEquals("disabled", result.getString("reason"))
    }

    @Test fun zeroBudgetAllowsStableRecoveryButNoUnstableRetry() {
        for (attempt in 0..1) {
            val result = ConfigCore.policy("retry_decision", JSONObject()
                .put("attempt", attempt).put("max_retries", 0).put("elapsed_ms", 30_000)).getJSONObject("value")
            assertEquals(attempt == 0, result.isNull("reason"))
        }
    }

    @Test fun maximumFiniteBudgetCanBeExhausted() {
        val next = ConfigCore.policy("next_attempt", JSONObject().put("attempt", Int.MAX_VALUE)).getLong("value")
        assertEquals(Int.MAX_VALUE.toLong() + 1, next)
        val result = ConfigCore.policy("retry_decision", JSONObject()
            .put("attempt", next).put("max_retries", Int.MAX_VALUE)).getJSONObject("value")
        assertEquals("retry_limit", result.getString("reason"))
    }

    @Test fun shortForcedCycleStillHasAnInterAttemptFloor() {
        val next = ConfigCore.policy("next_attempt", JSONObject()
            .put("attempt", 3).put("forced", true).put("established", true)
            .put("connected_ms", 200)).getLong("value")
        assertEquals(0L, next)
        val result = ConfigCore.policy("retry_decision", JSONObject()
            .put("attempt", next).put("elapsed_ms", 200)).getJSONObject("value")
        assertEquals(1300L, result.getLong("delay_ms"))
    }
}
