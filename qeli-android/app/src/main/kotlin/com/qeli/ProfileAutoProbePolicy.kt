package com.qeli

/** Shared timing policy for Android's lifecycle-aware automatic profile polling. */
internal object ProfileAutoProbePolicy {
    const val DEFAULT_INTERVAL_SECS = 30
    const val MIN_INTERVAL_SECS = 10
    const val MAX_INTERVAL_SECS = 3_600
    const val SWEEP_COOLDOWN_MS = 15_000L

    fun clampIntervalSeconds(value: Int): Int =
        value.coerceIn(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS)

    fun canStartSweep(
        enabled: Boolean,
        tunnelBusy: Boolean,
        nowMs: Long,
        lastSweepMs: Long,
    ): Boolean {
        if (!enabled || tunnelBusy) return false
        if (lastSweepMs <= 0L) return true
        val elapsed = nowMs - lastSweepMs
        return elapsed < 0L || elapsed >= SWEEP_COOLDOWN_MS
    }
}
