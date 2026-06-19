package com.qeli

import kotlin.math.ln
import kotlin.math.max
import kotlin.random.Random

/**
 * Idle cover-traffic scheduler — the Kotlin mirror of the Rust `protocol::shaper`
 * (DPI-AUDIT 6.1/6.2). When enabled, an idle tunnel emits cover packets at gaps
 * sampled from an exponential (Poisson-process) distribution rather than a fixed
 * heartbeat, with a browsing-ish size distribution, capped by a byte budget.
 * Cover packets are empty-payload encrypted records the peer drops, so this is
 * not a wire-format change. Sampling is timing/size only (not secret).
 */
class TrafficShaper(
    enabledIn: Boolean,
    private val gapMeanMs: Long,
    private val gapMinMs: Long,
    gapMaxMs: Long,
    private val budgetBytesPerSec: Int,
    private val minSize: Int,
    maxSize: Int,
) {
    val enabled: Boolean = enabledIn && budgetBytesPerSec > 0
    private val gapMax: Long = max(gapMinMs, gapMaxMs)
    private val sizeMax: Int = max(minSize, maxSize)
    private var tokens: Double = budgetBytesPerSec.toDouble()
    private var lastRefillNanos: Long = System.nanoTime()

    /** Next inter-cover gap (ms): exponential (inverse-CDF), clamped to [min,max]. */
    fun nextGapMs(): Long {
        val u = Random.nextDouble()
        val sampled = -max(1L, gapMeanMs).toDouble() * ln(max(1e-12, 1.0 - u))
        return sampled.toLong().coerceIn(gapMinMs, gapMax)
    }

    /** Sample a cover packet size in [minSize, maxSize]. */
    fun nextSize(): Int = if (minSize >= sizeMax) minSize else Random.nextInt(minSize, sizeMax + 1)

    /** Token-bucket check+spend; true (and deducts) if the budget allows [bytes]. */
    fun trySpend(bytes: Int): Boolean {
        if (budgetBytesPerSec <= 0) return false
        val now = System.nanoTime()
        val elapsed = (now - lastRefillNanos) / 1_000_000_000.0
        lastRefillNanos = now
        tokens = minOf(tokens + elapsed * budgetBytesPerSec, budgetBytesPerSec.toDouble())
        return if (tokens >= bytes) { tokens -= bytes; true } else false
    }
}
