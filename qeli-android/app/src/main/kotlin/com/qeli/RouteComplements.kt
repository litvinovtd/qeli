package com.qeli

import java.math.BigInteger
import java.net.InetAddress

/** Pure route-planning helpers shared by the Android service and JVM tests. */
internal object RouteComplements {
    private const val MAX_ROUTES = 200
    private val ONE = BigInteger.ONE
    private val IPV6_MAX = ONE.shiftLeft(128).subtract(ONE)

    /** IPv6 space (`::/0`) minus [excludes], represented as a minimal CIDR list. */
    fun ipv6(excludes: List<String>): List<String>? {
        val ranges = excludes.mapNotNull(::ipv6Range)
        if (ranges.size != excludes.size) return null
        val sorted = ranges.sortedBy { it.first }
        val result = mutableListOf<String>()
        var cursor = BigInteger.ZERO
        for ((start, end) in sorted) {
            if (start > cursor && !appendRange(cursor, start - ONE, result)) return null
            if (end >= cursor) cursor = end + ONE
            if (cursor > IPV6_MAX) break
        }
        if (cursor <= IPV6_MAX && !appendRange(cursor, IPV6_MAX, result)) return null
        return result
    }

    private fun ipv6Range(cidr: String): Pair<BigInteger, BigInteger>? {
        val slash = cidr.indexOf('/')
        val addressText = (if (slash < 0) cidr else cidr.substring(0, slash)).trim()
        if (':' !in addressText || '%' in addressText) return null
        val prefix = if (slash < 0) 128
            else cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (prefix !in 0..128) return null
        val bytes = try { InetAddress.getByName(addressText).address } catch (_: Exception) { return null }
        if (bytes.size != 16) return null
        val address = BigInteger(1, bytes)
        val hostBits = 128 - prefix
        val base = if (hostBits == 128) BigInteger.ZERO
            else address.shiftRight(hostBits).shiftLeft(hostBits)
        val size = ONE.shiftLeft(hostBits)
        return base to base.add(size).subtract(ONE)
    }

    private fun appendRange(
        start: BigInteger, end: BigInteger, output: MutableList<String>
    ): Boolean {
        var cursor = start
        while (cursor <= end) {
            val alignmentBits = if (cursor == BigInteger.ZERO) 128
                else minOf(cursor.lowestSetBit, 128)
            val remainingBits = end.subtract(cursor).add(ONE).bitLength() - 1
            val hostBits = minOf(alignmentBits, remainingBits)
            val prefix = 128 - hostBits
            output += "${formatIpv6(cursor)}/$prefix"
            if (output.size > MAX_ROUTES) return false
            cursor = cursor.add(ONE.shiftLeft(hostBits))
        }
        return true
    }

    private fun formatIpv6(value: BigInteger): String {
        val source = value.toByteArray()
        val bytes = ByteArray(16)
        val copy = minOf(source.size, bytes.size)
        System.arraycopy(source, source.size - copy, bytes, bytes.size - copy, copy)
        return requireNotNull(InetAddress.getByAddress(bytes).hostAddress)
    }
}
