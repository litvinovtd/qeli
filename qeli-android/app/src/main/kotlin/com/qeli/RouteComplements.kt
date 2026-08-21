package com.qeli

import java.math.BigInteger
import java.net.InetAddress

/** Pure route-planning helpers shared by the Android service and JVM tests. */
internal object RouteComplements {
    /** A bare IP literal denotes exactly one host in its address family. */
    internal fun hostPrefix(address: String): Int = if (':' in address) 128 else 32

    /** A missing family in a full tunnel needs a local sink unless bypass was explicit. */
    internal fun needsSyntheticSink(
        fullTunnel: Boolean,
        hasAddress: Boolean,
        allowLeak: Boolean,
    ): Boolean = fullTunnel && !hasAddress && !allowLeak

    /** Bound Builder route growth; over-complex complements are rejected, never truncated. */
    // Two unrelated IPv6 /128 exclusions have an exact minimal complement of 254 prefixes.
    // The previous 200-route ceiling therefore rejected an ordinary two-host bypass even
    // though the builder can carry it. Keep a finite abuse bound while admitting that case.
    private const val MAX_ROUTES = 512
    private const val IPV4_MAX = 0xffff_ffffL
    private val ONE = BigInteger.ONE
    private val IPV6_MAX = ONE.shiftLeft(128).subtract(ONE)

    /** IPv4 space (`0.0.0.0/0`) minus [excludes], represented as a minimal CIDR list. */
    fun ipv4(excludes: List<String>): List<String>? {
        val ranges = excludes.mapNotNull(::ipv4Range)
        if (ranges.size != excludes.size) return null
        val sorted = ranges.sortedBy { it.first }
        val result = mutableListOf<String>()
        var cursor = 0L
        for ((start, end) in sorted) {
            if (start > cursor && !appendIpv4Range(cursor, start - 1, result)) return null
            if (end >= cursor) cursor = end + 1
            if (cursor > IPV4_MAX) break
        }
        if (cursor <= IPV4_MAX && !appendIpv4Range(cursor, IPV4_MAX, result)) return null
        return result
    }

    /** Exact CIDR representation of one IPv4 [cidr] after carving out [excludes]. */
    private fun subtractIpv4(cidr: String, excludes: List<String>): List<String>? {
        val (baseStart, baseEnd) = ipv4Range(cidr) ?: return null
        val ranges = excludes
            .filterNot { ':' in it.substringBefore('/') }
            .map { ipv4Range(it) ?: return null }
            .sortedBy { it.first }
        val result = mutableListOf<String>()
        var cursor = baseStart
        for ((excludedStart, excludedEnd) in ranges) {
            if (excludedEnd < cursor || excludedStart > baseEnd) continue
            if (excludedStart > cursor &&
                !appendIpv4Range(cursor, minOf(baseEnd, excludedStart - 1), result)) return null
            if (excludedEnd >= cursor) cursor = excludedEnd + 1
            if (cursor > baseEnd) break
        }
        if (cursor <= baseEnd && !appendIpv4Range(cursor, baseEnd, result)) return null
        return result
    }

    private fun ipv4Range(cidr: String): Pair<Long, Long>? {
        val slash = cidr.indexOf('/')
        val addressText = (if (slash < 0) cidr else cidr.substring(0, slash)).trim()
        val prefix = if (slash < 0) 32
            else cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val octets = addressText.split('.')
        if (octets.size != 4) return null
        var address = 0L
        for (octet in octets) {
            val value = octet.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            address = (address shl 8) or value.toLong()
        }
        val size = 1L shl (32 - prefix)
        val mask = if (prefix == 0) 0L else IPV4_MAX xor (size - 1)
        val base = address and mask
        return base to base + size - 1
    }

    private fun appendIpv4Range(start: Long, end: Long, output: MutableList<String>): Boolean {
        var cursor = start
        while (cursor <= end) {
            var prefix = 32
            while (prefix > 0) {
                val size = 1L shl (32 - (prefix - 1))
                if (cursor % size != 0L || cursor + size - 1 > end) break
                prefix--
            }
            output += "${formatIpv4(cursor)}/$prefix"
            if (output.size > MAX_ROUTES) return false
            cursor += 1L shl (32 - prefix)
        }
        return true
    }

    private fun formatIpv4(value: Long): String =
        "${(value ushr 24) and 0xff}.${(value ushr 16) and 0xff}." +
            "${(value ushr 8) and 0xff}.${value and 0xff}"

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

    /** Exact CIDR representation of one IPv6 [cidr] after carving out [excludes]. */
    private fun subtractIpv6(cidr: String, excludes: List<String>): List<String>? {
        val (baseStart, baseEnd) = ipv6Range(cidr) ?: return null
        val ranges = excludes
            .filter { ':' in it.substringBefore('/') }
            .map { ipv6Range(it) ?: return null }
            .sortedBy { it.first }
        val result = mutableListOf<String>()
        var cursor = baseStart
        for ((excludedStart, excludedEnd) in ranges) {
            if (excludedEnd < cursor || excludedStart > baseEnd) continue
            if (excludedStart > cursor &&
                !appendRange(cursor, minOf(baseEnd, excludedStart - ONE), result)) return null
            if (excludedEnd >= cursor) cursor = excludedEnd + ONE
            if (cursor > baseEnd) break
        }
        if (cursor <= baseEnd && !appendRange(cursor, baseEnd, result)) return null
        return result
    }

    /**
     * Return the exact part of [cidr] not covered by same-family [excludes].
     *
     * This is needed on Android 12 and older: those releases have no `excludeRoute`, so
     * simply dropping a broad included/pushed route because a narrow exclusion overlaps it
     * also drops every innocent destination in the remainder of that route.
     */
    fun subtract(cidr: String, excludes: List<String>): List<String>? =
        if (':' in cidr.substringBefore('/')) subtractIpv6(cidr, excludes)
        else subtractIpv4(cidr, excludes)

    /**
     * Count original server-pushed routes whose effective fragments all reached the VPN
     * builder. The Rust core publishes originals separately from its exclusion-fragmented
     * route list, so direct string equality under-counts every partially carved route.
     */
    fun countInstalledOriginals(
        originals: Set<String>,
        installedFragments: Set<String>,
        excludes: List<String>,
        protectedCidrs: Set<String>,
    ): Int = originals.count { original ->
        val required = if (original in protectedCidrs) listOf(original)
            else subtract(original, excludes)
        required != null && required.isNotEmpty() && required.all(installedFragments::contains)
    }

    /** True when two valid, same-family CIDRs share at least one address. */
    fun overlaps(a: String, b: String): Boolean {
        val aHost = a.substringBefore('/')
        val bHost = b.substringBefore('/')
        if ((':' in aHost) != (':' in bHost)) return false
        return if (':' in aHost) {
            val ar = ipv6Range(a) ?: return false
            val br = ipv6Range(b) ?: return false
            ar.first <= br.second && br.first <= ar.second
        } else {
            val ar = ipv4Range(a) ?: return false
            val br = ipv4Range(b) ?: return false
            ar.first <= br.second && br.first <= ar.second
        }
    }

    /**
     * Whether [cidr] contains [gateway] and is at least as specific as the negotiated
     * on-link prefix. `null` means malformed input; opposite address families return false.
     */
    fun overridesOnLinkGateway(cidr: String, gateway: String, onLinkPrefix: Int): Boolean? {
        val cidrIpv6 = ':' in cidr.substringBefore('/')
        val gatewayIpv6 = ':' in gateway
        if (cidrIpv6 != gatewayIpv6) return false
        val slash = cidr.indexOf('/')
        val maximum = if (cidrIpv6) 128 else 32
        val prefix = if (slash < 0) maximum
            else cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (prefix !in 0..maximum || onLinkPrefix !in 0..maximum) return null
        if (prefix < onLinkPrefix) return false
        return if (cidrIpv6) {
            val route = ipv6Range(cidr) ?: return null
            val host = ipv6Range(gateway) ?: return null
            route.first <= host.first && host.first <= route.second
        } else {
            val route = ipv4Range(cidr) ?: return null
            val host = ipv4Range(gateway) ?: return null
            route.first <= host.first && host.first <= route.second
        }
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
