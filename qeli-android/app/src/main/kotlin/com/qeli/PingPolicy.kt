package com.qeli

/** A failed latency sample is not evidence that an authenticated VPN is disconnected. */
internal object PingPolicy {
    const val UNREACHABLE = -1L
    const val CHECKING = -2L
    const val CONNECTED_WITHOUT_RTT = -3L
    enum class Kind { SERVER_TCP, SERVER_UDP, TUNNEL_ICMP }
    data class Target(val kind: Kind, val host: String, val port: Int? = null)
    fun target(connected: Boolean, udp: Boolean, server: String, port: Int, gateway: String): Target =
        if (connected) Target(Kind.TUNNEL_ICMP, gateway)
        else Target(if (udp) Kind.SERVER_UDP else Kind.SERVER_TCP, server, port)
    fun result(target: Target, measuredMs: Long): Long = when {
        measuredMs >= 0 -> measuredMs
        target.kind == Kind.TUNNEL_ICMP -> CONNECTED_WITHOUT_RTT
        else -> UNREACHABLE
    }
    fun reachable(value: Long?) = value != null && (value >= 0 || value == CONNECTED_WITHOUT_RTT)
    fun <T> tunnelNetwork(networks: Iterable<T>, isVpn: (T) -> Boolean, hasOwnAddress: (T) -> Boolean): T? =
        networks.filter { isVpn(it) && hasOwnAddress(it) }.singleOrNull()
}

/** UI-thread ledger: a slow older tap must never overwrite a newer probe result. */
internal class PingRequests {
    private var next = 0L
    private val latest = mutableMapOf<Int, Long>()
    fun begin(index: Int): Long {
        next = if (next == Long.MAX_VALUE) 1 else next + 1
        latest[index] = next
        return next
    }
    fun current(index: Int, ticket: Long) = latest[index] == ticket
}

/** Snapshot checked again before publishing, including a reconnect into the same profile. */
internal data class PingSession(val status: String, val since: Long, val gateway: String, val localIp: String)
