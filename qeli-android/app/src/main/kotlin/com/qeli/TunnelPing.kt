package com.qeli

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.FileDescriptor
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/** Rootless ICMP over the existing Android VPN network, for TCP and UDP equally.
 * Bind explicitly to our VPN (matched by its authenticated address), never to an
 * arbitrary default/physical network. No new handshake, credentials or server port. */
internal object TunnelPing {
    private val random = SecureRandom()
    suspend fun measure(cm: ConnectivityManager, localIp: String, gateway: String): Long = withContext(Dispatchers.IO) {
        val local = numericAddress(localIp) ?: return@withContext -1L
        val destination = numericAddress(gateway) ?: return@withContext -1L
        if ((local is Inet6Address) != (destination is Inet6Address)) return@withContext -1L
        val network = runCatching { PingPolicy.tunnelNetwork(cm.allNetworks.asIterable(),
            { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true },
            { cm.getLinkProperties(it)?.linkAddresses?.any { address -> address.address == local } == true },
        ) }.getOrNull() ?: return@withContext -1L
        suspendCancellableCoroutine { continuation ->
            val socket = runCatching { EchoSocket(network, local, destination) }.getOrNull()
            if (socket == null) {
                if (continuation.isActive) continuation.resume(-1L)
                return@suspendCancellableCoroutine
            }
            continuation.invokeOnCancellation { socket.close() }
            val result = runCatching {
                val request = IcmpEcho.request(destination is Inet6Address, random.nextInt(65536), ByteArray(IcmpEcho.NONCE_SIZE).also(random::nextBytes))
                IcmpExchange.run(socket, request, destination is Inet6Address, SystemClock::elapsedRealtimeNanos, { !continuation.isActive })
            }.getOrDefault(-1L)
            if (continuation.isActive) continuation.resume(result)
        }
    }
    private fun numericAddress(value: String) = runCatching {
        Os.inet_pton(OsConstants.AF_INET, value) ?: Os.inet_pton(OsConstants.AF_INET6, value)
    }.getOrNull()

    private class EchoSocket(network: Network, local: java.net.InetAddress, gateway: java.net.InetAddress) : IcmpExchange.Socket {
        private val closed = AtomicBoolean(false)
        // Android documents O_NONBLOCK/O_CLOEXEC as aliases for the SOCK_* flags
        // on older API levels. Set them atomically at creation; fcntlInt needs API 30.
        // Never block in write/read if a stalled VPN fills a queue or readiness changes.
        private val fd: FileDescriptor = Os.socket(if (gateway is Inet6Address) OsConstants.AF_INET6 else OsConstants.AF_INET,
            OsConstants.SOCK_DGRAM or OsConstants.O_NONBLOCK or OsConstants.O_CLOEXEC,
            if (gateway is Inet6Address) OsConstants.IPPROTO_ICMPV6 else OsConstants.IPPROTO_ICMP)
        init {
            try {
                network.bindSocket(fd)
                Os.connect(fd, gateway, 0)
                check((Os.getsockname(fd) as? InetSocketAddress)?.address == local) { "Ping source is not the authenticated VPN address" }
            } catch (error: Exception) { close(); throw error }
        }
        override fun send(packet: ByteArray) {
            check(!closed.get())
            check(Os.write(fd, packet, 0, packet.size) == packet.size) { "Incomplete ICMP write" }
        }
        override fun receive(timeoutMs: Int): ByteArray? {
            check(!closed.get())
            val poll = StructPollfd().apply { fd = this@EchoSocket.fd; events = OsConstants.POLLIN.toShort() }
            if (Os.poll(arrayOf(poll), timeoutMs) == 0) return null
            check(poll.revents.toInt() and OsConstants.POLLIN != 0) { "ICMP socket closed or failed" }
            val reply = ByteArray(2048)
            return reply.copyOf(Os.read(fd, reply, 0, reply.size))
        }
        override fun close() { if (closed.compareAndSet(false, true)) runCatching { Os.close(fd) } }
    }
}
