package com.qeli

/** ICMP datagram socket payload, not a second VPN protocol or a new server listener.
 * Linux ping sockets rewrite the identifier/checksum; correlate the sequence and a fresh
 * unpredictable payload instead. IPv6 checksum is supplied by the kernel ping socket. */
internal object IcmpEcho {
    const val NONCE_SIZE = 16
    fun request(ipv6: Boolean, sequence: Int, nonce: ByteArray): ByteArray {
        require(sequence in 0..65535 && nonce.size == NONCE_SIZE)
        return ByteArray(8 + NONCE_SIZE).also { packet ->
            packet[0] = (if (ipv6) 128 else 8).toByte()
            packet[6] = (sequence ushr 8).toByte(); packet[7] = sequence.toByte()
            nonce.copyInto(packet, 8)
            if (!ipv6) {
                val sum = checksum(packet)
                packet[2] = (sum ushr 8).toByte(); packet[3] = sum.toByte()
            }
        }
    }
    fun matches(reply: ByteArray, request: ByteArray, ipv6: Boolean): Boolean =
        reply.size == 8 + NONCE_SIZE && request.size == reply.size &&
            (reply[0].toInt() and 255) == (if (ipv6) 129 else 0) && reply[1] == 0.toByte() &&
            reply[6] == request[6] && reply[7] == request[7] &&
            reply.copyOfRange(8, reply.size).contentEquals(request.copyOfRange(8, request.size)) &&
            (ipv6 || checksum(reply) == 0)
    fun checksum(packet: ByteArray): Int {
        var sum = 0
        for (i in packet.indices step 2) sum += ((packet[i].toInt() and 255) shl 8) +
            (if (i + 1 < packet.size) packet[i + 1].toInt() and 255 else 0)
        while (sum ushr 16 != 0) sum = (sum and 65535) + (sum ushr 16)
        return sum.inv() and 65535
    }
}

/** Small injectable exchange so malformed replies, cancellation and deadlines are testable
 * without Android or root. All paths close the socket; no fallback to a physical network. */
internal object IcmpExchange {
    interface Socket : AutoCloseable {
        fun send(packet: ByteArray)
        fun receive(timeoutMs: Int): ByteArray?
    }
    fun run(socket: Socket, request: ByteArray, ipv6: Boolean, nowNanos: () -> Long,
            cancelled: () -> Boolean, timeoutMs: Int = 3000): Long = socket.use {
        require(timeoutMs in 1..5000)
        if (cancelled()) return -1
        val start = nowNanos()
        val budget = timeoutMs * 1_000_000L
        socket.send(request)
        while (!cancelled()) {
            val elapsed = nowNanos() - start
            if (elapsed < 0 || elapsed >= budget) return -1
            val remainingMs = ((budget - elapsed + 999_999) / 1_000_000).coerceIn(1, 250).toInt()
            val reply = socket.receive(remainingMs) ?: continue
            val finished = nowNanos() - start
            if (!cancelled() && finished in 0 until budget && IcmpEcho.matches(reply, request, ipv6))
                return finished / 1_000_000
        }
        -1
    }
}
