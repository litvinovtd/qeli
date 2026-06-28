package com.qeli.protocol

/**
 * App-layer fragmentation for the large UDP handshake messages. Port of
 * qeli/src/protocol/udp_frag.rs.
 *
 * The post-quantum UDP handshake is big (ML-KEM-768: ek 1184 B in the ClientHello,
 * ct 1088 B + cert in the ServerHello -> CH ~1440 B, SH ~1959 B). A single ~2 KB
 * datagram is IP-fragmented, and mobile / CGNAT networks routinely DROP IP fragments,
 * so the UDP handshake silently hangs (works on Wi-Fi, fails on LTE). We split the
 * ClientHello (and reassemble the ServerHello) into <=MAX_CHUNK-byte fragments that
 * never need IP fragmentation.
 *
 * Wire: [MAGIC(3)][msgId(1)][idx(1)][count(1)][chunk...]. Sits below the QUIC-mask /
 * obfs-XOR transforms (each fragment is wrapped independently). The magic cannot open a
 * TLS record (0x16 0x03), so a fragment is distinguishable from a legacy single datagram.
 */
object UdpFrag {
    val MAGIC = byteArrayOf(0xF0.toByte(), 0x9B.toByte(), 0x71.toByte())
    const val HDR_LEN = 6            // magic(3) + msgId(1) + idx(1) + count(1)
    const val MAX_CHUNK = 1200       // payload bytes per fragment (safe < IPv6 min 1280 / LTE)
    const val MAX_FRAGS = 24         // anti-DoS cap on the reassembly buffer
    const val MSG_CLIENT_HELLO: Byte = 1
    const val MSG_SERVER_HELLO: Byte = 2

    fun isFragment(d: ByteArray): Boolean =
        d.size >= HDR_LEN && d[0] == MAGIC[0] && d[1] == MAGIC[1] && d[2] == MAGIC[2]

    /** Split a handshake message into fragment datagrams (always >= 1). */
    fun fragment(msgId: Byte, msg: ByteArray): List<ByteArray> {
        val count = maxOf(1, (msg.size + MAX_CHUNK - 1) / MAX_CHUNK)
        return (0 until count).map { i ->
            val start = i * MAX_CHUNK
            val len = minOf(MAX_CHUNK, msg.size - start)
            val f = ByteArray(HDR_LEN + len)
            f[0] = MAGIC[0]; f[1] = MAGIC[1]; f[2] = MAGIC[2]
            f[3] = msgId; f[4] = i.toByte(); f[5] = count.toByte()
            System.arraycopy(msg, start, f, HDR_LEN, len)
            f
        }
    }

    /** Reassembles the fragments of ONE message. Tolerates out-of-order arrival and
     *  duplicates; throws on a malformed/inconsistent fragment. */
    class Reassembler {
        private var msgId: Byte = 0
        private var count = 0
        private var have = 0
        private var parts: Array<ByteArray?> = arrayOf()

        /** Feed one fragment datagram. Returns the full message once every fragment has
         *  arrived, else null. */
        fun push(d: ByteArray): ByteArray? {
            require(isFragment(d)) { "not a fragment" }
            val mId = d[3]
            val idx = d[4].toInt() and 0xFF
            val cnt = d[5].toInt() and 0xFF
            require(cnt in 1..MAX_FRAGS) { "bad fragment count" }
            require(idx < cnt) { "fragment index out of range" }
            if (count == 0) {
                msgId = mId; count = cnt; parts = arrayOfNulls(cnt); have = 0
            } else require(mId == msgId && cnt == count) { "inconsistent fragment" }
            if (parts[idx] == null) { parts[idx] = d.copyOfRange(HDR_LEN, d.size); have++ }
            if (have != count) return null
            val total = parts.sumOf { it!!.size }
            val out = ByteArray(total)
            var o = 0
            for (p in parts) { System.arraycopy(p!!, 0, out, o, p.size); o += p.size }
            return out
        }
    }
}
