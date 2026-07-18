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
    // A throwaway pre-handshake junk decoy (AmneziaWG-style Jc on UDP): carries no real
    // data; the server drops it cheaply before its rate limiter. The client may emit `jc`
    // of these before its ClientHello to blur the first datagrams' size/count.
    const val MSG_JUNK: Byte = 3
    // Path-MTU probe (client->server): a single-fragment datagram padded so the whole
    // outer datagram is exactly the size being tested (sent with DF, so an oversized one
    // is dropped, not IP-fragmented -> no ACK). Body: [id(2 LE)][outerSize(2 LE)] + pad.
    // The server echoes a tiny MSG_MTU_PROBE_ACK. Recognized before the reassembler.
    const val MSG_MTU_PROBE: Byte = 4
    const val MSG_MTU_PROBE_ACK: Byte = 5
    const val PROBE_BODY_LEN = 4     // id(2) + outerSize(2)

    fun isFragment(d: ByteArray): Boolean =
        d.size >= HDR_LEN && d[0] == MAGIC[0] && d[1] == MAGIC[1] && d[2] == MAGIC[2]

    /** True if [d] (after obfs/QUIC unwrap) is an AWG junk decoy datagram. */
    fun isJunk(d: ByteArray): Boolean = isFragment(d) && d[3] == MSG_JUNK

    /** True if [d] (after unwrap) is a path-MTU probe. */
    fun isMtuProbe(d: ByteArray): Boolean =
        isFragment(d) && d[3] == MSG_MTU_PROBE && d.size >= HDR_LEN + PROBE_BODY_LEN

    /** True if [d] (after unwrap) is a path-MTU probe ACK. */
    fun isMtuProbeAck(d: ByteArray): Boolean =
        isFragment(d) && d[3] == MSG_MTU_PROBE_ACK && d.size >= HDR_LEN + PROBE_BODY_LEN

    /** Read (id, outerSize) from a probe or probe-ACK datagram, or null if too short. */
    fun parseMtuProbe(d: ByteArray): Pair<Int, Int>? {
        if (d.size < HDR_LEN + PROBE_BODY_LEN) return null
        val id = (d[HDR_LEN].toInt() and 0xFF) or ((d[HDR_LEN + 1].toInt() and 0xFF) shl 8)
        val size = (d[HDR_LEN + 2].toInt() and 0xFF) or ((d[HDR_LEN + 3].toInt() and 0xFF) shl 8)
        return Pair(id, size)
    }

    /** Build a probe datagram padded so the total outer datagram is [outerSize] bytes,
     *  or null if it can't hold the header+body. */
    fun mtuProbeDatagram(id: Int, outerSize: Int): ByteArray? {
        val min = HDR_LEN + PROBE_BODY_LEN
        if (outerSize < min || outerSize > 0xFFFF) return null
        val d = ByteArray(outerSize)
        d[0] = MAGIC[0]; d[1] = MAGIC[1]; d[2] = MAGIC[2]
        d[3] = MSG_MTU_PROBE; d[4] = 0; d[5] = 1
        d[HDR_LEN] = (id and 0xFF).toByte(); d[HDR_LEN + 1] = ((id shr 8) and 0xFF).toByte()
        d[HDR_LEN + 2] = (outerSize and 0xFF).toByte(); d[HDR_LEN + 3] = ((outerSize shr 8) and 0xFF).toByte()
        val pad = ByteArray(outerSize - min)
        java.security.SecureRandom().nextBytes(pad)
        System.arraycopy(pad, 0, d, min, pad.size)
        return d
    }

    /** Build the tiny ACK for a received probe (echoes its id + outerSize). */
    fun mtuProbeAckDatagram(id: Int, outerSize: Int): ByteArray {
        val d = ByteArray(HDR_LEN + PROBE_BODY_LEN)
        d[0] = MAGIC[0]; d[1] = MAGIC[1]; d[2] = MAGIC[2]
        d[3] = MSG_MTU_PROBE_ACK; d[4] = 0; d[5] = 1
        d[HDR_LEN] = (id and 0xFF).toByte(); d[HDR_LEN + 1] = ((id shr 8) and 0xFF).toByte()
        d[HDR_LEN + 2] = (outerSize and 0xFF).toByte(); d[HDR_LEN + 3] = ((outerSize shr 8) and 0xFF).toByte()
        return d
    }

    /** Build ONE junk decoy datagram: a single-fragment [MSG_JUNK] message with [len]
     *  random body bytes. Same on-wire envelope as a real fragment, so it rides the
     *  identical obfs-XOR / QUIC mask and the peer's [isJunk] recognizes it after unwrap. */
    fun junkDatagram(len: Int): ByteArray {
        val body = ByteArray(len)
        java.security.SecureRandom().nextBytes(body)
        val d = ByteArray(HDR_LEN + len)
        d[0] = MAGIC[0]; d[1] = MAGIC[1]; d[2] = MAGIC[2]
        d[3] = MSG_JUNK; d[4] = 0; d[5] = 1
        System.arraycopy(body, 0, d, HDR_LEN, len)
        return d
    }

    /** Split a handshake message into fragment datagrams (always >= 1). */
    fun fragment(msgId: Byte, msg: ByteArray): List<ByteArray> {
        val count = maxOf(1, (msg.size + MAX_CHUNK - 1) / MAX_CHUNK)
        // The receiver rejects count > MAX_FRAGS and the on-wire idx/count are single bytes,
        // so an oversize message would pack "successfully" here and then fail at the peer as a
        // mysterious handshake hang (or, past 255 fragments, silently misassemble). Fail loudly
        // at the source instead — parity with the Rust sender.
        require(count <= MAX_FRAGS) {
            "handshake message too large to fragment ($count > $MAX_FRAGS fragments)"
        }
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
            // Cap the per-fragment chunk (parity with the Rust reassembler): a legit
            // fragment is <= MAX_CHUNK, so a larger one is malformed. Bounds a reassembly
            // buffer at MAX_FRAGS*MAX_CHUNK instead of MAX_FRAGS*65535.
            require(d.size - HDR_LEN <= MAX_CHUNK) { "fragment chunk too large" }
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
