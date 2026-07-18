package com.qeli.protocol

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * QUIC-masking for the UDP transport. Mirrors qeli/src/protocol/quic.rs:
 * the data plane is wrapped in QUIC-looking long/short headers so a passive
 * observer sees QUIC packets instead of a raw obfuscated stream.
 */
object Quic {
    private const val VERSION_V1 = 0x00000001
    private const val LONG_HEADER_FLAG = 0xC0
    private const val SHORT_HEADER_FLAG = 0x40

    private val random = SecureRandom()

    fun generateConnectionId(): ByteArray = ByteArray(4).also { random.nextBytes(it) }

    /** RFC 9001 §17.2.2 Initial long header (mirrors quic.rs::wrap_quic_long):
     *  flags | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | token_len=0 |
     *  length_varint(2) | pn(4) | data. The long packet type lives in bits 4-5;
     *  the low 2 bits are the packet-number length minus one (we always emit a
     *  4-byte pn → 0b11). A zero Token Length + a Length varint make it a
     *  well-formed (unencrypted) QUIC v1 Initial the server's unwrap accepts. */
    fun wrapLong(data: ByteArray, connectionId: ByteArray, packetNumber: Int, packetType: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(LONG_HEADER_FLAG or ((packetType and 0x03) shl 4) or 0x03)
        out.writeIntBE(VERSION_V1)
        out.write(4)                       // DCID length
        out.write(connectionId, 0, 4)
        out.write(0)                       // SCID length = 0
        out.write(0)                       // Token Length varint = 0
        // Length covers the packet number (4) + payload; a 2-byte QUIC varint (0b01 prefix).
        val length = (4 + data.size) and 0x3FFF
        out.write(0x40 or (length ushr 8)) // Length varint, high byte
        out.write(length and 0xFF)         // Length varint, low byte
        out.writeIntBE(packetNumber)       // 4-byte packet number
        out.write(data)
        return out.toByteArray()
    }

    /** flags | dcid(4) | pn(4) | data */
    fun wrapShort(data: ByteArray, connectionId: ByteArray, packetNumber: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(SHORT_HEADER_FLAG or 0x03)
        out.write(connectionId, 0, 4)
        out.writeIntBE(packetNumber)
        out.write(data)
        return out.toByteArray()
    }

    /** Parse a QUIC packet and return the inner payload, or null if malformed. */
    fun unwrapPayload(packet: ByteArray): ByteArray? {
        if (packet.isEmpty()) return null
        val isLong = (packet[0].toInt() and 0x80) != 0
        return if (isLong) unwrapLong(packet) else unwrapShort(packet)
    }

    private fun unwrapLong(packet: ByteArray): ByteArray? {
        // flags+version(5) + dcid_len(1) + scid_len(1) + token_len(1) + length(1) + pn(≥1)
        if (packet.size < 12) return null
        val flags = packet[0].toInt() and 0xFF
        val pnLen = (flags and 0x03) + 1
        val off = intArrayOf(5) // skip flags + version
        val dcidLen = packet[off[0]].toInt() and 0xFF; off[0] += 1
        if (off[0] + dcidLen > packet.size) return null
        off[0] += dcidLen
        if (off[0] >= packet.size) return null
        val scidLen = packet[off[0]].toInt() and 0xFF; off[0] += 1
        if (off[0] + scidLen > packet.size) return null
        off[0] += scidLen
        // RFC 9001 §17.2.2: Token Length varint, token, then a Length varint. Skip both.
        val tokenLen = readVarint(packet, off) ?: return null
        // tokenLen is a QUIC varint (0 .. 2^62-1). Guard in LONG arithmetic: without this the
        // old Int accumulator overflowed negative and `off[0] += tokenLen` drove the offset
        // below zero → ArrayIndexOutOfBounds on the next read (a pre-auth reconnect-DoS on the
        // no-obfs udp-quic wire). tokenLen is >= 0 now; reject anything that doesn't fit before
        // the (safe) Int cast.
        if (tokenLen < 0 || off[0] + tokenLen > packet.size) return null
        off[0] += tokenLen.toInt()
        readVarint(packet, off) ?: return null
        // packet number (pn_len bytes, from the flags' low 2 bits)
        if (off[0] + pnLen > packet.size) return null
        off[0] += pnLen
        return packet.copyOfRange(off[0], packet.size)
    }

    /** QUIC variable-length integer (RFC 9000 §16): the first byte's top 2 bits give
     *  the length (1/2/4/8), the value is the remaining bits. Advances `off[0]`. */
    private fun readVarint(buf: ByteArray, off: IntArray): Long? {
        if (off[0] >= buf.size) return null
        val first = buf[off[0]].toInt() and 0xFF
        val len = 1 shl (first ushr 6)
        if (off[0] + len > buf.size) return null
        // Accumulate into a Long: an 8-byte varint holds up to 2^62-1, which overflowed the
        // old Int accumulator negative and poisoned the caller's offset math.
        var v = (first and 0x3F).toLong()
        for (i in 1 until len) v = (v shl 8) or (buf[off[0] + i].toLong() and 0xFFL)
        off[0] += len
        return v
    }

    private fun unwrapShort(packet: ByteArray): ByteArray? {
        // 1 flags + 4 cid + at least 1 pn byte
        if (packet.size < 1 + 4 + 4) return null
        val flags = packet[0].toInt() and 0xFF
        val pnLen = (flags and 0x03) + 1
        var offset = 1 + 4 // flags + connection id
        val pnEnd = offset + pnLen.coerceAtMost(4)
        if (pnEnd > packet.size) return null
        offset = pnEnd
        return packet.copyOfRange(offset, packet.size)
    }

    private fun ByteArrayOutputStream.writeIntBE(value: Int) {
        write((value ushr 24) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF)
        write(value and 0xFF)
    }
}
