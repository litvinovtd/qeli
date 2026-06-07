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

    /** flags | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | pn(4) | data */
    fun wrapLong(data: ByteArray, connectionId: ByteArray, packetNumber: Int, packetType: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(LONG_HEADER_FLAG or (packetType and 0x0F))
        out.writeIntBE(VERSION_V1)
        out.write(4)
        out.write(connectionId, 0, 4)
        out.write(0)
        out.writeIntBE(packetNumber)
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
        // 1 flags + 4 version + 1 dcid_len + 1 scid_len + 4 pn = 11 minimum
        if (packet.size < 11) return null
        var offset = 5 // skip flags + version
        val dcidLen = packet[offset].toInt() and 0xFF
        offset += 1
        if (offset + dcidLen > packet.size) return null
        offset += dcidLen
        if (offset >= packet.size) return null
        val scidLen = packet[offset].toInt() and 0xFF
        offset += 1
        if (offset + scidLen > packet.size) return null
        offset += scidLen
        if (offset + 4 > packet.size) return null
        offset += 4 // packet number
        return packet.copyOfRange(offset, packet.size)
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
