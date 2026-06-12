package com.qeli.protocol

import com.qeli.crypto.PacketCipher
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

class PacketCodec(
    private val cipher: PacketCipher,
    private val random: SecureRandom = SecureRandom(),
    private var paddingEnabled: Boolean = true,
    private var paddingMin: Int = 0,
    private var paddingMax: Int = 255,
    // Wire framing. false = TLS record ([0x17 0x03 0x03][u16 len], 5-byte header) for
    // fake-tls/obfs/reality; true = bare [u16 len] (2-byte header) for the `plain`
    // wire mode. Mirrors the Rust PacketCodec Framing::Tls / Framing::Raw.
    private val raw: Boolean = false
) {
    private val headerSize = if (raw) 2 else HEADER_SIZE
    /** Override padding params (used to apply server-pushed obfuscation after
     *  auth, without recreating the codec — the packet counter must continue or
     *  the server's replay window rejects the first data packet as a replay). */
    fun setPadding(enabled: Boolean, min: Int, max: Int) {
        paddingEnabled = enabled
        paddingMin = min
        paddingMax = max
    }

    private val counter = AtomicLong(0)

    // Anti-replay sliding window (mirrors the server's packet.rs window). Bit i of
    // [replayBitmap] marks counter (replayHighest - i) as already seen. A strict
    // "must be > last" check (the old behaviour) dropped every reordered datagram
    // on UDP, where reordering is normal; a window accepts in-window reorderings
    // while still rejecting true replays. Decrypt runs single-threaded (one
    // download job), so plain fields are safe.
    private var replayHighest: Long = -1
    private val replayBits = LongArray(REPLAY_WORDS) // 2048-bit window (M-13)

    /** True if [seq] is fresh (not a replay / not too old); records it as seen. */
    private fun acceptCounter(seq: Long): Boolean {
        if (replayHighest < 0) { replayHighest = seq; replayBits[0] = 1L; return true }
        if (seq > replayHighest) {
            val advance = seq - replayHighest
            if (advance >= REPLAY_WINDOW) replayBits.fill(0L) else shiftWindow(advance.toInt())
            replayHighest = seq
            replayBits[0] = replayBits[0] or 1L          // distance 0 = current highest seq
            return true
        }
        val diff = replayHighest - seq
        if (diff >= REPLAY_WINDOW) return false          // older than the window
        val wi = (diff / 64).toInt()
        val mask = 1L shl (diff % 64).toInt()
        if (replayBits[wi] and mask != 0L) return false  // already seen → replay
        replayBits[wi] = replayBits[wi] or mask
        return true
    }

    /** Multi-word left shift of the replay window by [n] bits (toward higher
     *  distance), dropping bits that fall off the top. Mirrors packet.rs. */
    private fun shiftWindow(n: Int) {
        val words = n / 64
        val off = n % 64
        if (off == 0) {
            for (i in REPLAY_WORDS - 1 downTo 0)
                replayBits[i] = if (i >= words) replayBits[i - words] else 0L
        } else {
            for (i in REPLAY_WORDS - 1 downTo 0) {
                val lo = if (i >= words) replayBits[i - words] shl off else 0L
                val hi = if (i > words) replayBits[i - words - 1] ushr (64 - off) else 0L
                replayBits[i] = lo or hi
            }
        }
    }

    companion object {
        const val HEADER_SIZE = 5
        const val NONCE_SIZE = 12
        const val TAG_SIZE = 16
        const val COUNTER_SIZE = 8
        const val REPLAY_WINDOW = 2048 // WireGuard-sized anti-replay window (M-13)
        const val REPLAY_WORDS = REPLAY_WINDOW / 64
        const val APPLICATION_DATA: Byte = 0x17
        const val MAX_RECORD_SIZE = 16384 + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE + 256

        private fun buildTlsRecordHeader(contentType: Byte, length: Int): ByteArray {
            return byteArrayOf(
                contentType,
                0x03, 0x03,
                ((length shr 8) and 0xFF).toByte(),
                (length and 0xFF).toByte()
            )
        }
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val currentCounter = counter.getAndIncrement()
        if (currentCounter >= Long.MAX_VALUE - 1000) {
            throw PacketException("Counter exhausted - session must be renegotiated")
        }

        val nonce = ByteArray(NONCE_SIZE).also { random.nextBytes(it) }

        val paddingLen = if (paddingEnabled) {
            val lo = paddingMin.coerceIn(0, 65535)
            val hi = paddingMax.coerceIn(lo, 65535)
            if (hi > lo) lo + random.nextInt(hi - lo + 1) else lo
        } else 0
        val padding = ByteArray(paddingLen).also { if (paddingLen > 0) random.nextBytes(it) }

        val inner = ByteArray(COUNTER_SIZE + plaintext.size + paddingLen + 2)
        inner[0] = ((currentCounter shr 56) and 0xFF).toByte()
        inner[1] = ((currentCounter shr 48) and 0xFF).toByte()
        inner[2] = ((currentCounter shr 40) and 0xFF).toByte()
        inner[3] = ((currentCounter shr 32) and 0xFF).toByte()
        inner[4] = ((currentCounter shr 24) and 0xFF).toByte()
        inner[5] = ((currentCounter shr 16) and 0xFF).toByte()
        inner[6] = ((currentCounter shr 8) and 0xFF).toByte()
        inner[7] = (currentCounter and 0xFF).toByte()
        System.arraycopy(plaintext, 0, inner, COUNTER_SIZE, plaintext.size)
        System.arraycopy(padding, 0, inner, COUNTER_SIZE + plaintext.size, paddingLen)
        inner[inner.size - 2] = ((paddingLen shr 8) and 0xFF).toByte()
        inner[inner.size - 1] = (paddingLen and 0xFF).toByte()

        val ciphertext = cipher.encrypt(inner, nonce)

        val payloadLen = NONCE_SIZE + ciphertext.size

        return ByteArray(headerSize + payloadLen).apply {
            if (raw) {
                // Bare 2-byte big-endian length prefix (no TLS type/version).
                this[0] = ((payloadLen shr 8) and 0xFF).toByte()
                this[1] = (payloadLen and 0xFF).toByte()
            } else {
                val header = buildTlsRecordHeader(APPLICATION_DATA, payloadLen)
                System.arraycopy(header, 0, this, 0, HEADER_SIZE)
            }
            System.arraycopy(nonce, 0, this, headerSize, NONCE_SIZE)
            System.arraycopy(ciphertext, 0, this, headerSize + NONCE_SIZE, ciphertext.size)
        }
    }

    fun decrypt(packet: ByteArray): ByteArray {
        if (packet.size < headerSize + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE + 2) {
            throw PacketException("Packet too short: ${packet.size}")
        }

        val payloadLen = if (raw) {
            ((packet[0].toInt() and 0xFF) shl 8) or (packet[1].toInt() and 0xFF)
        } else {
            if (packet[0] != APPLICATION_DATA) {
                throw PacketException("Wrong content type: ${packet[0]}")
            }
            ((packet[3].toInt() and 0xFF) shl 8) or (packet[4].toInt() and 0xFF)
        }
        if (payloadLen > MAX_RECORD_SIZE) {
            throw PacketException("Packet too large: $payloadLen")
        }
        // Defensive bounds (parity with the Rust decoder): the declared length must
        // hold nonce+tag+counter+pad_len and fit within the bytes present, else the
        // copyOfRange calls below would throw a raw index exception. (L3)
        if (payloadLen < NONCE_SIZE + TAG_SIZE + COUNTER_SIZE + 2 ||
            headerSize + payloadLen > packet.size
        ) {
            throw PacketException("Packet truncated: payloadLen=$payloadLen, have=${packet.size - headerSize}")
        }

        val nonce = packet.copyOfRange(headerSize, headerSize + NONCE_SIZE)
        val ciphertext = packet.copyOfRange(headerSize + NONCE_SIZE, headerSize + payloadLen)

        val plaintext = cipher.decrypt(ciphertext, nonce)

        if (plaintext.size < COUNTER_SIZE + 2) {
            throw PacketException("Decrypted payload too short: ${plaintext.size}")
        }

        val packetCounter = ((plaintext[0].toLong() and 0xFF) shl 56) or
                ((plaintext[1].toLong() and 0xFF) shl 48) or
                ((plaintext[2].toLong() and 0xFF) shl 40) or
                ((plaintext[3].toLong() and 0xFF) shl 32) or
                ((plaintext[4].toLong() and 0xFF) shl 24) or
                ((plaintext[5].toLong() and 0xFF) shl 16) or
                ((plaintext[6].toLong() and 0xFF) shl 8) or
                (plaintext[7].toLong() and 0xFF)

        if (!acceptCounter(packetCounter)) {
            throw PacketException("Replay detected: counter $packetCounter (window highest $replayHighest)")
        }

        val paddingLen = ((plaintext[plaintext.size - 2].toInt() and 0xFF) shl 8) or
                (plaintext[plaintext.size - 1].toInt() and 0xFF)

        if (COUNTER_SIZE + paddingLen + 2 > plaintext.size) {
            throw PacketException("Invalid padding: $paddingLen")
        }

        val dataLen = plaintext.size - COUNTER_SIZE - 2 - paddingLen
        return plaintext.copyOfRange(COUNTER_SIZE, COUNTER_SIZE + dataLen)
    }
}

class PacketException(message: String) : Exception(message)