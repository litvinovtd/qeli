package com.qeli.protocol

import com.qeli.crypto.PacketCipher
import java.security.MessageDigest
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

    // M6: per-instance nonce seed + PRP key. The nonce goes on the wire and the peer never
    // inverts the PRP (it reads the nonce straight off the wire), so these are LOCAL randomness
    // and need NOT match the peer's — they only have to make (seed‖counter) unique per key,
    // which a monotonic counter + a fresh per-session key guarantee. A fresh seed per instance
    // also keeps nonces unique across a reconnect that reused the key. (Rust derives this key
    // from the AEAD key instead; both are correct precisely because it is one-sided.)
    private val nonceSeed = ByteArray(4).also { random.nextBytes(it) }
    private val noncePrpKey = ByteArray(32).also { random.nextBytes(it) }

    // Anti-replay sliding window (mirrors the server's packet.rs window). Bit i of
    // [replayBitmap] marks counter (replayHighest - i) as already seen. A strict
    // "must be > last" check (the old behaviour) dropped every reordered datagram
    // on UDP, where reordering is normal; a window accepts in-window reorderings
    // while still rejecting true replays. Decrypt runs single-threaded (one
    // download job), so plain fields are safe.
    // The counter is an UNSIGNED 64-bit wire value; `Long` only holds its bit pattern.
    //
    // "Not initialised yet" used to be encoded as `replayHighest < 0`, which collides with
    // every counter whose top bit is set. One record with a counter >= 2^63 — the sequence
    // is read straight out of the decrypted plaintext, so a hostile or compromised server
    // picks it — left `replayHighest` negative, and from then on the `< 0` branch fired on
    // EVERY packet and returned true unconditionally: the window was off for the rest of the
    // session and any captured record could be replayed at will. Rust never had this because
    // it stores the counter as `u64` and keeps a separate `initialized` flag; Swift is fine
    // too (`UInt64?`). Only these two ports encoded the sentinel in-band.
    // (Audit 2026-08-04, H-06.)
    private var replayInitialized = false
    private var replayHighest: Long = 0
    private val replayBits = LongArray(REPLAY_WORDS) // 2048-bit window (M-13)

    /** True if [seq] is fresh (not a replay / not too old); records it as seen.
     *  [seq] is compared as UNSIGNED — see [replayInitialized].
     *  `internal` so the shared replay-window fixture (`conformance/replay-window.json`) can
     *  drive it directly — the window is pure state, and going through [decrypt] would need a
     *  valid record per sequence number. */
    internal fun acceptCounter(seq: Long): Boolean {
        if (!replayInitialized) {
            replayInitialized = true
            replayHighest = seq
            replayBits[0] = 1L
            return true
        }
        if (java.lang.Long.compareUnsigned(seq, replayHighest) > 0) {
            val advance = seq - replayHighest   // unsigned distance; bit pattern is correct
            // Compare unsigned: an advance of >= 2^63 is a huge jump, not a negative one.
            if (java.lang.Long.compareUnsigned(advance, REPLAY_WINDOW.toLong()) >= 0) {
                replayBits.fill(0L)
            } else {
                shiftWindow(advance.toInt())
            }
            replayHighest = seq
            replayBits[0] = replayBits[0] or 1L          // distance 0 = current highest seq
            return true
        }
        val diff = replayHighest - seq                   // unsigned distance
        if (java.lang.Long.compareUnsigned(diff, REPLAY_WINDOW.toLong()) >= 0) return false
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

    // ── M6: counter-derived data-plane nonce (mirrors Rust packet.rs) ────────────
    /** Build the 96-bit wire nonce for [counterValue] as PRP(seed(4) ‖ counter_be(8)).
     *  A balanced Feistel network is bijective for any round function, so distinct
     *  (seed,counter) inputs — the counter is monotonic — always map to distinct nonces
     *  (no AEAD nonce reuse), while the on-wire value no longer increments by 1 (no
     *  visible-counter DPI tell). Replaces the previous random 96-bit nonce, which carried
     *  a birthday-collision risk the construction removes by design. */
    private fun nonceForCounter(counterValue: Long): ByteArray =
        prpNonce(noncePrpKey, rawNonce(nonceSeed, counterValue))

    companion object {
        const val HEADER_SIZE = 5
        const val NONCE_SIZE = 12
        const val TAG_SIZE = 16
        const val COUNTER_SIZE = 8
        const val REPLAY_WINDOW = 2048 // WireGuard-sized anti-replay window (M-13)
        const val REPLAY_WORDS = REPLAY_WINDOW / 64
        const val APPLICATION_DATA: Byte = 0x17
        const val MAX_RECORD_SIZE = 16384 + NONCE_SIZE + TAG_SIZE + COUNTER_SIZE + 256

        /** The pre-permutation nonce input: seed(4) ‖ counter big-endian(8). Split out of
         *  [nonceForCounter] so the whole derivation is unit-testable without an instance
         *  (building a codec needs a PacketCipher, which needs Conscrypt + android.util.Log). */
        internal fun rawNonce(seed: ByteArray, counterValue: Long): ByteArray {
            val raw = ByteArray(NONCE_SIZE)
            System.arraycopy(seed, 0, raw, 0, 4)
            raw[4] = ((counterValue shr 56) and 0xFF).toByte()
            raw[5] = ((counterValue shr 48) and 0xFF).toByte()
            raw[6] = ((counterValue shr 40) and 0xFF).toByte()
            raw[7] = ((counterValue shr 32) and 0xFF).toByte()
            raw[8] = ((counterValue shr 24) and 0xFF).toByte()
            raw[9] = ((counterValue shr 16) and 0xFF).toByte()
            raw[10] = ((counterValue shr 8) and 0xFF).toByte()
            raw[11] = (counterValue and 0xFF).toByte()
            return raw
        }

        /** 96-bit balanced Feistel permutation, 4 rounds; round fn = SHA256(key‖round‖half)[..6].
         *  Byte-for-byte identical to Rust `packet.rs prp_nonce` (not required for interop —
         *  the peer reads the nonce straight off the wire — but kept identical for auditability). */
        internal fun prpNonce(key: ByteArray, raw: ByteArray): ByteArray {
            var l = raw.copyOfRange(0, 6)
            var r = raw.copyOfRange(6, 12)
            for (round in 0 until 4) {
                val f = prpRound(key, round.toByte(), r)
                val nr = ByteArray(6)
                for (i in 0 until 6) nr[i] = (l[i].toInt() xor f[i].toInt()).toByte()
                l = r
                r = nr
            }
            val out = ByteArray(NONCE_SIZE)
            System.arraycopy(l, 0, out, 0, 6)
            System.arraycopy(r, 0, out, 6, 6)
            return out
        }

        private fun prpRound(key: ByteArray, round: Byte, half: ByteArray): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(key)
            md.update(round)
            md.update(half)
            return md.digest().copyOfRange(0, 6)
        }

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
        val paddingLen = if (paddingEnabled) {
            val lo = paddingMin.coerceIn(0, 65535)
            val hi = paddingMax.coerceIn(lo, 65535)
            if (hi > lo) lo + random.nextInt(hi - lo + 1) else lo
        } else 0
        return encryptPadded(plaintext, paddingLen)
    }

    /** Encrypt with an EXPLICIT padding length, ignoring the configured padding
     *  range. Used by flow-shaping cover traffic (empty plaintext + sized
     *  padding); the wire format is byte-identical to [encrypt]. */
    fun encryptPadded(plaintext: ByteArray, padLen: Int): ByteArray {
        val currentCounter = counter.getAndIncrement()
        if (currentCounter >= Long.MAX_VALUE - 1000) {
            throw PacketException("Counter exhausted - session must be renegotiated")
        }

        val nonce = nonceForCounter(currentCounter)

        val paddingLen = padLen.coerceIn(0, 65535)
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
        // Guard the record size BEFORE writing the 16-bit length field (parity with Rust
        // encrypt_packet's MAX_RECORD_SIZE check). Without it, an oversized padding_max or
        // shaping cover size can build a record the peer rejects as too large, and past 65535
        // the length write wraps and desyncs the whole TCP stream. Fail here instead.
        if (payloadLen > MAX_RECORD_SIZE) {
            throw PacketException(
                "record payload $payloadLen exceeds MAX_RECORD_SIZE $MAX_RECORD_SIZE — " +
                    "reduce padding_max or the shaping cover size"
            )
        }

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

    /** Encrypt with the configured padding range, but capped so that
     *  `plaintext.size + padding` never exceeds [maxInnerPlusPad]. Keeps the padded
     *  record inside the (probed) tunnel MTU so a DF-marked UDP datagram is not dropped
     *  with EMSGSIZE after path-MTU probing — the server pushes 40–400 B of padding,
     *  which otherwise pushes every full-size data packet past the path MTU and killed
     *  the udp-quic tunnel on the first packet. Mirrors the Rust client's per-packet
     *  pad_cap (client/mod.rs). */
    fun encryptCapped(plaintext: ByteArray, maxInnerPlusPad: Int): ByteArray {
        if (!paddingEnabled) return encryptPadded(plaintext, 0)
        val room = (maxInnerPlusPad - plaintext.size).coerceAtLeast(0)
        val lo = paddingMin.coerceIn(0, room)
        val hi = paddingMax.coerceIn(lo, room)
        val pad = if (hi > lo) lo + random.nextInt(hi - lo + 1) else lo
        return encryptPadded(plaintext, pad)
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
            // The legacy_record_version too, not just the content type. Every record we EMIT
            // carries 0x03 0x03, and a real TLS 1.3 peer emits nothing else on an established
            // connection — so accepting other bytes made the masking framing looser than the
            // thing it imitates, for no gain. (Audit 2026-08-03, P3.)
            if (packet[1] != 0x03.toByte() || packet[2] != 0x03.toByte()) {
                throw PacketException("Wrong record version: ${packet[1]} ${packet[2]}")
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

        // Validate the padding BEFORE recording the counter, like the Rust and iOS clients.
        // A record that decrypts (so it is genuinely from the peer) but carries malformed
        // padding is a peer bug, not an attack — recording it first needlessly burned that
        // counter's slot in the replay window. (Audit 2026-07-30.)
        val paddingLen = ((plaintext[plaintext.size - 2].toInt() and 0xFF) shl 8) or
                (plaintext[plaintext.size - 1].toInt() and 0xFF)

        if (COUNTER_SIZE + paddingLen + 2 > plaintext.size) {
            throw PacketException("Invalid padding: $paddingLen")
        }

        if (!acceptCounter(packetCounter)) {
            throw PacketException("Replay detected: counter $packetCounter (window highest $replayHighest)")
        }

        val dataLen = plaintext.size - COUNTER_SIZE - 2 - paddingLen
        return plaintext.copyOfRange(COUNTER_SIZE, COUNTER_SIZE + dataLen)
    }
}

class PacketException(message: String) : Exception(message)