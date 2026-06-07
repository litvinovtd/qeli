package com.qeli.protocol

import java.security.MessageDigest

/**
 * `obfs` wire mode. Mirrors qeli/src/protocol/obfs.rs.
 *
 * The entire connection is XORed with a ChaCha20 keystream keyed by a PSK.
 * Each side sends a random 12-byte nonce in the clear at connection start, then
 * derives its send keystream from (psk, own_nonce) and its receive keystream
 * from (psk, peer_nonce). The keystream is continuous for the lifetime of the
 * connection, so a stateful generator per direction advances across calls.
 *
 * NOTE: the keystream is a pure-Kotlin RFC 8439 ChaCha20 (see
 * Companion.chacha20Block) — NOT javax `Cipher("ChaCha20")`, whose
 * ChaCha20ParameterSpec(byte[],int) ctor is missing on some Android runtimes
 * (NoSuchMethodError → crash on connect).
 */
class ObfsStream private constructor(
    private val writeKs: ChaCha20Keystream,
    private val readKs: ChaCha20Keystream
) {
    private val writeLock = Any()
    private val readLock = Any()

    /** XOR outbound bytes (keystream advances). */
    fun transformWrite(data: ByteArray): ByteArray = synchronized(writeLock) {
        writeKs.xor(data)
    }

    /** XOR inbound bytes (keystream advances). */
    fun transformRead(data: ByteArray): ByteArray = synchronized(readLock) {
        readKs.xor(data)
    }

    /** Stateful continuous ChaCha20 keystream (IETF, counter from 0). Tracks the
     *  block counter + intra-block offset so successive [xor] calls form one
     *  unbroken keystream — byte-for-byte compatible with the Rust streaming
     *  ObfsStream (chacha20 crate's apply_keystream). */
    class ChaCha20Keystream(private val key: ByteArray, private val nonce: ByteArray) {
        private var counter = 0
        private var block = ByteArray(0)
        private var blockOff = 0
        fun xor(data: ByteArray): ByteArray {
            val out = ByteArray(data.size)
            for (i in data.indices) {
                if (blockOff >= block.size) {
                    block = chacha20Block(key, counter, nonce); counter++; blockOff = 0
                }
                out[i] = (data[i].toInt() xor block[blockOff].toInt()).toByte()
                blockOff++
            }
            return out
        }
    }

    companion object {
        private const val NONCE_LEN = 12

        /** key = SHA256("qeli-obfs-key-v1" || psk) */
        fun deriveKey(psk: String): ByteArray {
            val md = MessageDigest.getInstance("SHA-256")
            md.update("qeli-obfs-key-v1".toByteArray(Charsets.UTF_8))
            md.update(psk.toByteArray(Charsets.UTF_8))
            return md.digest()
        }

        /**
         * Per-datagram obfs for UDP (mirrors qeli/src/protocol/obfs.rs::
         * obfs_datagram_seal/open). Unlike the streaming TCP mode, each datagram
         * is self-contained: a fresh 12-byte nonce prefix + ChaCha20(key,nonce)
         * XOR of the payload. Stateless → tolerates UDP loss/reordering.
         */
        fun datagramSeal(key: ByteArray, payload: ByteArray): ByteArray {
            val rnd = java.security.SecureRandom()
            val nonce = ByteArray(NONCE_LEN).also { rnd.nextBytes(it) }
            // QUIC short-header-shaped flag byte (fixed bit set) so the datagram
            // isn't high-entropy random from byte 0 (DPI-AUDIT tell 4.2). Ignored on open.
            val flag = byteArrayOf((0x40 or rnd.nextInt(0x40)).toByte())
            return flag + nonce + chacha20Xor(key, nonce, payload)
        }

        /** Open a sealed datagram, or null if too short / malformed. */
        fun datagramOpen(key: ByteArray, datagram: ByteArray): ByteArray? {
            if (datagram.size < 1 + NONCE_LEN) return null
            val nonce = datagram.copyOfRange(1, 1 + NONCE_LEN) // [0] = QUIC-shaped flag
            return chacha20Xor(key, nonce, datagram.copyOfRange(1 + NONCE_LEN, datagram.size))
        }

        // ── pure-Kotlin ChaCha20 (RFC 8439) keystream XOR ───────────────────
        //
        // Android's javax `Cipher("ChaCha20")` + ChaCha20ParameterSpec is not
        // usable across all runtime images (the (byte[],int) ctor is missing on
        // some), so the stream cipher is implemented directly. IETF ChaCha20:
        // 12-byte nonce, 32-bit block counter starting at 0 — byte-for-byte
        // compatible with the Rust `chacha20` crate (qeli/src/protocol/obfs.rs).

        /** XOR [data] with the ChaCha20(key, counter=0.., nonce) keystream. */
        fun chacha20Xor(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
            val out = ByteArray(data.size)
            var counter = 0
            var off = 0
            while (off < data.size) {
                val block = chacha20Block(key, counter, nonce)
                val n = minOf(64, data.size - off)
                for (i in 0 until n) out[off + i] = (data[off + i].toInt() xor block[i].toInt()).toByte()
                off += n; counter++
            }
            return out
        }

        fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
            val s = IntArray(16)
            s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
            for (i in 0..7) s[4 + i] = leInt(key, i * 4)
            s[12] = counter
            for (i in 0..2) s[13 + i] = leInt(nonce, i * 4)
            val w = s.copyOf()
            repeat(10) {
                qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
                qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
            }
            val out = ByteArray(64)
            for (i in 0..15) putLeInt(out, i * 4, w[i] + s[i])
            return out
        }

        private fun qr(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
            s[a] += s[b]; s[d] = rotl(s[d] xor s[a], 16)
            s[c] += s[d]; s[b] = rotl(s[b] xor s[c], 12)
            s[a] += s[b]; s[d] = rotl(s[d] xor s[a], 8)
            s[c] += s[d]; s[b] = rotl(s[b] xor s[c], 7)
        }

        private fun rotl(x: Int, n: Int): Int = (x shl n) or (x ushr (32 - n))
        private fun leInt(b: ByteArray, o: Int): Int =
            (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)
        private fun putLeInt(b: ByteArray, o: Int, v: Int) {
            b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v ushr 8) and 0xFF).toByte()
            b[o + 2] = ((v ushr 16) and 0xFF).toByte(); b[o + 3] = ((v ushr 24) and 0xFF).toByte()
        }

        /**
         * Client handshake: write our nonce, read the server's, derive keystreams.
         * [sendRaw] / [recvRaw] operate on the raw (un-obfuscated) socket.
         *
         * When [fronting] is set, a WebSocket Upgrade handshake is performed first
         * (mirrors qeli/src/protocol/obfs.rs::ws): the connection's first bytes are
         * printable HTTP text so they survive the GFW/TSPU "fully encrypted traffic"
         * heuristic, then the existing nonce exchange follows the `101` response.
         */
        fun connect(
            key: ByteArray,
            fronting: Boolean,
            sendRaw: (ByteArray) -> Unit,
            recvRaw: (Int) -> ByteArray
        ): ObfsStream {
            if (fronting) {
                sendRaw(buildWsRequest())
                val head = readHttpHead(recvRaw)
                require(head.startsWith("HTTP/1.1 101")) {
                    "obfs ws: server did not switch protocols"
                }
            }
            val local = ByteArray(NONCE_LEN).also { java.security.SecureRandom().nextBytes(it) }
            sendRaw(local)
            val peer = recvRaw(NONCE_LEN)
            return ObfsStream(
                writeKs = ChaCha20Keystream(key, local),
                readKs = ChaCha20Keystream(key, peer)
            )
        }

        // ── WebSocket-Upgrade fronting (client side) ─────────────────────────

        private const val MAX_HTTP_HEAD = 4096
        private val WS_HOSTS = arrayOf(
            "www.cloudflare.com", "www.google.com", "www.microsoft.com",
            "www.apple.com", "www.amazon.com"
        )
        private val WS_USER_AGENTS = arrayOf(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
        )
        private const val B64_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        private const val PATH_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

        /** Standard base64 with padding (inline — keeps this file framework-free). */
        private fun base64(data: ByteArray): String {
            val sb = StringBuilder((data.size + 2) / 3 * 4)
            var i = 0
            while (i + 3 <= data.size) {
                val n = ((data[i].toInt() and 0xFF) shl 16) or
                    ((data[i + 1].toInt() and 0xFF) shl 8) or (data[i + 2].toInt() and 0xFF)
                sb.append(B64_ALPHABET[(n ushr 18) and 0x3F])
                sb.append(B64_ALPHABET[(n ushr 12) and 0x3F])
                sb.append(B64_ALPHABET[(n ushr 6) and 0x3F])
                sb.append(B64_ALPHABET[n and 0x3F])
                i += 3
            }
            when (data.size - i) {
                1 -> {
                    val n = (data[i].toInt() and 0xFF) shl 16
                    sb.append(B64_ALPHABET[(n ushr 18) and 0x3F])
                    sb.append(B64_ALPHABET[(n ushr 12) and 0x3F])
                    sb.append("==")
                }
                2 -> {
                    val n = ((data[i].toInt() and 0xFF) shl 16) or ((data[i + 1].toInt() and 0xFF) shl 8)
                    sb.append(B64_ALPHABET[(n ushr 18) and 0x3F])
                    sb.append(B64_ALPHABET[(n ushr 12) and 0x3F])
                    sb.append(B64_ALPHABET[(n ushr 6) and 0x3F])
                    sb.append('=')
                }
            }
            return sb.toString()
        }

        /** Build a randomised WebSocket Upgrade request (the client's first bytes). */
        private fun buildWsRequest(): ByteArray {
            val rnd = java.security.SecureRandom()
            val host = WS_HOSTS[rnd.nextInt(WS_HOSTS.size)]
            val ua = WS_USER_AGENTS[rnd.nextInt(WS_USER_AGENTS.size)]
            val pathLen = 12 + rnd.nextInt(17) // 12..28
            val path = StringBuilder("/")
            repeat(pathLen) { path.append(PATH_ALPHABET[rnd.nextInt(PATH_ALPHABET.length)]) }
            val wsKey = base64(ByteArray(16).also { rnd.nextBytes(it) })
            val req = "GET $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: $ua\r\n" +
                "Accept: */*\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: $wsKey\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "\r\n"
            return req.toByteArray(Charsets.US_ASCII)
        }

        /** Read an HTTP head up to and including CRLFCRLF, bounded (anti-OOM). */
        private fun readHttpHead(recvRaw: (Int) -> ByteArray): String {
            val buf = java.io.ByteArrayOutputStream(256)
            // Rolling big-endian window of the last 4 bytes; Int is 32-bit so the
            // shift naturally keeps only the most recent four.
            var window = 0
            while (true) {
                val b = recvRaw(1)
                if (b.isEmpty()) throw java.io.IOException("obfs ws: connection closed during handshake")
                buf.write(b[0].toInt())
                window = (window shl 8) or (b[0].toInt() and 0xFF)
                if (buf.size() >= 4 && window == 0x0D0A0D0A) {
                    return buf.toString("US-ASCII")
                }
                if (buf.size() > MAX_HTTP_HEAD) throw java.io.IOException("obfs ws: handshake head too large")
            }
        }
    }
}
