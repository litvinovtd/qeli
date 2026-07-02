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
    private val readKs: ChaCha20Keystream,
    // F3: when fronting == websocket, the post-101 stream (junk, nonce exchange,
    // and all data) is carried as RFC-6455 binary frames. `wsWriter`/`wsReader`
    // are null for fronting == none, in which case the wire is the raw continuous
    // ChaCha20-XOR exactly as before (regression-critical byte-identity).
    private val wsWriter: WsFrameWriter? = null,
    private val wsReader: WsFrameReader? = null
) {
    private val writeLock = Any()
    private val readLock = Any()

    /** True when this stream carries WebSocket binary framing (fronting=websocket). */
    val isWebSocket: Boolean get() = wsWriter != null

    /** XOR outbound bytes (keystream advances). */
    fun transformWrite(data: ByteArray): ByteArray = synchronized(writeLock) {
        writeKs.xor(data)
    }

    /** XOR inbound bytes (keystream advances). */
    fun transformRead(data: ByteArray): ByteArray = synchronized(readLock) {
        readKs.xor(data)
    }

    // ── F3 framed I/O (websocket fronting only) ─────────────────────────
    //
    // With WS fronting the transport MUST route socket I/O through these instead
    // of the raw path: [writeFramed] does ChaCha20 THEN masks + WS-frames the
    // cipherbytes; [readFramed] deframes+unmasks WS frames THEN ChaCha20-decrypts,
    // returning exactly [size] plaintext bytes. For fronting=none these are never
    // called (SocketIO keeps the raw transformWrite/readBytes path → byte-identical).

    /** Encrypt+frame [data] and push it to the socket via [sendRaw]. WS-only. */
    fun writeFramed(data: ByteArray, sendRaw: (ByteArray) -> Unit) {
        val w = wsWriter ?: throw IllegalStateException("writeFramed on non-websocket ObfsStream")
        val cipher = synchronized(writeLock) { writeKs.xor(data) }
        sendRaw(w.frame(cipher))
    }

    /** Read+deframe+decrypt exactly [size] plaintext bytes via [recvRaw]. WS-only. */
    fun readFramed(size: Int, recvRaw: (Int) -> ByteArray): ByteArray {
        val r = wsReader ?: throw IllegalStateException("readFramed on non-websocket ObfsStream")
        val cipher = r.read(size, recvRaw)
        return synchronized(readLock) { readKs.xor(cipher) }
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

    // ── F3: RFC-6455 binary framing (opcode 0x2, FIN=1) ──────────────────
    //
    // Byte-for-byte identical to the Rust/C# WS framers so the three ends agree.
    //   byte0 = 0x82 (FIN=1, opcode=0x2)
    //   byte1 = (MASK<<7) | len7; len7 in {0..125, 126→u16 BE ext, 127→u64 BE ext}
    //   client->server: MASK=1, 4 random mask bytes, payload[i]=cipher[i]^mask[i%4]
    //   server->client: MASK=0, no mask bytes, payload=cipher (unmasked, per RFC)
    // The WRITER chunks plaintext-cipher into <=16384-byte frame payloads.

    /** Client->server frame writer: masks (F3) and length-prefixes cipherbytes. */
    class WsFrameWriter {
        private val rnd = java.security.SecureRandom()

        /** Emit [cipher] as one or more masked binary frames (each <=16384 payload). */
        fun frame(cipher: ByteArray): ByteArray {
            val out = java.io.ByteArrayOutputStream(cipher.size + 8)
            var off = 0
            do {
                val n = minOf(WS_MAX_PAYLOAD, cipher.size - off)
                val mask = ByteArray(4).also { rnd.nextBytes(it) }
                writeFrame(out, cipher, off, n, mask)
                off += n
            } while (off < cipher.size)
            return out.toByteArray()
        }

        private fun writeFrame(out: java.io.ByteArrayOutputStream, src: ByteArray, srcOff: Int, len: Int, mask: ByteArray) {
            out.write(0x82)                       // FIN=1, opcode=0x2 (binary)
            writeLenPrefix(out, len, masked = true)
            out.write(mask)                       // 4 mask bytes (MASK=1)
            for (i in 0 until len) out.write((src[srcOff + i].toInt() xor mask[i % 4].toInt()) and 0xFF)
        }
    }

    /** STATEFUL server->client (+ any inbound) reframer. TCP can split a header
     *  across reads or coalesce a frame tail with the next header, so this buffers
     *  a partial header and tracks the remaining payload length across [read]s.
     *  Server->client frames are unmasked (MASK=0). Inbound masked frames (should
     *  not occur s->c) are still unmasked defensively if MASK=1 is seen. */
    class WsFrameReader {
        private val pending = java.io.ByteArrayOutputStream()  // decoded cipher not yet consumed
        private var pendingOff = 0

        /** Return exactly [size] cipher bytes, pulling+deframing raw as needed. */
        fun read(size: Int, recvRaw: (Int) -> ByteArray): ByteArray {
            while (pending.size() - pendingOff < size) decodeOneFrame(recvRaw)
            val buf = pending.toByteArray()
            val out = buf.copyOfRange(pendingOff, pendingOff + size)
            pendingOff += size
            // Compact once fully consumed to bound memory.
            if (pendingOff >= pending.size()) { pending.reset(); pendingOff = 0 }
            return out
        }

        /** F2 (WS): read one whole binary frame and DISCARD its payload. Junk is
         *  consumed before any data is buffered, so `pending` must stay empty. */
        fun discardOneFrame(recvRaw: (Int) -> ByteArray) {
            require(pending.size() == pendingOff) { "obfs ws: junk after data buffered" }
            decodeOneFrame(recvRaw)
            pending.reset(); pendingOff = 0
        }

        private fun recvExact(size: Int, recvRaw: (Int) -> ByteArray): ByteArray {
            val buf = ByteArray(size)
            var off = 0
            while (off < size) {
                val chunk = recvRaw(size - off)
                if (chunk.isEmpty()) throw java.io.IOException("obfs ws: connection closed mid-frame")
                System.arraycopy(chunk, 0, buf, off, chunk.size); off += chunk.size
            }
            return buf
        }

        private fun decodeOneFrame(recvRaw: (Int) -> ByteArray) {
            val b0 = recvExact(1, recvRaw)[0].toInt() and 0xFF
            require(b0 == 0x82) { "obfs ws: unexpected frame byte0 0x${Integer.toHexString(b0)}" }
            val b1 = recvExact(1, recvRaw)[0].toInt() and 0xFF
            val masked = (b1 and 0x80) != 0
            var len = (b1 and 0x7F).toLong()
            when (len) {
                126L -> { val e = recvExact(2, recvRaw); len = ((e[0].toInt() and 0xFF).toLong() shl 8) or (e[1].toInt() and 0xFF).toLong() }
                127L -> { val e = recvExact(8, recvRaw); len = 0L; for (i in 0 until 8) len = (len shl 8) or (e[i].toInt() and 0xFF).toLong() }
            }
            require(len in 0..WS_MAX_READ_PAYLOAD) { "obfs ws: frame payload too large ($len)" }
            val mask = if (masked) recvExact(4, recvRaw) else null
            val payload = recvExact(len.toInt(), recvRaw)
            if (mask != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor mask[i % 4].toInt()).toByte()
            pending.write(payload)
        }
    }

    companion object {
        private const val NONCE_LEN = 12
        // F3 caps: writer emits <=16384-byte payloads; reader accepts the larger
        // 8-byte form defensively but bounds it to 1 MiB to prevent OOM.
        private const val WS_MAX_PAYLOAD = 16384
        private const val WS_MAX_READ_PAYLOAD = 1L shl 20
        // F2 caps (bound memory): jc<=128 junk records, each <=1400 bytes.
        private const val AWG_JC_CAP = 128
        private const val AWG_LEN_CAP = 1400

        /** Build one WS binary frame for a raw payload (used by junk in WS mode and
         *  by the F3 masking test vector). Client-side => MASK=1 with [mask]. */
        fun wsBinaryFrame(payload: ByteArray, mask: ByteArray): ByteArray {
            val out = java.io.ByteArrayOutputStream(payload.size + 8)
            out.write(0x82)
            writeLenPrefix(out, payload.size, masked = true)
            out.write(mask)
            for (i in payload.indices) out.write((payload[i].toInt() xor mask[i % 4].toInt()) and 0xFF)
            return out.toByteArray()
        }

        /** Write byte1 + optional extended length. `masked` sets the MASK bit. */
        private fun writeLenPrefix(out: java.io.ByteArrayOutputStream, len: Int, masked: Boolean) {
            val maskBit = if (masked) 0x80 else 0x00
            when {
                len <= 125 -> out.write(maskBit or len)
                len <= 65535 -> { out.write(maskBit or 126); out.write((len ushr 8) and 0xFF); out.write(len and 0xFF) }
                else -> {
                    out.write(maskBit or 127)
                    for (sh in intArrayOf(56, 48, 40, 32, 24, 16, 8, 0)) out.write(((len.toLong() ushr sh) and 0xFF).toInt())
                }
            }
        }

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
            recvRaw: (Int) -> ByteArray,
            // F2 AmneziaWG junk. jc=0 (default) => zero extra bytes => byte-identical
            // to the pre-F2 wire. Both ends MUST share the same jc; jmin/jmax are
            // sender-only. Caps enforced here (jc<=128, len<=1400) to bound memory.
            awgJc: Int = 0,
            awgJmin: Int = 40,
            awgJmax: Int = 300
        ): ObfsStream {
            if (fronting) {
                sendRaw(buildWsRequest())
                val head = readHttpHead(recvRaw)
                require(head.startsWith("HTTP/1.1 101")) {
                    "obfs ws: server did not switch protocols"
                }
            }
            // F3: with WS fronting the ENTIRE post-101 stream (junk + nonce + data)
            // is carried as binary frames. Build the framers now so junk and the
            // nonce exchange below already go through them.
            val wsWriter = if (fronting) WsFrameWriter() else null
            val wsReader = if (fronting) WsFrameReader() else null

            // F2: junk records go AFTER the front handshake (or TCP connect) and
            // BEFORE the nonce exchange. Sender emits jc records; receiver reads and
            // discards exactly jc records. Enforce caps.
            val jc = awgJc.coerceIn(0, AWG_JC_CAP)
            if (jc > 0) {
                val jmin = awgJmin.coerceIn(1, AWG_LEN_CAP)
                val jmax = awgJmax.coerceIn(jmin, AWG_LEN_CAP)
                emitJunk(jc, jmin, jmax, fronting, wsWriter, sendRaw)
                discardJunk(jc, fronting, wsReader, recvRaw)
            }

            // Nonce exchange. In WS mode both the outbound and inbound nonce are a
            // binary frame; in raw mode they are the bare 12 bytes as before.
            val local = ByteArray(NONCE_LEN).also { java.security.SecureRandom().nextBytes(it) }
            if (wsWriter != null) sendRaw(wsWriter.frame(local)) else sendRaw(local)
            val peer = if (wsReader != null) wsReader.read(NONCE_LEN, recvRaw) else recvRaw(NONCE_LEN)
            return ObfsStream(
                writeKs = ChaCha20Keystream(key, local),
                readKs = ChaCha20Keystream(key, peer),
                wsWriter = wsWriter,
                wsReader = wsReader
            )
        }

        /** F2: send [jc] junk records, each of a uniform-random length in
         *  [jmin,jmax]. Non-WS wire: [u16 BE len][len random bytes]. WS wire: one
         *  binary frame per junk record whose payload is len random bytes. */
        private fun emitJunk(
            jc: Int, jmin: Int, jmax: Int, fronting: Boolean,
            wsWriter: WsFrameWriter?, sendRaw: (ByteArray) -> Unit
        ) {
            val rnd = java.security.SecureRandom()
            repeat(jc) {
                val len = jmin + (if (jmax > jmin) rnd.nextInt(jmax - jmin + 1) else 0)
                val body = ByteArray(len).also { rnd.nextBytes(it) }
                if (fronting && wsWriter != null) {
                    sendRaw(wsWriter.frame(body))
                } else {
                    val rec = ByteArray(2 + len)
                    rec[0] = ((len ushr 8) and 0xFF).toByte(); rec[1] = (len and 0xFF).toByte()
                    System.arraycopy(body, 0, rec, 2, len)
                    sendRaw(rec)
                }
            }
        }

        /** F2: read and DISCARD exactly [jc] junk records. Non-WS: [u16 len][bytes].
         *  WS: [jc] binary frames (the reframer consumes each whole frame). */
        private fun discardJunk(
            jc: Int, fronting: Boolean,
            wsReader: WsFrameReader?, recvRaw: (Int) -> ByteArray
        ) {
            repeat(jc) {
                if (fronting && wsReader != null) {
                    // One junk record == one WS frame == one reframer chunk. Consume
                    // exactly its payload and no more.
                    wsReader.discardOneFrame(recvRaw)
                } else {
                    val hdr = recvExactRaw(2, recvRaw)
                    val len = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
                    require(len <= AWG_LEN_CAP) { "obfs awg: junk record too large ($len)" }
                    recvExactRaw(len, recvRaw)
                }
            }
        }

        /** Read exactly [size] raw bytes (recvRaw may return short reads). */
        private fun recvExactRaw(size: Int, recvRaw: (Int) -> ByteArray): ByteArray {
            val buf = ByteArray(size)
            var off = 0
            while (off < size) {
                val chunk = recvRaw(size - off)
                if (chunk.isEmpty()) throw java.io.IOException("obfs: connection closed")
                System.arraycopy(chunk, 0, buf, off, chunk.size); off += chunk.size
            }
            return buf
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
