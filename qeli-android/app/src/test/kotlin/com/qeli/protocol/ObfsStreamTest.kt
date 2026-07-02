package com.qeli.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wire-parity tests for the obfs transport's F2 (AmneziaWG junk) and F3
 * (WebSocket binary framing) behaviour. The F3 masking vector is the SHARED
 * cross-language test vector — the Rust, C#, and Kotlin implementations MUST all
 * emit exactly these bytes so the three ends provably agree byte-for-byte.
 */
class ObfsStreamTest {

    // ── F3: mandatory cross-language WebSocket masking vector ────────────────
    //
    // Post-cipher bytes [0x01,0x02,0x03] + mask [0xAA,0xBB,0xCC,0xDD] MUST frame
    // to exactly [0x82,0x83,0xAA,0xBB,0xCC,0xDD,0xAB,0xB9,0xCF].
    //   0x01^0xAA=0xAB, 0x02^0xBB=0xB9, 0x03^0xCC=0xCF.
    @Test
    fun f3_maskingVector_isExact() {
        val cipher = byteArrayOf(0x01, 0x02, 0x03)
        val mask = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte())
        val frame = ObfsStream.wsBinaryFrame(cipher, mask)
        val expected = byteArrayOf(
            0x82.toByte(), 0x83.toByte(),
            0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte(),
            0xAB.toByte(), 0xB9.toByte(), 0xCF.toByte()
        )
        assertArrayEquals(expected, frame)
    }

    // ── F3: length-prefix forms + stateful reframer round-trip ───────────────

    @Test
    fun f3_writer_reader_roundtrip_acrossFrameAndReadBoundaries() {
        // Payload that spans multiple 16384-byte frames AND the 126/u16 length form.
        val payload = ByteArray(40000) { ((it * 31 + 7) and 0xFF).toByte() }
        val writer = ObfsStream.WsFrameWriter()
        val wire = writer.frame(payload)

        // byte0 must be 0x82 and the first frame must use the 126 (u16) length form
        // (payload chunk == 16384 > 125).
        assertEquals(0x82, wire[0].toInt() and 0xFF)
        assertEquals(0x80 or 126, wire[1].toInt() and 0xFF)  // MASK=1, len7=126

        // Feed the wire back through the STATEFUL reader in awkward chunks (split
        // headers, coalesced tails) to prove the reframer buffers correctly.
        val src = ChunkedSource(wire, chunkSizes = intArrayOf(1, 2, 3, 5, 7, 11, 4096))
        val reader = ObfsStream.WsFrameReader()
        // The reader returns the UNMASKED cipherbytes; masked writer XORs on write,
        // reader XORs back on read, so we recover the original payload.
        val out = reader.read(payload.size) { want -> src.recv(want) }
        assertArrayEquals(payload, out)
    }

    @Test
    fun f3_writer_smallPayload_usesInlineLength() {
        val writer = ObfsStream.WsFrameWriter()
        val wire = writer.frame(ByteArray(3) { 0x11 })
        // 0x82, then MASK=1|len7=3, then 4 mask bytes, then 3 payload = 9 bytes.
        assertEquals(9, wire.size)
        assertEquals(0x82, wire[0].toInt() and 0xFF)
        assertEquals(0x80 or 3, wire[1].toInt() and 0xFF)
    }

    // ── F2: junk emit/discard round-trip in NON-WS (raw) fronting ────────────
    //
    // The [u16 len][bytes] junk records must be emitted before the nonce and read
    // back off. We drive a client connect() against a mirror peer over a pipe.

    @Test
    fun f2_nonWs_junk_roundtrip_establishesKeystream() {
        val key = ObfsStream.deriveKey("unit-test-psk")
        val client = Pipe()
        val peer = PeerPipe(client)
        val threadB = Thread { peer.serverHandshake(jc = 4) }
        threadB.start()
        val sA = ObfsStream.connect(
            key, fronting = false,
            sendRaw = { client.send(it) }, recvRaw = { client.recv(it) },
            awgJc = 4, awgJmin = 40, awgJmax = 300
        )
        threadB.join(5000)
        assertTrue("handshake completed", peer.completed)
        assertTrue(sA.transformWrite(ByteArray(8)).size == 8)
        assertTrue("raw obfs is not WebSocket-framed", !sA.isWebSocket)
    }

    // ── Regression: jc=0 / fronting=none must be byte-identical to legacy ────

    @Test
    fun jc0_nonWs_producesZeroExtraBytes() {
        val key = ObfsStream.deriveKey("unit-test-psk")
        val sent = mutableListOf<ByteArray>()
        // With jc=0 and fronting=none, connect() must send EXACTLY one thing before
        // reading: the bare 12-byte nonce — no junk, no WS request, no framing.
        val peerNonce = ByteArray(12) { 0x5A }
        val recvQueue = ArrayDeque<ByteArray>().apply { add(peerNonce) }
        val s = ObfsStream.connect(
            key, fronting = false,
            sendRaw = { sent.add(it.copyOf()) },
            recvRaw = { n -> recvQueue.removeFirst().also { require(it.size == n) } },
            awgJc = 0
        )
        assertEquals("exactly one raw send (the nonce)", 1, sent.size)
        assertEquals("nonce is 12 bytes, no junk prefix", 12, sent[0].size)
        assertTrue(s.transformWrite(ByteArray(4)).size == 4)
        assertTrue("jc=0/fronting=none is not WS-framed", !s.isWebSocket)
    }

    // ── helpers ────────────────────────────────────────────────

    /** Feeds a fixed buffer out in a cycling pattern of small chunk sizes to force
     *  the reframer to handle split headers and coalesced tails. */
    private class ChunkedSource(private val data: ByteArray, private val chunkSizes: IntArray) {
        private var off = 0
        private var idx = 0
        fun recv(max: Int): ByteArray {
            if (off >= data.size) return ByteArray(0)
            val want = minOf(max, chunkSizes[idx % chunkSizes.size], data.size - off)
            idx++
            val out = data.copyOfRange(off, off + want)
            off += want
            return out
        }
    }

    /** Minimal in-memory duplex: client half. */
    private class Pipe {
        val aToB = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val bToA = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        private var buf = ByteArray(0)
        private var pos = 0
        fun send(b: ByteArray) { aToB.put(b.copyOf()) }
        fun recv(n: Int): ByteArray {
            while (pos + n > buf.size) {
                val more = bToA.poll(5, java.util.concurrent.TimeUnit.SECONDS)
                    ?: throw java.io.IOException("pipe recv timeout")
                buf = buf.copyOfRange(pos, buf.size) + more; pos = 0
            }
            return buf.copyOfRange(pos, pos + n).also { pos += n }
        }
    }

    /** The peer/server side: discards jc [u16 len][bytes] junk + the nonce, then
     *  replies with its own 12-byte nonce. */
    private class PeerPipe(private val client: Pipe) {
        @Volatile var completed = false
        private var buf = ByteArray(0)
        private var pos = 0
        private fun recv(n: Int): ByteArray {
            while (pos + n > buf.size) {
                val more = client.aToB.poll(5, java.util.concurrent.TimeUnit.SECONDS)
                    ?: throw java.io.IOException("peer recv timeout")
                buf = buf.copyOfRange(pos, buf.size) + more; pos = 0
            }
            return buf.copyOfRange(pos, pos + n).also { pos += n }
        }
        fun serverHandshake(jc: Int) {
            // receive the client's jc junk records
            repeat(jc) {
                val hdr = recv(2)
                val len = ((hdr[0].toInt() and 0xFF) shl 8) or (hdr[1].toInt() and 0xFF)
                recv(len)
            }
            // send our OWN jc junk records back — junk is BIDIRECTIONAL, so the
            // client's connect() runs discardJunk(jc) here waiting for exactly these
            // (mirrors the Rust accept(): recv jc, then send jc).
            repeat(jc) {
                val len = 40 + (it * 13) % 261 // any length in [40, 300]
                val body = ByteArray(len) { i -> (i and 0xFF).toByte() }
                client.bToA.put(byteArrayOf(((len ushr 8) and 0xFF).toByte(), (len and 0xFF).toByte()) + body)
            }
            recv(12) // client nonce
            client.bToA.put(ByteArray(12) { 0x33 }) // our nonce
            completed = true
        }
    }
}
