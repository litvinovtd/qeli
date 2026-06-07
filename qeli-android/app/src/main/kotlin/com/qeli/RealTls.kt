package com.qeli

/**
 * Native REALITY TLS 1.3 handshake + record framing, backed by the Rust
 * `realtls` core via JNI (`src/protocol/realtls/jni.rs` → `libqeli.so`). This is
 * the genuine browser-grade TLS stack shared with the Rust/Windows clients, so
 * the Android client's on-wire fingerprint matches Chrome.
 *
 * Usage (the qeli tunnel runs *inside* this TLS session — nested):
 * ```
 * val tls = RealTls.create(serverPubKey, shortId, sni)
 * socket.write(tls.clientHello())
 * while (!tls.established()) {
 *     val out = tls.recv(socket.readSome())   // empty = need more
 *     if (out.isNotEmpty()) socket.write(out) // handshake's final flight
 * }
 * // application data:
 * socket.write(tls.seal(innerBytes))
 * val plain = tls.open(socket.readSome())     // concatenated inner stream
 * ...
 * tls.close()
 * ```
 */
class RealTls private constructor(private var handle: Long) {

    /** The ClientHello to send first (browser-grade, REALITY token in session_id). */
    fun clientHello(): ByteArray = nativeClientHello(handle) ?: ByteArray(0)

    /**
     * Feed inbound server bytes. Returns the bytes to send once the handshake
     * completes (ChangeCipherSpec + client Finished), or an empty array while
     * more input is needed. Throws on a protocol error.
     */
    fun recv(data: ByteArray): ByteArray =
        nativeRecv(handle, data) ?: error("realtls handshake error")

    fun established(): Boolean = nativeEstablished(handle)

    /** Frame application data as one TLS record (after the handshake). */
    fun seal(plaintext: ByteArray): ByteArray =
        nativeSeal(handle, plaintext) ?: error("realtls seal error")

    /** Decrypt inbound application bytes → concatenated plaintext (may be empty). */
    fun open(data: ByteArray): ByteArray =
        nativeOpen(handle, data) ?: error("realtls open error")

    fun close() {
        if (handle != 0L) {
            nativeFree(handle)
            handle = 0L
        }
    }

    companion object {
        init {
            System.loadLibrary("qeli")
        }

        /**
         * @param realityPub the server profile's pinned X25519 identity (32 bytes)
         * @param shortId    the REALITY short_id (8 bytes)
         * @param sni        the borrowed SNI (e.g. "www.microsoft.com")
         */
        fun create(realityPub: ByteArray, shortId: ByteArray, sni: String): RealTls {
            val h = nativeNew(realityPub, shortId, sni)
            check(h != 0L) { "RealTls native init failed" }
            return RealTls(h)
        }

        @JvmStatic
        private external fun nativeNew(realityPub: ByteArray, shortId: ByteArray, sni: String): Long
        @JvmStatic
        private external fun nativeClientHello(handle: Long): ByteArray?
        @JvmStatic
        private external fun nativeRecv(handle: Long, data: ByteArray): ByteArray?
        @JvmStatic
        private external fun nativeSeal(handle: Long, data: ByteArray): ByteArray?
        @JvmStatic
        private external fun nativeOpen(handle: Long, data: ByteArray): ByteArray?
        @JvmStatic
        private external fun nativeEstablished(handle: Long): Boolean
        @JvmStatic
        private external fun nativeFree(handle: Long)
    }
}
