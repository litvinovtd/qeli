package com.qeli.protocol

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

object TlsHandshake {

    init {
        // Load the Rust core for the shared fake-tls ClientHello (nativeFakeClientHello);
        // tolerate absence so the managed fallback still works if the lib is missing.
        try { System.loadLibrary("qeli") } catch (_: Throwable) {}
    }

    private const val CLIENT_HELLO: Byte = 0x01
    private const val SERVER_HELLO: Byte = 0x02
    private val random = SecureRandom()

    /** ML-KEM-768 ciphertext length (FIPS 203): the server's hybrid key_share PQ part. */
    private const val MLKEM_CT_LEN = 1088

    /**
     * Fingerprint-only ClientHello (classic x25519 key_share). Kept for tests and any
     * non-PQ caller; the live fake-tls / obfs / UDP paths use [buildClientHelloPq]
     * because the server now requires the X25519MLKEM768 share for the hybrid tunnel.
     */
    fun buildClientHello(keyShare: ByteArray, sni: String = "www.cloudflare.com", padToMin: Int = 0): ByteArray =
        buildClientHelloInner(keyShare, null, sni, padToMin)

    /**
     * Hybrid post-quantum ClientHello: carries the real ML-KEM-768 encapsulation key
     * in an X25519MLKEM768 (0x11ec) key_share alongside the classic x25519 share, so
     * the server can encapsulate against it. Mirrors Rust `build_client_hello_pq`; the
     * caller keeps the matching [com.qeli.MlKem] handle to decapsulate the reply.
     */
    fun buildClientHelloPq(x25519Pub: ByteArray, mlKemEk: ByteArray, sni: String = "www.cloudflare.com", padToMin: Int = 0): ByteArray {
        // Prefer the shared Rust builder (libqeli.so) so every client emits the identical
        // fake-tls hello (GREASE / per-connection shuffle / ALPN); fall back to the managed
        // builder if the native lib/export is unavailable so the client never crashes.
        try {
            val hello = nativeFakeClientHello(x25519Pub, mlKemEk, sni, padToMin)
            if (hello != null && hello.isNotEmpty()) return hello
        } catch (_: Throwable) { /* native lib/export missing → managed builder */ }
        return buildClientHelloInner(x25519Pub, mlKemEk, sni, padToMin)
    }

    @JvmStatic
    private external fun nativeFakeClientHello(
        x25519Pub: ByteArray, mlKemEk: ByteArray, sni: String, padToMin: Int
    ): ByteArray?

    /**
     * Build a fake-TLS ClientHello record. [padToMin] inflates the record to at
     * least that many bytes via a TLS padding extension (RFC 7685); pass 1200 for
     * UDP (the server rejects shorter UDP initials), 0 for TCP. GREASE values
     * (RFC 8701) are included first/last for JA3 polymorphism. When [mlKemEk] is
     * non-null the key_share + supported_groups advertise X25519MLKEM768 (hybrid PQ).
     */
    private fun buildClientHelloInner(x25519Pub: ByteArray, mlKemEk: ByteArray?, sni: String, padToMin: Int): ByteArray {
        val pq = mlKemEk != null
        val sessionId = ByteArray(32).also { random.nextBytes(it) }
        val randomBytes = ByteArray(32).also { random.nextBytes(it) }
        val greaseFirst = greaseValue()
        val greaseLast = greaseValue()

        val extensions = ByteArrayOutputStream()
        buildGreaseExtension(extensions, greaseFirst)
        // SNI: normal host, or special tokens (browser dialing a bare IP). "" / "!" =
        // omit the extension; "~" = present but empty; "@" = empty server_name_list.
        when (sni) {
            "", "!" -> {}
            "~" -> buildEmptySniExtension(extensions)
            "@" -> buildEmptySniListExtension(extensions)
            else -> buildSniExtension(extensions, sni)
        }
        buildEmptyExtension(extensions, 0x0017) // extended_master_secret
        buildSupportedGroupsExtension(extensions, pq)
        if (pq) buildClientKeyShareExtensionPq(extensions, x25519Pub, mlKemEk!!)
        else buildClientKeyShareExtension(extensions, x25519Pub)
        buildPskKeyExchangeModesExtension(extensions)
        buildSupportedVersionsExtension(extensions)
        buildSignatureAlgorithmsExtension(extensions)
        buildCompressCertificateExtension(extensions)
        buildGreaseExtension(extensions, greaseLast)

        // RFC 7685 padding: inflate the record to >= padToMin bytes.
        // record size = 9 (record+handshake headers) + 79 (fixed body) + extLen.
        val projected = 88 + extensions.size()
        if (padToMin > projected + 4) {
            val padData = padToMin - projected - 4 // 4 = padding ext header
            extensions.write(0x00); extensions.write(0x15) // padding extension type
            extensions.writeShort(padData)
            extensions.write(ByteArray(padData))
        }

        val body = ByteArrayOutputStream().apply {
            writeShort(0x0303)
            write(randomBytes)
            write(sessionId.size)
            write(sessionId)
            writeShort(6)
            writeShort(0x1301) // TLS_AES_128_GCM_SHA256
            writeShort(0x1302) // TLS_AES_256_GCM_SHA384
            writeShort(0x1303) // TLS_CHACHA20_POLY1305_SHA256
            write(1)
            write(0x00)
            writeShort(extensions.size())
            write(extensions.toByteArray())
        }.toByteArray()

        val rawHandshake = ByteArrayOutputStream().apply {
            write(CLIENT_HELLO.toInt())
            writeInt24(body.size)
            write(body)
        }.toByteArray()

        return ByteArrayOutputStream().apply {
            write(0x16)
            write(0x03); write(0x03)
            writeShort(rawHandshake.size)
            write(rawHandshake)
        }.toByteArray()
    }

    /** A random GREASE value (RFC 8701): 0x0A0A, 0x1A1A, … 0xFAFA. */
    private fun greaseValue(): Int {
        val b = (random.nextInt(16) shl 4) or 0x0A
        return (b shl 8) or b
    }

    private fun buildGreaseExtension(buf: ByteArrayOutputStream, value: Int) {
        buf.writeShort(value)
        buf.write(0x00); buf.write(0x00) // zero-length data
    }

    fun parseServerHello(data: ByteArray): ByteArray? {
        if (data.size < 5 || data[0] != SERVER_HELLO) return null
        val bodyLen = readInt24(data, 1)
        if (bodyLen < 43 || data.size < 4 + bodyLen) return null
        var pos = 4

        pos += 2 // version
        pos += 32 // random
        val sessionIdLen = readByte(data, pos); pos += 1 + sessionIdLen
        pos += 2 // cipher suite
        pos += 1 // compression
        if (pos + 2 > data.size) return null
        val extLen = readShort(data, pos); pos += 2
        if (pos + extLen > data.size) return null
        val extEnd = pos + extLen

        while (pos + 4 <= extEnd) {
            val extType = readShort(data, pos)
            val extDataLen = readShort(data, pos + 2); pos += 4
            if (pos + extDataLen > extEnd) break
            if (extType == 0x0033) {
                if (extDataLen < 6) return null
                val group = readShort(data, pos + 2)
                val keyLen = readShort(data, pos + 4)
                if (group == 0x001d && keyLen >= 32) {
                    return data.copyOfRange(pos + 6, pos + 6 + 32)
                }
            }
            pos += extDataLen
        }
        return null
    }

    /** Hybrid ServerHello key_share: the ML-KEM ciphertext + the server's x25519 public. */
    data class PqServerHello(val ciphertext: ByteArray, val serverX25519: ByteArray)

    /**
     * Parse a hybrid ServerHello (handshake-message bytes, starting 0x02), returning
     * the ML-KEM-768 ciphertext (1088) and the server's x25519 public (32) from its
     * X25519MLKEM768 (0x11ec) key_share. Mirrors Rust `parse_server_hello_pq`; null if
     * the hybrid share is absent or malformed.
     */
    fun parseServerHelloPq(data: ByteArray): PqServerHello? {
        if (data.size < 5 || data[0] != SERVER_HELLO) return null
        val bodyLen = readInt24(data, 1)
        if (bodyLen < 43 || data.size < 4 + bodyLen) return null
        var pos = 4

        pos += 2 // version
        pos += 32 // random
        val sessionIdLen = readByte(data, pos); pos += 1 + sessionIdLen
        pos += 2 // cipher suite
        pos += 1 // compression
        if (pos + 2 > data.size) return null
        val extLen = readShort(data, pos); pos += 2
        if (pos + extLen > data.size) return null
        val extEnd = pos + extLen

        while (pos + 4 <= extEnd) {
            val extType = readShort(data, pos)
            val extDataLen = readShort(data, pos + 2); pos += 4
            if (pos + extDataLen > extEnd) break
            if (extType == 0x0033) {
                if (extDataLen < 6) return null
                val group = readShort(data, pos + 2)
                val keyLen = readShort(data, pos + 4)
                // server_share length(2) skipped via +2; value = ct(1088) ‖ x25519(32).
                if (group == 0x11EC && keyLen == MLKEM_CT_LEN + 32 && pos + 6 + keyLen <= extEnd) {
                    val ct = data.copyOfRange(pos + 6, pos + 6 + MLKEM_CT_LEN)
                    val sx = data.copyOfRange(pos + 6 + MLKEM_CT_LEN, pos + 6 + MLKEM_CT_LEN + 32)
                    return PqServerHello(ct, sx)
                }
            }
            pos += extDataLen
        }
        return null
    }

    private fun buildSniExtension(buf: ByteArrayOutputStream, sni: String) {
        val sniBytes = sni.toByteArray()
        // One ServerName = name_type(1) + host_name<u16>. RFC 6066 wraps a
        // server_name_list<u16> around it; a real browser sends exactly one entry.
        val nameBytes = ByteArrayOutputStream().apply {
            write(0x00) // hostname type
            writeShort(sniBytes.size)
            write(sniBytes)
        }.toByteArray()
        buf.write(0x00); buf.write(0x00) // SNI extension type 0x0000
        buf.writeShort(2 + nameBytes.size) // extension_data length = list_len(2) + entry
        // server_name_list length. This 2-byte prefix was MISSING: without it a parser
        // reads the first two bytes as a zero-length list — a spurious empty leading
        // ServerName (a DPI fingerprint). Matches the Rust client's build_sni_extension.
        buf.writeShort(nameBytes.size)
        buf.write(nameBytes)
    }

    /** SNI extension present but empty (zero-length data) — sni = ~. */
    private fun buildEmptySniExtension(buf: ByteArrayOutputStream) {
        buf.write(0x00); buf.write(0x00) // SNI extension type
        buf.write(0x00); buf.write(0x00) // extension data length 0
    }

    /** SNI extension with an empty server_name_list (no entries) — sni = @. */
    private fun buildEmptySniListExtension(buf: ByteArrayOutputStream) {
        buf.write(0x00); buf.write(0x00) // SNI extension type
        buf.write(0x00); buf.write(0x02) // extension data length 2
        buf.write(0x00); buf.write(0x00) // server_name_list length 0
    }

    private fun buildClientKeyShareExtension(buf: ByteArrayOutputStream, keyShare: ByteArray) {
        val entry = ByteArrayOutputStream().apply {
            writeShort(0x001d)
            writeShort(keyShare.size)
            write(keyShare)
        }.toByteArray()
        val list = ByteArrayOutputStream().apply {
            writeShort(entry.size)
            write(entry)
        }.toByteArray()
        buf.write(0x00); buf.write(0x33) // key_share extension type
        buf.writeShort(list.size)
        buf.write(list)
    }

    /**
     * Hybrid key_share: two entries, PQ first like Chrome — X25519MLKEM768 (value =
     * ML-KEM ek(1184) ‖ x25519(32)) then classic x25519. Mirrors Rust
     * `build_key_share_extension`.
     */
    private fun buildClientKeyShareExtensionPq(buf: ByteArrayOutputStream, x25519Pub: ByteArray, mlKemEk: ByteArray) {
        val pqValue = mlKemEk + x25519Pub // ek ‖ x25519
        val shares = ByteArrayOutputStream().apply {
            writeShort(0x11EC)        // X25519MLKEM768
            writeShort(pqValue.size)  // 1216
            write(pqValue)
            writeShort(0x001D)        // x25519
            writeShort(x25519Pub.size)
            write(x25519Pub)
        }.toByteArray()
        val list = ByteArrayOutputStream().apply {
            writeShort(shares.size)   // client_shares_length
            write(shares)
        }.toByteArray()
        buf.write(0x00); buf.write(0x33) // key_share extension type
        buf.writeShort(list.size)
        buf.write(list)
    }

    private fun buildSupportedVersionsExtension(buf: ByteArrayOutputStream) {
        buf.write(0x00); buf.write(0x2B) // supported_versions
        buf.write(0x00); buf.write(0x03) // extension data length: 3
        buf.write(0x02) // versions list length: 2
        buf.write(0x03); buf.write(0x04) // TLS 1.3 (0x0304)
    }

    private fun buildPskKeyExchangeModesExtension(buf: ByteArrayOutputStream) {
        buf.write(0x00); buf.write(0x2D) // psk_key_exchange_modes
        buf.write(0x00); buf.write(0x02) // extension data length: 2
        buf.write(0x01) // KE modes length: 1
        buf.write(0x01) // PSK with (EC)DHE
    }

    private fun buildSignatureAlgorithmsExtension(buf: ByteArrayOutputStream) {
        val algorithms = byteArrayOf(
            0x04, 0x03, // rsa_pss_rsae_sha256
            0x05, 0x03, // rsa_pss_rsae_sha384
            0x06, 0x03, // rsa_pss_rsae_sha512
            0x08, 0x04, // rsa_pss_rsae_sha256 (RSA-PSS)
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x02, 0x01  // rsa_pkcs1_sha1
        )
        buf.write(0x00); buf.write(0x0D) // signature_algorithms
        buf.writeShort(algorithms.size + 2) // extension_data length = list_length(2) + algorithms
        buf.writeShort(algorithms.size)     // supported_signature_algorithms length
        buf.write(algorithms)
    }

    private fun buildSupportedGroupsExtension(buf: ByteArrayOutputStream, pq: Boolean) {
        // PQ first like current Chrome when the hybrid share is offered.
        val groups = if (pq)
            byteArrayOf(0x11, 0xEC.toByte(), 0x00, 0x1D, 0x00, 0x17) // X25519MLKEM768, x25519, secp256r1
        else
            byteArrayOf(0x00, 0x1D, 0x00, 0x17)                      // x25519, secp256r1
        buf.write(0x00); buf.write(0x0A) // supported_groups
        buf.writeShort(groups.size + 2) // extension_data length = list_length(2) + groups
        buf.writeShort(groups.size)     // named_group_list length
        buf.write(groups)
    }

    private fun buildCompressCertificateExtension(buf: ByteArrayOutputStream) {
        buf.write(0x00); buf.write(0x1B) // compress_certificate
        buf.write(0x00); buf.write(0x03) // extension data length: 3
        buf.write(0x02) // algorithms list length: 2
        buf.write(0x00); buf.write(0x02) // brotli
    }

    private fun buildEmptyExtension(buf: ByteArrayOutputStream, extType: Int) {
        buf.write((extType shr 8) and 0xFF)
        buf.write(extType and 0xFF)
        buf.write(0x00); buf.write(0x00) // zero-length data
    }

    fun isChangeCipherSpec(record: ByteArray): Boolean {
        return record.size == 6 &&
                record[0] == 0x14.toByte() &&
                record[1] == 0x03.toByte() &&
                record[2] == 0x03.toByte() &&
                record[3] == 0x00.toByte() &&
                record[4] == 0x01.toByte() &&
                record[5] == 0x01.toByte()
    }

    private fun readShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private fun readInt24(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 16) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                (data[offset + 2].toInt() and 0xFF)
    }

    private fun readByte(data: ByteArray, offset: Int): Int {
        return data[offset].toInt() and 0xFF
    }

    private fun ByteArrayOutputStream.writeShort(value: Int) {
        write((value shr 8) and 0xFF)
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.writeInt24(value: Int) {
        write((value shr 16) and 0xFF)
        write((value shr 8) and 0xFF)
        write(value and 0xFF)
    }
}