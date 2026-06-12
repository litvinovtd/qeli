package com.qeli.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object KeyDerivation {

    private const val HMAC_ALGO = "HmacSHA256"

    /**
     * SHA-256 over the in-order concatenation of the given handshake records.
     * Mirrors crypto/auth.rs::handshake_transcript_hash. The TCP path passes
     * [clientHello, serverHelloRecord, certRecord, finishedRecord]; both sides
     * hash the exact bytes they sent/received so the channel binding holds
     * regardless of each peer's internal record layout.
     */
    fun handshakeTranscript(records: List<ByteArray>): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        records.forEach { md.update(it) }
        return md.digest()
    }

    /**
     * Server-authentication proof (v2, channel-bound). Mirrors
     * crypto/exchange.rs::compute_auth_proof:
     * PRK   = HMAC(salt=staticShared, ikm=ephemeralShared);
     * proof = HKDF-Expand(PRK, "vpn-server-auth-proof-v2" || transcriptHash, 32).
     * The transcript hash binds the proof to the fake-TLS handshake
     * (ClientHello/ServerHello/Certificate/Finished): any in-flight tampering
     * changes the hash and breaks verification. The v2 info string is a
     * wire-format break from the unbound v1 proof — the server now always
     * binds, so the client must too.
     */
    fun deriveAuthProof(staticShared: ByteArray, ephemeralShared: ByteArray, transcriptHash: ByteArray): ByteArray {
        val prk = hmac(key = staticShared, data = ephemeralShared)
        val info = "vpn-server-auth-proof-v2".toByteArray(Charsets.UTF_8) + transcriptHash
        return expand(prk, info, 32)
    }

    /**
     * Client→server key proof. Mirrors crypto/auth.rs::compute_client_key_proof:
     * PRK = HMAC(salt=staticShared, ikm=ephemeralShared);
     * proof = HKDF-Expand(PRK, "vpn-client-key-proof-v1" || transcriptHash, 32).
     * Only a client that has the server's static public key pinned can compute it,
     * letting a server with require_client_key_proof reject unpinned clients.
     */
    fun deriveClientKeyProof(staticShared: ByteArray, ephemeralShared: ByteArray, transcriptHash: ByteArray): ByteArray {
        val prk = hmac(key = staticShared, data = ephemeralShared)
        val info = "vpn-client-key-proof-v1".toByteArray(Charsets.UTF_8) + transcriptHash
        return expand(prk, info, 32)
    }

    fun deriveKeys(
        sharedSecret: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val salt = "qeli-key-derivation-v1".toByteArray(Charsets.UTF_8)
        val prk = hmac(salt, sharedSecret)

        val serverToClient = expand(prk, "server-to-client-enc-key".toByteArray(), 32)
        val clientToServer = expand(prk, "client-to-server-enc-key".toByteArray(), 32)
        return Pair(serverToClient, clientToServer)
    }

    /**
     * Hybrid post-quantum key schedule: the directional keys depend on BOTH the
     * classic X25519 shared secret AND the ML-KEM-768 shared secret, concatenated as
     * the HKDF IKM (`x25519 ‖ mlkem`, 64 bytes) under a distinct v2 salt. Mirrors Rust
     * `crypto::derive::derive_keys_hybrid` byte-for-byte — the order and salt are
     * wire-format, so a hybrid peer cannot interop with a classic one (no silent PQ
     * downgrade). Used by the fake-tls / obfs / UDP modes; `plain` stays on
     * [deriveKeys].
     */
    fun deriveKeysHybrid(
        x25519Shared: ByteArray, mlkemShared: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val salt = "qeli-key-derivation-v2-hybrid".toByteArray(Charsets.UTF_8)
        val ikm = x25519Shared + mlkemShared // x25519 first, then ML-KEM
        val prk = hmac(salt, ikm)

        val serverToClient = expand(prk, "server-to-client-enc-key".toByteArray(), 32)
        val clientToServer = expand(prk, "client-to-server-enc-key".toByteArray(), 32)
        return Pair(serverToClient, clientToServer)
    }

    /** [deriveKeys] with the static-ephemeral DH `es` folded into the IKM (`ee ‖ es`)
     *  under a distinct salt, binding the keys to the server identity (H-1). Mirrors
     *  Rust `derive_keys_bound`. Enabled by `bind_static_to_session`. */
    fun deriveKeysBound(ee: ByteArray, es: ByteArray): Pair<ByteArray, ByteArray> {
        val salt = "qeli-key-derivation-v1-static-bound".toByteArray(Charsets.UTF_8)
        val prk = hmac(salt, ee + es)
        val serverToClient = expand(prk, "server-to-client-enc-key".toByteArray(), 32)
        val clientToServer = expand(prk, "client-to-server-enc-key".toByteArray(), 32)
        return Pair(serverToClient, clientToServer)
    }

    /** [deriveKeysHybrid] with `es` folded in (IKM = `x25519 ‖ mlkem ‖ es`). Mirrors
     *  Rust `derive_keys_hybrid_bound`. See [deriveKeysBound]. */
    fun deriveKeysHybridBound(
        x25519Shared: ByteArray, mlkemShared: ByteArray, es: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val salt = "qeli-key-derivation-v2-hybrid-static-bound".toByteArray(Charsets.UTF_8)
        val ikm = x25519Shared + mlkemShared + es
        val prk = hmac(salt, ikm)
        val serverToClient = expand(prk, "server-to-client-enc-key".toByteArray(), 32)
        val clientToServer = expand(prk, "client-to-server-enc-key".toByteArray(), 32)
        return Pair(serverToClient, clientToServer)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(key, HMAC_ALGO))
        return mac.doFinal(data)
    }

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGO)
        mac.init(SecretKeySpec(prk, HMAC_ALGO))

        val result = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var blockIndex = 1

        while (offset < length) {
            mac.update(t)
            mac.update(info)
            mac.update(blockIndex.toByte())
            t = mac.doFinal()

            val copyLen = minOf(t.size, length - offset)
            System.arraycopy(t, 0, result, offset, copyLen)
            offset += copyLen
            blockIndex++
        }
        return result
    }

}
