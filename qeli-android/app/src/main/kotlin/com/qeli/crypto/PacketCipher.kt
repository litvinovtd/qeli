package com.qeli.crypto

import android.util.Log
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD wrapper for Android/Conscrypt.
 *
 * Android Conscrypt supports "ChaCha20-Poly1305" (since API 28).
 * The transformation must NOT include mode/padding: no "/NONE/NO_PADDING".
 * Nonce: 12 bytes via IvParameterSpec.
 * Tag: 16 bytes, appended to ciphertext by Conscrypt automatically.
 */
class PacketCipher(private val key: ByteArray) {

    private val keySpec = SecretKeySpec(key, "ChaCha20-Poly1305")

    companion object {
        const val NONCE_SIZE = 12
        const val TAG_SIZE   = 16

        // Try algorithm names in order; Conscrypt on API 28+ uses the first one.
        private val ALGO = pickAlgorithm()

        private fun pickAlgorithm(): String {
            for (name in listOf("ChaCha20-Poly1305", "CHACHA20-POLY1305")) {
                try {
                    Cipher.getInstance(name)
                    Log.d("PacketCipher", "Using cipher algorithm: $name")
                    return name
                } catch (_: Exception) {}
            }
            throw RuntimeException("ChaCha20-Poly1305 not supported on this device")
        }
    }

    /**
     * Encrypt [plaintext] with [nonce] (12 bytes).
     * Returns ciphertext + 16-byte authentication tag.
     */
    fun encrypt(plaintext: ByteArray, nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes, got ${nonce.size}" }
        // Create a fresh Cipher instance per operation — Conscrypt is not always thread-safe
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(nonce))
        return cipher.doFinal(plaintext)
    }

    /**
     * Decrypt [ciphertextWithTag] (ciphertext + 16-byte tag) with [nonce].
     * Returns plaintext.
     */
    fun decrypt(ciphertextWithTag: ByteArray, nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes, got ${nonce.size}" }
        require(ciphertextWithTag.size >= TAG_SIZE) {
            "Ciphertext too short: ${ciphertextWithTag.size} (need at least $TAG_SIZE for tag)"
        }
        val cipher = Cipher.getInstance(ALGO)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(nonce))
        return cipher.doFinal(ciphertextWithTag)
    }
}
