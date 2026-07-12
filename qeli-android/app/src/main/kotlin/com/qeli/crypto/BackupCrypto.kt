package com.qeli.crypto

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Optional passphrase encryption for the profile-backup file. Without a passphrase the
 * backup stays plaintext JSON (legacy behaviour); with one, the JSON is sealed so an
 * exported file no longer leaks credentials (passwords / obfs_key) at rest.
 *
 * Container: a small line-based envelope beginning with [MAGIC], so [isEncrypted] can tell
 * an encrypted backup apart from a legacy plaintext one. The key is derived with
 * PBKDF2-HMAC-SHA256 and the payload sealed with AES-256-GCM (authenticated), so a wrong
 * passphrase fails cleanly (GCM tag mismatch) rather than yielding garbage. Deliberately
 * uses only `java.*`/`javax.crypto` (no `android.*`) so it is unit-testable on the JVM.
 */
object BackupCrypto {
    const val MAGIC = "QELI-ENC-1"
    private const val ITER = 210_000
    private const val KEY_BITS = 256
    private const val SALT_LEN = 16
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    /** Seal [plaintext] under [passphrase] into the line-based envelope. */
    fun encrypt(plaintext: String, passphrase: String): ByteArray {
        require(passphrase.isNotEmpty()) { "passphrase required" }
        val rng = SecureRandom()
        val salt = ByteArray(SALT_LEN).also { rng.nextBytes(it) }
        val iv = ByteArray(IV_LEN).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(passphrase, salt, ITER), GCMParameterSpec(TAG_BITS, iv))
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return listOf(MAGIC, ITER.toString(), b64(salt), b64(iv), b64(ct))
            .joinToString("\n")
            .toByteArray(Charsets.UTF_8)
    }

    /** True if [bytes] is an encrypted envelope (vs a legacy plaintext backup). */
    fun isEncrypted(bytes: ByteArray): Boolean {
        val n = MAGIC.toByteArray(Charsets.UTF_8).size
        return bytes.size >= n && String(bytes, 0, n, Charsets.UTF_8) == MAGIC
    }

    /** Open an encrypted envelope; throws on a wrong passphrase (GCM tag mismatch). */
    fun decrypt(bytes: ByteArray, passphrase: String): String {
        val lines = String(bytes, Charsets.UTF_8).split("\n")
        require(lines.size >= 5 && lines[0] == MAGIC) { "not an encrypted qeli backup" }
        val iter = lines[1].toIntOrNull() ?: ITER
        val salt = unb64(lines[2])
        val iv = unb64(lines[3])
        val ct = unb64(lines[4])
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(passphrase, salt, iter), GCMParameterSpec(TAG_BITS, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    private fun key(passphrase: String, salt: ByteArray, iter: Int): SecretKeySpec {
        val spec = PBEKeySpec(passphrase.toCharArray(), salt, iter, KEY_BITS)
        val raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s.trim())
}
