package com.qeli.crypto

import java.nio.charset.CharacterCodingException
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class BackupCryptoTest {
    private val sample = """{"profiles":[{"name":"P","pass":"secret","obfs_key":"psk"}]}"""

    @Test fun roundTrip() {
        val enc = BackupCrypto.encrypt(sample, "correct horse")
        assertTrue("envelope must be tagged", BackupCrypto.isEncrypted(enc))
        assertEquals(sample, BackupCrypto.decrypt(enc, "correct horse"))
    }

    @Test fun wrongPassphraseFails() {
        val enc = BackupCrypto.encrypt(sample, "correct horse")
        assertThrows(AEADBadTagException::class.java) {
            BackupCrypto.decrypt(enc, "battery staple")
        }
    }

    @Test fun plaintextIsNotDetectedAsEncrypted() {
        assertFalse(BackupCrypto.isEncrypted(sample.toByteArray()))
    }

    @Test fun ciphertextDiffersFromPlaintextAndAcrossRuns() {
        val a = BackupCrypto.encrypt(sample, "pw")
        val b = BackupCrypto.encrypt(sample, "pw")
        // Random salt+IV per run → distinct ciphertext (no deterministic leak), both decrypt back.
        assertFalse(a.contentEquals(b))
        assertEquals(BackupCrypto.decrypt(a, "pw"), BackupCrypto.decrypt(b, "pw"))
        assertArrayEquals(sample.toByteArray(), BackupCrypto.decrypt(a, "pw").toByteArray())
    }

    @Test fun authenticatedMalformedUtf8IsRejectedWithoutChangingCredentials() {
        val salt = ByteArray(16) { it.toByte() }
        val iv = ByteArray(12) { (it + 16).toByte() }
        val derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec("pw".toCharArray(), salt, 210_000, 256)).encoded
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derived, "AES"), GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(byteArrayOf(0xC3.toByte()))
        val envelope = listOf(
            BackupCrypto.MAGIC,
            "210000",
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(ciphertext),
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

        assertThrows(CharacterCodingException::class.java) {
            BackupCrypto.decrypt(envelope, "pw")
        }
    }

    @Test fun backupBudgetsApplyBeforeExpensiveCrypto() {
        assertThrows(IllegalArgumentException::class.java) {
            BackupCrypto.encrypt("x".repeat(8 * 1024 * 1024 + 1), "pw")
        }
        assertThrows(IllegalArgumentException::class.java) {
            BackupCrypto.decrypt(ByteArray(BackupCrypto.MAX_BACKUP_BYTES + 1), "pw")
        }
    }

    @Test fun rejectsUnboundedOrMalformedKdfCostBeforeDerivation() {
        val enc = BackupCrypto.encrypt(sample, "pw").toString(Charsets.UTF_8).split("\n").toMutableList()
        enc[1] = (BackupCrypto.MAX_ACCEPTED_ITER + 1).toString()
        assertThrows(IllegalArgumentException::class.java) {
            BackupCrypto.decrypt(enc.joinToString("\n").toByteArray(), "pw")
        }

        enc[1] = "not-a-number"
        assertThrows(IllegalArgumentException::class.java) {
            BackupCrypto.decrypt(enc.joinToString("\n").toByteArray(), "pw")
        }
    }
}
