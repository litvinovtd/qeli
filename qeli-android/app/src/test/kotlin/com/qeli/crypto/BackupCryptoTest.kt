package com.qeli.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
        try {
            BackupCrypto.decrypt(enc, "battery staple")
            throw AssertionError("wrong passphrase must not decrypt")
        } catch (e: Exception) {
            // GCM tag mismatch (AEADBadTagException) — a wrong passphrase is rejected, not garbage.
            assertTrue(e !is AssertionError)
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
}
