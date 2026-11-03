package com.qeli

import com.qeli.crypto.BackupCrypto
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import org.junit.Assert.*
import org.junit.Test

class BackupExporterTest {
    @Test fun plaintextArchiveIsExactUtf8AndTemporaryBytesAreCleared() {
        val captured = ByteArrayOutputStream(); var temporary: ByteArray? = null; var closed = false
        val sink = object : OutputStream() {
            override fun write(value: Int) { captured.write(value) }
            override fun write(bytes: ByteArray) { temporary = bytes; captured.write(bytes) }
            override fun close() { closed = true }
        }
        BackupExporter.write("archive: профиль", "") { sink }
        assertEquals("archive: профиль", captured.toString("UTF-8")); assertTrue(closed)
        assertTrue(requireNotNull(temporary).all { it == 0.toByte() })
    }
    @Test fun encryptedArchiveReopensWithTheCorrectPassphrase() {
        val sink = ByteArrayOutputStream(); BackupExporter.write("archive-fixture", "passphrase") { sink }
        val bytes = sink.toByteArray(); assertTrue(BackupCrypto.isEncrypted(bytes))
        assertEquals("archive-fixture", BackupCrypto.decrypt(bytes, "passphrase"))
        assertThrows(javax.crypto.AEADBadTagException::class.java) { BackupCrypto.decrypt(bytes, "wrong") }
    }
    @Test fun nullDestinationIsAnExportFailure() {
        assertThrows(IllegalStateException::class.java) { BackupExporter.write("archive", "") { null } }
    }
    @Test fun failedWriteClosesTheSinkAndClearsTemporaryBytes() {
        var closed = false; var temporary: ByteArray? = null
        val sink = object : OutputStream() {
            override fun write(value: Int) { throw IOException("write refused") }
            override fun write(bytes: ByteArray) { temporary = bytes; throw IOException("write refused") }
            override fun close() { closed = true }
        }
        assertThrows(IOException::class.java) { BackupExporter.write("archive", "") { sink } }
        assertTrue(closed); assertTrue(requireNotNull(temporary).all { it == 0.toByte() })
    }
    @Test fun closeFailureCannotBecomeSuccess() {
        val sink = object : ByteArrayOutputStream() { override fun close() { throw IOException("close refused") } }
        assertThrows(IOException::class.java) { BackupExporter.write("archive", "") { sink } }
    }
    @Test fun oversizedUtf8PlaintextIsRejectedBeforeOpeningTheSink() {
        var opened = false
        val archive = "é".repeat(ProfileLimits.MAX_ARCHIVE_BYTES / 2 + 1)
        assertThrows(IllegalArgumentException::class.java) {
            BackupExporter.write(archive, "") { opened = true; ByteArrayOutputStream() }
        }
        assertFalse(opened)
    }
}
