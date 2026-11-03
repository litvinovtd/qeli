package com.qeli

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import java.io.ByteArrayInputStream
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DiagnosticLogStoreInstrumentedTest {
    @Test
    fun privateNoBackupJournalSurvivesReopenAndClears() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(
            context.noBackupFilesDir,
            "diagnostic-test-${UUID.randomUUID()}",
        )
        try {
            DiagnosticLogStore.append(
                directory,
                message = "screen off",
                sessionId = "device-test",
                level = "debug",
                timestampMs = 123L,
            )
            assertEquals(
                listOf(DiagnosticLogEntry(123L, "device-test", "debug", "screen off")),
                DiagnosticLogStore.read(directory),
            )

            DiagnosticLogStore.clear(directory)
            assertFalse(File(directory, DiagnosticLogStore.FILE_NAME).exists())
        } finally {
            directory.deleteRecursively()
        }
    }
    @Test fun oversizedPrivateJournalRetainsNewestRecordAndCompacts() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val directory = File(context.noBackupFilesDir, "diagnostic-test-${UUID.randomUUID()}")
        try {
            DiagnosticLogStore.append(directory, "latest", timestampMs = 42L)
            val file = File(directory, DiagnosticLogStore.FILE_NAME)
            val valid = file.readBytes()
            file.outputStream().use { out ->
                val garbage = ByteArray(16 * 1024) { 'x'.code.toByte() }
                repeat(512) { out.write(garbage) }
                out.write('\n'.code); out.write(valid)
            }
            assertEquals(listOf("latest"), DiagnosticLogStore.read(directory).map { it.message })
            assertTrue(file.length() <= DiagnosticLogStore.MAX_BYTES)
        } finally { directory.deleteRecursively() }
    }

    @Test fun sharedInputBudgetRejectsExcessAndPreservesZeroBulkReadData() {
        assertTrue(runCatching { BoundedInput.read(ByteArrayInputStream(ByteArray(33)), 32) }.isFailure)
        val bytes = byteArrayOf(1, 2, 3)
        val zeroBulk = object : ByteArrayInputStream(bytes) {
            override fun read(buffer: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertTrue(bytes.contentEquals(BoundedInput.read(zeroBulk, 3)))
    }
}
