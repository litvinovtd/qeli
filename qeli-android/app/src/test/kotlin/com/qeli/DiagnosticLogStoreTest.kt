package com.qeli

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticLogStoreTest {
    @Test
    fun `normal rotation leaves headroom instead of compacting every following append`() = withTempDirectory { directory ->
        DiagnosticLogStore.appendBatch(directory, (0..1000).map {
            DiagnosticLogStore.entry("event-$it", timestampMs = it.toLong())
        })
        val rotated = DiagnosticLogStore.read(directory)
        assertEquals(750, rotated.size)
        assertEquals("event-1000", rotated.last().message)
        DiagnosticLogStore.append(directory, "next")
        assertEquals(751, DiagnosticLogStore.read(directory).size)
    }

    private fun withTempDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("qeli-diagnostic-log-").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `entries survive a new reader with structured metadata`() = withTempDirectory { directory ->
        DiagnosticLogStore.append(
            directory = directory,
            message = "first\r\nsecond\u0000",
            sessionId = "session-01",
            level = "debug",
            timestampMs = 1_234L,
        )

        assertEquals(
            listOf(DiagnosticLogEntry(1_234L, "session-01", "debug", "first\\nsecond")),
            DiagnosticLogStore.read(directory),
        )
    }

    @Test
    fun `entry limit keeps the newest records`() = withTempDirectory { directory ->
        repeat(5) { index ->
            DiagnosticLogStore.append(
                directory,
                "event-$index",
                timestampMs = index.toLong(),
                maxEntries = 3,
                maxBytes = 16_384L,
            )
        }

        assertEquals(
            listOf("event-2", "event-3", "event-4"),
            DiagnosticLogStore.read(directory, maxEntries = 3, maxBytes = 16_384L)
                .map { it.message },
        )
    }

    @Test
    fun `byte limit keeps a bounded newest tail`() = withTempDirectory { directory ->
        repeat(5) { index ->
            DiagnosticLogStore.append(
                directory,
                "event-$index-${"x".repeat(60)}",
                timestampMs = index.toLong(),
                maxEntries = 100,
                maxBytes = 180L,
            )
        }

        val file = File(directory, DiagnosticLogStore.FILE_NAME)
        val restored = DiagnosticLogStore.read(directory, maxEntries = 100, maxBytes = 180L)
        assertTrue(restored.isNotEmpty())
        assertEquals("event-4-${"x".repeat(60)}", restored.last().message)
        assertTrue(file.length() <= 180L)
    }

    @Test
    fun `truncated tail is ignored and compacted`() = withTempDirectory { directory ->
        DiagnosticLogStore.append(directory, "complete", timestampMs = 10L)
        val file = File(directory, DiagnosticLogStore.FILE_NAME)
        file.appendText("truncated-record", StandardCharsets.UTF_8)

        assertEquals(listOf("complete"), DiagnosticLogStore.read(directory).map { it.message })
        assertFalse(file.readText(StandardCharsets.UTF_8).contains("truncated-record"))
        DiagnosticLogStore.append(directory, "after-recovery", timestampMs = 11L)
        assertEquals(
            listOf("complete", "after-recovery"),
            DiagnosticLogStore.read(directory).map { it.message },
        )
    }

    @Test
    fun `concurrent service and activity writers do not lose records`() =
        withTempDirectory { directory ->
            val executor = Executors.newFixedThreadPool(4)
            repeat(4) { writer ->
                executor.submit {
                    repeat(100) { index ->
                        DiagnosticLogStore.append(
                            directory,
                            "writer-$writer-event-$index",
                            sessionId = "session",
                        )
                    }
                }
            }
            executor.shutdown()
            assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS))
            assertEquals(400, DiagnosticLogStore.read(directory).size)
        }

    @Test
    fun `clear removes durable history`() = withTempDirectory { directory ->
        DiagnosticLogStore.append(directory, "before-clear")
        DiagnosticLogStore.clear(directory)

        assertTrue(DiagnosticLogStore.read(directory).isEmpty())
        assertFalse(File(directory, DiagnosticLogStore.FILE_NAME).exists())
    }

    @Test fun `oversized corrupt prefix retains complete newest records`() = withTempDirectory { directory ->
        DiagnosticLogStore.append(directory, "latest", timestampMs = 42L)
        val file = File(directory, DiagnosticLogStore.FILE_NAME)
        val valid = file.readBytes()
        file.outputStream().use { output ->
            val garbage = ByteArray(16 * 1024) { 'x'.code.toByte() }
            repeat(512) { output.write(garbage) }
            output.write('\n'.code); output.write(valid)
        }
        assertEquals(listOf("latest"), DiagnosticLogStore.read(directory).map { it.message })
        assertTrue(file.length() <= DiagnosticLogStore.MAX_BYTES)
    }
    @Test fun `large valid history keeps the requested newest entry count`() = withTempDirectory { directory ->
        val file = File(directory, DiagnosticLogStore.FILE_NAME)
        val encoded = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("профиль".toByteArray(StandardCharsets.UTF_8))
        file.bufferedWriter(StandardCharsets.UTF_8).use { out ->
            repeat(50_000) { i -> out.write("$i\tinfo\t\t$encoded\n") }
        }
        val entries = DiagnosticLogStore.read(directory, maxEntries = 3)
        assertEquals(listOf(49_997L, 49_998L, 49_999L), entries.map { it.timestampMs })
        assertTrue(entries.all { it.message == "профиль" })
        assertTrue(file.length() <= DiagnosticLogStore.MAX_BYTES)
    }
    @Test fun `append repairs an oversized existing journal before adding a record`() = withTempDirectory { directory ->
        val file = File(directory, DiagnosticLogStore.FILE_NAME)
        file.outputStream().use { out -> repeat(64) { out.write(ByteArray(16 * 1024) { 'x'.code.toByte() }) } }
        DiagnosticLogStore.append(directory, "after-recovery", maxBytes = 128)
        assertEquals(listOf("after-recovery"), DiagnosticLogStore.read(directory, maxBytes = 128).map { it.message })
        assertTrue(file.length() <= 128)
    }
}
