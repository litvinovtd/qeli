package com.qeli

import java.io.File
import java.nio.file.Files
import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AndroidDiagnosticJournalTest {
    private class PausedDispatcher : CoroutineDispatcher() {
        private val tasks = ArrayDeque<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) { tasks.addLast(block) }
        fun drain() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
    }

    private fun journal(block: (File, AndroidDiagnosticJournal, PausedDispatcher) -> Unit) {
        val directory = Files.createTempDirectory("qeli-journal-").toFile()
        val dispatcher = PausedDispatcher()
        val journal = AndroidDiagnosticJournal.isolated(directory, dispatcher)
        try { block(directory, journal, dispatcher) }
        finally { journal.close(); dispatcher.drain(); directory.deleteRecursively() }
    }

    @Test fun `clear fences queued appends and pending read then accepts fresh events`() = journal { _, journal, worker ->
        val old = journal.append("old", "aabbccdd")
        val staleRead = journal.read()
        val cleared = journal.clearAll()
        val fresh = journal.append("new", "aabbccdd")
        val snapshot = journal.read()
        worker.drain()
        runBlocking {
            assertTrue(runCatching { staleRead.await() }.isFailure)
            assertEquals(fresh.epoch, cleared.await())
            assertTrue(fresh.epoch > old.epoch)
            assertEquals(listOf("new"), snapshot.await().entries.map { it.message })
            assertEquals(fresh.sequence, snapshot.await().throughSequence)
        }
    }

    @Test fun `terminal failure retains journal and optional report across new owner`() = journal { directory, journal, worker ->
        journal.setRetainLastError(true)
        journal.beginSession("aabbccdd")
        journal.append("native transport generation failed (rc=-7)", "aabbccdd", "error")
        val finished = journal.finishSession("aabbccdd", terminalError = true, clearCurrent = true)
        worker.drain()
        runBlocking { finished.await() }
        assertEquals(listOf("native transport generation failed (rc=-7)"),
            DiagnosticLogStore.read(directory).map { it.message })
        val secondWorker = PausedDispatcher()
        val reopened = AndroidDiagnosticJournal.isolated(directory, secondWorker)
        try {
            reopened.setRetainLastError(true)
            val saved = reopened.exportLastError()
            secondWorker.drain()
            val report = JSONObject(runBlocking { saved.await()!! })
            assertEquals("aabbccdd", report.getString("session_id"))
            assertEquals(-7, report.getJSONArray("events").getJSONObject(0).getInt("native_return_code"))
            assertTrue(report.isNull("carrier_metrics"))
        } finally { reopened.close(); secondWorker.drain() }
    }

    @Test fun `error report opt out invalidates queued capture without erasing the ordinary journal`() = journal { directory, journal, worker ->
        journal.setRetainLastError(true)
        journal.append("Connection lost", "aabbccdd", "error")
        val finish = journal.finishSession("aabbccdd", true, true)
        val disabled = journal.setRetainLastError(false)
        worker.drain()
        runBlocking { finish.await(); disabled.await() }
        assertFalse(File(directory, AndroidDiagnosticJournal.REPORT_FILE).exists())
        assertEquals(listOf("Connection lost"), DiagnosticLogStore.read(directory).map { it.message })
    }

    @Test fun `default retention keeps connection error in journal without saving an error report`() = journal { directory, journal, worker ->
        val before = journal.append("[SECURITY] SERVER KEY MISMATCH", "aabbccdd", "error")
        val finish = journal.finishSession("aabbccdd", true, true)
        worker.drain()
        runBlocking { finish.await() }
        assertFalse(File(directory, AndroidDiagnosticJournal.REPORT_FILE).exists())
        assertEquals(before.epoch, journal.epoch)
        assertEquals(listOf("[SECURITY] SERVER KEY MISMATCH"), DiagnosticLogStore.read(directory).map { it.message })
    }

    @Test fun `ordinary disconnect still clears by default and advances epoch`() = journal { directory, journal, worker ->
        val before = journal.append("connected", "aabbccdd")
        val finish = journal.finishSession("aabbccdd", terminalError = false, clearCurrent = true)
        worker.drain()
        assertTrue(runBlocking { finish.await() } > before.epoch)
        assertTrue(DiagnosticLogStore.read(directory).isEmpty())
    }

    @Test fun `disabled disconnect cleanup keeps history and epoch`() = journal { directory, journal, worker ->
        val before = journal.append("connected", "aabbccdd")
        val finish = journal.finishSession("aabbccdd", terminalError = false, clearCurrent = false)
        worker.drain()
        assertEquals(before.epoch, runBlocking { finish.await() })
        assertEquals(listOf("connected"), DiagnosticLogStore.read(directory).map { it.message })
    }

    @Test fun `explicit clear cancels queued error capture and removes old saved report`() = journal { directory, journal, worker ->
        journal.setRetainLastError(true)
        journal.append("old error", "aabbccdd", "error")
        journal.finishSession("aabbccdd", true, true)
        worker.drain()
        assertTrue(File(directory, AndroidDiagnosticJournal.REPORT_FILE).exists())
        journal.append("new error", "aabbccdd", "error")
        val capture = journal.finishSession("aabbccdd", true, true)
        val clear = journal.clearAll()
        worker.drain()
        runBlocking { clear.await(); assertTrue(runCatching { capture.await() }.isFailure) }
        assertFalse(File(directory, AndroidDiagnosticJournal.REPORT_FILE).exists())
        assertTrue(DiagnosticLogStore.read(directory).isEmpty())
    }

    @Test fun `log flood and repeated reads have bounded queues while clear remains available`() = journal { _, journal, worker ->
        repeat(1_000) { journal.append("event $it", "aabbccdd") }
        val report = journal.exportCurrent()
        val reads = List(100) { journal.read() }
        assertTrue(reads.any { it.isCompleted }) // Rejected controls complete immediately.
        worker.drain()
        assertEquals(760, JSONObject(runBlocking { report.await() }).getInt("dropped_queue_events"))
        val clear = journal.clearAll()
        worker.drain()
        runBlocking { clear.await() }
    }

    @Test fun `read barrier sequence excludes later live events`() = journal { _, journal, worker ->
        val old = journal.append("before", "aabbccdd")
        val read = journal.read()
        val live = journal.append("after", "aabbccdd")
        worker.drain()
        val snapshot = runBlocking { read.await() }
        assertEquals(old.sequence, snapshot.throughSequence)
        assertTrue(live.sequence > snapshot.throughSequence)
        assertEquals(listOf("before"), snapshot.entries.map { it.message })
    }

    @Test fun `final unavailable metrics retain last good timestamp and mark the failed read`() = journal { _, journal, worker ->
        journal.beginSession("aabbccdd")
        val valid = """{"schema":1,"scope":"tcp_uplink","completion":"local_write_flush_not_peer_ack",
            "age_semantics":"queue_wait_sample_and_pending_episode","progress_timestamps":"sampled",
            "payloads":"queued_tunnel_payloads_including_control","supported":true,"runtime_available":true,
            "finished":false,"run_id":3,"elapsed_ms":100,"omitted_carriers":0,"carriers":[]}"""
        journal.updateCarrierDiagnostics(valid)
        val first = journal.exportCurrent()
        worker.drain()
        val firstReport = JSONObject(runBlocking { first.await() })
        journal.updateCarrierDiagnostics(null, preserveLastOnUnavailable = true)
        val finalSnapshot = journal.exportCurrent()
        worker.drain()
        val finalReport = JSONObject(runBlocking { finalSnapshot.await() })
        assertEquals(firstReport.getLong("carrier_metrics_captured_at_ms"), finalReport.getLong("carrier_metrics_captured_at_ms"))
        assertEquals(3, finalReport.getJSONObject("carrier_metrics").getInt("run_id"))
        assertFalse(finalReport.isNull("carrier_metrics_latest_read_unavailable_at_ms"))
        journal.beginSession("11223344")
        val fresh = journal.exportCurrent()
        worker.drain()
        assertTrue(JSONObject(runBlocking { fresh.await() }).isNull("carrier_metrics"))
    }

    @Test fun `privacy revision invalidates export even when live log epoch stays unchanged`() = journal { _, journal, worker ->
        journal.setRetainLastError(true)
        val epoch = journal.epoch
        val revision = journal.privacyRevision
        val oldExport = journal.exportLastError()
        journal.setRetainLastError(false)
        worker.drain()
        assertEquals(epoch, journal.epoch)
        assertTrue(journal.privacyRevision > revision)
        runBlocking { assertTrue(runCatching { oldExport.await() }.isFailure) }
    }

    @Test fun `a blocked external export cannot start additional provider writes`() = journal { _, journal, _ ->
        assertTrue(journal.tryStartExternalExport())
        assertFalse(journal.tryStartExternalExport())
        journal.finishExternalExport()
        assertTrue(journal.tryStartExternalExport())
        journal.finishExternalExport()
    }
}
