package com.qeli

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.ArrayDeque

internal data class JournalRecord(val entry: DiagnosticLogEntry, val epoch: Long, val sequence: Long)
internal data class JournalSnapshot(val entries: List<DiagnosticLogEntry>, val epoch: Long, val throughSequence: Long)

/** One process-owned IO consumer. Producers never wait for disk or an unbounded executor queue. */
internal class AndroidDiagnosticJournal private constructor(private val directory: File,
    dispatcher: CoroutineDispatcher = Dispatchers.IO) {
    companion object {
        private const val QUEUE_LIMIT = 256
        private const val CONTROL_RESERVE = 16
        private const val BATCH_LIMIT = 32
        internal const val REPORT_LIMIT = 1024 * 1024
        internal const val REPORT_FILE = "qeli-last-error.json"
        private var instance: AndroidDiagnosticJournal? = null
        @Synchronized fun get(directory: File): AndroidDiagnosticJournal =
            instance ?: AndroidDiagnosticJournal(directory).also { instance = it }

        // A separate owner makes ordering/fence regressions testable without Android components.
        internal fun isolated(directory: File, dispatcher: CoroutineDispatcher = Dispatchers.IO) =
            AndroidDiagnosticJournal(directory, dispatcher)
    }

    private sealed interface Command
    private data class Append(val record: JournalRecord) : Command
    private class Control(val run: () -> Unit, val reject: () -> Unit, val essential: Boolean) : Command
    private val lock = Any()
    private val queue = ArrayDeque<Command>()
    private val wake = Channel<Unit>(Channel.CONFLATED)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private var currentEpoch = 0L
    private var sequence = 0L
    private var reportFence = 0L
    private var retainError = false
    private var retentionInitialized = false
    private var activeSession = ""
    private var metrics: Metrics? = null
    private var dropped = 0L
    private var writeFailures = 0L
    private var pendingReportDelete: CompletableDeferred<Unit>? = null
    private var externalExportInProgress = false
    private data class Metrics(val snapshot: String?, val capturedAt: Long, val lastUnavailableAt: Long? = null)
    val epoch: Long get() = synchronized(lock) { currentEpoch }
    val privacyRevision: Long get() = synchronized(lock) { reportFence }
    // A DocumentsProvider may ignore cancellation. Across Activity recreation, permit only
    // one blocking provider write, without blocking the journal consumer or VPN shutdown.
    fun tryStartExternalExport(): Boolean = synchronized(lock) {
        if (externalExportInProgress) false else { externalExportInProgress = true; true }
    }
    fun finishExternalExport() = synchronized(lock) { externalExportInProgress = false }
    internal fun close() { scope.cancel(); wake.close() }

    init {
        scope.launch {
            for (ignored in wake) {
                while (true) {
                    val command = synchronized(lock) { if (queue.isEmpty()) null else queue.removeFirst() } ?: break
                    when (command) {
                        is Control -> command.run()
                        is Append -> {
                            val batch = mutableListOf(command.record.entry)
                            synchronized(lock) {
                                while (batch.size < BATCH_LIMIT && queue.peekFirst() is Append) {
                                    batch += (queue.removeFirst() as Append).record.entry
                                }
                            }
                            try { DiagnosticLogStore.appendBatch(directory, batch) }
                            catch (_: Exception) { synchronized(lock) { writeFailures++ } }
                        }
                    }
                }
            }
        }
    }

    fun beginSession(sessionId: String) = synchronized(lock) {
        if (activeSession != sessionId) metrics = null
        activeSession = sessionId
    }

    fun updateCarrierDiagnostics(snapshot: String?, preserveLastOnUnavailable: Boolean = false) = synchronized(lock) {
        val clean = CarrierDiagnostics.sanitize(snapshot)
        val now = System.currentTimeMillis()
        metrics = if (clean == null && preserveLastOnUnavailable && metrics?.snapshot != null) {
            metrics!!.copy(lastUnavailableAt = now)
        } else Metrics(clean, now, if (clean == null) now else null)
    }

    fun append(message: String, sessionId: String, level: String = "info",
               timestampMs: Long = System.currentTimeMillis()): JournalRecord = synchronized(lock) {
        val record = JournalRecord(DiagnosticLogStore.entry(message, sessionId, level, timestampMs),
            currentEpoch, ++sequence)
        if (queue.size >= QUEUE_LIMIT - CONTROL_RESERVE) dropped++
        else { queue.addLast(Append(record)); wake.trySend(Unit) }
        record
    }

    fun read(): CompletableDeferred<JournalSnapshot> = synchronized(lock) {
        val readEpoch = currentEpoch
        val through = sequence
        control { JournalSnapshot(DiagnosticLogStore.read(directory), readEpoch, through) }
    }

    /** This privacy boundary invalidates queued reports as well as delayed Activity broadcasts. */
    fun clearAll(): CompletableDeferred<Long> = synchronized(lock) {
        currentEpoch++
        reportFence++
        metrics = null
        discardQueuedControlsAndAppends()
        pendingReportDelete = null
        val clearEpoch = currentEpoch
        control(essential = true) {
            DiagnosticLogStore.clear(directory)
            deleteReport()
            clearEpoch
        }
    }

    fun setRetainLastError(enabled: Boolean): CompletableDeferred<Unit> = synchronized(lock) {
        if (retentionInitialized && retainError == enabled) return@synchronized CompletableDeferred(Unit)
        retentionInitialized = true
        retainError = enabled
        reportFence++
        if (enabled) CompletableDeferred(Unit) else {
            // Privacy controls cannot be starved by repeated exports/reads. Dropped controls
            // fail visibly; queued appends still retain their original order.
            discardQueuedControls()
            pendingReportDelete?.takeUnless { it.isCompleted } ?: control(essential = true) {
                deleteReport()
            }.also { pendingReportDelete = it }
        }
    }

    /** A failed connection retains its ordinary journal regardless of the disconnect preference.
     * The separately opt-in structured error report keeps its own privacy fence. */
    fun finishSession(sessionId: String, terminalError: Boolean, clearCurrent: Boolean): CompletableDeferred<Long> =
        synchronized(lock) {
            val capturedMetrics = metrics
            val captureFence = reportFence
            val capture = terminalError && retainError
            val clearLog = clearCurrent && !terminalError
            if (clearLog) currentEpoch++
            val finishEpoch = currentEpoch
            if (clearLog) metrics = null
            control(essential = true) {
                try {
                    if (capture && synchronized(lock) { retainError && reportFence == captureFence }) {
                        val report = report(DiagnosticLogStore.read(directory), sessionId, "terminal_error", capturedMetrics)
                        // The single consumer serializes a subsequently requested deletion after
                        // this write. The fence also avoids capture if clear/opt-out raced the read.
                        if (synchronized(lock) { retainError && reportFence == captureFence }) writeReport(report)
                    }
                } finally { if (clearLog) DiagnosticLogStore.clear(directory) }
                finishEpoch
            }
        }

    fun exportCurrent(): CompletableDeferred<String> = synchronized(lock) {
        val capturedMetrics = metrics
        val session = activeSession
        control { report(DiagnosticLogStore.read(directory), session, "current", capturedMetrics) }
    }

    fun exportLastError(): CompletableDeferred<String?> = synchronized(lock) {
        val fence = reportFence
        control {
            if (!synchronized(lock) { retainError && reportFence == fence }) null else {
                val file = File(directory, REPORT_FILE)
                if (!file.exists()) null else {
                    val bytes = file.inputStream().use { BoundedInput.read(it, REPORT_LIMIT) }
                    try {
                        // Saved files are produced only by this codec; reject corruption/version drift.
                        String(bytes, Charsets.UTF_8).takeIf {
                            file.length() <= REPORT_LIMIT && JSONObject(it).optInt("schema") == 1 &&
                                synchronized(lock) { retainError && reportFence == fence }
                        }
                    } finally { bytes.fill(0) }
                }
            }
        }
    }

    private fun <T> control(essential: Boolean = false, body: () -> T): CompletableDeferred<T> {
        val result = CompletableDeferred<T>()
        if (essential && (queue.count { it is Control } >= CONTROL_RESERVE || queue.size >= QUEUE_LIMIT)) {
            discardQueuedControls()
        }
        if (queue.count { it is Control } >= CONTROL_RESERVE || queue.size >= QUEUE_LIMIT) {
            result.completeExceptionally(IllegalStateException("Diagnostic journal is busy"))
            return result
        }
        queue.addLast(Control(
            run = { try { result.complete(body()) } catch (error: Exception) { result.completeExceptionally(error) } },
            reject = { result.completeExceptionally(IllegalStateException("Diagnostic operation superseded by privacy cleanup")) },
            essential = essential,
        ))
        wake.trySend(Unit)
        return result
    }

    private fun discardQueuedControls() {
        val iterator = queue.iterator()
        while (iterator.hasNext()) {
            val next = iterator.next()
            if (next is Control && !next.essential) { iterator.remove(); next.reject() }
        }
    }

    private fun discardQueuedControlsAndAppends() {
        queue.forEach { if (it is Control) it.reject() }
        queue.clear()
    }

    private fun report(entries: List<DiagnosticLogEntry>, session: String, kind: String, captured: Metrics?): String {
        val counts = synchronized(lock) { dropped to writeFailures }
        return DiagnosticReportCodec.encode(entries, session, kind, captured?.snapshot,
            captured?.capturedAt, counts.first, counts.second, captured?.lastUnavailableAt).also {
            check(it.toByteArray(Charsets.UTF_8).size <= REPORT_LIMIT) { "Diagnostic report is too large" }
        }
    }

    private fun writeReport(report: String) {
        check(directory.exists() || directory.mkdirs())
        val target = File(directory, REPORT_FILE)
        val temp = File(directory, "$REPORT_FILE.tmp")
        temp.writeText(report, Charsets.UTF_8)
        try { Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING) }
        catch (_: Exception) { Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING) }
    }

    private fun deleteReport() {
        listOf(REPORT_FILE, "$REPORT_FILE.tmp").forEach { name ->
            val file = File(directory, name)
            check(!file.exists() || file.delete()) { "Unable to delete diagnostic report" }
        }
    }
}

/** No free-text redaction promise: exported messages are classified, never copied. */
internal object DiagnosticReportCodec {
    fun encode(entries: List<DiagnosticLogEntry>, sessionId: String, kind: String,
               metrics: String?, metricsAt: Long?, dropped: Long, writeFailures: Long,
               metricsUnavailableAt: Long? = null): String {
        val events = JSONArray()
        entries.takeLast(DiagnosticLogStore.MAX_ENTRIES).forEach { entry ->
            events.put(JSONObject().put("timestamp_ms", entry.timestampMs)
                .put("session_id", safeSession(entry.sessionId)).put("level", entry.level)
                .put("event", category(entry.message)).put("reason_code", reason(entry.message))
                .put("native_return_code", nativeCode(entry.message) ?: JSONObject.NULL))
        }
        return JSONObject().put("schema", 1).put("app", "qeli-android")
            .put("kind", kind).put("captured_at_ms", System.currentTimeMillis())
            .put("session_id", safeSession(sessionId)).put("raw_messages_included", false)
            .put("dropped_queue_events", dropped).put("journal_write_failures", writeFailures)
            .put("events", events).put("carrier_metrics", metrics?.let(::JSONObject) ?: JSONObject.NULL)
            .put("carrier_metrics_captured_at_ms", metricsAt ?: JSONObject.NULL)
            .put("carrier_metrics_latest_read_unavailable_at_ms", metricsUnavailableAt ?: JSONObject.NULL).toString(2)
    }

    private fun safeSession(value: String): String = value.takeIf { it.matches(Regex("[a-f0-9]{8}")) } ?: ""
    internal fun category(message: String): String {
        val value = message.take(256).lowercase()
        return when {
            value.startsWith("carrier diagnostics") || value.startsWith("tcp carrier ") -> "carrier_health"
            value.startsWith("session ") || value.startsWith("=== vpn session ") -> "session"
            value.contains("reconnect") || value.startsWith("retry") -> "recovery"
            value.contains("network") || value.contains("carrier") -> "physical_network"
            value.contains("dns") || value.contains("resolve") -> "dns"
            value.contains("mtu") || value.contains("pmtu") -> "path_mtu"
            value.contains("handshake") -> "handshake"
            value.contains("tun") || value.contains("route") -> "tunnel"
            value.contains("connected") || value.contains("disconnect") -> "connection_state"
            value.contains("timeout") || value.contains("timed out") -> "timeout"
            value.contains("error") || value.contains("fail") -> "error"
            else -> "other"
        }
    }

    private fun nativeCode(message: String): Int? = Regex("native transport generation failed \\(rc=(-?[0-9]{1,6})\\)")
        .find(message.take(4096))?.groupValues?.get(1)?.toIntOrNull()

    internal fun reason(message: String): String {
        val value = message.take(4096).lowercase()
        return when {
            value.contains("native transport generation failed (rc=") -> "native_generation_failed"
            value.contains("reconnect is disabled") -> "reconnect_disabled"
            value.contains("max reconnect retries") -> "retry_budget_exhausted"
            value.startsWith("server stopped reconnect:") || value.contains("session terminated by server") -> "server_terminated_session"
            value.contains("vpn permission denied") || value.startsWith("[security]") -> "permission_or_security_rejection"
            value.contains("has no usable ipv4 or ipv6 address") -> "carrier_dns_empty"
            value.contains("unknownhostexception") -> "dns_lookup_failed"
            value.contains("sockettimeoutexception") || value.contains("timed out") -> "operation_timed_out"
            value.contains("connectexception") -> "socket_connect_failed"
            value.contains("network lost") -> "physical_network_lost"
            value.contains("no usable") && value.contains("network") -> "no_usable_network"
            value.contains("link mtu changed") -> "link_mtu_changed"
            value.contains("user disconnect") -> "user_disconnect"
            value.contains("connection closed cleanly") -> "transport_closed_cleanly"
            value.startsWith("connect request rejected:") -> "connect_preflight_rejected"
            else -> "unspecified"
        }
    }
}
