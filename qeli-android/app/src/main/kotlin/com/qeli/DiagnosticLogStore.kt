package com.qeli

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Base64

/** One durable diagnostic event. Secrets and complete profile text must never be written here. */
internal data class DiagnosticLogEntry(
    val timestampMs: Long,
    val sessionId: String,
    val level: String,
    val message: String,
)

/**
 * Process-independent bounded journal used by both the VPN service and its Activity.
 *
 * Each field that can contain arbitrary text is URL-safe base64 encoded, so a truncated final
 * write can invalidate only that line. The next read ignores the partial record and atomically
 * compacts the file. Android's private no-backup directory is supplied by the caller; keeping the
 * storage engine free of framework types makes its corruption and rotation behaviour JVM-testable.
 */
internal object DiagnosticLogStore {
    internal const val FILE_NAME = "qeli-diagnostic.log"
    internal const val MAX_ENTRIES = 1_000
    internal const val MAX_BYTES = 512L * 1024L
    private const val MAX_MESSAGE_CHARS = 4_096
    private const val MAX_SESSION_CHARS = 64
    // One normalized UTF-8/base64 record fits within this extra boundary allowance.
    private const val MAX_RECORD_BYTES = 24 * 1024

    private val lock = Any()
    private val knownCounts = mutableMapOf<String, Int>()
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    internal fun append(
        directory: File,
        message: String,
        sessionId: String = "",
        level: String = "info",
        timestampMs: Long = System.currentTimeMillis(),
        maxEntries: Int = MAX_ENTRIES,
        maxBytes: Long = MAX_BYTES,
    ): DiagnosticLogEntry {
        val entry = entry(message, sessionId, level, timestampMs)
        appendBatch(directory, listOf(entry), maxEntries, maxBytes)
        return entry
    }

    internal fun entry(message: String, sessionId: String = "", level: String = "info",
                       timestampMs: Long = System.currentTimeMillis()): DiagnosticLogEntry =
        DiagnosticLogEntry(timestampMs.coerceAtLeast(0L), normalizeSessionId(sessionId),
            normalizeLevel(level), normalizeMessage(message))

    /** Production callers batch on their single IO worker; never call this on Android main. */
    internal fun appendBatch(directory: File, entries: List<DiagnosticLogEntry>,
                             maxEntries: Int = MAX_ENTRIES, maxBytes: Long = MAX_BYTES) {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(maxBytes > 0) { "maxBytes must be positive" }
        if (entries.isEmpty()) return
        synchronized(lock) {
            check(directory.exists() || directory.mkdirs()) {
                "cannot create diagnostic log directory '${directory.absolutePath}'"
            }
            val file = File(directory, FILE_NAME)
            val key = file.absoluteFile.normalize().path
            var count = knownCounts[key]
            if (count == null) {
                val loaded = loadUnlocked(file, maxBytes)
                val retained = retainNewest(loaded.entries, maxEntries, maxBytes)
                if (loaded.hadInvalidRecord || retained.size != loaded.entries.size ||
                    file.length() > maxBytes
                ) {
                    rewriteUnlocked(file, retained)
                }
                count = retained.size
            }

            FileOutputStream(file, true).use { output ->
                entries.forEach { raw ->
                    output.write(encode(entry(raw.message, raw.sessionId, raw.level, raw.timestampMs))
                        .toByteArray(StandardCharsets.UTF_8))
                }
            }
            count += entries.size
            if (count > maxEntries || file.length() > maxBytes) {
                // Leave headroom after rotation: a long session must not rewrite 1000 records
                // for every subsequent event. Tiny test/custom limits retain exact semantics.
                val loaded = loadUnlocked(file, maxBytes).entries
                val retained = retainNewest(loaded,
                    if (maxEntries >= 32) maxEntries * 3 / 4 else maxEntries,
                    if (maxBytes >= MAX_RECORD_BYTES * 2) maxBytes * 3 / 4 else maxBytes)
                rewriteUnlocked(file, retained)
                count = retained.size
            }
            knownCounts[key] = count
        }
    }

    internal fun read(
        directory: File,
        maxEntries: Int = MAX_ENTRIES,
        maxBytes: Long = MAX_BYTES,
    ): List<DiagnosticLogEntry> {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(maxBytes > 0) { "maxBytes must be positive" }
        synchronized(lock) {
            val file = File(directory, FILE_NAME)
            if (!file.exists()) return emptyList()
            val loaded = loadUnlocked(file, maxBytes)
            val retained = retainNewest(loaded.entries, maxEntries, maxBytes)
            if (loaded.hadInvalidRecord || retained.size != loaded.entries.size ||
                file.length() > maxBytes
            ) {
                rewriteUnlocked(file, retained)
            }
            knownCounts[file.absoluteFile.normalize().path] = retained.size
            return retained
        }
    }

    internal fun clear(directory: File) {
        synchronized(lock) {
            val file = File(directory, FILE_NAME)
            val temp = File(directory, "$FILE_NAME.tmp")
            if (file.exists() && !file.delete()) {
                throw IllegalStateException("cannot clear diagnostic log '${file.absolutePath}'")
            }
            if (temp.exists()) temp.delete()
            knownCounts.remove(file.absoluteFile.normalize().path)
        }
    }

    private data class LoadResult(
        val entries: List<DiagnosticLogEntry>,
        val hadInvalidRecord: Boolean,
    )

    private fun loadUnlocked(file: File, maxBytes: Long): LoadResult {
        if (!file.exists()) return LoadResult(emptyList(), false)
        val entries = mutableListOf<DiagnosticLogEntry>()
        var invalid = false
        // Rotation bounds normal writes, but a corrupt/restored file can be much larger.
        // Seek to a bounded tail before decoding; include one complete record at the edge.
        FileInputStream(file).use { input ->
            val budget = (minOf(maxBytes, MAX_BYTES) + MAX_RECORD_BYTES).toInt()
            val start = (input.channel.size() - budget).coerceAtLeast(0L)
            val partialFirstLine = if (start > 0) {
                input.channel.position(start - 1)
                invalid = true
                input.read() != '\n'.code
            } else false
            val bytes = BoundedInput.read(input, budget)
            try {
                bytes.inputStream().bufferedReader(StandardCharsets.UTF_8).use { reader ->
                    if (partialFirstLine) reader.readLine()
                    reader.forEachLine { line ->
                        val entry = decode(line)
                        if (entry == null) invalid = true else entries += entry
                    }
                }
            } finally { bytes.fill(0) }
        }
        return LoadResult(entries, invalid)
    }

    private fun retainNewest(
        entries: List<DiagnosticLogEntry>,
        maxEntries: Int,
        maxBytes: Long,
    ): List<DiagnosticLogEntry> {
        val newestFirst = ArrayList<DiagnosticLogEntry>(minOf(entries.size, maxEntries))
        var bytes = 0L
        for (index in entries.indices.reversed()) {
            if (newestFirst.size >= maxEntries) break
            val entry = entries[index]
            val encodedBytes = encode(entry).toByteArray(StandardCharsets.UTF_8).size.toLong()
            if (bytes + encodedBytes > maxBytes) break
            newestFirst += entry
            bytes += encodedBytes
        }
        newestFirst.reverse()
        return newestFirst
    }

    private fun rewriteUnlocked(file: File, entries: List<DiagnosticLogEntry>) {
        file.parentFile?.mkdirs()
        val temp = File(file.parentFile, "$FILE_NAME.tmp")
        temp.bufferedWriter(StandardCharsets.UTF_8).use { writer ->
            entries.forEach { writer.write(encode(it)) }
        }
        try {
            Files.move(
                temp.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: Exception) {
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun encode(entry: DiagnosticLogEntry): String = buildString {
        append(entry.timestampMs)
        append('\t').append(entry.level)
        append('\t').append(encodeText(entry.sessionId))
        append('\t').append(encodeText(entry.message))
        append('\n')
    }

    private fun decode(line: String): DiagnosticLogEntry? = runCatching {
        val fields = line.split('\t', limit = 4)
        if (fields.size != 4) return null
        val timestamp = fields[0].toLongOrNull() ?: return null
        DiagnosticLogEntry(
            timestampMs = timestamp.coerceAtLeast(0L),
            level = normalizeLevel(fields[1]),
            sessionId = normalizeSessionId(decodeText(fields[2])),
            message = normalizeMessage(decodeText(fields[3])),
        )
    }.getOrNull()

    private fun encodeText(value: String): String =
        encoder.encodeToString(value.toByteArray(StandardCharsets.UTF_8))

    private fun decodeText(value: String): String =
        String(decoder.decode(value), StandardCharsets.UTF_8)

    private fun normalizeLevel(value: String): String = when (value.trim().lowercase()) {
        "debug", "trace", "warn", "error" -> value.trim().lowercase()
        else -> "info"
    }

    private fun normalizeSessionId(value: String): String = value.asSequence()
        .filter { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' }
        .take(MAX_SESSION_CHARS)
        .joinToString("")

    private fun normalizeMessage(value: String): String = value
        .replace("\r\n", "\\n")
        .replace("\r", "\\n")
        .replace("\n", "\\n")
        .asSequence()
        .filterNot { it.isISOControl() }
        .take(MAX_MESSAGE_CHARS)
        .joinToString("")
}
