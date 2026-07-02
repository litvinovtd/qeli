package com.qeli

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Result of a successful update check. */
data class UpdateInfo(val latest: String, val url: String, val isNewer: Boolean)

/**
 * Opt-in "check for updates" for the Android app.
 *
 * PRIVACY (this is a censorship-resistance VPN): the check is never run unless the
 * user enables it, and MainActivity only calls it while the tunnel is UP — the
 * request is left UNPROTECTED so it flows THROUGH the tunnel (hiding the real IP and
 * the "runs qeli" fingerprint). It is a bare, unauthenticated GET of PUBLIC release
 * metadata with a GENERIC User-Agent (no version/id/OS sent; comparison is local),
 * and it is notification-only — it never downloads or installs anything.
 *
 * Reads the releases LIST (not /releases/latest, which skips qeli's pre-releases) and
 * takes the first non-draft entry, mirroring install-reality-server.sh. Any failure
 * returns null (fail-soft).
 */
object UpdateChecker {
    private const val RELEASES = "https://api.github.com/repos/litvinovtd/qeli/releases"
    private const val PAGE = "https://github.com/litvinovtd/qeli/releases"

    suspend fun check(currentVersionName: String): UpdateInfo? = withContext(Dispatchers.IO) {
        var conn: HttpsURLConnection? = null
        try {
            conn = (URL(RELEASES).openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 10000
                readTimeout = 10000
                // A qeli-branded UA would itself fingerprint the host — send a generic one.
                setRequestProperty("User-Agent", "Mozilla/5.0")
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            }
            if (conn.responseCode !in 200..299) return@withContext null
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val arr = JSONArray(body)
            for (i in 0 until arr.length()) {
                val rel = arr.optJSONObject(i) ?: continue
                if (rel.optBoolean("draft", false)) continue
                val tag = rel.optString("tag_name", "")
                if (tag.isEmpty()) continue
                val url = rel.optString("html_url", PAGE).ifEmpty { PAGE }
                val norm = normalize(tag)
                return@withContext UpdateInfo(norm, url, isNewer(norm, currentVersionName))
            }
            null
        } catch (_: Exception) {
            null
        } finally {
            conn?.disconnect()
        }
    }

    /** Strip a leading 'v', drop any '-prerelease'/'+build' suffix → dotted numeric core. */
    fun normalize(s: String): String {
        var v = s.trim()
        if (v.startsWith("v") || v.startsWith("V")) v = v.substring(1)
        val cut = v.indexOfFirst { it == '-' || it == '+' }
        if (cut >= 0) v = v.substring(0, cut)
        return if (v.isEmpty()) "0" else v
    }

    /** True if [latest] is strictly newer than [current] — NUMERIC compare, not lexical. */
    fun isNewer(latest: String, current: String): Boolean {
        val a = normalize(latest).split(".").map { it.toIntOrNull() ?: 0 }
        val b = normalize(current).split(".").map { it.toIntOrNull() ?: 0 }
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }
}
