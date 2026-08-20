package com.qeli

import android.net.Network
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import java.net.URL
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HttpsURLConnection
import kotlin.coroutines.resume

/** Result of a successful update check. */
data class UpdateInfo(val latest: String, val url: String, val isNewer: Boolean)

/**
 * Opt-in "check for updates" for the Android app.
 *
 * PRIVACY (this is a censorship-resistance VPN): the check is never run unless the
 * user enables it, and MainActivity only calls it when [hasPrivatePath] proves the active
 * profile captures this app without a family leak or route exclusion. The request is bound
 * to the concrete VPN [Network] that was active when the check began: if that network goes
 * away, Android fails the request instead of migrating it to a physical network. The tunnel
 * carrier remains protected separately by VpnService, so this application request still
 * travels THROUGH the VPN (hiding the real IP and the "runs qeli" fingerprint). It is a
 * bare, unauthenticated GET of PUBLIC release
 * metadata with a GENERIC User-Agent (no version/id/OS sent; comparison is local),
 * and it is notification-only — it never downloads or installs anything.
 *
 * Reads the releases LIST (not /releases/latest, which skips qeli's pre-releases) and
 * takes the first non-draft entry, mirroring install-qeli-server.sh. Any failure
 * returns null (fail-soft).
 */
object UpdateChecker {
    private const val RELEASES = "https://api.github.com/repos/litvinovtd/qeli/releases"
    private const val PAGE = "https://github.com/litvinovtd/qeli/releases"

    /**
     * Whether an update request made by qeli itself is guaranteed to enter the active VPN.
     *
     * Android deliberately skips its own package in `apps_mode = include`, because adding
     * the VPN owner to the allowed list would also capture the tunnel socket and loop it.
     * Therefore an include profile can never provide a private path for this request. In
     * `all` and `exclude` modes qeli remains captured. Any explicit route or missing-family
     * escape hatch makes the destination-family path unknowable until DNS resolves GitHub,
     * so privacy is refused conservatively.
     */
    fun hasPrivatePath(
        config: com.qeli.model.VpnConfig,
        globalAllowLan: Boolean = false,
    ): Boolean =
        config.isFullTunnel &&
            !config.appsMode.equals("include", ignoreCase = true) &&
            !config.allowIpv4Leak &&
            !config.allowIpv6Leak &&
            !config.allowLan &&
            !globalAllowLan &&
            config.excludeRoutes.isEmpty()

    suspend fun check(currentVersionName: String, vpnNetwork: Network): UpdateInfo? =
        withContext(Dispatchers.IO) {
            suspendCancellableCoroutine { continuation ->
                val connection = AtomicReference<HttpsURLConnection?>()
                // HttpsURLConnection is blocking IO, so coroutine cancellation alone does not
                // wake responseCode/readText. The cancellable continuation invokes this handler
                // as soon as the VPN lifecycle cancels the job, from another thread if necessary.
                continuation.invokeOnCancellation { connection.get()?.disconnect() }

                val result = try {
                    // Network.openConnection pins DNS and every socket created for redirects to
                    // this VPN generation. URL.openConnection would follow Android's changing
                    // default network and could escape during asynchronous service teardown.
                    val conn = (vpnNetwork.openConnection(URL(RELEASES)) as HttpsURLConnection).apply {
                        requestMethod = "GET"
                        connectTimeout = 10000
                        readTimeout = 10000
                        // A qeli-branded UA would fingerprint the host — send a generic one.
                        setRequestProperty("User-Agent", "Mozilla/5.0")
                        setRequestProperty("Accept", "application/vnd.github+json")
                        setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
                    }
                    connection.set(conn)
                    // Cancellation may have happened just before the connection reference became
                    // visible to the handler. In that race, do not start DNS/connect at all.
                    if (!continuation.isActive) {
                        null
                    } else if (conn.responseCode !in 200..299) {
                        null
                    } else {
                        val body = conn.inputStream.bufferedReader().use { it.readText() }
                        val arr = JSONArray(body)
                        var found: UpdateInfo? = null
                        for (i in 0 until arr.length()) {
                            val rel = arr.optJSONObject(i) ?: continue
                            if (rel.optBoolean("draft", false)) continue
                            val tag = rel.optString("tag_name", "")
                            if (tag.isEmpty()) continue
                            val url = rel.optString("html_url", PAGE).ifEmpty { PAGE }
                            val norm = normalize(tag)
                            found = UpdateInfo(norm, url, isNewer(norm, currentVersionName))
                            break
                        }
                        found
                    }
                } catch (_: Exception) {
                    null
                } finally {
                    connection.getAndSet(null)?.disconnect()
                }
                // CancellableContinuation arbitrates a concurrent cancel/resume atomically. Do
                // not use the internal tryResume/completeResume API: the stable resume extension
                // is cancellation-aware and keeps this source compatible with supported releases.
                if (continuation.isActive) continuation.resume(result)
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
