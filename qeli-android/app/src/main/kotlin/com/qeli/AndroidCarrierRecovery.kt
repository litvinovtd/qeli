package com.qeli

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

/** Callback notifications accelerate recovery; they are not the sole source of truth.
 * A capability change can restore the same Network without another onAvailable callback. */
internal class AndroidCarrierGate(private val recheckMs: Long = 1_000L) {
    init { require(recheckMs > 0) }

    private val changed = Channel<Unit>(Channel.CONFLATED)

    fun signalChange() { changed.trySend(Unit) }

    /** Return whether we actually waited. Parent cancellation is never converted to a retry. */
    suspend fun awaitUsable(isUsable: () -> Boolean, onWaiting: () -> Unit = {}): Boolean {
        var waited = false
        while (true) {
            currentCoroutineContext().ensureActive()
            if (isUsable()) return waited
            if (!waited) {
                waited = true
                onWaiting()
            }
            withTimeoutOrNull(recheckMs) { changed.receive() }
        }
    }
}

internal enum class AndroidCarrierKind { CELLULAR, WIFI, ETHERNET, OTHER }

internal data class AndroidCarrierPreference(
    val usable: Boolean,
    val validated: Boolean,
    val kind: AndroidCarrierKind,
)

/** Pre-31 has no public best-matching observer. Prefer validated carriers and permit a
 * validated Wi-Fi/Ethernet replacement of cellular; retain equivalent carriers to avoid
 * turning a secondary radio's registration into a handover. An unvalidated carrier may be
 * used as a last resort, but cannot supersede a usable validated carrier. */
internal object AndroidCarrierPreferencePolicy {
    fun <T> bestOf(candidates: Iterable<T>, preference: (T) -> AndroidCarrierPreference): T? =
        candidates.fold<T, T?>(null) { selected, candidate ->
            if (shouldReplace(selected?.let(preference), preference(candidate))) candidate else selected
        }

    fun shouldReplace(current: AndroidCarrierPreference?, candidate: AndroidCarrierPreference): Boolean {
        if (!candidate.usable) return false
        if (current == null || !current.usable) return true
        if (candidate.validated != current.validated) return candidate.validated
        if (!candidate.validated) return false
        return rank(candidate.kind) > rank(current.kind)
    }

    private fun rank(kind: AndroidCarrierKind): Int = when (kind) {
        AndroidCarrierKind.ETHERNET -> 2
        AndroidCarrierKind.WIFI -> 1
        AndroidCarrierKind.CELLULAR, AndroidCarrierKind.OTHER -> 0
    }
}

internal data class AndroidPhysicalNetworkSignature(val path: String, val mtu: Int) {
    fun isMtuOnlyChange(previous: AndroidPhysicalNetworkSignature): Boolean =
        path == previous.path && mtu != previous.mtu
}

internal data class AndroidCarrierSnapshot<C, L>(val capabilities: C? = null, val links: L? = null)

/** Used only by one callback owner. Merge the objects Android supplied instead of reading
 * potentially stale synchronous getters from inside the callback. Keep the current carrier
 * while bounding secondary observations; live socket/retry lookups do not use this cache. */
internal class AndroidCarrierSnapshots<K, C, L>(private val capacity: Int = 8) {
    init { require(capacity > 0) }
    private val entries = LinkedHashMap<K, AndroidCarrierSnapshot<C, L>>()

    @Synchronized operator fun get(key: K): AndroidCarrierSnapshot<C, L>? = entries[key]

    @Synchronized fun capabilities(key: K, value: C, current: K?): AndroidCarrierSnapshot<C, L> =
        put(key, (entries[key] ?: AndroidCarrierSnapshot<C, L>()).copy(capabilities = value), current)

    @Synchronized fun links(key: K, value: L, current: K?): AndroidCarrierSnapshot<C, L> =
        put(key, (entries[key] ?: AndroidCarrierSnapshot<C, L>()).copy(links = value), current)

    private fun put(key: K, value: AndroidCarrierSnapshot<C, L>, current: K?): AndroidCarrierSnapshot<C, L> {
        entries.remove(key)
        entries[key] = value
        while (entries.size > capacity) entries.remove(entries.keys.first { it != current })
        return value
    }

    @Synchronized fun retainOnly(key: K) { entries.keys.retainAll(setOf(key)) }
    @Synchronized fun remove(key: K) { entries.remove(key) }
    @Synchronized fun size(): Int = entries.size
}

/** Best-matching observers do not report onLost for superseded networks. Bound the retained
 * observations even when Android never sends that callback; replacement refreshes recency. */
internal class AndroidNetworkSignatureCache<K>(private val capacity: Int = 8) {
    init { require(capacity > 0) }
    private val entries = LinkedHashMap<K, AndroidPhysicalNetworkSignature>()

    @Synchronized operator fun get(key: K): AndroidPhysicalNetworkSignature? = entries[key]

    @Synchronized operator fun set(key: K, value: AndroidPhysicalNetworkSignature) {
        entries.remove(key)
        entries[key] = value
        while (entries.size > capacity) entries.remove(entries.keys.first())
    }

    @Synchronized fun putIfAbsent(key: K, value: AndroidPhysicalNetworkSignature) {
        if (!entries.containsKey(key)) this[key] = value
    }

    @Synchronized fun retainOnly(key: K) { entries.keys.retainAll(setOf(key)) }
    @Synchronized fun remove(key: K) { entries.remove(key) }
    @Synchronized fun clear() { entries.clear() }
    @Synchronized fun size(): Int = entries.size
}
