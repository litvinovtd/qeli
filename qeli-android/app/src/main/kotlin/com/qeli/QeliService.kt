package com.qeli

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import com.qeli.model.PushedFacts
import com.qeli.model.VpnConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet4Address
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class VpnServiceImpl : VpnService() {

    // @Volatile: written by startVpn() on the main thread, but read/closed by
    // teardownAndWait()/stopVpn() invoked from background IO coroutines (reconnect loop,
    // network-change callback). Without it a background thread could see a stale
    // native generation/scope during a rapid connect↔disconnect. (audit 4.3)
    @Volatile private var supervisor: Job? = null
    @Volatile private var coroutineScope: CoroutineScope? = null
    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    // Rust owns handshake and payload; this service is the platform adapter for Android APIs.
    @Volatile private var transportCore: TransportCore? = null
    // The blocking JNI runner owns Rust's duplicated TUN descriptors. Manual disconnect must
    // join this Job before Android/UI can be told that routes and DNS are restored.
    @Volatile private var transportJob: Job? = null
    @Volatile private var activeConfig: VpnConfig? = null
    @Volatile private var nativeFatalError: Throwable? = null
    private var wakeLock: PowerManager.WakeLock? = null
    // Watches the default network (Wi-Fi <-> LTE switch). On a change we cancel the
    // live native generation to reconnect on the new network without waiting for its
    // dead-connection timeout.
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var screenReceiver: BroadcastReceiver? = null
    private var wakeReconnectJob: Job? = null
    @Volatile private var screenOffAt = 0L
    @Volatile
    private var currentNetwork: Network? = null
    // Every non-VPN network we currently see, used ONLY on the pre-31 fallback path of
    // [registerNetworkCallback] to tell "the link we are on died" from "some other link
    // appeared". Empty on API 31+, which gets the best-matching callback instead.
    private val underlyingNets = java.util.Collections.synchronizedSet(mutableSetOf<Network>())
    private val networkSignatures = java.util.concurrent.ConcurrentHashMap<Network, String>()

    // Network.getAllByName is a blocking platform call and ignores thread interruption on
    // several Android resolver implementations. Keep a bounded service-owned pool: one old
    // physical network may remain stuck while the replacement network still gets a resolver
    // slot, but repeated network flaps cannot grow an unbounded worker/queue population.
    private val carrierDnsExecutor = Executors.newFixedThreadPool(MAX_CARRIER_DNS_REQUESTS) { runnable ->
        Thread(runnable, "qeli-carrier-dns").apply { isDaemon = true }
    }
    private val carrierDnsLock = Any()
    private val carrierDnsRequests = mutableMapOf<String, CarrierDnsRequest>()

    // Session cancellation cannot finalize itself: connectWithRetry may be the code requesting
    // shutdown. A service-lifetime scope joins the blocking native runner.
    private val teardownSupervisor = SupervisorJob()
    private val teardownScope = CoroutineScope(teardownSupervisor + Dispatchers.IO)
    @Volatile private var teardownJob: Job? = null

    private data class CarrierDnsRequest(
        val key: String,
        val deadlineAt: Long,
        val future: Future<List<String>>,
    )

    @Volatile
    private var userRequestedDisconnect = false

    @Volatile
    private var stopping = false

    // Timestamp of the last network-change forced reconnect, to debounce a flapping
    // default network (see forceReconnect).
    @Volatile
    private var lastForceReconnectAt = 0L
    // True while forceReconnect() deliberately cancels the native generation for a network
    // change. The resulting cancellation/error is expected, so it is not surfaced as an ERR.
    @Volatile
    private var forcedReconnectInFlight = false
    @Volatile
    private var pausedByTrustedWifi = false
    @Volatile
    private var trustedPauseInFlight = false
    @Volatile
    private var trustedWaitConfig: VpnConfig? = null
    private var trustedResumeJob: Job? = null

    private val CHANNEL_ID = "vpn_obfuscated_channel"
    private val NOTIFICATION_ID = 1001

    companion object {
        private const val MAX_CARRIER_DNS_REQUESTS = 2
        const val ACTION_CONNECT = "com.qeli.CONNECT"
        const val ACTION_DISCONNECT = "com.qeli.DISCONNECT"
        const val ACTION_REEVALUATE_TRUSTED = "com.qeli.REEVALUATE_TRUSTED_WIFI"
        const val EXTRA_CONFIG = "config"
        const val BROADCAST_STATUS = "com.qeli.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_ERROR = "error"
        const val EXTRA_LOG = "log"
        const val EXTRA_IP = "ip"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_DISCONNECTING = "disconnecting"
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_WAITING_TRUSTED = "waiting_trusted_wifi"
        const val STATUS_ERROR = "error"
        const val STATUS_STATS = "stats"
        const val EXTRA_UP = "up"     // upload rate, bytes/sec
        const val EXTRA_DOWN = "down" // download rate, bytes/sec
        const val EXTRA_UP_TOTAL = "up_total"     // cumulative bytes sent this session
        const val EXTRA_DOWN_TOTAL = "down_total" // cumulative bytes received this session

        // UDP handshake retransmit tick — see recvUdpWithRetransmit.
        private const val TRANSPORT_CORE_POLL_MIN_MS = 20L
        private const val TRANSPORT_CORE_POLL_MAX_MS = 250L
        private const val NATIVE_TEARDOWN_WARN_MS = 5_000L

        // LAN-bypass (allow_lan): private ranges carved out of a full tunnel so local
        // devices stay reachable over Wi-Fi. RFC1918 + link-local + the local-multicast
        // /24 (mDNS/SSDP, so AirPlay/Chromecast discovery works). The tunnel's own /24
        // (added via addAddress) is a more-specific connected route, so excluding 10/8
        // here does NOT strand the tunnel gateway.
        private val LAN_BYPASS_EXCLUDES = listOf(
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/24"
        )
        // 0.0.0.0/0 minus RFC1918 (10/8, 172.16/12, 192.168/16) as an explicit covering set,
        // for pre-Android-13 devices that lack excludeRoute. Multicast (224/3) is intentionally
        // omitted so mDNS/SSDP stay off the tunnel (on Wi-Fi) for LAN discovery.
        /**
         * Ceiling on the pre-13 complement split. A handful of excludes needs a few dozen
         * prefixes; a pathological list could need thousands, and VpnService.Builder does
         * not accept an unbounded route table. Past this we refuse and warn rather than
         * install a partial set that silently excludes only some of what was asked. (C-22)
         */
        private const val MAX_COMPLEMENT_ROUTES = 200

        private val PUBLIC_MINUS_RFC1918 = listOf(
            "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
            "64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12",
            "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7",
            "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16",
            "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10", "193.0.0.0/8",
            "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"
        )

        // Last known tunnel state, readable by a (re)created Activity so it can
        // restore its UI without a fresh broadcast. The foreground service keeps
        // running across Activity recreation (theme switch / rotation), so the
        // tunnel itself is never interrupted — only the UI needs to re-sync.
        @Volatile
        @JvmField
        var liveStatus: String = STATUS_DISCONNECTED
        @Volatile
        @JvmField
        var liveIp: String = ""
        @Volatile
        @JvmField
        var liveTrustedSsid: String = ""

        // Session uptime anchor + cumulative byte counters, also readable after
        // recreation so the stats card restores its values.
        @Volatile
        @JvmField
        var liveConnectedAt: Long = 0L
        @Volatile
        @JvmField
        var liveBytesUp: Long = 0L
        @Volatile
        @JvmField
        var liveBytesDown: Long = 0L

        // ── negotiated facts the UI cannot derive from the profile ──
        // The protection card states what is actually in force, and these are only known
        // after the handshake: the server pushes DNS/MTU/routes/streams, and the system
        // owns the lockdown switch. Published as snapshot fields (same pattern as liveIp)
        // rather than parsed out of the log — log lines are the documented error-catalog
        // surface (docs/*/TROUBLESHOOTING.md), not a data channel.
        /** Resolver the server pushed, empty when it pushed none. */
        @Volatile
        @JvmField
        var liveDns: String = ""

        /** MTU actually applied to the TUN (explicit profile value or the pushed one). */
        @Volatile
        @JvmField
        var liveMtu: Int = 0

        /** Bonded streams the server allowed; 1 means single-stream. */
        @Volatile
        @JvmField
        var liveStreams: Int = 1

        /** Routes the server pushed and this client applied. */
        @Volatile
        @JvmField
        var liveRoutes: Int = 0

        /**
         * System "Always-on VPN" with "Block connections without VPN".
         *
         * The authoritative owner methods belong to a running VpnService (API 29+). The
         * Activity displays this value only after the guarded NetworkPlan has been applied.
         */
        @Volatile
        @JvmField
        var liveLockdown: Boolean = false

        /**
         * Everything else the server pushed, as applied. Route list is capped at the source
         * (see [PushedFacts]) so neither this field nor the UI can be handed an unbounded
         * list; the session token is deliberately absent.
         */
        @Volatile
        @JvmField
        var livePushed: PushedFacts = PushedFacts()
    }

    /**
     * How many pushed routes the builder took, filled while building and published after
     * `establish()` returns. `-1` until then — see [PushedFacts.routesInstalled].
     */
    private var pushedRoutesInstalled: Int = -1

    // ── lifecycle ────────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        try {
            createNotificationChannel()
        } catch (e: Exception) {
            Log.e("VpnSvc", "Failed to create notification channel: ${e.message}", e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val config = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getSerializableExtra(EXTRA_CONFIG, VpnConfig::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getSerializableExtra(EXTRA_CONFIG) as? VpnConfig
                }
                // The LAST gate, and the only one that cannot be bypassed. Every way to connect
                // — the main screen, the widget, the Quick Settings tile, boot autostart —
                // funnels into this one action, and each of them validates on its own. That
                // left correctness resting on four separate callers remembering to; the
                // original defect was exactly that (validate() ran on IMPORT, and connect /
                // always-on / boot each skipped it). Checking here means a fifth entry point
                // added later cannot silently reintroduce it.
                //
                // Not a security boundary: the service is `exported="false"` and gated behind
                // BIND_VPN_SERVICE, so no other app can send this. This is about the next
                // caller, not an attacker. (Audit 2026-07-31.)
                val rejected = config?.let { runCatching { it.validate() }.exceptionOrNull() }
                when {
                    config == null -> rejectForegroundConnect("Invalid profile: missing configuration")
                    rejected != null -> {
                        Log.e("VpnSvc", "Refusing to connect: ${rejected.message}")
                        rejectForegroundConnect("Invalid profile: ${rejected.message}")
                    }
                    else -> {
                        setConnectionDesired(true)
                        startTrustedAware(config)
                    }
                }
            }
            ACTION_DISCONNECT -> {
                userRequestedDisconnect = true
                setConnectionDesired(false)
                pausedByTrustedWifi = false
                trustedWaitConfig = null
                trustedResumeJob?.cancel()
                liveTrustedSsid = ""
                stopVpn()
            }
            ACTION_REEVALUATE_TRUSTED -> {
                // This action can be the one Android redelivers after killing the foreground
                // controller. In that fresh process the in-memory wait config is gone, so
                // rebuild it from the active profile before evaluating the current network.
                if (activeConfig != null || trustedWaitConfig != null) {
                    reevaluateTrustedWifi()
                } else if (connectionDesired()) {
                    val cfg = ProfileStore.activeProfileConfigText(this)
                        ?.let { raw ->
                            runCatching { VpnConfig.parse(raw).also { it.validate() } }.getOrNull()
                        }
                    if (cfg != null) startTrustedAware(cfg)
                    else stopVpn("No usable active profile")
                }
            }
            // Always-on VPN (Settings > Network > VPN > "Always-on", incl. "Block
            // connections without VPN"). The OS starts us with exactly this action and no
            // extras. There was no branch for it and no `else`, so the service started,
            // did nothing at all, and stopped — always-on never connected on ANY device,
            // and with lockdown enabled that left the phone with NO network whatsoever
            // (the kill switch blocks everything until a VPN that never comes up does).
            // BootReceiver's own KDoc even recommends always-on as the reliable
            // alternative to autostart, which made this the advertised path.
            // (Audit 2026-07-27, M1)
            VpnService.SERVICE_INTERFACE -> {
                // validate() too, not just parse(): always-on is the path with NO UI to show a
                // rejection, so an out-of-range saved profile would otherwise be carried all the
                // way into the tunnel. A failure lands in the same "no usable profile" branch
                // below, which does report itself. (Audit 2026-07-30, #11.)
                val cfg = ProfileStore.activeProfileConfigText(this)
                    ?.let { runCatching { VpnConfig.parse(it).also { c -> c.validate() } }.getOrNull() }
                if (cfg == null || cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST") {
                    // Nothing to connect. Say so loudly: with lockdown on, the user sees a
                    // dead network and no explanation anywhere.
                    Log.e("VpnSvc", "Always-on VPN start: no usable active profile")
                    broadcastStatus(STATUS_ERROR, "Always-on VPN: no usable profile — open Qeli and select one")
                    stopSelf()
                    return START_NOT_STICKY
                }
                broadcastLog("Always-on VPN start requested by the system")
                setConnectionDesired(true)
                // Always-on is another connect entry point, not an exemption from the local
                // Trusted Wi-Fi policy. Lockdown/kill_switch are still authoritative inside
                // startTrustedAware() and force a real TUN; plain always-on may wait exactly
                // like the app/widget/tile paths.
                startTrustedAware(cfg)
                // REDELIVER_INTENT rather than the blanket NOT_STICKY below: an always-on
                // tunnel is supposed to come back by itself if the process is killed. STICKY
                // must NOT be used — it redelivers a NULL intent, which lands in the `null`
                // branch above (stopVpn) and produces exactly the stop-loop / zombie tunnel
                // that comment warns about. REDELIVER_INTENT hands this same
                // "android.net.VpnService" intent back instead, so the restart reconnects.
                return START_REDELIVER_INTENT
            }
            null -> stopVpn()
            // Anything else is not ours: do nothing rather than tearing a live tunnel down
            // on an unrecognised action (the missing branch above is what this costs).
            else -> Log.w("VpnSvc", "Ignoring unknown service action: ${intent?.action}")
        }
        // While trusted-network automation is armed this foreground service is the durable
        // controller. REDELIVER (never STICKY/null) restores either the original config or the
        // active profile after low-memory process death. Manual Disconnect clears the desired
        // bit first, so it remains NOT_STICKY and can never resurrect a user-stopped tunnel.
        val trusted = trustedWifiSettings()
        val automationArmed = pausedByTrustedWifi || trustedPauseInFlight ||
            (trusted.enabled && trusted.ssids.isNotEmpty())
        return if (!stopping && connectionDesired() && automationArmed) {
            START_REDELIVER_INTENT
        } else {
            START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        // The user can revoke/disconnect Qeli from Android's system VPN screen instead of
        // using our UI. Treat that as the same explicit intent so trusted-network automation
        // cannot resurrect the tunnel. Do not call VpnService's default stopSelf(); stopVpn()
        // first performs the joined native/TUN teardown and then stops the service.
        userRequestedDisconnect = true
        setConnectionDesired(false)
        pausedByTrustedWifi = false
        trustedWaitConfig = null
        trustedResumeJob?.cancel()
        liveTrustedSsid = ""
        stopVpn()
    }

    override fun onDestroy() {
        // Normal destruction happens only after stopVpn has joined the native runner and called
        // stopSelf. If Android destroys us independently, do the strongest synchronous cleanup
        // available; process death is the final descriptor boundary after this callback.
        if (transportCore != null || vpnInterface != null) {
            val core = transportCore
            runCatching { core?.stop() }
            supervisor?.cancel()
            try { vpnInterface?.close() } catch (_: Exception) {}
            vpnInterface = null
            transportCore = null
            runCatching { core?.close() }
        }
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        wakeLock = null
        unregisterNetworkCallback()
        unregisterScreenReceiver()
        trustedResumeJob?.cancel()
        teardownSupervisor.cancel()
        synchronized(carrierDnsLock) {
            carrierDnsRequests.values.forEach { it.future.cancel(true) }
            carrierDnsRequests.clear()
        }
        carrierDnsExecutor.shutdownNow()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(CHANNEL_ID, s(R.string.notif_channel_name), NotificationManager.IMPORTANCE_LOW))
    }

    /**
     * Resolve a string in the language the user picked in Settings.
     *
     * Not just `getString`: the app forces its locale in MainActivity.attachBaseContext,
     * but that only wraps the *Activity* — this Service keeps the device locale, so its
     * notification would sit in the phone's language while the rest of the UI is in the
     * chosen one. Wrap the same way here (mirrors QeliApp.wrap).
     */
    private fun s(resId: Int, vararg args: Any): String {
        val cfg = android.content.res.Configuration(resources.configuration)
        cfg.setLocale(java.util.Locale.forLanguageTag(QeliApp.language(this)))
        val ctx = createConfigurationContext(cfg)
        return if (args.isEmpty()) ctx.getString(resId) else ctx.getString(resId, *args)
    }

    private fun showNotification(text: String): Boolean {
        return try {
            val tapIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val pendingIntent = PendingIntent.getActivity(
                this, 0, tapIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            // "Disconnect" action → stop the tunnel from the notification shade without opening the app.
            val disconnectPending = PendingIntent.getService(
                this, 1, Intent(this, VpnServiceImpl::class.java).setAction(ACTION_DISCONNECT),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notification = Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Qeli")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .addAction(Notification.Action.Builder(
                    android.graphics.drawable.Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    s(R.string.disconnect), disconnectPending).build())
                .build()
            startForeground(NOTIFICATION_ID, notification)
            true
        } catch (e: Exception) {
            Log.e("VpnSvc", "startForeground failed: ${e.javaClass.simpleName}: ${e.message}", e)
            false
        }
    }

    /** Satisfy startForegroundService's promotion contract even when the final config gate
     * rejects the request before a tunnel generation exists. A live/waiting controller must
     * remain untouched; only a fresh, otherwise-idle service instance is stopped here. */
    private fun rejectForegroundConnect(message: String) {
        Log.e("VpnSvc", message)
        broadcastStatus(STATUS_ERROR, message)
        if (transportCore == null && vpnInterface == null && transportJob?.isActive != true &&
            !pausedByTrustedWifi && !trustedPauseInFlight) {
            showNotification(message)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopping = true
            stopSelf()
        }
    }

    private data class TrustedWifiSettings(val enabled: Boolean, val ssids: List<String>)

    private fun trustedWifiSettings(): TrustedWifiSettings {
        val prefs = getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
        return TrustedWifiSettings(
            enabled = prefs.getBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false),
            ssids = TrustedWifiPolicy.parse(
                prefs.getString(MainActivity.PREF_TRUSTED_WIFI_SSIDS, ""),
            ),
        )
    }

    private fun connectionDesired(): Boolean =
        getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
            .getBoolean(MainActivity.PREF_CONNECTION_DESIRED, false)

    private fun setConnectionDesired(desired: Boolean) {
        getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(MainActivity.PREF_CONNECTION_DESIRED, desired)
            .apply()
    }

    @Suppress("DEPRECATION")
    private fun observedWifiSsid(caps: NetworkCapabilities): String? {
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return null
        val fromCapabilities = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            (caps.transportInfo as? WifiInfo)?.ssid
        } else {
            null
        }
        if (TrustedWifiPolicy.normalizeObservedSsid(fromCapabilities) != null) return fromCapabilities
        return runCatching {
            getSystemService(WifiManager::class.java)?.connectionInfo?.ssid
        }.getOrNull()
    }

    private fun classifyNetwork(caps: NetworkCapabilities?): TrustedWifiPolicy.NetworkKind {
        val settings = trustedWifiSettings()
        return TrustedWifiPolicy.classify(
            enabled = settings.enabled,
            configuredSsids = settings.ssids,
            hasNetwork = caps != null,
            isWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true,
            observedSsid = caps?.let(::observedWifiSsid),
        )
    }

    /** Used before Builder.establish(), while Android's active network is still physical. */
    private fun currentNetworkKind(): TrustedWifiPolicy.NetworkKind {
        val cm = getSystemService(ConnectivityManager::class.java)
            ?: return TrustedWifiPolicy.NetworkKind.NO_NETWORK
        val network = currentNetwork ?: runCatching { cm.activeNetwork }.getOrNull()
            ?: return TrustedWifiPolicy.NetworkKind.NO_NETWORK
        val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull()
        return classifyNetwork(caps)
    }

    private fun currentTrustedSsid(): String {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return ""
        val network = currentNetwork ?: runCatching { cm.activeNetwork }.getOrNull() ?: return ""
        val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: return ""
        return TrustedWifiPolicy.normalizeObservedSsid(observedWifiSsid(caps)).orEmpty()
    }

    private fun startTrustedAware(config: VpnConfig) {
        trustedWaitConfig = config
        userRequestedDisconnect = false
        // A requested/system lockdown cannot coexist with an intentionally absent TUN.
        val pauseAllowed = TrustedWifiPolicy.canPause(
            configKillSwitch = config.killSwitch,
            systemLockdown = preEstablishmentLockdownState().second,
        )
        if (!pauseAllowed) {
            startVpn(config)
            return
        }
        if (currentNetworkKind() == TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI) {
            enterTrustedWifiWait(config, currentTrustedSsid())
        } else {
            startVpn(config)
        }
    }

    private fun enterTrustedWifiWait(config: VpnConfig, ssid: String) {
        trustedWaitConfig = config
        liveTrustedSsid = ssid
        trustedResumeJob?.cancel()
        if (trustedPauseInFlight) return
        // Capability callbacks continue while waiting. Re-registering from inside every
        // callback produces an unregister/register/onAvailable loop on several Android builds.
        if (pausedByTrustedWifi && !trustedPauseInFlight && netCallback != null) return
        if (transportCore != null || vpnInterface != null || transportJob?.isActive == true) {
            pauseTunnelForTrustedWifi(config, ssid)
            return
        }
        pausedByTrustedWifi = true
        trustedPauseInFlight = false
        stopping = false
        if (!registerNetworkCallback()) {
            // Waiting without an observer is a permanent fail-open state: after leaving this
            // SSID nothing can restore the TUN. Keep privacy protection up when Android/OEM
            // refuses the callback, even though that means Trusted Wi-Fi pause is unavailable.
            pausedByTrustedWifi = false
            trustedWaitConfig = null
            liveTrustedSsid = ""
            broadcastLog("Trusted Wi-Fi pause unavailable: no network observer; keeping VPN active")
            startVpn(config)
            return
        }
        if (!showNotification(
                s(R.string.notif_trusted_wifi, ssid.ifBlank { s(R.string.trusted_wifi_unknown) })
            )) {
            pausedByTrustedWifi = false
            stopVpn("Notification permission denied")
            return
        }
        broadcastStatus(STATUS_WAITING_TRUSTED)
    }

    @Synchronized
    private fun pauseTunnelForTrustedWifi(config: VpnConfig, ssid: String) {
        if (trustedPauseInFlight || pausedByTrustedWifi) return
        trustedPauseInFlight = true
        trustedWaitConfig = config
        liveTrustedSsid = ssid
        stopping = true
        teardownJob = teardownScope.launch {
            teardownAndWait(keepNetworkObserver = true)
            try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
            wakeLock = null
            liveIp = ""
            liveConnectedAt = 0L
            liveDns = ""
            liveMtu = 0
            liveStreams = 1
            liveRoutes = 0
            liveLockdown = false
            livePushed = PushedFacts()
            pushedRoutesInstalled = -1
            liveBytesUp = 0L
            liveBytesDown = 0L
            withContext(Dispatchers.Main.immediate) {
                stopping = false
                trustedPauseInFlight = false
                // Disconnect can arrive while the native runner is being joined. stopVpn()
                // intentionally cannot start a second teardown then, so honor the persisted
                // user intent at this single completion point instead of publishing WAITING.
                if (!connectionDesired()) {
                    pausedByTrustedWifi = false
                    stopVpn()
                    return@withContext
                }
                pausedByTrustedWifi = true
                // The handoff may finish after the phone has already left Wi-Fi (or after the
                // user removed this SSID in Settings). Re-evaluate now because callbacks that
                // arrived during teardown saw `pausedByTrustedWifi == false` and could not arm
                // the resume job yet.
                val pauseAllowed = TrustedWifiPolicy.canPause(
                    configKillSwitch = config.killSwitch,
                    systemLockdown = preEstablishmentLockdownState().second,
                )
                val observerAvailable = netCallback != null || registerNetworkCallback()
                when (TrustedWifiPolicy.pauseCompletionAction(
                    connectionDesired = connectionDesired(),
                    pauseAllowed = pauseAllowed,
                    networkKind = currentNetworkKind(),
                    observerAvailable = observerAvailable,
                )) {
                    TrustedWifiPolicy.PauseCompletionAction.STOP -> {
                        pausedByTrustedWifi = false
                        stopVpn()
                        return@withContext
                    }
                    TrustedWifiPolicy.PauseCompletionAction.RESUME -> {
                        if (!observerAvailable)
                            broadcastLog("Trusted Wi-Fi observer was lost; restoring VPN fail-closed")
                        scheduleTrustedResume(
                            250L,
                            resumeEvenIfTrusted = !pauseAllowed || !observerAvailable,
                        )
                        return@withContext
                    }
                    TrustedWifiPolicy.PauseCompletionAction.RESUME_AFTER_REDACTION -> {
                        scheduleTrustedResume(2_000L)
                        return@withContext
                    }
                    TrustedWifiPolicy.PauseCompletionAction.WAIT -> Unit
                }
                if (!showNotification(
                        s(R.string.notif_trusted_wifi, ssid.ifBlank { s(R.string.trusted_wifi_unknown) }),
                    )) {
                    pausedByTrustedWifi = false
                    stopVpn("Notification permission denied")
                    return@withContext
                }
                broadcastStatus(STATUS_WAITING_TRUSTED)
            }
        }
    }

    private fun scheduleTrustedResume(delayMs: Long, resumeEvenIfTrusted: Boolean = false) {
        if (!pausedByTrustedWifi || !connectionDesired()) return
        trustedResumeJob?.cancel()
        trustedResumeJob = teardownScope.launch {
            delay(delayMs)
            val kind = currentNetworkKind()
            if (!TrustedWifiPolicy.shouldResumeAfterDelay(kind, resumeEvenIfTrusted) ||
                !pausedByTrustedWifi || !connectionDesired()) return@launch
            val config = trustedWaitConfig ?: ProfileStore.activeProfileConfigText(this@VpnServiceImpl)
                ?.let { runCatching { VpnConfig.parse(it).also { value -> value.validate() } }.getOrNull() }
            if (config == null) {
                withContext(Dispatchers.Main.immediate) { stopVpn("No usable active profile") }
                return@launch
            }
            withContext(Dispatchers.Main.immediate) {
                pausedByTrustedWifi = false
                trustedPauseInFlight = false
                liveTrustedSsid = ""
                broadcastLog(
                    if (resumeEvenIfTrusted)
                        "Trusted Wi-Fi pause is no longer safe — restoring the previous connection"
                    else
                        "Left trusted Wi-Fi — restoring the previous connection"
                )
                startVpn(config)
            }
        }
    }

    private fun reevaluateTrustedWifi(caps: NetworkCapabilities? = null) {
        if (!connectionDesired()) return
        val kind = caps?.let(::classifyNetwork) ?: currentNetworkKind()
        when (kind) {
            TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI -> {
                val config = activeConfig ?: trustedWaitConfig ?: return
                val pauseAllowed = TrustedWifiPolicy.canPause(
                    configKillSwitch = config.killSwitch,
                    systemLockdown = preEstablishmentLockdownState().second,
                )
                if (!pauseAllowed) {
                    // The initial connect path already has this guard. Repeat it here because a
                    // Settings edit or network callback can otherwise dismantle a live lockdown
                    // tunnel. If we were already waiting, restore the TUN even though the SSID is
                    // still trusted; Android's lockdown contract is authoritative.
                    if (pausedByTrustedWifi) {
                        scheduleTrustedResume(250L, resumeEvenIfTrusted = true)
                    }
                    return
                }
                val ssid = caps?.let(::observedWifiSsid)
                    ?.let(TrustedWifiPolicy::normalizeObservedSsid)
                    .orEmpty()
                    .ifBlank(::currentTrustedSsid)
                enterTrustedWifiWait(config, ssid)
            }
            TrustedWifiPolicy.NetworkKind.OTHER_NETWORK -> scheduleTrustedResume(250L)
            // Missing/redacted SSID is never allowed to keep VPN suppressed. The short delay
            // absorbs Android's transient redaction while a Wi-Fi handoff is still settling.
            TrustedWifiPolicy.NetworkKind.UNKNOWN_WIFI -> scheduleTrustedResume(2_000L)
            TrustedWifiPolicy.NetworkKind.NO_NETWORK -> Unit
        }
    }

    private fun startVpn(config: VpnConfig) {
        if (stopping || teardownJob?.isActive == true) {
            broadcastLog("Connect ignored while the previous VPN is still disconnecting")
            return
        }
        if (transportCore != null || vpnInterface != null || transportJob?.isActive == true) {
            broadcastLog("Connect ignored because a VPN generation is already active")
            return
        }
        // Android owns the only kill switch that survives this process: Always-on VPN with
        // "Block connections without VPN". A profile may request it, but the app cannot turn
        // the system policy on. Bind the portable config flag to the observable OS state and
        // refuse to connect unless the guarantee is already active. This check happens before
        // tearing down an existing generation and is repeated when the authenticated plan is
        // applied, closing the Settings-change race between connect and NetworkPlan ACK.
        val killSwitchReadiness = currentKillSwitchReadiness(config)
        val killSwitchError = killSwitchError(killSwitchReadiness)
        if (killSwitchError != null) {
            Log.e("VpnSvc", "Refusing unprotected kill-switch connection: $killSwitchError")
            broadcastLog("SECURITY: $killSwitchError")
            broadcastStatus(STATUS_ERROR, killSwitchError)
            // ACTION_CONNECT arrives through startForegroundService on current Android. Keep
            // the promotion contract, then stop this rejected foreground instance so Android
            // can start it normally after the user changes the system policy. The next retry
            // recomputes the prepared-provider + secure-lockdown proof from live state.
            showNotification(killSwitchError)
            if (transportCore == null && vpnInterface == null) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopping = true // onDestroy must not replace the visible ERROR with DISCONNECTED
                stopSelf()
            }
            return
        }
        when (killSwitchReadiness) {
            AndroidKillSwitchReadiness.READY -> broadcastLog(s(R.string.kill_switch_active))
            AndroidKillSwitchReadiness.SPLIT_TUNNEL_IGNORED ->
                broadcastLog(s(R.string.kill_switch_split_ignored))
            else -> Unit
        }

        // The guards above require the previous generation to be fully gone. This is
        // what prevents "Disconnect then Connect" from overlapping two scopes/TUNs.
        stopping = false
        pausedByTrustedWifi = false
        trustedPauseInFlight = false
        liveTrustedSsid = ""
        userRequestedDisconnect = false
        activeConfig = config
        nativeFatalError = null
        var initialCoreEvents: List<TransportCoreEvent> = emptyList()
        transportCore = runCatching {
            val stableDeviceId = deviceId()
            val core = try {
                TransportCore.create(
                    config.toTransportCoreIni(),
                    deviceId = stableDeviceId,
                    platformCapabilities = TransportCore.PLATFORM_ROUTES or
                        TransportCore.PLATFORM_DNS or
                        TransportCore.PLATFORM_TUN_FD or
                        TransportCore.PLATFORM_SOCKET_PROTECT or
                        TransportCore.PLATFORM_SERVER_IDENTITY or
                        (if (killSwitchReadiness == AndroidKillSwitchReadiness.READY)
                            TransportCore.PLATFORM_KILL_SWITCH else 0L),
                )
            } finally {
                stableDeviceId.fill(0)
            }
            try {
                core.start()
                val lifecycle = core.drainEvents()
                check(lifecycle.filter {
                    it.kind == TransportCoreEventCodec.KIND_STATE_CHANGED
                }.map { it.state } == listOf(
                    TransportCore.STATE_CREATED,
                    TransportCore.STATE_CONNECTING,
                )) { "unexpected transport core lifecycle events" }
                initialCoreEvents = lifecycle.filter {
                    it.kind != TransportCoreEventCodec.KIND_STATE_CHANGED
                }
                core
            } catch (error: Throwable) {
                try { core.close() } catch (_: Throwable) {}
                throw error
            }
        }.getOrElse { error ->
            broadcastLog("ERROR: native transport core unavailable (${error.message})")
            null
        }
        if (transportCore == null) {
            activeConfig = null
            rejectForegroundConnect("Native transport core unavailable")
            return
        }
        transportCore?.let { core ->
            debugLog(
                "Shared native transport active: ABI 0x" +
                    TransportCore.abiVersion().toUInt().toString(16) +
                    ", state=${core.state()}, lifecycle events drained"
            )
        }
        broadcastLog("Service started: ${config.protocol.uppercase()}/${config.wireMode}" +
            if (config.isUdp && config.quicEnabled) "+QUIC" else "")
        broadcastLog(
            "Connecting to ${logValue(config.serverAddress)}:${config.port} " +
                "as user '${logValue(config.username)}'"
        )
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Qeli::TunnelLock")
            // No timeout: the lock is bounded by the foreground-service lifecycle and is
            // always released in stopVpn(). A 12h timeout used to let the CPU sleep after
            // 12h on a long-lived session, silently stalling the data plane until traffic
            // woke the device again.
            wakeLock?.acquire()
        } catch (e: Exception) {
            Log.e("VpnSvc", "WakeLock failed: ${e.message}", e)
        }

        supervisor = SupervisorJob()
        coroutineScope = CoroutineScope(supervisor!! + Dispatchers.IO)
        transportCore?.let { core -> launchTransportCoreEventPump(core, initialCoreEvents) }
        registerNetworkCallback()
        registerScreenReceiver()
        broadcastStatus(STATUS_CONNECTING)

        if (!showNotification(s(R.string.notif_connecting))) {
            stopVpn("Notification permission denied")
            return
        }

        // Publish the Job before it can enter JNI. Otherwise an immediate native failure
        // can call stopVpn before teardown has a runner to join.
        val runner = coroutineScope!!.launch(start = CoroutineStart.LAZY) {
            try {
                connectWithRetry(config)
            } catch (e: kotlinx.coroutines.CancellationException) {
                // normal teardown — ignore
            } catch (e: Exception) {
                Log.e("VpnSvc", "Unhandled: ${e.message}", e)
                broadcastLog("FATAL: ${e.javaClass.simpleName}: ${e.message}")
                stopVpn(e.message ?: "VPN service failed")
            }
        }
        transportJob = runner
        runner.start()
    }

    private fun launchTransportCoreEventPump(
        core: TransportCore,
        initialEvents: List<TransportCoreEvent> = emptyList(),
    ) {
        val scope = coroutineScope ?: return
        scope.launch {
            var pollDelayMs = TRANSPORT_CORE_POLL_MIN_MS
            try {
                initialEvents.forEach { event -> dispatchTransportCoreEvent(core, event) }
                while (currentCoroutineContext().isActive && transportCore === core) {
                    val event = core.pollEvent()
                    if (event == null) {
                        delay(pollDelayMs)
                        pollDelayMs = (pollDelayMs * 2).coerceAtMost(TRANSPORT_CORE_POLL_MAX_MS)
                        continue
                    }
                    pollDelayMs = TRANSPORT_CORE_POLL_MIN_MS
                    // One event that cannot be answered must not end the loop. This dispatcher
                    // is the ONLY thing that answers protect()/plan/identity requests, so
                    // killing it does not fail one generation — it fails every generation from
                    // then on (PLATFORM_REJECTED, rc=-10) until the service is restarted by
                    // hand. Each event has already been consumed by pollEvent, so continuing
                    // cannot spin on the same failure.
                    try {
                        dispatchTransportCoreEvent(core, event)
                    } catch (error: kotlinx.coroutines.CancellationException) {
                        throw error
                    } catch (error: Throwable) {
                        broadcastLog(
                            "WARN: transport event ${event.kind} not handled " +
                                "(${error.message}) — the tunnel keeps retrying"
                        )
                    }
                }
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Throwable) {
                if (transportCore === core) {
                    broadcastLog("ERROR: native transport event dispatcher failed (${error.message})")
                    runCatching { core.stop() }
                }
            }
        }
        debugLog("Native transport platform dispatcher active")
    }

    private fun dispatchTransportCoreEvent(core: TransportCore, event: TransportCoreEvent) {
        when (event.kind) {
            TransportCoreEventCodec.KIND_STATE_CHANGED ->
                Log.d("VpnSvc", "Shared transport core state=${event.state}")
            TransportCoreEventCodec.KIND_SOCKET_PROTECT -> {
                val outcome = TransportCoreEventDispatcher.protectSocket(
                    event,
                    attempt = { fd -> protect(fd) },
                    beforeRetry = {
                        try {
                            Thread.sleep(100)
                        } catch (error: InterruptedException) {
                            Thread.currentThread().interrupt()
                            throw error
                        }
                    },
                )
                core.socketProtectResult(outcome.sequence, outcome.protected, outcome.reason)
                if (!outcome.protected) {
                    broadcastLog("ERROR: ${outcome.reason ?: "socket protection rejected"}")
                }
            }
            TransportCoreEventCodec.KIND_SERVER_IDENTITY -> {
                val outcome = TransportCoreEventDispatcher.verifyServerIdentity(event) {
                        serverId, publicKey ->
                    if (!checkKnownHost(serverId, publicKey)) {
                        // Rust emits this event only after the peer proves possession of the
                        // key, so persisting here cannot be poisoned by an unauthenticated reply.
                        try {
                            recordKnownHost(serverId, publicKey)
                        } catch (error: SecurityException) {
                            if (activeConfig?.allowUnpinnedTofu != true) throw error
                            broadcastLog(
                                "WARN: ${error.message}; continuing unpinned because " +
                                    "allow_unpinned_tofu = true"
                            )
                        }
                    }
                }
                if (!outcome.trusted) {
                    nativeFatalError = SecurityException(
                        outcome.reason ?: "server identity rejected"
                    )
                }
                core.serverIdentityResult(outcome.sequence, outcome.trusted, outcome.reason)
            }
            TransportCoreEventCodec.KIND_ERROR -> {
                val message = if (event.payloadFormat == TransportCoreEventCodec.PAYLOAD_UTF8) {
                    event.payload.toString(Charsets.UTF_8).take(512)
                } else {
                    "malformed error payload"
                }
                broadcastLog("Native transport error ${event.errorCode}: $message")
            }
            TransportCoreEventCodec.KIND_NETWORK_PLAN -> applyNativeNetworkPlan(core, event)
            else -> throw IllegalStateException("unknown transport core event ${event.kind}")
        }
    }

    /** Execute the authenticated Rust plan with Android APIs, then transfer a duplicate of
     * the established TUN to the native packet pump before acknowledging Running. */
    private fun applyNativeNetworkPlan(core: TransportCore, event: TransportCoreEvent) {
        val plan = TransportCoreEventCodec.decodeNetworkPlan(event)
        val username = activeConfig?.username?.let(::logValue) ?: "?"
        broadcastLog("Auth OK: user='$username', IP ${plan.tunnelAddress}")
        plan.connectionLog.forEach(::broadcastLog)
        val config = activeConfig
        if (config == null || transportCore !== core) {
            runCatching {
                core.networkPlanResult(plan.generation, false, "VPN service is stopping")
            }
            return
        }
        var tun: ParcelFileDescriptor? = null
        var acknowledged = false
        try {
            check(plan.fullTunnel == config.isFullTunnel) {
                "native plan routing mode differs from the active profile"
            }
            val expectedKillSwitch = config.killSwitch && config.isFullTunnel
            check(plan.killSwitch == expectedKillSwitch) {
                "native plan kill-switch differs from the active profile"
            }
            if (plan.killSwitch) {
                val readiness = currentKillSwitchReadiness(config)
                check(readiness == AndroidKillSwitchReadiness.READY) {
                    killSwitchError(readiness) ?: "Android lockdown changed"
                }
            }
            val unsupportedDns = plan.dnsServers.firstOrNull { it.port != 53 }
            check(unsupportedDns == null) {
                "Android VpnService cannot apply DNS ${unsupportedDns?.address}:${unsupportedDns?.port}; only port 53 is supported"
            }
            liveDns = plan.dnsServers.firstOrNull()?.address.orEmpty()
            liveMtu = plan.mtu
            liveRoutes = plan.routes.size
            liveStreams = plan.maxStreams
            livePushed = PushedFacts(
                routes = plan.pushedRoutes.take(PushedFacts.ROUTE_SAMPLE),
                routeCount = plan.pushedRoutes.size,
                multipathAdaptive = plan.adaptive,
                paddingEnabled = plan.dataPlane.paddingEnabled,
                paddingMin = plan.dataPlane.paddingMin,
                paddingMax = plan.dataPlane.paddingMax,
                heartbeatEnabled = plan.dataPlane.heartbeatEnabled,
                heartbeatIntervalMs = plan.dataPlane.heartbeatIntervalMs,
                shapingEnabled = plan.dataPlane.shapingEnabled,
            )
            tun = setupTunInterface(config, plan)
            vpnInterface = tun
            if (plan.killSwitch) {
                // Before establish(), Android's public isAlwaysOn/isLockdownEnabled calls
                // deliberately return false because the app is not yet the current VPN owner.
                // Once Builder.establish() succeeds they become the strongest possible check:
                // require both live owner flags before giving Rust the TUN or ACKing the plan.
                val readiness = currentKillSwitchReadiness(config, requireEstablishedOwner = true)
                check(readiness == AndroidKillSwitchReadiness.READY) {
                    killSwitchError(readiness) ?: "Android lockdown changed during TUN setup"
                }
            }
            liveLockdown = currentOwnerLockdownState().second
            core.setTunFd(plan.generation, tun.fd)
            core.networkPlanResult(plan.generation, applied = true)
            acknowledged = true
            broadcastLog(
                "Native NetworkPlan ${plan.generation} APPLIED: mode=" +
                    "${if (plan.fullTunnel) "full" else "split"} " +
                    "address=${plan.tunnelAddress}/${plan.prefixLength} mtu=${plan.mtu} " +
                    "dns=${plan.dnsServers.joinToString { "${it.address}:${it.port}" }.ifEmpty { "system unchanged" }} " +
                    "pushed_routes=$pushedRoutesInstalled/${plan.pushedRoutes.size} " +
                    "plan_routes=${plan.routes.size}; Rust owns the TUN payload"
            )
            announceConnected(plan.tunnelAddress)
        } catch (error: Throwable) {
            if (!acknowledged) {
                runCatching {
                    core.networkPlanResult(
                        plan.generation,
                        applied = false,
                        reason = error.message ?: "Android failed to apply NetworkPlan",
                    )
                }
            }
            try { tun?.close() } catch (_: Throwable) {}
            if (vpnInterface === tun) vpnInterface = null
            broadcastLog("ERROR: Native NetworkPlan ${plan.generation} failed: ${error.message}")
        }
    }

    /**
     * The public owner checks are authoritative after Builder.establish(). AOSP intentionally
     * returns false before that point: VpnManagerService.getVpnIfOwner() has no owner UID until
     * an interface exists. Keep failures visible instead of silently weakening the policy.
     */
    private fun currentOwnerLockdownState(): Pair<Boolean, Boolean> {
        // Both public owner-state APIs were added in API 29.  runCatching only handles a
        // runtime exception; it is not an SDK availability guard and lintRelease correctly
        // rejects an unconditional reference when minSdk is 28.  Older Android versions are
        // already fail-closed by AndroidKillSwitchPolicy as LOCKDOWN_NOT_OBSERVABLE.
        if (Build.VERSION.SDK_INT < AndroidKillSwitchPolicy.LOCKDOWN_STATUS_API) {
            return false to false
        }
        val alwaysOn = runCatching { isAlwaysOn }.getOrElse { error ->
            Log.w("VpnSvc", "Cannot query Android Always-on owner state", error)
            false
        }
        val lockdown = runCatching { isLockdownEnabled }.getOrElse { error ->
            Log.w("VpnSvc", "Cannot query Android lockdown owner state", error)
            false
        }
        return alwaysOn to lockdown
    }

    /**
     * Pre-establishment proof uses only public/readable system contracts:
     *  - VpnService.prepare(this) == null proves Qeli is the currently prepared VPN provider;
     *  - always_on_vpn_lockdown is a read-only-to-apps Settings.Secure policy owned by Android.
     * Android cannot set lockdown without an Always-on package, so their conjunction proves that
     * this prepared provider is protected. The owner APIs are rechecked after establish().
     */
    private fun preEstablishmentLockdownState(): Pair<Boolean, Boolean> {
        if (Build.VERSION.SDK_INT < AndroidKillSwitchPolicy.LOCKDOWN_STATUS_API) {
            return false to false
        }
        val prepared = runCatching { VpnService.prepare(this) == null }.getOrElse { error ->
            Log.w("VpnSvc", "Cannot verify the prepared Android VPN provider", error)
            false
        }
        val lockdownPolicy = runCatching {
            Settings.Secure.getInt(contentResolver, "always_on_vpn_lockdown", 0) == 1
        }.getOrElse { error ->
            Log.w("VpnSvc", "Cannot read Android Always-on lockdown policy", error)
            false
        }
        return prepared to (prepared && lockdownPolicy)
    }

    private fun currentKillSwitchReadiness(
        config: VpnConfig,
        requireEstablishedOwner: Boolean = false,
    ): AndroidKillSwitchReadiness {
        val (alwaysOn, lockdown) = if (requireEstablishedOwner) {
            currentOwnerLockdownState()
        } else {
            preEstablishmentLockdownState()
        }
        return AndroidKillSwitchPolicy.evaluate(
            requested = config.killSwitch,
            fullTunnel = config.isFullTunnel,
            apiLevel = Build.VERSION.SDK_INT,
            alwaysOn = alwaysOn,
            lockdown = lockdown,
        )
    }

    private fun killSwitchError(readiness: AndroidKillSwitchReadiness): String? = when (readiness) {
        AndroidKillSwitchReadiness.LOCKDOWN_NOT_OBSERVABLE -> s(R.string.kill_switch_android_too_old)
        AndroidKillSwitchReadiness.ALWAYS_ON_DISABLED -> s(R.string.kill_switch_enable_always_on)
        AndroidKillSwitchReadiness.LOCKDOWN_DISABLED -> s(R.string.kill_switch_enable_lockdown)
        else -> null
    }

    /** One generation of the synchronous Rust owner plus Android UI statistics polling. */
    private suspend fun runNativeTransport(config: VpnConfig, carrierGeneration: Int) {
        val core = transportCore ?: throw IllegalStateException("native transport is unavailable")
        if (core.state() != TransportCore.STATE_CONNECTING) {
            core.stop()
            core.start()
        }
        // Explicit dns_servers or the authenticated server push are the only sources.
        val fallbackDns = emptyList<String>()
        val carrierAddresses = resolvePhysicalCarrierAddresses(config, carrierGeneration)
        debugLog("Physical carrier candidates: ${carrierAddresses.joinToString(", ")}")
        nativeFatalError = null
        kotlinx.coroutines.coroutineScope {
            val statsJob = launch {
                var previous = core.stats()
                var previousAt = SystemClock.elapsedRealtime()
                var reportedKernelDrops = previous.udpKernelDrops
                var reportedInternalDrops = previous.udpInternalDrops
                var lastTelemetryAt = previousAt
                var udpReadyLogged = false
                while (currentCoroutineContext().isActive && transportCore === core) {
                    delay(1000)
                    val current = runCatching { core.stats() }.getOrElse { break }
                    val now = SystemClock.elapsedRealtime()
                    val elapsed = (now - previousAt).coerceAtLeast(1)
                    liveBytesUp = current.txBytes
                    liveBytesDown = current.rxBytes
                    broadcastStats(
                        (current.txBytes - previous.txBytes).coerceAtLeast(0) * 1000 / elapsed,
                        (current.rxBytes - previous.rxBytes).coerceAtLeast(0) * 1000 / elapsed,
                        current.txBytes,
                        current.rxBytes,
                    )
                    if (current.udpKernelDrops < previous.udpKernelDrops ||
                        current.udpInternalDrops < previous.udpInternalDrops ||
                        current.udpBufferGrows < previous.udpBufferGrows
                    ) {
                        reportedKernelDrops = 0
                        reportedInternalDrops = 0
                        lastTelemetryAt = now
                        udpReadyLogged = false
                    }
                    val changed = current.udpRecvBufferBytes != previous.udpRecvBufferBytes ||
                        current.udpKernelDrops != previous.udpKernelDrops ||
                        current.udpInternalDrops != previous.udpInternalDrops ||
                        current.udpBufferGrows != previous.udpBufferGrows
                    val grew = current.udpBufferGrows > previous.udpBufferGrows
                    if (!udpReadyLogged && current.udpRecvBufferBytes > 0) {
                        broadcastLog("UDP ready: receive buffer ${current.udpRecvBufferBytes / 1024} KiB")
                        udpReadyLogged = true
                    } else if (grew) {
                        broadcastLog(
                            "UDP receive buffer grew to ${current.udpRecvBufferBytes / 1024} KiB " +
                                "(growths=${current.udpBufferGrows})"
                        )
                    }
                    val pendingKernel = (current.udpKernelDrops - reportedKernelDrops).coerceAtLeast(0)
                    val pendingInternal = (current.udpInternalDrops - reportedInternalDrops).coerceAtLeast(0)
                    val detailed = detailedLog(config)
                    val reportDetailed = detailed && changed && now - lastTelemetryAt >= 5_000
                    val reportCompact = !detailed && (pendingKernel > 0 || pendingInternal > 0) &&
                        (pendingKernel + pendingInternal >= 32 || now - lastTelemetryAt >= 30_000)
                    if (reportDetailed || reportCompact) {
                        val prefix = if (detailed) "UDP telemetry" else "WARN: UDP packet loss"
                        broadcastLog(
                            "$prefix: kernel +$pendingKernel (${current.udpKernelDrops} total), " +
                                "internal +$pendingInternal (${current.udpInternalDrops} total), " +
                                "buffer=${current.udpRecvBufferBytes / 1024} KiB, " +
                                "grows=${current.udpBufferGrows}"
                        )
                        reportedKernelDrops = current.udpKernelDrops
                        reportedInternalDrops = current.udpInternalDrops
                        lastTelemetryAt = now
                    }
                    previous = current
                    previousAt = now
                }
            }
            val result = try {
                core.runTransport(fallbackDns, carrierAddresses)
            } finally {
                statsJob.cancel()
            }
            nativeFatalError?.let { fatal ->
                nativeFatalError = null
                throw fatal
            }
            if (!currentCoroutineContext().isActive) {
                throw kotlinx.coroutines.CancellationException("VPN service stopped")
            }
            if (result != 0) {
                throw IllegalStateException("native transport generation failed (rc=$result)")
            }
            throw IllegalStateException("native transport generation stopped")
        }
    }

    /**
     * Resolve every A record through Android's selected non-VPN Network. `InetAddress` and
     * Tokio's system resolver may be captured by the retained TUN during reconnect, creating
     * an infinite DNS/reconnect loop. Network.getAllByName is explicitly bound to the physical
     * link. Rotate the stable answer set between generations so UDP (whose connect is local and
     * cannot prove reachability) also fails over after a dead first address.
     */
    private suspend fun resolvePhysicalCarrierAddresses(
        config: VpnConfig,
        generation: Int,
    ): List<String> = withContext(Dispatchers.IO) {
        val cm = getSystemService(ConnectivityManager::class.java)
            ?: throw IllegalStateException("ConnectivityManager is unavailable")
        val selected = currentNetwork
            ?: cm.activeNetwork?.takeIf { usableCarrierNetwork(cm, it) }
            // `currentNetwork` is null between onLost and the next onAvailable, and while the
            // fail-closed TUN is retained `activeNetwork` is our OWN vpn — so both of the
            // lookups above come back empty exactly when a network change needs them most,
            // and every retry died here until a new best match happened to arrive. Ask the
            // framework for the whole list instead of the one network it thinks is active.
            ?: firstUsableCarrierNetwork(cm)
            ?: throw IllegalStateException("No physical network is available for carrier DNS")
        val timeoutMs = config.connectionTimeoutSecs.coerceIn(1, 30) * 1000L
        val key = "${selected.networkHandle}:${config.serverAddress}"
        val request = synchronized(carrierDnsLock) {
            carrierDnsRequests.entries.removeAll { (requestKey, request) ->
                requestKey != key && request.future.isDone
            }
            carrierDnsRequests[key] ?: run {
                if (carrierDnsRequests.size >= MAX_CARRIER_DNS_REQUESTS) {
                    throw IllegalStateException(
                        "Too many physical-network DNS lookups are still blocked; " +
                            "cannot resolve ${config.serverAddress} on the current network",
                    )
                }
                CarrierDnsRequest(
                    key = key,
                    deadlineAt = SystemClock.elapsedRealtime() + timeoutMs,
                    future = carrierDnsExecutor.submit<List<String>> {
                        selected.getAllByName(config.serverAddress)
                            .filterIsInstance<Inet4Address>()
                            .mapNotNull { it.hostAddress }
                            .distinct()
                    },
                ).also { carrierDnsRequests[key] = it }
            }
        }
        val addresses = try {
            if (request.future.isDone) {
                request.future.get()
            } else {
                val remainingMs = request.deadlineAt - SystemClock.elapsedRealtime()
                if (remainingMs <= 0L) throw TimeoutException("carrier DNS deadline expired")
                request.future.get(remainingMs, TimeUnit.MILLISECONDS)
            }
        } catch (error: TimeoutException) {
            // Do not call Future.cancel(): getAllByName ignores interruption on affected
            // Android builds, while Future would still become isDone immediately and let a
            // retry create another stuck worker. Retain this keyed request until it really
            // completes so the resolver population stays bounded.
            throw IllegalStateException(
                "Timed out resolving ${config.serverAddress} on the physical network",
                error,
            )
        } finally {
            if (request.future.isDone) {
                synchronized(carrierDnsLock) {
                    if (carrierDnsRequests[request.key] === request) {
                        carrierDnsRequests.remove(request.key)
                    }
                }
            }
        }
        if (addresses.isEmpty()) {
            throw IllegalStateException("${config.serverAddress} has no IPv4 address on the physical network")
        }
        val offset = Math.floorMod(generation, addresses.size)
        addresses.drop(offset) + addresses.take(offset)
    }

    private suspend fun connectWithRetry(config: VpnConfig) {
        var attempt = 0
        var carrierGeneration = 0
        val baseMs = config.reconnectBaseDelaySecs * 1000
        val maxMs = config.reconnectMaxDelaySecs * 1000
        // Floor between the START of consecutive connect attempts. A server that
        // accepts auth then immediately drops, or a flapping Wi-Fi<->LTE network,
        // used to reconnect back-to-back: a session that reached CONNECTED resets
        // attempt to 0, so the backoff above is skipped and native transport is
        // re-entered with no delay. On a fast flap that became a tight loop that
        // flooded the UI with log broadcasts until the main thread ANR'd. Measuring
        // from the attempt START means a healthy long-lived session still reconnects
        // promptly (it ran well past the floor), while a sub-second flap is throttled.
        val minReconnectMs = 1500L
        val stableMs = 30_000L         // a session must run this long to count as "stable"
        var lastAttemptStart = 0L
        var firstAttempt = true        // very first connect: no reconnect gating / delay / status change
        // Why the loop gave up, for the give-up broadcast below; null = still running / cancelled.
        var giveUpReason: String? = null
        // THIS coroutine's own liveness, not the service field. `coroutineScope?.isActive` read
        // the SERVICE field, which teardown() nulls and startVpn() immediately replaces — so a
        // cancelled retry loop that was still parked in a blocking JNI call looked at the NEW
        // scope, decided it was alive, and carried on operating on the new session's state.
        // (Audit 2026-07-27, M3)
        while (currentCoroutineContext().isActive) {
            try {
                if (!firstAttempt) {
                    // The reconnect policy applies to EVERY reconnect — INCLUDING after an
                    // established drop. Previously the gate/status/backoff lived under
                    // `attempt > 0`, and `attempt` reset to 0 after established, so on the
                    // common flapping path reconnectEnabled=false / max-retries were silently
                    // ignored and the Tile/UI stayed Connected while the TUN was torn down.
                    if (!config.reconnectEnabled) {
                        giveUpReason = "Reconnect is disabled — giving up"
                        broadcastLog(giveUpReason); break
                    }
                    if (config.reconnectMaxRetries in 0 until attempt) {
                        giveUpReason = "Max reconnect retries (${config.reconnectMaxRetries}) reached — giving up"
                        broadcastLog(giveUpReason); break
                    }
                    // Leave Connected BEFORE re-entering — no green-Tile leak window while the
                    // TUN/routes are down.
                    broadcastStatus(STATUS_CONNECTING)
                    showNotification(s(R.string.notif_reconnecting, attempt.coerceAtLeast(1)))
                    if (attempt > 0) {
                        val pow = Math.pow(2.0, (attempt - 1).coerceAtMost(7).toDouble()).toLong()
                        val delayMs = (baseMs * pow.coerceAtMost(100)).coerceAtMost(maxMs).coerceAtLeast(1000)
                        broadcastLog("Reconnect attempt $attempt in ${delayMs / 1000}s")
                        delay(delayMs)
                    } else {
                        broadcastLog("Reconnecting…") // a stable session dropped — reconnect promptly
                    }
                    // Inter-attempt floor: throttle a sub-second flap even when the backoff was
                    // skipped (no-op when the previous attempt already ran past the floor).
                    val sinceLast = SystemClock.elapsedRealtime() - lastAttemptStart
                    if (lastAttemptStart != 0L && sinceLast < minReconnectMs) {
                        delay(minReconnectMs - sinceLast)
                    }
                }
                firstAttempt = false
                lastAttemptStart = SystemClock.elapsedRealtime()
                // The native generation owns its carriers; stop/free cancellation is the only
                // cross-thread teardown path.
                runNativeTransport(config, carrierGeneration++)
                broadcastLog("Connection closed cleanly")
                if (userRequestedDisconnect) break
                val forced = forcedReconnectInFlight
                forcedReconnectInFlight = false
                val ran = SystemClock.elapsedRealtime() - lastAttemptStart
                attempt = nextAttempt(attempt, ran, stableMs, forced)
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Genuine cancellation (user disconnect / service stop) — never
                // treat as a retryable error, or the loop spins on delay() which
                // re-throws CancellationException immediately.
                throw e
            } catch (e: SecurityException) {
                broadcastLog("[SECURITY] ${e.message}")
                stopVpn(e.message ?: "VPN permission denied")
                return
            } catch (e: Exception) {
                // Our OWN context, not the service scope — see the loop condition. A blocking
                // native generation may return only after its stop token is observed; reading
                // the service field here made a cancelled attempt log an
                // alarming ERR and keep retrying against the new session. (Audit 2026-07-27, M3)
                if (!currentCoroutineContext().isActive) break
                val forced = forcedReconnectInFlight
                if (forced) {
                    // We stopped the native generation ourselves for a network change; the
                    // "Network changed — reconnecting" line already told the user. Do not
                    // surface its completion error as another ERR.
                    forcedReconnectInFlight = false
                } else {
                    broadcastLog("ERR: [${e.javaClass.simpleName}] ${e.message}")
                    var cause = e.cause
                    while (cause != null) { broadcastLog("  <- ${cause.message}"); cause = cause.cause }
                }
                val ran = SystemClock.elapsedRealtime() - lastAttemptStart
                attempt = nextAttempt(attempt, ran, stableMs, forced)
                // Keep the Java TUN descriptor open across backoff so routing remains
                // captured fail-closed; stop only the native transport generation.
                runCatching { transportCore?.stop() }
            }
        }
        // We are out of the retry loop.
        //
        // If our own coroutine was cancelled, the teardown belongs to whoever cancelled us
        // (stopVpn, or a startVpn that already replaced this session) — running it here would
        // dismantle the NEW session. (Audit 2026-07-27, M3)
        if (!currentCoroutineContext().isActive) return
        // Full teardown on EVERY exit, user disconnect or give-up alike. The give-up path used
        // to run only partial transport cleanup: the PARTIAL_WAKE_LOCK (taken without a timeout) was
        // held forever, stopForeground never ran, and the last status broadcast was still
        // CONNECTING — so the notification, the Quick Settings tile and the UI all sat on
        // "Reconnecting…" over a service that had stopped trying, until the user force-stopped
        // the app. (Audit 2026-07-27, B4)
        // Reconnect was disabled or max-retries ran out — preserve that as the terminal
        // status, but publish it only after the native runner has released its TUN.
        stopVpn(if (!userRequestedDisconnect) giveUpReason ?: "Connection lost" else null)
    }

    /** Cancel the native generation, then wait until it has released the TUN. */
    private suspend fun teardownAndWait(keepNetworkObserver: Boolean = false) {
        if (!keepNetworkObserver) unregisterNetworkCallback()
        unregisterScreenReceiver()

        val core = transportCore
        val runner = transportJob
        runCatching { core?.stop() }
        supervisor?.cancel()

        // Close the Java descriptor immediately to wake native reads. The native
        // duplicate remains valid until LinuxTunPump exits, so do not advertise
        // DISCONNECTED or allow a reconnect before runner.join() completes.
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        if (runner != null) {
            val stoppedPromptly = withTimeoutOrNull(NATIVE_TEARDOWN_WARN_MS) {
                runner.join()
                true
            } == true
            if (!stoppedPromptly) {
                Log.w(
                    "VpnSvc",
                    "Native transport teardown exceeded ${NATIVE_TEARDOWN_WARN_MS}ms; waiting for TUN release"
                )
                runner.join()
            }
        }

        try { core?.close() } catch (error: Exception) {
            Log.w("VpnSvc", "Shared transport core teardown failed: ${error.message}")
        }
        transportJob = null
        transportCore = null
        supervisor = null
        coroutineScope = null
        activeConfig = null
        nativeFatalError = null
    }

    // ── network-change fast reconnect ────────────────────────────────────────
    /** Register an UNDERLYING-network watcher. When the underlying network changes
     *  (Wi-Fi <-> mobile) AFTER we are connected, stop the native generation so the
     *  retry loop reconnects on the new network at once instead of waiting for its
     *  dead-connection timeout.
     *
     *  Must NOT watch the default network / must exclude VPN: when we establish, our
     *  own tun becomes the default network, and watching it makes the tunnel's own
     *  bring-up look like a "network change" → immediate reconnect loop (even on a
     *  stable LAN). The NetworkRequest requires NOT_VPN and onAvailable also skips
     *  TRANSPORT_VPN, so our tun is never treated as a network change.
     *
     *  (Audit 2026-07-27, M2) It must equally not watch EVERY network. A plain
     *  `registerNetworkCallback(INTERNET + NOT_VPN)` fires for every matching network on the
     *  device, and the old `prev != network` test read any newly-appearing one as an
     *  underlying switch: a phone parked on stable Wi-Fi with mobile data on tore its tunnel
     *  down and re-handshaked every time the cell radio re-registered (lift, basement,
     *  train) — while the default route never moved. The mirror case was worse: losing Wi-Fi
     *  while LTE is ALREADY up produces no onAvailable at all, and onLost was not
     *  implemented, so the one switch that really matters was noticed only by rxDead, ≥30 s
     *  later. API 31+ therefore uses registerBestMatchingNetworkCallback, whose onAvailable
     *  means "the best match CHANGED"; older releases (minSdk is 28) fall back to tracking
     *  the set of candidates and reacting only when the link we are actually on disappears.
     *  registerDefaultNetworkCallback is deliberately NOT the fallback: a VPN app is subject
     *  to its own VPN, so once we establish, our default network IS the tun. */
    private fun registerNetworkCallback(): Boolean {
        unregisterNetworkCallback()
        val cm = getSystemService(ConnectivityManager::class.java) ?: run {
            broadcastLog("network callback unavailable: ConnectivityManager missing")
            return false
        }
        // NOT_VPN → our own tun is never reported (else it self-triggers a reconnect
        // loop right after connecting); INTERNET → ignore transient link-only networks.
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val bestMatching = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                // Belt-and-suspenders: never react to our own VPN tun (the NOT_VPN
                // request should already exclude it).
                val caps = cm.getNetworkCapabilities(network)
                if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                val enteringTrustedWifi =
                    classifyNetwork(caps) == TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI
                networkSignatures[network] = physicalNetworkSignature(cm, network)
                val prev = currentNetwork
                if (bestMatching) {
                    // Best-matching callback: every onAvailable IS a change of the best
                    // (non-VPN, internet-capable) network — i.e. of the link we ride on.
                    currentNetwork = network
                    if (prev != null && prev != network && !enteringTrustedWifi) {
                        switchedNetwork("Network changed")
                    }
                    reevaluateTrustedWifi(caps)
                    return
                }
                // Pre-31: we hear about EVERY candidate, so adopt one only while we have
                // none (or the one we had is gone). A second network merely showing up is
                // not a switch — that misreading is the bug this branch exists to avoid.
                underlyingNets.add(network)
                if (prev == null || !underlyingNets.contains(prev)) {
                    currentNetwork = network
                    if (prev != null && !enteringTrustedWifi) switchedNetwork("Network changed")
                }
                if (network == currentNetwork) reevaluateTrustedWifi(caps)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                if (!TrustedWifiPolicy.shouldEvaluateCallback(network == currentNetwork)) return
                val trustedKind = classifyNetwork(caps)
                reevaluateTrustedWifi(caps)
                if (trustedKind == TrustedWifiPolicy.NetworkKind.TRUSTED_WIFI) return
                underlyingNetworkStateChanged(cm, network, "Network capabilities changed")
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: android.net.LinkProperties,
            ) {
                underlyingNetworkStateChanged(cm, network, "Network link properties changed")
            }

            override fun onLost(network: Network) {
                networkSignatures.remove(network)
                if (!bestMatching) underlyingNets.remove(network)
                // Only the link we are actually on matters; any other one going away is
                // none of our business.
                if (network != currentNetwork) return
                // Pre-31 we may already know a replacement (LTE that was up all along) —
                // adopt it so the retry loop lands there immediately instead of waiting
                // out rxDead. On 31+ the framework sends a fresh onAvailable for the new
                // best match, so leave it unset.
                currentNetwork = if (bestMatching) null
                    else synchronized(underlyingNets) { underlyingNets.firstOrNull() }
                switchedNetwork("Network lost")
                currentNetwork?.let { replacement ->
                    cm.getNetworkCapabilities(replacement)?.let(::reevaluateTrustedWifi)
                }
            }
        }
        currentNetwork = null
        underlyingNets.clear()
        // Pre-31 seed: we are called from startVpn BEFORE establish(), so at THIS moment the
        // app's active network really is the underlying default (afterwards it is our own
        // tun, which is why we can't just keep asking). Without the seed the fallback path
        // adopts whichever candidate happens to call back first — often the cell radio while
        // the phone is really on Wi-Fi — and would then miss the Wi-Fi loss it exists to
        // catch. (Audit 2026-07-27, M2)
        if (!bestMatching) {
            val active = try { cm.activeNetwork } catch (_: Exception) { null }
            val activeCaps = active?.let { cm.getNetworkCapabilities(it) }
            if (activeCaps != null && !activeCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                currentNetwork = active
                underlyingNets.add(active)
            }
        }
        netCallback = cb
        try {
            if (bestMatching) {
                cm.registerBestMatchingNetworkCallback(
                    req, cb, android.os.Handler(android.os.Looper.getMainLooper())
                )
            } else {
                cm.registerNetworkCallback(req, cb)
            }
        } catch (e: Exception) {
            broadcastLog("network callback unavailable: ${e.message}"); netCallback = null
            return false
        }
        return true
    }

    /** A Network object can survive screen-off, DHCP renewal and Wi-Fi reassociation. Watching
     * only onAvailable/onLost misses exactly that case: the native socket remains tied to a dead
     * path until heartbeat timeout. Compare stable link facts (addresses/routes/DNS and the
     * validated/suspended capabilities), excluding RSSI/bandwidth noise. */
    private fun underlyingNetworkStateChanged(
        cm: ConnectivityManager,
        network: Network,
        why: String,
    ) {
        if (network != currentNetwork) return
        val next = physicalNetworkSignature(cm, network)
        val previous = networkSignatures[network] ?: return
        if (previous == next) return
        // Going into Android's suspended state is not a usable reconnect target: wait for
        // NOT_SUSPENDED (or the screen-on settling path) before replacing the generation,
        // otherwise screen-off itself starts a backoff loop while Wi-Fi sleeps.
        //
        // Crucially, do NOT record `next` on the way out. Storing a signature we did not act
        // on destroys the only evidence that the link changed: the later NOT_SUSPENDED event
        // then compares the new signature against itself and sees no change, and so does the
        // screen-on path — which is how a phone that changed networks while asleep came back
        // to "same network, keeping the tunnel" and sat on a dead link. The baseline must stay
        // at the last state we actually reconnected onto.
        val caps = cm.getNetworkCapabilities(network)
        if (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED) != true) return
        networkSignatures[network] = next
        switchedNetwork(why)
    }

    /** A link we could actually reach the server over: not our own tun, and internet-capable. */
    private fun usableCarrierNetwork(cm: ConnectivityManager, network: Network): Boolean {
        val caps = try { cm.getNetworkCapabilities(network) } catch (_: Exception) { null }
        return caps != null
            && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    /** Last-resort lookup when the tracked network is gone: prefer a validated link, but take
     *  an unvalidated one over failing the attempt outright — captive portals and networks
     *  that have not finished probing still carry our UDP fine. */
    private fun firstUsableCarrierNetwork(cm: ConnectivityManager): Network? {
        val candidates = try {
            @Suppress("DEPRECATION")
            cm.allNetworks.filter { usableCarrierNetwork(cm, it) }
        } catch (_: Exception) {
            return null
        }
        return candidates.firstOrNull { network ->
            cm.getNetworkCapabilities(network)
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        } ?: candidates.firstOrNull()
    }

    private fun physicalNetworkSignature(cm: ConnectivityManager, network: Network): String {
        val caps = cm.getNetworkCapabilities(network)
        val links = cm.getLinkProperties(network)
        val transports = listOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR,
            NetworkCapabilities.TRANSPORT_ETHERNET,
        ).filter { caps?.hasTransport(it) == true }.joinToString(",")
        val addresses = links?.linkAddresses?.map { it.toString() }?.sorted().orEmpty()
        val routes = links?.routes?.map { it.toString() }?.sorted().orEmpty()
        val dns = links?.dnsServers?.mapNotNull { it.hostAddress }?.sorted().orEmpty()
        return buildString {
            append(links?.interfaceName.orEmpty())
            append("|t=").append(transports)
            append("|validated=").append(caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
            append("|active=").append(caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED) == true)
            append("|a=").append(addresses.joinToString(","))
            append("|r=").append(routes.joinToString(","))
            append("|d=").append(dns.joinToString(","))
        }
    }

    private fun registerScreenReceiver() {
        unregisterScreenReceiver()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> screenOffAt = SystemClock.elapsedRealtime()
                    Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> {
                        val sleptAt = screenOffAt
                        if (sleptAt == 0L) return
                        screenOffAt = 0L
                        scheduleWakeReconnect(SystemClock.elapsedRealtime() - sleptAt)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(receiver, filter)
            }
            screenReceiver = receiver
        } catch (error: Exception) {
            broadcastLog("screen wake callback unavailable: ${error.message}")
        }
    }

    /** Wait for the physical link to be usable after screen-on, then replace the native
     * generation while retaining the fail-closed TUN. The PARTIAL_WAKE_LOCK keeps the CPU
     * running, so Rust's suspend-clock detector alone cannot observe every Wi-Fi/NAT sleep. */
    private fun scheduleWakeReconnect(screenOffMs: Long) {
        if (screenOffMs < 1_000L || liveStatus != STATUS_CONNECTED) return
        wakeReconnectJob?.cancel()
        wakeReconnectJob = coroutineScope?.launch {
            val cm = getSystemService(ConnectivityManager::class.java)
            val deadline = SystemClock.elapsedRealtime() + 15_000L
            while (currentCoroutineContext().isActive && SystemClock.elapsedRealtime() < deadline) {
                val network = currentNetwork
                val caps = network?.let { cm?.getNetworkCapabilities(it) }
                val links = network?.let { cm?.getLinkProperties(it) }
                val hasIPv4 = links?.linkAddresses?.any { it.address is Inet4Address } == true
                val usable = caps != null
                    && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
                    && hasIPv4
                if (usable) break
                delay(250)
            }
            if (liveStatus == STATUS_CONNECTED) {
                // Only cycle the tunnel if the physical path actually CHANGED while the screen
                // was off. Reconnecting on every wake tore down healthy tunnels dozens of times
                // an hour on a normally-used phone, and each cycle costs a full handshake plus —
                // until the fix below — a step of reconnect backoff, so a user who merely checks
                // their phone often ended up with the tunnel down more than up. A path that died
                // silently (NAT rebinding, a dozing AP) does NOT change this signature, but the
                // data plane's own dead-link detector notices it within seconds and reconnects,
                // so nothing is lost by waiting for real evidence instead of guessing.
                val net = currentNetwork
                val signature = net?.let { n -> cm?.let { physicalNetworkSignature(it, n) } }
                val before = net?.let { networkSignatures[it] }
                if (signature != null && before != null && signature == before) {
                    broadcastLog(
                        "Device woke after ${screenOffMs / 1000}s screen-off — same network, " +
                            "keeping the tunnel"
                    )
                    return@launch
                }
                // Adopt the signature we are about to reconnect onto, so the capability events
                // that follow the reconnect do not read as yet another change.
                if (net != null && signature != null) networkSignatures[net] = signature
                switchedNetwork("Device woke after ${screenOffMs / 1000}s screen-off")
            }
        }
    }

    /** The underlying link changed or died: reconnect at once, but only from an established
     *  tunnel (a connect already in flight is retried by the loop anyway). */
    /**
     * Next value of the reconnect-backoff counter.
     *
     * The backoff exists to stop a broken path from being hammered, so only a FAILURE may
     * advance it. A cycle we asked for ourselves — a wake or a network change — is not a
     * failure, and counting it as one is what turned normal phone use into an outage: each
     * screen-off cycled the tunnel, sessions between cycles rarely reach [stableMs], so the
     * counter climbed 1→2→4→…→32 s and the tunnel spent more time waiting out a penalty than
     * carrying traffic (reproduced on the lab emulator: attempt 6, 32 s, after six wakes).
     * A deliberate cycle of a session that was actually established clears the counter — the
     * path just demonstrably worked; one that never established leaves it untouched rather
     * than rewarding a flapping link. `forceReconnect`'s own debounce and the inter-attempt
     * floor keep this from hot-looping.
     */
    private fun nextAttempt(attempt: Int, ranMs: Long, stableMs: Long, forced: Boolean): Int {
        val established = liveStatus == STATUS_CONNECTED
        return when {
            forced -> if (established) 0 else attempt
            established && ranMs >= stableMs -> 0
            else -> attempt + 1
        }
    }

    private fun switchedNetwork(why: String) {
        if (liveStatus != STATUS_CONNECTED) return
        broadcastLog("$why — reconnecting on the current network")
        forceReconnect()
    }

    private fun unregisterNetworkCallback() {
        val cb = netCallback
        netCallback = null
        underlyingNets.clear()
        networkSignatures.clear()
        if (cb != null) {
            try { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) } catch (_: Exception) {}
        }
    }

    private fun unregisterScreenReceiver() {
        wakeReconnectJob?.cancel()
        wakeReconnectJob = null
        screenOffAt = 0L
        val receiver = screenReceiver
        screenReceiver = null
        if (receiver != null) {
            try { unregisterReceiver(receiver) } catch (_: Exception) {}
        }
    }

    /** Cancel the live native generation (not the TUN) so the retry loop reconnects. Does NOT set
     *  userRequestedDisconnect, so the reconnect proceeds. */
    private fun forceReconnect() {
        // Debounce: a flapping default network (poor coverage, elevator, Wi-Fi<->LTE
        // bouncing) fires onAvailable repeatedly. Without this guard every callback
        // stopped the live generation and kicked another reconnect, and together with
        // the zero-backoff reset that spun the retry loop. One forced reconnect per
        // window is enough — the retry loop reconnects on the now-current network.
        val now = SystemClock.elapsedRealtime()
        if (now - lastForceReconnectAt < 3000L) return
        lastForceReconnectAt = now
        val core = transportCore ?: return
        forcedReconnectInFlight = true
        runCatching { core.stop() }
            .onFailure { broadcastLog("Network-change native stop failed: ${it.message}") }
    }

    @Synchronized
    private fun stopVpn(finalError: String? = null) {
        if (stopping) return
        stopping = true
        if (transportCore != null || vpnInterface != null || transportJob?.isActive == true) {
            broadcastStatus(STATUS_DISCONNECTING)
            showNotification(s(R.string.disconnecting))
        }

        teardownJob = teardownScope.launch {
            teardownAndWait()
            try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
            wakeLock = null
            // NB: do NOT reset userRequestedDisconnect here — the retry loop may still
            // be unwinding and must see it as true so it does not reconnect. It is
            // reset in startVpn() on the next explicit Connect.
            liveIp = ""
            liveConnectedAt = 0L
            // Clear the negotiated snapshot only after native teardown; until then the
            // system still owns a live VPN generation and its routes/DNS snapshot.
            liveDns = ""
            liveMtu = 0
            liveStreams = 1
            liveRoutes = 0
            liveLockdown = false
            livePushed = PushedFacts()
            pushedRoutesInstalled = -1
            liveBytesUp = 0L
            liveBytesDown = 0L
            pausedByTrustedWifi = false
            trustedPauseInFlight = false
            trustedWaitConfig = null
            trustedResumeJob?.cancel()
            liveTrustedSsid = ""

            withContext(Dispatchers.Main.immediate) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                if (finalError == null) {
                    broadcastStatus(STATUS_DISCONNECTED)
                } else {
                    broadcastStatus(STATUS_ERROR, finalError)
                }
                stopSelf()
            }
        }
    }

    private fun broadcastStatus(status: String, error: String? = null) {
        if (status != STATUS_STATS) liveStatus = status
        sendBroadcast(Intent(BROADCAST_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATUS, status)
            error?.let { putExtra(EXTRA_ERROR, it) }
        })
    }

    private fun broadcastLog(msg: String) {
        Log.d("VpnSvc", msg)
        sendBroadcast(Intent(BROADCAST_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_LOG, msg)
        })
    }

    private fun effectiveLogLevel(config: VpnConfig? = activeConfig): String {
        val prefs = getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
        val configured = if (prefs.contains(MainActivity.PREF_LOG_LEVEL)) {
            prefs.getString(MainActivity.PREF_LOG_LEVEL, MainActivity.DEFAULT_LOG_LEVEL)
        } else {
            config?.loggingLevel
        }
        return configured?.lowercase()?.takeIf { it == "debug" || it == "trace" } ?: "info"
    }

    private fun detailedLog(config: VpnConfig? = activeConfig): Boolean =
        effectiveLogLevel(config) != "info"

    private fun debugLog(message: String) {
        if (detailedLog()) broadcastLog(message)
    }

    private fun logValue(value: String): String = value
        .asSequence()
        .filterNot { it.isISOControl() }
        .take(128)
        .joinToString("")
        .ifEmpty { "?" }

    private fun broadcastStats(upRate: Long, downRate: Long, upTotal: Long, downTotal: Long) {
        sendBroadcast(Intent(BROADCAST_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATUS, STATUS_STATS)
            putExtra(EXTRA_UP, upRate)
            putExtra(EXTRA_DOWN, downRate)
            putExtra(EXTRA_UP_TOTAL, upTotal)
            putExtra(EXTRA_DOWN_TOTAL, downTotal)
        })
    }

    /** Trust-on-first-use with persistence (parity with the Rust/desktop known_hosts):
     *  pin the server's static key on first sight (keyed by serverId = host:port) and
     *  verify it on every later connect — a changed key throws SecurityException as a
     *  probable MITM instead of being silently accepted. Kept in private prefs (server
     *  public keys are not secrets). */
    /** Check a received key against an existing pin. Returns true when a pin exists
     *  and matches, false when the host is unknown; throws on a mismatch.
     *
     *  Split from [recordKnownHost] on purpose: checking must happen as early as
     *  possible (fail fast on a changed key), but RECORDING has to wait until the peer
     *  has proved it owns the key — see the call site. */
    private fun checkKnownHost(serverId: String, receivedHex: String): Boolean {
        val prefs = getSharedPreferences("qeli_known_hosts", Context.MODE_PRIVATE)
        val pinned = prefs.getString(serverId, null) ?: return false
        if (!pinned.equals(receivedHex, ignoreCase = true)) {
            throw SecurityException(
                "SERVER KEY MISMATCH for $serverId - possible MITM. Pinned $pinned, got " +
                    "$receivedHex. If you deliberately rotated the key, clear the saved key " +
                    "for this server and reconnect."
            )
        }
        return true
    }

    /** Persist a first-use pin. Call ONLY after the auth proof verified. */
    private fun recordKnownHost(serverId: String, receivedHex: String) {
        val persisted = getSharedPreferences("qeli_known_hosts", Context.MODE_PRIVATE)
            .edit().putString(serverId, receivedHex).commit()
        if (!persisted) {
            throw SecurityException("could not persist the proven server key for $serverId")
        }
        broadcastLog("Pinned server key for $serverId on first use (TOFU); a future change will abort as MITM")
    }

    /**
     * Load (or first-time generate + persist) this device's stable 16-byte id, kept
     * in SharedPreferences so it survives reinstalls of the VPN profile and reconnects.
     */
    private fun deviceId(): ByteArray {
        val prefs = getSharedPreferences("qeli_device", Context.MODE_PRIVATE)
        val stored = prefs.getString("device_id", null)
        if (stored != null && stored.length == 32) {
            try {
                val id = ByteArray(16) { stored.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
                // An all-zero id (corrupted prefs) would give every such device the
                // SAME identity, so their sessions would supersede each other; treat
                // it as corrupt and regenerate below.
                if (id.any { b -> b != 0.toByte() }) return id
            } catch (_: Exception) { /* corrupt -> regenerate below */ }
        }
        val id = ByteArray(16)
        SecureRandom().nextBytes(id)
        prefs.edit().putString("device_id", id.joinToString("") { "%02x".format(it) }).apply()
        return id
    }

    // ── Android TUN / route / DNS adapter ──

    private fun setupTunInterface(
        config: VpnConfig,
        plan: TransportCoreNetworkPlan,
    ): ParcelFileDescriptor {
        // Some devices/ROMs reject the IPv6 capture address (fd00:71e1::1/128) at
        // establish() with "Cannot set address" even though addAddress() itself did
        // NOT throw (the failure surfaces only at establish, which is outside any
        // try/catch). Try WITH IPv6 first; if establish fails, retry IPv4-only so the
        // tunnel still comes up (IPv4-over-VPN; IPv6 then exits the physical iface —
        // far better than not connecting at all).
        // Capture the previous TUN: on a clean-path reconnect it is still open here.
        // establish() below replaces it at the OS level, so we close the old fd only
        // AFTER the new one is up — no no-TUN gap (hence no leak window), but we also
        // don't orphan the old descriptor across reconnects.
        val previous = vpnInterface
        val tun = try {
            buildTunInterface(config, plan, withIpv6 = true)
        } catch (e: Exception) {
            broadcastLog("TUN establish with IPv6 failed (${e.message}); retrying IPv4-only")
            buildTunInterface(config, plan, withIpv6 = false)
        }
        if (previous != null && previous !== tun) {
            try { previous.close() } catch (_: Exception) {}
        }

        // Only NOW is a route a fact. Everything before this merely ASKED the builder for one,
        // and `establish()` is what turns the whole set into an interface — so publishing the
        // count earlier (where `logServerPush` runs, before this function is even called)
        // described an intention as though it were the state of the device. Published here, and
        // only after a build that returned: a failed establish throws out of the calls above,
        // so the card is never told the routes are in force.
        //
        // `buildTunInterface` may have run twice (IPv6, then IPv4-only), and the field holds
        // the LAST attempt's count — which is the attempt that produced this `tun`.
        livePushed = livePushed.copy(routesInstalled = pushedRoutesInstalled)
        val requested = livePushed.routeCount
        if (pushedRoutesInstalled in 0 until requested) {
            broadcastLog(
                "WARNING: ${requested - pushedRoutesInstalled} of $requested pushed route(s) " +
                    "were NOT installed — traffic for them is NOT in the tunnel"
            )
        }
        return tun
    }

    private fun buildTunInterface(
        config: VpnConfig,
        plan: TransportCoreNetworkPlan,
        withIpv6: Boolean,
    ): ParcelFileDescriptor {
        val tunnelAddress = plan.tunnelAddress
        val prefixLength = plan.prefixLength
        val tunnelMtu = plan.mtu
        val fullTunnel = plan.fullTunnel
        return Builder().apply {
            setMtu(tunnelMtu)
            addAddress(tunnelAddress, prefixLength)

            if (fullTunnel) {
                // LAN bypass: per-profile allow_lan OR the global Settings toggle. When on,
                // the local/private ranges are carved out of the tunnel so Wi-Fi/LAN devices
                // stay reachable directly (no need to disconnect the VPN).
                val allowLan = config.allowLan ||
                    getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
                        .getBoolean(MainActivity.PREF_ALLOW_LAN, false)
                // User excludes that must be handled HERE rather than by excludeRoute():
                // below API 33 the only way to exclude is to never route it in, and a route
                // cannot be removed once added — so the decision has to happen before any
                // `0.0.0.0/0`. (C-22)
                val pre13Ipv4Excludes = if (Build.VERSION.SDK_INT < 33)
                    config.excludeRoutes.filterNot { ':' in it } else emptyList()
                val pre13Ipv6Excludes = if (Build.VERSION.SDK_INT < 33)
                    config.excludeRoutes.filter { ':' in it } else emptyList()
                when {
                    allowLan && Build.VERSION.SDK_INT >= 33 -> {
                        addRoute("0.0.0.0", 0)
                        for (cidr in LAN_BYPASS_EXCLUDES) {
                            try {
                                val slash = cidr.indexOf('/')
                                excludeRoute(android.net.IpPrefix(
                                    android.system.Os.inet_pton(
                                        android.system.OsConstants.AF_INET,
                                        cidr.substring(0, slash)),
                                    cidr.substring(slash + 1).toInt()))
                            } catch (e: Exception) { broadcastLog("bad LAN-exclude $cidr: ${e.message}") }
                        }
                        broadcastLog("LAN bypass ON — local networks reachable directly")
                    }
                    // Pre-13 with user excludes: one complement covering BOTH the LAN
                    // ranges (when the bypass is on) and the user's excludes. Computing
                    // them separately would let the second set re-add what the first
                    // carved out.
                    pre13Ipv4Excludes.isNotEmpty() -> {
                        val carveOut =
                            (if (allowLan) LAN_BYPASS_EXCLUDES else emptyList()) + pre13Ipv4Excludes
                        val complement = complementRoutes(carveOut)
                        when {
                            complement == null -> {
                                broadcastLog("WARNING: could not build a pre-13 route split for " +
                                    "${carveOut.size} exclude(s) — they are NOT excluded and " +
                                    "will go through the tunnel")
                                addRoute("0.0.0.0", 0)
                            }
                            complement.isEmpty() ->
                                broadcastLog("exclude routes cover the entire address space — " +
                                    "no IPv4 traffic is routed into the tunnel")
                            else -> {
                                for (cidr in complement) addCidrRoute(cidr)
                                broadcastLog("pre-13 route split: ${complement.size} prefixes, " +
                                    "excluding ${carveOut.joinToString(", ")}")
                            }
                        }
                    }
                    allowLan -> {
                        // Pre-Android 13: no excludeRoute → route the complement of RFC1918.
                        for (cidr in PUBLIC_MINUS_RFC1918) addCidrRoute(cidr)
                        broadcastLog("LAN bypass ON (pre-13 route split) — local networks reachable directly")
                    }
                    else -> addRoute("0.0.0.0", 0)
                }
                // Capture IPv6 too, or dual-stack traffic bypasses a "full" tunnel
                // entirely (the classic VPN IPv6 leak: IPv4 goes through the VPN while
                // IPv6 exits the physical interface). The server is IPv4-only, so these
                // packets are dropped inside the tunnel rather than leaking — apps fall
                // back to IPv4-over-VPN. Skipped on the IPv4-only retry above.
                // allow_ipv6_leak opt-out: skip the capture so native IPv6 keeps flowing on the
                // physical interface (the user accepts it bypasses the IPv4-only tunnel).
                if (config.allowIpv6Leak) {
                    // Android BLOCKS an address family the VPN never mentions. Merely
                    // skipping the capture therefore killed IPv6 outright — the exact
                    // opposite of what this opt-out promises (and of the comment above).
                    // allowFamily() is what actually lets IPv6 keep flowing on the
                    // physical interface. (C-14)
                    allowFamily(android.system.OsConstants.AF_INET6)
                } else if (withIpv6) {
                    addAddress("fd00:71e1::1", 128)
                    if (pre13Ipv6Excludes.isEmpty()) {
                        addRoute("::", 0)
                    } else {
                        val complement = RouteComplements.ipv6(pre13Ipv6Excludes)
                            ?: throw IllegalArgumentException(
                                "cannot build a complete pre-Android-13 IPv6 route split for " +
                                    pre13Ipv6Excludes.joinToString(", "))
                        for (cidr in complement) addCidrRoute(cidr)
                        broadcastLog(
                            "pre-13 IPv6 route split: ${complement.size} prefixes, excluding " +
                                pre13Ipv6Excludes.joinToString(", "))
                    }
                    allowFamily(android.system.OsConstants.AF_INET6)
                }
            } else {
                // The tunnel subnet itself is always reachable in split mode. Use the
                // authenticated prefix from the canonical plan rather than assuming /24.
                addRoute(subnetBase(tunnelAddress, prefixLength), prefixLength)
                // VpnService blocks an address family that the Builder never mentions.
                // Split tunnel must leave non-included IPv6 on the underlying network; any
                // explicit IPv6 route applied below remains more specific and is still
                // captured fail-closed by the IPv4-only inner data plane.
                allowFamily(android.system.OsConstants.AF_INET6)
            }

            // Subnets the server advertised (`route = …` on the profile / per-user) are a
            // specific, explicit admin decision — always honoured, like OpenVPN's
            // `push "route …"`. Until 0.7.12 these sat behind routeLocalNetworks, so a
            // correctly configured route was silently dropped on every default client.
            pushedRoutesInstalled = applyCoreNetworkRoutes(
                this,
                plan.routes,
                pushedCidrs = plan.pushedRoutes.toHashSet(),
                excluded = config.excludeRoutes,
                fullTunnel = fullTunnel,
            )

            // Split-tunnel exclude (parity with Rust/win/mac): carve these destinations out
            // of the tunnel. VpnService.Builder.excludeRoute is API 33+; older Android has no
            // clean per-route exclusion, so we log and skip.
            if (config.excludeRoutes.isNotEmpty()) {
                if (Build.VERSION.SDK_INT >= 33) {
                    for (cidr in config.excludeRoutes) {
                        try {
                            val slash = cidr.indexOf('/')
                            val addr = if (slash < 0) cidr else cidr.substring(0, slash)
                            val prefix = if (slash < 0) RouteComplements.hostPrefix(addr)
                                else cidr.substring(slash + 1).toIntOrNull() ?: continue
                            val family = if (':' in addr) android.system.OsConstants.AF_INET6
                                else android.system.OsConstants.AF_INET
                            val address = android.system.Os.inet_pton(family, addr)
                                ?: throw IllegalArgumentException("not an IP literal")
                            excludeRoute(android.net.IpPrefix(address, prefix))
                            broadcastLog("exclude $cidr from tunnel")
                        } catch (e: Exception) { broadcastLog("bad exclude route $cidr: ${e.message}") }
                    }
                } else if (config.isFullTunnel) {
                    // Pre-13 full-tunnel excludes were already applied as a complement route
                    // split in the routing decision above — they HAVE to be, because a route
                    // cannot be removed once `0.0.0.0/0` is in the builder. Nothing to do
                    // here; the log line there reports what was installed. (C-22)
                } else {
                    // Split tunnel: nothing routes into the tunnel by default, so an exclude
                    // is honoured simply by not adding that route.
                    broadcastLog("exclude routes: split-tunnel mode already leaves " +
                        "${config.excludeRoutes.size} destination(s) outside the tunnel")
                }
            }

            // Rust has already resolved config/push/fallback priority; Android only applies
            // the canonical DNS list attached to this authenticated generation.
            if (config.dnsMode != "tunnel") {
                broadcastLog("dns = ${config.dnsMode}: leaving the system resolver alone")
            }
            val dns = plan.dnsServers.map { it.address }
            dns.forEach { try { addDnsServer(it) } catch (e: Exception) { broadcastLog("bad dns $it: ${e.message}") } }

            // Per-app split tunnel. "include" = only the listed apps enter the tunnel;
            // "exclude" = every app except the listed ones. Uninstalled packages are
            // skipped (addAllowed/Disallowed throws NameNotFoundException). Our own
            // package is never added in include mode — its tunnel socket is protect()ed,
            // and self-including would loop traffic.
            //
            // If a mode ends up matching NO app, Android applies no per-app restriction at
            // all and routes EVERY app through the tunnel. That direction is safe (it
            // over-captures — nothing escapes the VPN), but it is the opposite of what the
            // user asked for, so it must never be silent: an imported profile or apps
            // uninstalled since the list was made land here. The UI cannot produce it (an
            // empty include selection collapses back to "all"), which is exactly why it
            // would otherwise go unnoticed.
            when (config.appsMode) {
                "include" -> {
                    var added = 0
                    for (pkg in config.apps) {
                        if (pkg == packageName) continue
                        try { addAllowedApplication(pkg); added++ }
                        catch (_: PackageManager.NameNotFoundException) { broadcastLog("split: app not installed: $pkg") }
                    }
                    if (added > 0) broadcastLog("split-tunnel: only $added app(s) routed through VPN")
                    else throw IllegalStateException(
                        "split-tunnel 'include' matched no installed app; refusing to route every " +
                            "app through the VPN. Check whether the selected apps were uninstalled."
                    )
                }
                "exclude" -> {
                    var excluded = 0
                    for (pkg in config.apps) {
                        if (pkg == packageName) continue
                        try { addDisallowedApplication(pkg); excluded++ }
                        catch (_: PackageManager.NameNotFoundException) { broadcastLog("split: app not installed: $pkg") }
                    }
                    if (excluded > 0) broadcastLog("split-tunnel: $excluded app(s) excluded from VPN")
                    else if (config.apps.isNotEmpty()) broadcastLog(
                        "split-tunnel WARNING: 'exclude' matched no installed app — every app, " +
                        "including the ones meant to stay outside, is going through the VPN. " +
                        "Check the app list (were they uninstalled?)."
                    )
                }
            }

            allowFamily(android.system.OsConstants.AF_INET)
        }.establish() ?: throw Exception("Failed to establish VPN interface")
    }

    /** Apply the canonical Rust route list and return how many routes landed. */
    private fun applyCoreNetworkRoutes(
        builder: Builder,
        routes: List<TransportCoreNetworkRoute>,
        pushedCidrs: Set<String>,
        excluded: List<String>,
        fullTunnel: Boolean,
    ): Int {
        val seen = HashSet<String>()
        var pushedInstalled = 0
        for (route in routes) {
            if (!seen.add(route.cidr)) continue
            if (excluded.any { cidrOverlaps(it, route.cidr) }) {
                broadcastLog("core plan route REFUSED: ${route.cidr} overlaps `exclude`")
                continue
            }
            if (!builder.addCidrRoute(route.cidr)) continue
            if (route.cidr in pushedCidrs) pushedInstalled++
            val detail = buildString {
                append("core plan route: ").append(route.cidr).append(" -> APPLIED")
                if (route.gateway.isNotEmpty() || route.metric > 0) {
                    append(" (Android ignores next-hop/metric; interface route)")
                }
                if (fullTunnel) append(" [covered by full tunnel]")
            }
            broadcastLog(detail)
        }
        return pushedInstalled
    }

    /**
     * Add one CIDR to the builder. Returns whether it actually went in.
     *
     * The result used to be discarded, so a malformed prefix or a builder rejection was logged
     * and then reported as applied anyway — the caller had no way to know. Anything that counts
     * routes for the user has to count what the builder TOOK.
     */
    private fun Builder.addCidrRoute(cidr: String): Boolean {
        val slash = cidr.indexOf('/')
        if (slash < 0) {
            val hostPrefix = RouteComplements.hostPrefix(cidr)
            return try { addRoute(cidr, hostPrefix); true }
            catch (e: Exception) { broadcastLog("bad route $cidr: ${e.message}"); false }
        }
        val addr = cidr.substring(0, slash)
        val prefix = cidr.substring(slash + 1).toIntOrNull() ?: run {
            broadcastLog("bad route $cidr: prefix is not a number")
            return false
        }
        return try { addRoute(addr, prefix); true }
        catch (e: Exception) { broadcastLog("bad route $cidr: ${e.message}"); false }
    }

    /**
     * IPv4 space (`0.0.0.0/0`) MINUS [excludes], as a minimal list of CIDRs. (C-22)
     *
     * Pre-Android-13 has no `excludeRoute`, so the only way to keep a destination out of a
     * full tunnel is to never route it in: install the complement instead of a default
     * route. Same trick as [PUBLIC_MINUS_RFC1918], but computed for arbitrary user
     * excludes rather than hardcoded for RFC1918.
     *
     * Returns `null` when it CANNOT be built (a malformed entry, or more than
     * [MAX_COMPLEMENT_ROUTES] prefixes) — distinct from an EMPTY list, which is a valid
     * answer meaning "the excludes cover everything, so route nothing into the tunnel".
     * Conflating the two would turn `exclude = 0.0.0.0/0` into a default route, i.e. the
     * exact opposite of what was asked.
     */
    private fun complementRoutes(excludes: List<String>): List<String>? {
        val ranges = excludes.mapNotNull { cidrRange(it) }
        if (ranges.size != excludes.size) return null  // malformed entry → cannot build
        val sorted = ranges.sortedBy { it.first }
        val out = mutableListOf<String>()
        var cursor = 0L
        for ((start, end) in sorted) {
            if (start > cursor) rangeToCidrs(cursor, start - 1, out)
            if (end + 1 > cursor) cursor = end + 1
        }
        if (cursor <= 0xFFFFFFFFL) rangeToCidrs(cursor, 0xFFFFFFFFL, out)
        return if (out.size > MAX_COMPLEMENT_ROUTES) null else out
    }

    /** `a.b.c.d[/p]` → inclusive [start, end] as unsigned-32 values held in a Long. */
    private fun cidrRange(cidr: String): Pair<Long, Long>? {
        val slash = cidr.indexOf('/')
        val addrPart = (if (slash < 0) cidr else cidr.substring(0, slash)).trim()
        val prefix = if (slash < 0) 32 else cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        val octets = addrPart.split(".")
        if (octets.size != 4) return null
        var addr = 0L
        for (o in octets) {
            val v = o.toIntOrNull() ?: return null
            if (v !in 0..255) return null
            addr = (addr shl 8) or v.toLong()
        }
        val mask = if (prefix == 0) 0L else ((1L shl 32) - (1L shl (32 - prefix)))
        val base = addr and mask
        val size = 1L shl (32 - prefix)
        return Pair(base, base + size - 1)
    }

    /** Cover the inclusive range [start]..[end] with the fewest aligned CIDR blocks. */
    private fun rangeToCidrs(start: Long, end: Long, out: MutableList<String>) {
        var cur = start
        while (cur <= end) {
            var bits = 32
            while (bits > 0) {
                val size = 1L shl (32 - (bits - 1))
                if (cur % size != 0L || cur + size - 1 > end) break
                bits--
            }
            out.add("${longToIp(cur)}/$bits")
            cur += 1L shl (32 - bits)
        }
    }

    private fun longToIp(v: Long): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

    /**
     * Network address of [ip] under [prefix]. The old version zeroed the last octet,
     * which is only correct for /24 — with a /16 or /20 tunnel it produced a base
     * address outside the actual subnet, so the split-tunnel route covered the wrong
     * range. (C-13)
     */
    /** True when the two IPv4 CIDRs share any address — i.e. one contains the other.
     *  Used to keep a server-pushed route from re-adding a range the user excluded. */
    private fun cidrOverlaps(a: String, b: String): Boolean {
        fun parse(c: String): Pair<Int, Int>? {
            val slash = c.indexOf('/')
            val host = if (slash >= 0) c.substring(0, slash) else c
            val prefix = if (slash >= 0) c.substring(slash + 1).toIntOrNull() ?: return null else 32
            if (prefix !in 0..32) return null
            val o = host.split(".")
            if (o.size != 4) return null
            var addr = 0
            for (part in o) {
                val v = part.toIntOrNull() ?: return null
                if (v !in 0..255) return null
                addr = (addr shl 8) or v
            }
            return addr to prefix
        }
        val (aa, ap) = parse(a) ?: return false
        val (ba, bp) = parse(b) ?: return false
        // Compare on the SHORTER prefix: two ranges overlap iff the wider one contains the
        // narrower one's network address.
        val p = minOf(ap, bp)
        val mask = if (p <= 0) 0 else (-1 shl (32 - p))
        return (aa and mask) == (ba and mask)
    }

    private fun subnetBase(ip: String, prefix: Int): String {
        val o = ip.split(".")
        if (o.size != 4) return ip
        val v = o.map { it.toIntOrNull() ?: return ip }
        val addr = (v[0] shl 24) or (v[1] shl 16) or (v[2] shl 8) or v[3]
        // Kotlin's `shl` uses only the low 5 bits of the count, so `-1 shl 32` would be
        // -1 (all ones) instead of 0 — handle prefix 0 explicitly.
        val mask = if (prefix <= 0) 0 else (-1 shl (32 - prefix))
        val net = addr and mask
        return "${(net ushr 24) and 0xFF}.${(net ushr 16) and 0xFF}.${(net ushr 8) and 0xFF}.${net and 0xFF}"
    }

    private fun announceConnected(clientIp: String) {
        liveStatus = STATUS_CONNECTED
        liveIp = clientIp
        liveConnectedAt = System.currentTimeMillis()
        liveBytesUp = 0L
        liveBytesDown = 0L
        sendBroadcast(Intent(BROADCAST_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATUS, STATUS_CONNECTED)
            putExtra(EXTRA_IP, clientIp)
        })
        showNotification(s(R.string.notif_connected, clientIp))
    }
}
