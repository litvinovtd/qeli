package com.qeli

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import com.qeli.model.PushedFacts
import com.qeli.model.VpnConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.security.SecureRandom

class VpnServiceImpl : VpnService() {

    // @Volatile: written by startVpn() on the main thread, but read/closed by
    // teardown()/stopVpn() invoked from background IO coroutines (reconnect loop,
    // network-change callback). Without it a background thread could see a stale
    // native generation/scope during a rapid connect↔disconnect. (audit 4.3)
    @Volatile private var supervisor: Job? = null
    @Volatile private var coroutineScope: CoroutineScope? = null
    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    // Rust owns handshake and payload; this service is the platform adapter for Android APIs.
    @Volatile private var transportCore: TransportCore? = null
    @Volatile private var activeConfig: VpnConfig? = null
    @Volatile private var nativeFatalError: Throwable? = null
    private var wakeLock: PowerManager.WakeLock? = null
    // Watches the default network (Wi-Fi <-> LTE switch). On a change we cancel the
    // live native generation to reconnect on the new network without waiting for its
    // dead-connection timeout.
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var currentNetwork: Network? = null
    // Every non-VPN network we currently see, used ONLY on the pre-31 fallback path of
    // [registerNetworkCallback] to tell "the link we are on died" from "some other link
    // appeared". Empty on API 31+, which gets the best-matching callback instead.
    private val underlyingNets = java.util.Collections.synchronizedSet(mutableSetOf<Network>())

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

    private val CHANNEL_ID = "vpn_obfuscated_channel"
    private val NOTIFICATION_ID = 1001

    companion object {
        const val ACTION_CONNECT = "com.qeli.CONNECT"
        const val ACTION_DISCONNECT = "com.qeli.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        const val BROADCAST_STATUS = "com.qeli.STATUS"
        const val EXTRA_STATUS = "status"
        const val EXTRA_ERROR = "error"
        const val EXTRA_LOG = "log"
        const val EXTRA_IP = "ip"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_ERROR = "error"
        const val STATUS_STATS = "stats"
        const val EXTRA_UP = "up"     // upload rate, bytes/sec
        const val EXTRA_DOWN = "down" // download rate, bytes/sec
        const val EXTRA_UP_TOTAL = "up_total"     // cumulative bytes sent this session
        const val EXTRA_DOWN_TOTAL = "down_total" // cumulative bytes received this session

        // UDP handshake retransmit tick — see recvUdpWithRetransmit.
        private const val TRANSPORT_CORE_POLL_MIN_MS = 20L
        private const val TRANSPORT_CORE_POLL_MAX_MS = 250L

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
                    config == null -> Log.e("VpnSvc", "Config is null in intent")
                    rejected != null -> {
                        Log.e("VpnSvc", "Refusing to connect: ${rejected.message}")
                        broadcastStatus(STATUS_ERROR, "Invalid profile: ${rejected.message}")
                    }
                    else -> startVpn(config)
                }
            }
            ACTION_DISCONNECT -> {
                userRequestedDisconnect = true
                stopVpn()
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
                startVpn(cfg)
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
        // NOT_STICKY: never let the OS auto-restart this service after it stops
        // (STICKY redelivered a null intent -> stopVpn loop / zombie tunnel).
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
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

    private fun startVpn(config: VpnConfig) {
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

        // Tear down any previous session first so a reconnect can't run two
        // tunnels at once (this is what made "Disconnect then Connect" need an
        // app restart — the old scope/TUN lingered).
        teardown()
        stopping = false
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
            broadcastStatus(STATUS_ERROR, "Native transport core unavailable")
            return
        }
        transportCore?.let { core ->
            broadcastLog(
                "Shared native transport active: ABI 0x" +
                    TransportCore.abiVersion().toUInt().toString(16) +
                    ", state=${core.state()}, lifecycle events drained"
            )
        }
        broadcastLog("Service started: ${config.protocol.uppercase()}/${config.wireMode}" +
            if (config.isUdp && config.quicEnabled) "+QUIC" else "")
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
        broadcastStatus(STATUS_CONNECTING)

        if (!showNotification(s(R.string.notif_connecting))) {
            broadcastStatus(STATUS_ERROR, "Notification permission denied")
            stopVpn()
            return
        }

        coroutineScope!!.launch {
            try {
                connectWithRetry(config)
            } catch (e: kotlinx.coroutines.CancellationException) {
                // normal teardown — ignore
            } catch (e: Exception) {
                Log.e("VpnSvc", "Unhandled: ${e.message}", e)
                broadcastLog("FATAL: ${e.javaClass.simpleName}: ${e.message}")
                stopVpn()
            }
        }
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
                    dispatchTransportCoreEvent(core, event)
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
        broadcastLog("Native transport platform dispatcher active")
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
        broadcastLog("Auth OK, IP ${plan.tunnelAddress}")
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
        broadcastLog("Physical carrier candidates: ${carrierAddresses.joinToString(", ")}")
        nativeFatalError = null
        kotlinx.coroutines.coroutineScope {
            val statsJob = launch {
                var previous = core.stats()
                var previousAt = System.currentTimeMillis()
                while (currentCoroutineContext().isActive && transportCore === core) {
                    delay(1000)
                    val current = runCatching { core.stats() }.getOrElse { break }
                    val now = System.currentTimeMillis()
                    val elapsed = (now - previousAt).coerceAtLeast(1)
                    liveBytesUp = current.txBytes
                    liveBytesDown = current.rxBytes
                    broadcastStats(
                        (current.txBytes - previous.txBytes).coerceAtLeast(0) * 1000 / elapsed,
                        (current.rxBytes - previous.rxBytes).coerceAtLeast(0) * 1000 / elapsed,
                        current.txBytes,
                        current.rxBytes,
                    )
                    if (current.udpRecvBufferBytes != previous.udpRecvBufferBytes ||
                        current.udpKernelDrops != previous.udpKernelDrops ||
                        current.udpInternalDrops != previous.udpInternalDrops ||
                        current.udpBufferGrows != previous.udpBufferGrows
                    ) {
                        broadcastLog(
                            "UDP buffers: granted=${current.udpRecvBufferBytes / 1024} KiB " +
                                "kernel_drops=${current.udpKernelDrops} " +
                                "internal_drops=${current.udpInternalDrops} " +
                                "grows=${current.udpBufferGrows}"
                        )
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
        val selected = currentNetwork ?: cm.activeNetwork?.takeIf { network ->
            val caps = cm.getNetworkCapabilities(network)
            caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } ?: throw IllegalStateException("No physical network is available for carrier DNS")
        val addresses = selected.getAllByName(config.serverAddress)
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .distinct()
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
                    val sinceLast = System.currentTimeMillis() - lastAttemptStart
                    if (lastAttemptStart != 0L && sinceLast < minReconnectMs) {
                        delay(minReconnectMs - sinceLast)
                    }
                }
                firstAttempt = false
                lastAttemptStart = System.currentTimeMillis()
                // The native generation owns its carriers; stop/free cancellation is the only
                // cross-thread teardown path.
                runNativeTransport(config, carrierGeneration++)
                broadcastLog("Connection closed cleanly")
                if (userRequestedDisconnect) break
                // Reset the backoff only after a STABLE session (established AND ran a while);
                // a connect-then-instant-drop keeps escalating (can't hot-loop, still counts
                // toward max-retries).
                val ran = System.currentTimeMillis() - lastAttemptStart
                attempt = if (liveStatus == STATUS_CONNECTED && ran >= stableMs) 0 else attempt + 1
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Genuine cancellation (user disconnect / service stop) — never
                // treat as a retryable error, or the loop spins on delay() which
                // re-throws CancellationException immediately.
                throw e
            } catch (e: SecurityException) {
                broadcastLog("[SECURITY] ${e.message}")
                broadcastStatus(STATUS_ERROR, e.message)
                stopVpn()
                return
            } catch (e: Exception) {
                // Our OWN context, not the service scope — see the loop condition. A blocking
                // native generation may return only after its stop token is observed; reading
                // the service field here made a cancelled attempt log an
                // alarming ERR and keep retrying against the new session. (Audit 2026-07-27, M3)
                if (!currentCoroutineContext().isActive) break
                if (forcedReconnectInFlight) {
                    // We stopped the native generation ourselves for a network change; the
                    // "Network changed — reconnecting" line already told the user. Do not
                    // surface its completion error as another ERR.
                    forcedReconnectInFlight = false
                } else {
                    broadcastLog("ERR: [${e.javaClass.simpleName}] ${e.message}")
                    var cause = e.cause
                    while (cause != null) { broadcastLog("  <- ${cause.message}"); cause = cause.cause }
                }
                // Reset the backoff only after a STABLE established session; otherwise escalate.
                val ran = System.currentTimeMillis() - lastAttemptStart
                attempt = if (liveStatus == STATUS_CONNECTED && ran >= stableMs) 0 else attempt + 1
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
        stopVpn()
        // Reconnect was disabled or max-retries ran out — that is a failure, not a clean stop.
        // Broadcast it AFTER stopVpn (which ends on STATUS_DISCONNECTED) so the UI keeps the
        // reason on screen ("tap to retry") instead of a bare "disconnected". (B4)
        if (!userRequestedDisconnect) {
            broadcastStatus(STATUS_ERROR, giveUpReason ?: "Connection lost")
        }
    }

    /** Cancel the native generation and close the platform-owned TUN. */
    private fun teardown() {
        unregisterNetworkCallback()
        val core = transportCore
        runCatching { core?.stop() }
        supervisor?.cancel()
        supervisor = null
        coroutineScope = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        transportCore = null
        try { core?.close() } catch (error: Exception) {
            Log.w("VpnSvc", "Shared transport core teardown failed: ${error.message}")
        }
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
    private fun registerNetworkCallback() {
        unregisterNetworkCallback()
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
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
                val prev = currentNetwork
                if (bestMatching) {
                    // Best-matching callback: every onAvailable IS a change of the best
                    // (non-VPN, internet-capable) network — i.e. of the link we ride on.
                    currentNetwork = network
                    if (prev != null && prev != network) switchedNetwork("Network changed")
                    return
                }
                // Pre-31: we hear about EVERY candidate, so adopt one only while we have
                // none (or the one we had is gone). A second network merely showing up is
                // not a switch — that misreading is the bug this branch exists to avoid.
                underlyingNets.add(network)
                if (prev == null || !underlyingNets.contains(prev)) {
                    currentNetwork = network
                    if (prev != null) switchedNetwork("Network changed")
                }
            }

            override fun onLost(network: Network) {
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
        }
    }

    /** The underlying link changed or died: reconnect at once, but only from an established
     *  tunnel (a connect already in flight is retried by the loop anyway). */
    private fun switchedNetwork(why: String) {
        if (liveStatus != STATUS_CONNECTED) return
        broadcastLog("$why — reconnecting on the current network")
        forceReconnect()
    }

    private fun unregisterNetworkCallback() {
        val cb = netCallback ?: return
        netCallback = null
        underlyingNets.clear()
        try { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) } catch (_: Exception) {}
    }

    /** Cancel the live native generation (not the TUN) so the retry loop reconnects. Does NOT set
     *  userRequestedDisconnect, so the reconnect proceeds. */
    private fun forceReconnect() {
        // Debounce: a flapping default network (poor coverage, elevator, Wi-Fi<->LTE
        // bouncing) fires onAvailable repeatedly. Without this guard every callback
        // stopped the live generation and kicked another reconnect, and together with
        // the zero-backoff reset that spun the retry loop. One forced reconnect per
        // window is enough — the retry loop reconnects on the now-current network.
        val now = System.currentTimeMillis()
        if (now - lastForceReconnectAt < 3000L) return
        lastForceReconnectAt = now
        val core = transportCore ?: return
        forcedReconnectInFlight = true
        runCatching { core.stop() }
            .onFailure { broadcastLog("Network-change native stop failed: ${it.message}") }
    }

    private fun stopVpn() {
        if (stopping) return
        stopping = true
        teardown()
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        wakeLock = null
        // NB: do NOT reset userRequestedDisconnect here — the retry loop may still
        // be unwinding and must see it as true so it does not reconnect. It is
        // reset in startVpn() on the next explicit Connect.
        liveIp = ""
        liveConnectedAt = 0L
        // Clear the negotiated snapshot too, or the protection card keeps showing the dead
        // session's DNS/MTU/streams as if they were still in force.
        liveDns = ""
        liveMtu = 0
        liveStreams = 1
        liveRoutes = 0
        liveLockdown = false
        livePushed = PushedFacts()
        pushedRoutesInstalled = -1
        liveBytesUp = 0L
        liveBytesDown = 0L
        stopForeground(STOP_FOREGROUND_REMOVE)
        broadcastStatus(STATUS_DISCONNECTED)
        stopSelf()
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
                            val prefix = if (slash < 0) 32 else cidr.substring(slash + 1).toIntOrNull() ?: continue
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
            return try { addRoute(cidr, 32); true }
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
