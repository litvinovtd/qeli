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
import android.util.Log
import com.qeli.crypto.KeyDerivation
import com.qeli.crypto.KeyExchange
import com.qeli.crypto.PacketCipher
import com.qeli.model.PushedFacts
import com.qeli.model.VpnConfig
import com.qeli.protocol.CtrlFrame
import com.qeli.protocol.MtuLadder
import com.qeli.protocol.ObfsStream
import com.qeli.protocol.PacketCodec
import com.qeli.protocol.Quic
import com.qeli.protocol.TlsHandshake
import com.qeli.protocol.UdpFrag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class VpnServiceImpl : VpnService() {

    // @Volatile: written by startVpn() on the main thread, but read/closed by
    // teardown()/stopVpn() invoked from background IO coroutines (reconnect loop,
    // network-change callback). Without it a background thread could see a stale
    // socket/scope during a rapid connect↔disconnect. (audit 4.3)
    @Volatile private var supervisor: Job? = null
    @Volatile private var coroutineScope: CoroutineScope? = null
    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    // TC-2.1 migration shadow: the shared Rust core owns strict config parsing and lifecycle,
    // while Kotlin remains the only packet reader until the network-plan/JNI handoff lands.
    @Volatile private var transportCore: TransportCore? = null
    private var wakeLock: PowerManager.WakeLock? = null
    // Watches the default network (Wi-Fi <-> LTE switch). On a change we close the
    // live sockets to force a prompt reconnect on the new network, instead of waiting
    // ~45s for the dead-connection (rxDead) timeout to notice.
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var currentNetwork: Network? = null
    // Every non-VPN network we currently see, used ONLY on the pre-31 fallback path of
    // [registerNetworkCallback] to tell "the link we are on died" from "some other link
    // appeared". Empty on API 31+, which gets the best-matching callback instead.
    private val underlyingNets = java.util.Collections.synchronizedSet(mutableSetOf<Network>())

    /**
     * The transport sockets of ONE connect attempt. (Audit 2026-07-27, M3)
     *
     * These used to be service fields (`socketChannel` / `udpSocket` / `bondedSockets`).
     * Coroutine cancellation never reaches a thread blocked in `SocketChannel.connect/read`,
     * so a retry-loop iteration could still be parked in connect() long after a NEWER attempt
     * had published its own socket into those shared fields. When the stale one finally threw,
     * its error path called `closeSockets()` — which by then closed the *live* session's
     * socket, killing a healthy tunnel and blaming it on a bogus `ERR:` line. Per-attempt
     * handles mean a late attempt can only ever close its own, already-dead sockets.
     */
    private class Attempt {
        @Volatile var tcp: SocketChannel? = null
        @Volatile var udp: DatagramSocket? = null
        // Secondary bonded sockets (stream-bonding / multipath). Closed with the attempt so
        // their blocking reads unblock and the per-stream coroutines exit; the primary is
        // [tcp]. Empty in single-stream modes.
        val bonded: MutableList<SocketChannel> =
            java.util.Collections.synchronizedList(mutableListOf<SocketChannel>())
        // TCP connect+handshake watchdog: a blocking SocketChannel connect/read ignores
        // soTimeout and coroutine cancellation, so a server that accepts TCP then goes silent
        // would pin the client in Connecting forever. The watchdog closes the channel after
        // connectionTimeoutSecs unless the handshake completed, turning the hang into a
        // reconnect. `handshakeComplete` is flipped when the data plane starts. Per-attempt
        // for the same reason as the sockets: a stale watchdog must not stand down (or fire)
        // on behalf of the attempt that replaced it.
        @Volatile var handshakeComplete = false
        @Volatile var watchdog: Thread? = null

        /** Close every transport socket of THIS attempt (never the TUN). */
        fun closeSockets() {
            try { tcp?.close() } catch (_: Exception) {}
            synchronized(bonded) {
                bonded.forEach { try { it.close() } catch (_: Exception) {} }
                bonded.clear()
            }
            try { udp?.close() } catch (_: Exception) {}
            tcp = null
            udp = null
        }
    }

    // The attempt whose sockets are currently live. Published by the retry loop before each
    // attempt, so a user Disconnect / network change can reach into the CURRENT attempt
    // without any code path having to guess which one that is.
    @Volatile private var liveAttempt: Attempt? = null

    // Stream-bonding wire constants, mirrored from protocol/mod.rs (JOIN_MAGIC /
    // JOIN_TOKEN_LEN). A secondary connection presents JOIN_MAGIC‖token‖index
    // instead of credentials; the server replies "JOINOK".
    private val joinMagic = "QELIJOIN".toByteArray(Charsets.US_ASCII)
    private val maxBonded = 8

    @Volatile
    private var userRequestedDisconnect = false

    @Volatile
    private var stopping = false

    // Timestamp of the last network-change forced reconnect, to debounce a flapping
    // default network (see forceReconnect).
    @Volatile
    private var lastForceReconnectAt = 0L
    // True while forceReconnect() DELIBERATELY closes the live sockets for a network change.
    // The data-plane read then fails with `recvfrom EBADF (Bad file descriptor)` — that's the
    // intended trigger, so it's logged as a clean "reconnecting", not a scary ERR. Cleared
    // when the resulting error is caught by the retry loop.
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
        private const val HS_RETRANSMIT_MS = 1000L
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
         * Only a running VpnService can read this (API 30+), which is exactly why the card
         * could not state it before: from the Activity it is simply not observable.
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
        // Tear down any previous session first so a reconnect can't run two
        // tunnels at once (this is what made "Disconnect then Connect" need an
        // app restart — the old scope/TUN lingered).
        teardown()
        stopping = false
        userRequestedDisconnect = false
        var initialCoreEvents: List<TransportCoreEvent> = emptyList()
        transportCore = runCatching {
            val stableDeviceId = deviceId()
            val core = try {
                TransportCore.create(
                    config.toTransportCoreIni(),
                    deviceId = stableDeviceId,
                    platformCapabilities = TransportCore.PLATFORM_SYSTEM_PLAN or
                        TransportCore.PLATFORM_SOCKET_PROTECT,
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
            // Shadow mode must not disturb the proven Kotlin data plane. Treat a mismatch as
            // migration telemetry until the Rust core owns the handshake and network plan.
            broadcastLog("WARNING: shared transport core shadow unavailable (${error.message})")
            null
        }
        transportCore?.let { core ->
            broadcastLog(
                "Shared transport core shadow active: ABI 0x" +
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
                // Shadow failures retire only the migration path. The established Kotlin
                // transport remains authoritative until native handshake/data-plane handoff.
                if (transportCore === core) {
                    transportCore = null
                    try { core.close() } catch (closeError: Throwable) {
                        Log.w("VpnSvc", "Shared transport core retirement failed: ${closeError.message}")
                    }
                    broadcastLog("WARNING: shared transport core dispatcher disabled (${error.message})")
                }
            }
        }
        broadcastLog("Shared transport core socket-protect dispatcher active")
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
                    throw IllegalStateException(outcome.reason ?: "socket protection rejected")
                }
            }
            TransportCoreEventCodec.KIND_ERROR -> {
                val message = if (event.payloadFormat == TransportCoreEventCodec.PAYLOAD_UTF8) {
                    event.payload.toString(Charsets.UTF_8).take(512)
                } else {
                    "malformed error payload"
                }
                throw IllegalStateException("transport core error ${event.errorCode}: $message")
            }
            TransportCoreEventCodec.KIND_NETWORK_PLAN -> throw IllegalStateException(
                "transport core emitted a network plan before Android handoff was enabled"
            )
            else -> throw IllegalStateException("unknown transport core event ${event.kind}")
        }
    }

    private suspend fun connectWithRetry(config: VpnConfig) {
        var attempt = 0
        val baseMs = config.reconnectBaseDelaySecs * 1000
        val maxMs = config.reconnectMaxDelaySecs * 1000
        // Floor between the START of consecutive connect attempts. A server that
        // accepts auth then immediately drops, or a flapping Wi-Fi<->LTE network,
        // used to reconnect back-to-back: a session that reached CONNECTED resets
        // attempt to 0, so the backoff above is skipped and runVpnConnection is
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
        // cancelled retry loop that was still parked in a blocking socket call looked at the NEW
        // scope, decided it was alive, and carried on operating on the new session's state.
        // (Audit 2026-07-27, M3)
        while (currentCoroutineContext().isActive) {
            // Transport handles belong to this attempt alone; a stale iteration can then only
            // close its own dead sockets, never the live session's. (Audit 2026-07-27, M3)
            val transports = Attempt()
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
                // Publish before connecting: forceReconnect()/teardown() must be able to close
                // the sockets of the attempt that is CURRENTLY running (a blocking connect is
                // interruptible only that way).
                liveAttempt = transports
                runVpnConnection(config, transports)
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
                // connect/read only throws once someone closes the socket, which is long after
                // cancellation; reading the service field here made a cancelled attempt log an
                // alarming ERR and keep retrying against the new session. (Audit 2026-07-27, M3)
                if (!currentCoroutineContext().isActive) { transports.closeSockets(); break }
                if (forcedReconnectInFlight) {
                    // We closed the socket ourselves for a network change (forceReconnect);
                    // the recvfrom EBADF is expected — the "Network changed — reconnecting"
                    // line already told the user. Don't surface it as an ERR.
                    forcedReconnectInFlight = false
                } else {
                    broadcastLog("ERR: [${e.javaClass.simpleName}] ${e.message}")
                    var cause = e.cause
                    while (cause != null) { broadcastLog("  <- ${cause.message}"); cause = cause.cause }
                }
                // Reset the backoff only after a STABLE established session; otherwise escalate.
                val ran = System.currentTimeMillis() - lastAttemptStart
                attempt = if (liveStatus == STATUS_CONNECTED && ran >= stableMs) 0 else attempt + 1
                // Reconnect path: drop only OUR attempt's sockets. Keep the TUN so routing
                // stays captured (fail-closed) across the backoff+re-handshake;
                // setupTunInterface replaces it in place. (Full TUN teardown happens below on
                // give-up / stop.)
                transports.closeSockets()
            }
        }
        // We are out of the retry loop.
        //
        // If our own coroutine was cancelled, the teardown belongs to whoever cancelled us
        // (stopVpn, or a startVpn that already replaced this session) — running it here would
        // dismantle the NEW session. (Audit 2026-07-27, M3)
        if (!currentCoroutineContext().isActive) return
        // Full teardown on EVERY exit, user disconnect or give-up alike. The give-up path used
        // to call only closeTransports(): the PARTIAL_WAKE_LOCK (taken without a timeout) was
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

    /** Close only the transport sockets (TCP/UDP/bonded), leaving the TUN in place.
     *  Used on the RECONNECT path: keeping vpnInterface open means Android keeps routing
     *  captured while we re-handshake, so apps' packets go into the (temporarily dead) TUN
     *  and are dropped — fail-CLOSED — instead of leaking cleartext over the physical link.
     *  setupTunInterface()'s handoff then replaces the TUN in place once the new session is
     *  up. Closing+nulling the TUN here (as the old closeTransports did) opened a leak window
     *  for the whole backoff+handshake on every drop, defeating that handoff. */
    private fun closeSockets() {
        // Only the CURRENT attempt's sockets — an earlier attempt owns (and closes) its own.
        // (Audit 2026-07-27, M3)
        liveAttempt?.closeSockets()
    }

    /** Full teardown of the data plane: sockets AND the TUN. Only for a real stop
     *  (user disconnect / give-up), never between reconnect attempts. */
    private fun closeTransports() {
        closeSockets()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }

    /** Cancel the connection scope and close every transport (TUN/socket).
     *  Used both to fully stop and to reset before a fresh connect. */
    private fun teardown() {
        unregisterNetworkCallback()
        supervisor?.cancel(); supervisor = null; coroutineScope = null
        closeTransports()
        val core = transportCore
        transportCore = null
        try { core?.close() } catch (e: Exception) {
            Log.w("VpnSvc", "Shared transport core teardown failed: ${e.message}")
        }
        // Retire the attempt AFTER its sockets are closed: closing is what unblocks the
        // retry coroutine parked in connect/read, and dropping the reference first would
        // leave it parked forever with nobody holding its socket. (Audit 2026-07-27, M3)
        liveAttempt = null
    }

    // ── network-change fast reconnect ────────────────────────────────────────
    /** Register an UNDERLYING-network watcher. When the underlying network changes
     *  (Wi-Fi <-> mobile) AFTER we are connected, close the live sockets so the data
     *  plane errors and the retry loop reconnects on the new network at once, instead
     *  of waiting for the ~45s rxDead timeout.
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

    /** Close the live network sockets (not the TUN) so the data-plane reader/writer
     *  coroutines error out → the retry loop reconnects. Does NOT set
     *  userRequestedDisconnect, so the reconnect proceeds. */
    private fun forceReconnect() {
        // Debounce: a flapping default network (poor coverage, elevator, Wi-Fi<->LTE
        // bouncing) fires onAvailable repeatedly. Without this guard every callback
        // tore the live sockets down and kicked another reconnect, and together with
        // the zero-backoff reset that spun the retry loop. One forced reconnect per
        // window is enough — the retry loop reconnects on the now-current network.
        val now = System.currentTimeMillis()
        if (now - lastForceReconnectAt < 3000L) return
        lastForceReconnectAt = now
        forcedReconnectInFlight = true
        // The CURRENT attempt's sockets only (M3) — an older, abandoned attempt has already
        // closed its own, and reaching into shared fields is how a stale loop used to close
        // the live session's socket.
        liveAttempt?.closeSockets()
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

    // ── shared session model ─────────────────────────────────────────────────

    private data class Session(
        val clientIp: String,
        // VPN subnet prefix length pushed by the server (default /24 for older
        // servers that omit it) — used as the TUN address prefix.
        val prefix: Int,
        val dnsIp: String,
        val routesJson: String,
        // TUN MTU pushed by the server (its profile's tun.mtu); 0 = the server is
        // too old to push one.
        val pushedMtu: Int = 0,
        // Stream-bonding (multipath): per-session JOIN token (lowercase hex) and how
        // many parallel connections the server permits. maxStreams<=1 (or an older
        // server that omits these) → plain single-stream behaviour. `adaptive` =
        // ramp streams up under load instead of opening exactly maxStreams.
        val sessionToken: String = "",
        val maxStreams: Int = 1,
        val adaptive: Boolean = false
    )

    private class AuthOk(val session: Session, val obf: JSONObject?)

    private fun parseOk(authStr: String): AuthOk {
        // Self-describing keyed payload (server handler.rs::build_auth_ok):
        //   OK:{"client_ip":..,"server_ip":..,"dns":..,"dns_port":..,
        //       "routes":[..],"obfuscation":{..}}
        // Looked up by KEY, so an added/reordered field can't mis-map (the old
        // positional OK:a:b:c:.. format caused exactly that class of bug).
        val json = JSONObject(authStr.removePrefix("OK:"))
        val clientIp = json.optString("client_ip", "")
        if (clientIp.isEmpty()) throw Exception("server OK response missing client_ip")
        val session = Session(
            clientIp = clientIp,
            // VPN subnet prefix (default /24 when an older server omits it); clamped
            // to a valid host range so a bad push can't produce an unusable mask.
            prefix = json.optInt("prefix", 24).let { if (it in 1..32) it else 24 },
            // Empty when the server's DNS proxy is off — the client then uses its
            // own configured resolvers (config.dnsServers) instead of a dead push.
            dnsIp = json.optString("dns", ""),
            routesJson = json.optJSONArray("routes")?.toString() ?: "[]",
            // Server-pushed MTU; out-of-range/absent => 0 (not pushed).
            pushedMtu = json.optInt("mtu", 0).let { if (it in VpnConfig.MTU_MIN..VpnConfig.MTU_MAX) it else 0 },
            // Stream-bonding push (handler.rs::build_auth_ok). Absent on older
            // servers → token "", maxStreams 1, adaptive false → single stream.
            sessionToken = json.optString("session_token", ""),
            maxStreams = json.optInt("max_streams", 1).coerceIn(1, 64),
            adaptive = json.optBoolean("multipath_adaptive", false)
        )
        return AuthOk(session, json.optJSONObject("obfuscation"))
    }

    /** Server-pushed obfuscation params the client applies so it can't drift out
     *  of sync with the server. Mirrors crate::config::PushedObf; only the fields
     *  this client acts on are decoded. */
    private class PushedObf(
        val paddingEnabled: Boolean, val paddingMin: Int, val paddingMax: Int,
        val hbEnabled: Boolean, val hbIntervalMs: Long, val hbJitterMs: Long, val hbDataSize: Int,
        val shEnabled: Boolean, val shGapMeanMs: Long, val shGapMinMs: Long,
        val shGapMaxMs: Long, val shBudget: Int, val shMinSize: Int, val shMaxSize: Int,
        val shStealth: Boolean, val shStealthRateMbps: Int
    )

    private fun decodePushedObf(obf: JSONObject?): PushedObf? {
        if (obf == null) return null
        val pad = obf.optJSONObject("padding") ?: JSONObject()
        val hb = obf.optJSONObject("heartbeat") ?: JSONObject()
        val sh = obf.optJSONObject("traffic_shaping") ?: JSONObject()
        // Clamp everything the SERVER sends into a range this client can actually emit.
        //
        // These values were taken verbatim. A `padding.max_bytes` or shaping `max_size` past
        // what fits in one record makes PacketCodec.encryptPadded throw MAX_RECORD_SIZE on
        // the very first packet — the exception surfaces as a tunnel error, the client
        // reconnects, gets the same push, and loops. A server does not have to be malicious
        // for this: an operator typing an extra digit is enough, and until now the server did
        // not validate these either (fixed in the same pass). The iOS client already clamps
        // its push; this brings Android to the same footing.
        //
        // Bounds mirror what the codec can carry: padding rides inside one record, so cap it
        // well below MAX_RECORD_SIZE; a gap of 0 ms would spin the cover loop; a zero budget
        // means no cover at all, which `enabled` already expresses.
        val padCap = 16384
        val pMin = pad.optInt("min_bytes", 0).coerceIn(0, padCap)
        val pMax = pad.optInt("max_bytes", 255).coerceIn(pMin, padCap)
        val sMin = sh.optInt("min_size", 64).coerceIn(1, padCap)
        val sMax = sh.optInt("max_size", 1024).coerceIn(sMin, padCap)
        val gMin = sh.optLong("idle_gap_min_ms", 40).coerceIn(1, 3_600_000)
        val gMax = sh.optLong("idle_gap_max_ms", 6000).coerceIn(gMin, 3_600_000)
        return PushedObf(
            paddingEnabled = pad.optBoolean("enabled", true),
            paddingMin = pMin,
            paddingMax = pMax,
            hbEnabled = hb.optBoolean("enabled", true),
            hbIntervalMs = hb.optLong("interval_ms", 15000).coerceIn(1_000, 3_600_000),
            hbJitterMs = hb.optLong("jitter_ms", 2000).coerceIn(0, 600_000),
            // The heartbeat's padded size. The client now pads its keepalive to this, so
            // dropping the pushed value meant the server's chosen size never arrived and
            // the local default was used instead — the one knob the server has for making
            // the beat less recognisable did nothing.
            hbDataSize = hb.optInt("data_size_bytes", 16).coerceIn(0, padCap),
            shEnabled = sh.optBoolean("enabled", false),
            shGapMeanMs = sh.optLong("idle_gap_mean_ms", 700).coerceIn(gMin, gMax),
            shGapMinMs = gMin,
            shGapMaxMs = gMax,
            shBudget = sh.optInt("budget_bytes_per_sec", 16384).coerceIn(1, 1 shl 26),
            shMinSize = sMin,
            shMaxSize = sMax,
            shStealth = sh.optBoolean("stealth", false),
            shStealthRateMbps = sh.optInt("stealth_rate_mbps", 2).coerceIn(1, 10_000)
        )
    }

    /** Resolve the effective TUN MTU: an explicit client config value (>0) wins,
     *  else the server-pushed value (>0), else the auto fallback (1400). */
    private fun effectiveMtu(configMtu: Int, pushedMtu: Int): Int = when {
        configMtu > 0 -> configMtu
        pushedMtu > 0 -> pushedMtu
        else -> 1400
    }

    /**
     * Verify the server auth message and return the server's static public key.
     * Mirrors client/mod.rs::verify_server_identity: ≥64B = static_pub||proof,
     * 32B = proof-only (requires pinning).
     */
    /** Result of verifying the server's auth proof: its static public key and the
     *  static-static shared secret (reused to build the client proof — computing
     *  it once avoids a second X25519 op). */
    private class ServerAuth(val staticPub: ByteArray, val staticShared: ByteArray)

    private fun verifyServerAuth(
        msg: ByteArray,
        clientPrivateKey: PrivateKey,
        ephemeralShared: ByteArray,
        transcriptHash: ByteArray,
        pinnedHex: String?,
        serverId: String,
        // false = refuse to connect when the server key is not pinned. (Audit 2026-08-04, M-20.)
        allowUnpinnedTofu: Boolean = true
    ): ServerAuth {
        val ke = KeyExchange()
        val pinnedBytes = pinnedHex
            ?.lowercase()?.replace(Regex("[: -]"), "")
            ?.takeIf { it.length == 64 }
            ?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()

        val serverStaticPub: ByteArray
        val receivedProof: ByteArray
        // Hex key to pin once the proof below verifies; null = nothing to pin.
        var pinOnSuccess: String? = null
        if (msg.size >= 64) {
            serverStaticPub = msg.copyOfRange(0, 32)
            receivedProof = msg.copyOfRange(32, 64)
            if (pinnedBytes != null) {
                if (!serverStaticPub.contentEquals(pinnedBytes))
                    throw SecurityException("SERVER KEY MISMATCH - possible MITM")
            } else {
                // `allow_unpinned_tofu = false` means "never speak to a server I cannot
                // verify". The key was parsed and then read by nothing, so a profile that
                // said false did TOFU anyway — and TOFU against an active MITM pins the
                // ATTACKER's key permanently. (Audit 2026-08-04, M-20.)
                if (!allowUnpinnedTofu) {
                    throw SecurityException(
                        "server key is not pinned and 'allow_unpinned_tofu = false' — refusing " +
                            "trust-on-first-use; add the server's 'key' to this profile"
                    )
                }
                // No explicit pin -> trust-on-first-use WITH persistence (parity with
                // the Rust/desktop clients): pin on first sight, verify on every later
                // connect. CHECK an existing pin now (fail fast on a changed key);
                // RECORD a new one only after the proof verifies below.
                //
                // Recording before verification let ANY injected reply poison the pin
                // permanently: the bogus key was stored, the proof then failed and the
                // connect aborted — but the record stayed, so the real server was
                // rejected as a MITM on every later attempt until the user cleared the
                // saved key by hand. One forged packet, indefinite lockout.
                val receivedHex = serverStaticPub.joinToString("") { "%02x".format(it) }
                if (!checkKnownHost(serverId, receivedHex)) pinOnSuccess = receivedHex
            }
        } else if (msg.size >= 32) {
            // proof-only: server hid its key (require-pinned mode)
            serverStaticPub = pinnedBytes
                ?: throw SecurityException("server sent proof-only but no server_public_key pinned")
            receivedProof = msg.copyOfRange(0, 32)
        } else {
            throw SecurityException("server auth message too short: ${msg.size}")
        }

        val staticShared = ke.computeSharedSecret(clientPrivateKey, serverStaticPub)
        val expected = KeyDerivation.deriveAuthProof(staticShared, ephemeralShared, transcriptHash)
        // Constant-time compare: contentEquals() short-circuits on the first
        // mismatching byte and would leak a timing oracle on the auth proof (T1).
        if (!MessageDigest.isEqual(receivedProof, expected)) {
            throw SecurityException("server auth proof INVALID")
        }
        // Proof verified: the peer holds the private key for the key it presented, so
        // this is now worth remembering. Anything that failed above never reaches here
        // and therefore cannot leave a pin behind.
        pinOnSuccess?.let { recordKnownHost(serverId, it) }
        return ServerAuth(serverStaticPub, staticShared)
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
        getSharedPreferences("qeli_known_hosts", Context.MODE_PRIVATE)
            .edit().putString(serverId, receivedHex).apply()
        broadcastLog("Pinned server key for $serverId on first use (TOFU); a future change will abort as MITM")
    }

    /**
     * Build the auth plaintext. The server (server/handler.rs receive_auth and
     * udp_handler) always expects the layout `[client_key_proof:32][user:pass]`:
     * the first 32 bytes are the client→server key proof (verified only when the
     * server runs with require_client_key_proof, but the prefix is mandatory in
     * the wire format either way), followed by "username:password".
     *
     * The proof binds knowledge of the server's static public key + this
     * handshake's transcript, so it needs the server static key (returned by
     * verifyServerAuth) to derive static_shared.
     */
    private fun buildClientAuthPlaintext(
        config: VpnConfig,
        staticShared: ByteArray,
        ephemeralShared: ByteArray,
        transcriptHash: ByteArray
    ): ByteArray {
        val proof = KeyDerivation.deriveClientKeyProof(staticShared, ephemeralShared, transcriptHash)
        val creds = "${config.username}:${config.password}".toByteArray()
        // Present this device's stable id (marker 0x00 + 16 bytes) so the server keys
        // the session/pool IP by device: several devices of one login coexist, and the
        // SAME device cleanly supersedes its own old session on an IP change (Wi-Fi<->LTE).
        return proof + byteArrayOf(0) + deviceId() + creds  // [proof:32][0x00][device_id:16][user:pass]
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

    /** H-1: when [config].bindStaticToSession is set (the default since 0.7.1), compute
     *  es = X25519(clientPriv, pinned server static pub) so the data keys bind to the
     *  server identity. null = only when explicitly disabled. Requires a real pinned key. */
    private fun staticEs(config: VpnConfig, ke: KeyExchange, clientPriv: java.security.PrivateKey): ByteArray? {
        if (!config.bindStaticToSession) return null
        // bind_static defaults ON, but there is nothing to bind to until a key is pinned —
        // and a freshly created (or link-imported) profile has none. Throwing here left the
        // default profile unable to connect AND made TOFU unreachable, which is precisely
        // how the key gets learned in the first place. Relax to TOFU instead, and say so:
        // with no pinned key there is no binding to downgrade, only the choice between
        // "trust on first use" and "cannot connect at all". (C-11)
        val clean = config.serverPublicKeyHex
            ?.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' } ?: ""
        val unpinned = clean.isEmpty() ||
            (clean.length == 64 && hexToBytes(clean).all { it == 0.toByte() })
        if (unpinned) {
            broadcastLog("bind_static is on but no server key is pinned — connecting TOFU " +
                "(trust on first use). Pin the key (`qeli show-identity`) to enable identity binding.")
            return null
        }
        if (clean.length != 64) throw Exception("invalid server_public_key hex")
        return ke.computeSharedSecret(clientPriv, hexToBytes(clean))
    }

    private fun makeCodecs(config: VpnConfig, sharedSecret: ByteArray, raw: Boolean = false, es: ByteArray? = null): Pair<PacketCodec, PacketCodec> {
        val (serverToClient, clientToServer) = if (es != null)
            KeyDerivation.deriveKeysBound(sharedSecret, es)
        else KeyDerivation.deriveKeys(sharedSecret)
        val enc = PacketCodec(PacketCipher(clientToServer), SecureRandom(),
            config.paddingEnabled, config.paddingMin, config.paddingMax, raw = raw)
        val dec = PacketCodec(PacketCipher(serverToClient), raw = raw)
        return enc to dec
    }

    /** Hybrid (post-quantum) codecs for the fake-tls / obfs / UDP modes: keys depend on
     *  both the X25519 and the ML-KEM-768 shared secrets. `plain` keeps [makeCodecs]. */
    private fun makeCodecsHybrid(config: VpnConfig, x25519Shared: ByteArray, mlkemShared: ByteArray, es: ByteArray? = null): Pair<PacketCodec, PacketCodec> {
        val (serverToClient, clientToServer) = if (es != null)
            KeyDerivation.deriveKeysHybridBound(x25519Shared, mlkemShared, es)
        else KeyDerivation.deriveKeysHybrid(x25519Shared, mlkemShared)
        val enc = PacketCodec(PacketCipher(clientToServer), SecureRandom(),
            config.paddingEnabled, config.paddingMin, config.paddingMax, raw = false)
        val dec = PacketCodec(PacketCipher(serverToClient), raw = false)
        return enc to dec
    }

    // ── TUN setup ────────────────────────────────────────────────────────────

    private fun setupTunInterface(config: VpnConfig, session: Session): ParcelFileDescriptor {
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
            buildTunInterface(config, session, withIpv6 = true)
        } catch (e: Exception) {
            broadcastLog("TUN establish with IPv6 failed (${e.message}); retrying IPv4-only")
            buildTunInterface(config, session, withIpv6 = false)
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
        session: Session,
        withIpv6: Boolean,
    ): ParcelFileDescriptor {
        return Builder().apply {
            setMtu(config.mtu)
            addAddress(session.clientIp, session.prefix)

            if (config.isFullTunnel) {
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
                val pre13Excludes =
                    if (Build.VERSION.SDK_INT < 33) config.excludeRoutes else emptyList()
                when {
                    allowLan && Build.VERSION.SDK_INT >= 33 -> {
                        addRoute("0.0.0.0", 0)
                        for (cidr in LAN_BYPASS_EXCLUDES) {
                            try {
                                val slash = cidr.indexOf('/')
                                excludeRoute(android.net.IpPrefix(
                                    java.net.InetAddress.getByName(cidr.substring(0, slash)),
                                    cidr.substring(slash + 1).toInt()))
                            } catch (e: Exception) { broadcastLog("bad LAN-exclude $cidr: ${e.message}") }
                        }
                        broadcastLog("LAN bypass ON — local networks reachable directly")
                    }
                    // Pre-13 with user excludes: one complement covering BOTH the LAN
                    // ranges (when the bypass is on) and the user's excludes. Computing
                    // them separately would let the second set re-add what the first
                    // carved out.
                    pre13Excludes.isNotEmpty() -> {
                        val carveOut =
                            (if (allowLan) LAN_BYPASS_EXCLUDES else emptyList()) + pre13Excludes
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
                    addRoute("::", 0)
                    allowFamily(android.system.OsConstants.AF_INET6)
                }
            } else {
                // tunnel subnet + explicit includes. Use the prefix the server pushed —
                // the address above is set with `session.prefix`, so hardcoding /24 here
                // routed a different range than the interface actually owns. (C-13)
                addRoute(subnetBase(session.clientIp, session.prefix), session.prefix)
                config.includeRoutes.forEach { addCidrRoute(it) }
            }

            // Subnets the server advertised (`route = …` on the profile / per-user) are a
            // specific, explicit admin decision — always honoured, like OpenVPN's
            // `push "route …"`. Until 0.7.12 these sat behind routeLocalNetworks, so a
            // correctly configured route was silently dropped on every default client.
            pushedRoutesInstalled = applyPushedRoutes(
                this,
                session.routesJson,
                excluded = config.excludeRoutes,
                fullTunnel = config.addDefaultGateway,
            )

            // routeLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
            // default because it would hijack the device's own LAN (printers, NAS, router).
            if (config.routeLocalNetworks) {
                listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").forEach { addCidrRoute(it) }
                broadcastLog("Routing local networks (RFC1918 blanket) through the tunnel")
            }

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
                            excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(addr), prefix))
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

            // Resolvers in priority order: explicit config > server-pushed (session.dnsIp,
            // e.g. dns.push_servers) > public fallback 1.1.1.1/8.8.8.8, and only on a full
            // tunnel (a split tunnel leaves the system resolver alone). The public fallback
            // lives here, NOT as a config default, so a config without DNS stays clean.
            if (config.dnsMode != "tunnel") {
                broadcastLog("dns = ${config.dnsMode}: leaving the system resolver alone")
            }
            val dns = effectiveDns(config, session)
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
                    else broadcastLog(
                        "split-tunnel WARNING: 'include' matched no installed app — Android is " +
                        "routing EVERY app through the VPN, the opposite of what was configured. " +
                        "Check the app list (were they uninstalled?)."
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

    /** Log EVERY setting the server pushed at auth, and what this client did with it.
     *  Without this you cannot tell "the server never sent it" from "the client dropped it"
     *  — from the outside both look identical (a missing route/DNS and no log at all). Each
     *  item says WHY it was not applied and which knob fixes it. */
    /**
     * Resolvers actually programmed on the TUN, in priority order: `dns = off`/`system` wins
     * over everything, then explicit `dnsServers`, then the server-pushed one, then the public
     * fallback on a full tunnel only (a split tunnel leaves the system resolver alone). The
     * fallback lives here and NOT as a config default, so a profile without DNS round-trips
     * clean.
     *
     * Extracted because the card used to publish `session.dnsIp` — the PUSHED value —
     * regardless of whether it had been applied. With `dns = off`, or with explicit resolvers
     * in the profile, the card named a server the tunnel was not using. One function for the
     * decision and the display means they cannot disagree again.
     * (Audit 2026-08-02, follow-up.)
     */
    private fun effectiveDns(config: VpnConfig, session: Session): List<String> = when {
        config.dnsMode != "tunnel" -> emptyList()
        config.dnsServers.isNotEmpty() -> config.dnsServers
        session.dnsIp.isNotEmpty() -> listOf(session.dnsIp)
        config.isFullTunnel -> listOf("1.1.1.1", "8.8.8.8")
        else -> emptyList()
    }.filter { it.isNotEmpty() }

    private fun logServerPush(config: VpnConfig, session: Session, pushed: PushedObf? = null) {
        val nRoutes = try {
            if (session.routesJson.isBlank()) 0 else JSONArray(session.routesJson).length()
        } catch (e: Exception) { 0 }
        // Publish the negotiated values for the protection card. Same numbers the log line
        // below prints — taken from the session directly, so the UI never has to read them
        // back out of text.
        // What the tunnel WILL USE, not what the server offered: with `dns = off` or explicit
        // resolvers in the profile the push is ignored, and naming it here made the card claim
        // a resolver that was never programmed. Empty = the device's own resolvers are left
        // alone, which the UI renders as "system DNS".
        liveDns = effectiveDns(config, session).firstOrNull() ?: ""
        liveMtu = effectiveMtu(config.mtu, session.pushedMtu)
        liveStreams = session.maxStreams
        // What the server SENT. `livePushed.routesInstalled` carries what the builder took,
        // filled in after establish() — a reconnect re-enters here, so reset it with the rest.
        liveRoutes = nRoutes
        pushedRoutesInstalled = -1
        // Keep only a sample. A server may advertise a very long list (a country-sized
        // prefix set is a legitimate split-tunnel setup), and everything downstream — this
        // @Volatile field and a detail sheet that inflates one view per row without
        // recycling — would otherwise scale with it.
        val sample = ArrayList<String>(PushedFacts.ROUTE_SAMPLE)
        try {
            val arr = if (session.routesJson.isBlank()) null else JSONArray(session.routesJson)
            var i = 0
            while (arr != null && i < arr.length() && sample.size < PushedFacts.ROUTE_SAMPLE) {
                arr.optString(i).takeIf { it.isNotEmpty() }?.let { sample.add(it) }
                i++
            }
        } catch (_: Exception) { /* the count above already says how many there were */ }
        livePushed = PushedFacts(
            routes = sample,
            routeCount = nRoutes,
            multipathAdaptive = session.adaptive,
            // Padding comes from the PUSH, not from `config`: the server's values are applied
            // straight to the codec (`encCodec.setPadding`) and never copied back, so the
            // config still holds the profile's numbers while the wire uses the server's.
            // Reporting the config here would describe padding this tunnel is not emitting.
            // Heartbeat and shaping ARE copied into the effective config, so either source
            // agrees for them; taken from the push too, for one rule instead of two.
            paddingEnabled = pushed?.paddingEnabled ?: config.paddingEnabled,
            paddingMin = pushed?.paddingMin ?: config.paddingMin,
            paddingMax = pushed?.paddingMax ?: config.paddingMax,
            heartbeatEnabled = pushed?.hbEnabled ?: config.heartbeatEnabled,
            heartbeatIntervalMs = pushed?.hbIntervalMs ?: config.heartbeatIntervalMs,
            shapingEnabled = pushed?.shEnabled ?: config.shapingEnabled,
        )
        liveLockdown = try {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && isLockdownEnabled
        } catch (_: Exception) { false }
        broadcastLog(
            "server push: ip=${session.clientIp}/${session.prefix} " +
                "mtu=${if (session.pushedMtu > 0) session.pushedMtu.toString() else "-"} " +
                "dns=${session.dnsIp.ifEmpty { "-" }} routes=$nRoutes streams=${session.maxStreams}"
        )
        // MTU — the profile's own explicit mtu wins over the pushed one.
        when {
            session.pushedMtu <= 0 ->
                broadcastLog("server push: mtu not sent (older server) — using ${effectiveMtu(config.mtu, session.pushedMtu)}")
            config.mtu > 0 ->
                broadcastLog("server push: mtu ${session.pushedMtu} IGNORED — this profile sets mtu = ${config.mtu} (wins)")
            else ->
                broadcastLog("server push: mtu ${session.pushedMtu} APPLIED (mtu = 0/auto)")
        }
        // DNS — the profile's own DNS list (if any) overrides the pushed resolver.
        when {
            session.dnsIp.isEmpty() ->
                broadcastLog("server push: no DNS sent — on the server set dns.push_servers = <ip>, or dns.enabled = true + dns.listen")
            config.dnsServers.isNotEmpty() ->
                broadcastLog("server push: DNS ${session.dnsIp} IGNORED — this profile's own DNS (${config.dnsServers.joinToString(", ")}) overrides it")
            else ->
                broadcastLog("server push: DNS ${session.dnsIp} APPLIED")
        }
        // Routes — each applied one is logged separately by applyPushedRoutes.
        if (nRoutes == 0) {
            broadcastLog(
                "server push: no routes sent — the server profile has no valid `route = <cidr> …` " +
                    "(or this user's personal routes override it with an empty set)"
            )
        } else {
            broadcastLog("server push: $nRoutes route(s) received — see the 'pushed route' lines below")
        }
        if (session.maxStreams > 1) {
            broadcastLog("server push: multipath max_streams=${session.maxStreams} adaptive=${session.adaptive}")
        }
    }

    /** Install the server's routes. Returns how many the builder actually took.
     *
     *  [excluded] are the user's own `exclude = …` ranges and [fullTunnel] says whether the
     *  profile already routes everything. Both exist to stop the SERVER widening the tunnel
     *  past what the user asked for — see the two guards below. */
    private fun applyPushedRoutes(
        builder: Builder,
        routesJson: String,
        excluded: List<String> = emptyList(),
        fullTunnel: Boolean = false
    ): Int {
        if (routesJson.isBlank() || routesJson == "[]") return 0
        var installed = 0
        try {
            val arr = JSONArray(routesJson)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val cidr = o.optString("cidr")
                if (cidr.isEmpty()) {
                    broadcastLog("pushed route IGNORED: empty CIDR (fix the server's `route =` line)")
                    continue
                }
                // The SERVER may not turn a split-tunnel profile into a full-tunnel one.
                //
                // This ran in BOTH builder branches with no scope check at all, so a profile
                // deliberately set to `gateway = false` applied whatever arrived — including
                // 0.0.0.0/0 — while the protection card still said SPLIT_ROUTES. A prefix
                // wide enough to redefine the default route is the user's decision, not the
                // peer's. Narrower routes are the site-to-site case this feature is for and
                // stay allowed. (Audit 2026-08-04.)
                val prefix = cidr.substringAfter('/', "32").toIntOrNull() ?: 32
                if (!fullTunnel && prefix < 8) {
                    broadcastLog(
                        "pushed route REFUSED: $cidr — a /$prefix covers the default route and " +
                            "this profile is split-tunnel. Enable full-tunnel yourself if that " +
                            "is what you want."
                    )
                    continue
                }
                // Below API 33 the user's `exclude` list is implemented as a COMPLEMENT of
                // included ranges (excludeRoute arrived in API 33), and that complement is
                // built BEFORE this runs — so a pushed route re-added exactly the range the
                // user asked to keep out of the tunnel. On 33+ excludeRoute is applied after
                // and wins, but refusing here keeps both paths honest. (Audit 2026-08-04.)
                if (excluded.any { cidrOverlaps(it, cidr) }) {
                    broadcastLog(
                        "pushed route REFUSED: $cidr — it overlaps this profile's `exclude` list"
                    )
                    continue
                }
                val gw = o.optString("gateway")
                val metric = o.optInt("metric", 0)
                // Report the route EXACTLY as it arrived, then what actually happened to it.
                // Android's VpnService.Builder routes are interface-scoped: it has no per-route
                // next-hop or metric, so a pushed gateway/metric cannot be honoured here (traffic
                // enters the tunnel and the server forwards it, which reaches the same place).
                val got = StringBuilder(cidr)
                if (gw.isNotEmpty()) got.append(" gateway=").append(gw)
                if (metric > 0) got.append(" metric=").append(metric)
                // APPLIED is a claim about the BUILDER, so it may only be printed when the
                // builder took the route. It used to be printed unconditionally, right after a
                // call whose failure `addCidrRoute` swallowed into a log line — so the same
                // route could produce "bad route …" and "-> APPLIED" one line apart, and the
                // second is the one a reader believes.
                if (!builder.addCidrRoute(cidr)) {
                    broadcastLog("pushed route: $got -> NOT APPLIED (see the error above)")
                    continue
                }
                installed++
                if (gw.isNotEmpty() || metric > 0) {
                    broadcastLog("pushed route: $got -> APPLIED into the tunnel (Android routes are interface-scoped: next-hop/metric not settable)")
                } else {
                    broadcastLog("pushed route: $got -> APPLIED into the tunnel")
                }
            }
        } catch (e: Exception) {
            broadcastLog("routes parse error: ${e.message}")
        }
        return installed
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

    // ── dispatch ─────────────────────────────────────────────────────────────

    private suspend fun runVpnConnection(config: VpnConfig, transports: Attempt) {
        if (config.isUdp) connectUdp(config, transports) else connectTcp(config, transports)
    }

    /**
     * VpnService hands back a TUN fd in NON-BLOCKING mode. Our data-plane reader
     * uses a blocking read() loop, so a non-blocking fd makes read() return 0 the
     * moment the queue drains — which the loop would misread as EOF and exit,
     * permanently killing the upload path after the first few packets. Clear
     * O_NONBLOCK so read() blocks until a packet arrives.
     */
    private fun forceBlocking(pfd: ParcelFileDescriptor): Boolean {
        // Explicit version gate rather than "call it and catch NoSuchMethodError": lint
        // (rightly) flags the unguarded call as a NewApi error, and exception-driven control
        // flow hides from every static check what a version check states plainly. The catch
        // below stays as a backstop for vendor images that lie about their API level. (C-01)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            broadcastLog("Os.fcntlInt needs Android 11 (API 30) — using the poll-based " +
                "non-blocking read path")
            return false
        }
        return try {
            val fd = pfd.fileDescriptor
            val fl = android.system.Os.fcntlInt(fd, android.system.OsConstants.F_GETFL, 0)
            android.system.Os.fcntlInt(fd, android.system.OsConstants.F_SETFL,
                fl and android.system.OsConstants.O_NONBLOCK.inv())
            true
        } catch (e: Throwable) {
            // MUST be Throwable, not Exception: `Os.fcntlInt` is API 30, and on Android
            // 9/10 (minSdk 28) the missing method throws NoSuchMethodError (a subclass of
            // Error, NOT Exception) — a narrow `catch (Exception)` let it escape and crash
            // the VPN service during bring-up. (C-01)
            //
            // Returning false (rather than swallowing) matters: the fd is STILL
            // non-blocking on those releases, so the read loop has to cope with EAGAIN
            // instead of assuming a blocking read. See [awaitTunReadable]. (C-01)
            broadcastLog("forceBlocking unavailable (${e.javaClass.simpleName}) — " +
                "using the poll-based non-blocking read path (Android < 11)")
            false
        }
    }

    /**
     * Wait until the TUN fd has data (or [timeoutMs] elapses). Used ONLY when
     * [forceBlocking] could not clear O_NONBLOCK — i.e. Android 9/10, where `Os.fcntlInt`
     * does not exist. (C-01)
     *
     * Without this the loop spins: a non-blocking read returns EAGAIN immediately and
     * forever, burning a core. `Os.poll` is API 21, so it is available exactly where
     * `fcntlInt` is not, and it blocks in the kernel like a blocking read would.
     *
     * Returns true if the fd is readable, false on timeout (the caller just retries, which
     * also gives the coroutine a cancellation checkpoint).
     */
    private fun awaitTunReadable(pfd: ParcelFileDescriptor, timeoutMs: Int): Boolean {
        return try {
            val pollFd = android.system.StructPollfd().apply {
                fd = pfd.fileDescriptor
                events = android.system.OsConstants.POLLIN.toShort()
            }
            android.system.Os.poll(arrayOf(pollFd), timeoutMs) > 0
        } catch (e: Throwable) {
            // poll itself failed — fall back to a short sleep so we cannot busy-spin.
            try { Thread.sleep(5) } catch (_: InterruptedException) {}
            false
        }
    }

    /**
     * One TUN read that tolerates a non-blocking fd. Returns the byte count, 0 for
     * "nothing yet, try again", or -1 for a genuine EOF.
     *
     * On Android 11+ ([blocking] = true) this is a plain read — unchanged behaviour. On
     * 9/10 an empty non-blocking fd surfaces as an EAGAIN IOException, which the old loop
     * could not distinguish from a closed fd and treated as EOF, killing the upload path
     * after the first few packets. (C-01)
     */
    private fun readTun(
        input: java.io.FileInputStream,
        buf: ByteArray,
        pfd: ParcelFileDescriptor,
        blocking: Boolean,
    ): Int {
        if (blocking) return input.read(buf)
        if (!awaitTunReadable(pfd, 250)) return 0     // timeout — let the caller re-loop
        return try {
            input.read(buf)
        } catch (e: java.io.IOException) {
            // EAGAIN/EWOULDBLOCK = "no data right now", NOT end of stream. Anything else is
            // a real error and propagates.
            val m = e.message ?: ""
            if (m.contains("EAGAIN", true) || m.contains("EWOULDBLOCK", true)) 0 else throw e
        }
    }

    // ── transport abstraction ────────────────────────────────────────────────
    //
    // TCP and UDP differ only in framing/liveness; the handshake and the data-
    // plane loop are otherwise identical. A small Transport hides those two
    // differences so both share one performHandshake() and one runTunnelLoop().

    private interface Transport {
        /** Send one record. [longHeader] only matters for the UDP/QUIC initial. */
        fun send(record: ByteArray, longHeader: Boolean = false)
        /** Block until the next inbound TLS record is available; return it whole. */
        fun recvRecord(): ByteArray
        /** Set a read timeout (ms) for liveness detection (UDP only; 0 = block). */
        fun setReadTimeout(ms: Int) {}
        /** Wall-clock deadline (epoch ms) the fragment-reassembly loop must honour, so a
         *  flood of never-completing fragments can't outrun the handshake timeout. UDP only;
         *  Long.MAX_VALUE = no deadline (the data plane). */
        fun setFillDeadline(deadline: Long) {}
    }

    /** TCP transport: records are length-framed on a byte stream; obfs (if any)
     *  is applied transparently by writeFully/readBytes via the outer [obfs]. */
    private inner class TcpTransport(
        private val io: SocketIO,
        private val raw: Boolean = false
    ) : Transport {
        override fun send(record: ByteArray, longHeader: Boolean) = io.writeFully(record)
        // raw = `plain` wire mode: bare length-prefixed records (no TLS header).
        override fun recvRecord(): ByteArray = if (raw) io.readRawRecord() else io.readTlsRecord()
        // SocketChannel blocking reads ignore soTimeout; TCP liveness is handled
        // by the heartbeat job's rxDead check instead.
    }

    /** UDP transport: each datagram carries one or more whole TLS records (the
     *  handshake bundle), or exactly one record (data plane). recvRecord slices
     *  the next record out of the current datagram, fetching a new one when the
     *  buffer drains. QUIC framing is wrapped/unwrapped here. */
    private inner class UdpTransport(
        private val sock: DatagramSocket,
        private val quic: Boolean,
        private val connectionId: ByteArray,
        private val pn: AtomicInteger,
        // `obfs` wire mode: per-datagram ChaCha20 XOR (null = fake-tls pass-through).
        private val obfsKey: ByteArray?
    ) : Transport {
        private var buf = ByteArray(0)
        private var pos = 0
        // Serialize concurrent datagram sends (upload + heartbeat coroutines).
        private val sendLock = Any()

        /** Bytes the outer layers add on the WIRE beyond the tunnel MTU itself: the obfs
         *  datagram seal, the QUIC short header, and the UDP + IP headers. Mirrors the Rust
         *  client's `seal_overhead() + QUIC_SHORT_HEADER_MIN + 8 + (40|20)`.
         *
         *  The path-MTU ladder needs this because its rungs are INNER (tunnel) MTUs while the
         *  path limit it must respect is an OUTER size — see [MtuLadder.rungs]. */
        fun outerOverhead(): Int =
            (if (obfsKey != null) ObfsStream.DATAGRAM_SEAL_OVERHEAD else 0) +
                (if (quic) Quic.SHORT_HEADER_MIN else 0) +
                8 +                                      // UDP header
                (if (sock.inetAddress is java.net.Inet6Address) 40 else 20)

        override fun send(record: ByteArray, longHeader: Boolean) {
            // The handshake ClientHello (longHeader) is large (post-quantum) — fragment
            // it so no datagram needs IP fragmentation (mobile / CGNAT drop IP fragments
            // → UDP handshake fails on LTE). Data / auth (short header) already fit one.
            val pieces =
                if (longHeader) UdpFrag.fragment(UdpFrag.MSG_CLIENT_HELLO, record) else listOf(record)
            for (piece in pieces) {
                val framed = if (quic) {
                    if (longHeader) Quic.wrapLong(piece, connectionId, pn.getAndIncrement(), 0x00)
                    else Quic.wrapShort(piece, connectionId, pn.getAndIncrement())
                } else piece
                val out = if (obfsKey != null) ObfsStream.datagramSeal(obfsKey, framed) else framed
                synchronized(sendLock) { sock.send(DatagramPacket(out, out.size)) }
            }
        }

        /** AWG junk (AmneziaWG-style Jc on UDP): emit [jc] throwaway decoy datagrams of
         *  random size BEFORE the ClientHello — a polymorphic start blurring the first
         *  datagrams' size/count. Each rides the SAME QUIC / obfs mask as a real datagram;
         *  the server drops it cheaply before its rate limiter. */
        fun sendJunkPreamble(jc: Int, jmin: Int, jmax: Int) {
            val n = jc.coerceIn(0, 128)
            val jmaxC = jmax.coerceIn(0, 1400)
            val jminC = jmin.coerceIn(0, jmaxC)
            val rng = java.security.SecureRandom()
            repeat(n) {
                val len = (if (jminC >= jmaxC) jminC else jminC + rng.nextInt(jmaxC - jminC + 1))
                    .coerceIn(1, UdpFrag.MAX_CHUNK)   // never IP-fragment on LTE/CGNAT
                val junk = UdpFrag.junkDatagram(len)
                val framed = if (quic) Quic.wrapLong(junk, connectionId, pn.getAndIncrement(), 0x00) else junk
                val out = if (obfsKey != null) ObfsStream.datagramSeal(obfsKey, framed) else framed
                synchronized(sendLock) { sock.send(DatagramPacket(out, out.size)) }
            }
        }

        /** Receive one datagram into the buffer (skipping malformed packets). The
         *  fragmented ServerHello is reassembled across datagrams here.
         *  May throw SocketTimeoutException, which the caller maps to liveness. */
        private fun fill() {
            val rbuf = ByteArray(65535)
            var re: UdpFrag.Reassembler? = null
            while (true) {
                // Honour the handshake wall-clock: soTimeout only fires when the socket is
                // IDLE, but a flood of incomplete fragments keeps datagrams arriving so this
                // loop would spin past the handshake deadline forever. Throwing a
                // SocketTimeoutException unwinds to recvUdpWithRetransmit, whose own deadline
                // check then fails the handshake into a fresh reconnect. (No deadline = data
                // plane, so this never fires there.)
                if (System.currentTimeMillis() >= fillDeadline)
                    throw java.net.SocketTimeoutException(
                        "UDP: fragment reassembly did not complete before the handshake deadline")
                val pkt = DatagramPacket(rbuf, rbuf.size)
                sock.receive(pkt)
                var raw: ByteArray? = rbuf.copyOf(pkt.length)
                if (obfsKey != null) raw = ObfsStream.datagramOpen(obfsKey, raw!!)
                val payload = if (raw == null) null else if (quic) Quic.unwrapPayload(raw) else raw
                if (payload == null) continue   // malformed datagram — drop
                // Reassemble a fragmented handshake message: the ServerHello, and since
                // 0.7.14 also a large AuthOK (msg_id 6), which a big pushed-route set puts
                // over the fragment budget. Deliberately keyed on isFragment rather than on a
                // specific msgId — a real record can never carry the magic in either framing
                // (see UdpFrag.MSG_AUTH_OK), so this stays correct on the data plane too.
                // Everything else passes through unchanged.
                if (UdpFrag.isFragment(payload)) {
                    if (re == null) re = UdpFrag.Reassembler()
                    val full = try { re.push(payload) } catch (e: Exception) { re = null; continue }
                    if (full == null) continue   // need more fragments
                    buf = full; pos = 0; return
                }
                buf = payload; pos = 0; return
            }
        }

        override fun recvRecord(): ByteArray {
            // Keep pulling datagrams until we have at least a 5-byte record header. A datagram
            // whose (unwrapped) payload is shorter — a stray / tiny / malformed control
            // datagram — must be SKIPPED, not indexed past its end: reading buf[pos+4] on a
            // <5-byte buffer threw ArrayIndexOutOfBoundsException (length=4; index=4) and, now
            // that the real error is surfaced, killed the tunnel loop into a reconnect storm.
            while (true) {
                while (pos + 5 > buf.size) fill()
                val len = ((buf[pos + 3].toInt() and 0xFF) shl 8) or (buf[pos + 4].toInt() and 0xFF)
                // A datagram must carry the WHOLE record it declares. Clamping the end to the
                // buffer (`coerceAtMost`) quietly turned a truncated record into a shorter
                // valid-looking one: the AEAD then failed and the tunnel dropped, with the real
                // cause — a peer or middlebox that cut the datagram — nowhere in the log. UDP
                // has no continuation, so no later datagram can complete it; drop this one and
                // read the next. The length is bounded too: a record larger than the codec will
                // ever accept is garbage or a hostile length field, and must not size a copy.
                // (Audit 2026-07-29, #17.)
                if (len > PacketCodec.MAX_RECORD_SIZE || pos + 5 + len > buf.size) {
                    buf = ByteArray(0)   // force fill() to pull the next datagram
                    pos = 0
                    continue
                }
                val end = pos + 5 + len
                val rec = buf.copyOfRange(pos, end)
                pos = end
                return rec
            }
        }

        override fun setReadTimeout(ms: Int) { sock.soTimeout = ms }

        private var fillDeadline: Long = Long.MAX_VALUE
        override fun setFillDeadline(deadline: Long) { fillDeadline = deadline }

        // ── path-MTU probe helpers (used before the TUN is established) ──────────
        /** The DatagramSocket's underlying fd (hidden on Android) via reflection, or null. */
        private fun socketFd(): java.io.FileDescriptor? = try {
            val implField = DatagramSocket::class.java.getDeclaredField("impl").apply { isAccessible = true }
            val impl = implField.get(sock)
            val fdField = java.net.DatagramSocketImpl::class.java.getDeclaredField("fd").apply { isAccessible = true }
            fdField.get(impl) as? java.io.FileDescriptor
        } catch (e: Exception) { null }

        /** Toggle Don't-Fragment via IP_MTU_DISCOVER. on=true -> IP_PMTUDISC_PROBE (DF,
         *  ignore the cached PMTU so we can probe); on=false -> IP_PMTUDISC_DONT (fragment).
         *  Best-effort: returns false if the fd/setsockopt is unavailable (probe is skipped). */
        fun setDontFragment(on: Boolean): Boolean = try {
            val fd = socketFd() ?: return false
            // Linux values (Android is Linux): IP_MTU_DISCOVER=10, PMTUDISC_PROBE=3, DONT=0.
            android.system.Os.setsockoptInt(fd, android.system.OsConstants.IPPROTO_IP, 10, if (on) 3 else 0)
            true
        } catch (e: Exception) { false }

        /** Receive one datagram, unwrap the obfs/QUIC mask, return the payload (or null on
         *  timeout/malformed). Catches a probe ACK before the data loop starts. */
        fun recvRawPayload(timeoutMs: Int): ByteArray? {
            sock.soTimeout = timeoutMs
            return try {
                val rbuf = ByteArray(65535)
                val pkt = DatagramPacket(rbuf, rbuf.size)
                sock.receive(pkt)
                var raw: ByteArray? = rbuf.copyOf(pkt.length)
                if (obfsKey != null) raw = ObfsStream.datagramOpen(obfsKey, raw!!)
                if (raw == null) null else if (quic) Quic.unwrapPayload(raw) else raw
            } catch (e: Exception) { null }   // timeout / oversized-reply
        }
    }

    /** REALITY transport: the qeli protocol runs *inside* a genuine TLS 1.3
     *  session. Each inner qeli record is sealed as one TLS application_data
     *  record; inbound TLS records are decrypted and re-sliced into inner qeli
     *  records. Wraps [TcpTransport] (the raw socket IO). */
    private inner class RealTlsTransport(private val inner: Transport, private val tls: RealTls) : Transport {
        private var inBuf = ByteArray(0)

        override fun send(record: ByteArray, longHeader: Boolean) = inner.send(tls.seal(record))

        override fun recvRecord(): ByteArray {
            while (!hasInnerRecord()) {
                val plain = tls.open(inner.recvRecord()) // decrypt one outer TLS record
                if (plain.isNotEmpty()) inBuf += plain
            }
            val len = ((inBuf[3].toInt() and 0xFF) shl 8) or (inBuf[4].toInt() and 0xFF)
            val total = 5 + len
            val rec = inBuf.copyOfRange(0, total)
            inBuf = inBuf.copyOfRange(total, inBuf.size)
            return rec
        }

        private fun hasInnerRecord(): Boolean {
            if (inBuf.size < 5) return false
            val len = ((inBuf[3].toInt() and 0xFF) shl 8) or (inBuf[4].toInt() and 0xFF)
            return inBuf.size >= 5 + len
        }

        override fun setReadTimeout(ms: Int) = inner.setReadTimeout(ms)
    }

    /** Drive the native REALITY TLS 1.3 handshake over the raw socket, then return
     *  the established session for the nested tunnel. */
    private fun doRealTlsHandshake(config: VpnConfig, io: SocketIO): RealTls {
        val sni = config.sni ?: pickSni(config.serverAddress)
        val realityPub = hexToBytes(config.serverPublicKeyHex
            ?: throw Exception("reality-tls requires a pinned server key (auth.server_public_key)"))
        require(realityPub.size == 32) { "server key must be 32 bytes (64 hex chars)" }
        val shortId = shortIdFromHex(config.realityShortId
            ?: throw Exception("reality-tls requires reality_sid"))
        val tls = RealTls.create(realityPub, shortId, sni)
        io.writeRaw(tls.clientHello())
        while (!tls.established()) {
            val out = tls.recv(io.readSomeRaw())
            if (out.isNotEmpty()) io.writeRaw(out)
        }
        broadcastLog("REALITY TLS 1.3 established (SNI $sni)")
        return tls
    }

    // ── connection setup (transport-specific) ────────────────────────────────

    /** protect() the tunnel's own socket so its traffic to the server bypasses the
     *  VPN — otherwise it loops back through the tunnel and the handshake dies. The
     *  call can transiently return false during service-start / reconnect races (seen
     *  in the wild as a flapping "protect() returned false"), so retry a few times
     *  before warning. `attempt` is the platform protect() for this socket type. */
    /**
     * protect() the carrier socket so it bypasses our own TUN, retrying a few times while
     * VpnService settles.
     *
     * FAIL-FAST on total failure (C-15). Continuing with an UNPROTECTED carrier socket is
     * not a degraded connection, it is a broken one: the encrypted traffic is routed back
     * into the tunnel it is supposed to carry, so the link either never establishes or
     * flaps — and the old code only logged a WARN and carried on, which turned a clear
     * failure into a mystery reconnect loop. Throwing hands control to the reconnect
     * machinery, which backs off and reports the real reason.
     *
     * Callers that open OPTIONAL sockets (bonded streams) already catch per-stream, so
     * this aborts only that stream there, not the working primary link.
     */
    private fun protectSocket(label: String, attempt: () -> Boolean) {
        repeat(5) { i ->
            if (attempt()) return
            if (i < 4) try { Thread.sleep(100) } catch (_: InterruptedException) {}
        }
        val msg = "protect() failed for $label after 5 attempts — the socket would carry " +
            "tunnel traffic INTO the tunnel. Usually another active/always-on VPN holds the " +
            "path, or VpnService is not ready yet."
        broadcastLog("ERROR: $msg")
        throw IllegalStateException(msg)
    }

    private suspend fun connectTcp(config: VpnConfig, transports: Attempt) {
        // Username omitted: broadcastLog also writes to Logcat (release), which lands in
        // bug reports / adb. Password/keys are never logged; keep the username out too. (LOW)
        broadcastLog("Connecting TCP ${config.serverAddress}:${config.port}...")
        // Publish the channel into THIS ATTEMPT before the blocking connect(), so a user
        // Disconnect or a network change can close it to interrupt connect() immediately.
        // (A blocking SocketChannel.connect/read ignores coroutine cancellation — closing
        // the channel from another thread is the only way to break it. Previously the field
        // was assigned only AFTER connect returned, so a connect that hung on a dead/changed
        // network couldn't be stopped — the Disconnect button did nothing until the OS TCP
        // timeout.) Per-attempt since 0.7.13, see [Attempt]. (Audit 2026-07-27, M3)
        val sock = SocketChannel.open()
        transports.tcp = sock
        if (userRequestedDisconnect) { try { sock.close() } catch (_: Exception) {}; throw kotlinx.coroutines.CancellationException("disconnect requested") }
        // Bound the whole connect + handshake by connectionTimeoutSecs. A blocking
        // SocketChannel connect/read ignores soTimeout, so without this a server that
        // accepts TCP then stalls at the app layer would hang here forever with no
        // reconnect. Closing the channel from the watchdog throws AsynchronousCloseException
        // out of the blocking call → the retry loop reconnects. Cleared in runTcpAfterHandshake.
        transports.handshakeComplete = false
        transports.watchdog = Thread {
            val deadline = System.currentTimeMillis() + config.connectionTimeoutSecs * 1000
            while (!transports.handshakeComplete && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(100) } catch (_: InterruptedException) { return@Thread }
            }
            if (!transports.handshakeComplete) {
                broadcastLog("TCP connect/handshake exceeded ${config.connectionTimeoutSecs}s — " +
                    "closing socket to force a reconnect")
                try { sock.close() } catch (_: Exception) {}
            }
        }.apply { isDaemon = true; name = "qeli-tcp-hs-watchdog"; start() }
        protectSocket("server") { protect(sock.socket()) }
        sock.socket().soTimeout = config.connectionTimeoutSecs.toInt() * 1000
        sock.connect(InetSocketAddress(config.serverAddress, config.port))
        sock.socket().keepAlive = true
        sock.socket().tcpNoDelay = true
        sock.configureBlocking(true)
        broadcastLog("TCP connected")
        val io = SocketIO(sock)

        // Every TCP wire mode builds its primary transport, runs the qeli handshake,
        // then hands off to runTcpAfterHandshake which decides single-stream vs
        // bonded multipath (server-pushed max_streams). Stream bonding is supported
        // on ALL TCP modes; the per-mode connector lives in openBondedStream.
        when {
            config.wireMode.equals("plain", ignoreCase = true) -> {
                // No TLS mimicry: raw X25519 key exchange, then bare length-prefixed
                // records (Framing::Raw).
                broadcastLog("plain mode: raw key exchange, no TLS mimicry")
                val r = performHandshakePlain(config, io)
                runTcpAfterHandshake(io, TcpTransport(io, raw = true), null, r, transports)
            }
            config.wireMode.equals("reality-tls", ignoreCase = true) -> {
                // Genuine browser TLS 1.3 (REALITY) carries the tunnel; the qeli
                // protocol runs nested inside it.
                val tls = doRealTlsHandshake(config, io)
                val transport = RealTlsTransport(TcpTransport(io), tls)
                val r = performHandshake(config, transport, padToMin = 0)
                runTcpAfterHandshake(io, transport, tls, r, transports)
            }
            config.wireMode.equals("obfs", ignoreCase = true) -> {
                // XOR the whole stream with a PSK-keyed ChaCha20 keystream; nonces
                // are exchanged in the clear (writeRaw/readRaw bypass obfs) first.
                if (config.obfsKey.isBlank())
                    throw Exception("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)")
                val fronting = config.obfsFronting.equals("websocket", ignoreCase = true)
                broadcastLog(if (fronting) "obfs mode: WebSocket fronting + nonce exchange" else "obfs mode: exchanging nonces")
                io.obfs = ObfsStream.connect(ObfsStream.deriveKey(config.obfsKey), fronting,
                    sendRaw = { io.writeRaw(it) }, recvRaw = { io.readRaw(it) },
                    awgJc = if (config.awgEnabled) config.awgJc else 0,
                    awgJmin = config.awgJmin, awgJmax = config.awgJmax,
                    wsHost = wsHostFor(config))
                val transport = TcpTransport(io)
                val r = performHandshake(config, transport, padToMin = 0)
                runTcpAfterHandshake(io, transport, null, r, transports)
            }
            else -> {
                // fake-tls: TLS-record mimicry applied by the qeli handshake/codec.
                val transport = TcpTransport(io)
                val r = performHandshake(config, transport, padToMin = 0)
                runTcpAfterHandshake(io, transport, null, r, transports)
            }
        }
    }

    /** Shared TCP tail: announce, bring up the TUN, then run the bonded multipath
     *  loop (server pushed max_streams>1 + a token) or the single-stream loop. */
    private suspend fun runTcpAfterHandshake(
        io: SocketIO, transport: Transport, tls: RealTls?, r: HandshakeResult, transports: Attempt
    ) {
        // Handshake done — stand THIS attempt's connect/handshake watchdog down before the
        // data plane (whose own rxDead liveness takes over), so it can't close a live tunnel.
        transports.handshakeComplete = true
        transports.watchdog?.interrupt()
        transports.watchdog = null
        broadcastLog("Auth OK, IP ${r.session.clientIp}")
        logServerPush(r.config, r.session, r.pushedObf)
        vpnInterface = setupTunInterface(r.config, r.session)
        // Announce Connected (green + "established" for the reconnect backoff) only AFTER the
        // TUN is up; see the UDP path / issue #69. At Auth OK it showed green with no working
        // tunnel and reset the backoff on a TUN-establish failure → tight reconnect loop.
        announceConnected(r.session.clientIp)
        if (r.session.maxStreams > 1 && r.session.sessionToken.isNotBlank()) {
            broadcastLog("Multipath: server allows up to ${r.session.maxStreams} bonded " +
                "stream(s) (adaptive=${r.session.adaptive})")
            val primary = Stream(io, transport, r.enc, r.dec, tls)
            runMultipathTunnelLoop(r.config, primary, r.session, r.pushedObf, vpnInterface!!, transports)
        } else {
            broadcastLog("TUN ready, entering tunnel loop")
            try {
                runTunnelLoop(r.config, transport, vpnInterface!!, r.enc, r.dec, isUdp = false)
            } finally {
                // Single-stream owns `tls` (reality-tls) — close the native TLS session so
                // it doesn't leak across every reconnect (multipath hands it to the primary
                // Stream, which closes it on teardown). Null for other wire modes.
                try { tls?.close() } catch (_: Throwable) {}
            }
        }
    }

    private suspend fun connectUdp(config: VpnConfig, transports: Attempt) {
        // Username omitted — see TCP path. (client-audit LOW: username-logging)
        broadcastLog("Connecting UDP ${config.serverAddress}:${config.port}...")
        val sock = DatagramSocket()
        protectSocket("server UDP") { protect(sock) }
        // Ask for a bigger receive buffer than the ~200 KB default. UDP has no autotuning:
        // whatever the socket is given is what it gets, and at tunnel speeds that default is
        // only tens of milliseconds of traffic — one GC pause or scheduling hiccup and the
        // kernel drops datagrams. Every dropped datagram is a lost TCP segment INSIDE the
        // tunnel, so the inner connection halves its window; that is what caps UDP throughput.
        // The exact same defect on the server side cost half the uplink until it was fixed.
        // Best-effort by design: the kernel clamps the request to net.core.rmem_max and may
        // grant less, and a refusal must not break the connection — hence the catch. 2 MB, not
        // more: the buffer only has to absorb a stall, and an oversized one would queue packets
        // instead of dropping them, adding latency under sustained overload.
        try {
            val before = sock.receiveBufferSize
            sock.receiveBufferSize = 2 * 1024 * 1024
            // Log what the kernel ACTUALLY granted, not what we asked for — it silently
            // clamps to net.core.rmem_max, and without this line a clamped buffer is
            // indistinguishable from a working one when reading a throughput report.
            broadcastLog("UDP recv buffer: ${before / 1024} KB -> ${sock.receiveBufferSize / 1024} KB")
        } catch (e: Exception) {
            broadcastLog("UDP: could not enlarge the receive buffer (${e.message}); using the default")
        }
        sock.connect(InetSocketAddress(config.serverAddress, config.port))
        sock.soTimeout = config.connectionTimeoutSecs.toInt() * 1000
        transports.udp = sock

        val quic = config.quicEnabled
        val connectionId = if (quic) Quic.generateConnectionId() else ByteArray(4)
        if (config.wireMode.equals("obfs", ignoreCase = true) && config.obfsKey.isBlank())
            throw Exception("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)")
        val obfsKey = if (config.wireMode.equals("obfs", ignoreCase = true) && config.obfsKey.isNotEmpty())
            ObfsStream.deriveKey(config.obfsKey) else null
        val transport = UdpTransport(sock, quic, connectionId, AtomicInteger(0), obfsKey)
        if (quic) broadcastLog("UDP QUIC masking enabled")
        if (obfsKey != null) broadcastLog("UDP obfs mode enabled")
        // AWG junk (AmneziaWG-style Jc) on UDP: decoy preamble before the ClientHello.
        // OFF by default (awgJc=0) → byte-identical to the prior wire.
        if (config.awgEnabled && config.awgJc > 0) {
            transport.sendJunkPreamble(config.awgJc, config.awgJmin, config.awgJmax)
            broadcastLog("UDP: sent AWG junk preamble (jc=${config.awgJc}) before ClientHello")
        }
        establishAndRun(config, transport, padToMin = 1200, isUdp = true)
    }

    /** Shared tail: run the handshake over [transport], bring up the TUN, loop. */
    private suspend fun establishAndRun(
        config: VpnConfig, transport: Transport, padToMin: Int, isUdp: Boolean
    ) {
        val r = performHandshake(config, transport, padToMin, isUdp)
        runAfterHandshake(config, transport, isUdp, r)
    }

    /** Post-handshake path (announce, TUN setup, tunnel loop) shared by the
     *  fake-tls/obfs/reality path and the plain path. */
    private suspend fun runAfterHandshake(
        origConfig: VpnConfig, transport: Transport, isUdp: Boolean, r: HandshakeResult
    ) {
        broadcastLog("Auth OK, IP ${r.session.clientIp}")
        logServerPush(r.config, r.session, r.pushedObf)
        var cfg = r.config
        // Auto MTU on UDP: discover the path MTU (DF probes from the pushed ceiling down)
        // BEFORE establishing the TUN — Android fixes the VpnService MTU at establish() and
        // can't change it live, so probing must precede setupTunInterface. r.config.mtu is
        // already the resolved effective MTU; only probe when the user left mtu=0 (auto).
        // Fail-safe: a miss keeps the pushed/effective MTU. TCP is untouched (kernel PMTUD).
        if (isUdp && origConfig.mtu == 0 && origConfig.mtuProbe && transport is UdpTransport) {
            val ceiling = cfg.mtu
            val probed = probeUdpMtu(transport, ceiling)
            if (probed > 0) {
                broadcastLog("UDP path-MTU probe: tunnel MTU $probed (ceiling $ceiling)")
                cfg = cfg.copy(mtu = probed)
                // Republish: `logServerPush` ran BEFORE the probe and could only know the
                // pushed/config ceiling, so the card kept showing 1400 while the TUN and the
                // data plane were on 1280. The probe is the last word on this number, so it
                // has to be the one displayed. (Audit 2026-08-02, follow-up.)
                liveMtu = probed
            } else broadcastLog("UDP path-MTU probe: no result — using MTU $ceiling")
        }
        vpnInterface = setupTunInterface(cfg, r.session)
        // Announce Connected (green + "established" for the reconnect backoff) only AFTER the
        // TUN is up. Doing it at Auth OK, before setupTunInterface, showed a green light with no
        // working tunnel AND made a TUN-establish failure look established → the backoff reset
        // to 0 and re-authed in a tight loop, tripping the hosting's anti-DDoS (issue #69).
        // Mirrors the C# client's Status(Connected)/_wasConnected placement.
        announceConnected(r.session.clientIp)
        broadcastLog("TUN ready, entering tunnel loop")
        runTunnelLoop(cfg, transport, vpnInterface!!, r.enc, r.dec, isUdp)
    }

    /** Active path-MTU discovery on a UDP transport (Android; mirrors the Rust/C# client).
     *  Sends DF-marked probes from [ceiling] down a small ladder; each probe's wire size
     *  equals a full data packet of the candidate MTU, so the largest the server echoes is
     *  a size that traverses the path unfragmented. Returns that MTU or -1 (caller keeps
     *  the pushed/effective MTU) on any miss — purely additive. */
    private fun probeUdpMtu(t: UdpTransport, ceiling: Int): Int {
        val recOverhead = 48   // qeli UDP record + margin, so a probe certifies a real packet
        if (!t.setDontFragment(true)) return -1
        var found = -1
        val ladder = MtuLadder.rungs(ceiling, recOverhead + t.outerOverhead())
        // Randomize the probe-id sequence per connection. A fixed start ("MT") plus a
        // predictable +1 per rung let an off-path attacker forge a probe-ACK and pin the client
        // to a too-large MTU — a DoS on fake-tls-UDP-without-obfs, where the probe rides in the
        // clear. A random 16-bit start means the attacker must guess the id too. Mirrors Rust.
        var id = SecureRandom().nextInt(0x10000)

        // One rung: send up to twice, accept only an ACK echoing this id AND this size.
        // Matching BOTH echoed fields is what stops a stale or forged ACK for a different rung
        // from pinning the client to an MTU the path cannot carry. (Audit 2026-07-30.)
        fun tryMtu(m: Int): Boolean {
            id = (id + 1) and 0xFFFF
            val outerSize = m + recOverhead
            val probe = UdpFrag.mtuProbeDatagram(id, outerSize) ?: return false
            repeat(2) {
                try { t.send(probe, longHeader = false) }
                catch (e: Exception) { return false }   // EMSGSIZE: link < probe
                val payload = t.recvRawPayload(220)
                if (payload != null && UdpFrag.isMtuProbeAck(payload)
                    && UdpFrag.parseMtuProbe(payload) == Pair(id, outerSize)) return true
            }
            return false
        }

        // Coarse pass: walk the rungs high to low, keep the first that answers, and remember
        // the lowest that did NOT — that pair brackets the path's real MTU.
        var failedAbove = -1
        for (m in ladder) {
            if (tryMtu(m)) { found = m; break }
            failedAbove = m
        }

        // Refinement: the coarse pass certifies the best rung that FITS, not the path's
        // maximum. With rungs at 9000 and 6000 an 8999-byte path was pinned to 6000 and threw
        // away a third of every frame — a ladder can only land on its own numbers, so adding
        // rungs moves the loss around instead of removing it. Binary-search the bracket; `lo`
        // has always been proven to work, so a refinement that finds nothing better still
        // returns the coarse result. (Audit 2026-08-01, §8.)
        if (found > 0 && failedAbove > found) {
            var lo = found
            var hi = failedAbove
            // A plain loop, not `repeat`: `return@repeat` continues to the NEXT iteration, so a
            // narrow bracket would spin out the whole budget instead of stopping.
            for (i in 0 until MtuLadder.REFINE_MAX_PROBES) {
                val mid = MtuLadder.refineStep(lo, hi) ?: break
                if (tryMtu(mid)) lo = mid else hi = mid
            }
            found = lo
        }
        // Keep DF on success (packets <= the MTU never fragment); clear it on a miss so a
        // network that drops our probes behaves exactly as before (fragmentation allowed).
        t.setDontFragment(found > 0)
        return found
    }

    // ── shared handshake (transport-agnostic) ────────────────────────────────

    private class HandshakeResult(
        val session: Session, val config: VpnConfig,
        val enc: PacketCodec, val dec: PacketCodec,
        // Server-pushed obfuscation, retained so bonded secondary streams apply the
        // same padding distribution (uniform per-stream fingerprint).
        val pushedObf: PushedObf? = null
    )

    /** Receive one record on UDP, re-sending [resend] on a jittered ~1s tick until a datagram
     *  arrives or [deadline] passes. Used for BOTH handshake legs (ClientHello->ServerHello and
     *  auth->AuthOK), which share one deadline.
     *
     *  UDP has no retransmit of its own, so a single dropped handshake datagram — routine on a
     *  lossy / CGNAT / mobile path, or right after a network change — used to stall the attempt
     *  for the whole connectionTimeoutSecs before the outer loop retried from scratch. Mirrors the
     *  Rust client's hs_deadline / HS_RETRANSMIT_INTERVAL loop: the server's reassembler dedups
     *  duplicate ClientHello fragments, continuation fragments are not re-charged by its
     *  new-session rate limiter, and a duplicate auth packet is replay-dropped — so re-sending is
     *  safe.
     *
     *  The reverse direction is repaired by the SAME retransmit: the server caches its
     *  ServerHello and AuthOK and re-emits on a byte-identical request, the AuthOK up to a small
     *  per-session cap. That is why [resend] must be the identical bytes — the server matches on
     *  them. Only once the cap is spent does this fall through to the deadline and a fresh-port
     *  reconnect, which redoes the whole handshake cleanly. (This used to say the server never
     *  re-emits; it has since 0.7.14.) Jitter keeps a fleet reconnecting after a shared outage
     *  from phase-locking on exact 1.000s ticks. */
    private fun recvUdpWithRetransmit(
        transport: Transport, resend: ByteArray, longHeader: Boolean, config: VpnConfig,
        deadline: Long, expected: String, what: String
    ): ByteArray {
        val rng = SecureRandom()
        var sends = 1   // the caller already sent it once
        // Bound the fragment-reassembly loop by the same handshake deadline, so a flood of
        // never-completing fragments can't spin fill() past it (soTimeout only fires on idle).
        transport.setFillDeadline(deadline)
        try {
            while (true) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) throw Exception(
                    "UDP: no $expected after $sends $what send(s) in ${config.connectionTimeoutSecs}s")
                val round = minOf(HS_RETRANSMIT_MS + rng.nextInt(250), left)
                transport.setReadTimeout(maxOf(round, 1L).toInt())
                try { return transport.recvRecord() }
                catch (_: java.net.SocketTimeoutException) { /* round elapsed — retransmit */ }
                transport.send(resend, longHeader)   // ClientHello: re-sends every fragment
                sends++
                if (sends == 2) broadcastLog("UDP: no $expected yet — re-sending $what")
            }
        } finally {
            // Restore the full per-read budget for the remaining handshake legs.
            transport.setReadTimeout(config.connectionTimeoutSecs.toInt() * 1000)
            // Clear the fill deadline so the data plane's reassembly isn't time-bounded.
            transport.setFillDeadline(Long.MAX_VALUE)
        }
    }

    private fun performHandshake(
        config: VpnConfig, transport: Transport, padToMin: Int, isUdp: Boolean = false
    ): HandshakeResult {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()
        // Which X25519 backend ran, plus API level and ABI. Android had no platform X25519
        // before API 33, so on older devices this line is the difference between "it works"
        // and a silent reconnect loop — worth one log line per connection.
        broadcastLog(KeyExchange.describe())
        val sni = config.sni ?: pickSni(config.serverAddress)
        // Both UDP legs share ONE deadline, so the whole handshake still fits a single
        // connectionTimeoutSecs no matter how many datagrams are re-sent. TCP ignores it (the
        // kernel retransmits there) and stays byte-identical.
        val hsDeadline = System.currentTimeMillis() + config.connectionTimeoutSecs * 1000

        // Hybrid PQ: generate an ML-KEM-768 keypair, run the classic+PQ exchange, and
        // free the native key in finally (so a handshake error can't leak it). The
        // server requires the X25519MLKEM768 share for every non-plain mode.
        val mlkem = MlKem.generate()
        val clientHello: ByteArray
        val serverHelloRecord: ByteArray
        val certRecord: ByteArray
        val finishedRecord: ByteArray
        val sharedSecret: ByteArray
        val mlkemShared: ByteArray
        try {
            clientHello = TlsHandshake.buildClientHelloPq(clientKeyPair.publicKeyBytes, mlkem.encapsulationKey, sni, padToMin)
            transport.send(clientHello, longHeader = true)
            broadcastLog("ClientHello sent (${clientHello.size}B, hybrid X25519+ML-KEM)")

            serverHelloRecord = if (isUdp)
                recvUdpWithRetransmit(transport, clientHello, longHeader = true, config, hsDeadline,
                    "ServerHello", "ClientHello")
            else transport.recvRecord()
            val pq = TlsHandshake.parseServerHelloPq(
                parseHandshakeMessage(serverHelloRecord) ?: throw Exception("Failed to parse ServerHello")
            ) ?: throw Exception("Failed to parse hybrid ServerHello")

            // ChangeCipherSpec (optional), Certificate, Finished.
            var rec = transport.recvRecord()
            if (TlsHandshake.isChangeCipherSpec(rec)) rec = transport.recvRecord()
            certRecord = rec
            finishedRecord = transport.recvRecord()

            sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, pq.serverX25519)
            mlkemShared = mlkem.decapsulate(pq.ciphertext)
        } finally {
            mlkem.close()
        }

        // Auth proof binds to the classic X25519 ephemeral shared (server uses the
        // same); the ML-KEM secret only feeds the hybrid data-plane KDF.
        val (encCodec, decCodec) = makeCodecsHybrid(config, sharedSecret, mlkemShared,
            es = staticEs(config, ke, clientKeyPair.privateKey)) // H-1
        // Transcript: ClientHello, ServerHello, Certificate, Finished (plaintext records).
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientHello, serverHelloRecord, certRecord, finishedRecord)
        )

        // Post-ServerHello flight is now positional-by-record: Certificate and
        // Finished were already consumed above; the server ALWAYS sends exactly one
        // NewSessionTicket (now application_data, 0x17) which we discard by length,
        // and the record AFTER it is the encrypted auth proof. No type peeking — NST
        // and auth-proof are indistinguishable by content type (both 0x17).
        transport.recvRecord() // NewSessionTicket (discarded)
        val authRec = transport.recvRecord()
        val authProofMsg = decCodec.decrypt(authRec)
        val sa = verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex, "${config.serverAddress}:${config.port}", config.allowUnpinnedTofu)
        broadcastLog("Server identity verified [OK]")

        val authPlain = buildClientAuthPlaintext(config, sa.staticShared, sharedSecret, transcriptHash)
        // Encrypt ONCE and re-send the identical inner bytes (only the QUIC wrapper's packet
        // number changes per send): a duplicate that reaches the server is replay-dropped, while a
        // re-send after loss is processed as the real auth. Re-encrypting per send would instead
        // advance this codec's counter past what the server has actually seen.
        val authPacket = encCodec.encrypt(authPlain)
        transport.send(authPacket)

        // A record that decrypts is not automatically the AuthOK.
        //
        // Server cover and heartbeat traffic carries an EMPTY payload and is encrypted with
        // these very keys, so it decrypts perfectly and used to be accepted here — then failed
        // the `OK:` check below with "Auth failed: " and an empty message. The server no longer
        // emits either before the AuthOK, but UDP still loses and reorders: the AuthOK can be
        // dropped while the beacon that follows it arrives. "Empty is not an answer" holds
        // whoever is on the other end, and the retransmit loop is already the right place to
        // wait — a re-sent AUTH makes the server re-emit its AuthOK.
        //
        // Deliberately NOT "anything that isn't OK:": a non-empty refusal from the server must
        // still fail fast rather than spin until the deadline. (Audit 2026-08-03, P1.)
        val authResponse = if (isUdp) {
            var plain: ByteArray
            while (true) {
                plain = decCodec.decrypt(recvUdpWithRetransmit(
                    transport, authPacket, longHeader = false, config,
                    hsDeadline, "AuthOK", "auth"))
                if (plain.isNotEmpty()) break
                broadcastLog("UDP: server cover/beacon arrived before the AuthOK — still waiting")
            }
            plain
        } else {
            decCodec.decrypt(transport.recvRecord())
        }
        val authStr = String(authResponse)
        if (!authStr.startsWith("OK:")) throw Exception("Auth failed: $authStr")
        val ok = parseOk(authStr)

        // Apply server-pushed obfuscation params. Padding is set IN PLACE on the
        // client->server codec so its packet counter keeps advancing — a fresh
        // codec would restart at 0 and the server's replay window would reject the
        // first data packet. Heartbeat params go into an effective config used by
        // the tunnel loop.
        // Resolve the effective TUN MTU: explicit client config (>0) wins, else
        // the server-pushed value (>0), else fall back to 1400. Carried in
        // effConfig so BOTH the TUN setup (setMtu) and the data loop (read buffer)
        // use the resolved value.
        var effConfig = config.copy(mtu = effectiveMtu(config.mtu, ok.session.pushedMtu))
        val pushed = decodePushedObf(ok.obf)
        pushed?.let { po ->
            encCodec.setPadding(po.paddingEnabled, po.paddingMin, po.paddingMax)
            effConfig = effConfig.copy(
                heartbeatEnabled = po.hbEnabled,
                heartbeatIntervalMs = po.hbIntervalMs,
                heartbeatJitterMs = po.hbJitterMs,
                heartbeatDataSize = po.hbDataSize,
                shapingEnabled = po.shEnabled,
                shapingGapMeanMs = po.shGapMeanMs,
                shapingGapMinMs = po.shGapMinMs,
                shapingGapMaxMs = po.shGapMaxMs,
                shapingBudgetBytesPerSec = po.shBudget,
                shapingMinSize = po.shMinSize,
                shapingMaxSize = po.shMaxSize,
                shapingStealth = po.shStealth,
                shapingStealthRateMbps = po.shStealthRateMbps
            )
            broadcastLog("Applied server-pushed obfuscation params")
        }
        broadcastLog("TUN MTU: ${effConfig.mtu}")
        return HandshakeResult(ok.session, effConfig, encCodec, decCodec, pushed)
    }

    /**
     * `plain` wire mode handshake: no TLS mimicry. Exchange ephemeral X25519 publics
     * raw, bind the channel to H(client_pub‖server_pub), then run the same encrypted
     * auth flow over bare length-prefixed records. Mirrors qeli/src/client/mod.rs.
     */
    private fun performHandshakePlain(config: VpnConfig, io: SocketIO): HandshakeResult {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()

        // 1. Raw exchange of the 32-byte ephemeral public keys (no framing).
        io.writeFully(clientKeyPair.publicKeyBytes)
        val serverPublicKey = io.readRaw(32)
        broadcastLog("plain: exchanged ephemeral keys")

        // 2. Transcript binds to both raw publics.
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientKeyPair.publicKeyBytes, serverPublicKey)
        )

        val sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, serverPublicKey)
        val (encCodec, decCodec) = makeCodecs(config, sharedSecret, raw = true,
            es = staticEs(config, ke, clientKeyPair.privateKey)) // H-1

        // 3. Server auth proof (raw record).
        val authProofMsg = decCodec.decrypt(io.readRawRecord())
        val sa = verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex, "${config.serverAddress}:${config.port}", config.allowUnpinnedTofu)
        broadcastLog("Server identity verified [OK] (plain)")

        // 4. Client auth.
        val authPlain = buildClientAuthPlaintext(config, sa.staticShared, sharedSecret, transcriptHash)
        io.writeFully(encCodec.encrypt(authPlain))

        // 5. Auth response (raw record).
        val authResponse = decCodec.decrypt(io.readRawRecord())
        val authStr = String(authResponse)
        if (!authStr.startsWith("OK:")) throw Exception("Auth failed: $authStr")
        val ok = parseOk(authStr)

        // Resolve the effective TUN MTU: explicit client config (>0) wins, else
        // the server-pushed value (>0), else fall back to 1400. Carried in
        // effConfig so BOTH the TUN setup (setMtu) and the data loop (read buffer)
        // use the resolved value.
        var effConfig = config.copy(mtu = effectiveMtu(config.mtu, ok.session.pushedMtu))
        val pushed = decodePushedObf(ok.obf)
        pushed?.let { po ->
            encCodec.setPadding(po.paddingEnabled, po.paddingMin, po.paddingMax)
            effConfig = effConfig.copy(
                heartbeatEnabled = po.hbEnabled,
                heartbeatIntervalMs = po.hbIntervalMs,
                heartbeatJitterMs = po.hbJitterMs,
                heartbeatDataSize = po.hbDataSize,
                shapingEnabled = po.shEnabled,
                shapingGapMeanMs = po.shGapMeanMs,
                shapingGapMinMs = po.shGapMinMs,
                shapingGapMaxMs = po.shGapMaxMs,
                shapingBudgetBytesPerSec = po.shBudget,
                shapingMinSize = po.shMinSize,
                shapingMaxSize = po.shMaxSize,
                shapingStealth = po.shStealth,
                shapingStealthRateMbps = po.shStealthRateMbps
            )
            broadcastLog("Applied server-pushed obfuscation params")
        }
        broadcastLog("TUN MTU: ${effConfig.mtu}")
        return HandshakeResult(ok.session, effConfig, encCodec, decCodec, pushed)
    }

    // ── shared tunnel loop (transport-agnostic) ──────────────────────────────

    /**
     * Scope for the data-plane children (upload / download / heartbeat / stats) of the
     * CURRENT attempt.
     *
     * They used to be launched into the service-wide `coroutineScope`, read at loop entry.
     * That field is nulled by teardown() and replaced by the next startVpn(), so a stale
     * attempt still unwinding could hang its jobs off the NEW session's scope, where nothing
     * that cancels the old attempt reaches them. Deriving the scope from the calling
     * coroutine ties them to the attempt that created them instead.
     *
     * The job is a SupervisorJob so the behaviour is unchanged in the other direction: these
     * children report failures through the tunnelError channel, and one of them dying must
     * not cancel its siblings or the retry loop. (Audit 2026-07-27, M3)
     */
    private suspend fun dataPlaneScope(): CoroutineScope {
        val ctx = currentCoroutineContext()
        return CoroutineScope(ctx + SupervisorJob(ctx[Job]))
    }

    /** Tell the server what this build is, so `list-clients` and the panel can answer "who still
     *  needs to update?". Sent once per attempt on the same authenticated in-tunnel path as the
     *  MTU report, and nothing waits for a reply — a server that predates the frame discards it
     *  and shows the session as unknown, exactly as before.
     *
     *  No re-send on UDP, unlike the MTU report: losing this costs a label in an operator's
     *  table, not the session's downlink sizing. */
    private fun reportClientInfo(transport: Transport, enc: PacketCodec) {
        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName
        } catch (_: Exception) {
            null
        } ?: return
        val frame = CtrlFrame.clientInfo(version) ?: return
        try {
            // No padding, for the same reason as the MTU report above.
            transport.send(enc.encryptPadded(frame, 0))
        } catch (e: Exception) {
            // Never fatal: this is diagnostics. A real transport failure surfaces in the loop.
            broadcastLog("could not report client version: ${e.message}")
        }
    }

    /** Re-send delays for the unacknowledged MTU report on UDP, measured as successive GAPS, so the copies land ~2 s and ~8 s after the first.
     *  Spread so an isolated drop AND a short burst of loss are both survived. */
    private val reportRetryDelaysMs = longArrayOf(2_000, 6_000)

    /** Tell the server the MTU we settled on (#13). It sizes its downlink from the profile's
     *  tun.mtu — the path up to ITS tun — so it cannot see that our leg is narrower (a probed
     *  LTE/CGNAT path, or an explicit smaller mtu in our config). Without this, every large
     *  packet it forwards is dropped with no signal to anyone: the connection establishes and
     *  then stalls on the first big transfer.
     *
     *  The frame is unacknowledged by design (the server never answers a control frame), so on
     *  UDP a single lost datagram would leave the server on `path_mtu = 0` for the WHOLE
     *  session — on precisely the unreliable transport where the report matters most. The frame
     *  is idempotent (the server simply stores the latest value, and the copies all carry the same one), so re-sending costs a
     *  few bytes and removes that single point of loss. TCP retransmits for us, so it sends
     *  once. (Audit 2026-07-30, #5.)
     *
     *  Never fatal: the tunnel works without the report, just without the downlink narrowing. */
    private fun reportTunnelMtu(
        transport: Transport, enc: PacketCodec, mtu: Int, isUdp: Boolean, scope: CoroutineScope
    ) {
        fun sendOnce(attempt: Int): Boolean = try {
            // NO padding, like the Rust client. A plain encrypt() applies the configured padding, so
            // with padding_min near the MTU a six-byte control frame became a datagram larger than
            // the path MTU just discovered — and under DF it failed with EMSGSIZE, every re-send
            // identically, leaving the server without an MTU at all. (Audit 2026-07-31, §6.)
            transport.send(enc.encryptPadded(CtrlFrame.mtuReport(mtu), 0))
            if (attempt == 0) broadcastLog("reported tunnel MTU $mtu to the server")
            true
        } catch (e: Exception) {
            if (attempt == 0) broadcastLog("could not report tunnel MTU: ${e.message}")
            false
        }

        if (!sendOnce(0) || !isUdp) return
        scope.launch {
            reportRetryDelaysMs.forEachIndexed { i, d ->
                kotlinx.coroutines.delay(d)
                if (!sendOnce(i + 1)) return@launch
            }
        }
    }

    private suspend fun runTunnelLoop(
        config: VpnConfig, transport: Transport, tunFd: ParcelFileDescriptor,
        encCodec: PacketCodec, decCodec: PacketCodec, isUdp: Boolean
    ) {
        val scope = dataPlaneScope()
        // false on Android 9/10 (no Os.fcntlInt) → the reads below must tolerate EAGAIN.
        val tunBlocking = forceBlocking(tunFd)
        val tunInput = FileInputStream(tunFd.fileDescriptor)
        val tunOutput = FileOutputStream(tunFd.fileDescriptor)
        val buf = ByteArray(config.mtu + 100)
        val rng = SecureRandom()
        val lastRx = AtomicLong(System.currentTimeMillis())
        // Last USER uplink packet (not a keepalive) — drives the uplink-active/downlink-
        // silent dead-session check below.
        val lastTx = AtomicLong(System.currentTimeMillis())
        val bytesUp = AtomicLong(0)
        val bytesDown = AtomicLong(0)
        val rxDead = maxOf(config.heartbeatIntervalMs * 3, 30_000L)
        // Does the SERVER owe us traffic on an idle tunnel? Only when its heartbeat or its
        // flow-shaping cover is on. With both off the server is silent by design, so a
        // silence-based reconnect fires on a perfectly healthy link — every rxDead, i.e.
        // roughly every 30 s, forever. The Rust and C# clients already gate on this; Android
        // did not, which is why an idle UDP session reconnected in a loop.
        // (Audit 2026-07-29, #10.)
        val expectServerData = (config.heartbeatEnabled && config.heartbeatIntervalMs > 0) ||
            config.shapingEnabled
        val tunnelError = kotlinx.coroutines.channels.Channel<Throwable>(kotlinx.coroutines.channels.Channel.CONFLATED)

        // Tell the server the MTU we settled on (#13). It sizes its downlink from the profile's
        // tun.mtu — the path up to ITS tun — so it cannot see that our leg is narrower (a probed
        // LTE/CGNAT path, or an explicit smaller mtu in our config). Without this, every large
        // packet it forwards is dropped with no signal to anyone: the connection establishes and
        // then stalls on the first big transfer. Sent once per attempt, fire-and-forget — the
        // server ignores a value that is not narrower, and an older server discards the frame.
        reportTunnelMtu(transport, encCodec, config.mtu, isUdp, scope)
        reportClientInfo(transport, encCodec)

        // Poll the UDP RX path every ~3s (not once per rxDead) so the dead-session / resume
        // checks below run promptly instead of up to rxDead late. TCP ignores the timeout;
        // the heartbeat job checks rxDead there.
        if (isUdp) transport.setReadTimeout(3000)

        // Stealth (TCP-only): rate-cap the uplink to stealth_rate and fill the cap
        // gaps with jittered small cover, so an upload stops looking like a high-rate
        // bulk transfer (mirrors the Rust client). The server already shapes the
        // downlink for every client; this is the matching uplink half.
        val uploadJob = scope.launch(Dispatchers.IO) {
            val upShaper = TrafficShaper(
                config.shapingEnabled, config.shapingGapMeanMs, config.shapingGapMinMs,
                config.shapingGapMaxMs, config.shapingBudgetBytesPerSec,
                config.shapingMinSize, config.shapingMaxSize,
                config.shapingStealth, config.shapingStealthRateMbps
            )
            val upStealth = upShaper.stealth && !isUdp
            try {
                while (isActive) {
                    val len = readTun(tunInput, buf, tunFd, tunBlocking)
                    if (len < 0) break          // genuine EOF (fd closed)
                    if (len == 0) continue      // no data this round — keep reading
                    if (((buf[0].toInt() and 0xFF) shr 4) != 4) continue // IPv4 only
                    // Cap padding so the padded record stays inside the (probed) tunnel MTU:
                    // with DF set after the MTU probe, the server-pushed 40–400 B of padding
                    // otherwise blows a full-size data packet past the path MTU → the kernel
                    // rejects it with EMSGSIZE. On UDP that must DROP the datagram (inner TCP
                    // retransmits), never tear the tunnel down — a genuinely dead link is
                    // caught by the RX-liveness timeout below. TCP is an in-order stream, so
                    // a write error there IS fatal. (This EMSGSIZE-was-fatal path is what put
                    // udp-quic into an endless auth→"closed cleanly"→reconnect loop.)
                    try {
                        transport.send(if (isUdp) encCodec.encryptCapped(buf.copyOf(len), config.mtu)
                                       else encCodec.encrypt(buf.copyOf(len)))
                    } catch (e: Exception) {
                        if (!isUdp) throw e
                        continue    // drop-on-egress-error (UDP loss semantics)
                    }
                    bytesUp.addAndGet(len.toLong())
                    lastTx.set(System.currentTimeMillis()) // user uplink is flowing
                    if (upStealth) {
                        var remaining = upShaper.stealthPaceMs(len)
                        while (remaining > 6 && isActive) {
                            val csize = upShaper.nextSize()
                            if (upShaper.trySpend(csize)) transport.send(encCodec.encryptPadded(ByteArray(0), csize))
                            val step = minOf(remaining, (rng.nextInt(15) + 4).toLong())
                            delay(step)
                            remaining -= step
                        }
                    }
                }
            } catch (e: Exception) { tunnelError.trySend(e) }
        }

        val downloadJob = scope.launch(Dispatchers.IO) {
            try {
                while (isActive) {
                    val rec = try {
                        transport.recvRecord()
                    } catch (e: java.net.SocketTimeoutException) {
                        val now = System.currentTimeMillis()
                        // Uplink active but nothing coming back ⇒ dead session (network
                        // change, reaped after a nap, NAT rebind). A live tunnel with active
                        // TX always returns ACKs/data. Independent of heartbeat/shaping.
                        if (now - lastTx.get() < 2000L && now - lastRx.get() > 8000L) {
                            tunnelError.trySend(Exception("uplink active but no downlink >8s")); break
                        }
                        if (expectServerData && now - lastRx.get() > rxDead) {
                            tunnelError.trySend(Exception("no data from server for >${rxDead / 1000}s")); break
                        }
                        continue
                    }
                    // UDP datagrams can be reordered/corrupt → drop and continue.
                    // TCP is an in-order stream → a decrypt failure is fatal desync.
                    val plaintext = if (isUdp) {
                        try { decCodec.decrypt(rec) } catch (_: Exception) { continue }
                    } else decCodec.decrypt(rec)
                    lastRx.set(System.currentTimeMillis())
                    if (plaintext.isNotEmpty()) {
                        tunOutput.write(plaintext); tunOutput.flush()
                        bytesDown.addAndGet(plaintext.size.toLong())
                    }
                }
            } catch (e: Exception) { tunnelError.trySend(e) }
        }

        // Heartbeat OR — when flow-shaping is on — Poisson idle cover. Cover
        // replaces the fixed heartbeat: same empty encrypted record the peer
        // drops, but at exponential (non-periodic) gaps + browsing-ish sizes,
        // capped by a byte budget (DPI-AUDIT 6.1/6.2). Budget bounds cover during
        // active transfer, so no separate idle-gate is needed here.
        val heartbeatJob = scope.launch(Dispatchers.IO) {
            val shaper = TrafficShaper(
                config.shapingEnabled, config.shapingGapMeanMs, config.shapingGapMinMs,
                config.shapingGapMaxMs, config.shapingBudgetBytesPerSec,
                config.shapingMinSize, config.shapingMaxSize
            )
            val hbOn = config.heartbeatEnabled && config.heartbeatIntervalMs > 0
            if (!shaper.enabled && !hbOn) return@launch
            while (isActive) {
                val wait = if (shaper.enabled) shaper.nextGapMs().coerceAtLeast(1)
                           else (config.heartbeatIntervalMs + jitterMs(rng, config.heartbeatJitterMs)).coerceAtLeast(1000)
                delay(wait)
                try {
                    if (shaper.enabled) {
                        // Cap cover size to the (probed) MTU on UDP so a DF-marked cover
                        // datagram isn't rejected with EMSGSIZE (same reason as data above).
                        var size = shaper.nextSize()
                        if (isUdp) size = size.coerceAtMost((config.mtu - 60).coerceAtLeast(0))
                        if (shaper.trySpend(size)) transport.send(encCodec.encryptPadded(ByteArray(0), size))
                    } else {
                        // Pad the keepalive to config.heartbeatDataSize (+ up to 32), the same
                        // as the Rust client. It used to go out EMPTY, so the server-pushed
                        // `data_size_bytes` this config parses did nothing here — and an empty
                        // encrypted record at a fixed cadence is the most distinctive size a
                        // DPI box could ask for, which is precisely what the setting exists to
                        // avoid. Capped to the path MTU on UDP for the same reason as cover.
                        var hb = config.heartbeatDataSize.coerceAtLeast(0)
                        var hbHi = hb + 32
                        if (isUdp) {
                            val cap = (config.mtu - 60).coerceAtLeast(0)
                            hb = hb.coerceAtMost(cap); hbHi = hbHi.coerceAtMost(cap)
                        }
                        val size = if (hbHi > hb) hb + rng.nextInt(hbHi - hb + 1) else hb
                        transport.send(encCodec.encryptPadded(ByteArray(0), size))
                    }
                } catch (e: Exception) {
                    // A failed keepalive/cover send is not fatal on UDP (drop, like data);
                    // liveness is detected by the RX timeout. On TCP a write error is fatal.
                    if (isUdp) continue
                    tunnelError.trySend(e); break
                }
                // TCP has no read timeout, so detect a dead server here.
                if (expectServerData && !isUdp && System.currentTimeMillis() - lastRx.get() > rxDead) {
                    tunnelError.trySend(Exception("no data from server for >${rxDead / 1000}s"))
                    break
                }
            }
        }

        // Stats: once a second, broadcast the up/down byte-rate for the UI readout.
        val statsJob = scope.launch(Dispatchers.IO) {
            var lastUp = 0L; var lastDown = 0L; var lastT = System.currentTimeMillis()
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                val dt = (now - lastT).coerceAtLeast(1)
                val u = bytesUp.get(); val d = bytesDown.get()
                liveBytesUp = u; liveBytesDown = d
                broadcastStats((u - lastUp) * 1000 / dt, (d - lastDown) * 1000 / dt, u, d)
                lastUp = u; lastDown = d; lastT = now
            }
        }

        val cause: Throwable
        try {
            cause = tunnelError.receive()
        } finally {
            // Cancel only OUR data-plane jobs — never the service-wide scope, of which
            // connectWithRetry is itself a child: cancelling that would kill the reconnect
            // loop, which made delay() throw CancellationException and spin the loop
            // instantly on every disconnect. Since the jobs now hang off a per-attempt
            // scope (see dataPlaneScope), cancelling that scope IS "only our jobs", and it
            // also retires the attempt's own job instead of leaving one behind per
            // reconnect. (Audit 2026-07-27, M3)
            uploadJob.cancel(); downloadJob.cancel(); heartbeatJob.cancel(); statsJob.cancel()
            scope.cancel()
        }
        // Surface the REAL reason the tunnel dropped. Swallowing it here logged a
        // misleading "Connection closed cleanly" for what was actually an error (e.g. the
        // EMSGSIZE loop above), and reset the reconnect backoff as if it were a clean
        // shutdown. Re-throw so connectWithRetry logs the cause and backs off correctly.
        throw cause
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

    /** Symmetric heartbeat jitter in [-jitter, +jitter). Avoids RandomGenerator.nextLong(bound) (API 34+). */
    private fun jitterMs(rng: SecureRandom, jitter: Long): Long {
        if (jitter <= 0) return 0L
        val r = (rng.nextLong() and Long.MAX_VALUE) % (jitter * 2)
        return r - jitter
    }

    /** The `Host:` value for the obfs WebSocket Upgrade, with the same precedence the
     *  fake-TLS SNI uses: an explicit `obfuscation.sni` wins, else the connect hostname,
     *  else null (a random decoy) when dialling a bare IP — so the cleartext header agrees
     *  with where the packets actually go instead of naming an unrelated CDN. Rust has done
     *  this since audit 2026-07-27 (E2); this port had not. (Audit 2026-08-04, M-08.) */
    private fun wsHostFor(config: VpnConfig): String? {
        config.sni?.let { if (it.isNotEmpty()) return it }
        val isIp = config.serverAddress.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
        return if (isIp) null else config.serverAddress
    }

    private fun pickSni(address: String): String {
        // Use the server address as SNI when it's a hostname; random realistic SNI for raw IPs.
        val isIp = address.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
        if (!isIp) return address
        // ONE list, shared with the WebSocket Host pool — see TlsHandshake.DEFAULT_SNI_POOL.
        val pool = TlsHandshake.DEFAULT_SNI_POOL
        return pool[SecureRandom().nextInt(pool.size)]
    }

    // ── stateless TLS parsing / hex helpers (socket-agnostic) ────────────────

    private fun parseHandshakeMessage(record: ByteArray): ByteArray? {
        if (record.size < 6) return null
        if ((record[0].toInt() and 0xFF) != 0x16) return null
        val payloadLen = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
        if (record.size < 5 + payloadLen) return null
        return record.copyOfRange(5, 5 + payloadLen)
    }

    /** Hex string → bytes (ignores `:`/space separators). */
    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        return ByteArray(clean.length / 2) {
            ((Character.digit(clean[it * 2], 16) shl 4) or Character.digit(clean[it * 2 + 1], 16)).toByte()
        }
    }

    /** REALITY short_id: hex → exactly 8 bytes, zero-padded (matches the Rust
     *  `crypto::reality::short_id_from_hex`). */
    private fun shortIdFromHex(hex: String): ByteArray {
        val clean = hex.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
        val out = ByteArray(8)
        var i = 0
        while (i / 2 < 8 && i + 1 < clean.length) {
            out[i / 2] = ((Character.digit(clean[i], 16) shl 4) or Character.digit(clean[i + 1], 16)).toByte()
            i += 2
        }
        return out
    }

    // ── per-socket IO (one instance per bonded stream) ───────────────────────
    //
    // Each connection — the primary plus every secondary bonded stream — owns one
    // SocketIO: its own channel, optional obfs transform, and write lock. These
    // framed read/write helpers used to be instance methods bound to the single
    // `socketChannel`; making them per-socket is what lets several reality-tls
    // connections run in parallel for stream bonding (multipath).
    private inner class SocketIO(val channel: SocketChannel) {
        var obfs: ObfsStream? = null
        private val writeLock = Any()

        /** Write [data] through the obfs transform (if any), serialized per socket. */
        fun writeFully(data: ByteArray) {
            val o = obfs
            // F3: under WebSocket fronting the ciphered bytes travel as masked
            // client->server binary frames (writeFramed = ChaCha20 THEN WS-frame);
            // otherwise they go out as the raw continuous ChaCha20-XOR stream.
            if (o != null && o.isWebSocket) { o.writeFramed(data) { writeRaw(it) }; return }
            writeRaw(o?.transformWrite(data) ?: data)
        }

        fun writeRaw(data: ByteArray) {
            synchronized(writeLock) {
                var off = 0
                while (off < data.size) {
                    val n = channel.write(ByteBuffer.wrap(data, off, data.size - off))
                    if (n < 0) throw Exception("Connection closed")
                    off += n
                }
            }
        }

        fun readTlsRecord(): ByteArray {
            val header = readBytes(5)
            val payloadLen = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
            if (payloadLen > 65535) throw Exception("TLS record too large: $payloadLen")
            return header + readBytes(payloadLen)
        }

        /** Read one bare length-prefixed record ([u16 len][nonce][ct]) for the
         *  `plain` wire mode. Mirrors read_record(Framing::Raw) on the Rust side. */
        fun readRawRecord(): ByteArray {
            val header = readBytes(2)
            val payloadLen = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
            if (payloadLen > 65535) throw Exception("raw record too large: $payloadLen")
            return header + readBytes(payloadLen)
        }

        /** Read [size] de-obfuscated bytes from this socket. */
        fun readBytes(size: Int): ByteArray {
            val o = obfs
            // F3: under WebSocket fronting pull `size` cipherbytes out of the inbound
            // binary frames (readFramed = WS-deframe THEN ChaCha20) before returning;
            // otherwise read them straight off the raw stream (pre-F3 behaviour).
            if (o != null && o.isWebSocket) return o.readFramed(size) { readRaw(it) }
            val raw = readRaw(size)
            return o?.transformRead(raw) ?: raw
        }

        /** Read exactly [size] raw bytes (before obfs transform). */
        fun readRaw(size: Int): ByteArray {
            val buf = ByteArray(size)
            var off = 0
            // The channel is blocking, so read() returns >=1 or -1 (EOF) — never 0
            // with a non-empty buffer (T11: the old n==0 + Thread.sleep retry was a
            // dead busy-wait, and not a real timeout). Liveness is enforced by the
            // rxDead deadline in the data-plane/heartbeat loops, not here.
            while (off < size) {
                val n = channel.read(ByteBuffer.wrap(buf, off, size - off))
                if (n < 0) throw Exception("Connection closed")
                off += n
            }
            return buf
        }

        /** Read whatever raw bytes are currently available (≥1), for the realtls
         *  handshake which buffers/parses incrementally. */
        fun readSomeRaw(max: Int = 16384): ByteArray {
            // Blocking channel: read() blocks for >=1 byte or returns -1 (EOF).
            val buf = ByteArray(max)
            val n = channel.read(ByteBuffer.wrap(buf))
            if (n < 0) throw Exception("Connection closed")
            return buf.copyOf(n)
        }
    }

    // ── stream bonding (multipath) ───────────────────────────────────────────
    //
    // One logical tunnel carried over N parallel reality-tls connections that the
    // server aggregates into one session (one TUN IP). Each Stream owns its own
    // socket, RealTls session, and enc/dec codecs (independent nonce space). The
    // primary authenticates; secondaries present the session JOIN token.

    private inner class Stream(
        val io: SocketIO,
        val transport: Transport,
        val enc: PacketCodec,
        val dec: PacketCodec,
        val tls: RealTls?,
        // Set once when this stream dies (reader/writer/upload), so its death is
        // counted exactly once for the live-stream tally (loss-resilience).
        val dead: java.util.concurrent.atomic.AtomicBoolean = java.util.concurrent.atomic.AtomicBoolean(false)
    )

    /**
     * Secondary-connection handshake. Identical to performHandshake up to verifying
     * the server identity, but instead of credentials it presents the per-session
     * JOIN token (JOIN_MAGIC‖token‖stream_index); the server replies "JOINOK".
     * Mirrors qeli/src/client/mod.rs::tcp_join_handshake.
     */
    private fun performJoinHandshake(
        config: VpnConfig, transport: Transport, token: ByteArray, index: Int
    ): Pair<PacketCodec, PacketCodec> {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()
        val sni = config.sni ?: pickSni(config.serverAddress)

        val mlkem = MlKem.generate() // hybrid PQ, same as the primary handshake
        val clientHello: ByteArray
        val serverHelloRecord: ByteArray
        val certRecord: ByteArray
        val finishedRecord: ByteArray
        val sharedSecret: ByteArray
        val mlkemShared: ByteArray
        try {
            clientHello = TlsHandshake.buildClientHelloPq(clientKeyPair.publicKeyBytes, mlkem.encapsulationKey, sni, 0)
            transport.send(clientHello, longHeader = true)

            serverHelloRecord = transport.recvRecord()
            val pq = TlsHandshake.parseServerHelloPq(
                parseHandshakeMessage(serverHelloRecord) ?: throw Exception("JOIN: parse ServerHello")
            ) ?: throw Exception("JOIN: parse hybrid ServerHello")

            var rec = transport.recvRecord()
            if (TlsHandshake.isChangeCipherSpec(rec)) rec = transport.recvRecord()
            certRecord = rec
            finishedRecord = transport.recvRecord()

            sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, pq.serverX25519)
            mlkemShared = mlkem.decapsulate(pq.ciphertext)
        } finally {
            mlkem.close()
        }
        val (encCodec, decCodec) = makeCodecsHybrid(config, sharedSecret, mlkemShared,
            es = staticEs(config, ke, clientKeyPair.privateKey)) // H-1
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientHello, serverHelloRecord, certRecord, finishedRecord)
        )

        // Positional flight (see performHandshake): always discard one NST (0x17)
        // record, then the next record is the encrypted auth proof.
        transport.recvRecord() // NewSessionTicket (discarded)
        val authRec = transport.recvRecord()
        val authProofMsg = decCodec.decrypt(authRec)
        verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex, "${config.serverAddress}:${config.port}", config.allowUnpinnedTofu)

        // Present the session JOIN token instead of username:password.
        val join = ByteArray(joinMagic.size + token.size + 1)
        System.arraycopy(joinMagic, 0, join, 0, joinMagic.size)
        System.arraycopy(token, 0, join, joinMagic.size, token.size)
        join[join.size - 1] = index.toByte()
        transport.send(encCodec.encrypt(join))

        val ack = decCodec.decrypt(transport.recvRecord())
        if (String(ack) != "JOINOK") throw Exception("JOIN rejected by server")
        return encCodec to decCodec
    }

    /** Open one secondary bonded connection (same wire mode as the primary) and
     *  JOIN it to the session. The socket is protect()ed (so it doesn't loop back
     *  through the VPN) and registered for teardown. Works for every TCP mode. */
    private fun openBondedStream(
        config: VpnConfig, token: ByteArray, index: Int, transports: Attempt
    ): Stream {
        val ch = SocketChannel.open()
        var registered = false
        try {
            protectSocket("bonded #$index") { protect(ch.socket()) }
            ch.socket().soTimeout = config.connectionTimeoutSecs.toInt() * 1000
            ch.connect(InetSocketAddress(config.serverAddress, config.port))
            ch.socket().keepAlive = true
            ch.socket().tcpNoDelay = true
            ch.configureBlocking(true)
            transports.bonded.add(ch)
            registered = true
            val io = SocketIO(ch)
            return when {
                config.wireMode.equals("plain", ignoreCase = true) -> {
                    val transport = TcpTransport(io, raw = true)
                    val (enc, dec) = performJoinHandshakePlain(config, io, token, index)
                    Stream(io, transport, enc, dec, null)
                }
                config.wireMode.equals("reality-tls", ignoreCase = true) -> {
                    val tls = doRealTlsHandshake(config, io)
                    try {
                        val transport = RealTlsTransport(TcpTransport(io), tls)
                        val (enc, dec) = performJoinHandshake(config, transport, token, index)
                        Stream(io, transport, enc, dec, tls)
                    } catch (e: Throwable) {
                        // JOIN failed — the outer catch only closes the socket, so close the
                        // native TLS session here before rethrowing (else it leaks per attempt).
                        try { tls.close() } catch (_: Throwable) {}
                        throw e
                    }
                }
                config.wireMode.equals("obfs", ignoreCase = true) -> {
                    val fronting = config.obfsFronting.equals("websocket", ignoreCase = true)
                    // AWG junk must be sent on EVERY connection (the server expects
                    // `jc` junk records per obfs handshake, bonded streams included).
                    io.obfs = ObfsStream.connect(ObfsStream.deriveKey(config.obfsKey), fronting,
                        sendRaw = { io.writeRaw(it) }, recvRaw = { io.readRaw(it) },
                        awgJc = if (config.awgEnabled) config.awgJc else 0,
                        awgJmin = config.awgJmin, awgJmax = config.awgJmax)
                    val transport = TcpTransport(io)
                    val (enc, dec) = performJoinHandshake(config, transport, token, index)
                    Stream(io, transport, enc, dec, null)
                }
                else -> { // fake-tls
                    val transport = TcpTransport(io)
                    val (enc, dec) = performJoinHandshake(config, transport, token, index)
                    Stream(io, transport, enc, dec, null)
                }
            }
        } catch (e: Throwable) {
            // Don't leak the socket if connect or the JOIN handshake throws (T10).
            if (registered) transports.bonded.remove(ch)
            try { ch.close() } catch (_: Throwable) {}
            throw e
        }
    }

    /**
     * `plain` secondary-connection handshake: raw X25519 exchange + identity verify
     * (mirrors performHandshakePlain), then present the JOIN token over raw-framed
     * records instead of credentials. Mirrors tcp_join_handshake's plain branch.
     */
    private fun performJoinHandshakePlain(
        config: VpnConfig, io: SocketIO, token: ByteArray, index: Int
    ): Pair<PacketCodec, PacketCodec> {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()
        io.writeFully(clientKeyPair.publicKeyBytes)
        val serverPublicKey = io.readRaw(32)
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientKeyPair.publicKeyBytes, serverPublicKey)
        )
        val sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, serverPublicKey)
        val (encCodec, decCodec) = makeCodecs(config, sharedSecret, raw = true,
            es = staticEs(config, ke, clientKeyPair.privateKey)) // H-1
        val authProofMsg = decCodec.decrypt(io.readRawRecord())
        verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex, "${config.serverAddress}:${config.port}", config.allowUnpinnedTofu)

        val join = ByteArray(joinMagic.size + token.size + 1)
        System.arraycopy(joinMagic, 0, join, 0, joinMagic.size)
        System.arraycopy(token, 0, join, joinMagic.size, token.size)
        join[join.size - 1] = index.toByte()
        io.writeFully(encCodec.encrypt(join))

        val ack = decCodec.decrypt(io.readRawRecord())
        if (String(ack) != "JOINOK") throw Exception("JOIN(plain) rejected by server")
        return encCodec to decCodec
    }

    /**
     * Multipath data plane: one upload coroutine round-robins outgoing TUN packets
     * across the live streams; each stream has its own download + heartbeat
     * coroutine (its dec codec is therefore single-threaded, and seal/open on its
     * RealTls are serialized by the per-instance lock). FIXED mode opens
     * maxStreams immediately; ADAPTIVE ramps from 1 up under measured load.
     */
    private suspend fun runMultipathTunnelLoop(
        config: VpnConfig, primary: Stream, session: Session,
        pushedObf: PushedObf?, tunFd: ParcelFileDescriptor, transports: Attempt
    ) {
        val scope = dataPlaneScope()
        // Report the MTU here too, not only in the single-stream loop: this branch is taken
        // whenever the server profile allows bonding, and it used to skip the report entirely —
        // so the server stayed on path_mtu = 0 and the downlink narrowing never engaged for any
        // bonded client. Sent on the PRIMARY stream, before the others are ramped up. Bonding is
        // TCP-only, so no UDP re-sends are needed. (Audit 2026-07-30, #4.)
        reportTunnelMtu(primary.transport, primary.enc, config.mtu, isUdp = false, scope = scope)
        reportClientInfo(primary.transport, primary.enc)
        // false on Android 9/10 (no Os.fcntlInt) → the reads below must tolerate EAGAIN.
        val tunBlocking = forceBlocking(tunFd)
        val tunInput = FileInputStream(tunFd.fileDescriptor)
        val tunOutput = FileOutputStream(tunFd.fileDescriptor)
        val tunWriteLock = Any()
        val rng = SecureRandom()
        val lastRx = AtomicLong(System.currentTimeMillis())
        val lastTx = AtomicLong(System.currentTimeMillis()) // last USER uplink packet (see single-path)
        val bytesUp = AtomicLong(0)
        val bytesDown = AtomicLong(0)
        val rxDead = maxOf(config.heartbeatIntervalMs * 3, 30_000L)
        // Same gate as the single-stream path: with the server's heartbeat and cover both
        // off it is silent by design, and a silence-based reconnect would fire on a healthy
        // bonded session too. (Audit 2026-07-29, #10.)
        val expectServerData = (config.heartbeatEnabled && config.heartbeatIntervalMs > 0) ||
            config.shapingEnabled
        val tunnelError = kotlinx.coroutines.channels.Channel<Throwable>(
            kotlinx.coroutines.channels.Channel.CONFLATED
        )

        val streams = java.util.concurrent.CopyOnWriteArrayList<Stream>()
        val jobs = java.util.concurrent.CopyOnWriteArrayList<Job>()
        val token = hexToBytes(session.sessionToken)
        val target = session.maxStreams.coerceIn(1, maxBonded)
        val rr = AtomicInteger(0)
        // Count of streams still up; a stream's death tears the tunnel down only when
        // this reaches 0 (losing one bonded stream degrades to the rest).
        val live = AtomicInteger(0)

        // Handle one stream's death: counted once (s.dead), drop it from the rotation,
        // and fire the fatal tunnel error ONLY if it was the last live stream.
        fun onStreamDeath(s: Stream, e: Throwable) {
            if (!s.dead.getAndSet(true)) {
                streams.remove(s)
                try { s.tls?.close() } catch (_: Exception) {}
                try { s.io.channel.close() } catch (_: Exception) {}
                if (live.decrementAndGet() <= 0) tunnelError.trySend(e)
                else broadcastLog("Bonded stream lost; ${streams.size} stream(s) remain")
            }
        }

        // Per-stream download + heartbeat. Decrypt is single-threaded per stream;
        // the shared TUN writer is serialized by tunWriteLock.
        fun launchStreamJobs(s: Stream) {
            live.incrementAndGet()
            jobs.add(scope.launch(Dispatchers.IO) {
                try {
                    while (isActive) {
                        val plaintext = s.dec.decrypt(s.transport.recvRecord())
                        lastRx.set(System.currentTimeMillis())
                        if (plaintext.isNotEmpty()) {
                            synchronized(tunWriteLock) { tunOutput.write(plaintext); tunOutput.flush() }
                            bytesDown.addAndGet(plaintext.size.toLong())
                        }
                    }
                } catch (e: Exception) { onStreamDeath(s, e) }
            })
            // Per-stream heartbeat OR (flow-shaping on) Poisson idle cover. Each
            // bonded stream carries its own cover budget.
            val shaperS = TrafficShaper(
                config.shapingEnabled, config.shapingGapMeanMs, config.shapingGapMinMs,
                config.shapingGapMaxMs, config.shapingBudgetBytesPerSec,
                config.shapingMinSize, config.shapingMaxSize
            )
            val hbOnS = config.heartbeatEnabled && config.heartbeatIntervalMs > 0
            if (shaperS.enabled || hbOnS) {
                jobs.add(scope.launch(Dispatchers.IO) {
                    while (isActive) {
                        val wait = if (shaperS.enabled) shaperS.nextGapMs().coerceAtLeast(1)
                                   else (config.heartbeatIntervalMs + jitterMs(rng, config.heartbeatJitterMs)).coerceAtLeast(1000)
                        delay(wait)
                        try {
                            if (shaperS.enabled) {
                                val size = shaperS.nextSize()
                                if (shaperS.trySpend(size)) s.transport.send(s.enc.encryptPadded(ByteArray(0), size))
                            } else {
                                s.transport.send(s.enc.encrypt(ByteArray(0)))
                            }
                        } catch (e: Exception) { onStreamDeath(s, e); break }
                    }
                })
            }
        }

        streams.add(primary)
        launchStreamJobs(primary)

        if (!session.adaptive) {
            // FIXED: open the remaining streams now.
            for (idx in 1 until target) {
                try {
                    val s = openBondedStream(config, token, idx, transports)
                    pushedObf?.let { s.enc.setPadding(it.paddingEnabled, it.paddingMin, it.paddingMax) }
                    streams.add(s); launchStreamJobs(s)
                    broadcastLog("Bonded stream #$idx joined (${streams.size} active)")
                } catch (e: Exception) {
                    broadcastLog("bonded #$idx failed: ${e.javaClass.simpleName}: ${e.message}")
                }
            }
            broadcastLog("Multipath: ${streams.size} bonded stream(s) active (fixed)")
        } else {
            // ADAPTIVE: ramp from 1 stream up based on measured throughput.
            jobs.add(scope.launch(Dispatchers.IO) {
                var lastBytes = 0L; var bestRate = 0L; var idx = 1
                while (isActive) {
                    delay(3000)
                    if (streams.size >= target) break
                    // Both directions, as in the Rust client: keyed on upload alone the ramp
                    // is blind to download-only load — i.e. to the case bonding exists for
                    // (a big download) — and never grows past the first stream.
                    val now = bytesUp.get() + bytesDown.get()
                    val rate = (now - lastBytes) / 3          // bytes/s (up+down)
                    lastBytes = now
                    val underLoad = rate > 250_000             // >~2 Mbps — ramp under demand
                    val improving = rate > bestRate + bestRate / 10
                    if (rate > bestRate) bestRate = rate
                    if (!underLoad) continue
                    if (streams.size > 1 && !improving) {
                        broadcastLog("Multipath adaptive: plateau at ${streams.size} stream(s)"); break
                    }
                    try {
                        val s = openBondedStream(config, token, idx, transports)
                        pushedObf?.let { s.enc.setPadding(it.paddingEnabled, it.paddingMin, it.paddingMax) }
                        streams.add(s); launchStreamJobs(s); idx++
                        broadcastLog("Multipath adaptive: ramped to ${streams.size} stream(s) (${rate / 1000} KB/s)")
                    } catch (e: Exception) { broadcastLog("adaptive ramp failed: ${e.message}") }
                }
            })
        }

        // Single upload coroutine: round-robin TUN packets across live streams.
        jobs.add(scope.launch(Dispatchers.IO) {
            val buf = ByteArray(config.mtu + 100)
            try {
                while (isActive) {
                    // Same EAGAIN-tolerant read as the single-stream loop: on Android 9/10
                    // the fd stays non-blocking, and a bare read() there would surface as a
                    // false EOF and kill the bonded upload path too. (C-01)
                    val len = readTun(tunInput, buf, tunFd, tunBlocking)
                    if (len < 0) break
                    if (len == 0) continue
                    if (((buf[0].toInt() and 0xFF) shr 4) != 4) continue   // IPv4 only
                    val pkt = buf.copyOf(len)
                    // Round-robin over a consistent snapshot; a dead stream's send is
                    // non-fatal (drop it from the rotation, the tunnel runs on the rest).
                    val snap = streams.toTypedArray()
                    if (snap.isEmpty()) continue
                    val i = (rr.getAndIncrement() % snap.size).let { if (it < 0) it + snap.size else it }
                    val s = snap[i]
                    try {
                        s.transport.send(s.enc.encrypt(pkt))
                        bytesUp.addAndGet(len.toLong())
                        lastTx.set(System.currentTimeMillis()) // user uplink is flowing
                    } catch (e: Exception) { onStreamDeath(s, e) }
                }
            } catch (e: Exception) { tunnelError.trySend(e) }
        })

        // Stats once a second (same readout as the single-stream loop).
        jobs.add(scope.launch(Dispatchers.IO) {
            var lastUp = 0L; var lastDown = 0L; var lastT = System.currentTimeMillis()
            while (isActive) {
                delay(1000)
                val nowT = System.currentTimeMillis(); val dt = (nowT - lastT).coerceAtLeast(1)
                val u = bytesUp.get(); val d = bytesDown.get()
                liveBytesUp = u; liveBytesDown = d
                broadcastStats((u - lastUp) * 1000 / dt, (d - lastDown) * 1000 / dt, u, d)
                lastUp = u; lastDown = d; lastT = nowT
            }
        })

        // Liveness: reconnect on active-uplink/dead-downlink, or on server silence.
        jobs.add(scope.launch(Dispatchers.IO) {
            while (isActive) {
                delay(3000)
                val now = System.currentTimeMillis()
                // Uplink active but nothing coming back on any stream ⇒ dead session.
                if (now - lastTx.get() < 2000L && now - lastRx.get() > 8000L) {
                    tunnelError.trySend(Exception("uplink active but no downlink >8s")); break
                }
                if (expectServerData && now - lastRx.get() > rxDead) {
                    tunnelError.trySend(Exception("no data from server for >${rxDead / 1000}s")); break
                }
            }
        })

        val cause: Throwable
        try {
            cause = tunnelError.receive()
        } finally {
            jobs.forEach { it.cancel() }
            scope.cancel()   // retire this attempt's data-plane job too (M3)
            // Close every stream's socket + free its native TLS handle so a
            // reconnect starts clean (no leaked fds / native handles).
            streams.forEach {
                try { it.tls?.close() } catch (_: Exception) {}
                try { it.io.channel.close() } catch (_: Exception) {}
            }
            synchronized(transports.bonded) { transports.bonded.clear() }
        }
        // Re-throw for the same reason the single-stream loop does (see runTunnelLoop):
        // returning normally here is indistinguishable from a clean shutdown, so
        // connectWithRetry logged "Connection closed cleanly", reset the backoff, and —
        // worst of all — never ran closeTransports(), leaving the TUN fd open and still
        // the device's default route while the tunnel behind it was dead.
        throw cause
    }
}
