package com.qeli

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.qeli.crypto.KeyDerivation
import com.qeli.crypto.KeyExchange
import com.qeli.crypto.PacketCipher
import com.qeli.model.VpnConfig
import com.qeli.protocol.ObfsStream
import com.qeli.protocol.PacketCodec
import com.qeli.protocol.Quic
import com.qeli.protocol.TlsHandshake
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
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
import java.security.PrivateKey
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class VpnServiceImpl : VpnService() {

    private var supervisor: Job? = null
    private var coroutineScope: CoroutineScope? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var socketChannel: SocketChannel? = null
    private var udpSocket: DatagramSocket? = null
    private var obfs: ObfsStream? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private val writeLock = Any()

    @Volatile
    private var userRequestedDisconnect = false

    @Volatile
    private var stopping = false

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
    }

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
                if (config != null) startVpn(config)
                else Log.e("VpnSvc", "Config is null in intent")
            }
            ACTION_DISCONNECT -> {
                userRequestedDisconnect = true
                stopVpn()
            }
            null -> stopVpn()
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
            .createNotificationChannel(NotificationChannel(CHANNEL_ID, "VPN Service", NotificationManager.IMPORTANCE_LOW))
    }

    private fun showNotification(text: String): Boolean {
        return try {
            val tapIntent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            val pendingIntent = PendingIntent.getActivity(
                this, 0, tapIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notification = Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Qeli")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_SECRET)
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
        broadcastLog("Service started: ${config.protocol.uppercase()}/${config.wireMode}" +
            if (config.isUdp && config.quicEnabled) "+QUIC" else "")
        try {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Qeli::TunnelLock")
            wakeLock?.acquire(12 * 60 * 60 * 1000L)
        } catch (e: Exception) {
            Log.e("VpnSvc", "WakeLock failed: ${e.message}", e)
        }

        supervisor = SupervisorJob()
        coroutineScope = CoroutineScope(supervisor!! + Dispatchers.IO)
        broadcastStatus(STATUS_CONNECTING)

        if (!showNotification("Connecting...")) {
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

    private suspend fun connectWithRetry(config: VpnConfig) {
        var attempt = 0
        val baseMs = config.reconnectBaseDelaySecs * 1000
        val maxMs = config.reconnectMaxDelaySecs * 1000
        while (coroutineScope?.isActive == true) {
            try {
                if (attempt > 0) {
                    if (!config.reconnectEnabled) { broadcastLog("Reconnect disabled, giving up"); break }
                    if (config.reconnectMaxRetries in 0 until attempt) {
                        broadcastLog("Max retries reached, giving up"); break
                    }
                    val pow = Math.pow(2.0, (attempt - 1).coerceAtMost(7).toDouble()).toLong()
                    val delayMs = (baseMs * pow.coerceAtMost(100)).coerceAtMost(maxMs).coerceAtLeast(1000)
                    broadcastStatus(STATUS_CONNECTING)
                    showNotification("Reconnecting... (attempt $attempt)")
                    broadcastLog("Reconnect attempt $attempt in ${delayMs / 1000}s")
                    delay(delayMs)
                }
                runVpnConnection(config)
                broadcastLog("Connection closed cleanly")
                if (userRequestedDisconnect) break
                // If the tunnel was established (auth OK → STATUS_CONNECTED), this
                // was a healthy session that dropped — reset the backoff so the
                // reconnect is prompt; only consecutive *pre-established* failures
                // escalate the delay.
                attempt = if (liveStatus == STATUS_CONNECTED) 0 else attempt + 1
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
                if (coroutineScope?.isActive != true) break
                broadcastLog("ERR: [${e.javaClass.simpleName}] ${e.message}")
                var cause = e.cause
                while (cause != null) { broadcastLog("  <- ${cause.message}"); cause = cause.cause }
                // An established tunnel dropping throws here too; reset the backoff
                // if it had connected so reconnect is prompt (only consecutive
                // pre-established failures escalate the delay).
                attempt = if (liveStatus == STATUS_CONNECTED) 0 else attempt + 1
                closeTransports()
            }
        }
        if (userRequestedDisconnect) stopVpn()
    }

    private fun closeTransports() {
        try { socketChannel?.close() } catch (_: Exception) {}
        try { udpSocket?.close() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        socketChannel = null
        udpSocket = null
        vpnInterface = null
        obfs = null
    }

    /** Cancel the connection scope and close every transport (TUN/socket).
     *  Used both to fully stop and to reset before a fresh connect. */
    private fun teardown() {
        supervisor?.cancel(); supervisor = null; coroutineScope = null
        closeTransports()
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
        val pushedMtu: Int = 0
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
            pushedMtu = json.optInt("mtu", 0).let { if (it in 576..9000) it else 0 }
        )
        return AuthOk(session, json.optJSONObject("obfuscation"))
    }

    /** Server-pushed obfuscation params the client applies so it can't drift out
     *  of sync with the server. Mirrors crate::config::PushedObf; only the fields
     *  this client acts on are decoded. */
    private class PushedObf(
        val paddingEnabled: Boolean, val paddingMin: Int, val paddingMax: Int,
        val hbEnabled: Boolean, val hbIntervalMs: Long, val hbJitterMs: Long
    )

    private fun decodePushedObf(obf: JSONObject?): PushedObf? {
        if (obf == null) return null
        val pad = obf.optJSONObject("padding") ?: JSONObject()
        val hb = obf.optJSONObject("heartbeat") ?: JSONObject()
        return PushedObf(
            paddingEnabled = pad.optBoolean("enabled", true),
            paddingMin = pad.optInt("min_bytes", 0),
            paddingMax = pad.optInt("max_bytes", 255),
            hbEnabled = hb.optBoolean("enabled", true),
            hbIntervalMs = hb.optLong("interval_ms", 15000),
            hbJitterMs = hb.optLong("jitter_ms", 2000)
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
        pinnedHex: String?
    ): ServerAuth {
        val ke = KeyExchange()
        val pinnedBytes = pinnedHex
            ?.lowercase()?.replace(Regex("[: -]"), "")
            ?.takeIf { it.length == 64 }
            ?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()

        val serverStaticPub: ByteArray
        val receivedProof: ByteArray
        if (msg.size >= 64) {
            serverStaticPub = msg.copyOfRange(0, 32)
            receivedProof = msg.copyOfRange(32, 64)
            if (pinnedBytes != null && !serverStaticPub.contentEquals(pinnedBytes)) {
                throw SecurityException("SERVER KEY MISMATCH - possible MITM")
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
        if (!receivedProof.contentEquals(expected)) {
            throw SecurityException("server auth proof INVALID")
        }
        return ServerAuth(serverStaticPub, staticShared)
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
        return proof + creds  // [proof:32][username:password]
    }

    private fun makeCodecs(config: VpnConfig, sharedSecret: ByteArray, raw: Boolean = false): Pair<PacketCodec, PacketCodec> {
        val (serverToClient, clientToServer) = KeyDerivation.deriveKeys(sharedSecret)
        val enc = PacketCodec(PacketCipher(clientToServer), SecureRandom(),
            config.paddingEnabled, config.paddingMin, config.paddingMax, raw = raw)
        val dec = PacketCodec(PacketCipher(serverToClient), raw = raw)
        return enc to dec
    }

    // ── TUN setup ────────────────────────────────────────────────────────────

    private fun setupTunInterface(config: VpnConfig, session: Session): ParcelFileDescriptor {
        return Builder().apply {
            setMtu(config.mtu)
            addAddress(session.clientIp, session.prefix)

            if (config.isFullTunnel) {
                addRoute("0.0.0.0", 0)
                // Capture IPv6 too, or dual-stack traffic bypasses a "full" tunnel
                // entirely (the classic VPN IPv6 leak: IPv4 goes through the VPN while
                // IPv6 exits the physical interface). The server is IPv4-only, so these
                // packets are dropped inside the tunnel rather than leaking — apps fall
                // back to IPv4-over-VPN. Adding an IPv6 address is required before an
                // IPv6 route, and implicitly allows AF_INET6.
                try {
                    addAddress("fd00:71e1::1", 128)
                    addRoute("::", 0)
                    allowFamily(android.system.OsConstants.AF_INET6)
                } catch (e: Exception) {
                    broadcastLog("IPv6 capture unavailable: ${e.message}")
                }
            } else {
                // tunnel subnet + explicit includes
                addRoute(subnetBase(session.clientIp), 24)
                config.includeRoutes.forEach { addCidrRoute(it) }
            }

            // Route private/local networks only when enabled: the server-pushed
            // subnets PLUS the RFC1918 ranges, so LAN resources behind the server
            // work through the VPN. When disabled, local traffic stays off-tunnel
            // and pushed networks are ignored.
            if (config.routeLocalNetworks) {
                applyPushedRoutes(this, session.routesJson)
                listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").forEach { addCidrRoute(it) }
                broadcastLog("Routing local networks (RFC1918 + pushed) through the tunnel")
            }

            val dns = (if (config.dnsServers.isNotEmpty()) config.dnsServers else listOf(session.dnsIp))
                .filter { it.isNotEmpty() }
            dns.forEach { try { addDnsServer(it) } catch (e: Exception) { broadcastLog("bad dns $it: ${e.message}") } }

            allowFamily(android.system.OsConstants.AF_INET)
        }.establish() ?: throw Exception("Failed to establish VPN interface")
    }

    private fun applyPushedRoutes(builder: Builder, routesJson: String) {
        if (routesJson.isBlank() || routesJson == "[]") return
        try {
            val arr = JSONArray(routesJson)
            for (i in 0 until arr.length()) {
                val cidr = arr.getJSONObject(i).optString("cidr")
                if (cidr.isEmpty()) continue
                builder.addCidrRoute(cidr)
                broadcastLog("pushed route: $cidr")
            }
        } catch (e: Exception) {
            broadcastLog("routes parse error: ${e.message}")
        }
    }

    private fun Builder.addCidrRoute(cidr: String) {
        val slash = cidr.indexOf('/')
        if (slash < 0) { addRoute(cidr, 32); return }
        val addr = cidr.substring(0, slash)
        val prefix = cidr.substring(slash + 1).toIntOrNull() ?: return
        try { addRoute(addr, prefix) } catch (e: Exception) { broadcastLog("bad route $cidr: ${e.message}") }
    }

    private fun subnetBase(ip: String): String {
        val o = ip.split(".")
        return if (o.size == 4) "${o[0]}.${o[1]}.${o[2]}.0" else ip
    }

    // ── dispatch ─────────────────────────────────────────────────────────────

    private suspend fun runVpnConnection(config: VpnConfig) {
        if (config.isUdp) connectUdp(config) else connectTcp(config)
    }

    /**
     * VpnService hands back a TUN fd in NON-BLOCKING mode. Our data-plane reader
     * uses a blocking read() loop, so a non-blocking fd makes read() return 0 the
     * moment the queue drains — which the loop would misread as EOF and exit,
     * permanently killing the upload path after the first few packets. Clear
     * O_NONBLOCK so read() blocks until a packet arrives.
     */
    private fun forceBlocking(pfd: ParcelFileDescriptor) {
        try {
            val fd = pfd.fileDescriptor
            val fl = android.system.Os.fcntlInt(fd, android.system.OsConstants.F_GETFL, 0)
            android.system.Os.fcntlInt(fd, android.system.OsConstants.F_SETFL,
                fl and android.system.OsConstants.O_NONBLOCK.inv())
        } catch (e: Exception) {
            broadcastLog("forceBlocking failed: ${e.message}")
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
    }

    /** TCP transport: records are length-framed on a byte stream; obfs (if any)
     *  is applied transparently by writeFully/readBytes via the outer [obfs]. */
    private inner class TcpTransport(private val raw: Boolean = false) : Transport {
        override fun send(record: ByteArray, longHeader: Boolean) = writeFully(record)
        // raw = `plain` wire mode: bare length-prefixed records (no TLS header).
        override fun recvRecord(): ByteArray = if (raw) readRawRecord() else readTlsRecord()
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

        override fun send(record: ByteArray, longHeader: Boolean) {
            val framed = if (quic) {
                if (longHeader) Quic.wrapLong(record, connectionId, pn.getAndIncrement(), 0x02)
                else Quic.wrapShort(record, connectionId, pn.getAndIncrement())
            } else record
            val out = if (obfsKey != null) ObfsStream.datagramSeal(obfsKey, framed) else framed
            synchronized(writeLock) { sock.send(DatagramPacket(out, out.size)) }
        }

        /** Receive one datagram into the buffer (skipping malformed packets).
         *  May throw SocketTimeoutException, which the caller maps to liveness. */
        private fun fill() {
            val rbuf = ByteArray(65535)
            while (true) {
                val pkt = DatagramPacket(rbuf, rbuf.size)
                sock.receive(pkt)
                var raw: ByteArray? = rbuf.copyOf(pkt.length)
                if (obfsKey != null) raw = ObfsStream.datagramOpen(obfsKey, raw!!)
                val payload = if (raw == null) null else if (quic) Quic.unwrapPayload(raw) else raw
                if (payload != null) { buf = payload; pos = 0; return }
                // malformed datagram — drop and wait for the next one
            }
        }

        override fun recvRecord(): ByteArray {
            if (pos + 5 > buf.size) fill()   // need the next datagram for a new record
            val len = ((buf[pos + 3].toInt() and 0xFF) shl 8) or (buf[pos + 4].toInt() and 0xFF)
            val end = (pos + 5 + len).coerceAtMost(buf.size)
            val rec = buf.copyOfRange(pos, end)
            pos = end
            return rec
        }

        override fun setReadTimeout(ms: Int) { sock.soTimeout = ms }
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
    private fun doRealTlsHandshake(config: VpnConfig): RealTls {
        val sni = config.sni ?: pickSni(config.serverAddress)
        val realityPub = hexToBytes(config.serverPublicKeyHex
            ?: throw Exception("reality-tls requires a pinned server key (auth.server_public_key)"))
        require(realityPub.size == 32) { "server key must be 32 bytes (64 hex chars)" }
        val shortId = shortIdFromHex(config.realityShortId
            ?: throw Exception("reality-tls requires reality_sid"))
        val tls = RealTls.create(realityPub, shortId, sni)
        writeRaw(tls.clientHello())
        while (!tls.established()) {
            val out = tls.recv(readSomeRaw())
            if (out.isNotEmpty()) writeRaw(out)
        }
        broadcastLog("REALITY TLS 1.3 established (SNI $sni)")
        return tls
    }

    // ── connection setup (transport-specific) ────────────────────────────────

    private suspend fun connectTcp(config: VpnConfig) {
        broadcastLog("Connecting TCP ${config.serverAddress}:${config.port}...")
        socketChannel = SocketChannel.open().apply {
            if (!protect(socket())) broadcastLog("WARN: protect() returned false")
            socket().soTimeout = config.connectionTimeoutSecs.toInt() * 1000
            connect(InetSocketAddress(config.serverAddress, config.port))
            socket().keepAlive = true
            socket().tcpNoDelay = true
            configureBlocking(true)
        }
        broadcastLog("TCP connected")

        if (config.wireMode.equals("plain", ignoreCase = true)) {
            // No TLS mimicry: raw X25519 key exchange, then the encrypted qeli
            // protocol over bare length-prefixed records (Framing::Raw).
            obfs = null
            broadcastLog("plain mode: raw key exchange, no TLS mimicry")
            val r = performHandshakePlain(config)
            runAfterHandshake(TcpTransport(raw = true), isUdp = false, r)
            return
        }

        if (config.wireMode.equals("reality-tls", ignoreCase = true)) {
            // Genuine browser TLS 1.3 (REALITY) carries the tunnel; the existing
            // qeli protocol runs nested inside it. RealTlsTransport seals outgoing
            // records and opens incoming ones via the native realtls core.
            obfs = null
            val tls = doRealTlsHandshake(config)
            establishAndRun(config, RealTlsTransport(TcpTransport(), tls), padToMin = 0, isUdp = false)
            return
        }

        // obfs wire mode: XOR the whole stream with a PSK-keyed ChaCha20 keystream.
        // Nonces are exchanged in the clear (writeRaw/readRaw bypass obfs) BEFORE
        // any framed record, so the TcpTransport's framed IO is obfs-wrapped.
        obfs = if (config.wireMode.equals("obfs", ignoreCase = true)) {
            if (config.obfsKey.isBlank())
                throw Exception("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)")
            val fronting = config.obfsFronting.equals("websocket", ignoreCase = true)
            broadcastLog(if (fronting) "obfs mode: WebSocket fronting + nonce exchange" else "obfs mode: exchanging nonces")
            val key = ObfsStream.deriveKey(config.obfsKey)
            ObfsStream.connect(key, fronting, sendRaw = { writeRaw(it) }, recvRaw = { readRaw(it) })
        } else null

        establishAndRun(config, TcpTransport(), padToMin = 0, isUdp = false)
    }

    private suspend fun connectUdp(config: VpnConfig) {
        broadcastLog("Connecting UDP ${config.serverAddress}:${config.port}...")
        val sock = DatagramSocket()
        if (!protect(sock)) broadcastLog("WARN: protect() returned false")
        sock.connect(InetSocketAddress(config.serverAddress, config.port))
        sock.soTimeout = config.connectionTimeoutSecs.toInt() * 1000
        udpSocket = sock

        val quic = config.quicEnabled
        val connectionId = if (quic) Quic.generateConnectionId() else ByteArray(4)
        if (config.wireMode.equals("obfs", ignoreCase = true) && config.obfsKey.isBlank())
            throw Exception("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)")
        val obfsKey = if (config.wireMode.equals("obfs", ignoreCase = true) && config.obfsKey.isNotEmpty())
            ObfsStream.deriveKey(config.obfsKey) else null
        val transport = UdpTransport(sock, quic, connectionId, AtomicInteger(0), obfsKey)
        if (quic) broadcastLog("UDP QUIC masking enabled")
        if (obfsKey != null) broadcastLog("UDP obfs mode enabled")
        establishAndRun(config, transport, padToMin = 1200, isUdp = true)
    }

    /** Shared tail: run the handshake over [transport], bring up the TUN, loop. */
    private suspend fun establishAndRun(
        config: VpnConfig, transport: Transport, padToMin: Int, isUdp: Boolean
    ) {
        val r = performHandshake(config, transport, padToMin)
        runAfterHandshake(transport, isUdp, r)
    }

    /** Post-handshake path (announce, TUN setup, tunnel loop) shared by the
     *  fake-tls/obfs/reality path and the plain path. */
    private suspend fun runAfterHandshake(transport: Transport, isUdp: Boolean, r: HandshakeResult) {
        broadcastLog("Auth OK, IP ${r.session.clientIp}")
        announceConnected(r.session.clientIp)
        vpnInterface = setupTunInterface(r.config, r.session)
        broadcastLog("TUN ready, entering tunnel loop")
        runTunnelLoop(r.config, transport, vpnInterface!!, r.enc, r.dec, isUdp)
    }

    // ── shared handshake (transport-agnostic) ────────────────────────────────

    private class HandshakeResult(
        val session: Session, val config: VpnConfig,
        val enc: PacketCodec, val dec: PacketCodec
    )

    private fun performHandshake(
        config: VpnConfig, transport: Transport, padToMin: Int
    ): HandshakeResult {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()

        val sni = config.sni ?: pickSni(config.serverAddress)
        val clientHello = TlsHandshake.buildClientHello(clientKeyPair.publicKeyBytes, sni, padToMin)
        transport.send(clientHello, longHeader = true)
        broadcastLog("ClientHello sent (${clientHello.size}B)")

        val serverHelloRecord = transport.recvRecord()
        val serverPublicKey = TlsHandshake.parseServerHello(
            parseHandshakeMessage(serverHelloRecord) ?: throw Exception("Failed to parse ServerHello")
        ) ?: throw Exception("Failed to extract server public key")

        // ChangeCipherSpec (optional), Certificate, Finished.
        var rec = transport.recvRecord()
        if (TlsHandshake.isChangeCipherSpec(rec)) rec = transport.recvRecord()
        val certRecord = rec
        val finishedRecord = transport.recvRecord()

        val sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, serverPublicKey)
        val (encCodec, decCodec) = makeCodecs(config, sharedSecret)
        // Transcript: ClientHello, ServerHello, Certificate, Finished (plaintext records).
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientHello, serverHelloRecord, certRecord, finishedRecord)
        )

        // The next record is either a plaintext NewSessionTicket (handshake, type
        // 0x16 — discard it) or the encrypted auth proof (application data, 0x17).
        // Peeking the content type makes this work whether or not the server sends
        // an NST, on both TCP and UDP.
        var authRec = transport.recvRecord()
        if (authRec.isNotEmpty() && (authRec[0].toInt() and 0xFF) == 0x16) authRec = transport.recvRecord()
        val authProofMsg = decCodec.decrypt(authRec)
        val sa = verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex)
        broadcastLog("Server identity verified [OK]")

        val authPlain = buildClientAuthPlaintext(config, sa.staticShared, sharedSecret, transcriptHash)
        transport.send(encCodec.encrypt(authPlain))

        val authResponse = decCodec.decrypt(transport.recvRecord())
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
        decodePushedObf(ok.obf)?.let { po ->
            encCodec.setPadding(po.paddingEnabled, po.paddingMin, po.paddingMax)
            effConfig = effConfig.copy(
                heartbeatEnabled = po.hbEnabled,
                heartbeatIntervalMs = po.hbIntervalMs,
                heartbeatJitterMs = po.hbJitterMs
            )
            broadcastLog("Applied server-pushed obfuscation params")
        }
        broadcastLog("TUN MTU: ${effConfig.mtu}")
        return HandshakeResult(ok.session, effConfig, encCodec, decCodec)
    }

    /**
     * `plain` wire mode handshake: no TLS mimicry. Exchange ephemeral X25519 publics
     * raw, bind the channel to H(client_pub‖server_pub), then run the same encrypted
     * auth flow over bare length-prefixed records. Mirrors qeli/src/client/mod.rs.
     */
    private fun performHandshakePlain(config: VpnConfig): HandshakeResult {
        val ke = KeyExchange()
        val clientKeyPair = ke.generateKeyPair()

        // 1. Raw exchange of the 32-byte ephemeral public keys (no framing).
        writeFully(clientKeyPair.publicKeyBytes)
        val serverPublicKey = readRaw(32)
        broadcastLog("plain: exchanged ephemeral keys")

        // 2. Transcript binds to both raw publics.
        val transcriptHash = KeyDerivation.handshakeTranscript(
            listOf(clientKeyPair.publicKeyBytes, serverPublicKey)
        )

        val sharedSecret = ke.computeSharedSecret(clientKeyPair.privateKey, serverPublicKey)
        val (encCodec, decCodec) = makeCodecs(config, sharedSecret, raw = true)

        // 3. Server auth proof (raw record).
        val authProofMsg = decCodec.decrypt(readRawRecord())
        val sa = verifyServerAuth(authProofMsg, clientKeyPair.privateKey, sharedSecret, transcriptHash, config.serverPublicKeyHex)
        broadcastLog("Server identity verified [OK] (plain)")

        // 4. Client auth.
        val authPlain = buildClientAuthPlaintext(config, sa.staticShared, sharedSecret, transcriptHash)
        writeFully(encCodec.encrypt(authPlain))

        // 5. Auth response (raw record).
        val authResponse = decCodec.decrypt(readRawRecord())
        val authStr = String(authResponse)
        if (!authStr.startsWith("OK:")) throw Exception("Auth failed: $authStr")
        val ok = parseOk(authStr)

        // Resolve the effective TUN MTU: explicit client config (>0) wins, else
        // the server-pushed value (>0), else fall back to 1400. Carried in
        // effConfig so BOTH the TUN setup (setMtu) and the data loop (read buffer)
        // use the resolved value.
        var effConfig = config.copy(mtu = effectiveMtu(config.mtu, ok.session.pushedMtu))
        decodePushedObf(ok.obf)?.let { po ->
            encCodec.setPadding(po.paddingEnabled, po.paddingMin, po.paddingMax)
            effConfig = effConfig.copy(
                heartbeatEnabled = po.hbEnabled,
                heartbeatIntervalMs = po.hbIntervalMs,
                heartbeatJitterMs = po.hbJitterMs
            )
            broadcastLog("Applied server-pushed obfuscation params")
        }
        broadcastLog("TUN MTU: ${effConfig.mtu}")
        return HandshakeResult(ok.session, effConfig, encCodec, decCodec)
    }

    // ── shared tunnel loop (transport-agnostic) ──────────────────────────────

    private suspend fun runTunnelLoop(
        config: VpnConfig, transport: Transport, tunFd: ParcelFileDescriptor,
        encCodec: PacketCodec, decCodec: PacketCodec, isUdp: Boolean
    ) {
        val scope = coroutineScope!!
        forceBlocking(tunFd)
        val tunInput = FileInputStream(tunFd.fileDescriptor)
        val tunOutput = FileOutputStream(tunFd.fileDescriptor)
        val buf = ByteArray(config.mtu + 100)
        val rng = SecureRandom()
        val lastRx = AtomicLong(System.currentTimeMillis())
        val bytesUp = AtomicLong(0)
        val bytesDown = AtomicLong(0)
        val rxDead = maxOf(config.heartbeatIntervalMs * 3, 30_000L)
        val tunnelError = kotlinx.coroutines.channels.Channel<Throwable>(kotlinx.coroutines.channels.Channel.CONFLATED)

        // UDP: a read timeout lets the download job wake to check liveness/cancel.
        // TCP: blocking reads ignore it; the heartbeat job checks rxDead instead.
        if (isUdp) transport.setReadTimeout(rxDead.toInt())

        val uploadJob = scope.launch(Dispatchers.IO) {
            try {
                while (isActive) {
                    val len = tunInput.read(buf)
                    if (len < 0) break          // genuine EOF (fd closed)
                    if (len == 0) continue      // no data this round — keep reading
                    if (((buf[0].toInt() and 0xFF) shr 4) != 4) continue // IPv4 only
                    transport.send(encCodec.encrypt(buf.copyOf(len)))
                    bytesUp.addAndGet(len.toLong())
                }
            } catch (e: Exception) { tunnelError.trySend(e) }
        }

        val downloadJob = scope.launch(Dispatchers.IO) {
            try {
                while (isActive) {
                    val rec = try {
                        transport.recvRecord()
                    } catch (e: java.net.SocketTimeoutException) {
                        if (System.currentTimeMillis() - lastRx.get() > rxDead) {
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

        val heartbeatJob = scope.launch(Dispatchers.IO) {
            if (!config.heartbeatEnabled || config.heartbeatIntervalMs <= 0) return@launch
            val interval = config.heartbeatIntervalMs
            while (isActive) {
                val jitter = jitterMs(rng, config.heartbeatJitterMs)
                delay((interval + jitter).coerceAtLeast(1000))
                try {
                    transport.send(encCodec.encrypt(ByteArray(0)))
                } catch (e: Exception) { tunnelError.trySend(e); break }
                // TCP has no read timeout, so detect a dead server here.
                if (!isUdp && System.currentTimeMillis() - lastRx.get() > rxDead) {
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

        try {
            tunnelError.receive()
        } finally {
            // Cancel only OUR data-plane jobs. Do NOT cancelChildren() on the scope
            // here: connectWithRetry runs as a sibling child of the same scope, so
            // cancelling all children would kill the reconnect loop itself — which
            // made delay() throw CancellationException and spin the loop instantly
            // on every disconnect.
            uploadJob.cancel(); downloadJob.cancel(); heartbeatJob.cancel(); statsJob.cancel()
        }
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
        showNotification("Connected: $clientIp")
    }

    /** Symmetric heartbeat jitter in [-jitter, +jitter). Avoids RandomGenerator.nextLong(bound) (API 34+). */
    private fun jitterMs(rng: SecureRandom, jitter: Long): Long {
        if (jitter <= 0) return 0L
        val r = (rng.nextLong() and Long.MAX_VALUE) % (jitter * 2)
        return r - jitter
    }

    private fun pickSni(address: String): String {
        // Use the server address as SNI when it's a hostname; random realistic SNI for raw IPs.
        val isIp = address.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
        if (!isIp) return address
        val pool = listOf("www.cloudflare.com", "www.microsoft.com", "www.apple.com", "www.google.com")
        return pool[SecureRandom().nextInt(pool.size)]
    }

    // ── TCP framing / IO (with optional obfs transform) ──────────────────────

    private fun parseHandshakeMessage(record: ByteArray): ByteArray? {
        if (record.size < 6) return null
        if ((record[0].toInt() and 0xFF) != 0x16) return null
        val payloadLen = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
        if (record.size < 5 + payloadLen) return null
        return record.copyOfRange(5, 5 + payloadLen)
    }

    private fun readTlsRecord(): ByteArray {
        val header = readBytes(5)
        val payloadLen = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        if (payloadLen > 65535) throw Exception("TLS record too large: $payloadLen")
        return header + readBytes(payloadLen)
    }

    /** Read one bare length-prefixed record ([u16 len][nonce][ct]) for the `plain`
     *  wire mode. Mirrors read_record(Framing::Raw) on the Rust side. */
    private fun readRawRecord(): ByteArray {
        val header = readBytes(2)
        val payloadLen = ((header[0].toInt() and 0xFF) shl 8) or (header[1].toInt() and 0xFF)
        if (payloadLen > 65535) throw Exception("raw record too large: $payloadLen")
        return header + readBytes(payloadLen)
    }

    /** Read [size] de-obfuscated bytes from the TCP transport. */
    private fun readBytes(size: Int): ByteArray {
        val raw = readRaw(size)
        return obfs?.transformRead(raw) ?: raw
    }

    /** Read exactly [size] raw bytes (before obfs transform). */
    private fun readRaw(size: Int): ByteArray {
        val buf = ByteArray(size)
        var off = 0
        var retry = 0
        while (off < size) {
            val n = socketChannel!!.read(ByteBuffer.wrap(buf, off, size - off))
            if (n < 0) throw Exception("Connection closed")
            if (n == 0) {
                if (++retry > 100) throw Exception("Read timeout")
                Thread.sleep(minOf(10L * retry, 100L)); continue
            }
            retry = 0; off += n
        }
        return buf
    }

    /** Read whatever raw bytes are currently available (≥1), for the realtls
     *  handshake which buffers/parses incrementally. */
    private fun readSomeRaw(max: Int = 16384): ByteArray {
        val buf = ByteArray(max)
        var retry = 0
        while (true) {
            val n = socketChannel!!.read(ByteBuffer.wrap(buf))
            if (n < 0) throw Exception("Connection closed")
            if (n == 0) {
                if (++retry > 200) throw Exception("Read timeout")
                Thread.sleep(minOf(10L * retry, 100L)); continue
            }
            return buf.copyOf(n)
        }
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

    /** Write [data] through the obfs transform (if any), serialized across threads. */
    private fun writeFully(data: ByteArray) {
        val out = obfs?.transformWrite(data) ?: data
        writeRaw(out)
    }

    private fun writeRaw(data: ByteArray) {
        synchronized(writeLock) {
            var off = 0
            while (off < data.size) {
                val n = socketChannel!!.write(ByteBuffer.wrap(data, off, data.size - off))
                if (n < 0) throw Exception("Connection closed")
                off += n
            }
        }
    }
}
