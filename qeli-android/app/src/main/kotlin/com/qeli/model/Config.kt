package com.qeli.model

import org.json.JSONArray
import org.json.JSONObject
import java.io.Serializable

/**
 * Full qeli client configuration. Mirrors the relevant fields of the Rust
 * ClientConfig (qeli/src/config/client.rs). Built either from the simple
 * UI fields or by importing a JSON config via [fromJson].
 */
data class VpnConfig(
    // ── server ──
    val serverAddress: String,
    val port: Int,
    val protocol: String = "tcp",              // "tcp" | "udp"
    val connectionTimeoutSecs: Long = 30,
    // ── reconnect ──
    val reconnectEnabled: Boolean = true,
    val reconnectMaxRetries: Int = -1,
    val reconnectBaseDelaySecs: Long = 1,
    val reconnectMaxDelaySecs: Long = 60,
    // ── auth ──
    val username: String,
    val password: String,
    val serverPublicKeyHex: String? = null,    // pinned static key (hex), null = TOFU
    // H-1: bind data keys to the server static identity (must match server's
    // auth.bind_static_to_session + requires a pinned key). Default TRUE
    // (secure-by-default since 0.7.1); set false for a legacy 0.7.0 / TOFU server.
    val bindStaticToSession: Boolean = true,
    // ── tun ──
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    val mtu: Int = 0,
    // ── routing ──
    // Default to full-tunnel: a VPN should carry ALL traffic so nothing leaks
    // outside the encrypted path. Split-tunnel stays available via an imported
    // JSON config (routing.mode = "split-tunnel").
    val routingMode: String = "full-tunnel",   // "full-tunnel" | "split-tunnel"
    val addDefaultGateway: Boolean = true,
    val includeRoutes: List<String> = emptyList(),
    val excludeRoutes: List<String> = emptyList(),
    // Route private/local networks (RFC1918) through the VPN. When true, the
    // client adds the private ranges AND applies any networks the server pushed,
    // so LAN resources behind the server work through the tunnel. When false
    // (default), local networks are not tunnelled and pushed networks are ignored.
    val routeLocalNetworks: Boolean = false,
    // ── dns ──
    // Public resolvers reachable through the tunnel (the server NATs them out).
    // Without this, full-tunnel would point DNS at the server's tun IP, which
    // only resolves if the server runs a DNS proxy.
    val dnsServers: List<String> = listOf("1.1.1.1", "8.8.8.8"),
    // ── obfuscation ──
    val wireMode: String = "fake-tls",         // "fake-tls" | "obfs"
    val obfsKey: String = "",
    // obfs anti-FET fronting: "websocket" (default) wraps the nonce exchange in a
    // WebSocket Upgrade handshake; "none" is the legacy raw nonce. Must match the
    // server. Mirrors ClientObfuscationConfig::fronting in the Rust client.
    val obfsFronting: String = "websocket",
    // F2: AmneziaWG-style pre-handshake junk (obfs mode only). OFF by default so
    // the wire is byte-identical to today. When awgEnabled && awgJc>0, the sender
    // emits awgJc junk records (each uniform length in [awgJmin,awgJmax]) right
    // after the front/TCP handshake and before the nonce exchange; the peer reads
    // and discards awgJc records. Both ends MUST share awgJc; jmin/jmax are
    // sender-only. Mirrors obf.awg.* in the Rust/C# clients.
    val awgEnabled: Boolean = false,
    val awgJc: Int = 0,      // junk record count, cap 128
    val awgJmin: Int = 40,   // min junk length
    val awgJmax: Int = 300,  // max junk length (require jmin<=jmax<=1400)
    val quicEnabled: Boolean = false,
    val sni: String? = null,
    // REALITY short_id (hex) — pairs with serverPublicKeyHex to seal the auth
    // token into the realtls ClientHello (wireMode = "reality-tls").
    val realityShortId: String? = null,
    // padding
    val paddingEnabled: Boolean = true,
    val paddingMin: Int = 0,
    val paddingMax: Int = 255,
    // heartbeat
    val heartbeatEnabled: Boolean = true,
    val heartbeatIntervalMs: Long = 15000,
    val heartbeatDataSize: Int = 16,
    val heartbeatJitterMs: Long = 2000,
    // flow shaping (idle cover traffic; DPI-AUDIT 6.1/6.2). Normally pushed from
    // the server. Defaults mirror the Rust TrafficShapingConfig.
    val shapingEnabled: Boolean = false,
    val shapingGapMeanMs: Long = 700,
    val shapingGapMinMs: Long = 40,
    val shapingGapMaxMs: Long = 6000,
    val shapingBudgetBytesPerSec: Int = 16384,
    val shapingMinSize: Int = 64,
    val shapingMaxSize: Int = 1024,
    // Stealth (Phase 2): rate-cap the data plane + cover under load. TCP-only.
    val shapingStealth: Boolean = false,
    val shapingStealthRateMbps: Int = 2
) : Serializable {

    /** True when the protocol is UDP (DatagramChannel transport, QUIC masking). */
    val isUdp: Boolean get() = protocol.equals("udp", ignoreCase = true)

    val isFullTunnel: Boolean
        get() = addDefaultGateway || routingMode.equals("full-tunnel", ignoreCase = true)

    /**
     * Serialize back to the canonical qeli JSON client-config schema (the one
     * [fromJson] reads). Used to store an imported `qeli://` link as a normal
     * profile so the rest of the app (ping, edit, connect) treats it uniformly.
     * Only connection essentials are emitted; the server pushes the rest.
     */
    fun toConfigJson(label: String? = null): String = JSONObject().apply {
        if (!label.isNullOrBlank()) put("name", label)
        put("server", JSONObject()
            .put("address", serverAddress)
            .put("port", port)
            .put("protocol", protocol))
        put("auth", JSONObject()
            .put("username", username)
            .put("password", password)
            .put("server_public_key", serverPublicKeyHex ?: ""))
        put("routing", JSONObject().put("mode", "full-tunnel").put("add_default_gateway", true)
            .put("route_local_networks", routeLocalNetworks))
        // Carry the resolvers explicitly so a qeli://-imported profile has working
        // DNS instead of falling back to the server's pushed DNS (which may be a
        // tunnel-only/disabled resolver). Public resolvers reach out via the tunnel.
        put("dns", JSONObject().put("servers", JSONArray(dnsServers)))
        put("obfuscation", JSONObject().apply {
            put("mode", wireMode)
            if (!sni.isNullOrBlank()) put("sni", sni)
            if (obfsKey.isNotEmpty()) put("obfs_key", obfsKey)
            if (obfsFronting != "websocket") put("fronting", obfsFronting)
            // F2: emit the awg block only when enabled (keeps default configs clean).
            if (awgEnabled) put("awg", JSONObject()
                .put("enabled", true)
                .put("jc", awgJc)
                .put("jmin", awgJmin)
                .put("jmax", awgJmax))
            // reality-tls short_id and the UDP QUIC-masking flag are connection-
            // essential for those modes; omitting them silently downgraded a
            // reality / udp+quic profile to a plain one on round-trip (fromJson
            // reads both back).
            if (!realityShortId.isNullOrEmpty()) put("reality_short_id", realityShortId)
            if (quicEnabled) put("quic", JSONObject().put("enabled", true))
        })
    }.toString()

    /**
     * Render the connection essentials to the flat-INI `[qeli]` format — the
     * SAME schema the Rust client reads (qeli/src/config/client.rs::from_ini),
     * so a profile exported here is loadable by the desktop/CLI client too.
     * `dns` and `mtu` are app extras the Rust client simply ignores.
     */
    fun toIni(label: String? = null): String = buildString {
        if (!label.isNullOrBlank()) append("# ").append(label).append('\n')
        append("[qeli]\n")
        append("server = ").append(serverAddress).append(':').append(port).append('\n')
        append("proto = ").append(protocol).append('\n')
        append("user = ").append(username).append('\n')
        append("pass = ").append(password).append('\n')
        if (!serverPublicKeyHex.isNullOrEmpty()) append("key = ").append(serverPublicKeyHex).append('\n')
        if (!bindStaticToSession) append("bind_static = false\n")  // on by default; emit only when off
        append("mode = ").append(wireMode).append('\n')
        if (!sni.isNullOrBlank()) append("sni = ").append(sni).append('\n')
        if (!realityShortId.isNullOrEmpty()) append("reality_sid = ").append(realityShortId).append('\n')
        if (obfsKey.isNotEmpty()) append("obfs_key = ").append(obfsKey).append('\n')
        if (obfsFronting != "websocket") append("front = ").append(obfsFronting).append('\n')
        // F2: AmneziaWG junk. Emit only when enabled (default OFF → byte-identical
        // round-trip). Mirrors the Rust client's awg/jc/jmin/jmax INI keys.
        if (awgEnabled) {
            append("awg = true\n")
            append("jc = ").append(awgJc).append('\n')
            append("jmin = ").append(awgJmin).append('\n')
            append("jmax = ").append(awgJmax).append('\n')
        }
        if (quicEnabled) append("quic = true\n")  // udp+quic profiles: lost on round-trip without this
        // Routing: full-tunnel is the default; emit `gateway = false` only for an
        // explicit split-tunnel so the choice survives a save round-trip (the editor
        // re-serializes to INI). Mirrors the Rust client's `gateway` key.
        if (!isFullTunnel) append("gateway = false\n")
        if (routeLocalNetworks) append("route_local = true\n")
        if (dnsServers.isNotEmpty()) append("dns = ").append(dnsServers.joinToString(", ")).append('\n')
        if (mtu > 0) append("mtu = ").append(mtu).append('\n')  // 0 = auto, omit
        // Reconnect / timeout tuning (Android extras; the Rust client ignores them).
        // Emitted only when diverging from the defaults.
        if (!reconnectEnabled) append("reconnect = false\n")
        if (reconnectMaxRetries != -1) append("reconnect_retries = ").append(reconnectMaxRetries).append('\n')
        if (reconnectBaseDelaySecs != 1L) append("reconnect_base_delay = ").append(reconnectBaseDelaySecs).append('\n')
        if (reconnectMaxDelaySecs != 60L) append("reconnect_max_delay = ").append(reconnectMaxDelaySecs).append('\n')
        if (connectionTimeoutSecs != 30L) append("timeout = ").append(connectionTimeoutSecs).append('\n')
    }

    companion object {
        private const val serialVersionUID = 2L

        /**
         * Parse a profile config in EITHER format: flat-INI (starts with a
         * section header / comment) or legacy JSON (starts with `{`). The app
         * now stores INI; this keeps old JSON profiles working transparently.
         */
        fun parse(text: String): VpnConfig =
            when {
                // A raw qeli:// share link — parity with the C# VpnConfig.Parse. Callers
                // like pingActive/probe pass stored p.text (normally already INI), but a
                // qeli:// here would otherwise fall into fromIni and fail "missing [qeli]".
                text.trimStart().startsWith("qeli://") -> fromQeliUri(text.trim())
                text.trimStart().startsWith("{") -> fromJson(text)
                else -> fromIni(text)
            }

        /**
         * Parse the flat-INI `[qeli]` client config (mirrors the Rust
         * ClientConfig::from_ini). Only connection essentials live in the file;
         * everything else is defaulted and overwritten by the server at
         * handshake. `dns`/`mtu` are optional app extras.
         */
        fun fromIni(text: String): VpnConfig {
            val ini = parseIni(text)
            val q = ini["qeli"] ?: throw IllegalArgumentException("config: missing [qeli] section")
            val server = q["server"]?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("[qeli] missing required key 'server' (host:port)")
            val ci = server.lastIndexOf(':')
            require(ci > 0) { "'server' must be host:port, got '$server'" }
            val host = server.substring(0, ci)
            require(host.isNotEmpty()) { "'server' has empty host" }
            val port = server.substring(ci + 1).toIntOrNull()
                ?: throw IllegalArgumentException("'server' has invalid port: '$server'")
            fun bool(v: String?) = v?.trim()?.lowercase() in setOf("true", "1", "yes", "on")
            // Routing: full-tunnel by default on phones (a VPN should carry ALL traffic);
            // `gateway = false` opts into split-tunnel (only the tunnel subnet + pushed
            // routes). Mirrors the Rust client's `gateway` key — the only way to pick
            // split-tunnel via INI (there is no UI toggle).
            val fullTunnel = q["gateway"]?.let { bool(it) } ?: true
            // DNS: `dns = <ip,ip>` is the Android resolver list. Tolerate the Rust/router
            // MODE values (`off`/`tunnel`/`system`) by falling back to the defaults
            // instead of adding a literal "off" as a resolver (which throws at establish).
            val dnsRaw = q["dns"]?.trim()
            val dns = if (dnsRaw.isNullOrEmpty() || dnsRaw.lowercase() in setOf("off", "tunnel", "system"))
                null
            else
                dnsRaw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            return VpnConfig(
                serverAddress = host,
                port = port,
                protocol = q["proto"]?.ifBlank { null } ?: "tcp",
                connectionTimeoutSecs = q["timeout"]?.toLongOrNull() ?: 30L,
                reconnectEnabled = q["reconnect"]?.let { bool(it) } ?: true,
                reconnectMaxRetries = q["reconnect_retries"]?.toIntOrNull() ?: -1,
                reconnectBaseDelaySecs = q["reconnect_base_delay"]?.toLongOrNull() ?: 1L,
                reconnectMaxDelaySecs = q["reconnect_max_delay"]?.toLongOrNull() ?: 60L,
                username = q["user"]?.ifBlank { null } ?: "client",
                password = q["pass"] ?: "",
                serverPublicKeyHex = q["key"]?.takeIf { it.isNotEmpty() },
                // H-1: on by default; needs a pinned key. `bind_static = false` for TOFU.
                bindStaticToSession = q["bind_static"]?.let { bool(it) } ?: true,
                routingMode = if (fullTunnel) "full-tunnel" else "split-tunnel",
                addDefaultGateway = fullTunnel,
                wireMode = q["mode"]?.ifBlank { null } ?: "fake-tls",
                sni = q["sni"]?.takeIf { it.isNotEmpty() },
                realityShortId = q["reality_sid"]?.takeIf { it.isNotEmpty() },
                obfsKey = q["obfs_key"] ?: "",
                obfsFronting = q["front"]?.ifBlank { null } ?: "websocket",
                // F2: AmneziaWG junk. `awg = true` + jc/jmin/jmax (caps applied at use).
                awgEnabled = bool(q["awg"]),
                awgJc = q["jc"]?.toIntOrNull() ?: 0,
                awgJmin = q["jmin"]?.toIntOrNull() ?: 40,
                awgJmax = q["jmax"]?.toIntOrNull() ?: 300,
                quicEnabled = bool(q["quic"]),
                routeLocalNetworks = bool(q["route_local"]),
                dnsServers = if (dns.isNullOrEmpty()) listOf("1.1.1.1", "8.8.8.8") else dns,
                mtu = q["mtu"]?.toIntOrNull() ?: 0  // 0 = auto (use server-pushed MTU)
            )
        }

        /** Minimal line-oriented INI parser (mirrors qeli/src/config/format.rs):
         *  `[section]` / `[kind:instance]`, `key = value`, full-line `;`/`#`
         *  comments, surrounding double-quotes stripped. */
        private fun parseIni(text: String): Map<String, MutableMap<String, String>> {
            val out = LinkedHashMap<String, MutableMap<String, String>>()
            var cur: MutableMap<String, String>? = null
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith(";") || line.startsWith("#")) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    val name = line.substring(1, line.length - 1).trim().substringBefore(':').trim()
                    cur = out.getOrPut(name) { LinkedHashMap() }
                } else {
                    val eq = line.indexOf('=')
                    if (eq < 0) continue
                    val k = line.substring(0, eq).trim()
                    var v = line.substring(eq + 1).trim()
                    if (v.length >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length - 1)
                    if (k.isNotEmpty()) cur?.put(k, v)
                }
            }
            return out
        }

        /**
         * Parse a qeli JSON client config. Unknown fields are ignored; missing
         * fields fall back to the Rust defaults. Supports both the canonical
         * schema and a few legacy aliases.
         */
        fun fromJson(text: String): VpnConfig {
            val root = JSONObject(text)
            val server = root.optJSONObject("server") ?: JSONObject()
            val reconnect = server.optJSONObject("reconnect") ?: JSONObject()
            val auth = root.optJSONObject("auth") ?: JSONObject()
            val tun = root.optJSONObject("tun") ?: JSONObject()
            val routing = root.optJSONObject("routing") ?: JSONObject()
            val dns = root.optJSONObject("dns") ?: JSONObject()
            val obf = root.optJSONObject("obfuscation") ?: JSONObject()
            val padding = obf.optJSONObject("padding") ?: JSONObject()
            val heartbeat = obf.optJSONObject("heartbeat") ?: JSONObject()
            val quic = obf.optJSONObject("quic") ?: JSONObject()
            val awg = obf.optJSONObject("awg") ?: JSONObject()

            val password = when {
                auth.has("password") && !auth.isNull("password") -> auth.optString("password")
                root.has("password") -> root.optString("password")
                else -> ""
            }

            return VpnConfig(
                serverAddress = server.optString("address", root.optString("address", "127.0.0.1")),
                port = server.optInt("port", root.optInt("port", 443)),
                protocol = server.optString("protocol", "tcp"),
                connectionTimeoutSecs = server.optLong("connection_timeout_secs", 30),
                reconnectEnabled = reconnect.optBoolean("enabled", true),
                reconnectMaxRetries = reconnect.optInt("max_retries", -1),
                reconnectBaseDelaySecs = reconnect.optLong("base_delay_secs", 1),
                reconnectMaxDelaySecs = reconnect.optLong("max_delay_secs", 60),
                username = auth.optString("username", root.optString("username", "client")),
                password = password,
                serverPublicKeyHex = auth.optStringOrNull("server_public_key"),
                bindStaticToSession = auth.optBoolean("bind_static_to_session", true),
                mtu = tun.optInt("mtu", 0),  // 0 = auto (use server-pushed MTU)
                // Default to full-tunnel (a VPN should carry ALL traffic) so a config
                // without a routing section doesn't silently leak outside the tunnel.
                // Explicit "split-tunnel" is still honoured: isFullTunnel only becomes
                // true via add_default_gateway or mode=="full-tunnel".
                routingMode = routing.optString("mode", "full-tunnel"),
                addDefaultGateway = routing.optBoolean("add_default_gateway", false),
                includeRoutes = routing.optStringList("include"),
                excludeRoutes = routing.optStringList("exclude"),
                routeLocalNetworks = routing.optBoolean("route_local_networks", false),
                dnsServers = dns.optStringList("servers"),
                wireMode = obf.optString("mode", "fake-tls"),
                obfsKey = obf.optString("obfs_key", ""),
                obfsFronting = obf.optString("fronting", "websocket"),
                awgEnabled = awg.optBoolean("enabled", false),
                awgJc = awg.optInt("jc", 0),
                awgJmin = awg.optInt("jmin", 40),
                awgJmax = awg.optInt("jmax", 300),
                quicEnabled = quic.optBoolean("enabled", false),
                sni = obf.optStringOrNull("sni"),
                realityShortId = obf.optStringOrNull("reality_short_id"),
                paddingEnabled = padding.optBoolean("enabled", true),
                paddingMin = padding.optInt("min_bytes", 0),
                paddingMax = padding.optInt("max_bytes", 255),
                heartbeatEnabled = heartbeat.optBoolean("enabled", true),
                heartbeatIntervalMs = heartbeat.optLong("interval_ms", 15000),
                heartbeatDataSize = heartbeat.optInt("data_size_bytes", 16),
                heartbeatJitterMs = heartbeat.optLong("jitter_ms", 2000)
            )
        }

        /**
         * Parse a `qeli://` share link (the compact, QR-friendly format produced
         * by the server's `/api/share` and `qeli add-client --link`). Mirrors the
         * Rust `ClientLink::from_uri` (qeli/src/config/share.rs).
         *
         * Shape:
         * `qeli://<user>:<pass>@<host>:<port>?proto=tcp&mode=fake-tls&key=<hex>&sni=<host>&obfs=<key>#<label>`
         *
         * Everything not carried by the link is defaulted here and overwritten by
         * the server at handshake time (routes, DNS, MTU, obfuscation params).
         */
        fun fromQeliUri(uri: String): VpnConfig {
            val trimmed = uri.trim()
            val rest0 = trimmed.removePrefix("qeli://")
            require(rest0.length != trimmed.length) { "not a qeli:// link" }

            // Split off #fragment (label), then ?query.
            val (beforeFrag, _label) = rest0.split("#", limit = 2).let {
                if (it.size == 2) it[0] to pctDecode(it[1]) else it[0] to null
            }
            val (authority, query) = beforeFrag.split("?", limit = 2).let {
                if (it.size == 2) it[0] to it[1] else it[0] to null
            }

            // userinfo@host:port  (rsplit so passwords containing '@' if escaped are safe)
            val atIdx = authority.lastIndexOf('@')
            val userinfo = if (atIdx >= 0) authority.substring(0, atIdx) else null
            val hostPort = if (atIdx >= 0) authority.substring(atIdx + 1) else authority
            val host: String
            val port: Int
            if (hostPort.startsWith('[')) {
                // Bracketed IPv6 literal: [2001:db8::1]:443 — split on ']:' so the
                // colons inside the address aren't mistaken for the port separator.
                val rb = hostPort.indexOf(']')
                require(rb > 0 && rb + 1 < hostPort.length && hostPort[rb + 1] == ':') {
                    "qeli:// authority malformed IPv6 [host]:port"
                }
                host = hostPort.substring(1, rb)
                port = hostPort.substring(rb + 2).toIntOrNull()
                    ?: throw IllegalArgumentException("invalid port in qeli:// link")
            } else {
                val colonIdx = hostPort.lastIndexOf(':')
                require(colonIdx > 0) { "qeli:// authority missing :port" }
                host = hostPort.substring(0, colonIdx)
                port = hostPort.substring(colonIdx + 1).toIntOrNull()
                    ?: throw IllegalArgumentException("invalid port in qeli:// link")
            }
            require(host.isNotEmpty()) { "empty host in qeli:// link" }

            var user = ""
            var pass = ""
            if (userinfo != null) {
                val sep = userinfo.indexOf(':')
                if (sep >= 0) {
                    user = pctDecode(userinfo.substring(0, sep))
                    pass = pctDecode(userinfo.substring(sep + 1))
                } else {
                    user = pctDecode(userinfo)
                }
            }

            var proto = "tcp"; var mode = "fake-tls"
            var key: String? = null; var sni: String? = null; var obfs = ""
            var front = "websocket"; var quic = false; var rsid: String? = null
            // F2 AmneziaWG junk: awg (=1 when enabled), jc, jmin, jmax.
            var awg = false; var jc = 0; var jmin = 40; var jmax = 300
            query?.split("&")?.forEach { pair ->
                if (pair.isEmpty()) return@forEach
                val eq = pair.indexOf('=')
                val k = if (eq >= 0) pair.substring(0, eq) else pair
                val v = pctDecode(if (eq >= 0) pair.substring(eq + 1) else "")
                when (k) {
                    "proto" -> proto = v
                    "mode" -> mode = v
                    "key" -> key = v.ifEmpty { null }
                    "sni" -> sni = v.ifEmpty { null }
                    "rsid" -> rsid = v.ifEmpty { null }
                    "obfs" -> obfs = v
                    "front" -> if (v.isNotEmpty()) front = v
                    "quic" -> quic = v == "1" || v.equals("true", ignoreCase = true)
                    "awg" -> awg = v == "1" || v.equals("true", ignoreCase = true)
                    "jc" -> jc = v.toIntOrNull() ?: 0
                    "jmin" -> jmin = v.toIntOrNull() ?: 40
                    "jmax" -> jmax = v.toIntOrNull() ?: 300
                    // forward-compatible: ignore unknown params
                }
            }

            return VpnConfig(
                serverAddress = host,
                port = port,
                protocol = proto,
                username = user,
                password = pass,
                serverPublicKeyHex = key,
                wireMode = mode,
                obfsKey = obfs,
                obfsFronting = front,
                awgEnabled = awg,
                awgJc = jc,
                awgJmin = jmin,
                awgJmax = jmax,
                quicEnabled = quic,
                sni = sni,
                realityShortId = rsid
            )
        }

        /** Percent-decode; invalid escapes pass through literally (matches Rust). */
        private fun pctDecode(s: String): String {
            if (s.indexOf('%') < 0) return s
            val out = StringBuilder(s.length)
            var i = 0
            val bytes = ArrayList<Byte>(s.length)
            while (i < s.length) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length) {
                    val h = hexVal(s[i + 1]); val l = hexVal(s[i + 2])
                    if (h >= 0 && l >= 0) { bytes.add(((h shl 4) or l).toByte()); i += 3; continue }
                }
                // flush any pending UTF-8 bytes before appending a literal char
                if (bytes.isNotEmpty()) { out.append(String(bytes.toByteArray(), Charsets.UTF_8)); bytes.clear() }
                out.append(c); i++
            }
            if (bytes.isNotEmpty()) out.append(String(bytes.toByteArray(), Charsets.UTF_8))
            return out.toString()
        }

        private fun hexVal(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> -1
        }

        private fun JSONObject.optStringOrNull(key: String): String? {
            if (!has(key) || isNull(key)) return null
            val v = optString(key, "")
            return v.ifEmpty { null }
        }

        private fun JSONObject.optStringList(key: String): List<String> {
            val arr = optJSONArray(key) ?: return emptyList()
            return (0 until arr.length()).mapNotNull { arr.optString(it).ifEmpty { null } }
        }
    }
}
