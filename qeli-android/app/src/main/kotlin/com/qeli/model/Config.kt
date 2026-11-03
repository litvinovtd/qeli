package com.qeli.model

import java.io.Serializable

/**
 * Full qeli client configuration. Mirrors the relevant fields of the Rust
 * ClientConfig (qeli/src/config/client.rs). Built either from the simple
 * UI fields or by importing a flat-INI config via [fromIni] / [parse].
 */
data class VpnConfig(
    // ── server ──
    val serverAddress: String,
    val port: Int,
    val protocol: String = ConfigDefaults.protocol,              // "tcp" | "udp"
    val connectionTimeoutSecs: Long = ConfigDefaults.connectionTimeoutSecs,
    // ── reconnect ──
    val reconnectEnabled: Boolean = ConfigDefaults.reconnectEnabled,
    val reconnectMaxRetries: Int = ConfigDefaults.reconnectMaxRetries,
    val reconnectBaseDelaySecs: Long = ConfigDefaults.reconnectBaseDelaySecs,
    val reconnectMaxDelaySecs: Long = ConfigDefaults.reconnectMaxDelaySecs,
    // ── auth ──
    val username: String,
    val password: String,
    val serverPublicKeyHex: String? = ConfigDefaults.serverPublicKeyHex,    // pinned static key (hex), null = TOFU
    // H-1: bind data keys to the server static identity (must match server's
    // auth.bind_static_to_session + requires a pinned key). Default TRUE
    // (secure-by-default since 0.7.1); set false for a legacy 0.7.0 / TOFU server.
    val bindStaticToSession: Boolean = ConfigDefaults.bindStaticToSession,
    // Escape hatch only when a first-seen, server-proven key cannot be persisted. False by
    // default: storage failure aborts fail-closed. True never permits a mismatch with an
    // existing pin; it only allows this session to continue without durable TOFU state.
    val allowUnpinnedTofu: Boolean = ConfigDefaults.allowUnpinnedTofu,
    // ── tun ──
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    val mtu: Int = ConfigDefaults.mtu,
    // Active UDP path-MTU probing when mtu == 0 (default on; kill switch = false). No
    // effect on TCP transports (the kernel does PMTUD) or when mtu > 0 (explicit).
    val mtuProbe: Boolean = ConfigDefaults.mtuProbe,
    // ── routing ──
    // Default to full-tunnel: a VPN should carry ALL traffic so nothing leaks
    // outside the encrypted path. No INI key sets this directly — `fromIni` derives it
    // from `gateway`, and the UI writes it — so `validate` is where a bad value is caught.
    val routingMode: String = "full-tunnel",   // "full-tunnel" | "split-tunnel"
    val addDefaultGateway: Boolean = ConfigDefaults.addDefaultGateway,
    // Inner IPv6 acceptance policy negotiated with the server.
    val ipv6: String = ConfigDefaults.ipv6,                 // "auto" | "required" | "off"
    // Preserve the logical session across carrier changes when safely negotiated.
    val roaming: String = ConfigDefaults.roaming,              // "off" | "auto" | "required"
    // Android implements the shared kill-switch contract by requiring the OS-owned
    // Always-on VPN lockdown before a full-tunnel connection may start. The app cannot
    // flip that system policy itself, but it can verify it from the running VpnService and
    // fail closed when the profile requires protection that is not active.
    val killSwitch: Boolean = ConfigDefaults.killSwitch,
    val includeRoutes: List<String> = emptyList(),
    val excludeRoutes: List<String> = emptyList(),
    // Add the built-in RFC1918 private ranges to the VPN. Authenticated server-pushed routes
    // are applied independently of this flag; false only suppresses the extra local ranges.
    val pullRoutes: Boolean = ConfigDefaults.pullRoutes,
    val routeLocalNetworks: Boolean = ConfigDefaults.routeLocalNetworks,
    // Full-tunnel blocks IPv6 only when the negotiated plan is IPv4-only, closing the dual-stack
    // leak; set true to OPT OUT and keep native IPv6 (it bypasses the tunnel). Default off;
    // mirrors the Rust/desktop `allow_ipv6_leak`.
    val allowIpv6Leak: Boolean = ConfigDefaults.allowIpv6Leak,
    // Symmetric escape hatch for an IPv6-only full tunnel. Secure default blocks IPv4.
    val allowIpv4Leak: Boolean = ConfigDefaults.allowIpv4Leak,
    // Allow direct access to the local/LAN network while on a full tunnel: carve the
    // RFC1918 private ranges OUT of the tunnel so Wi-Fi/LAN devices (printers, NAS,
    // Chromecast, the router UI) stay reachable without disconnecting the VPN. Off by
    // default (a full tunnel normally carries everything). Distinct from — and the
    // inverse of — route_local_networks. Android extra; the desktop/CLI client ignores it.
    val allowLan: Boolean = ConfigDefaults.allowLan,
    // ── dns ──
    // Explicit resolvers reached through the tunnel. Empty means that authenticated server
    // push may supply the list; if neither source does, Android leaves the system resolver
    // untouched and reports the missing tunnel DNS instead of inventing a public resolver.
    val dnsServers: List<String> = emptyList(),
    /**
     * DNS handling mode, mirroring `dns.mode` in the Rust client: `tunnel` (default — install
     * resolvers reachable through the tunnel), `off` or `system` (leave the device resolver
     * alone).
     *
     * Legacy mobile profiles used the same `dns` key for both a mode and a resolver list.
     * Readers still accept that form, while writers use canonical `dns_servers`; the mode is
     * kept separately so `off`/`system` survives an edit. (Audit 2026-08-02, §3.)
     */
    val dnsMode: String = ConfigDefaults.dnsMode,
    // ── obfuscation ──
    val wireMode: String = ConfigDefaults.wireMode,         // "fake-tls" | "obfs"
    val obfsKey: String = ConfigDefaults.obfsKey,
    // obfs anti-FET fronting: "websocket" (default) wraps the nonce exchange in a
    // WebSocket Upgrade handshake; "none" is the legacy raw nonce. Must match the
    // server. Mirrors ClientObfuscationConfig::fronting in the Rust client.
    val obfsFronting: String = ConfigDefaults.obfsFronting,
    // F2: AmneziaWG-style pre-handshake junk (obfs mode only). OFF by default so
    // the wire is byte-identical to today. When awgEnabled && awgJc>0, the sender
    // emits awgJc junk records (each uniform length in [awgJmin,awgJmax]) right
    // after the front/TCP handshake and before the nonce exchange; the peer reads
    // and discards awgJc records. Both ends MUST share awgJc; jmin/jmax are
    // sender-only. Mirrors obf.awg.* in the Rust/C# clients.
    val awgEnabled: Boolean = ConfigDefaults.awgEnabled,
    val awgJc: Int = ConfigDefaults.awgJc,      // junk record count, cap 128
    val awgJmin: Int = ConfigDefaults.awgJmin,   // min junk length
    val awgJmax: Int = ConfigDefaults.awgJmax,  // max junk length (require jmin<=jmax<=1400)
    val quicEnabled: Boolean = ConfigDefaults.quicEnabled,
    val sni: String? = ConfigDefaults.sni,
    // REALITY short_id (hex) — pairs with serverPublicKeyHex to seal the auth
    // token into the realtls ClientHello (wireMode = "reality-tls").
    val realityShortId: String? = ConfigDefaults.realityShortId,
    // padding
    val paddingEnabled: Boolean = ConfigDefaults.paddingEnabled,
    val paddingMin: Int = ConfigDefaults.paddingMin,
    val paddingMax: Int = ConfigDefaults.paddingMax,
    // heartbeat
    val heartbeatEnabled: Boolean = ConfigDefaults.heartbeatEnabled,
    val heartbeatIntervalMs: Long = ConfigDefaults.heartbeatIntervalMs,
    val heartbeatDataSize: Int = ConfigDefaults.heartbeatDataSize,
    val heartbeatJitterMs: Long = ConfigDefaults.heartbeatJitterMs,
    // flow shaping (idle cover traffic; DPI-AUDIT 6.1/6.2). Normally pushed from
    // the server. Defaults mirror the Rust TrafficShapingConfig.
    val shapingEnabled: Boolean = ConfigDefaults.shapingEnabled,
    val shapingGapMeanMs: Long = ConfigDefaults.shapingGapMeanMs,
    val shapingGapMinMs: Long = ConfigDefaults.shapingGapMinMs,
    val shapingGapMaxMs: Long = ConfigDefaults.shapingGapMaxMs,
    val shapingBudgetBytesPerSec: Int = ConfigDefaults.shapingBudgetBytesPerSec,
    val shapingMinSize: Int = ConfigDefaults.shapingMinSize,
    val shapingMaxSize: Int = ConfigDefaults.shapingMaxSize,
    // Stealth (Phase 2): rate-cap the data plane + cover under load. TCP-only.
    val shapingStealth: Boolean = ConfigDefaults.shapingStealth,
    val shapingStealthRateMbps: Int = ConfigDefaults.shapingStealthRateMbps,
    // ── per-app split tunnel (Android-only extra; the Rust/desktop clients ignore these) ──
    // "all" = every app uses the VPN (default). "include" = ONLY [apps] are tunnelled.
    // "exclude" = every app EXCEPT [apps]. [apps] holds Android package names.
    val appsMode: String = ConfigDefaults.appsMode,             // "all" | "include" | "exclude"
    val apps: List<String> = emptyList(),
    // ── [logging] passthrough ──
    // Not used by the app (its own log settings live in SharedPreferences); carried so a
    // desktop/router client.conf opened and re-saved here keeps its logging section instead
    // of silently losing it. Mirrors qeli/src/config/client.rs, which parses AND re-emits it.
    val loggingLevel: String? = ConfigDefaults.loggingLevel,
    val loggingFile: String? = ConfigDefaults.loggingFile,
    val loggingTimeFormat: String? = ConfigDefaults.loggingTimeFormat,
    // Desktop-only route sources are still part of the portable INI contract. Keep every
    // repeated occurrence so editing a desktop profile on Android cannot discard all but the
    // last file. Android does not open these host paths itself.
    val routeFiles: List<String> = emptyList(),
    /**
     * `[qeli]` keys this Kotlin model accepts but does not edit — transport-owned or foreign
     * platform settings in the Rust schema (`post_up`, `exit_node`, `gateway_nat`, …).
     *
     * Accepting them without keeping them made import-then-save LOSSY in the worst possible
     * direction: a desktop `client.conf` opened here and re-saved came back missing its
     * post-up/post-down hooks, socket settings and routing policy. The keys were on the
     * allowlist precisely so such a profile would open, and then the profile was quietly
     * gutted by the act of opening it. Exactly the failure the `[logging]` passthrough above
     * already exists to prevent — this is the same fix for the rest of them.
     *
     * Stored verbatim (original key spelling and value) and re-emitted by [toIni] after the
     * keys this port does model, so a round trip is byte-stable for everything it does not
     * understand. (Audit 2026-08-02, §7.)
     */
    val carriedKeys: Map<String, String> = emptyMap(),
    /**
     * Keys whose boolean value was neither true-ish nor false-ish — `gateway = ture`.
     *
     * Carried instead of being resolved at parse time because the ORIGINAL STRING IS LOST once
     * a bool is produced, so nothing downstream could ever tell a typo from a deliberate
     * `false`. That mattered: every unknown value used to read as `false`, so `kill_switch =
     * ture` silently disabled the kill switch and `bind_static = ture` silently dropped the
     * static-key binding — a security downgrade with no message anywhere.
     *
     * Parsing still SUCCEEDS (the editor must be able to open a bad profile in order to fix
     * it); [validate] is what refuses to connect. Same split as the enum checks.
     * (Audit 2026-07-31.)
     */
    val unparsedBooleanKeys: List<String> = emptyList(),

    /** Rust reports duplicate scalars; drafts display the first and validation refuses them. */
    val duplicateKeys: List<String> = emptyList(),

    /**
     * Numeric fields whose value was present but unreadable, which used to fall back to the
     * default in silence. `server`'s port has always thrown; this covers the rest, and keeps
     * this port as strict as the C# one. Parsing still SUCCEEDS; [validate] refuses.
     * (Audit 2026-08-01, §P2.)
     */
    val unparsedNumericKeys: List<String> = emptyList(),

    /**
     * `[qeli]` keys no qeli client understands — i.e. misspellings. The setting they were meant
     * to change silently keeps its default, which is how `gatway = true` left a tunnel split
     * with nothing said. Reported, not resolved; [validate] refuses. (Audit 2026-08-01, §14.)
     */
    val nativeSource: String? = null,
    val unknownKeys: List<String> = emptyList()
) : Serializable {

    /** True when the protocol is UDP (DatagramChannel transport, QUIC masking). */
    val isUdp: Boolean get() = protocol.equals("udp", ignoreCase = true)

    /**
     * `all` counts too. The validator accepts `split-tunnel | full-tunnel | all` (the Rust
     * client's set, see `client/route.rs`), but this only compared against `full-tunnel` — so a
     * perfectly valid `routing.mode = "all"` profile validated and then ran as a SPLIT tunnel,
     * quietly sending everything outside the VPN past it. (Audit 2026-07-31, §2.)
     */
    val isFullTunnel: Boolean
        get() = com.qeli.ConfigCore.policy("full_tunnel", org.json.JSONObject().put("gateway",addDefaultGateway).put("mode",routingMode)).getBoolean("value")
    val allowsNativePathRoaming: Boolean
        get() = com.qeli.ConfigCore.policy("roaming_allowed", org.json.JSONObject().put("mode",roaming).put("local",carriedKeys["local"].orEmpty()).put("port",carriedKeys["lport"].orEmpty().ifBlank { "0" })).getBoolean("value")

    /** Validation and serialization use the Rust document service; fromIni can open a draft. */
    fun validate() { ConfigProjection.operation(this,"validate") }
    fun toQeliUri(name: String? = null): String = ConfigProjection.operation(this,"uri",name).getString("text")
    fun toIni(label: String? = null): String = ConfigProjection.operation(this,"export",label).getString("text")
    fun toTransportCoreIni(label: String? = null): String = ConfigProjection.operation(this,"runtime",label).getString("text")
    fun toTransportProbeIni(): String = ConfigProjection.operation(this,"probe").getString("text")
    companion object {
        private const val serialVersionUID = 2L
        const val MTU_MIN = 576
        const val MTU_MAX = 16602
        const val AUTH_CRED_BUDGET = 1114
        fun mtuInRange(mtu: Int): Boolean = com.qeli.ConfigCore.policy("mtu",org.json.JSONObject().put("value",mtu)).getBoolean("value")
        fun parse(text: String): VpnConfig = ConfigProjection.parse(text).also { it.validate() }
        fun fromIni(text: String): VpnConfig = ConfigProjection.parse(text)
        fun fromQeliUri(text: String): VpnConfig = ConfigProjection.parse(text)
    }
}
