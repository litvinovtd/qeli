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
    // Escape hatch only when a first-seen, server-proven key cannot be persisted. False by
    // default: storage failure aborts fail-closed. True never permits a mismatch with an
    // existing pin; it only allows this session to continue without durable TOFU state.
    val allowUnpinnedTofu: Boolean = false,
    // ── tun ──
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    val mtu: Int = 0,
    // Active UDP path-MTU probing when mtu == 0 (default on; kill switch = false). No
    // effect on TCP transports (the kernel does PMTUD) or when mtu > 0 (explicit).
    val mtuProbe: Boolean = true,
    // ── routing ──
    // Default to full-tunnel: a VPN should carry ALL traffic so nothing leaks
    // outside the encrypted path. No INI key sets this directly — `fromIni` derives it
    // from `gateway`, and the UI writes it — so `validate` is where a bad value is caught.
    val routingMode: String = "full-tunnel",   // "full-tunnel" | "split-tunnel"
    val addDefaultGateway: Boolean = true,
    // Android implements the shared kill-switch contract by requiring the OS-owned
    // Always-on VPN lockdown before a full-tunnel connection may start. The app cannot
    // flip that system policy itself, but it can verify it from the running VpnService and
    // fail closed when the profile requires protection that is not active.
    val killSwitch: Boolean = false,
    val includeRoutes: List<String> = emptyList(),
    val excludeRoutes: List<String> = emptyList(),
    // Route private/local networks (RFC1918) through the VPN. When true, the
    // client adds the private ranges AND applies any networks the server pushed,
    // so LAN resources behind the server work through the tunnel. When false
    // (default), local networks are not tunnelled and pushed networks are ignored.
    val routeLocalNetworks: Boolean = false,
    // Full-tunnel captures IPv6 into the (IPv4-only) tunnel to close the classic dual-stack
    // leak; set true to OPT OUT and keep native IPv6 (it bypasses the tunnel). Default off;
    // mirrors the Rust/desktop `allow_ipv6_leak`.
    val allowIpv6Leak: Boolean = false,
    // Allow direct access to the local/LAN network while on a full tunnel: carve the
    // RFC1918 private ranges OUT of the tunnel so Wi-Fi/LAN devices (printers, NAS,
    // Chromecast, the router UI) stay reachable without disconnecting the VPN. Off by
    // default (a full tunnel normally carries everything). Distinct from — and the
    // inverse of — route_local_networks. Android extra; the desktop/CLI client ignores it.
    val allowLan: Boolean = false,
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
    val dnsMode: String = "tunnel",
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
    val shapingStealthRateMbps: Int = 2,
    // ── per-app split tunnel (Android-only extra; the Rust/desktop clients ignore these) ──
    // "all" = every app uses the VPN (default). "include" = ONLY [apps] are tunnelled.
    // "exclude" = every app EXCEPT [apps]. [apps] holds Android package names.
    val appsMode: String = "all",             // "all" | "include" | "exclude"
    val apps: List<String> = emptyList(),
    // ── [logging] passthrough ──
    // Not used by the app (its own log settings live in SharedPreferences); carried so a
    // desktop/router client.conf opened and re-saved here keeps its logging section instead
    // of silently losing it. Mirrors qeli/src/config/client.rs, which parses AND re-emits it.
    val loggingLevel: String? = null,
    val loggingFile: String? = null,
    val loggingTimeFormat: String? = null,
    /**
     * `[qeli]` keys this Kotlin model accepts but does not edit — transport-owned or foreign
     * platform settings in [KNOWN_INI_KEYS] (`post_up`, `exit_node`, `gateway_nat`, …).
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

    /**
     * Keys that appeared more than once in one section, as `section.key`.
     *
     * A key read as a SINGLE value but written twice makes the file ambiguous, and the ports
     * resolved it differently: this parser folds entries into a map and keeps the LAST, while
     * the Rust client takes the FIRST. Two `server` lines therefore sent the Rust client to one
     * host and every GUI client to another, out of one file, with nothing reported anywhere.
     *
     * Recorded, not resolved — picking a winner still leaves the other implementations
     * disagreeing, and only the author knows which line was meant. Parsing still SUCCEEDS, as
     * with [unparsedBooleanKeys]; [validate] is what refuses. (Audit 2026-08-01, §7.)
     */
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
        get() = addDefaultGateway ||
            routingMode.equals("full-tunnel", ignoreCase = true) ||
            routingMode.equals("all", ignoreCase = true)

    /**
     * Reject configs that cannot be represented as flat-INI, and range-check the numeric
     * fields. Mirrors the iOS `VPNConfig.validate()` so both mobile clients accept and
     * refuse exactly the same profiles.
     *
     * The control-character scan is a SECURITY guard, not cosmetics. [toIni] writes
     * `key = value` verbatim, so a password / SNI / route carrying a newline lets an
     * imported `qeli://` link forge additional INI keys — e.g. appending
     * `\nbind_static = false` turns off binding the session to the pinned server key, and
     * the forged line comes back as trusted config on the next save. Checked on emit (the
     * moment the forgery would be written) and on link import (untrusted input entering).
     *
     * Parsing stays lenient about the STRING fields for the same reason (an odd sni already
     * on disk must not lock the user out of their own profile), but NOT about the numeric
     * ranges: `mtu` and the padding bounds are checked at import too, because an
     * out-of-range value there is not a cosmetic problem — it produces a tunnel that cannot
     * establish, or records the peer rejects, with no hint of why. See [checkedMtu] /
     * [checkedPadding]. (Audit 2026-07-27, C6)
     */
    fun validate() {
        // A boolean nobody could parse is a typo, and every one of them used to read as
        // `false` — so `kill_switch = ture` disabled the kill switch and `bind_static = ture`
        // dropped the static-key binding, silently. Refuse to connect rather than run with a
        // setting the user plainly did not choose. (Audit 2026-07-31.)
        require(unparsedBooleanKeys.isEmpty()) {
            "unrecognised boolean value for ${unparsedBooleanKeys.joinToString(", ")} — " +
                "expected true/false, yes/no, on/off or 1/0"
        }

        // A key written twice is ambiguous, and the ports disagreed on which line wins — the
        // same file reached two different servers depending on the client. (Audit 2026-08-01.)
        require(duplicateKeys.isEmpty()) {
            "key(s) ${duplicateKeys.joinToString(", ")} appear more than once and are read as a " +
                "single value; implementations disagree on which wins — keep one"
        }

        // Keep a distinct path for a real security control a future Android version cannot
        // honour. The set is empty today: kill_switch is modelled and enforced through the
        // OS Always-on VPN lockdown. (Audit 2026-08-04, M-20 follow-up.)
        for (k in unknownKeys) {
            UNSUPPORTED_INI_KEYS[k.lowercase()]?.let { why ->
                throw IllegalArgumentException("'$k' is not supported by the Android client. $why")
            }
        }

        // A misspelled key name is invisible: nothing reads it, so the setting it was meant to
        // change silently keeps its default. (Audit 2026-08-01, §14.)
        require(unknownKeys.isEmpty()) {
            "unknown key(s), likely misspelled: ${unknownKeys.joinToString(", ")} — nothing " +
                "reads these, so the setting they were meant to change is at its default"
        }

        // A number nobody could parse must not become a default in silence. (Audit 2026-08-01.)
        require(unparsedNumericKeys.isEmpty()) {
            "unparseable number for ${unparsedNumericKeys.joinToString(", ")} — the default " +
                "would have been used instead"
        }

        // The fallback for this one is the WIDEST setting, so a typo does not narrow the
        // tunnel, it opens it: `apps_mode = includ` would have tunnelled every app while the
        // user believed only a few were selected. (Audit 2026-08-02, §10.)
        require(appsMode in setOf("all", "include", "exclude")) {
            "apps_mode must be all, include or exclude — got '$appsMode'"
        }
        // Same reasoning: the fallback is "tunnel", so a typo does not fail — it picks the
        // opposite of `off`/`system` and sends every lookup through the VPN.
        require(dnsMode in setOf("off", "tunnel", "system")) {
            "dns mode must be off, tunnel or system — got '$dnsMode'"
        }

        // Credentials must leave the AUTH message inside one datagram on UDP.
        //
        // AUTH goes out UNFRAGMENTED, unlike the ClientHello beside it and the AuthOK coming
        // back, and its size IS the credentials — nothing else in it varies. A long generated
        // token used as a password pushes the record past the fragment budget, the datagram
        // then needs IP fragmentation, and a mobile or CGNAT path drops it. The symptom is a
        // handshake that times out only on those networks: indistinguishable from an
        // unreachable server, with nothing in any log. This bound exists in the Rust client;
        // without it here the same profile worked on a laptop and hung on the phone.
        //
        // BYTES, not characters: the wire carries UTF-8, so a non-Latin password is longer
        // than it looks. (Audit 2026-08-02, follow-up.)
        val credBytes = username.toByteArray(Charsets.UTF_8).size +
            password.toByteArray(Charsets.UTF_8).size + 1 // + the ':' separator
        require(credBytes <= AUTH_CRED_BUDGET) {
            "'user' + 'pass' are $credBytes bytes, over the $AUTH_CRED_BUDGET a UDP AUTH " +
                "datagram can carry — the handshake would be dropped by any path that " +
                "discards IP fragments (mobile, CGNAT) and would look like an unreachable " +
                "server. Shorten them."
        }
        // The flat INI spells the MODE and the RESOLVER LIST with the same `dns` key, so a
        // misspelled mode does not fall through to an error — it falls through to being read
        // as an ADDRESS. `dns = of` became a resolver named "of", the tunnel installed it, and
        // every lookup went to something that cannot answer. A resolver must be an IP literal
        // (you cannot resolve a resolver by name), so checking that turns the typo back into
        // an error. (Audit 2026-08-02, follow-up.)
        for (server in dnsServers) {
            require(isIpLiteral(server)) {
                "dns server '$server' is not an IP address — if you meant a mode, it must be " +
                    "off, tunnel or system"
            }
        }
        fun scalar(name: String, v: String?) {
            val bad = v?.firstOrNull { it == '\r' || it == '\n' || it == '\u0000' } ?: return
            throw IllegalArgumentException(
                "'$name' contains a control character (0x%02X); refusing to write it".format(bad.code)
            )
        }
        scalar("server", serverAddress); scalar("proto", protocol)
        scalar("user", username); scalar("pass", password)
        scalar("key", serverPublicKeyHex); scalar("mode", wireMode)
        scalar("sni", sni); scalar("reality_sid", realityShortId)
        scalar("obfs_key", obfsKey); scalar("front", obfsFronting)
        for (v in includeRoutes) scalar("include", v)
        for (v in excludeRoutes) scalar("exclude", v)
        for (v in dnsServers) scalar("dns", v)
        for (v in apps) scalar("apps", v)
        scalar("logging.level", loggingLevel); scalar("logging.file", loggingFile)
        scalar("logging.time_format", loggingTimeFormat)
        // Carried keys are written back verbatim, so they get the same INI-forgery gate as
        // everything else this port emits — a `post_up` with an embedded newline would
        // otherwise inject arbitrary config lines on save.
        for ((k, v) in carriedKeys) scalar(k, v)

        require(serverAddress.isNotEmpty()) { "'server' has empty host" }
        require(port in 1..65535) { "'server' port out of range: $port" }
        require(protocol == "tcp" || protocol == "udp") { "'proto' must be tcp or udp, got '$protocol'" }
        require(connectionTimeoutSecs in 1..300) { "'timeout' must be 1..300, got $connectionTimeoutSecs" }
        require(wireMode in WIRE_MODES) { "'mode' must be one of $WIRE_MODES, got '$wireMode'" }
        // Same class as `mode`, and left unchecked: both are compared against ONE literal at
        // the use site, so an unknown value does not error — it silently takes the other
        // branch. `front = webscoket` drops the WebSocket framing the profile asked for and the
        // peer then disagrees about the wire; `routing_mode = full-tunel` with
        // add_default_gateway = false quietly becomes a split tunnel. (Audit 2026-07-31, §3.)
        require(obfsFronting in FRONTING_MODES) {
            "'front' must be one of $FRONTING_MODES, got '$obfsFronting'"
        }
        require(routingMode in ROUTING_MODES) {
            "'routing_mode' must be one of $ROUTING_MODES, got '$routingMode'"
        }
        // A mode that needs a secret must HAVE it, or the profile is valid and unusable.
        //
        // Each of these was checked at the use site or not at all, so the app called the
        // profile fine and the failure surfaced mid-handshake — where it reads as a server or
        // network problem rather than a missing field. The short_id is the sharpest case: this
        // side parses hex leniently and the SERVER strictly, so `reality_sid = deadbeeg` became
        // a different token here and matched nothing there. (Audit 2026-08-03, P2.)
        if (wireMode.lowercase() == "reality-tls") {
            val sid = realityShortId?.trim().orEmpty()
            require(sid.isNotEmpty()) {
                "'mode = reality-tls' requires 'reality_sid' — it is the token the server uses " +
                    "to tell qeli clients from probes; without it this client is treated as a " +
                    "probe and proxied to the decoy site"
            }
            require(sid.length % 2 == 0 && sid.length <= 16 &&
                sid.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' } &&
                sid.any { it != '0' }) {
                "'reality_sid' must be 1..8 bytes of hex (2..16 hex digits, not all zero), got " +
                    "'$sid' — this client parses hex leniently and the SERVER does not, so a " +
                    "malformed value silently becomes a different token and never matches"
            }
            require(!serverPublicKeyHex.isNullOrBlank()) {
                "'mode = reality-tls' requires a pinned server 'key' — REALITY's whole point is " +
                    "that an unauthenticated peer is proxied to the decoy site, which a TOFU " +
                    "client cannot tell apart from the real server"
            }
        }
        require(wireMode.lowercase() != "obfs" || obfsKey.isNotBlank()) {
            "'mode = obfs' requires a non-empty 'obfs_key' — an empty key is publicly derivable, " +
                "so the stream is obfuscated against nobody (the server refuses the same pairing)"
        }
        // Both fields are individually valid and the PAIR is not. The server refuses these two
        // combinations, so a client that accepts them cannot reach any working profile — it
        // just fails later and less clearly. Worse for `reality-tls`: nothing about the name
        // says TCP, so the operator believes they have the strongest masking available while
        // the datagram path quietly falls back to fake-tls framing. (Audit 2026-08-03, P2.)
        if (protocol.lowercase() == "udp") {
            require(wireMode.lowercase() != "plain") {
                "'mode = plain' is TCP-only (raw framing has no datagram form) — set " +
                    "proto = tcp, or pick obfs/fake-tls for a UDP profile"
            }
            require(wireMode.lowercase() != "reality-tls") {
                "'mode = reality-tls' is TCP-only — it terminates a REAL TLS 1.3 session, " +
                    "which UDP cannot carry. Set proto = tcp, or pick obfs for UDP"
            }
        }
        // 0 = auto. Matches the Rust client, which rejects anything outside MTU_MIN..MTU_MAX.
        // Same predicate the import paths use, so emit and import can never disagree. (C6)
        require(mtuInRange(mtu)) { "'mtu' must be 0 (auto) or $MTU_MIN..$MTU_MAX, got $mtu" }
        require(paddingMin >= 0 && paddingMax >= paddingMin && paddingMax <= PADDING_CEILING) {
            "padding range invalid: $paddingMin..$paddingMax (expected 0..$PADDING_CEILING)"
        }
    }

    /**
     * Build a compact `qeli://` share link (inverse of [fromQeliUri]); mirrors the C#
     * VpnConfig.ToQeliUri and the Rust ClientLink::to_uri, so the link imports on every
     * client + the server's /api/share. [name] becomes the `#label` fragment.
     */
    fun toQeliUri(name: String? = null): String {
        validate()
        val sb = StringBuilder("qeli://")
        // Always `user:pass@`, even when the password is empty — that is what the Rust
        // ClientLink::to_uri and the iOS client emit, so the same profile now produces a
        // byte-identical link (and QR) on every platform.
        sb.append(pctEncode(username)).append(':').append(pctEncode(password))
        // Bracket an IPv6 literal so its colons aren't read as the :port separator.
        val host = if (serverAddress.contains(':') && !serverAddress.startsWith('[')) "[$serverAddress]" else serverAddress
        sb.append('@').append(host).append(':').append(port)
        val q = mutableListOf("proto=$protocol", "mode=$wireMode")
        if (!serverPublicKeyHex.isNullOrEmpty()) q.add("key=$serverPublicKeyHex")
        if (!sni.isNullOrEmpty()) q.add("sni=${pctEncode(sni!!)}")
        if (!realityShortId.isNullOrEmpty()) q.add("rsid=${pctEncode(realityShortId!!)}")
        if (obfsKey.isNotEmpty()) q.add("obfs=${pctEncode(obfsKey)}")
        if (awgEnabled) { q.add("awg=1"); q.add("jc=$awgJc"); q.add("jmin=$awgJmin"); q.add("jmax=$awgJmax") }
        if (quicEnabled) q.add("quic=1")
        if (mtu > 0) q.add("mtu=$mtu")   // 0 = auto, omit
        // `front` affects the wire: omitting it does not mean "default" to the importer,
        // it means the import silently re-defaults to websocket — a different framing, so
        // the tunnel never handshakes. Carried by every implementation. (C-12)
        if (obfsFronting != "websocket") q.add("front=${pctEncode(obfsFronting)}")
        // `bind_static` and `mtu_probe` are deliberately NOT emitted. They are local device
        // policy, not a property of the server, and the link is defined as carrying only
        // what the client cannot learn any other way. Android was the only implementation
        // that put them in: Rust, C# and Swift dropped them as unknown params, so a link
        // shared from here arrived elsewhere with bind_static silently back ON — demanding
        // a pinned key the link never carried. Emitting `bind_static=0` was also the worse
        // half of the divergence: it hands a security downgrade to anyone the QR is
        // forwarded to. Set both in the profile itself instead. Parsing them stays below,
        // as tolerance for links this app issued before 0.7.13.
        sb.append('?').append(q.joinToString("&"))
        if (!name.isNullOrBlank()) sb.append('#').append(pctEncode(name))
        return sb.toString()
    }

    // `toConfigJson` lived here — DELETED (Audit 2026-07-27, X4). It had no callers: the app
    // stores profiles as flat-INI via [toIni], and an imported qeli:// link goes through that
    // same path. It also hardcoded `routing.mode = "full-tunnel"` + `add_default_gateway =
    // true` regardless of the config it was serialising, so anyone who wired it up would have
    // silently overridden a split-tunnel profile — dead code that was wrong on the one field
    // a VPN cannot afford to get wrong.

    /**
     * Render the connection essentials to the flat-INI `[qeli]` format — the
     * SAME schema the Rust client reads (qeli/src/config/client.rs::from_ini),
     * so a profile exported here is loadable by the desktop/CLI client too.
     * `dns` and `mtu` are app extras the Rust client simply ignores.
     */
    fun toIni(label: String? = null): String = buildString {
        // Emit-time gate: refuses control characters (INI forgery) and out-of-range values.
        validate()
        // A label carrying a newline would forge INI lines just like a scalar would.
        if (!label.isNullOrBlank()) append("# ").append(label.replace(Regex("[\\r\\n\\u0000]"), " ")).append('\n')
        append("[qeli]\n")
        append("server = ").append(serverAddress).append(':').append(port).append('\n')
        append("proto = ").append(protocol).append('\n')
        append("user = ").append(username).append('\n')
        append("pass = ").append(password).append('\n')
        if (!serverPublicKeyHex.isNullOrEmpty()) append("key = ").append(serverPublicKeyHex).append('\n')
        if (!bindStaticToSession) append("bind_static = false\n")  // on by default; emit only when off
        if (allowUnpinnedTofu) append("allow_unpinned_tofu = true\n")
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
        append("gateway = ").append(isFullTunnel).append('\n')
        if (killSwitch) append("kill_switch = true\n")
        if (routeLocalNetworks) append("route_local = true\n")
        if (allowIpv6Leak) append("allow_ipv6_leak = true\n")
        if (allowLan) append("allow_lan = true\n")  // LAN bypass (exclude RFC1918 from tunnel)
        if (includeRoutes.isNotEmpty()) append("include = ").append(includeRoutes.joinToString(", ")).append('\n')
        if (excludeRoutes.isNotEmpty()) append("exclude = ").append(excludeRoutes.joinToString(", ")).append('\n')
        // One key, two meanings — mirroring the Rust client. A non-default MODE wins over the
        // server list: `dns = off` must survive a save/load round-trip, or re-saving a profile
        // would silently turn "leave my resolver alone" back into tunnel-managed DNS.
        if (dnsMode != "tunnel") append("dns = ").append(dnsMode).append('\n')
        if (dnsServers.isNotEmpty()) append("dns_servers = ").append(dnsServers.joinToString(", ")).append('\n')
        if (mtu > 0) append("mtu = ").append(mtu).append('\n')  // 0 = auto, omit
        if (!mtuProbe) append("mtu_probe = false\n")  // default true, emit only when off
        // Per-app split tunnel (Android extra). Emit only when active so default
        // profiles stay byte-identical and the desktop/CLI client (which ignores
        // these keys) round-trips them harmlessly.
        // Emitted independently (matching iOS): coupling them dropped `apps_mode = include`
        // with an empty list, silently reverting the profile to "all apps tunnelled".
        if (appsMode != "all") append("apps_mode = ").append(appsMode).append('\n')
        if (apps.isNotEmpty()) append("apps = ").append(apps.joinToString(", ")).append('\n')
        // Reconnect is Android lifecycle policy; timeout is transport-core policy. Reconnect
        // remains sparse while timeout is explicit at the Android→Rust boundary.
        if (!reconnectEnabled) append("reconnect = false\n")
        if (reconnectMaxRetries != -1) append("reconnect_retries = ").append(reconnectMaxRetries).append('\n')
        if (reconnectBaseDelaySecs != 1L) append("reconnect_base_delay = ").append(reconnectBaseDelaySecs).append('\n')
        if (reconnectMaxDelaySecs != 60L) append("reconnect_max_delay = ").append(reconnectMaxDelaySecs).append('\n')
        append("timeout = ").append(connectionTimeoutSecs).append('\n')
        // Padding / heartbeat / shaping are explicit local values at the core boundary. The
        // key names match the iOS client exactly, so without these an
        // iOS-exported profile silently lost its shaping/heartbeat tuning here.
        append("padding = ").append(paddingEnabled).append('\n')
        append("padding_min = ").append(paddingMin).append('\n')
        append("padding_max = ").append(paddingMax).append('\n')
        append("heartbeat = ").append(heartbeatEnabled).append('\n')
        append("heartbeat_interval = ").append(heartbeatIntervalMs).append('\n')
        append("heartbeat_size = ").append(heartbeatDataSize).append('\n')
        append("heartbeat_jitter = ").append(heartbeatJitterMs).append('\n')
        append("shaping = ").append(shapingEnabled).append('\n')
        append("shaping_gap_mean = ").append(shapingGapMeanMs).append('\n')
        append("shaping_gap_min = ").append(shapingGapMinMs).append('\n')
        append("shaping_gap_max = ").append(shapingGapMaxMs).append('\n')
        append("shaping_budget = ").append(shapingBudgetBytesPerSec).append('\n')
        append("shaping_min_size = ").append(shapingMinSize).append('\n')
        append("shaping_max_size = ").append(shapingMaxSize).append('\n')
        append("shaping_stealth = ").append(shapingStealth).append('\n')
        append("shaping_stealth_mbps = ").append(shapingStealthRateMbps).append('\n')
        // Re-emit the keys this port accepts but does not model, verbatim and in a stable
        // order. Without this, opening a CLI profile here and saving it deleted its hooks
        // (`post_up`/`post_down`), socket policy and routing policy — silently, and as
        // a side effect of merely opening it. (Audit 2026-08-02, §7.)
        for ((k, v) in carriedKeys.toSortedMap()) append(k).append(" = ").append(v).append('\n')
        // Re-emit [logging] verbatim so a desktop/router client.conf survives a mobile save.
        if (!loggingLevel.isNullOrEmpty() || !loggingFile.isNullOrEmpty() || !loggingTimeFormat.isNullOrEmpty()) {
            append("\n[logging]\n")
            if (!loggingLevel.isNullOrEmpty()) append("level = ").append(loggingLevel).append('\n')
            if (!loggingFile.isNullOrEmpty()) append("file = ").append(loggingFile).append('\n')
            if (!loggingTimeFormat.isNullOrEmpty()) append("time_format = ").append(loggingTimeFormat).append('\n')
        }
    }

    /** Canonical INI passed to the shared Rust transport core. */
    fun toTransportCoreIni(label: String? = null): String = toIni(label)

    /**
     * Credential-free strict profile for the native UDP reachability diagnostic. The probe
     * stops at the first server flight, so user/password, trust, routing and performance
     * settings do not cross this JNI boundary. Rust remains the sole owner of TLS/PQ,
     * fragmentation, QUIC and obfs construction.
     */
    fun toTransportProbeIni(): String = buildString {
        validate()
        append("[qeli]\n")
        append("server = ").append(serverAddress).append(':').append(port).append('\n')
        append("proto = ").append(protocol).append('\n')
        append("mode = ").append(wireMode).append('\n')
        if (!sni.isNullOrBlank()) append("sni = ").append(sni).append('\n')
        if (obfsKey.isNotEmpty()) append("obfs_key = ").append(obfsKey).append('\n')
        if (quicEnabled) append("quic = true\n")
    }

    companion object {
        private const val serialVersionUID = 2L

        /** Wire modes the client can actually dial; same set as the iOS validator. */
        private val WIRE_MODES = setOf("plain", "fake-tls", "obfs", "reality-tls")
        private val FRONTING_MODES = setOf("websocket", "none")
        private val ROUTING_MODES = setOf("split-tunnel", "full-tunnel", "all")

        /**
         * Values of `mtu_probe` that turn probing OFF. Anything else — including an
         * unrecognised word — leaves the default (on), which is what the Rust `bool_or`
         * and the iOS client do. Using the generic truthy `bool()` here would instead read
         * a typo as "off", disabling probing on a config the desktop client accepts.
         */
        private val MTU_PROBE_OFF = setOf("false", "0", "no", "off")

        // ── imported-value ranges (Audit 2026-07-27, C6) ─────────────────────────
        // The SERVER-pushed mtu was already range-checked (QeliService.parseOk clamps to
        // 576..16638), the locally imported one was not: `qeli://…?mtu=99999`, or a
        // hand-written `mtu = 40`, went straight through to VpnService.Builder.setMtu, where
        // establish() fails and the retry loop reconnects forever with an opaque error. An
        // out-of-range padding_max is the same class of bug one layer down — every data
        // record then exceeds the shared Rust record-size limit and the peer drops it. Same ranges
        // as the Rust client (qeli/src/config/client.rs) and the C# port.
        /**
         * Upper bound for both reconnect delays, in seconds (one day).
         *
         * Shared with the C# client, where it is not a matter of taste: that port's reconnect
         * loop waits via `WaitHandle.WaitOne(Int)`, so a delay past ~24.8 days truncates on the
         * cast and can land negative, throwing and killing the loop. Here the delay is a Long
         * all the way down, but a profile is portable — one bound, one behaviour.
         */
        const val RECONNECT_DELAY_SECS_MAX = 86_400L

        const val MTU_MIN = 576
        /** Derived, in Rust, from the record format (protocol/packet.rs MAX_TUNNEL_MTU): a record holds nonce + counter + payload + padding-length + tag and must fit MAX_RECORD_SIZE, so anything larger the PEER REJECTS. Mirrored here as a literal; the four ports and the two UIs must all carry the same number, because raising it in one place only is worse than not raising it — see Audit 2026-08-01 §1. */
        const val MTU_MAX = 16638
        private const val PADDING_CEILING = 1400   // the per-packet pad_cap wire ceiling

        /** 0 (auto) or a plausible tunnel MTU. */
        fun mtuInRange(mtu: Int): Boolean = mtu == 0 || mtu in MTU_MIN..MTU_MAX

        /** Explicit TUN MTU from a config FILE (flat-INI); 0 = auto. REJECTS, like
         *  the Rust `from_ini` and the C# `CheckedMtu`: a bad value in a file the user wrote
         *  by hand is a mistake worth surfacing at import (every import path already reports
         *  the message), not something to silently rewrite behind their back. */
        private fun checkedMtu(mtu: Int): Int =
            if (mtuInRange(mtu)) mtu
            else throw IllegalArgumentException(
                "invalid mtu $mtu — expected 0 (auto) or $MTU_MIN..$MTU_MAX"
            )

        /** Same range for a `qeli://` LINK, but falling back to auto instead of throwing —
         *  mirrors the Rust link importer, which is infallible and only warns. A scanned or
         *  pasted link must still yield a usable profile; the mtu is the one thing in it the
         *  server re-pushes anyway. */
        private fun linkMtuOrAuto(mtu: Int): Int {
            if (mtuInRange(mtu)) return mtu
            warn("qeli:// link mtu $mtu is out of range (expected 0 or $MTU_MIN..$MTU_MAX) — using auto")
            return 0
        }

        /** Clamp imported padding bounds to 0..[PADDING_CEILING] and restore min <= max.
         *  Clamped rather than rejected: unlike mtu these are pure obfuscation knobs, so
         *  narrowing them costs the user nothing, while an oversized max breaks every
         *  packet. */
        private fun checkedPadding(min: Int, max: Int): Pair<Int, Int> {
            val lo = min.coerceIn(0, PADDING_CEILING)
            return lo to max.coerceIn(lo, PADDING_CEILING)
        }

        /** Warn without dragging `android.util.Log` into the JVM unit tests, where the
         *  android.jar stub throws "not mocked" and would fail the link-conformance run
         *  the moment a fixture carries an out-of-range value. */
        private fun warn(msg: String) {
            try { android.util.Log.w("VpnConfig", msg) } catch (_: Throwable) { /* off-device */ }
        }

        /**
         * Parse a profile config, detecting the format by content: a qeli:// share
         * link, or the flat-INI the app stores. A leading `{` is recognised only to
         * name the retired JSON format — see [jsonRetired].
         */
        fun parse(text: String): VpnConfig =
            when {
                // A raw qeli:// share link — parity with the C# VpnConfig.Parse. Callers
                // like pingActive/probe pass stored p.text (normally already INI), but a
                // qeli:// here would otherwise fall into fromIni and fail "missing [qeli]".
                text.trimStart().startsWith("qeli://") -> fromQeliUri(text.trim())
                text.trimStart().startsWith("{") -> throw IllegalArgumentException(jsonRetired)
                else -> fromIni(text)
            }

        /**
         * JSON is RETIRED, and detected only so the message can say so.
         *
         * It was the original config format and stopped being written years ago; INI
         * replaced it and every tool emits INI. What remained was a second, entirely
         * parallel parser per client — with its own defaults, its own leniency and its
         * own bugs. It kept accruing findings the INI path had already fixed (numbers
         * silently defaulting, unknown keys dropped, types coerced) because hardening it
         * meant doing every fix twice, in four languages, for a format nobody produces.
         *
         * Letting `{…}` fall through to fromIni instead would "work" but report a
         * meaningless "missing [qeli]". Someone opening a genuinely old file deserves to
         * be told what happened and what to do. (Retired 2026-08-02.)
         */
        const val jsonRetired: String =
            "this is a JSON profile, a format qeli no longer reads — export the profile " +
                "again from the server panel, or use its qeli:// link, to get the current " +
                "INI format"

        /**
         * Parse the flat-INI `[qeli]` client config (mirrors the Rust
         * ClientConfig::from_ini). Only connection essentials live in the file;
         * everything else is defaulted and overwritten by the server at
         * handshake. `dns`/`mtu` are optional app extras.
         */
        fun fromIni(text: String): VpnConfig {
            val dupKeys = mutableListOf<String>()
            val ini = parseIni(text, dupKeys)
            val q = ini["qeli"] ?: throw IllegalArgumentException("config: missing [qeli] section")
            val log = ini["logging"]
            val server = q["server"]?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("[qeli] missing required key 'server' (host:port)")
            val ci = server.lastIndexOf(':')
            require(ci > 0) { "'server' must be host:port, got '$server'" }
            val host = server.substring(0, ci)
            require(host.isNotEmpty()) { "'server' has empty host" }
            val port = server.substring(ci + 1).toIntOrNull()
                ?: throw IllegalArgumentException("'server' has invalid port: '$server'")
            // Accepts the same spellings as the Rust client's `bool_or`. An unrecognised value
            // is RECORDED (see `unparsedBooleanKeys`) and falls back to the caller's default,
            // rather than silently reading as `false`.
            val badNums = mutableListOf<String>()
            val badBools = mutableListOf<String>()
            fun boolAt(key: String, default: Boolean): Boolean {
                val raw = q[key]?.trim()?.lowercase() ?: return default
                return when (raw) {
                    "true", "1", "yes", "on" -> true
                    "false", "0", "no", "off" -> false
                    else -> { badBools.add(key); default }
                }
            }
            // Routing: full-tunnel by default on phones (a VPN should carry ALL traffic);
            // `gateway = false` opts into split-tunnel (only the tunnel subnet + pushed
            // routes). Mirrors the Rust client's `gateway` key — the only way to pick
            // split-tunnel via INI (there is no UI toggle).
            val fullTunnel = boolAt("gateway", true)
            // DNS: `dns = <ip,ip>` is the Android resolver list, but the SAME key is a MODE in
            // the Rust/router client (`off` / `tunnel` / `system`, see config/client.rs).
            //
            // Legacy mobile profiles used the same key for both meanings. The mode is now kept
            // separately and honoured at connect time; writers emit resolver lists through the
            // canonical `dns_servers` key.
            // (Audit 2026-08-02, §3.)
            val dnsRaw = q["dns"]?.trim()
            val dnsModeParsed = dnsRaw?.lowercase()?.takeIf { it in setOf("off", "tunnel", "system") }
            val canonicalDns = q["dns_servers"]?.trim()?.takeIf { it.isNotEmpty() }
            val dns = when {
                canonicalDns != null -> canonicalDns.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                dnsRaw.isNullOrEmpty() || dnsModeParsed != null -> null
                else -> dnsRaw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            }
            // Padding bounds are CLAMPED, not rejected — see [checkedPadding]. (C6) That is
            // about a number out of range; a value that is not a number at all is a typo, and
            // falling back to the default in silence is the same failure the boolean handling
            // already fixed. `server`'s port has always thrown here, so this closes the rest.
            // (Audit 2026-08-01, §P2.)
            val pad = checkedPadding(
                numAt("padding_min", 0, badNums, q),
                numAt("padding_max", 255, badNums, q)
            )
            return VpnConfig(
                serverAddress = host,
                port = port,
                protocol = q["proto"]?.ifBlank { null } ?: "tcp",
                connectionTimeoutSecs = longAt("timeout", 30L, badNums, q),
                reconnectEnabled = boolAt("reconnect", true),
                reconnectMaxRetries = numAt("reconnect_retries", -1, badNums, q),
                // Bounded to a day, matching the C# client. Unbounded, `reconnect_base_delay`
                // multiplied by 1000 in QeliService could overflow Long outright, and even
                // short of that the value is not a backoff policy any more — the desktop port
                // hits a harder cliff (its wait takes an Int), so one bound for both keeps a
                // shared profile behaving the same on every client.
                reconnectBaseDelaySecs =
                    rangedLong("reconnect_base_delay", 1L, 1L, RECONNECT_DELAY_SECS_MAX, badNums, q),
                reconnectMaxDelaySecs =
                    rangedLong("reconnect_max_delay", 60L, 1L, RECONNECT_DELAY_SECS_MAX, badNums, q),
                username = q["user"]?.ifBlank { null } ?: "client",
                password = q["pass"] ?: "",
                serverPublicKeyHex = q["key"]?.takeIf { it.isNotEmpty() },
                // H-1: on by default; needs a pinned key. `bind_static = false` for TOFU.
                bindStaticToSession = boolAt("bind_static", true),
                allowUnpinnedTofu = boolAt("allow_unpinned_tofu", false),
                routingMode = if (fullTunnel) "full-tunnel" else "split-tunnel",
                addDefaultGateway = fullTunnel,
                killSwitch = boolAt("kill_switch", false),
                wireMode = q["mode"]?.ifBlank { null } ?: "fake-tls",
                sni = q["sni"]?.takeIf { it.isNotEmpty() },
                realityShortId = q["reality_sid"]?.takeIf { it.isNotEmpty() },
                obfsKey = q["obfs_key"] ?: "",
                obfsFronting = q["front"]?.ifBlank { null } ?: "websocket",
                // F2: AmneziaWG junk. `awg = true` + jc/jmin/jmax (caps applied at use).
                awgEnabled = boolAt("awg", false),
                awgJc = numAt("jc", 0, badNums, q),
                awgJmin = numAt("jmin", 40, badNums, q),
                awgJmax = numAt("jmax", 300, badNums, q),
                quicEnabled = boolAt("quic", false),
                routeLocalNetworks = boolAt("route_local", false),
                allowIpv6Leak = boolAt("allow_ipv6_leak", false),
                allowLan = boolAt("allow_lan", false),
                // Explicit per-CIDR routing (comma-separated). exclude carves subnets OUT of
                // the tunnel (VpnService.excludeRoute, API 33+); include forces subnets IN.
                includeRoutes = q["include"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
                excludeRoutes = q["exclude"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
                dnsServers = if (dns.isNullOrEmpty()) emptyList() else dns,
                dnsMode = dnsModeParsed ?: "tunnel",
                // 0 = auto (use server-pushed MTU). Range-checked: see [checkedMtu].
                mtu = checkedMtu(numAt("mtu", 0, badNums, q)),
                // Same false-set as the Rust `bool_or` and the iOS client. The old test
                // (`!= "false" && != "0"`) read `mtu_probe = off` / `no` as ON — the exact
                // opposite of what the user wrote, and of what the desktop client does.
                // Through boolAt like every other boolean: the old "anything not in the
                // off-set is ON" reading meant `mtu_probe = ture` silently enabled probing
                // and was never recorded as a typo. (Audit 2026-07-31.)
                mtuProbe = boolAt("mtu_probe", true),
                // Per-app split tunnel (Android extra). Kept RAW, not coerced: [validate]
                // refuses an unknown value. Coercing here silently turned `apps_mode = includ`
                // into "all" — the WIDEST setting — so a typo broadened the tunnel to every
                // app instead of failing. A missing key is still "all". (Audit 2026-08-02, §10.)
                appsMode = q["apps_mode"]?.trim()?.lowercase() ?: "all",
                apps = q["apps"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
                // Local overrides for the normally server-pushed knobs. Key names match iOS.
                paddingEnabled = boolAt("padding", true),
                paddingMin = pad.first,
                paddingMax = pad.second,
                heartbeatEnabled = boolAt("heartbeat", true),
                // Range-checked, matching the C# reader. Unbounded, `heartbeat_interval = -1`
                // parsed cleanly and then disabled the heartbeat entirely while `heartbeat =
                // true` still claimed it was on — a keepalive that silently is not one. The
                // jitter floor is 0 (no jitter is a valid choice); the interval's is 1.
                heartbeatIntervalMs =
                    rangedLong("heartbeat_interval", 15000L, 1L, Long.MAX_VALUE, badNums, q),
                heartbeatDataSize = rangedNum("heartbeat_size", 16, 0, Int.MAX_VALUE, badNums, q),
                heartbeatJitterMs =
                    rangedLong("heartbeat_jitter", 2000L, 0L, Long.MAX_VALUE, badNums, q),
                shapingEnabled = boolAt("shaping", false),
                // Same floors as the C# reader: every one of these is a duration or a size, so
                // zero or negative is not a setting but a value nothing can act on.
                shapingGapMeanMs =
                    rangedLong("shaping_gap_mean", 700L, 1L, Long.MAX_VALUE, badNums, q),
                shapingGapMinMs =
                    rangedLong("shaping_gap_min", 40L, 1L, Long.MAX_VALUE, badNums, q),
                shapingGapMaxMs =
                    rangedLong("shaping_gap_max", 6000L, 1L, Long.MAX_VALUE, badNums, q),
                shapingBudgetBytesPerSec =
                    rangedNum("shaping_budget", 16384, 1, Int.MAX_VALUE, badNums, q),
                shapingMinSize = rangedNum("shaping_min_size", 64, 1, Int.MAX_VALUE, badNums, q),
                shapingMaxSize = rangedNum("shaping_max_size", 1024, 1, Int.MAX_VALUE, badNums, q),
                shapingStealth = boolAt("shaping_stealth", false),
                shapingStealthRateMbps =
                    rangedNum("shaping_stealth_mbps", 2, 1, Int.MAX_VALUE, badNums, q),
                // Carried through untouched so re-saving a desktop config keeps its logging.
                loggingLevel = log?.get("level")?.takeIf { it.isNotEmpty() },
                loggingFile = log?.get("file")?.takeIf { it.isNotEmpty() },
                loggingTimeFormat = log?.get("time_format")?.takeIf { it.isNotEmpty() },
                unparsedBooleanKeys = badBools.toList(),
                duplicateKeys = dupKeys.toList(),
                unparsedNumericKeys = badNums.toList(),
                unknownKeys = q.keys.filter { it.lowercase() !in KNOWN_INI_KEYS }.sorted(),
                // Accepted but not modelled — kept so saving does not delete them.
                carriedKeys = q.filterKeys { it.lowercase() in CARRIED_INI_KEYS }
            )
        }

        /** Minimal line-oriented INI parser (mirrors qeli/src/config/format.rs):
         *  `[section]` / `[kind:instance]`, `key = value`, full-line `;`/`#`
         *  comments, surrounding double-quotes stripped. */
        /**
         * Keys this port ACCEPTS but does not model — read into [carriedKeys] and written
         * back verbatim, so opening and saving a CLI profile does not strip them.
         *
         * They are on the allowlist because a desktop profile carrying them must open here;
         * they are in THIS list because accepting a key without keeping it is how the
         * open-and-save round trip silently deleted hooks and security settings.
         * (Audit 2026-08-02, §7.)
         *
         * Declared BEFORE [KNOWN_INI_KEYS], which folds it in — a companion object's property
         * initializers run in declaration order, so the other way round leaves it null.
         */
        /**
         * Largest `user` + `:` + `pass`, in UTF-8 bytes, that still fits one AUTH datagram.
         *
         * The AUTH plaintext is `proof(32)` + the optional `[0x00 device_id(16)]` prefix +
         * `user:pass`, and the whole thing rides in one unfragmented datagram — so the
         * credentials are what decides whether it survives a path that drops IP fragments.
         * UI-side mirror of Rust `udp_frag::MAX_CHUNK - AUTH_OVERHEAD`: 1280-byte IPv6
         * minimum MTU minus IPv6/UDP/obfs/QUIC/reserve/fragment headers and the 49-byte AUTH
         * envelope. This is a validation scalar, not a Kotlin wire implementation.
         */
        const val AUTH_CRED_BUDGET = 1114

        /**
         * True for a bare IPv4 or IPv6 literal.
         *
         * Deliberately hand-rolled rather than `InetAddress.getByName`, which performs a DNS
         * LOOKUP for anything that is not a literal — on the main thread, during config
         * validation, for a value that is by definition not resolvable yet.
         */
        private fun isIpLiteral(s: String): Boolean {
            val v = s.trim()
            if (v.isEmpty()) return false
            if (':' in v) {
                // IPv6, structurally — not just "has colons and legal characters".
                //
                // The first version of this check accepted anything made of hex digits and
                // colons with at least two colons, which passes `::::`, `1::2::3` and
                // `abcd:::`. Those are not addresses: the config validated and the failure
                // surfaced later, when the TUN was built and the DNS entry was quietly not
                // added. A structural check keeps the error where the value was written.
                // Three or more colons in a row are never legal, and a NON-OVERLAPPING search
                // for `::` does not see them: in `abcd:::` it matches one pair and resumes past
                // it, leaving a lone colon it never counts. Reject the run directly.
                if (":::" in v) return false
                // A single leading or trailing colon is only legal as half of a `::`.
                if (v.startsWith(":") && !v.startsWith("::")) return false
                if (v.endsWith(":") && !v.endsWith("::")) return false
                // At most one `::`, and it is the only place a run of groups may be omitted.
                if (Regex("::").findAll(v).count() > 1) return false
                val compressed = v.contains("::")
                val groups = v.split(':')

                // A trailing IPv4 form (`::ffff:1.2.3.4`) is legal only in the LAST group, and
                // it stands for TWO 16-bit groups, not one. Counting it as one both rejected
                // the valid `1:2:3:4:5:6:192.0.2.1` (seven groups by that arithmetic, eight in
                // reality) and accepted the over-long `1:2:3:4:5:6::192.0.2.1`.
                var groupCount = 0
                for ((i, g) in groups.withIndex()) {
                    if (g.isEmpty()) continue           // one side of `::`, or a leading/trailing pair
                    if ('.' in g) {
                        if (i != groups.lastIndex) return false
                        val quads = g.split('.')
                        if (quads.size != 4 || !quads.all { q ->
                                q.isNotEmpty() && q.length <= 3 && q.all(Char::isDigit) && q.toInt() <= 255
                            }
                        ) return false
                        groupCount += 2
                        continue
                    }
                    if (g.length > 4 || !g.all { it.isDigit() || it in "abcdefABCDEF" }) return false
                    groupCount++
                }
                // Exactly 8 without `::`; fewer than 8 with it — `::` must stand for at least
                // one omitted group, so a "compressed" address that already has 8 is malformed.
                return if (compressed) groupCount < 8 else groupCount == 8
            }
            val parts = v.split('.')
            return parts.size == 4 && parts.all { p ->
                p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255
            }
        }

        /** Real cross-client keys Android must reject by name instead of silently carrying. */
        private val UNSUPPORTED_INI_KEYS: Map<String, String> = emptyMap()

        private val CARRIED_INI_KEYS = setOf(
            // Not edited by the Android model. Some are foreign platform/lifecycle fields;
            // transport-owned socket settings are preserved here and consumed by Rust after
            // [toTransportCoreIni] crosses the JNI boundary.
            // NB: `allow_unpinned_tofu` used to live here — carried through saves but read by
            // nothing. It is a modelled field now (see VpnConfig.allowUnpinnedTofu), so it
            // must NOT also be carried or toIni would emit it twice. (Audit 2026-08-04, M-20.)
            "autostart", "dev", "dev_attach", "dev_node", "exit_node", "forward",
            "gateway_nat", "keepalive", "lan_subnet", "post_down", "post_up", "tcp_nodelay",
            "local", "lport", "metric", "name", "persist_tun", "route_file",
            // Password sources remain headless-only. Buffer values, when present, reach the
            // common carrier implementation even though Android has no editor control for them.
            "password_command", "password_file", "recv_buffer_size", "send_buffer_size",
        )

        /**
         * Every `[qeli]` key any qeli client understands — the union across the four ports,
         * NOT just the ones this one reads.
         *
         * The distinction is the whole point. A key this port ignores is not necessarily a
         * typo: `keepalive`, `post_up`, `exit_node` and friends are real settings the Rust
         * client acts on, and a desktop profile carrying them must still open here. Only a
         * name NOTHING understands is a typo — a misspelled `gatway = true` silently leaving
         * the tunnel split is the failure this catches. (Audit 2026-08-01, §14.)
         *
         * Kept honest by `everything toIni writes is accepted back` in the test suite.
         */
        private val KNOWN_INI_KEYS = setOf(
            // Read by this port.
            "allow_ipv6_leak", "allow_unpinned_tofu", "awg", "bind_static",
            "dns", "dns_servers", "exclude",
            "front", "gateway", "heartbeat", "heartbeat_interval", "kill_switch",
            "heartbeat_jitter", "heartbeat_size", "include", "jc", "jmax", "jmin", "key",
            "mode", "mtu", "mtu_probe",
            "obfs_key", "padding", "padding_max", "padding_min", "pass",
            "proto", "quic", "reality_sid", "reconnect", "reconnect_base_delay",
            "reconnect_max_delay", "reconnect_retries", "route_local", "server",
            "shaping", "shaping_budget", "shaping_gap_max", "shaping_gap_mean",
            "shaping_gap_min", "shaping_max_size", "shaping_min_size", "shaping_stealth",
            "shaping_stealth_mbps", "sni", "timeout", "user",
            // Per-app tunnelling, written by THIS port. `apps` is emitted once per selected
            // package, and the round-trip guard walks single-valued keys, so a repeated key
            // slipped past it — and an exported profile then failed to re-import here with
            // "unknown key(s): apps, apps_mode".
            "apps", "apps_mode",
            // Also written by this port, and missed for the same reason in reverse: `toIni`
            // emits it only when it is ON (`if (allowLan)`), so a round-trip built from a
            // default config never produced the line and the guard never saw it. A profile
            // with LAN bypass enabled failed to re-import into the app that wrote it.
            // (Audit 2026-08-02, §2.)
            "allow_lan",
        ) + CARRIED_INI_KEYS

        /**
         * An INI integer, recording the key when the value is present but not a number.
         *
         * Absent keeps the default silently — that is what a default is for. A value that is
         * THERE and unreadable is a typo, and substituting the default without a word is the
         * same failure mode `boolAt` exists to prevent. (Audit 2026-08-01, §P2.)
         */
        /** [numAt] for a Long-valued key. */
        private fun longAt(
            key: String,
            default: Long,
            bad: MutableList<String>,
            q: Map<String, String>
        ): Long {
            val raw = q[key]?.trim() ?: return default
            if (raw.isEmpty()) return default
            return raw.toLongOrNull() ?: run { bad.add(key); default }
        }

        /**
         * [longAt] with a range, recording out-of-range exactly like unreadable.
         *
         * Falling back to the default on an out-of-range value is not a clamp — a clamp pins to
         * the nearest bound, this jumps somewhere else entirely — so it has to be reported, or
         * the setting the user wrote is silently replaced by an unrelated one. Mirrors the C#
         * `RangedLong`.
         */
        private fun rangedLong(
            key: String,
            default: Long,
            lo: Long,
            hi: Long,
            bad: MutableList<String>,
            q: Map<String, String>
        ): Long {
            val v = longAt(key, default, bad, q)
            if (v in lo..hi) return v
            if (!q[key].isNullOrBlank() && key !in bad) bad.add(key)
            return default
        }

        private fun numAt(
            key: String,
            default: Int,
            bad: MutableList<String>,
            q: Map<String, String>
        ): Int {
            val raw = q[key]?.trim() ?: return default
            if (raw.isEmpty()) return default
            return raw.toIntOrNull() ?: run { bad.add(key); default }
        }

        /** [numAt] with a range. Int counterpart of [rangedLong]; same reasoning. */
        private fun rangedNum(
            key: String,
            default: Int,
            lo: Int,
            hi: Int,
            bad: MutableList<String>,
            q: Map<String, String>
        ): Int {
            val v = numAt(key, default, bad, q)
            if (v in lo..hi) return v
            if (!q[key].isNullOrBlank() && key !in bad) bad.add(key)
            return default
        }

        private fun parseIni(
            text: String,
            duplicates: MutableList<String>? = null
        ): Map<String, MutableMap<String, String>> {
            val out = LinkedHashMap<String, MutableMap<String, String>>()
            var cur: MutableMap<String, String>? = null
            var curName = ""
            for (raw in text.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith(";") || line.startsWith("#")) continue
                if (line.startsWith("[") && line.endsWith("]")) {
                    val name = line.substring(1, line.length - 1).trim().substringBefore(':').trim()
                    cur = out.getOrPut(name) { LinkedHashMap() }
                    curName = name
                } else {
                    val eq = line.indexOf('=')
                    if (eq < 0) continue
                    val k = line.substring(0, eq).trim()
                    var v = line.substring(eq + 1).trim()
                    if (v.length >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length - 1)
                    if (k.isEmpty()) continue
                    // Keep LAST-wins, so a file that never had a duplicate parses exactly as it
                    // did before, and record the ambiguity for validate() to refuse.
                    val qualified = "$curName.$k"
                    if (cur?.put(k, v) != null && duplicates?.contains(qualified) == false) {
                        duplicates.add(qualified)
                    }
                }
            }
            return out
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
            // `toIntOrNull` accepts ANY Int — 0, 99999 and negatives all parsed fine and
            // produced a profile that only failed later with an opaque socket error. Swift
            // and C# already range-checked here; Kotlin and Rust did not. Divergence found
            // by the conformance fixtures (conformance/qeli-links.json).
            require(port in 1..65535) { "port $port out of range in qeli:// link (1..65535)" }

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
            // Parsed here so a link emitted by toQeliUri survives a round trip. `mtu` was
            // already being EMITTED but had no case below, so importing dropped it. (C-12)
            var linkMtu = 0; var linkMtuProbe = true; var bindStatic = true
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
                    // Out-of-range → fall back to auto rather than importing a value the
                    // client can't apply, and SAY SO (a silently dropped mtu looks like the
                    // link never carried one). Matches the Rust from_link fallback; iOS used
                    // to reject the whole link and this app used to import it verbatim, so
                    // `qeli://…?mtu=99999` reached VpnService.Builder.setMtu and turned into
                    // an endless establish-fail → reconnect loop. (Audit 2026-07-27, C6)
                    "mtu" -> linkMtu = linkMtuOrAuto(v.toIntOrNull() ?: 0)
                    // Legacy tolerance only — this app stopped EMITTING these in 0.7.13
                    // (see toQeliUri). Kept so links it issued earlier still import the way
                    // they were shared; no other implementation carries them.
                    "mtu_probe" -> linkMtuProbe = !(v == "0" || v.equals("false", ignoreCase = true))
                    "bind_static" -> bindStatic = !(v == "0" || v.equals("false", ignoreCase = true))
                    // forward-compatible: ignore unknown params
                }
            }

            // Alias convenience: `mode=udp-quic` / `udp-obfs` fold transport+QUIC into the
            // wire mode. Split it back into proto + wire mode + quic — the same mapping the
            // Rust link parser applies (config/share.rs). Android was the only client that
            // did NOT expand these: it kept the alias as the literal wire mode, which no
            // handshake matches, so such a link imported cleanly and then never connected.
            // Applied AFTER the loop because `proto` may come later in the query.
            when (mode) {
                "udp-quic" -> { proto = "udp"; mode = "fake-tls"; quic = true }
                "udp-obfs" -> { proto = "udp"; mode = "obfs" }
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
                realityShortId = rsid,
                mtu = linkMtu,
                mtuProbe = linkMtuProbe,
                bindStaticToSession = bindStatic
            ).also {
                // A link is untrusted input: validate at the boundary so a forged newline
                // in user/pass/sni can never reach the profile store (and from there the
                // next toIni). Same gate the iOS client applies to an imported link.
                it.validate()
            }
        }

        /** Percent-encode UTF-8 bytes except RFC 3986 unreserved (mirrors C# Uri.EscapeDataString). */
        private fun pctEncode(s: String): String {
            val sb = StringBuilder(s.length)
            for (b in s.toByteArray(Charsets.UTF_8)) {
                val c = (b.toInt() and 0xFF).toChar()
                if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_' || c == '.' || c == '~')
                    sb.append(c)
                else sb.append('%').append("%02X".format(b.toInt() and 0xFF))
            }
            return sb.toString()
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

    }
}
