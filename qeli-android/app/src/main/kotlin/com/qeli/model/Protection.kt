package com.qeli.model

/**
 * What the SERVER pushed for this session, as the client applied it.
 *
 * Only knowable after the handshake, so it lives beside the tunnel rather than in the
 * profile. Two deliberate limits:
 *
 * * [routes] is CAPPED at [ROUTE_SAMPLE] entries with [routeCount] carrying the real total.
 *   A server may advertise an arbitrarily long list — an operator pushing a country-sized
 *   prefix set is a normal thing to do — and the detail sheet builds a view per row with no
 *   recycling. Capping at the source keeps both the snapshot and the sheet bounded instead
 *   of hoping the list stays short.
 * * the session token is NOT here and must never be: it is the credential that authorises a
 *   bonded stream to join this session.
 */
data class PushedFacts(
    val routes: List<String> = emptyList(),
    val routeCount: Int = 0,

    /**
     * How many of [routeCount] the builder actually took, or `-1` before the TUN exists.
     *
     * The card used to show [routeCount] — the number the server SENT — as though it were the
     * number in force. Those differ whenever a route is malformed or the builder rejects it:
     * `addRoute` throws, the failure is logged, and the tunnel comes up carrying less than the
     * card claims. That is the one direction a protection card must never be wrong in, so the
     * installed count is tracked separately and published only once `establish()` has returned.
     *
     * `-1` is deliberately not `0`: "not installed yet" and "installed none" look identical
     * otherwise, and the first is a normal moment during connect while the second is a fault.
     */
    val routesInstalled: Int = -1,
    val multipathAdaptive: Boolean = false,
    val paddingEnabled: Boolean = false,
    val paddingMin: Int = 0,
    val paddingMax: Int = 0,
    val heartbeatEnabled: Boolean = false,
    val heartbeatIntervalMs: Long = 0,
    val shapingEnabled: Boolean = false,
) {
    companion object {
        /** How many pushed routes the UI ever holds or renders. */
        const val ROUTE_SAMPLE = 6
    }
}

/** How much of the device's traffic the tunnel carries. */
enum class ProtectionScope {
    /** Every app, every route. */
    ALL,

    /** Only the apps the user picked (`apps_mode = include`). */
    ONLY_SELECTED,

    /** Every app except the ones the user picked (`apps_mode = exclude`). */
    ALL_EXCEPT,

    /** Split tunnel: only the configured/pushed routes go through the VPN. */
    SPLIT_ROUTES,
}

/** Something that narrows what the tunnel protects, worth telling the user about. */
enum class ProtectionWarning {
    /** `allow_lan` — RFC1918 is carved out, so LAN traffic is not in the tunnel. */
    LAN_OUTSIDE,

    /** `allow_ipv4_leak` — native IPv4 may bypass an IPv6-only full tunnel. */
    IPV4_OUTSIDE,

    /** `allow_ipv6_leak` — native IPv6 may bypass an IPv4-only full tunnel. */
    IPV6_OUTSIDE,

    /** Explicit `exclude` routes. */
    EXCLUDED_ROUTES,

    /** No pinned server key: the first connection trusts whoever answers (TOFU). */
    NO_PINNED_KEY,
}

/**
 * What a profile actually protects, derived from the profile alone.
 *
 * This backs a card that makes SECURITY CLAIMS, so the rule is: state only what the config
 * guarantees, and give anything that narrows the tunnel its own line rather than folding it
 * into a reassuring headline. A card that says "all traffic is protected" when it isn't is
 * worse than no card at all.
 *
 * Deliberately a pure function of [VpnConfig] with enum outputs — no Context, no string
 * resources — so the decisions are unit-testable and the wording stays localizable.
 * Runtime facts the profile cannot know (which resolver the server actually pushed, the
 * negotiated MTU, whether the system lockdown is on) are NOT guessed here; they arrive with
 * the tunnel snapshot.
 */
data class ProtectionSummary(
    val scope: ProtectionScope,
    /** Size of the per-app selection; meaningful for ONLY_SELECTED / ALL_EXCEPT. */
    val appCount: Int,
    val excludedRouteCount: Int,
    /** X25519 + ML-KEM-768. True for every wire mode except `plain`. */
    val postQuantum: Boolean,
    val dnsThroughTunnel: Boolean,
    val keyPinned: Boolean,
    val warnings: List<ProtectionWarning>,
) {
    /**
     * True only when nothing narrows what the tunnel carries — the one condition under
     * which the UI may claim "all traffic is protected".
     *
     * [ProtectionWarning.NO_PINNED_KEY] is excluded on purpose: pinning decides WHO the
     * client is willing to talk to, not HOW MUCH traffic it carries. It still gets its own
     * warning line.
     */
    val carriesEverything: Boolean
        get() = scope == ProtectionScope.ALL &&
            warnings.none { it != ProtectionWarning.NO_PINNED_KEY }

    companion object {
        /**
         * @param globalAllowLan the app-wide Settings toggle. It MUST be passed, because the
         * tunnel carves the private ranges out on `config.allowLan || globalAllowLan`
         * (QeliService) — reading only the profile field made the card claim "all traffic is
         * protected" while RFC1918, link-local and multicast went past the VPN. A card that
         * makes security claims has to be wrong in the SAFE direction, and this was wrong in
         * the other one. (Audit 2026-08-02, §6.)
         */
        @JvmOverloads
        fun of(config: VpnConfig, globalAllowLan: Boolean = false): ProtectionSummary {
            val apps = config.apps.size
            val scope = when {
                config.appsMode.equals("include", ignoreCase = true) -> ProtectionScope.ONLY_SELECTED
                config.appsMode.equals("exclude", ignoreCase = true) -> ProtectionScope.ALL_EXCEPT
                !config.isFullTunnel -> ProtectionScope.SPLIT_ROUTES
                else -> ProtectionScope.ALL
            }
            val warnings = buildList {
                // The compact strip can show only the first warning. Missing-family egress is
                // the broadest bypass, so keep both family escape hatches ahead of narrower
                // LAN/route exceptions.
                if (config.allowIpv4Leak) add(ProtectionWarning.IPV4_OUTSIDE)
                if (config.allowIpv6Leak) add(ProtectionWarning.IPV6_OUTSIDE)
                if (config.excludeRoutes.isNotEmpty()) add(ProtectionWarning.EXCLUDED_ROUTES)
                // allow_lan only carves routes out of a full-tunnel capture. In split mode it
                // must not imply that authenticated include/pushed routes were subtracted.
                if (config.isFullTunnel && (config.allowLan || globalAllowLan)) {
                    add(ProtectionWarning.LAN_OUTSIDE)
                }
                if (config.serverPublicKeyHex.isNullOrEmpty()) add(ProtectionWarning.NO_PINNED_KEY)
            }
            return ProtectionSummary(
                scope = scope,
                appCount = apps,
                excludedRouteCount = config.excludeRoutes.size,
                // Every mode runs the hybrid PQ ClientHello except `plain`, which uses a
                // raw X25519 exchange (QeliService: performHandshakePlain vs
                // performHandshake). obfs and reality-tls are transport wrappers around the
                // SAME PQ handshake, so they count as post-quantum.
                postQuantum = !config.wireMode.equals("plain", ignoreCase = true),
                // Explicit resolvers are reached through the tunnel; a full tunnel captures
                // DNS regardless. Anything narrower cannot be claimed from the profile
                // alone, so it is reported as system DNS until the snapshot says otherwise.
                dnsThroughTunnel = config.dnsServers.isNotEmpty() || config.isFullTunnel,
                keyPinned = !config.serverPublicKeyHex.isNullOrEmpty(),
                warnings = warnings,
            )
        }
    }
}

/**
 * Non-secret properties of the immutable configuration owned by the running VPN generation.
 *
 * The profile editor is intentionally usable while connected. UI code must therefore not
 * parse the currently saved profile when it describes the live connection: those edits do
 * not take effect until reconnect and may even refer to a different active profile. Keep the
 * password, session token and device identity out of this process-wide snapshot.
 */
data class LiveConnectionProperties(
    val serverAddress: String,
    val port: Int,
    val wireMode: String,
    val protocol: String,
    val quicEnabled: Boolean,
    val configuredMtu: Int,
    val reconnectEnabled: Boolean,
    val protection: ProtectionSummary,
) {
    val displayEndpoint: String
        get() = if (serverAddress.contains(':')) "[$serverAddress]:$port" else "$serverAddress:$port"

    companion object {
        fun of(config: VpnConfig, globalAllowLan: Boolean): LiveConnectionProperties =
            LiveConnectionProperties(
                serverAddress = config.serverAddress,
                port = config.port,
                wireMode = config.wireMode,
                protocol = config.protocol,
                quicEnabled = config.quicEnabled,
                configuredMtu = config.mtu,
                reconnectEnabled = config.reconnectEnabled,
                protection = ProtectionSummary.of(config, globalAllowLan),
            )
    }
}
