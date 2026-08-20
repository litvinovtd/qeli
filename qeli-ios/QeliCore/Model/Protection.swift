import Foundation

// `PushedFacts` used to live here. It moved to PushedFacts.swift: `TunnelSnapshot` carries
// it, and the widget target compiles TunnelSnapshot from an explicit file list, so keeping it
// next to `ProtectionSummary` — which is built from a `VPNConfig` — would pull the config
// model into an extension that needs none of it.

/// How much of the device's traffic the tunnel carries.
///
/// Structurally identical to the Android `ProtectionScope` so the two cards stay comparable
/// case for case, but **iOS only ever produces `.all` and `.splitRoutes`** — see
/// `.onlySelected` below. The unreachable cases are kept for that parity (and the UI keeps
/// strings for them), NOT because this platform can reach them.
enum ProtectionScope: Equatable, Sendable {
    /// Every app, every route.
    case all
    /// Only the apps the user picked (`apps_mode = include`).
    ///
    /// **Never produced on iOS.** Per-app rules need `NEAppRule`, which needs an MDM-managed
    /// configuration, so the selection is not in force and reporting it as the scope would
    /// confirm a restriction that does not exist. A profile carrying `apps_mode` gets
    /// `ProtectionWarning.perAppNotApplied` instead. Do not wire this back up without a
    /// managed configuration to back it. (Audit 2026-08-02, §7.)
    case onlySelected
    /// Every app except the ones the user picked (`apps_mode = exclude`).
    /// **Never produced on iOS**, for the same reason as `.onlySelected`.
    case allExcept
    /// Split tunnel: only the configured/pushed routes go through the VPN.
    case splitRoutes
}

/// Something that narrows what the tunnel protects, worth telling the user about.
enum ProtectionWarning: Equatable, Sendable {
    /// `allow_lan` — RFC1918 is carved out, so LAN traffic is not in the tunnel.
    case lanOutside
    /// `allow_ipv4_leak` — native IPv4 may bypass an IPv6-only full tunnel.
    case ipv4Outside
    /// `allow_ipv6_leak` — native IPv6 may bypass an IPv4-only full tunnel.
    case ipv6Outside
    /// Explicit `exclude` routes.
    case excludedRoutes
    /// No pinned server key: the first connection trusts whoever answers (TOFU).
    case noPinnedKey
    /// The profile carries `apps_mode`, but iOS cannot apply per-app rules without MDM
    /// (`NEAppRule` needs a managed configuration), so EVERY app goes through the tunnel
    /// regardless of the selection. (Audit 2026-08-02, §7.)
    case perAppNotApplied
}

extension VPNConfig {
    /// Release metadata resolves through DNS and may use either address family. Only an
    /// unqualified full capture can promise that an app-owned request enters this tunnel.
    func hasPrivateUpdatePath(globalAllowLAN: Bool = false) -> Bool {
        isFullTunnel
            && !allowIPv4Leak
            && !allowIPv6Leak
            && !allowLAN
            && !globalAllowLAN
            && excludeRoutes.isEmpty
    }
}

/// What a profile actually protects, derived from the profile alone.
///
/// Mirror of the Android `ProtectionSummary`, decision for decision — the two cards must
/// never disagree about the same profile.
///
/// This backs a card that makes SECURITY CLAIMS, so the rule is: state only what the config
/// guarantees, and give anything that narrows the tunnel its own line rather than folding it
/// into a reassuring headline. A card that says "all traffic is protected" when it isn't is
/// worse than no card at all.
///
/// Deliberately a pure function of `VPNConfig` with enum outputs — no view code, no
/// localized text — so the decisions are testable and the wording stays localizable.
/// Runtime facts the profile cannot know (which resolver the server actually pushed, the
/// negotiated MTU) are NOT guessed here; they arrive with the tunnel snapshot.
struct ProtectionSummary: Equatable, Sendable {
    let scope: ProtectionScope
    /// Size of the per-app selection; meaningful for `onlySelected` / `allExcept`.
    let appCount: Int
    let excludedRouteCount: Int
    /// X25519 + ML-KEM-768. True for every wire mode except `plain`.
    let postQuantum: Bool
    let dnsThroughTunnel: Bool
    let keyPinned: Bool
    let warnings: [ProtectionWarning]

    private init(
        scope: ProtectionScope,
        appCount: Int,
        excludedRouteCount: Int,
        postQuantum: Bool,
        dnsThroughTunnel: Bool,
        keyPinned: Bool,
        warnings: [ProtectionWarning]
    ) {
        self.scope = scope
        self.appCount = appCount
        self.excludedRouteCount = excludedRouteCount
        self.postQuantum = postQuantum
        self.dnsThroughTunnel = dnsThroughTunnel
        self.keyPinned = keyPinned
        self.warnings = warnings
    }

    /// True only when nothing narrows what the tunnel carries — the one condition under
    /// which the UI may claim "all traffic is protected".
    ///
    /// `noPinnedKey` is excluded on purpose: pinning decides WHO the client is willing to
    /// talk to, not HOW MUCH traffic it carries. It still gets its own warning line.
    /// `perAppNotApplied` is excluded for the opposite reason to `noPinnedKey`: an unapplied
    /// per-app selection does not narrow what the tunnel carries, it WIDENS it — every app
    /// goes through the VPN even though only some were picked. Counting it as a narrowing
    /// would make the card claim less protection than there is. (Audit 2026-08-02, §7.)
    var carriesEverything: Bool {
        scope == .all && warnings.allSatisfy { $0 == .noPinnedKey || $0 == .perAppNotApplied }
    }

    /// - Parameter globalAllowLAN: the app-wide "Allow local network access" setting.
    ///   `TunnelManager` and `QeliNativeTunnelEngine` both carve the private ranges out of a
    ///   full tunnel on `config.allowLAN || settings.allowLAN`, so the card reads the same pair.
    ///   It used to read only the profile field, and with the app-wide switch on it announced
    ///   "all traffic is protected" while RFC1918, link-local and multicast went past the
    ///   VPN — the card erring in the UNSAFE direction, which is the one thing it may never
    ///   do. Mirrors the same fix on Android. (Audit 2026-08-02, §13.)
    init(config: VPNConfig, globalAllowLAN: Bool = false) {
        // `apps_mode` is REPORTED, not applied, on this platform.
        //
        // Consumer iOS cannot install per-app rules: `NEAppRule` requires a managed
        // configuration, and `VPNConfig` says so itself. So a profile with
        // `apps_mode = include` does NOT leave the unselected apps outside — every app goes
        // through the tunnel. Mapping the mode straight onto the scope made the card confirm a
        // restriction that is not in force: the user reads "only the selected apps are
        // protected", arranges their traffic around that belief, and the truth is the
        // opposite. The scope now follows the ROUTES, which is what this platform actually
        // enforces, and the unapplied selection gets its own warning line instead of a
        // headline. (Audit 2026-08-02, §7.)
        let mode = config.appsMode.lowercased()
        let perAppRequested = mode == "include" || mode == "exclude"
        scope = config.isFullTunnel ? .all : .splitRoutes
        appCount = config.apps.count
        excludedRouteCount = config.excludeRoutes.count
        // Every mode runs the hybrid PQ ClientHello except `plain`, which uses a raw X25519
        // exchange. obfs and reality-tls are transport wrappers around the SAME PQ
        // handshake, so they count as post-quantum.
        postQuantum = config.wireMode.lowercased() != "plain"
        // Explicit resolvers are reached through the tunnel; a full tunnel captures DNS
        // regardless. Anything narrower cannot be claimed from the profile alone.
        dnsThroughTunnel = !config.dnsServers.isEmpty || config.isFullTunnel
        keyPinned = !(config.serverPublicKeyHex ?? "").isEmpty

        var found: [ProtectionWarning] = []
        // The compact strip renders only the first warning, so broad missing-family egress
        // must outrank narrower LAN and route exceptions.
        if config.allowIPv4Leak { found.append(.ipv4Outside) }
        if config.allowIPv6Leak { found.append(.ipv6Outside) }
        if !config.excludeRoutes.isEmpty { found.append(.excludedRoutes) }
        if config.isFullTunnel && (config.allowLAN || globalAllowLAN) {
            found.append(.lanOutside)
        }
        if (config.serverPublicKeyHex ?? "").isEmpty { found.append(.noPinnedKey) }
        // Deliberately a warning and NOT part of `carriesEverything`: an unapplied per-app
        // selection does not narrow the tunnel — it widens it beyond what the user asked for.
        // The card must say so without claiming the tunnel protects less than it does.
        if perAppRequested { found.append(.perAppNotApplied) }
        warnings = found
    }
}

extension LiveConnectionProperties {
    /// Build the persisted UI projection from the immutable PacketTunnel configuration.
    init(config: VPNConfig, globalAllowLAN: Bool) {
        let summary = ProtectionSummary(config: config, globalAllowLAN: globalAllowLAN)
        let liveScope: LiveProtectionScope
        switch summary.scope {
        case .all: liveScope = .all
        case .onlySelected: liveScope = .onlySelected
        case .allExcept: liveScope = .allExcept
        case .splitRoutes: liveScope = .splitRoutes
        }
        let liveWarnings = summary.warnings.map { warning -> LiveProtectionWarning in
            switch warning {
            case .lanOutside: return .lanOutside
            case .ipv4Outside: return .ipv4Outside
            case .ipv6Outside: return .ipv6Outside
            case .excludedRoutes: return .excludedRoutes
            case .noPinnedKey: return .noPinnedKey
            case .perAppNotApplied: return .perAppNotApplied
            }
        }
        self.init(
            serverAddress: config.serverAddress,
            port: config.port,
            wireMode: config.wireMode,
            protocolName: config.protocolName,
            quicEnabled: config.quicEnabled,
            configuredMTU: config.mtu,
            reconnectEnabled: config.reconnectEnabled,
            scope: liveScope,
            appCount: summary.appCount,
            excludedRouteCount: summary.excludedRouteCount,
            postQuantum: summary.postQuantum,
            dnsThroughTunnel: summary.dnsThroughTunnel,
            keyPinned: summary.keyPinned,
            warnings: liveWarnings
        )
    }
}

extension ProtectionSummary {
    /// Rehydrate the display model without consulting a profile edited after connect.
    init(live: LiveConnectionProperties) {
        let protectionScope: ProtectionScope
        switch live.scope {
        case .all: protectionScope = .all
        case .onlySelected: protectionScope = .onlySelected
        case .allExcept: protectionScope = .allExcept
        case .splitRoutes: protectionScope = .splitRoutes
        }
        let protectionWarnings = live.warnings.map { warning -> ProtectionWarning in
            switch warning {
            case .lanOutside: return .lanOutside
            case .ipv4Outside: return .ipv4Outside
            case .ipv6Outside: return .ipv6Outside
            case .excludedRoutes: return .excludedRoutes
            case .noPinnedKey: return .noPinnedKey
            case .perAppNotApplied: return .perAppNotApplied
            }
        }
        self.init(
            scope: protectionScope,
            appCount: live.appCount,
            excludedRouteCount: live.excludedRouteCount,
            postQuantum: live.postQuantum,
            dnsThroughTunnel: live.dnsThroughTunnel,
            keyPinned: live.keyPinned,
            warnings: protectionWarnings
        )
    }
}
