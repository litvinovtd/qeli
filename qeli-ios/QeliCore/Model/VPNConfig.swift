import Foundation

struct VPNConfig: Codable, Equatable, Sendable {
    /// Keys whose boolean value was neither true-ish nor false-ish — `gateway = ture`.
    ///
    /// Carried instead of being resolved at parse time because the ORIGINAL STRING IS LOST once
    /// a `Bool` is produced, so nothing downstream could tell a typo from a deliberate `false`.
    /// That mattered: every unknown value read as `false`, so `bind_static = ture` silently
    /// dropped the static-key binding and `gateway = ture` silently turned a full tunnel into a
    /// split one — with no message anywhere.
    ///
    /// Parsing still SUCCEEDS (an editor must be able to open a bad profile to fix it);
    /// ``validate()`` is what refuses. (Audit 2026-07-31.)
    var unparsedBooleanKeys: [String] = []

    /// Rust reports duplicate scalars; a draft displays the first value and cannot activate.
    var duplicateKeys: [String] = []

    /// Numeric fields whose value was present but unreadable, which used to fall back to the
    /// default in silence. `server`'s port has always thrown; this covers the rest and keeps
    /// this port as strict as the C# one. Parsing still SUCCEEDS; ``validate()`` refuses.
    /// (Audit 2026-08-01, §P2.)
    var unparsedNumericKeys: [String] = []

    /// `[qeli]` keys no qeli client understands — i.e. misspellings. The setting they were
    /// meant to change silently keeps its default, which is how `gatway = true` left a tunnel
    /// split with nothing said. Reported, not resolved; ``validate()`` refuses.
    /// (Audit 2026-08-01, §14.)
    var unknownKeys: [String] = []

    /// Bounds used when decoding the native NetworkPlan; runtime validation lives in Rust.
    static let mtuMin = 576
    static let mtuMax = 16602

    var serverAddress: String
    var port: Int
    var protocolName: String = ConfigDefaults.protocolName
    var connectionTimeoutSeconds: Int = ConfigDefaults.connectionTimeoutSeconds

    var reconnectEnabled: Bool = ConfigDefaults.reconnectEnabled
    var reconnectMaxRetries: Int = ConfigDefaults.reconnectMaxRetries
    var reconnectBaseDelaySeconds: Int = ConfigDefaults.reconnectBaseDelaySeconds
    var reconnectMaxDelaySeconds: Int = ConfigDefaults.reconnectMaxDelaySeconds

    var username: String = ConfigDefaults.username
    var password: String = ConfigDefaults.password
    var serverPublicKeyHex: String? = ConfigDefaults.serverPublicKeyHex
    var bindStaticToSession: Bool = ConfigDefaults.bindStaticToSession
    var allowUnpinnedTofu: Bool = ConfigDefaults.allowUnpinnedTofu

    var mtu: Int = ConfigDefaults.mtu
    var mtuProbe: Bool = ConfigDefaults.mtuProbe
    var routingMode = "full-tunnel"
    var ipv6Policy: String = ConfigDefaults.ipv6Policy
    var roamingPolicy: String = ConfigDefaults.roamingPolicy
    var addDefaultGateway: Bool = ConfigDefaults.addDefaultGateway
    var includeRoutes: [String] = []
    var excludeRoutes: [String] = []
    var pullRoutes: Bool = ConfigDefaults.pullRoutes
    var routeLocalNetworks: Bool = ConfigDefaults.routeLocalNetworks
    var allowIPv6Leak: Bool = ConfigDefaults.allowIPv6Leak
    var allowIPv4Leak: Bool = ConfigDefaults.allowIPv4Leak
    var allowLAN: Bool = ConfigDefaults.allowLAN
    var dnsServers: [String] = []
    /// DNS handling mode, mirroring `dns.mode` in the Rust client: `tunnel` (default — install
    /// resolvers reachable through the tunnel), `off` or `system` (leave the device resolver
    /// alone).
    ///
    /// Legacy mobile profiles used the same `dns` key for both a mode and a resolver list.
    /// Readers still accept that form, while writers use canonical `dns_servers`; the mode is
    /// kept separately so `off`/`system` survives an edit. (Audit 2026-08-02, §3.)
    var dnsMode: String = ConfigDefaults.dnsMode

    var wireMode: String = ConfigDefaults.wireMode
    var obfsKey: String = ConfigDefaults.obfsKey
    var obfsFronting: String = ConfigDefaults.obfsFronting
    var awgEnabled: Bool = ConfigDefaults.awgEnabled
    var awgJunkCount: Int = ConfigDefaults.awgJunkCount
    var awgJunkMin: Int = ConfigDefaults.awgJunkMin
    var awgJunkMax: Int = ConfigDefaults.awgJunkMax
    var quicEnabled: Bool = ConfigDefaults.quicEnabled
    var sni: String? = ConfigDefaults.sni
    var realityShortID: String? = ConfigDefaults.realityShortID

    var paddingEnabled: Bool = ConfigDefaults.paddingEnabled
    var paddingMin: Int = ConfigDefaults.paddingMin
    var paddingMax: Int = ConfigDefaults.paddingMax

    /// Largest `user` + `:` + `pass`, in UTF-8 bytes, that still fits one AUTH datagram.
    ///
    /// The AUTH plaintext is `proof(32)` + the optional `[0x00 device_id(16)]` prefix +
    /// `user:pass`, and the whole thing rides in one unfragmented datagram — so the
    /// credentials are what decides whether it survives a path that drops IP fragments.
    /// UI-side mirror of Rust `udp_frag::MAX_CHUNK - AUTH_OVERHEAD`. This is a validation
    /// scalar, not a second Swift wire implementation; the conformance test pins it to the
    /// legacy fixture while the production packet tunnel remains Rust-only.
    static let authCredentialBudget = 1_114

    var heartbeatEnabled: Bool = ConfigDefaults.heartbeatEnabled
    var heartbeatIntervalMilliseconds: Int = ConfigDefaults.heartbeatIntervalMilliseconds
    var heartbeatDataSize: Int = ConfigDefaults.heartbeatDataSize
    var heartbeatJitterMilliseconds: Int = ConfigDefaults.heartbeatJitterMilliseconds

    var shapingEnabled: Bool = ConfigDefaults.shapingEnabled
    var shapingGapMeanMilliseconds: Int = ConfigDefaults.shapingGapMeanMilliseconds
    var shapingGapMinMilliseconds: Int = ConfigDefaults.shapingGapMinMilliseconds
    var shapingGapMaxMilliseconds: Int = ConfigDefaults.shapingGapMaxMilliseconds
    var shapingBudgetBytesPerSecond: Int = ConfigDefaults.shapingBudgetBytesPerSecond
    var shapingMinSize: Int = ConfigDefaults.shapingMinSize
    var shapingMaxSize: Int = ConfigDefaults.shapingMaxSize
    var shapingStealth: Bool = ConfigDefaults.shapingStealth
    var shapingStealthRateMbps: Int = ConfigDefaults.shapingStealthRateMbps

    // Retained for Android/share/backup round-trip. Applying arbitrary app rules on
    // consumer iOS requires MDM and is deliberately not attempted by the app.
    var appsMode: String = ConfigDefaults.appsMode
    var apps: [String] = []

    /// Desktop-only route sources are preserved as an ordered list because `route_file` is
    /// deliberately repeatable. iOS never opens these host paths; it only keeps a portable
    /// desktop profile lossless while it is viewed or edited here.
    var routeFiles: [String] = []

    /// `[qeli]` keys accepted but not modelled (``carriedINIKeys``), kept verbatim so a save
    /// does not delete them. Written back by ``toINI()`` after the modelled keys.
    var carriedKeys: [String: String] = [:]

    // [logging] passthrough. Not used by the app (its own log setting lives in
    // AppSettings); carried so a desktop/router client.conf opened and re-saved here keeps
    // its logging section instead of silently losing it — the Rust client parses AND
    // re-emits these, and the Android client now does too.
    var loggingLevel: String? = ConfigDefaults.loggingLevel
    var loggingFile: String? = ConfigDefaults.loggingFile
    var loggingTimeFormat: String? = ConfigDefaults.loggingTimeFormat

    var isUDP: Bool { protocolName.caseInsensitiveCompare("udp") == .orderedSame }
    /// `all` counts too. The validator accepts `split-tunnel | full-tunnel | all` (the Rust
    /// client's set, see `client/route.rs`), but this only compared against `full-tunnel` — so a
    /// perfectly valid `routing.mode = "all"` profile validated and then ran as a SPLIT tunnel,
    /// quietly sending everything outside the VPN past it. (Audit 2026-07-31, §2.)
    var isFullTunnel: Bool {
        (try? ConfigCore.policy("full_tunnel",["gateway":addDefaultGateway,"mode":routingMode])["value"] as? Bool) ?? false
    }
    var allowsNativePathRoaming: Bool {
        (try? ConfigCore.policy("roaming_allowed",["mode":roamingPolicy,"local":carriedKeys["local"] ?? "","port":carriedKeys["lport"]?.nonEmpty ?? "0"])["value"] as? Bool) ?? false
    }

    init(serverAddress: String, port: Int) {
        self.serverAddress = serverAddress
        self.port = port
    }

    var nativeSource: String? = nil

    init(parsing text: String) throws { self = try Self.nativeImport(text); try validate() }
    func validate() throws { _ = try nativeOperation("validate") }
    static func fromINI(_ text: String) throws -> VPNConfig { try nativeImport(text) }
    static func fromQeliURI(_ text: String) throws -> VPNConfig { try nativeImport(text) }
    static func label(fromQeliURI text: String) -> String? {
        guard let c=try? nativeImport(text) else { return nil }
        return c.carriedKeys["name"]?.nonEmpty
    }
    func toINI(label: String? = nil) throws -> String { try nativeOperation("export",label:label)["text"] as! String }
    func toTransportCoreINI(label: String? = nil) throws -> String { try nativeOperation("runtime",label:label)["text"] as! String }
    func toQeliURI(label: String? = nil) throws -> String { try nativeOperation("uri",label:label)["text"] as! String }
}

enum VPNConfigError: LocalizedError, Equatable {
    case invalid(String)

    var errorDescription: String? {
        switch self { case .invalid(let message): return message }
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
