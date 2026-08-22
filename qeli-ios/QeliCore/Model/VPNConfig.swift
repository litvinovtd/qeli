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

    /// Keys that appeared more than once in one section, as `section.key`.
    ///
    /// A key read as a SINGLE value but written twice makes the file ambiguous, and the ports
    /// resolved it differently: this parser folds entries into a dictionary and keeps the LAST,
    /// while the Rust client takes the FIRST. Two `server` lines therefore sent the Rust client
    /// to one host and every GUI client to another, out of one file, with nothing reported.
    ///
    /// Recorded, not resolved — picking a winner still leaves the other implementations
    /// disagreeing, and only the author knows which line was meant. Parsing still SUCCEEDS, as
    /// with ``unparsedBooleanKeys``; ``validate()`` is what refuses. (Audit 2026-08-01, §7.)
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

    /// Every `[qeli]` key any qeli client understands — the union across the four ports, NOT
    /// just the ones this one reads.
    ///
    /// The distinction is the whole point. A key this port ignores is not necessarily a typo:
    /// `keepalive`, `post_up`, `exit_node` and friends are real Rust-client file-only settings
    /// (docs/ru/CONFIG.md, "Что пушем НЕ передаётся"), and a CLI profile carrying them must
    /// still open here. Only a name NOTHING understands is a typo.
    // Set(...) around the literal, not just the `Set<String>` annotation: a contextual type
    // does not propagate through a method call, so Swift types the literal as Array first and
    // then cannot find `union` on it.
    static let knownINIKeys: Set<String> = Set<String>([
        // Read by this port.
        // `allow_lan`, `apps` and `apps_mode` are read AND written a few lines below — leaving
        // them out made this port reject a profile it had exported itself, and every profile
        // carrying per-app tunnelling or allow-LAN from Android. An unknown-key check is only
        // as good as its list: a missing entry does not degrade to "ignored", it rejects the
        // whole config.
        "allow_ipv4_leak", "allow_ipv6_leak", "allow_lan", "allow_unpinned_tofu", "apps", "apps_mode",
        "awg", "bind_static", "dns", "dns_servers", "exclude",
        "front", "gateway", "heartbeat", "heartbeat_interval", "heartbeat_jitter",
        "heartbeat_size", "include", "jc", "jmax", "jmin", "key",
        "ipv6", "mode", "mtu", "mtu_probe", "obfs_key", "padding",
        "padding_max", "padding_min", "pass", "proto", "quic", "reality_sid",
        "reconnect", "reconnect_base_delay", "reconnect_max_delay", "reconnect_retries",
        "route_local", "server", "shaping", "shaping_budget", "shaping_gap_max",
        "shaping_gap_mean", "shaping_gap_min", "shaping_max_size", "shaping_min_size",
        "shaping_stealth", "shaping_stealth_mbps", "sni", "timeout", "user",
    ]).union(carriedINIKeys)

    /// Keys this port ACCEPTS but does not model — read into ``carriedKeys`` and written back
    /// verbatim, so opening and saving a CLI profile does not strip them.
    ///
    /// They are on the allowlist because a desktop profile carrying them must open here; they
    /// are in THIS list because accepting a key without keeping it is how the open-and-save
    /// round trip silently deleted hooks and security settings. Allowlisting alone was the
    /// first half of the fix and, on its own, the more dangerous half: it makes the profile
    /// open, which is exactly what leads someone to save it. (Audit 2026-08-02, §4 of the
    /// follow-up; Android got both halves first.)
    static let carriedINIKeys: Set<String> = [
        // Not edited by the iOS model. Foreign platform/lifecycle fields survive a round trip;
        // transport-owned socket settings are consumed by Rust at the native boundary.
        "autostart", "dev", "dev_attach", "device_type", "dev_node", "exit_node", "forward",
        "gateway_nat", "keepalive", "lan_subnet", "lan_subnet_ipv6", "post_down", "post_up", "tcp_nodelay",
        "kill_switch", "local", "lport", "metric", "name", "persist_tun", "route_file",
        // Socket settings plus headless-only password sources.
        "password_command", "password_file", "reality_compact", "reality_split",
        "reality_split_delay", "recv_buffer_size", "send_buffer_size",
    ]

    /// Accepted tunnel-MTU range. The ceiling is derived, in Rust, from the record format
    /// (`protocol/packet.rs MAX_TUNNEL_MTU`): a record holds nonce + counter + payload +
    /// padding-length + tag and must fit `MAX_RECORD_SIZE`, so anything larger the PEER
    /// REJECTS. Mirrored here as a literal — the four ports and the two UIs must all carry the
    /// same number, because raising it in one place only is worse than not raising it.
    /// (Audit 2026-08-01, §1.)
    static let mtuMin = 576
    static let mtuMax = 16638

    /// Upper bound for both reconnect delays, in seconds (one day). Shared with the Kotlin and
    /// C# ports; see the note at the parse site for why the desktop client cannot go higher.
    static let reconnectDelaySecondsMax = 86_400

    var serverAddress: String
    var port: Int
    var protocolName: String = "tcp"
    var connectionTimeoutSeconds: Int = 30

    var reconnectEnabled = true
    var reconnectMaxRetries = -1
    var reconnectBaseDelaySeconds = 1
    var reconnectMaxDelaySeconds = 60

    var username: String = "client"
    var password: String = ""
    var serverPublicKeyHex: String?
    var bindStaticToSession = true
    var allowUnpinnedTofu = false

    var mtu = 0
    var mtuProbe = true
    var routingMode = "full-tunnel"
    var ipv6Policy = "auto"
    var addDefaultGateway = true
    var includeRoutes: [String] = []
    var excludeRoutes: [String] = []
    var routeLocalNetworks = false
    var allowIPv6Leak = false
    var allowIPv4Leak = false
    var allowLAN = false
    var dnsServers: [String] = []
    /// DNS handling mode, mirroring `dns.mode` in the Rust client: `tunnel` (default — install
    /// resolvers reachable through the tunnel), `off` or `system` (leave the device resolver
    /// alone).
    ///
    /// Legacy mobile profiles used the same `dns` key for both a mode and a resolver list.
    /// Readers still accept that form, while writers use canonical `dns_servers`; the mode is
    /// kept separately so `off`/`system` survives an edit. (Audit 2026-08-02, §3.)
    var dnsMode: String = "tunnel"

    var wireMode = "fake-tls"
    var obfsKey = ""
    var obfsFronting = "websocket"
    var awgEnabled = false
    var awgJunkCount = 0
    var awgJunkMin = 40
    var awgJunkMax = 300
    var quicEnabled = false
    var sni: String?
    var realityShortID: String?

    var paddingEnabled = true
    var paddingMin = 0
    var paddingMax = 255

    /// Largest `user` + `:` + `pass`, in UTF-8 bytes, that still fits one AUTH datagram.
    ///
    /// The AUTH plaintext is `proof(32)` + the optional `[0x00 device_id(16)]` prefix +
    /// `user:pass`, and the whole thing rides in one unfragmented datagram — so the
    /// credentials are what decides whether it survives a path that drops IP fragments.
    /// UI-side mirror of Rust `udp_frag::MAX_CHUNK - AUTH_OVERHEAD`. This is a validation
    /// scalar, not a second Swift wire implementation; the conformance test pins it to the
    /// legacy fixture while the production packet tunnel remains Rust-only.
    static let authCredentialBudget = 1_114

    /// Largest `padding_max` that can be encoded, mirroring the Rust client's cap.
    ///
    /// Padding rides on EVERY record, so this bounds the record, not a one-off. It applies to
    /// both a local profile (`validate()`) and a server-pushed value (`clampPushedObfuscation`)
    /// — the local one used to go unchecked, and applies FIRST. (Audit 2026-08-02, §9.)
    static let paddingMaxCeiling = 1_400
    var heartbeatEnabled = true
    var heartbeatIntervalMilliseconds = 15_000
    var heartbeatDataSize = 16
    var heartbeatJitterMilliseconds = 2_000

    var shapingEnabled = false
    var shapingGapMeanMilliseconds = 700
    var shapingGapMinMilliseconds = 40
    var shapingGapMaxMilliseconds = 6_000
    var shapingBudgetBytesPerSecond = 16_384
    var shapingMinSize = 64
    var shapingMaxSize = 1_024
    var shapingStealth = false
    var shapingStealthRateMbps = 2

    // Retained for Android/share/backup round-trip. Applying arbitrary app rules on
    // consumer iOS requires MDM and is deliberately not attempted by the app.
    var appsMode = "all"
    var apps: [String] = []

    /// `[qeli]` keys accepted but not modelled (``carriedINIKeys``), kept verbatim so a save
    /// does not delete them. Written back by ``toINI()`` after the modelled keys.
    var carriedKeys: [String: String] = [:]

    // [logging] passthrough. Not used by the app (its own log setting lives in
    // AppSettings); carried so a desktop/router client.conf opened and re-saved here keeps
    // its logging section instead of silently losing it — the Rust client parses AND
    // re-emits these, and the Android client now does too.
    var loggingLevel: String?
    var loggingFile: String?
    var loggingTimeFormat: String?

    var isUDP: Bool { protocolName.caseInsensitiveCompare("udp") == .orderedSame }
    /// `all` counts too. The validator accepts `split-tunnel | full-tunnel | all` (the Rust
    /// client's set, see `client/route.rs`), but this only compared against `full-tunnel` — so a
    /// perfectly valid `routing.mode = "all"` profile validated and then ran as a SPLIT tunnel,
    /// quietly sending everything outside the VPN past it. (Audit 2026-07-31, §2.)
    var isFullTunnel: Bool {
        addDefaultGateway || routingMode == "full-tunnel" || routingMode == "all"
    }

    init(serverAddress: String, port: Int) {
        self.serverAddress = serverAddress
        self.port = port
    }

    init(parsing text: String) throws {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("qeli://") {
            self = try Self.fromQeliURI(trimmed)
        } else if trimmed.hasPrefix("{") {
            // JSON is RETIRED, and detected only so the message can say so.
            //
            // It was the original config format and stopped being written years ago; INI
            // replaced it and every tool emits INI. What remained was a second, entirely
            // parallel parser per client — with its own defaults, its own leniency and its
            // own bugs. It kept accruing findings the INI path had already fixed (numbers
            // silently defaulting, unknown keys dropped, types coerced) because hardening
            // it meant doing every fix twice, in four languages, for a format nobody
            // produces.
            //
            // Letting `{…}` fall through to fromINI instead would "work" but report a
            // meaningless "missing [qeli]". Someone opening a genuinely old file deserves
            // to be told what happened and what to do. (Retired 2026-08-02.)
            throw VPNConfigError.invalid(
                "this is a JSON profile, a format qeli no longer reads — export the profile "
                    + "again from the server panel, or use its qeli:// link, to get the "
                    + "current INI format")
        } else {
            self = try Self.fromINI(trimmed)
        }
        try validate()
    }

    /// Clamp every obfuscation/shaping value the SERVER pushes in AuthOK into a usable
    /// range.
    ///
    /// `validate()` covers what the user types (port, timeout, mtu, padding) but nothing
    /// that arrives over the wire, and the AuthOK parsers assigned these fields straight
    /// from the JSON. Two consequences, both remote and post-authentication:
    ///
    /// * a large `idle_gap_mean_ms` made `TrafficShaper.nextGapMilliseconds` produce a
    ///   `Double` outside `Int`'s range, and `Int(_:)` TRAPS rather than saturating —
    ///   killing the Network Extension process on the first heartbeat tick;
    /// * a large `padding.max_bytes` pushed records past `MaxRecordSize`, so
    ///   `PacketCodec.encrypt` threw, the uplink died, the client reconnected, got the
    ///   same value and looped forever.
    ///
    /// Clamping rather than rejecting: a server that pushes an odd value is far more
    /// likely misconfigured than hostile, and refusing to connect would be a worse
    /// outcome than shaping slightly differently than asked. (Audit 2026-07-27, C10.)
    mutating func clampPushedObfuscation() {
        // Padding must leave room inside one record; the ceiling mirrors the Rust client's.
        paddingMin = min(max(paddingMin, 0), Self.paddingMaxCeiling)
        paddingMax = min(max(paddingMax, paddingMin), Self.paddingMaxCeiling)

        shapingGapMeanMilliseconds = min(max(shapingGapMeanMilliseconds, 1), 60_000)
        shapingGapMinMilliseconds = min(max(shapingGapMinMilliseconds, 0), 60_000)
        shapingGapMaxMilliseconds = min(
            max(shapingGapMaxMilliseconds, shapingGapMinMilliseconds),
            60_000
        )
        shapingMinSize = min(max(shapingMinSize, 0), 1_400)
        shapingMaxSize = min(max(shapingMaxSize, shapingMinSize), 1_400)
        shapingBudgetBytesPerSecond = min(max(shapingBudgetBytesPerSecond, 0), 100_000_000)
        shapingStealthRateMbps = min(max(shapingStealthRateMbps, 1), 10_000)

        heartbeatIntervalMilliseconds = min(max(heartbeatIntervalMilliseconds, 1_000), 600_000)
        heartbeatJitterMilliseconds = min(max(heartbeatJitterMilliseconds, 0), 60_000)
    }

    func validate() throws {
        // A boolean nobody could parse is a typo, and every one of them used to read as `false`
        // — so `bind_static = ture` dropped the static-key binding and `gateway = ture` turned a
        // full tunnel into a split one, silently. Refuse to connect rather than run with a
        // setting the user plainly did not choose. (Audit 2026-07-31.)
        if !unparsedBooleanKeys.isEmpty {
            throw VPNConfigError.invalid(
                "unrecognised boolean value for \(unparsedBooleanKeys.joined(separator: ", ")) — "
                + "expected true/false, yes/no, on/off or 1/0")
        }

        // A misspelled key name is invisible: nothing reads it, so the setting it was meant to
        // change silently keeps its default. (Audit 2026-08-01, §14.)
        if !unknownKeys.isEmpty {
            throw VPNConfigError.invalid(
                "unknown key(s), likely misspelled: \(unknownKeys.joined(separator: ", ")) — "
                + "nothing reads these, so the setting they were meant to change is at its default")
        }

        // A number nobody could parse must not become a default in silence. (Audit 2026-08-01.)
        if !unparsedNumericKeys.isEmpty {
            throw VPNConfigError.invalid(
                "unparseable number for \(unparsedNumericKeys.joined(separator: ", ")) — the "
                + "default would have been used instead")
        }

        // A key written twice is ambiguous, and the ports disagreed on which line wins — the
        // same file reached two different servers depending on the client. (Audit 2026-08-01.)
        if !duplicateKeys.isEmpty {
            throw VPNConfigError.invalid(
                "key(s) \(duplicateKeys.joined(separator: ", ")) appear more than once and are "
                + "read as a single value; implementations disagree on which wins — keep one")
        }

        // String enums the runtime compares against ONE literal, so an unknown value does not
        // error — it silently selects the other branch. `front = webscoket` drops the WebSocket
        // framing and the peer then disagrees about the wire; `routing_mode = full-tunel` with
        // `add_default_gateway = false` quietly becomes a split tunnel. `proto` and `mode` were
        // already checked below. (Audit 2026-07-31, §3.)
        let enums: [(String, String, [String])] = [
            ("front", obfsFronting, ["websocket", "none"]),
            ("routing_mode", routingMode, ["split-tunnel", "full-tunnel", "all"]),
            ("ipv6", ipv6Policy, ["auto", "required", "off"])
        ]
        for (field, value, allowed) in enums where !allowed.contains(value) {
            throw VPNConfigError.invalid(
                "unknown \(field) '\(value)' — expected "
                + allowed.map { "'\($0)'" }.joined(separator: " or "))
        }

        let scalarFields: [(String, String)] = [
            ("server", serverAddress),
            ("proto", protocolName),
            ("user", username),
            ("pass", password),
            ("key", serverPublicKeyHex ?? ""),
            ("routing_mode", routingMode),
            ("mode", wireMode),
            ("obfs_key", obfsKey),
            ("front", obfsFronting),
            ("sni", sni ?? ""),
            ("reality_sid", realityShortID ?? ""),
            ("apps_mode", appsMode)
        ]
        for (field, value) in scalarFields where Self.containsForbiddenINICharacters(value) {
            throw VPNConfigError.invalid("\(field) contains a forbidden line break or NUL character")
        }
        // Carried keys are written back verbatim, so they need the same INI-forgery gate as
        // everything else this port emits — a `post_up` with an embedded newline would
        // otherwise inject arbitrary config lines on save.
        for (field, value) in carriedKeys
        where Self.containsForbiddenINICharacters(field) || Self.containsForbiddenINICharacters(value) {
            throw VPNConfigError.invalid("\(field) contains a forbidden line break or NUL character")
        }
        let listFields: [(String, [String])] = [
            ("include", includeRoutes),
            ("exclude", excludeRoutes),
            ("dns", dnsServers),
            ("apps", apps)
        ]
        for (field, values) in listFields where values.contains(where: Self.containsForbiddenINICharacters) {
            throw VPNConfigError.invalid("\(field) contains a forbidden line break or NUL character")
        }
        for (field, routes) in [("include", includeRoutes), ("exclude", excludeRoutes)] {
            for route in routes where !Self.isCIDRLiteral(route) {
                throw VPNConfigError.invalid(
                    "\(field) route '\(route)' is not an IPv4/IPv6 CIDR literal")
            }
        }
        guard !serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VPNConfigError.invalid("server host is empty")
        }
        guard !serverAddress.contains("[") && !serverAddress.contains("]") else {
            throw VPNConfigError.invalid(
                "serverAddress stores a bare host; brackets belong only around an IPv6 endpoint")
        }
        if serverAddress.contains(":"), !Self.isIPLiteral(serverAddress) {
            throw VPNConfigError.invalid("server contains an invalid IPv6 address: \(serverAddress)")
        }
        guard (1...65_535).contains(port) else {
            throw VPNConfigError.invalid("server port must be between 1 and 65535")
        }
        guard ["tcp", "udp"].contains(protocolName.lowercased()) else {
            throw VPNConfigError.invalid("proto must be tcp or udp")
        }
        guard (1...300).contains(connectionTimeoutSeconds) else {
            throw VPNConfigError.invalid("timeout must be between 1 and 300 seconds")
        }
        guard ["plain", "fake-tls", "obfs", "reality-tls"].contains(wireMode.lowercased()) else {
            throw VPNConfigError.invalid("unsupported mode: \(wireMode)")
        }
        // A mode that needs a secret must HAVE it, or the profile is valid and unusable.
        //
        // Each of these was checked at the use site or not at all, so the app called the
        // profile fine and the failure surfaced mid-handshake — where it reads as a server or
        // network problem rather than a missing field. The short_id is the sharpest case: this
        // side parses hex leniently and the SERVER strictly, so `reality_sid = deadbeeg` became
        // a different token here and matched nothing there. (Audit 2026-08-03, P2.)
        if wireMode.lowercased() == "reality-tls" {
            let sid = (realityShortID ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !sid.isEmpty else {
                throw VPNConfigError.invalid(
                    "mode = reality-tls requires reality_sid — it is the token the server uses "
                        + "to tell qeli clients from probes; without it this client is treated "
                        + "as a probe and proxied to the decoy site")
            }
            let hex = CharacterSet(charactersIn: "0123456789abcdefABCDEF")
            guard sid.count % 2 == 0, sid.count <= 16,
                  sid.unicodeScalars.allSatisfy(hex.contains), sid.contains(where: { $0 != "0" })
            else {
                throw VPNConfigError.invalid(
                    "reality_sid must be 1..8 bytes of hex (2..16 hex digits, not all zero), got "
                        + "'\(sid)' — this client parses hex leniently and the SERVER does not, "
                        + "so a malformed value silently becomes a different token")
            }
            guard !(serverPublicKeyHex ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw VPNConfigError.invalid(
                    "mode = reality-tls requires a pinned server key — REALITY's whole point is "
                        + "that an unauthenticated peer is proxied to the decoy site, which a "
                        + "TOFU client cannot tell apart from the real server")
            }
        }
        if wireMode.lowercased() == "obfs",
           obfsKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw VPNConfigError.invalid(
                "mode = obfs requires a non-empty obfs_key — an empty key is publicly derivable, "
                    + "so the stream is obfuscated against nobody (the server refuses the same "
                    + "pairing)")
        }
        // Both fields are individually valid and the PAIR is not. The server refuses these two
        // combinations, so a client that accepts them cannot reach any working profile — it
        // just fails later and less clearly. Worse for `reality-tls`: nothing about the name
        // says TCP, so the operator believes they have the strongest masking available while
        // the datagram path quietly falls back to fake-tls framing. (Audit 2026-08-03, P2.)
        if protocolName.lowercased() == "udp" {
            if wireMode.lowercased() == "plain" {
                throw VPNConfigError.invalid(
                    "mode = plain is TCP-only (raw framing has no datagram form) — set "
                        + "proto = tcp, or pick obfs/fake-tls for a UDP profile")
            }
            if wireMode.lowercased() == "reality-tls" {
                throw VPNConfigError.invalid(
                    "mode = reality-tls is TCP-only — it terminates a REAL TLS 1.3 session, "
                        + "which UDP cannot carry. Set proto = tcp, or pick obfs for UDP")
            }
        }
        if mtu != 0 && !(Self.mtuMin...Self.mtuMax).contains(mtu) {
            throw VPNConfigError.invalid("mtu must be 0 or between \(Self.mtuMin) and \(Self.mtuMax)")
        }
        if ipv6Policy == "required", mtu > 0, mtu < 1280 {
            throw VPNConfigError.invalid(
                "ipv6 = required needs an explicit mtu of at least 1280 (or 0 for auto), got \(mtu)")
        }
        guard paddingMin >= 0, paddingMax >= paddingMin else {
            throw VPNConfigError.invalid("padding range is invalid")
        }
        // Padding is added to EVERY record, so an unbounded maximum is not a large-packet
        // setting — it is a record that cannot be encoded. A server-pushed value is clamped
        // on arrival, but the local profile is applied first: `padding_max = 65535` produced
        // `recordTooLarge` during AUTH or on the first data records, i.e. a tunnel that
        // connects and then dies, from a number the config editor accepted. The ceiling
        // matches the other ports. (Audit 2026-08-02, §9.)
        guard paddingMax <= Self.paddingMaxCeiling else {
            throw VPNConfigError.invalid(
                "padding_max must be at most \(Self.paddingMaxCeiling) — padding rides on every "
                    + "record, and a larger value cannot be encoded")
        }
        // A misspelled `apps_mode` must not resolve to the WIDEST setting in silence.
        // Handled like `proto` and `mode` above: the raw value is kept and refused here,
        // rather than coerced at parse time where the original is lost and `apps_mode =
        // includ` quietly tunnels every app. (Audit 2026-08-02, §10.)
        guard ["all", "include", "exclude"].contains(appsMode.lowercased()) else {
            throw VPNConfigError.invalid(
                "apps_mode must be all, include or exclude — got '\(appsMode)'")
        }
        // Same reasoning: the fallback is "tunnel", so a typo does not fail — it picks the
        // opposite of `off`/`system` and sends every lookup through the VPN.
        guard ["off", "tunnel", "system"].contains(dnsMode.lowercased()) else {
            throw VPNConfigError.invalid("dns mode must be off, tunnel or system — got '\(dnsMode)'")
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
        let credentialBytes = username.utf8.count + password.utf8.count + 1  // + the ':'
        guard credentialBytes <= Self.authCredentialBudget else {
            throw VPNConfigError.invalid(
                "'user' + 'pass' are \(credentialBytes) bytes, over the "
                    + "\(Self.authCredentialBudget) a UDP AUTH datagram can carry — the "
                    + "handshake would be dropped by any path that discards IP fragments "
                    + "(mobile, CGNAT) and would look like an unreachable server. Shorten them.")
        }
        // The flat INI spells the MODE and the RESOLVER LIST with the same `dns` key, so a
        // misspelled mode does not fall through to an error — it falls through to being read
        // as an ADDRESS. `dns = of` became a resolver named "of", the tunnel installed it, and
        // every lookup went to something that cannot answer. A resolver must be an IP literal
        // (you cannot resolve a resolver by name), so checking that turns the typo back into
        // an error. (Audit 2026-08-02, follow-up.)
        for server in dnsServers where !Self.isIPLiteral(server) {
            throw VPNConfigError.invalid(
                "dns server '\(server)' is not an IP address — if you meant a mode, it must be "
                    + "off, tunnel or system")
        }
    }

    /// True for a bare IPv4 or IPv6 literal.
    ///
    /// Deliberately not `getaddrinfo`: that RESOLVES anything which is not a literal, which is
    /// a network round trip during config validation for a value that is by definition not
    /// resolvable yet.
    /// `inet_pton` rather than a hand-rolled parser: it is the system's own literal parser,
    /// it does NOT resolve, and it is exact. The first version of this check tested "hex
    /// digits and colons, at least two colons", which accepts `::::`, `1::2::3` and `abcd:::`
    /// — the config then validated and the failure surfaced later, when the network settings
    /// were built and quietly refused. (Audit 2026-08-02, follow-up.)
    static func isIPLiteral(_ s: String) -> Bool {
        let v = s.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { return false }
        var v4 = in_addr()
        if v.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return true }
        var v6 = in6_addr()
        return v.withCString { inet_pton(AF_INET6, $0, &v6) } == 1
    }

    static func isCIDRLiteral(_ s: String) -> Bool {
        let value = s.trimmingCharacters(in: .whitespaces)
        let parts = value.split(
            separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), Self.isIPLiteral(String(parts[0])) else {
            return false
        }
        guard parts.count == 2 else { return true }
        let maximum = parts[0].contains(":") ? 128 : 32
        guard !parts[1].isEmpty,
              parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
              let prefix = Int(parts[1]) else { return false }
        return (0...maximum).contains(prefix)
    }

    static func fromINI(_ text: String) throws -> VPNConfig {
        var dupKeys: [String] = []
        let sections = parseINI(text, duplicates: &dupKeys)
        guard let qeli = sections["qeli"] else {
            throw VPNConfigError.invalid("config is missing [qeli] section")
        }
        guard let endpoint = qeli["server"], !endpoint.isEmpty else {
            throw VPNConfigError.invalid("[qeli] is missing server = host:port")
        }
        let (host, port) = try parseEndpoint(endpoint)
        // Accepts the same spellings as the Rust client's `bool_or`. An unrecognised value is
        // RECORDED (see `unparsedBooleanKeys`) and falls back to the caller's default, instead
        // of silently reading as `false`.
        // An INI integer, recording the key when the value is present but not a number.
        //
        // Absent keeps the default silently — that is what a default is for. A value that is
        // THERE and unreadable is a typo, and substituting the default without a word is the
        // same failure `boolAt` exists to prevent. (Audit 2026-08-01, §P2.)
        var badNums: [String] = []
        func numAt(_ key: String, default fallback: Int) -> Int {
            guard let raw = qeli[key]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
                return fallback
            }
            guard let parsed = Int(raw) else {
                badNums.append(key)
                return fallback
            }
            return parsed
        }
        /// ``numAt`` with a range, recording out-of-range exactly like unreadable.
        ///
        /// Falling back to the default on an out-of-range value is not a clamp — a clamp pins to
        /// the nearest bound, this jumps somewhere else entirely — so it has to be reported, or
        /// the setting the user wrote is silently replaced by an unrelated one. Mirrors the C#
        /// `RangedLong` and the Kotlin `rangedLong`.
        func rangedNum(_ key: String, default fallback: Int, _ lo: Int, _ hi: Int) -> Int {
            let v = numAt(key, default: fallback)
            if v >= lo && v <= hi { return v }
            let present = !(qeli[key]?.trimmingCharacters(in: .whitespaces).isEmpty ?? true)
            if present && !badNums.contains(key) { badNums.append(key) }
            return fallback
        }
        var badBools: [String] = []
        func boolAt(_ key: String, default fallback: Bool) -> Bool {
            guard let raw = qeli[key]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
                return fallback
            }
            switch raw.lowercased() {
            case "true", "1", "yes", "on": return true
            case "false", "0", "no", "off": return false
            default:
                badBools.append(key)
                return fallback
            }
        }
        let list: (String?) -> [String] = { value in
            value?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty } ?? []
        }

        var config = VPNConfig(serverAddress: host, port: port)
        config.protocolName = qeli["proto"].nonEmpty ?? "tcp"
        config.connectionTimeoutSeconds = numAt("timeout", default: 30)
        config.reconnectEnabled = boolAt("reconnect", default: true)
        config.reconnectMaxRetries = numAt("reconnect_retries", default: -1)
        // Bounded to a day, matching the other ports. On the desktop client the bound is not a
        // matter of taste — its reconnect loop waits via `WaitHandle.WaitOne(Int32)`, so a
        // delay past ~24.8 days truncates and can throw — and a profile is portable, so one
        // bound everywhere beats three behaviours out of one file.
        config.reconnectBaseDelaySeconds =
            rangedNum("reconnect_base_delay", default: 1, 1, Self.reconnectDelaySecondsMax)
        config.reconnectMaxDelaySeconds =
            rangedNum("reconnect_max_delay", default: 60, 1, Self.reconnectDelaySecondsMax)
        config.username = qeli["user"].nonEmpty ?? "client"
        config.password = qeli["pass"] ?? ""
        config.serverPublicKeyHex = qeli["key"].nonEmpty
        config.bindStaticToSession = boolAt("bind_static", default: true)
        config.allowUnpinnedTofu = boolAt("allow_unpinned_tofu", default: false)
        config.mtu = numAt("mtu", default: 0)
        // Through boolAt like every other boolean: the old "anything not in the off-set is ON"
        // reading meant `mtu_probe = ture` silently enabled probing and was never recorded as a
        // typo. (Audit 2026-07-31.)
        config.mtuProbe = boolAt("mtu_probe", default: true)

        let fullTunnel = boolAt("gateway", default: true)
        config.routingMode = fullTunnel ? "full-tunnel" : "split-tunnel"
        config.ipv6Policy = qeli["ipv6"]?.lowercased() ?? "auto"
        config.addDefaultGateway = fullTunnel
        config.includeRoutes = list(qeli["include"])
        config.excludeRoutes = list(qeli["exclude"])
        config.routeLocalNetworks = boolAt("route_local", default: false)
        config.allowIPv6Leak = boolAt("allow_ipv6_leak", default: false)
        config.allowIPv4Leak = boolAt("allow_ipv4_leak", default: false)
        config.allowLAN = boolAt("allow_lan", default: false)
        // `dns` is a resolver LIST here and a MODE in the Rust/router client (`off` / `tunnel`
        // / `system`). Legacy profiles overloaded the key; the mode is now kept independently
        // and honoured at connect time while resolver lists are written as `dns_servers`.
        if let raw = qeli["dns"], ["off", "system"].contains(raw.lowercased()) {
            config.dnsMode = raw.lowercased()
        }
        if let dns = qeli["dns_servers"]?.nonEmpty {
            config.dnsServers = list(dns)
        } else if let dns = qeli["dns"], !["off", "system", "tunnel"].contains(dns.lowercased()) {
            config.dnsServers = list(dns)
        }

        // Carried through untouched so re-saving a desktop config keeps its logging section.
        if let logging = sections["logging"] {
            config.loggingLevel = logging["level"].nonEmpty
            config.loggingFile = logging["file"].nonEmpty
            config.loggingTimeFormat = logging["time_format"].nonEmpty
        }

        config.wireMode = qeli["mode"].nonEmpty ?? "fake-tls"
        config.sni = qeli["sni"].nonEmpty
        config.realityShortID = qeli["reality_sid"].nonEmpty
        config.obfsKey = qeli["obfs_key"] ?? ""
        config.obfsFronting = qeli["front"].nonEmpty ?? "websocket"
        config.awgEnabled = boolAt("awg", default: false)
        config.awgJunkCount = numAt("jc", default: 0)
        config.awgJunkMin = numAt("jmin", default: 40)
        config.awgJunkMax = numAt("jmax", default: 300)
        config.quicEnabled = boolAt("quic", default: false)

        config.paddingEnabled = boolAt("padding", default: true)
        config.paddingMin = numAt("padding_min", default: 0)
        config.paddingMax = numAt("padding_max", default: 255)
        config.heartbeatEnabled = boolAt("heartbeat", default: true)
        // Range-checked, matching the C# reader. Unbounded, `heartbeat_interval = -1` parsed
        // cleanly and then disabled the heartbeat entirely while `heartbeat = true` still
        // claimed it was on — a keepalive that silently is not one. Jitter and size may be 0
        // (no jitter, empty payload are real choices); the interval may not.
        config.heartbeatIntervalMilliseconds =
            rangedNum("heartbeat_interval", default: 15_000, 1, Int.max)
        config.heartbeatDataSize = rangedNum("heartbeat_size", default: 16, 0, Int.max)
        config.heartbeatJitterMilliseconds =
            rangedNum("heartbeat_jitter", default: 2_000, 0, Int.max)

        config.shapingEnabled = boolAt("shaping", default: false)
        // Same floors as the C# reader: every one of these is a duration or a size, so zero or
        // negative is not a setting but a value nothing can act on.
        config.shapingGapMeanMilliseconds = rangedNum("shaping_gap_mean", default: 700, 1, Int.max)
        config.shapingGapMinMilliseconds = rangedNum("shaping_gap_min", default: 40, 1, Int.max)
        config.shapingGapMaxMilliseconds = rangedNum("shaping_gap_max", default: 6_000, 1, Int.max)
        config.shapingBudgetBytesPerSecond =
            rangedNum("shaping_budget", default: 16_384, 1, Int.max)
        config.shapingMinSize = rangedNum("shaping_min_size", default: 64, 1, Int.max)
        config.shapingMaxSize = rangedNum("shaping_max_size", default: 1_024, 1, Int.max)
        config.shapingStealth = boolAt("shaping_stealth", default: false)
        config.shapingStealthRateMbps = rangedNum("shaping_stealth_mbps", default: 2, 1, Int.max)

        // Kept RAW, not coerced: `validate()` refuses an unknown value, the same way it does
        // for `proto` and `mode`. Coercing here silently turned `apps_mode = includ` into
        // "all" — the widest setting — so a typo broadened the tunnel instead of failing.
        // (Audit 2026-08-02, §10.)
        config.appsMode = qeli["apps_mode"]?.lowercased() ?? "all"
        config.apps = list(qeli["apps"])
        config.unparsedBooleanKeys = badBools
        config.duplicateKeys = dupKeys
        config.unparsedNumericKeys = badNums
        config.unknownKeys = qeli.keys
            .filter { !Self.knownINIKeys.contains($0.lowercased()) }
            .sorted()
        // Accepted but not modelled — kept so saving does not delete them.
        config.carriedKeys = qeli.filter { Self.carriedINIKeys.contains($0.key.lowercased()) }
        return config
    }


    static func fromQeliURI(_ uri: String) throws -> VPNConfig {
        guard uri.hasPrefix("qeli://") else { throw VPNConfigError.invalid("not a qeli:// link") }
        var remainder = String(uri.dropFirst("qeli://".count))
        if let hash = remainder.firstIndex(of: "#") { remainder = String(remainder[..<hash]) }

        let query: String?
        if let question = remainder.firstIndex(of: "?") {
            query = String(remainder[remainder.index(after: question)...])
            remainder = String(remainder[..<question])
        } else {
            query = nil
        }

        let at = remainder.lastIndex(of: "@")
        let userInfo = at.map { String(remainder[..<$0]) }
        let endpoint = at.map { String(remainder[remainder.index(after: $0)...]) } ?? remainder
        let (host, port) = try parseEndpoint(endpoint)

        var config = VPNConfig(serverAddress: host, port: port)
        if let userInfo {
            if let colon = userInfo.firstIndex(of: ":") {
                config.username = percentDecode(String(userInfo[..<colon]))
                config.password = percentDecode(String(userInfo[userInfo.index(after: colon)...]))
            } else {
                config.username = percentDecode(userInfo)
            }
        }

        for item in query?.split(separator: "&", omittingEmptySubsequences: true) ?? [] {
            let parts = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = String(parts[0])
            let value = percentDecode(parts.count == 2 ? String(parts[1]) : "")
            switch key {
            case "proto": config.protocolName = value
            case "mode": config.wireMode = value
            case "key": config.serverPublicKeyHex = value.nonEmpty
            case "sni": config.sni = value.nonEmpty
            case "rsid": config.realityShortID = value.nonEmpty
            case "obfs": config.obfsKey = value
            case "front": config.obfsFronting = value.nonEmpty ?? "websocket"
            case "quic": config.quicEnabled = value == "1" || value.lowercased() == "true"
            case "awg": config.awgEnabled = value == "1" || value.lowercased() == "true"
            case "jc": config.awgJunkCount = Int(value) ?? 0
            case "jmin": config.awgJunkMin = Int(value) ?? 40
            case "jmax": config.awgJunkMax = Int(value) ?? 300
            // Out-of-range → auto, rather than rejecting the whole link in validate()
            // below. Matches the Rust `from_link` clamp; the Android client now does the
            // same, so one shared link no longer imports on one platform and fails on
            // another over a value the client would have ignored anyway.
            case "mtu": config.mtu = Int(value).flatMap { $0 == 0 || (Self.mtuMin...Self.mtuMax).contains($0) ? $0 : 0 } ?? 0
            default: break
            }
        }

        // Alias convenience: `mode=udp-quic` / `udp-obfs` fold transport+QUIC into the
        // wire mode. Split it back into proto + wire mode + quic — the same mapping the
        // Rust link parser applies (config/share.rs). Done AFTER the loop, not inside the
        // `mode` case, because `proto` may arrive later in the query and would otherwise
        // overwrite the transport the alias just implied.
        switch config.wireMode {
        case "udp-quic":
            config.protocolName = "udp"
            config.wireMode = "fake-tls"
            config.quicEnabled = true
        case "udp-obfs":
            config.protocolName = "udp"
            config.wireMode = "obfs"
        default:
            break
        }

        // Validate before handing the config back. Parsing alone accepted anything an
        // `Int` could hold, so `:0` and `:65536` produced a config that only failed much
        // later — and the reject tests, which call this method directly, passed them.
        try config.validate()
        return config
    }

    static func label(fromQeliURI uri: String) -> String? {
        guard let hash = uri.firstIndex(of: "#") else { return nil }
        return percentDecode(String(uri[uri.index(after: hash)...])).nonEmpty
    }

    func toINI(label: String? = nil) throws -> String {
        try validate()
        if let label, Self.containsForbiddenINICharacters(label) {
            throw VPNConfigError.invalid("profile label contains a forbidden line break or NUL character")
        }
        let endpoint = Self.formatEndpoint(host: serverAddress, port: port)
        var lines: [String] = []
        if let label = label?.trimmingCharacters(in: .whitespacesAndNewlines), !label.isEmpty {
            lines.append("# \(label.replacingOccurrences(of: "\n", with: " "))")
        }
        lines += [
            "[qeli]",
            "server = \(endpoint)",
            "proto = \(protocolName)",
            "user = \(username)",
            "pass = \(password)",
            "mode = \(wireMode)"
        ]
        if let value = serverPublicKeyHex { lines.append("key = \(value)") }
        if !bindStaticToSession { lines.append("bind_static = false") }
        if allowUnpinnedTofu { lines.append("allow_unpinned_tofu = true") }
        if let value = sni { lines.append("sni = \(value)") }
        if let value = realityShortID { lines.append("reality_sid = \(value)") }
        if !obfsKey.isEmpty { lines.append("obfs_key = \(obfsKey)") }
        if obfsFronting != "websocket" { lines.append("front = \(obfsFronting)") }
        if quicEnabled { lines.append("quic = true") }
        if awgEnabled {
            lines += ["awg = true", "jc = \(awgJunkCount)", "jmin = \(awgJunkMin)", "jmax = \(awgJunkMax)"]
        }
        if mtu != 0 { lines.append("mtu = \(mtu)") }
        if !mtuProbe { lines.append("mtu_probe = false") }
        lines.append("gateway = \(isFullTunnel ? "true" : "false")")
        if ipv6Policy != "auto" { lines.append("ipv6 = \(ipv6Policy)") }
        if !includeRoutes.isEmpty { lines.append("include = \(includeRoutes.joined(separator: ", "))") }
        if !excludeRoutes.isEmpty { lines.append("exclude = \(excludeRoutes.joined(separator: ", "))") }
        if routeLocalNetworks { lines.append("route_local = true") }
        if allowIPv6Leak { lines.append("allow_ipv6_leak = true") }
        if allowIPv4Leak { lines.append("allow_ipv4_leak = true") }
        if allowLAN { lines.append("allow_lan = true") }
        // One key, two meanings — mirroring the Rust client. A non-default MODE wins over the
        // server list: `dns = off` must survive a save/load round-trip, or re-saving a profile
        // would silently turn "leave my resolver alone" back into tunnel-managed DNS.
        if dnsMode != "tunnel" { lines.append("dns = \(dnsMode)") }
        if !dnsServers.isEmpty { lines.append("dns_servers = \(dnsServers.joined(separator: ", "))") }
        lines.append("padding = \(paddingEnabled ? "true" : "false")")
        lines.append("padding_min = \(paddingMin)")
        lines.append("padding_max = \(paddingMax)")
        lines.append("heartbeat = \(heartbeatEnabled ? "true" : "false")")
        lines.append("heartbeat_interval = \(heartbeatIntervalMilliseconds)")
        lines.append("heartbeat_size = \(heartbeatDataSize)")
        lines.append("heartbeat_jitter = \(heartbeatJitterMilliseconds)")
        lines.append("shaping = \(shapingEnabled ? "true" : "false")")
        lines.append("shaping_gap_mean = \(shapingGapMeanMilliseconds)")
        lines.append("shaping_gap_min = \(shapingGapMinMilliseconds)")
        lines.append("shaping_gap_max = \(shapingGapMaxMilliseconds)")
        lines.append("shaping_budget = \(shapingBudgetBytesPerSecond)")
        lines.append("shaping_min_size = \(shapingMinSize)")
        lines.append("shaping_max_size = \(shapingMaxSize)")
        lines.append("shaping_stealth = \(shapingStealth ? "true" : "false")")
        lines.append("shaping_stealth_mbps = \(shapingStealthRateMbps)")
        if appsMode != "all" { lines.append("apps_mode = \(appsMode)") }
        if !apps.isEmpty { lines.append("apps = \(apps.joined(separator: ", "))") }
        if !reconnectEnabled { lines.append("reconnect = false") }
        if reconnectMaxRetries != -1 { lines.append("reconnect_retries = \(reconnectMaxRetries)") }
        if reconnectBaseDelaySeconds != 1 { lines.append("reconnect_base_delay = \(reconnectBaseDelaySeconds)") }
        if reconnectMaxDelaySeconds != 60 { lines.append("reconnect_max_delay = \(reconnectMaxDelaySeconds)") }
        lines.append("timeout = \(connectionTimeoutSeconds)")
        // Re-emit the keys this port accepts but does not model, verbatim and in a stable
        // order. Without this, opening a CLI profile here and saving it deleted its hooks
        // (`post_up`/`post_down`), socket policy and routing policy — silently, and as
        // a side effect of merely opening it. (Audit 2026-08-02, §4 of the follow-up.)
        for key in carriedKeys.keys.sorted() {
            if let value = carriedKeys[key] { lines.append("\(key) = \(value)") }
        }
        // Re-emit [logging] so a desktop/router client.conf survives an edit on the phone.
        if loggingLevel?.nonEmpty != nil || loggingFile?.nonEmpty != nil || loggingTimeFormat?.nonEmpty != nil {
            lines.append("")
            lines.append("[logging]")
            if let value = loggingLevel?.nonEmpty { lines.append("level = \(value)") }
            if let value = loggingFile?.nonEmpty { lines.append("file = \(value)") }
            if let value = loggingTimeFormat?.nonEmpty { lines.append("time_format = \(value)") }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Profile passed to the shared transport owner. iOS preserves foreign desktop keys when
    /// editing a portable profile, but its fail-closed policy is NetworkExtension On Demand,
    /// not the cross-platform `kill_switch` key; do not ask Rust to publish an unenforceable
    /// iOS NetworkPlan requirement.
    func toTransportCoreINI(label: String? = nil) throws -> String {
        let ini = try toINI(label: label)
        return ini.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { line in
                guard let eq = line.firstIndex(of: "=") else { return true }
                return line[..<eq].trimmingCharacters(in: .whitespaces)
                    .caseInsensitiveCompare("kill_switch") != .orderedSame
            }
            .joined(separator: "\n")
    }

    func toQeliURI(label: String? = nil) -> String {
        let auth = "\(Self.percentEncode(username)):\(Self.percentEncode(password))@"
        var query = ["proto=\(Self.percentEncode(protocolName))", "mode=\(Self.percentEncode(wireMode))"]
        if let key = serverPublicKeyHex { query.append("key=\(Self.percentEncode(key))") }
        if let sni { query.append("sni=\(Self.percentEncode(sni))") }
        if let realityShortID { query.append("rsid=\(Self.percentEncode(realityShortID))") }
        if !obfsKey.isEmpty { query.append("obfs=\(Self.percentEncode(obfsKey))") }
        if obfsFronting != "websocket" { query.append("front=\(Self.percentEncode(obfsFronting))") }
        if quicEnabled { query.append("quic=1") }
        if awgEnabled {
            query += ["awg=1", "jc=\(awgJunkCount)", "jmin=\(awgJunkMin)", "jmax=\(awgJunkMax)"]
        }
        if mtu != 0 { query.append("mtu=\(mtu)") }
        let fragment = label?.nonEmpty.map { "#\(Self.percentEncode($0))" } ?? ""
        return "qeli://\(auth)\(Self.formatEndpoint(host: serverAddress, port: port))?\(query.joined(separator: "&"))\(fragment)"
    }

    private static func parseINI(
        _ text: String, duplicates: inout [String]
    ) -> [String: [String: String]] {
        var result: [String: [String: String]] = [:]
        var section: String?
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("["), line.hasSuffix("]") {
                let body = line.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
                section = body.split(separator: ":", maxSplits: 1).first.map(String.init)
                if let section, result[section] == nil { result[section] = [:] }
                continue
            }
            guard let section, let equals = line.firstIndex(of: "=") else { continue }
            let key = line[..<equals].trimmingCharacters(in: .whitespaces)
            var value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }
            if !key.isEmpty {
                // Keep LAST-wins, so a file that never had a duplicate parses exactly as it did
                // before, and record the ambiguity for validate() to refuse.
                let qualified = "\(section).\(key)"
                if result[section, default: [:]][key] != nil, !duplicates.contains(qualified) {
                    duplicates.append(qualified)
                }
                result[section, default: [:]][key] = value
            }
        }
        return result
    }

    private static func parseEndpoint(_ endpoint: String) throws -> (String, Int) {
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]"),
                  endpoint.index(after: close) < endpoint.endIndex,
                  endpoint[endpoint.index(after: close)] == ":",
                  let port = Int(endpoint[endpoint.index(close, offsetBy: 2)...]) else {
                throw VPNConfigError.invalid("IPv6 endpoint must be [host]:port")
            }
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            guard host.contains(":"), isIPLiteral(host) else {
                throw VPNConfigError.invalid("invalid IPv6 endpoint address: \(host)")
            }
            guard (1...65_535).contains(port) else {
                throw VPNConfigError.invalid("server port must be between 1 and 65535")
            }
            return (host, port)
        }
        guard let colon = endpoint.lastIndex(of: ":"),
              colon > endpoint.startIndex,
              let port = Int(endpoint[endpoint.index(after: colon)...]) else {
            throw VPNConfigError.invalid("server must be host:port")
        }
        let host = String(endpoint[..<colon])
        guard !host.contains(":"), !host.contains("["), !host.contains("]") else {
            throw VPNConfigError.invalid("IPv6 endpoint must be bracketed as [address]:port")
        }
        guard (1...65_535).contains(port) else {
            throw VPNConfigError.invalid("server port must be between 1 and 65535")
        }
        return (host, port)
    }

    private static func formatEndpoint(host: String, port: Int) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    private static let unreserved: CharacterSet = {
        var set = CharacterSet.alphanumerics
        set.insert(charactersIn: "-._~")
        return set
    }()

    private static let forbiddenINICharacters = CharacterSet(charactersIn: "\r\n\0")

    private static func containsForbiddenINICharacters(_ value: String) -> Bool {
        value.rangeOfCharacter(from: forbiddenINICharacters) != nil
    }

    private static func percentEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
    }

    private static func percentDecode(_ value: String) -> String {
        value.removingPercentEncoding ?? value
    }
}

enum VPNConfigError: LocalizedError, Equatable {
    case invalid(String)

    var errorDescription: String? {
        switch self { case .invalid(let message): return message }
    }
}

private extension Optional where Wrapped == String {
    var nonEmpty: String? {
        guard let self, !self.isEmpty else { return nil }
        return self
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
