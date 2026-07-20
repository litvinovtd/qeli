import Foundation

struct VPNConfig: Codable, Equatable, Sendable {
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

    var mtu = 0
    var mtuProbe = true
    var routingMode = "full-tunnel"
    var addDefaultGateway = true
    var includeRoutes: [String] = []
    var excludeRoutes: [String] = []
    var routeLocalNetworks = false
    var allowIPv6Leak = false
    var allowLAN = false
    var dnsServers: [String] = []

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

    var isUDP: Bool { protocolName.caseInsensitiveCompare("udp") == .orderedSame }
    var isFullTunnel: Bool { addDefaultGateway || routingMode == "full-tunnel" }

    init(serverAddress: String, port: Int) {
        self.serverAddress = serverAddress
        self.port = port
    }

    init(parsing text: String) throws {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("qeli://") {
            self = try Self.fromQeliURI(trimmed)
        } else if trimmed.hasPrefix("{") {
            self = try Self.fromJSON(trimmed)
        } else {
            self = try Self.fromINI(trimmed)
        }
        try validate()
    }

    func validate() throws {
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
        let listFields: [(String, [String])] = [
            ("include", includeRoutes),
            ("exclude", excludeRoutes),
            ("dns", dnsServers),
            ("apps", apps)
        ]
        for (field, values) in listFields where values.contains(where: Self.containsForbiddenINICharacters) {
            throw VPNConfigError.invalid("\(field) contains a forbidden line break or NUL character")
        }
        guard !serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VPNConfigError.invalid("server host is empty")
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
        if mtu != 0 && !(576...9_000).contains(mtu) {
            throw VPNConfigError.invalid("mtu must be 0 or between 576 and 9000")
        }
        guard paddingMin >= 0, paddingMax >= paddingMin else {
            throw VPNConfigError.invalid("padding range is invalid")
        }
    }

    static func fromINI(_ text: String) throws -> VPNConfig {
        let sections = parseINI(text)
        guard let qeli = sections["qeli"] else {
            throw VPNConfigError.invalid("config is missing [qeli] section")
        }
        guard let endpoint = qeli["server"], !endpoint.isEmpty else {
            throw VPNConfigError.invalid("[qeli] is missing server = host:port")
        }
        let (host, port) = try parseEndpoint(endpoint)
        let bool: (String?) -> Bool = { value in
            guard let value else { return false }
            return ["true", "1", "yes", "on"].contains(value.lowercased())
        }
        let list: (String?) -> [String] = { value in
            value?.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty } ?? []
        }

        var config = VPNConfig(serverAddress: host, port: port)
        config.protocolName = qeli["proto"].nonEmpty ?? "tcp"
        config.connectionTimeoutSeconds = qeli["timeout"].flatMap(Int.init) ?? 30
        config.reconnectEnabled = qeli["reconnect"].map { bool($0) } ?? true
        config.reconnectMaxRetries = qeli["reconnect_retries"].flatMap(Int.init) ?? -1
        config.reconnectBaseDelaySeconds = qeli["reconnect_base_delay"].flatMap(Int.init) ?? 1
        config.reconnectMaxDelaySeconds = qeli["reconnect_max_delay"].flatMap(Int.init) ?? 60
        config.username = qeli["user"].nonEmpty ?? "client"
        config.password = qeli["pass"] ?? ""
        config.serverPublicKeyHex = qeli["key"].nonEmpty
        config.bindStaticToSession = qeli["bind_static"].map { bool($0) } ?? true
        config.mtu = qeli["mtu"].flatMap(Int.init) ?? 0
        config.mtuProbe = qeli["mtu_probe"].map { !["false", "0", "no", "off"].contains($0.lowercased()) } ?? true

        let fullTunnel = qeli["gateway"].map { bool($0) } ?? true
        config.routingMode = fullTunnel ? "full-tunnel" : "split-tunnel"
        config.addDefaultGateway = fullTunnel
        config.includeRoutes = list(qeli["include"])
        config.excludeRoutes = list(qeli["exclude"])
        config.routeLocalNetworks = bool(qeli["route_local"])
        config.allowIPv6Leak = bool(qeli["allow_ipv6_leak"])
        config.allowLAN = bool(qeli["allow_lan"])
        if let dns = qeli["dns"], !["off", "system", "tunnel"].contains(dns.lowercased()) {
            config.dnsServers = list(dns)
        }

        config.wireMode = qeli["mode"].nonEmpty ?? "fake-tls"
        config.sni = qeli["sni"].nonEmpty
        config.realityShortID = qeli["reality_sid"].nonEmpty
        config.obfsKey = qeli["obfs_key"] ?? ""
        config.obfsFronting = qeli["front"].nonEmpty ?? "websocket"
        config.awgEnabled = bool(qeli["awg"])
        config.awgJunkCount = qeli["jc"].flatMap(Int.init) ?? 0
        config.awgJunkMin = qeli["jmin"].flatMap(Int.init) ?? 40
        config.awgJunkMax = qeli["jmax"].flatMap(Int.init) ?? 300
        config.quicEnabled = bool(qeli["quic"])

        config.paddingEnabled = qeli["padding"].map { bool($0) } ?? true
        config.paddingMin = qeli["padding_min"].flatMap(Int.init) ?? 0
        config.paddingMax = qeli["padding_max"].flatMap(Int.init) ?? 255
        config.heartbeatEnabled = qeli["heartbeat"].map { bool($0) } ?? true
        config.heartbeatIntervalMilliseconds = qeli["heartbeat_interval"].flatMap(Int.init) ?? 15_000
        config.heartbeatDataSize = qeli["heartbeat_size"].flatMap(Int.init) ?? 16
        config.heartbeatJitterMilliseconds = qeli["heartbeat_jitter"].flatMap(Int.init) ?? 2_000

        config.shapingEnabled = bool(qeli["shaping"])
        config.shapingGapMeanMilliseconds = qeli["shaping_gap_mean"].flatMap(Int.init) ?? 700
        config.shapingGapMinMilliseconds = qeli["shaping_gap_min"].flatMap(Int.init) ?? 40
        config.shapingGapMaxMilliseconds = qeli["shaping_gap_max"].flatMap(Int.init) ?? 6_000
        config.shapingBudgetBytesPerSecond = qeli["shaping_budget"].flatMap(Int.init) ?? 16_384
        config.shapingMinSize = qeli["shaping_min_size"].flatMap(Int.init) ?? 64
        config.shapingMaxSize = qeli["shaping_max_size"].flatMap(Int.init) ?? 1_024
        config.shapingStealth = bool(qeli["shaping_stealth"])
        config.shapingStealthRateMbps = qeli["shaping_stealth_mbps"].flatMap(Int.init) ?? 2

        let mode = qeli["apps_mode"]?.lowercased() ?? "all"
        config.appsMode = ["include", "exclude"].contains(mode) ? mode : "all"
        config.apps = list(qeli["apps"])
        return config
    }

    static func fromJSON(_ text: String) throws -> VPNConfig {
        guard let data = text.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw VPNConfigError.invalid("profile JSON is invalid")
        }
        func dict(_ key: String, in parent: [String: Any] = root) -> [String: Any] {
            parent[key] as? [String: Any] ?? [:]
        }
        func string(_ key: String, in parent: [String: Any], default fallback: String = "") -> String {
            parent[key] as? String ?? fallback
        }
        func int(_ key: String, in parent: [String: Any], default fallback: Int) -> Int {
            (parent[key] as? NSNumber)?.intValue ?? fallback
        }
        func bool(_ key: String, in parent: [String: Any], default fallback: Bool) -> Bool {
            (parent[key] as? NSNumber)?.boolValue ?? fallback
        }
        func strings(_ key: String, in parent: [String: Any]) -> [String] {
            parent[key] as? [String] ?? []
        }

        let server = dict("server")
        let reconnect = dict("reconnect", in: server)
        let auth = dict("auth")
        let tun = dict("tun")
        let routing = dict("routing")
        let dns = dict("dns")
        let obfuscation = dict("obfuscation")
        let padding = dict("padding", in: obfuscation)
        let heartbeat = dict("heartbeat", in: obfuscation)
        let quic = dict("quic", in: obfuscation)
        let awg = dict("awg", in: obfuscation)
        let shaping = dict("shaping", in: obfuscation)

        var config = VPNConfig(
            serverAddress: string("address", in: server, default: string("address", in: root, default: "127.0.0.1")),
            port: int("port", in: server, default: int("port", in: root, default: 443))
        )
        config.protocolName = string("protocol", in: server, default: "tcp")
        config.connectionTimeoutSeconds = int("connection_timeout_secs", in: server, default: 30)
        config.reconnectEnabled = bool("enabled", in: reconnect, default: true)
        config.reconnectMaxRetries = int("max_retries", in: reconnect, default: -1)
        config.reconnectBaseDelaySeconds = int("base_delay_secs", in: reconnect, default: 1)
        config.reconnectMaxDelaySeconds = int("max_delay_secs", in: reconnect, default: 60)
        config.username = string("username", in: auth, default: string("username", in: root, default: "client"))
        config.password = string("password", in: auth, default: string("password", in: root))
        config.serverPublicKeyHex = string("server_public_key", in: auth).nonEmpty
        config.bindStaticToSession = bool("bind_static_to_session", in: auth, default: true)
        config.mtu = int("mtu", in: tun, default: 0)
        config.routingMode = string("mode", in: routing, default: "full-tunnel")
        config.addDefaultGateway = bool("add_default_gateway", in: routing, default: config.routingMode == "full-tunnel")
        config.includeRoutes = strings("include", in: routing)
        config.excludeRoutes = strings("exclude", in: routing)
        config.routeLocalNetworks = bool("route_local_networks", in: routing, default: false)
        config.allowIPv6Leak = bool("allow_ipv6_leak", in: routing, default: false)
        config.allowLAN = bool("allow_lan", in: routing, default: false)
        config.dnsServers = strings("servers", in: dns)
        config.wireMode = string("mode", in: obfuscation, default: "fake-tls")
        config.obfsKey = string("obfs_key", in: obfuscation)
        config.obfsFronting = string("fronting", in: obfuscation, default: "websocket")
        config.sni = string("sni", in: obfuscation).nonEmpty
        config.realityShortID = string("reality_short_id", in: obfuscation).nonEmpty
        config.paddingEnabled = bool("enabled", in: padding, default: true)
        config.paddingMin = int("min_bytes", in: padding, default: 0)
        config.paddingMax = int("max_bytes", in: padding, default: 255)
        config.heartbeatEnabled = bool("enabled", in: heartbeat, default: true)
        config.heartbeatIntervalMilliseconds = int("interval_ms", in: heartbeat, default: 15_000)
        config.heartbeatDataSize = int("data_size_bytes", in: heartbeat, default: 16)
        config.heartbeatJitterMilliseconds = int("jitter_ms", in: heartbeat, default: 2_000)
        config.quicEnabled = bool("enabled", in: quic, default: false)
        config.awgEnabled = bool("enabled", in: awg, default: false)
        config.awgJunkCount = int("jc", in: awg, default: 0)
        config.awgJunkMin = int("jmin", in: awg, default: 40)
        config.awgJunkMax = int("jmax", in: awg, default: 300)
        config.shapingEnabled = bool("enabled", in: shaping, default: false)
        config.shapingGapMeanMilliseconds = int("gap_mean_ms", in: shaping, default: 700)
        config.shapingGapMinMilliseconds = int("gap_min_ms", in: shaping, default: 40)
        config.shapingGapMaxMilliseconds = int("gap_max_ms", in: shaping, default: 6_000)
        config.shapingBudgetBytesPerSecond = int("budget_bytes_per_sec", in: shaping, default: 16_384)
        config.shapingMinSize = int("min_size", in: shaping, default: 64)
        config.shapingMaxSize = int("max_size", in: shaping, default: 1_024)
        config.shapingStealth = bool("stealth", in: shaping, default: false)
        config.shapingStealthRateMbps = int("stealth_rate_mbps", in: shaping, default: 2)
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
            case "mtu": config.mtu = Int(value) ?? 0
            default: break
            }
        }
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
        if !isFullTunnel { lines.append("gateway = false") }
        if !includeRoutes.isEmpty { lines.append("include = \(includeRoutes.joined(separator: ","))") }
        if !excludeRoutes.isEmpty { lines.append("exclude = \(excludeRoutes.joined(separator: ","))") }
        if routeLocalNetworks { lines.append("route_local = true") }
        if allowIPv6Leak { lines.append("allow_ipv6_leak = true") }
        if allowLAN { lines.append("allow_lan = true") }
        if !dnsServers.isEmpty { lines.append("dns = \(dnsServers.joined(separator: ","))") }
        if !paddingEnabled { lines.append("padding = false") }
        if paddingMin != 0 { lines.append("padding_min = \(paddingMin)") }
        if paddingMax != 255 { lines.append("padding_max = \(paddingMax)") }
        if !heartbeatEnabled { lines.append("heartbeat = false") }
        if heartbeatIntervalMilliseconds != 15_000 { lines.append("heartbeat_interval = \(heartbeatIntervalMilliseconds)") }
        if heartbeatDataSize != 16 { lines.append("heartbeat_size = \(heartbeatDataSize)") }
        if heartbeatJitterMilliseconds != 2_000 { lines.append("heartbeat_jitter = \(heartbeatJitterMilliseconds)") }
        if shapingEnabled { lines.append("shaping = true") }
        if shapingGapMeanMilliseconds != 700 { lines.append("shaping_gap_mean = \(shapingGapMeanMilliseconds)") }
        if shapingGapMinMilliseconds != 40 { lines.append("shaping_gap_min = \(shapingGapMinMilliseconds)") }
        if shapingGapMaxMilliseconds != 6_000 { lines.append("shaping_gap_max = \(shapingGapMaxMilliseconds)") }
        if shapingBudgetBytesPerSecond != 16_384 { lines.append("shaping_budget = \(shapingBudgetBytesPerSecond)") }
        if shapingMinSize != 64 { lines.append("shaping_min_size = \(shapingMinSize)") }
        if shapingMaxSize != 1_024 { lines.append("shaping_max_size = \(shapingMaxSize)") }
        if shapingStealth { lines.append("shaping_stealth = true") }
        if shapingStealthRateMbps != 2 { lines.append("shaping_stealth_mbps = \(shapingStealthRateMbps)") }
        if appsMode != "all" { lines.append("apps_mode = \(appsMode)") }
        if !apps.isEmpty { lines.append("apps = \(apps.joined(separator: ","))") }
        if !reconnectEnabled { lines.append("reconnect = false") }
        if reconnectMaxRetries != -1 { lines.append("reconnect_retries = \(reconnectMaxRetries)") }
        if reconnectBaseDelaySeconds != 1 { lines.append("reconnect_base_delay = \(reconnectBaseDelaySeconds)") }
        if reconnectMaxDelaySeconds != 60 { lines.append("reconnect_max_delay = \(reconnectMaxDelaySeconds)") }
        if connectionTimeoutSeconds != 30 { lines.append("timeout = \(connectionTimeoutSeconds)") }
        return lines.joined(separator: "\n") + "\n"
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

    private static func parseINI(_ text: String) -> [String: [String: String]] {
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
            if !key.isEmpty { result[section, default: [:]][key] = value }
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
            return (String(endpoint[endpoint.index(after: endpoint.startIndex)..<close]), port)
        }
        guard let colon = endpoint.lastIndex(of: ":"),
              colon > endpoint.startIndex,
              let port = Int(endpoint[endpoint.index(after: colon)...]) else {
            throw VPNConfigError.invalid("server must be host:port")
        }
        return (String(endpoint[..<colon]), port)
    }

    private static func formatEndpoint(host: String, port: Int) -> String {
        host.contains(":") && !host.hasPrefix("[") ? "[\(host)]:\(port)" : "\(host):\(port)"
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
