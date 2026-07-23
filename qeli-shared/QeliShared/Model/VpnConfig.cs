using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Qeli.Shared.Model;

/// <summary>Reachability of a profile's server, shown as a colored dot on the card.</summary>
public enum ProfileReachability { Unknown, Checking, Reachable, Unreachable }

/// <summary>
/// Full qeli client configuration. Mirrors the relevant fields of the Rust
/// ClientConfig and the Android VpnConfig. Built from the simple UI fields, an
/// imported JSON config (FromJson) or a qeli:// share link (FromQeliUri).
/// </summary>
public sealed class VpnConfig : INotifyPropertyChanged
{
    [field: JsonIgnore]
    public event PropertyChangedEventHandler? PropertyChanged;

    private ProfileReachability _reachability = ProfileReachability.Unknown;
    private int? _latencyMs;

    /// <summary>Live server reachability (UI only); raises change notifications.</summary>
    [JsonIgnore]
    public ProfileReachability Reachability
    {
        get => _reachability;
        set
        {
            if (_reachability == value) return;
            _reachability = value;
            Notify(nameof(Reachability));
            Notify(nameof(LatencyText));
        }
    }

    /// <summary>Last measured TCP latency in ms (UI only).</summary>
    [JsonIgnore]
    public int? LatencyMs
    {
        get => _latencyMs;
        set { _latencyMs = value; Notify(nameof(LatencyText)); }
    }

    /// <summary>Badge text for the profile card: "38 ms" / "offline" / "…" / "".</summary>
    [JsonIgnore]
    public string LatencyText => _reachability switch
    {
        ProfileReachability.Reachable => _latencyMs is int ms ? $"{ms} ms" : "ok",
        ProfileReachability.Unreachable => Qeli.Shared.Loc.T("Offline"),
        ProfileReachability.Checking => "…",
        _ => "",
    };

    private void Notify(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    // server
    public string ServerAddress { get; init; } = "127.0.0.1";
    public int Port { get; init; } = 443;
    public string Protocol { get; init; } = "tcp";       // "tcp" | "udp"
    public long ConnectionTimeoutSecs { get; init; } = 30;
    // OpenVPN-parity outbound-socket binding (issue #69). LocalAddress = bind the carrier
    // socket to a specific local IP (multi-homed host / pick egress NIC; OpenVPN `local`);
    // LocalPort = bind to a fixed local source port (OpenVPN `lport`) for firewall rules.
    // Empty / 0 = OS default (any address, ephemeral port).
    public string? LocalAddress { get; init; }
    public int LocalPort { get; init; }
    // reconnect
    public bool ReconnectEnabled { get; init; } = true;
    public int ReconnectMaxRetries { get; init; } = -1;
    public long ReconnectBaseDelaySecs { get; init; } = 1;
    public long ReconnectMaxDelaySecs { get; init; } = 60;
    // auth
    public string Username { get; init; } = "client";
    public string Password { get; init; } = "";
    public string? ServerPublicKeyHex { get; init; }     // pinned static key (hex), null = TOFU
    // H-1: bind data keys to the server static identity (folds es into the KDF).
    // Must match the server's auth.bind_static_to_session and requires a pinned key.
    // Default TRUE (secure-by-default since 0.7.1); wire-breaking — set false (or
    // pass bind_static=false) to talk to a legacy 0.7.0 / TOFU server.
    public bool BindStaticToSession { get; init; } = true;
    // tun
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    public int Mtu { get; init; } = 0;
    // Active UDP path-MTU probing when Mtu == 0 (default on; kill switch = false). No
    // effect on TCP transports (the OS does PMTUD there) or when Mtu > 0 (explicit).
    public bool MtuProbe { get; init; } = true;
    // routing
    public string RoutingMode { get; init; } = "full-tunnel";
    public bool AddDefaultGateway { get; init; } = true;
    public List<string> IncludeRoutes { get; init; } = new();
    public List<string> ExcludeRoutes { get; init; } = new();
    public bool RouteLocalNetworks { get; init; }
    // Extra split-tunnel routes loaded from a FILE of CIDRs (one per line, '#'/';'
    // comments allowed) — OpenVPN's route-include-from-file. Merged with IncludeRoutes at
    // tunnel setup. Empty = none.
    public string? RouteFile { get; init; }
    // TUN interface routing metric (OpenVPN `route-metric` / a lower value = higher
    // priority). 0 = OS default. Applied to the tunnel adapter after addressing.
    public int InterfaceMetric { get; init; }
    // Force a specific TUN adapter name (OpenVPN `dev-node`). Windows: names the Wintun
    // adapter instead of the auto-derived Qeli-<hash>. Empty = auto.
    public string? DevNode { get; init; }
    // OpenVPN-style persist-tun: keep the TUN adapter + routes UP across reconnects
    // (until the user disconnects) instead of tearing them down and recreating them each
    // attempt. Avoids the adapter flicker + the brief route gap on every reconnect, and
    // fails closed (no physical-NIC leak) during the reconnect window. Off by default.
    public bool PersistTun { get; init; }
    // #13: enable OS IP forwarding on THIS node (no NAT) so a LAN behind the client is
    // routable through the tunnel (site-to-site). macOS: net.inet.ip.forwarding=1; Windows:
    // per-interface netsh forwarding (best-effort). Mirrors the Rust client's routing.forward.
    public bool Forward { get; init; }
    // Firewall kill-switch (full-tunnel only): block ALL egress except the tunnel,
    // the server, DNS and DHCP while connected, so a tunnel drop can't leak traffic
    // onto the physical NIC during reconnect. Platform-specific (Win: Windows
    // Firewall default-block + allow rules; mac: pf anchor). Default off.
    public bool KillSwitch { get; init; }
    // Full-tunnel captures IPv6 into the tunnel (the server is IPv4-only, so it is black-holed)
    // to close the classic dual-stack IPv6 leak. Set true to OPT OUT — a dual-stack user who
    // wants native IPv6, accepting that it bypasses the tunnel. Default off (fail-closed);
    // mirrors the Rust client's `allow_ipv6_leak`.
    public bool AllowIpv6Leak { get; init; }
    // dns — empty by default so a config the user never gave DNS round-trips WITHOUT a
    // `dns = 1.1.1.1, 8.8.8.8` line and the server-pushed DNS (dns.push_servers) is honoured.
    // The public-resolver fallback moved to connect time (SetupTun): explicit > server-pushed
    // > 1.1.1.1/8.8.8.8 (full-tunnel only). See the per-platform SetupTun DNS block.
    public List<string> DnsServers { get; init; } = new();
    // obfuscation
    public string WireMode { get; init; } = "fake-tls";  // "fake-tls" | "obfs" | "reality-tls" | "plain"
    public string ObfsKey { get; init; } = "";
    // obfs anti-FET fronting: "websocket" (default) wraps the nonce exchange in a
    // WebSocket Upgrade handshake; "none" is the legacy raw nonce. Must match the
    // server. Mirrors ClientObfuscationConfig::fronting (Rust) / VpnConfig.obfsFronting (Android).
    public string ObfsFronting { get; init; } = "websocket";
    // F2 AmneziaWG-style pre-handshake junk (obfs mode). OFF by default → zero extra
    // bytes on the wire (byte-identical to the pre-F2 wire). Both ends MUST agree on
    // AwgJc (the junk-record count); AwgJmin/AwgJmax bound each record's random length
    // and are sender-only. Mirrors the Rust AwgParams / obf.awg.* config.
    public bool AwgEnabled { get; init; }
    public uint AwgJc { get; init; }              // record count (cap 128); 0 = disabled
    public ushort AwgJmin { get; init; } = 40;    // min junk-record length
    public ushort AwgJmax { get; init; } = 300;   // max junk-record length (jmin<=jmax<=1400)
    public bool QuicEnabled { get; init; }
    public string? Sni { get; init; }
    // REALITY short_id (hex) — pairs with ServerPublicKeyHex to seal the auth
    // token into the realtls ClientHello (WireMode = "reality-tls").
    public string? RealityShortId { get; init; }
    // padding
    public bool PaddingEnabled { get; init; } = true;
    public int PaddingMin { get; init; }
    public int PaddingMax { get; init; } = 255;
    // heartbeat
    public bool HeartbeatEnabled { get; init; } = true;
    public long HeartbeatIntervalMs { get; init; } = 15000;
    public int HeartbeatDataSize { get; init; } = 16;
    public long HeartbeatJitterMs { get; init; } = 2000;
    // flow shaping (idle cover traffic; DPI-AUDIT 6.1/6.2). Normally pushed from
    // the server. Defaults mirror the Rust TrafficShapingConfig.
    public bool ShapingEnabled { get; init; }
    public long ShapingGapMeanMs { get; init; } = 700;
    public long ShapingGapMinMs { get; init; } = 40;
    public long ShapingGapMaxMs { get; init; } = 6000;
    public int ShapingBudgetBytesPerSec { get; init; } = 16384;
    public int ShapingMinSize { get; init; } = 64;
    public int ShapingMaxSize { get; init; } = 1024;
    // Stealth (Phase 2): rate-cap the data plane + cover under load. TCP-only.
    public bool ShapingStealth { get; init; }
    public int ShapingStealthRateMbps { get; init; } = 2;

    // Optional display label (UI only).
    public string? Name { get; set; }

    /// <summary>Stable unique profile id (GUID hex). Profiles are referenced by this
    /// in app settings (service / auto-connect) instead of by DisplayName — two
    /// accounts on the SAME server share a DisplayName, so a name-based lookup would
    /// silently pick the wrong one (connect as user2 when user3 was chosen). Persisted;
    /// an old profile without one gets a fresh id on first load and is saved back.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    [JsonIgnore]
    public string DisplayName =>
        // A distinct label wins; otherwise fall back to "server (user)" so two accounts
        // on the same server are DISTINGUISHABLE in the list and settings dropdowns
        // (the bare ServerAddress collided). Imported INI configs default Name to the
        // host, so treat Name == ServerAddress as "no distinct label" too.
        (!string.IsNullOrWhiteSpace(Name) && Name != ServerAddress)
            ? Name!
            : $"{ServerAddress} ({Username})";

    [JsonIgnore]
    public string Endpoint => $"{ServerAddress}:{Port} · {Protocol.ToUpperInvariant()} · {WireMode}";

    [JsonIgnore]
    public bool IsUdp => Protocol.Equals("udp", StringComparison.OrdinalIgnoreCase);

    [JsonIgnore]
    public bool IsFullTunnel =>
        AddDefaultGateway || RoutingMode.Equals("full-tunnel", StringComparison.OrdinalIgnoreCase);

    /// <summary>Clone applying server-pushed heartbeat + flow-shaping params after auth.</summary>
    public VpnConfig WithPushedObf(bool hbEnabled, long hbIntervalMs, long hbJitterMs,
        bool shEnabled, long shGapMeanMs, long shGapMinMs, long shGapMaxMs,
        int shBudget, int shMinSize, int shMaxSize,
        bool shStealth, int shStealthRateMbps) => new()
    {
        ServerAddress = ServerAddress, Port = Port, Protocol = Protocol,
        ConnectionTimeoutSecs = ConnectionTimeoutSecs,
        LocalAddress = LocalAddress, LocalPort = LocalPort,
        RouteFile = RouteFile, InterfaceMetric = InterfaceMetric, DevNode = DevNode,
        ReconnectEnabled = ReconnectEnabled, ReconnectMaxRetries = ReconnectMaxRetries,
        ReconnectBaseDelaySecs = ReconnectBaseDelaySecs, ReconnectMaxDelaySecs = ReconnectMaxDelaySecs,
        Username = Username, Password = Password, ServerPublicKeyHex = ServerPublicKeyHex,
        BindStaticToSession = BindStaticToSession,
        Mtu = Mtu, MtuProbe = MtuProbe, RoutingMode = RoutingMode, AddDefaultGateway = AddDefaultGateway,
        IncludeRoutes = IncludeRoutes, ExcludeRoutes = ExcludeRoutes, RouteLocalNetworks = RouteLocalNetworks,
        PersistTun = PersistTun, KillSwitch = KillSwitch, AllowIpv6Leak = AllowIpv6Leak, Forward = Forward,
        DnsServers = DnsServers, WireMode = WireMode, ObfsKey = ObfsKey, ObfsFronting = ObfsFronting,
        AwgEnabled = AwgEnabled, AwgJc = AwgJc, AwgJmin = AwgJmin, AwgJmax = AwgJmax,
        QuicEnabled = QuicEnabled, Sni = Sni,
        RealityShortId = RealityShortId,
        PaddingEnabled = PaddingEnabled, PaddingMin = PaddingMin, PaddingMax = PaddingMax,
        HeartbeatEnabled = hbEnabled, HeartbeatIntervalMs = hbIntervalMs,
        HeartbeatDataSize = HeartbeatDataSize, HeartbeatJitterMs = hbJitterMs,
        ShapingEnabled = shEnabled, ShapingGapMeanMs = shGapMeanMs, ShapingGapMinMs = shGapMinMs,
        ShapingGapMaxMs = shGapMaxMs, ShapingBudgetBytesPerSec = shBudget,
        ShapingMinSize = shMinSize, ShapingMaxSize = shMaxSize,
        ShapingStealth = shStealth, ShapingStealthRateMbps = shStealthRateMbps,
        Name = Name, Id = Id,
    };

    /// <summary>Clone applying the fields the profile editor's FORM edits, preserving every
    /// other field from `this` (OpenVPN local/lport/dev_node/metric/route_file/persist_tun,
    /// kill-switch, AWG, reconnect, shaping, Id, …). The editor rebuilds a config on Save;
    /// without this, any field with no form control — e.g. set via the manual INI editor or
    /// import — was silently dropped (issue #69).</summary>
    public VpnConfig WithEditorFields(
        string? name, string serverAddress, int port, string protocol, string wireMode,
        string obfsKey, string obfsFronting, string? realityShortId, string? sni, bool quicEnabled,
        string username, string password, string? serverPublicKeyHex,
        string routingMode, bool addDefaultGateway, bool routeLocalNetworks,
        int mtu, List<string> dnsServers,
        bool paddingEnabled, int paddingMin, int paddingMax,
        bool heartbeatEnabled, long heartbeatIntervalMs, long heartbeatJitterMs) => new()
    {
        // ── form-edited fields (from params) ──
        ServerAddress = serverAddress, Port = port, Protocol = protocol, WireMode = wireMode,
        ObfsKey = obfsKey, ObfsFronting = obfsFronting, RealityShortId = realityShortId,
        Sni = sni, QuicEnabled = quicEnabled,
        Username = username, Password = password, ServerPublicKeyHex = serverPublicKeyHex,
        RoutingMode = routingMode, AddDefaultGateway = addDefaultGateway, RouteLocalNetworks = routeLocalNetworks,
        Mtu = mtu, DnsServers = dnsServers,
        PaddingEnabled = paddingEnabled, PaddingMin = paddingMin, PaddingMax = paddingMax,
        HeartbeatEnabled = heartbeatEnabled, HeartbeatIntervalMs = heartbeatIntervalMs, HeartbeatJitterMs = heartbeatJitterMs,
        Name = name,
        // ── preserved from `this` (no form control) ──
        Id = Id, ConnectionTimeoutSecs = ConnectionTimeoutSecs,
        LocalAddress = LocalAddress, LocalPort = LocalPort,
        RouteFile = RouteFile, InterfaceMetric = InterfaceMetric, DevNode = DevNode,
        ReconnectEnabled = ReconnectEnabled, ReconnectMaxRetries = ReconnectMaxRetries,
        ReconnectBaseDelaySecs = ReconnectBaseDelaySecs, ReconnectMaxDelaySecs = ReconnectMaxDelaySecs,
        BindStaticToSession = BindStaticToSession, MtuProbe = MtuProbe,
        IncludeRoutes = IncludeRoutes, ExcludeRoutes = ExcludeRoutes,
        PersistTun = PersistTun, KillSwitch = KillSwitch, AllowIpv6Leak = AllowIpv6Leak, Forward = Forward,
        AwgEnabled = AwgEnabled, AwgJc = AwgJc, AwgJmin = AwgJmin, AwgJmax = AwgJmax,
        HeartbeatDataSize = HeartbeatDataSize,
        ShapingEnabled = ShapingEnabled, ShapingGapMeanMs = ShapingGapMeanMs, ShapingGapMinMs = ShapingGapMinMs,
        ShapingGapMaxMs = ShapingGapMaxMs, ShapingBudgetBytesPerSec = ShapingBudgetBytesPerSec,
        ShapingMinSize = ShapingMinSize, ShapingMaxSize = ShapingMaxSize,
        ShapingStealth = ShapingStealth, ShapingStealthRateMbps = ShapingStealthRateMbps,
    };

    // REMOVED: ToConfigJson(). It had no call sites anywhere in the tree, and what it
    // produced was wrong: `routing.mode` was hardcoded to "full-tunnel" with
    // `add_default_gateway: true` regardless of the profile's real routing, and it
    // dropped most of the fields FromJson reads back (kill-switch, persist-tun,
    // include/exclude routes, reconnect, shaping, heartbeat, bind_static, mtu_probe…).
    // Anyone who called it would have silently rewritten a split-tunnel profile into a
    // full-tunnel one. Deleted rather than half-fixed: writing ~30 fields of untested
    // serialization for a method nobody calls just moves the trap. Reinstate it against
    // FromJson field-by-field, with a round-trip test, if a caller ever needs it. (Shared)
    /// <summary>Bracket-wrap a bare IPv6 literal for a URI authority (RFC 3986:
    /// <c>qeli://user@[2001:db8::1]:443</c>); IPv4 / hostnames pass through unchanged.</summary>
    private static string UriHost(string host) =>
        host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;

    /// <summary>Build a compact qeli:// share link (inverse of FromQeliUri).</summary>
    public string ToQeliUri()
    {
        var sb = new StringBuilder("qeli://");
        sb.Append(Uri.EscapeDataString(Username));
        if (!string.IsNullOrEmpty(Password)) sb.Append(':').Append(Uri.EscapeDataString(Password));
        sb.Append('@').Append(UriHost(ServerAddress)).Append(':').Append(Port);

        var q = new List<string> { $"proto={Protocol}", $"mode={WireMode}" };
        if (!string.IsNullOrEmpty(ServerPublicKeyHex)) q.Add($"key={ServerPublicKeyHex}");
        if (!string.IsNullOrEmpty(Sni)) q.Add($"sni={Uri.EscapeDataString(Sni)}");
        if (!string.IsNullOrEmpty(RealityShortId)) q.Add($"rsid={Uri.EscapeDataString(RealityShortId)}");
        if (!string.IsNullOrEmpty(ObfsKey)) q.Add($"obfs={Uri.EscapeDataString(ObfsKey)}");
        // F2 AmneziaWG junk: emit only when enabled (off = byte-identical, no params).
        if (AwgEnabled)
        {
            q.Add("awg=1");
            q.Add($"jc={AwgJc}");
            q.Add($"jmin={AwgJmin}");
            q.Add($"jmax={AwgJmax}");
        }
        // QUIC masking is required for a udp+quic profile — without it the link
        // round-trips to plain UDP and a quic-mode server stays silent.
        if (QuicEnabled) q.Add("quic=1");
        if (Mtu > 0) q.Add($"mtu={Mtu}");  // 0 = auto, omit
        sb.Append('?').Append(string.Join("&", q));

        if (!string.IsNullOrWhiteSpace(Name)) sb.Append('#').Append(Uri.EscapeDataString(Name!));
        return sb.ToString();
    }

    /// <summary>Serialize to the flat-INI qeli config (inverse of FromIni).</summary>
    /// <summary>
    /// Strip control characters (incl. CR/LF) from a value before it goes into the
    /// flat-INI. This file is line-oriented, so a newline inside any value ends the
    /// line early and everything after it is read back as a NEW key — and the keys that
    /// matter (`password_command`, `post_up`) are executed through a shell by the
    /// client. A profile name or password pasted from elsewhere is enough to smuggle
    /// one in. Mirrors `ini_sanitize` in the OpenWrt init script. (Shared)
    /// </summary>
    private static string IniSafe(string? v) =>
        v is null ? "" : new string(v.Where(c => !char.IsControl(c)).ToArray());

    public string ToIni()
    {
        var sb = new StringBuilder();
        sb.AppendLine("[qeli]");
        if (!string.IsNullOrWhiteSpace(Name)) sb.AppendLine($"name = {IniSafe(Name)}");
        sb.AppendLine($"server = {IniSafe(ServerAddress)}:{Port}");
        sb.AppendLine($"proto = {IniSafe(Protocol)}");
        sb.AppendLine($"user = {IniSafe(Username)}");
        sb.AppendLine($"pass = {IniSafe(Password)}");
        if (!string.IsNullOrEmpty(ServerPublicKeyHex)) sb.AppendLine($"key = {IniSafe(ServerPublicKeyHex)}");
        if (!BindStaticToSession) sb.AppendLine("bind_static = false");  // on by default; emit only when off
        sb.AppendLine($"mode = {IniSafe(WireMode)}");
        if (!string.IsNullOrEmpty(ObfsKey)) sb.AppendLine($"obfs_key = {IniSafe(ObfsKey)}");
        if (!string.IsNullOrEmpty(Sni)) sb.AppendLine($"sni = {IniSafe(Sni)}");
        if (!string.IsNullOrEmpty(RealityShortId)) sb.AppendLine($"reality_sid = {IniSafe(RealityShortId)}");
        // Only emit `front` when it diverges from the default, mirroring Rust to_ini_string.
        if (!string.IsNullOrEmpty(ObfsFronting) && ObfsFronting != "websocket") sb.AppendLine($"front = {IniSafe(ObfsFronting)}");
        // F2 AmneziaWG junk: emit only when enabled (off by default → nothing on the wire).
        if (AwgEnabled)
        {
            sb.AppendLine("awg = true");
            sb.AppendLine($"jc = {AwgJc}");
            sb.AppendLine($"jmin = {AwgJmin}");
            sb.AppendLine($"jmax = {AwgJmax}");
        }
        if (QuicEnabled) sb.AppendLine("quic = true");
        // Routing: emit `gateway = false` only for split-tunnel so the choice survives
        // a save/export round-trip (mirrors the Rust/Android client's `gateway` key).
        if (!IsFullTunnel) sb.AppendLine("gateway = false");
        if (RouteLocalNetworks) sb.AppendLine("route_local = true");
        if (IncludeRoutes.Count > 0) sb.AppendLine($"include = {string.Join(", ", IncludeRoutes.Select(IniSafe))}");
        if (ExcludeRoutes.Count > 0) sb.AppendLine($"exclude = {string.Join(", ", ExcludeRoutes.Select(IniSafe))}");
        if (PersistTun) sb.AppendLine("persist_tun = true");
        if (Forward) sb.AppendLine("forward = true");
        if (KillSwitch) sb.AppendLine("kill_switch = true");
        if (AllowIpv6Leak) sb.AppendLine("allow_ipv6_leak = true");
        if (!string.IsNullOrEmpty(LocalAddress)) sb.AppendLine($"local = {IniSafe(LocalAddress)}");
        if (LocalPort > 0) sb.AppendLine($"lport = {LocalPort}");
        if (!string.IsNullOrEmpty(RouteFile)) sb.AppendLine($"route_file = {IniSafe(RouteFile)}");
        if (InterfaceMetric > 0) sb.AppendLine($"metric = {InterfaceMetric}");
        if (!string.IsNullOrEmpty(DevNode)) sb.AppendLine($"dev_node = {IniSafe(DevNode)}");
        if (DnsServers.Count > 0) sb.AppendLine($"dns = {string.Join(", ", DnsServers.Select(IniSafe))}");
        if (Mtu > 0) sb.AppendLine($"mtu = {Mtu}");  // 0 = auto, omit
        if (!MtuProbe) sb.AppendLine("mtu_probe = false");  // default true, emit only when off
        return sb.ToString();
    }

    /// <summary>Deep copy (for "Duplicate"). Runtime-only fields reset to defaults.
    /// A duplicate is a DISTINCT profile, so it gets a fresh <see cref="Id"/>.</summary>
    public VpnConfig Clone()
    {
        var c = JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(this))!;
        c.Id = Guid.NewGuid().ToString("N");
        return c;
    }

    /// <summary>
    /// Parse a config in any supported format, detecting by content: a qeli://
    /// share link, legacy JSON ({…}), or the canonical flat-INI (everything else).
    /// INI is the current format; JSON is only kept for backward compatibility.
    /// Mirrors the Android VpnConfig.parse.
    /// </summary>
    public static VpnConfig Parse(string text)
    {
        var t = text.TrimStart();
        if (t.StartsWith("qeli://", StringComparison.OrdinalIgnoreCase)) return FromQeliUri(text);
        if (t.StartsWith("{")) return FromJson(text);
        return FromIni(text);
    }

    public static VpnConfig FromJson(string text)
    {
        var root = JsonNode.Parse(text)!.AsObject();
        var server = Obj(root, "server");
        var reconnect = Obj(server, "reconnect");
        var auth = Obj(root, "auth");
        var tun = Obj(root, "tun");
        var routing = Obj(root, "routing");
        var dns = Obj(root, "dns");
        var obf = Obj(root, "obfuscation");
        var padding = Obj(obf, "padding");
        var heartbeat = Obj(obf, "heartbeat");
        var quic = Obj(obf, "quic");
        var awg = Obj(obf, "awg");

        string password = StrOrNull(auth, "password") ?? StrOrNull(root, "password") ?? "";

        return new VpnConfig
        {
            Name = StrOrNull(root, "name"),
            ServerAddress = Str(server, "address", Str(root, "address", "127.0.0.1")),
            Port = Int(server, "port", Int(root, "port", 443)),
            Protocol = Str(server, "protocol", "tcp"),
            ConnectionTimeoutSecs = Long(server, "connection_timeout_secs", 30),
            ReconnectEnabled = Bool(reconnect, "enabled", true),
            ReconnectMaxRetries = Int(reconnect, "max_retries", -1),
            ReconnectBaseDelaySecs = Long(reconnect, "base_delay_secs", 1),
            ReconnectMaxDelaySecs = Long(reconnect, "max_delay_secs", 60),
            Username = Str(auth, "username", Str(root, "username", "client")),
            Password = password,
            ServerPublicKeyHex = StrOrNull(auth, "server_public_key"),
            BindStaticToSession = Bool(auth, "bind_static_to_session", true),
            Mtu = Int(tun, "mtu", 0),  // 0 = auto (use server-pushed MTU)
            RoutingMode = Str(routing, "mode", "full-tunnel"),
            AddDefaultGateway = Bool(routing, "add_default_gateway", false),
            IncludeRoutes = StrList(routing, "include"),
            ExcludeRoutes = StrList(routing, "exclude"),
            RouteLocalNetworks = Bool(routing, "route_local_networks", false),
            KillSwitch = Bool(routing, "kill_switch", false),
            AllowIpv6Leak = Bool(routing, "allow_ipv6_leak", false),
            DnsServers = StrList(dns, "servers"),
            WireMode = Str(obf, "mode", "fake-tls"),
            ObfsKey = Str(obf, "obfs_key", ""),
            ObfsFronting = Str(obf, "fronting", "websocket"),
            AwgEnabled = Bool(awg, "enabled", false),
            AwgJc = (uint)Math.Clamp(Int(awg, "jc", 0), 0, 128),
            AwgJmin = (ushort)Math.Clamp(Int(awg, "jmin", 40), 0, 1400),
            AwgJmax = (ushort)Math.Clamp(Int(awg, "jmax", 300), 0, 1400),
            QuicEnabled = Bool(quic, "enabled", false),
            Sni = StrOrNull(obf, "sni"),
            RealityShortId = StrOrNull(obf, "reality_short_id"),
            PaddingEnabled = Bool(padding, "enabled", true),
            PaddingMin = Int(padding, "min_bytes", 0),
            PaddingMax = Int(padding, "max_bytes", 255),
            HeartbeatEnabled = Bool(heartbeat, "enabled", true),
            HeartbeatIntervalMs = Long(heartbeat, "interval_ms", 15000),
            HeartbeatDataSize = Int(heartbeat, "data_size_bytes", 16),
            HeartbeatJitterMs = Long(heartbeat, "jitter_ms", 2000),
        };
    }

    /// <summary>
    /// Parse a flat-INI qeli client config (the current format, single [qeli] section):
    /// server=host:port, proto, user, pass, key, mode, obfs_key, sni, route_local.
    /// Matches qeli/src/config/client.rs from_ini. Full-line # / ; comments only.
    /// </summary>
    public static VpnConfig FromIni(string text)
    {
        var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string section = "";
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
            if (line[0] == '[' && line.EndsWith("]")) { section = line[1..^1].Trim(); continue; }
            int eq = line.IndexOf('=');
            if (eq < 0) continue;
            if (section.Equals("qeli", StringComparison.OrdinalIgnoreCase))
                q[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }

        string Get(string k, string def = "") => q.TryGetValue(k, out var v) ? v : def;

        var server = Get("server");
        string host = "127.0.0.1";
        int port = 443;
        int colon = server.LastIndexOf(':');
        if (colon > 0)
        {
            host = server[..colon];
            int.TryParse(server[(colon + 1)..], out port);
        }
        else if (server.Length > 0) host = server;
        if (port is < 1 or > 65535) port = 443;

        string key = new string(Get("key").Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        bool keyValid = key.Length == 64 && key.Any(ch => ch != '0'); // all-zero = TOFU
        string sni = Get("sni");

        // Routing: full-tunnel by default; `gateway = false` opts into split-tunnel.
        // Mirrors the Rust/Android `gateway` key — the only way to pick split-tunnel
        // via an imported INI / qeli:// link (the GUI routing dropdown is a separate path).
        bool fullTunnel = q.TryGetValue("gateway", out var gwv) ? IniBool(gwv) : true;
        // DNS: `dns = <ip,ip>` is the resolver list; tolerate the Rust/router MODE words
        // (off/tunnel/system) by keeping the defaults instead of treating "off" as a resolver.
        var dnsRaw = Get("dns");
        List<string>? dnsList = (dnsRaw.Length == 0
                || dnsRaw.Equals("off", StringComparison.OrdinalIgnoreCase)
                || dnsRaw.Equals("tunnel", StringComparison.OrdinalIgnoreCase)
                || dnsRaw.Equals("system", StringComparison.OrdinalIgnoreCase))
            ? null
            : dnsRaw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

        // Alias: `mode=udp-quic` / `udp-obfs` fold transport+QUIC into the wire mode.
        var (proto, mode, quic) = NormalizeMode(Get("proto", "tcp"), Get("mode", "fake-tls"), IniBool(Get("quic")));

        return new VpnConfig
        {
            Name = Get("name", host),
            ServerAddress = host,
            Port = port,
            Protocol = proto,
            Username = Get("user", "client"),
            Password = Get("pass"),
            ServerPublicKeyHex = keyValid ? key : null,
            // H-1: on by default; needs a pinned key. `bind_static = false` for TOFU.
            BindStaticToSession = q.TryGetValue("bind_static", out var bs) ? IniBool(bs) : true,
            WireMode = mode,
            ObfsKey = Get("obfs_key"),
            ObfsFronting = Get("front", "websocket"),
            // F2 AmneziaWG junk (off by default). `awg = true` enables; jc/jmin/jmax
            // bound the junk. Clamped to the wire caps (jc<=128, len<=1400).
            AwgEnabled = IniBool(Get("awg")),
            AwgJc = (uint)(uint.TryParse(Get("jc"), out var jcv) ? Math.Min(jcv, 128u) : 0u),
            AwgJmin = (ushort)(ushort.TryParse(Get("jmin"), out var jminv) ? Math.Min(jminv, (ushort)1400) : (ushort)40),
            AwgJmax = (ushort)(ushort.TryParse(Get("jmax"), out var jmaxv) ? Math.Min(jmaxv, (ushort)1400) : (ushort)300),
            QuicEnabled = quic,
            Sni = sni.Length > 0 ? sni : null,
            RealityShortId = Get("reality_sid").Length > 0 ? Get("reality_sid") : null,
            RouteLocalNetworks = IniBool(Get("route_local")),
            // Explicit per-CIDR routing (comma-separated). `exclude` carves subnets OUT of
            // the tunnel (routed via the physical gateway, so it works in full-tunnel too);
            // `include` forces subnets IN (split-tunnel). Mirrors the Rust/Android keys.
            IncludeRoutes = SplitCidrs(Get("include")),
            ExcludeRoutes = SplitCidrs(Get("exclude")),
            PersistTun = IniBool(Get("persist_tun")),
            Forward = IniBool(Get("forward")),
            // Was neither parsed nor emitted here, so an imported/exported flat-INI silently
            // dropped the kill-switch flag — the leak protection the user asked for failed
            // OPEN. Rust reads it (client.rs) and FromJson already did; mirror them.
            KillSwitch = IniBool(Get("kill_switch")),
            AllowIpv6Leak = IniBool(Get("allow_ipv6_leak")),
            LocalAddress = Get("local").Length > 0 ? Get("local") : null,
            LocalPort = int.TryParse(Get("lport"), out var lpv) && lpv is > 0 and <= 65535 ? lpv : 0,
            RouteFile = Get("route_file").Length > 0 ? Get("route_file") : null,
            InterfaceMetric = int.TryParse(Get("metric"), out var imv) && imv > 0 ? imv : 0,
            // Accept the Rust/Android client's `dev` key as an alias for `dev_node` so a
            // shared flat-INI config's TUN interface name transfers across clients.
            DevNode = Get("dev_node").Length > 0 ? Get("dev_node")
                    : Get("dev").Length > 0 ? Get("dev") : null,
            Mtu = int.TryParse(Get("mtu"), out var miv) ? miv : 0,  // 0 = auto
            MtuProbe = Get("mtu_probe") is var mp && (mp.Length == 0 || IniBool(mp)),  // default true
            RoutingMode = fullTunnel ? "full-tunnel" : "split-tunnel",
            AddDefaultGateway = fullTunnel,
            DnsServers = dnsList ?? new List<string>(),  // empty when unset; fallback at connect time
        };
    }

    private static bool IniBool(string v) =>
        v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" ||
        v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);

    /// <summary>Split a comma-separated CIDR list, trimming blanks. Values are validated
    /// again (strict IP literal) before being spliced into route commands.</summary>
    private static List<string> SplitCidrs(string v) =>
        v.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

    /// <summary>
    /// Parse a qeli:// share link. Mirrors Android VpnConfig.fromQeliUri /
    /// qeli/src/config/share.rs:
    /// qeli://user:pass@host:port?proto=tcp&amp;mode=fake-tls&amp;key=hex&amp;sni=host&amp;obfs=key#label
    /// </summary>
    public static VpnConfig FromQeliUri(string uri)
    {
        string trimmed = uri.Trim();
        if (!trimmed.StartsWith("qeli://", StringComparison.Ordinal))
            throw new FormatException("not a qeli:// link");
        string rest0 = trimmed.Substring("qeli://".Length);

        string beforeFrag; string? label = null;
        int hashIdx = rest0.IndexOf('#');
        if (hashIdx >= 0) { beforeFrag = rest0[..hashIdx]; label = PctDecode(rest0[(hashIdx + 1)..]); }
        else beforeFrag = rest0;

        string authority; string? query = null;
        int qIdx = beforeFrag.IndexOf('?');
        if (qIdx >= 0) { authority = beforeFrag[..qIdx]; query = beforeFrag[(qIdx + 1)..]; }
        else authority = beforeFrag;

        int atIdx = authority.LastIndexOf('@');
        string? userinfo = atIdx >= 0 ? authority[..atIdx] : null;
        string hostPort = atIdx >= 0 ? authority[(atIdx + 1)..] : authority;
        string host; int port;
        if (hostPort.StartsWith('['))
        {
            // Bracketed IPv6 literal: [2001:db8::1]:443 — split on the ']:' so the
            // colons inside the address aren't mistaken for the port separator.
            int rb = hostPort.IndexOf(']');
            if (rb < 0 || rb + 1 >= hostPort.Length || hostPort[rb + 1] != ':')
                throw new FormatException("qeli:// authority malformed IPv6 [host]:port");
            host = hostPort[1..rb];
            if (!int.TryParse(hostPort[(rb + 2)..], out port))
                throw new FormatException("invalid port in qeli:// link");
        }
        else
        {
            int colonIdx = hostPort.LastIndexOf(':');
            if (colonIdx <= 0) throw new FormatException("qeli:// authority missing :port");
            host = hostPort[..colonIdx];
            if (!int.TryParse(hostPort[(colonIdx + 1)..], out port))
                throw new FormatException("invalid port in qeli:// link");
        }
        if (host.Length == 0) throw new FormatException("empty host in qeli:// link");
        // FromIni already range-checks the port; this path only checked that it PARSED,
        // so `:0`, `:99999` or a negative value sailed through into a profile that then
        // failed at connect time with an opaque socket error. Reject at import. (Shared)
        if (port is < 1 or > 65535)
            throw new FormatException($"port {port} out of range in qeli:// link (1..65535)");

        string user = "", pass = "";
        if (userinfo != null)
        {
            int sep = userinfo.IndexOf(':');
            if (sep >= 0) { user = PctDecode(userinfo[..sep]); pass = PctDecode(userinfo[(sep + 1)..]); }
            else user = PctDecode(userinfo);
        }

        string proto = "tcp", mode = "fake-tls", obfs = "", front = "websocket";
        string? key = null, sni = null, rsid = null;
        bool quic = false;
        int mtu = 0;  // 0 = auto (use server-pushed MTU)
        // F2 AmneziaWG junk params (off unless awg=1).
        bool awg = false;
        uint awgJc = 0;
        ushort awgJmin = 40, awgJmax = 300;
        if (query != null)
        {
            foreach (var pair in query.Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                string k = eq >= 0 ? pair[..eq] : pair;
                string v = PctDecode(eq >= 0 ? pair[(eq + 1)..] : "");
                switch (k)
                {
                    case "proto": proto = v; break;
                    case "mode": mode = v; break;
                    // Same normalisation FromIni applies: keep hex digits only, lowercase,
                    // and treat anything that is not a 64-char non-all-zero key as unpinned
                    // (TOFU) instead of storing junk that only fails at handshake. (Shared)
                    case "key":
                    {
                        var hex = new string(v.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
                        key = hex.Length == 64 && hex.Any(ch => ch != '0') ? hex : null;
                        break;
                    }
                    case "sni": sni = v.Length == 0 ? null : v; break;
                    case "rsid": rsid = v.Length == 0 ? null : v; break;
                    case "obfs": obfs = v; break;
                    case "front": if (v.Length > 0) front = v; break;
                    case "quic": quic = v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase); break;
                    case "mtu": int.TryParse(v, out mtu); break;
                    case "awg": awg = v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase); break;
                    case "jc": if (uint.TryParse(v, out var jcp)) awgJc = Math.Min(jcp, 128u); break;
                    case "jmin": if (ushort.TryParse(v, out var jminp)) awgJmin = Math.Min(jminp, (ushort)1400); break;
                    case "jmax": if (ushort.TryParse(v, out var jmaxp)) awgJmax = Math.Min(jmaxp, (ushort)1400); break;
                }
            }
        }

        // Alias convenience: some users fold transport+QUIC into the wire mode
        // (`mode=udp-quic` / `udp-obfs`). Split it back into proto + wire mode + quic.
        (proto, mode, quic) = NormalizeMode(proto, mode, quic);

        return new VpnConfig
        {
            Name = label,
            ServerAddress = host, Port = port, Protocol = proto,
            Username = user, Password = pass, ServerPublicKeyHex = key,
            WireMode = mode, ObfsKey = obfs, ObfsFronting = front, Sni = sni, QuicEnabled = quic,
            AwgEnabled = awg, AwgJc = awgJc, AwgJmin = awgJmin, AwgJmax = awgJmax,
            RealityShortId = rsid, Mtu = mtu,
        };
    }

    /// <summary>Accept convenience aliases where transport/QUIC is folded into the wire
    /// mode: `udp-quic` → (udp, fake-tls, quic on); `udp-obfs` → (udp, obfs). Anything
    /// else passes through unchanged.</summary>
    private static (string proto, string mode, bool quic) NormalizeMode(string proto, string mode, bool quic) =>
        mode.ToLowerInvariant() switch
        {
            "udp-quic" => ("udp", "fake-tls", true),
            "udp-obfs" => ("udp", "obfs", quic),
            _ => (proto, mode, quic),
        };

    // ── JSON helpers ──────────────────────────────────────────────────────────
    private static JsonObject Obj(JsonObject? parent, string key) =>
        parent?[key] as JsonObject ?? new JsonObject();

    private static string Str(JsonObject o, string key, string def) =>
        o[key] is JsonValue v && v.TryGetValue(out string? s) ? s! : def;

    private static string? StrOrNull(JsonObject o, string key)
    {
        if (o[key] is JsonValue v && v.TryGetValue(out string? s) && !string.IsNullOrEmpty(s)) return s;
        return null;
    }

    private static int Int(JsonObject o, string key, int def) =>
        o[key] is JsonValue v && v.TryGetValue(out int i) ? i : def;

    private static long Long(JsonObject o, string key, long def) =>
        o[key] is JsonValue v && v.TryGetValue(out long l) ? l : def;

    private static bool Bool(JsonObject o, string key, bool def) =>
        o[key] is JsonValue v && v.TryGetValue(out bool b) ? b : def;

    private static List<string> StrList(JsonObject o, string key)
    {
        var result = new List<string>();
        if (o[key] is JsonArray arr)
            foreach (var n in arr)
                if (n is JsonValue v && v.TryGetValue(out string? s) && !string.IsNullOrEmpty(s))
                    result.Add(s!);
        return result;
    }

    private static string PctDecode(string s)
    {
        if (s.IndexOf('%') < 0) return s;
        var bytes = new List<byte>(s.Length);
        var outSb = new StringBuilder(s.Length);
        int i = 0;
        void Flush() { if (bytes.Count > 0) { outSb.Append(Encoding.UTF8.GetString(bytes.ToArray())); bytes.Clear(); } }
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '%' && i + 2 < s.Length)
            {
                int h = HexVal(s[i + 1]); int l = HexVal(s[i + 2]);
                if (h >= 0 && l >= 0) { bytes.Add((byte)((h << 4) | l)); i += 3; continue; }
            }
            Flush();
            outSb.Append(c); i++;
        }
        Flush();
        return outSb.ToString();
    }

    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'a' and <= 'f' => c - 'a' + 10,
        >= 'A' and <= 'F' => c - 'A' + 10,
        _ => -1,
    };
}
