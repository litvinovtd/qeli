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
    // routing
    public string RoutingMode { get; init; } = "full-tunnel";
    public bool AddDefaultGateway { get; init; } = true;
    public List<string> IncludeRoutes { get; init; } = new();
    public List<string> ExcludeRoutes { get; init; } = new();
    public bool RouteLocalNetworks { get; init; }
    // Firewall kill-switch (full-tunnel only): block ALL egress except the tunnel,
    // the server, DNS and DHCP while connected, so a tunnel drop can't leak traffic
    // onto the physical NIC during reconnect. Platform-specific (Win: Windows
    // Firewall default-block + allow rules; mac: pf anchor). Default off.
    public bool KillSwitch { get; init; }
    // dns
    public List<string> DnsServers { get; init; } = new() { "1.1.1.1", "8.8.8.8" };
    // obfuscation
    public string WireMode { get; init; } = "fake-tls";  // "fake-tls" | "obfs" | "reality-tls" | "plain"
    public string ObfsKey { get; init; } = "";
    // obfs anti-FET fronting: "websocket" (default) wraps the nonce exchange in a
    // WebSocket Upgrade handshake; "none" is the legacy raw nonce. Must match the
    // server. Mirrors ClientObfuscationConfig::fronting (Rust) / VpnConfig.obfsFronting (Android).
    public string ObfsFronting { get; init; } = "websocket";
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

    // Optional display label (UI only).
    public string? Name { get; set; }

    [JsonIgnore]
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? ServerAddress : Name!;

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
        int shBudget, int shMinSize, int shMaxSize) => new()
    {
        ServerAddress = ServerAddress, Port = Port, Protocol = Protocol,
        ConnectionTimeoutSecs = ConnectionTimeoutSecs,
        ReconnectEnabled = ReconnectEnabled, ReconnectMaxRetries = ReconnectMaxRetries,
        ReconnectBaseDelaySecs = ReconnectBaseDelaySecs, ReconnectMaxDelaySecs = ReconnectMaxDelaySecs,
        Username = Username, Password = Password, ServerPublicKeyHex = ServerPublicKeyHex,
        BindStaticToSession = BindStaticToSession,
        Mtu = Mtu, RoutingMode = RoutingMode, AddDefaultGateway = AddDefaultGateway,
        IncludeRoutes = IncludeRoutes, ExcludeRoutes = ExcludeRoutes, RouteLocalNetworks = RouteLocalNetworks,
        KillSwitch = KillSwitch,
        DnsServers = DnsServers, WireMode = WireMode, ObfsKey = ObfsKey, ObfsFronting = ObfsFronting, QuicEnabled = QuicEnabled, Sni = Sni,
        RealityShortId = RealityShortId,
        PaddingEnabled = PaddingEnabled, PaddingMin = PaddingMin, PaddingMax = PaddingMax,
        HeartbeatEnabled = hbEnabled, HeartbeatIntervalMs = hbIntervalMs,
        HeartbeatDataSize = HeartbeatDataSize, HeartbeatJitterMs = hbJitterMs,
        ShapingEnabled = shEnabled, ShapingGapMeanMs = shGapMeanMs, ShapingGapMinMs = shGapMinMs,
        ShapingGapMaxMs = shGapMaxMs, ShapingBudgetBytesPerSec = shBudget,
        ShapingMinSize = shMinSize, ShapingMaxSize = shMaxSize,
        Name = Name,
    };

    /// <summary>Serialize to the canonical qeli JSON client-config schema.</summary>
    public string ToConfigJson(string? label = null)
    {
        var root = new JsonObject();
        if (!string.IsNullOrWhiteSpace(label)) root["name"] = label;
        else if (!string.IsNullOrWhiteSpace(Name)) root["name"] = Name;
        root["server"] = new JsonObject
        {
            ["address"] = ServerAddress, ["port"] = Port, ["protocol"] = Protocol,
        };
        root["auth"] = new JsonObject
        {
            ["username"] = Username, ["password"] = Password,
            ["server_public_key"] = ServerPublicKeyHex ?? "",
        };
        root["routing"] = new JsonObject
        {
            ["mode"] = "full-tunnel", ["add_default_gateway"] = true,
            ["route_local_networks"] = RouteLocalNetworks,
        };
        root["dns"] = new JsonObject { ["servers"] = new JsonArray(DnsServers.Select(s => (JsonNode)s!).ToArray()) };
        if (Mtu > 0) root["tun"] = new JsonObject { ["mtu"] = Mtu };  // 0 = auto, omit
        var obf = new JsonObject { ["mode"] = WireMode };
        if (!string.IsNullOrWhiteSpace(Sni)) obf["sni"] = Sni;
        if (ObfsKey.Length > 0) obf["obfs_key"] = ObfsKey;
        if (ObfsFronting != "websocket") obf["fronting"] = ObfsFronting;
        // reality-tls short_id and the UDP QUIC-masking flag are connection-essential
        // for those modes — omitting them silently downgraded a reality/udp+quic
        // profile to a plain one on round-trip (FromJson reads both back).
        if (!string.IsNullOrWhiteSpace(RealityShortId)) obf["reality_short_id"] = RealityShortId;
        if (QuicEnabled) obf["quic"] = new JsonObject { ["enabled"] = true };
        root["obfuscation"] = obf;
        return root.ToJsonString();
    }

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
        // QUIC masking is required for a udp+quic profile — without it the link
        // round-trips to plain UDP and a quic-mode server stays silent.
        if (QuicEnabled) q.Add("quic=1");
        if (Mtu > 0) q.Add($"mtu={Mtu}");  // 0 = auto, omit
        sb.Append('?').Append(string.Join("&", q));

        if (!string.IsNullOrWhiteSpace(Name)) sb.Append('#').Append(Uri.EscapeDataString(Name!));
        return sb.ToString();
    }

    /// <summary>Serialize to the flat-INI qeli config (inverse of FromIni).</summary>
    public string ToIni()
    {
        var sb = new StringBuilder();
        sb.AppendLine("[qeli]");
        if (!string.IsNullOrWhiteSpace(Name)) sb.AppendLine($"name = {Name}");
        sb.AppendLine($"server = {ServerAddress}:{Port}");
        sb.AppendLine($"proto = {Protocol}");
        sb.AppendLine($"user = {Username}");
        sb.AppendLine($"pass = {Password}");
        if (!string.IsNullOrEmpty(ServerPublicKeyHex)) sb.AppendLine($"key = {ServerPublicKeyHex}");
        if (!BindStaticToSession) sb.AppendLine("bind_static = false");  // on by default; emit only when off
        sb.AppendLine($"mode = {WireMode}");
        if (!string.IsNullOrEmpty(ObfsKey)) sb.AppendLine($"obfs_key = {ObfsKey}");
        if (!string.IsNullOrEmpty(Sni)) sb.AppendLine($"sni = {Sni}");
        if (!string.IsNullOrEmpty(RealityShortId)) sb.AppendLine($"reality_sid = {RealityShortId}");
        // Only emit `front` when it diverges from the default, mirroring Rust to_ini_string.
        if (!string.IsNullOrEmpty(ObfsFronting) && ObfsFronting != "websocket") sb.AppendLine($"front = {ObfsFronting}");
        if (QuicEnabled) sb.AppendLine("quic = true");
        if (RouteLocalNetworks) sb.AppendLine("route_local = true");
        if (Mtu > 0) sb.AppendLine($"mtu = {Mtu}");  // 0 = auto, omit
        return sb.ToString();
    }

    /// <summary>Deep copy (for "Duplicate"). Runtime-only fields reset to defaults.</summary>
    public VpnConfig Clone() =>
        JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(this))!;

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
            DnsServers = StrList(dns, "servers"),
            WireMode = Str(obf, "mode", "fake-tls"),
            ObfsKey = Str(obf, "obfs_key", ""),
            ObfsFronting = Str(obf, "fronting", "websocket"),
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

        return new VpnConfig
        {
            Name = Get("name", host),
            ServerAddress = host,
            Port = port,
            Protocol = Get("proto", "tcp"),
            Username = Get("user", "client"),
            Password = Get("pass"),
            ServerPublicKeyHex = keyValid ? key : null,
            // H-1: on by default; needs a pinned key. `bind_static = false` for TOFU.
            BindStaticToSession = q.TryGetValue("bind_static", out var bs) ? IniBool(bs) : true,
            WireMode = Get("mode", "fake-tls"),
            ObfsKey = Get("obfs_key"),
            ObfsFronting = Get("front", "websocket"),
            QuicEnabled = IniBool(Get("quic")),
            Sni = sni.Length > 0 ? sni : null,
            RealityShortId = Get("reality_sid").Length > 0 ? Get("reality_sid") : null,
            RouteLocalNetworks = IniBool(Get("route_local")),
            Mtu = int.TryParse(Get("mtu"), out var miv) ? miv : 0,  // 0 = auto
        };
    }

    private static bool IniBool(string v) =>
        v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" ||
        v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);

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
                    case "key": key = v.Length == 0 ? null : v; break;
                    case "sni": sni = v.Length == 0 ? null : v; break;
                    case "rsid": rsid = v.Length == 0 ? null : v; break;
                    case "obfs": obfs = v; break;
                    case "front": if (v.Length > 0) front = v; break;
                    case "quic": quic = v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase); break;
                    case "mtu": int.TryParse(v, out mtu); break;
                }
            }
        }

        return new VpnConfig
        {
            Name = label,
            ServerAddress = host, Port = port, Protocol = proto,
            Username = user, Password = pass, ServerPublicKeyHex = key,
            WireMode = mode, ObfsKey = obfs, ObfsFronting = front, Sni = sni, QuicEnabled = quic,
            RealityShortId = rsid, Mtu = mtu,
        };
    }

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
