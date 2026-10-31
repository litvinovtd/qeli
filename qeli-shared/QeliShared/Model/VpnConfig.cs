using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Qeli.Shared.Model;

/// <summary>Reachability of a profile's server, shown as a colored dot on the card.</summary>
public enum ProfileReachability { Unknown, Checking, Reachable, Unreachable }

/// <summary>
/// Full qeli client configuration. Mirrors the relevant fields of the Rust
/// ClientConfig and the Android VpnConfig. Built from the simple UI fields, an
/// imported flat-INI config (FromIni) or a qeli:// share link (FromQeliUri).
/// </summary>
public sealed partial class VpnConfig : INotifyPropertyChanged
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
    public string Protocol { get; init; } = ConfigDefaults.Protocol;       // "tcp" | "udp"
    public long ConnectionTimeoutSecs { get; init; } = ConfigDefaults.ConnectionTimeoutSecs;
    // OpenVPN-parity outbound-socket binding (issue #69). LocalAddress = bind the carrier
    // socket to a specific local IP (multi-homed host / pick egress NIC; OpenVPN `local`);
    // LocalPort = bind to a fixed local source port (OpenVPN `lport`) for firewall rules.
    // Empty / 0 = OS default (any address, ephemeral port).
    public string? LocalAddress { get; init; } = ConfigDefaults.LocalAddress;
    public int LocalPort { get; init; } = ConfigDefaults.LocalPort;
    // reconnect
    public bool ReconnectEnabled { get; init; } = ConfigDefaults.ReconnectEnabled;
    public int ReconnectMaxRetries { get; init; } = ConfigDefaults.ReconnectMaxRetries;
    public long ReconnectBaseDelaySecs { get; init; } = ConfigDefaults.ReconnectBaseDelaySecs;
    public long ReconnectMaxDelaySecs { get; init; } = ConfigDefaults.ReconnectMaxDelaySecs;
    // auth
    public string Username { get; init; } = ConfigDefaults.Username;
    public string Password { get; init; } = ConfigDefaults.Password;
    /// <summary>Runtime journal detail carried into desktop service/daemon profiles.
    /// It is an application preference, not a transport-core setting.</summary>
    public string LoggingLevel { get; set; } = ConfigDefaults.LoggingLevel;
    public string? ServerPublicKeyHex { get; init; } = ConfigDefaults.ServerPublicKeyHex;     // pinned static key (hex), null = TOFU
    // H-1: bind data keys to the server static identity (folds es into the KDF).
    // Must match the server's auth.bind_static_to_session and requires a pinned key.
    // Default TRUE (secure-by-default since 0.7.1); wire-breaking — set false (or
    // pass bind_static=false) to talk to a legacy 0.7.0 / TOFU server.
    public bool BindStaticToSession { get; init; } = ConfigDefaults.BindStaticToSession;
    /// <summary>Permit first-use trust when the proven key cannot be persisted. False keeps
    /// the TOFU store fail-closed; it never weakens an existing-pin mismatch.</summary>
    public bool AllowUnpinnedTofu { get; init; } = ConfigDefaults.AllowUnpinnedTofu;
    // tun
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    public int Mtu { get; init; } = ConfigDefaults.Mtu;
    // Active outer UDP path-MTU probing, independently of Mtu. Default on; false
    // disables startup/live probes. No effect on TCP (the OS performs PMTUD).
    public bool MtuProbe { get; init; } = ConfigDefaults.MtuProbe;
    // routing
    public string RoutingMode { get; init; } = "full-tunnel";
    /// <summary>Inner IPv6 negotiation policy: auto, required or off.</summary>
    public string Ipv6Policy { get; init; } = ConfigDefaults.Ipv6Policy;
    /// <summary>Session migration policy: off, auto or required.</summary>
    public string RoamingPolicy { get; init; } = ConfigDefaults.RoamingPolicy;
    public bool AddDefaultGateway { get; init; } = ConfigDefaults.AddDefaultGateway;
    public List<string> IncludeRoutes { get; init; } = new();
    public List<string> ExcludeRoutes { get; init; } = new();
    public bool PullRoutes { get; init; } = ConfigDefaults.PullRoutes;
    public bool WindowsDisableSharing { get; init; } = ConfigDefaults.WindowsDisableSharing;
    public bool WindowsPersistentAdapter { get; init; } = ConfigDefaults.WindowsPersistentAdapter;
    /// <summary>Application-resolved Windows policy carried only in a trusted service
    /// snapshot/archive, not in INI or qeli://. Null legacy snapshots default to off.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? WindowsAdapterMode { get; init; }
    public bool RouteLocalNetworks { get; init; } = ConfigDefaults.RouteLocalNetworks;
    // Extra split-tunnel routes loaded from CIDR/OpenVPN route files. Repeating route_file
    // is intentional: RouteFile keeps the first path for profile-store compatibility and
    // AdditionalRouteFiles keeps the remaining paths in declaration order.
    public string? RouteFile { get; init; }
    public List<string> AdditionalRouteFiles { get; init; } = new();
    [JsonIgnore]
    public IReadOnlyList<string> RouteFilePaths =>
        (string.IsNullOrWhiteSpace(RouteFile)
            ? AdditionalRouteFiles
            : new[] { RouteFile }.Concat(AdditionalRouteFiles))
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Distinct(StringComparer.Ordinal)
        .ToArray();
    // TUN interface routing metric (OpenVPN `route-metric` / a lower value = higher
    // priority). 0 = OS default. Applied to the tunnel adapter after addressing.
    public int InterfaceMetric { get; init; } = ConfigDefaults.InterfaceMetric;
    // Force a specific TUN adapter name (OpenVPN `dev-node`). Windows: names the Wintun
    // adapter instead of the auto-derived Qeli-<hash>. Empty = auto.
    public string? DevNode { get; init; } = ConfigDefaults.DevNode;
    // OpenVPN-style persist-tun: keep the TUN adapter + routes UP across reconnects
    // (until the user disconnects) instead of tearing them down and recreating them each
    // attempt. Avoids the adapter flicker + the brief route gap on every reconnect, and
    // fails closed (no physical-NIC leak) during the reconnect window. Off by default.
    public bool PersistTun { get; init; } = ConfigDefaults.PersistTun;
    // #13: enable OS IP forwarding on THIS node (no NAT) so a LAN behind the client is
    // routable through the tunnel (site-to-site). macOS: net.inet.ip.forwarding=1; Windows:
    // per-interface netsh forwarding (best-effort). Mirrors the Rust client's routing.forward.
    public bool Forward { get; init; } = ConfigDefaults.Forward;
    // Firewall kill-switch (full-tunnel only): block ALL egress except the tunnel,
    // the server, DNS and DHCP while connected, so a tunnel drop can't leak traffic
    // onto the physical NIC during reconnect. Platform-specific (Win: Windows
    // Firewall default-block + allow rules; mac: pf anchor). Default off.
    public bool KillSwitch { get; init; } = ConfigDefaults.KillSwitch;
    // In a full tunnel whose negotiated plan has no IPv6 address, the platform blocks that
    // family to close the classic dual-stack leak. Set true to explicitly allow native IPv6
    // to bypass such an IPv4-only tunnel. A dual/IPv6 plan always carries IPv6 in qeli.
    public bool AllowIpv6Leak { get; init; } = ConfigDefaults.AllowIpv6Leak;
    // Symmetric escape hatch for an IPv6-only full tunnel. Secure default blocks IPv4.
    public bool AllowIpv4Leak { get; init; } = ConfigDefaults.AllowIpv4Leak;
    // Per-application routing. The value syntax is platform-owned: Android and macOS use
    // package/signing identifiers, while Windows uses canonical executable paths. Keeping the
    // common model typed means a profile can be edited on any desktop without losing the
    // selection and each platform can apply the same include/exclude contract.
    public string AppsMode { get; init; } = ConfigDefaults.AppsMode;
    public List<string> Apps { get; init; } = new();

    [JsonIgnore]
    public bool UsesAppFilter =>
        Apps.Count > 0
        && (AppsMode.Equals("include", StringComparison.OrdinalIgnoreCase)
            || AppsMode.Equals("exclude", StringComparison.OrdinalIgnoreCase));
    // Empty by default so a profile that never specified DNS round-trips without inventing a
    // resolver and server-pushed DNS remains authoritative. Resolution order is explicit list,
    // then authenticated server push, then no change to the host resolver.
    public List<string> DnsServers { get; init; } = new();

    /// <summary>DNS handling mode, mirroring `dns.mode` in the Rust client: `tunnel` (default —
    /// install resolvers reachable through the tunnel), `off` or `system` (leave the device
    /// resolver alone).
    ///
    /// Legacy mobile profiles used the same `dns` key for both a mode and a resolver list.
    /// Readers still accept that form, while writers use canonical `dns_servers`; the mode is
    /// kept separately so `off`/`system` survives an edit. (Audit 2026-08-02, §3.)</summary>
    public string DnsMode { get; init; } = ConfigDefaults.DnsMode;
    // obfuscation
    public string WireMode { get; init; } = ConfigDefaults.WireMode;  // "fake-tls" | "obfs" | "reality-tls" | "plain"
    public string ObfsKey { get; init; } = ConfigDefaults.ObfsKey;
    // obfs anti-FET fronting: "websocket" (default) wraps the nonce exchange in a
    // WebSocket Upgrade handshake; "none" is the legacy raw nonce. Must match the
    // server. Mirrors ClientObfuscationConfig::fronting (Rust) / VpnConfig.obfsFronting (Android).
    public string ObfsFronting { get; init; } = ConfigDefaults.ObfsFronting;
    // F2 AmneziaWG-style pre-handshake junk (obfs mode). OFF by default → zero extra
    // bytes on the wire (byte-identical to the pre-F2 wire). Both ends MUST agree on
    // AwgJc (the junk-record count); AwgJmin/AwgJmax bound each record's random length
    // and are sender-only. Mirrors the Rust AwgParams / obf.awg.* config.
    public bool AwgEnabled { get; init; } = ConfigDefaults.AwgEnabled;
    public uint AwgJc { get; init; } = ConfigDefaults.AwgJc;              // record count (cap 128); 0 = disabled
    public ushort AwgJmin { get; init; } = ConfigDefaults.AwgJmin;    // min junk-record length
    public ushort AwgJmax { get; init; } = ConfigDefaults.AwgJmax;   // max junk-record length (jmin<=jmax<=1400)
    public bool QuicEnabled { get; init; } = ConfigDefaults.QuicEnabled;
    public string? Sni { get; init; } = ConfigDefaults.Sni;
    // REALITY short_id (hex) — pairs with ServerPublicKeyHex to seal the auth
    // token into the realtls ClientHello (WireMode = "reality-tls").
    public string? RealityShortId { get; init; } = ConfigDefaults.RealityShortId;
    // padding
    public bool PaddingEnabled { get; init; } = ConfigDefaults.PaddingEnabled;
    /// <summary>Keys whose boolean value was neither true-ish nor false-ish — `gateway = ture`.
    ///
    /// Carried instead of being resolved at parse time because the ORIGINAL STRING IS LOST once
    /// a bool is produced, so nothing downstream could tell a typo from a deliberate `false`.
    /// That mattered: every unknown value read as `false`, so <c>kill_switch = ture</c> silently
    /// disabled the kill switch and <c>bind_static = ture</c> silently dropped the static-key
    /// binding — a security downgrade with no message anywhere.
    ///
    /// Parsing still SUCCEEDS (an editor must be able to open a bad profile to fix it);
    /// <see cref="Validate"/> is what refuses. (Audit 2026-07-31.)</summary>
    public IReadOnlyList<string> UnparsedBooleanKeys { get; init; } = Array.Empty<string>();

    /// <summary>Rust reports duplicate scalars. Drafts display the first value; activation refuses the ambiguity.</summary>
    public IReadOnlyList<string> DuplicateKeys { get; init; } = Array.Empty<string>();

    /// <summary>`[qeli]` keys no qeli client understands — i.e. misspellings. The setting they
    /// were meant to change silently keeps its default, which is how `gatway = true` left a
    /// tunnel split with nothing said. Reported, not resolved; Validate() refuses.
    /// (Audit 2026-08-01, §14.)</summary>
    public IReadOnlyList<string> UnknownKeys { get; init; } = Array.Empty<string>();

    /// <summary>Numeric fields whose value could not be parsed (or was out of range), which
    /// used to fall back to a default in silence — the same failure mode the boolean handling
    /// already fixed. `server = host:notnum` became `host:443`, i.e. a different server, with
    /// nothing said anywhere. Parsing still succeeds so an editor can open the profile;
    /// Validate() is what refuses. (Audit 2026-08-01, §P2.)</summary>
    public IReadOnlyList<string> UnparsedNumericKeys { get; init; } = Array.Empty<string>();

    /// <summary>`[qeli]` keys accepted but not modelled (generated from the Rust schema), kept
    /// verbatim so a save does not delete them. Re-emitted by ToIni() after the modelled
    /// keys.</summary>
    public IReadOnlyDictionary<string, string> CarriedKeys { get; init; }
        = new Dictionary<string, string>();

    /// <summary>The TEXT of every value this parse could not use, by key — the offending line
    /// as the author wrote it.</summary>
    /// <remarks>
    /// The marker lists above say a value was wrong; this says WHAT it was, and that is what
    /// makes the manual editor honest. Only this port needs it, because only this port stores
    /// profiles as objects: Android and iOS keep the profile as text, so their editors show the
    /// author's own file. Here "Manual edit" opens <c>BuildFromForm().ToIni()</c> — a
    /// re-emission — and without the raw text the bad line is simply absent from what the user
    /// is shown. They see a clean config, press OK, and the re-parse produces a clean object:
    /// the typo is LAUNDERED and its line is gone from the profile, with the setting left at a
    /// default nobody chose. Re-emitted by ToIni() so the round trip shows the mistake and a
    /// re-parse re-derives the same markers.
    /// </remarks>
    public IReadOnlyDictionary<string, string> InvalidRawValues { get; init; }
        = new Dictionary<string, string>();

    public int PaddingMin { get; init; } = ConfigDefaults.PaddingMin;
    public int PaddingMax { get; init; } = ConfigDefaults.PaddingMax;
    // heartbeat
    public bool HeartbeatEnabled { get; init; } = ConfigDefaults.HeartbeatEnabled;
    public long HeartbeatIntervalMs { get; init; } = ConfigDefaults.HeartbeatIntervalMs;
    public int HeartbeatDataSize { get; init; } = ConfigDefaults.HeartbeatDataSize;
    public long HeartbeatJitterMs { get; init; } = ConfigDefaults.HeartbeatJitterMs;
    // flow shaping (idle cover traffic; DPI-AUDIT 6.1/6.2). Normally pushed from
    // the server. Defaults mirror the Rust TrafficShapingConfig.
    public bool ShapingEnabled { get; init; } = ConfigDefaults.ShapingEnabled;
    public long ShapingGapMeanMs { get; init; } = ConfigDefaults.ShapingGapMeanMs;
    public long ShapingGapMinMs { get; init; } = ConfigDefaults.ShapingGapMinMs;
    public long ShapingGapMaxMs { get; init; } = ConfigDefaults.ShapingGapMaxMs;
    public int ShapingBudgetBytesPerSec { get; init; } = ConfigDefaults.ShapingBudgetBytesPerSec;
    public int ShapingMinSize { get; init; } = ConfigDefaults.ShapingMinSize;
    public int ShapingMaxSize { get; init; } = ConfigDefaults.ShapingMaxSize;
    // Stealth (Phase 2): rate-cap the data plane + cover under load. TCP-only.
    public bool ShapingStealth { get; init; } = ConfigDefaults.ShapingStealth;
    public int ShapingStealthRateMbps { get; init; } = ConfigDefaults.ShapingStealthRateMbps;

    // Optional display label (UI only).
    public string? Name { get; set; } = ConfigDefaults.Name;

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
    /// <summary>`all` counts too. Validate() accepts `split-tunnel | full-tunnel | all` (the
    /// Rust client's set, see client/route.rs), but this only compared against `full-tunnel` —
    /// so a perfectly valid `routing.mode = "all"` profile validated and then ran as a SPLIT
    /// tunnel, quietly sending everything outside the VPN past it. (Audit 2026-07-31, §2.)</summary>
    public bool AllowsNativePathRoaming => ConfigCore.Policy("roaming_allowed", new {
        mode=RoamingPolicy, local=LocalAddress ?? "", port=LocalPort.ToString(System.Globalization.CultureInfo.InvariantCulture)
    }).GetProperty("value").GetBoolean();

    public bool IsFullTunnel => ConfigCore.Policy("full_tunnel", new { gateway=AddDefaultGateway, mode=RoutingMode }).GetProperty("value").GetBoolean();


    /// <summary>Clone applying the fields the profile editor's FORM edits, preserving every
    /// other field from `this` (OpenVPN local/lport/dev_node/metric/route_file/persist_tun,
    /// kill-switch, AWG, reconnect, shaping, Id, …). The editor rebuilds a config on Save;
    /// without this, any field with no form control — e.g. set via the manual INI editor or
    /// import — was silently dropped (issue #69).</summary>
    /// The INI keys whose booleans the editor FORM supplies directly. A value the user picks in
    /// the form replaces whatever unparseable text was there, so its typo marker must be
    /// cleared; every other key keeps its marker because nothing in the form touched it.
    private static readonly string[] EditorControlledBooleanKeys =
    {
        "quic", "gateway", "route_local", "padding", "heartbeat",
    };

    /// <summary>Numeric keys the editor form supplies a real value for, so a marker on them is
    /// genuinely resolved by Save.</summary>
    /// <remarks>
    /// Names as <c>FromIni</c> records them — the port is recorded under <c>server (port)</c>,
    /// because in the flat INI it is the tail of the <c>server</c> line and not a key of its own.
    /// Newer editor controls such as timeout/reconnect are optional parameters of
    /// <see cref="WithEditorFields"/> so conformance callers can still represent an untouched
    /// field. Their markers are removed conditionally in the initializer below.
    /// </remarks>
    private static readonly string[] EditorControlledNumericKeys =
    {
        "server (port)", "mtu", "padding_min", "padding_max",
        "heartbeat_interval", "heartbeat_jitter",
    };

    public VpnConfig WithEditorFields(
        string? name, string serverAddress, int port, string protocol, string wireMode,
        string obfsKey, string obfsFronting, string? realityShortId, string? sni, bool quicEnabled,
        string username, string password, string? serverPublicKeyHex,
        string routingMode, bool addDefaultGateway, bool routeLocalNetworks,
        int mtu, List<string> dnsServers,
        bool paddingEnabled, int paddingMin, int paddingMax,
        bool heartbeatEnabled, long heartbeatIntervalMs, long heartbeatJitterMs,
        string? appsMode = null, List<string>? apps = null,
        long? connectionTimeoutSecs = null, bool? reconnectEnabled = null,
        int? reconnectMaxRetries = null, bool? persistTun = null,
        bool? mtuProbe = null, bool? killSwitch = null, string? dnsMode = null,
        string? ipv6Policy = null, string? roamingPolicy = null,
        bool? allowIpv4Leak = null, bool? allowIpv6Leak = null, bool? pullRoutes = null, bool? windowsDisableSharing = null,
        bool? windowsPersistentAdapter = null, string? devNode = null) => new()
    {
        // ── form-edited fields (from params) ──
        ServerAddress = serverAddress, Port = port, Protocol = protocol, WireMode = wireMode,
        ObfsKey = obfsKey, ObfsFronting = obfsFronting, RealityShortId = realityShortId,
        Sni = sni, QuicEnabled = quicEnabled,
        Username = username, Password = password, ServerPublicKeyHex = serverPublicKeyHex,
        RoutingMode = routingMode, AddDefaultGateway = addDefaultGateway, RouteLocalNetworks = routeLocalNetworks,
        Mtu = mtu, DnsServers = dnsServers,
        // Typing resolvers into the form MEANS "use these", so it has to move the mode off
        // `off`/`system` — otherwise the address the user just entered is stored and then
        // ignored, with the UI showing it as if it applied. The mode is kept when the field is
        // left empty, so a `dns = off` profile saved without touching DNS stays `off`.
        DnsMode = dnsMode ?? (dnsServers.Count > 0 ? "tunnel" : DnsMode),
        PaddingEnabled = paddingEnabled, PaddingMin = paddingMin, PaddingMax = paddingMax,
        HeartbeatEnabled = heartbeatEnabled, HeartbeatIntervalMs = heartbeatIntervalMs, HeartbeatJitterMs = heartbeatJitterMs,
        Name = name,
        AppsMode = appsMode ?? AppsMode,
        Apps = apps ?? Apps,
        ConnectionTimeoutSecs = connectionTimeoutSecs ?? ConnectionTimeoutSecs,
        ReconnectEnabled = reconnectEnabled ?? ReconnectEnabled,
        ReconnectMaxRetries = reconnectMaxRetries ?? ReconnectMaxRetries,
        PersistTun = persistTun ?? PersistTun,
        PullRoutes = pullRoutes ?? PullRoutes,
        WindowsDisableSharing = windowsDisableSharing ?? WindowsDisableSharing,
        WindowsPersistentAdapter = windowsPersistentAdapter ?? WindowsPersistentAdapter,
        WindowsAdapterMode = WindowsAdapterMode,
        MtuProbe = mtuProbe ?? MtuProbe,
        KillSwitch = killSwitch ?? KillSwitch,
        // ── preserved from `this` (no form control) ──
        Id = Id, NativeSource = NativeSource,
        LocalAddress = LocalAddress, LocalPort = LocalPort,
        RouteFile = RouteFile, AdditionalRouteFiles = AdditionalRouteFiles,
        InterfaceMetric = InterfaceMetric, DevNode = devNode ?? DevNode,
        ReconnectBaseDelaySecs = ReconnectBaseDelaySecs, ReconnectMaxDelaySecs = ReconnectMaxDelaySecs,
        BindStaticToSession = BindStaticToSession, AllowUnpinnedTofu = AllowUnpinnedTofu,
        Ipv6Policy = ipv6Policy ?? Ipv6Policy,
        RoamingPolicy = roamingPolicy ?? RoamingPolicy,
        IncludeRoutes = IncludeRoutes, ExcludeRoutes = ExcludeRoutes,
        AllowIpv4Leak = allowIpv4Leak ?? AllowIpv4Leak,
        AllowIpv6Leak = allowIpv6Leak ?? AllowIpv6Leak, Forward = Forward,
        AwgEnabled = AwgEnabled, AwgJc = AwgJc, AwgJmin = AwgJmin, AwgJmax = AwgJmax,
        HeartbeatDataSize = HeartbeatDataSize,
        ShapingEnabled = ShapingEnabled, ShapingGapMeanMs = ShapingGapMeanMs, ShapingGapMinMs = ShapingGapMinMs,
        ShapingGapMaxMs = ShapingGapMaxMs, ShapingBudgetBytesPerSec = ShapingBudgetBytesPerSec,
        ShapingMinSize = ShapingMinSize, ShapingMaxSize = ShapingMaxSize,
        ShapingStealth = ShapingStealth, ShapingStealthRateMbps = ShapingStealthRateMbps,
        // The keys this port accepts but does not model. THE FORM HAS NO CONTROL FOR ANY OF
        // THEM, so they must ride across untouched — this method is the GUI's Save path, and
        // omitting them here undid the whole point of storing them: `FromIni → ToIni` kept
        // `post_up`, `allow_unpinned_tofu` and the rest, while opening the profile in the
        // editor and pressing Save still deleted them. The conformance test only exercised the
        // direct parse/serialize pair, so it stayed green throughout.
        // (Audit 2026-08-02, follow-up.)
        CarriedKeys = CarriedKeys,
        // The other two typo markers must survive as well, for the same reason as the booleans
        // below — and they were the ones still being laundered.
        //
        // `reconnect_base_delay = bad` parses to the default AND records the key. Opening the
        // profile in the editor and pressing Save rebuilt the config without the marker, so
        // Validate() then saw something clean and the setting sat at its default with the
        // original line gone from the file. An unknown key is the same case, and for a security
        // flag it is a silent weakening. (Audit 2026-08-02, follow-up.)
        //
        // Numbers, unlike unknown keys, need the SAME subtraction the booleans get: the form
        // does supply port, mtu, padding and heartbeat, so carrying those markers wholesale
        // left the profile rejected even after the user fixed the very field in the dialog —
        // a dead end with no way out of the UI. Carried minus what the form just rewrote.
        UnparsedNumericKeys = UnparsedNumericKeys
            .Where(k => !EditorControlledNumericKeys.Contains(k))
            .Where(k => connectionTimeoutSecs == null || k != "timeout")
            .Where(k => reconnectMaxRetries == null || k != "reconnect_retries")
            .ToArray(),
            UnknownKeys = UnknownKeys,
            // The raw text behind those markers, minus the ones the form just resolved — a marker
            // and its evidence have to disappear together, or ToIni would re-emit a bad line for a
            // field the dialog has already fixed.
            InvalidRawValues = InvalidRawValues
            .Where(kv => !EditorControlledNumericKeys.Contains(kv.Key)
                         && !EditorControlledBooleanKeys.Contains(kv.Key))
            .Where(kv => connectionTimeoutSecs == null || kv.Key != "timeout")
            .Where(kv => reconnectMaxRetries == null || kv.Key != "reconnect_retries")
            .Where(kv => reconnectEnabled == null || kv.Key != "reconnect")
            .Where(kv => persistTun == null || kv.Key != "persist_tun")
            .Where(kv => mtuProbe == null || kv.Key != "mtu_probe")
            .Where(kv => killSwitch == null || kv.Key != "kill_switch")
            .Where(kv => pullRoutes == null || kv.Key != "pull_routes")
            .Where(kv => windowsDisableSharing == null || kv.Key != "windows_disable_sharing")
            .Where(kv => windowsPersistentAdapter == null || kv.Key != "windows_persistent_adapter")
            .ToDictionary(kv => kv.Key, kv => kv.Value),
            // Carried, MINUS whatever this form just rewrote.
            //
            // Carrying it wholesale was wrong in the other direction: the user fixes the offending
            // checkbox, saves, and the profile stays rejected forever with no way out of the UI.
            // Dropping it wholesale is the original bug — the manual editor would LAUNDER a typo,
            // since Save rebuilds the config and Validate() then sees a clean one with the setting
            // silently off. The form supplies real values for the booleans below, so those keys are
            // genuinely resolved and only the rest must survive. (Audit 2026-08-01, §10.)
            UnparsedBooleanKeys = UnparsedBooleanKeys
            .Where(k => !EditorControlledBooleanKeys.Contains(k))
            .Where(k => reconnectEnabled == null || k != "reconnect")
            .Where(k => persistTun == null || k != "persist_tun")
            .Where(k => mtuProbe == null || k != "mtu_probe")
            .Where(k => killSwitch == null || k != "kill_switch")
            .Where(k => pullRoutes == null || k != "pull_routes")
            .Where(k => windowsDisableSharing == null || k != "windows_disable_sharing")
            .Where(k => windowsPersistentAdapter == null || k != "windows_persistent_adapter")
            .ToArray(),
            // The native source preserves duplicate declarations until the document is
            // explicitly repaired. Keep the UI diagnostics across unrelated form edits too.
            DuplicateKeys = DuplicateKeys,
        };

    // Opaque native document retains absent/empty fields, foreign fields and draft errors.
    public string? NativeSource { get; init; }
    public string ToQeliUri() => NativeOperation("uri").GetProperty("text").GetString()!;
    public string ToIni() => NativeOperation("export").GetProperty("text").GetString()!;
    public string ToTransportCoreIni() => NativeOperation("runtime").GetProperty("text").GetString()!;
    public void Validate(bool platformCapabilities = true) => _ = NativeOperation("validate");
    public static VpnConfig Parse(string text) { var config=NativeImport(text); config.Validate(); return config; }
    /// <summary>Read a config/link file within the native 256 KiB budget without lossy UTF-8 decoding.</summary>
    public static VpnConfig ParseFile(string path)
    {
        const int maxBytes = 256 * 1024;
        using var file = File.OpenRead(path);
        var bytes = new byte[maxBytes + 1];
        try
        {
            var count = 0;
            while (count < bytes.Length)
            {
                var read = file.Read(bytes.AsSpan(count));
                if (read == 0) break;
                count += read;
            }
            if (count > maxBytes) throw new ArgumentException("Configuration exceeds 256 KiB.", nameof(path));
            return Parse(new UTF8Encoding(false, true).GetString(bytes.AsSpan(0, count)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public static VpnConfig FromIni(string text) => NativeImport(text);
    public static VpnConfig FromQeliUri(string text) => NativeImport(text);
    public VpnConfig Clone() { var c=JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(this))!; c.Id=Guid.NewGuid().ToString("N"); return c; }
    internal const int MtuMin=576;
    internal const int MtuMax=16602;
    public static int AuthCredentialBudget => TransportWireLimits.AuthCredentialBudget;
}
