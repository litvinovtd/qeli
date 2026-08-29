using System.ComponentModel;
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
    /// <summary>Runtime journal detail carried into desktop service/daemon profiles.
    /// It is an application preference, not a transport-core setting.</summary>
    public string LoggingLevel { get; set; } = "info";
    public string? ServerPublicKeyHex { get; init; }     // pinned static key (hex), null = TOFU
    // H-1: bind data keys to the server static identity (folds es into the KDF).
    // Must match the server's auth.bind_static_to_session and requires a pinned key.
    // Default TRUE (secure-by-default since 0.7.1); wire-breaking — set false (or
    // pass bind_static=false) to talk to a legacy 0.7.0 / TOFU server.
    public bool BindStaticToSession { get; init; } = true;
    /// <summary>Permit first-use trust when the proven key cannot be persisted. False keeps
    /// the TOFU store fail-closed; it never weakens an existing-pin mismatch.</summary>
    public bool AllowUnpinnedTofu { get; init; }
    // tun
    // 0 = auto: adopt the MTU the server pushes at auth (falls back to 1400 if the
    // server is too old to push one). A value > 0 is an explicit override.
    public int Mtu { get; init; } = 0;
    // Active UDP path-MTU probing when Mtu == 0 (default on; kill switch = false). No
    // effect on TCP transports (the OS does PMTUD there) or when Mtu > 0 (explicit).
    public bool MtuProbe { get; init; } = true;
    // routing
    public string RoutingMode { get; init; } = "full-tunnel";
    /// <summary>Inner IPv6 negotiation policy: auto, required or off.</summary>
    public string Ipv6Policy { get; init; } = "auto";
    /// <summary>Session migration policy: off, auto or required.</summary>
    public string RoamingPolicy { get; init; } = "auto";
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
    // In a full tunnel whose negotiated plan has no IPv6 address, the platform blocks that
    // family to close the classic dual-stack leak. Set true to explicitly allow native IPv6
    // to bypass such an IPv4-only tunnel. A dual/IPv6 plan always carries IPv6 in qeli.
    public bool AllowIpv6Leak { get; init; }
    // Symmetric escape hatch for an IPv6-only full tunnel. Secure default blocks IPv4.
    public bool AllowIpv4Leak { get; init; }
    // Per-application routing. The value syntax is platform-owned: Android and macOS use
    // package/signing identifiers, while Windows uses canonical executable paths. Keeping the
    // common model typed means a profile can be edited on any desktop without losing the
    // selection and each platform can apply the same include/exclude contract.
    public string AppsMode { get; init; } = "all";
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
    public string DnsMode { get; init; } = "tunnel";
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

    /// <summary>A key that appears twice and is read as a SINGLE value makes the config ambiguous, and the implementations resolved it differently: this parser folds entries into a map and keeps the LAST, while the Rust client takes the FIRST. Two `server` lines therefore sent the Rust client to one host and every GUI client to another, from one file, with nothing reported. Recorded rather than resolved — picking a winner still leaves the others disagreeing. (Audit 2026-08-01, §7.)</summary>
    public IReadOnlyList<string> DuplicateKeys { get; init; } = Array.Empty<string>();

    /// <summary>Every `[qeli]` key any qeli client understands — the union across the four
    /// ports, NOT just the ones this one reads.
    ///
    /// The distinction is the whole point. A key this port ignores is not necessarily a typo:
    /// `keepalive`, `post_up`, `exit_node` and friends are real settings the Rust client acts
    /// on, and a desktop profile carrying them must still open here (it is preserved verbatim
    /// on re-save via the extra-key carry). Only a name NOTHING understands is a typo, and
    /// that is what gets reported — a misspelled `gatway = true` silently leaving the tunnel
    /// split is the failure this catches.
    ///
    /// Kept in sync by `RoundTripKeysAreAllKnown` in the conformance suite, which asserts that
    /// everything `ToIni` emits appears here.</summary>
    /// <summary>Keys this port ACCEPTS but does not model — read into <see cref="CarriedKeys"/>
    /// and written back verbatim, so opening and saving a profile does not strip them.</summary>
    /// <remarks>
    /// They are on the allowlist because a profile carrying them must open here; they are in
    /// THIS list because accepting a key without keeping it is how the open-and-save round trip
    /// silently deleted hooks, security settings and — for the mobile keys — the whole per-app
    /// selection. Allowlisting alone was the first half of the fix and, on its own, the more
    /// dangerous half: it makes the profile open, which is exactly what leads someone to save
    /// it. (Audit 2026-08-02, §4 of the follow-up; Android got both halves first.)
    /// <para>
    /// Declared BEFORE <c>KnownIniKeys</c>, which folds it in — static initialisers run in
    /// declaration order, so the other way round hands <c>Union</c> a null set at class load.
    /// </para>
    /// </remarks>
    public static readonly HashSet<string> CarriedIniKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Not edited by this managed model. Platform/lifecycle fields are preserved for their
        // owner; transport-owned socket settings are consumed by Rust through
        // ToTransportCoreIni even though the desktop editor has no control for them.
        // NB: `dns_servers` used to live here (carried, not understood). It is READ and WRITTEN
        // by this port now — see FromIni/ToIni — so it moved to KnownIniKeys below. Leaving it
        // here as well would have made it both carried and modelled, and `ToIni` would emit it
        // twice: once from CarriedKeys, once from the DNS block. (Audit 2026-08-03, D2.)
        "autostart", "dev_attach", "device_type", "exit_node",
        "gateway_nat", "keepalive", "lan_subnet", "lan_subnet_ipv6", "post_down", "post_up", "tcp_nodelay",
        // Socket settings plus headless-only password sources.
        "password_command", "password_file", "reality_compact", "reality_split",
        "reality_split_delay", "recv_buffer_size", "send_buffer_size",
        // `allow_lan` remains mobile-owned. `apps`/`apps_mode` are modelled below because the
        // Windows and macOS clients now apply the same per-application contract as Android.
        "allow_lan",
    };

    private static readonly HashSet<string> KnownIniKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Read by this port.
        "allow_ipv4_leak", "allow_ipv6_leak", "allow_unpinned_tofu", "apps", "apps_mode", "awg", "bind_static", "dev", "dev_node", "dns", "dns_servers",
        "exclude", "forward",
        "front", "gateway", "heartbeat", "heartbeat_interval", "heartbeat_jitter",
        "heartbeat_size", "include", "jc", "jmax", "jmin", "key", "kill_switch", "local",
        "ipv6", "lport", "metric", "mode", "mtu", "mtu_probe", "name", "obfs_key", "padding", "roaming",
        "padding_max", "padding_min", "pass", "persist_tun", "proto", "quic", "reality_sid",
        "reconnect", "reconnect_base_delay", "reconnect_max_delay", "reconnect_retries",
        "route_file", "route_local", "server", "shaping", "shaping_budget", "shaping_gap_max",
        "shaping_gap_mean", "shaping_gap_min", "shaping_max_size", "shaping_min_size",
        "shaping_stealth", "shaping_stealth_mbps", "sni", "timeout", "user",
    }.Union(CarriedIniKeys).ToHashSet(StringComparer.OrdinalIgnoreCase);

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

    /// <summary>`[qeli]` keys accepted but not modelled (<see cref="CarriedIniKeys"/>), kept
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
    /// <summary>`all` counts too. Validate() accepts `split-tunnel | full-tunnel | all` (the
    /// Rust client's set, see client/route.rs), but this only compared against `full-tunnel` —
    /// so a perfectly valid `routing.mode = "all"` profile validated and then ran as a SPLIT
    /// tunnel, quietly sending everything outside the VPN past it. (Audit 2026-07-31, §2.)</summary>
    public bool IsFullTunnel =>
        AddDefaultGateway
        || RoutingMode.Equals("full-tunnel", StringComparison.OrdinalIgnoreCase)
        || RoutingMode.Equals("all", StringComparison.OrdinalIgnoreCase);


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
        bool? allowIpv4Leak = null, bool? allowIpv6Leak = null) => new()
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
        MtuProbe = mtuProbe ?? MtuProbe,
        KillSwitch = killSwitch ?? KillSwitch,
        // ── preserved from `this` (no form control) ──
        Id = Id,
        LocalAddress = LocalAddress, LocalPort = LocalPort,
        RouteFile = RouteFile, InterfaceMetric = InterfaceMetric, DevNode = DevNode,
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
            .ToArray(),
            // DuplicateKeys is deliberately NOT carried (it defaults to empty). Unlike a bool typo,
            // a duplicate cannot survive this call: the parse already collapsed the key to one
            // value, and saving rewrites the file with one line per key. The ambiguity is genuinely
            // gone, so carrying the marker would reject a profile that is now fine.
        };

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
        // anti-FET fronting. FromQeliUri already read this, but ToQeliUri never wrote it:
        // an obfs profile with `front=none` shared from the desktop came back as the
        // default `websocket` on import — a different framing, so the tunnel never
        // handshakes. Emitted only when it diverges from the default, matching Rust
        // (config/client.rs: `.filter(|s| s != "websocket")`).
        if (!string.IsNullOrEmpty(ObfsFronting) && ObfsFronting != "websocket")
            q.Add($"front={Uri.EscapeDataString(ObfsFronting)}");
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
        if (!RoamingPolicy.Equals("auto", StringComparison.OrdinalIgnoreCase))
            q.Add($"roaming={RoamingPolicy.ToLowerInvariant()}");
        // Per-application routing is deliberately file-only. Application identifiers are
        // platform-owned (Windows paths versus Android/macOS identifiers), and Rust, Android
        // and iOS all treat qeli:// as a connection descriptor rather than device policy.
        // Emitting apps_* here made the shared link contract platform-dependent.
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
        sb.AppendLine($"server = {IniSafe(UriHost(ServerAddress))}:{Port}");
        sb.AppendLine($"proto = {IniSafe(Protocol)}");
        sb.AppendLine($"user = {IniSafe(Username)}");
        sb.AppendLine($"pass = {IniSafe(Password)}");
        if (!string.IsNullOrEmpty(ServerPublicKeyHex)) sb.AppendLine($"key = {IniSafe(ServerPublicKeyHex)}");
        if (!BindStaticToSession) sb.AppendLine("bind_static = false");  // on by default; emit only when off
        if (AllowUnpinnedTofu) sb.AppendLine("allow_unpinned_tofu = true");
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
        if (!Ipv6Policy.Equals("auto", StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"ipv6 = {IniSafe(Ipv6Policy.ToLowerInvariant())}");
        if (!RoamingPolicy.Equals("auto", StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"roaming = {IniSafe(RoamingPolicy.ToLowerInvariant())}");
        if (RouteLocalNetworks) sb.AppendLine("route_local = true");
        if (IncludeRoutes.Count > 0) sb.AppendLine($"include = {string.Join(", ", IncludeRoutes.Select(IniSafe))}");
        if (ExcludeRoutes.Count > 0) sb.AppendLine($"exclude = {string.Join(", ", ExcludeRoutes.Select(IniSafe))}");
        // Emit independently: an empty include list is intentionally invalid/fail-closed and
        // must not silently round-trip back to `all`.
        if (!AppsMode.Equals("all", StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"apps_mode = {IniSafe(AppsMode)}");
        if (Apps.Count > 0)
            sb.AppendLine($"apps = {string.Join(", ", Apps.Select(IniSafe))}");
        if (PersistTun) sb.AppendLine("persist_tun = true");
        if (Forward) sb.AppendLine("forward = true");
        if (KillSwitch) sb.AppendLine("kill_switch = true");
        if (AllowIpv6Leak) sb.AppendLine("allow_ipv6_leak = true");
        if (AllowIpv4Leak) sb.AppendLine("allow_ipv4_leak = true");
        if (!string.IsNullOrEmpty(LocalAddress)) sb.AppendLine($"local = {IniSafe(LocalAddress)}");
        if (LocalPort > 0) sb.AppendLine($"lport = {LocalPort}");
        if (!string.IsNullOrEmpty(RouteFile)) sb.AppendLine($"route_file = {IniSafe(RouteFile)}");
        if (InterfaceMetric > 0) sb.AppendLine($"metric = {InterfaceMetric}");
        if (!string.IsNullOrEmpty(DevNode)) sb.AppendLine($"dev_node = {IniSafe(DevNode)}");
        // `dns` is the MODE, `dns_servers` is the resolver LIST — the split the key table in
        // CONFIG.md documents and the Rust client implements. This port used to pack the list
        // into `dns`, which made a desktop profile with custom resolvers unusable on the
        // CLI/router client (it validates `dns` against the mode words and refused the file).
        // FromIni still ACCEPTS the old spelling, so nothing is lost on upgrade; writing only
        // the documented one migrates a profile the first time it is saved.
        //
        // The mode is emitted whenever it is non-default, independently of the list: `dns = off`
        // has to survive a save/load round-trip, or re-saving would silently turn "leave my
        // resolver alone" back into tunnel-managed DNS.
        if (DnsMode != "tunnel") sb.AppendLine($"dns = {DnsMode}");
        if (DnsServers.Count > 0) sb.AppendLine($"dns_servers = {string.Join(", ", DnsServers.Select(IniSafe))}");
        if (Mtu > 0) sb.AppendLine($"mtu = {Mtu}");  // 0 = auto, omit
        if (!MtuProbe) sb.AppendLine("mtu_probe = false");  // default true, emit only when off

        // Reconnect / timeout / padding / heartbeat / shaping.
        //
        // These used to be missing here entirely, and FromIni did not read them either — so
        // an INI round-trip silently reset all five groups to defaults. That is not just an
        // export concern: the Windows and macOS config editors save through
        // BuildFromForm().ToIni(), so merely OPENING a profile and pressing save discarded
        // whatever the user (or an imported iOS/Android profile) had set. Android hit exactly
        // this and fixed it; the key names below are its dialect, so profiles interchange
        // between the mobile and desktop clients unchanged.
        //
        // Reconnect policy remains sparse because it is GUI lifecycle state. Timeout and the
        // transport data-plane groups are explicit at the GUI→Rust boundary so both sides use
        // the same values even when their UI defaults evolve independently.
        if (!ReconnectEnabled) sb.AppendLine("reconnect = false");
        if (ReconnectMaxRetries != -1) sb.AppendLine($"reconnect_retries = {ReconnectMaxRetries}");
        if (ReconnectBaseDelaySecs != 1) sb.AppendLine($"reconnect_base_delay = {ReconnectBaseDelaySecs}");
        if (ReconnectMaxDelaySecs != 60) sb.AppendLine($"reconnect_max_delay = {ReconnectMaxDelaySecs}");
        sb.AppendLine($"timeout = {ConnectionTimeoutSecs}");
        sb.AppendLine($"padding = {PaddingEnabled.ToString().ToLowerInvariant()}");
        sb.AppendLine($"padding_min = {PaddingMin}");
        sb.AppendLine($"padding_max = {PaddingMax}");
        sb.AppendLine($"heartbeat = {HeartbeatEnabled.ToString().ToLowerInvariant()}");
        sb.AppendLine($"heartbeat_interval = {HeartbeatIntervalMs}");
        sb.AppendLine($"heartbeat_size = {HeartbeatDataSize}");
        sb.AppendLine($"heartbeat_jitter = {HeartbeatJitterMs}");
        sb.AppendLine($"shaping = {ShapingEnabled.ToString().ToLowerInvariant()}");
        sb.AppendLine($"shaping_gap_mean = {ShapingGapMeanMs}");
        sb.AppendLine($"shaping_gap_min = {ShapingGapMinMs}");
        sb.AppendLine($"shaping_gap_max = {ShapingGapMaxMs}");
        sb.AppendLine($"shaping_budget = {ShapingBudgetBytesPerSec}");
        sb.AppendLine($"shaping_min_size = {ShapingMinSize}");
        sb.AppendLine($"shaping_max_size = {ShapingMaxSize}");
        sb.AppendLine($"shaping_stealth = {ShapingStealth.ToString().ToLowerInvariant()}");
        sb.AppendLine($"shaping_stealth_mbps = {ShapingStealthRateMbps}");
        // Re-emit the keys this port accepts but does not model, verbatim and in a stable
        // order. Without this, opening a CLI or mobile profile here and saving it deleted its
        // hooks (`post_up`/`post_down`), socket policy, routing policy and the whole
        // per-app selection — silently, and as a side effect of merely opening it. `IniSafe`
        // applies here too: a value with an embedded newline would otherwise forge config
        // lines on save. (Audit 2026-08-02, §4 of the follow-up.)
        foreach (var key in CarriedKeys.Keys.OrderBy(k => k, StringComparer.Ordinal))
            sb.AppendLine($"{IniSafe(key)} = {IniSafe(CarriedKeys[key])}");
        var text = sb.ToString();

        // Put the UNUSABLE lines back exactly as the author wrote them.
        //
        // Everything above emits the value this port ENDED UP with, which for a bad line is the
        // default — so `reconnect_base_delay = bad` came back as `= 1`, and `gatway = true`
        // came back as nothing at all. That is what let the manual editor launder a typo: the
        // dialog opens on this text, the user never sees their mistake, and OK re-parses a
        // config that is clean because the evidence was dropped on the way out.
        //
        // Restored last so it overrides the modelled emission, and by rewriting the key's line
        // rather than appending — appending would leave two lines for one key, which the parser
        // reports as a duplicate: a second, invented complaint on top of the real one.
        // (Audit 2026-08-02, §4 of the follow-up.)
        return InvalidRawValues.Count == 0 ? text : RestoreInvalidLines(text);
    }

    /// <summary>Canonical profile passed to the Rust transport owner. The ordinary exported
    /// INI stays sparse, but values whose historical GUI defaults differ from Rust defaults
    /// are made explicit at this boundary.</summary>
    public string ToTransportCoreIni()
    {
        var lines = ToIni().Replace("\r", "").Split('\n').ToList();
        int section = lines.FindIndex(line => line.Trim().Equals("[qeli]", StringComparison.OrdinalIgnoreCase));
        if (section < 0) throw new InvalidDataException("transport profile has no [qeli] section");

        void Ensure(string key, string value)
        {
            bool present = lines.Any(line =>
            {
                int eq = line.IndexOf('=');
                return eq > 0 && line[..eq].Trim().Equals(key, StringComparison.OrdinalIgnoreCase);
            });
            if (!present) lines.Insert(++section, $"{key} = {value}");
        }

        Ensure("gateway", IsFullTunnel ? "true" : "false");
        Ensure("timeout", ConnectionTimeoutSecs.ToString());
        Ensure("padding", PaddingEnabled ? "true" : "false");
        Ensure("padding_min", PaddingMin.ToString());
        Ensure("padding_max", PaddingMax.ToString());
        Ensure("heartbeat", HeartbeatEnabled ? "true" : "false");
        Ensure("heartbeat_interval", HeartbeatIntervalMs.ToString());
        Ensure("heartbeat_size", HeartbeatDataSize.ToString());
        Ensure("heartbeat_jitter", HeartbeatJitterMs.ToString());
        Ensure("shaping", ShapingEnabled ? "true" : "false");
        Ensure("shaping_gap_mean", ShapingGapMeanMs.ToString());
        Ensure("shaping_gap_min", ShapingGapMinMs.ToString());
        Ensure("shaping_gap_max", ShapingGapMaxMs.ToString());
        Ensure("shaping_budget", ShapingBudgetBytesPerSec.ToString());
        Ensure("shaping_min_size", ShapingMinSize.ToString());
        Ensure("shaping_max_size", ShapingMaxSize.ToString());
        Ensure("shaping_stealth", ShapingStealth ? "true" : "false");
        Ensure("shaping_stealth_mbps", ShapingStealthRateMbps.ToString());
        return string.Join("\n", lines);
    }

    /// <summary>Replace (or append) one line per <see cref="InvalidRawValues"/> entry.</summary>
    private string RestoreInvalidLines(string ini)
    {
        var lines = ini.Replace("\r", "").Split('\n').ToList();
        foreach (var (key, raw) in InvalidRawValues.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var line = $"{IniSafe(key)} = {IniSafe(raw)}";
            int at = lines.FindIndex(l =>
            {
                int eq = l.IndexOf('=');
                return eq > 0 && l[..eq].Trim().Equals(key, StringComparison.OrdinalIgnoreCase);
            });
            if (at >= 0) lines[at] = line;
            else lines.Insert(Math.Max(lines.Count - 1, 0), line);
        }
        return string.Join("\n", lines);
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
    /// share link, or the canonical flat-INI (everything else). A leading brace is
    /// recognised only to report the retired JSON format by name.
    /// Mirrors the Android VpnConfig.parse.
    /// </summary>
    public static VpnConfig Parse(string text)
    {
        var t = text.TrimStart();
        if (t.StartsWith("qeli://", StringComparison.OrdinalIgnoreCase)) return FromQeliUri(text);
        // JSON is RETIRED, and detected only so the message can say so.
        //
        // It was the original config format and stopped being written years ago; INI replaced
        // it and every tool emits INI. What remained was a second, entirely parallel parser
        // per client — with its own defaults, its own leniency and its own bugs. It kept
        // accruing findings that the INI path had already fixed (numbers silently defaulting,
        // unknown keys ignored, types coerced) because hardening it meant doing every fix
        // twice, in four languages, for a format nobody produces.
        //
        // Letting `{…}` fall through to the INI parser instead would "work" but report a
        // meaningless syntax error on line 1. Someone opening a genuinely old file deserves to
        // be told what happened and what to do. (Retired 2026-08-02.)
        if (t.StartsWith("{"))
        {
            throw new ArgumentException(
                "this is a JSON profile, a format qeli no longer reads — export the profile "
                + "again from the server panel, or use its qeli:// link, to get the current "
                + "INI format");
        }
        return FromIni(text);
    }

    /// <summary>
    /// Parse a flat-INI qeli client config (the current format, single [qeli] section):
    /// server=host:port, proto, user, pass, key, mode, obfs_key, sni, route_local.
    /// Matches qeli/src/config/client.rs from_ini. Full-line # / ; comments only.
    /// </summary>
    public static VpnConfig FromIni(string text)
    {
        var q = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var dupKeys = new List<string>();
        string section = "";
        foreach (var raw in text.Replace("\r", "").Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
            if (line[0] == '[' && line.EndsWith("]")) { section = line[1..^1].Trim(); continue; }
            int eq = line.IndexOf('=');
            if (eq < 0) continue;
            if (section.Equals("qeli", StringComparison.OrdinalIgnoreCase))
            {
                var iniKey = line[..eq].Trim();
                var iniValue = line[(eq + 1)..].Trim();
                if (!q.TryAdd(iniKey, iniValue))
                {
                    // Second occurrence: keep the map's LAST-wins behaviour, so a config that
                    // never had a duplicate parses exactly as before, and record the ambiguity
                    // for Validate() to refuse.
                    q[iniKey] = iniValue;
                    if (!dupKeys.Contains(iniKey)) dupKeys.Add(iniKey);
                }
            }
        }

        string Get(string k, string def = "") => q.TryGetValue(k, out var v) ? v : def;

        var server = Get("server");
        // Accepts the same spellings as the Rust client's `bool_or`. An unrecognised value is
        // RECORDED (see UnparsedBooleanKeys) and falls back to the caller's default, instead of
        // silently reading as false.
        var badBools = new List<string>();
        bool BoolAt(string key, bool dflt)
        {
            if (!q.TryGetValue(key, out var raw)) return dflt;
            var v = raw.Trim();
            if (v.Length == 0) return dflt;
            if (v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1"
                || v.Equals("yes", StringComparison.OrdinalIgnoreCase)
                || v.Equals("on", StringComparison.OrdinalIgnoreCase)) return true;
            if (v.Equals("false", StringComparison.OrdinalIgnoreCase) || v == "0"
                || v.Equals("no", StringComparison.OrdinalIgnoreCase)
                || v.Equals("off", StringComparison.OrdinalIgnoreCase)) return false;
            badBools.Add(key);
            return dflt;
        }
        // A number nobody could parse is a typo, and substituting the default silently is the
        // same failure mode the boolean handling already fixed: the profile connects, just not
        // where the file says. `server = host:notnum` became `host:443` — a different server
        // entirely, with nothing reported. Recorded here and refused by Validate(), while
        // parsing still SUCCEEDS so an editor can open the profile to fix it.
        // (Audit 2026-08-01, §P2.)
        var badNums = new List<string>();
        long LongAt(string key, long dflt)
        {
            var v = Get(key);
            if (v.Length == 0) return dflt;
            if (long.TryParse(v, out var parsed)) return parsed;
            badNums.Add(key);
            return dflt;
        }
        int NumAt(string key, int dflt) => (int)Math.Clamp(LongAt(key, dflt), int.MinValue, int.MaxValue);
        // Out of range is recorded, exactly like unparseable — the Validate() message already
        // says "unparseable OR out-of-range", so this list was simply never being filled.
        //
        // The previous note here called the silent fallback "a documented clamp, not a
        // mistake". It is not a clamp: a clamp would pin the value to the nearest bound,
        // whereas this jumps to the DEFAULT, which is somewhere else entirely. `lport = 99999`
        // became 0 (bind anywhere), a negative heartbeat became 15 s — the setting the user
        // wrote silently replaced by an unrelated one. The `server` port a few lines below had
        // already been fixed this way and the rest were left behind; QeliConformance then
        // pinned the silent behaviour as correct. (Audit 2026-08-02, §11.)
        int RangedNum(string key, int dflt, int lo, int hi)
        {
            int v = NumAt(key, dflt);
            if (v >= lo && v <= hi) return v;
            if (Get(key).Length > 0 && !badNums.Contains(key)) badNums.Add(key);
            return dflt;
        }
        long RangedLong(string key, long dflt, long lo, long hi)
        {
            long v = LongAt(key, dflt);
            if (v >= lo && v <= hi) return v;
            if (Get(key).Length > 0 && !badNums.Contains(key)) badNums.Add(key);
            return dflt;
        }
        var iniPad = CheckedPadding(NumAt("padding_min", 0), NumAt("padding_max", 255));
        string host = "127.0.0.1";
        int port = 443;
        int colon = -1;
        if (server.StartsWith('['))
        {
            int close = server.IndexOf(']');
            if (close <= 1 || close + 1 >= server.Length || server[close + 1] != ':')
                throw new ArgumentException(
                    $"'server' IPv6 endpoint must be [address]:port, got '{server}'");
            host = server[1..close];
            colon = close + 1;
            if (!System.Net.IPAddress.TryParse(host, out var address)
                || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new ArgumentException($"'server' contains an invalid IPv6 address '{host}'");
            if (!int.TryParse(server[(close + 2)..], out port)) badNums.Add("server (port)");
        }
        else
        {
            colon = server.LastIndexOf(':');
            if (colon > 0)
            {
                host = server[..colon];
                if (host.Contains(':'))
                    throw new ArgumentException(
                        $"'server' IPv6 endpoint must be bracketed as [address]:port, got '{server}'");
                if (!int.TryParse(server[(colon + 1)..], out port)) badNums.Add("server (port)");
            }
            else if (server.Length > 0) host = server;
        }
        if (port is < 1 or > 65535)
        {
            // Out of range is as wrong as unparseable: `:0` and `:99999` are not ports, and
            // quietly becoming 443 sends the client somewhere it was never told to go.
            if (server.Length > 0 && colon > 0 && !badNums.Contains("server (port)"))
                badNums.Add("server (port)");
            port = 443;
        }

        // A key that was SUPPLIED but is unusable must fail loudly, never silently unpin.
        //
        // `keyValid ? key : null` used to turn a truncated or corrupted pin into null, and
        // null means TOFU — so a link whose `key` lost one character downgraded the client
        // from "verify this exact server" to "trust whatever answers first", with no message
        // anywhere. Rust, Kotlin and Swift all keep the supplied value and fail at the
        // handshake instead; C# was the only port that quietly weakened the profile.
        // Rejecting at import is the same fail-closed outcome, just with a usable error.
        // An ABSENT key still means TOFU — that is a deliberate configuration, not a typo.
        // (Audit 2026-08-04, H-08.)
        string keyRaw = Get("key").Trim();
        string key = new string(keyRaw.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        bool keyValid = key.Length == 64 && key.Any(ch => ch != '0'); // all-zero = TOFU
        if (keyRaw.Length > 0 && !keyValid)
        {
            throw new ArgumentException(
                $"'key' must be 64 hex digits and not all zero, got '{keyRaw}' ({key.Length} "
                + "hex digits). Leave it out entirely for trust-on-first-use — a malformed "
                + "key must not silently become an unpinned profile.");
        }
        string sni = Get("sni");

        // Routing: full-tunnel by default; `gateway = false` opts into split-tunnel.
        // Mirrors the Rust/Android `gateway` key — the only way to pick split-tunnel
        // via an imported INI / qeli:// link (the GUI routing dropdown is a separate path).
        bool fullTunnel = BoolAt("gateway", true);
        // DNS: `dns = <ip,ip>` is the resolver list here, but the SAME key is a MODE in the
        // Rust/router client (`off` / `tunnel` / `system`).
        //
        // Recognising the mode words was only half the job: they were mapped to "no explicit
        // resolvers", and SetupTun then treats that as "nothing chosen" and installs the public
        // fallback on a full tunnel. So `dns = off` — which means LEAVE MY RESOLVER ALONE —
        // sent every lookup to Cloudflare and Google instead. The mode is now KEPT and honoured
        // at connect time. (Audit 2026-08-02, §3.)
        var dnsRaw = Get("dns");
        string dnsMode = dnsRaw.Equals("off", StringComparison.OrdinalIgnoreCase)
                || dnsRaw.Equals("tunnel", StringComparison.OrdinalIgnoreCase)
                || dnsRaw.Equals("system", StringComparison.OrdinalIgnoreCase)
            ? dnsRaw.ToLowerInvariant()
            : "tunnel";
        // The resolver LIST belongs in `dns_servers`; `dns` is the mode. That is what the
        // documented key table says (CONFIG.md) and what the Rust client implements, and this
        // port was the one deviating — it packed the list into `dns`, so a desktop profile with
        // custom resolvers was REJECTED outright by the CLI/router client ("unknown dns
        // '1.1.1.1, 9.9.9.9'"), while a Rust-written profile lost its `dns_servers` here in the
        // other direction, silently falling back to whatever the server pushed.
        //
        // BOTH forms are read, on purpose: profiles already saved by older builds carry the
        // list in `dns`, and dropping that would wipe the setting on upgrade. Only the
        // documented key is WRITTEN (see ToIni), so files migrate on the next save.
        // `dns_servers` wins when both are present — it is the explicit, current spelling.
        // (Audit 2026-08-03, D2.)
        List<string> ParseResolvers(string raw) =>
            raw.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
        var dnsServersRaw = Get("dns_servers");
        List<string>? dnsList = null;
        if (dnsServersRaw.Length > 0)
        {
            dnsList = ParseResolvers(dnsServersRaw);
        }
        else if (dnsRaw.Length > 0 && !dnsRaw.Equals("off", StringComparison.OrdinalIgnoreCase)
                 && !dnsRaw.Equals("tunnel", StringComparison.OrdinalIgnoreCase)
                 && !dnsRaw.Equals("system", StringComparison.OrdinalIgnoreCase))
        {
            dnsList = ParseResolvers(dnsRaw);   // legacy spelling, migrated on the next save
        }
        if (dnsList != null && dnsList.Count == 0) dnsList = null;

        // Alias: `mode=udp-quic` / `udp-obfs` fold transport+QUIC into the wire mode.
        var (proto, mode, quic) = NormalizeMode(Get("proto", "tcp"), Get("mode", "fake-tls"), BoolAt("quic", false));

        var cfg = new VpnConfig
        {
            Name = Get("name", host),
            ServerAddress = host,
            Port = port,
            Protocol = proto,
            Username = Get("user", "client"),
            Password = Get("pass"),
            ServerPublicKeyHex = keyValid ? key : null,
            // H-1: on by default; needs a pinned key. `bind_static = false` for TOFU.
            BindStaticToSession = BoolAt("bind_static", true),
            AllowUnpinnedTofu = BoolAt("allow_unpinned_tofu", false),
            WireMode = mode,
            ObfsKey = Get("obfs_key"),
            ObfsFronting = Get("front", "websocket"),
            // F2 AmneziaWG junk (off by default). `awg = true` enables; jc/jmin/jmax
            // bound the junk. Clamped to the wire caps (jc<=128, len<=1400).
            AwgEnabled = BoolAt("awg", false),
            AwgJc = (uint)RangedNum("jc", 0, 0, 128),
            AwgJmin = (ushort)RangedNum("jmin", 40, 0, 1400),
            AwgJmax = (ushort)RangedNum("jmax", 300, 0, 1400),
            QuicEnabled = quic,
            Sni = sni.Length > 0 ? sni : null,
            RealityShortId = Get("reality_sid").Length > 0 ? Get("reality_sid") : null,
            RouteLocalNetworks = BoolAt("route_local", false),
            // Explicit per-CIDR routing (comma-separated). `exclude` carves subnets OUT of
            // the tunnel (routed via the physical gateway, so it works in full-tunnel too);
            // `include` forces subnets IN (split-tunnel). Mirrors the Rust/Android keys.
            IncludeRoutes = SplitCidrs(Get("include")),
            ExcludeRoutes = SplitCidrs(Get("exclude")),
            // Keep unknown values verbatim; Validate() rejects them. Coercing a typo to `all`
            // would silently widen the tunnel.
            AppsMode = Get("apps_mode", "all").Trim().ToLowerInvariant(),
            Apps = Get("apps").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            PersistTun = BoolAt("persist_tun", false),
            Forward = BoolAt("forward", false),
            // Was neither parsed nor emitted here, so an imported/exported flat-INI silently
            // dropped the kill-switch flag — the leak protection the user asked for failed
            // OPEN. The Rust client reads it (client.rs); mirror it.
            KillSwitch = BoolAt("kill_switch", false),
            Ipv6Policy = Get("ipv6", "auto").Trim().ToLowerInvariant(),
            RoamingPolicy = Get("roaming", "auto").Trim().ToLowerInvariant(),
            AllowIpv6Leak = BoolAt("allow_ipv6_leak", false),
            AllowIpv4Leak = BoolAt("allow_ipv4_leak", false),
            LocalAddress = Get("local").Length > 0 ? Get("local") : null,
            LocalPort = RangedNum("lport", 0, 1, 65535),
            RouteFile = Get("route_file").Length > 0 ? Get("route_file") : null,
            InterfaceMetric = RangedNum("metric", 0, 1, int.MaxValue),
            // Accept the Rust/Android client's `dev` key as an alias for `dev_node` so a
            // shared flat-INI config's TUN interface name transfers across clients.
            DevNode = Get("dev_node").Length > 0 ? Get("dev_node")
                    : Get("dev").Length > 0 ? Get("dev") : null,
            Mtu = CheckedMtu(NumAt("mtu", 0)),  // 0 = auto
            MtuProbe = BoolAt("mtu_probe", true),
            // The counterpart of the block ToIni now emits. Every one of these defaults to
            // the value the property already carries, so an absent key leaves it untouched
            // and a profile without them behaves exactly as before. (Audit 2026-07-29, #7.)
            ReconnectEnabled = BoolAt("reconnect", true),
            ReconnectMaxRetries = NumAt("reconnect_retries", -1),
            // Bounded by what the reconnect loop can actually WAIT for, not by what a long can
            // hold. `VpnTunnelBase` computes the backoff in ms and passes it to
            // `WaitHandle.WaitOne(int)`; anything past int.MaxValue ms (~24.8 days) truncates
            // on the cast, and a truncated value that lands negative makes WaitOne throw —
            // killing the reconnect loop outright, which is the opposite of what a long delay
            // was asking for. A day is already far beyond any real backoff policy.
            ReconnectBaseDelaySecs = RangedLong("reconnect_base_delay", 1, 1, ReconnectDelaySecsMax),
            ReconnectMaxDelaySecs = RangedLong("reconnect_max_delay", 60, 1, ReconnectDelaySecsMax),
            ConnectionTimeoutSecs = CheckedTimeout(LongAt("timeout", 30)),
            PaddingEnabled = BoolAt("padding", true),
            // Through CheckedPadding: on its own each field only checked `>= 0`,
            // so a hand-written INI could set padding_min > padding_max (an inverted range) or a
            // five-digit padding far past PaddingCeiling — records the peer would reject.
            // (Audit 2026-07-30, #11.)
            PaddingMin = iniPad.Min,
            PaddingMax = iniPad.Max,
            HeartbeatEnabled = BoolAt("heartbeat", true),
            HeartbeatIntervalMs = RangedLong("heartbeat_interval", 15000, 1, long.MaxValue),
            HeartbeatDataSize = RangedNum("heartbeat_size", 16, 0, int.MaxValue),
            HeartbeatJitterMs = RangedLong("heartbeat_jitter", 2000, 0, long.MaxValue),
            ShapingEnabled = BoolAt("shaping", false),
            ShapingGapMeanMs = RangedLong("shaping_gap_mean", 700, 1, long.MaxValue),
            ShapingGapMinMs = RangedLong("shaping_gap_min", 40, 1, long.MaxValue),
            ShapingGapMaxMs = RangedLong("shaping_gap_max", 6000, 1, long.MaxValue),
            ShapingBudgetBytesPerSec = RangedNum("shaping_budget", 16384, 1, int.MaxValue),
            ShapingMinSize = RangedNum("shaping_min_size", 64, 1, int.MaxValue),
            ShapingMaxSize = RangedNum("shaping_max_size", 1024, 1, int.MaxValue),
            ShapingStealth = BoolAt("shaping_stealth", false),
            ShapingStealthRateMbps = RangedNum("shaping_stealth_mbps", 2, 1, int.MaxValue),
            UnparsedBooleanKeys = badBools,
            DuplicateKeys = dupKeys,
            UnparsedNumericKeys = badNums,
            UnknownKeys = q.Keys.Where(k => !KnownIniKeys.Contains(k)).OrderBy(k => k).ToArray(),
            // The offending text itself, so ToIni can put the line back exactly as written.
            // Keyed off the marker lists rather than collected at each reader: the port is
            // recorded as `server (port)`, which is not an INI key and has no line of its own,
            // so it is deliberately absent here — `server = host:99999` is re-emitted whole by
            // the modelled path anyway.
            InvalidRawValues = q
                .Where(kv => badNums.Contains(kv.Key) || badBools.Contains(kv.Key)
                             || !KnownIniKeys.Contains(kv.Key))
                .ToDictionary(kv => kv.Key, kv => kv.Value),
            // Accepted but not modelled — kept so saving does not delete them.
            CarriedKeys = q.Where(kv => CarriedIniKeys.Contains(kv.Key))
                           .ToDictionary(kv => kv.Key, kv => kv.Value),
            RoutingMode = fullTunnel ? "full-tunnel" : "split-tunnel",
            AddDefaultGateway = fullTunnel,
            DnsServers = dnsList ?? new List<string>(),  // empty when unset; server push may fill it
            DnsMode = dnsMode,
        };
        // NB: `Validate()` is deliberately NOT called here.
        //
        // `FromIni` is the LENIENT parser: it clamps out-of-range numbers and records them in
        // `UnparsedNumericKeys` / `InvalidRawValues` so the config editor can open a broken
        // profile and show what is wrong — and `WireConformance.RunIniBounds` asserts exactly
        // that by feeding it out-of-range values on purpose. Validating in here made both
        // impossible (the first attempt at this fix did, and the harness threw instead of
        // running). The check belongs at the IMPORT boundary, where an untrusted profile is
        // being ADDED — see the `Parse` call sites in the two GUIs. `FromQeliUri` does
        // validate, because a link is always an import and never an editor load.
        // (Audit 2026-08-04, H-07.)
        return cfg;
    }

    // ── imported-value ranges ────────────────────────────────────────────────
    // `port` and the server-pushed `max_streams` were range-checked at import, but `mtu`
    // and the padding bounds were not: a hand-written config or a pasted
    // `qeli://…?mtu=999999` (or a negative) became a profile that failed at connect with
    // an opaque TUN/socket error, and an out-of-range padding_max built records the peer
    // rejects as oversized. Same ranges the Rust client enforces — config/client.rs:
    // mtu is 0 (auto) or 576..=16602; padding is bounded by the 1400-byte wire ceiling the
    // per-packet pad_cap uses. (Audit 2026-07-27, C6)
    internal const int MtuMin = 576;
    /// <summary>Derived, in Rust, from the record format (protocol/packet.rs MAX_TUNNEL_MTU): a record holds nonce + counter + payload + padding-length + tag and must fit MAX_RECORD_SIZE, so anything larger the PEER REJECTS. Mirrored here as a literal; the four ports and the two UIs must all carry the same number, because raising it in one place only is worse than not raising it — see Audit 2026-08-01 §1.</summary>
    internal const int MtuMax = 16602;
    private const int PaddingCeiling = 1400;

    /// <summary>Range-check an explicit TUN MTU from a config FILE (flat-INI);
    /// 0 = auto. REJECTS, like the Rust <c>from_ini</c>: a bad value in a file the user
    /// wrote by hand is a mistake worth surfacing at import (both GUI import paths show
    /// the message), not something to silently rewrite. (Audit 2026-07-27, C6)</summary>
    private static int CheckedMtu(int mtu) =>
        mtu == 0 || (mtu >= MtuMin && mtu <= MtuMax)
            ? mtu
            : throw new FormatException($"invalid mtu {mtu} — expected 0 (auto) or {MtuMin}..{MtuMax}");

    /// <summary>Same range for a <c>qeli://</c> link, but falls back to auto instead of
    /// throwing — mirrors the Rust link importer, which is infallible and only warns. A
    /// scanned or pasted link should still yield a usable profile. (Audit 2026-07-27, C6)</summary>
    private static int LinkMtu(int mtu) => mtu == 0 || (mtu >= MtuMin && mtu <= MtuMax) ? mtu : 0;

    /// <summary>Clamp the connect timeout to the common 1..300 s transport contract.
    /// This prevents overflow or effectively unbounded waits in every consumer, including
    /// the active Rust runtime and retained configuration diagnostics.</summary>
    private const long TimeoutSecsMin = 1;
    private const long TimeoutSecsMax = 300;

    /// <summary>Upper bound for both reconnect delays, in seconds (one day).</summary>
    /// <remarks>
    /// Not a taste judgement about backoff: the loop in <c>VpnTunnelBase</c> ends at
    /// <c>WaitHandle.WaitOne(int)</c>, so a delay past <c>int.MaxValue</c> ms (~24.8 days)
    /// truncates on the cast and can land negative, which throws and takes the reconnect loop
    /// with it. A day leaves three orders of magnitude of headroom under that cliff.
    /// </remarks>
    private const long ReconnectDelaySecsMax = 86_400;

    private static long CheckedTimeout(long secs) =>
        secs <= 0 ? 30 : Math.Clamp(secs, TimeoutSecsMin, TimeoutSecsMax);

    /// <summary>Clamp imported padding bounds to 0..1400 and restore min &lt;= max. Clamped
    /// rather than rejected: unlike mtu these are pure obfuscation knobs, so narrowing them
    /// costs the user nothing while an oversized max would make every data record exceed
    /// PacketCodec.MaxRecordSize. (Audit 2026-07-27, C6)</summary>
    private static (int Min, int Max) CheckedPadding(int min, int max)
    {
        min = Math.Clamp(min, 0, PaddingCeiling);
        return (min, Math.Clamp(max, min, PaddingCeiling));
    }

    /// <summary>Largest `user` + `:` + `pass`, in UTF-8 bytes, that still fits one AUTH
    /// datagram.</summary>
    /// <remarks>
    /// The AUTH plaintext is <c>proof(32)</c> + the optional <c>[0x00 device_id(16)]</c> prefix
    /// + <c>user:pass</c>, and the whole thing rides in one unfragmented datagram — so the
    /// credentials are what decides whether it survives a path that drops IP fragments.
    /// Derived from <see cref="TransportWireLimits.AuthCredentialBudget"/>, the same
    /// production wire-size contract used by the standalone managed conformance codec.
    /// </remarks>
    public static int AuthCredentialBudget => TransportWireLimits.AuthCredentialBudget;

    /// <summary>True for a bare IPv4 or IPv6 literal.</summary>
    /// <remarks>
    /// Deliberately not <c>Dns.GetHostAddresses</c>: that RESOLVES anything which is not a
    /// literal, which is a network round trip during config validation for a value that is by
    /// definition not resolvable yet.
    /// </remarks>
    private static bool IsIpLiteral(string s)
    {
        var v = s.Trim();
        if (v.Length == 0) return false;
        if (!System.Net.IPAddress.TryParse(v, out var addr)) return false;
        // `IPAddress.TryParse` accepts the historical IPv4 shorthands — `1` → 0.0.0.1,
        // `127.1` → 127.0.0.1, `0x7f000001` → 127.0.0.1 — which Rust, Kotlin and Swift all
        // refuse. Choosing the "system parser" here for exactness bought the opposite: one
        // profile validated on Windows/macOS and was rejected everywhere else, which is worse
        // than either behaviour on its own. Require the canonical dotted quad by round-tripping
        // the parse: a shorthand does not print back as it was written.
        // (Audit 2026-08-02, follow-up.)
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return addr.ToString() == v;
        }
        return true;   // IPv6 has no such shorthand; TryParse is strict there.
    }

    /// <summary>Reject a config the runtime would then silently reinterpret. The desktop client
    /// had no equivalent of the Rust client's <c>ClientConfig::validate()</c>, so every string
    /// enum fell through to another branch on a typo: an unknown protocol became TCP, an unknown
    /// wire mode became fake-TLS, an unknown <c>front</c> meant raw obfs — and an unparseable
    /// boolean read as false, which disabled the kill switch and the static-key binding.
    ///
    /// Called at CONNECT, not at load: an editor must still be able to open a bad profile in
    /// order to fix it. Same split as the Rust client. (Audit 2026-07-31.)
    ///
    /// <para><paramref name="platformCapabilities"/> is retained for source compatibility
    /// with older callers. Runtime family support is now negotiated by the Rust core against
    /// the concrete adapter capabilities before a NetworkPlan is emitted.</para></summary>
    public void Validate(bool platformCapabilities = true)
    {
        _ = platformCapabilities;
        // The flat INI spells the MODE and the RESOLVER LIST with the same `dns` key, so a
        // misspelled mode does not fall through to an error — it falls through to being read
        // as an ADDRESS. `dns = of` became a resolver named "of", the tunnel installed it, and
        // every lookup went to something that cannot answer. A resolver must be an IP literal
        // (you cannot resolve a resolver by name), so checking that turns the typo back into
        // an error. (Audit 2026-08-02, follow-up.)
        foreach (var server in DnsServers)
        {
            if (!string.IsNullOrWhiteSpace(server) && !IsIpLiteral(server))
            {
                throw new ArgumentException(
                    $"dns server '{server}' is not an IP address — if you meant a mode, it must "
                    + "be off, tunnel or system");
            }
        }
        if (!new[] { "off", "tunnel", "system" }.Contains(DnsMode.ToLowerInvariant()))
        {
            throw new ArgumentException(
                $"dns mode must be off, tunnel or system — got '{DnsMode}'");
        }
        if (!new[] { "auto", "required", "off" }.Contains(Ipv6Policy.ToLowerInvariant()))
        {
            throw new ArgumentException(
                $"ipv6 policy must be auto, required or off — got '{Ipv6Policy}'");
        }
        if (!new[] { "off", "auto", "required" }.Contains(RoamingPolicy.ToLowerInvariant()))
        {
            throw new ArgumentException(
                $"roaming policy must be off, auto or required — got '{RoamingPolicy}'");
        }
        if (RoamingPolicy.Equals("required", StringComparison.OrdinalIgnoreCase)
            && (!string.IsNullOrWhiteSpace(LocalAddress) || LocalPort != 0))
        {
            throw new ArgumentException(
                "roaming = required cannot be combined with local or a non-zero lport");
        }
        if (Mtu != 0 && (Mtu < MtuMin || Mtu > MtuMax))
        {
            throw new ArgumentException(
                $"mtu must be 0 (auto) or {MtuMin}..{MtuMax}, got {Mtu}");
        }
        if (Ipv6Policy.Equals("required", StringComparison.OrdinalIgnoreCase)
            && Mtu > 0 && Mtu < 1280)
        {
            throw new ArgumentException(
                $"ipv6 = required needs an explicit mtu of at least 1280 (or 0 for auto), got {Mtu}");
        }
        // Credentials must leave the AUTH message inside one datagram on UDP.
        //
        // AUTH goes out UNFRAGMENTED, unlike the ClientHello beside it and the AuthOK coming
        // back, and its size IS the credentials — nothing else in it varies. A long generated
        // token used as a password pushes the record past the fragment budget, the datagram
        // then needs IP fragmentation, and a mobile or CGNAT path drops it. The symptom is a
        // handshake that times out only on those networks: indistinguishable from an
        // unreachable server, with nothing in any log. This bound exists in the Rust client;
        // without it here the same profile worked on one client and hung on another.
        //
        // BYTES, not characters: the wire carries UTF-8, so a non-Latin password is longer
        // than it looks. (Audit 2026-08-02, follow-up.)
        int credentialBytes = Encoding.UTF8.GetByteCount(Username)
            + Encoding.UTF8.GetByteCount(Password) + 1;  // + the ':' separator
        if (credentialBytes > AuthCredentialBudget)
        {
            throw new ArgumentException(
                $"'user' + 'pass' are {credentialBytes} bytes, over the {AuthCredentialBudget} "
                + "a UDP AUTH datagram can carry — the handshake would be dropped by any path "
                + "that discards IP fragments (mobile, CGNAT) and would look like an "
                + "unreachable server. Shorten them.");
        }
        if (DuplicateKeys.Count > 0)
        {
            throw new ArgumentException(
                $"key(s) {string.Join(", ", DuplicateKeys)} appear more than once and are read "
                + "as a single value; implementations disagree on which wins — keep one");
        }
        if (UnknownKeys.Count > 0)
        {
            throw new ArgumentException(
                $"unknown key(s), likely misspelled: {string.Join(", ", UnknownKeys)} — nothing "
                + "reads these, so the setting they were meant to change is at its default");
        }
        if (UnparsedNumericKeys.Count > 0)
        {
            throw new ArgumentException(
                $"unparseable or out-of-range number for {string.Join(", ", UnparsedNumericKeys)} "
                + "— the default would have been used instead, which for a port means "
                + "connecting somewhere the config never named");
        }
        if (UnparsedBooleanKeys.Count > 0)
        {
            throw new ArgumentException(
                $"unrecognised boolean value for {string.Join(", ", UnparsedBooleanKeys)} — "
                + "expected true/false, yes/no, on/off or 1/0");
        }

        static void Enum_(string field, string got, params string[] allowed)
        {
            foreach (var a in allowed)
            {
                if (string.Equals(got, a, StringComparison.Ordinal)) return;
            }
            throw new ArgumentException(
                $"unknown {field} '{got}' — expected {string.Join(" or ", allowed.Select(x => $"'{x}'"))}");
        }

        if (Port is < 1 or > 65535) throw new ArgumentException($"'server' port out of range: {Port}");
        if (string.IsNullOrWhiteSpace(ServerAddress))
            throw new ArgumentException("'server' has empty host");
        if (ServerAddress.Contains('[') || ServerAddress.Contains(']'))
            throw new ArgumentException(
                "'server' stores a bare host; brackets belong only around an IPv6 endpoint in INI");
        if (ServerAddress.Contains(':') && !IsIpLiteral(ServerAddress))
            throw new ArgumentException($"'server' contains an invalid IPv6 address '{ServerAddress}'");
        Enum_("proto", Protocol, "tcp", "udp");
        Enum_("mode", WireMode, "fake-tls", "obfs", "plain", "reality-tls");
        Enum_("apps_mode", AppsMode, "all", "include", "exclude");
        if (!AppsMode.Equals("all", StringComparison.OrdinalIgnoreCase) && Apps.Count == 0)
            throw new ArgumentException(
                "'apps_mode' is include/exclude but 'apps' is empty — refusing to silently "
                + "turn a per-application profile into an unrestricted tunnel");
        // Forwarded LAN packets have no owning desktop application. WinDivert therefore has
        // no process identity with which to include/exclude them, and the macOS transparent
        // proxy only receives application flows. Both platform SetupTun branches deliberately
        // skip host forwarding in per-app mode; accepting the pair made `forward = true` look
        // active while it did nothing. Refuse the unsupported topology at the config boundary.
        if (Forward && UsesAppFilter)
            throw new ArgumentException(
                "'forward = true' cannot be combined with per-application routing on desktop — "
                + "forwarded LAN traffic has no application identity; use 'apps_mode = all'");
        // Both fields are individually valid and the PAIR is not. The server refuses these two
        // combinations, so a client that accepts them cannot reach any working profile — it
        // just fails later and less clearly. Worse for `reality-tls`: nothing about the name
        // says TCP, so the operator believes they have the strongest masking available while
        // the datagram path quietly falls back to fake-tls framing. (Audit 2026-08-03, P2.)
        if (Protocol.Equals("udp", StringComparison.OrdinalIgnoreCase))
        {
            if (WireMode.Equals("plain", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "'mode = plain' is TCP-only (raw framing has no datagram form) — set "
                    + "proto = tcp, or pick obfs/fake-tls for a UDP profile");
            }
            if (WireMode.Equals("reality-tls", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "'mode = reality-tls' is TCP-only — it terminates a REAL TLS 1.3 session, "
                    + "which UDP cannot carry. Set proto = tcp, or pick obfs for UDP");
            }
        }
        // A mode that needs a secret must HAVE it, or the profile is valid and unusable.
        //
        // Each of these was checked at the use site or not at all, so the editor called the
        // profile fine and the failure surfaced mid-handshake — where it reads as a server or
        // network problem rather than a missing field. The short_id is the sharpest case: this
        // side parses hex leniently and the SERVER strictly, so `reality_sid = deadbeeg` became
        // a different token here and matched nothing there. (Audit 2026-08-03, P2.)
        if (WireMode.Equals("reality-tls", StringComparison.OrdinalIgnoreCase))
        {
            var sid = (RealityShortId ?? "").Trim();
            if (sid.Length == 0)
            {
                throw new ArgumentException(
                    "'mode = reality-tls' requires 'reality_sid' — it is the token the server "
                    + "uses to tell qeli clients from probes; without it this client is treated "
                    + "as a probe and proxied to the decoy site");
            }
            if (sid.Length % 2 != 0 || sid.Length > 16
                || !sid.All(Uri.IsHexDigit) || sid.All(c => c == '0'))
            {
                throw new ArgumentException(
                    $"'reality_sid' must be 1..8 bytes of hex (2..16 hex digits, not all zero), "
                    + $"got '{sid}' — this client parses hex leniently and the SERVER does not, "
                    + "so a malformed value silently becomes a different token and never matches");
            }
            if ((ServerPublicKeyHex ?? "").Trim().Length == 0)
            {
                throw new ArgumentException(
                    "'mode = reality-tls' requires a pinned server 'key' — REALITY's whole point "
                    + "is that an unauthenticated peer is proxied to the decoy site, which a "
                    + "TOFU client cannot tell apart from the real server");
            }
        }
        if (WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase) && ObfsKey.Trim().Length == 0)
        {
            throw new ArgumentException(
                "'mode = obfs' requires a non-empty 'obfs_key' — an empty key is publicly "
                + "derivable, so the stream is obfuscated against nobody (the server refuses "
                + "the same combination)");
        }
        Enum_("front", ObfsFronting, "websocket", "none");
        Enum_("routing mode", RoutingMode, "split-tunnel", "full-tunnel", "all");
        foreach (var (field, routes) in new[]
                 {
                     ("include", (IEnumerable<string>)IncludeRoutes),
                     ("exclude", (IEnumerable<string>)ExcludeRoutes),
                 })
        {
            foreach (string route in routes)
            {
                if (!IsStrictCidr(route))
                    throw new ArgumentException(
                        $"'{field}' route '{route}' is not an IPv4/IPv6 CIDR literal");
            }
        }
        if (ShapingGapMeanMs <= 0 || ShapingGapMinMs <= 0 || ShapingGapMaxMs <= 0
            || ShapingBudgetBytesPerSec <= 0 || ShapingMinSize <= 0 || ShapingMaxSize <= 0
            || ShapingStealthRateMbps <= 0)
        {
            throw new ArgumentException(
                "shaping durations, sizes, budget and stealth rate must be positive");
        }
        if (ShapingGapMinMs > ShapingGapMaxMs)
            throw new ArgumentException(
                $"shaping gap range is inverted: {ShapingGapMinMs}..{ShapingGapMaxMs}");
        if (ShapingMinSize > ShapingMaxSize)
            throw new ArgumentException(
                $"shaping size range is inverted: {ShapingMinSize}..{ShapingMaxSize}");
        if (ShapingEnabled && ShapingBudgetBytesPerSec < ShapingMaxSize)
        {
            throw new ArgumentException(
                $"shaping budget ({ShapingBudgetBytesPerSec}) must be at least max_size "
                + $"({ShapingMaxSize}) so each scheduled cover record can be emitted");
        }
        if (ConnectionTimeoutSecs is < 1 or > 300)
            throw new ArgumentException($"'timeout' must be 1..300, got {ConnectionTimeoutSecs}");
    }


    /// <summary>Split a comma-separated CIDR list, trimming blanks. Values are validated
    /// again (strict IP literal) before being spliced into route commands.</summary>
    private static List<string> SplitCidrs(string v) =>
        v.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

    private static bool IsStrictCidr(string value)
    {
        string text = value.Trim();
        if (text.Length == 0) return false;
        string[] parts = text.Split('/');
        if (parts.Length is < 1 or > 2) return false;
        string addressText = parts[0];
        bool ipv6 = addressText.Contains(':');
        if (!System.Net.IPAddress.TryParse(addressText, out var address)) return false;
        if (ipv6 != (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6))
            return false;
        if (!ipv6)
        {
            string[] octets = addressText.Split('.');
            if (octets.Length != 4 || octets.Any(o => o.Length == 0
                    || o.Any(c => !char.IsAsciiDigit(c))
                    || !byte.TryParse(o, out _)))
                return false;
        }
        int maximum = ipv6 ? 128 : 32;
        return parts.Length == 1
            || (parts[1].Length > 0 && parts[1].All(char.IsAsciiDigit)
                && int.TryParse(parts[1], out int prefix) && prefix <= maximum);
    }

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
            if (!System.Net.IPAddress.TryParse(host, out var address)
                || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new FormatException($"invalid IPv6 address in qeli:// link: '{host}'");
            if (!int.TryParse(hostPort[(rb + 2)..], out port))
                throw new FormatException("invalid port in qeli:// link");
        }
        else
        {
            int colonIdx = hostPort.LastIndexOf(':');
            if (colonIdx <= 0) throw new FormatException("qeli:// authority missing :port");
            host = hostPort[..colonIdx];
            if (host.Contains(':') || host.Contains('[') || host.Contains(']'))
                throw new FormatException(
                    "qeli:// IPv6 authority must be bracketed as [address]:port");
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
        string roaming = "auto";
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
                            // Supplied-but-unusable must fail loudly, never silently unpin —
                            // see the identical guard in FromIni. (Audit 2026-08-04, H-08.)
                            var raw = v.Trim();
                            var hex = new string(raw.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
                            bool ok = hex.Length == 64 && hex.Any(ch => ch != '0');
                            if (raw.Length > 0 && !ok)
                            {
                                throw new ArgumentException(
                                    $"'key' must be 64 hex digits and not all zero, got '{raw}' "
                                    + $"({hex.Length} hex digits). Omit it entirely for "
                                    + "trust-on-first-use — a malformed key must not silently "
                                    + "become an unpinned profile.");
                            }
                            key = ok ? hex : null;
                            break;
                        }
                    case "sni": sni = v.Length == 0 ? null : v; break;
                    case "rsid": rsid = v.Length == 0 ? null : v; break;
                    case "obfs": obfs = v; break;
                    case "front": if (v.Length > 0) front = v; break;
                    case "quic": quic = v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase); break;
                    case "mtu": int.TryParse(v, out mtu); break;
                    case "roaming": roaming = v.Trim().ToLowerInvariant(); break;
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

        var cfg = new VpnConfig
        {
            Name = label,
            ServerAddress = host,
            Port = port,
            Protocol = proto,
            Username = user,
            Password = pass,
            ServerPublicKeyHex = key,
            WireMode = mode,
            ObfsKey = obfs,
            ObfsFronting = front,
            Sni = sni,
            QuicEnabled = quic,
            AwgEnabled = awg,
            AwgJc = awgJc,
            AwgJmin = awgJmin,
            AwgJmax = awgJmax,
            RealityShortId = rsid,
            RoamingPolicy = roaming,
            Mtu = LinkMtu(mtu),
        };
        // Kotlin's fromQeliUri and Swift's fromQeliURI both end with validate(); C# defined
        // the same checks and then never ran them on any import path — grep found Validate()
        // called only from the test harness. So every semantic rule the other clients
        // enforce (mode must be a known value, udp+plain and udp+reality-tls are refused,
        // mode=obfs needs an obfs_key, mode=reality-tls needs BOTH a reality_sid and a
        // pinned key) was inert here: a link Android and iOS reject imported cleanly on
        // Windows and macOS, and reality-tls without a pinned key means the client cannot
        // tell the real server from the decoy an active prober is proxied to.
        // (Audit 2026-08-04, H-07.)
        cfg.Validate(platformCapabilities: false);
        return cfg;
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
