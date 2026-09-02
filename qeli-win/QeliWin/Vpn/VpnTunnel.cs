using System.Net;
using System.Text.Json;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliWin.Vpn;

/// <summary>Windows platform binding for the shared qeli data plane
/// (<see cref="VpnTunnelBase"/>): opens a WintunAdapter and configures the
/// addressing / routes / DNS for the session via NetworkConfigurator.</summary>
public sealed class VpnTunnel : VpnTunnelBase
{
    private NetworkConfigurator? _net;
    private bool _useWinDivert;
    private readonly Dictionary<ulong, RoamingObservation> _roamingObservations = new();
    private readonly Dictionary<ulong, RoamingCandidate> _roamingCandidates = new();

    private sealed record RoamingObservation(
        ulong Generation,
        string PathIdentity,
        VpnConfig Config,
        string[] CarrierAddresses);

    private sealed class RoamingCandidate
    {
        public required ulong Generation { get; init; }
        public required ulong CandidateId { get; init; }
        public required ulong UpdateId { get; init; }
        public required string PathIdentity { get; init; }
        public required VpnConfig Config { get; init; }
        public required string[] OldCarriers { get; init; }
        public required string[] NewCarriers { get; init; }
        public required string[] UnionCarriers { get; init; }
        public required string[] PolicyCarriers { get; set; }
        public NetworkConfigurator.RoamingRouteLease? Routes { get; init; }
        public bool Bound { get; set; }
    }

    // Normal profiles keep the zero-copy Rust-owned Wintun path. Per-app profiles use
    // WinDivert as an IPacketTunDevice, so the shared ABI 1.11 packet pumps connect it to
    // the same Rust transport core without replacing or duplicating that core.
    protected override bool NativeWintunOwnership => !_useWinDivert;

    // A retained system Wintun can only be replaced safely while the shared base owns the
    // temporary fail-closed firewall transaction. Per-app WinDivert plans are reconfigured
    // in place, but keeping this capability enabled is required for the normal system-TUN
    // path when an authenticated NetworkPlan changes under persist_tun.
    protected override bool SupportsPlanReplacementGuard => true;

    protected override ulong NativeIpv6Capabilities(VpnConfig config) =>
        NativeIpv6SystemPlanCapabilities | NativeIpv6KillSwitchCapability;

    // A fixed source address/port is an explicit user routing contract. Candidate sockets
    // are deliberately left on reconnect fallback until the Rust candidate factory can
    // preserve that exact bind. Every ordinary TCP and UDP transport shares this path.
    protected override ulong NativeRoamingCapabilities(VpnConfig config) =>
        AllowsNativePathRoaming(config)
            ? NativeRoamingPathCapabilities | NativePathRefreshCapability
            : 0;

    internal static bool AllowsNativePathRoaming(VpnConfig config) =>
        !config.RoamingPolicy.Equals("off", StringComparison.OrdinalIgnoreCase)
        && string.IsNullOrWhiteSpace(config.LocalAddress) && config.LocalPort == 0;

    internal static void RunRoamingCapabilitySelfTest(Action<string, bool> check)
    {
        var ordinaryProfiles = new[]
        {
            new VpnConfig { Protocol = "tcp", WireMode = "fake-tls" },
            new VpnConfig { Protocol = "udp", WireMode = "fake-tls" },
            new VpnConfig { Protocol = "udp", WireMode = "fake-tls", QuicEnabled = true },
            new VpnConfig { Protocol = "udp", WireMode = "obfs" },
        };
        check("Native path roaming covers TCP and every UDP camouflage mode",
            ordinaryProfiles.All(AllowsNativePathRoaming));
        check("Fixed local address or port stays on reconnect fallback",
            !AllowsNativePathRoaming(new VpnConfig { LocalAddress = "192.0.2.10" })
            && !AllowsNativePathRoaming(new VpnConfig { LocalPort = 41000 }));
        check("roaming = off disables the native path executor",
            !AllowsNativePathRoaming(new VpnConfig { RoamingPolicy = "off" }));
    }

    protected override NativePathUpdate? CaptureNativeRoamingPath(VpnConfig config,
        IReadOnlyList<string> carrierAddresses, ulong generation, ulong updateId, string reason)
    {
        IPAddress[] carriers = carrierAddresses
            .Select(IPAddress.Parse)
            .Distinct()
            .ToArray();
        NativePathUpdate update = NetworkConfigurator.CaptureRoamingPath(
            carriers, generation, updateId, reason);
        if (_roamingObservations.Count >= 16)
            _roamingObservations.Remove(_roamingObservations.Keys.Min());
        _roamingObservations[updateId] = new RoamingObservation(
            generation, PathIdentity(update), config,
            carriers.Select(item => item.ToString()).ToArray());
        return update;
    }

    protected override void ApplyNativeRoamingCommand(NativePathCommand command)
    {
        switch (command.Action)
        {
            case "prepare_path": PrepareRoamingCandidate(command); break;
            case "bind_socket": BindRoamingCandidate(command); break;
            case "commit_path": CommitRoamingCandidate(command); break;
            case "abort_path": AbortRoamingCandidate(command); break;
            default: throw new InvalidOperationException(
                $"unsupported Windows roaming action {command.Action}");
        }
    }

    protected override void ResetNativeRoamingPath()
    {
        var failures = new List<string>();
        foreach (RoamingCandidate candidate in _roamingCandidates.Values.ToArray())
        {
            try
            {
                AbortCandidate(candidate);
                _roamingCandidates.Remove(candidate.CandidateId);
            }
            catch (Exception error) { failures.Add(error.Message); }
        }
        _roamingObservations.Clear();
        if (failures.Count != 0)
            throw new InvalidOperationException(
                "Windows roaming cleanup failed: " + string.Join("; ", failures));
    }

    private void PrepareRoamingCandidate(NativePathCommand command)
    {
        if (_roamingCandidates.Count != 0 || _roamingCandidates.ContainsKey(command.CandidateId))
            throw new InvalidOperationException("another Windows roaming candidate is already active");
        if (!_roamingObservations.TryGetValue(command.Path.UpdateId, out var observation)
            || observation.Generation != command.Generation
            || observation.PathIdentity != PathIdentity(command.Path))
            throw new InvalidOperationException("Windows roaming PREPARE does not match an observation");

        string[] next = command.Path.ResolvedAddresses
            .Select(item => IPAddress.Parse(item.Address).ToString())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        string[] union = observation.CarrierAddresses.Concat(next)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        NetworkConfigurator.RoamingRouteLease? routes = null;
        if (_useWinDivert)
        {
            if (_tun is not WinDivertAdapter)
                throw new InvalidOperationException("WinDivert roaming adapter is not active");
        }
        else
        {
            routes = (_net ?? throw new InvalidOperationException(
                "Windows network configurator is not active")).PrepareRoamingRoutes(command.Path);
        }

        var candidate = new RoamingCandidate
        {
            Generation = command.Generation,
            CandidateId = command.CandidateId,
            UpdateId = command.Path.UpdateId,
            PathIdentity = observation.PathIdentity,
            Config = observation.Config,
            OldCarriers = observation.CarrierAddresses,
            NewCarriers = next,
            UnionCarriers = union,
            PolicyCarriers = observation.CarrierAddresses,
            Routes = routes,
        };
        try
        {
            SetCandidatePolicy(candidate, union);
        }
        catch (Exception setupError)
        {
            var rollbackFailures = new List<Exception>();
            try { routes?.Abort(); }
            catch (Exception error) { rollbackFailures.Add(error); }
            try { SetCandidatePolicy(candidate, candidate.OldCarriers); }
            catch (Exception error) { rollbackFailures.Add(error); }
            if (rollbackFailures.Count != 0)
            {
                rollbackFailures.Insert(0, setupError);
                throw new AggregateException(
                    "Windows roaming PREPARE and rollback both failed", rollbackFailures);
            }
            throw;
        }
        _roamingCandidates.Add(command.CandidateId, candidate);
        Log($"Windows roaming PREPARE {command.CandidateId}: interface "
            + $"{command.Path.InterfaceIndex}, carriers {string.Join(", ", union)}");
    }

    private void BindRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        if (candidate.Bound)
            throw new InvalidOperationException("Windows roaming candidate socket is already bound");
        uint ifIndex = command.Path.InterfaceIndex
            ?? throw new InvalidOperationException("Windows roaming BIND has no interface index");
        long socket = command.SocketHandle
            ?? throw new InvalidOperationException("Windows roaming BIND has no socket handle");
        WindowsRoamingSocket.Bind(socket, ifIndex,
            command.Path.LocalAddresses.Select(IPAddress.Parse).ToArray());
        candidate.Bound = true;
        Log($"Windows roaming BIND {command.CandidateId}: SOCKET {socket} -> if {ifIndex}");
    }

    private void CommitRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        if (!candidate.Bound)
            throw new InvalidOperationException("Windows roaming COMMIT arrived before BIND");
        SetCandidatePolicy(candidate, candidate.NewCarriers);
        try { candidate.Routes?.Commit(); }
        catch (Exception routeError)
        {
            try { SetCandidatePolicy(candidate, candidate.UnionCarriers); }
            catch (Exception policyError)
            {
                throw new AggregateException(
                    "Windows roaming route commit and policy rollback both failed",
                    routeError, policyError);
            }
            throw;
        }
        _roamingCandidates.Remove(candidate.CandidateId);
        _roamingObservations.Remove(candidate.UpdateId);
        Log($"Windows roaming COMMIT {candidate.CandidateId}: "
            + string.Join(", ", candidate.NewCarriers));
    }

    private void AbortRoamingCandidate(NativePathCommand command)
    {
        RoamingCandidate candidate = GetCandidate(command);
        AbortCandidate(candidate);
        _roamingCandidates.Remove(candidate.CandidateId);
        _roamingObservations.Remove(candidate.UpdateId);
        Log($"Windows roaming ABORT {candidate.CandidateId}");
    }

    private void AbortCandidate(RoamingCandidate candidate)
    {
        var failures = new List<Exception>();
        try { candidate.Routes?.Abort(); }
        catch (Exception error) { failures.Add(error); }
        try { SetCandidatePolicy(candidate, candidate.OldCarriers); }
        catch (Exception error) { failures.Add(error); }
        if (failures.Count != 0)
            throw new AggregateException("Windows roaming rollback failed", failures);
    }

    private RoamingCandidate GetCandidate(NativePathCommand command)
    {
        if (!_roamingCandidates.TryGetValue(command.CandidateId, out var candidate)
            || candidate.Generation != command.Generation
            || candidate.PathIdentity != PathIdentity(command.Path))
            throw new InvalidOperationException("Windows roaming command is stale or mismatched");
        return candidate;
    }

    private void SetCandidatePolicy(RoamingCandidate candidate, string[] next)
    {
        if (_tun is WinDivertAdapter divert)
        {
            divert.SetCarrierAddresses(next.Select(IPAddress.Parse),
                candidate.Config.Port, candidate.Config.Protocol);
        }
        else if (EgressGuardEngaged)
        {
            KillSwitch.UpdateServerAddresses(candidate.PolicyCarriers, next, Log);
        }
        candidate.PolicyCarriers = next;
    }

    private static string PathIdentity(NativePathUpdate path) =>
        JsonSerializer.Serialize(path);

    protected override void PrepareTransport(VpnConfig config) =>
        _useWinDivert = config.UsesAppFilter;

    /// <summary>Surface network steps that failed during SetupTun so the shared base can
    /// qualify the Connected status instead of showing an unconditional green. (C-17)</summary>
    protected override IReadOnlyList<string> NetworkWarnings =>
        _net?.Degraded ?? (IReadOnlyList<string>)Array.Empty<string>();

    /// <summary>DNS apply failure from the platform configurator — gates the kill-switch
    /// policy in the shared base. (Р2)</summary>
    protected override bool NetworkDnsFailed => _net?.DnsFailed ?? false;

    // Wintun adapter creation (~10 s) started in the background at connect kickoff so it
    // overlaps the handshake (PrewarmTun) and SetupTun just consumes it. _prewarmId pins the
    // identity so we only reuse a warmed adapter for the SAME profile.
    private Task<WintunAdapter?>? _prewarm;
    private (string name, Guid guid) _prewarmId;

    /// <summary>Begin creating the Wintun adapter in parallel with the handshake. Its name/GUID
    /// come from the config (known before auth), so nothing here needs the session. No-op if a
    /// warm is already in flight (a retried attempt reuses it).</summary>
    protected override void PrewarmTun(VpnConfig config)
    {
        // WinDivert needs the authenticated client address and is cheap to open. It is
        // created in SetupTun; only Wintun benefits from prewarming.
        if (_useWinDivert) return;
        if (_prewarm != null) return;
        var id = AdapterIdentity(config);
        _prewarmId = id;
        _prewarm = Task.Run(() =>
        {
            try { var w = new WintunAdapter(); w.Open(id.name, id.guid); return (WintunAdapter?)w; }
            catch (Exception e) { Log($"Wintun prewarm failed ({e.Message}); will open in SetupTun"); return null; }
        });
    }

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
        IReadOnlyList<IPAddress> carrierCandidates,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var assigned = session.NetworkAddresses;
        // persist-tun: reuse only when the complete applied network-plan fingerprint matches;
        // the same client IP can arrive with different routes, DNS, prefix or MTU.
        if (ReusePersistedTun(config, session, serverIp))
        {
            if (_tun is WinDivertAdapter retained)
            {
                var retainedIpv4 = assigned.FirstOrDefault(address =>
                    address.Family.Equals("ipv4", StringComparison.OrdinalIgnoreCase));
                var retainedIpv6 = assigned.FirstOrDefault(address =>
                    address.Family.Equals("ipv6", StringComparison.OrdinalIgnoreCase));
                retained.Reconfigure(
                    retainedIpv4 == null ? null : IPAddress.Parse(retainedIpv4.Address),
                    retainedIpv6 == null ? null : IPAddress.Parse(retainedIpv6.Address),
                    config.Apps,
                    config.AppsMode.Equals("include", StringComparison.OrdinalIgnoreCase),
                    EffectiveDns(session),
                    session.AllowIpv4Leak,
                    session.AllowIpv6Leak,
                    config.IsFullTunnel,
                    ConnectedTunnelPrefixes(session),
                    config.RouteLocalNetworks,
                    config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(session)),
                    config.ExcludeRoutes,
                    PushedRouteCidrs(session.PlannedRoutes),
                    serverIp,
                    config.Port,
                    config.Protocol,
                    EffectiveMtu(config.Mtu, session.PushedMtu),
                    physicalLocalRoutes:
                        RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes());
                retained.SetTunnelUp(true);
            }
            return;
        }

        if (_useWinDivert)
        {
            _net = null;
            var ipv4 = assigned.FirstOrDefault(address =>
                address.Family.Equals("ipv4", StringComparison.OrdinalIgnoreCase));
            var ipv6 = assigned.FirstOrDefault(address =>
                address.Family.Equals("ipv6", StringComparison.OrdinalIgnoreCase));
            var adapter = new WinDivertAdapter(
                ipv4 == null ? null : IPAddress.Parse(ipv4.Address),
                ipv6 == null ? null : IPAddress.Parse(ipv6.Address),
                config.Apps,
                includeMode: config.AppsMode.Equals("include", StringComparison.OrdinalIgnoreCase),
                dnsServers: EffectiveDns(session),
                allowIpv4Leak: session.AllowIpv4Leak,
                allowIpv6Leak: session.AllowIpv6Leak,
                fullTunnel: config.IsFullTunnel,
                tunnelSubnets: ConnectedTunnelPrefixes(session),
                routeLocal: config.RouteLocalNetworks,
                includeRoutes: config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(session)),
                excludeRoutes: config.ExcludeRoutes,
                pushedRoutes: PushedRouteCidrs(session.PlannedRoutes),
                carrierIp: serverIp,
                carrierPort: config.Port,
                carrierProtocol: config.Protocol,
                tunnelMtu: EffectiveMtu(config.Mtu, session.PushedMtu),
                log: Log,
                physicalLocalRoutes:
                    RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes());
            adapter.Open();
            cancellationToken.ThrowIfCancellationRequested();
            adapter.SetTunnelUp(true);
            _tun = adapter;
            Log($"Per-app split tunnel ACTIVE: mode={config.AppsMode}, apps={config.Apps.Count}; "
                + "WinDivert packet path is attached to the common Rust transport core");
            return;
        }

        _net = new NetworkConfigurator(Log);
        // Resolve every possible A/AAAA carrier path before the /1 or /0 capture routes
        // exist. The Rust core can select any candidate on a later reconnect; pinning
        // only the first authenticated peer would let another candidate recurse into
        // Wintun after DNS rotation.
        var carrierPaths = carrierCandidates
            .Distinct()
            .Select(address =>
            {
                var path = _net.PhysicalPathFor(address);
                return (address,
                    ifIndex: path.ifIndex,
                    gateway: path.gateway);
            })
            .ToArray();
        // Resolve every bypass before installing the /1 capture routes. IPv4 and IPv6
        // commonly leave through different gateways; reusing the carrier's IPv4 path made
        // an IPv6 exclude syntactically accepted but impossible to install.
        var bypassPaths = config.ExcludeRoutes
            .Select(route => (route, path: _net.PhysicalPathForRoute(route)))
            .ToArray();

        uint drv = WintunAdapter.RunningDriverVersion();
        // Coexistence note: if another app has already loaded the shared Wintun kernel
        // driver (OpenVPN/WireGuard/Tailscale), surface it. qeli bundles Wintun 0.14.1 —
        // two apps on the SAME 0.14.x driver coexist fine, but a different (older) version
        // can be disrupted by the version swap the single shared driver forces.
        if (drv != 0)
            Log($"NOTE: a Wintun driver ({drv >> 16}.{drv & 0xFF}) is already loaded by another app; " +
                "qeli uses 0.14.1 — running alongside another Wintun VPN needs a matching 0.14.x on both sides.");
        // Per-tunnel adapter identity (name + GUID) so several qeli tunnels can run on
        // ONE host without fighting over a single Wintun adapter; stable across runs of
        // the same tunnel, so the adapter is still reused rather than recreated.
        var (adapterName, adapterGuid) = AdapterIdentity(config);
        // Consume the adapter prewarmed in parallel with the handshake (PrewarmTun) if it
        // matches this profile; otherwise open synchronously (prewarm skipped or failed).
        WintunAdapter? wintun = null;
        if (_prewarm != null && _prewarmId == (adapterName, adapterGuid))
        {
            try { wintun = _prewarm.GetAwaiter().GetResult(); } catch { }
            _prewarm = null;
        }
        if (wintun == null)
        {
            wintun = new WintunAdapter();
            wintun.Open(adapterName, adapterGuid);
        }
        var (tunIndex, alias) = _net.ResolveInterface(wintun.Luid);
        Log($"Wintun adapter '{alias}' (if {tunIndex}, driver {drv >> 16}.{drv & 0xFF})");
        _tun = wintun;
        var localCaptureRoutes = config.RouteLocalNetworks
            && assigned.Any(address => address.Family == "ipv4")
            ? RouteLocalPolicy.BuildCapturePrefixes(
                RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes(alias, tunIndex),
                config.ExcludeRoutes)
            : Array.Empty<string>();

        foreach (var address in assigned)
            _net.SetAddress(alias, address.Address, address.PrefixLength);
        var connectedPrefixes = ConnectedTunnelPrefixes(session);
        foreach (var cidr in connectedPrefixes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net.AddOnLinkRoute(cidr, session.ClientIp, tunIndex))
                throw new InvalidOperationException(
                    $"connected tunnel prefix {cidr} was not applied");
        }
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(alias, mtu,
            assigned.Any(address => address.Family == "ipv4"),
            assigned.Any(address => address.Family == "ipv6"));
        if (config.InterfaceMetric > 0) _net.SetMetric(wintun.Luid, alias, config.InterfaceMetric);  // OpenVPN route-metric (IPv4+IPv6)

        // Pin the carrier route to the server through the physical gateway BEFORE we hijack
        // the default route, so the encrypted tunnel never loops on itself. But when `local`
        // binds the carrier to a specific source (e.g. routing it through ANOTHER VPN), the
        // auto-detected PHYSICAL gateway/interface contradicts that bind — pinning here would
        // force the carrier out the wrong NIC and break the return path. Skip the pin then and
        // let the bound interface's own routing carry the carrier; the user owns that route
        // (issue #69).
        if (!string.IsNullOrEmpty(config.LocalAddress))
            Log($"local = {config.LocalAddress}: not pinning the server route — carrier follows the bound interface's routing");
        else
        {
            foreach (var (address, ifIndex, gateway) in carrierPaths)
            {
                if (ifIndex != 0)
                    _net.PinServerRoute(address, gateway, ifIndex);
                else if (config.IsFullTunnel)
                {
                    throw new InvalidOperationException(
                        $"carrier {address} has no usable physical path in full-tunnel mode");
                }
                else
                {
                    Log($"WARN: could not determine a physical path for carrier {address}");
                }
            }
        }

        if (config.IsFullTunnel)
        {
            var ipv4 = assigned.FirstOrDefault(address => address.Family == "ipv4");
            var ipv6 = assigned.FirstOrDefault(address => address.Family == "ipv6");
            if (ipv4 != null)
                _net.SetFullTunnelRoutes(TunnelGatewayForRoute(session, "0.0.0.0/0"), tunIndex);
            else if (!session.AllowIpv4Leak)
            {
                const string sink = "169.254.71.1";
                _net.SetAddress(alias, sink, 32);
                _net.SetFullTunnelRoutes(sink, tunIndex);
            }
            if (ipv6 != null)
                _net.SetFullTunnelRoutesV6(alias);
            else if (!session.AllowIpv6Leak)
                _net.CaptureIPv6(alias);
        }
        else if (!session.PlanIncludesClientRoutes)
        {
            foreach (var r in config.IncludeRoutes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_net.AddRoute(r, TunnelGatewayForRoute(session, r), tunIndex))
                    throw new InvalidOperationException($"include route {r} was not applied");
            }
        }
        if (!config.IsFullTunnel)
            ApplyRouteFileRoutes(session, tunIndex, cancellationToken);

        // Subnets the server advertised (`route = …` on the profile / per-user) are a
        // specific, explicit admin decision — always honoured, like OpenVPN's
        // `push "route …"`. Until 0.7.12 these sat behind RouteLocalNetworks, so a
        // correctly configured route was silently dropped on every default client.
        ApplyPushedRoutes(session, tunIndex, connectedPrefixes, cancellationToken);

        // RouteLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
        // default because it would hijack the machine's own LAN (printers, NAS, router).
        if (config.RouteLocalNetworks && !session.PlanIncludesClientRoutes)
        {
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_net.AddRoute(r, TunnelGatewayForRoute(session, r), tunIndex))
                    throw new InvalidOperationException($"route_local route {r} was not applied");
            }
            Log("Routing local networks (RFC1918 blanket) through the tunnel");
        }

        foreach (string route in localCaptureRoutes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net.AddRoute(route, TunnelGatewayForRoute(session, route), tunIndex))
                throw new InvalidOperationException(
                    $"route_local connected-prefix override {route} was not applied");
        }
        if (localCaptureRoutes.Count > 0)
            Log($"route_local: {localCaptureRoutes.Count} connected-prefix override route(s) "
                + "installed without replacing physical routes");

        // Exclude: carve these destinations out of the tunnel. Route them via the physical
        // gateway so exclusion works even in full-tunnel (a plain delete is a no-op there);
        // fall back to a delete only when the gateway is unknown (split-tunnel).
        foreach (var (r, path) in bypassPaths)
        {
            if (path.ifIndex != 0)
                _net.PinBypassRoute(r, path.gateway, path.ifIndex);
            else if (config.IsFullTunnel)
                throw new InvalidOperationException(
                    $"exclude route {r} has no usable physical path in full-tunnel mode");
            else
                _net.DeleteRoute(r);
        }

        // #13: pure L3 forwarding for a LAN BEHIND this Windows node (no NAT), so the far
        // side can route to it through the tunnel. Best-effort per-interface enable.
        if (config.Forward)
            EnableIpForwarding(
                alias,
                assigned.Any(address => address.Family == "ipv4"),
                assigned.Any(address => address.Family == "ipv6"));

        _net.SetDns(alias, EffectiveDns(session));

        // LAST step of bring-up: ask the OS whether the carrier still leaves via the
        // physical interface. Everything above only proved the commands were issued; this
        // checks what the routing table actually decided, which is what "Connected" claims.
        // Skipped when `local` binds the carrier elsewhere (e.g. through another VPN) —
        // there the user owns the path and the server route is deliberately not pinned. (C-17)
        if (string.IsNullOrEmpty(config.LocalAddress))
            foreach (var path in carrierPaths)
                _net.VerifyCarrierPath(
                    path.address, tunIndex, path.ifIndex, path.gateway);
    }

    private string? _forwardingAlias;
    private bool? _ipv4ForwardingWasOn;
    private bool? _ipv6ForwardingWasOn;

    /// <summary>Enable forwarding only for address families present in the authenticated
    /// NetworkPlan and retain their original values for teardown. A requested forwarding mode
    /// is part of the plan, so a failed command aborts setup instead of reporting a feature
    /// that is not active.</summary>
    private void EnableIpForwarding(string alias, bool hasIpv4, bool hasIpv6)
    {
        bool? ipv4WasOn = hasIpv4 ? ReadIpForwarding(alias, "IPv4") : null;
        bool? ipv6WasOn = hasIpv6 ? ReadIpForwarding(alias, "IPv6") : null;
        _forwardingAlias = alias;
        _ipv4ForwardingWasOn = ipv4WasOn;
        _ipv6ForwardingWasOn = ipv6WasOn;
        try
        {
            if (ipv4WasOn == false) SetIpForwarding(alias, "ipv4", enabled: true);
            if (ipv6WasOn == false) SetIpForwarding(alias, "ipv6", enabled: true);
            string families = hasIpv4 && hasIpv6 ? "IPv4 and IPv6" : hasIpv4 ? "IPv4" : "IPv6";
            Log($"{families} forwarding enabled on '{alias}' (no NAT). For LAN->tunnel routing enable " +
                "forwarding on the LAN NIC too (netsh …forwarding=enabled) or set IPEnableRouter.");
        }
        catch (Exception setupError)
        {
            try { RestoreIpForwarding(); }
            catch (Exception rollbackError)
            {
                throw new InvalidOperationException(
                    $"could not enable IP forwarding ({setupError.Message}); rollback also failed: {rollbackError.Message}",
                    setupError);
            }
            throw new InvalidOperationException($"could not enable IP forwarding: {setupError.Message}", setupError);
        }
    }

    private static bool ReadIpForwarding(string alias, string family)
    {
        string escapedAlias = alias.Replace("'", "''", StringComparison.Ordinal);
        string script =
            $"$v=(Get-NetIPInterface -InterfaceAlias '{escapedAlias}' -AddressFamily {family} -ErrorAction Stop).Forwarding;" +
            "[Console]::Out.Write($v.ToString())";
        var psi = new System.Diagnostics.ProcessStartInfo(SystemPaths.PowerShell)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = SystemPaths.SystemDirectory,
        };
        psi.ArgumentList.Add("-NoLogo");
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-EncodedCommand");
        psi.ArgumentList.Add(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)));
        var result = RunForwardingCommand(psi, $"query {family} forwarding on '{alias}'");
        return result.Trim() switch
        {
            "Enabled" => true,
            "Disabled" => false,
            var value => throw new InvalidOperationException(
                $"unexpected {family} forwarding state '{value}' on '{alias}'"),
        };
    }

    private static void SetIpForwarding(string alias, string family, bool enabled)
    {
        var psi = new System.Diagnostics.ProcessStartInfo(SystemPaths.Netsh)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = SystemPaths.SystemDirectory,
        };
        foreach (var argument in new[]
        {
            "interface", family, "set", "interface", alias,
            $"forwarding={(enabled ? "enabled" : "disabled")}",
        }) psi.ArgumentList.Add(argument);
        _ = RunForwardingCommand(psi,
            $"set {family} forwarding {(enabled ? "enabled" : "disabled")} on '{alias}'");
    }

    private static string RunForwardingCommand(
        System.Diagnostics.ProcessStartInfo startInfo, string operation)
    {
        using var process = System.Diagnostics.Process.Start(startInfo)
            ?? throw new InvalidOperationException($"failed to start process to {operation}");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(5_000))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"timed out while trying to {operation}");
        }
        string output = stdout.GetAwaiter().GetResult();
        string error = stderr.GetAwaiter().GetResult();
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"failed to {operation} (exit {process.ExitCode}): " +
                (string.IsNullOrWhiteSpace(error) ? output.Trim() : error.Trim()));
        return output;
    }

    private void RestoreIpForwarding()
    {
        string? alias = _forwardingAlias;
        if (alias == null) return;
        if (_ipv4ForwardingWasOn == false) SetIpForwarding(alias, "ipv4", enabled: false);
        if (_ipv6ForwardingWasOn == false) SetIpForwarding(alias, "ipv6", enabled: false);
        _forwardingAlias = null;
        _ipv4ForwardingWasOn = null;
        _ipv6ForwardingWasOn = null;
    }

    private void ApplyRouteFileRoutes(Session session, uint tunIndex,
        CancellationToken cancellationToken)
    {
        int installed = 0;
        foreach (string route in EffectiveRouteFileRoutes(session))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net!.AddRoute(route, TunnelGatewayForRoute(session, route), tunIndex,
                logSuccess: false))
                throw new InvalidOperationException($"route_file route {route} was not applied");
            installed++;
        }
        if (installed > 0)
            Log($"route_file: installed {installed} unique route(s) via the tunnel gateway");
    }

    private void ApplyPushedRoutes(Session session, uint tunIndex,
        IReadOnlyList<string> alreadyApplied, CancellationToken cancellationToken)
    {
        IReadOnlyList<PlannedRoute> routes = session.PlannedRoutes;
        if (routes.Count == 0) return;
        var seen = new HashSet<string>(alreadyApplied, StringComparer.OrdinalIgnoreCase);
        foreach (var route in routes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!seen.Add(route.Cidr)) continue;
            string got = route.Cidr
                + (route.Gateway.Length > 0 ? $" gateway={route.Gateway}" : "")
                + (route.Metric != 0 ? $" metric={route.Metric}" : "");
            string gateway = TunnelGatewayForRoute(session, route.Cidr, route.Gateway);
            if (!_net!.AddRoute(route.Cidr, gateway, tunIndex))
                throw new InvalidOperationException(
                    $"canonical NetworkPlan route {route.Cidr} was not applied");
            Log(route.Metric != 0
                ? $"pushed route: {got} -> APPLIED via tunnel gateway {gateway} (metric not settable here)"
                : $"pushed route: {got} -> APPLIED via tunnel gateway {gateway}");
        }
    }

    private static string TunnelGatewayForRoute(Session session, string cidr,
        string? requestedGateway = null)
    {
        bool ipv6 = cidr.Contains(':');
        if (!string.IsNullOrWhiteSpace(requestedGateway)) return requestedGateway;
        AssignedAddress? assigned = session.NetworkAddresses.FirstOrDefault(address =>
            address.Family.Equals(ipv6 ? "ipv6" : "ipv4", StringComparison.OrdinalIgnoreCase));
        if (assigned == null || string.IsNullOrWhiteSpace(assigned.Gateway))
            throw new InvalidOperationException(
                $"no authenticated tunnel gateway for route {cidr}");
        return assigned.Gateway;
    }

    private static IReadOnlyList<string> PushedRouteCidrs(IReadOnlyList<PlannedRoute> routes) =>
        routes.Select(route => route.Cidr).ToArray();

    protected override bool KeepTunDuringReconnect(VpnConfig config) =>
        config.UsesAppFilter || base.KeepTunDuringReconnect(config);

    protected override bool TryReconfigurePersistedTun(
        VpnConfig config, Session session, IPAddress serverIp)
    {
        // SetupTun performs the single policy refresh after the shared reuse decision.
        // Merely confirm that this retained adapter can be changed in place; system Wintun
        // must instead pass through the firewall-guarded rebuild branch.
        return config.UsesAppFilter && _tun is WinDivertAdapter;
    }

    protected override void OnTransportInterrupted(VpnConfig config)
    {
        if (_tun is WinDivertAdapter adapter) adapter.SetTunnelUp(false);
    }

    // Deterministic per-PROFILE adapter identity: a stable name + GUID keyed on
    // host:port PLUS the profile's stable unique Id. This way
    //   * two profiles to the SAME server (two accounts, or two tunnels to the same
    //     address at once) get DISTINCT adapters — the Id differs — and
    //   * a profile reached by port-forwarding to a DIFFERENT server on the same host
    //     but another port doesn't collide — the port differs —
    // while the SAME profile reconnecting keeps ONE adapter (host, port and Id are all
    // stable), so it is reused rather than recreated (also lets persist-tun keep it up
    // across reconnects). Keying on the address alone collided in both cases (issue #69).
    // The hash is for uniqueness only (not security).
    private static (string name, Guid guid) AdapterIdentity(VpnConfig config)
    {
        // OpenVPN dev-node: an explicit adapter name overrides the auto-derived one. The
        // GUID is still derived from that name so it stays stable across runs.
        if (!string.IsNullOrWhiteSpace(config.DevNode))
        {
            byte[] dh = System.Security.Cryptography.MD5.HashData(
                System.Text.Encoding.UTF8.GetBytes("qeli-adapter:dev-node:" + config.DevNode));
            return (config.DevNode!, new Guid(dh));
        }
        string keyStr = $"{config.ServerAddress}:{config.Port}|{config.Id}";
        if (string.IsNullOrEmpty(config.ServerAddress) && string.IsNullOrEmpty(config.Id))
            return ("Qeli", new Guid("d3a1f4e0-1c2b-4a6e-9f10-abcd00000001"));
        byte[] h = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes("qeli-adapter:" + keyStr));
        return ($"Qeli-{Convert.ToHexString(h, 0, 3)}", new Guid(h));
    }

    protected override void BeforeTunDispose()
    {
        RestoreIpForwarding();
        // DNS belongs to the Wintun interface, so reset it before its last handle closes.
        // Retain the configurator on failure; CleanupPlatform below then retries and makes
        // the base lifecycle report Error instead of a false clean disconnect.
        var network = _net;
        network?.Dispose();
        if (ReferenceEquals(_net, network)) _net = null;
    }

    protected override void CleanupPlatform()
    {
        Exception? roamingCleanupError = null;
        try { ResetNativeRoamingPath(); }
        catch (Exception error) { roamingCleanupError = error; }
        // Retry here if the pre-dispose restore failed; CleanupPlatform exceptions are
        // surfaced by the shared lifecycle instead of claiming a clean disconnect.
        try
        {
            RestoreIpForwarding();
            // A firewall rule may still name an unconsumed adapter after a partial engage.
            // Keep that alias alive until KillSwitchDisengage has removed the rule.
            if (!EgressGuardEngaged) DisposeUnusedPrewarm();
            var network = _net;
            network?.Dispose();
            if (ReferenceEquals(_net, network)) _net = null;
        }
        catch (Exception platformError) when (roamingCleanupError != null)
        {
            throw new AggregateException(
                "Windows roaming and platform cleanup both failed",
                roamingCleanupError, platformError);
        }
        if (roamingCleanupError != null) throw roamingCleanupError;
    }

    // Firewall kill-switch (full-tunnel only). Allow the Wintun adapter by its
    // per-tunnel name (derived from the server address, same as SetupTun).
    //
    // The adapter must EXIST before the rule is created. `New-NetFirewallRule` resolves
    // -InterfaceAlias at creation time and fails with "The specified interface was not
    // found on the system" when it doesn't — unlike Linux nft/iptables, where an interface
    // name may refer to a device that only appears later. This code was written under the
    // Linux assumption, and since the kill-switch is deliberately raised BEFORE the first
    // connect (leak-proof from the very first attempt), engaging it for a profile whose
    // adapter did not exist yet always failed — and fail-closed then refused to start the
    // profile at all. Bringing the adapter up here costs nothing extra: SetupTun consumes
    // exactly this prewarmed adapter (same name + GUID), so nothing is created twice.
    protected override bool KillSwitchEngageFailureRetainsOwnership(Exception error) =>
        error is AggregateException;
    protected override void KillSwitchEngage(VpnConfig config)
    {
        try
        {
            string actualAlias = EnsureTunAdapterExists(config);
            KillSwitch.Engage(config.ServerAddress, actualAlias, Log);
        }
        catch (AggregateException) { throw; }
        catch
        {
            DisposeUnusedPrewarm();
            throw;
        }
    }

    protected override void CarrierAddressesChanging(
        VpnConfig config, IReadOnlyList<string> previous, IReadOnlyList<string> refreshed)
    {
        if (EgressGuardEngaged && !config.UsesAppFilter)
            KillSwitch.UpdateServerAddresses(previous, refreshed, Log);
    }

    /// <summary>Bring the Wintun adapter up NOW, synchronously, so a firewall rule can name
    /// it. Reuses the ordinary prewarm path (idempotent — SetupTun still consumes the warmed
    /// adapter). Throws with an actionable message when it cannot be created, so the caller's
    /// fail-closed path reports the real cause instead of an opaque firewall error.</summary>
    private string EnsureTunAdapterExists(VpnConfig config)
    {
        if (_tun is WintunAdapter live && !string.IsNullOrWhiteSpace(live.AdapterName))
            return live.AdapterName;
        PrewarmTun(config);         // no-op when a warm is already in flight
        WintunAdapter? warmed = null;
        try { warmed = _prewarm?.GetAwaiter().GetResult(); } catch { /* reported just below */ }
        if (warmed == null || string.IsNullOrWhiteSpace(warmed.AdapterName))
            throw new InvalidOperationException(
                "the Wintun adapter could not be created, so no firewall rule can name it " +
                "(Windows rejects a rule for a missing interface). Check that the Wintun driver " +
                "loads and that qeli is running elevated.");
        // WintunAdapter.Open may have resolved a name/GUID collision by creating name-0,
        // name-1, ... . Firewall and WinDivert rules must use this actual alias, never the
        // precomputed profile identity that collided.
        return warmed.AdapterName;
    }

    private void DisposeUnusedPrewarm()
    {
        var prewarm = _prewarm;
        if (prewarm == null) return;
        try { prewarm.GetAwaiter().GetResult()?.Dispose(); } catch { }
        if (ReferenceEquals(_prewarm, prewarm)) _prewarm = null;
    }

    protected override void KillSwitchDisengage()
    {
        // Remove firewall rules before releasing the adapter alias they name.
        KillSwitch.Disengage(Log);
        if (_tun == null) DisposeUnusedPrewarm();
    }
}
