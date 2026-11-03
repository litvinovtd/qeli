using System.Net;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Vpn;

/// <summary>macOS platform binding for the shared qeli data plane
/// (<see cref="VpnTunnelBase"/>): opens a UtunDevice and configures the
/// addressing / routes / DNS for the session via NetworkConfigurator.</summary>
public sealed partial class VpnTunnel : VpnTunnelBase
{
    private NetworkConfigurator? _net;
    private PerAppController? _perApp;
    private UtunDevice? _prewarmedUtun;

    protected override bool NativeTunFdOwnership => true;

    // NetworkPlan replacement for a retained system utun is a fail-closed transaction: the
    // base engages the platform firewall guard before the old plan is removed and releases it
    // only after the replacement is fully applied.
    protected override bool SupportsPlanReplacementGuard => true;

    protected override ulong NativeIpv6Capabilities(VpnConfig config) =>
        NativeIpv6SystemPlanCapabilities | NativeIpv6KillSwitchCapability;

    /// <summary>Surface network steps that failed during SetupTun so the shared base can
    /// qualify the Connected status instead of showing an unconditional green. (C-17)</summary>
    protected override IReadOnlyList<string> NetworkWarnings =>
        _net?.Degraded ?? (IReadOnlyList<string>)Array.Empty<string>();

    /// <summary>DNS apply failure from the platform configurator — gates the kill-switch
    /// policy in the shared base. (Р2)</summary>
    protected override bool NetworkDnsFailed => _net?.DnsFailed ?? false;

    private static IReadOnlyList<string> PerAppTunnelSubnets(Session session)
    {
        var assigned = session.NetworkAddresses;
        // Destination policy only needs a canonical membership prefix. CIDR matching masks
        // host bits, so the authenticated address plus its on-link prefix is sufficient.
        return assigned.Select(address =>
            $"{address.Address}/{address.OnLinkPrefixLength}").ToArray();
    }

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
        IReadOnlyList<IPAddress> carrierCandidates,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // persist-tun: reuse only when the complete applied network-plan fingerprint matches;
        // the same client IP can arrive with different routes, DNS, prefix or MTU.
        if (ReusePersistedTun(config, session, serverIp))
        {
            if (config.UsesAppFilter && _tun is UtunDevice retained)
            {
                (_perApp ??= new PerAppController(Log)).StartOrUpdate(
                    config, retained.Name, serverIp, EffectiveDns(session),
                    config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(session)).ToArray(),
                    config.ExcludeRoutes, PushedRouteCidrs(session.PlannedRoutes),
                    PerAppTunnelSubnets(session),
                    RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes(retained.Name, log: Log),
                    session.NetworkAddresses.Any(address => address.Family == "ipv4"),
                    session.NetworkAddresses.Any(address => address.Family == "ipv6"),
                    tunnelUp: true);
            }
            return;
        }
        _net = new NetworkConfigurator(Log);
        // Resolve all possible A/AAAA peers before installing any full-tunnel routes.
        // Rust may choose a different candidate on reconnect, so every candidate must
        // retain an independently resolved physical path.
        var carrierPaths = carrierCandidates
            .Distinct()
            .Select(address =>
            {
                var (physicalIf, gateway) = _net.PathToServer(address);
                return (address, physicalIf, gateway);
            })
            .ToArray();
        // Resolve bypasses before the full-tunnel routes are installed. IPv4 and IPv6
        // may use different physical interfaces and gateways.
        var bypassPaths = config.ExcludeRoutes
            .Select(route => (route, path: _net.PhysicalPathForRoute(route)))
            .ToArray();

        var utun = _prewarmedUtun;
        _prewarmedUtun = null;
        if (utun == null)
        {
            utun = new UtunDevice();
            utun.Open();
        }
        string dev = utun.Name;
        var selectedPath = carrierPaths.First(path => path.address.Equals(serverIp));
        Log($"utun interface '{dev}' (physical path {selectedPath.physicalIf ?? "?"} via {selectedPath.gateway?.ToString() ?? "?"})");
        _tun = utun;

        var assigned = session.NetworkAddresses;
        var localCaptureRoutes = config.RouteLocalNetworks
            && assigned.Any(address => address.Family == "ipv4")
            ? RouteLocalPolicy.BuildCapturePrefixes(
                RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes(dev, log: Log),
                config.ExcludeRoutes)
            : Array.Empty<string>();
        foreach (var address in assigned)
            _net.SetAddress(dev, address.Address, address.PrefixLength);
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(dev, mtu);

        // Pin the carrier route to the server through the physical gateway BEFORE we hijack
        // the default route, so the encrypted tunnel never loops on itself. But when `local`
        // binds the carrier to a specific source (e.g. routing it through ANOTHER VPN), the
        // auto-detected physical gateway contradicts that bind — skip the pin then and let the
        // bound interface's own routing carry the carrier; the user owns that route (issue #69).
        if (!string.IsNullOrEmpty(config.LocalAddress))
            Log($"local = {config.LocalAddress}: not pinning the server route — carrier follows the bound interface's routing");
        else
        {
            foreach (var (address, physicalIf, gateway) in carrierPaths)
            {
                if (gateway != null || physicalIf != null)
                    _net.PinServerRoute(address, gateway, physicalIf);
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

        // The firewall was raised before authentication. Once this utun is the generation's
        // actual adapter, atomically drop any old/replacement alias from the PF allowlist.
        if (EgressGuardEngaged)
            KillSwitch.UpdateTunnelInterfaces(new[] { dev }, Log);

        // Per-app mode is deliberately NOT expressed as host routes or host DNS. A signed
        // NETransparentProxyProvider classifies flows by source-app signing identifier and
        // binds only the selected sockets to this utun. Unselected applications therefore
        // retain the machine's ordinary route and resolver. Keeping this branch before all
        // global route/DNS mutations is what makes include/exclude genuinely per-app.
        if (config.UsesAppFilter)
        {
            (_perApp ??= new PerAppController(Log)).StartOrUpdate(
                config, dev, serverIp, EffectiveDns(session),
                config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(session)).ToArray(),
                config.ExcludeRoutes, PushedRouteCidrs(session.PlannedRoutes),
                PerAppTunnelSubnets(session),
                RouteLocalPolicy.DiscoverConnectedRfc1918Prefixes(dev, log: Log),
                assigned.Any(address => address.Family == "ipv4"),
                assigned.Any(address => address.Family == "ipv6"),
                tunnelUp: true);
            if (string.IsNullOrEmpty(config.LocalAddress))
                foreach (var address in carrierPaths.Select(path => path.address))
                    _net.VerifyCarrierPath(address, dev);
            return;
        }

        var connectedPrefixes = ConnectedTunnelPrefixes(session);
        foreach (var cidr in connectedPrefixes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net.AddRoute(cidr, dev))
                throw new InvalidOperationException(
                    $"connected tunnel prefix {cidr} was not applied");
        }

        if (config.IsFullTunnel)
        {
            var ipv4 = assigned.FirstOrDefault(address => address.Family == "ipv4");
            var ipv6 = assigned.FirstOrDefault(address => address.Family == "ipv6");
            if (ipv4 != null)
                _net.SetFullTunnelRoutes(dev);
            else if (!session.AllowIpv4Leak)
            {
                _net.SetAddress(dev, "169.254.71.1", 32);
                _net.SetFullTunnelRoutes(dev);
            }
            if (ipv6 != null)
                _net.SetFullTunnelRoutesV6(dev);
            else if (!session.AllowIpv6Leak)
                _net.CaptureIPv6(dev);
        }
        else if (!session.PlanIncludesClientRoutes)
        {
            foreach (var r in config.IncludeRoutes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_net.AddRoute(r, dev))
                    throw new InvalidOperationException($"include route {r} was not applied");
            }
        }
        if (!config.IsFullTunnel)
            ApplyRouteFileRoutes(session, dev, cancellationToken);

        // Subnets the server advertised (`route = …` on the profile / per-user) are a
        // specific, explicit admin decision — always honoured, like OpenVPN's
        // `push "route …"`. Until 0.7.12 these sat behind RouteLocalNetworks, so a
        // correctly configured route was silently dropped on every default client.
        ApplyPushedRoutes(session.PlannedRoutes, dev, connectedPrefixes, cancellationToken);

        // RouteLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
        // default because it would hijack the machine's own LAN (printers, NAS, router).
        if (config.RouteLocalNetworks && !session.PlanIncludesClientRoutes)
        {
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_net.AddRoute(r, dev))
                    throw new InvalidOperationException($"route_local route {r} was not applied");
            }
            Log("Routing local networks (RFC1918 blanket) through the tunnel");
        }

        foreach (string route in localCaptureRoutes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net.AddRoute(route, dev))
                throw new InvalidOperationException(
                    $"route_local connected-prefix override {route} was not applied");
        }
        if (localCaptureRoutes.Count > 0)
            Log($"route_local: {localCaptureRoutes.Count} connected-prefix override route(s) "
                + "installed without replacing physical routes");

        // Exclude: route these subnets via the physical gateway so exclusion works even in
        // full-tunnel (a plain delete is a no-op there); fall back to a delete when the
        // gateway is unknown (split-tunnel).
        foreach (var (r, path) in bypassPaths)
        {
            if (path.gateway != null || path.iface != null)
                _net.PinBypassRoute(r, path.gateway, path.iface);
            else if (config.IsFullTunnel)
                throw new InvalidOperationException(
                    $"exclude route {r} has no usable physical path in full-tunnel mode");
            else
                _net.DeleteRoute(r);
        }

        // #13: pure L3 forwarding for a LAN BEHIND this Mac (no NAT), so the far side can
        // route to it through the tunnel (site-to-site). macOS gates it on one sysctl.
        if (config.Forward)
            EnableIpForwarding(
                assigned.Any(address => address.Family == "ipv4"),
                assigned.Any(address => address.Family == "ipv6"));

        if (!_net.SetDns(EffectiveDns(session)))
            throw new InvalidOperationException(
                "canonical NetworkPlan DNS servers were not applied");

        // LAST step of bring-up — see the Windows counterpart. Ask the OS what the routing
        // table actually decided rather than trusting that the commands took. Skipped when
        // `local` binds the carrier elsewhere and the pin was deliberately not done. (C-17)
        if (string.IsNullOrEmpty(config.LocalAddress))
            foreach (var address in carrierPaths.Select(path => path.address))
                _net.VerifyCarrierPath(address, dev);
    }

    private ForwardingJournal? _forwarding;
    private void EnableIpForwarding(bool hasIpv4, bool hasIpv6) =>
        (_forwarding ??= ForwardingJournal.Create(Log)).Enable(hasIpv4, hasIpv6);
    private void RestoreIpForwarding() {
        _forwarding?.ReleaseOwned();
        _forwarding = null; // Failed restore retains the journal/coordinator for retry.
    }

    private void ApplyRouteFileRoutes(Session session, string dev,
        CancellationToken cancellationToken)
    {
        int installed = 0;
        foreach (string route in EffectiveRouteFileRoutes(session))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_net!.AddRoute(route, dev, logSuccess: false))
                throw new InvalidOperationException($"route_file route {route} was not applied");
            installed++;
        }
        if (installed > 0)
            Log($"route_file: installed {installed} unique route(s) via the tunnel interface");
    }

    private void ApplyPushedRoutes(IReadOnlyList<PlannedRoute> routes, string dev,
        IReadOnlyList<string> alreadyApplied, CancellationToken cancellationToken)
    {
        if (routes.Count == 0) return;
        var seen = new HashSet<string>(alreadyApplied, StringComparer.OrdinalIgnoreCase);
        foreach (var route in routes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!seen.Add(route.Cidr)) continue;
            // Desktop routes are interface-scoped, so next-hop/metric are diagnostic only.
            string got = route.Cidr
                + (route.Gateway.Length > 0 ? $" gateway={route.Gateway}" : "")
                + (route.Metric != 0 ? $" metric={route.Metric}" : "");
            if (!_net!.AddRoute(route.Cidr, dev))
                throw new InvalidOperationException(
                    $"canonical NetworkPlan route {route.Cidr} was not applied");
            Log(route.Gateway.Length > 0 || route.Metric != 0
                ? $"pushed route: {got} -> APPLIED via the tunnel interface (next-hop/metric not settable here)"
                : $"pushed route: {got} -> APPLIED via the tunnel interface");
        }
    }

    private static IReadOnlyList<string> PushedRouteCidrs(IReadOnlyList<PlannedRoute> routes) =>
        routes.Select(route => route.Cidr).ToArray();

    protected override void CleanupPlatform()
    {
        var failures = new List<Exception>();
        // The base normally resets roaming before platform cleanup. Retry here because a
        // failed ABORT deliberately retains its lease and policy ownership for another pass.
        try { ResetNativeRoamingPath(); }
        catch (Exception error) { failures.Add(error); }
        // Undo the host-wide sysctl before dropping the configurator, so a disconnect
        // leaves the machine as it was found. (C-18)
        try { RestoreIpForwarding(); }
        catch (Exception error) { failures.Add(error); }
        try
        {
            // NetworkConfigurator deliberately throws when the physical service's DNS was
            // not restored. Keep the configurator referenced in that case so a second Stop
            // in this process can retry instead of forgetting the recovery action.
            DisposeNetworkConfigurator();
        }
        catch (Exception error)
        {
            failures.Add(error);
        }
        // BeforeTunDispose already confirmed proxy stop. Do not forget a controller
        // whose cleanup still owns a live guardian.
        if (_perApp is { Started: true }) failures.Add(new InvalidOperationException("per-app cleanup remains active"));
        else _perApp = null;
        if (failures.Count == 1) throw failures[0];
        if (failures.Count > 1)
            throw new AggregateException("macOS platform cleanup is incomplete", failures);
    }

    // The system extension stays installed and retains its flow rules across a carrier
    // reconnect. Selected apps are failed closed until the same utun is usable again.
    protected override bool KeepTunDuringReconnect(VpnConfig config) =>
        config.UsesAppFilter || base.KeepTunDuringReconnect(config);

    protected override bool TryReconfigurePersistedTun(
        VpnConfig config, Session session, IPAddress serverIp)
    {
        if (!config.UsesAppFilter)
        {
            // With a user kill-switch already engaged, the base does not engage a second
            // replacement guard. Move PF to the reserved replacement name while the old
            // descriptor is still alive. If the atomic reload fails, neither allowed alias
            // has been released; only after success may the base close the old utun.
            if (EgressGuardEngaged && _tun is UtunDevice)
            {
                var replacement = EnsurePrewarmedUtun();
                KillSwitch.UpdateTunnelInterfaces(new[] { replacement.Name }, Log);
            }
            return false;
        }
        if (!config.UsesAppFilter || _tun is not UtunDevice retained) return false;

        // The transparent proxy was put into tunnel-down mode before reconnect, so selected
        // flows remain fail-closed. Keep the same utun descriptor (and therefore the native
        // ownership contract), and replace its address/MTU and carrier pin. SetupTun publishes
        // the new authenticated flow policy once, after this carrier verification succeeds.
        var oldNetwork = _net;
        oldNetwork?.Dispose();
        if (ReferenceEquals(_net, oldNetwork)) _net = null;

        var nextNetwork = new NetworkConfigurator(Log);
        _net = nextNetwork;
        try
        {
            var (physicalIf, gateway) = nextNetwork.PathToServer(serverIp);
            // A dual-stack plan carries two independent addresses. Re-applying only the
            // legacy primary ClientIp silently dropped the IPv6 side after oldNetwork.Dispose
            // removed its alias, while the flow classifier was told that IPv6 was available.
            var assigned = session.NetworkAddresses;
            foreach (var address in assigned)
                nextNetwork.SetAddress(retained.Name, address.Address, address.PrefixLength);
            nextNetwork.SetMtu(retained.Name, EffectiveMtu(config.Mtu, session.PushedMtu));

            if (!string.IsNullOrEmpty(config.LocalAddress))
                Log($"local = {config.LocalAddress}: not pinning the server route — carrier follows the bound interface's routing");
            else if (gateway != null || physicalIf != null)
                nextNetwork.PinServerRoute(serverIp, gateway, physicalIf);
            else
                Log("WARN: could not determine physical gateway; per-app carrier may loop");

            if (string.IsNullOrEmpty(config.LocalAddress))
                nextNetwork.VerifyCarrierPath(serverIp, retained.Name);
            return true;
        }
        catch
        {
            try { nextNetwork.Dispose(); } catch { }
            if (ReferenceEquals(_net, nextNetwork)) _net = null;
            throw;
        }
    }

    protected override void OnTransportInterrupted(VpnConfig config)
    {
        if (config.UsesAppFilter) _perApp?.SetTunnelDown();
    }

    protected override void PrepareRetainedTunForNetworkRebuild(VpnConfig config)
    {
        if (!config.UsesAppFilter) return;

        // A retained per-app utun is safe because the extension is already tunnel-down, but
        // the old host route to the carrier can make the next handshake follow a vanished
        // gateway. Remove only that platform network transaction; keep the utun descriptor
        // and transparent-proxy classifier for fail-closed in-place reconfiguration.
        DisposeNetworkConfigurator();
    }

    /// <summary>Idempotent configurator teardown: replays surviving undo entries
    /// (successful ones are removed inside Dispose; failed ones stay registered for
    /// the next pass). Every teardown path funnels through here so the dispose/null-out
    /// dance exists exactly once.</summary>
    private void DisposeNetworkConfigurator()
    {
        var network = _net;
        network?.Dispose();
        if (ReferenceEquals(_net, network)) _net = null;
    }

    protected override void BeforeTunDispose()
    {
        _perApp?.Stop();
        RestoreIpForwarding(); // Refusal retains the live TUN and its cleanup ownership.
        // Reset DNS and routes BEFORE closing the utun descriptor: XNU destroys the
        // interface on close and configd then holds SCPreferences for ~20 s (with DHCP
        // probes), blocking networksetup.
        DisposeNetworkConfigurator();
    }

    // Firewall kill-switch (full-tunnel only) via pf. Create/reserve the next utun before
    // raising PF, so the allowlist names only interfaces actually owned by this tunnel.
    protected override bool KillSwitchEngageFailureRetainsOwnership(Exception error) =>
        error is AggregateException;
    protected override void KillSwitchEngage(VpnConfig config)
    {
        var names = new List<string>();
        if (_tun is UtunDevice current) names.Add(current.Name);
        names.Add(EnsurePrewarmedUtun().Name);
        try
        {
            KillSwitch.Engage(config.ServerAddress, names, Log);
        }
        catch (AggregateException)
        {
            // PF rollback itself failed. Keep the named utun alive so a partially active
            // fail-closed ruleset cannot suddenly refer to a recycled foreign interface.
            throw;
        }
        catch
        {
            _prewarmedUtun?.Dispose();
            _prewarmedUtun = null;
            throw;
        }
    }

    private UtunDevice EnsurePrewarmedUtun()
    {
        if (_prewarmedUtun != null) return _prewarmedUtun;
        var device = new UtunDevice();
        try
        {
            device.Open();
            _prewarmedUtun = device;
            return device;
        }
        catch
        {
            device.Dispose();
            throw;
        }
    }

    protected override void CarrierAddressesChanging(
        VpnConfig config, IReadOnlyList<string> previous, IReadOnlyList<string> refreshed)
    {
        if (EgressGuardEngaged && !config.UsesAppFilter)
            KillSwitch.UpdateServerAddresses(refreshed, Log);
    }

    protected override void KillSwitchDisengage()
    {
        // Remove PF rules first. If that fails, retain the reserved interface and its name;
        // the base will keep ownership armed and retry instead of allowing alias recycling.
        KillSwitch.Disengage(Log);
        _prewarmedUtun?.Dispose();
        _prewarmedUtun = null;
    }
}
