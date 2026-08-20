using System.Net;
using System.Text.Json.Nodes;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Vpn;

/// <summary>macOS platform binding for the shared qeli data plane
/// (<see cref="VpnTunnelBase"/>): opens a UtunDevice and configures the
/// addressing / routes / DNS for the session via NetworkConfigurator.</summary>
public sealed class VpnTunnel : VpnTunnelBase
{
    private NetworkConfigurator? _net;
    private PerAppController? _perApp;

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


    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
        IReadOnlyList<IPAddress> carrierCandidates)
    {
        // persist-tun: reuse only when the complete applied network-plan fingerprint matches;
        // the same client IP can arrive with different routes, DNS, prefix or MTU.
        if (ReusePersistedTun(config, session, serverIp))
        {
            if (config.UsesAppFilter && _tun is UtunDevice retained)
            {
                (_perApp ??= new PerAppController(Log)).StartOrUpdate(
                    config, retained.Name, serverIp, EffectiveDns(config, session),
                    config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(config, session)).ToArray(),
                    config.ExcludeRoutes, PushedRouteCidrs(session.RoutesJson),
                    session.NetworkAddresses?.Any(address => address.Family == "ipv4") ?? true,
                    session.NetworkAddresses?.Any(address => address.Family == "ipv6") ?? false,
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

        var utun = new UtunDevice();
        utun.Open();
        string dev = utun.Name;
        var selectedPath = carrierPaths.First(path => path.address.Equals(serverIp));
        Log($"utun interface '{dev}' (physical path {selectedPath.physicalIf ?? "?"} via {selectedPath.gateway?.ToString() ?? "?"})");
        _tun = utun;

        var assigned = session.NetworkAddresses
            ?? new[] { new AssignedAddress("ipv4", session.ClientIp, session.Prefix,
                session.Prefix, null) };
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
                if (gateway != null)
                {
                    _net.PinServerRoute(address, gateway);
                }
                else if (physicalIf != null)
                {
                    // `route -n get` resolved an interface but no gateway: the peer is
                    // on-link and its connected route is already the correct bypass.
                    Log($"server {address} is on-link (same subnet) — not pinning; the connected route keeps the carrier off the tunnel");
                }
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

        // Per-app mode is deliberately NOT expressed as host routes or host DNS. A signed
        // NETransparentProxyProvider classifies flows by source-app signing identifier and
        // binds only the selected sockets to this utun. Unselected applications therefore
        // retain the machine's ordinary route and resolver. Keeping this branch before all
        // global route/DNS mutations is what makes include/exclude genuinely per-app.
        if (config.UsesAppFilter)
        {
            (_perApp ??= new PerAppController(Log)).StartOrUpdate(
                config, dev, serverIp, EffectiveDns(config, session),
                config.IncludeRoutes.Concat(EffectiveRouteFileRoutes(config, session)).ToArray(),
                config.ExcludeRoutes, PushedRouteCidrs(session.RoutesJson),
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
            if (!_net.AddRoute(cidr, dev))
                throw new InvalidOperationException(
                    $"connected tunnel prefix {cidr} was not applied");

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
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, dev);
        }
        if (!config.IsFullTunnel)
            foreach (var r in EffectiveRouteFileRoutes(config, session))
                _net.AddRoute(r, dev);  // OpenVPN route-file

        // Subnets the server advertised (`route = …` on the profile / per-user) are a
        // specific, explicit admin decision — always honoured, like OpenVPN's
        // `push "route …"`. Until 0.7.12 these sat behind RouteLocalNetworks, so a
        // correctly configured route was silently dropped on every default client.
        ApplyPushedRoutes(session.RoutesJson, dev, connectedPrefixes);

        // RouteLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
        // default because it would hijack the machine's own LAN (printers, NAS, router).
        if (config.RouteLocalNetworks && !session.PlanIncludesClientRoutes)
        {
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, dev);
            Log("Routing local networks (RFC1918 blanket) through the tunnel");
        }

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

        if (!_net.SetDns(EffectiveDns(config, session)))
            throw new InvalidOperationException(
                "canonical NetworkPlan DNS servers were not applied");

        // LAST step of bring-up — see the Windows counterpart. Ask the OS what the routing
        // table actually decided rather than trusting that the commands took. Skipped when
        // `local` binds the carrier elsewhere and the pin was deliberately not done. (C-17)
        if (string.IsNullOrEmpty(config.LocalAddress))
            foreach (var address in carrierPaths.Select(path => path.address))
                _net.VerifyCarrierPath(address, dev);
    }

    /// <summary>Was `net.inet.ip.forwarding` already 1 before we touched it? Null = we never
    /// changed it. Turning the user's Mac into a router is a HOST-WIDE change that outlived
    /// the tunnel — it was set on connect and never put back, so a single site-to-site
    /// session left IP forwarding on until the next reboot. (C-18)</summary>
    private bool? _ipForwardingWasOn;
    private bool? _ipv6ForwardingWasOn;

    /// <summary>Enable kernel forwarding (no NAT) for active NetworkPlan families (#13).
    /// The tunnel runs elevated; a failure aborts setup because forward=true is part of the plan.
    /// The previous value is remembered and restored in <see cref="CleanupPlatform"/>.</summary>
    private void EnableIpForwarding(bool hasIpv4, bool hasIpv6)
    {
        bool? ipv4WasOn = hasIpv4 ? ReadSysctlFlag("net.inet.ip.forwarding") : null;
        bool? ipv6WasOn = hasIpv6 ? ReadSysctlFlag("net.inet6.ip6.forwarding") : null;
        _ipForwardingWasOn = ipv4WasOn;
        _ipv6ForwardingWasOn = ipv6WasOn;
        try
        {
            if (ipv4WasOn == false) SetSysctl("net.inet.ip.forwarding=1");
            if (ipv6WasOn == false) SetSysctl("net.inet6.ip6.forwarding=1");
            string families = hasIpv4 && hasIpv6 ? "IPv4 and IPv6" : hasIpv4 ? "IPv4" : "IPv6";
            Log($"IP forwarding enabled/preserved for {families} — LAN behind this node routable through the tunnel, no NAT");
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

    /// <summary>Put `net.inet.ip.forwarding` back to 0 if WE turned it on. (C-18)</summary>
    private void RestoreIpForwarding()
    {
        if (_ipForwardingWasOn == false) SetSysctl("net.inet.ip.forwarding=0");
        if (_ipv6ForwardingWasOn == false) SetSysctl("net.inet6.ip6.forwarding=0");
        if (_ipForwardingWasOn != null || _ipv6ForwardingWasOn != null)
            Log("IP forwarding restored to its previous IPv4/IPv6 state");
        _ipForwardingWasOn = null;
        _ipv6ForwardingWasOn = null;
    }

    private static bool ReadSysctlFlag(string name)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("/usr/sbin/sysctl", $"-n {name}")
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = System.Diagnostics.Process.Start(psi);
        if (p == null) throw new InvalidOperationException($"could not start sysctl to read {name}");
        var outp = p.StandardOutput.ReadToEndAsync();
        var err = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(3000))
        {
            try { p.Kill(true); } catch { }
            throw new TimeoutException($"sysctl timed out while reading {name}");
        }
        string output = outp.GetAwaiter().GetResult().Trim();
        string error = err.GetAwaiter().GetResult().Trim();
        if (p.ExitCode != 0)
            throw new InvalidOperationException($"sysctl could not read {name}: {error}");
        return output switch
        {
            "0" => false,
            "1" => true,
            _ => throw new InvalidOperationException($"sysctl returned invalid value '{output}' for {name}"),
        };
    }

    private static void SetSysctl(string assignment)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("/usr/sbin/sysctl", $"-w {assignment}")
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = System.Diagnostics.Process.Start(psi);
        if (p == null) throw new InvalidOperationException($"could not start sysctl for {assignment}");
        var output = p.StandardOutput.ReadToEndAsync();
        var error = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(3000))
        {
            try { p.Kill(true); } catch { }
            throw new TimeoutException($"sysctl timed out while setting {assignment}");
        }
        string stdout = output.GetAwaiter().GetResult().Trim();
        string stderr = error.GetAwaiter().GetResult().Trim();
        if (p.ExitCode != 0)
            throw new InvalidOperationException(
                $"sysctl could not set {assignment}: " +
                (string.IsNullOrWhiteSpace(stderr) ? stdout : stderr));
    }

    private void ApplyPushedRoutes(string routesJson, string dev,
        IReadOnlyList<string> alreadyApplied)
    {
        if (string.IsNullOrWhiteSpace(routesJson) || routesJson == "[]") return;
        try
        {
            var seen = new HashSet<string>(alreadyApplied, StringComparer.OrdinalIgnoreCase);
            if (JsonNode.Parse(routesJson) is not JsonArray arr)
                throw new InvalidOperationException("NetworkPlan routes payload is not an array");
            foreach (var n in arr)
                {
                    string cidr = (n?["cidr"] as JsonValue)?.GetValue<string>() ?? "";
                    if (cidr.Length == 0)
                    {
                        Log("pushed route IGNORED: empty CIDR (fix the server's `route =` line)");
                        continue;
                    }
                    if (!seen.Add(cidr)) continue;
                    // Report the route EXACTLY as it arrived, then what actually happened to it.
                    // `route add -net … -interface utunN` is interface-scoped, so a pushed
                    // next-hop/metric cannot be honoured — traffic enters the tunnel and the
                    // server forwards it, which reaches the same place.
                    string gw = (n?["gateway"] as JsonValue)?.GetValue<string>() ?? "";
                    string mt = n?["metric"]?.ToString() ?? "";
                    string got = cidr
                               + (gw.Length > 0 ? $" gateway={gw}" : "")
                               + (mt.Length > 0 && mt != "0" ? $" metric={mt}" : "");
                    if (!_net!.AddRoute(cidr, dev))
                        throw new InvalidOperationException(
                            $"canonical NetworkPlan route {cidr} was not applied");
                    Log(gw.Length > 0 || (mt.Length > 0 && mt != "0")
                        ? $"pushed route: {got} -> APPLIED via the tunnel interface (next-hop/metric not settable here)"
                        : $"pushed route: {got} -> APPLIED via the tunnel interface");
                }
        }
        catch (Exception e)
        {
            throw new InvalidOperationException(
                $"could not apply canonical NetworkPlan routes: {e.Message}", e);
        }
    }

    private static IReadOnlyList<string> PushedRouteCidrs(string routesJson)
    {
        if (string.IsNullOrWhiteSpace(routesJson) || routesJson == "[]")
            return Array.Empty<string>();
        try
        {
            return JsonNode.Parse(routesJson) is JsonArray arr
                ? arr.Select(n => (n?["cidr"] as JsonValue)?.GetValue<string>() ?? "")
                    .Where(c => c.Length > 0).ToArray()
                : Array.Empty<string>();
        }
        catch { return Array.Empty<string>(); }
    }

    protected override void CleanupPlatform()
    {
        // Undo the host-wide sysctl before dropping the configurator, so a disconnect
        // leaves the machine as it was found. (C-18)
        RestoreIpForwarding();
        var network = _net;
        try
        {
            // NetworkConfigurator deliberately throws when the physical service's DNS was
            // not restored. Keep the configurator referenced in that case so a second Stop
            // in this process can retry instead of forgetting the recovery action.
            network?.Dispose();
            if (ReferenceEquals(_net, network)) _net = null;
        }
        finally
        {
            _perApp = null;
        }
    }

    // The system extension stays installed and retains its flow rules across a carrier
    // reconnect. Selected apps are failed closed until the same utun is usable again.
    protected override bool KeepTunDuringReconnect(VpnConfig config) =>
        config.UsesAppFilter || base.KeepTunDuringReconnect(config);

    protected override bool TryReconfigurePersistedTun(
        VpnConfig config, Session session, IPAddress serverIp)
    {
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
            var assigned = session.NetworkAddresses
                ?? new[] { new AssignedAddress("ipv4", session.ClientIp, session.Prefix,
                    session.Prefix, null) };
            foreach (var address in assigned)
                nextNetwork.SetAddress(retained.Name, address.Address, address.PrefixLength);
            nextNetwork.SetMtu(retained.Name, EffectiveMtu(config.Mtu, session.PushedMtu));

            if (!string.IsNullOrEmpty(config.LocalAddress))
                Log($"local = {config.LocalAddress}: not pinning the server route — carrier follows the bound interface's routing");
            else if (gateway != null)
                nextNetwork.PinServerRoute(serverIp, gateway);
            else if (physicalIf != null)
                Log($"server {serverIp} is on-link (same subnet) — not pinning; the connected route keeps the carrier off the tunnel");
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
        var network = _net;
        network?.Dispose();
        if (ReferenceEquals(_net, network)) _net = null;
    }

    protected override void BeforeTunDispose() => _perApp?.Stop();

    // Firewall kill-switch (full-tunnel only) via pf. The utun name is dynamic, so
    // KillSwitch passes utun0..15 (the rule matches once our utun appears).
    protected override void KillSwitchEngage(VpnConfig config) =>
        KillSwitch.Engage(config.ServerAddress, Log);

    protected override void CarrierAddressesChanging(
        VpnConfig config, IReadOnlyList<string> previous, IReadOnlyList<string> refreshed)
    {
        if (EgressGuardEngaged && !config.UsesAppFilter)
            KillSwitch.UpdateServerAddresses(refreshed, Log);
    }

    protected override void KillSwitchDisengage() => KillSwitch.Disengage(Log);
}
