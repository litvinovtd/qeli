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

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        // persist-tun: reuse the utun + routes from the previous attempt when the server
        // re-assigned the same client IP (no interface flicker / route gap on reconnect).
        if (ReusePersistedTun(config, session)) return;
        _net = new NetworkConfigurator(Log);
        var (physicalIf, gateway) = _net.PathToServer(serverIp);

        var utun = new UtunDevice();
        utun.Open();
        string dev = utun.Name;
        Log($"utun interface '{dev}' (physical path {physicalIf ?? "?"} via {gateway?.ToString() ?? "?"})");
        _tun = utun;

        _net.SetAddress(dev, session.ClientIp, session.Prefix);
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
        else if (gateway != null)
            _net.PinServerRoute(serverIp, gateway);
        else if (physicalIf != null)
            // `route -n get` resolved the interface but returned no gateway ⇒ the server is on-link
            // (same subnet as the client). The connected-subnet route already keeps the carrier off
            // the tunnel; pinning it via a gateway would make the path asymmetric and stall the
            // tunnel on a same-LAN setup (see TROUBLESHOOTING §6.8). Skip the pin.
            Log($"server {serverIp} is on-link (same subnet) — not pinning; the connected route keeps the carrier off the tunnel");
        else
            Log("WARN: could not determine physical gateway; full-tunnel may loop");

        if (config.IsFullTunnel)
        {
            _net.SetFullTunnelRoutes(dev);
            // Capture IPv6 into the (IPv4-only) tunnel to close the dual-stack leak (E2),
            // unless the user opted out via allow_ipv6_leak to keep native IPv6.
            if (!config.AllowIpv6Leak)
                _net.CaptureIPv6(dev);
        }
        else
        {
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, dev);
            foreach (var r in LoadRouteFile(config)) _net.AddRoute(r, dev);  // OpenVPN route-file
        }

        // Subnets the server advertised (`route = …` on the profile / per-user) are a
        // specific, explicit admin decision — always honoured, like OpenVPN's
        // `push "route …"`. Until 0.7.12 these sat behind RouteLocalNetworks, so a
        // correctly configured route was silently dropped on every default client.
        ApplyPushedRoutes(session.RoutesJson, dev);

        // RouteLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
        // default because it would hijack the machine's own LAN (printers, NAS, router).
        if (config.RouteLocalNetworks)
        {
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, dev);
            Log("Routing local networks (RFC1918 blanket) through the tunnel");
        }

        // Exclude: route these subnets via the physical gateway so exclusion works even in
        // full-tunnel (a plain delete is a no-op there); fall back to a delete when the
        // gateway is unknown (split-tunnel).
        foreach (var r in config.ExcludeRoutes)
        {
            if (gateway != null) _net.PinBypassRoute(r, gateway);
            else _net.DeleteRoute(r);
        }

        // #13: pure L3 forwarding for a LAN BEHIND this Mac (no NAT), so the far side can
        // route to it through the tunnel (site-to-site). macOS gates it on one sysctl.
        if (config.Forward) EnableIpForwarding();

        _net.SetDns(EffectiveDns(config, session));
    }

    /// <summary>Enable kernel IPv4 forwarding (no NAT) for a LAN behind this node (#13).
    /// Best-effort: needs root (the tunnel already runs elevated); a failure is logged.</summary>
    private void EnableIpForwarding()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("sysctl", "-w net.inet.ip.forwarding=1")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(3000);
            Log("IP forwarding enabled (net.inet.ip.forwarding=1) — LAN behind this node routable through the tunnel, no NAT");
        }
        catch (Exception e) { Log($"WARN: could not enable IP forwarding: {e.Message}"); }
    }

    private void ApplyPushedRoutes(string routesJson, string dev)
    {
        if (string.IsNullOrWhiteSpace(routesJson) || routesJson == "[]") return;
        try
        {
            if (JsonNode.Parse(routesJson) is JsonArray arr)
                foreach (var n in arr)
                {
                    string cidr = (n?["cidr"] as JsonValue)?.GetValue<string>() ?? "";
                    if (cidr.Length > 0) { _net!.AddRoute(cidr, dev); Log($"pushed route: {cidr}"); }
                }
        }
        catch (Exception e) { Log($"routes parse error: {e.Message}"); }
    }

    protected override void CleanupPlatform()
    {
        try { _net?.Dispose(); } catch { }
        _net = null;
    }

    // Firewall kill-switch (full-tunnel only) via pf. The utun name is dynamic, so
    // KillSwitch passes utun0..15 (the rule matches once our utun appears).
    protected override void KillSwitchEngage(VpnConfig config) =>
        KillSwitch.Engage(config.ServerAddress, Log);

    protected override void KillSwitchDisengage() => KillSwitch.Disengage(Log);
}
