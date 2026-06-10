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

        // Pin the carrier route to the server through the physical gateway BEFORE
        // we hijack the default route, so the encrypted tunnel never loops on itself.
        if (gateway != null)
            _net.PinServerRoute(serverIp, gateway);
        else
            Log("WARN: could not determine physical gateway; full-tunnel may loop");

        if (config.IsFullTunnel)
        {
            _net.SetFullTunnelRoutes(dev);
            _net.CaptureIPv6(dev); // close the dual-stack IPv6 leak (E2)
        }
        else
        {
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, dev);
        }

        if (config.RouteLocalNetworks)
        {
            ApplyPushedRoutes(session.RoutesJson, dev);
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, dev);
            Log("Routing local networks (RFC1918 + pushed) through the tunnel");
        }

        var dns = (config.DnsServers.Count > 0 ? config.DnsServers : new List<string> { session.DnsIp })
            .Where(s => !string.IsNullOrEmpty(s)).ToList();
        _net.SetDns(dns);
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
}
