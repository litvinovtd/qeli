using System.Net;
using System.Text.Json.Nodes;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliWin.Vpn;

/// <summary>Windows platform binding for the shared qeli data plane
/// (<see cref="VpnTunnelBase"/>): opens a WintunAdapter and configures the
/// addressing / routes / DNS for the session via NetworkConfigurator.</summary>
public sealed class VpnTunnel : VpnTunnelBase
{
    // Stable GUID so the same Wintun adapter is reused across runs.
    private static readonly Guid AdapterGuid = new("d3a1f4e0-1c2b-4a6e-9f10-abcd00000001");
    private NetworkConfigurator? _net;

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        _net = new NetworkConfigurator(Log);
        uint physicalIf = _net.PhysicalIfIndexFor(serverIp);
        var gateway = _net.FindGatewayFor(serverIp);

        var wintun = new WintunAdapter();
        uint drv = WintunAdapter.RunningDriverVersion();
        wintun.Open("Qeli", AdapterGuid);
        var (tunIndex, alias) = _net.ResolveInterface(wintun.Luid);
        Log($"Wintun adapter '{alias}' (if {tunIndex}, driver {drv >> 16}.{drv & 0xFF})");
        _tun = wintun;

        _net.SetAddress(alias, session.ClientIp, session.Prefix);
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(alias, mtu);

        // Pin the carrier route to the server through the physical gateway BEFORE
        // we hijack the default route, so the encrypted tunnel never loops on itself.
        if (gateway != null && physicalIf != 0)
            _net.PinServerRoute(serverIp, gateway, physicalIf);
        else
            Log("WARN: could not determine physical gateway; full-tunnel may loop");

        if (config.IsFullTunnel)
        {
            _net.SetFullTunnelRoutes(session.ClientIp, tunIndex);
            _net.CaptureIPv6(alias); // close the dual-stack IPv6 leak (E2)
        }
        else
        {
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, session.ClientIp, tunIndex);
        }

        if (config.RouteLocalNetworks)
        {
            ApplyPushedRoutes(session.RoutesJson, session.ClientIp, tunIndex);
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, session.ClientIp, tunIndex);
            Log("Routing local networks (RFC1918 + pushed) through the tunnel");
        }

        var dns = (config.DnsServers.Count > 0 ? config.DnsServers : new List<string> { session.DnsIp })
            .Where(s => !string.IsNullOrEmpty(s)).ToList();
        _net.SetDns(alias, dns);
    }

    private void ApplyPushedRoutes(string routesJson, string clientIp, uint tunIndex)
    {
        if (string.IsNullOrWhiteSpace(routesJson) || routesJson == "[]") return;
        try
        {
            if (JsonNode.Parse(routesJson) is JsonArray arr)
                foreach (var n in arr)
                {
                    string cidr = (n?["cidr"] as JsonValue)?.GetValue<string>() ?? "";
                    if (cidr.Length > 0) { _net!.AddRoute(cidr, clientIp, tunIndex); Log($"pushed route: {cidr}"); }
                }
        }
        catch (Exception e) { Log($"routes parse error: {e.Message}"); }
    }

    protected override void CleanupPlatform()
    {
        try { _net?.Dispose(); } catch { }
        _net = null;
    }

    // Firewall kill-switch (full-tunnel only). Allow the Wintun adapter by its stable
    // name "Qeli" (the rule matches once the adapter appears on reconnect, like the
    // Linux `oifname vpn0`), so the kill-switch can be raised before the tun exists.
    protected override void KillSwitchEngage(VpnConfig config) =>
        KillSwitch.Engage(config.ServerAddress, "Qeli", Log);

    protected override void KillSwitchDisengage() => KillSwitch.Disengage(Log);
}
