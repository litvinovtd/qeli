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
    private NetworkConfigurator? _net;

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        _net = new NetworkConfigurator(Log);
        uint physicalIf = _net.PhysicalIfIndexFor(serverIp);
        var gateway = _net.FindGatewayFor(serverIp);

        var wintun = new WintunAdapter();
        uint drv = WintunAdapter.RunningDriverVersion();
        // Per-tunnel adapter identity (name + GUID) so several qeli tunnels can run on
        // ONE host without fighting over a single Wintun adapter; stable across runs of
        // the same tunnel, so the adapter is still reused rather than recreated.
        var (adapterName, adapterGuid) = AdapterIdentity(config.ServerAddress);
        wintun.Open(adapterName, adapterGuid);
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

        // Split-tunnel exclude: drop these destinations from the tunnel (parity with the
        // Rust client + macOS). No-op in full-tunnel (they're covered by the /1 splits).
        foreach (var r in config.ExcludeRoutes) _net.DeleteRoute(r);

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

    // Deterministic per-tunnel adapter identity: a stable name + GUID derived from the
    // server address. Same tunnel across runs → same adapter (reused); different tunnels
    // → different adapters, so N can coexist on one host. The hash is for uniqueness
    // only (not security). An empty address keeps the legacy "Qeli" id.
    private static (string name, Guid guid) AdapterIdentity(string serverAddress)
    {
        if (string.IsNullOrEmpty(serverAddress))
            return ("Qeli", new Guid("d3a1f4e0-1c2b-4a6e-9f10-abcd00000001"));
        byte[] h = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes("qeli-adapter:" + serverAddress));
        return ($"Qeli-{Convert.ToHexString(h, 0, 3)}", new Guid(h));
    }

    protected override void CleanupPlatform()
    {
        try { _net?.Dispose(); } catch { }
        _net = null;
    }

    // Firewall kill-switch (full-tunnel only). Allow the Wintun adapter by its
    // per-tunnel name (derived from the server address, same as SetupTun); the rule
    // matches once the adapter appears on reconnect, like the Linux `oifname vpn0`, so
    // it can be raised before the tun exists.
    protected override void KillSwitchEngage(VpnConfig config) =>
        KillSwitch.Engage(config.ServerAddress, AdapterIdentity(config.ServerAddress).name, Log);

    protected override void KillSwitchDisengage() => KillSwitch.Disengage(Log);
}
