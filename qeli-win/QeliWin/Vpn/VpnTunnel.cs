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
        // persist-tun: if the adapter + routes survived the previous attempt and the
        // server re-assigned the same client IP, reuse them (no adapter flicker / route gap).
        if (ReusePersistedTun(config, session)) return;
        _net = new NetworkConfigurator(Log);
        uint physicalIf = _net.PhysicalIfIndexFor(serverIp);
        var gateway = _net.FindGatewayFor(serverIp);

        var wintun = new WintunAdapter();
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
        wintun.Open(adapterName, adapterGuid);
        var (tunIndex, alias) = _net.ResolveInterface(wintun.Luid);
        Log($"Wintun adapter '{alias}' (if {tunIndex}, driver {drv >> 16}.{drv & 0xFF})");
        _tun = wintun;

        _net.SetAddress(alias, session.ClientIp, session.Prefix);
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(alias, mtu);
        if (config.InterfaceMetric > 0) _net.SetMetric(wintun.Luid, alias, config.InterfaceMetric);  // OpenVPN route-metric (IPv4+IPv6)

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
            foreach (var r in LoadRouteFile(config)) _net.AddRoute(r, session.ClientIp, tunIndex);  // OpenVPN route-file
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
        KillSwitch.Engage(config.ServerAddress, AdapterIdentity(config).name, Log);

    protected override void KillSwitchDisengage() => KillSwitch.Disengage(Log);
}
