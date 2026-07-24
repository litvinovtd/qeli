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
        if (_prewarm != null) return;
        var id = AdapterIdentity(config);
        _prewarmId = id;
        _prewarm = Task.Run(() =>
        {
            try { var w = new WintunAdapter(); w.Open(id.name, id.guid); return (WintunAdapter?)w; }
            catch (Exception e) { Log($"Wintun prewarm failed ({e.Message}); will open in SetupTun"); return null; }
        });
    }

    protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        // persist-tun: if the adapter + routes survived the previous attempt and the
        // server re-assigned the same client IP, reuse them (no adapter flicker / route gap).
        if (ReusePersistedTun(config, session)) return;
        _net = new NetworkConfigurator(Log);
        uint physicalIf = _net.PhysicalIfIndexFor(serverIp);
        var gateway = _net.FindGatewayFor(serverIp);

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

        _net.SetAddress(alias, session.ClientIp, session.Prefix);
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(alias, mtu);
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
        else if (_net.IsServerOnLink(serverIp))
            // Server is on the same subnet as the client (on-link). The connected-subnet route
            // already keeps the carrier off the tunnel; pinning it via the gateway would make the
            // path asymmetric and stall the tunnel on a same-LAN setup (see TROUBLESHOOTING §6.8).
            Log($"server {serverIp} is on-link (same subnet) — not pinning via the gateway; the connected route keeps the carrier off the tunnel");
        else if (gateway != null && physicalIf != 0)
            _net.PinServerRoute(serverIp, gateway, physicalIf);
        else
            Log("WARN: could not determine physical gateway; full-tunnel may loop");

        if (config.IsFullTunnel)
        {
            _net.SetFullTunnelRoutes(session.ClientIp, tunIndex);
            // Capture IPv6 into the (IPv4-only) tunnel to close the dual-stack leak (E2),
            // unless the user opted out via allow_ipv6_leak to keep native IPv6.
            if (!config.AllowIpv6Leak)
                _net.CaptureIPv6(alias);
        }
        else
        {
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, session.ClientIp, tunIndex);
            foreach (var r in LoadRouteFile(config)) _net.AddRoute(r, session.ClientIp, tunIndex);  // OpenVPN route-file
        }

        // Subnets the server advertised (`route = …` on the profile / per-user) are a
        // specific, explicit admin decision — always honoured, like OpenVPN's
        // `push "route …"`. Until 0.7.12 these sat behind RouteLocalNetworks, so a
        // correctly configured route was silently dropped on every default client.
        ApplyPushedRoutes(session.RoutesJson, session.ClientIp, tunIndex);

        // RouteLocalNetworks gates only the BLANKET RFC1918 pull, which stays off by
        // default because it would hijack the machine's own LAN (printers, NAS, router).
        if (config.RouteLocalNetworks)
        {
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, session.ClientIp, tunIndex);
            Log("Routing local networks (RFC1918 blanket) through the tunnel");
        }

        // Exclude: carve these destinations out of the tunnel. Route them via the physical
        // gateway so exclusion works even in full-tunnel (a plain delete is a no-op there);
        // fall back to a delete only when the gateway is unknown (split-tunnel).
        foreach (var r in config.ExcludeRoutes)
        {
            if (gateway != null && physicalIf != 0) _net.PinBypassRoute(r, gateway, physicalIf);
            else _net.DeleteRoute(r);
        }

        // #13: pure L3 forwarding for a LAN BEHIND this Windows node (no NAT), so the far
        // side can route to it through the tunnel. Best-effort per-interface enable.
        if (config.Forward) EnableIpForwarding(alias);

        _net.SetDns(alias, EffectiveDns(config, session));

        // LAST step of bring-up: ask the OS whether the carrier still leaves via the
        // physical interface. Everything above only proved the commands were issued; this
        // checks what the routing table actually decided, which is what "Connected" claims.
        // Skipped when `local` binds the carrier elsewhere (e.g. through another VPN) —
        // there the user owns the path and the server route is deliberately not pinned. (C-17)
        if (string.IsNullOrEmpty(config.LocalAddress))
            _net.VerifyCarrierPath(serverIp, tunIndex);
    }

    /// <summary>Enable IPv4 forwarding on the tunnel interface (no NAT) for a LAN behind this
    /// node (#13). Best-effort. Note: for the LAN→tunnel direction the admin may also need
    /// forwarding on the LAN NIC (or the global IPEnableRouter). Runs elevated already.</summary>
    private void EnableIpForwarding(string alias)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("netsh",
                $"interface ipv4 set interface \"{alias}\" forwarding=enabled")
            {
                UseShellExecute = false, RedirectStandardOutput = true,
                RedirectStandardError = true, CreateNoWindow = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(3000);
            Log($"IP forwarding enabled on '{alias}' (no NAT). For LAN->tunnel routing enable " +
                "forwarding on the LAN NIC too (netsh …forwarding=enabled) or set IPEnableRouter.");
        }
        catch (Exception e) { Log($"WARN: could not enable IP forwarding: {e.Message}"); }
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
                    if (cidr.Length == 0)
                    {
                        Log("pushed route IGNORED: empty CIDR (fix the server's `route =` line)");
                        continue;
                    }
                    // Report the route EXACTLY as it arrived, then what actually happened to it.
                    // Our routes are interface-scoped (CreateIpForwardEntry2 against the tun's
                    // index), so a pushed next-hop/metric cannot be honoured — traffic enters the
                    // tunnel and the server forwards it, which reaches the same place.
                    string gw = (n?["gateway"] as JsonValue)?.GetValue<string>() ?? "";
                    string mt = n?["metric"]?.ToString() ?? "";
                    string got = cidr
                               + (gw.Length > 0 ? $" gateway={gw}" : "")
                               + (mt.Length > 0 && mt != "0" ? $" metric={mt}" : "");
                    _net!.AddRoute(cidr, clientIp, tunIndex);
                    Log(gw.Length > 0 || (mt.Length > 0 && mt != "0")
                        ? $"pushed route: {got} -> APPLIED via the tunnel interface (next-hop/metric not settable here)"
                        : $"pushed route: {got} -> APPLIED via the tunnel interface");
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
        // A prewarmed adapter that SetupTun never consumed (handshake failed before it ran)
        // would otherwise leak a Wintun device — dispose it. Once consumed, _prewarm is null,
        // so the live adapter (now _tun) is disposed by the base, not here.
        if (_prewarm != null)
        {
            try { _prewarm.GetAwaiter().GetResult()?.Dispose(); } catch { }
            _prewarm = null;
        }
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
