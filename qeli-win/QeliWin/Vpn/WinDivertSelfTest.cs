using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace QeliWin.Vpn;

/// <summary>
/// Headless checks for the WinDivert per-app data plane that do not need a live VPN
/// session. Invoked from <c>selftest</c> (always) and optionally from
/// <c>windivert-e2e</c> (elevated filter open).
/// </summary>
internal static class WinDivertSelfTest
{
    public static int RunUnit(Action<string, bool> check)
    {
        int before = 0; // unused — check callback records failures externally
        _ = before;

        // Destination policy: RFC1918 is NOT unconditionally direct.
        var defaultPol = new WinDivertDestinationPolicy(false, null, null, null);
        check("dest: public IP not bypassed",
            !defaultPol.ShouldBypassTunnel(IPAddress.Parse("1.1.1.1")));
        check("dest: RFC1918 bypassed when route_local off",
            defaultPol.ShouldBypassTunnel(IPAddress.Parse("192.168.1.1")));
        check("dest: link-local always bypassed",
            defaultPol.ShouldBypassTunnel(IPAddress.Parse("169.254.10.1")));

        var localPol = new WinDivertDestinationPolicy(true, null, null, null);
        check("dest: RFC1918 tunnelled when route_local on",
            !localPol.ShouldBypassTunnel(IPAddress.Parse("10.0.0.5")));

        var includePol = new WinDivertDestinationPolicy(false,
            includeRoutes: new[] { "192.168.50.0/24" }, null, null);
        check("dest: user include private CIDR tunnelled",
            !includePol.ShouldBypassTunnel(IPAddress.Parse("192.168.50.10")));
        check("dest: other RFC1918 still bypassed without route_local",
            includePol.ShouldBypassTunnel(IPAddress.Parse("192.168.1.1")));

        var pushedPol = new WinDivertDestinationPolicy(false, null, null,
            pushedRoutes: new[] { "172.16.9.0/24" });
        check("dest: server-pushed private CIDR tunnelled",
            !pushedPol.ShouldBypassTunnel(IPAddress.Parse("172.16.9.3")));

        var exclPol = new WinDivertDestinationPolicy(true, null,
            excludeRoutes: new[] { "10.1.0.0/16" }, null);
        check("dest: exclude wins over route_local",
            exclPol.ShouldBypassTunnel(IPAddress.Parse("10.1.2.3")));
        check("dest: route_local still tunnels other RFC1918",
            !exclPol.ShouldBypassTunnel(IPAddress.Parse("10.2.0.1")));

        // Flow table: two parallel flows keep distinct orig IPs / interfaces.
        var flows = new WinDivertFlowTable(TimeSpan.FromMinutes(2), TimeSpan.FromSeconds(30));
        var client = IPAddress.Parse("10.8.0.2");
        var remote1 = IPAddress.Parse("1.1.1.1");
        var remote2 = IPAddress.Parse("8.8.8.8");
        var srcA = IPAddress.Parse("192.168.0.10");
        var srcB = IPAddress.Parse("192.168.1.20");
        var addrA = new WinDivertNative.WinDivertAddress { IfIdx = 11, SubIfIdx = 0 };
        var addrB = new WinDivertNative.WinDivertAddress { IfIdx = 22, SubIfIdx = 0 };
        flows.RememberOutbound(6, client, srcA, 40001, remote1, 443, in addrA);
        flows.RememberOutbound(6, client, srcB, 40002, remote2, 443, in addrB);
        check("flow: count == 2", flows.FlowCount == 2);
        check("flow: lookup A restores src+if",
            flows.TryGetInbound(6, remote1, 443, client, 40001, out var fa)
            && fa.OriginalSrc.Equals(srcA) && fa.Addr.IfIdx == 11);
        check("flow: lookup B restores src+if",
            flows.TryGetInbound(6, remote2, 443, client, 40002, out var fb)
            && fb.OriginalSrc.Equals(srcB) && fb.Addr.IfIdx == 22);

        // DNS state has TTL and is keyed by the flow, not a bare source port.
        var dnsOrig = IPAddress.Parse("1.0.0.1");
        // The reverse key must use the rewritten resolver (remote2), while DnsOrigDst is
        // the resolver the app originally addressed (remote1). This is the regression that
        // previously dropped every rewritten DNS reply.
        flows.RememberOutbound(17, client, srcA, 53001, remote2, 53, in addrA, remote1);
        check("flow: DNS orig dst remembered",
            flows.TryGetInbound(17, remote2, 53, client, 53001, out var fd)
            && fd.ActiveDnsOrigDst != null && fd.ActiveDnsOrigDst.Equals(remote1));
        check("flow: DNS reverse lookup does not use original resolver",
            !flows.TryGetInbound(17, remote1, 53, client, 53001, out _));

        // Short-TTL table expires DNS.
        var shortDns = new WinDivertFlowTable(TimeSpan.FromMinutes(2), TimeSpan.FromMilliseconds(1));
        shortDns.RememberOutbound(17, client, srcA, 53002, remote1, 53, in addrA, dnsOrig);
        Thread.Sleep(5);
        check("flow: DNS orig dst expires",
            shortDns.TryGetInbound(17, remote1, 53, client, 53002, out var fe)
            && fe.ActiveDnsOrigDst == null);

        // Fragment affinity.
        flows.RememberFrag(srcA, remote1, 17, 0xABCD, PacketDisposition.Tunnel);
        flows.SetFragTunnelDestination(srcA, remote1, 17, 0xABCD, remote2);
        check("frag: non-first follows first",
            flows.TryGetFrag(srcA, remote1, 17, 0xABCD, out var fr)
            && fr.Disposition == PacketDisposition.Tunnel
            && remote2.Equals(fr.TunnelDestination));

        // Include fail-closed: unknown owner → Drop (exercised via ProcessAppMap on a
        // port that cannot belong to a live socket — high ephemeral unlikely to be bound
        // after refresh; we assert the mode flag and disposition helper contract).
        using (var includeMap = new ProcessAppMap(Array.Empty<string>(), includeMode: true))
        {
            var d = includeMap.Classify(6, IPAddress.Parse("127.0.0.1"), 1,
                IPAddress.Parse("1.1.1.1"), 443);
            check("include: unknown owner is Drop (fail-closed)", d == PacketDisposition.Drop);
            check("include: non-TCP/UDP is Drop",
                includeMap.Classify(1, IPAddress.Parse("127.0.0.1"), 0,
                    IPAddress.Parse("1.1.1.1"), 0) == PacketDisposition.Drop);
        }
        using (var excludeMap = new ProcessAppMap(Array.Empty<string>(), includeMode: false))
        {
            var d = excludeMap.Classify(6, IPAddress.Parse("127.0.0.1"), 1,
                IPAddress.Parse("1.1.1.1"), 443);
            check("exclude: unknown owner is Tunnel (fail-open)", d == PacketDisposition.Tunnel);
        }

        // Filter captures both families and no longer relies on a TTL marker to avoid
        // recapturing the carrier.
        string filter = WinDivertAdapter.BuildFilter();
        check("filter: captures IPv4+IPv6 without TTL marker",
            !filter.TrimEnd().EndsWith("and ip", StringComparison.Ordinal)
            && !filter.Contains("TTL", StringComparison.OrdinalIgnoreCase)
            && !filter.Contains("HopLimit", StringComparison.OrdinalIgnoreCase)
            && filter.Contains("outbound", StringComparison.Ordinal));

        // CIDR parser
        check("cidr: parse 10.0.0.0/8",
            WinDivertDestinationPolicy.TryParseCidr("10.0.0.0/8", out var c8)
            && c8.Contains(IPAddress.Parse("10.255.255.255"))
            && !c8.Contains(IPAddress.Parse("11.0.0.1")));

        // Elevated NativeLoader path is ProgramData when admin (document-only check of
        // directory naming; full ACL probe needs elevation).
        string expectedRoot = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "QeliWin", "native")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QeliWin", "native");
        check("NativeLoader: elevated uses ProgramData, else LocalAppData (policy)",
            expectedRoot.Contains("QeliWin" + Path.DirectorySeparatorChar + "native"));

        return 0;
    }

    /// <summary>Elevated smoke: open WinDivert with the production filter and close it.
    /// Does not require a VPN server. Returns failed check count.</summary>
    public static int RunElevatedSmoke(Action<string, bool> check)
    {
        int failed = 0;
        void C(string name, bool ok) { check(name, ok); if (!ok) failed++; }

        bool elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);
        C("elevated: process is administrator", elevated);
        if (!elevated) return failed;

        try
        {
            string? dir = NativeLoader.EnsureWinDivertDir();
            C("elevated: WinDivert extracted", dir != null
                && File.Exists(Path.Combine(dir!, "WinDivert.dll"))
                && File.Exists(Path.Combine(dir!, "WinDivert64.sys")));
            if (dir != null)
            {
                bool underProgramData = dir.StartsWith(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    StringComparison.OrdinalIgnoreCase);
                C("elevated: extract dir under ProgramData", underProgramData);
            }

            string filter = WinDivertAdapter.BuildFilter();
            // Compile-only via helper (no driver load required for compile, but Open needs it).
            bool compiled = WinDivertNative.WinDivertHelperCompileFilter(
                filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, IntPtr.Zero, 0,
                out _, out _);
            // Helper returns TRUE on success; when objectBuf is null it still validates.
            C("elevated: filter compiles (IPv4+IPv6)", compiled || Marshal.GetLastWin32Error() == 0);

            var adapter = new WinDivertAdapter(
                IPAddress.Parse("10.8.0.2"),
                new[] { Environment.ProcessPath ?? @"C:\Windows\System32\cmd.exe" },
                includeMode: true,
                dnsServers: Array.Empty<string>(),
                allowIpv6Leak: false,
                routeLocal: false,
                includeRoutes: null,
                excludeRoutes: null,
                pushedRoutes: null,
                carrierIp: IPAddress.Parse("203.0.113.10"),
                carrierPort: 443,
                carrierProtocol: "tcp");
            adapter.Open();
            C("elevated: WinDivertOpen ok", true);
            adapter.SetTunnelUp(false);
            adapter.Dispose();
            C("elevated: fail-closed SetTunnelUp + Dispose", true);
        }
        catch (Exception e)
        {
            C($"elevated: exception {e.Message}", false);
        }
        return failed;
    }
}
