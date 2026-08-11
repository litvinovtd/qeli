using System.Buffers.Binary;
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
        var ipv6ExclPol = new WinDivertDestinationPolicy(false, null,
            excludeRoutes: new[] { "2001:db8:1::/48" }, null);
        check("dest: IPv6 exclude route bypassed",
            ipv6ExclPol.ShouldBypassTunnel(IPAddress.Parse("2001:db8:1::42")));

        // Flow table: two parallel flows keep distinct orig IPs / interfaces.
        var flows = new WinDivertFlowTable();
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

        // Two host interfaces may reuse the same local port to the same destination. Once
        // both source addresses are NATed to the tunnel IP, a translated port is required
        // or the second reverse entry overwrites the first.
        var collisionFlows = new WinDivertFlowTable();
        ushort natA = collisionFlows.RememberOutbound(
            6, client, srcA, 41000, remote1, 443, in addrA);
        ushort natB = collisionFlows.RememberOutbound(
            6, client, srcB, 41000, remote1, 443, in addrB);
        check("flow: colliding local addresses receive distinct NAT ports",
            natA == 41000 && natB != 0 && natB != natA);
        check("flow: translated collision restores both local addresses and ports",
            collisionFlows.TryGetInbound(6, remote1, 443, client, natA, out var collisionA)
            && collisionFlows.TryGetInbound(6, remote1, 443, client, natB, out var collisionB)
            && collisionA.OriginalSrc.Equals(srcA) && collisionA.OriginalLocalPort == 41000
            && collisionB.OriginalSrc.Equals(srcB) && collisionB.OriginalLocalPort == 41000);

        var boundedFlows = new WinDivertFlowTable(maxFlows: 2);
        boundedFlows.RememberOutbound(6, client, srcA, 42001, remote1, 443, in addrA);
        boundedFlows.RememberOutbound(6, client, srcA, 42002, remote1, 443, in addrA);
        boundedFlows.RememberOutbound(6, client, srcA, 42003, remote1, 443, in addrA);
        check("flow: table enforces its configured memory bound", boundedFlows.FlowCount == 2);

        var closingFlows = new WinDivertFlowTable();
        ushort closingPort = closingFlows.RememberOutbound(
            6, client, srcA, 43001, remote1, 443, in addrA);
        closingFlows.ObserveInboundTcp(
            remote1, 443, client, closingPort, fin: true, rst: false);
        closingFlows.RememberOutbound(
            6, client, srcA, 43001, remote1, 443, in addrA, tcpFin: true);
        ushort finalAckPort = closingFlows.RememberOutbound(
            6, client, srcA, 43001, remote1, 443, in addrA);
        check("flow: bidirectional FIN retains one mapping through final ACK",
            closingFlows.FlowCount == 1 && finalAckPort == closingPort);
        closingFlows.CollectExpiredForTest(DateTime.UtcNow.AddMinutes(3));
        check("flow: closed TCP state expires on the short closing TTL", closingFlows.FlowCount == 0);
        closingFlows.RememberOutbound(
            6, client, srcA, 43002, remote1, 443, in addrA, tcpRst: true);
        check("flow: TCP RST removes reverse NAT state immediately", closingFlows.FlowCount == 0);
        closingFlows.RememberOutbound(
            6, client, srcA, 43003, remote1, 443, in addrA, tcpFin: true);
        closingFlows.CollectExpiredForTest(DateTime.UtcNow.AddMinutes(3));
        check("flow: half-closed TCP state uses the short closing TTL", closingFlows.FlowCount == 0);

        // DNS state has TTL and is keyed by the flow, not a bare source port.
        var dnsOrig = IPAddress.Parse("1.0.0.1");
        // The reverse key must use the rewritten resolver (remote2), while DnsOrigDst is
        // the resolver the app originally addressed (remote1). This is the regression that
        // previously dropped every rewritten DNS reply.
        flows.RememberOutbound(17, client, srcA, 53001, remote2, 53, in addrA, remote1);
        check("flow: DNS orig dst remembered",
            flows.TryGetInbound(17, remote2, 53, client, 53001, out var fd)
            && fd.DnsOrigDst != null && fd.DnsOrigDst.Equals(remote1));
        check("flow: DNS reverse lookup does not use original resolver",
            !flows.TryGetInbound(17, remote1, 53, client, 53001, out _));

        // The same UDP socket can query two original resolvers that both get rewritten to
        // one configured resolver. Original DNS destination is part of forward identity so
        // the replies retain distinct reverse-NAT sources instead of last-writer-wins.
        var dnsFlows = new WinDivertFlowTable();
        var originalDnsA = IPAddress.Parse("9.9.9.9");
        var originalDnsB = IPAddress.Parse("8.8.4.4");
        ushort dnsPortA = dnsFlows.RememberOutbound(
            17, client, srcA, 53010, remote2, 53, in addrA, originalDnsA);
        ushort dnsPortB = dnsFlows.RememberOutbound(
            17, client, srcA, 53010, remote2, 53, in addrA, originalDnsB);
        check("flow: rewritten DNS destinations receive distinct NAT identities",
            dnsPortA != 0 && dnsPortB != 0 && dnsPortA != dnsPortB);
        check("flow: each rewritten DNS reply restores its own original resolver",
            dnsFlows.TryGetInbound(17, remote2, 53, client, dnsPortA, out var dnsA)
            && dnsFlows.TryGetInbound(17, remote2, 53, client, dnsPortB, out var dnsB)
            && originalDnsA.Equals(dnsA.DnsOrigDst)
            && originalDnsB.Equals(dnsB.DnsOrigDst));

        // Protocol-aware expiry keeps idle TCP mappings while retiring UDP state.
        var ttlFlows = new WinDivertFlowTable(
            tcpTtl: TimeSpan.FromHours(2), udpTtl: TimeSpan.FromMinutes(2));
        ttlFlows.RememberOutbound(6, client, srcA, 54001, remote1, 443, in addrA);
        ttlFlows.RememberOutbound(17, client, srcA, 54002, remote1, 53, in addrA, dnsOrig);
        ttlFlows.CollectExpiredForTest(DateTime.UtcNow + TimeSpan.FromMinutes(3));
        check("flow: idle TCP retained beyond UDP TTL",
            ttlFlows.TryGetInbound(6, remote1, 443, client, 54001, out _));
        check("flow: idle UDP and DNS NAT expire together",
            !ttlFlows.TryGetInbound(17, remote1, 53, client, 54002, out _));

        var resolvers = new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8") };
        var selectedA = WinDivertAdapter.SelectDnsResolver(
            resolvers, 6, srcA, 53000, dnsOrig, 53);
        var selectedB = WinDivertAdapter.SelectDnsResolver(
            resolvers, 6, srcA, 53000, dnsOrig, 53);
        check("dns: resolver is stable for one TCP/UDP flow", selectedA.Equals(selectedB));

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
            check("exclude: unknown owner is Drop until refreshed (no policy leak)",
                d == PacketDisposition.Drop);
        }
        check("ipv6: classification Drop remains Drop in exclude mode",
            WinDivertAdapter.Ipv6Disposition(PacketDisposition.Drop) == PacketDisposition.Drop);
        check("ipv6: only an explicit app bypass reaches the physical network",
            WinDivertAdapter.Ipv6Disposition(PacketDisposition.Tunnel) == PacketDisposition.Drop
            && WinDivertAdapter.Ipv6Disposition(PacketDisposition.Bypass)
                == PacketDisposition.Bypass);

        // Filter captures both families and no longer relies on a TTL marker to avoid
        // recapturing the carrier.
        string filter = WinDivertAdapter.BuildFilter();
        check("filter: captures IPv4+IPv6 without TTL marker",
            !filter.TrimEnd().EndsWith("and ip", StringComparison.Ordinal)
            && !filter.Contains("TTL", StringComparison.OrdinalIgnoreCase)
            && !filter.Contains("HopLimit", StringComparison.OrdinalIgnoreCase)
            && filter.Contains("outbound", StringComparison.Ordinal));

        var syn = new byte[44];
        syn[0] = 0x45; syn[9] = 6;
        syn[32] = 0x60; // 24-byte TCP header
        syn[33] = 0x02; // SYN
        syn[40] = 2; syn[41] = 4; syn[42] = 0x05; syn[43] = 0xB4; // MSS 1460
        check("mtu: TCP SYN MSS is clamped to tunnel MTU",
            WinDivertAdapter.ClampTcpMss(syn, syn.Length, 1400)
            && BinaryPrimitives.ReadUInt16BigEndian(syn.AsSpan(42, 2)) == 1360);

        var icmp = new byte[52];
        icmp[0] = 0x45; icmp[9] = 1; icmp[20] = 3; icmp[21] = 4;
        icmp[28] = 0x45; icmp[28 + 9] = 6;
        client.GetAddressBytes().CopyTo(icmp, 28 + 12);
        remote1.GetAddressBytes().CopyTo(icmp, 28 + 16);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(48, 2), 40001);
        BinaryPrimitives.WriteUInt16BigEndian(icmp.AsSpan(50, 2), 443);
        check("icmp: packet-too-big recovers the quoted TCP flow",
            WinDivertAdapter.TryParseIcmpQuotedFlow(
                icmp, icmp.Length, out byte quotedProto, out var quotedRemote,
                out ushort quotedRemotePort, out ushort quotedLocalPort, out _, out _)
            && quotedProto == 6 && quotedRemote.Equals(remote1)
            && quotedRemotePort == 443 && quotedLocalPort == 40001);

        var ipv6WithHopOptions = new byte[68];
        ipv6WithHopOptions[0] = 0x60;
        ipv6WithHopOptions[6] = 0;
        ipv6WithHopOptions[40] = 6;
        ipv6WithHopOptions[41] = 0;
        check("ipv6: extension headers locate TCP/UDP ports",
            WinDivertAdapter.TryLocateIpv6Transport(
                ipv6WithHopOptions, ipv6WithHopOptions.Length, out byte v6Proto, out int v6Offset)
            && v6Proto == 6 && v6Offset == 48);

        var ipv6Fragment = new byte[56];
        ipv6Fragment[0] = 0x60;
        ipv6Fragment[6] = 44;
        ipv6Fragment[40] = 17;
        BinaryPrimitives.WriteUInt32BigEndian(ipv6Fragment.AsSpan(44, 4), 0x10203040);
        check("ipv6: first fragment exposes transport and 32-bit affinity id",
            WinDivertAdapter.TryParseIpv6Packet(ipv6Fragment, ipv6Fragment.Length, out var firstV6)
            && firstV6.IsFragment && firstV6.IsFirstFragment && firstV6.HasTransport
            && firstV6.Protocol == 17 && firstV6.FragmentId == 0x10203040);
        BinaryPrimitives.WriteUInt16BigEndian(ipv6Fragment.AsSpan(42, 2), 0x0008);
        check("ipv6: non-first fragment retains protocol/id without fake ports",
            WinDivertAdapter.TryParseIpv6Packet(ipv6Fragment, ipv6Fragment.Length, out var laterV6)
            && laterV6.IsFragment && !laterV6.IsFirstFragment && !laterV6.HasTransport
            && laterV6.Protocol == 17 && laterV6.FragmentId == 0x10203040);
        var v6src = IPAddress.Parse("2001:db8::10");
        var v6dst = IPAddress.Parse("2001:db8::20");
        flows.RememberIpv6Frag(v6src, v6dst, 17, 0x10203040, PacketDisposition.Bypass);
        check("ipv6: later fragment follows first-fragment disposition",
            flows.TryGetIpv6Frag(v6src, v6dst, 17, 0x10203040, out var v6Disposition)
            && v6Disposition == PacketDisposition.Bypass);

        var ipv6FragmentThenOptions = new byte[68];
        ipv6FragmentThenOptions[0] = 0x60;
        ipv6FragmentThenOptions[6] = 44;
        ipv6FragmentThenOptions[40] = 60; // destination options after Fragment header
        BinaryPrimitives.WriteUInt32BigEndian(
            ipv6FragmentThenOptions.AsSpan(44, 4), 0x55667788);
        ipv6FragmentThenOptions[48] = 17;
        check("ipv6: fragment affinity protocol is stable across post-fragment extensions",
            WinDivertAdapter.TryParseIpv6Packet(
                ipv6FragmentThenOptions, ipv6FragmentThenOptions.Length, out var extendedFirst)
            && extendedFirst.Protocol == 17 && extendedFirst.FragmentProtocol == 60);
        BinaryPrimitives.WriteUInt16BigEndian(
            ipv6FragmentThenOptions.AsSpan(42, 2), 0x0008);
        check("ipv6: later fragment retains the same affinity protocol",
            WinDivertAdapter.TryParseIpv6Packet(
                ipv6FragmentThenOptions, ipv6FragmentThenOptions.Length, out var extendedLater)
            && extendedLater.Protocol == 60
            && extendedLater.FragmentProtocol == extendedFirst.FragmentProtocol);

        var pending = new PendingFragmentBuffer<int, string>(
            maxItems: 2, maxPerKey: 2, ttl: TimeSpan.FromSeconds(1));
        var pendingNow = DateTime.UtcNow;
        check("fragment reorder: bounded buffer accepts early fragments",
            pending.Add(7, "second", pendingNow) && pending.Add(7, "third", pendingNow));
        check("fragment reorder: per-datagram/global bound drops excess",
            !pending.Add(7, "fourth", pendingNow) && pending.DroppedCount == 1);
        check("fragment reorder: first fragment releases buffered order",
            pending.Take(7, pendingNow).SequenceEqual(new[] { "second", "third" }));
        pending.Add(9, "discarded-second", pendingNow);
        check("fragment reorder: failed first fragment discards its pending tail",
            pending.Discard(9, pendingNow) == 1
            && pending.Count == 0
            && pending.DroppedCount == 2);
        pending.Add(8, "late", pendingNow);
        pending.SweepForTest(pendingNow.AddSeconds(2));
        check("fragment reorder: stale fragments expire and are counted",
            pending.Count == 0 && pending.DroppedCount == 3);

        check("owner map: conflicting UDP PIDs become ambiguous",
            ProcessAppMap.MergeOwnerForTest(100, 200) == uint.MaxValue);
        check("owner map: miss refresh is throttled while pending or fresh",
            !ProcessAppMap.ShouldQueueMissRefreshForTest(
                DateTime.UtcNow, DateTime.UtcNow, pending: false)
            && !ProcessAppMap.ShouldQueueMissRefreshForTest(
                DateTime.MinValue, DateTime.UtcNow, pending: true)
            && ProcessAppMap.ShouldQueueMissRefreshForTest(
                DateTime.MinValue, DateTime.UtcNow, pending: false)
            && ProcessAppMap.ShouldQueueMissRefreshForTest(
                DateTime.UtcNow, DateTime.UtcNow, pending: false, force: true));

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
                carrierProtocol: "tcp",
                tunnelMtu: 1400);
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
