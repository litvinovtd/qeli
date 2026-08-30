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
        var defaultPol = new WinDivertDestinationPolicy(false, null, null, null,
            physicalLocalRoutes: new[] { "192.168.1.0/24" });
        check("dest: public IP not bypassed",
            !defaultPol.ShouldBypassTunnel(IPAddress.Parse("1.1.1.1")));
        check("dest: connected RFC1918 bypassed when route_local off",
            defaultPol.ShouldBypassTunnel(IPAddress.Parse("192.168.1.1")));
        check("dest: remote RFC1918 follows full-tunnel policy",
            !defaultPol.ShouldBypassTunnel(IPAddress.Parse("192.168.50.1")));
        check("dest: link-local always bypassed",
            defaultPol.ShouldBypassTunnel(IPAddress.Parse("169.254.10.1")));

        var localPol = new WinDivertDestinationPolicy(true, null, null, null);
        check("dest: RFC1918 tunnelled when route_local on",
            !localPol.ShouldBypassTunnel(IPAddress.Parse("10.0.0.5")));

        var includePol = new WinDivertDestinationPolicy(false,
            includeRoutes: new[] { "192.168.50.0/24" }, null, null,
            physicalLocalRoutes: new[] { "192.168.1.0/24" });
        check("dest: user include private CIDR tunnelled",
            !includePol.ShouldBypassTunnel(IPAddress.Parse("192.168.50.10")));
        check("dest: connected RFC1918 still bypassed without route_local",
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

        var splitPol = new WinDivertDestinationPolicy(false,
            includeRoutes: new[] { "198.51.100.0/24", "2001:db8:20::/48" },
            excludeRoutes: null, pushedRoutes: null,
            fullTunnel: false, tunnelSubnets: new[] { "10.8.0.2/24" });
        check("dest: split public IPv4 bypassed",
            splitPol.ShouldBypassTunnel(IPAddress.Parse("1.1.1.1")));
        check("dest: split public include tunnelled",
            !splitPol.ShouldBypassTunnel(IPAddress.Parse("198.51.100.7")));
        check("dest: split connected tunnel subnet tunnelled",
            !splitPol.ShouldBypassTunnel(IPAddress.Parse("10.8.0.1")));
        check("dest: split native IPv6 bypassed",
            splitPol.ShouldBypassTunnel(IPAddress.Parse("2001:4860:4860::8888")));
        check("dest: split IPv6 include remains captured fail-closed",
            !splitPol.ShouldBypassTunnel(IPAddress.Parse("2001:db8:20::7")));
        check("dest: explicit include is marked as required tunnel intent",
            splitPol.RequiresTunnel(IPAddress.Parse("198.51.100.7"))
            && splitPol.RequiresTunnel(IPAddress.Parse("2001:db8:20::7")));
        var excludedRequiredPol = new WinDivertDestinationPolicy(false,
            includeRoutes: new[] { "198.51.100.0/24" },
            excludeRoutes: new[] { "198.51.100.0/25" }, pushedRoutes: null);
        check("dest: explicit exclude wins over required tunnel intent",
            !excludedRequiredPol.RequiresTunnel(IPAddress.Parse("198.51.100.7")));

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

        var ownershipPruned = new WinDivertFlowTable(
            tcpFlowExists: (_, _, _, _) => false,
            tcpOwnershipGrace: TimeSpan.FromSeconds(10));
        ownershipPruned.RememberOutbound(6, client, srcA, 54003, remote1, 443, in addrA);
        ownershipPruned.CollectExpiredForTest(DateTime.UtcNow.AddSeconds(11));
        check("flow: missed FIN/RST is pruned when Windows no longer owns the socket",
            ownershipPruned.FlowCount == 0);

        var ownershipRetained = new WinDivertFlowTable(
            tcpFlowExists: (_, _, _, _) => true,
            tcpOwnershipGrace: TimeSpan.FromSeconds(10));
        ownershipRetained.RememberOutbound(6, client, srcA, 54004, remote1, 443, in addrA);
        ownershipRetained.CollectExpiredForTest(DateTime.UtcNow.AddDays(7));
        check("flow: live OS-owned TCP survives arbitrary idle time",
            ownershipRetained.FlowCount == 1);
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

        // Unknown ownership is returned immediately so capture never blocks on the endpoint scan.
        // WinDivertAdapter holds it in a bounded queue; one unresolved retry is dropped.
        // Exercise the non-blocking ProcessAppMap half of that contract here.
        using (var includeMap = new ProcessAppMap(Array.Empty<string>(), includeMode: true))
        {
            var d = includeMap.Classify(6, IPAddress.Parse("127.0.0.1"), 1,
                IPAddress.Parse("1.1.1.1"), 443);
            check("include: unknown owner is deferred without blocking capture",
                d == PacketDisposition.Unknown);
            check("include: non-TCP/UDP is Drop",
                includeMap.Classify(1, IPAddress.Parse("127.0.0.1"), 0,
                    IPAddress.Parse("1.1.1.1"), 0) == PacketDisposition.Drop);
        }
        using (var excludeMap = new ProcessAppMap(Array.Empty<string>(), includeMode: false))
        {
            var d = excludeMap.Classify(6, IPAddress.Parse("127.0.0.1"), 1,
                IPAddress.Parse("1.1.1.1"), 443);
            check("exclude: unknown owner is deferred without a policy leak",
                d == PacketDisposition.Unknown);
        }
        check("family policy: active IPv6 tunnels selected traffic",
            WinDivertAdapter.DispositionForFamily(
                PacketDisposition.Tunnel, familyAvailable: true, allowLeak: false)
                == PacketDisposition.Tunnel);
        check("family policy: unavailable family is fail-closed by default",
            WinDivertAdapter.DispositionForFamily(
                PacketDisposition.Tunnel, familyAvailable: false, allowLeak: false)
                == PacketDisposition.Drop);
        check("family policy: explicit leak opt-out bypasses an unavailable default family",
            WinDivertAdapter.DispositionForFamily(
                PacketDisposition.Tunnel, familyAvailable: false, allowLeak: true)
                == PacketDisposition.Bypass);
        check("family policy: explicit tunnel route stays fail-closed despite leak opt-out",
            WinDivertAdapter.DispositionForFamily(
                PacketDisposition.Tunnel, familyAvailable: false, allowLeak: true,
                tunnelRequired: true) == PacketDisposition.Drop);
        check("family policy: explicit app bypass is never captured",
            WinDivertAdapter.DispositionForFamily(
                PacketDisposition.Bypass, familyAvailable: true, allowLeak: false)
                == PacketDisposition.Bypass);
        check("dns family: configured other-family resolver fails closed",
            WinDivertAdapter.TunnelDnsFamilyMismatch(
                isDns: true, configuredDnsCount: 1, hasCompatibleDns: false));
        check("dns family: compatible or unconfigured resolver is not mismatch",
            !WinDivertAdapter.TunnelDnsFamilyMismatch(
                isDns: true, configuredDnsCount: 1, hasCompatibleDns: true)
            && !WinDivertAdapter.TunnelDnsFamilyMismatch(
                isDns: true, configuredDnsCount: 0, hasCompatibleDns: false)
            && !WinDivertAdapter.TunnelDnsFamilyMismatch(
                isDns: false, configuredDnsCount: 1, hasCompatibleDns: false));
        check("dns46 mtu: IPv6 header growth reduces the advertised IPv4 path MTU",
            WinDivertAdapter.EffectiveIpv4PathMtu(
                tunnelMtu: 1280, ipv4HeaderLength: 20, translateToIpv6: true) == 1260
            && WinDivertAdapter.EffectiveIpv4PathMtu(
                tunnelMtu: 1280, ipv4HeaderLength: 20, translateToIpv6: false) == 1280
            && WinDivertAdapter.EffectiveIpv4PathMtu(
                tunnelMtu: 1280, ipv4HeaderLength: 60, translateToIpv6: true) == 1280);

        // Filter captures both families and no longer relies on a TTL marker to avoid
        // recapturing the carrier.
        string filter = WinDivertAdapter.BuildFilter();
        check("filter: captures IPv4+IPv6 without TTL marker",
            !filter.TrimEnd().EndsWith("and ip", StringComparison.Ordinal)
            && !filter.Contains("TTL", StringComparison.OrdinalIgnoreCase)
            && !filter.Contains("HopLimit", StringComparison.OrdinalIgnoreCase)
            && filter.Contains("outbound", StringComparison.Ordinal));

        string killSwitchFilter = WinDivertKillSwitchGate.BuildFilter(
            42,
            new[] { "203.0.113.7", "2001:db8::7" },
            new[] { "192.0.2.53" });
        check("kill-switch priority: valid and ordered before the normal capture handle",
            WinDivertKillSwitchGate.DropGatePriority is >= -300 and <= 300
            && WinDivertKillSwitchGate.DropGatePriority > 0);
        check("kill-switch filter: excludes Wintun and allows only named endpoints",
            killSwitchFilter.Contains("ifIdx != 42", StringComparison.Ordinal)
            && killSwitchFilter.Contains("ip.DstAddr == 203.0.113.7", StringComparison.Ordinal)
            && killSwitchFilter.Contains("ipv6.DstAddr == 2001:db8::7", StringComparison.Ordinal)
            && killSwitchFilter.Contains("ip.DstAddr == 192.0.2.53", StringComparison.Ordinal)
            && killSwitchFilter.Contains("udp.DstPort == 67", StringComparison.Ordinal));

        string restoreScript = KillSwitch.BuildRestoreScriptForTest(
            new Dictionary<string, string>
            {
                ["Domain"] = "Block",
                ["Private"] = "Allow",
            });
        int removeRulesAt = restoreScript.IndexOf("Remove-NetFirewallRule", StringComparison.Ordinal);
        check("kill-switch restore: restores every profile before removing allow rules",
            restoreScript.Contains("-Name Domain -DefaultOutboundAction Block", StringComparison.Ordinal)
            && restoreScript.Contains("-Name Private -DefaultOutboundAction Allow", StringComparison.Ordinal)
            && restoreScript.Contains("-Name Public -DefaultOutboundAction NotConfigured", StringComparison.Ordinal)
            && removeRulesAt > restoreScript.LastIndexOf("Set-NetFirewallProfile", StringComparison.Ordinal));

        var syn = new byte[44];
        syn[0] = 0x45; syn[9] = 6;
        syn[32] = 0x60; // 24-byte TCP header
        syn[33] = 0x02; // SYN
        BinaryPrimitives.WriteUInt16BigEndian(syn.AsSpan(36, 2), 0x1234);
        syn[40] = 2; syn[41] = 4; syn[42] = 0x05; syn[43] = 0xB4; // MSS 1460
        check("mtu: TCP SYN MSS is clamped to tunnel MTU",
            WinDivertAdapter.ClampTcpMss(syn, syn.Length, 1400)
            && BinaryPrimitives.ReadUInt16BigEndian(syn.AsSpan(42, 2)) == 1360
            && BinaryPrimitives.ReadUInt16BigEndian(syn.AsSpan(36, 2)) == 0x1298);

        var oddMssSyn = new byte[48];
        oddMssSyn[0] = 0x45; oddMssSyn[9] = 6;
        oddMssSyn[32] = 0x70; oddMssSyn[33] = 0x02; // 28-byte TCP SYN header
        BinaryPrimitives.WriteUInt16BigEndian(oddMssSyn.AsSpan(36, 2), 0x1234);
        oddMssSyn[40] = 1; // NOP: the MSS value now straddles checksum words
        oddMssSyn[41] = 2; oddMssSyn[42] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(oddMssSyn.AsSpan(43, 2), 1460);
        oddMssSyn[45] = 1;
        check("mtu: unaligned MSS clamp adjusts both TCP checksum words",
            WinDivertAdapter.ClampTcpMss(oddMssSyn, oddMssSyn.Length, 1400)
            && BinaryPrimitives.ReadUInt16BigEndian(oddMssSyn.AsSpan(43, 2)) == 1360
            && BinaryPrimitives.ReadUInt16BigEndian(oddMssSyn.AsSpan(36, 2)) == 0x7634);

        // Options whose copy bit is clear belong only to the first IPv4 fragment. Also refuse
        // an already-fragmented packet whose final byte cannot fit the 13-bit offset field.
        var optionPacket = new byte[24 + 64];
        optionPacket[0] = 0x46; // IPv4, IHL=24
        BinaryPrimitives.WriteUInt16BigEndian(
            optionPacket.AsSpan(2, 2), (ushort)optionPacket.Length);
        optionPacket[20] = 7;   // Record Route: copy bit clear
        optionPacket[21] = 4;
        for (int i = 24; i < optionPacket.Length; i++) optionPacket[i] = (byte)i;
        var optionFragments = WinDivertAdapter.FragmentIpv4ForSelfTest(
            optionPacket, optionPacket.Length, 48);
        check("mtu: non-copy IPv4 option remains only on first fragment",
            optionFragments.Length >= 2
            && (optionFragments[0][0] & 0x0F) == 6
            && (optionFragments[1][0] & 0x0F) == 5);

        BinaryPrimitives.WriteUInt16BigEndian(optionPacket.AsSpan(6, 2), 0x1FFE);
        check("mtu: IPv4 fragment offset overflow is rejected",
            WinDivertAdapter.FragmentIpv4ForSelfTest(
                optionPacket, optionPacket.Length, 48).Length == 0);

        // A NAT rewrite on an already-fragmented datagram must adjust the checksum that
        // covers the complete original UDP payload. Recalculating against the first
        // fragment alone produces a checksum that is invalid after reassembly.
        var oldNatSrc = IPAddress.Parse("192.168.10.25");
        var newNatSrc = IPAddress.Parse("10.8.0.2");
        var oldNatDst = IPAddress.Parse("9.9.9.9");
        var newNatDst = IPAddress.Parse("1.1.1.1");
        var fullUdp = BuildIpv4UdpDatagram(oldNatSrc, oldNatDst, 51000, 53, 48);
        var expectedUdp = (byte[])fullUdp.Clone();
        newNatSrc.GetAddressBytes().CopyTo(expectedUdp, 12);
        newNatDst.GetAddressBytes().CopyTo(expectedUdp, 16);
        BinaryPrimitives.WriteUInt16BigEndian(expectedUdp.AsSpan(20, 2), 52000);
        BinaryPrimitives.WriteUInt16BigEndian(expectedUdp.AsSpan(22, 2), 5353);
        BinaryPrimitives.WriteUInt16BigEndian(expectedUdp.AsSpan(26, 2), 0);
        ushort expectedUdpChecksum = CalculateIpv4TransportChecksum(expectedUdp, 17);

        var firstUdpFragment = fullUdp.AsSpan(0, 36).ToArray();
        newNatSrc.GetAddressBytes().CopyTo(firstUdpFragment, 12);
        newNatDst.GetAddressBytes().CopyTo(firstUdpFragment, 16);
        BinaryPrimitives.WriteUInt16BigEndian(firstUdpFragment.AsSpan(20, 2), 52000);
        BinaryPrimitives.WriteUInt16BigEndian(firstUdpFragment.AsSpan(22, 2), 5353);
        bool udpAdjusted = WinDivertAdapter.AdjustFragmentTransportChecksumForSelfTest(
            firstUdpFragment, firstUdpFragment.Length, 17,
            oldNatSrc, newNatSrc, oldNatDst, newNatDst,
            51000, 52000, 53, 5353);
        check("fragment NAT: UDP checksum is adjusted for the complete datagram",
            udpAdjusted
            && BinaryPrimitives.ReadUInt16BigEndian(firstUdpFragment.AsSpan(26, 2))
                == expectedUdpChecksum);

        BinaryPrimitives.WriteUInt16BigEndian(firstUdpFragment.AsSpan(26, 2), 0);
        check("fragment NAT: disabled IPv4 UDP checksum remains disabled",
            WinDivertAdapter.AdjustFragmentTransportChecksumForSelfTest(
                firstUdpFragment, firstUdpFragment.Length, 17,
                oldNatSrc, newNatSrc, oldNatDst, newNatDst,
                51000, 52000, 53, 5353)
            && BinaryPrimitives.ReadUInt16BigEndian(firstUdpFragment.AsSpan(26, 2)) == 0);

        var fullTcp = BuildIpv4TcpSegment(oldNatSrc, oldNatDst, 51001, 443, 48);
        var expectedTcp = (byte[])fullTcp.Clone();
        newNatSrc.GetAddressBytes().CopyTo(expectedTcp, 12);
        newNatDst.GetAddressBytes().CopyTo(expectedTcp, 16);
        BinaryPrimitives.WriteUInt16BigEndian(expectedTcp.AsSpan(20, 2), 52001);
        BinaryPrimitives.WriteUInt16BigEndian(expectedTcp.AsSpan(22, 2), 8443);
        BinaryPrimitives.WriteUInt16BigEndian(expectedTcp.AsSpan(36, 2), 0);
        ushort expectedTcpChecksum = CalculateIpv4TransportChecksum(expectedTcp, 6);
        var firstTcpFragment = fullTcp.AsSpan(0, 44).ToArray();
        newNatSrc.GetAddressBytes().CopyTo(firstTcpFragment, 12);
        newNatDst.GetAddressBytes().CopyTo(firstTcpFragment, 16);
        BinaryPrimitives.WriteUInt16BigEndian(firstTcpFragment.AsSpan(20, 2), 52001);
        BinaryPrimitives.WriteUInt16BigEndian(firstTcpFragment.AsSpan(22, 2), 8443);
        check("fragment NAT: TCP checksum is adjusted for the complete segment",
            WinDivertAdapter.AdjustFragmentTransportChecksumForSelfTest(
                firstTcpFragment, firstTcpFragment.Length, 6,
                oldNatSrc, newNatSrc, oldNatDst, newNatDst,
                51001, 52001, 443, 8443)
            && BinaryPrimitives.ReadUInt16BigEndian(firstTcpFragment.AsSpan(36, 2))
                == expectedTcpChecksum);

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
        BinaryPrimitives.WriteUInt16BigEndian(ipv6WithHopOptions.AsSpan(4, 2), 28);
        ipv6WithHopOptions[6] = 0;
        ipv6WithHopOptions[40] = 6;
        ipv6WithHopOptions[41] = 0;
        check("ipv6: extension headers locate TCP/UDP ports",
            WinDivertAdapter.TryLocateIpv6Transport(
                ipv6WithHopOptions, ipv6WithHopOptions.Length, out byte v6Proto, out int v6Offset)
            && v6Proto == 6 && v6Offset == 48);

        var emptyIpv6 = new byte[40];
        emptyIpv6[0] = 0x60;
        emptyIpv6[6] = 59; // No Next Header
        check("ipv6: zero-payload base packet is valid, not a jumbogram",
            WinDivertAdapter.TryParseIpv6Packet(
                emptyIpv6, emptyIpv6.Length, out var emptyIpv6Meta)
            && emptyIpv6Meta.Protocol == 59
            && emptyIpv6Meta.TransportOffset == 40
            && !emptyIpv6Meta.HasTransport
            && !emptyIpv6Meta.IsFragment);

        var ipv6Syn = new byte[64];
        ipv6Syn[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ipv6Syn.AsSpan(4, 2), 24);
        ipv6Syn[6] = 6;
        ipv6Syn[52] = 0x60; // 24-byte TCP header
        ipv6Syn[53] = 0x02; // SYN
        BinaryPrimitives.WriteUInt16BigEndian(ipv6Syn.AsSpan(56, 2), 0x1234);
        ipv6Syn[60] = 2; ipv6Syn[61] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(ipv6Syn.AsSpan(62, 2), 1460);
        check("ipv6: TCP SYN MSS accounts for the 40-byte IPv6 header",
            WinDivertAdapter.TryParseIpv6Packet(
                ipv6Syn, ipv6Syn.Length, out var ipv6SynMeta)
            && WinDivertAdapter.ClampIpv6TcpMss(
                ipv6Syn, ipv6Syn.Length, ipv6SynMeta, 1400)
            && BinaryPrimitives.ReadUInt16BigEndian(ipv6Syn.AsSpan(62, 2)) == 1340
            && BinaryPrimitives.ReadUInt16BigEndian(ipv6Syn.AsSpan(56, 2)) == 0x12AC);

        var icmpv6 = new byte[92];
        icmpv6[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(icmpv6.AsSpan(4, 2), 52);
        icmpv6[6] = 58;
        icmpv6[40] = 2; // Packet Too Big
        icmpv6[48] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(icmpv6.AsSpan(52, 2), 4);
        icmpv6[54] = 6;
        var clientV6 = IPAddress.Parse("fd71::2");
        var remoteV6 = IPAddress.Parse("2001:db8::20");
        clientV6.GetAddressBytes().CopyTo(icmpv6, 56);
        remoteV6.GetAddressBytes().CopyTo(icmpv6, 72);
        BinaryPrimitives.WriteUInt16BigEndian(icmpv6.AsSpan(88, 2), 40001);
        BinaryPrimitives.WriteUInt16BigEndian(icmpv6.AsSpan(90, 2), 443);
        check("icmpv6: Packet Too Big recovers the quoted TCP flow",
            WinDivertAdapter.TryParseIcmpv6QuotedFlow(
                icmpv6, icmpv6.Length, out byte quotedV6Proto, out var quotedV6Remote,
                out ushort quotedV6RemotePort, out ushort quotedV6LocalPort,
                out _, out _)
            && quotedV6Proto == 6 && quotedV6Remote.Equals(remoteV6)
            && quotedV6RemotePort == 443 && quotedV6LocalPort == 40001);

        var ipv6Fragment = new byte[56];
        ipv6Fragment[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ipv6Fragment.AsSpan(4, 2), 16);
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

        var malformedV6Fragment = (byte[])ipv6Fragment.Clone();
        malformedV6Fragment[41] = 1;
        check("ipv6: Fragment reserved byte is rejected",
            !WinDivertAdapter.TryParseIpv6Packet(
                malformedV6Fragment, malformedV6Fragment.Length, out _));
        malformedV6Fragment = (byte[])ipv6Fragment.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(malformedV6Fragment.AsSpan(42, 2), 0x0002);
        check("ipv6: Fragment reserved bits are rejected",
            !WinDivertAdapter.TryParseIpv6Packet(
                malformedV6Fragment, malformedV6Fragment.Length, out _));

        var misalignedV6Fragment = new byte[57];
        ipv6Fragment.CopyTo(misalignedV6Fragment, 0);
        BinaryPrimitives.WriteUInt16BigEndian(misalignedV6Fragment.AsSpan(4, 2), 17);
        BinaryPrimitives.WriteUInt16BigEndian(misalignedV6Fragment.AsSpan(42, 2), 0x0001);
        check("ipv6: non-final Fragment payload must be 8-byte aligned",
            !WinDivertAdapter.TryParseIpv6Packet(
                misalignedV6Fragment, misalignedV6Fragment.Length, out _));

        var duplicateV6Fragment = new byte[64];
        duplicateV6Fragment[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(duplicateV6Fragment.AsSpan(4, 2), 24);
        duplicateV6Fragment[6] = 44;
        duplicateV6Fragment[40] = 44;
        duplicateV6Fragment[48] = 17;
        check("ipv6: duplicate Fragment Header is rejected",
            !WinDivertAdapter.TryParseIpv6Packet(
                duplicateV6Fragment, duplicateV6Fragment.Length, out _));

        var overflowingV6Fragment = new byte[64];
        overflowingV6Fragment[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(overflowingV6Fragment.AsSpan(4, 2), 24);
        overflowingV6Fragment[6] = 60;
        overflowingV6Fragment[40] = 44;
        overflowingV6Fragment[48] = 17;
        BinaryPrimitives.WriteUInt16BigEndian(overflowingV6Fragment.AsSpan(50, 2), 0xFFF0);
        check("ipv6: reassembled payload includes pre-Fragment extension bytes",
            !WinDivertAdapter.TryParseIpv6Packet(
                overflowingV6Fragment, overflowingV6Fragment.Length, out _));
        var v6src = IPAddress.Parse("2001:db8::10");
        var v6dst = IPAddress.Parse("2001:db8::20");
        flows.RememberIpv6Frag(v6src, v6dst, 17, 0x10203040, PacketDisposition.Bypass);
        check("ipv6: later fragment follows first-fragment disposition",
            flows.TryGetIpv6Frag(v6src, v6dst, 17, 0x10203040, out var v6Disposition)
            && v6Disposition == PacketDisposition.Bypass);
        flows.SetIpv6FragTunnelDestination(
            v6src, v6dst, 17, 0x10203040, IPAddress.Parse("2001:db8::53"));
        check("ipv6: DNS fragment affinity retains the rewritten destination",
            flows.TryGetIpv6FragEntry(
                v6src, v6dst, 17, 0x10203040, out var v6FragmentEntry)
            && IPAddress.Parse("2001:db8::53").Equals(v6FragmentEntry.TunnelDestination));
        var inboundV6Flow = new WinDivertFlowTable.FlowEntry
        {
            OriginalSrc = IPAddress.Parse("2001:db8:1::10"),
            OriginalLocalPort = 53000,
        };
        flows.RememberInboundIpv6Frag(
            v6dst, v6src, 17, 0xAABBCCDD, in inboundV6Flow);
        check("ipv6: inbound non-first fragment restores first-fragment flow",
            flows.TryGetInboundIpv6Frag(
                v6dst, v6src, 17, 0xAABBCCDD, out var restoredV6Flow)
            && restoredV6Flow.OriginalSrc.Equals(inboundV6Flow.OriginalSrc)
            && restoredV6Flow.OriginalLocalPort == 53000);

        var natOldSource = IPAddress.Parse("2001:db8:1::10").GetAddressBytes();
        var natNewSource = IPAddress.Parse("fd71::2").GetAddressBytes();
        var natOldDestination = IPAddress.Parse("2001:db8:2::20").GetAddressBytes();
        var natNewDestination = IPAddress.Parse("2001:db8:2::53").GetAddressBytes();
        const ushort originalChecksum = 0x4A21;
        ushort translatedChecksum = WinDivertAdapter.AdjustIpv6NatChecksum(
            originalChecksum,
            natOldSource, natNewSource, natOldDestination, natNewDestination,
            53000, 54000, 53, 53, 17);
        ushort restoredChecksum = WinDivertAdapter.AdjustIpv6NatChecksum(
            translatedChecksum,
            natNewSource, natOldSource, natNewDestination, natOldDestination,
            54000, 53000, 53, 53, 17);
        check("ipv6: fragmented NAT checksum adjustment is reversible",
            translatedChecksum != originalChecksum && restoredChecksum == originalChecksum);

        var ipv6FragmentThenOptions = new byte[68];
        ipv6FragmentThenOptions[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(ipv6FragmentThenOptions.AsSpan(4, 2), 28);
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
        var defaultDestinations = new WinDivertDestinationPolicy(
            routeLocal: false, includeRoutes: null, excludeRoutes: null, pushedRoutes: null,
            physicalLocalRoutes: new[] { "192.168.1.0/24" });
        check("ipv6 policy: ULA and multicast follow full-tunnel policy",
            !defaultDestinations.ShouldBypassTunnel(IPAddress.Parse("fd00::1"))
            && !defaultDestinations.ShouldBypassTunnel(IPAddress.Parse("ff02::1")));
        var includedV6Destinations = new WinDivertDestinationPolicy(
            routeLocal: false,
            includeRoutes: new[] { "fd12:3456::/48" },
            excludeRoutes: null,
            pushedRoutes: new[] { "ff05::/16" });
        check("ipv6 policy: explicit and pushed local routes enter the tunnel",
            !includedV6Destinations.ShouldBypassTunnel(IPAddress.Parse("fd12:3456::1"))
            && !includedV6Destinations.ShouldBypassTunnel(IPAddress.Parse("ff05::1234")));

        using (var retained = new WinDivertAdapter(
            IPAddress.Parse("10.8.0.2"), null,
            new[] { Environment.ProcessPath ?? @"C:\Windows\System32\cmd.exe" },
            includeMode: true,
            dnsServers: Array.Empty<string>(),
            allowIpv4Leak: false,
            allowIpv6Leak: false,
            fullTunnel: true,
            tunnelSubnets: new[] { "10.8.0.0/24" },
            routeLocal: false,
            includeRoutes: null,
            excludeRoutes: null,
            pushedRoutes: null,
            carrierIp: IPAddress.Parse("203.0.113.10"),
            carrierPort: 443,
            carrierProtocol: "tcp",
            tunnelMtu: 1400))
        {
            retained.Reconfigure(
                IPAddress.Parse("10.8.0.3"), IPAddress.Parse("fd71:e1::3"),
                new[] { Environment.ProcessPath ?? @"C:\Windows\System32\cmd.exe" },
                includeMode: false,
                Array.Empty<string>(),
                allowIpv4Leak: true,
                allowIpv6Leak: true,
                fullTunnel: true,
                tunnelSubnets: new[] { "10.8.0.0/24", "fd71:e1::/64" },
                routeLocal: false,
                includeRoutes: null,
                excludeRoutes: null,
                pushedRoutes: null,
                carrierIp: IPAddress.Parse("203.0.113.11"),
                carrierPort: 443,
                carrierProtocol: "tcp",
                tunnelMtu: 1380);
            check("persisted per-app plan refreshes negotiated IPv4/IPv6 leak policy",
                retained.LeakPolicyForSelfTest() == (true, true));
            check("persisted per-app plan refreshes app selection mode",
                retained.AppPolicyForSelfTest() == (1, false));

            retained.SetTunnelUp(true);
            var beforeCarrierSwap = retained.CarrierStateForSelfTest();
            retained.SetCarrierAddresses(new[]
            {
                IPAddress.Parse("203.0.113.11"),
                IPAddress.Parse("203.0.113.12"),
                IPAddress.Parse("2001:db8::12"),
            }, 443, "tcp");
            var preparedCarriers = retained.CarrierStateForSelfTest();
            retained.SetCarrierAddresses(
                new[] { IPAddress.Parse("203.0.113.12") }, 443, "tcp");
            var committedCarrier = retained.CarrierStateForSelfTest();
            check("roaming per-app PREPARE exposes the old/new carrier union",
                preparedCarriers.addresses == "2001:db8::12,203.0.113.11,203.0.113.12");
            check("roaming per-app COMMIT narrows the carrier allow-set",
                committedCarrier.addresses == "203.0.113.12");
            check("roaming per-app carrier swaps preserve flows and tunnel-up generation",
                preparedCarriers.generation == beforeCarrierSwap.generation
                && committedCarrier.generation == beforeCarrierSwap.generation
                && preparedCarriers.tunnelUp && committedCarrier.tunnelUp);
        }

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

    private static byte[] BuildIpv4UdpDatagram(
        IPAddress source, IPAddress destination,
        ushort sourcePort, ushort destinationPort, int payloadLength)
    {
        var packet = new byte[20 + 8 + payloadLength];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 17;
        source.GetAddressBytes().CopyTo(packet, 12);
        destination.GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), destinationPort);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(24, 2), (ushort)(packet.Length - 20));
        for (int i = 28; i < packet.Length; i++) packet[i] = (byte)(i * 17 + 3);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(26, 2), CalculateIpv4TransportChecksum(packet, 17));
        return packet;
    }

    private static ushort CalculateIpv4TransportChecksum(byte[] packet, byte protocol)
    {
        int ihl = (packet[0] & 0x0F) * 4;
        int transportLength = packet.Length - ihl;
        uint sum = AddChecksumWords(packet.AsSpan(12, 8), 0);
        sum += protocol;
        sum += (uint)transportLength;
        sum = AddChecksumWords(packet.AsSpan(ihl, transportLength), sum);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        ushort checksum = (ushort)~sum;
        return checksum == 0 ? (ushort)0xFFFF : checksum;
    }

    private static byte[] BuildIpv4TcpSegment(
        IPAddress source, IPAddress destination,
        ushort sourcePort, ushort destinationPort, int payloadLength)
    {
        var packet = new byte[20 + 20 + payloadLength];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 6;
        source.GetAddressBytes().CopyTo(packet, 12);
        destination.GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20, 2), sourcePort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22, 2), destinationPort);
        packet[32] = 0x50; // 20-byte TCP header
        packet[33] = 0x18; // PSH + ACK
        for (int i = 40; i < packet.Length; i++) packet[i] = (byte)(i * 29 + 7);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(36, 2), CalculateIpv4TransportChecksum(packet, 6));
        return packet;
    }

    private static uint AddChecksumWords(ReadOnlySpan<byte> bytes, uint sum)
    {
        int i = 0;
        for (; i + 1 < bytes.Length; i += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(i, 2));
        if (i < bytes.Length) sum += (uint)bytes[i] << 8;
        return sum;
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

            string killSwitchFilter = WinDivertKillSwitchGate.BuildFilter(
                42, new[] { "203.0.113.7" }, new[] { "192.0.2.53" });
            bool killSwitchCompiled = WinDivertNative.WinDivertHelperCompileFilter(
                killSwitchFilter, WinDivertNative.WINDIVERT_LAYER_NETWORK, IntPtr.Zero, 0,
                out _, out _);
            C("elevated: strict kill-switch filter compiles",
                killSwitchCompiled || Marshal.GetLastWin32Error() == 0);

            var adapter = new WinDivertAdapter(
                IPAddress.Parse("10.8.0.2"),
                null,
                new[] { Environment.ProcessPath ?? @"C:\Windows\System32\cmd.exe" },
                includeMode: true,
                dnsServers: Array.Empty<string>(),
                allowIpv4Leak: false,
                allowIpv6Leak: false,
                fullTunnel: true,
                tunnelSubnets: new[] { "10.8.0.0/24" },
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
