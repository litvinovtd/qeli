using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Configures the Wintun adapter (IP/MTU/DNS/routes) and the system routing table.
/// This is the Windows analogue of the Android VpnService.Builder calls. All changes
/// are recorded as undo actions and reverted on Dispose so a disconnect leaves the
/// machine exactly as it was — no leaked default route, no broken DNS.
/// </summary>
public sealed class NetworkConfigurator : IDisposable
{
    private readonly Action<string> _log;
    private readonly List<Action> _undo = new();
    private readonly List<string> _degraded = new();
    private string? _dnsAlias;

    /// <summary>
    /// Network setup steps that FAILED but did not abort the connect. These used to be
    /// swallowed by `optional: true` while the log still printed the success line and the
    /// UI still went green — so a tunnel whose DNS never applied (queries leaking to the
    /// physical resolver) or whose pushed routes never landed looked perfectly healthy.
    /// The caller surfaces these so "Connected" can be qualified rather than assumed. (C-17)
    /// </summary>
    public IReadOnlyList<string> Degraded => _degraded;

    /// <summary>True when any network step silently failed — the tunnel is up but not
    /// configured as intended.</summary>
    public bool IsDegraded => _degraded.Count > 0;

    /// True when a DNS apply FAILED (not merely a route). Kept separate from the general
    /// degraded list because that distinction decides whether the tunnel is torn down
    /// under a kill-switch: DNS leaking to the physical resolver is exactly what the
    /// kill-switch exists to prevent, a missing secondary route is not. (Р2)
    public bool DnsFailed => _degraded.Exists(d => d.StartsWith("DNS ", StringComparison.Ordinal)
                                               || d.StartsWith("secondary DNS", StringComparison.Ordinal));


    private void Degrade(string what)
    {
        _degraded.Add(what);
        _log($"WARNING: {what}");
    }

    public NetworkConfigurator(Action<string> log) => _log = log;

    [DllImport("iphlpapi.dll")]
    private static extern int ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);

    // GetBestInterfaceEx takes a full SOCKADDR, so it resolves the outgoing interface for
    // BOTH IPv4 and IPv6 destinations — unlike the IPv4-only GetBestInterface(uint) it
    // replaces. This is the groundwork for reaching an IPv6 server (issue #69).
    [DllImport("iphlpapi.dll")]
    private static extern int GetBestInterfaceEx(byte[] pDestAddr, out uint bestIfIndex);

    /// <summary>Marshal an IPAddress into a Winsock SOCKADDR (sockaddr_in / sockaddr_in6)
    /// for the dual-stack iphlpapi calls.</summary>
    private static byte[] BuildSockaddr(IPAddress ip)
    {
        byte[] addr = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var sa = new byte[28];              // sockaddr_in6
            sa[0] = 23;                         // AF_INET6 (sin6_family, LE u16)
            Array.Copy(addr, 0, sa, 8, 16);     // sin6_addr (after family+port+flowinfo)
            BitConverter.GetBytes((uint)ip.ScopeId).CopyTo(sa, 24); // sin6_scope_id
            return sa;
        }
        var s4 = new byte[16];                  // sockaddr_in
        s4[0] = 2;                              // AF_INET
        Array.Copy(addr, 0, s4, 4, 4);          // sin_addr
        return s4;
    }

    /// <summary>Best outgoing interface index to reach <paramref name="ip"/> (0 on failure).
    /// Works for IPv4 and IPv6.</summary>
    private static uint BestInterfaceIndex(IPAddress ip) =>
        GetBestInterfaceEx(BuildSockaddr(ip), out uint ifIndex) == 0 ? ifIndex : 0;

    [DllImport("iphlpapi.dll")]
    private static extern void InitializeIpForwardEntry(IntPtr row);

    [DllImport("iphlpapi.dll")]
    private static extern int CreateIpForwardEntry2(IntPtr row);

    [DllImport("iphlpapi.dll")]
    private static extern int DeleteIpForwardEntry2(IntPtr row);

    /// <summary>Resolve the Wintun interface index and friendly alias from its LUID.</summary>
    public (uint index, string alias) ResolveInterface(ulong luid)
    {
        if (ConvertInterfaceLuidToIndex(ref luid, out uint index) != 0)
            throw new InvalidOperationException("ConvertInterfaceLuidToIndex failed");

        // The alias may take a moment to appear after the adapter is created.
        string? alias = null;
        for (int i = 0; i < 50 && alias == null; i++)
        {
            alias = FindAliasByIndex(index);
            if (alias == null) Thread.Sleep(100);
        }
        if (alias == null) throw new InvalidOperationException($"No network interface with index {index}");
        return (index, alias);
    }

    private static string? FindAliasByIndex(uint index)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties().GetIPv4Properties();
                if (p != null && (uint)p.Index == index) return ni.Name;
            }
            catch { /* interface without IPv4 props */ }
        }
        return null;
    }

    /// <summary>Find the physical default gateway used to reach <paramref name="serverIp"/>.
    /// Family-aware: returns the IPv4 gateway for an IPv4 server, the IPv6 gateway for an
    /// IPv6 server.</summary>
    public IPAddress? FindGatewayFor(IPAddress serverIp)
    {
        uint ifIndex = BestInterfaceIndex(serverIp);
        if (ifIndex == 0) return null;
        bool v6 = serverIp.AddressFamily == AddressFamily.InterNetworkV6;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties();
                uint idx = v6 ? (uint)p.GetIPv6Properties().Index : (uint)p.GetIPv4Properties().Index;
                if (idx != ifIndex) continue;
                var want = v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
                var any = v6 ? IPAddress.IPv6Any : IPAddress.Any;
                foreach (var gw in p.GatewayAddresses)
                    if (gw.Address.AddressFamily == want && !gw.Address.Equals(any))
                        return gw.Address;
            }
            catch { /* interface without the requested family */ }
        }
        return null;
    }

    /// <summary>Pin a /32 or /128 host route to the VPN server through the physical gateway so
    /// the encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(IPAddress serverIp, IPAddress gateway, uint physicalIfIndex)
    {
        if (serverIp.AddressFamily != gateway.AddressFamily)
            throw new InvalidOperationException(
                $"server route family mismatch: server {serverIp}, gateway {gateway}");
        string s = serverIp.ToString();
        bool v6 = serverIp.AddressFamily == AddressFamily.InterNetworkV6;
        Run("route", v6
            ? $"-6 add {s}/128 {gateway} metric 1 if {physicalIfIndex}"
            : $"add {s} mask 255.255.255.255 {gateway} metric 1 if {physicalIfIndex}");
        _undo.Add(() => Run("route", v6
            ? $"-6 delete {s}/128"
            : $"delete {s} mask 255.255.255.255", optional: true));
        _log($"Pinned server route {s} via {gateway}");
    }

    /// <summary>True when <paramref name="serverIp"/> is directly reachable (on-link) on the
    /// physical interface toward it — i.e. it shares that interface's subnet. Then the
    /// connected-subnet route already keeps the carrier off the tunnel (its /24 beats the
    /// full-tunnel <c>0.0.0.0/1</c> + <c>128.0.0.0/1</c> halves, and there is nothing to override
    /// in split-tunnel), so pinning a /32 via the gateway is not only unnecessary but BREAKS
    /// same-LAN setups: routing an on-link server through the gateway makes the path asymmetric
    /// (out via the gateway, replies come back directly) and the gateway drops the sustained data
    /// plane — the handshake squeaks through, the tunnel then stalls. Same subnet ⇒ skip the pin.</summary>
    public bool IsServerOnLink(IPAddress serverIp)
    {
        uint ifIndex = BestInterfaceIndex(serverIp);
        if (ifIndex == 0) return false;
        byte[] srv = serverIp.GetAddressBytes();
        bool v6 = serverIp.AddressFamily == AddressFamily.InterNetworkV6;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties();
                uint index = v6
                    ? (uint)p.GetIPv6Properties().Index
                    : (uint)p.GetIPv4Properties().Index;
                if (index != ifIndex) continue;
                foreach (var ua in p.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != serverIp.AddressFamily) continue;
                    int prefix = ua.PrefixLength;
                    int maxPrefix = v6 ? 128 : 32;
                    if (prefix is < 1 || prefix > maxPrefix) continue;
                    if (SamePrefix(ua.Address.GetAddressBytes(), srv, prefix)) return true;
                }
            }
            catch { /* interface without the requested family */ }
        }
        return false;
    }

    private static bool SamePrefix(byte[] a, byte[] b, int prefix)
    {
        if (a.Length != b.Length || prefix < 0 || prefix > a.Length * 8) return false;
        int wholeBytes = prefix / 8;
        for (int i = 0; i < wholeBytes; i++)
            if (a[i] != b[i]) return false;
        int remaining = prefix % 8;
        if (remaining == 0) return true;
        int mask = 0xFF << (8 - remaining);
        return (a[wholeBytes] & mask) == (b[wholeBytes] & mask);
    }

    public uint PhysicalIfIndexFor(IPAddress serverIp) => BestInterfaceIndex(serverIp);

    /// <summary>Resolve an exclude prefix through the routing table before full-tunnel
    /// routes are installed. IPv4 and IPv6 can use different NICs and gateways.</summary>
    public (IPAddress? gateway, uint ifIndex) PhysicalPathForRoute(string cidr)
    {
        var (addr, _) = ParseCidr(cidr);
        if (addr == null || !IPAddress.TryParse(addr, out var destination)) return (null, 0);
        if (destination.Equals(IPAddress.Any)) destination = IPAddress.Parse("1.1.1.1");
        else if (destination.Equals(IPAddress.IPv6Any))
            destination = IPAddress.Parse("2606:4700:4700::1111");
        return (FindGatewayFor(destination), PhysicalIfIndexFor(destination));
    }

    /// <summary>Assign the client IP to the tun adapter with the server-pushed subnet prefix.</summary>
    public void SetAddress(string alias, string clientIp, int prefix = 24)
    {
        if (!IPAddress.TryParse(clientIp, out var address))
            throw new InvalidOperationException($"invalid tunnel address {clientIp}");
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (prefix is < 1 or > 128)
                throw new InvalidOperationException($"invalid IPv6 tunnel prefix {prefix}");
            Run("netsh", $"interface ipv6 delete address interface=\"{alias}\" address={clientIp}", optional: true);
            Run("netsh", $"interface ipv6 add address interface=\"{alias}\" address={clientIp}/{prefix} store=active");
            _undo.Add(() => Run("netsh",
                $"interface ipv6 delete address interface=\"{alias}\" address={clientIp}", optional: true));
            _log($"Set {alias} address {clientIp}/{prefix}");
            return;
        }
        string mask = PrefixToMask(prefix);
        Run("netsh", $"interface ipv4 set address name=\"{alias}\" source=static address={clientIp} mask={mask}");
        _log($"Set {alias} address {clientIp}/{(prefix is >= 1 and <= 32 ? prefix : 24)}");
    }

    public void SetMtu(string alias, int mtu, bool ipv4, bool ipv6)
    {
        if (ipv4)
            Run("netsh", $"interface ipv4 set subinterface \"{alias}\" mtu={mtu} store=active");
        if (ipv6)
            Run("netsh", $"interface ipv6 set subinterface \"{alias}\" mtu={mtu} store=active");
    }

    // MIB_IPINTERFACE_ROW (netioapi.h) — only the fields we touch are named; the rest is
    // opaque padding preserved verbatim between Get and Set. Over-sized (>= the OS struct,
    // ~184 B on x64) so GetIpInterfaceEntry can never write past our buffer. Metric is a
    // PER-FAMILY property, so we run the Get/Set pair once for AF_INET and once for AF_INET6.
    [StructLayout(LayoutKind.Explicit, Size = 200)]
    private struct MIB_IPINTERFACE_ROW
    {
        [FieldOffset(0)] public ushort Family;             // ADDRESS_FAMILY
        [FieldOffset(8)] public ulong InterfaceLuid;      // NET_LUID
        [FieldOffset(16)] public uint InterfaceIndex;
        [FieldOffset(44)] public byte UseAutomaticMetric; // BOOLEAN — must be false or Metric is ignored
        [FieldOffset(148)] public uint Metric;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

    [DllImport("iphlpapi.dll")]
    private static extern int SetIpInterfaceEntry(ref MIB_IPINTERFACE_ROW row);

    private const ushort AF_INET = 2;
    private const ushort AF_INET6 = 23;

    /// <summary>Set the tunnel adapter's routing metric (OpenVPN route-metric; a lower value =
    /// higher priority) for BOTH IPv4 and IPv6. Prefers the typed WinAPI SetIpInterfaceEntry
    /// (no netsh string-building / process spawn, and it covers IPv6 — issue #69); falls back
    /// to netsh for whichever family the API call didn't take. Best-effort.</summary>
    public void SetMetric(ulong luid, string alias, int metric)
    {
        foreach (ushort fam in new[] { AF_INET, AF_INET6 })
        {
            if (TrySetMetricApi(luid, fam, metric)) continue;
            // Fallback: netsh for this family (older path; keeps working if the API rejects it).
            string ipv = fam == AF_INET ? "ipv4" : "ipv6";
            Run("netsh", $"interface {ipv} set interface \"{alias}\" metric={metric}", optional: true);
        }
        _log($"Set {alias} interface metric {metric} (IPv4 + IPv6)");
    }

    /// <summary>Set the per-family interface metric via WinAPI. Get the current row (so every
    /// other field is preserved), flip off automatic metric, write our value, put it back.
    /// Returns false if the interface has no binding for that family (then the caller may
    /// fall back to netsh).</summary>
    private static bool TrySetMetricApi(ulong luid, ushort family, int metric)
    {
        var row = new MIB_IPINTERFACE_ROW { Family = family, InterfaceLuid = luid };
        if (GetIpInterfaceEntry(ref row) != 0) return false; // e.g. IPv6 disabled on this adapter
        row.UseAutomaticMetric = 0;
        row.Metric = (uint)metric;
        return SetIpInterfaceEntry(ref row) == 0;
    }

    /// <summary>Override the default route via the tunnel using two /1 routes (WireGuard-style),
    /// which beat the existing 0.0.0.0/0 without deleting it.</summary>
    public void SetFullTunnelRoutes(string clientIp, uint tunIndex)
    {
        Run("route", $"add 0.0.0.0 mask 128.0.0.0 {clientIp} metric 1 if {tunIndex}");
        Run("route", $"add 128.0.0.0 mask 128.0.0.0 {clientIp} metric 1 if {tunIndex}");
        _undo.Add(() => Run("route", "delete 0.0.0.0 mask 128.0.0.0", optional: true));
        _undo.Add(() => Run("route", "delete 128.0.0.0 mask 128.0.0.0", optional: true));
        _log("Default route now via tunnel (0.0.0.0/1 + 128.0.0.0/1)");
    }

    /// <summary>Install the IPv6 redirect-gateway route set without inventing an address.
    /// The extra GUA/ULA prefixes beat router-advertised routes that are more specific than
    /// the two /1 halves.</summary>
    public void SetFullTunnelRoutesV6(string alias)
    {
        string[] nets = { "::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7" };
        foreach (var net in nets)
        {
            Run("netsh", $"interface ipv6 add route {net} \"{alias}\" metric=1");
            string captured = net;
            _undo.Add(() => Run("netsh",
                $"interface ipv6 delete route {captured} \"{alias}\"", optional: true));
        }
        _log($"IPv6 default route now via tunnel ({string.Join(", ", nets)})");
    }

    /// <summary>Legacy fail-closed capture used only when a full-tunnel NetworkPlan has no
    /// IPv6 address. A dual/IPv6 plan uses SetFullTunnelRoutesV6 with its real assignment.
    ///
    /// `::/1 + 8000::/1` beat the default `::/0`, but a router-advertised `2000::/3`
    /// (global-unicast default) is MORE specific and would still win by longest-prefix
    /// match — so we ALSO add `2000::/4 + 3000::/4` (together = all of `2000::/3`) and
    /// `fc00::/7` (ULA), mirroring what OpenVPN's redirect-gateway installs. Link-local
    /// (`fe80::/10`) and multicast are deliberately left alone. A total route failure is
    /// tolerated only when the host has no usable native IPv6 address; a partial capture or
    /// a live native path fails the plan closed. See RELEASE-FIXES E2.</summary>
    public void CaptureIPv6(string alias)
    {
        bool nativeIpv6Present = HasUsableNativeIpv6(alias);
        bool addrOk = Run("netsh", $"interface ipv6 add address \"{alias}\" fd71:e1::1/64", optional: true);
        string[] nets = { "::/1", "8000::/1", "2000::/4", "3000::/4", "fc00::/7" };
        var failed = new List<string>();
        foreach (var net in nets)
            if (!Run("netsh", $"interface ipv6 add route {net} \"{alias}\" metric=1", optional: true))
                failed.Add(net);
        foreach (var net in nets)
        {
            string n = net; // capture per-iteration for the undo closure
            _undo.Add(() => Run("netsh", $"interface ipv6 delete route {n} \"{alias}\"", optional: true));
        }
        _undo.Add(() => Run("netsh", $"interface ipv6 delete address \"{alias}\" fd71:e1::1", optional: true));

        // A partial route set is never safe: longest-prefix routing can still send the
        // uncovered classes to a physical interface. A total failure is harmless only on
        // a host that genuinely has no usable native IPv6 address at apply time.
        if (failed.Count != 0 && (failed.Count != nets.Length || nativeIpv6Present))
            throw new InvalidOperationException(
                $"IPv6 fail-closed capture failed ({nets.Length - failed.Count}/{nets.Length} " +
                $"routes installed; failed: {string.Join(", ", failed)}; " +
                $"native IPv6 present: {nativeIpv6Present})");
        if (failed.Count == 0)
            _log($"IPv6 captured into tunnel ({string.Join(", ", nets)})");
        else
            _log("IPv6 is disabled on every non-tunnel interface; no native family exists to capture");
        if (!addrOk && failed.Count != nets.Length)
            _log("note: the tunnel's IPv6 address could not be added; IPv6 capture may be incomplete.");
    }

    private static bool HasUsableNativeIpv6(string tunnelAlias)
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                string.Equals(ni.Name, tunnelAlias, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                foreach (var unicast in ni.GetIPProperties().UnicastAddresses)
                {
                    var address = unicast.Address;
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 &&
                        !address.Equals(IPAddress.IPv6Any) &&
                        !address.Equals(IPAddress.IPv6Loopback) &&
                        !address.IsIPv6LinkLocal &&
                        !address.IsIPv6Multicast &&
                        !address.IsIPv4MappedToIPv6)
                        return true;
                }
            }
            catch { /* an interface can disappear while the snapshot is being read */ }
        }
        return false;
    }

    public bool AddRoute(string cidr, string clientIp, uint tunIndex)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return false; }
        bool v6 = IPAddress.Parse(addr).AddressFamily == AddressFamily.InterNetworkV6;
        // Program the route in-process via CreateIpForwardEntry2 (iphlpapi) instead of
        // spawning route.exe. A large split-tunnel list (e.g. 12k blocked-hosting
        // prefixes) otherwise costs one CreateProcess+wait per prefix — minutes of
        // startup. Each qeli tunnel is its own adapter/index, so there is none of the
        // OpenVPN-3 single-tunnel limitation. Falls back to route.exe on any API error.
        if (TryRouteApi(create: true, addr!, prefix, tunIndex))
        {
            _undo.Add(() =>
            {
                if (!TryRouteApi(create: false, addr!, prefix, tunIndex))
                    Run("route", v6
                        ? $"-6 delete {addr}/{prefix}"
                        : $"delete {addr} mask {PrefixToMask(prefix)}", optional: true);
            });
        }
        else
        {
            string mask = v6 ? "" : PrefixToMask(prefix);
            // Both the API and route.exe failed → this destination is NOT in the tunnel.
            // Saying "via tunnel" here was a plain lie in the log. (C-17)
            string args = v6
                ? $"-6 add {addr}/{prefix} metric 1 if {tunIndex}"
                : $"add {addr} mask {mask} {clientIp} metric 1 if {tunIndex}";
            if (!Run("route", args, optional: true))
            {
                Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
                return false;
            }
            _undo.Add(() => Run("route", v6
                ? $"-6 delete {addr}/{prefix}"
                : $"delete {addr} mask {mask}", optional: true));
        }
        _log($"route {cidr} via tunnel");
        return true;
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        bool v6 = IPAddress.Parse(addr).AddressFamily == AddressFamily.InterNetworkV6;
        Run("route", v6
            ? $"-6 delete {addr}/{prefix}"
            : $"delete {addr} mask {PrefixToMask(prefix)}", optional: true);
        _log($"exclude {cidr} from tunnel");
    }

    /// <summary>Route a subnet AROUND the tunnel via the physical gateway, so an excluded
    /// destination reaches the network directly even in full-tunnel (where a plain
    /// DeleteRoute is a no-op — the 0.0.0.0/1 + 128.0.0.0/1 splits still cover it). The
    /// specific prefix beats the /1 halves by longest-prefix match. Undone on disconnect.</summary>
    public void PinBypassRoute(string cidr, IPAddress gateway, uint physicalIfIndex)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null)
            throw new InvalidOperationException($"invalid exclude route {cidr}");
        bool v6 = IPAddress.Parse(addr).AddressFamily == AddressFamily.InterNetworkV6;
        if (gateway.AddressFamily != (v6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork))
            throw new InvalidOperationException(
                $"exclude route {cidr} has no physical gateway of the same address family");
        string mask = PrefixToMask(prefix);
        Run("route", v6
            ? $"-6 delete {addr}/{prefix}"
            : $"delete {addr} mask {mask}", optional: true);  // clear any tunnel copy first
        // In full-tunnel the /1 halves already cover this prefix, so a failed pin means the
        // destination stays INSIDE the tunnel — the opposite of the requested exclude, and
        // for a kill-switch bypass (e.g. the server's own IP) that is what wedges a
        // reconnect. Not silent any more. (C-17)
        string addArgs = v6
            ? $"-6 add {addr}/{prefix} {gateway} metric 1 if {physicalIfIndex}"
            : $"add {addr} mask {mask} {gateway} metric 1 if {physicalIfIndex}";
        if (!Run("route", addArgs, optional: true))
            throw new InvalidOperationException(
                $"exclude route {cidr} via {gateway} was not programmed");
        _undo.Add(() => Run("route", v6
            ? $"-6 delete {addr}/{prefix}"
            : $"delete {addr} mask {mask}", optional: true));
        _log($"exclude {cidr} via physical gateway {gateway}");
    }

    // MIB_IPFORWARD_ROW2 is 104 bytes on x64; we write only the fields we need at
    // their documented offsets and let InitializeIpForwardEntry fill the rest (infinite
    // lifetimes, protocol, …). The SOCKADDR_INET unions below are populated for either
    // IPv4 or IPv6; the next hop is unspecified/on-link for tunnel-interface routes.
    private const int Row2Size = 104;
    private const int OffIfIndex = 8;
    private const int OffDstFamily = 12;
    private const int OffDstAddr = 16;
    private const int OffDstV6Addr = 20;
    private const int OffDstPrefixLen = 40;
    private const int OffNextHopFamily = 44;
    private const int OffMetric = 84;
    private const short AfInet = 2;
    private const short AfInet6 = 23;

    private static bool TryRouteApi(bool create, string addr, int prefix, uint ifIndex)
    {
        if (!IPAddress.TryParse(addr, out var ip)) return false;
        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;
        int maxPrefix = v6 ? 128 : 32;
        if (prefix < 0 || prefix > maxPrefix) return false;
        IntPtr row = Marshal.AllocHGlobal(Row2Size);
        try
        {
            InitializeIpForwardEntry(row);
            Marshal.WriteInt32(row, OffIfIndex, (int)ifIndex);
            short family = v6 ? AfInet6 : AfInet;
            Marshal.WriteInt16(row, OffDstFamily, family);
            byte[] bytes = ip.GetAddressBytes();
            Marshal.Copy(bytes, 0, row + (v6 ? OffDstV6Addr : OffDstAddr), bytes.Length);
            Marshal.WriteByte(row, OffDstPrefixLen, (byte)prefix);
            // Unspecified next hop = on-link via ifIndex.
            Marshal.WriteInt16(row, OffNextHopFamily, family);
            Marshal.WriteInt32(row, OffMetric, 1);
            int rc = create ? CreateIpForwardEntry2(row) : DeleteIpForwardEntry2(row);
            // 0 = NO_ERROR; 5010 = ERROR_OBJECT_ALREADY_EXISTS (create is idempotent);
            // 1168 = ERROR_NOT_FOUND (delete of an absent route is fine).
            return rc == 0 || (create && rc == 5010) || (!create && rc == 1168);
        }
        catch { return false; }
        finally { Marshal.FreeHGlobal(row); }
    }

    /// <summary>
    /// After every route is in place, confirm the carrier traffic still leaves through the
    /// PHYSICAL interface and not through the tunnel we just created. (C-17)
    /// </summary>
    /// <remarks>
    /// This is the one invariant a tunnel cannot survive breaking: if the route to the
    /// server resolves to the tun adapter, the encrypted carrier is fed back into the
    /// tunnel it is supposed to carry, and the link deadlocks immediately. Every earlier
    /// check only proved a command was ISSUED — this is the first that asks the OS what the
    /// routing table actually decided, which is what "Connected" is meant to imply.
    ///
    /// An unresolved path remains degraded because the OS supplied no answer. A path that
    /// resolves to the exact TUN index is definitive and fatal: ACKing that plan would start
    /// a carrier whose packets are routed back into itself.
    /// </remarks>
    public void VerifyCarrierPath(IPAddress serverIp, uint tunIndex)
    {
        uint best = BestInterfaceIndex(serverIp);
        if (best == 0)
        {
            Degrade($"could not resolve the outgoing interface for {serverIp} after applying " +
                    "routes — cannot confirm the carrier bypasses the tunnel");
            return;
        }
        if (best == tunIndex)
        {
            throw new InvalidOperationException(
                $"the route to the server {serverIp} resolves to the TUNNEL adapter " +
                $"(if {tunIndex}); the encrypted carrier would loop back into itself. " +
                "The server-route pin did not take effect");
        }
        _log($"carrier path verified: {serverIp} leaves via interface {best} (tunnel is if {tunIndex})");
    }

    public void SetDns(string alias, IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return;
        var parsed = servers.Select(server => IPAddress.TryParse(server, out var address)
                ? address : throw new InvalidOperationException($"invalid DNS address {server}"))
            .ToList();
        foreach (var group in parsed.GroupBy(address =>
                     address.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4"))
        {
            var values = group.Select(address => address.ToString()).ToList();
            Run("netsh",
                $"interface {group.Key} set dnsservers name=\"{alias}\" static {values[0]} primary validate=no");
            for (int i = 1; i < values.Count; i++)
                Run("netsh",
                    $"interface {group.Key} add dnsservers name=\"{alias}\" {values[i]} index={i + 1} validate=no");
            string family = group.Key;
            _undo.Add(() => Run("netsh",
                $"interface {family} set dnsservers name=\"{alias}\" dhcp", optional: true));
        }
        _log($"DNS set to {string.Join(", ", servers)}");
    }

    public void Dispose()
    {
        // Restore DNS while the Wintun adapter still exists. Unlike route cleanup, silently
        // forgetting a failed resolver reset gives the lifecycle layer no chance to retry.
        string? dnsFailure = null;
        if (_dnsAlias != null)
        {
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                if (Run("netsh",
                        $"interface ipv4 set dnsservers name=\"{_dnsAlias}\" dhcp",
                        optional: true))
                {
                    _log($"DNS reset to DHCP on \"{_dnsAlias}\"");
                    _dnsAlias = null;
                    break;
                }
                _log($"DNS reset attempt {attempt}/3 failed on \"{_dnsAlias}\"");
                if (attempt < 3) Thread.Sleep(250);
            }
            if (_dnsAlias != null)
                dnsFailure =
                    $"could not reset DNS on tunnel adapter \"{_dnsAlias}\"; cleanup will be retried";
        }

        // Routes are adapter-scoped or individually best-effort and disappear with Wintun.
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try { _undo[i](); } catch (Exception e) { _log($"undo error: {e.Message}"); }
        }
        _undo.Clear();
        if (dnsFailure != null) throw new InvalidOperationException(dnsFailure);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// <summary>Upper bound for one netsh/route/powershell call. These finish in
    /// well under a second normally; the bound only exists so a wedged child can
    /// never hang a connect/disconnect (or kill-switch removal) forever.</summary>
    private const int CommandTimeoutMs = 30_000;

    /// <summary>Run <paramref name="exe"/> to completion, bounded. Returns true iff it
    /// exited 0, so callers can report what actually happened instead of assuming success.
    ///
    /// Both pipes are drained ASYNCHRONOUSLY before waiting: a sequential
    /// ReadToEnd(stdout) then ReadToEnd(stderr) deadlocks if the child fills the stderr
    /// buffer while the parent is still blocked on stdout EOF (the same trap
    /// ServiceManager.cs already documents). A non-optional failure still throws.</summary>
    private bool Run(string exe, string args, bool optional = false)
    {
        // Resolve to an absolute System32 path. Passing a bare name lets CreateProcessW
        // search the calling image's directory FIRST, and this process is elevated (or
        // LocalSystem in service mode) — see SystemPaths. (Audit 2026-08-04, H-05.)
        var psi = new ProcessStartInfo(SystemPaths.Resolve(exe), args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = SystemPaths.SystemDirectory,
        };
        using var p = Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(CommandTimeoutMs))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            var timedOut = $"{exe} {args} -> timed out after {CommandTimeoutMs} ms";
            _log(timedOut);
            if (!optional) throw new InvalidOperationException(timedOut);
            return false;
        }
        string stdout = Drain(outTask), stderr = Drain(errTask);
        if (p.ExitCode != 0)
        {
            if (!optional)
                throw new InvalidOperationException($"{exe} {args} -> exit {p.ExitCode}: {stdout}{stderr}".Trim());
            return false;
        }
        return true;
    }

    /// <summary>Collect an already-exited child's pipe text without ever blocking
    /// indefinitely (the process is gone, so EOF is imminent; the bound is paranoia).</summary>
    private static string Drain(Task<string> t)
    {
        try { return t.Wait(5_000) ? t.Result : ""; }
        catch { return ""; }
    }

    private static (string? addr, int prefix) ParseCidr(string cidr)
    {
        // Server-pushed / config routes are spliced into `route add ...` argument lines,
        // so an unvalidated addr token is an argument-injection vector. Accept only a
        // strict IP literal (no whitespace, only [0-9A-Fa-f:.]) with an in-range prefix;
        // anything else returns (null, ..) so AddRoute logs "bad route" and drops it.
        int slash = cidr.IndexOf('/');
        if (slash < 0)
        {
            if (!IsStrictIp(cidr) || !IPAddress.TryParse(cidr, out var bare)) return (null, 0);
            return (cidr, bare.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32);
        }
        string addr = cidr[..slash];
        if (!IsStrictIp(addr) || !IPAddress.TryParse(addr, out var parsed)) return (null, 0);
        int maxPrefix = parsed.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        return int.TryParse(cidr[(slash + 1)..], out int prefix) && prefix >= 0 && prefix <= maxPrefix
            ? (addr, prefix) : (null, 0);
    }

    /// <summary>True only if <paramref name="s"/> is a bare IP literal safe to splice into a
    /// route command line: no whitespace, only [0-9A-Fa-f:.], and it parses as an IP.</summary>
    private static bool IsStrictIp(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (char c in s)
            if (!(char.IsAsciiDigit(c) || char.IsAsciiHexDigit(c) || c == ':' || c == '.'))
                return false;
        return IPAddress.TryParse(s, out _);
    }

    private static string PrefixToMask(int prefix)
    {
        prefix = Math.Clamp(prefix, 0, 32);
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        return $"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}";
    }
}
