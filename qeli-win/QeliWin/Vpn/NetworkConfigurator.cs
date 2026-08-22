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
    private readonly Func<string, string, bool, bool>? _runOverride;
    private readonly HashSet<string> _dnsFamilies = new(StringComparer.Ordinal);
    private readonly List<OwnedRoute> _ownedRoutes = new();
    private string? _dnsAlias;

    private sealed class OwnedRoute
    {
        public required string Network { get; init; }
        public required int Prefix { get; init; }
        public required string Description { get; init; }
        public required Func<bool> Delete { get; init; }
        public bool Active { get; set; } = true;
    }

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

    public NetworkConfigurator(Action<string> log) : this(log, null) { }

    internal NetworkConfigurator(Action<string> log, Func<string, string, bool, bool>? runOverride)
    {
        _log = log;
        _runOverride = runOverride;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);

    [DllImport("iphlpapi.dll")]
    private static extern int GetBestRoute2(
        IntPtr interfaceLuid,
        uint interfaceIndex,
        IntPtr sourceAddress,
        IntPtr destinationAddress,
        uint addressSortOptions,
        IntPtr bestRoute,
        IntPtr bestSourceAddress);

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
            var properties = ni.GetIPProperties();
            try
            {
                var ipv4 = properties.GetIPv4Properties();
                if (ipv4 != null && (uint)ipv4.Index == index) return ni.Name;
            }
            catch { /* interface without IPv4 props */ }
            try
            {
                var ipv6 = properties.GetIPv6Properties();
                if (ipv6 != null && (uint)ipv6.Index == index) return ni.Name;
            }
            catch { /* interface without IPv6 props */ }
        }
        return null;
    }

    private sealed record RoutePath(uint InterfaceIndex, IPAddress? Gateway, IPAddress? Source);

    /// <summary>Ask the Windows routing stack for the complete selected path. Unlike
    /// GetBestInterfaceEx + "first gateway on that NIC", GetBestRoute2 returns the actual
    /// next-hop chosen for this destination and correctly represents on-link routes with an
    /// unspecified next-hop.</summary>
    private static RoutePath? BestRouteFor(IPAddress destination, IPAddress? source = null)
    {
        IntPtr dst = Marshal.AllocHGlobal(SockaddrInetSize);
        IntPtr src = source == null ? IntPtr.Zero : Marshal.AllocHGlobal(SockaddrInetSize);
        IntPtr bestSource = Marshal.AllocHGlobal(SockaddrInetSize);
        IntPtr row = Marshal.AllocHGlobal(Row2Size);
        try
        {
            Clear(dst, SockaddrInetSize);
            Clear(bestSource, SockaddrInetSize);
            Clear(row, Row2Size);
            WriteSockaddr(dst, 0, destination);
            if (source != null)
            {
                Clear(src, SockaddrInetSize);
                WriteSockaddr(src, 0, source);
            }
            if (GetBestRoute2(IntPtr.Zero, 0, src, dst, 0, row, bestSource) != 0)
                return null;
            uint ifIndex = unchecked((uint)Marshal.ReadInt32(row, OffIfIndex));
            IPAddress? nextHop = ReadSockaddr(row, OffNextHopFamily);
            if (nextHop != null && IsUnspecified(nextHop)) nextHop = null;
            IPAddress? selectedSource = ReadSockaddr(bestSource, 0);
            return ifIndex == 0 ? null : new RoutePath(ifIndex, nextHop, selectedSource);
        }
        catch { return null; }
        finally
        {
            Marshal.FreeHGlobal(row);
            Marshal.FreeHGlobal(bestSource);
            if (src != IntPtr.Zero) Marshal.FreeHGlobal(src);
            Marshal.FreeHGlobal(dst);
        }
    }

    public (IPAddress? gateway, uint ifIndex) PhysicalPathFor(IPAddress destination)
    {
        var path = BestRouteFor(destination);
        return path == null
            ? (null, 0)
            : (path.Gateway, path.InterfaceIndex);
    }

    /// <summary>Pin a /32 or /128 host route to the VPN server through the physical gateway so
    /// the encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(IPAddress serverIp, IPAddress? gateway, uint physicalIfIndex)
    {
        if (physicalIfIndex == 0)
            throw new InvalidOperationException($"server route {serverIp} has no physical interface");
        if (gateway != null && serverIp.AddressFamily != gateway.AddressFamily)
            throw new InvalidOperationException(
                $"server route family mismatch: server {serverIp}, gateway {gateway}");
        string s = serverIp.ToString();
        bool v6 = serverIp.AddressFamily == AddressFamily.InterNetworkV6;
        int prefix = v6 ? 128 : 32;
        var (result, row) = TryCreateRouteApi(serverIp, prefix, physicalIfIndex, gateway);
        if (result == RouteApiResult.Created)
            OwnRoute(serverIp, prefix, $"server route {s}", () => TryDeleteRouteApi(row!));
        else if (result == RouteApiResult.Failed)
        {
            if (gateway == null)
                throw new InvalidOperationException(
                    $"on-link server route {s} on interface {physicalIfIndex} was not programmed");
            string add = v6
                ? $"-6 add {s}/128 {gateway} metric 1 if {physicalIfIndex}"
                : $"add {s} mask 255.255.255.255 {gateway} metric 1 if {physicalIfIndex}";
            Run("route", add);
            OwnRoute(serverIp, prefix, $"server route {s}", () => Run("route", v6
                ? $"-6 delete {s}/128 {gateway} if {physicalIfIndex}"
                : $"delete {s} mask 255.255.255.255 {gateway} if {physicalIfIndex}", optional: true));
        }
        _log(result == RouteApiResult.AlreadyExists
            ? $"Preserving an existing exact server route {s} on interface {physicalIfIndex}"
            : $"Pinned server route {s} " + (gateway == null
                ? $"on-link on interface {physicalIfIndex}"
                : $"via {gateway}"));
    }

    /// <summary>An on-link carrier has no gateway, but still needs an exact route bound to
    /// the selected physical interface before full-tunnel routes are installed. Do not invent
    /// the interface's default gateway: that breaks same-LAN carrier paths.</summary>
    /// <summary>Resolve an exclude prefix through the routing table before full-tunnel
    /// routes are installed. IPv4 and IPv6 can use different NICs and gateways.</summary>
    public (IPAddress? gateway, uint ifIndex) PhysicalPathForRoute(string cidr)
    {
        var (addr, _) = ParseCidr(cidr);
        if (addr == null || !IPAddress.TryParse(addr, out var destination)) return (null, 0);
        if (destination.Equals(IPAddress.Any)) destination = IPAddress.Parse("1.1.1.1");
        else if (destination.Equals(IPAddress.IPv6Any))
            destination = IPAddress.Parse("2606:4700:4700::1111");
        var path = BestRouteFor(destination);
        return path == null ? (null, 0) : (path.Gateway, path.InterfaceIndex);
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
        if (!IPAddress.TryParse(clientIp, out var gateway) ||
            gateway.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException($"invalid IPv4 tunnel gateway {clientIp}");
        foreach (string cidr in new[] { "0.0.0.0/1", "128.0.0.0/1" })
        {
            var (literal, prefix) = ParseCidr(cidr);
            var network = IPAddress.Parse(literal!);
            string mask = PrefixToMask(prefix);
            var result = InstallOwnedRoute(
                network, prefix, tunIndex, null, $"full-tunnel route {cidr}",
                $"add {network} mask {mask} {gateway} metric 1 if {tunIndex}",
                $"delete {network} mask {mask} {gateway} if {tunIndex}");
            if (result == RouteApiResult.Failed)
                throw new InvalidOperationException($"full-tunnel route {cidr} was not programmed");
        }
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
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        bool v6 = network.AddressFamily == AddressFamily.InterNetworkV6;
        // Program the route in-process via CreateIpForwardEntry2 (iphlpapi) instead of
        // spawning route.exe. A large split-tunnel list (e.g. 12k blocked-hosting
        // prefixes) otherwise costs one CreateProcess+wait per prefix — minutes of
        // startup. Each qeli tunnel is its own adapter/index, so there is none of the
        // OpenVPN-3 single-tunnel limitation. Falls back to route.exe on any API error.
        IPAddress? nextHop = null; // Wintun route is on-link; clientIp is only route.exe fallback syntax
        string mask = v6 ? "" : PrefixToMask(prefix);
        string add = v6
            ? $"-6 add {network}/{prefix} metric 1 if {tunIndex}"
            : $"add {network} mask {mask} {clientIp} metric 1 if {tunIndex}";
        string delete = v6
            ? $"-6 delete {network}/{prefix} if {tunIndex}"
            : $"delete {network} mask {mask} {clientIp} if {tunIndex}";
        var result = InstallOwnedRoute(
            network, prefix, tunIndex, nextHop, $"tunnel route {cidr}", add, delete);
        if (result == RouteApiResult.Failed)
        {
            Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
            return false;
        }
        if (result == RouteApiResult.AlreadyExists)
            _log($"route {cidr} already exists on this tunnel interface; preserving it");
        _log($"route {cidr} via tunnel");
        return true;
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        int removed = DeleteOwnedRoutes(network, prefix);
        _log(removed == 0
            ? $"exclude {cidr}: no Qeli-owned tunnel route existed; preserving system routes"
            : $"exclude {cidr}: removed {removed} Qeli-owned tunnel route(s)");
    }

    /// <summary>Route a subnet AROUND the tunnel via the physical gateway, so an excluded
    /// destination reaches the network directly even in full-tunnel (where a plain
    /// DeleteRoute is a no-op — the 0.0.0.0/1 + 128.0.0.0/1 splits still cover it). The
    /// specific prefix beats the /1 halves by longest-prefix match. Undone on disconnect.</summary>
    public void PinBypassRoute(string cidr, IPAddress? gateway, uint physicalIfIndex)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null)
            throw new InvalidOperationException($"invalid exclude route {cidr}");
        IPAddress network = NetworkAddress(IPAddress.Parse(addr), prefix);
        bool v6 = network.AddressFamily == AddressFamily.InterNetworkV6;
        if (physicalIfIndex == 0)
            throw new InvalidOperationException($"exclude route {cidr} has no physical interface");
        if (gateway != null && gateway.AddressFamily != network.AddressFamily)
            throw new InvalidOperationException(
                $"exclude route {cidr} has no physical gateway of the same address family");
        DeleteOwnedRoutes(network, prefix); // remove only a route this transaction created
        string mask = PrefixToMask(prefix);
        string? add = gateway == null ? null : v6
            ? $"-6 add {network}/{prefix} {gateway} metric 1 if {physicalIfIndex}"
            : $"add {network} mask {mask} {gateway} metric 1 if {physicalIfIndex}";
        string? delete = gateway == null ? null : v6
            ? $"-6 delete {network}/{prefix} {gateway} if {physicalIfIndex}"
            : $"delete {network} mask {mask} {gateway} if {physicalIfIndex}";
        var result = InstallOwnedRoute(
            network, prefix, physicalIfIndex, gateway, $"bypass route {cidr}", add, delete);
        if (result == RouteApiResult.Failed)
            throw new InvalidOperationException(
                $"exclude route {cidr} via physical interface {physicalIfIndex} was not programmed");
        _log(result == RouteApiResult.AlreadyExists
            ? $"exclude {cidr}: preserving an existing matching physical route"
            : $"exclude {cidr} via " + (gateway == null
                ? $"on-link interface {physicalIfIndex}"
                : $"physical gateway {gateway}"));
    }

    // MIB_IPFORWARD_ROW2 is 104 bytes on x64; we write only the fields we need at
    // their documented offsets and let InitializeIpForwardEntry fill the rest (infinite
    // lifetimes, protocol, …). The SOCKADDR_INET unions below are populated for either
    // IPv4 or IPv6; the next hop is unspecified/on-link for tunnel-interface routes.
    private const int Row2Size = 104;
    private const int SockaddrInetSize = 28;
    private const int OffIfIndex = 8;
    private const int OffDstFamily = 12;
    private const int OffDstPrefixLen = 40;
    private const int OffNextHopFamily = 44;
    private const int OffMetric = 84;
    private const short AfInet = 2;
    private const short AfInet6 = 23;

    private enum RouteApiResult { Created, AlreadyExists, Failed }

    private RouteApiResult InstallOwnedRoute(
        IPAddress address,
        int prefix,
        uint ifIndex,
        IPAddress? nextHop,
        string description,
        string? fallbackAdd,
        string? fallbackDelete)
    {
        var (result, row) = TryCreateRouteApi(address, prefix, ifIndex, nextHop);
        if (result == RouteApiResult.Created)
            OwnRoute(address, prefix, description, () => TryDeleteRouteApi(row!));
        else if (result == RouteApiResult.Failed && fallbackAdd != null && fallbackDelete != null &&
                 Run("route", fallbackAdd, optional: true))
        {
            OwnRoute(address, prefix, description,
                () => Run("route", fallbackDelete, optional: true));
            result = RouteApiResult.Created;
        }
        return result;
    }

    private static (RouteApiResult result, byte[]? row) TryCreateRouteApi(
        IPAddress address, int prefix, uint ifIndex, IPAddress? nextHop)
    {
        try
        {
            byte[] row = BuildRouteRow(address, prefix, ifIndex, nextHop);
            int rc = InvokeRouteApi(create: true, row);
            return rc switch
            {
                0 => (RouteApiResult.Created, row),
                5010 => (RouteApiResult.AlreadyExists, row),
                _ => (RouteApiResult.Failed, null),
            };
        }
        catch { return (RouteApiResult.Failed, null); }
    }

    private static bool TryDeleteRouteApi(byte[] row)
    {
        try
        {
            int rc = InvokeRouteApi(create: false, row);
            return rc is 0 or 1168;
        }
        catch { return false; }
    }

    private static int InvokeRouteApi(bool create, byte[] rowBytes)
    {
        IntPtr row = Marshal.AllocHGlobal(Row2Size);
        try
        {
            Marshal.Copy(rowBytes, 0, row, Row2Size);
            return create ? CreateIpForwardEntry2(row) : DeleteIpForwardEntry2(row);
        }
        finally { Marshal.FreeHGlobal(row); }
    }

    private static byte[] BuildRouteRow(
        IPAddress address, int prefix, uint ifIndex, IPAddress? nextHop, uint metric = 1)
    {
        bool v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        int maxPrefix = v6 ? 128 : 32;
        if (prefix < 0 || prefix > maxPrefix || ifIndex == 0)
            throw new ArgumentOutOfRangeException(nameof(prefix));
        if (nextHop != null && nextHop.AddressFamily != address.AddressFamily)
            throw new ArgumentException("route next-hop family mismatch", nameof(nextHop));
        address = NetworkAddress(address, prefix);
        IntPtr row = Marshal.AllocHGlobal(Row2Size);
        try
        {
            Clear(row, Row2Size);
            InitializeIpForwardEntry(row);
            Marshal.WriteInt32(row, OffIfIndex, unchecked((int)ifIndex));
            WriteSockaddr(row, OffDstFamily, address);
            Marshal.WriteByte(row, OffDstPrefixLen, (byte)prefix);
            WriteSockaddr(row, OffNextHopFamily,
                nextHop ?? (v6 ? IPAddress.IPv6Any : IPAddress.Any));
            Marshal.WriteInt32(row, OffMetric, unchecked((int)metric));
            var bytes = new byte[Row2Size];
            Marshal.Copy(row, bytes, 0, bytes.Length);
            return bytes;
        }
        finally { Marshal.FreeHGlobal(row); }
    }

    private static void Clear(IntPtr pointer, int length) =>
        Marshal.Copy(new byte[length], 0, pointer, length);

    private static void WriteSockaddr(IntPtr pointer, int offset, IPAddress address)
    {
        bool v6 = address.AddressFamily == AddressFamily.InterNetworkV6;
        Marshal.WriteInt16(pointer, offset, v6 ? AfInet6 : AfInet);
        byte[] bytes = address.GetAddressBytes();
        Marshal.Copy(bytes, 0, pointer + offset + (v6 ? 8 : 4), bytes.Length);
        if (v6) Marshal.WriteInt32(pointer, offset + 24, unchecked((int)address.ScopeId));
    }

    private static IPAddress? ReadSockaddr(IntPtr pointer, int offset)
    {
        short family = Marshal.ReadInt16(pointer, offset);
        if (family == AfInet)
        {
            var bytes = new byte[4];
            Marshal.Copy(pointer + offset + 4, bytes, 0, bytes.Length);
            return new IPAddress(bytes);
        }
        if (family == AfInet6)
        {
            var bytes = new byte[16];
            Marshal.Copy(pointer + offset + 8, bytes, 0, bytes.Length);
            uint scope = unchecked((uint)Marshal.ReadInt32(pointer, offset + 24));
            return new IPAddress(bytes, scope);
        }
        return null;
    }

    private static bool IsUnspecified(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    private void OwnRoute(IPAddress address, int prefix, string description, Func<bool> delete)
    {
        _ownedRoutes.Add(new OwnedRoute
        {
            Network = NetworkAddress(address, prefix).ToString(),
            Prefix = prefix,
            Description = description,
            Delete = delete,
        });
    }

    private bool DeleteOwnedRoute(OwnedRoute route)
    {
        if (!route.Active) return true;
        if (!route.Delete()) return false;
        route.Active = false;
        return true;
    }

    private int DeleteOwnedRoutes(IPAddress address, int prefix)
    {
        string network = NetworkAddress(address, prefix).ToString();
        int removed = 0;
        foreach (var route in _ownedRoutes.Where(route => route.Active &&
                     route.Prefix == prefix && route.Network == network).ToArray())
        {
            if (!DeleteOwnedRoute(route))
                throw new InvalidOperationException($"could not remove Qeli-owned {route.Description}");
            removed++;
        }
        return removed;
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
    public void VerifyCarrierPath(
        IPAddress serverIp,
        uint tunIndex,
        uint expectedPhysicalIfIndex,
        IPAddress? expectedGateway)
    {
        var actual = BestRouteFor(serverIp);
        if (actual == null)
        {
            Degrade($"could not resolve the outgoing route for {serverIp} after applying " +
                    "routes — cannot confirm the carrier bypasses the tunnel");
            return;
        }
        if (actual.InterfaceIndex == tunIndex)
        {
            throw new InvalidOperationException(
                $"the route to the server {serverIp} resolves to the TUNNEL adapter " +
                $"(if {tunIndex}); the encrypted carrier would loop back into itself. " +
                "The server-route pin did not take effect");
        }
        if (expectedPhysicalIfIndex != 0 && actual.InterfaceIndex != expectedPhysicalIfIndex)
            throw new InvalidOperationException(
                $"carrier {serverIp} moved from physical interface {expectedPhysicalIfIndex} " +
                $"to {actual.InterfaceIndex} while the network plan was being applied");
        if (!SameNextHop(actual.Gateway, expectedGateway))
            throw new InvalidOperationException(
                $"carrier {serverIp} next-hop changed while applying the network plan " +
                $"({expectedGateway?.ToString() ?? "on-link"} -> " +
                $"{actual.Gateway?.ToString() ?? "on-link"})");
        _log($"carrier path verified: {serverIp} leaves via interface {actual.InterfaceIndex}, " +
             $"next-hop {actual.Gateway?.ToString() ?? "on-link"} (tunnel is if {tunIndex})");
    }

    private static bool SameNextHop(IPAddress? left, IPAddress? right)
    {
        if (left == null || right == null) return left == null && right == null;
        return left.AddressFamily == right.AddressFamily &&
               left.GetAddressBytes().SequenceEqual(right.GetAddressBytes()) &&
               (left.AddressFamily != AddressFamily.InterNetworkV6 ||
                left.ScopeId == 0 || right.ScopeId == 0 || left.ScopeId == right.ScopeId);
    }

    public void SetDns(string alias, IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return;
        if (_dnsAlias != null && !string.Equals(_dnsAlias, alias, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"DNS is already configured on adapter \"{_dnsAlias}\"; refusing to lose its cleanup state");

        var parsed = servers.Select(server => IPAddress.TryParse(server, out var address)
                ? address : throw new InvalidOperationException($"invalid DNS address {server}"))
            .ToList();
        foreach (var group in parsed.GroupBy(address =>
                     address.AddressFamily == AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4"))
        {
            var values = group.Select(address => address.ToString()).ToList();
            Run("netsh",
                $"interface {group.Key} set dnsservers name=\"{alias}\" static {values[0]} primary validate=no");
            // Record ownership immediately after the first successful mutation. If adding a
            // secondary resolver fails, Dispose must still restore this family to DHCP.
            _dnsAlias = alias;
            _dnsFamilies.Add(group.Key);
            for (int i = 1; i < values.Count; i++)
                Run("netsh",
                    $"interface {group.Key} add dnsservers name=\"{alias}\" {values[i]} index={i + 1} validate=no");
        }
        _log($"DNS set to {string.Join(", ", servers)}");
    }

    public void Dispose()
    {
        var failedRoutes = new List<string>();
        for (int i = _ownedRoutes.Count - 1; i >= 0; i--)
        {
            var route = _ownedRoutes[i];
            if (!route.Active) continue;
            try
            {
                if (!DeleteOwnedRoute(route)) failedRoutes.Add(route.Description);
            }
            catch (Exception e)
            {
                failedRoutes.Add(route.Description);
                _log($"route cleanup error ({route.Description}): {e.Message}");
            }
        }
        _ownedRoutes.RemoveAll(route => !route.Active);

        // Restore DNS while the Wintun adapter still exists. Unlike route cleanup, silently
        // forgetting a failed resolver reset gives the lifecycle layer no chance to retry.
        var failedDnsFamilies = new List<string>();
        string? alias = _dnsAlias;
        if (alias != null)
        {
            foreach (string family in _dnsFamilies.ToArray())
            {
                bool restored = false;
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    if (Run("netsh",
                            $"interface {family} set dnsservers name=\"{alias}\" dhcp",
                            optional: true))
                    {
                        restored = true;
                        _dnsFamilies.Remove(family);
                        _log($"{family} DNS reset to DHCP on \"{alias}\"");
                        break;
                    }
                    _log($"{family} DNS reset attempt {attempt}/3 failed on \"{alias}\"");
                    if (attempt < 3 && _runOverride == null) Thread.Sleep(250);
                }
                if (!restored) failedDnsFamilies.Add(family);
            }
            if (_dnsFamilies.Count == 0) _dnsAlias = null;
        }

        // Routes are adapter-scoped or individually best-effort and disappear with Wintun.
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try { _undo[i](); } catch (Exception e) { _log($"undo error: {e.Message}"); }
        }
        _undo.Clear();
        if (failedDnsFamilies.Count != 0 || failedRoutes.Count != 0)
            throw new InvalidOperationException(
                "platform cleanup will be retried: " +
                (failedDnsFamilies.Count == 0 ? "" :
                    $"could not reset {string.Join("/", failedDnsFamilies)} DNS on \"{alias}\"; ") +
                (failedRoutes.Count == 0 ? "" :
                    $"could not remove routes: {string.Join(", ", failedRoutes)}"));
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
        if (_runOverride != null)
        {
            bool succeeded = _runOverride(exe, args, optional);
            if (!succeeded && !optional)
                throw new InvalidOperationException($"{exe} {args} -> simulated command failure");
            return succeeded;
        }

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

    /// <summary>Non-admin regression coverage for dual-stack DNS ownership and retries.</summary>
    internal static void RunDnsLifecycleSelfTest(Action<string, bool> check)
    {
        var commands = new List<string>();
        bool Record(string exe, string args, bool optional)
        {
            commands.Add($"{exe} {args}");
            return true;
        }

        var dual = new NetworkConfigurator(_ => { }, Record);
        dual.SetDns("qeli-selftest", new[] { "1.1.1.1", "2606:4700:4700::1111" });
        dual.Dispose();
        check("NetworkConfigurator restores IPv4 and IPv6 DNS", commands.Any(command =>
                  command.Contains("interface ipv4 set dnsservers", StringComparison.Ordinal) &&
                  command.EndsWith("dhcp", StringComparison.Ordinal)) &&
              commands.Any(command =>
                  command.Contains("interface ipv6 set dnsservers", StringComparison.Ordinal) &&
                  command.EndsWith("dhcp", StringComparison.Ordinal)));

        int resetAttempts = 0;
        bool FailTwice(string exe, string args, bool optional)
        {
            if (args.Contains("interface ipv6 set dnsservers", StringComparison.Ordinal) &&
                args.EndsWith("dhcp", StringComparison.Ordinal))
            {
                resetAttempts++;
                return resetAttempts >= 3;
            }
            return true;
        }

        var transient = new NetworkConfigurator(_ => { }, FailTwice);
        transient.SetDns("qeli-selftest", new[] { "2606:4700:4700::1111" });
        transient.Dispose();
        check("NetworkConfigurator retries transient IPv6 DNS cleanup", resetAttempts == 3);

        var partialCommands = new List<string>();
        bool FailSecondary(string exe, string args, bool optional)
        {
            partialCommands.Add($"{exe} {args}");
            return !args.Contains("add dnsservers", StringComparison.Ordinal);
        }
        var partial = new NetworkConfigurator(_ => { }, FailSecondary);
        bool applyFailed = false;
        try
        {
            partial.SetDns("qeli-selftest", new[] { "1.1.1.1", "1.0.0.1" });
        }
        catch (InvalidOperationException) { applyFailed = true; }
        partial.Dispose();
        check("NetworkConfigurator cleans DNS after a partial apply failure",
            applyFailed && partialCommands.Any(command =>
                command.Contains("interface ipv4 set dnsservers", StringComparison.Ordinal) &&
                command.EndsWith("dhcp", StringComparison.Ordinal)));
    }

    internal static void RunRouteLifecycleSelfTest(Action<string, bool> check)
    {
        byte[] row = BuildRouteRow(
            IPAddress.Parse("2001:db8:20::beef"), 64, 37,
            new IPAddress(IPAddress.Parse("fe80::1").GetAddressBytes(), 37));
        IntPtr native = Marshal.AllocHGlobal(Row2Size);
        try
        {
            Marshal.Copy(row, 0, native, row.Length);
            var destination = ReadSockaddr(native, OffDstFamily);
            var nextHop = ReadSockaddr(native, OffNextHopFamily);
            check("Windows route row preserves IPv6 prefix/interface/next-hop scope",
                destination?.ToString() == "2001:db8:20::" &&
                Marshal.ReadByte(native, OffDstPrefixLen) == 64 &&
                unchecked((uint)Marshal.ReadInt32(native, OffIfIndex)) == 37 &&
                nextHop?.ToString() == "fe80::1%37");
        }
        finally { Marshal.FreeHGlobal(native); }

        row = BuildRouteRow(IPAddress.Parse("198.51.100.99"), 24, 9, null);
        native = Marshal.AllocHGlobal(Row2Size);
        try
        {
            Marshal.Copy(row, 0, native, row.Length);
            var destination = ReadSockaddr(native, OffDstFamily);
            var nextHop = ReadSockaddr(native, OffNextHopFamily);
            check("Windows route row normalizes IPv4 and represents on-link next-hop",
                destination?.ToString() == "198.51.100.0" &&
                nextHop != null && IsUnspecified(nextHop));
        }
        finally { Marshal.FreeHGlobal(native); }
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

    private static IPAddress NetworkAddress(IPAddress address, int prefix)
    {
        byte[] bytes = address.GetAddressBytes();
        int maxPrefix = bytes.Length * 8;
        if (prefix < 0 || prefix > maxPrefix)
            throw new ArgumentOutOfRangeException(nameof(prefix));
        int whole = prefix / 8;
        int bits = prefix % 8;
        if (bits != 0)
        {
            bytes[whole] &= (byte)(0xff << (8 - bits));
            whole++;
        }
        Array.Clear(bytes, whole, bytes.Length - whole);
        return address.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPAddress(bytes, address.ScopeId)
            : new IPAddress(bytes);
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
