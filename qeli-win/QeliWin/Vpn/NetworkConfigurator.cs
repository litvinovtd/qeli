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

    /// <summary>Pin a /32 host route to the VPN server through the physical gateway so the
    /// encrypted carrier traffic never loops back into the tunnel (Android's protect()).</summary>
    public void PinServerRoute(IPAddress serverIp, IPAddress gateway, uint physicalIfIndex)
    {
        string s = serverIp.ToString();
        Run("route", $"add {s} mask 255.255.255.255 {gateway} metric 1 if {physicalIfIndex}");
        _undo.Add(() => Run("route", $"delete {s}", optional: true));
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
        if (serverIp.AddressFamily != AddressFamily.InterNetwork) return false; // the /32 pin is IPv4
        uint ifIndex = BestInterfaceIndex(serverIp);
        if (ifIndex == 0) return false;
        byte[] srv = serverIp.GetAddressBytes();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties();
                if ((uint)p.GetIPv4Properties().Index != ifIndex) continue;
                foreach (var ua in p.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    int prefix = ua.PrefixLength;
                    if (prefix is < 1 or > 32) continue;
                    if (SameV4Subnet(ua.Address.GetAddressBytes(), srv, prefix)) return true;
                }
            }
            catch { /* interface without IPv4 props */ }
        }
        return false;
    }

    private static bool SameV4Subnet(byte[] a, byte[] b, int prefix)
    {
        uint ua = (uint)((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]);
        uint ub = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        return (ua & mask) == (ub & mask);
    }

    public uint PhysicalIfIndexFor(IPAddress serverIp) => BestInterfaceIndex(serverIp);

    /// <summary>Assign the client IP to the tun adapter with the server-pushed subnet prefix.</summary>
    public void SetAddress(string alias, string clientIp, int prefix = 24)
    {
        string mask = PrefixToMask(prefix);
        Run("netsh", $"interface ipv4 set address name=\"{alias}\" source=static address={clientIp} mask={mask}");
        _log($"Set {alias} address {clientIp}/{(prefix is >= 1 and <= 32 ? prefix : 24)}");
    }

    public void SetMtu(string alias, int mtu)
    {
        Run("netsh", $"interface ipv4 set subinterface \"{alias}\" mtu={mtu} store=active", optional: true);
    }

    // MIB_IPINTERFACE_ROW (netioapi.h) — only the fields we touch are named; the rest is
    // opaque padding preserved verbatim between Get and Set. Over-sized (>= the OS struct,
    // ~184 B on x64) so GetIpInterfaceEntry can never write past our buffer. Metric is a
    // PER-FAMILY property, so we run the Get/Set pair once for AF_INET and once for AF_INET6.
    [StructLayout(LayoutKind.Explicit, Size = 200)]
    private struct MIB_IPINTERFACE_ROW
    {
        [FieldOffset(0)]   public ushort Family;             // ADDRESS_FAMILY
        [FieldOffset(8)]   public ulong  InterfaceLuid;      // NET_LUID
        [FieldOffset(16)]  public uint   InterfaceIndex;
        [FieldOffset(44)]  public byte   UseAutomaticMetric; // BOOLEAN — must be false or Metric is ignored
        [FieldOffset(148)] public uint   Metric;
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

    /// <summary>Capture IPv6 into the tunnel in full-tunnel mode so dual-stack traffic
    /// can't bypass it (the classic VPN IPv6 leak: IPv4 goes through the VPN while
    /// IPv6 exits the physical NIC). The server is IPv4-only, so these packets are
    /// blackholed inside the tunnel rather than leaked — apps fall back to IPv4.
    ///
    /// `::/1 + 8000::/1` beat the default `::/0`, but a router-advertised `2000::/3`
    /// (global-unicast default) is MORE specific and would still win by longest-prefix
    /// match — so we ALSO add `2000::/4 + 3000::/4` (together = all of `2000::/3`) and
    /// `fc00::/7` (ULA), mirroring what OpenVPN's redirect-gateway installs. Link-local
    /// (`fe80::/10`) and multicast are deliberately left alone. All optional: a host with
    /// IPv6 disabled simply has nothing to capture. See RELEASE-FIXES E2.</summary>
    public void CaptureIPv6(string alias)
    {
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

        // Report what ACTUALLY happened. These commands are optional by design — a host
        // with IPv6 disabled has nothing to capture and every add fails harmlessly, so a
        // failure is NOT proof of a leak and must not abort the connection. But claiming
        // "captured" unconditionally hid the opposite case (IPv6 present, capture partly
        // or wholly failed → traffic leaves outside the tunnel while the log said it was
        // covered). Say which ranges are actually covered and flag the leak risk.
        if (failed.Count == 0)
            _log($"IPv6 captured into tunnel ({string.Join(", ", nets)})");
        else if (failed.Count == nets.Length)
            _log("IPv6 NOT captured: every route add failed. If this host has IPv6 disabled " +
                 "there is nothing to capture and nothing leaks; if it does have IPv6, that " +
                 "traffic is leaving OUTSIDE the tunnel — check that qeli runs elevated.");
        else
            _log($"WARNING: IPv6 only partially captured — {nets.Length - failed.Count}/{nets.Length} " +
                 $"ranges; failed: {string.Join(", ", failed)}. IPv6 matching the failed ranges may " +
                 "leave OUTSIDE the tunnel.");
        if (!addrOk && failed.Count != nets.Length)
            _log("note: the tunnel's IPv6 address could not be added; IPv6 capture may be incomplete.");
    }

    public void AddRoute(string cidr, string clientIp, uint tunIndex)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad route {cidr}"); return; }
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
                    Run("route", $"delete {addr} mask {PrefixToMask(prefix)}", optional: true);
            });
        }
        else
        {
            string mask = PrefixToMask(prefix);
            // Both the API and route.exe failed → this destination is NOT in the tunnel.
            // Saying "via tunnel" here was a plain lie in the log. (C-17)
            if (!Run("route", $"add {addr} mask {mask} {clientIp} metric 1 if {tunIndex}", optional: true))
            {
                Degrade($"route {cidr} NOT programmed — traffic to it stays outside the tunnel");
                return;
            }
            _undo.Add(() => Run("route", $"delete {addr} mask {mask}", optional: true));
        }
        _log($"route {cidr} via tunnel");
    }

    /// <summary>Split-tunnel exclude: drop a destination from the tunnel so it falls back
    /// to the physical route (mirrors the Rust client's `ip route del ... dev tun`).</summary>
    public void DeleteRoute(string cidr)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        Run("route", $"delete {addr} mask {PrefixToMask(prefix)}", optional: true);
        _log($"exclude {cidr} from tunnel");
    }

    /// <summary>Route a subnet AROUND the tunnel via the physical gateway, so an excluded
    /// destination reaches the network directly even in full-tunnel (where a plain
    /// DeleteRoute is a no-op — the 0.0.0.0/1 + 128.0.0.0/1 splits still cover it). The
    /// specific prefix beats the /1 halves by longest-prefix match. Undone on disconnect.</summary>
    public void PinBypassRoute(string cidr, IPAddress gateway, uint physicalIfIndex)
    {
        var (addr, prefix) = ParseCidr(cidr);
        if (addr == null) { _log($"bad exclude route {cidr}"); return; }
        string mask = PrefixToMask(prefix);
        Run("route", $"delete {addr} mask {mask}", optional: true);  // clear any tunnel copy first
        // In full-tunnel the /1 halves already cover this prefix, so a failed pin means the
        // destination stays INSIDE the tunnel — the opposite of the requested exclude, and
        // for a kill-switch bypass (e.g. the server's own IP) that is what wedges a
        // reconnect. Not silent any more. (C-17)
        if (!Run("route", $"add {addr} mask {mask} {gateway} metric 1 if {physicalIfIndex}", optional: true))
        {
            Degrade($"bypass route {cidr} via {gateway} NOT programmed — it stays inside the tunnel");
            return;
        }
        _undo.Add(() => Run("route", $"delete {addr} mask {mask}", optional: true));
        _log($"exclude {cidr} via physical gateway {gateway}");
    }

    // MIB_IPFORWARD_ROW2 is 104 bytes on x64; we write only the fields we need at
    // their documented offsets and let InitializeIpForwardEntry fill the rest (infinite
    // lifetimes, protocol, …). IPv4 only — AddRoute parses IPv4 CIDRs (IPv6 is captured
    // separately in CaptureIPv6). Returns false on any error so the caller can fall back.
    private const int Row2Size = 104;
    private const int OffIfIndex = 8;
    private const int OffDstFamily = 12;
    private const int OffDstAddr = 16;
    private const int OffDstPrefixLen = 40;
    private const int OffNextHopFamily = 44;
    private const int OffMetric = 84;
    private const short AfInet = 2;

    private static bool TryRouteApi(bool create, string addr, int prefix, uint ifIndex)
    {
        if (!IPAddress.TryParse(addr, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork)
            return false;
        IntPtr row = Marshal.AllocHGlobal(Row2Size);
        try
        {
            InitializeIpForwardEntry(row);
            Marshal.WriteInt32(row, OffIfIndex, (int)ifIndex);
            Marshal.WriteInt16(row, OffDstFamily, AfInet);
            Marshal.Copy(ip.GetAddressBytes(), 0, row + OffDstAddr, 4);
            Marshal.WriteByte(row, OffDstPrefixLen, (byte)Math.Clamp(prefix, 0, 32));
            // NextHop family AF_INET, address left 0.0.0.0 = on-link via ifIndex.
            Marshal.WriteInt16(row, OffNextHopFamily, AfInet);
            Marshal.WriteInt32(row, OffMetric, 1);
            int rc = create ? CreateIpForwardEntry2(row) : DeleteIpForwardEntry2(row);
            // 0 = NO_ERROR; 5010 = ERROR_OBJECT_ALREADY_EXISTS (create is idempotent);
            // 1168 = ERROR_NOT_FOUND (delete of an absent route is fine).
            return rc == 0 || (create && rc == 5010) || (!create && rc == 1168);
        }
        catch { return false; }
        finally { Marshal.FreeHGlobal(row); }
    }

    public void SetDns(string alias, IReadOnlyList<string> servers)
    {
        if (servers.Count == 0) return;
        // A failed DNS apply is the single most consequential "optional" failure here:
        // the tunnel carries traffic while name resolution keeps going to the physical
        // resolver, which is both a privacy leak and the classic "VPN is on but sites
        // resolve wrong" symptom. It was logged as success regardless. (C-17)
        bool primaryOk = Run("netsh",
            $"interface ipv4 set dnsservers name=\"{alias}\" static {servers[0]} primary validate=no",
            optional: true);
        if (!primaryOk)
        {
            Degrade($"DNS NOT applied to \"{alias}\" — queries will use the system resolver, " +
                    $"not the tunnel's ({string.Join(", ", servers)})");
            return;
        }
        for (int i = 1; i < servers.Count; i++)
        {
            if (!Run("netsh",
                    $"interface ipv4 add dnsservers name=\"{alias}\" {servers[i]} index={i + 1} validate=no",
                    optional: true))
                Degrade($"secondary DNS {servers[i]} not applied");
        }
        _undo.Add(() => Run("netsh", $"interface ipv4 set dnsservers name=\"{alias}\" dhcp", optional: true));
        _log($"DNS set to {string.Join(", ", servers)}");
    }

    public void Dispose()
    {
        // Undo in reverse order, best-effort.
        for (int i = _undo.Count - 1; i >= 0; i--)
        {
            try { _undo[i](); } catch (Exception e) { _log($"undo error: {e.Message}"); }
        }
        _undo.Clear();
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
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
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
        if (slash < 0) return IsStrictIp(cidr) ? (cidr, 32) : (null, 0);
        string addr = cidr[..slash];
        if (!IsStrictIp(addr)) return (null, 0);
        return int.TryParse(cidr[(slash + 1)..], out int prefix) && prefix is >= 0 and <= 32
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
