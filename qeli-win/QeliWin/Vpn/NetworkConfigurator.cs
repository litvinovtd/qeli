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

    public NetworkConfigurator(Action<string> log) => _log = log;

    [DllImport("iphlpapi.dll")]
    private static extern int ConvertInterfaceLuidToIndex(ref ulong luid, out uint index);

    [DllImport("iphlpapi.dll")]
    private static extern int GetBestInterface(uint destAddr, out uint bestIfIndex);

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

    /// <summary>Find the physical default gateway used to reach <paramref name="serverIp"/>.</summary>
    public IPAddress? FindGatewayFor(IPAddress serverIp)
    {
        uint dest = BitConverter.ToUInt32(serverIp.GetAddressBytes(), 0);
        if (GetBestInterface(dest, out uint ifIndex) != 0) return null;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var p = ni.GetIPProperties();
                if ((uint)p.GetIPv4Properties().Index != ifIndex) continue;
                foreach (var gw in p.GatewayAddresses)
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !gw.Address.Equals(IPAddress.Any))
                        return gw.Address;
            }
            catch { /* skip */ }
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

    public uint PhysicalIfIndexFor(IPAddress serverIp)
    {
        uint dest = BitConverter.ToUInt32(serverIp.GetAddressBytes(), 0);
        return GetBestInterface(dest, out uint ifIndex) == 0 ? ifIndex : 0;
    }

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
    /// blackholed inside the tunnel rather than leaked — apps fall back to IPv4. We
    /// assign a ULA to the adapter and route ::/1 + 8000::/1 through it (two /1s beat
    /// the existing ::/0 without deleting it, mirroring the IPv4 split). All optional:
    /// a host with IPv6 disabled simply has nothing to capture. See RELEASE-FIXES E2.</summary>
    public void CaptureIPv6(string alias)
    {
        Run("netsh", $"interface ipv6 add address \"{alias}\" fd71:e1::1/64", optional: true);
        Run("netsh", $"interface ipv6 add route ::/1 \"{alias}\" metric=1", optional: true);
        Run("netsh", $"interface ipv6 add route 8000::/1 \"{alias}\" metric=1", optional: true);
        _undo.Add(() => Run("netsh", $"interface ipv6 delete route 8000::/1 \"{alias}\"", optional: true));
        _undo.Add(() => Run("netsh", $"interface ipv6 delete route ::/1 \"{alias}\"", optional: true));
        _undo.Add(() => Run("netsh", $"interface ipv6 delete address \"{alias}\" fd71:e1::1", optional: true));
        _log("IPv6 captured into tunnel (::/1 + 8000::/1) — no dual-stack leak");
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
            Run("route", $"add {addr} mask {mask} {clientIp} metric 1 if {tunIndex}", optional: true);
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
        Run("netsh", $"interface ipv4 set dnsservers name=\"{alias}\" static {servers[0]} primary validate=no", optional: true);
        for (int i = 1; i < servers.Count; i++)
            Run("netsh", $"interface ipv4 add dnsservers name=\"{alias}\" {servers[i]} index={i + 1} validate=no", optional: true);
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
    private void Run(string exe, string args, bool optional = false)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0 && !optional)
            throw new InvalidOperationException($"{exe} {args} -> exit {p.ExitCode}: {stdout}{stderr}".Trim());
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
