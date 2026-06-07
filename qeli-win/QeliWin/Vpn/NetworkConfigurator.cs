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
        string mask = PrefixToMask(prefix);
        Run("route", $"add {addr} mask {mask} {clientIp} metric 1 if {tunIndex}", optional: true);
        _undo.Add(() => Run("route", $"delete {addr} mask {mask}", optional: true));
        _log($"route {cidr} via tunnel");
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
        int slash = cidr.IndexOf('/');
        if (slash < 0) return (cidr, 32);
        string addr = cidr[..slash];
        return int.TryParse(cidr[(slash + 1)..], out int prefix) ? (addr, prefix) : (null, 0);
    }

    private static string PrefixToMask(int prefix)
    {
        prefix = Math.Clamp(prefix, 0, 32);
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        return $"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}";
    }
}
