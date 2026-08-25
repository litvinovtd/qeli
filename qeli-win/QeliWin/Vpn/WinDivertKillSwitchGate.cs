using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Kernel drop gate that makes the Windows kill-switch a real allow-list even
/// when pre-existing firewall Allow rules are present. Matching packets are
/// discarded by WinDivert itself (WINDIVERT_FLAG_DROP), so no carrier traffic is
/// copied through userspace and the VPN throughput path is unchanged.
/// </summary>
internal sealed class WinDivertKillSwitchGate : IDisposable
{
    // WinDivert accepts priorities only in [-300, 300]. The drop gate must run before the
    // normal priority-0 per-app handle so blocked carrier traffic cannot be re-injected by
    // another Qeli handle first.
    internal static readonly short DropGatePriority = 300;

    private IntPtr _handle;

    private WinDivertKillSwitchGate(IntPtr handle) => _handle = handle;

    public static WinDivertKillSwitchGate Open(
        string tunAlias,
        IEnumerable<string> serverAddresses,
        IEnumerable<string> dnsAddresses)
    {
        uint tunIndex = ResolveInterfaceIndex(tunAlias);
        if (tunIndex == 0)
            throw new InvalidOperationException(
                $"kill-switch: cannot resolve Wintun interface index for '{tunAlias}'");

        WinDivertAdapter.EnsureDriverLoaded();
        string filter = BuildFilter(tunIndex, serverAddresses, dnsAddresses);
        IntPtr handle = WinDivertNative.WinDivertOpen(
            filter,
            WinDivertNative.WINDIVERT_LAYER_NETWORK,
            priority: DropGatePriority,
            WinDivertNative.WINDIVERT_FLAG_DROP);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            int error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                error == 5
                    ? "kill-switch: WinDivert access denied — run Qeli elevated"
                    : $"kill-switch: WinDivert drop gate failed (Win32 {error}); "
                      + "the strict physical-interface allow-list was not installed");
        }
        return new WinDivertKillSwitchGate(handle);
    }

    internal static string BuildFilter(
        uint tunIndex,
        IEnumerable<string> serverAddresses,
        IEnumerable<string> dnsAddresses)
    {
        if (tunIndex == 0) throw new ArgumentOutOfRangeException(nameof(tunIndex));
        var servers = ParseAddresses(serverAddresses);
        if (servers.Count == 0)
            throw new InvalidOperationException("kill-switch: server allow-list is empty");
        var resolvers = ParseAddresses(dnsAddresses);

        static string AddressClause(IPAddress address) =>
            address.AddressFamily == AddressFamily.InterNetwork
                ? $"(ip and ip.DstAddr == {address})"
                : $"(ipv6 and ipv6.DstAddr == {address})";

        string server = string.Join(" or ", servers.Select(AddressClause));
        string dns = resolvers.Count == 0
            ? "false"
            : $"((tcp.DstPort == 53 or udp.DstPort == 53) and ({string.Join(" or ", resolvers.Select(AddressClause))}))";
        // Permit DHCPv4/v6 discovery. Everything else leaving a physical interface
        // matches this expression and is dropped in the driver. Packets routed to
        // the Wintun index never match and continue into the encrypted tunnel.
        string allowed = $"({server}) or ({dns}) or (udp.DstPort == 67 or udp.DstPort == 547)";
        return $"outbound and !loopback and ifIdx != {tunIndex} and not ({allowed})";
    }

    private static List<IPAddress> ParseAddresses(IEnumerable<string> values) =>
        values.Select(value => IPAddress.TryParse(value, out var address) ? address : null)
            .Where(address => address is not null)
            .Cast<IPAddress>()
            .Distinct()
            .ToList();

    private static uint ResolveInterfaceIndex(string alias)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!nic.Name.Equals(alias, StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var properties = nic.GetIPProperties();
                int index = properties.GetIPv4Properties()?.Index
                    ?? properties.GetIPv6Properties()?.Index
                    ?? 0;
                if (index > 0) return checked((uint)index);
            }
            catch { }
        }
        return 0;
    }

    public void Dispose()
    {
        IntPtr handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            try { WinDivertNative.WinDivertClose(handle); } catch { }
    }
}
