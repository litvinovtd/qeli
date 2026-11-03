using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Qeli.Shared.Vpn;

/// <summary>
/// Shared route_local contract for desktop clients. The canonical NetworkPlan contains the
/// broad RFC1918 routes; these helpers discover directly connected RFC1918 prefixes and
/// split each into two more-specific tunnel routes so an existing connected route cannot
/// win by longest-prefix matching. Operator routes are never deleted or replaced.
/// </summary>
public static class RouteLocalPolicy
{
    public static IReadOnlyList<string> DiscoverConnectedRfc1918Prefixes(
        string? excludedInterfaceName = null,
        uint excludedInterfaceIndex = 0,
        Action<string>? log = null)
    {
        NetworkInterface[] networkInterfaces;
        try
        {
            networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException error)
        {
            log?.Invoke(DiscoveryWarning("network-interface list", error));
            return Array.Empty<string>();
        }

        return DiscoverConnectedRfc1918PrefixesForTest(
            networkInterfaces.Select(networkInterface => new Ipv4InterfaceProbe(
                networkInterface.Name,
                () => ReadIpv4Interface(networkInterface))),
            excludedInterfaceName,
            excludedInterfaceIndex,
            log);
    }

    internal static IReadOnlyList<string> DiscoverConnectedRfc1918PrefixesForTest(
        IEnumerable<Ipv4InterfaceProbe> probes,
        string? excludedInterfaceName = null,
        uint excludedInterfaceIndex = 0,
        Action<string>? log = null)
    {
        var prefixes = new HashSet<string>();
        foreach (Ipv4InterfaceProbe probe in probes)
        {
            if (!string.IsNullOrWhiteSpace(excludedInterfaceName)
                && probe.Name.Equals(excludedInterfaceName, StringComparison.OrdinalIgnoreCase))
                continue;

            try
            {
                Ipv4InterfaceSnapshot? snapshot = probe.Read();
                if (snapshot == null)
                    continue;
                if (excludedInterfaceIndex != 0
                    && unchecked((uint)snapshot.InterfaceIndex) == excludedInterfaceIndex)
                    continue;

                foreach (Ipv4AddressSnapshot address in snapshot.Addresses)
                {
                    prefixes.Add($"{address.Address}/{address.PrefixLength}");
                }
            }
            catch (NetworkInformationException error)
            {
                // Windows exposes WFP/QoS/filter interfaces that are operational but do not
                // implement IPv4. A single such adapter must not reject the complete VPN
                // NetworkPlan; retain prefixes from healthy adapters and fail closed by
                // tunnelling an unknown private destination instead of bypassing it.
                log?.Invoke(DiscoveryWarning($"network interface '{probe.Name}'", error));
            }
        }
        return Qeli.Shared.Model.ConfigCore.Policy("private_prefixes", new { prefixes }).GetProperty("value")
            .EnumerateArray().Select(x=>x.GetString()!).ToArray();
    }

    private static Ipv4InterfaceSnapshot? ReadIpv4Interface(NetworkInterface networkInterface)
    {
        if (networkInterface.OperationalStatus != OperationalStatus.Up
            || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback
            || !networkInterface.Supports(NetworkInterfaceComponent.IPv4))
            return null;

        IPInterfaceProperties properties = networkInterface.GetIPProperties();
        IPv4InterfaceProperties ipv4 = properties.GetIPv4Properties();
        var addresses = properties.UnicastAddresses
            .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => new Ipv4AddressSnapshot(address.Address, address.PrefixLength))
            .ToArray();
        return new Ipv4InterfaceSnapshot(ipv4.Index, addresses);
    }

    private static string DiscoveryWarning(string source, NetworkInformationException error) =>
        $"WARN: skipped {source} while discovering connected IPv4 routes "
        + $"(NetworkInformation error {error.ErrorCode}: {error.Message})";

    internal sealed record Ipv4InterfaceProbe(
        string Name, Func<Ipv4InterfaceSnapshot?> Read);

    internal sealed record Ipv4InterfaceSnapshot(
        int InterfaceIndex, IReadOnlyList<Ipv4AddressSnapshot> Addresses);

    internal readonly record struct Ipv4AddressSnapshot(
        IPAddress Address, int PrefixLength);

    public static IReadOnlyList<string> BuildCapturePrefixes(
        IEnumerable<string> connectedPrefixes, IEnumerable<string>? excludeRoutes = null) =>
        Qeli.Shared.Model.ConfigCore.Policy("capture_prefixes", new { prefixes=connectedPrefixes, excludes=excludeRoutes ?? Array.Empty<string>() })
            .GetProperty("value").EnumerateArray().Select(x=>x.GetString()!).ToArray();
}
