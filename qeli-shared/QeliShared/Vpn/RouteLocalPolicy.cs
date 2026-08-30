using System.Buffers.Binary;
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
    private static readonly Ipv4Cidr[] Rfc1918 =
    {
        ParseIpv4("10.0.0.0/8"),
        ParseIpv4("172.16.0.0/12"),
        ParseIpv4("192.168.0.0/16"),
    };

    public static IReadOnlyList<string> DiscoverConnectedRfc1918Prefixes(
        string? excludedInterfaceName = null,
        uint excludedInterfaceIndex = 0)
    {
        var prefixes = new HashSet<Ipv4Cidr>();
        foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up
                || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback
                || (!string.IsNullOrWhiteSpace(excludedInterfaceName)
                    && networkInterface.Name.Equals(
                        excludedInterfaceName, StringComparison.OrdinalIgnoreCase)))
                continue;

            IPInterfaceProperties properties = networkInterface.GetIPProperties();
            int interfaceIndex = properties.GetIPv4Properties()?.Index ?? 0;
            if (excludedInterfaceIndex != 0 && interfaceIndex == excludedInterfaceIndex)
                continue;

            foreach (UnicastIPAddressInformation address in properties.UnicastAddresses)
            {
                if (address.Address.AddressFamily != AddressFamily.InterNetwork)
                    continue;
                if (!TryParseIpv4($"{address.Address}/{address.PrefixLength}", out var cidr))
                    continue;
                if (Rfc1918.Any(root => Contains(root, cidr)))
                    prefixes.Add(cidr);
            }
        }
        return prefixes.OrderBy(value => value.Network)
            .ThenBy(value => value.Prefix)
            .Select(Render)
            .ToArray();
    }

    public static IReadOnlyList<string> BuildCapturePrefixes(
        IEnumerable<string> connectedPrefixes,
        IEnumerable<string>? excludeRoutes = null)
    {
        var excludes = (excludeRoutes ?? Array.Empty<string>())
            .Select(text => TryParseIpv4(text, out var cidr) ? cidr : (Ipv4Cidr?)null)
            .Where(value => value.HasValue)
            .Select(value => value!.Value)
            .ToArray();
        var captures = new HashSet<Ipv4Cidr>();
        foreach (string text in connectedPrefixes)
        {
            if (!TryParseIpv4(text, out var connected)
                || connected.Prefix >= 32
                || !Rfc1918.Any(root => Contains(root, connected)))
                continue;

            int childPrefix = connected.Prefix + 1;
            uint secondNetwork = connected.Network | (1u << (32 - childPrefix));
            foreach (var child in new[]
            {
                new Ipv4Cidr(connected.Network, childPrefix),
                new Ipv4Cidr(secondNetwork, childPrefix),
            })
            {
                // A broader/equal physical exclusion wins only if this capture route is
                // omitted. A narrower exclusion remains more-specific than the child and
                // is installed by the ordinary platform exclusion path afterwards.
                if (!excludes.Any(exclude => Contains(exclude, child)))
                    captures.Add(child);
            }
        }
        return captures.OrderBy(value => value.Network)
            .ThenBy(value => value.Prefix)
            .Select(Render)
            .ToArray();
    }

    private static Ipv4Cidr ParseIpv4(string text) =>
        TryParseIpv4(text, out var cidr)
            ? cidr
            : throw new InvalidOperationException($"invalid built-in IPv4 CIDR '{text}'");

    private static bool TryParseIpv4(string text, out Ipv4Cidr cidr)
    {
        cidr = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        string[] fields = text.Trim().Split('/', 2);
        if (!IPAddress.TryParse(fields[0], out IPAddress? address)
            || address.AddressFamily != AddressFamily.InterNetwork)
            return false;
        int prefix = 32;
        if (fields.Length == 2 && (!int.TryParse(fields[1], out prefix) || prefix is < 0 or > 32))
            return false;
        uint raw = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        uint mask = PrefixMask(prefix);
        cidr = new Ipv4Cidr(raw & mask, prefix);
        return true;
    }

    private static bool Contains(Ipv4Cidr outer, Ipv4Cidr inner) =>
        outer.Prefix <= inner.Prefix
        && (inner.Network & PrefixMask(outer.Prefix)) == outer.Network;

    private static uint PrefixMask(int prefix) =>
        prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);

    private static string Render(Ipv4Cidr cidr)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, cidr.Network);
        return $"{new IPAddress(bytes)}/{cidr.Prefix}";
    }

    private readonly record struct Ipv4Cidr(uint Network, int Prefix);
}
