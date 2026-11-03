using System.Net;
using System.Net.Sockets;
namespace Qeli.Shared.Model;

/// <summary>Immutable addresses from a committed NetworkPlan; never parsed from status prose.</summary>
public sealed record DesktopTunnelAddresses(string? Ipv4 = null, string? Ipv6 = null)
{
    public static readonly DesktopTunnelAddresses Empty = new();
    public bool IsValid => Valid(Ipv4, AddressFamily.InterNetwork) && Valid(Ipv6, AddressFamily.InterNetworkV6);
    private static bool Valid(string? value, AddressFamily family) => value is null ||
        (value.Length <= 45 && IPAddress.TryParse(value, out var ip) && ip.AddressFamily == family
         && !ip.IsIPv4MappedToIPv6 && ip.ScopeIdOrZero() == 0 && !IPAddress.IsLoopback(ip)
         && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any));
}
internal static class AddressScope
{
    internal static long ScopeIdOrZero(this IPAddress ip) => ip.AddressFamily == AddressFamily.InterNetworkV6 ? ip.ScopeId : 0;
}
