using System.Net;
using System.Net.Sockets;

namespace QeliWin.Vpn;

/// <summary>
/// Decides whether a destination should skip the per-app tunnel path entirely
/// (LAN / link-local / excluded) or remain subject to the app filter.
/// Unlike the old unconditional RFC1918 bypass, private ranges go through the
/// tunnel when <c>route_local</c>, a user <c>include</c>, or a server-pushed
/// route covers them.
/// </summary>
internal sealed class WinDivertDestinationPolicy
{
    private readonly List<Cidr> _tunnelPrivate = new();
    private readonly List<Cidr> _exclude = new();

    public WinDivertDestinationPolicy(
        bool routeLocal,
        IEnumerable<string>? includeRoutes,
        IEnumerable<string>? excludeRoutes,
        IEnumerable<string>? pushedRoutes)
    {
        if (routeLocal)
        {
            AddTunnel("10.0.0.0/8");
            AddTunnel("172.16.0.0/12");
            AddTunnel("192.168.0.0/16");
        }
        if (includeRoutes != null)
            foreach (var c in includeRoutes) AddTunnel(c);
        if (pushedRoutes != null)
            foreach (var c in pushedRoutes) AddTunnel(c);
        if (excludeRoutes != null)
            foreach (var c in excludeRoutes) AddExclude(c);
    }

    /// <summary>True → reinject without app filtering (keep on physical path).</summary>
    public bool ShouldBypassTunnel(IPAddress dst)
    {
        if (dst.AddressFamily == AddressFamily.InterNetworkV6)
            return IsIpv6LinkLocalOrLoopback(dst);

        if (IsIpv4LoopbackOrLinkLocal(dst)) return true;
        if (Matches(_exclude, dst)) return true;
        if (IsRfc1918(dst))
            return !Matches(_tunnelPrivate, dst);
        return false;
    }

    public static bool IsRfc1918(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        if (b[0] == 10) return true;
        if (b[0] == 172 && b[1] is >= 16 and <= 31) return true;
        if (b[0] == 192 && b[1] == 168) return true;
        return false;
    }

    public static bool IsIpv4LoopbackOrLinkLocal(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = ip.GetAddressBytes();
        if (b[0] == 127) return true;
        if (b[0] == 169 && b[1] == 254) return true;
        return false;
    }

    public static bool IsIpv6LinkLocalOrLoopback(IPAddress ip)
    {
        if (ip.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        // fe80::/10
        return b[0] == 0xfe && (b[1] & 0xc0) == 0x80;
    }

    private void AddTunnel(string cidr)
    {
        if (TryParseCidr(cidr, out var c) && c.Address.AddressFamily == AddressFamily.InterNetwork)
            _tunnelPrivate.Add(c);
    }

    private void AddExclude(string cidr)
    {
        if (TryParseCidr(cidr, out var c))
            _exclude.Add(c);
    }

    private static bool Matches(List<Cidr> list, IPAddress ip)
    {
        foreach (var c in list)
            if (c.Contains(ip)) return true;
        return false;
    }

    public static bool TryParseCidr(string text, out Cidr cidr)
    {
        cidr = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim();
        int slash = text.IndexOf('/');
        string addrPart = slash < 0 ? text : text[..slash];
        if (!IPAddress.TryParse(addrPart, out var addr) || addr == null) return false;
        int prefix;
        if (slash < 0)
            prefix = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        else if (!int.TryParse(text[(slash + 1)..], out prefix))
            return false;
        int max = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max) return false;
        cidr = new Cidr(addr, prefix);
        return true;
    }

    public readonly struct Cidr
    {
        public readonly IPAddress Address;
        public readonly int Prefix;

        public Cidr(IPAddress address, int prefix)
        {
            Address = address;
            Prefix = prefix;
        }

        public bool Contains(IPAddress ip)
        {
            if (ip.AddressFamily != Address.AddressFamily) return false;
            var a = Address.GetAddressBytes();
            var b = ip.GetAddressBytes();
            int full = Prefix / 8;
            int rem = Prefix % 8;
            for (int i = 0; i < full; i++)
                if (a[i] != b[i]) return false;
            if (rem == 0) return true;
            int mask = 0xFF << (8 - rem);
            return (a[full] & mask) == (b[full] & mask);
        }
    }
}
