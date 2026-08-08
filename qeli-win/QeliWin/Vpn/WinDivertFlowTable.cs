using System.Net;
using System.Net.Sockets;

namespace QeliWin.Vpn;

/// <summary>Per-flow state for WinDivert NAT reinjection. Indexed by the reverse 5-tuple
/// seen on tunnel→host replies (remote → clientIp:localPort), so parallel flows and
/// multiple NICs do not share a single <c>_lastAddr</c>/<c>_primaryIp</c>.</summary>
internal sealed class WinDivertFlowTable
{
    private readonly object _gate = new();
    private readonly Dictionary<FlowKey, FlowEntry> _byReverse = new();
    private readonly Dictionary<FragKey, FragEntry> _frags = new();
    private readonly TimeSpan _flowTtl;
    private readonly TimeSpan _dnsTtl;
    private DateTime _lastGc = DateTime.UtcNow;

    public WinDivertFlowTable(TimeSpan? flowTtl = null, TimeSpan? dnsTtl = null)
    {
        _flowTtl = flowTtl ?? TimeSpan.FromMinutes(2);
        _dnsTtl = dnsTtl ?? TimeSpan.FromSeconds(30);
    }

    public int FlowCount { get { lock (_gate) return _byReverse.Count; } }
    public int FragCount { get { lock (_gate) return _frags.Count; } }

    public void RememberOutbound(
        byte proto,
        IPAddress clientIp,
        IPAddress originalSrc,
        ushort localPort,
        IPAddress remoteIp,
        ushort remotePort,
        in WinDivertNative.WinDivertAddress addr,
        IPAddress? dnsOrigDst = null)
    {
        var key = new FlowKey(proto, remoteIp, remotePort, clientIp, localPort);
        lock (_gate)
        {
            MaybeGcUnlocked();
            _byReverse[key] = new FlowEntry
            {
                OriginalSrc = originalSrc,
                Addr = addr,
                DnsOrigDst = dnsOrigDst,
                LastSeen = DateTime.UtcNow,
                DnsExpires = dnsOrigDst != null ? DateTime.UtcNow + _dnsTtl : DateTime.MinValue,
            };
        }
    }

    public bool TryGetInbound(
        byte proto,
        IPAddress remoteIp,
        ushort remotePort,
        IPAddress clientIp,
        ushort localPort,
        out FlowEntry entry)
    {
        var key = new FlowKey(proto, remoteIp, remotePort, clientIp, localPort);
        lock (_gate)
        {
            MaybeGcUnlocked();
            if (!_byReverse.TryGetValue(key, out entry!)) return false;
            entry.LastSeen = DateTime.UtcNow;
            _byReverse[key] = entry;
            return true;
        }
    }

    public void RememberFrag(
        IPAddress src, IPAddress dst, byte proto, ushort ipId,
        PacketDisposition disposition, FlowKey? flowHint = null)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            _frags[new FragKey(src, dst, proto, ipId)] = new FragEntry
            {
                Disposition = disposition,
                FlowHint = flowHint,
                LastSeen = DateTime.UtcNow,
            };
        }
    }

    public bool TryGetFrag(
        IPAddress src, IPAddress dst, byte proto, ushort ipId,
        out FragEntry entry)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            if (!_frags.TryGetValue(new FragKey(src, dst, proto, ipId), out entry!))
                return false;
            entry.LastSeen = DateTime.UtcNow;
            _frags[new FragKey(src, dst, proto, ipId)] = entry;
            return true;
        }
    }

    private void MaybeGcUnlocked()
    {
        var now = DateTime.UtcNow;
        if (now - _lastGc < TimeSpan.FromSeconds(5)) return;
        _lastGc = now;
        foreach (var k in _byReverse.Where(kv => now - kv.Value.LastSeen > _flowTtl).Select(kv => kv.Key).ToList())
            _byReverse.Remove(k);
        foreach (var k in _frags.Where(kv => now - kv.Value.LastSeen > _flowTtl).Select(kv => kv.Key).ToList())
            _frags.Remove(k);
    }

    public readonly struct FlowKey : IEquatable<FlowKey>
    {
        public readonly byte Proto;
        public readonly IPAddress RemoteIp;
        public readonly ushort RemotePort;
        public readonly IPAddress LocalIp;
        public readonly ushort LocalPort;

        public FlowKey(byte proto, IPAddress remoteIp, ushort remotePort, IPAddress localIp, ushort localPort)
        {
            Proto = proto;
            RemoteIp = remoteIp;
            RemotePort = remotePort;
            LocalIp = localIp;
            LocalPort = localPort;
        }

        public bool Equals(FlowKey other) =>
            Proto == other.Proto
            && RemotePort == other.RemotePort
            && LocalPort == other.LocalPort
            && RemoteIp.Equals(other.RemoteIp)
            && LocalIp.Equals(other.LocalIp);

        public override bool Equals(object? obj) => obj is FlowKey k && Equals(k);
        public override int GetHashCode() => HashCode.Combine(Proto, RemoteIp, RemotePort, LocalIp, LocalPort);
    }

    public struct FlowEntry
    {
        public IPAddress OriginalSrc;
        public WinDivertNative.WinDivertAddress Addr;
        public IPAddress? DnsOrigDst;
        public DateTime LastSeen;
        public DateTime DnsExpires;

        public IPAddress? ActiveDnsOrigDst =>
            DnsOrigDst != null && DateTime.UtcNow <= DnsExpires ? DnsOrigDst : null;
    }

    public readonly struct FragKey : IEquatable<FragKey>
    {
        public readonly IPAddress Src, Dst;
        public readonly byte Proto;
        public readonly ushort Id;

        public FragKey(IPAddress src, IPAddress dst, byte proto, ushort id)
        {
            Src = src; Dst = dst; Proto = proto; Id = id;
        }

        public bool Equals(FragKey other) =>
            Proto == other.Proto && Id == other.Id && Src.Equals(other.Src) && Dst.Equals(other.Dst);
        public override bool Equals(object? obj) => obj is FragKey k && Equals(k);
        public override int GetHashCode() => HashCode.Combine(Src, Dst, Proto, Id);
    }

    public struct FragEntry
    {
        public PacketDisposition Disposition;
        public FlowKey? FlowHint;
        public DateTime LastSeen;
    }
}

/// <summary>What to do with a captured outbound packet.</summary>
internal enum PacketDisposition
{
    /// <summary>Rewrite and hand to the VPN tunnel.</summary>
    Tunnel,
    /// <summary>Reinject onto the wire (bypass VPN).</summary>
    Bypass,
    /// <summary>Drop — include fail-closed / IPv6 blackhole / VPN down.</summary>
    Drop,
}
