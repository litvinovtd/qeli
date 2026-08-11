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
    private readonly Dictionary<OriginalFlowKey, FlowKey> _byForward = new();
    private readonly Dictionary<FragKey, FragEntry> _frags = new();
    private readonly Dictionary<FragKey, InboundFragEntry> _inboundFrags = new();
    private readonly Dictionary<Ipv6FragKey, FragEntry> _ipv6Frags = new();
    private readonly TimeSpan _tcpTtl;
    private readonly TimeSpan _udpTtl;
    private readonly TimeSpan _fragmentTtl;
    private readonly TimeSpan _tcpClosingTtl;
    private readonly int _maxFlows;
    private readonly int _maxFragments;
    private int _nextNatPort = 49152;
    private DateTime _lastGc = DateTime.UtcNow;

    public WinDivertFlowTable(
        TimeSpan? tcpTtl = null,
        TimeSpan? udpTtl = null,
        TimeSpan? fragmentTtl = null,
        TimeSpan? tcpClosingTtl = null,
        int maxFlows = 65_536,
        int maxFragments = 16_384)
    {
        // TCP connections routinely remain idle for more than two minutes (SSH, IMAP,
        // database pools). UDP remains deliberately short-lived. DNS reverse-NAT state is
        // part of the flow and therefore has the same lifetime instead of an unrelated
        // 30-second timeout that could corrupt a delayed/retried reply.
        _tcpTtl = tcpTtl ?? TimeSpan.FromHours(2);
        _udpTtl = udpTtl ?? TimeSpan.FromMinutes(2);
        _fragmentTtl = fragmentTtl ?? TimeSpan.FromSeconds(30);
        _tcpClosingTtl = tcpClosingTtl ?? TimeSpan.FromMinutes(2);
        _maxFlows = Math.Max(1, maxFlows);
        _maxFragments = Math.Max(1, maxFragments);
    }

    public int FlowCount { get { lock (_gate) return _byReverse.Count; } }
    public int FragCount { get { lock (_gate) return _frags.Count; } }

    public void Clear()
    {
        lock (_gate)
        {
            _byReverse.Clear();
            _byForward.Clear();
            _frags.Clear();
            _inboundFrags.Clear();
            _ipv6Frags.Clear();
            _lastGc = DateTime.UtcNow;
        }
    }

    /// <summary>Remember an outbound flow and return the source port exposed inside the
    /// tunnel. The original port is retained whenever possible; a collision caused by two
    /// local addresses sharing the same 4-tuple gets a private translated port so replies
    /// remain unambiguous.</summary>
    public ushort RememberOutbound(
        byte proto,
        IPAddress clientIp,
        IPAddress originalSrc,
        ushort localPort,
        IPAddress remoteIp,
        ushort remotePort,
        in WinDivertNative.WinDivertAddress addr,
        IPAddress? dnsOrigDst = null,
        bool tcpFin = false,
        bool tcpRst = false)
    {
        var forward = new OriginalFlowKey(
            proto, originalSrc, localPort, remoteIp, remotePort, clientIp, dnsOrigDst);
        lock (_gate)
        {
            MaybeGcUnlocked();
            var now = DateTime.UtcNow;
            if (_byForward.TryGetValue(forward, out var existingKey)
                && _byReverse.TryGetValue(existingKey, out var existing))
            {
                existing.OriginalSrc = originalSrc;
                existing.OriginalLocalPort = localPort;
                existing.Addr = addr;
                existing.DnsOrigDst = dnsOrigDst;
                existing.LastSeen = now;
                if (tcpFin) { existing.OutboundFin = true; existing.ClosingSince ??= now; }
                _byReverse[existingKey] = existing;
                ushort translated = existingKey.LocalPort;
                // A bidirectional FIN exchange is not the end of a TCP flow: the final ACK
                // still has to use the same NAT mapping. Keep it under tcpClosingTtl; only
                // RST is terminal immediately.
                if (tcpRst) RemoveUnlocked(existingKey);
                return translated;
            }

            EnsureFlowCapacityUnlocked();
            ushort translatedPort = localPort;
            var key = new FlowKey(proto, remoteIp, remotePort, clientIp, translatedPort);
            if (_byReverse.ContainsKey(key))
            {
                translatedPort = AllocateNatPortUnlocked(proto, remoteIp, remotePort, clientIp);
                if (translatedPort == 0) return 0;
                key = new FlowKey(proto, remoteIp, remotePort, clientIp, translatedPort);
            }
            _byReverse[key] = new FlowEntry
            {
                OriginalSrc = originalSrc,
                OriginalLocalPort = localPort,
                Addr = addr,
                DnsOrigDst = dnsOrigDst,
                LastSeen = now,
                OutboundFin = tcpFin,
                ClosingSince = tcpFin ? now : null,
                ForwardKey = forward,
            };
            _byForward[forward] = key;
            if (tcpRst) RemoveUnlocked(key);
            return translatedPort;
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

    public void ObserveInboundTcp(
        IPAddress remoteIp, ushort remotePort, IPAddress clientIp, ushort translatedLocalPort,
        bool fin, bool rst)
    {
        var key = new FlowKey(6, remoteIp, remotePort, clientIp, translatedLocalPort);
        lock (_gate)
        {
            if (!_byReverse.TryGetValue(key, out var entry)) return;
            if (rst) { RemoveUnlocked(key); return; }
            if (fin)
            {
                entry.InboundFin = true;
                entry.ClosingSince ??= DateTime.UtcNow;
                _byReverse[key] = entry;
            }
        }
    }

    public void RememberFrag(
        IPAddress src, IPAddress dst, byte proto, ushort ipId,
        PacketDisposition disposition)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            EnsureFragmentCapacityUnlocked(_frags, entry => entry.LastSeen);
            _frags[new FragKey(src, dst, proto, ipId)] = new FragEntry
            {
                Disposition = disposition,
                LastSeen = DateTime.UtcNow,
            };
        }
    }

    public void RememberIpv6Frag(
        IPAddress src, IPAddress dst, byte proto, uint fragmentId,
        PacketDisposition disposition)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            EnsureFragmentCapacityUnlocked(_ipv6Frags, entry => entry.LastSeen);
            _ipv6Frags[new Ipv6FragKey(src, dst, proto, fragmentId)] = new FragEntry
            {
                Disposition = disposition,
                LastSeen = DateTime.UtcNow,
            };
        }
    }

    public bool TryGetIpv6Frag(
        IPAddress src, IPAddress dst, byte proto, uint fragmentId,
        out PacketDisposition disposition)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            var key = new Ipv6FragKey(src, dst, proto, fragmentId);
            if (!_ipv6Frags.TryGetValue(key, out var entry))
            {
                disposition = default;
                return false;
            }
            entry.LastSeen = DateTime.UtcNow;
            _ipv6Frags[key] = entry;
            disposition = entry.Disposition;
            return true;
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

    public void SetFragTunnelDestination(
        IPAddress src, IPAddress dst, byte proto, ushort ipId, IPAddress tunnelDestination)
    {
        lock (_gate)
        {
            var key = new FragKey(src, dst, proto, ipId);
            if (!_frags.TryGetValue(key, out var entry)) return;
            entry.TunnelDestination = tunnelDestination;
            entry.LastSeen = DateTime.UtcNow;
            _frags[key] = entry;
        }
    }

    /// <summary>Remember the reverse-NAT target selected by the first inbound fragment.
    /// Later fragments do not contain TCP/UDP ports, so without this association they were
    /// all dropped and fragmented replies stalled.</summary>
    public void RememberInboundFrag(
        IPAddress src, IPAddress dst, byte proto, ushort ipId, in FlowEntry flow)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            EnsureFragmentCapacityUnlocked(_inboundFrags, entry => entry.LastSeen);
            _inboundFrags[new FragKey(src, dst, proto, ipId)] = new InboundFragEntry
            {
                Flow = flow,
                LastSeen = DateTime.UtcNow,
            };
        }
    }

    public bool TryGetInboundFrag(
        IPAddress src, IPAddress dst, byte proto, ushort ipId, out FlowEntry flow)
    {
        lock (_gate)
        {
            MaybeGcUnlocked();
            var key = new FragKey(src, dst, proto, ipId);
            if (!_inboundFrags.TryGetValue(key, out var entry))
            {
                flow = default;
                return false;
            }
            entry.LastSeen = DateTime.UtcNow;
            _inboundFrags[key] = entry;
            flow = entry.Flow;
            return true;
        }
    }

    private void MaybeGcUnlocked()
    {
        var now = DateTime.UtcNow;
        if (now - _lastGc < TimeSpan.FromSeconds(5)) return;
        _lastGc = now;
        GcUnlocked(now);
    }

    private void GcUnlocked(DateTime now)
    {
        foreach (var k in _byReverse.Where(kv =>
                     now - kv.Value.LastSeen > (kv.Key.Proto == 6 ? _tcpTtl : _udpTtl)
                     || (kv.Value.ClosingSince is { } closing
                         && now - closing > _tcpClosingTtl))
                 .Select(kv => kv.Key).ToList())
            RemoveUnlocked(k);
        foreach (var k in _frags.Where(kv => now - kv.Value.LastSeen > _fragmentTtl).Select(kv => kv.Key).ToList())
            _frags.Remove(k);
        foreach (var k in _inboundFrags.Where(kv => now - kv.Value.LastSeen > _fragmentTtl).Select(kv => kv.Key).ToList())
            _inboundFrags.Remove(k);
        foreach (var k in _ipv6Frags.Where(kv => now - kv.Value.LastSeen > _fragmentTtl).Select(kv => kv.Key).ToList())
            _ipv6Frags.Remove(k);
    }

    private void EnsureFlowCapacityUnlocked()
    {
        while (_byReverse.Count >= _maxFlows && _byReverse.Count > 0)
        {
            var oldest = _byReverse.MinBy(kv => kv.Value.LastSeen).Key;
            RemoveUnlocked(oldest);
        }
    }

    private void EnsureFragmentCapacityUnlocked<TKey, TValue>(
        Dictionary<TKey, TValue> table, Func<TValue, DateTime> lastSeen)
        where TKey : notnull
    {
        while (table.Count >= _maxFragments && table.Count > 0)
        {
            TKey oldest = table.MinBy(kv => lastSeen(kv.Value)).Key;
            table.Remove(oldest);
        }
    }

    private ushort AllocateNatPortUnlocked(
        byte proto, IPAddress remoteIp, ushort remotePort, IPAddress clientIp)
    {
        for (int attempt = 0; attempt < ushort.MaxValue - 1023; attempt++)
        {
            int candidate = _nextNatPort++;
            if (_nextNatPort > ushort.MaxValue) _nextNatPort = 1024;
            if (candidate < 1024) continue;
            var key = new FlowKey(proto, remoteIp, remotePort, clientIp, (ushort)candidate);
            if (!_byReverse.ContainsKey(key)) return (ushort)candidate;
        }
        return 0;
    }

    private void RemoveUnlocked(FlowKey key)
    {
        if (!_byReverse.Remove(key, out var entry)) return;
        _byForward.Remove(entry.ForwardKey);
    }

    internal void CollectExpiredForTest(DateTime now)
    {
        lock (_gate)
        {
            GcUnlocked(now);
            _lastGc = now;
        }
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
        public ushort OriginalLocalPort;
        public WinDivertNative.WinDivertAddress Addr;
        public IPAddress? DnsOrigDst;
        public DateTime LastSeen;
        public DateTime? ClosingSince;
        public bool OutboundFin;
        public bool InboundFin;
        internal OriginalFlowKey ForwardKey;
    }

    internal readonly struct OriginalFlowKey : IEquatable<OriginalFlowKey>
    {
        public readonly byte Proto;
        public readonly IPAddress OriginalSrc, RemoteIp, ClientIp;
        public readonly IPAddress? DnsOrigDst;
        public readonly ushort OriginalLocalPort, RemotePort;

        public OriginalFlowKey(
            byte proto, IPAddress originalSrc, ushort originalLocalPort,
            IPAddress remoteIp, ushort remotePort, IPAddress clientIp, IPAddress? dnsOrigDst)
        {
            Proto = proto; OriginalSrc = originalSrc; OriginalLocalPort = originalLocalPort;
            RemoteIp = remoteIp; RemotePort = remotePort; ClientIp = clientIp;
            DnsOrigDst = dnsOrigDst;
        }

        public bool Equals(OriginalFlowKey other) =>
            Proto == other.Proto && OriginalLocalPort == other.OriginalLocalPort
            && RemotePort == other.RemotePort && OriginalSrc.Equals(other.OriginalSrc)
            && RemoteIp.Equals(other.RemoteIp) && ClientIp.Equals(other.ClientIp)
            && Equals(DnsOrigDst, other.DnsOrigDst);
        public override bool Equals(object? obj) => obj is OriginalFlowKey other && Equals(other);
        public override int GetHashCode() => HashCode.Combine(
            Proto, OriginalSrc, OriginalLocalPort, RemoteIp, RemotePort, ClientIp, DnsOrigDst);
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
        public IPAddress? TunnelDestination;
        public DateTime LastSeen;
    }

    public readonly struct Ipv6FragKey : IEquatable<Ipv6FragKey>
    {
        public readonly IPAddress Src, Dst;
        public readonly byte Proto;
        public readonly uint Id;

        public Ipv6FragKey(IPAddress src, IPAddress dst, byte proto, uint id)
        {
            Src = src; Dst = dst; Proto = proto; Id = id;
        }

        public bool Equals(Ipv6FragKey other) =>
            Proto == other.Proto && Id == other.Id && Src.Equals(other.Src) && Dst.Equals(other.Dst);
        public override bool Equals(object? obj) => obj is Ipv6FragKey other && Equals(other);
        public override int GetHashCode() => HashCode.Combine(Src, Dst, Proto, Id);
    }

    private struct InboundFragEntry
    {
        public FlowEntry Flow;
        public DateTime LastSeen;
    }
}

/// <summary>What to do with a captured outbound packet.</summary>
internal enum PacketDisposition
{
    /// <summary>Owner snapshot has not observed this socket yet; never emit to a NIC.</summary>
    Unknown,
    /// <summary>Rewrite and hand to the VPN tunnel.</summary>
    Tunnel,
    /// <summary>Reinject onto the wire (bypass VPN).</summary>
    Bypass,
    /// <summary>Drop — include fail-closed / IPv6 blackhole / VPN down.</summary>
    Drop,
}
