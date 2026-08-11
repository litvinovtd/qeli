using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Qeli.Shared.Vpn;

namespace QeliWin.Vpn;

/// <summary>
/// WinDivert-backed <see cref="ITunDevice"/> for per-app split tunnelling.
/// Captures outbound IPv4/IPv6, classifies by owning process via a full endpoint map,
/// tracks each flow (orig src IP, IfIdx, ports, DNS state), NAT-rewrites tunnelled IPv4
/// to the session client IP, and reinjects replies inbound on the correct interface.
/// Include mode is fail-closed; IPv6 of selected apps is dropped when
/// <c>allow_ipv6_leak</c> is false (server is IPv4-only).
/// </summary>
public sealed class WinDivertAdapter : IPacketTunDevice
{
    private readonly ProcessAppMap _apps;
    private readonly WinDivertFlowTable _flows = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.Ipv6FragKey, CapturedFragment>
        _pendingIpv6 = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.FragKey, CapturedFragment>
        _pendingOutboundIpv4 = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.FragKey, byte[]>
        _pendingInboundIpv4 = new();
    private WinDivertDestinationPolicy _dest;
    private readonly IPAddress _clientIp;
    private IReadOnlyList<IPAddress> _dnsServers;
    private readonly bool _allowIpv6Leak;
    private readonly Action<string>? _log;
    private CarrierEndpoint _carrier;
    private volatile int _tunnelMtu;
    private readonly byte[] _captureBuffer = new byte[0xFFFF];
    private readonly byte[] _injectBuffer = new byte[0xFFFF];
    private readonly Channel<PacketLease> _uplink = Channel.CreateBounded<PacketLease>(
        new BoundedChannelOptions(1024)
        {
            SingleWriter = true,
            SingleReader = false, // reconnect can briefly overlap a cancelling reader
            FullMode = BoundedChannelFullMode.Wait,
        });
    private Thread? _captureThread;
    private IntPtr _handle = IntPtr.Zero;
    private readonly object _gate = new();
    private volatile bool _disposed;
    private volatile bool _tunnelUp;
    private long _captured;
    private long _tunnelled;
    private long _bypassed;
    private long _policyDrops;
    private long _downDrops;
    private long _queueDrops;
    private long _mtuDrops;
    private long _fragmentedPackets;
    private long _icmpPacketTooBig;
    private long _replyInjected;
    private long _replyDrops;
    private long _earlyFragmentsBuffered;
    private long _reorderedFragmentsReleased;

    public WinDivertAdapter(
        IPAddress clientIp,
        IEnumerable<string> apps,
        bool includeMode,
        IEnumerable<string> dnsServers,
        bool allowIpv6Leak,
        bool routeLocal,
        IEnumerable<string>? includeRoutes,
        IEnumerable<string>? excludeRoutes,
        IEnumerable<string>? pushedRoutes,
        IPAddress carrierIp,
        int carrierPort,
        string carrierProtocol,
        int tunnelMtu,
        Action<string>? log = null)
    {
        _clientIp = clientIp;
        _apps = new ProcessAppMap(apps, includeMode);
        _allowIpv6Leak = allowIpv6Leak;
        _dest = new WinDivertDestinationPolicy(routeLocal, includeRoutes, excludeRoutes, pushedRoutes);
        _dnsServers = ParseDns(dnsServers);
        _carrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
        _tunnelMtu = ValidateMtu(tunnelMtu);
        _log = log;
    }

    /// <summary>Mark the VPN data plane down — include traffic is dropped, not reinjected.</summary>
    public void SetTunnelUp(bool up)
    {
        _tunnelUp = up;
        if (!up) DrainUplink();
    }

    /// <summary>Refresh authenticated policy while retaining the capture handle across a
    /// reconnect. NAT/fragment entries from an old native generation must never be reused.</summary>
    public void Reconfigure(
        IEnumerable<string> dnsServers,
        bool routeLocal,
        IEnumerable<string>? includeRoutes,
        IEnumerable<string>? excludeRoutes,
        IEnumerable<string>? pushedRoutes,
        IPAddress carrierIp,
        int carrierPort,
        string carrierProtocol,
        int tunnelMtu)
    {
        SetTunnelUp(false);
        _dnsServers = ParseDns(dnsServers);
        _dest = new WinDivertDestinationPolicy(
            routeLocal, includeRoutes, excludeRoutes, pushedRoutes);
        _carrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
        _tunnelMtu = ValidateMtu(tunnelMtu);
        _flows.Clear();
        _pendingIpv6.Clear();
        _pendingOutboundIpv4.Clear();
        _pendingInboundIpv4.Clear();
        _log?.Invoke($"WinDivert policy refreshed after reconnect (carrier {_carrier.Ip}:{_carrier.Port})");
    }

    public void Open()
    {
        if (_apps.SelectedCount == 0)
            throw new InvalidOperationException(
                "per-app profile contains no Windows executable paths; select at least one .exe "
                + "on this device (foreign app identifiers are preserved but cannot be applied here)");
        int addrSize = Marshal.SizeOf<WinDivertNative.WinDivertAddress>();
        if (addrSize != 80)
            throw new InvalidOperationException(
                $"WinDivertAddress layout mismatch: got {addrSize} bytes, expected 80 (WinDivert 2.2).");

        EnsureDriverLoaded();
        // Capture both IPv4 and IPv6. Do NOT put private-net exclusions in the filter —
        // WinDivert's filter compiler rejects that form; DestinationPolicy decides in
        // ReceivePacket. The qeli carrier is bypassed by its exact endpoint and process
        // ownership; mutating TTL/HopLimit is neither necessary nor a reliable recursion
        // guard (and the old IPv4/IPv6 OR expression captured the carrier anyway).
        string filter = "outbound and !loopback";

        _handle = WinDivertNative.WinDivertOpen(filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, 0, 0);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            int err = Marshal.GetLastWin32Error();
            string detail = CompileFilterError(filter);
            throw new InvalidOperationException(
                err == 5
                    ? "WinDivert access denied — run Qeli elevated (administrator)."
                    : $"WinDivertOpen failed (Win32 {err}){detail}. Is WinDivert64.sys loadable?");
        }
        try
        {
            WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
            WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_TIME, 2000);
            WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_SIZE, 8 * 1024 * 1024);
        }
        catch { /* best-effort */ }

        if (!_apps.HasPathMatches)
            _log?.Invoke("split-tunnel WARNING: no running process matched the app list — " +
                         (_apps.SelectedCount > 0
                             ? "check that the selected .exe paths are installed/running"
                             : "app list is empty"));
        _log?.Invoke(
            $"WinDivert per-app filter open (client {_clientIp}, {_apps.SelectedCount} app path(s), " +
            $"include={_apps.IncludeMode}, allow_ipv6_leak={_allowIpv6Leak}, mtu={_tunnelMtu})");
        _captureThread = new Thread(CaptureLoop)
        {
            IsBackground = true,
            Name = "qeli-windivert-capture",
        };
        _captureThread.Start();
    }

    private static string CompileFilterError(string filter)
    {
        try
        {
            if (WinDivertNative.WinDivertHelperCompileFilter(filter,
                    WinDivertNative.WINDIVERT_LAYER_NETWORK, IntPtr.Zero, 0,
                    out IntPtr errStr, out uint errPos)
                || errStr == IntPtr.Zero)
                return "";
            string msg = Marshal.PtrToStringAnsi(errStr) ?? "";
            return string.IsNullOrEmpty(msg) ? "" : $": {msg} (at {errPos})";
        }
        catch { return ""; }
    }

    public int ReceivePacket(byte[] destination, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(destination);
        try
        {
            var lease = _uplink.Reader.ReadAsync(ct).AsTask().GetAwaiter().GetResult();
            try
            {
                if (lease.Length > destination.Length) return 0;
                Buffer.BlockCopy(lease.Buffer, 0, destination, 0, lease.Length);
                return lease.Length;
            }
            finally { ArrayPool<byte>.Shared.Return(lease.Buffer); }
        }
        catch (OperationCanceledException) { return 0; }
        catch (ChannelClosedException) { return 0; }
    }

    private void CaptureLoop()
    {
        var buf = _captureBuffer;
        try
        {
            while (!_disposed)
            {
                IntPtr h;
                lock (_gate)
                {
                    if (_disposed || _handle == IntPtr.Zero) break;
                    h = _handle;
                }
            var addr = new WinDivertNative.WinDivertAddress();
            if (!WinDivertNative.WinDivertRecv(h, buf, (uint)buf.Length, out uint len, ref addr))
            {
                int err = Marshal.GetLastWin32Error();
                    if (_disposed || err == 6 /* INVALID_HANDLE */) break;
                if (err is 122 or 995) continue;
                Thread.Sleep(1);
                continue;
            }
            if (len < 20) continue;
            Interlocked.Increment(ref _captured);

            byte ver = (byte)(buf[0] >> 4);
            if (ver == 6)
            {
                HandleIpv6(buf, (int)len, ref addr);
                continue;
            }
            if (ver != 4) continue; // malformed/non-IP input: never leak it back to the host stack

            HandleIpv4(buf, (int)len, ref addr);
        }
        }
        finally { _uplink.Writer.TryComplete(); }
    }

    private void HandleIpv4(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        var decision = ClassifyIpv4(buf, len, ref addr, out var meta);
        bool discardPending = false;
        if (meta.IsFragment && meta.IsFirstFrag && decision != PacketDisposition.Unknown)
            _flows.RememberFrag(meta.OrigSrc, meta.Dst, meta.Proto, meta.IpId, decision);

        try
        {
            switch (decision)
            {
                case PacketDisposition.Bypass:
                    Interlocked.Increment(ref _bypassed);
                    Reinject(buf, len, ref addr);
                    return;
                case PacketDisposition.Drop:
                    Interlocked.Increment(ref _policyDrops);
                    return;
                case PacketDisposition.Tunnel:
                    if (!_tunnelUp)
                    {
                        Interlocked.Increment(ref _downDrops);
                        discardPending = true;
                        return;
                    }
                    ClampTcpMss(buf, len, _tunnelMtu);
                    if (len > _tunnelMtu && IsIpv4DontFragment(buf, len))
                    {
                        Interlocked.Increment(ref _mtuDrops);
                        discardPending = true;
                        InjectFragmentationNeeded(buf, len, _tunnelMtu, ref addr);
                        return;
                    }

                    byte[] packet = ArrayPool<byte>.Shared.Rent(len);
                    int packetLength = BuildTunnelPacket(buf, len, ref addr, meta, packet);
                    if (packetLength == 0)
                    {
                        discardPending = true;
                        ArrayPool<byte>.Shared.Return(packet);
                        return;
                    }
                    if (!_tunnelUp)
                    {
                        Interlocked.Increment(ref _downDrops);
                        discardPending = true;
                        ArrayPool<byte>.Shared.Return(packet);
                        return;
                    }
                    if (QueueTunnelPacket(packet, packetLength))
                        Interlocked.Increment(ref _tunnelled);
                    else
                        discardPending = true;
                    return;
                default:
                    // Unknown is used only for an early fragment held by the bounded
                    // reorder buffer. It must not be emitted or counted as a drop yet.
                    return;
            }
        }
        finally
        {
            if (meta.IsFragment && meta.IsFirstFrag && decision != PacketDisposition.Unknown)
                FlushPendingOutboundIpv4(
                    new WinDivertFlowTable.FragKey(
                        meta.OrigSrc, meta.Dst, meta.Proto, meta.IpId),
                    discardPending);
        }
    }

    private void FlushPendingOutboundIpv4(
        WinDivertFlowTable.FragKey key,
        bool discardPending)
    {
        if (discardPending)
        {
            _pendingOutboundIpv4.Discard(key);
            return;
        }
        foreach (var pending in _pendingOutboundIpv4.Take(key))
        {
            Interlocked.Increment(ref _reorderedFragmentsReleased);
            var pendingAddress = pending.Address;
            HandleIpv4(pending.Packet, pending.Packet.Length, ref pendingAddress);
        }
    }

    private void HandleIpv6(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        if (len < 40) return;
        var src = new IPAddress(buf.AsSpan(8, 16).ToArray());
        var dst = new IPAddress(buf.AsSpan(24, 16).ToArray());
        if (_dest.ShouldBypassTunnel(dst))
        {
            Interlocked.Increment(ref _bypassed);
            Reinject(buf, len, ref addr);
            return;
        }
        if (_allowIpv6Leak)
        {
            Interlocked.Increment(ref _bypassed);
            Reinject(buf, len, ref addr);
            return;
        }
        // Close the dual-stack leak: if the owning app would be tunnelled on IPv4, drop
        // IPv6 so the app falls back to IPv4-over-VPN. Otherwise reinject.
        bool parsed = TryParseIpv6Packet(buf, len, out var ipv6);
        byte proto = parsed ? ipv6.Protocol : (byte)0;
        byte affinityProto = parsed ? ipv6.FragmentProtocol : (byte)0;
        int offset = parsed ? ipv6.TransportOffset : 40;

        if (parsed && ipv6.IsFragment && !ipv6.IsFirstFragment)
        {
            if (_flows.TryGetIpv6Frag(src, dst, affinityProto, ipv6.FragmentId, out var remembered))
            {
                if (remembered == PacketDisposition.Bypass)
                {
                    Interlocked.Increment(ref _bypassed);
                    Reinject(buf, len, ref addr);
                }
                else
                {
                    Interlocked.Increment(ref _policyDrops);
                }
            }
            else
            {
                var key = new WinDivertFlowTable.Ipv6FragKey(
                    src, dst, affinityProto, ipv6.FragmentId);
                var copy = new byte[len];
                Buffer.BlockCopy(buf, 0, copy, 0, len);
                if (_pendingIpv6.Add(key, new CapturedFragment(copy, addr)))
                    Interlocked.Increment(ref _earlyFragmentsBuffered);
                else Interlocked.Increment(ref _policyDrops);
            }
            return;
        }

        ushort localPort = 0;
        if (parsed && ipv6.HasTransport && proto is 6 or 17 && len >= offset + 4)
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(offset));
        else if (proto is not (6 or 17))
        {
            // Unknown next-header chain: include fail-closed → drop candidates via Classify.
        }

        ushort remotePort = 0;
        if (parsed && ipv6.HasTransport && proto is 6 or 17 && len >= offset + 4)
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(offset + 2));
        if (IsCarrier(proto, dst, remotePort))
        {
            if (parsed && ipv6.IsFragment)
            {
                _flows.RememberIpv6Frag(
                    src, dst, affinityProto, ipv6.FragmentId, PacketDisposition.Bypass);
                FlushPendingIpv6(
                    new WinDivertFlowTable.Ipv6FragKey(src, dst, affinityProto, ipv6.FragmentId),
                    PacketDisposition.Bypass);
            }
            Reinject(buf, len, ref addr);
            return;
        }
        var disp = _apps.Classify(proto is 6 or 17 ? proto : (byte)0, src, localPort, dst, remotePort);
        var outcome = Ipv6Disposition(disp);
        if (parsed && ipv6.IsFragment)
        {
            _flows.RememberIpv6Frag(src, dst, affinityProto, ipv6.FragmentId, outcome);
            FlushPendingIpv6(
                new WinDivertFlowTable.Ipv6FragKey(src, dst, affinityProto, ipv6.FragmentId),
                outcome);
        }
        if (outcome == PacketDisposition.Drop)
        {
            Interlocked.Increment(ref _policyDrops);
            return; // drop — do not leak
        }
        Interlocked.Increment(ref _bypassed);
        Reinject(buf, len, ref addr);
    }

    /// <summary>The IPv6 data plane is bypass-only or drop-only. With leak protection
    /// enabled, every app decision except an explicit bypass remains fail-closed.</summary>
    internal static PacketDisposition Ipv6Disposition(PacketDisposition appDisposition) =>
        appDisposition == PacketDisposition.Bypass
            ? PacketDisposition.Bypass
            : PacketDisposition.Drop;

    private void FlushPendingIpv6(
        WinDivertFlowTable.Ipv6FragKey key, PacketDisposition disposition)
    {
        foreach (var pending in _pendingIpv6.Take(key))
        {
            Interlocked.Increment(ref _reorderedFragmentsReleased);
            if (disposition == PacketDisposition.Bypass)
            {
                var pendingAddress = pending.Address;
                Interlocked.Increment(ref _bypassed);
                Reinject(pending.Packet, pending.Packet.Length, ref pendingAddress);
            }
            else
            {
                Interlocked.Increment(ref _policyDrops);
            }
        }
    }

    internal static bool TryLocateIpv6Transport(
        byte[] packet, int length, out byte protocol, out int offset)
    {
        bool parsed = TryParseIpv6Packet(packet, length, out var meta);
        protocol = parsed ? meta.Protocol : (byte)0;
        offset = parsed ? meta.TransportOffset : 40;
        return parsed && meta.HasTransport;
    }

    internal static bool TryParseIpv6Packet(
        byte[] packet, int length, out Ipv6PacketMeta meta)
    {
        meta = default;
        if (length < 40 || (packet[0] >> 4) != 6) return false;
        byte next = packet[6];
        int offset = 40;
        bool fragmented = false;
        bool firstFragment = true;
        uint fragmentId = 0;
        byte fragmentProtocol = 0;
        for (int headers = 0; headers < 16; headers++)
        {
            if (next is 6 or 17)
            {
                meta = new Ipv6PacketMeta(
                    next, fragmented ? fragmentProtocol : next, offset,
                    fragmented, firstFragment, fragmentId,
                    length >= offset + 4);
                return true;
            }
            if (next is 0 or 43 or 60)
            {
                if (length < offset + 2) return false;
                byte following = packet[offset];
                int headerLength = (packet[offset + 1] + 1) * 8;
                if (headerLength < 8 || length < offset + headerLength) return false;
                next = following;
                offset += headerLength;
                continue;
            }
            if (next == 44)
            {
                if (length < offset + 8) return false;
                byte following = packet[offset];
                ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2));
                fragmented = true;
                fragmentProtocol = following;
                firstFragment = (fragment & 0xFFF8) == 0;
                fragmentId = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 4, 4));
                next = following;
                offset += 8;
                if (!firstFragment)
                {
                    meta = new Ipv6PacketMeta(
                        next, fragmentProtocol, offset, true, false, fragmentId,
                        HasTransport: false);
                    return true;
                }
                continue;
            }
            if (next == 51)
            {
                if (length < offset + 2) return false;
                byte following = packet[offset];
                int headerLength = (packet[offset + 1] + 2) * 4;
                if (headerLength < 8 || length < offset + headerLength) return false;
                next = following;
                offset += headerLength;
                continue;
            }
            meta = new Ipv6PacketMeta(
                next, fragmented ? fragmentProtocol : next, offset,
                fragmented, firstFragment, fragmentId,
                HasTransport: false);
            return true;
        }
        return false;
    }

    internal readonly record struct Ipv6PacketMeta(
        byte Protocol,
        byte FragmentProtocol,
        int TransportOffset,
        bool IsFragment,
        bool IsFirstFragment,
        uint FragmentId,
        bool HasTransport);

    private struct Ipv4Meta
    {
        public IPAddress OrigSrc;
        public IPAddress Dst;
        public byte Proto;
        public ushort LocalPort;
        public ushort RemotePort;
        public bool IsDns;
        public bool IsFragment;
        public bool IsFirstFrag;
        public ushort IpId;
        public IPAddress? FragmentTunnelDst;
    }

    private PacketDisposition ClassifyIpv4(
        byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr, out Ipv4Meta meta)
    {
        meta = default;
        int ihl = (buf[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return PacketDisposition.Drop;

        var src = new IPAddress(buf.AsSpan(12, 4).ToArray());
        var dst = new IPAddress(buf.AsSpan(16, 4).ToArray());
        byte proto = buf[9];
        ushort fragField = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(6, 2));
        ushort fragOffset = (ushort)(fragField & 0x1FFF);
        bool moreFrag = (fragField & 0x2000) != 0;
        bool isFrag = moreFrag || fragOffset != 0;
        bool isFirst = fragOffset == 0;
        ushort ipId = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(4, 2));

        meta = new Ipv4Meta
        {
            OrigSrc = src,
            Dst = dst,
            Proto = proto,
            IsFragment = isFrag,
            IsFirstFrag = isFirst,
            IpId = ipId,
        };

        // Non-first fragments: follow the disposition recorded for the first fragment.
        if (isFrag && !isFirst)
        {
            if (_flows.TryGetFrag(src, dst, proto, ipId, out var frag))
            {
                meta.FragmentTunnelDst = frag.TunnelDestination;
                return frag.Disposition;
            }
            if (_dest.ShouldBypassTunnel(dst)) return PacketDisposition.Bypass;
            var key = new WinDivertFlowTable.FragKey(src, dst, proto, ipId);
            var copy = new byte[len];
            Buffer.BlockCopy(buf, 0, copy, 0, len);
            if (_pendingOutboundIpv4.Add(key, new CapturedFragment(copy, addr)))
            {
                Interlocked.Increment(ref _earlyFragmentsBuffered);
                return PacketDisposition.Unknown;
            }
            return PacketDisposition.Drop;
        }

        ushort localPort = 0, remotePort = 0;
        if (proto is 6 or 17 && len >= ihl + 4)
        {
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl));
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl + 2));
        }
        meta = new Ipv4Meta
        {
            OrigSrc = src,
            Dst = dst,
            Proto = proto,
            LocalPort = localPort,
            RemotePort = remotePort,
            IsDns = proto is 6 or 17 && remotePort == 53,
            IsFragment = isFrag,
            IsFirstFrag = isFirst,
            IpId = ipId,
        };

        if (IsCarrier(proto, dst, remotePort)) return PacketDisposition.Bypass;
        // A configured/pushed tunnel DNS is authoritative even when the application's
        // original resolver is RFC1918. DestinationPolicy must see the eventual tunnel
        // destination, not prematurely bypass the packet before DNS NAT is applied.
        if (!meta.IsDns || _dnsServers.Count == 0)
            if (_dest.ShouldBypassTunnel(dst)) return PacketDisposition.Bypass;
        var disp = _apps.Classify(proto, src, localPort, dst, remotePort);
        return disp;
    }

    private int BuildTunnelPacket(
        byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr, Ipv4Meta meta,
        byte[] destination)
    {
        if (len > destination.Length)
        {
            _log?.Invoke($"WinDivert packet dropped: {len} bytes exceeds packet-pump buffer {destination.Length}");
            return 0;
        }
        var origSrc = meta.OrigSrc;
        WriteIpv4(buf, 12, _clientIp);

        IPAddress? dnsOrig = null;
        IPAddress tunnelDst = meta.FragmentTunnelDst ?? meta.Dst;
        var dnsServers = _dnsServers;
        if (meta.IsDns && dnsServers.Count > 0)
        {
            dnsOrig = meta.Dst;
            // Resolver selection is a stable function of the original 5-tuple. Choosing
            // randomly for every packet can send one TCP DNS connection (or retransmitted
            // UDP query) to several resolvers while reverse NAT still describes one flow.
            tunnelDst = SelectDnsResolver(
                dnsServers, meta.Proto, meta.OrigSrc, meta.LocalPort,
                meta.Dst, meta.RemotePort);
            WriteIpv4(buf, 16, tunnelDst);
        }
        else if (!tunnelDst.Equals(meta.Dst))
        {
            // Non-first DNS fragment: it has no UDP/TCP header, so carry the resolver
            // selected by the first fragment rather than splitting one datagram across
            // two destinations.
            WriteIpv4(buf, 16, tunnelDst);
        }

        if (meta.IsFragment && meta.IsFirstFrag)
            _flows.SetFragTunnelDestination(
                meta.OrigSrc, meta.Dst, meta.Proto, meta.IpId, tunnelDst);

        if (meta.Proto is 6 or 17 && meta.LocalPort != 0)
        {
            int ihl = (buf[0] & 0x0F) * 4;
            bool tcpFin = meta.Proto == 6 && len >= ihl + 14 && (buf[ihl + 13] & 0x01) != 0;
            bool tcpRst = meta.Proto == 6 && len >= ihl + 14 && (buf[ihl + 13] & 0x04) != 0;
            ushort translatedPort = _flows.RememberOutbound(
                meta.Proto, _clientIp, origSrc, meta.LocalPort,
                tunnelDst, meta.RemotePort, in addr, dnsOrig, tcpFin, tcpRst);
            if (translatedPort == 0)
            {
                _log?.Invoke("WinDivert packet dropped: NAT flow-port space exhausted");
                return 0;
            }
            if (translatedPort != meta.LocalPort)
                BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(ihl, 2), translatedPort);
        }

        FixChecksums(buf, len, ref addr);
        Buffer.BlockCopy(buf, 0, destination, 0, len);
        return len;
    }

    /// <summary>Queues one inner IPv4 packet. Packets larger than the negotiated tunnel
    /// MTU are fragmented only when the sender allowed IPv4 fragmentation. DF packets are
    /// handled before NAT by <see cref="InjectFragmentationNeeded"/>.</summary>
    private bool QueueTunnelPacket(byte[] packet, int length)
    {
        if (length <= _tunnelMtu)
        {
            if (_uplink.Writer.TryWrite(new PacketLease(packet, length))) return true;
            Interlocked.Increment(ref _queueDrops);
            ArrayPool<byte>.Shared.Return(packet);
            return false;
        }

        if (!TryFragmentIpv4(packet, length, _tunnelMtu, out var fragments))
        {
            Interlocked.Increment(ref _mtuDrops);
            ArrayPool<byte>.Shared.Return(packet);
            return false;
        }

        ArrayPool<byte>.Shared.Return(packet);
        bool complete = true;
        foreach (var fragment in fragments)
        {
            if (_tunnelUp && _uplink.Writer.TryWrite(fragment)) continue;
            complete = false;
            if (!_tunnelUp) Interlocked.Increment(ref _downDrops);
            else Interlocked.Increment(ref _queueDrops);
            ArrayPool<byte>.Shared.Return(fragment.Buffer);
        }
        if (complete) Interlocked.Increment(ref _fragmentedPackets);
        return complete;
    }

    internal static bool ClampTcpMss(byte[] packet, int length, int mtu)
    {
        if (length < 40 || (packet[0] >> 4) != 4 || packet[9] != 6) return false;
        int ihl = (packet[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl + 20) return false;
        ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        if ((fragment & 0x1FFF) != 0) return false;
        int tcpLength = (packet[ihl + 12] >> 4) * 4;
        if (tcpLength < 20 || length < ihl + tcpLength || (packet[ihl + 13] & 0x02) == 0)
            return false;

        int advertisedMss = Math.Max(536, mtu - 40);
        for (int pos = ihl + 20, end = ihl + tcpLength; pos < end;)
        {
            byte kind = packet[pos];
            if (kind == 0) break;
            if (kind == 1) { pos++; continue; }
            if (pos + 1 >= end) break;
            int optionLength = packet[pos + 1];
            if (optionLength < 2 || pos + optionLength > end) break;
            if (kind == 2 && optionLength == 4)
            {
                ushort current = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(pos + 2, 2));
                if (current <= advertisedMss) return false;
                BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(pos + 2, 2), (ushort)advertisedMss);
                return true;
            }
            pos += optionLength;
        }
        return false;
    }

    internal static bool IsIpv4DontFragment(byte[] packet, int length)
    {
        if (length < 20 || (packet[0] >> 4) != 4) return false;
        return (BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2)) & 0x4000) != 0;
    }

    private static bool TryFragmentIpv4(
        byte[] packet, int length, int mtu, out List<PacketLease> fragments)
    {
        fragments = new List<PacketLease>();
        if (length < 20 || (packet[0] >> 4) != 4) return false;
        int ihl = (packet[0] & 0x0F) * 4;
        int totalLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        if (ihl < 20 || totalLength < ihl || totalLength > length || mtu <= ihl + 8)
            return false;

        ushort originalFragment = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        if ((originalFragment & 0x4000) != 0) return false;
        int baseOffset = originalFragment & 0x1FFF;
        bool originalMore = (originalFragment & 0x2000) != 0;
        int maxPayload = ((mtu - ihl) / 8) * 8;
        int payloadLength = totalLength - ihl;
        if (maxPayload <= 0 || payloadLength <= maxPayload) return false;

        try
        {
            for (int consumed = 0; consumed < payloadLength; consumed += maxPayload)
            {
                int chunk = Math.Min(maxPayload, payloadLength - consumed);
                int fragmentLength = ihl + chunk;
                byte[] buffer = ArrayPool<byte>.Shared.Rent(fragmentLength);
                Buffer.BlockCopy(packet, 0, buffer, 0, ihl);
                Buffer.BlockCopy(packet, ihl + consumed, buffer, ihl, chunk);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)fragmentLength);
                bool more = consumed + chunk < payloadLength || originalMore;
                ushort field = (ushort)((originalFragment & 0x8000)
                    | (more ? 0x2000 : 0)
                    | (baseOffset + consumed / 8));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), field);
                WriteInternetChecksum(buffer.AsSpan(0, ihl), 10);
                fragments.Add(new PacketLease(buffer, fragmentLength));
            }
            return true;
        }
        catch
        {
            foreach (var fragment in fragments) ArrayPool<byte>.Shared.Return(fragment.Buffer);
            fragments.Clear();
            throw;
        }
    }

    private void InjectFragmentationNeeded(
        byte[] original, int originalLength, int mtu,
        ref WinDivertNative.WinDivertAddress capturedAddress)
    {
        if (originalLength < 20 || (original[0] >> 4) != 4) return;
        int ihl = (original[0] & 0x0F) * 4;
        if (ihl < 20 || originalLength < ihl) return;
        int quoted = Math.Min(originalLength, ihl + 8);
        int length = 20 + 8 + quoted;
        byte[] packet = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Array.Clear(packet, 0, length);
            packet[0] = 0x45;
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)length);
            packet[8] = 64;
            packet[9] = 1; // ICMP
            Buffer.BlockCopy(original, 16, packet, 12, 4); // remote -> local
            Buffer.BlockCopy(original, 12, packet, 16, 4);
            packet[20] = 3; // destination unreachable
            packet[21] = 4; // fragmentation needed and DF set
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(26, 2), (ushort)mtu);
            Buffer.BlockCopy(original, 0, packet, 28, quoted);
            WriteInternetChecksum(packet.AsSpan(20, 8 + quoted), 2);
            WriteInternetChecksum(packet.AsSpan(0, 20), 10);

            IntPtr h;
            lock (_gate)
            {
                if (_disposed || _handle == IntPtr.Zero) return;
                h = _handle;
            }
            var addr = capturedAddress;
            addr.Outbound = false;
            if (WinDivertNative.WinDivertSend(h, packet, (uint)length, out _, ref addr))
                Interlocked.Increment(ref _icmpPacketTooBig);
        }
        finally { ArrayPool<byte>.Shared.Return(packet); }
    }

    private static void WriteInternetChecksum(Span<byte> data, int checksumOffset)
    {
        data[checksumOffset] = 0;
        data[checksumOffset + 1] = 0;
        uint sum = 0;
        int i = 0;
        for (; i + 1 < data.Length; i += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
        if (i < data.Length) sum += (uint)data[i] << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(data.Slice(checksumOffset, 2), (ushort)~sum);
    }

    public void SendPacket(byte[] packet, int offset, int length)
    {
        if (_disposed || length < 20 || !_tunnelUp || offset < 0
            || length > packet.Length - offset || length > _injectBuffer.Length) return;
        IntPtr h;
        lock (_gate)
        {
            if (_disposed || _handle == IntPtr.Zero) return;
            h = _handle;
        }

        var buf = _injectBuffer;
        Buffer.BlockCopy(packet, offset, buf, 0, length);
        if ((buf[0] >> 4) != 4) return;
        int ihl = (buf[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl) return;

        byte proto = buf[9];
        var remoteIp = new IPAddress(buf.AsSpan(12, 4).ToArray());
        var clientIp = new IPAddress(buf.AsSpan(16, 4).ToArray());
        ushort fragField = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(6, 2));
        ushort fragOffset = (ushort)(fragField & 0x1FFF);
        bool moreFragments = (fragField & 0x2000) != 0;
        ushort ipId = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(4, 2));
        ushort remotePort = 0, localPort = 0;
        if (fragOffset == 0 && proto is 6 or 17 && length >= ihl + 4)
        {
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl));
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl + 2));
        }

        // ICMP errors carry the offending packet's original 5-tuple. They cannot be
        // looked up by the outer ICMP tuple (proto=1, no ports), so recover the quoted
        // TCP/UDP flow and reverse both the outer and quoted NAT addresses.
        if (fragOffset == 0 && proto == 1
            && TryParseIcmpQuotedFlow(
                buf, length, out byte quotedProto, out var quotedRemote,
                out ushort quotedRemotePort, out ushort quotedLocalPort,
                out int quotedIpOffset, out int quotedIhl)
            && new IPAddress(buf.AsSpan(quotedIpOffset + 12, 4).ToArray()).Equals(_clientIp)
            && _flows.TryGetInbound(
                quotedProto, quotedRemote, quotedRemotePort,
                _clientIp, quotedLocalPort, out var icmpFlow))
        {
            WriteIpv4(buf, 16, icmpFlow.OriginalSrc);
            WriteIpv4(buf, quotedIpOffset + 12, icmpFlow.OriginalSrc);
            if (icmpFlow.OriginalLocalPort != quotedLocalPort)
                BinaryPrimitives.WriteUInt16BigEndian(
                    buf.AsSpan(quotedIpOffset + quotedIhl, 2), icmpFlow.OriginalLocalPort);
            if (icmpFlow.DnsOrigDst is { } originalDns)
            {
                var outerSource = new IPAddress(buf.AsSpan(12, 4).ToArray());
                if (outerSource.Equals(quotedRemote)) WriteIpv4(buf, 12, originalDns);
                WriteIpv4(buf, quotedIpOffset + 16, originalDns);
            }
            WriteInternetChecksum(buf.AsSpan(quotedIpOffset, quotedIhl), 10);
            var icmpAddr = icmpFlow.Addr;
            icmpAddr.Outbound = false;
            FixChecksums(buf, length, ref icmpAddr);
            if (WinDivertNative.WinDivertSend(h, buf, (uint)length, out _, ref icmpAddr))
                Interlocked.Increment(ref _replyInjected);
            else
                Interlocked.Increment(ref _replyDrops);
            return;
        }

        WinDivertFlowTable.FlowEntry flow;
        IReadOnlyList<byte[]> reordered = Array.Empty<byte[]>();
        var fragmentKey = new WinDivertFlowTable.FragKey(remoteIp, clientIp, proto, ipId);
        if (fragOffset != 0)
        {
            if (!_flows.TryGetInboundFrag(remoteIp, clientIp, proto, ipId, out flow))
            {
                var copy = buf.AsSpan(0, length).ToArray();
                if (_pendingInboundIpv4.Add(fragmentKey, copy))
                    Interlocked.Increment(ref _earlyFragmentsBuffered);
                else Interlocked.Increment(ref _replyDrops);
                return;
            }
        }
        else if (!_flows.TryGetInbound(proto, remoteIp, remotePort, _clientIp, localPort, out flow))
        {
            // No matching flow — drop rather than guess a NIC/IP (fail-closed for include;
            // for exclude an orphan reply is better dropped than mis-delivered).
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        else if (moreFragments)
        {
            _flows.RememberInboundFrag(remoteIp, clientIp, proto, ipId, in flow);
            reordered = _pendingInboundIpv4.Take(fragmentKey);
        }

        WriteIpv4(buf, 16, flow.OriginalSrc);
        if (fragOffset == 0 && proto is 6 or 17 && flow.OriginalLocalPort != localPort)
            BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(ihl + 2, 2), flow.OriginalLocalPort);

        // Apply to every fragment. Only the first one has a UDP/TCP header, but all
        // fragments must expose the resolver address originally requested by the app.
        if (flow.DnsOrigDst is { } dns)
        {
            WriteIpv4(buf, 12, dns);
        }

        var addr = flow.Addr;
        addr.Outbound = false;
        FixChecksums(buf, length, ref addr);
        if (fragOffset == 0 && proto == 6 && length >= ihl + 14)
        {
            byte flags = buf[ihl + 13];
            _flows.ObserveInboundTcp(
                remoteIp, remotePort, _clientIp, localPort,
                fin: (flags & 0x01) != 0, rst: (flags & 0x04) != 0);
        }
        if (WinDivertNative.WinDivertSend(h, buf, (uint)length, out _, ref addr))
            Interlocked.Increment(ref _replyInjected);
        else
            Interlocked.Increment(ref _replyDrops);

        // The first fragment has now published reverse-NAT affinity and has itself been
        // injected. Re-run any early fragments in arrival order; they will hit the mapping.
        foreach (var pending in reordered)
        {
            Interlocked.Increment(ref _reorderedFragmentsReleased);
            SendPacket(pending, 0, pending.Length);
        }
    }

    internal static bool TryParseIcmpQuotedFlow(
        byte[] packet,
        int length,
        out byte protocol,
        out IPAddress remoteIp,
        out ushort remotePort,
        out ushort localPort,
        out int quotedIpOffset,
        out int quotedIhl)
    {
        protocol = 0;
        remoteIp = IPAddress.None;
        remotePort = 0;
        localPort = 0;
        quotedIpOffset = 0;
        quotedIhl = 0;
        if (length < 20 || (packet[0] >> 4) != 4 || packet[9] != 1) return false;
        int outerIhl = (packet[0] & 0x0F) * 4;
        if (outerIhl < 20 || length < outerIhl + 8 + 20) return false;
        byte type = packet[outerIhl];
        if (type is not (3 or 11 or 12)) return false;

        quotedIpOffset = outerIhl + 8;
        if ((packet[quotedIpOffset] >> 4) != 4) return false;
        quotedIhl = (packet[quotedIpOffset] & 0x0F) * 4;
        if (quotedIhl < 20 || length < quotedIpOffset + quotedIhl + 4) return false;
        ushort quotedFragment = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(quotedIpOffset + 6, 2));
        if ((quotedFragment & 0x1FFF) != 0) return false;
        protocol = packet[quotedIpOffset + 9];
        if (protocol is not (6 or 17)) return false;
        remoteIp = new IPAddress(packet.AsSpan(quotedIpOffset + 16, 4).ToArray());
        localPort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(quotedIpOffset + quotedIhl, 2));
        remotePort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(quotedIpOffset + quotedIhl + 2, 2));
        return localPort != 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _tunnelUp = false;
        IntPtr h;
        lock (_gate)
        {
            h = _handle;
            _handle = IntPtr.Zero;
        }
        if (h != IntPtr.Zero && h != new IntPtr(-1))
            try { WinDivertNative.WinDivertClose(h); } catch { }
        try { _captureThread?.Join(2000); } catch { }
        _uplink.Writer.TryComplete();
        DrainUplink();
        _pendingIpv6.Clear();
        _pendingOutboundIpv4.Clear();
        _pendingInboundIpv4.Clear();
        _apps.Dispose();
        _log?.Invoke("WinDivert stats: "
            + $"captured={Interlocked.Read(ref _captured)} "
            + $"tunnelled={Interlocked.Read(ref _tunnelled)} "
            + $"bypass={Interlocked.Read(ref _bypassed)} "
            + $"policy_drops={Interlocked.Read(ref _policyDrops)} "
            + $"down_drops={Interlocked.Read(ref _downDrops)} "
            + $"queue_drops={Interlocked.Read(ref _queueDrops)} "
            + $"mtu_drops={Interlocked.Read(ref _mtuDrops)} "
            + $"fragmented={Interlocked.Read(ref _fragmentedPackets)} "
            + $"icmp_frag_needed={Interlocked.Read(ref _icmpPacketTooBig)} "
            + $"replies={Interlocked.Read(ref _replyInjected)} "
            + $"reply_drops={Interlocked.Read(ref _replyDrops)} "
            + $"early_fragments_buffered={Interlocked.Read(ref _earlyFragmentsBuffered)} "
            + $"reordered_fragments_released={Interlocked.Read(ref _reorderedFragmentsReleased)} "
            + $"fragment_buffer_drops={_pendingIpv6.DroppedCount + _pendingOutboundIpv4.DroppedCount + _pendingInboundIpv4.DroppedCount}");
    }

    private void Reinject(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        IntPtr h;
        lock (_gate)
        {
            if (_disposed || _handle == IntPtr.Zero) return;
            h = _handle;
        }
        WinDivertNative.WinDivertSend(h, buf, (uint)len, out _, ref addr);
    }

    private static void WriteIpv4(byte[] buf, int offset, IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return;
        Buffer.BlockCopy(bytes, 0, buf, offset, 4);
    }

    private static void FixChecksums(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        addr.Flags = (byte)(addr.Flags & ~0xE0);
        WinDivertNative.WinDivertHelperCalcChecksums(buf, (uint)len, ref addr,
            WinDivertNative.WINDIVERT_HELPER_CHECKSUM_ALL);
    }

    private static void EnsureDriverLoaded()
    {
        string? dir = NativeLoader.EnsureWinDivertDir();
        if (dir == null)
            throw new InvalidOperationException("WinDivert.dll could not be extracted from the embedded resources.");
        IntPtr mod = WinDivertNative.LoadLibrary(Path.Combine(dir, "WinDivert.dll"));
        if (mod == IntPtr.Zero)
            throw new InvalidOperationException(
                $"LoadLibrary(WinDivert.dll) failed (Win32 {Marshal.GetLastWin32Error()}).");
    }

    /// <summary>Filter expression used at Open — exposed for self-tests.</summary>
    internal static string BuildFilter() =>
        "outbound and !loopback";

    private bool IsCarrier(byte protocol, IPAddress destination, ushort remotePort) =>
        _carrier is var carrier && protocol == carrier.Protocol && remotePort == carrier.Port
        && destination.Equals(carrier.Ip);

    private static CarrierEndpoint MakeCarrier(
        IPAddress ip, int port, string protocol) => new(
            ip,
            checked((ushort)port),
            protocol.Equals("udp", StringComparison.OrdinalIgnoreCase) ? (byte)17 : (byte)6);

    private static IReadOnlyList<IPAddress> ParseDns(IEnumerable<string> servers) =>
        servers.Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
            .Where(ip => ip != null && ip.AddressFamily == AddressFamily.InterNetwork)
            .Cast<IPAddress>()
            .ToList();

    internal static IPAddress SelectDnsResolver(
        IReadOnlyList<IPAddress> servers,
        byte protocol,
        IPAddress source,
        ushort sourcePort,
        IPAddress destination,
        ushort destinationPort)
    {
        if (servers.Count == 0)
            throw new ArgumentException("at least one DNS resolver is required", nameof(servers));

        // FNV-1a is deterministic within and across processes (unlike HashCode/string hash).
        uint hash = 2166136261;
        static void Add(ref uint h, byte value) { h ^= value; h *= 16777619; }
        Add(ref hash, protocol);
        foreach (byte b in source.GetAddressBytes()) Add(ref hash, b);
        Add(ref hash, (byte)(sourcePort >> 8)); Add(ref hash, (byte)sourcePort);
        foreach (byte b in destination.GetAddressBytes()) Add(ref hash, b);
        Add(ref hash, (byte)(destinationPort >> 8)); Add(ref hash, (byte)destinationPort);
        return servers[(int)(hash % (uint)servers.Count)];
    }

    private static int ValidateMtu(int mtu) =>
        mtu is >= 576 and <= 65535
            ? mtu
            : throw new ArgumentOutOfRangeException(nameof(mtu), mtu, "IPv4 tunnel MTU must be 576..65535");

    private void DrainUplink()
    {
        while (_uplink.Reader.TryRead(out var lease))
            ArrayPool<byte>.Shared.Return(lease.Buffer);
    }

    private readonly record struct PacketLease(byte[] Buffer, int Length);
    private readonly record struct CapturedFragment(
        byte[] Packet, WinDivertNative.WinDivertAddress Address);
    private sealed record CarrierEndpoint(IPAddress Ip, ushort Port, byte Protocol);
}
