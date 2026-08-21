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
/// tracks each flow (orig src IP, IfIdx, ports, DNS state), NAT-rewrites both enabled
/// address families to their session addresses, and reinjects replies inbound on the
/// correct interface. Include mode and unavailable address families are fail-closed
/// unless the corresponding explicit leak opt-out is enabled.
/// </summary>
public sealed class WinDivertAdapter : IPacketTunDevice
{
    private ProcessAppMap _apps;
    private readonly WinDivertFlowTable _flows;
    private readonly PendingFragmentBuffer<WinDivertFlowTable.Ipv6FragKey, CapturedFragment>
        _pendingIpv6 = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.FragKey, CapturedFragment>
        _pendingOutboundIpv4 = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.FragKey, byte[]>
        _pendingInboundIpv4 = new();
    private readonly PendingFragmentBuffer<WinDivertFlowTable.Ipv6FragKey, byte[]>
        _pendingInboundIpv6 = new();
    private WinDivertDestinationPolicy _dest;
    private IPAddress? _clientIpv4;
    private IPAddress? _clientIpv6;
    private IReadOnlyList<IPAddress> _dnsServers;
    // Negotiated family leak policy belongs to the authenticated NetworkPlan, not to the
    // lifetime of the WinDivert capture handle. A retained per-app adapter can survive a
    // reconnect whose available families/policy changed, so Reconfigure must replace it too.
    private bool _allowIpv4Leak;
    private bool _allowIpv6Leak;
    private bool _fullTunnel;
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
    private readonly object _policyGate = new();
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
        IPAddress? clientIpv4,
        IPAddress? clientIpv6,
        IEnumerable<string> apps,
        bool includeMode,
        IEnumerable<string> dnsServers,
        bool allowIpv4Leak,
        bool allowIpv6Leak,
        bool fullTunnel,
        IEnumerable<string>? tunnelSubnets,
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
        if (clientIpv4 != null && clientIpv4.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("clientIpv4 must be an IPv4 address", nameof(clientIpv4));
        if (clientIpv6 != null && clientIpv6.AddressFamily != AddressFamily.InterNetworkV6)
            throw new ArgumentException("clientIpv6 must be an IPv6 address", nameof(clientIpv6));
        if (clientIpv4 == null && clientIpv6 == null)
            throw new ArgumentException("at least one tunnel address family is required");
        _clientIpv4 = clientIpv4;
        _clientIpv6 = clientIpv6;
        _apps = new ProcessAppMap(apps, includeMode);
        // Bind the flow table to the adapter, not to this first ProcessAppMap instance:
        // persist_tun may atomically replace the app selection while retaining the capture.
        _flows = new WinDivertFlowTable(tcpFlowExists: CurrentAppHasTcpEndpoint);
        _allowIpv4Leak = allowIpv4Leak;
        _allowIpv6Leak = allowIpv6Leak;
        _fullTunnel = fullTunnel;
        _dest = new WinDivertDestinationPolicy(
            routeLocal, includeRoutes, excludeRoutes, pushedRoutes,
            fullTunnel, tunnelSubnets);
        _dnsServers = ParseDns(dnsServers);
        _carrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
        _tunnelMtu = ValidateMtu(tunnelMtu, clientIpv6 != null);
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
        IPAddress? clientIpv4,
        IPAddress? clientIpv6,
        IEnumerable<string> apps,
        bool includeMode,
        IEnumerable<string> dnsServers,
        bool allowIpv4Leak,
        bool allowIpv6Leak,
        bool fullTunnel,
        IEnumerable<string>? tunnelSubnets,
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
        if ((clientIpv4 != null && clientIpv4.AddressFamily != AddressFamily.InterNetwork)
            || (clientIpv6 != null && clientIpv6.AddressFamily != AddressFamily.InterNetworkV6)
            || (clientIpv4 == null && clientIpv6 == null))
            throw new ArgumentException("reconfigured tunnel addresses do not match their families");
        // Validate and materialize every throwing component before the atomic swap. A bad
        // CIDR/DNS/carrier/MTU must leave the complete old policy in force, not replace the
        // app map and then fail halfway through the remaining assignments.
        var replacementDns = ParseDns(dnsServers);
        var replacementDest = new WinDivertDestinationPolicy(
            routeLocal, includeRoutes, excludeRoutes, pushedRoutes,
            fullTunnel, tunnelSubnets);
        var replacementCarrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
        int replacementMtu = ValidateMtu(tunnelMtu, clientIpv6 != null);
        var replacementApps = new ProcessAppMap(apps, includeMode);
        if (replacementApps.SelectedCount == 0)
        {
            replacementApps.Dispose();
            throw new InvalidOperationException(
                "reconfigured per-app profile contains no Windows executable paths; "
                + "select at least one .exe on this device");
        }
        ProcessAppMap previousApps;
        lock (_policyGate)
        {
            previousApps = _apps;
            _apps = replacementApps;
            _clientIpv4 = clientIpv4;
            _clientIpv6 = clientIpv6;
            _dnsServers = replacementDns;
            _allowIpv4Leak = allowIpv4Leak;
            _allowIpv6Leak = allowIpv6Leak;
            _fullTunnel = fullTunnel;
            _dest = replacementDest;
            _carrier = replacementCarrier;
            _tunnelMtu = replacementMtu;
            _flows.Clear();
            _pendingIpv6.Clear();
            _pendingOutboundIpv4.Clear();
            _pendingInboundIpv4.Clear();
            _pendingInboundIpv6.Clear();
        }
        // Every packet/flow callback holds _policyGate, so no caller can still reference the
        // old map after the swap. Dispose it outside the gate to keep refresh shutdown out of
        // the capture critical section.
        previousApps.Dispose();
        _log?.Invoke(
            $"WinDivert policy refreshed after reconnect (carrier {_carrier.Ip}:{_carrier.Port}, "
            + $"apps={replacementApps.SelectedCount}, include={replacementApps.IncludeMode})");
    }

    internal (bool ipv4, bool ipv6) LeakPolicyForSelfTest()
    {
        lock (_policyGate) return (_allowIpv4Leak, _allowIpv6Leak);
    }

    internal (int count, bool include) AppPolicyForSelfTest()
    {
        lock (_policyGate) return (_apps.SelectedCount, _apps.IncludeMode);
    }

    private bool CurrentAppHasTcpEndpoint(
        IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort) =>
        _apps.HasTcpEndpoint(localIp, localPort, remoteIp, remotePort);

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
            $"WinDivert per-app filter open (IPv4 {_clientIpv4?.ToString() ?? "off"}, " +
            $"IPv6 {_clientIpv6?.ToString() ?? "off"}, {_apps.SelectedCount} app path(s), " +
            $"include={_apps.IncludeMode}, allow_ipv4_leak={_allowIpv4Leak}, " +
            $"allow_ipv6_leak={_allowIpv6Leak}, mtu={_tunnelMtu})");
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

                lock (_policyGate)
                {
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
        }
        finally { _uplink.Writer.TryComplete(); }
    }

    private void HandleIpv4(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        var decision = ClassifyIpv4(buf, len, ref addr, out var meta);
        bool requireIpv4Tunnel = decision == PacketDisposition.Tunnel
            && (_dest.RequiresTunnel(meta.Dst)
                || (meta.IsDns && CanTunnelDns()));
        bool ipv4PathAvailable = _clientIpv4 != null
            || (meta.IsDns && CanTunnelDns());
        decision = DispositionForFamily(
            decision, ipv4PathAvailable, _allowIpv4Leak, requireIpv4Tunnel);
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
                    bool dnsToIpv6 = meta.IsDns
                        && !HasTunnelDns(AddressFamily.InterNetwork)
                        && _clientIpv6 != null
                        && HasTunnelDns(AddressFamily.InterNetworkV6);
                    int ipv4PathMtu = EffectiveIpv4PathMtu(
                        _tunnelMtu, (buf[0] & 0x0F) * 4, dnsToIpv6);
                    // DNS46 replaces the IPv4 header with a 40-byte IPv6 header. Enforce
                    // the resulting inner-packet budget before creating NAT state. IPv4
                    // fragmentation cannot be used here because the translator deliberately
                    // accepts only complete UDP/TCP datagrams.
                    if (len > ipv4PathMtu
                        && (dnsToIpv6 || IsIpv4DontFragment(buf, len)))
                    {
                        Interlocked.Increment(ref _mtuDrops);
                        discardPending = true;
                        InjectFragmentationNeeded(buf, len, ipv4PathMtu, ref addr);
                        return;
                    }
                    ClampTcpMss(buf, len, ipv4PathMtu);

                    byte[] packet = ArrayPool<byte>.Shared.Rent(Math.Min(0xFFFF, len + 40));
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
        if (!TryParseIpv6Packet(buf, len, out var ipv6))
        {
            Interlocked.Increment(ref _policyDrops);
            return;
        }
        var src = new IPAddress(buf.AsSpan(8, 16).ToArray());
        var dst = new IPAddress(buf.AsSpan(24, 16).ToArray());
        byte proto = ipv6.Protocol;
        byte affinityProto = ipv6.FragmentProtocol;
        int transportOffset = ipv6.TransportOffset;

        if (ipv6.IsFragment && !ipv6.IsFirstFragment)
        {
            if (_flows.TryGetIpv6FragEntry(
                    src, dst, affinityProto, ipv6.FragmentId, out var remembered))
            {
                ProcessIpv6Decision(
                    buf, len, ref addr, ipv6, src, dst,
                    remembered.Disposition, remembered.TunnelDestination,
                    out _);
            }
            else if (_dest.ShouldBypassTunnel(dst))
            {
                Interlocked.Increment(ref _bypassed);
                Reinject(buf, len, ref addr);
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

        ushort localPort = 0, remotePort = 0;
        if (ipv6.HasTransport && proto is 6 or 17)
        {
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(transportOffset));
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(transportOffset + 2));
        }
        bool isDns = proto is 6 or 17 && remotePort == 53;
        bool canTunnelDns = CanTunnelDns();

        PacketDisposition outcome;
        if (IsCarrier(proto, dst, remotePort))
            outcome = PacketDisposition.Bypass;
        else if (TunnelDnsFamilyMismatch(isDns, _dnsServers.Count, canTunnelDns))
            outcome = PacketDisposition.Drop;
        else if ((!isDns || _dnsServers.Count == 0) && _dest.ShouldBypassTunnel(dst))
            outcome = PacketDisposition.Bypass;
        else
        {
            var appDisposition = isDns && canTunnelDns
                ? PacketDisposition.Tunnel
                : proto is 6 or 17
                ? _apps.Classify(proto, src, localPort, dst, remotePort)
                : PacketDisposition.Drop;
            outcome = DispositionForFamily(
                appDisposition, _clientIpv6 != null || (isDns && canTunnelDns), _allowIpv6Leak,
                _dest.RequiresTunnel(dst) || (isDns && canTunnelDns));
        }

        WinDivertFlowTable.Ipv6FragKey fragmentKey = default;
        if (ipv6.IsFragment)
        {
            fragmentKey = new WinDivertFlowTable.Ipv6FragKey(
                src, dst, affinityProto, ipv6.FragmentId);
            _flows.RememberIpv6Frag(src, dst, affinityProto, ipv6.FragmentId, outcome);
        }

        bool discardPending = false;
        try
        {
            ProcessIpv6Decision(
                buf, len, ref addr, ipv6, src, dst, outcome, null,
                out discardPending);
        }
        finally
        {
            if (ipv6.IsFragment)
                FlushPendingIpv6(fragmentKey, discardPending);
        }
    }

    private void ProcessIpv6Decision(
        byte[] buf,
        int len,
        ref WinDivertNative.WinDivertAddress addr,
        Ipv6PacketMeta meta,
        IPAddress src,
        IPAddress dst,
        PacketDisposition decision,
        IPAddress? fragmentTunnelDestination,
        out bool discardPending)
    {
        discardPending = false;
        switch (decision)
        {
            case PacketDisposition.Bypass:
                Interlocked.Increment(ref _bypassed);
                Reinject(buf, len, ref addr);
                return;
            case PacketDisposition.Drop:
                Interlocked.Increment(ref _policyDrops);
                discardPending = true;
                return;
            case PacketDisposition.Tunnel:
                if (!_tunnelUp)
                {
                    Interlocked.Increment(ref _downDrops);
                    discardPending = true;
                    return;
                }
                if (len > _tunnelMtu)
                {
                    Interlocked.Increment(ref _mtuDrops);
                    discardPending = true;
                    InjectIcmpv6PacketTooBig(buf, len, _tunnelMtu, meta, ref addr);
                    return;
                }
                ClampIpv6TcpMss(buf, len, meta, _tunnelMtu);

                byte[] packet = ArrayPool<byte>.Shared.Rent(Math.Min(0xFFFF, len + 20));
                int packetLength = BuildIpv6TunnelPacket(
                    buf, len, ref addr, meta, src, dst,
                    fragmentTunnelDestination, packet);
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
                discardPending = true;
                return;
        }
    }

    private bool HasTunnelDns(AddressFamily family) =>
        _dnsServers.Any(address => address.AddressFamily == family);

    private bool CanTunnelDns() =>
        (_clientIpv4 != null && HasTunnelDns(AddressFamily.InterNetwork))
        || (_clientIpv6 != null && HasTunnelDns(AddressFamily.InterNetworkV6));

    internal static int EffectiveIpv4PathMtu(
        int tunnelMtu, int ipv4HeaderLength, bool translateToIpv6)
    {
        if (!translateToIpv6) return tunnelMtu;
        int headerGrowth = Math.Max(0, 40 - ipv4HeaderLength);
        return Math.Max(68, tunnelMtu - headerGrowth);
    }

    internal static bool TunnelDnsFamilyMismatch(
        bool isDns, int configuredDnsCount, bool hasCompatibleDns) =>
        isDns && configuredDnsCount > 0 && !hasCompatibleDns;

    internal static PacketDisposition DispositionForFamily(
        PacketDisposition appDisposition, bool familyAvailable, bool allowLeak,
        bool tunnelRequired = false)
    {
        if (appDisposition is PacketDisposition.Bypass or PacketDisposition.Drop
            or PacketDisposition.Unknown)
            return appDisposition;
        if (familyAvailable) return PacketDisposition.Tunnel;
        if (tunnelRequired) return PacketDisposition.Drop;
        return allowLeak ? PacketDisposition.Bypass : PacketDisposition.Drop;
    }

    private void FlushPendingIpv6(
        WinDivertFlowTable.Ipv6FragKey key, bool discardPending)
    {
        if (discardPending)
        {
            _pendingIpv6.Discard(key);
            return;
        }
        foreach (var pending in _pendingIpv6.Take(key))
        {
            Interlocked.Increment(ref _reorderedFragmentsReleased);
            var pendingAddress = pending.Address;
            HandleIpv6(pending.Packet, pending.Packet.Length, ref pendingAddress);
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
        int payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
        // Payload Length zero is valid for a base-header-only packet (for example,
        // No Next Header). Any bytes beyond that would require Hop-by-Hop Jumbo Payload
        // processing, which this path deliberately does not implement. Length equality
        // also rejects truncated and trailing captures.
        if (payloadLength + 40 != length) return false;
        byte next = packet[6];
        int offset = 40;
        bool fragmented = false;
        bool firstFragment = true;
        uint fragmentId = 0;
        byte fragmentProtocol = 0;
        bool moreFragments = false;
        for (int headers = 0; headers < 16; headers++)
        {
            if (next is 6 or 17)
            {
                meta = new Ipv6PacketMeta(
                    next, fragmented ? fragmentProtocol : next, offset,
                    fragmented, firstFragment, moreFragments, fragmentId,
                    length >= offset + (next == 6 ? 20 : 8));
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
                if (fragmented || length < offset + 8) return false;
                byte following = packet[offset];
                ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 2, 2));
                int fragmentOffset = fragment >> 3;
                bool fragmentMore = (fragment & 0x0001) != 0;
                int fragmentPayloadLength = length - (offset + 8);
                long reassembledPayloadLength = (offset - 40L)
                    + fragmentOffset * 8L + fragmentPayloadLength;
                if (packet[offset + 1] != 0
                    || (fragment & 0x0006) != 0
                    || (fragmentMore && (fragmentPayloadLength & 7) != 0)
                    || ((fragmentOffset != 0 || fragmentMore) && fragmentPayloadLength == 0)
                    || reassembledPayloadLength > ushort.MaxValue)
                    return false;
                fragmented = true;
                fragmentProtocol = following;
                firstFragment = fragmentOffset == 0;
                moreFragments = fragmentMore;
                fragmentId = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 4, 4));
                next = following;
                offset += 8;
                if (!firstFragment)
                {
                    meta = new Ipv6PacketMeta(
                        next, fragmentProtocol, offset, true, false, moreFragments, fragmentId,
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
                fragmented, firstFragment, moreFragments, fragmentId,
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
        bool MoreFragments,
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
        // destination, not prematurely bypass the packet before DNS NAT is applied. A DNS
        // list containing only the other family cannot be translated safely and must not
        // fall back to the original physical resolver.
        bool canTunnelDns = CanTunnelDns();
        if (TunnelDnsFamilyMismatch(meta.IsDns, _dnsServers.Count, canTunnelDns))
            return PacketDisposition.Drop;
        if (!meta.IsDns || _dnsServers.Count == 0)
            if (_dest.ShouldBypassTunnel(dst)) return PacketDisposition.Bypass;
        // WinDivert's NETWORK layer can attribute TCP/UDP endpoints to a process.
        // Other protocols have no safe owning-process identity or reversible flow key.
        var disp = meta.IsDns && canTunnelDns
            ? PacketDisposition.Tunnel
            : proto is 6 or 17
            ? _apps.Classify(proto, src, localPort, dst, remotePort)
            : PacketDisposition.Drop;
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
        if (meta.IsDns && !HasTunnelDns(AddressFamily.InterNetwork)
            && _clientIpv6 != null && HasTunnelDns(AddressFamily.InterNetworkV6))
            return BuildIpv4DnsAsIpv6(buf, len, ref addr, meta, destination);
        var origSrc = meta.OrigSrc;
        var clientIp = _clientIpv4
            ?? throw new InvalidOperationException("IPv4 tunnel address is unavailable");
        WriteIpv4(buf, 12, clientIp);

        IPAddress? dnsOrig = null;
        IPAddress tunnelDst = meta.FragmentTunnelDst ?? meta.Dst;
        var dnsServers = _dnsServers
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .ToList();
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

        ushort translatedLocalPort = meta.LocalPort;
        if (meta.Proto is 6 or 17 && meta.LocalPort != 0)
        {
            int ihl = (buf[0] & 0x0F) * 4;
            bool tcpFin = meta.Proto == 6 && len >= ihl + 14 && (buf[ihl + 13] & 0x01) != 0;
            bool tcpRst = meta.Proto == 6 && len >= ihl + 14 && (buf[ihl + 13] & 0x04) != 0;
            ushort translatedPort = _flows.RememberOutbound(
                meta.Proto, clientIp, origSrc, meta.LocalPort,
                tunnelDst, meta.RemotePort, in addr, dnsOrig, tcpFin, tcpRst);
            if (translatedPort == 0)
            {
                _log?.Invoke("WinDivert packet dropped: NAT flow-port space exhausted");
                return 0;
            }
            if (translatedPort != meta.LocalPort)
                BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(ihl, 2), translatedPort);
            translatedLocalPort = translatedPort;
        }

        if (meta.IsFragment)
        {
            if (meta.IsFirstFrag && !AdjustFragmentTransportChecksum(
                    buf, len, meta.Proto, origSrc, clientIp, meta.Dst, tunnelDst,
                    meta.LocalPort, translatedLocalPort, meta.RemotePort, meta.RemotePort))
            {
                _log?.Invoke("WinDivert fragment dropped: first fragment does not contain a complete transport header");
                return 0;
            }
            FixFragmentChecksums(buf, len, meta.Proto, meta.IsFirstFrag, ref addr);
        }
        else
        {
            FixChecksums(buf, len, ref addr);
        }
        Buffer.BlockCopy(buf, 0, destination, 0, len);
        return len;
    }

    private int BuildIpv6TunnelPacket(
        byte[] buf,
        int len,
        ref WinDivertNative.WinDivertAddress addr,
        Ipv6PacketMeta meta,
        IPAddress originalSource,
        IPAddress originalDestination,
        IPAddress? fragmentTunnelDestination,
        byte[] destination)
    {
        if (len > destination.Length)
        {
            _log?.Invoke(
                $"WinDivert IPv6 packet dropped: {len} bytes exceeds packet-pump buffer {destination.Length}");
            return 0;
        }
        bool isDns = meta.HasTransport && meta.Protocol is 6 or 17
            && BinaryPrimitives.ReadUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset + 2, 2)) == 53;
        if (isDns && !HasTunnelDns(AddressFamily.InterNetworkV6)
            && _clientIpv4 != null && HasTunnelDns(AddressFamily.InterNetwork))
            return BuildIpv6DnsAsIpv4(
                buf, len, ref addr, meta, originalSource, originalDestination, destination);
        var clientIp = _clientIpv6
            ?? throw new InvalidOperationException("IPv6 tunnel address is unavailable");
        WriteIpv6(buf, 8, clientIp);

        ushort localPort = 0, remotePort = 0;
        if (meta.HasTransport && meta.Protocol is 6 or 17)
        {
            localPort = BinaryPrimitives.ReadUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset, 2));
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset + 2, 2));
        }

        IPAddress? dnsOriginal = null;
        IPAddress tunnelDestination = fragmentTunnelDestination ?? originalDestination;
        var dnsServers = _dnsServers
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetworkV6)
            .ToList();
        if (meta.HasTransport && meta.Protocol is 6 or 17
            && remotePort == 53 && dnsServers.Count > 0)
        {
            dnsOriginal = originalDestination;
            tunnelDestination = SelectDnsResolver(
                dnsServers, meta.Protocol, originalSource, localPort,
                originalDestination, remotePort);
            WriteIpv6(buf, 24, tunnelDestination);
        }
        else if (!tunnelDestination.Equals(originalDestination))
        {
            WriteIpv6(buf, 24, tunnelDestination);
        }

        if (meta.IsFragment && meta.IsFirstFragment)
            _flows.SetIpv6FragTunnelDestination(
                originalSource, originalDestination, meta.FragmentProtocol,
                meta.FragmentId, tunnelDestination);

        ushort translatedPort = localPort;
        if (meta.HasTransport && meta.Protocol is 6 or 17 && localPort != 0)
        {
            bool tcpFin = meta.Protocol == 6
                && len >= meta.TransportOffset + 14
                && (buf[meta.TransportOffset + 13] & 0x01) != 0;
            bool tcpRst = meta.Protocol == 6
                && len >= meta.TransportOffset + 14
                && (buf[meta.TransportOffset + 13] & 0x04) != 0;
            translatedPort = _flows.RememberOutbound(
                meta.Protocol, clientIp, originalSource, localPort,
                tunnelDestination, remotePort, in addr, dnsOriginal, tcpFin, tcpRst);
            if (translatedPort == 0)
            {
                _log?.Invoke("WinDivert IPv6 packet dropped: NAT flow-port space exhausted");
                return 0;
            }
            if (translatedPort != localPort)
                BinaryPrimitives.WriteUInt16BigEndian(
                    buf.AsSpan(meta.TransportOffset, 2), translatedPort);
        }

        if (meta.IsFragment)
        {
            if (meta.IsFirstFragment && meta.HasTransport && meta.Protocol is 6 or 17)
                AdjustIpv6TransportChecksum(
                    buf, meta, originalSource, clientIp,
                    originalDestination, tunnelDestination,
                    localPort, translatedPort, remotePort, remotePort);
            FixIpv6FragmentChecksums(buf, len, meta, ref addr);
        }
        else
        {
            FixChecksums(buf, len, ref addr);
        }
        Buffer.BlockCopy(buf, 0, destination, 0, len);
        return len;
    }

    private int BuildIpv4DnsAsIpv6(
        byte[] packet, int length, ref WinDivertNative.WinDivertAddress address,
        Ipv4Meta meta, byte[] destination)
    {
        if (meta.IsFragment || meta.Proto is not (6 or 17)
            || meta.LocalPort == 0 || meta.RemotePort != 53 || _clientIpv6 == null)
            return 0;
        int ihl = (packet[0] & 0x0F) * 4;
        int total = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2, 2));
        if (ihl < 20 || total < ihl || total > length) return 0;
        int payloadLength = total - ihl;
        int translatedLength = 40 + payloadLength;
        if (translatedLength > destination.Length || translatedLength > 0xFFFF) return 0;

        var resolvers = _dnsServers
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetworkV6)
            .ToList();
        if (resolvers.Count == 0) return 0;
        var resolver = SelectDnsResolver(
            resolvers, meta.Proto, meta.OrigSrc, meta.LocalPort, meta.Dst, meta.RemotePort);
        bool tcpFin = meta.Proto == 6 && total >= ihl + 14 && (packet[ihl + 13] & 0x01) != 0;
        bool tcpRst = meta.Proto == 6 && total >= ihl + 14 && (packet[ihl + 13] & 0x04) != 0;
        ushort translatedPort = _flows.RememberOutbound(
            meta.Proto, _clientIpv6, meta.OrigSrc, meta.LocalPort,
            resolver, meta.RemotePort, in address, meta.Dst, tcpFin, tcpRst);
        if (translatedPort == 0) return 0;

        Array.Clear(destination, 0, 40);
        destination[0] = (byte)(0x60 | (packet[1] >> 4));
        destination[1] = (byte)((packet[1] & 0x0F) << 4);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.AsSpan(4, 2), (ushort)payloadLength);
        destination[6] = meta.Proto;
        destination[7] = packet[8];
        WriteIpv6(destination, 8, _clientIpv6);
        WriteIpv6(destination, 24, resolver);
        Buffer.BlockCopy(packet, ihl, destination, 40, payloadLength);
        if (translatedPort != meta.LocalPort)
            BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(40, 2), translatedPort);
        FixChecksums(destination, translatedLength, ref address);
        return translatedLength;
    }

    private int BuildIpv6DnsAsIpv4(
        byte[] packet, int length, ref WinDivertNative.WinDivertAddress address,
        Ipv6PacketMeta meta, IPAddress originalSource, IPAddress originalDestination,
        byte[] destination)
    {
        if (meta.IsFragment || !meta.HasTransport || meta.Protocol is not (6 or 17)
            || _clientIpv4 == null) return 0;
        ushort localPort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(meta.TransportOffset, 2));
        ushort remotePort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(meta.TransportOffset + 2, 2));
        if (localPort == 0 || remotePort != 53) return 0;
        int payloadLength = length - meta.TransportOffset;
        int translatedLength = 20 + payloadLength;
        if (payloadLength < 8 || translatedLength > destination.Length
            || translatedLength > 0xFFFF) return 0;

        var resolvers = _dnsServers
            .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .ToList();
        if (resolvers.Count == 0) return 0;
        var resolver = SelectDnsResolver(
            resolvers, meta.Protocol, originalSource, localPort, originalDestination, remotePort);
        bool tcpFin = meta.Protocol == 6 && length >= meta.TransportOffset + 14
            && (packet[meta.TransportOffset + 13] & 0x01) != 0;
        bool tcpRst = meta.Protocol == 6 && length >= meta.TransportOffset + 14
            && (packet[meta.TransportOffset + 13] & 0x04) != 0;
        ushort translatedPort = _flows.RememberOutbound(
            meta.Protocol, _clientIpv4, originalSource, localPort,
            resolver, remotePort, in address, originalDestination, tcpFin, tcpRst);
        if (translatedPort == 0) return 0;

        Array.Clear(destination, 0, 20);
        destination[0] = 0x45;
        destination[1] = (byte)(((packet[0] & 0x0F) << 4) | (packet[1] >> 4));
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.AsSpan(2, 2), (ushort)translatedLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            destination.AsSpan(4, 2), (ushort)Random.Shared.Next(1, 0x10000));
        destination[8] = packet[7];
        destination[9] = meta.Protocol;
        WriteIpv4(destination, 12, _clientIpv4);
        WriteIpv4(destination, 16, resolver);
        Buffer.BlockCopy(packet, meta.TransportOffset, destination, 20, payloadLength);
        if (translatedPort != localPort)
            BinaryPrimitives.WriteUInt16BigEndian(destination.AsSpan(20, 2), translatedPort);
        FixChecksums(destination, translatedLength, ref address);
        return translatedLength;
    }

    /// <summary>Queues one inner IP packet. Oversized IPv4 may be fragmented when DF is
    /// clear. IPv6 is never fragmented by this router; its caller emits ICMPv6 PTB.</summary>
    private bool QueueTunnelPacket(byte[] packet, int length)
    {
        if (length <= _tunnelMtu)
        {
            if (_uplink.Writer.TryWrite(new PacketLease(packet, length))) return true;
            Interlocked.Increment(ref _queueDrops);
            ArrayPool<byte>.Shared.Return(packet);
            return false;
        }

        if ((packet[0] >> 4) != 4
            || !TryFragmentIpv4(packet, length, _tunnelMtu, out var fragments))
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
                RewriteTcpMssAndChecksum(packet, ihl, pos + 2, (ushort)advertisedMss);
                return true;
            }
            pos += optionLength;
        }
        return false;
    }

    internal static bool ClampIpv6TcpMss(
        byte[] packet, int length, Ipv6PacketMeta meta, int mtu)
    {
        if (length < 40 || (packet[0] >> 4) != 6
            || meta.Protocol != 6 || !meta.HasTransport
            || (meta.IsFragment && !meta.IsFirstFragment)) return false;
        int tcpOffset = meta.TransportOffset;
        if (length < tcpOffset + 20) return false;
        int tcpLength = (packet[tcpOffset + 12] >> 4) * 4;
        if (tcpLength < 20 || length < tcpOffset + tcpLength
            || (packet[tcpOffset + 13] & 0x02) == 0) return false;

        int advertisedMss = Math.Max(1220, mtu - 60);
        for (int pos = tcpOffset + 20, end = tcpOffset + tcpLength; pos < end;)
        {
            byte kind = packet[pos];
            if (kind == 0) break;
            if (kind == 1) { pos++; continue; }
            if (pos + 1 >= end) break;
            int optionLength = packet[pos + 1];
            if (optionLength < 2 || pos + optionLength > end) break;
            if (kind == 2 && optionLength == 4)
            {
                ushort current = BinaryPrimitives.ReadUInt16BigEndian(
                    packet.AsSpan(pos + 2, 2));
                if (current <= advertisedMss) return false;
                RewriteTcpMssAndChecksum(packet, tcpOffset, pos + 2, (ushort)advertisedMss);
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

    /// <summary>Build the header used after the first IPv4 fragment. RFC 791 copies only
    /// options whose type has the copy bit set; record-route/timestamp-style options stay on
    /// the first fragment. Refuse malformed option lengths before emitting any fragments.</summary>
    private static bool TryBuildLaterIpv4Header(
        byte[] packet, int ihl, out byte[] laterHeader)
    {
        laterHeader = Array.Empty<byte>();
        if (ihl < 20 || ihl > 60 || packet.Length < ihl) return false;
        var header = new byte[60];
        Buffer.BlockCopy(packet, 0, header, 0, 20);
        int read = 20;
        int write = 20;
        while (read < ihl)
        {
            byte option = packet[read];
            int kind = option & 0x1F;
            bool copied = (option & 0x80) != 0;
            if (kind == 0) break; // EOL
            if (kind == 1)       // NOP
            {
                if (copied) header[write++] = option;
                read++;
                continue;
            }
            if (read + 1 >= ihl) return false;
            int optionLength = packet[read + 1];
            if (optionLength < 2 || read + optionLength > ihl) return false;
            if (copied)
            {
                Buffer.BlockCopy(packet, read, header, write, optionLength);
                write += optionLength;
            }
            read += optionLength;
        }
        while ((write & 3) != 0) header[write++] = 0;
        header[0] = (byte)((header[0] & 0xF0) | (write / 4));
        Array.Resize(ref header, write);
        laterHeader = header;
        return true;
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
        if (!TryBuildLaterIpv4Header(packet, ihl, out var laterHeader)) return false;

        ushort originalFragment = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6, 2));
        if ((originalFragment & 0x4000) != 0) return false;
        int baseOffset = originalFragment & 0x1FFF;
        bool originalMore = (originalFragment & 0x2000) != 0;
        int payloadLength = totalLength - ihl;
        if (payloadLength <= 0 || (originalMore && (payloadLength & 7) != 0)) return false;
        int lastOffset = baseOffset + (payloadLength - 1) / 8;
        if (lastOffset > 0x1FFF) return false;
        int headerBudget = Math.Max(ihl, laterHeader.Length);
        int maxPayload = ((mtu - headerBudget) / 8) * 8;
        if (maxPayload <= 0 || payloadLength <= maxPayload) return false;

        try
        {
            for (int consumed = 0; consumed < payloadLength; consumed += maxPayload)
            {
                int chunk = Math.Min(maxPayload, payloadLength - consumed);
                int fragmentHeaderLength = consumed == 0 ? ihl : laterHeader.Length;
                int fragmentLength = fragmentHeaderLength + chunk;
                byte[] buffer = ArrayPool<byte>.Shared.Rent(fragmentLength);
                if (consumed == 0) Buffer.BlockCopy(packet, 0, buffer, 0, ihl);
                else Buffer.BlockCopy(laterHeader, 0, buffer, 0, laterHeader.Length);
                Buffer.BlockCopy(packet, ihl + consumed, buffer, fragmentHeaderLength, chunk);
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)fragmentLength);
                bool more = consumed + chunk < payloadLength || originalMore;
                ushort field = (ushort)((originalFragment & 0x8000)
                    | (more ? 0x2000 : 0)
                    | (baseOffset + consumed / 8));
                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), field);
                WriteInternetChecksum(buffer.AsSpan(0, fragmentHeaderLength), 10);
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

    internal static byte[][] FragmentIpv4ForSelfTest(byte[] packet, int length, int mtu)
    {
        if (!TryFragmentIpv4(packet, length, mtu, out var leases)) return Array.Empty<byte[]>();
        try
        {
            var copies = new byte[leases.Count][];
            for (int i = 0; i < leases.Count; i++)
                copies[i] = leases[i].Buffer.AsSpan(0, leases[i].Length).ToArray();
            return copies;
        }
        finally
        {
            foreach (var lease in leases) ArrayPool<byte>.Shared.Return(lease.Buffer);
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

    private void InjectIcmpv6PacketTooBig(
        byte[] original,
        int originalLength,
        int mtu,
        Ipv6PacketMeta meta,
        ref WinDivertNative.WinDivertAddress capturedAddress)
    {
        if (originalLength < 40 || (original[0] >> 4) != 6) return;
        // ICMPv6 errors must not be generated in response to another ICMPv6 error.
        if (meta.Protocol == 58 && originalLength > meta.TransportOffset
            && original[meta.TransportOffset] < 128) return;

        const int outerHeaderLength = 40;
        const int icmpHeaderLength = 8;
        int quotedLength = Math.Min(originalLength, 1280 - outerHeaderLength - icmpHeaderLength);
        int length = outerHeaderLength + icmpHeaderLength + quotedLength;
        byte[] packet = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            Array.Clear(packet, 0, length);
            packet[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(4, 2), checked((ushort)(icmpHeaderLength + quotedLength)));
            packet[6] = 58; // ICMPv6
            packet[7] = 64;
            Buffer.BlockCopy(original, 24, packet, 8, 16);  // remote -> local
            Buffer.BlockCopy(original, 8, packet, 24, 16);
            packet[40] = 2; // Packet Too Big
            packet[41] = 0;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(44, 4), (uint)mtu);
            Buffer.BlockCopy(original, 0, packet, 48, quotedLength);

            IntPtr h;
            lock (_gate)
            {
                if (_disposed || _handle == IntPtr.Zero) return;
                h = _handle;
            }
            var addr = capturedAddress;
            addr.Outbound = false;
            FixChecksums(packet, length, ref addr);
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

    private void InjectIpv4DnsReplyAsIpv6(
        byte[] packet, int length, int ihl, byte protocol,
        IPAddress remoteIp, IPAddress tunnelIp, ushort remotePort, ushort localPort,
        WinDivertFlowTable.FlowEntry flow, IntPtr handle)
    {
        if (flow.DnsOrigDst is not { AddressFamily: AddressFamily.InterNetworkV6 } dns
            || flow.OriginalSrc.AddressFamily != AddressFamily.InterNetworkV6)
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        int payloadLength = length - ihl;
        int translatedLength = 40 + payloadLength;
        if (payloadLength < 8 || translatedLength > packet.Length || translatedLength > 0xFFFF)
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        byte trafficClass = packet[1];
        byte hopLimit = packet[8];
        Buffer.BlockCopy(packet, ihl, packet, 40, payloadLength);
        Array.Clear(packet, 0, 40);
        packet[0] = (byte)(0x60 | (trafficClass >> 4));
        packet[1] = (byte)((trafficClass & 0x0F) << 4);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), (ushort)payloadLength);
        packet[6] = protocol;
        packet[7] = hopLimit;
        WriteIpv6(packet, 8, dns);
        WriteIpv6(packet, 24, flow.OriginalSrc);
        if (flow.OriginalLocalPort != localPort)
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(42, 2), flow.OriginalLocalPort);
        var address = flow.Addr;
        address.Outbound = false;
        FixChecksums(packet, translatedLength, ref address);
        if (protocol == 6 && payloadLength >= 14)
        {
            byte flags = packet[53];
            _flows.ObserveInboundTcp(
                remoteIp, remotePort, tunnelIp, localPort,
                fin: (flags & 0x01) != 0, rst: (flags & 0x04) != 0);
        }
        if (WinDivertNative.WinDivertSend(
                handle, packet, (uint)translatedLength, out _, ref address))
            Interlocked.Increment(ref _replyInjected);
        else
            Interlocked.Increment(ref _replyDrops);
    }

    private void InjectIpv6DnsReplyAsIpv4(
        byte[] packet, int length, Ipv6PacketMeta meta,
        IPAddress remoteIp, IPAddress tunnelIp, ushort remotePort, ushort localPort,
        WinDivertFlowTable.FlowEntry flow, IntPtr handle)
    {
        if (flow.DnsOrigDst is not { AddressFamily: AddressFamily.InterNetwork } dns
            || flow.OriginalSrc.AddressFamily != AddressFamily.InterNetwork)
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        int payloadLength = length - meta.TransportOffset;
        int translatedLength = 20 + payloadLength;
        if (payloadLength < 8 || translatedLength > packet.Length || translatedLength > 0xFFFF)
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        byte trafficClass = (byte)(((packet[0] & 0x0F) << 4) | (packet[1] >> 4));
        byte ttl = packet[7];
        Buffer.BlockCopy(packet, meta.TransportOffset, packet, 20, payloadLength);
        Array.Clear(packet, 0, 20);
        packet[0] = 0x45;
        packet[1] = trafficClass;
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(2, 2), (ushort)translatedLength);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(4, 2), (ushort)Random.Shared.Next(1, 0x10000));
        packet[8] = ttl;
        packet[9] = meta.Protocol;
        WriteIpv4(packet, 12, dns);
        WriteIpv4(packet, 16, flow.OriginalSrc);
        if (flow.OriginalLocalPort != localPort)
            BinaryPrimitives.WriteUInt16BigEndian(
                packet.AsSpan(22, 2), flow.OriginalLocalPort);
        var address = flow.Addr;
        address.Outbound = false;
        FixChecksums(packet, translatedLength, ref address);
        if (meta.Protocol == 6 && payloadLength >= 14)
        {
            byte flags = packet[33];
            _flows.ObserveInboundTcp(
                remoteIp, remotePort, tunnelIp, localPort,
                fin: (flags & 0x01) != 0, rst: (flags & 0x04) != 0);
        }
        if (WinDivertNative.WinDivertSend(
                handle, packet, (uint)translatedLength, out _, ref address))
            Interlocked.Increment(ref _replyInjected);
        else
            Interlocked.Increment(ref _replyDrops);
    }

    public void SendPacket(byte[] packet, int offset, int length)
    {
        lock (_policyGate) SendPacketCore(packet, offset, length);
    }

    private void SendPacketCore(byte[] packet, int offset, int length)
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
        byte version = (byte)(buf[0] >> 4);
        if (version == 6)
        {
            SendIpv6Packet(buf, length, h);
            return;
        }
        if (version != 4 || _clientIpv4 == null) return;
        var tunnelIpv4 = _clientIpv4;
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
            && new IPAddress(buf.AsSpan(quotedIpOffset + 12, 4).ToArray()).Equals(tunnelIpv4)
            && _flows.TryGetInbound(
                quotedProto, quotedRemote, quotedRemotePort,
                tunnelIpv4, quotedLocalPort, out var icmpFlow))
        {
            // Rewriting the quoted datagram changes the outer ICMP checksum. A complete
            // message can be recalculated normally; a first fragment cannot, so refuse it
            // rather than stamp a checksum over only the partial ICMP body.
            if (moreFragments)
            {
                Interlocked.Increment(ref _replyDrops);
                return;
            }
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
        else if (!_flows.TryGetInbound(proto, remoteIp, remotePort, tunnelIpv4, localPort, out flow))
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

        if (flow.OriginalSrc.AddressFamily != AddressFamily.InterNetwork)
        {
            if (moreFragments || fragOffset != 0)
            {
                _pendingInboundIpv4.Discard(fragmentKey);
                Interlocked.Increment(ref _replyDrops);
            }
            else
            {
                InjectIpv4DnsReplyAsIpv6(
                    buf, length, ihl, proto, remoteIp, tunnelIpv4,
                    remotePort, localPort, flow, h);
            }
            return;
        }

        var translatedSource = flow.DnsOrigDst ?? remoteIp;
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
        bool fragmented = moreFragments || fragOffset != 0;
        if (fragmented)
        {
            if (fragOffset == 0 && !AdjustFragmentTransportChecksum(
                    buf, length, proto, remoteIp, translatedSource,
                    clientIp, flow.OriginalSrc,
                    remotePort, remotePort, localPort, flow.OriginalLocalPort))
            {
                Interlocked.Increment(ref _replyDrops);
                return;
            }
            FixFragmentChecksums(buf, length, proto, fragOffset == 0, ref addr);
        }
        else
        {
            FixChecksums(buf, length, ref addr);
        }
        if (fragOffset == 0 && proto == 6 && length >= ihl + 14)
        {
            byte flags = buf[ihl + 13];
            _flows.ObserveInboundTcp(
                remoteIp, remotePort, tunnelIpv4, localPort,
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

    private void SendIpv6Packet(byte[] buf, int length, IntPtr handle)
    {
        var tunnelIpv6 = _clientIpv6;
        if (tunnelIpv6 == null || !TryParseIpv6Packet(buf, length, out var meta))
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }

        var remoteIp = new IPAddress(buf.AsSpan(8, 16).ToArray());
        var clientIp = new IPAddress(buf.AsSpan(24, 16).ToArray());

        // ICMPv6 errors quote the original outbound packet. Recover its translated
        // TCP/UDP tuple and restore both the outer destination and quoted tuple.
        if (!meta.IsFragment && meta.Protocol == 58
            && TryParseIcmpv6QuotedFlow(
                buf, length, out byte quotedProtocol, out var quotedRemote,
                out ushort quotedRemotePort, out ushort quotedLocalPort,
                out int quotedIpOffset, out int quotedTransportOffset)
            && new IPAddress(buf.AsSpan(quotedIpOffset + 8, 16).ToArray()).Equals(tunnelIpv6)
            && _flows.TryGetInbound(
                quotedProtocol, quotedRemote, quotedRemotePort,
                tunnelIpv6, quotedLocalPort, out var icmpFlow))
        {
            WriteIpv6(buf, 24, icmpFlow.OriginalSrc);
            WriteIpv6(buf, quotedIpOffset + 8, icmpFlow.OriginalSrc);
            if (icmpFlow.OriginalLocalPort != quotedLocalPort)
                BinaryPrimitives.WriteUInt16BigEndian(
                    buf.AsSpan(quotedTransportOffset, 2), icmpFlow.OriginalLocalPort);
            if (icmpFlow.DnsOrigDst is { } originalDns)
            {
                var outerSource = new IPAddress(buf.AsSpan(8, 16).ToArray());
                if (outerSource.Equals(quotedRemote)) WriteIpv6(buf, 8, originalDns);
                WriteIpv6(buf, quotedIpOffset + 24, originalDns);
            }

            var icmpAddress = icmpFlow.Addr;
            icmpAddress.Outbound = false;
            FixChecksums(buf, length, ref icmpAddress);
            if (WinDivertNative.WinDivertSend(
                    handle, buf, (uint)length, out _, ref icmpAddress))
                Interlocked.Increment(ref _replyInjected);
            else
                Interlocked.Increment(ref _replyDrops);
            return;
        }

        ushort remotePort = 0, localPort = 0;
        if (meta.HasTransport && meta.Protocol is 6 or 17)
        {
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset, 2));
            localPort = BinaryPrimitives.ReadUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset + 2, 2));
        }

        WinDivertFlowTable.FlowEntry flow;
        IReadOnlyList<byte[]> reordered = Array.Empty<byte[]>();
        var fragmentKey = new WinDivertFlowTable.Ipv6FragKey(
            remoteIp, clientIp, meta.FragmentProtocol, meta.FragmentId);
        if (meta.IsFragment && !meta.IsFirstFragment)
        {
            if (!_flows.TryGetInboundIpv6Frag(
                    remoteIp, clientIp, meta.FragmentProtocol, meta.FragmentId, out flow))
            {
                var copy = buf.AsSpan(0, length).ToArray();
                if (_pendingInboundIpv6.Add(fragmentKey, copy))
                    Interlocked.Increment(ref _earlyFragmentsBuffered);
                else
                    Interlocked.Increment(ref _replyDrops);
                return;
            }
        }
        else if (!meta.HasTransport || meta.Protocol is not (6 or 17)
            || !_flows.TryGetInbound(
                meta.Protocol, remoteIp, remotePort, tunnelIpv6, localPort, out flow))
        {
            Interlocked.Increment(ref _replyDrops);
            return;
        }
        else if (meta.IsFragment && meta.MoreFragments)
        {
            _flows.RememberInboundIpv6Frag(
                remoteIp, clientIp, meta.FragmentProtocol, meta.FragmentId, in flow);
            reordered = _pendingInboundIpv6.Take(fragmentKey);
        }

        if (flow.OriginalSrc.AddressFamily != AddressFamily.InterNetworkV6)
        {
            if (meta.IsFragment)
            {
                _pendingInboundIpv6.Discard(fragmentKey);
                Interlocked.Increment(ref _replyDrops);
            }
            else
            {
                InjectIpv6DnsReplyAsIpv4(
                    buf, length, meta, remoteIp, tunnelIpv6,
                    remotePort, localPort, flow, handle);
            }
            return;
        }

        var exposedSource = flow.DnsOrigDst ?? remoteIp;
        WriteIpv6(buf, 24, flow.OriginalSrc);
        if (meta.IsFirstFragment && meta.HasTransport && meta.Protocol is 6 or 17
            && flow.OriginalLocalPort != localPort)
            BinaryPrimitives.WriteUInt16BigEndian(
                buf.AsSpan(meta.TransportOffset + 2, 2), flow.OriginalLocalPort);
        if (flow.DnsOrigDst is { } dns) WriteIpv6(buf, 8, dns);

        var address = flow.Addr;
        address.Outbound = false;
        if (meta.IsFragment)
        {
            if (meta.IsFirstFragment && meta.HasTransport && meta.Protocol is 6 or 17)
                AdjustIpv6TransportChecksum(
                    buf, meta, remoteIp, exposedSource,
                    clientIp, flow.OriginalSrc,
                    remotePort, remotePort, localPort, flow.OriginalLocalPort);
            FixIpv6FragmentChecksums(buf, length, meta, ref address);
        }
        else
        {
            FixChecksums(buf, length, ref address);
        }
        if (meta.IsFirstFragment && meta.Protocol == 6
            && length >= meta.TransportOffset + 14)
        {
            byte flags = buf[meta.TransportOffset + 13];
            _flows.ObserveInboundTcp(
                remoteIp, remotePort, tunnelIpv6, localPort,
                fin: (flags & 0x01) != 0, rst: (flags & 0x04) != 0);
        }
        if (WinDivertNative.WinDivertSend(
                handle, buf, (uint)length, out _, ref address))
            Interlocked.Increment(ref _replyInjected);
        else
            Interlocked.Increment(ref _replyDrops);

        foreach (var pending in reordered)
        {
            Interlocked.Increment(ref _reorderedFragmentsReleased);
            SendPacket(pending, 0, pending.Length);
        }
    }

    internal static bool TryParseIcmpv6QuotedFlow(
        byte[] packet,
        int length,
        out byte protocol,
        out IPAddress remoteIp,
        out ushort remotePort,
        out ushort localPort,
        out int quotedIpOffset,
        out int quotedTransportOffset)
    {
        protocol = 0;
        remoteIp = IPAddress.IPv6None;
        remotePort = 0;
        localPort = 0;
        quotedIpOffset = 0;
        quotedTransportOffset = 0;
        if (!TryParseIpv6Packet(packet, length, out var outer)
            || outer.IsFragment || outer.Protocol != 58
            || length < outer.TransportOffset + 8 + 40) return false;
        byte type = packet[outer.TransportOffset];
        if (type is not (1 or 2 or 3 or 4)) return false;

        quotedIpOffset = outer.TransportOffset + 8;
        if (!TryLocateQuotedIpv6Transport(
                packet, quotedIpOffset, length,
                out protocol, out quotedTransportOffset)) return false;
        remoteIp = new IPAddress(packet.AsSpan(quotedIpOffset + 24, 16).ToArray());
        localPort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(quotedTransportOffset, 2));
        remotePort = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(quotedTransportOffset + 2, 2));
        return localPort != 0;
    }

    private static bool TryLocateQuotedIpv6Transport(
        byte[] packet,
        int ipv6Offset,
        int length,
        out byte protocol,
        out int transportOffset)
    {
        protocol = 0;
        transportOffset = 0;
        if (ipv6Offset < 0 || length < ipv6Offset + 40
            || (packet[ipv6Offset] >> 4) != 6) return false;
        byte next = packet[ipv6Offset + 6];
        int offset = ipv6Offset + 40;
        for (int headers = 0; headers < 16; headers++)
        {
            if (next is 6 or 17)
            {
                if (length < offset + 4) return false;
                protocol = next;
                transportOffset = offset;
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
                ushort fragment = BinaryPrimitives.ReadUInt16BigEndian(
                    packet.AsSpan(offset + 2, 2));
                if ((fragment & 0xFFF8) != 0) return false;
                next = packet[offset];
                offset += 8;
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
            return false;
        }
        return false;
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
        _pendingInboundIpv6.Clear();
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
            + $"fragment_buffer_drops={_pendingIpv6.DroppedCount + _pendingOutboundIpv4.DroppedCount + _pendingInboundIpv4.DroppedCount + _pendingInboundIpv6.DroppedCount}");
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

    private static void WriteIpv6(byte[] buf, int offset, IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 16) return;
        Buffer.BlockCopy(bytes, 0, buf, offset, 16);
    }

    /// <summary>Update a fragmented IPv4 TCP/UDP checksum incrementally after NAT. Computing
    /// from the first fragment alone would omit the payload carried by later fragments.</summary>
    private static bool AdjustFragmentTransportChecksum(
        byte[] packet, int length, byte protocol,
        IPAddress oldSource, IPAddress newSource,
        IPAddress oldDestination, IPAddress newDestination,
        ushort oldSourcePort, ushort newSourcePort,
        ushort oldDestinationPort, ushort newDestinationPort)
    {
        if (protocol is not (6 or 17)) return true;
        int ihl = (packet[0] & 0x0F) * 4;
        int checksumOffset = protocol == 6 ? ihl + 16 : ihl + 6;
        int minimumHeader = protocol == 6 ? ihl + 20 : ihl + 8;
        if (ihl < 20 || length < minimumHeader || checksumOffset + 2 > length) return false;

        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(checksumOffset, 2));
        if (protocol == 17 && checksum == 0) return true;
        var oldSrc = oldSource.GetAddressBytes();
        var newSrc = newSource.GetAddressBytes();
        var oldDst = oldDestination.GetAddressBytes();
        var newDst = newDestination.GetAddressBytes();
        if (oldSrc.Length != 4 || newSrc.Length != 4 || oldDst.Length != 4 || newDst.Length != 4)
            return false;
        for (int offset = 0; offset < 4; offset += 2)
        {
            checksum = AdjustChecksumWord(checksum,
                BinaryPrimitives.ReadUInt16BigEndian(oldSrc.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt16BigEndian(newSrc.AsSpan(offset, 2)));
            checksum = AdjustChecksumWord(checksum,
                BinaryPrimitives.ReadUInt16BigEndian(oldDst.AsSpan(offset, 2)),
                BinaryPrimitives.ReadUInt16BigEndian(newDst.AsSpan(offset, 2)));
        }
        checksum = AdjustChecksumWord(checksum, oldSourcePort, newSourcePort);
        checksum = AdjustChecksumWord(checksum, oldDestinationPort, newDestinationPort);
        if (protocol == 17 && checksum == 0) checksum = 0xFFFF;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(checksumOffset, 2), checksum);
        return true;
    }

    private static ushort AdjustChecksumWord(ushort checksum, ushort oldWord, ushort newWord)
    {
        uint sum = (uint)(~checksum & 0xFFFF) + (uint)(~oldWord & 0xFFFF) + newWord;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    /// <summary>Rewrite a two-byte MSS option and update the TCP checksum incrementally.
    /// The value can be unaligned after NOP options, in which case it spans two checksum
    /// words. Full packets are recalculated later; this adjustment is essential when the
    /// packet is subsequently split and the first fragment no longer contains the payload
    /// needed for a full transport checksum.</summary>
    private static void RewriteTcpMssAndChecksum(
        byte[] packet, int tcpOffset, int valueOffset, ushort newMss)
    {
        int relative = valueOffset - tcpOffset;
        int firstWordOffset = valueOffset - (relative & 1);
        int lastWordOffset = (relative & 1) == 0 ? firstWordOffset : firstWordOffset + 2;
        ushort oldFirst = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(firstWordOffset, 2));
        ushort oldLast = lastWordOffset == firstWordOffset
            ? oldFirst
            : BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(lastWordOffset, 2));

        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(valueOffset, 2), newMss);

        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(tcpOffset + 16, 2));
        ushort newFirst = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(firstWordOffset, 2));
        checksum = AdjustChecksumWord(checksum, oldFirst, newFirst);
        if (lastWordOffset != firstWordOffset)
        {
            ushort newLast = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(lastWordOffset, 2));
            checksum = AdjustChecksumWord(checksum, oldLast, newLast);
        }
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcpOffset + 16, 2), checksum);
    }

    private static void FixFragmentChecksums(
        byte[] packet, int length, byte protocol, bool firstFragment,
        ref WinDivertNative.WinDivertAddress addr)
    {
        addr.Flags = (byte)(addr.Flags & ~0xE0);
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)length, ref addr,
            WinDivertNative.WINDIVERT_HELPER_NO_ICMP_CHECKSUM
            | WinDivertNative.WINDIVERT_HELPER_NO_TCP_CHECKSUM
            | WinDivertNative.WINDIVERT_HELPER_NO_UDP_CHECKSUM);
        if (firstFragment && protocol == 6) addr.Flags |= 0x40;
        if (firstFragment && protocol == 17) addr.Flags |= 0x80;
    }

    internal static bool AdjustFragmentTransportChecksumForSelfTest(
        byte[] packet, int length, byte protocol,
        IPAddress oldSource, IPAddress newSource,
        IPAddress oldDestination, IPAddress newDestination,
        ushort oldSourcePort, ushort newSourcePort,
        ushort oldDestinationPort, ushort newDestinationPort) =>
        AdjustFragmentTransportChecksum(
            packet, length, protocol, oldSource, newSource, oldDestination, newDestination,
            oldSourcePort, newSourcePort, oldDestinationPort, newDestinationPort);

    private static void FixChecksums(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        addr.Flags = (byte)(addr.Flags & ~0xE0);
        WinDivertNative.WinDivertHelperCalcChecksums(buf, (uint)len, ref addr,
            WinDivertNative.WINDIVERT_HELPER_CHECKSUM_ALL);
    }

    private static void AdjustIpv6TransportChecksum(
        byte[] packet,
        Ipv6PacketMeta meta,
        IPAddress oldSource,
        IPAddress newSource,
        IPAddress oldDestination,
        IPAddress newDestination,
        ushort oldSourcePort,
        ushort newSourcePort,
        ushort oldDestinationPort,
        ushort newDestinationPort)
    {
        int checksumOffset = meta.TransportOffset + (meta.Protocol == 6 ? 16 : 6);
        if (checksumOffset + 2 > packet.Length) return;
        ushort checksum = BinaryPrimitives.ReadUInt16BigEndian(
            packet.AsSpan(checksumOffset, 2));
        ushort adjusted = AdjustIpv6NatChecksum(
            checksum,
            oldSource.GetAddressBytes(), newSource.GetAddressBytes(),
            oldDestination.GetAddressBytes(), newDestination.GetAddressBytes(),
            oldSourcePort, newSourcePort,
            oldDestinationPort, newDestinationPort,
            meta.Protocol);
        BinaryPrimitives.WriteUInt16BigEndian(
            packet.AsSpan(checksumOffset, 2), adjusted);
    }

    internal static ushort AdjustIpv6NatChecksum(
        ushort checksum,
        ReadOnlySpan<byte> oldSource,
        ReadOnlySpan<byte> newSource,
        ReadOnlySpan<byte> oldDestination,
        ReadOnlySpan<byte> newDestination,
        ushort oldSourcePort,
        ushort newSourcePort,
        ushort oldDestinationPort,
        ushort newDestinationPort,
        byte protocol)
    {
        if (oldSource.Length != 16 || newSource.Length != 16
            || oldDestination.Length != 16 || newDestination.Length != 16)
            throw new ArgumentException("IPv6 checksum adjustment requires 16-byte addresses");

        uint sum = (uint)(~checksum) & 0xFFFF;
        static void ReplaceWords(ref uint value, ReadOnlySpan<byte> oldBytes,
            ReadOnlySpan<byte> newBytes)
        {
            for (int i = 0; i < oldBytes.Length; i += 2)
            {
                ushort oldWord = BinaryPrimitives.ReadUInt16BigEndian(oldBytes.Slice(i, 2));
                ushort newWord = BinaryPrimitives.ReadUInt16BigEndian(newBytes.Slice(i, 2));
                value += (uint)(~oldWord) & 0xFFFF;
                value += newWord;
            }
        }
        static void ReplaceWord(ref uint value, ushort oldWord, ushort newWord)
        {
            value += (uint)(~oldWord) & 0xFFFF;
            value += newWord;
        }

        ReplaceWords(ref sum, oldSource, newSource);
        ReplaceWords(ref sum, oldDestination, newDestination);
        ReplaceWord(ref sum, oldSourcePort, newSourcePort);
        ReplaceWord(ref sum, oldDestinationPort, newDestinationPort);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        ushort result = (ushort)~sum;
        // UDP over IPv6 cannot use the IPv4 "checksum disabled" zero value.
        return protocol == 17 && result == 0 ? (ushort)0xFFFF : result;
    }

    private static void FixIpv6FragmentChecksums(
        byte[] packet,
        int length,
        Ipv6PacketMeta meta,
        ref WinDivertNative.WinDivertAddress address)
    {
        address.Flags = (byte)(address.Flags & ~0xE0);
        WinDivertNative.WinDivertHelperCalcChecksums(
            packet, (uint)length, ref address,
            WinDivertNative.WINDIVERT_HELPER_NO_TCP_CHECKSUM
            | WinDivertNative.WINDIVERT_HELPER_NO_UDP_CHECKSUM);
        if (meta.IsFirstFragment && meta.HasTransport)
        {
            if (meta.Protocol == 6) address.Flags |= 0x40;
            else if (meta.Protocol == 17) address.Flags |= 0x80;
        }
    }

    internal static void EnsureDriverLoaded()
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
            .Where(ip => ip != null && ip.AddressFamily is
                AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
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

    private static int ValidateMtu(int mtu, bool ipv6Enabled)
    {
        int minimum = ipv6Enabled ? 1280 : 576;
        return mtu >= minimum && mtu <= 65535
            ? mtu
            : throw new ArgumentOutOfRangeException(
                nameof(mtu), mtu,
                $"tunnel MTU must be {minimum}..65535 when IPv6 is "
                + (ipv6Enabled ? "enabled" : "disabled"));
    }

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
