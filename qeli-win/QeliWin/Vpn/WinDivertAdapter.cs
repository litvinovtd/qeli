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
    private WinDivertDestinationPolicy _dest;
    private readonly IPAddress _clientIp;
    private IReadOnlyList<IPAddress> _dnsServers;
    private readonly bool _allowIpv6Leak;
    private readonly Action<string>? _log;
    private CarrierEndpoint _carrier;
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
    private long _replyInjected;
    private long _replyDrops;

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
        Action<string>? log = null)
    {
        _clientIp = clientIp;
        _apps = new ProcessAppMap(apps, includeMode);
        _allowIpv6Leak = allowIpv6Leak;
        _dest = new WinDivertDestinationPolicy(routeLocal, includeRoutes, excludeRoutes, pushedRoutes);
        _dnsServers = ParseDns(dnsServers);
        _carrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
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
        string carrierProtocol)
    {
        SetTunnelUp(false);
        _dnsServers = ParseDns(dnsServers);
        _dest = new WinDivertDestinationPolicy(
            routeLocal, includeRoutes, excludeRoutes, pushedRoutes);
        _carrier = MakeCarrier(carrierIp, carrierPort, carrierProtocol);
        _flows.Clear();
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
            $"include={_apps.IncludeMode}, allow_ipv6_leak={_allowIpv6Leak})");
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

            var decision = ClassifyIpv4(buf, (int)len, ref addr, out var meta);
            switch (decision)
            {
                case PacketDisposition.Bypass:
                    Interlocked.Increment(ref _bypassed);
                    Reinject(buf, (int)len, ref addr);
                    continue;
                case PacketDisposition.Drop:
                    Interlocked.Increment(ref _policyDrops);
                    continue; // swallow — include fail-closed / VPN down / IPv6 policy N/A
                case PacketDisposition.Tunnel:
                    if (!_tunnelUp)
                    {
                        Interlocked.Increment(ref _downDrops);
                        continue; // fail-closed while VPN is down
                    }
                        byte[] packet = ArrayPool<byte>.Shared.Rent((int)len);
                        int packetLength = BuildTunnelPacket(buf, (int)len, ref addr, meta, packet);
                        if (packetLength == 0 || !_tunnelUp
                            || !_uplink.Writer.TryWrite(new PacketLease(packet, packetLength)))
                        {
                            if (packetLength > 0)
                            {
                                if (!_tunnelUp) Interlocked.Increment(ref _downDrops);
                                else Interlocked.Increment(ref _queueDrops);
                            }
                            ArrayPool<byte>.Shared.Return(packet);
                        }
                        else Interlocked.Increment(ref _tunnelled);
                        continue;
                default:
                    continue;
            }
        }
        }
        finally { _uplink.Writer.TryComplete(); }
    }

    private void HandleIpv6(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        if (_allowIpv6Leak)
        {
            Interlocked.Increment(ref _bypassed);
            Reinject(buf, len, ref addr);
            return;
        }
        // Close the dual-stack leak: if the owning app would be tunnelled on IPv4, drop
        // IPv6 so the app falls back to IPv4-over-VPN. Otherwise reinject.
        if (len < 40) return;
        byte next = buf[6];
        var src = new IPAddress(buf.AsSpan(8, 16).ToArray());
        var dst = new IPAddress(buf.AsSpan(24, 16).ToArray());
        if (_dest.ShouldBypassTunnel(dst))
        {
            Interlocked.Increment(ref _bypassed);
            Reinject(buf, len, ref addr);
            return;
        }
        // Skip extension headers best-effort for TCP/UDP ports.
        int offset = 40;
        byte proto = next;
        ushort localPort = 0;
        if (proto is 6 or 17 && len >= offset + 4)
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(offset));
        else if (proto is not (6 or 17))
        {
            // Unknown next-header chain: include fail-closed → drop candidates via Classify.
        }

        ushort remotePort = 0;
        if (proto is 6 or 17 && len >= offset + 4)
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(offset + 2));
        if (IsCarrier(proto, dst, remotePort))
        {
            Reinject(buf, len, ref addr);
            return;
        }
        var disp = _apps.Classify(proto is 6 or 17 ? proto : (byte)0, src, localPort, dst, remotePort);
        if (disp == PacketDisposition.Tunnel || (disp == PacketDisposition.Drop && _apps.IncludeMode))
        {
            Interlocked.Increment(ref _policyDrops);
            return; // drop — do not leak
        }
        Interlocked.Increment(ref _bypassed);
        Reinject(buf, len, ref addr);
    }

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
            // Unknown fragment association: include fail-closed.
            return _apps.IncludeMode ? PacketDisposition.Drop : PacketDisposition.Bypass;
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
        if (isFrag && isFirst)
            _flows.RememberFrag(src, dst, proto, ipId, disp);
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
            tunnelDst = dnsServers[Random.Shared.Next(dnsServers.Count)];
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
            _flows.RememberOutbound(
                meta.Proto, _clientIp, origSrc, meta.LocalPort,
                tunnelDst, meta.RemotePort, in addr, dnsOrig);
        }

        FixChecksums(buf, len, ref addr);
        Buffer.BlockCopy(buf, 0, destination, 0, len);
        return len;
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

        WinDivertFlowTable.FlowEntry flow;
        if (fragOffset != 0)
        {
            if (!_flows.TryGetInboundFrag(remoteIp, clientIp, proto, ipId, out flow))
            {
                Interlocked.Increment(ref _replyDrops);
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
        }

        WriteIpv4(buf, 16, flow.OriginalSrc);

        // Apply to every fragment. Only the first one has a UDP/TCP header, but all
        // fragments must expose the resolver address originally requested by the app.
        if (flow.ActiveDnsOrigDst is { } dns)
        {
            WriteIpv4(buf, 12, dns);
        }

        var addr = flow.Addr;
        addr.Outbound = false;
        FixChecksums(buf, length, ref addr);
        if (WinDivertNative.WinDivertSend(h, buf, (uint)length, out _, ref addr))
            Interlocked.Increment(ref _replyInjected);
        else
            Interlocked.Increment(ref _replyDrops);
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
        _apps.Dispose();
        _log?.Invoke("WinDivert stats: "
            + $"captured={Interlocked.Read(ref _captured)} "
            + $"tunnelled={Interlocked.Read(ref _tunnelled)} "
            + $"bypass={Interlocked.Read(ref _bypassed)} "
            + $"policy_drops={Interlocked.Read(ref _policyDrops)} "
            + $"down_drops={Interlocked.Read(ref _downDrops)} "
            + $"queue_drops={Interlocked.Read(ref _queueDrops)} "
            + $"replies={Interlocked.Read(ref _replyInjected)} "
            + $"reply_drops={Interlocked.Read(ref _replyDrops)}");
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

    private void DrainUplink()
    {
        while (_uplink.Reader.TryRead(out var lease))
            ArrayPool<byte>.Shared.Return(lease.Buffer);
    }

    private readonly record struct PacketLease(byte[] Buffer, int Length);
    private sealed record CarrierEndpoint(IPAddress Ip, ushort Port, byte Protocol);
}
