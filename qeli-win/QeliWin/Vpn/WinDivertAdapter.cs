using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
public sealed class WinDivertAdapter : ITunDevice
{
    private readonly ProcessAppMap _apps;
    private readonly WinDivertFlowTable _flows = new();
    private readonly WinDivertDestinationPolicy _dest;
    private readonly IPAddress _clientIp;
    private readonly IReadOnlyList<IPAddress> _dnsServers;
    private readonly bool _allowIpv6Leak;
    private readonly Action<string>? _log;
    private IntPtr _handle = IntPtr.Zero;
    private readonly object _gate = new();
    private volatile bool _disposed;
    private volatile bool _tunnelUp = true;

    public const short ProtectedTtl = WinDivertNative.ProtectedTtl;

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
        Action<string>? log = null)
    {
        _clientIp = clientIp;
        _apps = new ProcessAppMap(apps, includeMode);
        _allowIpv6Leak = allowIpv6Leak;
        _dest = new WinDivertDestinationPolicy(routeLocal, includeRoutes, excludeRoutes, pushedRoutes);
        _dnsServers = dnsServers
            .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
            .Where(ip => ip != null && ip.AddressFamily == AddressFamily.InterNetwork)
            .Cast<IPAddress>()
            .ToList();
        _log = log;
    }

    /// <summary>Mark the VPN data plane down — include traffic is dropped, not reinjected.</summary>
    public void SetTunnelUp(bool up) => _tunnelUp = up;

    public void Open()
    {
        int addrSize = Marshal.SizeOf<WinDivertNative.WinDivertAddress>();
        if (addrSize != 80)
            throw new InvalidOperationException(
                $"WinDivertAddress layout mismatch: got {addrSize} bytes, expected 80 (WinDivert 2.2).");

        EnsureDriverLoaded();
        // Capture both IPv4 and IPv6. Do NOT put private-net exclusions in the filter —
        // WinDivert's filter compiler rejects that form; DestinationPolicy decides in
        // ReceivePacket. Carrier packets use TTL/HopLimit == ProtectedTtl.
        string filter =
            $"(ip.TTL!={ProtectedTtl} or ipv6.HopLimit!={ProtectedTtl}) and " +
            "outbound and !loopback";

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

    public byte[]? ReceivePacket(CancellationToken ct)
    {
        var buf = new byte[0xFFFF];
        while (!ct.IsCancellationRequested && !_disposed)
        {
            IntPtr h;
            lock (_gate)
            {
                if (_disposed || _handle == IntPtr.Zero) return null;
                h = _handle;
            }

            var addr = new WinDivertNative.WinDivertAddress();
            if (!WinDivertNative.WinDivertRecv(h, buf, (uint)buf.Length, out uint len, ref addr))
            {
                int err = Marshal.GetLastWin32Error();
                if (_disposed || err == 6 /* INVALID_HANDLE */) return null;
                if (err is 122 or 995) continue;
                Thread.Sleep(1);
                continue;
            }
            if (len < 20) continue;

            byte ver = (byte)(buf[0] >> 4);
            if (ver == 6)
            {
                HandleIpv6(buf, (int)len, ref addr);
                continue;
            }
            if (ver != 4) { Reinject(buf, (int)len, ref addr); continue; }

            var decision = ClassifyIpv4(buf, (int)len, ref addr, out var meta);
            switch (decision)
            {
                case PacketDisposition.Bypass:
                    Reinject(buf, (int)len, ref addr);
                    continue;
                case PacketDisposition.Drop:
                    continue; // swallow — include fail-closed / VPN down / IPv6 policy N/A
                case PacketDisposition.Tunnel:
                    if (!_tunnelUp)
                        continue; // fail-closed while VPN is down
                    return BuildTunnelPacket(buf, (int)len, ref addr, meta);
                default:
                    continue;
            }
        }
        return null;
    }

    private void HandleIpv6(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        if (_allowIpv6Leak)
        {
            Reinject(buf, len, ref addr);
            return;
        }
        // Close the dual-stack leak: if the owning app would be tunnelled on IPv4, drop
        // IPv6 so the app falls back to IPv4-over-VPN. Otherwise reinject.
        if (len < 40) { Reinject(buf, len, ref addr); return; }
        byte next = buf[6];
        var src = new IPAddress(buf.AsSpan(8, 16).ToArray());
        var dst = new IPAddress(buf.AsSpan(24, 16).ToArray());
        if (_dest.ShouldBypassTunnel(dst))
        {
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

        var disp = _apps.Classify(proto is 6 or 17 ? proto : (byte)0, src, localPort);
        if (disp == PacketDisposition.Tunnel || (disp == PacketDisposition.Drop && _apps.IncludeMode))
            return; // drop — do not leak
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
    }

    private PacketDisposition ClassifyIpv4(
        byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr, out Ipv4Meta meta)
    {
        meta = default;
        int ihl = (buf[0] & 0x0F) * 4;
        if (ihl < 20 || len < ihl) return PacketDisposition.Bypass;

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

        if (_dest.ShouldBypassTunnel(dst))
            return PacketDisposition.Bypass;

        // Non-first fragments: follow the disposition recorded for the first fragment.
        if (isFrag && !isFirst)
        {
            if (_flows.TryGetFrag(src, dst, proto, ipId, out var frag))
                return frag.Disposition;
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
            IsDns = proto == 17 && remotePort == 53,
            IsFragment = isFrag,
            IsFirstFrag = isFirst,
            IpId = ipId,
        };

        var disp = _apps.Classify(proto, src, localPort);
        if (isFrag && isFirst)
            _flows.RememberFrag(src, dst, proto, ipId, disp);
        return disp;
    }

    private byte[] BuildTunnelPacket(
        byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr, Ipv4Meta meta)
    {
        var origSrc = meta.OrigSrc;
        WriteIpv4(buf, 12, _clientIp);

        IPAddress? dnsOrig = null;
        if (meta.IsDns && _dnsServers.Count > 0)
        {
            dnsOrig = meta.Dst;
            WriteIpv4(buf, 16, _dnsServers[Random.Shared.Next(_dnsServers.Count)]);
        }

        if (meta.Proto is 6 or 17 && meta.LocalPort != 0)
        {
            _flows.RememberOutbound(
                meta.Proto, _clientIp, origSrc, meta.LocalPort,
                meta.Dst, meta.RemotePort, in addr, dnsOrig);
        }

        FixChecksums(buf, len, ref addr);
        var pkt = new byte[len];
        Buffer.BlockCopy(buf, 0, pkt, 0, len);
        return pkt;
    }

    public void SendPacket(byte[] packet, int length)
    {
        if (_disposed || length < 20 || !_tunnelUp) return;
        IntPtr h;
        lock (_gate)
        {
            if (_disposed || _handle == IntPtr.Zero) return;
            h = _handle;
        }

        var buf = new byte[length];
        Buffer.BlockCopy(packet, 0, buf, 0, length);
        if ((buf[0] >> 4) != 4) return;
        int ihl = (buf[0] & 0x0F) * 4;
        if (ihl < 20 || length < ihl) return;

        byte proto = buf[9];
        var remoteIp = new IPAddress(buf.AsSpan(12, 4).ToArray());
        ushort remotePort = 0, localPort = 0;
        if (proto is 6 or 17 && length >= ihl + 4)
        {
            remotePort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl));
            localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl + 2));
        }

        if (!_flows.TryGetInbound(proto, remoteIp, remotePort, _clientIp, localPort, out var flow))
        {
            // No matching flow — drop rather than guess a NIC/IP (fail-closed for include;
            // for exclude an orphan reply is better dropped than mis-delivered).
            return;
        }

        WriteIpv4(buf, 16, flow.OriginalSrc);

        if (proto == 17 && remotePort == 53)
        {
            var dns = flow.ActiveDnsOrigDst;
            if (dns != null)
                WriteIpv4(buf, 12, dns);
        }

        var addr = flow.Addr;
        addr.Outbound = false;
        FixChecksums(buf, length, ref addr);
        WinDivertNative.WinDivertSend(h, buf, (uint)length, out _, ref addr);
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
        _apps.Dispose();
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
        $"(ip.TTL!={ProtectedTtl} or ipv6.HopLimit!={ProtectedTtl}) and outbound and !loopback";
}
