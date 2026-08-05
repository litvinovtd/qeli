using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Qeli.Shared.Vpn;

namespace QeliWin.Vpn;

/// <summary>
/// WinDivert-backed <see cref="ITunDevice"/> for per-app split tunnelling. Captures outbound
/// IPv4 packets, gates them by owning process (via <see cref="ProcessAppMap"/>), NAT-rewrites
/// tunnelled packets to the session client IP (VpnHood pattern), and reinjects replies inbound.
/// Carrier traffic is excluded by TTL=<see cref="WinDivertNative.ProtectedTtl"/> and by
/// never diverting our own PID.
/// </summary>
public sealed class WinDivertAdapter : ITunDevice
{
    private readonly ProcessAppMap _apps;
    private readonly IPAddress _clientIp;
    private readonly IPAddress _primaryIp;
    private readonly IReadOnlyList<IPAddress> _dnsServers;
    private readonly Action<string>? _log;
    private IntPtr _handle = IntPtr.Zero;
    private WinDivertNative.WinDivertAddress _lastAddr;
    private bool _haveLastAddr;
    private readonly object _gate = new();
    private volatile bool _disposed;

    // DNS rewrite: original destination for replies, keyed by client UDP source port.
    private readonly Dictionary<ushort, IPAddress> _dnsOrigDst = new();

    public const short ProtectedTtl = WinDivertNative.ProtectedTtl;

    public WinDivertAdapter(
        IPAddress clientIp,
        IEnumerable<string> apps,
        bool includeMode,
        IEnumerable<string> dnsServers,
        Action<string>? log = null)
    {
        _clientIp = clientIp;
        _apps = new ProcessAppMap(apps, includeMode);
        _dnsServers = dnsServers
            .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
            .Where(ip => ip != null && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Cast<IPAddress>()
            .ToList();
        _primaryIp = GetPrimaryIPv4() ?? IPAddress.Loopback;
        _log = log;
    }

    public void Open()
    {
        int addrSize = Marshal.SizeOf<WinDivertNative.WinDivertAddress>();
        if (addrSize != 80)
            throw new InvalidOperationException(
                $"WinDivertAddress layout mismatch: got {addrSize} bytes, expected 80 (WinDivert 2.2).");

        EnsureDriverLoaded();
        // VpnHood-style filter. Do NOT put `!((ip.DstAddr>=…))` private-net exclusions here —
        // WinDivert's filter compiler rejects that form (Win32 87, "Filter expression parse
        // error"). LAN destinations are reinjected in ReceivePacket instead.
        string filter =
            $"(ip.TTL!={ProtectedTtl} or ipv6.HopLimit!={ProtectedTtl}) and " +
            "outbound and !loopback and ip";

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
        _log?.Invoke($"WinDivert per-app filter open (primary {_primaryIp}, client {_clientIp}, " +
                     $"{(_apps.SelectedCount)} app path(s))");
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
                // ERROR_INSUFFICIENT_BUFFER / transient — retry
                if (err is 122 or 995) continue;
                Thread.Sleep(1);
                continue;
            }
            if (len < 20) continue;

            // Parse IPv4 header
            byte verIhl = buf[0];
            if ((verIhl >> 4) != 4) { Reinject(buf, (int)len, ref addr); continue; }
            int ihl = (verIhl & 0x0F) * 4;
            if (ihl < 20 || len < ihl) { Reinject(buf, (int)len, ref addr); continue; }

            // Keep LAN / link-local off the tunnel (filter can't express this reliably).
            if (IsPrivateOrLinkLocal(buf.AsSpan(16, 4)))
            {
                Reinject(buf, (int)len, ref addr);
                continue;
            }

            byte proto = buf[9];
            ushort localPort = 0;
            if (proto is 6 or 17 && len >= ihl + 4)
                localPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl));

            if (!_apps.ShouldTunnel(proto, localPort))
            {
                Reinject(buf, (int)len, ref addr);
                continue;
            }

            // Remember capture header for SendPacket reinject direction/ifindex.
            lock (_gate) { _lastAddr = addr; _haveLastAddr = true; }

            // Simulate adapter network: rewrite source → client tunnel IP (VpnHood pattern).
            var origSrc = new IPAddress(buf.AsSpan(12, 4).ToArray());
            WriteIpv4(buf, 12, _clientIp);

            // DNS simulation: rewrite destination of UDP/53 to a tunnel DNS server.
            if (proto == 17 && len >= ihl + 4)
            {
                ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl + 2));
                if (dstPort == 53 && _dnsServers.Count > 0)
                {
                    var origDst = new IPAddress(buf.AsSpan(16, 4).ToArray());
                    lock (_gate) { _dnsOrigDst[localPort] = origDst; }
                    WriteIpv4(buf, 16, _dnsServers[Random.Shared.Next(_dnsServers.Count)]);
                }
            }

            FixChecksums(buf, (int)len, ref addr);
            var pkt = new byte[len];
            Buffer.BlockCopy(buf, 0, pkt, 0, (int)len);
            _ = origSrc; // kept for potential future flow table; primary IP used on write
            return pkt;
        }
        return null;
    }

    public void SendPacket(byte[] packet, int length)
    {
        if (_disposed || length < 20) return;
        IntPtr h;
        WinDivertNative.WinDivertAddress addr;
        lock (_gate)
        {
            if (_disposed || _handle == IntPtr.Zero || !_haveLastAddr) return;
            h = _handle;
            addr = _lastAddr;
        }

        var buf = new byte[length];
        Buffer.BlockCopy(packet, 0, buf, 0, length);
        if ((buf[0] >> 4) != 4) return;
        int ihl = (buf[0] & 0x0F) * 4;

        // Inbound reinject: destination → primary adapter IP (so the real host socket receives it).
        WriteIpv4(buf, 16, _primaryIp);

        byte proto = buf[9];
        if (proto == 17 && length >= ihl + 4)
        {
            ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl));
            ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(ihl + 2));
            // DNS response: restore original DNS server address the app queried.
            if (srcPort == 53)
            {
                lock (_gate)
                {
                    if (_dnsOrigDst.TryGetValue(dstPort, out var orig))
                        WriteIpv4(buf, 12, orig);
                }
            }
        }

        addr.Outbound = false; // inbound
        FixChecksums(buf, length, ref addr);
        WinDivertNative.WinDivertSend(h, buf, (uint)length, out _, ref addr);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
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

    private static bool IsPrivateOrLinkLocal(ReadOnlySpan<byte> dst)
    {
        if (dst.Length < 4) return false;
        byte a = dst[0], b = dst[1];
        if (a == 10) return true;                              // 10.0.0.0/8
        if (a == 172 && b is >= 16 and <= 31) return true;      // 172.16.0.0/12
        if (a == 192 && b == 168) return true;                  // 192.168.0.0/16
        if (a == 169 && b == 254) return true;                  // 169.254.0.0/16
        if (a == 127) return true;                             // loopback (belt-and-braces)
        return false;
    }

    private static void WriteIpv4(byte[] buf, int offset, IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return;
        Buffer.BlockCopy(bytes, 0, buf, offset, 4);
    }

    private static void FixChecksums(byte[] buf, int len, ref WinDivertNative.WinDivertAddress addr)
    {
        // Ask WinDivert to recompute; clear "valid checksum" flags so it recalculates.
        addr.Flags = (byte)(addr.Flags & ~0xE0); // clear IP/TCP/UDP checksum-valid bits (bits 5-7)
        WinDivertNative.WinDivertHelperCalcChecksums(buf, (uint)len, ref addr,
            WinDivertNative.WINDIVERT_HELPER_CHECKSUM_ALL);
    }

    private static IPAddress? GetPrimaryIPv4()
    {
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback
                    or NetworkInterfaceType.Tunnel) continue;
                var props = ni.GetIPProperties();
                if (props.GatewayAddresses.Count == 0) continue;
                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                        && !IPAddress.IsLoopback(ua.Address))
                        return ua.Address;
                }
            }
        }
        catch { }
        return null;
    }

    private static void EnsureDriverLoaded()
    {
        // Extract WinDivert.dll (+ .sys beside it) via NativeLoader, then LoadLibrary so
        // WinDivert can find WinDivert64.sys next to the DLL.
        string? dir = NativeLoader.EnsureWinDivertDir();
        if (dir == null)
            throw new InvalidOperationException("WinDivert.dll could not be extracted from the embedded resources.");
        IntPtr mod = WinDivertNative.LoadLibrary(Path.Combine(dir, "WinDivert.dll"));
        if (mod == IntPtr.Zero)
            throw new InvalidOperationException(
                $"LoadLibrary(WinDivert.dll) failed (Win32 {Marshal.GetLastWin32Error()}).");
    }
}
