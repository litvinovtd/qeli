using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Maps local TCP/UDP endpoints → owning process → exe path for WinDivert NETWORK-layer
/// filtering. Keys include the local IP (not just the port) so UDP port reuse across
/// interfaces does not collide. Include mode is fail-closed: unknown owners are Drop.
/// </summary>
internal sealed class ProcessAppMap : IDisposable
{
    private readonly object _gate = new();
    private readonly object _refreshGate = new();
    private Dictionary<uint, string> _pidToPath = new();
    // TCP ownership includes the complete endpoint. Keying only by the local port lets two
    // simultaneous connections (or port reuse after close) inherit each other's process
    // decision. UDP's Windows table has no peer endpoint, so it uses the wildcard remote.
    private Dictionary<(byte proto, string local, ushort localPort,
        string remote, ushort remotePort), uint> _endpointToPid = new();
    private const uint AmbiguousPid = uint.MaxValue;
    private readonly HashSet<string> _selected;
    private readonly bool _includeMode; // true = only selected tunnel; false = selected bypass
    private DateTime _lastRefresh = DateTime.MinValue;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);
    private const int MissRefreshWaitMs = 75;
    private bool _refreshQueued;
    private readonly ManualResetEventSlim _refreshFinished = new(initialState: true);
    private readonly int _selfPid = Environment.ProcessId;
    private bool _disposed;

    public ProcessAppMap(IEnumerable<string> apps, bool includeMode)
    {
        _includeMode = includeMode;
        _selected = new HashSet<string>(
            apps.Where(LooksLikeWindowsExecutable).Select(NormalizePath).Where(p => p.Length > 0),
            StringComparer.OrdinalIgnoreCase);
        // Warm the ownership snapshot before WinDivert starts delivering packets. A socket
        // created in the remaining race window still triggers the bounded miss refresh below.
        ScheduleRefresh(force: true);
    }

    public int SelectedCount => _selected.Count;
    public bool IncludeMode => _includeMode;

    public bool HasPathMatches
    {
        get
        {
            ScheduleRefresh(force: false);
            _refreshFinished.Wait(250);
            lock (_gate)
            {
                foreach (uint pid in _endpointToPid.Values.Distinct())
                {
                    if (pid == AmbiguousPid) continue;
                    if (!_pidToPath.TryGetValue(pid, out var path))
                    {
                        path = QueryImagePath(pid);
                        if (path != null) _pidToPath[pid] = path;
                    }
                    if (path != null && _selected.Contains(path)) return true;
                }
            }
            return false;
        }
    }

    /// <summary>Classify an outbound packet by owning process.</summary>
    public PacketDisposition Classify(
        byte protocol, IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort)
    {
        var result = ClassifySnapshot(protocol, localIp, localPort, remoteIp, remotePort);
        if (result != PacketDisposition.Unknown) return result;

        ScheduleRefresh(force: true);
        if (!_refreshFinished.Wait(MissRefreshWaitMs)) return PacketDisposition.Drop;
        result = ClassifySnapshot(protocol, localIp, localPort, remoteIp, remotePort);
        return result == PacketDisposition.Unknown ? PacketDisposition.Drop : result;
    }

    private PacketDisposition ClassifySnapshot(
        byte protocol, IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort)
    {
        // Non-TCP/UDP has no socket owner to refresh: include stays fail-closed, while
        // exclude follows the existing default-tunnel policy.
        if (protocol is not (6 or 17))
            return _includeMode ? PacketDisposition.Drop : PacketDisposition.Tunnel;

        lock (_gate)
        {
            // Classification runs on the WinDivert capture thread. Never perform the
            // system-wide endpoint/PID scan here; use the latest snapshot and refresh it
            // on a coalesced worker when stale.
            ScheduleRefresh(force: false);
            string localKey = AddrKey(localIp);
            string remoteKey = AddrKey(remoteIp);
            string any = localIp.AddressFamily == AddressFamily.InterNetwork ? "0.0.0.0" : "::";
            if (!_endpointToPid.TryGetValue(
                    (protocol, localKey, localPort, remoteKey, remotePort), out uint pid)
                && !_endpointToPid.TryGetValue(
                    (protocol, localKey, localPort, any, 0), out pid))
            {
                // Also try wildcard 0.0.0.0 / :: bindings — UDP often binds any-local.
                if (!_endpointToPid.TryGetValue(
                        (protocol, any, localPort, remoteKey, remotePort), out pid)
                    && !_endpointToPid.TryGetValue(
                        (protocol, any, localPort, any, 0), out pid))
                {
                    // Socket creation races are common, especially for UDP. Refreshing all
                    // four kernel ownership tables synchronously for every missed packet
                    // stalled the capture loop and amplified packet loss. Coalesce misses
                    // into at most one background refresh per normal refresh interval; the
                    // current packet keeps the privacy-safe unknown-owner disposition.
                    ScheduleRefresh(force: true);
                    return PacketDisposition.Unknown;
                }
            }

            // SO_REUSEADDR can give the same UDP local endpoint to several processes.
            // A single arbitrary PID would leak an included app or capture an excluded one.
            if (pid == AmbiguousPid)
                return PacketDisposition.Unknown;

            if (pid == (uint)_selfPid) return PacketDisposition.Bypass;

            if (!_pidToPath.TryGetValue(pid, out var path))
            {
                path = QueryImagePath(pid);
                if (path != null) _pidToPath[pid] = path;
            }

            // Path unknown after lookup: same fail-closed rule as unknown port owner.
            if (path == null)
                return PacketDisposition.Unknown;

            bool selected = _selected.Contains(path);
            if (_includeMode)
                return selected ? PacketDisposition.Tunnel : PacketDisposition.Bypass;
            return selected ? PacketDisposition.Bypass : PacketDisposition.Tunnel;
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _refreshFinished.Set();
    }

    private void ForceRefreshUnlocked()
    {
        _endpointToPid.Clear();
        RefreshTcp(afInet: 2);
        RefreshTcp(afInet: 23); // AF_INET6
        RefreshUdp(afInet: 2);
        RefreshUdp(afInet: 23);
        var live = new HashSet<uint>(_endpointToPid.Values.Where(pid => pid != AmbiguousPid))
            { (uint)_selfPid };
        foreach (var pid in _pidToPath.Keys.Where(p => !live.Contains(p)).ToList())
            _pidToPath.Remove(pid);
        // A PID can be reused by a different executable. Keeping the old path merely because
        // the numeric PID is still present lets the replacement inherit the old app decision.
        // Revalidate every live owner on each endpoint refresh (the interval bounds the cost).
        foreach (uint pid in live)
        {
            if (pid == (uint)_selfPid) continue;
            string? path = QueryImagePath(pid);
            if (path != null) _pidToPath[pid] = path;
            else _pidToPath.Remove(pid);
        }
    }

    private void ScheduleRefresh(bool force)
    {
        lock (_refreshGate)
        {
            if (_disposed || !ShouldQueueMissRefreshForTest(
                    _lastRefresh, DateTime.UtcNow, _refreshQueued, force)) return;
            _refreshQueued = true;
            _refreshFinished.Reset();
        }
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                lock (_gate)
                    if (!_disposed) ForceRefreshUnlocked();
            }
            finally
            {
                lock (_refreshGate)
                {
                    _lastRefresh = DateTime.UtcNow;
                    _refreshQueued = false;
                    _refreshFinished.Set();
                }
            }
        });
    }

    internal static bool ShouldQueueMissRefreshForTest(
        DateTime lastRefresh, DateTime now, bool pending, bool force = false) =>
        !pending && (force || now - lastRefresh >= RefreshInterval);

    private void RefreshTcp(int afInet)
    {
        // TCP_TABLE_OWNER_PID_CONNECTIONS = 5
        uint size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, afInet, 5, 0);
        if (size == 0) return;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, afInet, 5, 0) != 0) return;
            int num = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            if (afInet == 2)
            {
                // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (24)
                for (int i = 0; i < num; i++)
                {
                    uint localAddr = unchecked((uint)Marshal.ReadInt32(row + 4));
                    uint localPortNbo = unchecked((uint)Marshal.ReadInt32(row + 8));
                    uint remoteAddr = unchecked((uint)Marshal.ReadInt32(row + 12));
                    uint remotePortNbo = unchecked((uint)Marshal.ReadInt32(row + 16));
                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                    ushort remotePort = (ushort)IPAddress.NetworkToHostOrder((short)(remotePortNbo & 0xFFFF));
                    uint pid = unchecked((uint)Marshal.ReadInt32(row + 20));
                    if (port != 0)
                        RememberOwner((6, V4Key(localAddr), port,
                            remotePort == 0 ? "0.0.0.0" : V4Key(remoteAddr), remotePort), pid);
                    row += 24;
                }
            }
            else
            {
                // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScopeId, localPort, remoteAddr[16],
                // remoteScopeId, remotePort, state, pid — 56 bytes on modern Windows.
                for (int i = 0; i < num; i++)
                {
                    var localBytes = new byte[16];
                    Marshal.Copy(row, localBytes, 0, 16);
                    var remoteBytes = new byte[16];
                    Marshal.Copy(row + 24, remoteBytes, 0, 16);
                    uint localPortNbo = unchecked((uint)Marshal.ReadInt32(row + 20));
                    uint remotePortNbo = unchecked((uint)Marshal.ReadInt32(row + 44));
                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                    ushort remotePort = (ushort)IPAddress.NetworkToHostOrder((short)(remotePortNbo & 0xFFFF));
                    uint pid = unchecked((uint)Marshal.ReadInt32(row + 52));
                    if (port != 0)
                        RememberOwner((6, new IPAddress(localBytes).ToString(), port,
                            remotePort == 0 ? "::" : new IPAddress(remoteBytes).ToString(), remotePort), pid);
                    row += 56;
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private void RefreshUdp(int afInet)
    {
        // UDP_TABLE_OWNER_PID = 1
        uint size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, afInet, 1, 0);
        if (size == 0) return;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, false, afInet, 1, 0) != 0) return;
            int num = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            if (afInet == 2)
            {
                // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid (12)
                for (int i = 0; i < num; i++)
                {
                    uint localAddr = unchecked((uint)Marshal.ReadInt32(row));
                    uint localPortNbo = unchecked((uint)Marshal.ReadInt32(row + 4));
                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                    uint pid = unchecked((uint)Marshal.ReadInt32(row + 8));
                    if (port != 0)
                        RememberOwner((17, V4Key(localAddr), port, "0.0.0.0", 0), pid);
                    row += 12;
                }
            }
            else
            {
                // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScopeId, localPort, pid — 28 bytes
                for (int i = 0; i < num; i++)
                {
                    var localBytes = new byte[16];
                    Marshal.Copy(row, localBytes, 0, 16);
                    uint localPortNbo = unchecked((uint)Marshal.ReadInt32(row + 20));
                    ushort port = (ushort)IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                    uint pid = unchecked((uint)Marshal.ReadInt32(row + 24));
                    if (port != 0)
                        RememberOwner((17, new IPAddress(localBytes).ToString(), port, "::", 0), pid);
                    row += 28;
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string V4Key(uint addrLe)
    {
        // MIB tables store IPv4 in network byte order on little-endian Windows as a DWORD
        // that IPAddress(long) expects in host order — use the 4-byte form.
        var b = BitConverter.GetBytes(addrLe);
        return new IPAddress(b).ToString();
    }

    private void RememberOwner(
        (byte proto, string local, ushort localPort, string remote, ushort remotePort) endpoint,
        uint pid)
    {
        if (!_endpointToPid.TryGetValue(endpoint, out uint existing))
            _endpointToPid[endpoint] = pid;
        else
            _endpointToPid[endpoint] = MergeOwnerForTest(existing, pid);
    }

    internal static uint MergeOwnerForTest(uint existing, uint incoming) =>
        existing == incoming ? existing : AmbiguousPid;

    private static string AddrKey(IPAddress ip) => ip.ToString();

    private static string? QueryImagePath(uint pid)
    {
        try
        {
            using var p = Process.GetProcessById((int)pid);
            return NormalizePath(p.MainModule?.FileName);
        }
        catch { return TryQueryImageName(pid); }
    }

    private static string? TryQueryImageName(uint pid)
    {
        IntPtr h = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var buf = new char[1024];
            int size = buf.Length;
            if (!QueryFullProcessImageName(h, 0, buf, ref size)) return null;
            return NormalizePath(new string(buf, 0, size));
        }
        finally { CloseHandle(h); }
    }

    public static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        try { return Path.GetFullPath(path.Trim()); }
        catch { return path.Trim(); }
    }

    private static bool LooksLikeWindowsExecutable(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        string path = value.Trim();
        return Path.IsPathRooted(path)
            && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Installed / running apps suitable for the picker UI.</summary>
    public static List<(string path, string name)> ListCandidateApps()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<(string path, string name)>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    string? path = null;
                    try { path = p.MainModule?.FileName; } catch { }
                    if (string.IsNullOrEmpty(path)) continue;
                    path = NormalizePath(path);
                    if (path.Length == 0 || !seen.Add(path)) continue;
                    if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                    if (path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase)
                        || path.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase))
                        continue;
                    string name = p.ProcessName;
                    try { name = Path.GetFileNameWithoutExtension(path); } catch { }
                    list.Add((path, name));
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }
        list.Sort((a, b) => string.Compare(a.name, b.name, StringComparison.OrdinalIgnoreCase));
        return list;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint dwOutBufLen,
        bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref uint dwOutBufLen,
        bool sort, int ipVersion, int tblClass, uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags,
        [Out] char[] lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);
}
