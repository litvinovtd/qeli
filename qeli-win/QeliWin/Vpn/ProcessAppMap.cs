using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Maps local TCP/UDP ports → owning process → exe path, so WinDivert NETWORK-layer packets
/// can be filtered by application. WinDivert's network address has no ProcessId; the IP Helper
/// owner-PID tables fill that gap.
/// </summary>
internal sealed class ProcessAppMap : IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<uint, string> _pidToPath = new();
    private readonly Dictionary<(byte proto, ushort port), uint> _portToPid = new();
    private readonly HashSet<string> _selected;
    private readonly bool _includeMode; // true = only selected tunnel; false = selected bypass
    private DateTime _lastRefresh = DateTime.MinValue;
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);
    private readonly int _selfPid = Environment.ProcessId;
    private bool _disposed;

    public ProcessAppMap(IEnumerable<string> apps, bool includeMode)
    {
        _includeMode = includeMode;
        _selected = new HashSet<string>(
            apps.Select(NormalizePath).Where(p => p.Length > 0),
            StringComparer.OrdinalIgnoreCase);
    }

    public int SelectedCount => _selected.Count;

    public bool HasPathMatches
    {
        get
        {
            lock (_gate)
            {
                MaybeRefreshUnlocked();
                foreach (var path in _pidToPath.Values)
                    if (_selected.Contains(path)) return true;
            }
            return false;
        }
    }

    /// <summary>Whether this packet's owning process should go through the VPN tunnel.</summary>
    public bool ShouldTunnel(byte protocol, ushort localPort)
    {
        if (protocol is not (6 or 17)) // TCP / UDP — ICMP etc. follow include/exclude default
            return !_includeMode; // exclude mode: tunnel unknowns; include: leave them alone

        lock (_gate)
        {
            MaybeRefreshUnlocked();
            if (!_portToPid.TryGetValue((protocol, localPort), out uint pid))
            {
                // Unknown owner: refresh once more and retry.
                ForceRefreshUnlocked();
                if (!_portToPid.TryGetValue((protocol, localPort), out pid))
                    return !_includeMode;
            }
            if (pid == (uint)_selfPid) return false; // never divert our own carrier

            if (!_pidToPath.TryGetValue(pid, out var path))
            {
                path = QueryImagePath(pid);
                if (path != null) _pidToPath[pid] = path;
            }
            bool selected = path != null && _selected.Contains(path);
            return _includeMode ? selected : !selected;
        }
    }

    public void Dispose() => _disposed = true;

    private void MaybeRefreshUnlocked()
    {
        if (_disposed) return;
        if (DateTime.UtcNow - _lastRefresh < RefreshInterval) return;
        ForceRefreshUnlocked();
    }

    private void ForceRefreshUnlocked()
    {
        _lastRefresh = DateTime.UtcNow;
        _portToPid.Clear();
        RefreshTcp();
        RefreshUdp();
        // Drop stale PID→path entries for dead processes (best-effort).
        var live = new HashSet<uint>(_portToPid.Values);
        live.Add((uint)_selfPid);
        foreach (var pid in _pidToPath.Keys.Where(p => !live.Contains(p)).ToList())
            _pidToPath.Remove(pid);
    }

    private void RefreshTcp()
    {
        // AF_INET = 2, TCP_TABLE_OWNER_PID_CONNECTIONS = 5
        uint size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
        if (size == 0) return;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) != 0) return;
            int num = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            // MIB_TCPROW_OWNER_PID: DWORD state, localAddr, localPort, remoteAddr, remotePort, owningPid
            for (int i = 0; i < num; i++)
            {
                uint localPortNbo = (uint)Marshal.ReadInt32(row + 8);
                ushort port = (ushort)System.Net.IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                uint pid = (uint)Marshal.ReadInt32(row + 20);
                if (port != 0) _portToPid[(6, port)] = pid;
                row += 24;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private void RefreshUdp()
    {
        // UDP_TABLE_OWNER_PID = 1, AF_INET = 2
        uint size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1, 0);
        if (size == 0) return;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, false, 2, 1, 0) != 0) return;
            int num = Marshal.ReadInt32(buf);
            IntPtr row = buf + 4;
            // MIB_UDPROW_OWNER_PID: localAddr, localPort, owningPid (12 bytes)
            for (int i = 0; i < num; i++)
            {
                uint localPortNbo = (uint)Marshal.ReadInt32(row + 4);
                ushort port = (ushort)System.Net.IPAddress.NetworkToHostOrder((short)(localPortNbo & 0xFFFF));
                uint pid = (uint)Marshal.ReadInt32(row + 8);
                if (port != 0) _portToPid[(17, port)] = pid;
                row += 12;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

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
                    // Skip ourselves and obvious system noise.
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
