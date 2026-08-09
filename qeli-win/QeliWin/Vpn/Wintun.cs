using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Platform lifecycle wrapper for WireGuard's Wintun adapter. Managed code creates a unique
/// interface and keeps its creator handle for network setup/cleanup, but never starts a session
/// or touches packet bytes. The ABI 1.9 Rust core opens an independent handle by
/// <see cref="AdapterName"/> and owns the session, wait event and both rings.
/// </summary>
public sealed class WintunAdapter : IDisposable, Qeli.Shared.Vpn.IWintunTunDevice
{
    private const string Dll = "wintun.dll";

    private IntPtr _adapter;
    private bool _disposed;

    public ulong Luid { get; private set; }
    public string AdapterName { get; private set; } = "";

    [DllImport(Dll, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr WintunCreateAdapter(string name, string tunnelType,
        ref Guid requestedGuid);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);

    [DllImport(Dll, SetLastError = true)]
    private static extern uint WintunGetRunningDriverVersion();

    /// <summary>Create a qeli-owned adapter. Requires administrator privileges.</summary>
    public void Open(string name, Guid guid)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_adapter != IntPtr.Zero)
            throw new InvalidOperationException("Wintun adapter is already open");

        // Never adopt an existing adapter: teardown must not remove a foreign VPN interface.
        // The stable name/GUID is attempted first; collisions use a fresh pair and the actual
        // created name is what ABI 1.9 hands to Rust for its independent OpenAdapter handle.
        string candidateName = name;
        Guid candidateGuid = guid;
        int error = 0;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            _adapter = WintunCreateAdapter(candidateName, "Qeli", ref candidateGuid);
            if (_adapter != IntPtr.Zero)
            {
                AdapterName = candidateName;
                break;
            }
            error = Marshal.GetLastWin32Error();
            candidateName = $"{name}-{attempt}";
            candidateGuid = Guid.NewGuid();
        }
        if (_adapter == IntPtr.Zero)
            throw new Win32Exception(error,
                $"WintunCreateAdapter failed (err {error}; fresh name/GUID retries also failed)");

        WintunGetAdapterLUID(_adapter, out ulong luid);
        Luid = luid;
    }

    public static uint RunningDriverVersion()
    {
        try { return WintunGetRunningDriverVersion(); } catch { return 0; }
    }

    /// <summary>Force-load the embedded wintun.dll without requiring an adapter.</summary>
    public static uint ProbeLoad() => WintunGetRunningDriverVersion();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_adapter != IntPtr.Zero)
        {
            WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }
        Luid = 0;
        AdapterName = "";
    }
}
