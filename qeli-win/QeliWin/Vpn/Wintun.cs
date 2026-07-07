using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Thin managed wrapper over WireGuard's Wintun userspace TUN driver (wintun.dll).
/// Provides a blocking ReceivePacket (with cancellation) and SendPacket over L3 IPv4
/// packets — the Windows analogue of Android's TUN ParcelFileDescriptor.
/// </summary>
public sealed class WintunAdapter : IDisposable, Qeli.Shared.Vpn.ITunDevice
{
    private const string Dll = "wintun.dll";

    // Capacity: power of two between 128 KiB and 64 MiB. 4 MiB ring.
    private const uint RingCapacity = 0x400000;

    private const uint ERROR_NO_MORE_ITEMS = 259;
    private const uint ERROR_HANDLE_EOF = 38;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 258;

    private IntPtr _adapter;
    private IntPtr _session;
    private IntPtr _readEvent;
    // True only when WE created `_adapter`. Dispose removes the adapter only if we created
    // it, so our teardown can never take down an adapter that belongs to another app.
    private bool _created;

    // Serializes native session use (ReceivePacket / SendPacket) against Dispose, so
    // the ring/session can never be freed by WintunEndSession while another thread is
    // inside WintunReceivePacket / WintunAllocateSendPacket. Without this, a reconnect
    // (which disposes the TUN) racing the still-running upload/download thread caused a
    // use-after-free inside wintun.dll → an uncatchable native Access Violation that
    // tore the whole process down (issue #69). The guarded native calls are all
    // non-blocking, so the lock is held only microseconds; the blocking wait below sits
    // OUTSIDE the lock. `_disposed` makes an in-flight receive/send bail as a clean
    // "session ended" instead of touching freed memory.
    private readonly object _gate = new();
    private volatile bool _disposed;

    public ulong Luid { get; private set; }

    // ── P/Invoke ────────────────────────────────────────────────────────────
    [DllImport(Dll, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr WintunCreateAdapter(string name, string tunnelType, ref Guid requestedGuid);

    [DllImport(Dll, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr WintunOpenAdapter(string name);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);

    [DllImport(Dll, SetLastError = true)]
    private static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunEndSession(IntPtr session);

    [DllImport(Dll, SetLastError = true)]
    private static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

    [DllImport(Dll, SetLastError = true)]
    private static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    [DllImport(Dll, SetLastError = true)]
    private static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunSendPacket(IntPtr session, IntPtr packet);

    [DllImport(Dll, SetLastError = true)]
    private static extern uint WintunGetRunningDriverVersion();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    // ── lifecycle ──────────────────────────────────────────────────────────
    /// <summary>Create (or reopen) the adapter and start a session. Requires admin.</summary>
    public void Open(string name, Guid guid)
    {
        // Create ONLY our own adapter — never WintunOpenAdapter an existing one. Adopting a
        // pre-existing adapter risks grabbing another app's (a name clash, or a handle the
        // driver hands us during a version-swap), and Dispose's WintunCloseAdapter would then
        // REMOVE it — that is how a user's OpenVPN adapter got deleted on our "Disconnect"
        // (issue #69). The name+GUID are per-tunnel-unique; on a collision retry with a fresh
        // name+GUID so `_adapter` is ALWAYS something WE created.
        _adapter = WintunCreateAdapter(name, "Qeli", ref guid);
        int err = _adapter == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        for (int i = 0; _adapter == IntPtr.Zero && i < 3; i++)
        {
            Guid fresh = Guid.NewGuid();
            _adapter = WintunCreateAdapter($"{name}-{i}", "Qeli", ref fresh);
        }
        if (_adapter == IntPtr.Zero)
            throw new Win32Exception(err,
                $"WintunCreateAdapter failed (err {err}; fresh name/GUID retries also failed)");
        _created = true;

        WintunGetAdapterLUID(_adapter, out ulong luid);
        Luid = luid;

        _session = WintunStartSession(_adapter, RingCapacity);
        if (_session == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WintunStartSession failed");

        _readEvent = WintunGetReadWaitEvent(_session);
    }

    public static uint RunningDriverVersion()
    {
        try { return WintunGetRunningDriverVersion(); } catch { return 0; }
    }

    /// <summary>Force-load wintun.dll (from the embedded resource) and return the running
    /// driver version (0 if the driver isn't active). Throws if the library can't load —
    /// used to verify embedding/resolution without needing admin or an adapter.</summary>
    public static uint ProbeLoad() => WintunGetRunningDriverVersion();

    /// <summary>
    /// Block until an outbound packet (system → tunnel) is available, copy it out and
    /// return it. Returns null on session end. Honors the cancellation token via a
    /// short wait timeout so a disconnect tears the read loop down promptly.
    /// </summary>
    public byte[]? ReceivePacket(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            IntPtr readEvent;
            lock (_gate)
            {
                if (_disposed || _session == IntPtr.Zero) return null; // torn down
                IntPtr ptr = WintunReceivePacket(_session, out uint size);
                if (ptr != IntPtr.Zero)
                {
                    var managed = new byte[size];
                    Marshal.Copy(ptr, managed, 0, (int)size);
                    WintunReleaseReceivePacket(_session, ptr);
                    return managed;
                }
                uint err = (uint)Marshal.GetLastWin32Error();
                if (err == ERROR_HANDLE_EOF) return null;              // session ended
                if (err != ERROR_NO_MORE_ITEMS)
                    throw new Win32Exception((int)err, "WintunReceivePacket failed");
                readEvent = _readEvent; // snapshot under the lock for the wait below
            }
            // Wait for the ring OUTSIDE the lock (up to 250 ms) so Dispose is never
            // blocked behind our sleep. A stale/zeroed event means we were torn down.
            if (readEvent == IntPtr.Zero) return null;
            WaitForSingleObject(readEvent, 250); // wake to re-check cancellation / _disposed
        }
        return null;
    }

    /// <summary>Inject one inbound packet (server → system). Drops it if the ring is full.</summary>
    public void SendPacket(byte[] packet, int length)
    {
        lock (_gate)
        {
            if (_disposed || _session == IntPtr.Zero) return; // torn down — drop, like UDP loss
            IntPtr ptr = WintunAllocateSendPacket(_session, (uint)length);
            if (ptr == IntPtr.Zero) return; // ring full / session ending — drop, like UDP loss
            Marshal.Copy(packet, 0, ptr, length);
            WintunSendPacket(_session, ptr);
        }
    }

    public void Dispose()
    {
        // Take the same lock the data-plane threads hold around their native session
        // calls, so EndSession/CloseAdapter can't free the session out from under an
        // in-flight ReceivePacket/SendPacket (the use-after-free that crashed the app).
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            if (_session != IntPtr.Zero) { WintunEndSession(_session); _session = IntPtr.Zero; }
            // Remove the adapter ONLY if we created it — never take down a foreign one.
            if (_adapter != IntPtr.Zero) { if (_created) WintunCloseAdapter(_adapter); _adapter = IntPtr.Zero; }
            _readEvent = IntPtr.Zero;
        }
    }
}
