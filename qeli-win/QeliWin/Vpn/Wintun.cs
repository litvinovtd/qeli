using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Thin managed wrapper over WireGuard's Wintun userspace TUN driver (wintun.dll).
/// Provides a blocking ReceivePacket (with cancellation) and SendPacket over L3 IPv4
/// packets — the Windows analogue of Android's TUN ParcelFileDescriptor.
/// </summary>
public sealed class WintunAdapter : IDisposable
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
        _adapter = WintunCreateAdapter(name, "Qeli", ref guid);
        if (_adapter == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            // Reuse a leftover adapter from a previous crash if creation collided.
            _adapter = WintunOpenAdapter(name);
            if (_adapter == IntPtr.Zero)
                throw new Win32Exception(err, $"WintunCreateAdapter failed (err {err})");
        }

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
            IntPtr ptr = WintunReceivePacket(_session, out uint size);
            if (ptr != IntPtr.Zero)
            {
                var managed = new byte[size];
                Marshal.Copy(ptr, managed, 0, (int)size);
                WintunReleaseReceivePacket(_session, ptr);
                return managed;
            }

            uint err = (uint)Marshal.GetLastWin32Error();
            if (err == ERROR_NO_MORE_ITEMS)
            {
                WaitForSingleObject(_readEvent, 250); // wake to re-check cancellation
                continue;
            }
            if (err == ERROR_HANDLE_EOF) return null; // session ended
            throw new Win32Exception((int)err, "WintunReceivePacket failed");
        }
        return null;
    }

    /// <summary>Inject one inbound packet (server → system). Drops it if the ring is full.</summary>
    public void SendPacket(byte[] packet, int length)
    {
        IntPtr ptr = WintunAllocateSendPacket(_session, (uint)length);
        if (ptr == IntPtr.Zero) return; // ring full / session ending — drop, like UDP loss
        Marshal.Copy(packet, 0, ptr, length);
        WintunSendPacket(_session, ptr);
    }

    public void Dispose()
    {
        if (_session != IntPtr.Zero) { WintunEndSession(_session); _session = IntPtr.Zero; }
        if (_adapter != IntPtr.Zero) { WintunCloseAdapter(_adapter); _adapter = IntPtr.Zero; }
        _readEvent = IntPtr.Zero;
    }
}
