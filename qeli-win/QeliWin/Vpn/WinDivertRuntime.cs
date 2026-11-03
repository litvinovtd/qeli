using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

// Injectable OS ownership operations; packet classification remains production code.
internal delegate bool WinDivertReceive(IntPtr handle, byte[] packet, uint capacity, out uint received, ref WinDivertNative.WinDivertAddress address);

internal sealed class WinDivertRuntime
{
    internal Action EnsureLoaded { get; init; } = WinDivertAdapter.EnsureDriverLoaded;
    internal Func<string, IntPtr> Open { get; init; } = filter =>
        WinDivertNative.WinDivertOpen(filter, WinDivertNative.WINDIVERT_LAYER_NETWORK, 0, 0);
    internal WinDivertReceive Receive { get; init; } = WinDivertNative.WinDivertRecv;
    internal Action<IntPtr> Shutdown { get; init; } = handle =>
    {
        if (!WinDivertNative.WinDivertShutdown(handle, 3)) // WINDIVERT_SHUTDOWN_BOTH
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WinDivertShutdown failed");
    };
    internal Action<IntPtr> Close { get; init; } = handle =>
    {
        if (!WinDivertNative.WinDivertClose(handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "WinDivertClose failed");
    };
    internal Action<IntPtr> Configure { get; init; } = handle =>
    {
        // Queue tuning is optional; ownership does not depend on these hints.
        try
        {
            WinDivertNative.WinDivertSetParam(handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
            WinDivertNative.WinDivertSetParam(handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_TIME, 2000);
            WinDivertNative.WinDivertSetParam(handle, WinDivertNative.WINDIVERT_PARAM_QUEUE_SIZE, 8 * 1024 * 1024);
        }
        catch { }
    };
    internal Func<ThreadStart, string, Thread> CreateThread { get; init; } = (body, name) =>
        new Thread(body) { IsBackground = true, Name = name };
    internal Action<Thread> StartThread { get; init; } = thread => thread.Start();
    internal int JoinMilliseconds { get; init; } = 2000;
}
