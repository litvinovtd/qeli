using System.Runtime.InteropServices;

namespace QeliWin.Service;

/// <summary>Shared Windows uptime clock for the service snapshot and its local reader.</summary>
internal static class ServiceMonotonicClock
{
    // Pin the wire clock to Win32: Environment.TickCount64 changes its treatment
    // of suspend time in .NET 11. GetTickCount64 includes sleep and is shared across
    // processes, so a pre-sleep snapshot expires without consulting calendar time.
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern ulong GetTickCount64();

    internal static long NowMilliseconds => checked((long)GetTickCount64());
}
