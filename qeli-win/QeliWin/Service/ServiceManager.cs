using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace QeliWin.Service;

/// <summary>
/// Installs/controls the Qeli Windows Service. Create/delete go through the Win32 SCM
/// API (robust binPath quoting); start/stop/status use ServiceController. The service
/// runs as LocalSystem with auto-start, so the VPN comes up at boot, before any logon.
/// </summary>
public static class ServiceManager
{
    public const string ServiceName = "QeliWinSvc";
    private const string DisplayName = "Qeli VPN Service";

    private static string ExePath =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    // ── Win32 SCM ────────────────────────────────────────────────────────────────
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x10;
    private const uint SERVICE_AUTO_START = 0x2;
    private const uint SERVICE_ERROR_NORMAL = 0x1;
    private const int ERROR_SERVICE_EXISTS = 1073;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateService(IntPtr scm, string serviceName, string displayName,
        uint desiredAccess, uint serviceType, uint startType, uint errorControl, string binaryPath,
        string? loadOrderGroup, IntPtr tagId, string? dependencies, string? serviceStartName, string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    // ── public API ────────────────────────────────────────────────────────────────
    public static bool IsInstalled() =>
        ServiceController.GetServices().Any(s =>
            s.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));

    public static bool IsRunning()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            sc.Refresh();
            return sc.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
        }
        catch { return false; }
    }

    public static void Install()
    {
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed");
        try
        {
            var svc = CreateService(scm, ServiceName, DisplayName, SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                $"\"{ExePath}\" --service", null, IntPtr.Zero, null, null /* LocalSystem */, null);
            if (svc == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_SERVICE_EXISTS) throw new Win32Exception(err, "CreateService failed");
            }
            else CloseServiceHandle(svc);
        }
        finally { CloseServiceHandle(scm); }
    }

    public static void Uninstall()
    {
        try { Stop(); } catch { }
        var scm = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scm == IntPtr.Zero) return;
        try
        {
            var svc = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
            if (svc != IntPtr.Zero) { DeleteService(svc); CloseServiceHandle(svc); }
        }
        finally { CloseServiceHandle(scm); }
    }

    public static void Start()
    {
        using var sc = new ServiceController(ServiceName);
        sc.Refresh();
        if (sc.Status is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
            sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
    }

    public static void Stop()
    {
        using var sc = new ServiceController(ServiceName);
        sc.Refresh();
        if (sc.CanStop)
        {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
        }
    }
}
