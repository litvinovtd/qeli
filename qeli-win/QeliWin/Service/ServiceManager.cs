using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
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

    /// <summary>
    /// Refuse to register a LocalSystem service pointing at an executable a
    /// non-administrator can overwrite.
    /// </summary>
    /// <remarks>
    /// The service runs as LocalSystem and starts at boot from whatever path is
    /// recorded here. qeli ships as a portable exe and the README says to copy it
    /// "anywhere" — so the recorded path is routinely something like
    /// <c>%USERPROFILE%\Downloads</c>, which the user (and anything running as the
    /// user) can rewrite. Replacing that file after installation is then a durable
    /// SYSTEM foothold that survives reboots and needs no elevation at any point.
    ///
    /// Requiring a protected root is the cheap, robust half of the fix: those
    /// directories are writable only by administrators, so an attacker who can
    /// modify the binary there already has the privileges they would be stealing.
    /// </remarks>
    internal static void EnsureProtectedLocation(string exePath)
    {
        string full;
        try { full = Path.GetFullPath(exePath); }
        catch (Exception e) { throw new InvalidOperationException($"Cannot resolve '{exePath}': {e.Message}"); }

        string[] roots =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        };
        bool underProtectedRoot = false;
        foreach (var root in roots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            var r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            if (full.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                underProtectedRoot = true;
                break;
            }
        }

        if (!underProtectedRoot)
        {
            throw new InvalidOperationException(
                "Refusing to install the Windows service: it would run as LocalSystem at boot " +
                $"from \"{full}\", a location a standard user can overwrite. Anyone able to " +
                "write that file could then run code as SYSTEM on every boot." +
                Environment.NewLine + Environment.NewLine +
                @"Move QeliWin under Program Files (e.g. C:\Program Files\QeliWin\) and " +
                "install the service from there.");
        }

        // Being UNDER Program Files is not the same as being protected.
        //
        // The prefix test was the whole check, and it is not sufficient: `C:\Windows\Temp`
        // sits under a "protected" root and is writable by every user by design, and any
        // third-party installer can create a permissive directory under Program Files. Either
        // way a standard user replaces the binary that the SCM then launches as LocalSystem at
        // boot — the exact escalation the prefix test exists to prevent, reached through a
        // path that satisfies it. The macOS side already walks the real ownership/permissions
        // (ServiceManager.EnsureProtectedLocation there); Windows only compared strings.
        //
        // So inspect the actual DACL of the file and of every directory above it, and refuse
        // if any of them grants write to a non-privileged principal. (Audit 2026-08-04.)
        foreach (var path in PathAndAncestors(full))
        {
            var who = NonAdminWriterOn(path);
            if (who != null)
            {
                throw new InvalidOperationException(
                    "Refusing to install the Windows service: it would run as LocalSystem at " +
                    $"boot from \"{full}\", but \"{path}\" grants write access to \"{who}\". " +
                    "Anyone in that group could replace the binary and run code as SYSTEM on " +
                    "every boot." + Environment.NewLine + Environment.NewLine +
                    @"Install under a directory only administrators can write (e.g. " +
                    @"C:\Program Files\QeliWin\), or fix its permissions.");
            }
        }
    }

    /// <summary>The path itself, then each parent up to and including the drive root.</summary>
    private static IEnumerable<string> PathAndAncestors(string full)
    {
        for (var p = full; !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p) ?? "")
        {
            yield return p;
            if (Path.GetPathRoot(p)?.Equals(p, StringComparison.OrdinalIgnoreCase) == true) yield break;
        }
    }

    /// <summary>Name of a non-privileged principal that can WRITE <paramref name="path"/>,
    /// or null when only privileged accounts can. Unreadable ACLs return null: refusing on a
    /// DACL we cannot read would block legitimate installs on locked-down systems, and the
    /// prefix check above still applies.</summary>
    internal static string? NonAdminWriterOn(string path)
    {
        const FileSystemRights Dangerous =
            FileSystemRights.WriteData      // create files in a dir / overwrite a file
            | FileSystemRights.AppendData   // create subdirectories
            | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions
            | FileSystemRights.TakeOwnership;

        // Groups that any interactive, non-elevated account is a member of. Administrators,
        // SYSTEM, TrustedInstaller and CREATOR OWNER are all expected to have write here.
        var untrusted = new[]
        {
            WellKnownSidType.WorldSid,               // Everyone
            WellKnownSidType.AuthenticatedUserSid,   // Authenticated Users
            WellKnownSidType.BuiltinUsersSid,        // BUILTIN\Users
            WellKnownSidType.InteractiveSid,         // INTERACTIVE
        };

        try
        {
            var sec = Directory.Exists(path)
                ? (FileSystemSecurity)new DirectoryInfo(path).GetAccessControl()
                : new FileInfo(path).GetAccessControl();
            foreach (FileSystemAccessRule rule in
                     sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow) continue;
                if ((rule.FileSystemRights & Dangerous) == 0) continue;
                if (rule.IdentityReference is not SecurityIdentifier sid) continue;
                foreach (var w in untrusted)
                {
                    if (sid.IsWellKnown(w))
                    {
                        try { return sid.Translate(typeof(NTAccount)).Value; }
                        catch { return sid.Value; }
                    }
                }
            }
        }
        catch
        {
            // No access to the DACL, or an unsupported filesystem — see the summary.
        }
        return null;
    }

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
        EnsureProtectedLocation(ExePath);
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
