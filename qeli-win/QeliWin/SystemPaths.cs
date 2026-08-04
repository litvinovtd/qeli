using System;
using System.IO;

namespace QeliWin;

/// <summary>
/// Absolute paths to the Windows system executables this app launches.
/// </summary>
/// <remarks>
/// Every external process used to be started by BARE NAME — <c>Process.Start("netsh", …)</c>,
/// <c>"route"</c>, <c>"powershell.exe"</c>, <c>"schtasks.exe"</c>. With
/// <c>UseShellExecute = false</c>, .NET calls CreateProcessW with <c>lpApplicationName =
/// NULL</c>, and that search order starts with THE DIRECTORY OF THE CALLING IMAGE, then the
/// current directory — System32 comes fourth.
///
/// The manifest requests <c>requireAdministrator</c>, and in service mode the same binary
/// runs as LocalSystem. So a <c>netsh.exe</c> or <c>powershell.exe</c> sitting next to
/// QeliWin.exe runs with those privileges. Nothing forces the app to live in a protected
/// directory: the portable build is normally run straight out of %USERPROFILE%\Downloads,
/// which any process of that user can write — no admin rights needed to plant the file, full
/// admin gained when qeli next starts and sweeps the kill-switch.
///
/// Resolving against %SystemRoot%\System32 removes the search entirely. Callers that already
/// pass an absolute path are left alone. (Audit 2026-08-04, H-05.)
/// </remarks>
internal static class SystemPaths
{
    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    /// <summary>%SystemRoot%\System32 — also the right working directory for these tools,
    /// so a relative lookup inside them cannot reach back into the app's directory.</summary>
    internal static string SystemDirectory => System32;

    internal static string Netsh => Path.Combine(System32, "netsh.exe");
    internal static string Route => Path.Combine(System32, "route.exe");
    internal static string SchTasks => Path.Combine(System32, "schtasks.exe");
    internal static string PowerShell =>
        Path.Combine(System32, "WindowsPowerShell", "v1.0", "powershell.exe");

    /// <summary>Map a bare tool name to its absolute System32 path. An argument that is
    /// already rooted is returned unchanged, so callers may pass either.</summary>
    internal static string Resolve(string exe)
    {
        if (Path.IsPathRooted(exe)) return exe;
        return exe.ToLowerInvariant() switch
        {
            "netsh" or "netsh.exe" => Netsh,
            "route" or "route.exe" => Route,
            "schtasks" or "schtasks.exe" => SchTasks,
            "powershell" or "powershell.exe" => PowerShell,
            // Anything else still gets pinned to System32 rather than being searched for.
            _ => Path.Combine(System32, exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exe : exe + ".exe"),
        };
    }
}
