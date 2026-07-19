using System.Diagnostics;

namespace QeliWin;

/// <summary>
/// "Service mode" autostart via a Windows Scheduled Task that runs at logon with
/// highest privileges — this starts the elevated app automatically without a UAC
/// prompt (a plain Run-key entry would prompt every logon because the app requires
/// admin). The app then auto-connects and self-reconnects via its normal loop.
/// </summary>
public static class AutoStartManager
{
    private const string TaskName = "QeliWinAutoStart";

    private static string ExePath => Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    public static bool IsEnabled() => Run($"/Query /TN \"{TaskName}\"") == 0;

    public static void Enable()
    {
        // Same reasoning as the service: /RL HIGHEST runs this elevated at every
        // logon from the recorded path, so registering a path a standard user can
        // overwrite hands out unattended high-integrity execution. Reuses the
        // service's check so both entry points share one definition of "protected".
        Service.ServiceManager.EnsureProtectedLocation(ExePath);
        // /RL HIGHEST = elevated, /SC ONLOGON = at user logon, /F = overwrite.
        Run($"/Create /TN \"{TaskName}\" /TR \"\\\"{ExePath}\\\" --autostart\" /SC ONLOGON /RL HIGHEST /F");
    }

    public static void Disable() => Run($"/Delete /TN \"{TaskName}\" /F");

    public static void Apply(bool enabled)
    {
        bool already = IsEnabled();
        if (enabled && !already) Enable();
        else if (!enabled && already) Disable();
        else if (enabled) Enable(); // refresh path in case the exe moved
    }

    private static int Run(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("schtasks.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            return p.ExitCode;
        }
        catch { return -1; }
    }
}
