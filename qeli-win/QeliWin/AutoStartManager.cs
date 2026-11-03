using System.Diagnostics;
using System.Runtime.InteropServices;

namespace QeliWin;

/// <summary>Elevated GUI logon task; failures are reported instead of silently succeeding.</summary>
public static class AutoStartManager
{
    private const string TaskName = "QeliWinAutoStart";
    private static string ExePath => Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    public static void Enable() => Apply(true);
    public static void Disable() => Apply(false);
    public static void Apply(bool enabled) => Apply(enabled, ExePath,
        Service.ServiceManager.EnsureProtectedLocation, Run, IsEnabled);

    internal static void Apply(bool enabled, string exePath, Action<string> requireProtected,
        Func<string, WindowsCommandResult> run, Func<bool> taskExists)
    {
        if (!enabled && !taskExists()) return; // Missing task is an idempotent disable, not an error.
        if (enabled) requireProtected(exePath);
        string args = enabled
            ? $"/Create /TN \"{TaskName}\" /TR \"\\\"{exePath}\\\" --autostart\" /SC ONLOGON /RL HIGHEST /F"
            : $"/Delete /TN \"{TaskName}\" /F";
        var result = run(args);
        if (result.ExitCode != 0)
            throw new InvalidOperationException(
                $"Autostart {(enabled ? "create" : "delete")} failed (exit {result.ExitCode}): {result.Error}{result.Output}");
    }

    public static bool IsEnabled() => HasTask(TaskName);

    internal static bool HasTask(string name)
    {
        object? scheduler = null, folder = null, task = null;
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service", throwOnError: true)!;
            scheduler = Activator.CreateInstance(type)!;
            ((dynamic)scheduler).Connect();
            folder = ((dynamic)scheduler).GetFolder(@"\");
            try { task = ((dynamic)folder).GetTask(name); }
            catch (Exception error) when (error.HResult == unchecked((int)0x80070002))
            { return false; } // Only an absent task; access/RPC/registration errors propagate.
            return true;
        }
        finally
        {
            foreach (var value in new[] { task, folder, scheduler })
                if (value != null && Marshal.IsComObject(value)) Marshal.ReleaseComObject(value);
        }
    }

    private static WindowsCommandResult Run(string args) => WindowsCommand.RunAsync(
        new ProcessStartInfo(SystemPaths.SchTasks, args) { WorkingDirectory = SystemPaths.SystemDirectory },
        TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
}
