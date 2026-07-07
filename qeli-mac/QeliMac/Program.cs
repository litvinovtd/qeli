using System.IO;
using Avalonia;

namespace QeliMac;

/// <summary>
/// Entry point. "--service" runs the headless launchd daemon (root, no GUI); the
/// selftest/handshake/connect/genassets/genicns verbs run headless for debugging/CI;
/// "uishot" renders UI screenshots; anything else launches the Avalonia GUI.
/// A top-level guard logs any startup exception so a launch crash is diagnosable.
/// </summary>
public static class Program
{
    private static readonly string[] CliVerbs = { "selftest", "handshake", "connect", "genassets", "genicns" };

    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogStartupError(e.ExceptionObject as Exception ?? new Exception("non-CLR fatal error"));

        // Restore any kill-switch a crashed prior run left in place (best-effort;
        // needs root — a no-op in the unprivileged GUI, but the elevated daemon
        // that drives the tunnel sweeps too). Must run before anything touches pf.
        try { Vpn.KillSwitch.Sweep(); } catch { }

        if (args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase)))
        {
            try { Service.ServiceHostRunner.Run(); return 0; }
            catch (Exception e) { LogStartupError(e); return 1; }
        }

        // Privileged daemon verbs — invoked as root by the GUI via the macOS admin
        // prompt (ServiceManager.RunSelfElevated). Headless, no display required.
        if (args.Length > 0 && Service.DaemonCli.Verbs.Contains(args[0].ToLowerInvariant()))
            return Service.DaemonCli.Run(args[0].ToLowerInvariant(), args.Skip(1).ToArray());

        if (args.Length > 0 && CliVerbs.Contains(args[0].ToLowerInvariant()))
            return CliRunner.Run(args[0], args.Skip(1).ToArray());

        // Offscreen UI screenshots — builds its own headless Avalonia app.
        if (args.Length > 0 && string.Equals(args[0], "uishot", StringComparison.OrdinalIgnoreCase))
            return UiShot.Run(args.Skip(1).ToArray());

        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
            return 0;
        }
        catch (Exception e)
        {
            LogStartupError(e);
            return 1;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();

    /// <summary>Append a startup/unhandled error to ~/Library/Application Support/Qeli/startup-error.log
    /// (and stderr) so a crash-on-launch can be diagnosed without a debugger.</summary>
    internal static void LogStartupError(Exception e)
    {
        var text = $"==== {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'} ====\n{e}\n\n";
        try
        {
            var dir = Model.Paths.UserDir;
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "startup-error.log"), text);
        }
        catch { /* ignore — best effort */ }
        try { Console.Error.WriteLine(text); } catch { }
    }
}
