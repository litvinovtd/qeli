using System.IO;
using System.Runtime.InteropServices;
using Avalonia;

namespace QeliMac;

/// <summary>
/// Entry point. "--service" runs the headless launchd daemon (root, no GUI); the
/// selftest/packetbench/handshake/connect/genassets/genicns verbs run headless for debugging/CI;
/// "uishot" renders UI screenshots; anything else launches the Avalonia GUI.
/// A top-level guard logs any startup exception so a launch crash is diagnosable.
/// </summary>
public static class Program
{
    private static readonly string[] CliVerbs = { "selftest", "packetbench", "handshake", "connect", "genassets", "genicns" };

    // Darwin's sigset_t is a bare uint32 with signal N in bit N-1, and SIG_SETMASK is 3.
    // Both read out of the macOS SDK headers rather than assumed: Linux's sigset_t is
    // wider, and marshalling that width here would read and write the wrong bytes.
    private const int SIG_SETMASK = 3;
    private const int SIGCHLD = 20;

    [DllImport("libc", SetLastError = true)]
    private static extern int pthread_sigmask(int how, ref uint set, out uint old);

    [DllImport("libc")]
    private static extern uint geteuid();

    /// <summary>
    /// For the root daemon helper launched by the GUI, unblock every signal inherited
    /// from the authorization trampoline; returns what had been blocked, or 0 when the
    /// current process is not that helper or there was nothing to clear.
    /// </summary>
    /// <remarks>
    /// Keep this the FIRST thing Main does. The GUI performs privileged work by re-running
    /// this same binary through <c>osascript -e 'do shell script "…" with administrator
    /// privileges'</c> (see <see cref="Service.ServiceManager.RunSelfElevated"/>).
    /// AppleScript runs that as <c>sh -c '&lt;one simple command&gt;'</c>, and for a single
    /// simple command sh execs instead of forking — so the helper becomes a DIRECT child of
    /// macOS's security_authtrampoline and inherits its signal mask, which blocks SIGCHLD
    /// (measured on macOS 26: 0xFBFEE027).
    ///
    /// A blocked SIGCHLD is not cosmetic here. System.Diagnostics.Process on Unix learns
    /// that a child exited from SIGCHLD *delivery*, not from a blocking waitpid, so while
    /// the signal is masked no child is ever reaped: every Process.WaitForExit(timeout) in
    /// the elevated helper runs to its full timeout and then reports a child that finished
    /// in milliseconds as still running.
    ///
    /// That is what made the daemon uninstallable. ServiceManager.Run3 bounds each
    /// `launchctl` call at 20 s; BootoutChecked spends three of them, concludes that a
    /// daemon which had never been installed is still loaded, and throws — before Install()
    /// ever writes the LaunchDaemon plist, so no plist was ever written and no daemon ever
    /// started. Every other spawned tool was hit the same way: networksetup/route/ifconfig
    /// (NetworkConfigurator.Exec, 30 s each) and pfctl (KillSwitch.Pf, 20 s each).
    ///
    /// This is invisible from a terminal AND through any shell wrapper, which is why it
    /// survived so long: a shell unblocks SIGCHLD for the children it forks, so both
    /// `sudo … daemon-install` and `do shell script "/bin/sh wrapper.sh"` work fine. Only
    /// the direct-exec path is broken — the one path the GUI actually uses. A regression
    /// test for this MUST invoke the binary as a direct `do shell script` child.
    ///
    /// Clearing the mask later also works — the runtime consults the current mask rather
    /// than caching it when its signal thread is created — but there is no reason to run
    /// the startup recovery below under a mask we already know is wrong.
    /// </remarks>
    private static uint ClearInheritedSignalMaskForElevatedDaemonHelper(string[] args)
    {
        // The leaked mask belongs specifically to the GUI -> osascript -> root helper
        // path. Do not rewrite signal policy for the normal GUI, the launchd service,
        // developer CLI verbs, or a direct root invocation. RunSelfElevated supplies
        // QELI_INVOKING_UID and invokes exactly one of DaemonCli.Verbs.
        if (!OperatingSystem.IsMacOS() ||
            geteuid() != 0 ||
            string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("QELI_INVOKING_UID")) ||
            args.Length == 0 ||
            !Service.DaemonCli.Verbs.Contains(args[0].ToLowerInvariant()))
            return 0;

        try
        {
            uint none = 0;
            int rc = pthread_sigmask(SIG_SETMASK, ref none, out uint previous);
            if (rc == 0) return previous;

            LogStartupNote($"could not clear the inherited signal mask: pthread_sigmask returned {rc}",
                           toStderr: false);
            return 0;
        }
        catch (Exception e)
        {
            LogStartupNote($"could not clear the inherited signal mask: {e.Message}", toStderr: false);
            return 0;
        }
    }

    [STAThread]
    public static int Main(string[] args)
    {
        // Before the elevated helper spawns a child process — see the method above.
        uint inheritedMask = ClearInheritedSignalMaskForElevatedDaemonHelper(args);
        if (inheritedMask != 0)
            LogStartupNote(
                $"cleared a non-empty inherited signal mask (0x{inheritedMask:X8})" +
                ((inheritedMask & (1u << (SIGCHLD - 1))) != 0
                    ? "; SIGCHLD was blocked, so without this every external command would " +
                      "have run to its full timeout and then been reported as still running"
                    : ""),
                // The log only. stderr is this process's user-facing channel when it runs as
                // the elevated helper: osascript hands it to the GUI as the failure message,
                // and a diagnostic note prepended to a real error only obscures it.
                toStderr: false);

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogStartupError(e.ExceptionObject as Exception ?? new Exception("non-CLR fatal error"));

        // Restore any kill-switch a crashed prior run left in place. The unprivileged GUI
        // may be unable to do this, but the root daemon must not start a new generation after
        // a failed recovery and silently overwrite the only restoration journal.
        Exception? killSwitchRecoveryFailure = null;
        try { Vpn.KillSwitch.Sweep(message => Console.Error.WriteLine($"qeli: {message}")); }
        catch (Exception e) { killSwitchRecoveryFailure = e; LogStartupError(e); }

        // networksetup persists DNS on the physical service after its owner dies. Restore a
        // stale journal before a restarted daemon can mistake qeli's 10.9.0.1 for the user's
        // original resolver and make the outage permanent. SetDns repeats this just before
        // acquisition; this startup sweep also repairs DNS when no reconnect is requested.
        Exception? dnsRecoveryFailure = null;
        try { Vpn.NetworkConfigurator.SweepDns(message => Console.Error.WriteLine($"qeli: {message}")); }
        catch (Exception e) { dnsRecoveryFailure = e; LogStartupError(e); }

        if (args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase)))
        {
            // Starting a new tunnel after a failed stale-journal restore could leave the host
            // with qeli DNS but no usable VPN. Let launchd retry the recovery on its next
            // supervised start; never overwrite the saved pre-qeli resolver snapshot.
            if (killSwitchRecoveryFailure != null || dnsRecoveryFailure != null) return 1;
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
    internal static void LogStartupError(Exception e) => LogStartupNote(e.ToString());

    /// <summary>Append one startup fact to that same log. <paramref name="toStderr"/> is false
    /// for notes that are diagnostics rather than failures: when this process runs as the
    /// elevated helper, stderr is what osascript hands back to the GUI as the error message,
    /// and a note prepended to a real error only obscures it.</summary>
    internal static void LogStartupNote(string message, bool toStderr = true)
    {
        var text = $"==== {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'} ====\n{message}\n\n";
        try
        {
            var dir = Model.Paths.UserDir;
            Directory.CreateDirectory(dir);
            File.AppendAllText(Path.Combine(dir, "startup-error.log"), text);
        }
        catch { /* ignore — best effort */ }
        if (toStderr) { try { Console.Error.WriteLine(text); } catch { } }
    }
}
