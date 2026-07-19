using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace QeliMac.Service;

/// <summary>
/// Installs/controls the Qeli launchd daemon — the macOS analogue of qeli-win's
/// Windows Service. The daemon is a system LaunchDaemon
/// (/Library/LaunchDaemons/&lt;label&gt;.plist) that runs the same executable with
/// <c>--service</c> as root, auto-starts at boot (before login) and is kept alive, so
/// the VPN comes up for all users. Install/uninstall/start/stop require root.
/// </summary>
public static class ServiceManager
{
    public const string ServiceName = "ru.autocash.qeli.daemon";
    private const string PlistPath = "/Library/LaunchDaemons/" + ServiceName + ".plist";
    // Modern launchctl service target: the system domain + the daemon's label.
    private const string ServiceTarget = "system/" + ServiceName;

    [DllImport("libc")] private static extern uint geteuid();

    /// <summary>True when the current process is NOT root, so privileged daemon
    /// operations must be routed through <see cref="RunSelfElevated"/> (admin prompt)
    /// instead of being run directly.</summary>
    public static bool NeedsElevation => geteuid() != 0;

    private static string ExePath =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    public static bool IsInstalled() => File.Exists(PlistPath);

    public static bool IsRunning()
    {
        try
        {
            // `print system/<label>` exits 0 only when the daemon is bootstrapped.
            var (_, code) = Run($"print {ServiceTarget}");
            return code == 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// Refuse to register a root LaunchDaemon pointing at a binary a non-root user
    /// can replace.
    /// </summary>
    /// <remarks>
    /// launchd starts this at boot as root from whatever path the plist records, and
    /// KeepAlive restarts it — but launchd does NOT check who owns that binary. The
    /// docs have users running straight out of <c>dist/</c> or <c>~/Downloads</c>, so
    /// the recorded path is typically user-writable, and overwriting it afterwards is
    /// persistent root with no elevation required.
    ///
    /// Checked as the real property rather than a fixed directory list: the binary and
    /// every ancestor must be root-owned and not group/other-writable. A writable
    /// PARENT is just as fatal as a writable file — you can swap the file out from
    /// under launchd by renaming.
    /// </remarks>
    internal static void EnsureProtectedLocation(string exePath)
    {
        var full = Path.GetFullPath(exePath);
        for (var path = full; !string.IsNullOrEmpty(path); path = Path.GetDirectoryName(path) ?? "")
        {
            // %u = owner uid, %Lp = permission bits in octal.
            var (outp, code) = Run2("/usr/bin/stat", $"-f \"%u %Lp\" \"{path}\"");
            if (code != 0)
                throw new InvalidOperationException($"Cannot stat '{path}' while validating the daemon path.");
            var parts = outp.Trim().Split(' ');
            if (parts.Length != 2 || !int.TryParse(parts[0], out var uid))
                throw new InvalidOperationException($"Unexpected stat output for '{path}': {outp.Trim()}");
            var mode = Convert.ToInt32(parts[1], 8);
            if (uid != 0 || (mode & 0b000_010_010) != 0)
                throw new InvalidOperationException(
                    "Refusing to install the LaunchDaemon: it would run as root at boot from " +
                    $"\"{full}\", but \"{path}\" is not root-owned or is group/world-writable. " +
                    "Anyone able to write there could then run code as root on every boot." +
                    Environment.NewLine + Environment.NewLine +
                    "Move Qeli.app to /Applications (owned by root, e.g. " +
                    "`sudo cp -R Qeli.app /Applications/ && sudo chown -R root:wheel /Applications/Qeli.app`) " +
                    "and install the service from there.");
            if (path == "/") break;
        }
    }

    public static void Install()
    {
        EnsureProtectedLocation(ExePath);
        File.WriteAllText(PlistPath, Plist());
        // chown root:wheel + 0644 so launchd accepts it as a system daemon.
        Run2("/usr/sbin/chown", $"root:wheel \"{PlistPath}\"");
        Run2("/bin/chmod", $"644 \"{PlistPath}\"");
        // Modern bootstrap/bootout — the legacy `load -w`/`unload -w` hang when invoked
        // outside an Aqua login session (e.g. under the osascript privilege trampoline).
        Run($"bootout {ServiceTarget}");          // clear any stale registration (no-op if absent)
        Run($"enable {ServiceTarget}");           // clear a disabled override (the legacy `-w`)
        Run($"bootstrap system \"{PlistPath}\""); // load + RunAtLoad start
    }

    public static void Uninstall()
    {
        try { Run($"bootout {ServiceTarget}"); } catch { }
        try { File.Delete(PlistPath); } catch { }
    }

    public static void Start()
    {
        if (!IsInstalled()) { Install(); return; }
        Run($"enable {ServiceTarget}");
        Run($"bootstrap system \"{PlistPath}\"");
    }

    public static void Stop() => Run($"bootout {ServiceTarget}");

    /// <summary>
    /// Re-exec this same binary with the given privileged verb as root, asking macOS
    /// for authorization via the native admin dialog (Touch ID / password). Used by the
    /// non-root GUI to install/control the daemon without launching the whole app under
    /// sudo. Returns (ok, output); ok is false on failure OR if the user cancels the
    /// prompt (<paramref name="canceled"/> is set in that case).
    /// </summary>
    public static (bool ok, string output, bool canceled) RunSelfElevated(params string[] verbArgs)
    {
        // /bin/sh command: '<exe>' '<arg1>' '<arg2>' …  (each token single-quoted).
        var sh = string.Join(' ', new[] { ExePath }.Concat(verbArgs).Select(ShQuote));
        // Embed that as an AppleScript string literal (escape \ then ").
        var asLit = "\"" + sh.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        var script = $"do shell script {asLit} with administrator privileges";

        var psi = new ProcessStartInfo("/usr/bin/osascript")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-e");
        psi.ArgumentList.Add(script);

        using var p = Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        // Cap the whole prompt+install (the user has to type the password within this).
        // Backstop only — the caller already runs this off the UI thread.
        if (!p.WaitForExit(300_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            return (false, "timed out waiting for the administrator prompt", false);
        }
        string outp = stdoutTask.GetAwaiter().GetResult();
        string err = stderrTask.GetAwaiter().GetResult();
        // osascript reports a user-cancelled auth dialog as error -128.
        bool canceled = p.ExitCode != 0 && err.Contains("-128");
        string msg = string.IsNullOrWhiteSpace(err) ? outp.Trim() : err.Trim();
        return (p.ExitCode == 0, msg, canceled);
    }

    /// <summary>POSIX single-quote a token so /bin/sh treats it literally.</summary>
    private static string ShQuote(string s) => "'" + s.Replace("'", "'\\''") + "'";

    private static string Plist() =>
        $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{ServiceName}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{ExePath}</string>
                <string>--service</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardErrorPath</key>
            <string>/Library/Application Support/Qeli/daemon.stderr.log</string>
        </dict>
        </plist>
        """;

    private static (string outp, int code) Run(string args) => Run2("/bin/launchctl", args);

    private static (string outp, int code) Run2(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        // Drain both pipes concurrently (a single sequential ReadToEnd can deadlock if
        // the other pipe's buffer fills) and bound the call so a wedged launchctl can't
        // hang the elevated helper forever.
        var so = p.StandardOutput.ReadToEndAsync();
        _ = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(20_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            return ("timed out", -1);
        }
        return (so.GetAwaiter().GetResult(), p.ExitCode);
    }
}
