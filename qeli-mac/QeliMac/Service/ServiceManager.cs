using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using QeliMac.Vpn;

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
    public const string ServiceName = "ru.qeli.app.daemon";
    private const string PlistPath = "/Library/LaunchDaemons/" + ServiceName + ".plist";
    // Modern launchctl service target: the system domain + the daemon's label.
    private const string ServiceTarget = "system/" + ServiceName;

    // Pre-0.7.12 label. The daemon plist records the EXECUTABLE PATH, not the bundle id,
    // so after an in-place upgrade the old daemon keeps running the new binary under the
    // old label — invisible to the new code, which only looks at the new plist. Installing
    // then leaves TWO daemons fighting over the same tun/port. Every privileged path below
    // clears the legacy registration first; both run as root already, so this costs nothing.
    private const string LegacyServiceName = "ru.autocash.qeli.daemon";
    private const string LegacyPlistPath = "/Library/LaunchDaemons/" + LegacyServiceName + ".plist";
    private const string LegacyServiceTarget = "system/" + LegacyServiceName;

    /// <summary>True when a pre-0.7.12 daemon is still registered on this machine.</summary>
    public static bool LegacyInstalled() => File.Exists(LegacyPlistPath);

    /// <summary>Boot out and delete the pre-0.7.12 daemon. Requires root; no-op when absent.</summary>
    private static void RemoveLegacy()
    {
        if (!File.Exists(LegacyPlistPath)) return;
        BootoutChecked(LegacyServiceTarget, "Stopping the legacy daemon");
        File.Delete(LegacyPlistPath);
        if (File.Exists(LegacyPlistPath))
            throw new IOException($"Could not remove legacy daemon plist '{LegacyPlistPath}'.");
    }

    [DllImport("libc")] private static extern uint geteuid();
    [DllImport("libc")] private static extern uint getuid();

    // stat(2) straight from libc. On x86_64 the 64-bit-inode entry point is `stat$INODE64`
    // (plain `stat` there is the legacy 32-bit-inode variant with a DIFFERENT layout, so
    // calling it would read the wrong offsets); arm64 has only ever had the 64-bit form and
    // exports it as `stat`.
    [DllImport("libc", EntryPoint = "stat$INODE64", SetLastError = true)]
    private static extern int stat_inode64(string path, byte[] buf);
    [DllImport("libc", EntryPoint = "stat", SetLastError = true)]
    private static extern int stat_plain(string path, byte[] buf);

    /// <summary>Owner uid, owner gid and permission bits of <paramref name="path"/>.</summary>
    /// <remarks>
    /// Done with a syscall rather than by running /usr/bin/stat, which is what this used to
    /// do — one spawned process per path component, five or more per check, each with its own
    /// 20-second timeout, and with stderr discarded. When any of them failed to produce output
    /// the caller could only say "Cannot stat '<c>path</c>'" about a file that plainly exists,
    /// which is exactly how a working installation reported itself as broken. A syscall cannot
    /// fail for reasons unrelated to the file, and when it does fail it says why.
    ///
    /// Offsets are those of macOS's 64-bit-inode `struct stat`, identical on arm64 and x86_64:
    /// st_mode is a uint16 at 4, st_uid a uint32 at 16, st_gid a uint32 at 20.
    /// </remarks>
    private static (int uid, int gid, int mode) StatOrThrow(string path)
    {
        var buf = new byte[256];   // comfortably larger than struct stat (144 bytes)
        int rc = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? stat_inode64(path, buf)
            : stat_plain(path, buf);
        if (rc != 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            var why = errno switch
            {
                2 => "no such file or directory",
                13 => "permission denied",
                20 => "a path component is not a directory",
                _ => $"errno {errno}",
            };
            throw new InvalidOperationException(
                $"Cannot inspect \"{path}\" while validating the daemon path: {why}.");
        }
        return (
            (int)BitConverter.ToUInt32(buf, 16),
            (int)BitConverter.ToUInt32(buf, 20),
            BitConverter.ToUInt16(buf, 4) & 0xFFF);
    }

    /// <summary>True when the current process is NOT root, so privileged daemon
    /// operations must be routed through <see cref="RunSelfElevated"/> (admin prompt)
    /// instead of being run directly.</summary>
    public static bool NeedsElevation => geteuid() != 0;

    private static string ExePath =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    // Counts the legacy daemon as installed: after an upgrade it is still there and still
    // running, so reporting "not installed" would make the UI lie and would hide the very
    // thing the user needs to replace.
    public static bool IsInstalled() => File.Exists(PlistPath) || File.Exists(LegacyPlistPath);

    public static bool IsRunning()
    {
        try
        {
            // `print system/<label>` exits 0 only when the daemon is bootstrapped.
            var (_, code) = Run($"print {ServiceTarget}");
            if (code == 0) return true;
            if (!File.Exists(LegacyPlistPath)) return false;
            var (_, legacyCode) = Run($"print {LegacyServiceTarget}");
            return legacyCode == 0;
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
            var (uid, gid, mode) = StatOrThrow(path);

            // World-writable is always fatal: ANY local account could swap the binary that
            // launchd then runs as root.
            bool worldWritable = (mode & 0b000_000_010) != 0;

            // Group-writable is fatal only when the group is not a system/admin one.
            //
            // This used to reject group-write outright, which rejected /Applications — macOS
            // ships it `root:admin 0775` precisely so admins can install apps — and therefore
            // rejected the exact location the error message told people to move the app to.
            // The daemon could then never be installed from a normal install, while the GUI
            // kept re-prompting for the admin password. The check was measuring the wrong
            // property: on macOS, membership in `admin` already confers sudo, so an admin
            // being able to write there is not an escalation — they can become root directly.
            // `wheel` (gid 0) is likewise root-equivalent. Every other group is a real
            // boundary and still refuses.
            const int GidWheel = 0, GidAdmin = 80;
            bool groupWritable = (mode & 0b000_010_000) != 0
                                 && gid != GidWheel && gid != GidAdmin;

            if (uid != 0 || worldWritable || groupWritable)
                throw new InvalidOperationException(
                    "Refusing to install the LaunchDaemon: it would run as root at boot from " +
                    $"\"{full}\", but \"{path}\" is not root-owned, is world-writable, or is " +
                    "writable by a non-administrator group. Anyone able to write there could " +
                    "then run code as root on every boot." +
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
        // Same reason as Start(): do not depend on the caller having written the profile
        // first for the daemon's log directory to exist.
        ServiceState.EnsureDir();
        // An already-loaded copy must see Disconnect BEFORE launchctl sends SIGTERM. If its
        // cleanup fails, bootout waits for exit and the privileged sweep below retries from
        // the persistent DNS journal before any replacement daemon may connect.
        ServiceState.SetDesiredConnected(false);
        RemoveLegacy();   // never leave the pre-0.7.12 daemon running alongside the new one
        BootoutChecked(ServiceTarget, "Stopping the previous daemon");
        NetworkConfigurator.SweepDns(ServiceState.AppendLog, requireReleased: true);
        File.WriteAllText(PlistPath, Plist());
        // chown root:wheel + 0644 so launchd accepts it as a system daemon.
        Run2("/usr/sbin/chown", $"root:wheel \"{PlistPath}\"");
        Run2("/bin/chmod", $"644 \"{PlistPath}\"");
        // Modern bootstrap/bootout — the legacy `load -w`/`unload -w` hang when invoked
        // outside an Aqua login session (e.g. under the osascript privilege trampoline).
        Run($"enable {ServiceTarget}");           // clear a disabled override (the legacy `-w`)
        ServiceState.SetDesiredConnected(true);
        var beforeInstall = StatusStamp();
        LaunchctlChecked($"bootstrap system \"{PlistPath}\"", "Loading the daemon",
                         () => StatusStamp() > beforeInstall);
    }

    public static void Uninstall()
    {
        ServiceState.SetDesiredConnected(false);
        RemoveLegacy();
        BootoutChecked(ServiceTarget, "Stopping the daemon");
        NetworkConfigurator.SweepDns(ServiceState.AppendLog, requireReleased: true);
        File.Delete(PlistPath);
        if (File.Exists(PlistPath))
            throw new IOException($"Could not remove daemon plist '{PlistPath}'.");
    }

    public static void Start()
    {
        // Deliberately checks the CURRENT plist rather than IsInstalled(): after an upgrade
        // only the legacy one exists, and bootstrapping a path that isn't there would fail.
        // Install() writes the new plist and clears the legacy registration on the way.
        // launchd creates the plist's StandardErrorPath FILE but not its directory, and if it
        // cannot open that path the job fails to spawn — `bootstrap` then wedges until our
        // 20 s bound kills it, reporting only "timed out". The directory normally exists
        // because daemon-install writes the profile into it first, so this held only by
        // accident of call order: delete /Library/Application Support/Qeli (a reasonable
        // thing to try when troubleshooting) and every later start hangs, with an error that
        // names launchctl and never mentions the missing directory.
        ServiceState.EnsureDir();
        ServiceState.SetDesiredConnected(true);
        if (!File.Exists(PlistPath)) { Install(); return; }
        // Validate the path here too. This branch used to skip it, which made the security
        // check depend on whether a plist happened to exist — and launchd is about to run
        // that binary as root either way, so an existing plist is no reason to trust it less
        // carefully. It also made "start" behave differently from "install" for the same
        // installation, which is how a GUI failure could look nothing like a terminal run.
        EnsureProtectedLocation(ExePath);
        RemoveLegacy();
        Run($"enable {ServiceTarget}");
        var beforeStart = StatusStamp();
        LaunchctlChecked($"bootstrap system \"{PlistPath}\"", "Starting the daemon",
                         () => StatusStamp() > beforeStart);
    }

    public static void Stop()
    {
        // Persist intent first. Even if launchctl fails, a still-running daemon observes the
        // file within one second and retries its own cleanup; after reboot RunAtLoad stays idle.
        ServiceState.SetDesiredConnected(false);
        if (File.Exists(LegacyPlistPath))
            BootoutChecked(LegacyServiceTarget, "Stopping the legacy daemon");
        BootoutChecked(ServiceTarget, "Stopping the daemon");
        // Do not print "OK stopped" while networksetup still points at qeli. Once bootout has
        // completed no legitimate owner remains, so LiveOwner is also an error here.
        NetworkConfigurator.SweepDns(ServiceState.AppendLog, requireReleased: true);
    }

    /// <summary>
    /// Re-exec this same binary with the given privileged verb as root, asking macOS
    /// for authorization via the native admin dialog (Touch ID / password). Used by the
    /// non-root GUI to install/control the daemon without launching the whole app under
    /// sudo. Returns (ok, output); ok is false on failure OR if the user cancels the
    /// prompt (<paramref name="canceled"/> is set in that case).
    /// </summary>
    public static (bool ok, string output, bool canceled) RunSelfElevated(params string[] verbArgs)
    {
        // SECURITY (C-06): validate that THIS binary lives in a root-owned, non-user-writable
        // location BEFORE running it as root. Otherwise a user-writable app bundle (e.g. run
        // from ~/Downloads) could be swapped DURING the admin prompt and executed as root — a
        // same-user local privilege escalation. The check previously ran only inside Install()
        // (already root, too late); do it here first, in the non-root context.
        try { EnsureProtectedLocation(ExePath); }
        catch (Exception ex) { return (false, ex.Message, false); }

        // /bin/sh command: '<exe>' '<arg1>' '<arg2>' …  (each token single-quoted).
        // `do shell script ... with administrator privileges` does not reliably set
        // SUDO_UID. Pass the real GUI uid explicitly so daemon-install can require
        // that the inspected handoff descriptor belongs to exactly this user.
        var command = new[] { "/usr/bin/env", $"QELI_INVOKING_UID={getuid()}", ExePath }
            .Concat(verbArgs);
        var sh = string.Join(' ', command.Select(ShQuote));
        // Embed that as an AppleScript string literal (escape \ then ").
        var asLit = "\"" + sh.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        var script = $"do shell script {asLit} with administrator privileges";

        var psi = new ProcessStartInfo("/usr/bin/osascript")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
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
            <!-- launchd will not start a job again within ThrottleInterval seconds of its last
                 start, and the default is 10. Here the job is started by a person pressing
                 Connect, so a disconnect followed by a reconnect landed inside that window and
                 sat there doing nothing visible — the delay was launchd holding the job back,
                 not the daemon being slow (it logs "Daemon starting" to "Auth OK" in about a
                 second). Lowered to 1 rather than 0: KeepAlive is on, so a daemon that dies at
                 startup would otherwise respawn as fast as the kernel can fork it. -->
            <key>ThrottleInterval</key>
            <integer>1</integer>
            <key>StandardErrorPath</key>
            <string>/Library/Application Support/Qeli/daemon.stderr.log</string>
        </dict>
        </plist>
        """;

    private static (string outp, int code) Run(string args) => Run2("/bin/launchctl", args);

    private static (string outp, int code) Run2(string exe, string args)
    {
        var (outp, _, code) = Run3(exe, args);
        return (outp, code);
    }

    /// <summary>
    /// Run a tool and return stdout, stderr and the exit code separately.
    /// </summary>
    /// <remarks>
    /// stderr is kept rather than discarded because it is the ONLY place launchctl explains
    /// itself: a failed `bootstrap` prints "Bootstrap failed: 5: Input/output error" there
    /// and nothing on stdout. It used to be dropped on the floor, so a failure surfaced as
    /// an empty message — the elevated helper then exited 0 and the GUI reported success
    /// while nothing had been loaded. Kept SEPARATE from stdout, not merged: callers parse
    /// stdout (stat's `uid gid mode`), and folding a warning into it would corrupt the parse.
    /// </remarks>
    private static (string outp, string err, int code) Run3(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        // Drain both pipes concurrently (a single sequential ReadToEnd can deadlock if
        // the other pipe's buffer fills) and bound the call so a wedged launchctl can't
        // hang the elevated helper forever.
        var so = p.StandardOutput.ReadToEndAsync();
        var se = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(20_000))
        {
            try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
            return ("", $"`{exe} {args}` timed out after 20s", -1);
        }
        return (so.GetAwaiter().GetResult(), se.GetAwaiter().GetResult(), p.ExitCode);
    }

    /// <summary>
    /// Run launchctl and throw with what it actually said when the step did not take effect.
    /// </summary>
    /// <remarks>
    /// The outcome is verified with <paramref name="succeeded"/> instead of trusting the exit
    /// code, because launchctl's codes are not a usable contract: `bootstrap` returns non-zero
    /// for "already loaded" (a no-op that is fine) and `bootout` returns non-zero for "not
    /// loaded" (equally fine), while a genuine failure can share the same code. Asking "is the
    /// daemon there now?" is the property we actually care about.
    /// </remarks>
    private static void LaunchctlChecked(string args, string what, Func<bool> succeeded)
    {
        var psi = new ProcessStartInfo("/bin/launchctl", args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var p = Process.Start(psi)!;
        var so = p.StandardOutput.ReadToEndAsync();
        var se = p.StandardError.ReadToEndAsync();

        // Watch the OUTCOME, not the process. `launchctl bootstrap` regularly takes tens of
        // seconds to return under the osascript privilege trampoline while the daemon it
        // started is already up and serving after one — waiting for launchctl to finish was
        // the whole of the delay users saw between pressing Connect and anything happening,
        // and long enough that they pressed again. It is also why a hard timeout was the
        // wrong tool: the call was not stuck, just slow to report.
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            if (succeeded()) return;                       // daemon is alive — done, whatever launchctl is doing
            if (p.HasExited && p.ExitCode == 0) return;    // nothing to wait for
            Thread.Sleep(250);
        }

        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { /* best effort */ }
        var detail = (se.IsCompletedSuccessfully ? se.Result : "").Trim();
        if (detail.Length == 0) detail = (so.IsCompletedSuccessfully ? so.Result : "").Trim();
        throw new InvalidOperationException(
            $"{what} failed: the daemon did not come up within 30s of `launchctl {args}`" +
            (detail.Length == 0 ? "." : $" — {detail}"));
    }

    /// <summary>Unload a launchd job and verify the job is actually gone before returning.</summary>
    private static void BootoutChecked(string target, string what)
    {
        var (outp, err, _) = Run3("/bin/launchctl", $"bootout {target}");
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            if (!LaunchdHasTarget(target)) return; // includes the normal "not loaded" case
            Thread.Sleep(250);
        }

        string detail = string.IsNullOrWhiteSpace(err) ? outp.Trim() : err.Trim();
        throw new InvalidOperationException(
            $"{what} failed: launchd still reports '{target}' after 30s" +
            (detail.Length == 0 ? "." : $" — {detail}"));
    }

    private static bool LaunchdHasTarget(string target)
    {
        try
        {
            var (_, _, code) = Run3("/bin/launchctl", $"print {target}");
            return code == 0 || code == -1; // timeout/unknown is not proof of absence
        }
        catch
        {
            // Failure to query is not proof that the privileged daemon stopped. Keep waiting
            // until BootoutChecked can surface the failure instead of claiming success.
            return true;
        }
    }

    /// <summary>
    /// Last-write time of the status file the daemon rewrites every second, or
    /// <see cref="DateTime.MinValue"/> when it does not exist yet.
    /// </summary>
    /// <remarks>
    /// Progress of this stamp is what "the daemon started" is judged by — deliberately NOT
    /// `launchctl print`, which is the very tool whose slowness this works around; asking a
    /// slow tool whether the slow tool succeeded only doubles the wait. Comparing against a
    /// stamp taken BEFORE the attempt, rather than asking "is the file recent", matters when
    /// restarting: the file left by the previous daemon is still seconds old and would have
    /// answered yes before the new one had written anything at all.
    /// </remarks>
    private static DateTime StatusStamp()
    {
        try
        {
            var f = new FileInfo(ServiceState.StatusFile);
            return f.Exists ? f.LastWriteTimeUtc : DateTime.MinValue;
        }
        catch { return DateTime.MinValue; }
    }
}
