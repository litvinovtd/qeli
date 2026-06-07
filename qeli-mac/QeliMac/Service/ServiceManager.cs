using System.Diagnostics;
using System.IO;

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

    private static string ExePath =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    public static bool IsInstalled() => File.Exists(PlistPath);

    public static bool IsRunning()
    {
        try
        {
            var (_, code) = Run($"list {ServiceName}");
            return code == 0; // loaded in the system domain
        }
        catch { return false; }
    }

    public static void Install()
    {
        File.WriteAllText(PlistPath, Plist());
        // chown root:wheel + 0644 so launchd accepts it as a system daemon.
        Run2("/usr/sbin/chown", $"root:wheel \"{PlistPath}\"");
        Run2("/bin/chmod", $"644 \"{PlistPath}\"");
        Run($"load -w \"{PlistPath}\"");
    }

    public static void Uninstall()
    {
        try { Run($"unload -w \"{PlistPath}\""); } catch { }
        try { File.Delete(PlistPath); } catch { }
    }

    public static void Start()
    {
        if (!IsInstalled()) Install();
        else Run($"load -w \"{PlistPath}\"");
    }

    public static void Stop() => Run($"unload \"{PlistPath}\"");

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
        string outp = p.StandardOutput.ReadToEnd();
        p.StandardError.ReadToEnd();
        p.WaitForExit();
        return (outp, p.ExitCode);
    }
}
