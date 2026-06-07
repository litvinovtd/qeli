using System.Diagnostics;
using System.IO;

namespace QeliMac;

/// <summary>
/// "Start at login" via a per-user launchd LaunchAgent (the macOS analogue of the
/// Windows Scheduled-Task autostart). Writes ~/Library/LaunchAgents/&lt;label&gt;.plist
/// that launches the app with <c>--autostart</c> at login. This does NOT run elevated
/// — the GUI then connects via sudo or the launchd daemon, exactly like qeli-win where
/// the always-on path is the service.
/// </summary>
public static class AutoStartManager
{
    private const string Label = "ru.autocash.qeli.autostart";

    private static string PlistPath
    {
        get
        {
            string home = Environment.GetEnvironmentVariable("SUDO_USER") is { Length: > 0 } u
                ? $"/Users/{u}"
                : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, "Library", "LaunchAgents", $"{Label}.plist");
        }
    }

    private static string ExePath =>
        Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule!.FileName;

    public static bool IsEnabled() => File.Exists(PlistPath);

    public static void Enable()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(PlistPath)!);
        File.WriteAllText(PlistPath, Plist());
        Launchctl($"unload \"{PlistPath}\"");          // reload if it existed
        Launchctl($"load -w \"{PlistPath}\"");
    }

    public static void Disable()
    {
        if (File.Exists(PlistPath))
        {
            Launchctl($"unload -w \"{PlistPath}\"");
            try { File.Delete(PlistPath); } catch { }
        }
    }

    public static void Apply(bool enabled)
    {
        if (enabled) Enable();
        else if (IsEnabled()) Disable();
    }

    private static string Plist() =>
        $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{Label}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{ExePath}</string>
                <string>--autostart</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>ProcessType</key>
            <string>Interactive</string>
        </dict>
        </plist>
        """;

    private static void Launchctl(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("/bin/launchctl", args)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
        }
        catch { /* best-effort */ }
    }
}
