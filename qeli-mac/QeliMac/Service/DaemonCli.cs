using System.IO;
using System.Text.Json;
using QeliMac.Model;

namespace QeliMac.Service;

/// <summary>
/// Headless privileged verbs the GUI invokes as root (via the native admin-auth
/// prompt — see <see cref="ServiceManager.RunSelfElevated"/>). They do the
/// install/uninstall/start/stop that touch /Library and launchctl, so the GUI
/// itself can keep running as the ordinary logged-in user (plain double-click,
/// no sudo). When the GUI already runs as root these are bypassed and the
/// <see cref="ServiceManager"/> primitives are called directly.
/// </summary>
public static class DaemonCli
{
    public static readonly string[] Verbs =
        { "daemon-install", "daemon-uninstall", "daemon-start", "daemon-stop" };

    public static int Run(string verb, string[] rest)
    {
        try
        {
            switch (verb)
            {
                case "daemon-install":
                    return Install(rest);
                case "daemon-uninstall":
                    ServiceManager.Uninstall();
                    Console.WriteLine("OK uninstalled");
                    return 0;
                case "daemon-start":
                    ServiceManager.Start();
                    Console.WriteLine("OK started");
                    return 0;
                case "daemon-stop":
                    ServiceManager.Stop();
                    Console.WriteLine("OK stopped");
                    return 0;
                default:
                    Console.Error.WriteLine($"unknown daemon verb '{verb}'");
                    return 2;
            }
        }
        catch (Exception e)
        {
            // osascript surfaces a non-zero exit + stderr to the GUI caller.
            Console.Error.WriteLine(e.Message);
            return 1;
        }
    }

    /// <summary>
    /// daemon-install &lt;profileJsonPath&gt; — read the GUI-written profile, encrypt it
    /// into the shared dir (as root), then (re)install + load the LaunchDaemon so it
    /// picks up the new profile. The temp profile file is deleted afterwards.
    /// </summary>
    private static int Install(string[] rest)
    {
        if (rest.Length < 1 || string.IsNullOrWhiteSpace(rest[0]))
        {
            Console.Error.WriteLine("daemon-install: missing profile path");
            return 2;
        }
        var path = rest[0];
        var cfg = JsonSerializer.Deserialize<VpnConfig>(File.ReadAllText(path))
                  ?? throw new InvalidOperationException("could not parse daemon profile");

        ServiceState.SaveProfile(cfg);                 // AES-GCM into /Library/Application Support/Qeli
        ServiceManager.Uninstall();                    // no-op if absent; ensures a clean reload
        ServiceManager.Install();                      // write plist + chown root:wheel + launchctl load -w

        try { File.Delete(path); } catch { /* best effort — it is user-owned 0600 */ }
        Console.WriteLine("OK installed");
        return 0;
    }
}
