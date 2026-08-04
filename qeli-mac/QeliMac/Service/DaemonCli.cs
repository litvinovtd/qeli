using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using QeliMac.Model;
using Qeli.Shared.Model;

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
        // This runs as ROOT and the path comes from argv, so vet the file before reading it.
        //
        // It used to be a bare `File.ReadAllText(path)`: no owner check, no mode check, no
        // symlink check, no type check. The caller (MainWindow.InstallDaemonElevated) writes
        // the profile to a PREDICTABLE path in the user's own directory —
        // ~/Library/Application Support/Qeli/pending-daemon-profile.json — and then triggers
        // the authorization prompt. The gap between "file written" and "root reads it" is the
        // entire duration of that prompt, up to the 300 s RunSelfElevated timeout, and any
        // process running as the user can watch for the file and swap it. What it swaps in
        // becomes the ROOT daemon's configuration: server address, credentials, routes, DNS,
        // with RunAtLoad + KeepAlive. The user, meanwhile, is looking at a password prompt
        // they themselves initiated.
        //
        // Vetting cannot close the race on its own — the file lives in a directory the
        // attacker controls — but it does reject the cases that matter: a symlink aimed at
        // something else, a file owned by another account, and anything group/world-writable.
        // The real fix is to stop passing the profile through a user-writable path at all
        // (stdin, or a root-owned mkstemp), which is a larger change to the caller.
        // (Audit 2026-08-04.)
        VetProfileHandoff(path);
        var cfg = JsonSerializer.Deserialize<VpnConfig>(File.ReadAllText(path))
                  ?? throw new InvalidOperationException("could not parse daemon profile");

        ServiceState.SaveProfile(cfg);                 // AES-GCM into /Library/Application Support/Qeli
        ServiceManager.Uninstall();                    // no-op if absent; ensures a clean reload
        ServiceManager.Install();                      // write plist + chown root:wheel + launchctl load -w

        try { File.Delete(path); } catch { /* best effort — it is user-owned 0600 */ }
        Console.WriteLine("OK installed");
        return 0;
    }

    [DllImport("libc", EntryPoint = "lstat$INODE64", SetLastError = true)]
    private static extern int lstat_inode64(string path, byte[] buf);
    [DllImport("libc", EntryPoint = "lstat", SetLastError = true)]
    private static extern int lstat_plain(string path, byte[] buf);

    /// <summary>Refuse a hand-off file that is not a plain, single-link, non-world/group-
    /// writable regular file owned by root or by the invoking (sudo) user. Uses lstat, so a
    /// symlink is judged on itself and rejected rather than followed.</summary>
    private static void VetProfileHandoff(string path)
    {
        var buf = new byte[256];   // comfortably larger than struct stat (144 bytes)
        int rc = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? lstat_inode64(path, buf)
            : lstat_plain(path, buf);
        if (rc != 0)
            throw new InvalidOperationException(
                $"daemon-install: cannot inspect \"{path}\": errno {Marshal.GetLastPInvokeError()}");

        // struct stat (macOS): st_mode u16 @8, st_nlink u16 @0x10-2… layout used elsewhere in
        // this project: st_mode @8, st_uid @16.
        int mode = BitConverter.ToUInt16(buf, 8);
        uint uid = BitConverter.ToUInt32(buf, 16);
        const int SIfmt = 0xF000, SIfreg = 0x8000;

        if ((mode & SIfmt) != SIfreg)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — not a regular file (a symlink here " +
                "would make root read, and act on, a file of someone else's choosing).");
        if ((mode & 0b000_010_010) != 0)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — it is group- or world-writable " +
                $"(mode {Convert.ToString(mode & 0x1FF, 8)}), so its contents are not " +
                "trustworthy input for a root daemon's configuration.");

        // The GUI runs as the user; under sudo/osascript SUDO_UID names them. Accept only
        // root or that user as the owner.
        uint expected = 0;
        var sudoUid = Environment.GetEnvironmentVariable("SUDO_UID");
        if (!string.IsNullOrEmpty(sudoUid) && uint.TryParse(sudoUid, out var su)) expected = su;
        if (uid != 0 && uid != expected)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — owned by uid {uid}, which is neither " +
                $"root nor the invoking user ({expected}).");
    }
}
