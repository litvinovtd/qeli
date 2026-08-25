using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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
        if (rest.Length < 2 || string.IsNullOrWhiteSpace(rest[0])
            || string.IsNullOrWhiteSpace(rest[1]))
        {
            Console.Error.WriteLine("daemon-install: expected profile path and SHA-256 digest");
            return 2;
        }
        var path = rest[0];
        byte[] expectedDigest;
        try
        {
            expectedDigest = Convert.FromHexString(rest[1]);
        }
        catch (FormatException)
        {
            Console.Error.WriteLine("daemon-install: invalid SHA-256 digest");
            return 2;
        }
        if (expectedDigest.Length != SHA256.HashSizeInBytes)
            throw new InvalidOperationException("daemon-install: invalid SHA-256 digest length");
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
        // File metadata checks alone cannot close the same-UID in-place write race. Bind the
        // handoff to the exact bytes selected by the GUI before the authorization prompt:
        // the expected digest is already part of the root command argv, and the helper hashes
        // bytes read from the same descriptor it inspected. Rename, replacement or in-place
        // modification therefore fails closed instead of changing the daemon configuration.
        var profileBytes = ReadProfileHandoff(path);
        var actualDigest = SHA256.HashData(profileBytes);
        if (!CryptographicOperations.FixedTimeEquals(expectedDigest, actualDigest))
            throw new InvalidOperationException(
                "daemon-install: profile changed after authorization was requested; retry the operation");
        var cfg = JsonSerializer.Deserialize<VpnConfig>(Encoding.UTF8.GetString(profileBytes))
                  ?? throw new InvalidOperationException("could not parse daemon profile");

        ServiceState.SaveProfile(cfg);                 // AES-GCM into /Library/Application Support/Qeli
        ServiceManager.Uninstall();                    // no-op if absent; ensures a clean reload
        ServiceManager.Install();                      // write plist + chown root:wheel + launchctl load -w

        Console.WriteLine("OK installed");
        return 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinTimespec { public nint Seconds; public nint Nanoseconds; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinStat
    {
        public int Device;
        public ushort Mode;
        public ushort LinkCount;
        public ulong Inode;
        public uint Uid;
        public uint Gid;
        public int RDevice;
        public DarwinTimespec AccessTime;
        public DarwinTimespec ModificationTime;
        public DarwinTimespec ChangeTime;
        public DarwinTimespec BirthTime;
        public long Size;
        public long Blocks;
        public int BlockSize;
        public uint Flags;
        public uint Generation;
        public int Spare;
        public long QSpare0;
        public long QSpare1;
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int open(string path, int flags, uint mode);
    [DllImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int fstat_inode64(int fd, out DarwinStat stat);
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int fstat_plain(int fd, out DarwinStat stat);

    /// <summary>Refuse a hand-off file that is not a plain, single-link, non-world/group-
    /// writable regular file owned by root or by the invoking user. Opens once with
    /// O_NOFOLLOW, validates that descriptor, and reads from the same descriptor.</summary>
    private static byte[] ReadProfileHandoff(string path)
    {
        const int O_RDONLY = 0x0000, O_NOFOLLOW = 0x0100, O_CLOEXEC = 0x1000000;
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
        if (fd < 0)
            throw new InvalidOperationException(
                $"daemon-install: cannot open \"{path}\" safely: errno {Marshal.GetLastPInvokeError()}");
        using var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        DarwinStat stat;
        int rc = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? fstat_inode64(fd, out stat)
            : fstat_plain(fd, out stat);
        if (rc != 0)
            throw new InvalidOperationException(
                $"daemon-install: cannot inspect opened handoff: errno {Marshal.GetLastPInvokeError()}");

        int mode = stat.Mode;
        uint uid = stat.Uid;
        const int SIfmt = 0xF000, SIfreg = 0x8000;

        if ((mode & SIfmt) != SIfreg || stat.LinkCount != 1)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — expected a single-link regular file.");
        if ((mode & 0b000_010_010) != 0)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — it is group- or world-writable " +
                $"(mode {Convert.ToString(mode & 0x1FF, 8)}), so its contents are not " +
                "trustworthy input for a root daemon's configuration.");

        // The GUI runs as the user; under sudo/osascript SUDO_UID names them. Accept only
        // root or that user as the owner.
        uint expected = 0;
        var invokingUid = Environment.GetEnvironmentVariable("QELI_INVOKING_UID")
            ?? Environment.GetEnvironmentVariable("SUDO_UID");
        if (!string.IsNullOrEmpty(invokingUid) && uint.TryParse(invokingUid, out var su)) expected = su;
        if (uid != 0 && uid != expected)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — owned by uid {uid}, which is neither " +
                $"root nor the invoking user ({expected}).");

        const int MaxProfileBytes = 4 * 1024 * 1024;
        if (stat.Size < 0 || stat.Size > MaxProfileBytes)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — invalid profile size {stat.Size}.");

        // Read from the SAME descriptor that was inspected. Renaming or replacing
        // the user-path during the authorization prompt can no longer change bytes
        // consumed by the root process.
        using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        var bytes = new byte[MaxProfileBytes + 1];
        int total = 0;
        while (total < bytes.Length)
        {
            int read = stream.Read(bytes, total, bytes.Length - total);
            if (read == 0) break;
            total += read;
        }
        if (total > MaxProfileBytes)
            throw new InvalidOperationException(
                $"daemon-install: refusing \"{path}\" — profile grew beyond {MaxProfileBytes} bytes while being read.");
        return bytes.AsSpan(0, total).ToArray();
    }
}
