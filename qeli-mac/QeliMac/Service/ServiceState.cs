using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QeliMac.Model;
using QeliMac.Vpn;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Service;

/// <summary>Status snapshot the daemon writes and the GUI polls.</summary>
public sealed class ServiceStatus
{
    public string Status { get; set; } = "Disconnected";
    public string? Extra { get; set; }
    public DateTime Time { get; set; }
    public long BytesUp { get; set; }
    public long BytesDown { get; set; }
    public DateTime? Since { get; set; }
}

/// <summary>
/// Shared state between the launchd daemon (writer, runs as root) and the GUI (reader),
/// stored under /Library/Application Support/Qeli so root can write and any user can
/// read. The macOS analogue of qeli-win's %ProgramData%\QeliWin exchange files.
/// </summary>
public static class ServiceState
{
    public static readonly string Dir = Paths.ServiceDir;
    public static string ProfileFile => Path.Combine(Dir, "service-profile.json");
    public static string StatusFile => Path.Combine(Dir, "service-status.json");
    public static string LogFile => Path.Combine(Dir, "service.log");
    public static string DesiredConnectionFile => Path.Combine(Dir, "service-connect.enabled");

    private static readonly object _logLock = new();
    private const long MaxLogBytes = 256 * 1024;

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

    private const int O_RDONLY = 0x0000;
    private const int O_WRONLY = 0x0001;
    private const int O_NOFOLLOW = 0x0100;
    private const int O_CREAT = 0x0200;
    private const int O_EXCL = 0x0800;
    private const int O_DIRECTORY = 0x100000;
    private const int O_CLOEXEC = 0x1000000;
    private const int S_IFMT = 0xF000;
    private const int S_IFDIR = 0x4000;
    private const int S_IFREG = 0x8000;

    [DllImport("libc")] private static extern uint geteuid();
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int open(string path, int flags, uint mode);
    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int openat(int directory, string path, int flags, uint mode);
    [DllImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int fstat_inode64(int fd, out DarwinStat stat);
    [DllImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static extern int fstat_plain(int fd, out DarwinStat stat);
    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int fchmod(int fd, uint mode);
    [DllImport("libc", EntryPoint = "renameat", SetLastError = true)]
    private static extern int renameat(int oldDirectory, string oldPath, int newDirectory, string newPath);
    [DllImport("libc", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int unlinkat(int directory, string path, int flags);
    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int fsync(int fd);

    private static int FStat(int fd, out DarwinStat stat) =>
        RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? fstat_inode64(fd, out stat)
            : fstat_plain(fd, out stat);

    /// <summary>
    /// Create the shared directory (root only) and refuse to use it unless root owns it and
    /// nobody else can write to it.
    /// </summary>
    /// <remarks>
    /// This used to be a bare <c>Directory.CreateDirectory(Dir)</c> — no owner check, no
    /// mode. On stock macOS the parent, /Library/Application Support, ships root:admin 0775,
    /// and an admin account is the DEFAULT account type. So any admin-group user could
    /// create "Qeli/" themselves, before qeli was ever installed, and own it. From there:
    /// plant a 32-byte .service.key and a service-profile.json encrypted under it, and the
    /// root daemon reads both at boot and brings up a tunnel to a server of their choosing;
    /// or symlink service.log at a system file and let the root daemon's ResetLog truncate
    /// it. Note the boundary this crosses: an admin can already become root WITH a password
    /// prompt — this gave it silently, at boot, with no prompt at all.
    ///
    /// ServiceManager.EnsureProtectedLocation already does exactly this vetting for the
    /// daemon EXECUTABLE, and qeli-win's ServiceState hardens the DACL on its own exchange
    /// directory for the same reason. Only the macOS state directory was left open.
    /// (Audit 2026-08-04, H-04.)
    ///
    /// The directory has to stay world-READABLE: the unprivileged GUI reads the status and
    /// log files out of it. 0755 root:wheel gives that while keeping writes root-only.
    /// </remarks>
    public static void EnsureDir()
    {
        if (!Directory.Exists(Dir))
        {
            // Only root may create it. A non-root create would land the directory owned by
            // the invoking user inside a parent any admin can write — the very situation
            // this method exists to prevent. Readers simply find no files yet.
            if (geteuid() != 0) return;
            Directory.CreateDirectory(Dir);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(Dir,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }
        ValidateDir();
    }

    /// <summary>Throw unless <see cref="Dir"/> is a real directory, owned by root, and not
    /// writable by group or other. Uses lstat, so a symlink planted at the path is judged on
    /// its own metadata and rejected rather than silently followed.</summary>
    private static void ValidateDir()
    {
        if (!OperatingSystem.IsMacOS()) return;
        using var directory = OpenValidatedDirectory();
    }

    /// Open the exact directory object with O_NOFOLLOW and validate the opened fd.
    /// All child operations use this fd through openat/renameat, so swapping the
    /// pathname after validation cannot redirect a privileged read or write.
    private static SafeFileHandle OpenValidatedDirectory()
    {
        int fd = open(Dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
        if (fd < 0)
            throw new InvalidOperationException(
                $"Cannot open \"{Dir}\" safely: errno {Marshal.GetLastPInvokeError()}.");
        var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        if (FStat(fd, out var stat) != 0)
        {
            handle.Dispose();
            throw new InvalidOperationException(
                $"Cannot inspect \"{Dir}\": errno {Marshal.GetLastPInvokeError()}.");
        }
        int mode = stat.Mode;
        if ((mode & S_IFMT) != S_IFDIR || stat.Uid != 0 || (mode & 0x12) != 0)
        {
            handle.Dispose();
            throw new InvalidOperationException(
                $"Refusing to use \"{Dir}\": expected a root-owned real directory writable " +
                $"only by root (uid={stat.Uid}, mode={Convert.ToString(mode & 0x1FF, 8)}). " +
                $"Remove it and reinstall the service.");
        }
        return handle;
    }

    private static void ValidateChild(DarwinStat stat, string name, bool privateRead)
    {
        int mode = stat.Mode;
        if ((mode & S_IFMT) != S_IFREG || stat.LinkCount != 1 || stat.Uid != 0
            || (mode & 0x12) != 0 || (privateRead && (mode & 0x3F) != 0))
            throw new InvalidOperationException(
                $"Refusing unsafe service state file '{name}' (uid={stat.Uid}, " +
                $"links={stat.LinkCount}, mode={Convert.ToString(mode & 0x1FF, 8)}).");
    }

    private static byte[]? ReadChild(string name, bool privateRead, long maxBytes)
    {
        if (!OperatingSystem.IsMacOS())
        {
            string path = Path.Combine(Dir, name);
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }
        using var directory = OpenValidatedDirectory();
        int dirfd = directory.DangerousGetHandle().ToInt32();
        int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
        if (fd < 0)
        {
            if (Marshal.GetLastPInvokeError() == 2) return null; // ENOENT
            throw new InvalidOperationException(
                $"Cannot open service state file '{name}': errno {Marshal.GetLastPInvokeError()}.");
        }
        using var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        if (FStat(fd, out var stat) != 0)
            throw new InvalidOperationException(
                $"Cannot inspect service state file '{name}': errno {Marshal.GetLastPInvokeError()}.");
        ValidateChild(stat, name, privateRead);
        if (stat.Size < 0 || stat.Size > maxBytes)
            throw new InvalidOperationException(
                $"Service state file '{name}' exceeds its {maxBytes}-byte limit.");
        using var stream = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        using var output = new MemoryStream((int)stat.Size);
        stream.CopyTo(output);
        return output.ToArray();
    }

    private static void AtomicWriteChild(string name, ReadOnlySpan<byte> data, uint mode)
    {
        EnsureDir();
        if (!OperatingSystem.IsMacOS())
        {
            File.WriteAllBytes(Path.Combine(Dir, name), data.ToArray());
            return;
        }
        using var directory = OpenValidatedDirectory();
        int dirfd = directory.DangerousGetHandle().ToInt32();
        string temp = $".{name}.{Guid.NewGuid():N}.tmp";
        int fd = openat(
            dirfd,
            temp,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
            mode
        );
        if (fd < 0)
            throw new InvalidOperationException(
                $"Cannot create temporary service state file: errno {Marshal.GetLastPInvokeError()}.");
        try
        {
            using (var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true))
            using (var stream = new FileStream(handle, FileAccess.Write, 4096, isAsync: false))
            {
                stream.Write(data);
                if (fchmod(fd, mode) != 0)
                    throw new InvalidOperationException(
                        $"Cannot protect temporary service state file: errno {Marshal.GetLastPInvokeError()}.");
                stream.Flush(flushToDisk: true);
            }
            fd = -1; // SafeFileHandle closed it.
            if (renameat(dirfd, temp, dirfd, name) != 0)
                throw new InvalidOperationException(
                    $"Cannot publish service state file '{name}': errno {Marshal.GetLastPInvokeError()}.");
            _ = fsync(dirfd);
        }
        finally
        {
            // No-op after a successful rename; removes a failed private temp file.
            _ = unlinkat(dirfd, temp, 0);
        }
    }

    // The daemon profile carries the server password / obfs_key, so it is encrypted at
    // rest with AES-256-GCM (mirrors qeli-win's DPAPI-LocalMachine ServiceState, E1).
    // Both writer (GUI as root) and reader (daemon as root) live in the system domain,
    // so the key is a root-only 0600 file in the shared dir (not the per-user Keychain).
    // On-disk layout: [nonce:12][tag:16][ciphertext]. Legacy plaintext is migrated.
    private const int NonceLen = 12;
    private const int TagLen = 16;

    private static byte[] ServiceKey()
    {
        EnsureDir();
        var existing = ReadChild(".service.key", privateRead: true, maxBytes: 32);
        if (existing != null)
        {
            if (existing.Length != 32)
                throw new CryptographicException(
                    "daemon service key is corrupt; refusing to replace it and lose the encrypted profile");
            return existing;
        }
        var key = RandomNumberGenerator.GetBytes(32);
        // Persist before returning. Returning a new but unsaved key made the profile
        // immediately undecryptable after the daemon restarted.
        AtomicWriteChild(".service.key", key, 0x180); // 0600
        return key;
    }

    public static void SaveProfile(VpnConfig cfg)
    {
        EnsureDir();
        var pt = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(cfg));
        var key = ServiceKey();
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var ct = new byte[pt.Length];
        var tag = new byte[TagLen];
        using (var gcm = new AesGcm(key, TagLen))
            gcm.Encrypt(nonce, pt, ct, tag);
        var blob = new byte[NonceLen + TagLen + ct.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, NonceLen);
        Buffer.BlockCopy(tag, 0, blob, NonceLen, TagLen);
        Buffer.BlockCopy(ct, 0, blob, NonceLen + TagLen, ct.Length);
        AtomicWriteChild("service-profile.json", blob, 0x180); // 0600
    }

    public static VpnConfig? LoadProfile()
    {
        try
        {
            var raw = ReadChild(
                "service-profile.json",
                privateRead: true,
                maxBytes: 4 * 1024 * 1024
            );
            if (raw == null) return null;
            string json;
            bool wasLegacyPlaintext = false;

            // Decide the FORMAT before trying to decrypt, and never fall back on a crypto
            // failure.
            //
            // The old shape was `try { AesGcm.Decrypt } catch { treat the bytes as JSON }`,
            // with no discrimination at all: a failed AUTHENTICATION TAG — i.e. a detected
            // forgery — took the same branch as a genuine pre-E1 plaintext file. The tag
            // therefore stopped being an authenticity boundary: to make the root daemon load
            // any VpnConfig you liked (server address, credentials, routes, DNS) you did not
            // need the key at all, you just wrote plain JSON. The migration then RE-ENCRYPTED
            // the forgery under the real key, erasing the evidence.
            //
            // A legacy file is UTF-8 JSON and starts with '{' (optionally after whitespace or
            // a BOM); a GCM blob starts with 12 random nonce bytes, which practically never
            // do. So: sniff first, and once we have committed to the encrypted format a tag
            // failure is fatal — the file is corrupt or forged, and either way must not be
            // used. (Audit 2026-08-04.)
            static bool LooksLikeLegacyJson(byte[] b)
            {
                int i = 0;
                if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) i = 3; // BOM
                while (i < b.Length && (b[i] == (byte)' ' || b[i] == (byte)'\t'
                                        || b[i] == (byte)'\r' || b[i] == (byte)'\n')) i++;
                return i < b.Length && b[i] == (byte)'{';
            }

            if (LooksLikeLegacyJson(raw))
            {
                json = Encoding.UTF8.GetString(raw);
                wasLegacyPlaintext = true;
            }
            else
            {
                if (raw.Length < NonceLen + TagLen)
                    throw new CryptographicException(
                        "daemon profile is neither legacy JSON nor a complete encrypted blob");
                var key = ServiceKey();
                var nonce = raw.AsSpan(0, NonceLen);
                var tag = raw.AsSpan(NonceLen, TagLen);
                var ct = raw.AsSpan(NonceLen + TagLen);
                var pt = new byte[ct.Length];
                using var gcm = new AesGcm(key, TagLen);
                // Throws on a tag mismatch — deliberately NOT caught here. Propagates to the
                // outer catch, which returns null, and the daemon starts no tunnel rather
                // than one an attacker described.
                gcm.Decrypt(nonce, ct, tag, pt);
                json = Encoding.UTF8.GetString(pt);
            }

            var cfg = JsonSerializer.Deserialize<VpnConfig>(json);
            if (wasLegacyPlaintext && cfg != null) SaveProfile(cfg);
            return cfg;
        }
        catch { return null; }
    }

    /// <summary>
    /// Persist the user's connection intent independently from whether the LaunchDaemon is
    /// installed. launchd may keep an installed daemon alive at boot, but an explicit
    /// Disconnect must survive that boot instead of silently reconnecting and reapplying DNS.
    /// Missing/corrupt state is fail-safe: the daemon stays idle until an explicit Start.
    /// </summary>
    public static void SetDesiredConnected(bool connected) =>
        AtomicWriteChild("service-connect.enabled", Encoding.ASCII.GetBytes(connected ? "1\n" : "0\n"), 0x180);

    public static bool DesiredConnected()
    {
        try
        {
            var raw = ReadChild("service-connect.enabled", privateRead: true, maxBytes: 16);
            return raw != null && Encoding.ASCII.GetString(raw).Trim() == "1";
        }
        catch { return false; }
    }

    public static void WriteStatus(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null)
    {
        try
        {
            EnsureDir();
            AtomicWriteChild("service-status.json", JsonSerializer.SerializeToUtf8Bytes(new ServiceStatus
            {
                Status = status.ToString(),
                Extra = extra,
                Time = DateTime.Now,
                BytesUp = bytesUp,
                BytesDown = bytesDown,
                Since = since,
            }), 0x1A4); // 0644
        }
        catch { /* ignore */ }
    }

    public static ServiceStatus? ReadStatus()
    {
        try
        {
            var raw = ReadChild("service-status.json", privateRead: false, maxBytes: 1024 * 1024);
            return raw == null ? null : JsonSerializer.Deserialize<ServiceStatus>(raw);
        }
        catch { return null; }
    }

    public static void ResetLog()
    {
        try { AtomicWriteChild("service.log", ReadOnlySpan<byte>.Empty, 0x1A4); } catch { }
    }

    public static void AppendLog(string line)
    {
        lock (_logLock)
        {
            try
            {
                var previous = ReadChild(
                    "service.log",
                    privateRead: false,
                    maxBytes: MaxLogBytes * 4
                ) ?? Array.Empty<byte>();
                if (previous.LongLength > MaxLogBytes) previous = Array.Empty<byte>();
                if (line.Length > 16 * 1024) line = line[..(16 * 1024)] + "…";
                var suffix = Encoding.UTF8.GetBytes(
                    $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}"
                );
                var combined = new byte[previous.Length + suffix.Length];
                Buffer.BlockCopy(previous, 0, combined, 0, previous.Length);
                Buffer.BlockCopy(suffix, 0, combined, previous.Length, suffix.Length);
                AtomicWriteChild("service.log", combined, 0x1A4); // 0644
            }
            catch { /* ignore */ }
        }
    }
}
