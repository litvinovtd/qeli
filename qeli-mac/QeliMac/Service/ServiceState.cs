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
public sealed class ServiceStatus : DesktopServiceStatus
{
    /// <summary>Written only by a completed root Stop(): launchd confirmed the daemon gone and
    /// DNS/firewall/forwarding recovery passed and no terminal daemon Error remains.
    /// A new explicit or launchd start invalidates it before attempting a connection.</summary>
    public bool Stopped { get; set; }
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
    private static readonly ServiceControlLock ControlLock = new(() => OpenControlLock(".service-control.lock"));
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, ServiceControlLock> OperationLocks = new();
    internal static IDisposable EnterOperation(string name)
    {
        ValidateChildName(name);
        return OperationLocks.GetOrAdd(name, key => new ServiceControlLock(() => OpenControlLock(key))).Enter();
    }
    private static void ValidateChildName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." || name.IndexOfAny(new[] { '/', '\\', '\0' }) >= 0)
            throw new ArgumentException("Service child must be a single filename", nameof(name));
    }
    internal static byte[]? ReadProtected(string name, int maximum)
    {
        ValidateChildName(name); EnsureDir();
        if (!Directory.Exists(Dir)) return null;
        return ReadChild(name, privateRead: false, maxBytes: maximum);
    }
    internal static bool WriteProtected(string name, byte[] bytes, bool replace = true)
    {
        ValidateChildName(name);
        return AtomicWriteChild(name, bytes, 0x180, replace);
    }
    internal static void DeleteProtected(string name)
    {
        ValidateChildName(name); EnsureDir();
        if (!OperatingSystem.IsMacOS()) { File.Delete(Path.Combine(Dir, name)); return; }
        using var directory = OpenValidatedDirectory();
        if (unlinkat(directory.DangerousGetHandle().ToInt32(), name, 0) != 0 && Marshal.GetLastPInvokeError() != 2)
            throw new IOException($"Cannot remove service child '{name}': errno {Marshal.GetLastPInvokeError()}");
    }
    internal static IDisposable EnterControl() => ControlLock.Enter();

    private static IDisposable OpenControlLock(string name)
    {
        EnsureDir();
        if (!OperatingSystem.IsMacOS())
            return new FileStream(Path.Combine(Dir, name),
                FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        using var directory = OpenValidatedDirectory();
        int fd = openat(directory.DangerousGetHandle().ToInt32(), name,
            0x2 | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0x180); // O_RDWR, 0600
        if (fd < 0) throw new IOException($"Cannot open daemon control lock: errno {Marshal.GetLastPInvokeError()}");
        var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        try
        {
            if (FStat(fd, out var stat) != 0) throw new IOException("Cannot inspect daemon control lock");
            // Builds before the openat ABI fix left root-owned locks with random modes. The
            // directory is already validated root-only, so a root-owned single-link regular
            // file here was made by us; repair it instead of refusing it forever.
            if (geteuid() == 0 && stat.Uid == 0 && stat.LinkCount == 1
                && (stat.Mode & S_IFMT) == S_IFREG && (stat.Mode & 0x1FF) != 0x180)
            {
                if (fchmod(fd, 0x180) != 0 || FStat(fd, out stat) != 0)
                    throw new IOException($"Cannot repair daemon control lock: errno {Marshal.GetLastPInvokeError()}");
            }
            ValidateChild(stat, name, privateRead: true);
            if (flock(fd, 0x2 | 0x4) != 0) // LOCK_EX | LOCK_NB (XNU sys/fcntl.h)
                throw new IOException($"Daemon control is busy: errno {Marshal.GetLastPInvokeError()}");
            return handle; // closing this exact fd releases the advisory lock
        }
        catch { handle.Dispose(); throw; }
    }
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
    private const int O_NONBLOCK = 0x0004;
    private const int O_NOFOLLOW = 0x0100;
    private const int O_CREAT = 0x0200;
    private const int O_EXCL = 0x0800;
    private const int O_DIRECTORY = 0x100000;
    private const int O_CLOEXEC = 0x1000000;
    private const int S_IFMT = 0xF000;
    private const int S_IFDIR = 0x4000;
    private const int S_IFREG = 0x8000;

    [DllImport("libc", SetLastError = true)] private static extern int flock(int fd, int operation);
    [DllImport("libc")] private static extern uint geteuid();
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int open(string path, int flags, uint mode);
    // openat(int, const char *, int, ...) is variadic: on Darwin ARM64 the mode must be on
    // the stack, so x3..x7 are padded. A plain 4-argument binding put it in x3, libc read
    // stack garbage instead, and O_CREAT made lock files with random modes (0551, 0544)
    // that ValidateChild then refused — the daemon could never take its control lock.
    // x86_64 passes the first variadic argument in a register. Same pattern as UtunDevice.
    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int openat_arm64(int directory, string path, int flags,
        long d3, long d4, long d5, long d6, long d7, long mode);
    [DllImport("libc", EntryPoint = "openat", SetLastError = true)]
    private static extern int openat_x64(int directory, string path, int flags, uint mode);
    private static int openat(int directory, string path, int flags, uint mode) =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? openat_arm64(directory, path, flags, 0, 0, 0, 0, 0, mode)
            : openat_x64(directory, path, flags, mode);
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

    // Registration uses a separate root-owned path, but the same fd/type/mode/size checks.
    internal static byte[]? ReadTrustedFile(string path, int maximum)
    {
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0);
        if (fd < 0)
        {
            if (Marshal.GetLastPInvokeError() == 2) return null;
            throw new IOException($"Cannot open daemon registration: errno {Marshal.GetLastPInvokeError()}");
        }
        using var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        if (FStat(fd, out var stat) != 0) throw new IOException("Cannot inspect daemon registration");
        ValidateChild(stat, path, privateRead: false);
        using var stream = new FileStream(handle, FileAccess.Read);
        return BoundedStorage.Read(stream, maximum);
    }

    private static byte[]? ReadChild(string name, bool privateRead, long maxBytes)
    {
        if (!OperatingSystem.IsMacOS())
        {
            string path = Path.Combine(Dir, name);
            try
            {
                using var snapshot = File.OpenRead(path);
                return BoundedStorage.Read(snapshot, checked((int)maxBytes));
            }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
        }
        using var directory = OpenValidatedDirectory();
        int dirfd = directory.DangerousGetHandle().ToInt32();
        int fd = openat(dirfd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0);
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
        return BoundedStorage.Read(stream, checked((int)maxBytes));
    }

    private static bool AtomicWriteChild(string name, ReadOnlySpan<byte> data, uint mode, bool replace = true)
    {
        EnsureDir();
        if (!OperatingSystem.IsMacOS())
        {
            string path = Path.Combine(Dir, name);
            if (!replace) return ServiceKeySelection.PublishExclusiveFile(path, data.ToArray());
            string temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(temporary, data.ToArray());
                try { File.Move(temporary, path, overwrite: replace); }
                catch (IOException) when (!replace && File.Exists(path)) { return false; }
                return true;
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
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
            if (!replace)
            {
                if (!ServiceKeySelection.PublishExclusiveMac(dirfd, temp, dirfd, name)) return false;
            }
            else if (renameat(dirfd, temp, dirfd, name) != 0)
            {
                int error = Marshal.GetLastPInvokeError();
                throw new InvalidOperationException($"Cannot publish service state file '{name}': errno {error}.");
            }
            _ = fsync(dirfd);
            return true;
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

    private static byte[] ServiceKey(bool allowCreate) => ServiceKeySelection.Get(
        () => { EnsureDir(); return ReadChild(".service.key", privateRead: true, maxBytes: 32); },
        bytes => AtomicWriteChild(".service.key", bytes, 0x180, replace: false), allowCreate);

    internal static byte[] EncodeProfile(VpnConfig cfg)
    {
        // Validate before touching the key or an existing daemon.
        ProfileStorePayload.Validate(cfg);
        return ServiceProfileCodec.Encode(cfg, () => ServiceKey(allowCreate: true));
    }
    internal static void PublishProfile(byte[] bytes)
    {
        if (bytes.Length > ServiceProfileCodec.MaximumBytes) throw new InvalidDataException("Daemon profile exceeds 4 MiB");
        AtomicWriteChild("service-profile.json", bytes, 0x180);
    }
    public static void SaveProfile(VpnConfig cfg) => PublishProfile(EncodeProfile(cfg));

    public static VpnConfig? LoadProfile()
    {
        var raw = ReadChild("service-profile.json", privateRead: true, maxBytes: ServiceProfileCodec.MaximumBytes);
        if (raw is null) return null; // Only absence means "no profile".
        var cfg = ServiceProfileCodec.Decode(raw, ServiceKey(allowCreate: false), out bool migrate);
        if (migrate) SaveProfile(cfg); // A migration write failure is observable.
        return cfg;
    }

    /// <summary>
    /// Persist the user's connection intent independently from whether the LaunchDaemon is
    /// installed. launchd may keep an installed daemon alive at boot, but an explicit
    /// Disconnect must survive that boot instead of silently reconnecting and reapplying DNS.
    /// Missing/corrupt state is fail-safe: the daemon stays idle until an explicit Start.
    /// </summary>
    public static void SetDesiredConnected(bool connected)
    {
        void Persist() => AtomicWriteChild("service-connect.enabled",
            Encoding.ASCII.GetBytes(connected ? "1\n" : "0\n"), 0x180);
        if (connected)
            ServiceStatusTransition.BeginStart(() => WriteStatusRequired(VpnStatus.Connecting, null), Persist);
        else Persist();
    }

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
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null, bool stopped = false)
    {
        try { WriteStatusRequired(status, extra, bytesUp, bytesDown, since, stopped); }
        catch { /* ignore */ }
    }

    internal static void WriteStatusRequired(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null, bool stopped = false)
    {
        EnsureDir();
        AtomicWriteChild("service-status.json", JsonSerializer.SerializeToUtf8Bytes(new ServiceStatus
        {
            Status = status.ToString(),
            Extra = extra is { Length: > 2048 } ? extra[..2048] : extra,
            Time = DateTime.Now,
            BytesUp = bytesUp,
            BytesDown = bytesDown,
            Since = since,
            Stopped = stopped,
        }), 0x1A4); // 0644
    }

    public static ServiceStatus? ReadStatus()
    {
        var raw = ReadChild("service-status.json", privateRead: false, maxBytes: 1024 * 1024);
        return raw is null ? null : DesktopServiceStatus.Decode<ServiceStatus>(raw);
    }
    public static string ReadLog()
    {
        var raw = ReadChild("service.log", privateRead: false, maxBytes: MaxLogBytes);
        return raw is null ? "" : new UTF8Encoding(false, true).GetString(raw);
    }
    internal static byte[] EncodeLogLine(string line, DateTime now)
    {
        if (line.Length > 16 * 1024)
        {
            int end = 16 * 1024;
            if (char.IsHighSurrogate(line[end - 1])) end--;
            line = line[..end] + " [truncated]";
        }
        return Encoding.UTF8.GetBytes($"{now:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}");
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
                var suffix = EncodeLogLine(line, DateTime.UtcNow);
                if (previous.LongLength > MaxLogBytes - suffix.Length) previous = Array.Empty<byte>();
                var combined = new byte[previous.Length + suffix.Length];
                Buffer.BlockCopy(previous, 0, combined, 0, previous.Length);
                Buffer.BlockCopy(suffix, 0, combined, previous.Length, suffix.Length);
                AtomicWriteChild("service.log", combined, 0x1A4); // 0644
            }
            catch { /* ignore */ }
        }
    }
}
