using System.IO;
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

    private static readonly object _logLock = new();
    private const long MaxLogBytes = 256 * 1024;

    [DllImport("libc")] private static extern uint geteuid();
    [DllImport("libc", EntryPoint = "lstat$INODE64", SetLastError = true)]
    private static extern int lstat_inode64(string path, byte[] buf);
    [DllImport("libc", EntryPoint = "lstat", SetLastError = true)]
    private static extern int lstat_plain(string path, byte[] buf);

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
        var buf = new byte[256];   // comfortably larger than struct stat (144 bytes)
        int rc = RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? lstat_inode64(Dir, buf)
            : lstat_plain(Dir, buf);
        if (rc != 0)
            throw new InvalidOperationException(
                $"Cannot inspect \"{Dir}\": errno {Marshal.GetLastPInvokeError()}.");

        // struct stat (macOS): st_mode at offset 8 (u16), st_uid at 16 (u32).
        int mode = BitConverter.ToUInt16(buf, 8);
        uint uid = BitConverter.ToUInt32(buf, 16);
        const int SIfmt = 0xF000, SIfdir = 0x4000;

        if ((mode & SIfmt) != SIfdir)
            throw new InvalidOperationException(
                $"Refusing to use \"{Dir}\": it is not a directory (possibly a symlink). " +
                "Remove it and reinstall the service.");
        if (uid != 0 || (mode & 0b000_010_010) != 0)
            throw new InvalidOperationException(
                $"Refusing to use \"{Dir}\": it must be owned by root and writable only by " +
                $"root (found uid={uid}, mode={Convert.ToString(mode & 0x1FF, 8)}). Anyone " +
                "able to write there could make the root daemon load a profile, or a signing " +
                "key, of their choosing at boot." + Environment.NewLine + Environment.NewLine +
                $"Fix with: sudo rm -rf \"{Dir}\" and reinstall the service.");
    }

    // The daemon profile carries the server password / obfs_key, so it is encrypted at
    // rest with AES-256-GCM (mirrors qeli-win's DPAPI-LocalMachine ServiceState, E1).
    // Both writer (GUI as root) and reader (daemon as root) live in the system domain,
    // so the key is a root-only 0600 file in the shared dir (not the per-user Keychain).
    // On-disk layout: [nonce:12][tag:16][ciphertext]. Legacy plaintext is migrated.
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private static string KeyFile => Path.Combine(Dir, ".service.key");

    private static byte[] ServiceKey()
    {
        try
        {
            if (File.Exists(KeyFile))
            {
                var k = File.ReadAllBytes(KeyFile);
                if (k.Length == 32) return k;
            }
        }
        catch { /* regenerate below */ }
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            EnsureDir();
            File.WriteAllBytes(KeyFile, key);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(KeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch { /* best effort */ }
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
        File.WriteAllBytes(ProfileFile, blob);
        if (!OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(ProfileFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
    }

    public static VpnConfig? LoadProfile()
    {
        try
        {
            if (!File.Exists(ProfileFile)) return null;
            var raw = File.ReadAllBytes(ProfileFile);
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

    public static void WriteStatus(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null)
    {
        try
        {
            EnsureDir();
            File.WriteAllText(StatusFile, JsonSerializer.Serialize(new ServiceStatus
            {
                Status = status.ToString(), Extra = extra, Time = DateTime.Now,
                BytesUp = bytesUp, BytesDown = bytesDown, Since = since,
            }));
        }
        catch { /* ignore */ }
    }

    public static ServiceStatus? ReadStatus()
    {
        try
        {
            return File.Exists(StatusFile)
                ? JsonSerializer.Deserialize<ServiceStatus>(File.ReadAllText(StatusFile))
                : null;
        }
        catch { return null; }
    }

    public static void ResetLog()
    {
        try { EnsureDir(); File.WriteAllText(LogFile, ""); } catch { }
    }

    public static void AppendLog(string line)
    {
        lock (_logLock)
        {
            try
            {
                EnsureDir();
                if (File.Exists(LogFile) && new FileInfo(LogFile).Length > MaxLogBytes)
                    File.WriteAllText(LogFile, "");
                File.AppendAllText(LogFile, $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}");
            }
            catch { /* ignore */ }
        }
    }
}
