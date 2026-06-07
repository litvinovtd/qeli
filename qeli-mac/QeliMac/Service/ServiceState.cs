using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QeliMac.Model;
using QeliMac.Vpn;

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

    public static void EnsureDir() => Directory.CreateDirectory(Dir);

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
            try
            {
                if (raw.Length < NonceLen + TagLen) throw new CryptographicException("too short");
                var key = ServiceKey();
                var nonce = raw.AsSpan(0, NonceLen);
                var tag = raw.AsSpan(NonceLen, TagLen);
                var ct = raw.AsSpan(NonceLen + TagLen);
                var pt = new byte[ct.Length];
                using var gcm = new AesGcm(key, TagLen);
                gcm.Decrypt(nonce, ct, tag, pt);
                json = Encoding.UTF8.GetString(pt);
            }
            catch
            {
                // Legacy plaintext profile (pre-E1) — read, then migrate to encrypted.
                json = Encoding.UTF8.GetString(raw);
                wasLegacyPlaintext = true;
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
                File.AppendAllText(LogFile, $"{DateTime.Now:HH:mm:ss}  {line}{Environment.NewLine}");
            }
            catch { /* ignore */ }
        }
    }
}
