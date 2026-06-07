using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QeliWin.Model;
using QeliWin.Vpn;

namespace QeliWin.Service;

/// <summary>Status snapshot the service writes and the GUI polls.</summary>
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
/// Shared state between the Windows Service (writer) and the GUI (reader), stored under
/// %ProgramData%\QeliWin so LocalSystem can write and any user can read.
/// </summary>
public static class ServiceState
{
    public static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "QeliWin");
    public static string ProfileFile => Path.Combine(Dir, "service-profile.json");
    public static string StatusFile => Path.Combine(Dir, "service-status.json");
    public static string LogFile => Path.Combine(Dir, "service.log");

    private static readonly object _logLock = new();
    private const long MaxLogBytes = 256 * 1024;

    public static void EnsureDir() => Directory.CreateDirectory(Dir);

    public static void SaveProfile(VpnConfig cfg)
    {
        EnsureDir();
        // Encrypt at rest with DPAPI LocalMachine scope: the GUI (current user) writes
        // it and the service (LocalSystem) reads it, so a cross-user scope is required.
        // This removes the trivial plaintext exposure of the password/obfs_key (a
        // copied file / backup / forensic image / casual `type` no longer reveals
        // them). See docs/RELEASE-FIXES.md E1.
        var json = JsonSerializer.Serialize(cfg);
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(ProfileFile, enc);
    }

    public static VpnConfig? LoadProfile()
    {
        try
        {
            if (!File.Exists(ProfileFile)) return null;
            var bytes = File.ReadAllBytes(ProfileFile);
            string json;
            bool wasLegacyPlaintext = false;
            try
            {
                var plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine);
                json = Encoding.UTF8.GetString(plain);
            }
            catch
            {
                // Legacy plaintext profile (pre-E1) — read, then migrate to encrypted.
                json = Encoding.UTF8.GetString(bytes);
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
