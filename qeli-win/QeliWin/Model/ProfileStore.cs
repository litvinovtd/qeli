using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace QeliWin.Model;

/// <summary>Persists the profile list to %APPDATA%\QeliWin\profiles.json,
/// encrypted at rest with DPAPI (current-user scope) — profiles carry the server
/// password and obfs_key, so they must not sit in plaintext. A legacy plaintext
/// file (pre-E1) is read transparently and re-written encrypted on load.</summary>
public static class ProfileStore
{
    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "QeliWin");
    private static readonly string FilePath = Path.Combine(Dir, "profiles.json");

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static List<VpnConfig> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new List<VpnConfig>();
            var bytes = File.ReadAllBytes(FilePath);
            string json;
            bool wasLegacyPlaintext = false;
            try
            {
                // Encrypted-at-rest (DPAPI, current user).
                var plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
                json = Encoding.UTF8.GetString(plain);
            }
            catch
            {
                // Legacy plaintext file written before E1 — read as-is, then migrate.
                json = Encoding.UTF8.GetString(bytes);
                wasLegacyPlaintext = true;
            }
            var profiles = JsonSerializer.Deserialize<List<VpnConfig>>(json, Options) ?? new List<VpnConfig>();
            // Re-write encrypted immediately so plaintext secrets stop lingering on disk.
            if (wasLegacyPlaintext) Save(profiles);
            return profiles;
        }
        catch { return new List<VpnConfig>(); }
    }

    public static void Save(IEnumerable<VpnConfig> profiles)
    {
        Directory.CreateDirectory(Dir);
        var json = JsonSerializer.Serialize(profiles, Options);
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(FilePath, enc);
    }
}
