using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

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
        // Absent file = normal first run. Only a PRESENT-but-unreadable file is dangerous.
        if (!File.Exists(FilePath)) return new List<VpnConfig>();
        try
        {
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
            // Profiles saved before the stable-Id fix have no "Id" field; the deserializer
            // left each at a fresh-GUID default that would otherwise change on every load
            // (settings reference profiles by Id). Persist once to freeze those Ids.
            bool needsIdMigration = profiles.Count > 0 && !json.Contains("\"Id\":");
            // Re-write encrypted immediately so plaintext secrets stop lingering on disk.
            if (wasLegacyPlaintext || needsIdMigration) Save(profiles);
            return profiles;
        }
        catch (Exception ex)
        {
            // The file exists but couldn't be decrypted/parsed. Do NOT silently return an
            // empty list — the next Save would overwrite the (possibly recoverable) file.
            // Preserve it aside first, then start empty.
            try { File.Move(FilePath, FilePath + ".corrupt-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds()); }
            catch { /* best effort */ }
            System.Diagnostics.Debug.WriteLine($"ProfileStore: profiles.json unreadable, preserved aside ({ex.Message})");
            return new List<VpnConfig>();
        }
    }

    public static void Save(IEnumerable<VpnConfig> profiles)
    {
        Directory.CreateDirectory(Dir);
        var json = JsonSerializer.Serialize(profiles, Options);
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.CurrentUser);
        // Atomic write: a crash mid-write must not truncate the only copy. `File.Replace`
        // swaps in the new file and keeps a one-generation `.bak` of the prior one.
        var tmp = FilePath + ".tmp";
        File.WriteAllBytes(tmp, enc);
        if (File.Exists(FilePath))
            File.Replace(tmp, FilePath, FilePath + ".bak");
        else
            File.Move(tmp, FilePath);
    }
}
