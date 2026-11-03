using System.IO;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliMac.Model;

/// <summary>Persists the profile list to ~/Library/Application Support/Qeli/profiles.json,
/// encrypted at rest with AES-256-GCM. Profiles carry the server password and
/// obfs_key, so they must not sit in plaintext; the AES key comes from the macOS
/// Keychain (see <see cref="SecureKey"/>). A legacy plaintext file (pre-E1) is read
/// transparently and re-written into a versioned authenticated envelope.
/// See docs/*/archive/plans/RELEASE-FIXES.md E1.</summary>
public static class ProfileStore
{
    private static readonly MacProfileArchive Archive = new(
        Path.Combine(Paths.UserDir, "profiles.json"), SecureKey.GetOrCreate);

    public static List<VpnConfig> Load() => Archive.Load();
    public static void Save(IEnumerable<VpnConfig> profiles) => Archive.Save(profiles);
}

// Uses production encryption/parsing/atomic writes with a path-scoped key provider.
internal sealed class MacProfileArchive(string filePath, Func<byte[]> getKey)
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly ProfileStoreFile StoreFile = new(filePath);

    public List<VpnConfig> Load()
    {
        // Absent file = normal first run. Only a PRESENT-but-unreadable file is dangerous.
        var stored = StoreFile.Read();
        if (stored is null) return new List<VpnConfig>();
        // Keychain/permission failures are not damaged profile bytes. Do not quarantine.
        var key = getKey();
        List<VpnConfig> profiles;
        bool needsMigration;
        try
        {
            var raw = stored;
            var plaintext = EncryptedEnvelope.Open(
                raw, key, allowLegacyArray: true, out bool needsEnvelopeMigration);
            try
            {
                profiles = ProfileStorePayload.Decode(StrictUtf8.GetString(plaintext), out bool needsIdMigration, Options);
                needsMigration = needsEnvelopeMigration || needsIdMigration;
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext); }
        }
        catch (Exception ex)
        {
            // Keep the unreadable original before attempting .bak recovery. Failure to
            // preserve it must stop loading, rather than allow a later Save to overwrite it.
            var preserved = StoreFile.PreserveUnreadable();
            System.Diagnostics.Debug.WriteLine(
                $"ProfileStore: profiles.json unreadable, preserved at {preserved} ({ex.Message})");

            // File.Replace keeps one last authenticated generation. Recover it automatically
            // instead of opening with an empty profile list after a torn/corrupt latest write.
            List<VpnConfig>? recovered = null;
            try
            {
                var backup = filePath + ".bak";
                if (File.Exists(backup))
                {
                    var plaintext = EncryptedEnvelope.Open(
                        ProfileStoreFile.ReadBounded(backup), key, true, out _);
                    try { recovered = ProfileStorePayload.Decode(StrictUtf8.GetString(plaintext), Options); }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext); }
                }
            }
            catch (Exception backupError)
            {
                System.Diagnostics.Debug.WriteLine($"ProfileStore: .bak recovery failed ({backupError.Message})");
            }
            if (recovered is null) return new List<VpnConfig>();

            // A write failure must propagate instead of hiding the successfully read backup.
            Save(recovered);
            System.Diagnostics.Debug.WriteLine("ProfileStore: restored profiles from authenticated .bak");
            return recovered;
        }

        // Do not quarantine a readable store if only its migration write fails.
        if (needsMigration) Save(profiles);
        return profiles;
    }

    public void Save(IEnumerable<VpnConfig> profiles)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filePath)!);
        var key = getKey();
        var pt = Encoding.UTF8.GetBytes(ProfileStorePayload.Encode(profiles, Options));
        try { StoreFile.Write(EncryptedEnvelope.Seal(pt, key)); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(pt); }
    }
}
