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

    private static readonly WindowsProfileArchive Archive = new(FilePath);

    public static List<VpnConfig> Load() => Archive.Load();
    public static void Save(IEnumerable<VpnConfig> profiles) => Archive.Save(profiles);
}

// A path-scoped archive also lets selftest exercise real DPAPI without opening user profiles.
internal sealed class WindowsProfileArchive(string filePath)
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly ProfileStoreFile StoreFile = new(filePath);

    private static List<VpnConfig> Decode(byte[] stored, out bool needsMigration)
    {
        byte[]? plaintext = null;
        try
        {
            bool legacy = false;
            try { plaintext = ProtectedData.Unprotect(stored, null, DataProtectionScope.CurrentUser); }
            catch (CryptographicException)
            {
                // Only DPAPI failure selects legacy; bad decrypted UTF-8/JSON is corruption.
                plaintext = stored;
                legacy = true;
            }
            var profiles = ProfileStorePayload.Decode(StrictUtf8.GetString(plaintext), out bool ids, Options);
            needsMigration = legacy || ids;
            return profiles;
        }
        finally
        {
            if (plaintext != null && !ReferenceEquals(plaintext, stored))
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public List<VpnConfig> Load()
    {
        var stored = StoreFile.Read(); // I/O/size failure cannot be treated as an empty store.
        if (stored is null) return new List<VpnConfig>();
        List<VpnConfig> profiles;
        bool needsMigration;
        try
        {
            try { profiles = Decode(stored, out needsMigration); }
            catch (Exception error)
            {
                // Quarantine must succeed against the observed revision BEFORE recovery.
                // Never overwrite an unreadable latest generation, even if backup is valid.
                var preserved = StoreFile.PreserveUnreadable();
                System.Diagnostics.Debug.WriteLine($"ProfileStore: preserved {preserved} ({error.Message})");
                List<VpnConfig>? recovered = null;
                byte[]? backupBytes = null;
                try
                {
                    if (File.Exists(filePath + ".bak"))
                    {
                        backupBytes = ProfileStoreFile.ReadBounded(filePath + ".bak");
                        recovered = Decode(backupBytes, out _);
                    }
                }
                catch (Exception backupError)
                {
                    System.Diagnostics.Debug.WriteLine($"ProfileStore: .bak recovery failed ({backupError.Message})");
                }
                finally
                {
                    if (backupBytes != null) CryptographicOperations.ZeroMemory(backupBytes);
                }
                if (recovered is null) return new List<VpnConfig>();
                // A failed recovery write is fatal. Save's stale-revision guard still applies.
                Save(recovered);
                return recovered;
            }
        }
        finally { CryptographicOperations.ZeroMemory(stored); }

        // A failed migration write does not turn a readable source into corruption.
        if (needsMigration) Save(profiles);
        return profiles;
    }

    public void Save(IEnumerable<VpnConfig> profiles)
    {
        var plaintext = Encoding.UTF8.GetBytes(ProfileStorePayload.Encode(profiles, Options));
        try
        {
            var encrypted = ProtectedData.Protect(plaintext, null, DataProtectionScope.CurrentUser);
            StoreFile.Write(encrypted);
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
}
