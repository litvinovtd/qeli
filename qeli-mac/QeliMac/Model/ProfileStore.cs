using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliMac.Model;

/// <summary>Persists the profile list to ~/Library/Application Support/Qeli/profiles.json,
/// encrypted at rest with AES-256-GCM. Profiles carry the server password and
/// obfs_key, so they must not sit in plaintext; the AES key comes from the macOS
/// Keychain (see <see cref="SecureKey"/>). A legacy plaintext file (pre-E1) is read
/// transparently and re-written encrypted. On-disk layout: [nonce:12][tag:16][ct].
/// See docs/RELEASE-FIXES.md E1.</summary>
public static class ProfileStore
{
    private static readonly string Dir = Paths.UserDir;
    private static readonly string FilePath = Path.Combine(Dir, "profiles.json");

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    private const int NonceLen = 12;
    private const int TagLen = 16;

    public static List<VpnConfig> Load()
    {
        // Absent file = normal first run. Only a PRESENT-but-unreadable file is dangerous.
        if (!File.Exists(FilePath)) return new List<VpnConfig>();
        try
        {
            var raw = File.ReadAllBytes(FilePath);
            string json;
            bool wasLegacyPlaintext = false;
            // Sniff the format instead of using "decrypt failed" as the legacy signal.
            //
            // `try { Decrypt } catch { treat as plaintext }` made a failed AES-GCM tag —
            // a detected forgery — indistinguishable from a genuine pre-E1 file, so anyone
            // able to write this file could replace the user's profiles (server address,
            // password, obfs_key) without holding the Keychain key, and the migration below
            // would then re-encrypt the forgery under the real one. A legacy file is JSON
            // and starts with '[' or '{'; a GCM blob starts with a random nonce.
            // Same defect and same fix as ServiceState.LoadProfile. (Audit 2026-08-04.)
            static bool LooksLikeLegacyJson(byte[] b)
            {
                int i = 0;
                if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) i = 3; // BOM
                while (i < b.Length && (b[i] == (byte)' ' || b[i] == (byte)'\t'
                                        || b[i] == (byte)'\r' || b[i] == (byte)'\n')) i++;
                return i < b.Length && (b[i] == (byte)'[' || b[i] == (byte)'{');
            }
            if (LooksLikeLegacyJson(raw))
            {
                json = Encoding.UTF8.GetString(raw);
                wasLegacyPlaintext = true;
            }
            else
            {
                // A tag failure throws out of here into the outer catch, which surfaces the
                // error rather than silently continuing with attacker-chosen profiles.
                json = Decrypt(raw);
            }
            var profiles = JsonSerializer.Deserialize<List<VpnConfig>>(json, Options) ?? new List<VpnConfig>();
            // Profiles saved before the stable-Id fix have no "Id" field; the deserializer
            // left each at a fresh-GUID default that would otherwise change on every load
            // (settings reference profiles by Id). Persist once to freeze those Ids.
            bool needsIdMigration = profiles.Count > 0 && !json.Contains("\"Id\":");
            if (wasLegacyPlaintext || needsIdMigration) Save(profiles); // re-write encrypted (and freeze Ids)
            return profiles;
        }
        catch (Exception ex)
        {
            // The file exists but couldn't be decrypted/parsed (e.g. Keychain key lost).
            // Do NOT silently return an empty list — the next Save would overwrite the
            // (possibly recoverable) file. Preserve it aside first, then start empty.
            try { File.Move(FilePath, FilePath + ".corrupt-" + DateTimeOffset.UtcNow.ToUnixTimeSeconds()); }
            catch { /* best effort */ }
            System.Diagnostics.Debug.WriteLine($"ProfileStore: profiles.json unreadable, preserved aside ({ex.Message})");
            return new List<VpnConfig>();
        }
    }

    public static void Save(IEnumerable<VpnConfig> profiles)
    {
        Directory.CreateDirectory(Dir);
        var key = SecureKey.GetOrCreate();
        var pt = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(profiles, Options));
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var ct = new byte[pt.Length];
        var tag = new byte[TagLen];
        using (var gcm = new AesGcm(key, TagLen))
            gcm.Encrypt(nonce, pt, ct, tag);

        var blob = new byte[NonceLen + TagLen + ct.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, NonceLen);
        Buffer.BlockCopy(tag, 0, blob, NonceLen, TagLen);
        Buffer.BlockCopy(ct, 0, blob, NonceLen + TagLen, ct.Length);
        // Atomic write (temp born 0600 + replace): a crash mid-write must not truncate the
        // only copy, and the secret ciphertext must never briefly be world-readable.
        var tmp = FilePath + ".tmp";
        File.WriteAllBytes(tmp, blob);
        if (!OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
        if (File.Exists(FilePath))
            File.Replace(tmp, FilePath, FilePath + ".bak");
        else
            File.Move(tmp, FilePath);
    }

    private static string Decrypt(byte[] blob)
    {
        if (blob.Length < NonceLen + TagLen) throw new CryptographicException("ciphertext too short");
        var key = SecureKey.GetOrCreate();
        var nonce = blob.AsSpan(0, NonceLen);
        var tag = blob.AsSpan(NonceLen, TagLen);
        var ct = blob.AsSpan(NonceLen + TagLen);
        var pt = new byte[ct.Length];
        using var gcm = new AesGcm(key, TagLen);
        gcm.Decrypt(nonce, ct, tag, pt);
        return Encoding.UTF8.GetString(pt);
    }
}
