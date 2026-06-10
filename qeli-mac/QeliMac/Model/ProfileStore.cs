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
        try
        {
            if (!File.Exists(FilePath)) return new List<VpnConfig>();
            var raw = File.ReadAllBytes(FilePath);
            string json;
            bool wasLegacyPlaintext = false;
            try
            {
                json = Decrypt(raw);
            }
            catch
            {
                // Legacy plaintext file written before E1 — read as-is, then migrate.
                json = Encoding.UTF8.GetString(raw);
                wasLegacyPlaintext = true;
            }
            var profiles = JsonSerializer.Deserialize<List<VpnConfig>>(json, Options) ?? new List<VpnConfig>();
            if (wasLegacyPlaintext) Save(profiles); // re-write encrypted
            return profiles;
        }
        catch { return new List<VpnConfig>(); }
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
        File.WriteAllBytes(FilePath, blob);
        if (!OperatingSystem.IsWindows())
            try { File.SetUnixFileMode(FilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
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
