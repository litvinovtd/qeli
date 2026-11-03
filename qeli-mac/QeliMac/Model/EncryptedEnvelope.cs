using System.Security.Cryptography;
using System.Text;

namespace QeliMac.Model;

/// <summary>
/// Versioned authenticated envelope shared by the GUI and launchd profile stores.
/// The former layout started with a random nonce, so a valid ciphertext whose first
/// byte happened to be '[' or '{' was misclassified as legacy JSON.
/// </summary>
internal static class EncryptedEnvelope
{
    private static ReadOnlySpan<byte> Magic => "QELIENC\0"u8;
    private const byte Version = 1;
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private static int HeaderLen => Magic.Length + 1;

    internal static byte[] Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
    {
        var blob = new byte[HeaderLen + NonceLen + TagLen + plaintext.Length];
        Magic.CopyTo(blob);
        blob[Magic.Length] = Version;
        var nonce = blob.AsSpan(HeaderLen, NonceLen);
        RandomNumberGenerator.Fill(nonce);
        var tag = blob.AsSpan(HeaderLen + NonceLen, TagLen);
        var ciphertext = blob.AsSpan(HeaderLen + NonceLen + TagLen);
        using var gcm = new AesGcm(key, TagLen);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, blob.AsSpan(0, HeaderLen));
        return blob;
    }

    /// <summary>
    /// Opens the current envelope, then the pre-envelope authenticated layout, and only
    /// then accepts a genuine legacy JSON document. Trying old AES-GCM first is essential:
    /// its random nonce is allowed to begin with a JSON punctuation byte.
    /// </summary>
    internal static byte[] Open(
        ReadOnlySpan<byte> blob,
        ReadOnlySpan<byte> key,
        bool allowLegacyArray,
        out bool needsMigration,
        bool allowLegacyPlaintext = true)
    {
        if (HasMagic(blob))
        {
            needsMigration = false;
            if (blob.Length < HeaderLen + NonceLen + TagLen)
                throw new CryptographicException("encrypted envelope is truncated");
            if (blob[Magic.Length] != Version)
                throw new CryptographicException(
                    $"unsupported encrypted envelope version {blob[Magic.Length]}");
            return Decrypt(
                blob.Slice(HeaderLen, NonceLen),
                blob.Slice(HeaderLen + NonceLen, TagLen),
                blob[(HeaderLen + NonceLen + TagLen)..],
                key,
                blob[..HeaderLen]);
        }

        // Pre-0.8.1 authenticated layout: [nonce:12][tag:16][ciphertext]. This MUST
        // precede the JSON check because nonce[0] is random.
        if (blob.Length >= NonceLen + TagLen)
        {
            try
            {
                var plaintext = Decrypt(
                    blob[..NonceLen],
                    blob.Slice(NonceLen, TagLen),
                    blob[(NonceLen + TagLen)..],
                    key,
                    ReadOnlySpan<byte>.Empty);
                needsMigration = true;
                return plaintext;
            }
            catch (CryptographicException) when (allowLegacyPlaintext && LooksLikeLegacyJson(blob, allowLegacyArray))
            {
                // A pre-encryption JSON store. The caller performs strict model parsing
                // before it is ever used and immediately rewrites it in the current format.
            }
        }
        else if (!allowLegacyPlaintext || !LooksLikeLegacyJson(blob, allowLegacyArray))
        {
            throw new CryptographicException("data is neither JSON nor a complete encrypted envelope");
        }

        needsMigration = true;
        return blob.ToArray();
    }

    private static bool HasMagic(ReadOnlySpan<byte> blob) =>
        blob.Length >= Magic.Length && blob[..Magic.Length].SequenceEqual(Magic);

    private static bool LooksLikeLegacyJson(ReadOnlySpan<byte> bytes, bool allowArray)
    {
        ReadOnlySpan<byte> utf8Bom = new byte[] { 0xEF, 0xBB, 0xBF };
        int index = bytes.StartsWith(utf8Bom) ? 3 : 0;
        while (index < bytes.Length && bytes[index] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            index++;
        return index < bytes.Length
            && (bytes[index] == (byte)'{' || (allowArray && bytes[index] == (byte)'['));
    }

    private static byte[] Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData)
    {
        var plaintext = new byte[ciphertext.Length];
        using var gcm = new AesGcm(key, TagLen);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    internal static void RunSelfTests(Action<string, bool> check)
    {
        var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
        var json = Encoding.UTF8.GetBytes("[{\"Name\":\"test\"}]");
        var current = Seal(json, key);
        var opened = Open(current, key, true, out var migrated);
        check("encrypted envelope: versioned round-trip", !migrated && opened.SequenceEqual(json));

        // Deterministically reproduce the old 2/256 collision instead of waiting for RNG.
        var nonce = new byte[NonceLen];
        nonce[0] = (byte)'[';
        var tag = new byte[TagLen];
        var ciphertext = new byte[json.Length];
        using (var gcm = new AesGcm(key, TagLen))
            gcm.Encrypt(nonce, json, ciphertext, tag);
        var legacy = nonce.Concat(tag).Concat(ciphertext).ToArray();
        opened = Open(legacy, key, true, out migrated);
        check("encrypted envelope: nonce punctuation stays ciphertext",
            migrated && opened.SequenceEqual(json));

        var wrongVersion = current.ToArray();
        wrongVersion[Magic.Length]++;
        bool rejected = false;
        try { _ = Open(wrongVersion, key, true, out _); }
        catch (CryptographicException) { rejected = true; }
        check("encrypted envelope: unknown version fails closed", rejected);
    }
}
