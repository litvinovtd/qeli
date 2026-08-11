using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace QeliMac.Model;

/// <summary>
/// Provides the 256-bit AES key used to encrypt the at-rest profile store
/// (<see cref="ProfileStore"/>). The key lives in the macOS login Keychain,
/// accessed directly through Security.framework with an explicit ACL for the current code-signing
/// identity. A Developer-ID release therefore keeps access across upgrades while
/// unrelated processes cannot reuse `/usr/bin/security` as a trusted proxy. If
/// the Keychain is unavailable we fall back
/// to a local key file with 0600 permissions — still AES-encrypted at rest
/// (no plaintext password/obfs_key on disk), just with a weaker key store.
/// </summary>
public static class SecureKey
{
    private const string Service = "ru.qeli.mac";
    private const string Account = "profile-store-key";
    private static readonly string FallbackKeyFile = Path.Combine(Paths.UserDir, ".store.key");

    /// <summary>Returns the AES-256 key, creating and persisting it on first use.</summary>
    public static byte[] GetOrCreate()
    {
        var stored = MacKeychain.Find(Service, Account);
        var k = DecodeKeychainValue(stored);
        if (k is { Length: 32 })
        {
            // Pre-0.7.15 stored base64 text through /usr/bin/security. Replace that
            // item with raw bytes and a Qeli-specific ACL without rotating the key.
            if (stored!.Length != 32)
            {
                if (!LegacyKeychainDelete())
                    throw new InvalidOperationException("Cannot remove the legacy Keychain item before ACL migration");
                if (!MacKeychain.Store(Service, Account, k) && !FileStore(k))
                    throw new InvalidOperationException("Cannot migrate the profile key to the Qeli Keychain ACL");
            }
            return k;
        }

        // The old item's ACL trusted /usr/bin/security, so a direct application
        // lookup may be denied. Read it once through the legacy path, delete it,
        // and recreate it under the current application's designated requirement.
        k = LegacyKeychainFind();
        if (k is { Length: 32 })
        {
            if (!LegacyKeychainDelete())
                throw new InvalidOperationException("Cannot remove the legacy Keychain item before ACL migration");
            if (!MacKeychain.Store(Service, Account, k) && !FileStore(k))
                throw new InvalidOperationException("Cannot migrate the legacy profile key");
            return k;
        }

        k = FileFind();
        if (k is { Length: 32 }) return k;

        var key = RandomNumberGenerator.GetBytes(32);
        // FAIL LOUD if the key cannot be persisted anywhere. Returning an unsaved key was
        // silent data loss: the caller encrypts the profile store with it, and on the next
        // launch neither the Keychain nor the fallback file has it — every saved profile is
        // permanently undecryptable, with nothing having reported a problem. Better to
        // refuse to save than to write something that can never be read back. (C-19)
        if (!MacKeychain.Store(Service, Account, key) && !FileStore(key))
            throw new InvalidOperationException(
                "Cannot persist the profile-encryption key: the macOS Keychain rejected it " +
                $"and the fallback key file (\"{FallbackKeyFile}\") could not be written. " +
                "Saving profiles now would produce data that can never be decrypted. " +
                "Check the Keychain permissions for this app, or the permissions on " +
                $"\"{Paths.UserDir}\".");
        return key;
    }

    // ── Keychain (preferred) ──────────────────────────────────────────────────
    private static byte[]? DecodeKeychainValue(byte[]? value)
    {
        if (value is null) return null;
        if (value.Length == 32) return value;
        try { return Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(value).Trim()); }
        catch { return null; }
    }

    private static byte[]? LegacyKeychainFind()
    {
        var (code, output) = Run($"find-generic-password -s {Service} -a {Account} -w");
        if (code != 0 || output.Length == 0) return null;
        try { return Convert.FromBase64String(output.Trim()); }
        catch { return null; }
    }

    private static bool LegacyKeychainDelete()
    {
        var (code, _) = Run($"delete-generic-password -s {Service} -a {Account}");
        return code == 0;
    }

    private static (int, string) Run(string args, string? stdin = null)
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/security", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = stdin != null,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi)!;
            // Drain both pipes concurrently and bound the wait: reading stdout to EOF and
            // only then stderr deadlocks if `security` fills the stderr buffer first, and
            // an unbounded WaitForExit lets a Keychain prompt hang the app. (C-19/C-24)
            var so = p.StandardOutput.ReadToEndAsync();
            var se = p.StandardError.ReadToEndAsync();
            if (stdin != null)
            {
                p.StandardInput.Write(stdin);
                p.StandardInput.Close();
            }
            if (!p.WaitForExit(20_000))
            {
                try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
                return (-1, "");
            }
            _ = se.GetAwaiter().GetResult();
            return (p.ExitCode, so.GetAwaiter().GetResult());
        }
        catch { return (-1, ""); }
    }

    // ── 0600 key-file fallback (when the Keychain is unavailable) ──────────────
    private static byte[]? FileFind()
    {
        try { return File.Exists(FallbackKeyFile) ? File.ReadAllBytes(FallbackKeyFile) : null; }
        catch { return null; }
    }

    /// <summary>Persist to the 0600 fallback file. Returns false on any failure so the
    /// caller can refuse to hand out a key it could not save. (C-19)</summary>
    private static bool FileStore(byte[] key)
    {
        try
        {
            Directory.CreateDirectory(Paths.UserDir);
            // Create the file 0600 BEFORE the bytes land in it, rather than writing at the
            // default mode and narrowing afterwards — the key is readable by anyone during
            // that window otherwise.
            if (!OperatingSystem.IsWindows())
            {
                using var fs = new FileStream(FallbackKeyFile, FileMode.Create, FileAccess.Write);
                File.SetUnixFileMode(FallbackKeyFile,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
                fs.Write(key, 0, key.Length);
            }
            else
            {
                File.WriteAllBytes(FallbackKeyFile, key);
            }
            return true;
        }
        catch { return false; }
    }
}
