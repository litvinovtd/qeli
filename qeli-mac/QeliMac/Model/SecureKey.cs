using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace QeliMac.Model;

/// <summary>
/// Provides the 256-bit AES key used to encrypt the at-rest profile store
/// (<see cref="ProfileStore"/>). The key lives in the macOS login Keychain,
/// fetched via the `security` CLI (no Security.framework P/Invoke).
///
/// Keychain ACLs are tied to code-signing identity, so a properly Developer-ID
/// signed + notarized build (RELEASE-FIXES.md M3) gets seamless access; an
/// ad-hoc/dev build may be denied. If the Keychain is unavailable we fall back
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
        var k = KeychainFind() ?? FileFind();
        if (k is { Length: 32 }) return k;

        var key = RandomNumberGenerator.GetBytes(32);
        if (!KeychainStore(key)) FileStore(key); // Keychain first; file fallback
        return key;
    }

    // ── Keychain (preferred) ──────────────────────────────────────────────────
    private static byte[]? KeychainFind()
    {
        var (code, outp) = Run($"find-generic-password -s {Service} -a {Account} -w");
        if (code != 0 || outp.Length == 0) return null;
        try { return Convert.FromBase64String(outp.Trim()); }
        catch { return null; }
    }

    private static bool KeychainStore(byte[] key)
    {
        var b64 = Convert.ToBase64String(key);
        // -U updates if present. NB: the key is briefly visible in argv (`ps`); an
        // acceptable trade vs. permanent plaintext-on-disk for the profile secrets.
        var (code, _) = Run($"add-generic-password -s {Service} -a {Account} -w {b64} -U");
        return code == 0;
    }

    private static (int, string) Run(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/security", args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi)!;
            var outp = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit();
            return (p.ExitCode, outp);
        }
        catch { return (-1, ""); }
    }

    // ── 0600 key-file fallback (when the Keychain is unavailable) ──────────────
    private static byte[]? FileFind()
    {
        try { return File.Exists(FallbackKeyFile) ? File.ReadAllBytes(FallbackKeyFile) : null; }
        catch { return null; }
    }

    private static void FileStore(byte[] key)
    {
        try
        {
            Directory.CreateDirectory(Paths.UserDir);
            File.WriteAllBytes(FallbackKeyFile, key);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(FallbackKeyFile,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        catch { /* best effort */ }
    }
}
