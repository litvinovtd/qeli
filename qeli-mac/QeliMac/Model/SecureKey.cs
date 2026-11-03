using System.Diagnostics;

namespace QeliMac.Model;

/// <summary>
/// Provides the 256-bit AES key used to encrypt the at-rest profile store
/// (<see cref="ProfileStore"/>). The key lives in the macOS login Keychain,
/// accessed directly through Security.framework with an explicit ACL for the current code-signing
/// identity. A Developer-ID release therefore keeps access across upgrades while
/// unrelated processes cannot reuse `/usr/bin/security` as a trusted proxy. If
/// the Keychain is unavailable we can use an existing local key file with 0600 permissions — still AES-encrypted at rest
/// (no plaintext password/obfs_key on disk), just with a weaker key store.
/// </summary>
public static class SecureKey
{
    private const string Service = "ru.qeli.mac";
    private const string Account = "profile-store-key";
    private static readonly ProfileKeyCoordinator Keys = new(Paths.UserDir,
        () => MacKeychain.Find(Service, Account),
        (key, allowUpdate) => MacKeychain.Store(Service, Account, key, allowUpdate),
        LegacyKeychainFind, LegacyKeychainDelete);

    public static byte[] GetOrCreate() => Keys.GetOrCreate();

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

    private static (int, string) Run(string args)
    {
        try
        {
            var result = ToolProcess.Run(new ProcessStartInfo("/usr/bin/security", args));
            return (result.ExitCode, result.Output);
        }
        catch { return (-1, ""); }
    }
}
