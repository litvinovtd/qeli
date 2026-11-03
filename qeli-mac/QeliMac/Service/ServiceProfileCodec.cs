using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;
using QeliMac.Model;

namespace QeliMac.Service;

internal static class ServiceProfileCodec
{
    internal const int MaximumBytes = 4 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    internal static byte[] Plaintext(VpnConfig profile)
    {
        ProfileStorePayload.Validate(profile);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(profile);
        if (bytes.Length > MaximumBytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("Daemon profile exceeds 4 MiB");
        }
        return bytes;
    }
    internal static VpnConfig DecodePlaintext(byte[] bytes)
    {
        if (bytes.Length > MaximumBytes) throw new InvalidDataException("Daemon profile exceeds 4 MiB");
        var profile = JsonSerializer.Deserialize<VpnConfig>(StrictUtf8.GetString(bytes))
            ?? throw new InvalidDataException("Daemon profile is empty");
        ProfileStorePayload.Validate(profile);
        return profile;
    }
    internal static VpnConfig Handoff(byte[] bytes, byte[] expectedDigest)
    {
        if (expectedDigest.Length != SHA256.HashSizeInBytes
            || !CryptographicOperations.FixedTimeEquals(expectedDigest, SHA256.HashData(bytes)))
            throw new InvalidDataException("daemon-install: profile changed after authorization was requested; retry the operation");
        return DecodePlaintext(bytes);
    }
    internal static byte[] Encode(VpnConfig profile, byte[] key) => Encode(profile, () => key);
    internal static byte[] Encode(VpnConfig profile, Func<byte[]> keyProvider)
    {
        var bytes = Plaintext(profile);
        try
        {
            // Envelope overhead is 9-byte header, 12-byte nonce and 16-byte tag.
            if (bytes.Length > MaximumBytes - 37) throw new InvalidDataException("Encrypted daemon profile exceeds 4 MiB");
            var encrypted = EncryptedEnvelope.Seal(bytes, keyProvider());
            if (encrypted.Length > MaximumBytes) throw new InvalidDataException("Encrypted daemon profile exceeds 4 MiB");
            return encrypted;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static VpnConfig Decode(byte[] encrypted, byte[] key, out bool migrate)
    {
        if (encrypted.Length > MaximumBytes) throw new InvalidDataException("Encrypted daemon profile exceeds 4 MiB");
        var bytes = EncryptedEnvelope.Open(encrypted, key, false, out migrate, allowLegacyPlaintext: false);
        try { return DecodePlaintext(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}

internal static class ServiceKeySelection
{
    [DllImport("libc", EntryPoint = "renameatx_np", SetLastError = true)]
    private static extern int RenameExclusive(int oldDirectory, string oldPath, int newDirectory, string newPath, uint flags);
    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string source, string destination);

    internal static bool PublishExclusiveMac(int oldDirectory, string oldPath, int newDirectory, string newPath)
    {
        // Darwin RENAME_EXCL, also used by the daemon's validated directory handles.
        if (RenameExclusive(oldDirectory, oldPath, newDirectory, newPath, 0x4) == 0) return true;
        int error = Marshal.GetLastPInvokeError();
        if (error == 17) return false; // EEXIST, including a dangling symlink.
        throw new IOException($"Cannot publish service key: errno {error}.");
    }

    internal static bool PublishExclusiveFile(string path, byte[] bytes)
    {
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temp, options)) { stream.Write(bytes); stream.Flush(flushToDisk: true); }
            if (OperatingSystem.IsMacOS())
                return PublishExclusiveMac(-2, temp, -2, path); // Darwin AT_FDCWD.
            if (OperatingSystem.IsWindows())
            {
                try { File.Move(temp, path, overwrite: false); }
                catch (IOException) when (File.Exists(path)) { return false; }
                return true;
            }
            // Unix File.Move(false) may use a check followed by an overwriting rename.
            // Link the complete private file atomically; unsupported filesystems fail closed.
            if (Link(temp, path) == 0) return true;
            int error = Marshal.GetLastPInvokeError();
            if (error == 17) return false;
            throw new IOException($"Cannot publish service key: errno {error}.");
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    // Publish must atomically refuse replacement, then read the actual winning key.
    internal static byte[] Get(Func<byte[]?> read, Func<byte[], bool> publishExclusive, bool allowCreate)
    {
        var key = read();
        if (key is null)
        {
            if (!allowCreate) throw new CryptographicException("Daemon service key is missing; re-save the profile from the GUI");
            _ = publishExclusive(RandomNumberGenerator.GetBytes(32));
            key = read();
        }
        if (key is not { Length: 32 })
            throw new CryptographicException("Daemon service key is missing or corrupt; refusing to replace it");
        return key;
    }
}
