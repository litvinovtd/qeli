using System.Diagnostics;
using System.Security.Cryptography;

namespace Qeli.Shared.Model;

/// <summary>
/// Coordinates one local profile store across app instances. A write is allowed only
/// against the exact bytes observed by the preceding load or successful write.
/// </summary>
public sealed class ProfileStoreFile(string path)
{
    // Allows more than the mobile 8 MiB plaintext archive while bounding corrupt input.
    public const int MaximumStoredBytes = 16 * 1024 * 1024;
    private readonly object _gate = new();
    private byte[]? _expectedHash;
    private bool _observed;

    public byte[]? Read()
    {
        lock (_gate)
        {
            using var fileLock = AcquireLock();
            var bytes = File.Exists(path) ? ReadBounded(path) : null;
            Remember(bytes);
            return bytes;
        }
    }

    public string PreserveUnreadable()
    {
        lock (_gate)
        {
            using var fileLock = AcquireLock();
            AssertUnchanged();
            var preserved = ProfileStoreRecovery.PreserveUnreadable(path);
            Remember(null);
            return preserved;
        }
    }

    public void Write(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length > MaximumStoredBytes)
            throw new IOException("The profile store exceeds 16 MiB.");
        lock (_gate)
        {
            using var fileLock = AcquireLock();
            AssertUnchanged();
            var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                var options = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                };
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                using (var stream = new FileStream(temporary, options))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }

                if (File.Exists(path))
                    File.Replace(temporary, path, path + ".bak");
                else
                    File.Move(temporary, path);
                Remember(bytes);
            }
            finally
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
        }
    }

    private FileStream AcquireLock()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var wait = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                return new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (wait.Elapsed < TimeSpan.FromSeconds(1))
            {
                // Another Qeli instance may hold the sidecar for a short read or write.
                // Keep the wait bounded so a wedged owner cannot freeze the UI.
                Thread.Sleep(25);
            }
        }
    }

    private void AssertUnchanged()
    {
        if (!_observed)
            throw new IOException("Load the profile store before saving it.");
        var currentHash = File.Exists(path) ? SHA256.HashData(ReadBounded(path)) : null;
        if ((_expectedHash is null) != (currentHash is null)
            || (_expectedHash is not null && currentHash is not null
                && !CryptographicOperations.FixedTimeEquals(_expectedHash, currentHash)))
            throw new IOException("The profile store changed in another app instance. Reopen Qeli before saving.");
    }

    /// <summary>Read a single snapshot with a budget, including if the file grows during I/O.</summary>
    public static byte[] ReadBounded(string filePath)
    {
        using var input = File.OpenRead(filePath);
        if (input.Length > MaximumStoredBytes)
            throw new IOException("The profile store exceeds 16 MiB.");
        using var output = new MemoryStream((int)Math.Min(input.Length, 64 * 1024));
        var buffer = new byte[64 * 1024];
        int read;
        while ((read = input.Read(buffer)) != 0)
        {
            if (output.Length + read > MaximumStoredBytes)
                throw new IOException("The profile store exceeds 16 MiB.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private void Remember(byte[]? bytes)
    {
        _expectedHash = bytes is null ? null : SHA256.HashData(bytes);
        _observed = true;
    }
}
