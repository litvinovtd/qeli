using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Qeli.Shared.Model;

/// <summary>Bounded, atomic storage for desktop application preferences.</summary>
public static class AppSettingsStore
{
    public const int MaximumBytes = 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static T Load<T>(string path, JsonSerializerOptions? options = null) where T : new()
    {
        try { return Read<T>(path, options); }
        catch (FileNotFoundException) { /* normal first run */ }
        catch (DirectoryNotFoundException) { /* normal first run */ }
        catch (Exception error)
        {
            Debug.WriteLine($"AppSettings: settings.json unreadable ({error.Message})");
            // If this move fails, opening defaults would allow a later Save to overwrite
            // the unreadable original. Stop instead, as for the profile store.
            var preserved = path + ".corrupt-" + Guid.NewGuid().ToString("N");
            try { File.Move(path, preserved); }
            catch (Exception moveError)
            {
                throw new IOException(
                    "Unreadable application settings could not be preserved.", moveError);
            }
            Debug.WriteLine($"AppSettings: preserved unreadable settings at {preserved}");
        }

        try
        {
            var backup = path + ".bak";
            if (!File.Exists(backup)) return new T();
            var settings = Read<T>(backup, options);
            Debug.WriteLine("AppSettings: recovered settings.json from .bak");
            return settings;
        }
        catch (Exception error)
        {
            Debug.WriteLine($"AppSettings: .bak recovery failed ({error.Message})");
            return new T();
        }
    }

    public static void Save<T>(T settings, string path, JsonSerializerOptions? options = null)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(settings, options);
        if (bytes.Length > MaximumBytes)
            throw new IOException("Application settings exceed 1 MiB.");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + $".tmp-{Environment.ProcessId}-{Guid.NewGuid():N}";
        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows())
                streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temp, streamOptions))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(path))
                File.Replace(temp, path, path + ".bak");
            else
                File.Move(temp, path);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private static T Read<T>(string path, JsonSerializerOptions? options)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > MaximumBytes)
            throw new IOException("Application settings exceed 1 MiB.");
        using var output = new MemoryStream((int)Math.Min(stream.Length, 64 * 1024));
        var buffer = new byte[64 * 1024];
        int count;
        while ((count = stream.Read(buffer)) != 0)
        {
            if (output.Length + count > MaximumBytes)
                throw new IOException("Application settings exceed 1 MiB.");
            output.Write(buffer, 0, count);
        }
        output.Position = 0;
        using var reader = new StreamReader(output, StrictUtf8, detectEncodingFromByteOrderMarks: true);
        return JsonSerializer.Deserialize<T>(reader.ReadToEnd(), options)
            ?? throw new JsonException("settings root is null");
    }
}
