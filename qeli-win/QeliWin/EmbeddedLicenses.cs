using System.IO;
using System.IO.Compression;
using System.Reflection;

namespace QeliWin;

/// <summary>Original legal resources, accessible without loading the VPN or its configuration.</summary>
internal static class EmbeddedLicenses
{
    private const string Prefix = "Qeli.Legal/";
    private static readonly Assembly Source = typeof(EmbeddedLicenses).Assembly;
    private static readonly IReadOnlyDictionary<string, string> Resources = Source.GetManifestResourceNames()
        .Where(name => name.StartsWith(Prefix, StringComparison.Ordinal))
        .ToDictionary(name => name[Prefix.Length..].Replace('\\', '/'), name => name, StringComparer.Ordinal);
    internal static IReadOnlyList<string> Names { get; } = Resources.Keys.Order(StringComparer.Ordinal).ToArray();

    internal static byte[] Read(string name)
    {
        if (!Resources.TryGetValue(name, out var resource)) throw new FileNotFoundException("Unknown license resource; use licenses --list", name);
        using var input = Source.GetManifestResourceStream(resource) ?? throw new IOException("Embedded license stream missing");
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }

    internal static void ExportDirectory(string directory)
    {
        var final = Path.GetFullPath(directory);
        if (Directory.Exists(final) || File.Exists(final)) throw new IOException("Export destination already exists; nothing was overwritten");
        var parent = Path.GetDirectoryName(final) ?? throw new IOException("Export destination has no parent");
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("Export parent directory does not exist");
        // Unique staging + non-overwriting rename avoids accepting an existing destination.
        var staging = Path.Combine(parent, ".qeli-licenses-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);
        foreach (var name in Names)
        {
            ValidateName(name);
            var file = Path.Combine(staging, name.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            using var output = new FileStream(file, FileMode.CreateNew, FileAccess.Write);
            output.Write(Read(name));
        }
        Directory.Move(staging, final);
    }

    internal static void WriteZip(Stream output)
    {
        using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        foreach (var name in Names)
        {
            ValidateName(name);
            var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
            entry.LastWriteTime = new DateTimeOffset(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
            using var target = entry.Open();
            target.Write(Read(name));
        }
    }

    private static void ValidateName(string name)
    {
        if (Path.IsPathRooted(name) || name.Contains(':') || name.Contains('\\') ||
            name.Split('/').Any(part => part.Length == 0 || part is "." or ".."))
            throw new InvalidDataException("Unsafe embedded license resource name");
    }

    internal static int Run(string[] arguments)
    {
        try
        {
            if (Names.Count == 0) throw new InvalidDataException("This build has no embedded legal resources");
            if (arguments.Length == 0)
            {
                Console.WriteLine($"Qeli: {Names.Count} embedded original license/notice/index resources");
                Console.WriteLine("Source: https://github.com/litvinovtd/qeli");
                Console.WriteLine("licenses --list | --file PATH | --export NEW_DIRECTORY");
                Console.WriteLine("Core license: rust/Qeli-AGPL-3.0.txt; client license: Qeli-MPL-2.0.txt");
                return 0;
            }
            if (arguments.SequenceEqual(new[] { "--list" }))
            {
                foreach (var name in Names) Console.WriteLine(name);
                return 0;
            }
            if (arguments.Length == 2 && arguments[0] == "--file")
            {
                using var output = Console.OpenStandardOutput();
                output.Write(Read(arguments[1]));
                return 0;
            }
            if (arguments.Length == 2 && arguments[0] == "--export")
            {
                ExportDirectory(arguments[1]);
                Console.WriteLine($"Exported {Names.Count} original resources to {Path.GetFullPath(arguments[1])}");
                return 0;
            }
            Console.Error.WriteLine("Usage: licenses [--list | --file PATH | --export NEW_DIRECTORY]");
            return 2;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"License inspection failed: {error.Message}");
            return 1;
        }
    }
}
