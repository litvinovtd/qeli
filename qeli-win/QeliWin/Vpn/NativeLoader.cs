using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Resolves the native libraries embedded in the executable (WireGuard's
/// <c>wintun.dll</c> TUN driver and <c>qeli.dll</c>, the Rust realtls FFI core),
/// so the app ships as a single exe with no loose DLLs. Each is extracted once to
/// %LOCALAPPDATA%\QeliWin\native and loaded from there; a module initializer
/// registers the resolver before any P/Invoke runs.
/// </summary>
internal static class NativeLoader
{
    // Native libs embedded as resources, by the name used in P/Invoke (lowercase).
    private static readonly string[] Embedded = { "wintun.dll", "qeli.dll" };

    private static readonly Dictionary<string, string> _extracted = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _lock = new();

    [ModuleInitializer]
    internal static void Init()
    {
        NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        // DllImport may pass "qeli" or "qeli.dll"; normalise to the file name.
        var name = libraryName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? libraryName : libraryName + ".dll";
        if (!Embedded.Contains(name, StringComparer.OrdinalIgnoreCase))
            return IntPtr.Zero; // not ours — fall back to default resolution

        var path = EnsureExtracted(name);
        return path != null ? NativeLibrary.Load(path) : IntPtr.Zero;
    }

    private static string? EnsureExtracted(string dllName)
    {
        lock (_lock)
        {
            if (_extracted.TryGetValue(dllName, out var cached) && File.Exists(cached)) return cached;

            var asm = typeof(NativeLoader).Assembly;
            var resName = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith(dllName, StringComparison.OrdinalIgnoreCase));
            if (resName == null) return null;

            using var src = asm.GetManifestResourceStream(resName);
            if (src == null) return null;

            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QeliWin", "native");
            Directory.CreateDirectory(dir);
            var outPath = Path.Combine(dir, dllName);

            // Rewrite only if missing or the size differs (cheap version check); if an
            // older copy is locked by a running session, reuse it instead of failing.
            bool needWrite = !File.Exists(outPath) || new FileInfo(outPath).Length != src.Length;
            if (needWrite)
            {
                try
                {
                    using var dst = File.Create(outPath);
                    src.CopyTo(dst);
                }
                catch (IOException) when (File.Exists(outPath))
                {
                    // In use by another instance — fall back to the existing file.
                }
            }

            _extracted[dllName] = outPath;
            return outPath;
        }
    }
}
