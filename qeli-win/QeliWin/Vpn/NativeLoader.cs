using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Resolves the native libraries embedded in the executable (WireGuard's
/// <c>wintun.dll</c> TUN driver, <c>qeli.dll</c> the Rust realtls FFI core, and
/// WinDivert for per-app split tunnelling), so the app ships as a single exe with no
/// loose DLLs. Each is extracted once to %LOCALAPPDATA%\QeliWin\native and loaded from
/// there; a module initializer registers the resolver before any P/Invoke runs.
/// </summary>
internal static class NativeLoader
{
    // Native libs embedded as resources, by the name used in P/Invoke (lowercase).
    // WinDivert.dll is case-sensitive in some loaders — LogicalName keeps the canonical casing.
    private static readonly string[] Embedded = { "wintun.dll", "qeli.dll", "WinDivert.dll" };

    private static readonly Dictionary<string, string> _extracted = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _lock = new();

    [ModuleInitializer]
    internal static void Init()
    {
        // wintun.dll / WinDivert.dll are P/Invoked from this (QeliWin) assembly…
        NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);
        // …but qeli.dll (the realtls FFI) is P/Invoked from the shared assembly
        // (Qeli.Shared.Vpn.RealTls). SetDllImportResolver is per-assembly, so the
        // resolver must be registered there too or reality-tls connects fail with
        // "Unable to load DLL 'qeli'" (the single-file exe has no loose qeli.dll).
        NativeLibrary.SetDllImportResolver(typeof(Qeli.Shared.Vpn.RealTls).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        // DllImport may pass "qeli" or "qeli.dll"; normalise to the file name.
        var name = libraryName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? libraryName : libraryName + ".dll";
        if (!Embedded.Contains(name, StringComparer.OrdinalIgnoreCase))
            return IntPtr.Zero; // not ours — fall back to default resolution

        // WinDivert also needs WinDivert64.sys beside the DLL before LoadLibrary.
        if (name.Equals("WinDivert.dll", StringComparison.OrdinalIgnoreCase))
        {
            var dir = EnsureWinDivertDir();
            if (dir == null) return IntPtr.Zero;
            return NativeLibrary.Load(Path.Combine(dir, "WinDivert.dll"));
        }

        var path = EnsureExtracted(name);
        return path != null ? NativeLibrary.Load(path) : IntPtr.Zero;
    }

    /// <summary>Extract WinDivert.dll + WinDivert64.sys into the native dir and return that
    /// directory. The driver must sit next to the DLL for WinDivertOpen to load it.</summary>
    internal static string? EnsureWinDivertDir()
    {
        lock (_lock)
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QeliWin", "native");
            Directory.CreateDirectory(dir);
            if (EnsureExtractedTo(dir, "WinDivert.dll") == null) return null;
            if (EnsureExtractedTo(dir, "WinDivert64.sys") == null) return null;
            return dir;
        }
    }

    private static string? EnsureExtracted(string dllName)
    {
        lock (_lock)
        {
            if (_extracted.TryGetValue(dllName, out var cached) && File.Exists(cached)) return cached;

            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QeliWin", "native");
            Directory.CreateDirectory(dir);
            return EnsureExtractedTo(dir, dllName);
        }
    }

    private static string? EnsureExtractedTo(string dir, string fileName)
    {
        if (_extracted.TryGetValue(fileName, out var cached) && File.Exists(cached)) return cached;

        var asm = typeof(NativeLoader).Assembly;
        var resName = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(fileName, StringComparison.OrdinalIgnoreCase));
        if (resName == null) return null;

        using var src = asm.GetManifestResourceStream(resName);
        if (src == null) return null;

        var outPath = Path.Combine(dir, fileName);

        using var mem = new MemoryStream();
        src.CopyTo(mem);
        var want = mem.ToArray();
        var wantHash = System.Security.Cryptography.SHA256.HashData(want);

        bool reuse = false;
        if (File.Exists(outPath))
        {
            try
            {
                var have = File.ReadAllBytes(outPath);
                reuse = System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Security.Cryptography.SHA256.HashData(have), wantHash);
            }
            catch { reuse = false; }
        }

        if (!reuse)
        {
            var tmp = outPath + "." + Environment.ProcessId + ".tmp";
            try
            {
                File.WriteAllBytes(tmp, want);
                File.Move(tmp, outPath, overwrite: true);
            }
            catch (IOException)
            {
                try { File.Delete(tmp); } catch { }
                if (!reuse) return null;
            }
            catch
            {
                try { File.Delete(tmp); } catch { }
                return null;
            }
        }

        _extracted[fileName] = outPath;
        return outPath;
    }
}
