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
        // wintun.dll is P/Invoked from this (QeliWin) assembly…
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

            // Read the embedded copy once: we need its bytes both to compare and to
            // write, and the hash must be taken over exactly what we would load.
            using var mem = new MemoryStream();
            src.CopyTo(mem);
            var want = mem.ToArray();
            var wantHash = System.Security.Cryptography.SHA256.HashData(want);

            // The extraction directory is under %LOCALAPPDATA%, i.e. writable by the
            // user and by anything running as them — while this process is elevated
            // (app.manifest requires administrator) and is about to load the result as
            // native code. So the on-disk copy is UNTRUSTED input and is only reused
            // when its content hashes to the embedded copy.
            //
            // The previous check compared file LENGTH, which a planted DLL trivially
            // matches (the release binary is public, so the target size is known and
            // padding is free).
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
                // Write to a private temp name and swap it in, so a concurrent reader
                // never observes a partially-written DLL.
                var tmp = outPath + "." + Environment.ProcessId + ".tmp";
                try
                {
                    File.WriteAllBytes(tmp, want);
                    File.Move(tmp, outPath, overwrite: true);
                }
                catch (IOException)
                {
                    // Locked by another instance that already mapped this DLL. Falling
                    // back to whatever is on disk is what the old code did — but that
                    // is exactly the bypass: hold the planted file open and the write
                    // fails, so an unverified DLL got loaded regardless of its size.
                    // Refuse instead; the caller reports a load failure.
                    try { File.Delete(tmp); } catch { }
                    if (!reuse) return null;
                }
                catch
                {
                    try { File.Delete(tmp); } catch { }
                    return null;
                }
            }

            _extracted[dllName] = outPath;
            return outPath;
        }
    }
}
