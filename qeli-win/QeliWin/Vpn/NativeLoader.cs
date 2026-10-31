using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Resolves the native libraries embedded in the executable (WireGuard's
/// <c>wintun.dll</c>, optional <c>WinDivert.dll</c>/<c>WinDivert64.sys</c>, and
/// <c>qeli.dll</c>, the Rust whole-client core),
/// so both hosts use identical embedded driver/core bytes (the CLI distribution is a folder). Each is extracted once to a
/// protected %ProgramData% directory when elevated (or %LOCALAPPDATA% without a privilege
/// boundary) and loaded from there; a module initializer
/// registers the resolver before any P/Invoke runs.
/// </summary>
internal static class NativeLoader
{
    // Native libs embedded as resources, by the name used in P/Invoke (lowercase).
    private static readonly string[] Embedded =
        { "wintun.dll", "qeli.dll", "WinDivert.dll", "WinDivert64.sys" };

    private static readonly Dictionary<string, (byte[] bytes, byte[] hash)> _images = new(StringComparer.OrdinalIgnoreCase);
    private static readonly NativeModuleCache _modules = new();
    private static readonly object _lock = new();
    private static string? _bundleId;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2255", Justification = "One shared Windows runtime registers the native resolver before GUI, CLI or service P/Invoke.")]
    [ModuleInitializer]
    internal static void Init()
    {
        // Wintun is P/Invoked from this shared Windows runtime assembly.
        NativeLibrary.SetDllImportResolver(typeof(NativeLoader).Assembly, Resolve);
        // …but qeli.dll (whole-client + realtls FFI) is P/Invoked from the shared
        // assembly. SetDllImportResolver is per-assembly, so the resolver must be
        // registered there too or every native transport mode fails with
        // "Unable to load DLL 'qeli'" (the single-file exe has no loose qeli.dll).
        NativeLibrary.SetDllImportResolver(typeof(Qeli.Shared.Vpn.VpnTunnelBase).Assembly, Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        => ResolveEmbedded(libraryName, EnsureExtracted, EnsureWinDivertDir);

    internal static IntPtr EnsureWinDivertLoaded() =>
        ResolveEmbedded("WinDivert.dll", EnsureExtracted, EnsureWinDivertDir);

    internal static IntPtr ResolveEmbedded(string libraryName,
        Func<string, string?> extract, Func<string?> extractDriverPair)
    {
        // DllImport may pass "qeli" or "qeli.dll"; normalise to the file name.
        var name = libraryName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
            ? libraryName : libraryName + ".dll";
        if (!Embedded.Contains(name, StringComparer.OrdinalIgnoreCase))
            return IntPtr.Zero; // not ours — fall back to default resolution

        // The WinDivert DLL loads its signed driver from the same directory. Extract the
        // pair before mapping the DLL so driver discovery cannot race first use.
        if (name.Equals("WinDivert.dll", StringComparison.OrdinalIgnoreCase)
            && extractDriverPair() == null)
            throw new DllNotFoundException("Protected extraction of WinDivert failed; refusing default DLL search.");
        var path = extract(name);
        if (path == null)
            throw new DllNotFoundException($"Protected extraction of {name} failed; refusing default DLL search.");
        return _modules.Load(name, path, NativeLibrary.Load);
    }

    internal static string? EnsureWinDivertDir()
    {
        string? dll = EnsureExtracted("WinDivert.dll");
        string? driver = EnsureExtracted("WinDivert64.sys");
        if (dll == null || driver == null) return null;
        string? dllDir = Path.GetDirectoryName(dll);
        string? driverDir = Path.GetDirectoryName(driver);
        return dllDir != null && dllDir.Equals(driverDir, StringComparison.OrdinalIgnoreCase)
            ? dllDir : null;
    }

    private static string? EnsureExtracted(string dllName)
    {
        lock (_lock)
        {
            // Cache trusted resource bytes, never a previously trusted disk path. Every
            // extraction request repeats directory/file trust and content verification.
            // One fingerprint covers the whole set, including the DLL/driver pair.
            // Same release number with different embedded bytes is a different cache.
            foreach (string name in Embedded)
                if (!_images.ContainsKey(name))
                {
                    using var src = typeof(NativeLoader).Assembly.GetManifestResourceStream(name);
                    if (src == null) return null;
                    using var mem = new MemoryStream();
                    src.CopyTo(mem);
                    var bytes = mem.ToArray();
                    _images.Add(name, (bytes, System.Security.Cryptography.SHA256.HashData(bytes)));
                }
            _bundleId ??= BundleId(Embedded.Select(name => (name, _images[name].hash)));
            var image = _images[dllName];
            bool elevated = IsElevated();
            // WHERE we extract decides whether the hash check below means anything.
            //
            // %LOCALAPPDATA% is writable by the user and by anything running as them, while
            // this process is elevated (app.manifest requires administrator; in service mode
            // it is LocalSystem) and is about to map the result as native code. Verifying the
            // hash and then calling NativeLibrary.Load(path) is a TOCTOU: the check reads the
            // file, the load re-opens it, and between the two a same-user process replaces
            // it. No amount of hashing closes that, because the attacker controls the
            // directory — the fix is to put the file somewhere they do not.
            //
            // Elevated: %ProgramData%\QeliWin\native with an explicit DACL (Administrators +
            // SYSTEM write, Users read-only, inheritance off). Not elevated: %LOCALAPPDATA%
            // as before — no privilege boundary is crossed there, so there is nothing to
            // escalate. (Audit 2026-08-04.)
            string dir;
            if (elevated)
            {
                using var migrationGate = QeliWin.Service.StorageMigration.EnterGate();
                // Native extraction never opens/creates the private service profile store.
                QeliWin.Service.StorageLayout.EnsureRoot();
                string nativeRoot = Path.Combine(QeliWin.Service.StorageLayout.Root, "native");
                if (!CreateProtectedDirectory(nativeRoot)) return null;
                dir = Path.Combine(nativeRoot, _bundleId);
                if (!CreateProtectedDirectory(dir)) return null;
                // Someone may have created it first with permissive rights.
                if (QeliWin.Service.ServiceManager.NonAdminWriterOn(dir) != null) return null;
            }
            else
            {
                dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "QeliWin", "native", _bundleId);
                Directory.CreateDirectory(dir);
            }
            var outPath = Path.Combine(dir, dllName);
            if (elevated && File.Exists(outPath)
                && QeliWin.Service.ServiceManager.NonAdminWriterOn(outPath) != null) return null;

            var want = image.bytes;
            bool reuse = false;
            if (File.Exists(outPath))
            {
                try
                {
                    using var have = new FileStream(outPath, FileMode.Open, FileAccess.Read,
                        FileShare.Read | FileShare.Delete);
                    reuse = MatchesEmbedded(have, want.Length, image.hash);
                }
                catch { reuse = false; }
            }

            if (!reuse)
            {
                // Write to a private temp name and swap it in, so a concurrent reader
                // never observes a partially-written DLL.
                var tmp = outPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        output.Write(want);
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
                    return null;
                }
                catch
                {
                    try { File.Delete(tmp); } catch { }
                    return null;
                }
            }

            return outPath;
        }
    }

    internal static string BundleId(IEnumerable<(string name, byte[] hash)> images)
    {
        using var digest = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        foreach (var (name, hash) in images.OrderBy(image => image.name, StringComparer.Ordinal))
        {
            digest.AppendData(System.Text.Encoding.UTF8.GetBytes(name + "\0"));
            digest.AppendData(hash);
        }
        return Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
    }

    internal static bool MatchesEmbedded(Stream input, long expectedLength, byte[] expectedHash)
    {
        if (input.CanSeek && input.Length != expectedLength) return false;
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            int read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, expectedLength - total + 1));
            if (read == 0) break;
            total += read;
            if (total > expectedLength) return false;
            hash.AppendData(buffer, 0, read);
        }
        return total == expectedLength && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            hash.GetHashAndReset(), expectedHash);
    }

    /// <summary>True when this process runs with the Administrators group enabled — the
    /// case where extracting to a user-writable directory would be an escalation.</summary>
    private static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch (Exception error)
        {
            throw new InvalidOperationException(
                "Cannot determine native cache privilege boundary; refusing DLL extraction", error);
        }
    }

    /// <summary>Create or verify a directory only Administrators and SYSTEM may write.
    /// Inheritance is disabled so a permissive ACL on the parent cannot widen it.</summary>
    private static bool CreateProtectedDirectory(string dir)
    {
        try
        {
            var admins = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var users = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);

            var sec = new System.Security.AccessControl.DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            sec.SetOwner(admins);
            const System.Security.AccessControl.InheritanceFlags Inherit =
                System.Security.AccessControl.InheritanceFlags.ContainerInherit
                | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
            foreach (var sid in new[] { admins, system })
            {
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    sid, System.Security.AccessControl.FileSystemRights.FullControl,
                    Inherit, System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
            }
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                users, System.Security.AccessControl.FileSystemRights.ReadAndExecute,
                Inherit, System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));

            if (!Directory.Exists(dir))
            {
                new DirectoryInfo(dir).Create(sec);
            }
            return QeliWin.Service.ServiceManager.NonAdminWriterOn(dir) == null;
        }
        catch
        {
            return false;
        }
    }
}
