using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Resolves the native libraries embedded in the executable (WireGuard's
/// <c>wintun.dll</c> TUN driver, <c>qeli.dll</c> the Rust realtls FFI core, and
/// WinDivert for per-app split tunnelling), so the app ships as a single exe with no
/// loose DLLs. Each is extracted once to a native dir and loaded from there; a module
/// initializer registers the resolver before any P/Invoke runs.
///
/// Elevated: %ProgramData%\QeliWin\native with an explicit DACL (Administrators +
/// SYSTEM write, Users read-only). Not elevated: %LOCALAPPDATA%\QeliWin\native.
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
            var dir = ResolveNativeDir();
            if (dir == null) return null;
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

            var dir = ResolveNativeDir();
            if (dir == null) return null;
            return EnsureExtractedTo(dir, dllName);
        }
    }

    /// <summary>
    /// WHERE we extract decides whether the hash check in <see cref="EnsureExtractedTo"/>
    /// means anything.
    ///
    /// %LOCALAPPDATA% is writable by the user and by anything running as them, while
    /// this process is elevated (app.manifest requires administrator; in service mode
    /// it is LocalSystem) and is about to map the result as native code. Verifying the
    /// hash and then calling NativeLibrary.Load(path) is a TOCTOU: the check reads the
    /// file, the load re-opens it, and between the two a same-user process replaces
    /// it. No amount of hashing closes that, because the attacker controls the
    /// directory — the fix is to put the file somewhere they do not.
    ///
    /// Elevated: %ProgramData%\QeliWin\native with an explicit DACL (Administrators +
    /// SYSTEM write, Users read-only, inheritance off). Not elevated: %LOCALAPPDATA%
    /// as before — no privilege boundary is crossed there, so there is nothing to
    /// escalate. (Audit 2026-08-04.)
    /// </summary>
    private static string? ResolveNativeDir()
    {
        if (IsElevated())
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "QeliWin", "native");
            if (!CreateProtectedDirectory(dir)) return null;
            // Someone may have created it first with permissive rights.
            if (QeliWin.Service.ServiceManager.NonAdminWriterOn(dir) != null) return null;
            return dir;
        }

        var local = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "QeliWin", "native");
        Directory.CreateDirectory(local);
        return local;
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

        // Read the embedded copy once: we need its bytes both to compare and to
        // write, and the hash must be taken over exactly what we would load.
        using var mem = new MemoryStream();
        src.CopyTo(mem);
        var want = mem.ToArray();
        var wantHash = System.Security.Cryptography.SHA256.HashData(want);

        // On-disk copy is UNTRUSTED input and is only reused when its content hashes
        // to the embedded copy. The previous check compared file LENGTH, which a
        // planted DLL trivially matches.
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

        _extracted[fileName] = outPath;
        return outPath;
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
        catch { return false; }
    }

    /// <summary>Create (or adopt) a directory only Administrators and SYSTEM may write.
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
                Directory.CreateDirectory(dir);
            }
            // Apply on both paths: an existing directory may predate this change.
            new DirectoryInfo(dir).SetAccessControl(sec);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
