using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using QeliWin.Model;
using QeliWin.Vpn;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliWin.Service;

/// <summary>Status snapshot the service writes and the GUI polls.</summary>
public sealed class ServiceStatus
{
    public string Status { get; set; } = "Disconnected";
    public string? Extra { get; set; }
    public DateTime Time { get; set; }
    public long BytesUp { get; set; }
    public long BytesDown { get; set; }
    public DateTime? Since { get; set; }
}

/// <summary>
/// Shared state between the Windows Service (writer) and the GUI (reader), stored under
/// %ProgramData%\QeliWin for LocalSystem and elevated administrators only.
/// </summary>
public static class ServiceState
{
    public static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "QeliWin");
    public static string ProfileFile => Path.Combine(Dir, "service-profile.json");
    public static string StatusFile => Path.Combine(Dir, "service-status.json");
    public static string LogFile => Path.Combine(Dir, "service.log");
    public static string DesiredConnectionFile => Path.Combine(Dir, "service-connect.enabled");

    private static readonly object _logLock = new();
    private const long MaxLogBytes = 256 * 1024;

    public static void EnsureDir()
    {
        // Do not repair/adopt a pre-existing untrusted directory: its files may have
        // been planted before the DACL was tightened. Fail before reading or writing.
        for (var parent = Path.GetDirectoryName(Dir); !string.IsNullOrEmpty(parent);
             parent = Path.GetDirectoryName(parent))
            RequireTrusted(parent, ancestor: true);
        if (!Directory.Exists(Dir))
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.SetOwner(admin);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            foreach (var id in new[] { admin, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
                security.AddAccessRule(new FileSystemAccessRule(id, FileSystemRights.FullControl,
                    inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(Dir).Create(security); // private from creation, not after writing
        }
        RequireTrusted(Dir, privateFile: true);
    }

    internal static void RequireTrusted(string path, bool ancestor = false, bool privateFile = false)
    {
        string? unsafeAccess = ServiceManager.NonAdminWriterOn(path, ancestor, privateFile);
        if (unsafeAccess != null)
            throw new UnauthorizedAccessException(
                $"Refusing untrusted service storage '{path}': {unsafeAccess}. " +
                "Stop VPN and complete network recovery; archive the unsafe storage, " +
                "then recreate it and re-save a trusted profile from the elevated GUI.");
    }

    internal static void CheckExistingFile(string path)
    {
        // GetAttributes distinguishes missing files from ACL/I/O errors and broken links.
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        RequireTrusted(path, privateFile: true);
    }

    /// <summary>Persist intent atomically; a missing/invalid flag means disconnected.</summary>
    public static void SetDesiredConnected(bool connected)
    {
        EnsureDir();
        AtomicWrite(DesiredConnectionFile, Encoding.UTF8.GetBytes(connected ? "1" : "0"));
    }

    public static bool DesiredConnected()
    {
        try
        {
            EnsureDir();
            CheckExistingFile(DesiredConnectionFile);
            return File.ReadAllText(DesiredConnectionFile).Trim() == "1";
        }
        catch { return false; }
    }

    // The containing directory is private and verified before calling this helper.
    // Publication is a same-directory rename; readers see the complete old or new file.
    internal static void AtomicWrite(string destination, byte[] bytes)
    {
        CheckExistingFile(destination);
        PublishAtomic(destination, temporary =>
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                RequireTrusted(temporary, privateFile: true);
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
        });
    }

    // Factored to fault-inject an interrupted writer without touching service storage.
    internal static void PublishAtomic(string destination, Action<string> writeTemporary)
    {
        string temporary = destination + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        string previous = temporary + ".previous";
        bool published = false;
        try
        {
            writeTemporary(temporary);
            // ReplaceFile preserves an existing reader's handle; MoveFileEx with
            // REPLACE_EXISTING can fail while that handle is open on Windows.
            // Keep a private rollback name: ReplaceFile has rare partial-failure
            // outcomes where the old file has moved but publication did not finish.
            if (File.Exists(destination)) File.Replace(temporary, destination, previous);
            else File.Move(temporary, destination);
            published = true;
        }
        catch (Exception failure)
        {
            if (File.Exists(previous) && !File.Exists(destination))
            {
                try { File.Move(previous, destination); }
                catch (Exception recovery)
                {
                    throw new IOException($"Profile publication failed; previous data retained at '{previous}': {recovery.Message}", failure);
                }
            }
            throw;
        }
        finally
        {
            try { File.Delete(temporary); } catch { }
            if (published) { try { File.Delete(previous); } catch { } }
        }
    }

    public static void SaveProfile(VpnConfig cfg)
    {
        EnsureDir();
        var json = JsonSerializer.Serialize(cfg);
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.LocalMachine);
        AtomicWrite(ProfileFile, enc);
    }

    public static VpnConfig? LoadProfile()
    {
        EnsureDir();
        CheckExistingFile(ProfileFile);
        byte[] bytes;
        // Allow atomic publication while the service has an old file open.
        try
        {
            using var file = new FileStream(ProfileFile, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            if (file.Length > 4 * 1024 * 1024) throw new InvalidDataException("Service profile is too large");
            using var copy = new MemoryStream();
            file.CopyTo(copy);
            bytes = copy.ToArray();
        }
        catch (FileNotFoundException) { return null; } // only absence is "no profile"
        string json;
        bool legacy = false;
        try { json = Encoding.UTF8.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine)); }
        catch (CryptographicException)
        {
            if (WindowsIdentity.GetCurrent().IsSystem)
                throw new InvalidDataException("Service profile is corrupt or not DPAPI-encrypted; re-save it from the GUI");
            json = Encoding.UTF8.GetString(bytes); // trusted, elevated legacy migration only
            legacy = true;
        }
        var cfg = JsonSerializer.Deserialize<VpnConfig>(json)
            ?? throw new InvalidDataException("Service profile is empty");
        if (legacy) SaveProfile(cfg);
        return cfg;
    }

    public static void WriteStatus(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null)
    {
        try
        {
            EnsureDir();
            AtomicWrite(StatusFile, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new ServiceStatus
            {
                Status = status.ToString(),
                Extra = extra,
                Time = DateTime.Now,
                BytesUp = bytesUp,
                BytesDown = bytesDown,
                Since = since,
            })));
        }
        catch { /* ignore */ }
    }

    public static ServiceStatus? ReadStatus()
    {
        try
        {
            return File.Exists(StatusFile)
                ? JsonSerializer.Deserialize<ServiceStatus>(File.ReadAllText(StatusFile))
                : null;
        }
        catch { return null; }
    }

    public static void ResetLog()
    {
        try { EnsureDir(); CheckExistingFile(LogFile); File.WriteAllText(LogFile, ""); } catch { }
    }

    public static void AppendLog(string line)
    {
        lock (_logLock)
        {
            try
            {
                EnsureDir();
                CheckExistingFile(LogFile);
                if (File.Exists(LogFile) && new FileInfo(LogFile).Length > MaxLogBytes)
                    File.WriteAllText(LogFile, "");
                File.AppendAllText(LogFile, $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}");
            }
            catch { /* ignore */ }
        }
    }
}
