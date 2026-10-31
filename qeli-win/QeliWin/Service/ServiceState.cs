using System.IO;
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
public sealed class ServiceStatus : DesktopServiceStatus
{
    public TunnelFailureKind? FailureKind {get;set;}
    public int? ControlProtocolVersion {get;set;}
    public string? ProfileId {get;set;}
    public string? SessionId {get;set;}
    // Optional for old services/GUIs. Do not infer the running profile from GUI selection.
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ProfileName { get; set; }
}

/// <summary>
/// Shared state between the Windows Service (writer) and the GUI (reader), stored under
/// %ProgramData%\QeliWin\service for LocalSystem and elevated administrators only.
/// </summary>
public static class ServiceState
{
    public static readonly string Dir = StorageLayout.ServiceDirectory;
    public static string ProfileFile => Path.Combine(Dir, "service-profile.json");
    public static string StatusFile => Path.Combine(Dir, "service-status.json");
    public static string LogFile => Path.Combine(Dir, "service.log");
    public static string DesiredConnectionFile => Path.Combine(Dir, "service-connect.enabled");

    private static readonly object _logLock = new();
    internal const int MaxLogBytes = 256 * 1024;
    internal const int MaxLogLineChars = 4096;
    internal const int MaximumProfileBytes = 4 * 1024 * 1024;
    internal const int MaximumStatusBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static void EnsureDir()
    {
        StorageLayout.EnsureRoot();
        StorageLayout.EnsureDirectory(Dir, privateData: true);
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
            using var file = OpenSnapshot(DesiredConnectionFile);
            return StrictUtf8.GetString(ReadBounded(file, 16)).Trim() == "1";
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

    // Read a single generation while allowing its atomic replacement, never a writer.
    private static FileStream OpenSnapshot(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);

    // Enforce the budget during streaming too, not just against an initial Length.
    internal static byte[] ReadBounded(Stream input, int maximumBytes)
    {
        using var output = new MemoryStream();
        var buffer = new byte[64 * 1024];
        try
        {
            while (true)
            {
                int read = input.Read(buffer, 0,
                    (int)Math.Min(buffer.Length, maximumBytes - output.Length + 1));
                if (read == 0) return output.ToArray();
                if (output.Length + read > maximumBytes)
                    throw new InvalidDataException("Service storage exceeds its byte limit");
                output.Write(buffer, 0, read);
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }

    internal static byte[] EncodeProfile(VpnConfig cfg)
    {
        ProfileStorePayload.Validate(cfg);
        var plaintext = StrictUtf8.GetBytes(JsonSerializer.Serialize(cfg));
        try
        {
            if (plaintext.Length > MaximumProfileBytes)
                throw new InvalidDataException("Service profile is too large");
            var encrypted = ProtectedData.Protect(plaintext, null, DataProtectionScope.LocalMachine);
            // The reader limits the stored blob, including DPAPI envelope overhead.
            if (encrypted.Length > MaximumProfileBytes)
                throw new InvalidDataException("Service profile is too large");
            return encrypted;
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    internal static VpnConfig DecodeProfile(byte[] bytes, bool allowLegacy, out bool legacy)
    {
        legacy = false;
        byte[]? plaintext = null;
        try
        {
            try { plaintext = ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine); }
            catch (CryptographicException)
            {
                if (!allowLegacy)
                    throw new InvalidDataException("Service profile is corrupt or not DPAPI-encrypted; re-save it from the GUI");
                plaintext = bytes; // trusted, elevated GUI legacy migration only
                legacy = true;
            }
            var cfg = JsonSerializer.Deserialize<VpnConfig>(StrictUtf8.GetString(plaintext))
                ?? throw new InvalidDataException("Service profile is empty");
            ProfileStorePayload.Validate(cfg);
            return cfg;
        }
        finally
        {
            if (plaintext != null && !ReferenceEquals(plaintext, bytes))
                CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static void SaveProfile(VpnConfig cfg) => PublishProfile(EncodeProfile(cfg));

    internal static void PublishProfile(byte[] encrypted)
    {
        if (encrypted.Length > MaximumProfileBytes)
            throw new InvalidDataException("Service profile is too large");
        EnsureDir();
        AtomicWrite(ProfileFile, encrypted);
    }

    public static VpnConfig? LoadProfile()
    {
        EnsureDir();
        CheckExistingFile(ProfileFile);
        byte[] bytes;
        try
        {
            using var file = OpenSnapshot(ProfileFile);
            bytes = ReadBounded(file, MaximumProfileBytes);
        }
        catch (FileNotFoundException) { return null; } // only absence is "no profile"
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var cfg = DecodeProfile(bytes, allowLegacy: !identity.IsSystem, out bool legacy);
            if (legacy) SaveProfile(cfg);
            return cfg;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static void WriteStatus(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null,
        DesktopTunnelAddresses? addresses = null, string? profileName = null, string? profileId=null, string? sessionId=null, TunnelFailureKind? failureKind=null)
    {
        try
        {
            // Timestamp the supplied counters before filesystem work can delay publication.
            long monotonicTimeMs = ServiceMonotonicClock.NowMilliseconds;
            DateTime sampledAt = DateTime.Now;
            EnsureDir();
            AtomicWrite(StatusFile, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new ServiceStatus
            {
                Status = status.ToString(),
                ProfileId=profileId,SessionId=sessionId,ControlProtocolVersion=1,FailureKind=status==VpnStatus.Error ? failureKind : null,
                ProfileName = profileName is { Length: > 256 } ? profileName[..256] : profileName,
                // Bound status even when an upstream error includes a large file/response.
                Extra = extra is { Length: > 2048 } ? extra[..2048] : extra,
                Time = sampledAt,
                MonotonicTimeMs = monotonicTimeMs,
                BytesUp = bytesUp,
                BytesDown = bytesDown,
                Since = since,
                Addresses = status == VpnStatus.Connected ? addresses ?? DesktopTunnelAddresses.Empty : DesktopTunnelAddresses.Empty,
            })));
        }
        catch { /* ignore */ }
    }

    internal static ServiceStatus? ReadExistingStatus()
    {
        if(!StorageLayout.Exists(Dir)) return null;
        RequireTrusted(Dir,privateFile:true);CheckExistingFile(StatusFile);
        try {using var file=OpenSnapshot(StatusFile);return DecodeStatus(ReadBounded(file,MaximumStatusBytes));}
        catch(FileNotFoundException) {return null;}
    }
    internal static string ReadExistingLog()
    {
        if(!StorageLayout.Exists(Dir)) return "";
        RequireTrusted(Dir,privateFile:true);CheckExistingFile(LogFile);
        try {using var file=new FileStream(LogFile,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);return ReadLogSnapshot(file);}
        catch(FileNotFoundException) {return "";}
    }
    public static ServiceStatus? ReadStatus()
    {
        EnsureDir();
        CheckExistingFile(StatusFile);
        try
        {
            using var file = OpenSnapshot(StatusFile);
            return DecodeStatus(ReadBounded(file, MaximumStatusBytes));
        }
        catch (FileNotFoundException) { return null; }
    }

    internal static ServiceStatus DecodeStatus(byte[] bytes)
    {
        var status = DesktopServiceStatus.Decode<ServiceStatus>(bytes);
        if(status.FailureKind.HasValue && !Enum.IsDefined(status.FailureKind.Value)) throw new InvalidDataException("Invalid service failure category");
        if(status.ProfileId?.Length>64 || status.SessionId?.Length>64 || status.ControlProtocolVersion is <1 or >4096) throw new InvalidDataException("Invalid service control metadata");
        if (status.ProfileName?.Length > 256) throw new InvalidDataException("Service profile name is too long");
        return status;
    }

    public static string ReadLog()
    {
        EnsureDir();
        CheckExistingFile(LogFile);
        try
        {
            using var file = new FileStream(LogFile, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return ReadLogSnapshot(file);
        }
        catch (FileNotFoundException) { return ""; }
    }

    // A bounded complete view also handles truncate+regrow and atomic rotation without
    // trusting a stale byte cursor. An incomplete UTF-8 write is retried next poll.
    internal static string ReadLogSnapshot(Stream stream) =>
        StrictUtf8.GetString(ReadBounded(stream, MaxLogBytes));

    public static void ResetLog()
    {
        lock (_logLock)
        {
            try { EnsureDir(); AtomicWrite(LogFile, []); } catch { }
        }
    }

    internal static byte[] EncodeLogLine(string line, DateTime now)
    {
        if (line.Length > MaxLogLineChars)
        {
            int end = MaxLogLineChars;
            if (char.IsHighSurrogate(line[end - 1])) end--;
            line = line[..end] + " [truncated]";
        }
        return Encoding.UTF8.GetBytes($"{now:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}");
    }

    internal static void AppendLogFile(string path, byte[] entry)
    {
        if (entry.Length > MaxLogBytes) throw new InvalidDataException("Log entry exceeds byte limit");
        // Rotate BEFORE writing, including a previously oversized legacy log.
        if (File.Exists(path) && new FileInfo(path).Length > MaxLogBytes - entry.Length)
            PublishAtomic(path, temporary => File.WriteAllBytes(temporary, entry));
        else
        {
            using var file = new FileStream(path, FileMode.Append, FileAccess.Write,
                FileShare.Read | FileShare.Delete);
            file.Write(entry);
        }
    }

    public static void AppendLog(string line)
    {
        lock (_logLock)
        {
            try
            {
                EnsureDir();
                CheckExistingFile(LogFile);
                AppendLogFile(LogFile, EncodeLogLine(line, DateTime.UtcNow));
            }
            catch { /* ignore */ }
        }
    }
}
