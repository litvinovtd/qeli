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
/// %ProgramData%\QeliWin so LocalSystem can write and any user can read.
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
        bool created = !Directory.Exists(Dir);
        Directory.CreateDirectory(Dir);
        if (created) RestrictDirAcl();
    }

    /// <summary>Persist the user's connection intent separately from SCM auto-start.
    /// The service itself may start at boot so it can be controlled before logon, but a
    /// missing/corrupt flag is safely interpreted as "stay disconnected".</summary>
    public static void SetDesiredConnected(bool connected)
    {
        EnsureDir();
        RestrictDirAcl();
        string temporary = DesiredConnectionFile + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, connected ? "1" : "0");
            File.Move(temporary, DesiredConnectionFile, overwrite: true);
        }
        finally
        {
            try { File.Delete(temporary); } catch { }
        }
    }

    public static bool DesiredConnected()
    {
        try { return File.ReadAllText(DesiredConnectionFile).Trim() == "1"; }
        catch { return false; }
    }

    /// <summary>
    /// Tighten the DACL of the %ProgramData%\QeliWin directory so only SYSTEM, the
    /// Administrators group and the creating user may write into it. %ProgramData%
    /// inherits a DACL that lets ordinary "Users"/"Authenticated Users" create files;
    /// without this a non-admin could PLANT a <c>service-profile.json</c> that the
    /// LocalSystem service then loads — pointing the machine-wide tunnel at an attacker
    /// server with attacker-chosen routing/DNS (local EoP + boot-time MITM). Dropping the
    /// inherited "Users" write on the directory closes the planting vector at the source.
    /// Best-effort: an ACL failure never breaks operation.
    /// </summary>
    private static void RestrictDirAcl()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var di = new DirectoryInfo(Dir);
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            void Allow(IdentityReference id) => sec.AddAccessRule(new FileSystemAccessRule(
                id, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));        // service
            Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            var me = WindowsIdentity.GetCurrent().User;                                   // GUI user (writer)
            if (me != null) Allow(me);
            di.SetAccessControl(sec);
        }
        catch
        {
            // Hardening only — leave the dir usable even if the ACL can't be set.
        }
    }

    public static void SaveProfile(VpnConfig cfg)
    {
        EnsureDir();
        // Re-assert the directory DACL on every save (idempotent): retroactively fixes a
        // dir created by an older build with the weak inherited %ProgramData% ACL. Runs in
        // the GUI/admin context, infrequently, so the cost is irrelevant.
        RestrictDirAcl();
        // Encrypt at rest with DPAPI LocalMachine scope: the GUI (current user) writes
        // it and the service (LocalSystem) reads it, so a cross-user scope is required.
        // This removes the trivial plaintext exposure of the password/obfs_key (a
        // copied file / backup / forensic image / casual `type` no longer reveals
        // them). See docs/RELEASE-FIXES.md E1.
        var json = JsonSerializer.Serialize(cfg);
        var enc = ProtectedData.Protect(Encoding.UTF8.GetBytes(json), null, DataProtectionScope.LocalMachine);
        File.WriteAllBytes(ProfileFile, enc);
        RestrictProfileAcl();
    }

    /// <summary>
    /// Tighten the DACL of the encrypted profile so only the writing user, the
    /// service (LocalSystem) and Administrators can read it (C1). The profile is
    /// DPAPI <c>LocalMachine</c>-scoped (so the service can decrypt it), which means
    /// any local process can decrypt the bytes — and %ProgramData% grants the broad
    /// "Users" group read by default. Without this, a non-admin local user could
    /// read the file and recover the VPN password / obfs_key. Best-effort: an ACL
    /// failure never breaks save (the DPAPI encryption still applies regardless).
    /// </summary>
    private static void RestrictProfileAcl()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var fi = new FileInfo(ProfileFile);
            var sec = new FileSecurity();
            // Drop inheritance (and the inherited Users ACE) — replace the DACL
            // with exactly the three principals below.
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            void Allow(IdentityReference id) => sec.AddAccessRule(
                new FileSystemAccessRule(id, FileSystemRights.FullControl, AccessControlType.Allow));
            Allow(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));        // service (reader)
            Allow(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            var me = WindowsIdentity.GetCurrent().User;                                   // GUI user (writer)
            if (me != null) Allow(me);
            fi.SetAccessControl(sec);
        }
        catch
        {
            // Hardening only — leave the file usable even if the ACL can't be set.
        }
    }

    public static VpnConfig? LoadProfile()
    {
        try
        {
            if (!File.Exists(ProfileFile)) return null;
            var bytes = File.ReadAllBytes(ProfileFile);
            string json;
            bool wasLegacyPlaintext = false;
            try
            {
                var plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.LocalMachine);
                json = Encoding.UTF8.GetString(plain);
            }
            catch
            {
                // Legacy plaintext profile (pre-E1) — read, then migrate to encrypted.
                // But NEVER when running as the service (LocalSystem): a non-DPAPI file in
                // the shared %ProgramData% dir may have been PLANTED by a non-admin to
                // redirect the LocalSystem tunnel (attacker server + machine-wide routing/DNS
                // = local EoP / boot-time MITM). Fail closed there — only DPAPI-encrypted
                // profiles the GUI wrote are trusted. The interactive GUI still migrates its
                // own legacy plaintext (IsSystem == false).
                if (OperatingSystem.IsWindows() && WindowsIdentity.GetCurrent().IsSystem)
                {
                    AppendLog("SECURITY: refusing to load a non-DPAPI (plaintext) service profile — " +
                              "possible planted file; delete it and reconfigure from the GUI.");
                    return null;
                }
                json = Encoding.UTF8.GetString(bytes);
                wasLegacyPlaintext = true;
            }
            var cfg = JsonSerializer.Deserialize<VpnConfig>(json);
            if (wasLegacyPlaintext && cfg != null) SaveProfile(cfg);
            return cfg;
        }
        catch { return null; }
    }

    public static void WriteStatus(VpnStatus status, string? extra,
        long bytesUp = 0, long bytesDown = 0, DateTime? since = null)
    {
        try
        {
            EnsureDir();
            File.WriteAllText(StatusFile, JsonSerializer.Serialize(new ServiceStatus
            {
                Status = status.ToString(), Extra = extra, Time = DateTime.Now,
                BytesUp = bytesUp, BytesDown = bytesDown, Since = since,
            }));
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
        try { EnsureDir(); File.WriteAllText(LogFile, ""); } catch { }
    }

    public static void AppendLog(string line)
    {
        lock (_logLock)
        {
            try
            {
                EnsureDir();
                if (File.Exists(LogFile) && new FileInfo(LogFile).Length > MaxLogBytes)
                    File.WriteAllText(LogFile, "");
                File.AppendAllText(LogFile, $"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss'Z'}  {line}{Environment.NewLine}");
            }
            catch { /* ignore */ }
        }
    }
}
