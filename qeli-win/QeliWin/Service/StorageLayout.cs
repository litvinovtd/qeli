using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace QeliWin.Service;

// Product data, private service state and immutable native images have different ACLs.
// Neither the release version nor a native image update changes recovery ownership.
internal static class StorageLayout
{
    internal static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "QeliWin");
    internal static string ServiceDirectory => Path.Combine(Root, "service");
    internal static readonly string[] LegacyFiles =
        ["service-profile.json", "service-status.json", "service.log", "service-connect.enabled"];

    internal static bool Exists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    internal static bool MigrationNeeded(string root)
    {
        if (!Exists(root)) return false;
        if (!Directory.Exists(root) || ServiceManager.NonAdminWriterOn(root) != null) return true;
        if (LegacyFiles.Any(name => Exists(Path.Combine(root, name)))) return true;
        string service = Path.Combine(root, "service");
        return Exists(service) && ServiceManager.NonAdminWriterOn(service, privateFile: true) != null;
    }

    internal static DirectorySecurity PrivateAcl()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.SetOwner(admin);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        foreach (var sid in new[] { admin, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                inherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    internal static void RequireAncestors(string path)
    {
        for (var parent = Path.GetDirectoryName(path); !string.IsNullOrEmpty(parent);
             parent = Path.GetDirectoryName(parent))
            ServiceState.RequireTrusted(parent, ancestor: true);
    }

    internal static void EnsureDirectory(string path, bool privateData = false)
    {
        RequireAncestors(path);
        if (!Exists(path)) new DirectoryInfo(path).Create(PrivateAcl());
        ServiceState.RequireTrusted(path, privateFile: privateData);
    }

    internal static void EnsureRoot()
    {
        if (MigrationNeeded(Root))
            throw new UnauthorizedAccessException(
                "Legacy or untrusted Qeli storage requires migration. Stop VPN and complete " +
                "network recovery, then launch the current GUI as administrator to prepare storage.");
        EnsureDirectory(Root);
    }
}
