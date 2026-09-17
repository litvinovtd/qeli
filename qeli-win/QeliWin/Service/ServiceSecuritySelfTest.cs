using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace QeliWin.Service;

internal static class ServiceSecuritySelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        int attempts = 0;
        check("service cleanup: persistent failure never reports success",
            !QeliWorker.TryStop(() => { attempts++; throw new IOException("injected cleanup"); }, _ => {}, _ => {})
                && attempts == 3);
        attempts = 0;
        check("service cleanup: transient failure is retried",
            QeliWorker.TryStop(() => { if (++attempts < 3) throw new IOException("transient"); }, _ => {}, _ => {})
                && attempts == 3);
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var arbitrary = new SecurityIdentifier("S-1-5-21-123-456-789-1001");
        FileSecurity Descriptor(SecurityIdentifier owner, SecurityIdentifier writer, FileSystemRights rights)
        {
            var acl = new FileSecurity();
            acl.SetOwner(owner);
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new FileSystemAccessRule(writer, rights, AccessControlType.Allow));
            return acl;
        }
        check("service ACL: privileged writer accepted",
            ServiceManager.UntrustedAccess(Descriptor(admin, admin, FileSystemRights.FullControl)) == null);
        check("service ACL: arbitrary user/group writer refused",
            ServiceManager.UntrustedAccess(Descriptor(admin, arbitrary, FileSystemRights.WriteData)) != null);
        check("service ACL: owner able to change DACL refused",
            ServiceManager.UntrustedAccess(Descriptor(arbitrary, admin, FileSystemRights.FullControl)) != null);
        check("service ACL: private profile reader refused",
            ServiceManager.UntrustedAccess(Descriptor(admin, arbitrary, FileSystemRights.ReadData), privateFile: true) != null);
        check("service ACL: creating ancestor siblings is harmless",
            ServiceManager.UntrustedAccess(Descriptor(admin, arbitrary, FileSystemRights.AppendData), ancestor: true) == null);
        check("service ACL: ancestor delete-child permits replacement",
            ServiceManager.UntrustedAccess(Descriptor(admin, arbitrary, FileSystemRights.DeleteSubdirectoriesAndFiles), ancestor: true) != null);
        check("service ACL: unreadable/missing path fails closed",
            ServiceManager.NonAdminWriterOn(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))) != null);
        var inheritOnly = new DirectorySecurity();
        inheritOnly.SetOwner(admin);
        inheritOnly.SetAccessRuleProtection(true, false);
        inheritOnly.AddAccessRule(new FileSystemAccessRule(admin, FileSystemRights.FullControl, AccessControlType.Allow));
        inheritOnly.AddAccessRule(new FileSystemAccessRule(arbitrary, FileSystemRights.WriteData,
            InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly, AccessControlType.Allow));
        check("service ACL: inherit-only ACE does not grant access to current object",
            ServiceManager.UntrustedAccess(inheritOnly) == null);
        foreach (var library in new[] { "qeli", "wintun.dll", "WinDivert.dll" })
        {
            bool refused = false;
            try { _ = QeliWin.Vpn.NativeLoader.ResolveEmbedded(library, _ => null, () => null); }
            catch (DllNotFoundException) { refused = true; }
            check($"native loader: {library} extraction refusal forbids fallback", refused);
        }
        check("native loader: unrelated OS library retains default resolution",
            QeliWin.Vpn.NativeLoader.ResolveEmbedded("kernel32", _ => throw new Exception("unexpected extraction"),
                () => throw new Exception("unexpected driver extraction")) == IntPtr.Zero);

        string dir = Path.Combine(Path.GetTempPath(), "qeli-atomic-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "profile");
            File.WriteAllText(path, "previous");
            bool interrupted = false;
            try
            {
                ServiceState.PublishAtomic(path, temporary => {
                    File.WriteAllText(temporary, "partial");
                    throw new IOException("injected writer interruption");
                });
            }
            catch (IOException) { interrupted = true; }
            check("service profile: interrupted write keeps previous version",
                interrupted && File.ReadAllText(path) == "previous");
            check("service profile: interrupted write removes its temporary file",
                Directory.GetFiles(dir).Length == 1);
            ServiceState.PublishAtomic(path, temporary => File.WriteAllText(temporary, "complete"));
            check("service profile: complete write replaces previous version",
                File.ReadAllText(path) == "complete" && Directory.GetFiles(dir).Length == 1);
            using var oldReader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            ServiceState.PublishAtomic(path, temporary => File.WriteAllText(temporary, "new"));
            using var text = new StreamReader(oldReader);
            check("service profile: open reader retains complete old version across rename",
                text.ReadToEnd() == "complete" && File.ReadAllText(path) == "new");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
