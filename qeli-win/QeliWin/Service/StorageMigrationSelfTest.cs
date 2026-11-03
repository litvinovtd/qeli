using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using QeliWin.Vpn;

namespace QeliWin.Service;

internal static class StorageMigrationSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        bool Fails(Action action)
        {
            try { action(); return false; }
            catch (IOException) { return true; }
        }
        byte[] a = SHA256.HashData([1]), b = SHA256.HashData([2]);
        string first = NativeLoader.BundleId([("qeli.dll", a), ("WinDivert.dll", b)]);
        check("native bundle: resource order does not affect identity",
            first == NativeLoader.BundleId([("WinDivert.dll", b), ("qeli.dll", a)]));
        check("native bundle: changed core has a distinct directory",
            first != NativeLoader.BundleId([("qeli.dll", b), ("WinDivert.dll", b)]));
        check("native bundle: changed driver has a distinct directory",
            first != NativeLoader.BundleId([("qeli.dll", a), ("WinDivert.dll", a)]));
        check("native bundle: missing/renamed resource changes identity",
            first != NativeLoader.BundleId([("qeli.dll", a)])
            && first != NativeLoader.BundleId([("qeli.dll", a), ("other.dll", b)]));
        check("native bundle: path component is a full hexadecimal SHA256",
            first.Length == 64 && first.All(c => char.IsAsciiHexDigit(c)));
        check("storage: service state is separate from the native cache",
            ServiceState.Dir == Path.Combine(StorageLayout.Root, "service")
            && ServiceState.ProfileFile == Path.Combine(StorageLayout.ServiceDirectory, "service-profile.json"));
        var acl = StorageLayout.PrivateAcl();
        check("storage: fresh private ACL accepts only trusted readers/writers",
            acl.AreAccessRulesProtected && ServiceManager.UntrustedAccess(acl, privateFile: true) == null);
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadData,
            AccessControlType.Allow));
        check("storage: public native read permission is not service-profile permission",
            ServiceManager.UntrustedAccess(acl) == null
            && ServiceManager.UntrustedAccess(acl, privateFile: true) != null);

        var events = new List<string>();
        string Run(Action readiness, Action? archive = null, Action? initialize = null) =>
            StorageMigration.ExecuteTransaction(readiness, () => { events.Add("backup"); return "private-backup"; },
                _ => { events.Add("archive"); archive?.Invoke(); },
                () => { events.Add("initialize"); initialize?.Invoke(); });
        check("migration: successful transaction rechecks before archive",
            Run(() => events.Add("recovery")) == "private-backup"
            && events.SequenceEqual(["recovery", "backup", "recovery", "archive", "initialize"]));
        events.Clear();
        check("migration: shutdown timeout preserves source without backup or initialization",
            Fails(() => Run(() => throw new IOException("previous tunnel task did not stop within 8s")))
            && events.Count == 0);
        int probes = 0;
        check("migration: newly active owner prevents rename",
            Fails(() => Run(() => { if (++probes == 2) throw new IOException("active owner"); }))
            && events.SequenceEqual(["backup"]));
        events.Clear();
        check("migration: rename failure never initializes over old files",
            Fails(() => Run(() => {}, () => throw new IOException("locked source")))
            && events.SequenceEqual(["backup", "archive"]));
        events.Clear();
        bool backupNamed = false;
        try { Run(() => {}, initialize: () => throw new IOException("injected initialization")); }
        catch (IOException error) { backupNamed = error.Message.Contains("private-backup"); }
        check("migration: initialization failure reports retained backup without rollback",
            backupNamed && events.SequenceEqual(["backup", "archive", "initialize"]));

        // Real filesystem move/retention, but deliberately no product storage/SCM/network I/O.
        string sandbox = Path.Combine(Path.GetTempPath(), "qeli-storage-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sandbox);
        try
        {
            string root = Path.Combine(sandbox, "root"), backup = Path.Combine(sandbox, "backup");
            Directory.CreateDirectory(root);
            byte[] original = [0, 1, 2, 255];
            File.WriteAllBytes(Path.Combine(root, "service-profile.json"), original);
            StorageMigration.ExecuteTransaction(() => {}, () => { Directory.CreateDirectory(backup); return backup; },
                dest => Directory.Move(root, Path.Combine(dest, "legacy")),
                () => Directory.CreateDirectory(Path.Combine(root, "service")));
            check("migration: archive preserves original bytes; new store has no imported profile/intent",
                File.ReadAllBytes(Path.Combine(backup, "legacy", "service-profile.json")).SequenceEqual(original)
                && !File.Exists(Path.Combine(root, "service", "service-profile.json"))
                && !File.Exists(Path.Combine(root, "service", "service-connect.enabled")));
            check("migration: occupied backup destination never overwrites original data",
                Fails(() => StorageMigration.ExecuteTransaction(() => {}, () => backup,
                    dest => Directory.Move(root, Path.Combine(dest, "legacy")), () => {}))
                && Directory.Exists(Path.Combine(root, "service"))
                && File.ReadAllBytes(Path.Combine(backup, "legacy", "service-profile.json")).SequenceEqual(original));
        }
        finally { Directory.Delete(sandbox, recursive: true); }
    }
}
