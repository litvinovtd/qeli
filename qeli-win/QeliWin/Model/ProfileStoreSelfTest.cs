using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliWin.Model;

internal static class ProfileStoreSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        string dir = Path.Combine(Path.GetTempPath(), "qeli-dpapi-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        byte[] Seal(byte[] bytes) => ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        string Open(string path) => new UTF8Encoding(false, true).GetString(
            ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser));
        bool Refused(Action action)
        {
            try { action(); return false; }
            catch (IOException) { return true; }
        }
        try
        {
            string path = Path.Combine(dir, "profiles");
            var archive = new WindowsProfileArchive(path);
            check("DPAPI store: first run is empty", archive.Load().Count == 0);
            var first = new VpnConfig { Id = "first", Password = "test-only-secret" };
            archive.Save(new[] { first });
            var previous = File.ReadAllBytes(path);
            check("DPAPI store: current-user authenticated roundtrip",
                ProfileStorePayload.Decode(Open(path)).Single().Password == first.Password
                && !previous.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(Open(path))));
            var read = new WindowsProfileArchive(path).Load();
            check("DPAPI store: encrypted load keeps Id and exact bytes",
                read.Single().Id == first.Id && File.ReadAllBytes(path).AsSpan().SequenceEqual(previous));
            archive.Save(new[] { new VpnConfig { Id = "second" } });
            check("DPAPI store: atomic save keeps exact encrypted previous generation",
                File.ReadAllBytes(path + ".bak").AsSpan().SequenceEqual(previous));
            var corrupt = Encoding.UTF8.GetBytes("not a profile archive");
            File.WriteAllBytes(path, corrupt);
            var recoveryOwner = new WindowsProfileArchive(path);
            var recovered = recoveryOwner.Load();
            check("DPAPI store: corrupt latest recovers authenticated backup",
                recovered.Count == 1 && recovered[0].Id == first.Id && recovered[0].Password == first.Password);
            check("DPAPI store: recovery republishes DPAPI data",
                File.Exists(path) && ProfileStorePayload.Decode(Open(path)).Single().Id == first.Id);
            check("DPAPI store: quarantine preserves exact corrupt bytes",
                Directory.GetFiles(dir, "profiles.corrupt-*").Length == 1
                && File.ReadAllBytes(Directory.GetFiles(dir, "profiles.corrupt-*").Single()).AsSpan().SequenceEqual(corrupt));
            check("DPAPI store: successful recovery keeps backup bytes",
                File.ReadAllBytes(path + ".bak").AsSpan().SequenceEqual(previous));
            check("DPAPI store: pre-recovery writer cannot replace restored generation",
                Refused(() => archive.Save(new[] { new VpnConfig { Id = "stale" } }))
                && ProfileStorePayload.Decode(Open(path)).Single().Id == first.Id);

            // Invalid DECRYPTED UTF-8 is never accepted with replacement characters.
            string utf = Path.Combine(dir, "utf");
            var badUtf8 = Seal(new byte[] { 0xff });
            File.WriteAllBytes(utf, badUtf8);
            File.WriteAllBytes(utf + ".bak", previous);
            check("DPAPI store: malformed decrypted UTF-8 selects quarantine and backup",
                new WindowsProfileArchive(utf).Load().Single().Id == first.Id
                && File.ReadAllBytes(Directory.GetFiles(dir, "utf.corrupt-*").Single()).AsSpan().SequenceEqual(badUtf8));

            string legacy = Path.Combine(dir, "legacy");
            File.WriteAllText(legacy, "[{\"Password\":\"legacy-test-secret\"}]", new UTF8Encoding(false));
            var legacyArchive = new WindowsProfileArchive(legacy);
            string migratedId = legacyArchive.Load().Single().Id;
            check("DPAPI store: legacy plaintext and missing Id migrate once",
                !string.IsNullOrWhiteSpace(migratedId)
                && ProfileStorePayload.Decode(Open(legacy)).Single().Id == migratedId
                && new WindowsProfileArchive(legacy).Load().Single().Id == migratedId);
            string legacyBackup = Path.Combine(dir, "legacy-backup");
            File.WriteAllBytes(legacyBackup, corrupt);
            File.WriteAllText(legacyBackup + ".bak", "[{\"Password\":\"legacy-backup-secret\"}]", new UTF8Encoding(false));
            var recoveredLegacy = new WindowsProfileArchive(legacyBackup).Load();
            check("DPAPI store: legacy backup is structurally checked and re-encrypted",
                recoveredLegacy.Count == 1
                && ProfileStorePayload.Decode(Open(legacyBackup)).Single().Id == recoveredLegacy[0].Id);

            foreach (var invalid in new[] { "null", "[null]", "[{\"Id\":\"a\",\"Password\":null}]",
                "[{\"Id\":\"a\"},{\"Id\":\"a\"}]", "{", "[42]" })
            {
                string broken = Path.Combine(dir, Guid.NewGuid().ToString("N"));
                File.WriteAllBytes(broken, corrupt);
                byte[] invalidBackup = Seal(Encoding.UTF8.GetBytes(invalid));
                File.WriteAllBytes(broken + ".bak", invalidBackup);
                check($"DPAPI store: invalid backup {invalid} is not republished",
                    new WindowsProfileArchive(broken).Load().Count == 0 && !File.Exists(broken)
                    && File.ReadAllBytes(broken + ".bak").AsSpan().SequenceEqual(invalidBackup));
            }
            string oversized = Path.Combine(dir, "oversized-backup");
            File.WriteAllBytes(oversized, corrupt);
            using (var file = File.Create(oversized + ".bak")) file.SetLength(ProfileStoreFile.MaximumStoredBytes + 1L);
            check("DPAPI store: oversized backup cannot be restored",
                new WindowsProfileArchive(oversized).Load().Count == 0 && !File.Exists(oversized));

            string blocked = Path.Combine(dir, "blocked");
            File.WriteAllBytes(blocked, corrupt);
            File.WriteAllBytes(blocked + ".bak", previous);
            using (var reader = new FileStream(blocked, FileMode.Open, FileAccess.Read, FileShare.Read))
                check("DPAPI store: failed quarantine refuses recovery before overwrite",
                    Refused(() => new WindowsProfileArchive(blocked).Load())
                    && File.ReadAllBytes(blocked).AsSpan().SequenceEqual(corrupt));
            string blockedMigration = Path.Combine(dir, "blocked-migration");
            byte[] validLegacy = Encoding.UTF8.GetBytes("[{\"Id\":\"legacy\"}]");
            File.WriteAllBytes(blockedMigration, validLegacy);
            using (var reader = new FileStream(blockedMigration, FileMode.Open, FileAccess.Read, FileShare.Read))
                check("DPAPI store: failed migration keeps readable original and raises error",
                    Refused(() => new WindowsProfileArchive(blockedMigration).Load())
                    && File.ReadAllBytes(blockedMigration).AsSpan().SequenceEqual(validLegacy)
                    && Directory.GetFiles(dir, "blocked-migration.corrupt-*").Length == 0);
        }
        finally
        {
            // Only this test's freshly created GUID directory is removed.
            Directory.Delete(dir, recursive: true);
        }
    }
}
