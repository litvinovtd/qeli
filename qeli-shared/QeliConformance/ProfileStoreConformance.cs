using System.Text.Json;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class ProfileStoreConformance
{
    public static void Run(Action<string, bool> check)
    {
        var dir = Path.Combine(Path.GetTempPath(), "qeli-profile-store-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "profiles.json");
            byte[] original = [0x00, 0xFF, 0x5A];
            File.WriteAllBytes(path, original);
            var preserved = ProfileStoreRecovery.PreserveUnreadable(path);
            check("profile store: quarantine preserves exact bytes before empty recovery",
                !File.Exists(path) && File.ReadAllBytes(preserved).SequenceEqual(original));

            bool failedClosed = false;
            try { ProfileStoreRecovery.PreserveUnreadable(path); }
            catch (IOException) { failedClosed = true; }
            check("profile store: failed quarantine refuses empty recovery", failedClosed);

            check("profile store: an empty array remains a valid empty list",
                ProfileStorePayload.Decode("[]").Count == 0);
            bool nullRootRejected = false;
            try { ProfileStorePayload.Decode("null"); }
            catch (JsonException) { nullRootRejected = true; }
            check("profile store: a null root is rejected before empty recovery", nullRootRejected);
            bool nullEntryRejected = false;
            try { ProfileStorePayload.Decode("[null]"); }
            catch (JsonException) { nullEntryRejected = true; }
            check("profile store: a null row cannot reach the desktop UI", nullEntryRejected);

            var mixed = ProfileStorePayload.Decode(
                """[{"Id":"fixed-id"},{"Name":"legacy"}]""", out bool needsIdMigration);
            check("profile store: mixed legacy IDs trigger one-time migration",
                needsIdMigration && mixed.Count == 2
                && mixed[0].Id == "fixed-id"
                && !string.IsNullOrWhiteSpace(mixed[1].Id)
                && mixed[0].Id != mixed[1].Id);
            var migrated = ProfileStorePayload.Decode(
                JsonSerializer.Serialize(mixed), out bool migratedAgain);
            check("profile store: migrated IDs stay stable after reload",
                !migratedAgain && migrated.Select(profile => profile.Id)
                    .SequenceEqual(mixed.Select(profile => profile.Id)));

            foreach (var invalid in new[]
            {
                """[{"Id":null}]""",
                """[{"Id":""}]""",
                """[{"Id":"same"},{"Id":"same"}]""",
            })
            {
                bool rejected = false;
                try { ProfileStorePayload.Decode(invalid); }
                catch (JsonException) { rejected = true; }
                check("profile store: invalid or duplicate explicit ID is rejected", rejected);
            }

            foreach (var invalid in new[]
            {
                """[{"Id":"safe","Protocol":null}]""",
                """[{"Id":"safe","IncludeRoutes":null}]""",
                """[{"Id":"safe","DnsServers":[null]}]""",
                """[{"Id":"safe","CarriedKeys":{"dns.mode":null}}]""",
            })
            {
                bool rejected = false;
                try { ProfileStorePayload.Decode(invalid); }
                catch (JsonException) { rejected = true; }
                check("profile store: null required config data is rejected on load", rejected);
            }

            bool nullWriteRejected = false;
            try { ProfileStorePayload.Encode([new VpnConfig { Protocol = null! }]); }
            catch (JsonException) { nullWriteRejected = true; }
            check("profile store: null required config data cannot be persisted",
                nullWriteRejected);

            bool duplicateWriteRejected = false;
            try
            {
                ProfileStorePayload.Encode([
                    new VpnConfig { Id = "same" },
                    new VpnConfig { Id = "same" },
                ]);
            }
            catch (JsonException) { duplicateWriteRejected = true; }
            check("profile store: duplicate IDs cannot be persisted", duplicateWriteRejected);

            var livePath = Path.Combine(dir, "live-profiles.json");
            var first = new ProfileStoreFile(livePath);
            var second = new ProfileStoreFile(livePath);
            check("profile store: both instances observe an absent initial file",
                first.Read() is null && second.Read() is null);
            first.Write([1, 2, 3]);
            bool staleCreateRejected = false;
            try { second.Write([4]); }
            catch (IOException) { staleCreateRejected = true; }
            check("profile store: stale create cannot replace another instance",
                staleCreateRejected && File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 1, 2, 3 }));

            check("profile store: second instance reloads the current bytes",
                second.Read()?.SequenceEqual(new byte[] { 1, 2, 3 }) == true);
            second.Write([4, 5]);
            bool staleUpdateRejected = false;
            try { first.Write([6]); }
            catch (IOException) { staleUpdateRejected = true; }
            check("profile store: stale update preserves the newer file and backup",
                staleUpdateRejected
                && File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 4, 5 })
                && File.ReadAllBytes(livePath + ".bak").SequenceEqual(new byte[] { 1, 2, 3 }));

            first.Read();
            second.Write([7]);
            bool staleQuarantineRejected = false;
            try { first.PreserveUnreadable(); }
            catch (IOException) { staleQuarantineRejected = true; }
            check("profile store: stale quarantine cannot move a newer valid file",
                staleQuarantineRejected && File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 7 }));

            first.Read();
            var quarantine = first.PreserveUnreadable();
            first.Write([8]);
            check("profile store: quarantine allows a fresh store while preserving original bytes",
                File.ReadAllBytes(quarantine).SequenceEqual(new byte[] { 7 })
                && File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 8 }));

            bool lockRejected = false;
            using (var held = new FileStream(livePath + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                try { first.Write([9]); }
                catch (IOException) { lockRejected = true; }
            }
            check("profile store: sidecar lock prevents a concurrent write",
                lockRejected && File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 8 }));
            first.Write([9]);
            check("profile store: write succeeds after the lock is released",
                File.ReadAllBytes(livePath).SequenceEqual(new byte[] { 9 }));

            Task<byte[]?> waitingRead;
            using (var held = new FileStream(livePath + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                using var started = new ManualResetEventSlim();
                waitingRead = Task.Run(() =>
                {
                    started.Set();
                    return new ProfileStoreFile(livePath).Read();
                });
                check("profile store: a transient lock keeps the second reader waiting",
                    started.Wait(TimeSpan.FromSeconds(2)) && !waitingRead.Wait(100));
            }
            check("profile store: the waiting reader loads after lock release",
                waitingRead.Wait(TimeSpan.FromSeconds(3))
                && waitingRead.Result?.SequenceEqual(new byte[] { 9 }) == true);

            var oversizedPath = Path.Combine(dir, "oversized-profiles.json");
            using (var large = File.Create(oversizedPath))
                large.SetLength(ProfileStoreFile.MaximumStoredBytes + 1L);
            var bounded = new ProfileStoreFile(oversizedPath);
            bool oversizedReadRejected = false;
            try { bounded.Read(); }
            catch (IOException) { oversizedReadRejected = true; }
            check("profile store: oversized input is refused before loading and preserved",
                oversizedReadRejected
                && new FileInfo(oversizedPath).Length == ProfileStoreFile.MaximumStoredBytes + 1L);

            File.WriteAllBytes(oversizedPath, [1]);
            bounded.Read();
            using (var large = new FileStream(oversizedPath, FileMode.Open, FileAccess.Write, FileShare.None))
                large.SetLength(ProfileStoreFile.MaximumStoredBytes + 1L);
            bool oversizedRevisionRejected = false;
            try { bounded.Write([2]); }
            catch (IOException) { oversizedRevisionRejected = true; }
            check("profile store: an oversized replacement blocks a stale write",
                oversizedRevisionRejected
                && new FileInfo(oversizedPath).Length == ProfileStoreFile.MaximumStoredBytes + 1L);

            bool oversizedOutputRejected = false;
            try { bounded.Write(new byte[ProfileStoreFile.MaximumStoredBytes + 1]); }
            catch (IOException) { oversizedOutputRejected = true; }
            check("profile store: oversized output is refused without changing the file",
                oversizedOutputRejected
                && new FileInfo(oversizedPath).Length == ProfileStoreFile.MaximumStoredBytes + 1L);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
