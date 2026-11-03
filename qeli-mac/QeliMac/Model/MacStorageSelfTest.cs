using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliMac.Model;

internal static class MacStorageSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "qeli-mac-storage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string Case(string name) { var p = Path.Combine(root, name); Directory.CreateDirectory(p); return p; }
        void Check(string name, bool ok) => check("mac storage: " + name, ok);
        static bool Fails(Action action)
        {
            try { action(); return false; }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or CryptographicException
                or InvalidOperationException or JsonException or DecoderFallbackException) { return true; }
        }
        var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
        var other = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        ProfileKeyCoordinator Keys(string dir, Func<byte[]?>? find = null,
            Func<byte[], bool, bool>? store = null, Func<byte[]?>? legacy = null,
            Func<bool>? delete = null) => new(dir, find ?? (() => null),
                store ?? ((_, _) => false), legacy ?? (() => null), delete ?? (() => false));
        try
        {
            string dir = Case("fresh-fallback");
            var keys = Keys(dir);
            var first = keys.GetOrCreate();
            Check("fallback survives separate coordinator", first.SequenceEqual(Keys(dir).GetOrCreate()));
            Check("fallback key is exactly 32 bytes", File.ReadAllBytes(Path.Combine(dir, ".store.key")).SequenceEqual(first));
            if (!OperatingSystem.IsWindows())
                Check("fallback created private", File.GetUnixFileMode(Path.Combine(dir, ".store.key"))
                    == (UnixFileMode.UserRead | UnixFileMode.UserWrite));

            dir = Case("keychain-first"); int adds = 0; byte[]? current = null; bool createOnly = false;
            keys = Keys(dir, () => current, (candidate, allowUpdate) =>
            { adds++; createOnly = !allowUpdate; current = candidate.ToArray(); return true; });
            first = keys.GetOrCreate();
            Check("fresh Keychain creation never permits update", createOnly && adds == 1);
            Check("Keychain key is reused", keys.GetOrCreate().SequenceEqual(first) && adds == 1);
            Check("Keychain success needs no fallback", !File.Exists(Path.Combine(dir, ".store.key")));

            dir = Case("duplicate-keychain"); int finds = 0;
            keys = Keys(dir, () => ++finds == 1 ? null : key, (_, _) => false);
            Check("duplicate item adopts verified existing key", keys.GetOrCreate().SequenceEqual(key));
            Check("duplicate item does not create competing fallback", !File.Exists(Path.Combine(dir, ".store.key")));

            dir = Case("keychain-denied"); adds = 0;
            keys = Keys(dir, () => throw new InvalidOperationException("locked"), (_, _) => { adds++; return true; });
            Check("denied Keychain does not look absent", Fails(() => keys.GetOrCreate()));
            Check("denied Keychain never rotates key", adds == 0 && !File.Exists(Path.Combine(dir, ".store.key")));
            File.WriteAllBytes(Path.Combine(dir, ".store.key"), key);
            Check("denied Keychain uses established fallback", keys.GetOrCreate().SequenceEqual(key));

            foreach (var length in new[] { 0, 31, 33, 1024 * 1024 })
            {
                dir = Case("bad-key-" + length); string path = Path.Combine(dir, ".store.key");
                var bad = new byte[length]; File.WriteAllBytes(path, bad); adds = 0;
                Check($"invalid fallback length {length} fails closed",
                    Fails(() => Keys(dir, store: (_, _) => { adds++; return true; }).GetOrCreate()));
                Check($"invalid fallback length {length} retained", adds == 0 && File.ReadAllBytes(path).SequenceEqual(bad));
            }
            dir = Case("bad-keychain");
            Check("malformed Keychain item cannot be replaced", Fails(() => Keys(dir, () => new byte[31]).GetOrCreate()));
            dir = Case("conflicting-keys"); File.WriteAllBytes(Path.Combine(dir, ".store.key"), key);
            Check("fallback and Keychain disagreement fails closed", Fails(() => Keys(dir, () => other).GetOrCreate()));

            foreach (var name in new[] { "profiles.json", "profiles.json.bak" })
            {
                dir = Case("lost-key-" + name); string path = Path.Combine(dir, name);
                var ciphertext = EncryptedEnvelope.Seal("[]"u8, key); File.WriteAllBytes(path, ciphertext);
                Check($"missing key preserves {name}", Fails(() => Keys(dir).GetOrCreate())
                    && File.ReadAllBytes(path).SequenceEqual(ciphertext) && !File.Exists(Path.Combine(dir, ".store.key")));
            }
            dir = Case("nonce-punctuation"); File.WriteAllBytes(Path.Combine(dir, "profiles.json"), "[broken encrypted bytes"u8.ToArray());
            Check("punctuation alone cannot authorize new key", Fails(() => Keys(dir).GetOrCreate()));
            dir = Case("legacy-array"); File.WriteAllText(Path.Combine(dir, "profiles.json"), "[{\"Name\":\"legacy\"}]");
            Check("complete legacy archive permits first key", Keys(dir).GetOrCreate().Length == 32);
            dir = Case("legacy-null"); File.WriteAllText(Path.Combine(dir, "profiles.json"), "[null]");
            Check("invalid legacy archive cannot authorize new key", Fails(() => Keys(dir).GetOrCreate()));

            dir = Case("migration-journal"); string journal = Path.Combine(dir, ".store.key.migration");
            File.WriteAllBytes(journal, key);
            Check("interrupted migration keeps exact key", Keys(dir).GetOrCreate().SequenceEqual(key)
                && File.ReadAllBytes(Path.Combine(dir, ".store.key")).SequenceEqual(key));
            Check("journal removed only after verified fallback", !File.Exists(journal));
            dir = Case("journal-conflict"); journal = Path.Combine(dir, ".store.key.migration"); File.WriteAllBytes(journal, key);
            Check("journal disagreement preserves recovery copy", Fails(() => Keys(dir, () => other).GetOrCreate())
                && File.ReadAllBytes(journal).SequenceEqual(key));
            dir = Case("journal-fallback-conflict");
            File.WriteAllBytes(Path.Combine(dir, ".store.key.migration"), key);
            File.WriteAllBytes(Path.Combine(dir, ".store.key"), other);
            Check("journal cannot overwrite a different fallback", Fails(() => Keys(dir).GetOrCreate())
                && File.ReadAllBytes(Path.Combine(dir, ".store.key")).SequenceEqual(other));
            dir = Case("migration-write-failure");
            File.WriteAllBytes(Path.Combine(dir, ".store.key.migration"), key);
            Directory.CreateDirectory(Path.Combine(dir, ".store.key"));
            Check("migration persistence failure keeps journal", Fails(() => Keys(dir).GetOrCreate())
                && File.ReadAllBytes(Path.Combine(dir, ".store.key.migration")).SequenceEqual(key));
            dir = Case("legacy-acl-denied"); current = null; int deletes = 0;
            keys = Keys(dir, () => current ?? throw new InvalidOperationException("old ACL"),
                (candidate, _) => { current = candidate.ToArray(); return true; }, () => key, () => { deletes++; return true; });
            Check("legacy ACL denial migrates recovered same key", keys.GetOrCreate().SequenceEqual(key) && deletes == 0);

            dir = Case("legacy-base64");
            current = Encoding.UTF8.GetBytes(Convert.ToBase64String(key));
            bool sawJournal = false;
            keys = Keys(dir, () => current, (candidate, update) =>
            {
                sawJournal = update && File.ReadAllBytes(Path.Combine(dir, ".store.key.migration")).SequenceEqual(key);
                current = candidate.ToArray(); return true;
            });
            Check("legacy base64 migration journals before mutation", keys.GetOrCreate().SequenceEqual(key) && sawJournal);
            Check("legacy base64 becomes raw existing key", current.SequenceEqual(key)
                && !File.Exists(Path.Combine(dir, ".store.key.migration")));

            dir = Case("concurrent-fallback");
            var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(() => Keys(dir).GetOrCreate())).ToArray();
            Task.WaitAll(tasks);
            Check("16 concurrent coordinators share one key", tasks.All(t => t.Result.SequenceEqual(tasks[0].Result))
                && File.ReadAllBytes(Path.Combine(dir, ".store.key")).SequenceEqual(tasks[0].Result));
            Check("two independent processes share persisted key", ProcessKeyRace(Case("process-race")));
            Check("sidecar lock contention is bounded", LockRejected(dir));

            dir = Case("archive"); string archive = Path.Combine(dir, "profiles.json");
            var store = new MacProfileArchive(archive, () => key);
            Check("absent archive is empty", store.Load().Count == 0);
            var profile = new VpnConfig { Name = "test", Password = "secret" };
            store.Save(new[] { profile });
            Check("encrypted archive roundtrip and identity", store.Load().Single().Id == profile.Id
                && !Encoding.UTF8.GetString(File.ReadAllBytes(archive)).Contains("secret"));
            var original = File.ReadAllBytes(archive);
            Check("key provider failure does not quarantine archive", Fails(() => new MacProfileArchive(archive,
                () => throw new InvalidOperationException("locked")).Load())
                && File.ReadAllBytes(archive).SequenceEqual(original) && Directory.GetFiles(dir, "*.corrupt-*").Length == 0);
            var stale = new MacProfileArchive(archive, () => key); stale.Load();
            profile.Name = "updated"; store.Save(new[] { profile });
            Check("stale archive write cannot replace winner", Fails(() => stale.Save(new[] { profile }))
                && store.Load().Single().Name == "updated");
            string? winnerName = store.Load().Single().Name;
            Check("failed key acquisition during Save preserves archive", Fails(() => new MacProfileArchive(archive,
                () => throw new InvalidOperationException("locked")).Save(new[] { profile }))
                && store.Load().Single().Name == winnerName);
            var corrupted = File.ReadAllBytes(archive); corrupted[^1] ^= 0x40; File.WriteAllBytes(archive, corrupted);
            Check("corrupt latest restores authenticated backup", store.Load().Single().Name == "test");
            Check("corrupt latest preserved before restore", Directory.GetFiles(dir, "profiles.json.corrupt-*").Length == 1);

            dir = Case("strict-utf8"); archive = Path.Combine(dir, "profiles.json");
            File.WriteAllBytes(archive, EncryptedEnvelope.Seal(new byte[] { 0xff }, key));
            Check("authenticated invalid UTF8 quarantined", new MacProfileArchive(archive, () => key).Load().Count == 0
                && !File.Exists(archive) && Directory.GetFiles(dir, "profiles.json.corrupt-*").Length == 1);
            dir = Case("legacy-migration"); archive = Path.Combine(dir, "profiles.json");
            File.WriteAllText(archive, "[{\"Name\":\"legacy\"}]");
            store = new MacProfileArchive(archive, () => key); var migrated = store.Load();
            Check("legacy archive encrypted and missing ID persisted", migrated.Count == 1
                && store.Load()[0].Id == migrated[0].Id && !Encoding.UTF8.GetString(File.ReadAllBytes(archive)).StartsWith("["));
            dir = Case("migration-save-failure"); archive = Path.Combine(dir, "profiles.json");
            var legacyBytes = Encoding.UTF8.GetBytes("[{\"Name\":\"legacy\"}]"); File.WriteAllBytes(archive, legacyBytes);
            int keyCalls = 0;
            Check("migration Save failure is not corruption", Fails(() => new MacProfileArchive(archive,
                () => ++keyCalls == 1 ? key : throw new InvalidOperationException("save denied")).Load())
                && File.ReadAllBytes(archive).SequenceEqual(legacyBytes)
                && Directory.GetFiles(dir, "profiles.json.corrupt-*").Length == 0);
            Check("explicit null fields cannot be saved", Fails(() => store.Save(new[] { new VpnConfig { Password = null! } })));

            using var exact = new MemoryStream(new byte[32]);
            Check("bounded read accepts exact key", BoundedStorage.Read(exact, 32).Length == 32);
            using var huge = new HugeStream();
            Check("oversized seekable source rejected before read", Fails(() => BoundedStorage.Read(huge, 32)) && huge.ReadBytes == 0);
            using var growing = new EndlessStream();
            Check("growing nonseekable source reads only overflow sentinel", Fails(() => BoundedStorage.Read(growing, 32))
                && growing.ReadBytes == 33);
            using var empty = new MemoryStream();
            Check("zero budget accepts empty", BoundedStorage.Read(empty, 0).Length == 0);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    // Only invoked by storage-selftest children, with an isolated parent-created directory.
    internal static int RunKeyProbe(string directory)
    {
        var key = new ProfileKeyCoordinator(directory, () => null, (_, _) => false,
            () => null, () => false).GetOrCreate();
        Console.WriteLine(Convert.ToHexString(SHA256.HashData(key)));
        return 0;
    }

    private static bool ProcessKeyRace(string directory)
    {
        var children = new List<System.Diagnostics.Process>();
        try
        {
            for (int i = 0; i < 2; i++)
            {
                var start = new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!)
                {
                    UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet", StringComparison.OrdinalIgnoreCase))
                    start.ArgumentList.Add(typeof(MacStorageSelfTest).Assembly.Location);
                start.ArgumentList.Add("storage-selftest"); start.ArgumentList.Add("--key-probe"); start.ArgumentList.Add(directory);
                children.Add(System.Diagnostics.Process.Start(start)!);
            }
            var reads = children.Select(p => (output: p.StandardOutput.ReadToEndAsync(), error: p.StandardError.ReadToEndAsync())).ToArray();
            string expected = "";
            foreach (var p in children)
            {
                if (!p.WaitForExit(15_000)) return false;
                if (p.ExitCode != 0) return false;
            }
            expected = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, ".store.key"))));
            return reads.All(r => r.output.GetAwaiter().GetResult().Trim() == expected && r.error.GetAwaiter().GetResult().Length == 0);
        }
        finally
        {
            foreach (var p in children)
            {
                try { if (!p.HasExited) { p.Kill(entireProcessTree: true); p.WaitForExit(2000); } } catch { }
                p.Dispose();
            }
        }
    }

    private static bool LockRejected(string directory)
    {
        using var held = new FileStream(Path.Combine(directory, ".store.key.lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var wait = System.Diagnostics.Stopwatch.StartNew();
        try { new ProfileKeyCoordinator(directory, () => null, (_, _) => false, () => null, () => false).GetOrCreate(); return false; }
        catch (IOException) { return wait.Elapsed >= TimeSpan.FromMilliseconds(900) && wait.Elapsed < TimeSpan.FromSeconds(3); }
    }

    private class EndlessStream : Stream
    {
        public int ReadBytes;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) { Array.Clear(buffer, offset, count); ReadBytes += count; return count; }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
    private sealed class HugeStream : EndlessStream
    {
        public override bool CanSeek => true;
        public override long Length => 2L * 1024 * 1024 * 1024;
    }
}
