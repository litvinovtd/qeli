using System.Text;
using System.Text.Json;
using QeliMac.Service;

namespace QeliMac.Vpn;

internal static class MacForwardingSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        void Check(string name, bool ok) => check("mac forwarding: " + name, ok);
        static bool Fails(Action action) { try { action(); return false; } catch (Exception e) when (e is IOException or InvalidDataException or InvalidOperationException or AggregateException or JsonException or DecoderFallbackException or ArgumentException) { return true; } }
        var a = new DnsJournal.Owner(100, 1000); var b = new DnsJournal.Owner(200, 2000);
        var token = Guid.NewGuid().ToString("N");
        var x = new Scenario(); var first = x.Journal(a, token);
        first.ReleaseOwned(); Check("unowned release has no storage/kernel effects", x.Events.Count == 0);
        Check("missing stale record has no kernel effects", !first.RecoverStale() && x.Events.SequenceEqual(new[] { "state-read" }));
        x.Events.Clear();
        Check("empty requested family set refuses before storage", Fails(() => first.Enable(false, false)) && x.Events.Count == 0);
        first.Enable(true, true);
        Check("both families enabled with a durable owner", first.Owned && x.Flags.Values.All(v => v) && x.State is not null);
        Check("all snapshots precede journal and every enable", x.Events.Take(4).SequenceEqual(new[] { "state-read", "read:ipv4", "read:ipv6", "publish" }) && x.NativeWritesHadJournal);
        byte[] original = x.State!.ToArray(); int writes = x.Writes;
        first.Enable(true, true);
        Check("idempotent enable preserves original values", x.State.SequenceEqual(original) && x.Writes == writes);
        Check("changed family set cannot overwrite active restore state", Fails(() => first.Enable(true, false)) && x.State.SequenceEqual(original));
        var second = x.Journal(b, Guid.NewGuid().ToString("N"));
        Check("another live process refuses without mutation", Fails(() => second.Enable(true, true)) && !second.Owned && x.State.SequenceEqual(original) && x.Writes == writes);
        var samePid = x.Journal(a, Guid.NewGuid().ToString("N"));
        Check("same PID different tunnel generation cannot acquire", Fails(() => samePid.Enable(true, true)) && !samePid.Owned && x.Writes == writes);
        Check("startup sweep preserves live owner", !second.RecoverStale() && x.State.SequenceEqual(original) && x.Writes == writes);
        first.ReleaseOwned();
        Check("confirmed cleanup restores both families before deleting journal", !first.Owned && x.Flags.Values.All(v => !v) && x.State is null && x.Events.Last() == "delete");
        int events = x.Events.Count; first.ReleaseOwned();
        Check("completed cleanup never runs twice", x.Events.Count == events);

        x = new(); x.Flags["ipv4"] = x.Flags["ipv6"] = true; first = x.Journal(a, token);
        first.Enable(true, true); Check("preexisting forwarding still reserves exclusive ownership", first.Owned && x.State is not null && x.Writes == 0);
        x.Flags["ipv4"] = false; first.ReleaseOwned();
        Check("preexisting and externally disabled values are preserved", !x.Flags["ipv4"] && x.Flags["ipv6"] && x.Writes == 0 && x.State is null);
        x = new(); x.Flags["ipv4"] = true; first = x.Journal(a, token); first.Enable(true, true); first.ReleaseOwned();
        Check("mixed snapshot restores only the family Qeli changed", x.Flags["ipv4"] && !x.Flags["ipv6"] && x.Events.Count(e => e.StartsWith("write:ipv4")) == 0);

        x = new() { Failure = "read:ipv6" }; first = x.Journal(a, token);
        Check("failed initial query cannot publish or activate", Fails(() => first.Enable(true, true)) && !first.Owned && x.State is null && x.Writes == 0);
        x = new() { IgnoreEnable = true }; first = x.Journal(a, token);
        Check("successful command without changed flag is refused and rolled back", Fails(() => first.Enable(true, true)) && !first.Owned && x.State is null && x.Flags.Values.All(v => !v));
        x = new() { Failure = "write:ipv6:1", MutateBeforeFailure = true }; first = x.Journal(a, token);
        Check("partial failing enable is recorded before mutation and rolled back", Fails(() => first.Enable(true, true)) && !first.Owned && x.State is null && x.Flags.Values.All(v => !v));
        x = new(); first = x.Journal(a, token); first.Enable(true, true); x.Failure = "write:ipv4:0";
        Check("failed IPv4 restore still attempts independent IPv6 cleanup", Fails(first.ReleaseOwned) && first.Owned && x.Flags["ipv4"] && !x.Flags["ipv6"] && x.State is not null);
        int ipv6Writes = x.Events.Count(e => e == "write:ipv6:0"); x.Failure = null; first.ReleaseOwned();
        Check("retry restores only the pending family", !first.Owned && !x.Flags["ipv4"] && x.State is null && x.Events.Count(e => e == "write:ipv6:0") == ipv6Writes);
        x = new(); first = x.Journal(a, token); first.Enable(true, true); x.IgnoreRestore = true;
        Check("zero exit without confirmed restore keeps journal", Fails(first.ReleaseOwned) && first.Owned && x.State is not null && x.Flags.Values.All(v => v));
        x.IgnoreRestore = false; first.ReleaseOwned();
        Check("unconfirmed restore remains retryable", !first.Owned && x.State is null && x.Flags.Values.All(v => !v));

        x = new(); first = x.Journal(a, token); first.Enable(true, true); x.Failure = "checkpoint";
        Check("checkpoint failure retains durable recovery after kernel restore", Fails(first.ReleaseOwned) && first.Owned && x.State is not null && x.Flags.Values.All(v => !v));
        writes = x.Writes; x.Failure = null; first.ReleaseOwned();
        Check("checkpoint retry recognizes already restored flags", !first.Owned && x.State is null && x.Writes == writes);
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.Failure = "delete";
        Check("delete failure retains completed journal and owner", Fails(first.ReleaseOwned) && first.Owned && x.State is not null && !x.Flags["ipv4"]);
        writes = x.Writes; x.Failure = null; first.ReleaseOwned();
        Check("final delete retries without another sysctl write", !first.Owned && x.State is null && x.Writes == writes);
        x = new() { PublishRefused = true }; first = x.Journal(a, token);
        Check("exclusive publish collision cannot change kernel state", Fails(() => first.Enable(true, false)) && !first.Owned && x.Writes == 0 && x.State is null);
        x = new() { Failure = "publish" }; first = x.Journal(a, token);
        Check("failed publication with proven absence leaves no false kernel owner", Fails(() => first.Enable(true, false)) && !first.Owned && x.Writes == 0 && x.State is null);
        x = new() { Failure = "publish", PublishBeforeFailure = true }; first = x.Journal(a, token);
        Check("unknown publication outcome re-reads and cleans its own record", Fails(() => first.Enable(true, false)) && !first.Owned && x.Writes == 0 && x.State is null);
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.State = null; writes = x.Writes;
        Check("missing journal after mutation never guesses previous value", Fails(first.ReleaseOwned) && first.Owned && x.Writes == writes && x.Flags["ipv4"]);
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.State = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(x.State!).Replace(token, Guid.NewGuid().ToString("N"))); writes = x.Writes;
        Check("foreign replaced record cannot authorize restore", Fails(first.ReleaseOwned) && first.Owned && x.Writes == writes);

        x = new(); first = x.Journal(a, token); first.Enable(true, true); x.Live = false;
        second = x.Journal(b, Guid.NewGuid().ToString("N"));
        Check("restart recovers dead owner from durable values", second.RecoverStale() && x.State is null && x.Flags.Values.All(v => !v));
        Check("repeat stale sweep is a no-op", !second.RecoverStale());
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.Live = false;
        second = x.Journal(b, Guid.NewGuid().ToString("N")); second.Enable(true, false); second.ReleaseOwned();
        Check("new acquisition restores stale baseline before taking its snapshot", !x.Flags["ipv4"] && x.State is null);

        foreach (string corrupt in new[] { "{}", "null", "{\"Version\":1}",
            $"{{\"Version\":1,\"Version\":1,\"Pid\":100,\"StartTicks\":1000,\"Token\":\"{token}\",\"Families\":[{{\"Name\":\"ipv4\",\"WasOn\":false,\"Pending\":true}}]}}" }) {
            x = new() { State = Encoding.UTF8.GetBytes(corrupt), Live = false }; first = x.Journal(a, token);
            Check("ambiguous/missing metadata refuses without kernel mutation", Fails(() => first.RecoverStale()) && x.Writes == 0 && x.State is not null);
        }
        foreach (var corrupt in new[] { Array.Empty<byte>(), new byte[4097], new byte[] { 255 } }) {
            x = new() { State = corrupt, Live = false }; first = x.Journal(a, token);
            Check("empty/oversized/invalid UTF8 journal stays intact", Fails(() => first.RecoverStale()) && x.Writes == 0 && x.State is not null);
        }
        x = new(); first = x.Journal(a, token); first.Enable(true, true); original = x.State!; first.ReleaseOwned();
        foreach (string corrupt in new[] {
            Encoding.UTF8.GetString(original).Replace("\"Version\": 1", "\"Version\": 2"),
            Encoding.UTF8.GetString(original).Replace("\"Name\": \"ipv6\"", "\"Name\": \"ipv4\""),
            Encoding.UTF8.GetString(original).Replace("\"Pending\": true", "\"Pending\": null"),
            Encoding.UTF8.GetString(original).Replace("\"WasOn\": false", "\"WasOn\": true") }) {
            x = new() { State = Encoding.UTF8.GetBytes(corrupt), Live = false }; first = x.Journal(a, token);
            Check("invalid schema/family/restore contract refuses", Fails(() => first.RecoverStale()) && x.Writes == 0 && x.State is not null);
        }
        x = new() { ThrowLog = true }; first = x.Journal(a, token); first.Enable(true, false); first.ReleaseOwned();
        Check("observer exception cannot undo completed ownership release", !first.Owned && x.State is null && !x.Flags["ipv4"]);
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.Failure = "delete"; x.DeleteBeforeFailure = true;
        Check("unknown deletion outcome keeps verified restore progress", Fails(first.ReleaseOwned) && first.Owned && x.State is null && !x.Flags["ipv4"]);
        x.Failure = null; writes = x.Writes; first.ReleaseOwned();
        Check("retry accepts absent record only after proven restore", !first.Owned && x.Writes == writes);
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.Failure = "delete"; x.DeleteBeforeFailure = true;
        Fails(first.ReleaseOwned); x.Failure = null; second = x.Journal(b, Guid.NewGuid().ToString("N")); second.Enable(true, false);
        original = x.State!.ToArray(); writes = x.Writes; first.ReleaseOwned();
        Check("old completed cleanup cannot erase subsequent owner", !first.Owned && second.Owned && x.State.SequenceEqual(original) && x.Writes == writes && x.Flags["ipv4"]);
        second.ReleaseOwned();
        x = new(); first = x.Journal(a, token); first.Enable(true, false); x.CheckpointRefused = true;
        Check("false checkpoint outcome retains record and responsibility", Fails(first.ReleaseOwned) && first.Owned && x.State is not null && !x.Flags["ipv4"]);
        x.CheckpointRefused = false; writes = x.Writes; first.ReleaseOwned();
        Check("false checkpoint outcome retries without kernel rewrites", !first.Owned && x.State is null && x.Writes == writes);
        var current = ForwardingJournal.CurrentOwner();
        using (var process = System.Diagnostics.Process.GetCurrentProcess())
            Check("production owner timestamp uses UTC process start", current.Pid == process.Id && current.StartTicks == process.StartTime.ToUniversalTime().Ticks);
        Check("production owner probe recognizes live generation", ForwardingJournal.OwnerAlive(current));
        Check("production owner probe rejects wrong start generation", !ForwardingJournal.OwnerAlive(new(current.Pid, current.StartTicks - 1)));
        CheckFileRecovery(Check, a, b, token);
        CheckSerialization(Check, a, b, token);
    }

    private static void CheckFileRecovery(Action<string, bool> check, DnsJournal.Owner a, DnsJournal.Owner b, string token) {
        var directory = Directory.CreateTempSubdirectory("qeli-forwarding-fixture-");
        string path = Path.Combine(directory.FullName, "state.json"); bool flag = false;
        try {
            byte[]? Read() { try { using var file = File.OpenRead(path); if (file.Length > ForwardingJournal.MaximumBytes) throw new InvalidDataException(); return File.ReadAllBytes(path); } catch (FileNotFoundException) { return null; } }
            bool Save(byte[] bytes, bool replace) { if (!replace) { using var file = new FileStream(path, FileMode.CreateNew); file.Write(bytes); file.Flush(true); } else File.WriteAllBytes(path, bytes); return true; }
            var operation = new ServiceControlLock(() => new FileStream(Path.Combine(directory.FullName, "lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
            ForwardingJournal Journal(DnsJournal.Owner owner, string key, bool live) => new(Read, Save, () => File.Delete(path), _ => flag, (_, value) => flag = value, _ => live, owner, key, operation.Enter, _ => {});
            var old = Journal(a, token, true); old.Enable(true, false);
            check("file-backed snapshot survives loss of old coordinator", flag && File.Exists(path));
            var restarted = Journal(b, Guid.NewGuid().ToString("N"), false);
            check("new coordinator recovers file-backed pre-crash snapshot", restarted.RecoverStale() && !flag && !File.Exists(path));
        }
        finally { File.Delete(path); File.Delete(Path.Combine(directory.FullName, "lock")); directory.Delete(); }
    }
    private static void CheckSerialization(Action<string, bool> check, DnsJournal.Owner a, DnsJournal.Owner b, string token) {
        var x = new Scenario(); using var entered = new ManualResetEventSlim(); using var resume = new ManualResetEventSlim();
        x.OnPublish = () => { entered.Set(); if (!resume.Wait(TimeSpan.FromSeconds(5))) throw new IOException("test barrier timeout"); };
        var first = x.Journal(a, token); var second = x.Journal(b, Guid.NewGuid().ToString("N"));
        var t1 = Task.Run(() => first.Enable(true, false));
        if (!entered.Wait(TimeSpan.FromSeconds(5))) { resume.Set(); t1.GetAwaiter().GetResult(); throw new IOException("test publication timeout"); }
        var t2 = Task.Run(() => { try { second.Enable(true, false); return false; } catch (IOException) { return true; } });
        try { check("second acquisition waits for complete first transaction", !t2.Wait(150)); }
        finally { resume.Set(); }
        Task.WaitAll(t1, t2); check("serialized contender observes live ownership before writes", t2.Result && !second.Owned && first.Owned && x.Writes == 1);
        first.ReleaseOwned();
    }
    private sealed class Scenario {
        internal byte[]? State;
        internal readonly Dictionary<string, bool> Flags = new() { ["ipv4"] = false, ["ipv6"] = false };
        internal readonly List<string> Events = new();
        internal bool Live = true, IgnoreEnable, IgnoreRestore, MutateBeforeFailure, PublishRefused, PublishBeforeFailure, NativeWritesHadJournal = true, ThrowLog, DeleteBeforeFailure, CheckpointRefused;
        internal string? Failure;
        internal int Writes;
        internal Action? OnPublish;
        private readonly object _gate = new();
        private sealed class Lease(object gate) : IDisposable { public void Dispose() => Monitor.Exit(gate); }
        internal ForwardingJournal Journal(DnsJournal.Owner owner, string token) => new(
            () => { Event("state-read"); return State?.ToArray(); },
            (bytes, replace) => { string step = replace ? "checkpoint" : "publish"; Events.Add(step); if (!replace && PublishRefused || replace && CheckpointRefused) return false;
                if (!replace && PublishBeforeFailure) State = bytes.ToArray();
                if (Failure == step) throw new IOException(step); State = bytes.ToArray(); if (!replace) OnPublish?.Invoke(); return true; },
            () => { if (DeleteBeforeFailure) State = null; Event("delete"); State = null; },
            name => { Event("read:" + name); return Flags[name]; },
            (name, value) => { string step = $"write:{name}:{(value ? 1 : 0)}"; Events.Add(step); Writes++; NativeWritesHadJournal &= State is not null;
                if (value && MutateBeforeFailure) Flags[name] = value;
                if (Failure == step) throw new IOException(step);
                if (!(value ? IgnoreEnable : IgnoreRestore)) Flags[name] = value; },
            _ => Live, owner, token,
            () => { Monitor.Enter(_gate); return new Lease(_gate); }, _ => { if (ThrowLog) throw new IOException("observer"); });
        private void Event(string step) { Events.Add(step); if (Failure == step) throw new IOException(step); }
    }
}
