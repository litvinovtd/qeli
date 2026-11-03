using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;
using QeliMac.Model;

namespace QeliMac.Service;

internal static class ServiceControlSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        void Check(string name, bool ok) => check("mac daemon: " + name, ok);
        static bool Fails(Action action)
        {
            try { action(); return false; }
            catch (Exception error) when (error is IOException or InvalidDataException or InvalidOperationException or JsonException
                or CryptographicException or DecoderFallbackException or System.Xml.XmlException) { return true; }
        }
        var key = Enumerable.Repeat((byte)90, 32).ToArray();
        var first = new VpnConfig { Id = "first", Name = "first", Password = "secret" };
        var second = new VpnConfig { Id = "second", Name = "second", ServerAddress = "192.0.2.2" };
        var encoded = ServiceProfileCodec.Encode(first, key);
        Check("authenticated profile roundtrip", ServiceProfileCodec.Decode(encoded, key, out bool migrate).Id == first.Id && !migrate);
        Check("daemon rejects plaintext profile", Fails(() => ServiceProfileCodec.Decode(ServiceProfileCodec.Plaintext(first), key, out _)));
        Check("daemon rejects ciphertext corruption", Fails(() => { var bad = encoded.ToArray(); bad[^1] ^= 1; ServiceProfileCodec.Decode(bad, key, out _); }));
        Check("daemon rejects truncated ciphertext", Fails(() => ServiceProfileCodec.Decode(encoded[..12], key, out _)));
        Check("daemon rejects required nulls", Fails(() => ServiceProfileCodec.Encode(new VpnConfig { Password = null! }, key)));
        Check("daemon rejects invalid authenticated UTF8", Fails(() => ServiceProfileCodec.Decode(EncryptedEnvelope.Seal(new byte[] { 255 }, key), key, out _)));
        var plain = ServiceProfileCodec.Plaintext(first);
        Check("digest-bound handoff preserves selected profile", ServiceProfileCodec.Handoff(plain, SHA256.HashData(plain)).Id == first.Id);
        Check("modified handoff cannot publish", Fails(() => ServiceProfileCodec.Handoff(plain, new byte[32])));
        Check("invalid handoff digest size rejected", Fails(() => ServiceProfileCodec.Handoff(plain, new byte[31])));
        Check("null handoff fields rejected", Fails(() => { var bytes = "{\"Password\":null}"u8.ToArray(); ServiceProfileCodec.Handoff(bytes, SHA256.HashData(bytes)); }));
        Check("invalid handoff UTF8 rejected", Fails(() => { var bytes = new byte[] { 255 }; ServiceProfileCodec.Handoff(bytes, SHA256.HashData(bytes)); }));
        Check("oversized profile rejected", Fails(() => ServiceProfileCodec.Encode(new VpnConfig { Password = new string('x', ServiceProfileCodec.MaximumBytes) }, key)));

        bool requestedKey = false;
        Check("oversized proposal rejected before any key side effect", Fails(() =>
            ServiceProfileCodec.Encode(new VpnConfig { Password = new string('x', ServiceProfileCodec.MaximumBytes) },
                () => { requestedKey = true; return key; })) && !requestedKey);

        Scenario Case(bool desired = true, bool installed = true) => new(first, desired, installed);
        var scenario = Case(); scenario.Transition.Apply(second, false);
        Check("changed running profile stops before publish/restart", scenario.Events.SequenceEqual(new[] { "validate", "stop", "publish", "start" }) && scenario.Active?.Id == second.Id);
        scenario = Case(false); scenario.Transition.Apply(second, false);
        Check("changed idle profile retains disconnect intent", scenario.Events.SequenceEqual(new[] { "validate", "stop", "publish" }) && !scenario.Desired);
        scenario = Case(false); scenario.Transition.Apply(first, false);
        Check("unchanged idle settings never reconnect", scenario.Events.SequenceEqual(new[] { "validate" }) && !scenario.Desired);
        scenario.Transition.Apply(first, true);
        Check("explicit Connect resumes same profile", scenario.Active?.Id == first.Id && scenario.Desired);
        scenario = Case(false, false); scenario.Transition.Apply(second, false);
        Check("fresh install publishes before load", scenario.Events.SequenceEqual(new[] { "publish", "install", "start" }) && scenario.Active?.Id == second.Id);
        scenario = Case(); scenario.Failure = "stop";
        Check("failed joined stop refuses new profile", Fails(() => scenario.Transition.Apply(second, false)) && scenario.Stored?.Id == first.Id && !scenario.Events.Contains("publish"));
        scenario = Case(); scenario.Failure = "publish";
        Check("failed publish cannot restart previous profile", Fails(() => scenario.Transition.Apply(second, false)) && scenario.Active is null && !scenario.Events.Contains("start"));
        scenario = Case(); scenario.Failure = "validate";
        Check("untrusted registration refuses before mutation", Fails(() => scenario.Transition.Apply(second, false)) && scenario.Events.SequenceEqual(new[] { "validate" }));
        scenario = Case();
        Check("invalid proposal cannot stop live daemon", Fails(() => scenario.Transition.Apply(new VpnConfig { Password = null! }, false)) && !scenario.Events.Contains("stop"));
        scenario = Case(); scenario.Failure = "read";
        Check("profile IO failure refuses replacement", Fails(() => scenario.Transition.Apply(second, false)) && scenario.Active?.Id == first.Id);
        var copy = ServiceProfileTransition.Snapshot(first, "debug");
        Check("profile snapshot keeps ID and isolates logging edit", copy.Id == first.Id && copy.LoggingLevel == "debug" && first.LoggingLevel != "debug");
        var settings = new AppSettings { Language = "en", ServiceEnabled = true };
        var proposed = AppSettings.Snapshot(settings); proposed.Language = "ru"; proposed.ServiceEnabled = false;
        Check("settings snapshot does not mutate live state", settings.Language == "en" && settings.ServiceEnabled && proposed.Language == "ru");

        int starts = 0, stops = 0, loads = 0;
        var lifecycle = new DaemonLifecycle(() => { loads++; throw new InvalidDataException("profile invalid"); }, _ => { starts++; return true; }, () => stops++, _ => {}, _ => {});
        lifecycle.Step(true); lifecycle.Step(true);
        Check("profile read failure remains Error and does not loop starts", lifecycle.Snapshot.status == VpnStatus.Error && loads == 1 && starts == 0);
        lifecycle.Shutdown();
        Check("shutdown after rejected profile confirms idle state without network cleanup",
            lifecycle.Snapshot.status == VpnStatus.Disconnected && stops == 0);
        lifecycle = new(() => first, _ => false, () => stops++, _ => {}, _ => {}); lifecycle.Step(true);
        Check("Start refusal remains Error", lifecycle.Snapshot.status == VpnStatus.Error && !lifecycle.Started);
        stops = 0; lifecycle.Shutdown();
        Check("partial refused Start still cleans on shutdown", stops == 1 && lifecycle.Snapshot.status == VpnStatus.Disconnected);
        stops = 0;
        lifecycle = new(() => first, _ => throw new IOException("partial start"), () => stops++, _ => {}, _ => {});
        lifecycle.Step(true); lifecycle.Shutdown();
        Check("throwing partial Start retains cleanup responsibility", stops == 1 && lifecycle.Snapshot.status == VpnStatus.Disconnected);
        bool failStop = true; starts = 0; stops = 0;
        lifecycle = new(() => first, _ => { starts++; return true; }, () => { stops++; if (failStop) throw new IOException("DNS restore failed"); }, _ => {}, _ => {});
        lifecycle.Step(true); lifecycle.Observe(VpnStatus.Connected, "ready"); lifecycle.Step(false);
        Check("failed cleanup retries exactly three times", stops == 3 && lifecycle.Snapshot.status == VpnStatus.Error);
        lifecycle.Observe(VpnStatus.Connected, "late callback");
        Check("late worker callback cannot erase cleanup Error", lifecycle.Snapshot.status == VpnStatus.Error && lifecycle.Snapshot.extra!.Contains("DNS restore failed"));
        lifecycle.Step(true);
        Check("failed cleanup refuses restart and network polling", starts == 1 && !lifecycle.CanPoll);
        Check("shutdown with surviving ownership refuses false success", Fails(lifecycle.Shutdown) && lifecycle.Snapshot.status == VpnStatus.Error);
        VpnStatus published = VpnStatus.Disconnected; string? publishedDetail = null;
        lifecycle.Publish((state, detail) => { published = state; publishedDetail = detail; });
        Check("final publication retains failed shutdown status and detail", published == VpnStatus.Error && publishedDetail?.Contains("disconnect incomplete") == true);
        failStop = false; lifecycle.Step(false);
        Check("successful cleanup clears ownership and Error", !lifecycle.Started && lifecycle.Snapshot.status == VpnStatus.Disconnected);
        lifecycle.Step(true);
        Check("explicit disconnect/reconnect restarts after cleanup", starts == 2 && lifecycle.Started);
        Parallel.For(0, 64, i => lifecycle.Observe(i % 2 == 0 ? VpnStatus.Connected : VpnStatus.Connecting, i % 2 == 0 ? "Connected" : "Connecting"));
        var pair = lifecycle.Snapshot;
        Check("worker status and detail remain one synchronized pair", pair.status.ToString() == pair.extra);

        var now = DateTime.UtcNow;
        var status = new ServiceStatus { Status = "Connected", Time = now, BytesUp = 2, BytesDown = 3 };
        Check("fresh daemon status reports connection", ServiceObservation.Resolve(status, now).Status == VpnStatus.Connected);
        status.Time = now.AddSeconds(6);
        Check("future daemon timestamp is not fresh", ServiceObservation.Resolve(status, now).Status == VpnStatus.Error);
        status.Time = now.AddSeconds(-6);
        Check("stale Connected is unknown Error", ServiceObservation.Resolve(status, now).Status == VpnStatus.Error);
        status.Status = "Error"; status.Extra = "cleanup incomplete";
        Check("stale terminal cleanup Error remains visible", ServiceObservation.Resolve(status, now).Extra == "cleanup incomplete");
        var idle = new ServiceStatus { Status = "Disconnected", Time = now.AddSeconds(-60) };
        Check("stale Disconnected from a running daemon is unknown Error", ServiceObservation.Resolve(idle, now).Status == VpnStatus.Error);
        idle.Stopped = true;
        Check("completed Stop stays Disconnected after the daemon exits", ServiceObservation.Resolve(idle, now).Status == VpnStatus.Disconnected);
        status.Stopped = true; status.Status = "Connected";
        Check("Stopped marker cannot vouch for a stale Connected", ServiceObservation.Resolve(status, now).Status == VpnStatus.Error);
        Check("Stopped marker roundtrips through the status codec", DesktopServiceStatus.Decode<ServiceStatus>(
            JsonSerializer.SerializeToUtf8Bytes(idle)).Stopped);
        Check("missing status is unknown rather than disconnected",ServiceObservation.Resolve(null, now).Status == VpnStatus.Error);
        foreach (var invalid in new[] { "99", "1", "connected", "future-state" })
        {
            status = new() { Status = invalid, Time = now };
            Check($"invalid status {invalid} rejected", Fails(() => DesktopServiceStatus.Decode<ServiceStatus>(JsonSerializer.SerializeToUtf8Bytes(status))));
        }
        status = new() { Status = "Connected", Time = now, BytesDown = -1 };
        Check("negative counters rejected", Fails(() => DesktopServiceStatus.Validate(status)));
        status = new() { Status = "Connected", Time = default };
        Check("missing heartbeat timestamp rejected", Fails(() => DesktopServiceStatus.Validate(status)));
        Check("invalid status UTF8 rejected", Fails(() => DesktopServiceStatus.Decode<ServiceStatus>(new byte[] { 255 })));
        Check("appended log emits suffix once", ServiceObservation.LogDelta("old\n", "old\nnew\n") == "new\n");
        Check("same-size rotation is not missed", ServiceObservation.LogDelta("old\n", "new\n") == "new\n");
        Check("unchanged log emits nothing", ServiceObservation.LogDelta("same", "same") == "");
        var log = ServiceState.EncodeLogLine(new string('x', 16383) + "😀" + new string('x', 5), now);
        Check("log truncation preserves valid Unicode", new UTF8Encoding(false, true).GetString(log).Contains("[truncated]") && log.Length < 64 * 1024);

        string exe = "/Applications/Qeli & test.app/Contents/MacOS/QeliMac";
        string plist = $"<plist version=\"1.0\"><dict><key>Label</key><string>{ServiceManager.ServiceName}</string><key>ProgramArguments</key><array><string>{PlistRegistration.Escape(exe)}</string><string>--service</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>";
        PlistRegistration.Validate(Encoding.UTF8.GetBytes(plist), ServiceManager.ServiceName, exe);
        Check("escaped executable path roundtrips plist", true);
        foreach (var mutation in new[] {
            plist.Replace("--service", "--other"), plist.Replace("--service</string>", "--service</string><string>extra</string>"),
            plist.Replace("<key>KeepAlive", "<key>Program</key><string>/tmp/foreign</string><key>KeepAlive"),
            plist.Replace("<key>KeepAlive", "<key>UserName</key><string>user</string><key>KeepAlive"),
            plist.Replace("<key>KeepAlive", "<key>EnvironmentVariables</key><dict/><key>KeepAlive"),
            plist.Replace("<key>KeepAlive", "<key>Label</key><string>duplicate</string><key>KeepAlive") })
            Check("foreign/duplicate/override plist rejected", Fails(() => PlistRegistration.Validate(Encoding.UTF8.GetBytes(mutation), ServiceManager.ServiceName, exe)));
        Check("oversized plist rejected", Fails(() => PlistRegistration.Validate(new byte[1024 * 1024 + 1], ServiceManager.ServiceName, exe)));
        string absent = $"Could not find service \"{ServiceManager.ServiceName}\" in domain for system";
        Check("exact service absence is recognized", ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", absent, 113));
        Check("macOS 27 prefixed service absence is recognized", ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", "Bad request.\n" + absent + "\n", 113));
        Check("unknown prefix cannot authorize cleanup", !ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", "Operation not permitted\n" + absent, 113));
        Check("permission error cannot authorize cleanup",!ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", "permission denied", 5));
        Check("query timeout cannot authorize cleanup", !ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", absent, -1));
        Check("foreign service absence cannot authorize cleanup", !ServiceManager.ConfirmsAbsent("system/" + ServiceManager.ServiceName, "", absent.Replace(ServiceManager.ServiceName, "other"), 113));

        string dir = Path.Combine(Path.GetTempPath(), "qeli-daemon-key-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, ".service.key");
            byte[]? Read() => File.Exists(path) ? File.ReadAllBytes(path) : null;
            bool Publish(byte[] bytes) => ServiceKeySelection.PublishExclusiveFile(path, bytes);
            Check("missing daemon key never generated during Load", Fails(() => ServiceKeySelection.Get(Read, Publish, false)) && !File.Exists(path));
            var created = ServiceKeySelection.Get(Read, Publish, true);
            Check("explicit Save creates persisted daemon key", created.SequenceEqual(File.ReadAllBytes(path)));
            Check("exclusive key publication refuses replacement", !Publish(new byte[32]) && Read()!.SequenceEqual(created));
            File.Delete(path); using var barrier = new Barrier(2); int reads = 0;
            byte[]? RacingRead() { if (Interlocked.Increment(ref reads) <= 2) { barrier.SignalAndWait(TimeSpan.FromSeconds(5)); return null; } return Read(); }
            var a = Task.Run(() => ServiceKeySelection.Get(RacingRead, Publish, true));
            var b = Task.Run(() => ServiceKeySelection.Get(RacingRead, Publish, true)); Task.WaitAll(a, b);
            Check("racing key creators both use actual atomic winner", a.Result.SequenceEqual(b.Result) && a.Result.SequenceEqual(Read()!));
            bool racesAgree = true;
            for (int round = 0; round < 32; round++)
            {
                File.Delete(path);
                using var start = new Barrier(4);
                int firstReads = 0, winners = 0;
                byte[]? ReadTogether()
                {
                    if (Interlocked.Increment(ref firstReads) <= 4)
                    {
                        if (!start.SignalAndWait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Key creator barrier timed out");
                        return null;
                    }
                    return Read();
                }
                bool CountPublish(byte[] bytes)
                {
                    bool won = Publish(bytes);
                    if (won) Interlocked.Increment(ref winners);
                    return won;
                }
                var creators = Enumerable.Range(0, 4).Select(_ => Task.Factory.StartNew(
                    () => ServiceKeySelection.Get(ReadTogether, CountPublish, true),
                    CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
                Task.WaitAll(creators);
                var winner = Read()!;
                racesAgree &= winners == 1 && creators.All(t => t.Result.SequenceEqual(winner));
            }
            Check("repeated four-way key publication has one immutable winner", racesAgree);
            Check("key publication removes all private temporary files", Directory.GetFiles(dir).Length == 1);
            if (!OperatingSystem.IsWindows())
            {
                Check("published key retains private Unix permissions", File.GetUnixFileMode(path) == (UnixFileMode.UserRead | UnixFileMode.UserWrite));
                File.Delete(path);
                File.CreateSymbolicLink(path, Path.Combine(dir, "missing-target"));
                Check("dangling key symlink cannot be replaced", !Publish(new byte[32]) && new FileInfo(path).LinkTarget != null);
                File.Delete(path);
            }
            File.WriteAllBytes(path, new byte[31]);
            Check("corrupt daemon key never overwritten", Fails(() => ServiceKeySelection.Get(Read, Publish, true)) && Read()!.Length == 31);
            Check("unpersisted daemon key never returned", Fails(() => ServiceKeySelection.Get(() => null, _ => false, true)));
        }
        finally { Directory.Delete(dir, true); }
        string lockDir = Path.Combine(Path.GetTempPath(), "qeli-control-lock-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(lockDir);
        try
        {
            IDisposable Acquire() => new FileStream(Path.Combine(lockDir, "control.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var firstLock = new ServiceControlLock(Acquire, 100);
            var otherLock = new ServiceControlLock(Acquire, 100);
            using (firstLock.Enter())
            {
                using (firstLock.Enter()) Check("nested control operation reuses owning lease", true);
                var watch = Stopwatch.StartNew();
                Check("competing control operation refuses within budget", Fails(() => { using var lease = otherLock.Enter(); }) && watch.Elapsed < TimeSpan.FromSeconds(2));
            }
            using (otherLock.Enter()) Check("completed outer control operation releases ownership", true);
            try { using var lease = firstLock.Enter(); throw new IOException("operation failed"); } catch (IOException) { }
            using (otherLock.Enter()) Check("failed control operation releases ownership", true);
        }
        finally { Directory.Delete(lockDir, true); }
        RunStatusTransitions(Check);
        RunTools(Check);
    }

    private static void RunStatusTransitions(Action<string, bool> check)
    {
        static bool Fails(Action action) { try { action(); return false; } catch { return true; } }
        var now = DateTime.UtcNow;
        ServiceStatus snapshot = new() { Status = "Disconnected", Time = now.AddMinutes(-1), Stopped = true };
        var events = new List<string>();
        void Invalidate()
        {
            events.Add("invalidate");
            snapshot = new() { Status = "Connecting", Time = now };
        }
        ServiceStatusTransition.BeginStart(Invalidate, () => events.Add("enable"));
        check("start invalidates completed Stop before enabling connection",
            events.SequenceEqual(new[] { "invalidate", "enable" }) && !snapshot.Stopped);
        check("startup with no daemon heartbeat becomes unknown, not permanently Disconnected",
            ServiceObservation.Resolve(snapshot, now.AddMinutes(1)).Status == VpnStatus.Error);
        bool enabled = false;
        check("failed required status invalidation refuses new connection",
            Fails(() => ServiceStatusTransition.BeginStart(() => throw new IOException("status write failed"), () => enabled = true)) && !enabled);
        snapshot = new() { Status = "Disconnected", Time = now.AddMinutes(-1), Stopped = true };
        check("failed intent write cannot retain old completed Stop receipt",
            Fails(() => ServiceStatusTransition.BeginStart(Invalidate, () => throw new IOException("intent failed"))) && !snapshot.Stopped);

        var writes = new List<(VpnStatus status, string? detail, bool stopped)>();
        void Publish(VpnStatus status, string? detail, bool stopped) => writes.Add((status, detail, stopped));
        var terminal = new ServiceStatus { Status = "Disconnected", Time = now };
        int recovered = 0;
        ServiceStatusTransition.CompleteStop(new Action[] { () => recovered++, () => recovered++, () => recovered++ }, () => terminal, Publish);
        check("completed Stop checks all network recoveries before publishing persistent disconnect",
            recovered == 3 && writes.Count == 1 && writes[0] == (VpnStatus.Disconnected, null, true));
        foreach (var failedJournal in new[] { "DNS", "firewall", "forwarding" })
        {
            writes.Clear(); recovered = 0;
            var recoveries = new[] { "DNS", "firewall", "forwarding" }.Select<string, Action>(name => () =>
            {
                recovered++;
                if (name == failedJournal) throw new IOException(name + " recovery incomplete");
            }).ToArray();
            check(failedJournal + " recovery failure cannot publish completed Stop",
                Fails(() => ServiceStatusTransition.CompleteStop(recoveries, () => terminal, Publish)) && recovered == 3
                && writes.Count == 1 && writes[0].status == VpnStatus.Error && !writes[0].stopped
                && writes[0].detail!.Contains(failedJournal));
        }
        writes.Clear();
        terminal.Status = "Error"; terminal.Extra = "disconnect incomplete: route cleanup failed";
        check("daemon cleanup Error survives successful journal recovery",
            Fails(() => ServiceStatusTransition.CompleteStop(Array.Empty<Action>(), () => terminal, Publish))
            && writes.Count == 1 && writes[0] == (VpnStatus.Error, terminal.Extra, false));
        foreach (var unknownStatus in new ServiceStatus?[] { null,
            new() { Status = "Connected", Time = now.AddMinutes(-1) },
            new() { Status = "Connecting", Time = now.AddMinutes(-1) } })
        {
            writes.Clear();
            check("missing or unsettled daemon status cannot confirm clean shutdown",
                Fails(() => ServiceStatusTransition.CompleteStop(Array.Empty<Action>(), () => unknownStatus, Publish))
                && writes.Count == 1 && writes[0].status == VpnStatus.Error && !writes[0].stopped);
        }
        writes.Clear();
        check("unreadable terminal status cannot authorize completed Stop",
            Fails(() => ServiceStatusTransition.CompleteStop(Array.Empty<Action>(), () => throw new IOException("status read failed"), Publish))
            && writes.Count == 1 && writes[0].status == VpnStatus.Error && !writes[0].stopped);
        writes.Clear(); terminal.Status = "Disconnected"; terminal.Extra = null;
        check("failed required Stop publication is an error, not successful disconnect",
            Fails(() => ServiceStatusTransition.CompleteStop(Array.Empty<Action>(), () => terminal, (status, detail, stopped) =>
            {
                if (stopped) throw new IOException("status write failed");
                Publish(status, detail, stopped);
            })) && writes.Count == 1 && writes[0].status == VpnStatus.Error && !writes[0].stopped);
        check("failed error publication cannot swallow failed recovery",
            Fails(() => ServiceStatusTransition.CompleteStop(new Action[] { () => throw new IOException("firewall") },
                () => terminal, (_, _, _) => throw new IOException("storage"))));
    }

    private static void RunTools(Action<string, bool> check)
    {
        // Actual child processes, no launchctl/osascript/service operations.
        string shell = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh";
        ProcessStartInfo Start(string script)
        {
            var start = new ProcessStartInfo(shell);
            if (OperatingSystem.IsWindows()) { start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-Command"); }
            else start.ArgumentList.Add("-c");
            start.ArgumentList.Add(script); return start;
        }
        var result = ToolProcess.Run(Start(OperatingSystem.IsWindows()
            ? "[Console]::Out.Write(('o'*32768)); [Console]::Error.Write(('e'*32768)); exit 7"
            : "head -c 32768 /dev/zero | tr '\\0' o; head -c 32768 /dev/zero | tr '\\0' e >&2; exit 7"), 10000);
        check("real dual-pipe child output drains and keeps nonzero exit", result.ExitCode == 7 && result.Output.Length == 32768 && result.Error.Length == 32768);
        bool refused = false; try { ToolProcess.RequireSuccess(result, "probe"); } catch (InvalidOperationException) { refused = true; }
        check("tool nonzero exit cannot report success", refused);
        var elapsed = Stopwatch.StartNew();
        result = ToolProcess.Run(Start(OperatingSystem.IsWindows() ? "Start-Sleep -Seconds 20" : "sleep 20"), 400);
        check("stalled child bounded by deadline", result.ExitCode == -1 && elapsed.Elapsed < TimeSpan.FromSeconds(5));
        result = ToolProcess.Run(Start(OperatingSystem.IsWindows() ? "[Console]::Out.Write(('o'*131072))" : "head -c 131072 /dev/zero"), 5000, maximumChars: 4096);
        check("tool output allocation is capped", result.ExitCode == -1);
        elapsed.Restart();
        result = ToolProcess.Run(Start(OperatingSystem.IsWindows() ? "exit 0" : "exit 0"), 800, () => false);
        check("zero command exit cannot bypass outcome verification", result.ExitCode == -1 && elapsed.Elapsed < TimeSpan.FromSeconds(5));
        result = ToolProcess.Run(Start(OperatingSystem.IsWindows() ? "Start-Sleep -Seconds 20" : "sleep 20"), 5000, () => true);
        check("verified outcome can finish a stalled query", result.ExitCode == 0);
        elapsed.Restart();
        result = ToolProcess.Run(Start("exit 7"), 5000, () => elapsed.ElapsedMilliseconds > 500);
        check("nonzero query exit can succeed only after confirmed outcome", result.ExitCode == 0 && elapsed.ElapsedMilliseconds >= 500);
        bool missing = false;
        try { ToolProcess.Run(new ProcessStartInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".missing"))); }
        catch (System.ComponentModel.Win32Exception) { missing = true; }
        check("process launch failure is observable", missing);
    }

    private sealed class Scenario
    {
        internal readonly List<string> Events = new();
        internal bool Exists, Desired;
        internal VpnConfig? Stored, Active;
        internal string? Failure;
        internal readonly DesktopServiceProfileTransition Transition;
        internal Scenario(VpnConfig first, bool desired, bool exists)
        {
            Desired = desired; Exists = exists; Stored = exists ? first : null; Active = exists && desired ? first : null;
            void Event(string action) { Events.Add(action); if (Failure == action) throw new IOException(action); }
            Transition = new(() => Exists, () => Desired,
                () => { if (Failure == "read") throw new IOException("read failed"); return Stored; },
                () => { Event("stop"); Active = null; Desired = false; },
                bytes => { Event("publish"); Stored = ServiceProfileCodec.DecodePlaintext(bytes); },
                () => { Event("install"); Exists = true; },
                () => { Event("start"); Desired = true; Active = Stored; },
                () => { Event("uninstall"); Exists = false; Active = null; },
                ServiceProfileCodec.Plaintext, () => Event("validate"));
        }
    }
}
