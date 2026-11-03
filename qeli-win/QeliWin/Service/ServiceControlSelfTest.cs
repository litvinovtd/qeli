using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text.Json;
using Qeli.Shared.Model;
using QeliWin.Model;

namespace QeliWin.Service;

internal static class ServiceControlSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        bool Fails(Action action)
        {
            try { action(); return false; }
            catch (Exception e) when (e is IOException or InvalidOperationException or JsonException or System.TimeoutException) { return true; }
        }
        VpnConfig Profile(string id, string host = "127.0.0.1") => new() { Id = id, ServerAddress = host };
        var original = Profile("first");
        var replacement = Profile("second", "192.0.2.2");
        Scenario Case(bool installed = true, bool desired = true) => new(original, installed, desired);
        var running = Case();
        running.Controller.Apply(replacement, false);
        check("service apply: running worker reloads changed profile after joined stop",
            running.Active?.Id == replacement.Id && running.Active.ServerAddress == replacement.ServerAddress
            && running.Events.SequenceEqual(new[] { "stop", "publish", "start" }));
        var unchanged = Case();
        unchanged.Controller.Apply(Profile("first"), false);
        check("service apply: unchanged running profile does not stop or republish",
            unchanged.Active?.Id == original.Id && unchanged.Events.SequenceEqual(new[] { "start" }));
        var stopped = Case(desired: false);
        stopped.Controller.Apply(replacement, false);
        check("service apply: changed idle profile stays disconnected",
            !stopped.Desired && stopped.Active is null && stopped.Stored?.Id == replacement.Id
            && stopped.Events.SequenceEqual(new[] { "stop", "publish" }));
        var idle = Case(desired: false);
        idle.Controller.Apply(Profile("first"), false);
        check("service apply: ordinary settings save never reconnects idle worker",
            idle.Active is null && !idle.Desired && idle.Events.Count == 0);
        idle.Controller.Apply(Profile("first"), true);
        check("service apply: explicit enable reconnects idle worker", idle.Active?.Id == original.Id && idle.Desired);
        var fresh = Case(installed: false, desired: false);
        fresh.Controller.Apply(replacement, false);
        check("service apply: first install publishes before install and start",
            fresh.Events.SequenceEqual(new[] { "publish", "install", "start" }) && fresh.Active?.Id == replacement.Id);
        var invalid = Case();
        check("service apply: invalid new config cannot stop or replace live profile",
            Fails(() => invalid.Controller.Apply(new VpnConfig { Password = null! }, false))
            && invalid.Events.Count == 0 && invalid.Active?.Id == original.Id);
        var stopFailure = Case();
        stopFailure.Failure = "stop";
        check("service apply: failed stop refuses publication and restart",
            Fails(() => stopFailure.Controller.Apply(replacement, false))
            && stopFailure.Stored?.Id == original.Id && stopFailure.Active?.Id == original.Id
            && stopFailure.Events.SequenceEqual(new[] { "stop" }));
        var writeFailure = Case();
        writeFailure.Failure = "publish";
        check("service apply: failed publication remains stopped with previous profile",
            Fails(() => writeFailure.Controller.Apply(replacement, false))
            && writeFailure.Stored?.Id == original.Id && writeFailure.Active is null && !writeFailure.Desired
            && writeFailure.Events.SequenceEqual(new[] { "stop", "publish" }));
        var installFailure = Case(installed: false, desired: false);
        installFailure.Failure = "install";
        check("service apply: failed install never starts",
            Fails(() => installFailure.Controller.Apply(replacement, false)) && installFailure.Active is null
            && installFailure.Events.SequenceEqual(new[] { "publish", "install" }));
        var startFailure = Case();
        startFailure.Failure = "start";
        check("service apply: start failure propagates and retains published profile",
            Fails(() => startFailure.Controller.Apply(replacement, false)) && startFailure.Active is null
            && startFailure.Stored?.Id == replacement.Id);
        var malformed = Case();
        malformed.Failure = "payload";
        malformed.Controller.Apply(replacement, false);
        check("service apply: trusted GUI can replace malformed old payload",
            malformed.Active?.Id == replacement.Id && malformed.Events.SequenceEqual(new[] { "stop", "publish", "start" }));
        var untrusted = Case();
        untrusted.Failure = "read";
        check("service apply: storage access error refuses replacement",
            Fails(() => untrusted.Controller.Apply(replacement, false)) && untrusted.Events.Count == 0
            && untrusted.Active?.Id == original.Id);
        var disable = Case();
        disable.Controller.Apply(null, false);
        check("service apply: disabled setting uninstalls existing service", disable.Events.SequenceEqual(new[] { "uninstall" }));
        var absent = Case(installed: false, desired: false);
        absent.Controller.Apply(null, false);
        check("service apply: disabled missing service performs no mutation", absent.Events.Count == 0);
        var identity = Case();
        check("service profile: delete guard uses stored Id rather than endpoint/name",
            identity.Controller.UsesProfile(original.Id) && !identity.Controller.UsesProfile("same-endpoint-other-account"));
        var copy = ServiceProfileTransition.Snapshot(original, "debug");
        copy.IncludeRoutes.Add("192.0.2.0/24");
        check("service profile: prepared snapshot keeps identity and isolates GUI fields",
            copy.Id == original.Id && copy.LoggingLevel == "debug" && original.LoggingLevel == "info"
            && original.IncludeRoutes.Count == 0);

        foreach (var initial in new[] { ServiceControllerStatus.Stopped, ServiceControllerStatus.Running,
            ServiceControllerStatus.Paused, ServiceControllerStatus.StartPending, ServiceControllerStatus.StopPending })
        {
            var state = initial;
            int stops = 0;
            var waits = new List<ServiceControllerStatus>();
            var budgets = new List<TimeSpan>();
            ServiceManager.StopController(() => { }, () => state, () => state is ServiceControllerStatus.Running or ServiceControllerStatus.Paused,
                () => { stops++; state = ServiceControllerStatus.StopPending; },
                (target, budget) => { waits.Add(target); budgets.Add(budget); state = target; });
            check($"SCM stop: {initial} confirms Stopped before returning",
                state == ServiceControllerStatus.Stopped && stops == (initial is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending ? 0 : 1)
                && budgets.All(b => b > TimeSpan.Zero && b <= TimeSpan.FromSeconds(20))
                && (budgets.Count < 2 || budgets[1] <= budgets[0]));
        }
        foreach (var state in new[] { ServiceControllerStatus.Running, ServiceControllerStatus.PausePending, ServiceControllerStatus.ContinuePending })
            check($"SCM stop: cannot-stop {state} refuses false success",
                Fails(() => ServiceManager.StopController(() => {}, () => state, () => false,
                    () => throw new Exception("unexpected stop"), (_, _) => throw new Exception("unexpected wait"))));
        int calls = 0;
        check("SCM stop: start-pending timeout cannot authorize profile replacement",
            Fails(() => ServiceManager.StopController(() => {}, () => ServiceControllerStatus.StartPending, () => false,
                () => calls++, (_, _) => throw new System.TimeoutException("injected"))) && calls == 0);
        var raceState = ServiceControllerStatus.StopPending;
        check("SCM stop: concurrent restart after wait is not reported cleaned",
            Fails(() => ServiceManager.StopController(() => { if (raceState == ServiceControllerStatus.Stopped) raceState = ServiceControllerStatus.Running; },
                () => raceState, () => false, () => {}, (target, _) => raceState = target)));

        string? command = null;
        AutoStartManager.Apply(true, @"C:\Program Files\QeliWin\QeliWin.exe", _ => {},
            args => { command = args; return new(0, "", ""); }, () => throw new Exception("enable must not query"));
        check("autostart: enable refreshes quoted protected executable path", command != null
            && command.Contains("/RL HIGHEST", StringComparison.Ordinal) && command.Contains("--autostart", StringComparison.Ordinal));
        check("autostart: create failure is visible",
            Fails(() => AutoStartManager.Apply(true, "protected.exe", _ => {}, _ => new(5,"","denied"), () => true)));
        check("autostart: delete failure is visible",
            Fails(() => AutoStartManager.Apply(false, "protected.exe", _ => {}, _ => new(5,"","denied"), () => true)));
        int commands = 0;
        AutoStartManager.Apply(false, "unused.exe", _ => throw new Exception("disable must not validate executable"),
            _ => { commands++; return new(0,"",""); }, () => false);
        check("autostart: absent task disable is idempotent without mutation", commands == 0);
        check("autostart: query error is not absence",
            Fails(() => AutoStartManager.Apply(false, "unused.exe", _ => {}, _ => new(0,"",""), () => throw new IOException("query failed"))));
        check("autostart: unsafe registration fails before scheduler command",
            Fails(() => AutoStartManager.Apply(true, "unsafe.exe", _ => throw new InvalidOperationException("unsafe"),
                _ => { commands++; return new(0,"",""); }, () => false)) && commands == 0);
        check("scheduler: read-only missing-task probe has no registration side effect",
            !AutoStartManager.HasTask("qeli-selftest-missing-" + Guid.NewGuid().ToString("N")));

        var settings = new AppSettings { AutoStart = true, Language = "en" };
        var proposal = settings.Snapshot();
        proposal.AutoStart = false;
        proposal.Language = "ru";
        check("settings: proposed edits do not mutate live snapshot before save",
            settings.AutoStart && settings.Language == "en" && !proposal.AutoStart && proposal.Language == "ru");
        string testDir = Path.Combine(Path.GetTempPath(), "qeli-settings-proposal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDir);
        try
        {
            string path = Path.Combine(testDir, "settings");
            AppSettingsStore.Save(settings, path);
            var before = File.ReadAllBytes(path);
            using (var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                check("settings: failed proposed write retains live settings and exact saved bytes",
                    Fails(() => AppSettingsStore.Save(proposal, path)) && settings.AutoStart && settings.Language == "en"
                    && File.ReadAllBytes(path).AsSpan().SequenceEqual(before));
        }
        finally { Directory.Delete(testDir, recursive: true); }
        RunCommandChecks(check);
    }

    private static void RunCommandChecks(Action<string, bool> check)
    {
        // Exercise pipe backpressure without making a successful fixture depend on
        // cold PowerShell/CLR startup on a busy host. Each pipe still exceeds 128 KiB.
        string outputLine = new string('o', 1024) + Environment.NewLine;
        string errorLine = new string('e', 1024) + Environment.NewLine;
        var info = new ProcessStartInfo(SystemPaths.Resolve("cmd")) { WorkingDirectory = SystemPaths.SystemDirectory };
        info.Arguments = "/d /q /c \"(for /L %i in (1,1,128) do @echo " + new string('o', 1024)
            + ") & (for /L %i in (1,1,128) do @echo " + new string('e', 1024) + ">&2) & exit /b 7\"";
        var result = WindowsCommand.RunAsync(info, TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
        check("command: real dual-pipe output drains without deadlock and stays bounded",
            result.ExitCode == 7 && result.Output == string.Concat(Enumerable.Repeat(outputLine, 4))[..4096]
            && result.Error == string.Concat(Enumerable.Repeat(errorLine, 4))[..4096]);
        var stalled = new ProcessStartInfo(SystemPaths.PowerShell) { WorkingDirectory = SystemPaths.SystemDirectory };
        stalled.ArgumentList.Add("-NoProfile"); stalled.ArgumentList.Add("-NonInteractive"); stalled.ArgumentList.Add("-Command");
        stalled.ArgumentList.Add("Start-Sleep -Seconds 20");
        var elapsed = Stopwatch.StartNew();
        bool timeout = false;
        int childPid = 0;
        try { WindowsCommand.RunAsync(stalled, TimeSpan.FromMilliseconds(400)).GetAwaiter().GetResult(); }
        catch (System.TimeoutException error) { timeout = true; childPid = (int)error.Data["ProcessId"]!; }
        bool exited = false;
        if (childPid != 0)
        {
            try { using var child = Process.GetProcessById(childPid); exited = child.WaitForExit(1000); }
            catch (ArgumentException) { exited = true; }
        }
        check("command: timed-out owned child really exits", exited);
        check("command: stalled owned child is cancelled within bounded deadline", timeout && elapsed.Elapsed < TimeSpan.FromSeconds(5));
        bool startError = false;
        try { WindowsCommand.RunAsync(new ProcessStartInfo(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".exe")),
            TimeSpan.FromSeconds(1)).GetAwaiter().GetResult(); }
        catch (System.ComponentModel.Win32Exception) { startError = true; }
        check("command: launch failure retains original error", startError);
    }

    private sealed class Scenario
    {
        internal readonly List<string> Events = new();
        internal bool Exists, Desired;
        internal VpnConfig? Stored, Active;
        internal string? Failure;
        internal readonly ServiceProfileTransition Controller;
        internal Scenario(VpnConfig old, bool exists, bool desired)
        {
            Exists = exists; Desired = desired; Stored = exists ? old : null; Active = exists && desired ? old : null;
            void Event(string operation) { Events.Add(operation); if (Failure == operation) throw new IOException("injected " + operation); }
            Controller = new(() => Exists, () => Desired,
                () => { if (Failure == "read") throw new IOException("injected read"); if (Failure == "payload") throw new JsonException("injected payload"); return Stored; },
                () => { Event("stop"); Active = null; Desired = false; },
                bytes => { Event("publish"); Stored = ServiceState.DecodeProfile(bytes, false, out _); },
                () => { Event("install"); Exists = true; },
                () => { Event("start"); Desired = true; Active ??= Stored; },
                () => { Event("uninstall"); Exists = false; Desired = false; Active = null; });
        }
    }
}
