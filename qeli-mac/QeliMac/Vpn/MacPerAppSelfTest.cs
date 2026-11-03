using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliMac.Vpn;

internal static class MacPerAppSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        void Check(string name, bool ok) => check("mac per-app: " + name, ok);
        static bool Fails(Action action) { try { action(); return false; } catch (Exception e) when (e is IOException or InvalidDataException or InvalidOperationException or AggregateException or PlatformNotSupportedException or TimeoutException or ArgumentException) { return true; } }
        var dir = Directory.CreateTempSubdirectory("qeli-per-app-fixture-");
        string helper = Path.Combine(dir.FullName, "helper"); File.WriteAllText(helper, "fixture");
        var events = new List<string>(); string? failure = null; bool alive = false, failJoin = false;
        string? handoff = null, mode = null; bool privateHandoff = false;
        var tokens = new List<string>(); int ownerPid = 0, wireVersion = 0; string? commandToken = null;
        PerAppController Controller(Action? validate = null) => new(_ => {}, helper, validate ?? (() => {}),
            args => {
                events.Add(args[0]);
                if (args[0] is "start" or "update") {
                    handoff = args[1]; using var state = JsonDocument.Parse(File.ReadAllBytes(handoff));
                    mode = state.RootElement.GetProperty("mode").GetString();
                    tokens.Add(state.RootElement.GetProperty("ownerToken").GetString()!);
                    ownerPid = state.RootElement.GetProperty("ownerPid").GetInt32();
                    wireVersion = state.RootElement.GetProperty("version").GetInt32();
                    privateHandoff = Path.GetFileName(handoff) == "state.json"
                        && Path.GetFileName(Path.GetDirectoryName(handoff)!).StartsWith("qeli-per-app-", StringComparison.Ordinal)
                        && Path.GetFullPath(Path.GetDirectoryName(handoff)!) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
                    if (!OperatingSystem.IsWindows()) privateHandoff &= File.GetUnixFileMode(handoff) == (UnixFileMode.UserRead | UnixFileMode.UserWrite)
                        && File.GetUnixFileMode(Path.GetDirectoryName(handoff)!) == (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                }
                if (args[0] is "down" or "stop") commandToken = args[1];
                if (failure == args[0]) throw new IOException(args[0]);
            }, path => { events.Add("guard"); alive = true; }, () => alive,
            () => { events.Add("join"); if (failJoin) throw new IOException("join"); alive = false; });
        var config = new VpnConfig { AppsMode = "INCLUDE", Apps = new() { "com.apple.Safari" } };
        void Start(PerAppController controller, VpnConfig? profile = null) => controller.StartOrUpdate(profile ?? config,
            "utun7", IPAddress.Parse("203.0.113.7"), new[] { "10.8.0.1" }, Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), new[] { "10.8.0.2/24" }, Array.Empty<string>(), true, false, true);
        try {
            var controller = Controller(); Start(controller);
            Check("start installs state and verifies guardian", controller.Started && alive && events.SequenceEqual(new[] { "guard", "start" }));
            Check("handoff uses a private directory and canonical mode", privateHandoff && mode == "include");
            Check("generation carries canonical token and parent identity", Guid.TryParseExact(tokens[^1], "N", out _) && ownerPid == Environment.ProcessId && wireVersion == 5);
            string firstToken = tokens[^1]; Start(controller);
            Check("updates retain the same owner generation", tokens[^1] == firstToken);
            Check("successful handoff removed after helper consumed it", handoff is not null && !File.Exists(handoff) && !Directory.Exists(Path.GetDirectoryName(handoff)));
            failure = "down"; events.Clear();
            Check("failed down is observable before reconnect", Fails(controller.SetTunnelDown) && controller.Started && alive && events.SequenceEqual(new[] { "down" }));
            Check("down command carries the current generation", commandToken == firstToken);
            failure = null; controller.SetTunnelDown();
            Check("down retries without stopping guardian", controller.Started && alive);
            failure = "stop"; events.Clear();
            Check("failed stop retains proxy and guardian ownership", Fails(controller.Stop) && controller.Started && alive && events.SequenceEqual(new[] { "stop" }));
            failure = null; failJoin = true; events.Clear();
            Check("failed guardian join remains retryable", Fails(controller.Stop) && controller.Started && alive && events.SequenceEqual(new[] { "stop", "join" }));
            Check("reconfiguration refuses while guardian retirement is pending", Fails(() => Start(controller)));
            Check("stop command carries the current generation", commandToken == firstToken);
            failJoin = false; events.Clear(); controller.Stop(); controller.Stop();
            Check("successful stop clears ownership once", !controller.Started && !alive && events.SequenceEqual(new[] { "join" }));
            Start(controller);
            Check("successful retirement rotates the owner token", tokens[^1] != firstToken);
            controller.Stop();
            controller = Controller(); failure = "start"; events.Clear();
            Check("partial start rolls back before forgetting ownership", Fails(() => Start(controller)) && !controller.Started && !alive && events.SequenceEqual(new[] { "guard", "start", "stop", "join" }));
            // An injected first start refusal and stop refusal exercise the actual aggregate path.
            string? partialHandoff = null;
            var partial = new PerAppController(_ => {}, helper, () => {}, args => { if (args[0] is "start" or "update") partialHandoff = args[1]; if (args[0] is "start" or "stop") throw new IOException(args[0]); }, _ => alive = true, () => alive, () => alive = false);
            Check("failed start rollback retains guardian and controller", Fails(() => Start(partial)) && partial.Started && alive);
            Check("failed start still removes private handoff", partialHandoff is not null && !File.Exists(partialHandoff) && !Directory.Exists(Path.GetDirectoryName(partialHandoff)));
            controller = Controller(); failure = null; Start(controller); failure = "update"; events.Clear();
            Check("failed live update retains fail-closed recovery ownership", Fails(() => Start(controller)) && controller.Started && alive && events.Count(x => x == "update") == 2 && !events.Contains("stop"));
            failure = null; controller.Stop();
            var observer = new PerAppController(_ => throw new IOException("observer"), helper, () => {}, args => {
                if (args[0] == "update") throw new IOException("update");
            }, _ => {}, () => true, () => {});
            Start(observer);
            Check("throwing observer cannot reverse successful activation", observer.Started);
            string? observed = null; try { Start(observer); } catch (IOException error) { observed = error.Message; }
            Check("throwing recovery observer preserves original update error", observed == "update" && observer.Started);
            observer.Stop();
            controller = Controller(); Start(controller); File.Delete(helper); events.Clear();
            Check("missing helper cannot silently confirm down", Fails(controller.SetTunnelDown) && controller.Started && alive && events.Count == 0);
            Check("missing helper cannot silently confirm cleanup", Fails(controller.Stop) && controller.Started && alive && events.Count == 0);
            File.WriteAllText(helper, "fixture"); controller.Stop();
            controller = Controller(); Start(controller); failJoin = true; Fails(controller.Stop);
            File.Delete(helper); failJoin = false; events.Clear(); controller.Stop();
            Check("confirmed stop can join after helper file removal", !controller.Started && events.SequenceEqual(new[] { "join" }));
            File.WriteAllText(helper, "fixture");
            controller = Controller(() => throw new PlatformNotSupportedException()); events.Clear();
            Check("platform refusal occurs before guardian or handoff", Fails(() => Start(controller)) && events.Count == 0 && !controller.Started);
            controller = Controller(); events.Clear();
            var oversized = new VpnConfig { AppsMode = "include", Apps = new() { "com.apple.Safari", new string('x', PerAppController.MaximumStateBytes) } };
            Check("oversized state refuses before starting guardian", Fails(() => Start(controller, oversized)) && events.Count == 0 && !controller.Started);
            var dead = new PerAppController(_ => {}, helper, () => {}, _ => {}, _ => {}, () => false, () => {});
            Check("exited guardian prevents successful activation", Fails(() => Start(dead)) && !dead.Started);
        }
        finally { File.Delete(helper); dir.Delete(); }
        string shell = OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") : "/bin/sh";
        string[] Args(string code) => OperatingSystem.IsWindows() ? new[] { "-NoProfile", "-NonInteractive", "-Command", code } : new[] { "-c", code };
        var start = new ProcessStartInfo(shell) { UseShellExecute = false, CreateNoWindow = true };
        foreach (string arg in Args(OperatingSystem.IsWindows() ? "Start-Sleep -Seconds 20" : "sleep 20")) start.ArgumentList.Add(arg);
        using (var guardian = Process.Start(start)!) {
            var watch = Stopwatch.StartNew();
            try {
                PerAppController.JoinGuardian(guardian);
                Check("real guardian is joined before release", guardian.HasExited && watch.Elapsed < TimeSpan.FromSeconds(5));
                PerAppController.JoinGuardian(guardian);
                Check("joining an exited guardian is repeatable", guardian.HasExited);
            }
            finally { if (!guardian.HasExited) { guardian.Kill(entireProcessTree: true); guardian.WaitForExit(5000); } }
        }
        var readyDir = Directory.CreateTempSubdirectory("qeli-guardian-ready-");
        string readyFile = Path.Combine(readyDir.FullName, "ready"), token = Guid.NewGuid().ToString("N");
        Process Child(string code) {
            var psi = new ProcessStartInfo(shell) { UseShellExecute = false, CreateNoWindow = true };
            foreach (string arg in Args(code)) psi.ArgumentList.Add(arg);
            return Process.Start(psi)!;
        }
        void ReadyCase(string name, string code, string? payload, bool expected, int timeout = 3000) {
            File.Delete(readyFile); if (payload is not null) File.WriteAllText(readyFile, payload, new System.Text.UTF8Encoding(false));
            using var process = Child(code);
            try {
                bool ok;
                try { PerAppController.WaitGuardianReady(process, readyFile, token, timeout); ok = true; }
                catch (Exception e) when (e is IOException or InvalidDataException or TimeoutException) { ok = false; }
                Check(name, ok == expected);
            } finally { PerAppController.JoinGuardian(process); }
        }
        string sleep = OperatingSystem.IsWindows() ? "Start-Sleep -Seconds 20" : "sleep 20";
        try {
            string escaped = readyFile.Replace("'", "''");
            string write = OperatingSystem.IsWindows()
                ? $"Start-Sleep -Milliseconds 150; [System.IO.File]::WriteAllText('{escaped}.pending', '{token}', [System.Text.UTF8Encoding]::new($false)); [System.IO.File]::Move('{escaped}.pending', '{escaped}'); {sleep}"
                : $"sleep 0.15; printf '%s' '{token}' > '{readyFile}.pending'; mv '{readyFile}.pending' '{readyFile}'; {sleep}";
            ReadyCase("real child acknowledges the exact generation before handoff removal", write, null, true);
            ReadyCase("live child without acknowledgement times out", sleep, null, false, 150);
            ReadyCase("another generation cannot acknowledge readiness", sleep, Guid.NewGuid().ToString("N"), false);
            ReadyCase("oversized readiness refuses with bounded read", sleep, new string('x', 4096), false);
            ReadyCase("empty readiness record is not an acknowledgement", sleep, "", false);
            ReadyCase("child exit before acknowledgement refuses activation", "exit 7", null, false);
            using var exited = Child("exit 0"); exited.WaitForExit(3000); File.WriteAllText(readyFile, token);
            Check("matching token from an exited guardian is refused", Fails(() => PerAppController.WaitGuardianReady(exited, readyFile, token)));
            Check("invalid readiness budget refuses immediately", Fails(() => PerAppController.WaitGuardianReady(exited, readyFile, token, 0)));
        } finally { File.Delete(readyFile); File.Delete(readyFile + ".pending"); readyDir.Delete(); }
        Check("production helper runner refuses nonzero exit", Fails(() => PerAppController.Run(shell, Args("exit 7"))));
        Check("production helper runner caps stdout", Fails(() => PerAppController.Run(shell, Args(OperatingSystem.IsWindows() ? "[Console]::Out.Write(('x'*131072))" : "head -c 131072 /dev/zero | tr '\\0' x"))));
        Check("production helper runner caps stderr", Fails(() => PerAppController.Run(shell, Args(OperatingSystem.IsWindows() ? "[Console]::Error.Write(('x'*131072))" : "head -c 131072 /dev/zero | tr '\\0' x >&2"))));
    }
}
