using System.Diagnostics;
using System.Reflection;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

/// <summary>Checks the actual cross-process lock/revision protocol, not only two objects.</summary>
internal static class ProfileStoreProcessConformance
{
    internal static int RunChild(string[] args)
    {
        if (args.Length != 4 || !byte.TryParse(args[3], out var value)) return 2;
        var store = new ProfileStoreFile(args[0]);
        _ = store.Read();
        File.WriteAllText(args[1], "observed");
        var deadline = Stopwatch.StartNew();
        while (!File.Exists(args[2]))
        {
            if (deadline.Elapsed > TimeSpan.FromSeconds(10)) return 3;
            Thread.Sleep(10);
        }
        try { store.Write([value]); return 0; }
        catch (IOException) { return 65; }
    }

    internal static void Run(Action<string, bool> check)
    {
        var dir = Path.Combine(Path.GetTempPath(), "qeli-store-process-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var children = new List<Process>();
        try
        {
            var path = Path.Combine(dir, "profiles.json");
            File.WriteAllBytes(path, [1]);
            var release = Path.Combine(dir, "release");
            var ready = new[] { Path.Combine(dir, "first-ready"), Path.Combine(dir, "second-ready") };
            for (var i = 0; i < 2; i++)
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
                if (string.Equals(Path.GetFileNameWithoutExtension(start.FileName), "dotnet", StringComparison.OrdinalIgnoreCase))
                    start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
                foreach (var arg in new[] { "profile-store-race-child", path, ready[i], release, (i + 2).ToString() })
                    start.ArgumentList.Add(arg);
                children.Add(Process.Start(start) ?? throw new IOException("Could not start store writer"));
            }
            var deadline = Stopwatch.StartNew();
            while (!ready.All(File.Exists) && children.All(p => !p.HasExited) && deadline.Elapsed < TimeSpan.FromSeconds(10))
                Thread.Sleep(10);
            var bothRead = ready.All(File.Exists);
            check("profile store: independent processes observe the same version before racing", bothRead);
            File.WriteAllText(release, "commit");
            var completed = children.All(p => p.WaitForExit(10_000));
            check("profile store: independent writers finish within the test budget", completed);
            if (bothRead && completed)
            {
                var winner = children.FindIndex(p => p.ExitCode == 0);
                check("profile store: exactly one independent writer wins and one refuses stale data",
                    winner >= 0 && children.Count(p => p.ExitCode == 0) == 1 && children.Count(p => p.ExitCode == 65) == 1);
                check("profile store: winning bytes survive and previous bytes remain in backup",
                    winner >= 0 && File.ReadAllBytes(path).SequenceEqual(new[] { (byte)(winner + 2) })
                    && File.ReadAllBytes(path + ".bak").SequenceEqual(new byte[] { 1 }));
                var fresh = new ProfileStoreFile(path);
                _ = fresh.Read();
                fresh.Write([4]);
                check("profile store: fresh reader can commit after both writer processes exit",
                    File.ReadAllBytes(path).SequenceEqual(new byte[] { 4 }));
            }
        }
        finally
        {
            foreach (var child in children)
            {
                if (!child.HasExited) { child.Kill(entireProcessTree: true); child.WaitForExit(); }
                child.Dispose();
            }
            Directory.Delete(dir, recursive: true);
        }
    }
}
