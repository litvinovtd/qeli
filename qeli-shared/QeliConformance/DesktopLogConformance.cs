using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class DesktopLogConformance
{
    internal static void Run(Action<string, bool> check)
    {
        var logs = new DesktopLogBuffer(128);
        logs.SetTarget("a");
        logs.AppendCurrent("first\n");
        logs.SetTarget("b");
        logs.AppendCurrent("second\n");
        check("desktop log: producer attribution does not depend on a later UI selection",
            logs.Read("a") == "first\n" && logs.Read("b") == "second\n");

        logs.TryRead("a", -1, out long firstRevision, out _);
        // Warm the exact measured path before counting allocations. Cold JIT,
        // tiering and first-use runtime work are not text snapshots from idle polls.
        bool unchanged = PollUnchanged(logs, firstRevision);
        long before = GC.GetAllocatedBytesForCurrentThread();
        unchanged &= PollUnchanged(logs, firstRevision);
        long idleAllocated = GC.GetAllocatedBytesForCurrentThread() - before;
        check($"desktop log: unchanged polls do not allocate text snapshots ({idleAllocated} B)",
            unchanged && idleAllocated < 4096);

        logs.Clear("a");
        check("desktop log: clearing removes only the requested profile",
            logs.Read("a") == "" && logs.Read("b") == "second\n"
            && logs.TryRead("a", firstRevision, out _, out var cleared) && cleared == "");
        logs.Append("a", "new session\n");
        check("desktop log: clear/recreate cannot reuse the last displayed revision",
            logs.TryRead("a", firstRevision, out _, out var newSession) && newSession == "new session\n");

        for (int i = 0; i < 100_000; i++) logs.Append("a", $"{i:D6}: message\n");
        string tail = logs.Read("a");
        check("desktop log: a log storm remains bounded and retains its final message",
            tail.Length <= 128 && tail.EndsWith("099999: message\n", StringComparison.Ordinal)
            && !tail.Contains("000000: message", StringComparison.Ordinal));

        // Incoming native text already exists; appending its tail must not allocate
        // a huge builder and then leave that capacity retained after trimming.
        string huge = new('x', 2 * 1024 * 1024);
        logs.Append("large", "warm\n");
        before = GC.GetAllocatedBytesForCurrentThread();
        logs.Append("large", huge);
        long largeAllocated = GC.GetAllocatedBytesForCurrentThread() - before;
        check("desktop log: oversized errors are bounded before growing the buffer",
            logs.Read("large").Length == 128 && largeAllocated < 32 * 1024);

        var unicode = new DesktopLogBuffer(2);
        unicode.Append("u", "😀x");
        check("desktop log: oversized truncation never starts inside a surrogate pair", unicode.Read("u") == "x");
        unicode.Clear("u");
        unicode.Append("u", "😀");
        unicode.Append("u", "x");
        check("desktop log: rolling truncation preserves Unicode boundaries", unicode.Read("u") == "x");

        var concurrent = new DesktopLogBuffer(4096);
        Parallel.For(0, 4, writer =>
        {
            for (int i = 0; i < 2000; i++) concurrent.Append($"p{writer}", $"{writer}:{i}\n");
        });
        check("desktop log: concurrent writers preserve separate bounded profile tails",
            Enumerable.Range(0, 4).All(writer => concurrent.Read($"p{writer}") is var text
                && text.Length <= 4096 && text.EndsWith($"{writer}:1999\n", StringComparison.Ordinal)));
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static bool PollUnchanged(DesktopLogBuffer logs, long revision)
    {
        bool unchanged = true;
        for (int i = 0; i < 10_000; i++)
            unchanged &= !logs.TryRead("a", revision, out _, out var text) && text == null;
        return unchanged;
    }
}
