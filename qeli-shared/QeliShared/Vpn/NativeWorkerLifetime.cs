namespace Qeli.Shared.Vpn;

/// <summary>Keep the native generation and its TUN owned until all worker tasks exit.</summary>
internal static class NativeWorkerLifetime
{
    internal static void CheckPacketPumps(Task? uplink, Task? downlink, CancellationToken stop)
    {
        if (stop.IsCancellationRequested) return;
        Check(uplink, "uplink");
        Check(downlink, "downlink");
    }

    private static void Check(Task? task, string direction)
    {
        if (task is null || !task.IsCompleted) return;
        try { task.GetAwaiter().GetResult(); }
        catch (Exception error)
        {
            throw new IOException($"native {direction} packet pump failed", error);
        }
        throw new IOException($"native {direction} packet pump stopped unexpectedly");
    }

    internal static void Join(params Task?[] workers)
    {
        // Task.WaitAll observes faults but still waits for every worker. Swallow their
        // terminal errors here only after joining; the run loop reports pump failures.
        try { Task.WaitAll(workers.OfType<Task>().ToArray()); }
        catch (AggregateException) { }
    }
}
