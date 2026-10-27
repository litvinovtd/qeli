using Qeli.Shared.Model;
using System.IO;
using System.Text.Json;
namespace Qeli.Conformance;
internal static class TrafficHistoryConformance
{
    internal static void Run(Action<string,bool> check)
    {
        var history=new TrafficHistory(); var session=DateTime.UtcNow;
        check("traffic: first sample is baseline", history.Add(1000,100,200,session,true) is null);
        check("traffic: counter deltas per elapsed second", history.Add(2000,1100,2200,session,true) is {Up:1000,Down:2000});
        for(int i=3;i<300;i++) history.Add(i*1000,i*1000,i*2000,session,true);
        check("traffic: bounded history",history.Samples.Count==TrafficHistory.Capacity);
        check("traffic: counter reset starts new baseline", history.Add(300000,0,0,session,true) is null && history.Samples.Count==0);
        check("traffic: changed session has no spike", history.Add(301000,5000,5000,session.AddSeconds(1),true) is null);
        history.Add(302000,6000,6000,session.AddSeconds(1),true);
        check("traffic: stale observation is a gap", history.Add(303000,7000,7000,session.AddSeconds(1),false) is null && history.Samples.Count==0);
        history.Add(304000,8000,8000,session.AddSeconds(1),true);
        check("traffic: long pause cannot bridge samples", history.Add(320000,9000,9000,session.AddSeconds(1),true) is null && history.Samples.Count==0);

        var service = new TrafficHistory();
        service.Add(1000,100,200,session,true);
        service.Add(2000,1100,2200,session,true);
        check("traffic: repeated source snapshot preserves rate without adding a zero",
            service.Add(2000,1100,2200,session,true) is {Up:1000,Down:2000} && service.Samples.Count==1);
        check("traffic: same-millisecond growth does not replace the baseline",
            service.Add(2000,2100,4200,session,true) is {Up:1000,Down:2000} && service.Samples.Count==1);
        check("traffic: accumulated delta uses the interval between source snapshots",
            service.Add(4000,3100,6200,session,true) is {Up:1000,Down:2000} && service.Samples.Count==2);
        check("traffic: a new idle snapshot records a genuine zero",
            service.Add(5000,3100,6200,session,true) is {Up:0,Down:0} && service.Samples.Count==3);
        check("traffic: counter reset takes precedence over duplicate time",
            service.Add(5000,10,20,session,true) is null && service.Samples.Count==0);
        check("traffic: duplicate baseline cannot restore an old rate",
            service.Add(5000,10,20,session,true) is null && service.Samples.Count==0);
        service.Add(6000,1010,2020,session,true);
        check("traffic: backwards source time starts a new baseline",
            service.Add(5000,2010,4020,session,true) is null && service.Samples.Count==0);
        service.Add(6000,3010,6020,session,true);
        check("traffic: changed session takes precedence over duplicate time",
            service.Add(6000,3010,6020,session.AddSeconds(1),true) is null && service.Samples.Count==0);
        service.Add(7000,4010,8020,session.AddSeconds(1),true);
        check("traffic: stale duplicate clears the remembered rate",
            service.Add(7000,4010,8020,session.AddSeconds(1),false) is null && service.Samples.Count==0);
        check("traffic: first observation after clearing is only a baseline",
            service.Add(7000,4010,8020,session.AddSeconds(1),true) is null && service.Samples.Count==0);

        ServiceClockChecks(check);
        ClockDomainChecks(check);
        ServiceStatusChecks(check);
        var background = new TrafficHistory();
        background.Add(1000, 0, 0, session, true);
        background.Add(2000, 1000, 2000, session, true);
        background.Add(3000, 2000, 4000, session, true);
        check("traffic: tray sampling retains measured history",
            background.Add(4000, 3000, 6000, session, true) is { Up: 1000, Down: 2000 }
            && background.Samples.Count == 3);
        check("traffic: UI pause preserves graph without inventing a rate",
            background.Add(20000, 19000, 38000, session, true) is null
            && background.Samples.Count == 3);
        check("traffic: first interval after UI pause excludes the missing interval",
            background.Add(21000, 20000, 40000, session, true) is { Up: 1000, Down: 2000 }
            && background.Samples.Count == 4);
    }

    private static readonly DateTime WallTime = new(2026, 1, 2, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime ServiceSince = WallTime.AddMinutes(-10);

    private static DesktopServiceStatus Snapshot(DateTime wall, long? monotonic, long up, long down)
        => new() { Status = "Connected", Time = wall, MonotonicTimeMs = monotonic, BytesUp = up, BytesDown = down, Since = ServiceSince };

    private static void ServiceClockChecks(Action<string, bool> check)
    {
        var history = new TrafficHistory();
        check("traffic service: monotonic first sample is baseline",
            history.AddService(Snapshot(WallTime, 1000, 100, 200), true) is null);
        check("traffic service: wall clock jumping forward does not change the rate",
            history.AddService(Snapshot(WallTime.AddHours(4), 2000, 1100, 2200), true) is { Up: 1000, Down: 2000 });
        check("traffic service: wall clock jumping backward does not change the interval",
            history.AddService(Snapshot(WallTime.AddHours(-4), 4000, 3100, 6200), true) is { Up: 1000, Down: 2000 }
            && history.Samples.Count == 2);
        check("traffic service: changed wall time cannot turn a repeated uptime into a new sample",
            history.AddService(Snapshot(WallTime.AddHours(8), 4000, 3100, 6200), true) is { Up: 1000, Down: 2000 }
            && history.Samples.Count == 2);
        check("traffic service: same-uptime growth waits for the next monotonic interval",
            history.AddService(Snapshot(WallTime.AddHours(-8), 4000, 4100, 8200), true) is { Up: 1000, Down: 2000 }
            && history.Samples.Count == 2);
        check("traffic service: deferred growth is counted once over the full interval",
            history.AddService(Snapshot(WallTime, 6000, 5100, 10200), true) is { Up: 1000, Down: 2000 }
            && history.Samples.Count == 3);
        check("traffic service: advancing uptime with idle counters adds a real zero",
            history.AddService(Snapshot(WallTime.AddHours(-4), 7000, 5100, 10200), true) is { Up: 0, Down: 0 }
            && history.Samples.Count == 4);
        check("traffic service: stale duplicate clears rate and samples",
            history.AddService(Snapshot(WallTime, 7000, 5100, 10200), false) is null && history.Samples.Count == 0);
        check("traffic service: fresh observation after a stale gap is a baseline",
            history.AddService(Snapshot(WallTime, 8000, 6100, 12200), true) is null);
        history.AddService(Snapshot(WallTime, 9000, 7100, 14200), true);
        int retainedSamples = history.Samples.Count;
        check("traffic service: suspend-sized uptime gap rebases without deleting history",
            history.AddService(Snapshot(WallTime, 15001, 17100, 34200), true) is null && history.Samples.Count == retainedSamples);
        check("traffic service: first interval after suspend uses only the new baseline",
            history.AddService(Snapshot(WallTime, 16001, 18100, 36200), true) is { Up: 1000, Down: 2000 });
        check("traffic service: backwards uptime resets even when counters and wall time advance",
            history.AddService(Snapshot(WallTime.AddSeconds(1), 12000, 19100, 38200), true) is null
            && history.Samples.Count == 0);
        check("traffic service: rate recovers from a backwards-uptime baseline",
            history.AddService(Snapshot(WallTime.AddSeconds(2), 13000, 20100, 40200), true) is { Up: 1000, Down: 2000 });

        var legacy = new TrafficHistory();
        check("traffic service: missing uptime uses the legacy wall-clock baseline",
            legacy.AddService(Snapshot(WallTime, null, 100, 200), true) is null);
        check("traffic service: legacy rate uses the source wall interval",
            legacy.AddService(Snapshot(WallTime.AddSeconds(2), null, 2100, 4200), true) is { Up: 1000, Down: 2000 });
        check("traffic service: legacy backwards wall time clears the prior rate",
            legacy.AddService(Snapshot(WallTime.AddHours(-1), null, 3100, 6200), true) is null
            && legacy.Samples.Count == 0);
    }

    private static void ClockDomainChecks(Action<string, bool> check)
    {
        // Deliberately overlap the numeric clocks. A reset must depend on the clock
        // domain itself, not accidentally on a large or backwards timestamp jump.
        string[] names = { "local", "service uptime", "legacy service wall" };
        long baseline = WallTime.Ticks / TimeSpan.TicksPerMillisecond;
        foreach (int from in new[] { 0, 1, 2 })
        foreach (int to in new[] { 0, 1, 2 })
        foreach (long offset in new long[] { 0, 1 })
        {
            if (from == to) continue;
            var history = new TrafficHistory();
            AddClock(history, from, baseline, 100, 200);
            AddClock(history, from, baseline + 1000, 1100, 2200);
            check($"traffic clocks: {names[from]} to {names[to]}, offset {offset}, resets before duplicate handling",
                AddClock(history, to, baseline + 1000 + offset, 2100, 4200) is null && history.Samples.Count == 0);
            check($"traffic clocks: {names[to]} resumes from its own baseline after {names[from]}, offset {offset}",
                AddClock(history, to, baseline + 2000 + offset, 3100, 6200) is { Up: 1000, Down: 2000 }
                && history.Samples.Count == 1);
        }
    }

    private static TrafficHistory.Rate? AddClock(TrafficHistory history, int clock, long tick, long up, long down)
        => clock switch
        {
            0 => history.Add(tick, up, down, ServiceSince, true),
            1 => history.AddService(Snapshot(WallTime, tick, up, down), true),
            _ => history.AddService(Snapshot(new DateTime(tick * TimeSpan.TicksPerMillisecond, DateTimeKind.Utc), null, up, down), true)
        };

    private static void ServiceStatusChecks(Action<string, bool> check)
    {
        var maxAge = TimeSpan.FromSeconds(5);
        var snapshot = Snapshot(WallTime.AddHours(4), 10000, 100, 200);
        check("service clock: freshness ignores forward wall-clock displacement",
            DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 11000));
        snapshot.Time = WallTime.AddHours(-4);
        check("service clock: freshness ignores backward wall-clock displacement",
            DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 11000));
        snapshot.Time = WallTime;
        check("service clock: present uptime requires a caller uptime instead of wall fallback",
            !DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge));
        check("service clock: future uptime is rejected even with fresh wall time",
            !DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 9999));
        check("service clock: freshness includes the exact age boundary",
            DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 15000));
        check("service clock: elapsed suspend time expires the snapshot despite fresh wall time",
            !DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 15001));

        snapshot.MonotonicTimeMs = null;
        check("service clock: legacy snapshots remain fresh by wall time without uptime",
            DesktopServiceStatus.Fresh(snapshot, WallTime.AddSeconds(4), maxAge));
        check("service clock: stale legacy snapshots are rejected",
            !DesktopServiceStatus.Fresh(snapshot, WallTime.AddSeconds(6), maxAge));
        byte[] legacyJson = JsonSerializer.SerializeToUtf8Bytes(snapshot);
        using (var json = JsonDocument.Parse(legacyJson))
            check("service clock: null uptime is omitted for legacy JSON compatibility",
                !json.RootElement.TryGetProperty("MonotonicTimeMs", out _));
        var legacyDecoded = DesktopServiceStatus.Decode<DesktopServiceStatus>(legacyJson);
        check("service clock: legacy JSON without uptime decodes without inventing a timestamp",
            legacyDecoded.MonotonicTimeMs is null && legacyDecoded.Time == WallTime && legacyDecoded.Since == ServiceSince);

        snapshot.MonotonicTimeMs = 0;
        var decoded = DesktopServiceStatus.Decode<DesktopServiceStatus>(JsonSerializer.SerializeToUtf8Bytes(snapshot));
        check("service clock: zero uptime roundtrips as present and valid",
            decoded.MonotonicTimeMs == 0 && DesktopServiceStatus.Fresh(decoded, WallTime.AddHours(4), maxAge, 1000));
        snapshot.MonotonicTimeMs = -1;
        check("service clock: negative uptime cannot fall back to wall freshness",
            !DesktopServiceStatus.Fresh(snapshot, WallTime, maxAge, 1000));
        bool rejected = false;
        try { DesktopServiceStatus.Decode<DesktopServiceStatus>(JsonSerializer.SerializeToUtf8Bytes(snapshot)); }
        catch (InvalidDataException) { rejected = true; }
        check("service clock: decoded negative uptime is rejected by validation", rejected);
    }
}
