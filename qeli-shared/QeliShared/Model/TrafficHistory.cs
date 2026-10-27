namespace Qeli.Shared.Model;

/// <summary>Bounded samples timed by their source. A repeated observation is not a new sample.</summary>
public sealed class TrafficHistory
{
    public const int Capacity = 120;
    public readonly record struct Rate(double Up, double Down);
    private enum Clock { LocalMonotonic, ServiceWall, ServiceUptime }
    private readonly Queue<Rate> _samples = new();
    private long _tick, _up, _down;
    private DateTime? _session;
    private Rate? _lastRate;
    private Clock? _clock;
    public IReadOnlyCollection<Rate> Samples => _samples;
    public void Clear() { _samples.Clear(); _session = null; _lastRate = null; _clock = null; }
    public Rate? Add(long tick, long up, long down, DateTime? session, bool fresh)
        => Add(tick, up, down, session, fresh, Clock.LocalMonotonic);

    public Rate? AddService(DesktopServiceStatus snapshot, bool fresh)
        => snapshot.MonotonicTimeMs is long tick
            ? Add(tick, snapshot.BytesUp, snapshot.BytesDown, snapshot.Since, fresh, Clock.ServiceUptime)
            : Add(snapshot.Time.ToUniversalTime().Ticks / TimeSpan.TicksPerMillisecond,
                snapshot.BytesUp, snapshot.BytesDown, snapshot.Since, fresh, Clock.ServiceWall);

    private Rate? Add(long tick, long up, long down, DateTime? session, bool fresh, Clock clock)
    {
        if (!fresh || session is null || tick < 0 || up < 0 || down < 0) { Clear(); return null; }
        // Upgrades/downgrades and service/local transitions must not mix clock origins,
        // even if their numeric timestamps happen to be close or identical.
        bool newSource = _clock != clock || _session != session || up < _up || down < _down
            || tick < _tick;
        bool reset = newSource || tick - _tick > 5000;
        // Re-reading a cached service snapshot must not append a false zero or move
        // the baseline. Same-millisecond counter growth belongs to the next interval.
        if (!reset && tick == _tick) return _lastRate;
        long elapsed = tick - _tick;
        _session = session;
        _clock = clock;
        long deltaUp = reset ? 0 : up - _up, deltaDown = reset ? 0 : down - _down;
        _tick = tick; _up = up; _down = down;
        // A suspended UI has no valid rate for the missing interval, but does not
        // lose the already measured graph. Only a new/reset source clears history.
        if (reset) { if (newSource) _samples.Clear(); _lastRate = null; return null; }
        var rate = new Rate(deltaUp * 1000.0 / elapsed, deltaDown * 1000.0 / elapsed);
        _lastRate = rate;
        _samples.Enqueue(rate);
        if (_samples.Count > Capacity) _samples.Dequeue();
        return rate;
    }
}
