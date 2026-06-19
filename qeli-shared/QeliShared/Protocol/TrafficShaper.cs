using System.Diagnostics;

namespace Qeli.Shared.Protocol;

/// <summary>
/// Idle cover-traffic scheduler — the C# mirror of the Rust <c>protocol::shaper</c>
/// (DPI-AUDIT 6.1/6.2). When enabled, an idle tunnel emits cover packets at gaps
/// sampled from an exponential (Poisson-process) distribution rather than a fixed
/// heartbeat, with a browsing-ish size distribution, capped by a byte budget.
/// Cover packets are empty-payload encrypted records the peer drops, so this is
/// not a wire-format change. Sampling is timing/size only (not secret), so the
/// system <see cref="Random"/> is fine here.
/// </summary>
public sealed class TrafficShaper
{
    public bool Enabled { get; }

    private readonly double _gapMeanMs;
    private readonly long _gapMinMs;
    private readonly long _gapMaxMs;
    private readonly int _budgetBytesPerSec;
    private readonly int _minSize;
    private readonly int _maxSize;
    private readonly Random _rng = new();
    private double _tokens;
    private long _lastRefillTicks;

    public TrafficShaper(bool enabled, long gapMeanMs, long gapMinMs, long gapMaxMs,
                         int budgetBytesPerSec, int minSize, int maxSize)
    {
        Enabled = enabled && budgetBytesPerSec > 0;
        _gapMeanMs = Math.Max(1, gapMeanMs);
        _gapMinMs = gapMinMs;
        _gapMaxMs = Math.Max(gapMinMs, gapMaxMs);
        _budgetBytesPerSec = budgetBytesPerSec;
        _minSize = minSize;
        _maxSize = Math.Max(minSize, maxSize);
        _tokens = budgetBytesPerSec; // start with ~1s of budget
        _lastRefillTicks = Stopwatch.GetTimestamp();
    }

    /// <summary>Next inter-cover gap in ms — exponential (inverse-CDF of Exp(1/mean)),
    /// clamped to [min, max]. The exponential tail is what makes it non-periodic.</summary>
    public int NextGapMs()
    {
        double u = _rng.NextDouble();
        double sampled = -_gapMeanMs * Math.Log(Math.Max(1e-12, 1.0 - u));
        return (int)Math.Clamp(sampled, _gapMinMs, _gapMaxMs);
    }

    /// <summary>Sample a cover packet size in [minSize, maxSize].</summary>
    public int NextSize() => _minSize >= _maxSize ? _minSize : _rng.Next(_minSize, _maxSize + 1);

    /// <summary>Token-bucket check+spend; true (and deducts) if the budget allows
    /// <paramref name="bytes"/> of cover, false if over budget (skip this cover).</summary>
    public bool TrySpend(int bytes)
    {
        if (_budgetBytesPerSec <= 0) return false;
        long now = Stopwatch.GetTimestamp();
        double elapsed = (now - _lastRefillTicks) / (double)Stopwatch.Frequency;
        _lastRefillTicks = now;
        // Cap at ~1s of budget so an idle period can't bank a burst.
        _tokens = Math.Min(_tokens + elapsed * _budgetBytesPerSec, _budgetBytesPerSec);
        if (_tokens >= bytes) { _tokens -= bytes; return true; }
        return false;
    }
}
