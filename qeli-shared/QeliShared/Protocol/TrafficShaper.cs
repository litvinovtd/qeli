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

    /// <summary>Stealth mode: rate-cap the data plane + run cover under load (not
    /// just idle). Implies <see cref="Enabled"/>. TCP-only (the caller gates UDP off,
    /// mirroring the Rust core where UDP stealth craters throughput).</summary>
    public bool Stealth { get; }

    private readonly double _gapMeanMs;
    private readonly long _gapMinMs;
    private readonly long _gapMaxMs;
    private readonly int _budgetBytesPerSec;
    private readonly int _minSize;
    private readonly int _maxSize;
    private readonly double _stealthRateBps;
    private readonly Random _rng = new();
    private double _tokens;
    private long _lastRefillTicks;
    // Separate token bucket (bits) for the stealth data-plane rate cap.
    private double _rateTokens;
    private long _rateLastTicks;

    public TrafficShaper(bool enabled, long gapMeanMs, long gapMinMs, long gapMaxMs,
                         int budgetBytesPerSec, int minSize, int maxSize,
                         bool stealth = false, int stealthRateMbps = 2)
    {
        Enabled = enabled && budgetBytesPerSec > 0;
        Stealth = Enabled && stealth;
        _gapMeanMs = Math.Max(1, gapMeanMs);
        _gapMinMs = gapMinMs;
        _gapMaxMs = Math.Max(gapMinMs, gapMaxMs);
        _budgetBytesPerSec = budgetBytesPerSec;
        _minSize = minSize;
        _maxSize = Math.Max(minSize, maxSize);
        _stealthRateBps = Math.Max(1, stealthRateMbps) * 1_000_000.0;
        _tokens = budgetBytesPerSec; // start with ~1s of budget
        _lastRefillTicks = Stopwatch.GetTimestamp();
        _rateLastTicks = _lastRefillTicks;
    }

    /// <summary>Stealth data-plane pacing: account <paramref name="bytes"/> against the
    /// stealth rate cap and return how long (ms) to sleep before the next send (0 if
    /// under budget or stealth is off). Carries a deficit so bursts average to the cap.</summary>
    public int StealthPaceMs(int bytes)
    {
        if (!Stealth) return 0;
        long now = Stopwatch.GetTimestamp();
        double elapsed = (now - _rateLastTicks) / (double)Stopwatch.Frequency;
        _rateLastTicks = now;
        _rateTokens = Math.Min(_rateTokens + elapsed * _stealthRateBps, _stealthRateBps);
        _rateTokens -= bytes * 8.0;
        if (_rateTokens >= 0) return 0;
        return (int)Math.Min(1000.0, -_rateTokens / _stealthRateBps * 1000.0);
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
