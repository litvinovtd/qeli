namespace QeliWin.Vpn;

/// <summary>
/// Small, short-lived holding area for non-first IP fragments that arrive before their
/// first fragment establishes policy/NAT affinity. Bounds are global and per datagram so
/// hostile fragment IDs cannot turn reordering support into unbounded memory use.
/// </summary>
internal sealed class PendingFragmentBuffer<TKey, TValue> where TKey : notnull
{
    private readonly object _gate = new();
    private readonly Dictionary<TKey, List<Item>> _items = new();
    private readonly int _maxItems;
    private readonly int _maxPerKey;
    private readonly TimeSpan _ttl;
    private int _count;
    private long _droppedCount;

    public PendingFragmentBuffer(int maxItems = 128, int maxPerKey = 16, TimeSpan? ttl = null)
    {
        _maxItems = Math.Max(1, maxItems);
        _maxPerKey = Math.Max(1, maxPerKey);
        _ttl = ttl ?? TimeSpan.FromSeconds(2);
    }

    public int Count { get { lock (_gate) return _count; } }
    public long DroppedCount { get { lock (_gate) return _droppedCount; } }

    public bool Add(TKey key, TValue value, DateTime? now = null)
    {
        lock (_gate)
        {
            SweepUnlocked(now ?? DateTime.UtcNow);
            if (_count >= _maxItems)
            {
                _droppedCount++;
                return false;
            }
            if (!_items.TryGetValue(key, out var bucket))
                _items[key] = bucket = new List<Item>();
            if (bucket.Count >= _maxPerKey)
            {
                _droppedCount++;
                return false;
            }
            bucket.Add(new Item(value, now ?? DateTime.UtcNow));
            _count++;
            return true;
        }
    }

    public IReadOnlyList<TValue> Take(TKey key, DateTime? now = null)
    {
        lock (_gate)
        {
            SweepUnlocked(now ?? DateTime.UtcNow);
            if (!_items.Remove(key, out var bucket)) return Array.Empty<TValue>();
            _count -= bucket.Count;
            return bucket.Select(item => item.Value).ToArray();
        }
    }

    public int Discard(TKey key, DateTime? now = null)
    {
        lock (_gate)
        {
            SweepUnlocked(now ?? DateTime.UtcNow);
            if (!_items.Remove(key, out var bucket)) return 0;
            _count -= bucket.Count;
            _droppedCount += bucket.Count;
            return bucket.Count;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _droppedCount += _count;
            _items.Clear();
            _count = 0;
        }
    }

    internal void SweepForTest(DateTime now)
    {
        lock (_gate) SweepUnlocked(now);
    }

    private void SweepUnlocked(DateTime now)
    {
        foreach (var key in _items.Keys.ToList())
        {
            var bucket = _items[key];
            int removed = bucket.RemoveAll(item => now - item.Created > _ttl);
            _count -= removed;
            _droppedCount += removed;
            if (bucket.Count == 0) _items.Remove(key);
        }
    }

    private readonly record struct Item(TValue Value, DateTime Created);
}
