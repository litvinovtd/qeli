using System.Text;

namespace Qeli.Shared.Model;

/// <summary>
/// Thread-safe, bounded per-profile diagnostics. Producers never enqueue UI jobs;
/// readers materialize text only when a visible view needs a newer revision.
/// </summary>
public sealed class DesktopLogBuffer
{
    public const int DefaultMaxChars = 256 * 1024;
    private sealed class Entry
    {
        internal readonly StringBuilder Text = new();
        internal long Revision;
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly int _maxChars;
    private string _target = "";
    private long _revision;

    public DesktopLogBuffer(int maxChars = DefaultMaxChars)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxChars, 2);
        _maxChars = maxChars;
    }

    public void SetTarget(string key)
    {
        lock (_gate) _target = key;
    }

    public void AppendCurrent(string text)
    {
        lock (_gate) AppendLocked(_target, text);
    }

    public void Append(string key, string text)
    {
        lock (_gate) AppendLocked(key, text);
    }

    private void AppendLocked(string key, string text)
    {
        if (text.Length == 0) return;
        if (!_entries.TryGetValue(key, out var entry))
            _entries.Add(key, entry = new Entry());

        // Bound BEFORE append: one oversized native error must not grow the backing
        // builder to the size of the entire incoming string and retain that capacity.
        var tail = text.AsSpan();
        if (tail.Length > _maxChars)
        {
            int start = tail.Length - _maxChars;
            if (char.IsLowSurrogate(tail[start]) && char.IsHighSurrogate(tail[start - 1])) start++;
            tail = tail[start..];
            entry.Text.Clear();
        }
        entry.Text.Append(tail);
        if (entry.Text.Length > _maxChars)
        {
            int cut = entry.Text.Length - _maxChars;
            for (int i = cut; i < entry.Text.Length; i++)
            {
                if (entry.Text[i] == '\n' && i + 1 < entry.Text.Length) { cut = i + 1; break; }
            }
            if (cut < entry.Text.Length && char.IsLowSurrogate(entry.Text[cut])
                && char.IsHighSurrogate(entry.Text[cut - 1])) cut++;
            entry.Text.Remove(0, cut);
        }
        entry.Revision = ++_revision;
    }

    public void Clear(string key)
    {
        lock (_gate) _entries.Remove(key);
    }

    public bool TryRead(string key, long knownRevision, out long revision, out string? text)
    {
        lock (_gate)
        {
            _entries.TryGetValue(key, out var entry);
            revision = entry?.Revision ?? 0;
            if (knownRevision == revision) { text = null; return false; }
            text = entry?.Text.ToString() ?? "";
            return true;
        }
    }

    /// <summary>Copy/export reads the latest diagnostics, not the last painted frame.</summary>
    public string Read(string key)
    {
        TryRead(key, -1, out _, out var text);
        return text!;
    }
}
