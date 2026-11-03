namespace QeliWin.Vpn;

// A failed retired-gate close may keep blocking traffic. Track every generation until
// successful close; never lose the previous handle when publishing its replacement.
internal sealed class RetainedDriverGates
{
    private IDisposable? _current;
    private readonly List<IDisposable> _retired = new();
    internal bool HasOwnership => _current != null || _retired.Count != 0;
    internal void Replace(Func<IDisposable> create, Action? published = null)
    {
        // Refuse another native Open while a retired generation cannot close.
        // Pending retirement is bounded to one generation, rather than growing on retries.
        CloseRetired();
        var next = create();
        if (_current != null) _retired.Add(_current);
        _current = next;
        published?.Invoke();
        CloseRetired();
    }
    internal void Close()
    {
        var failures = new List<Exception>();
        if (_current != null)
        {
            try { _current.Dispose(); _current = null; }
            catch (Exception error) { failures.Add(error); }
        }
        CloseRetired(failures);
        if (failures.Count != 0) throw new AggregateException("Driver gate cleanup incomplete; ownership retained", failures);
    }
    private void CloseRetired(List<Exception>? failures = null)
    {
        bool ownErrors = failures == null;
        failures ??= new();
        for (int i = _retired.Count - 1; i >= 0; i--)
        {
            try { _retired[i].Dispose(); _retired.RemoveAt(i); }
            catch (Exception error) { failures.Add(error); }
        }
        if (ownErrors && failures.Count != 0)
            throw new AggregateException("Previous driver gates remain owned for cleanup retry", failures);
    }
}
