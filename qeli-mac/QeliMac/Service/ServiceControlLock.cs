using System.Diagnostics;

namespace QeliMac.Service;

// Synchronous, reentrant on the owning thread. Native advisory lock releases on process exit.
internal sealed class ServiceControlLock(Func<IDisposable> tryAcquire, int milliseconds = 1000)
{
    private readonly ThreadLocal<State> _states = new(() => new());
    private sealed class State { internal int Depth; internal IDisposable? Handle; }

    internal IDisposable Enter()
    {
        var state = _states.Value!;
        if (state.Depth == 0)
        {
            var wait = Stopwatch.StartNew();
            while (true)
            {
                try { state.Handle = tryAcquire(); break; }
                catch (IOException) when (wait.ElapsedMilliseconds < milliseconds) { Thread.Sleep(25); }
            }
        }
        state.Depth++;
        return new Lease(state);
    }

    private sealed class Lease(State state) : IDisposable
    {
        private readonly int _thread = Environment.CurrentManagedThreadId;
        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;
            if (_thread != Environment.CurrentManagedThreadId) throw new InvalidOperationException("Control lease must be released on its owning thread");
            _disposed = true;
            if (--state.Depth == 0) { state.Handle!.Dispose(); state.Handle = null; }
        }
    }
}
