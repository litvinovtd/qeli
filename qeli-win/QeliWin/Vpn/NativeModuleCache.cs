namespace QeliWin.Vpn;

// These references intentionally live for the process: cached P/Invoke functions and
// Rust GetModuleHandle(Wintun) must never outlive their DLL. Repeated ensure calls do
// not add new LoadLibrary references; failed loads are retryable.
internal sealed class NativeModuleCache
{
    private readonly object _gate = new();
    private readonly Dictionary<string, IntPtr> _loaded = new(StringComparer.OrdinalIgnoreCase);
    internal IntPtr Load(string name, string path, Func<string, IntPtr> load)
    {
        lock (_gate)
        {
            if (_loaded.TryGetValue(name, out var module)) return module;
            module = load(path);
            if (module == IntPtr.Zero) throw new DllNotFoundException($"Native load returned no module: {name}");
            _loaded.Add(name, module);
            return module;
        }
    }
}
