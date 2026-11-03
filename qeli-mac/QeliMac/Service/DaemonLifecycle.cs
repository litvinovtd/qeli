using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Service;

// One daemon loop owns lifecycle flags; worker callbacks only update a synchronized status pair.
internal sealed class DaemonLifecycle(Func<VpnConfig?> load, Func<VpnConfig, bool> start,
    Action stop, Action<string> log, Action<int>? delay = null)
{
    private readonly object _statusGate = new();
    private VpnStatus _status = VpnStatus.Disconnected;
    private string? _extra;
    private bool _cleanupFailed;
    private bool _needsCleanup;
    private bool _startRefused;
    internal bool Started { get; private set; }
    internal bool CanPoll => Started && !_cleanupFailed;
    internal (VpnStatus status, string? extra) Snapshot { get { lock (_statusGate) return (_status, _extra); } }
    internal void Publish(Action<VpnStatus, string?> write)
    {
        lock (_statusGate) write(_status, _extra);
    }
    internal void Observe(VpnStatus status, string? extra)
    {
        lock (_statusGate)
        {
            if (_cleanupFailed) return; // Delayed worker callbacks cannot erase pending cleanup.
            _status = status; _extra = extra;
        }
    }
    internal void Step(bool desired)
    {
        if (!desired)
        {
            if (_needsCleanup && !StopWithRetry("user disconnect")) return;
            _startRefused = false;
            return;
        }
        if (Started || _startRefused || _cleanupFailed) return;
        try
        {
            var profile = load();
            if (profile is null) { Observe(VpnStatus.Disconnected, "no profile configured"); return; }
            ProfileStorePayload.Validate(profile);
            _needsCleanup = true; // Retain partial Start ownership even if it throws/refuses.
            Observe(VpnStatus.Connecting, null);
            Started = start(profile);
            _startRefused = !Started;
            if (!Started && Snapshot.status != VpnStatus.Error)
                Observe(VpnStatus.Error, "Tunnel start was refused; disconnect before retrying");
        }
        catch (Exception error)
        {
            _startRefused = true;
            Observe(VpnStatus.Error, error.Message);
            log($"Could not start tunnel: {error.Message}");
        }
    }
    private bool StopWithRetry(string reason)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                log($"Stopping tunnel ({reason}), attempt {attempt}/3");
                stop();
                Started = false; _needsCleanup = false;
                lock (_statusGate) { _cleanupFailed = false; _status = VpnStatus.Disconnected; _extra = null; }
                return true;
            }
            catch (Exception error)
            {
                lock (_statusGate)
                {
                    _cleanupFailed = true; _status = VpnStatus.Error;
                    _extra = $"disconnect incomplete: {error.Message}";
                }
                log($"Tunnel cleanup attempt {attempt}/3 failed: {error.Message}");
                if (attempt < 3) (delay ?? Thread.Sleep)(250);
            }
        }
        return false;
    }
    internal void Shutdown()
    {
        if (_needsCleanup && !StopWithRetry("launchd stop"))
            throw new InvalidOperationException("Daemon stopped before macOS network cleanup completed");
        // A rejected profile may leave Error without ever acquiring network ownership.
        // Successful shutdown is still a clean disconnect; failed cleanup above never reaches here.
        Observe(VpnStatus.Disconnected, null);
    }
}
