using Qeli.Shared.Vpn;

namespace QeliMac.Service;

// Privileged control writes are required, unlike the daemon's best-effort heartbeat.
// Keep ordering testable without invoking launchctl or touching host networking.
internal static class ServiceStatusTransition
{
    internal static void BeginStart(Action invalidateStopped, Action enableConnection)
    {
        invalidateStopped(); // Failure must leave the connection disabled.
        enableConnection();
    }

    internal static void CompleteStop(IEnumerable<Action> recoveries,
        Func<ServiceStatus?> readStatus, Action<VpnStatus, string?, bool> publish)
    {
        try
        {
            var failures = new List<Exception>();
            foreach (var recover in recoveries)
            {
                try { recover(); }
                catch (Exception error) { failures.Add(error); }
            }
            if (failures.Count != 0)
                throw new AggregateException("macOS network recovery remains incomplete", failures);

            // DNS recovery alone cannot vouch for all tunnel cleanup (routes, pf, etc.).
            // Never erase the daemon's terminal failure just because launchd lost its PID.
            var snapshot = readStatus();
            if (snapshot?.Status != nameof(VpnStatus.Disconnected))
                throw new InvalidOperationException(snapshot?.Status == nameof(VpnStatus.Error)
                    ? snapshot.Extra ?? "Daemon shutdown failed; network state is unknown"
                    : "Daemon did not confirm a clean disconnect; tunnel state is unknown");

            publish(VpnStatus.Disconnected, null, true);
        }
        catch (Exception error)
        {
            try { publish(VpnStatus.Error, error.Message, false); }
            catch (Exception publicationError)
            {
                throw new AggregateException("Stop failed and its status could not be published", error, publicationError);
            }
            throw;
        }
    }
}
