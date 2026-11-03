using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Service;

internal readonly record struct ServiceObservation(VpnStatus Status, string? Extra, ServiceStatus? Snapshot)
{
    internal static string LogDelta(string previous, string current) =>
        current.StartsWith(previous, StringComparison.Ordinal) ? current[previous.Length..] : current;
    internal static ServiceObservation Resolve(ServiceStatus? snapshot, DateTime now)
    {
        if (snapshot is null) return new(VpnStatus.Error, "Daemon status is unavailable; tunnel state is unknown", null);
        try { DesktopServiceStatus.Validate(snapshot); }
        catch { return new(VpnStatus.Error, "Daemon status is invalid", null); }
        // A terminal cleanup failure remains visible even after the daemon stops writing.
        if (!DesktopServiceStatus.Fresh(snapshot, now, TimeSpan.FromSeconds(5)))
            return snapshot.Status switch
            {
                nameof(VpnStatus.Error) => new(VpnStatus.Error, snapshot.Extra, null),
                // Only a completed root Stop() writes this; a hung daemon never can.
                nameof(VpnStatus.Disconnected) when snapshot.Stopped => new(VpnStatus.Disconnected, null, null),
                _ => new(VpnStatus.Error, "Daemon status is stale; tunnel state is unknown", null),
            };
        return new(Enum.Parse<VpnStatus>(snapshot.Status), snapshot.Extra, snapshot);
    }
}
