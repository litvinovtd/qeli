using QeliWin.Service;
using Qeli.Shared.Vpn;

namespace QeliCli;

internal static class ServiceResultPolicy
{
    internal static bool Connected(ServiceObservation observation,string profileId,long requestedAt) =>
        observation.Status==VpnStatus.Connected && observation.Snapshot?.ControlProtocolVersion==1 && observation.Snapshot?.ProfileId==profileId
        && observation.Snapshot.MonotonicTimeMs>=requestedAt;

    internal static bool CleanupConfirmed(ServiceStatus? terminal,long requestedAt,long? now=null) =>
        terminal?.Status==nameof(VpnStatus.Disconnected) && terminal.MonotonicTimeMs>=requestedAt && terminal.MonotonicTimeMs<=(now ?? ServiceMonotonicClock.NowMilliseconds);
}
