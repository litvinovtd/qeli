using Qeli.Shared.Model;
using QeliWin.Vpn;

namespace QeliWin.Service;

// Only OS adapters live here; transition decisions are shared by both desktop clients.
internal sealed class ServiceProfileTransition(
    Func<bool> installed, Func<bool> desiredConnected, Func<VpnConfig?> readProfile,
    Action stop, Action<byte[]> publish, Action install, Action start, Action uninstall,
    Action? validateRegistration = null, Func<IDisposable>? controlGate=null)
{
    internal static readonly ServiceProfileTransition Current = new(
        ServiceManager.IsInstalled, ServiceState.DesiredConnected, ServiceState.LoadProfile,
        ServiceManager.Stop, ServiceState.PublishProfile, ServiceManager.Install,
        ServiceManager.Start, ServiceManager.Uninstall, ServiceManager.EnsureRegistration, WindowsControlGate.Acquire);
    private readonly DesktopServiceProfileTransition Transition = new(
        installed, desiredConnected, readProfile, stop, publish, install, start, uninstall,
        ServiceState.EncodeProfile, validateRegistration);
    internal void Apply(VpnConfig? profile, bool connectRequested) { using var gate=controlGate?.Invoke(); Transition.Apply(profile, connectRequested); }
    internal bool UsesProfile(string id) => Transition.UsesProfile(id);
    internal static VpnConfig Snapshot(VpnConfig profile, string logLevel,string adapterMode=WindowsAdapterPolicy.Off) =>
        WindowsAdapterPolicy.Snapshot(DesktopServiceProfileTransition.Snapshot(profile, logLevel),adapterMode);
}
