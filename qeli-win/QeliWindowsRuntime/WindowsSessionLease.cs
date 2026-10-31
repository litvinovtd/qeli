using QeliWin.Service;

namespace QeliWin.Vpn;

/// <summary>One Windows tunnel owner, spanning reconnect and unfinished cleanup.
/// OS file sharing releases ownership after process death; recovery journals remain.</summary>
internal static class WindowsSessionLease
{
    internal static IDisposable Acquire()
    {
        StorageLayout.EnsureRoot();
        FileStream owner;
        try {owner=TrustedLease.Open(Path.Combine(StorageLayout.Root,"tunnel-owner.lock"));}
        catch(IOException error) when((error.HResult&0xffff)==32) {throw new InvalidOperationException("Another Qeli GUI, CLI or service owns the VPN",error);}
        try {
            // Recovery is mutating and belongs only to the exclusive tunnel owner.
            KillSwitch.Sweep();
            return new Lease(owner,WindowsAdapterModeGate.Shared());
        } catch {owner.Dispose();throw;}
    }
    private sealed class Lease(FileStream owner,IDisposable adapter):IDisposable
    {
        public void Dispose() {adapter.Dispose();owner.Dispose();}
    }
}
