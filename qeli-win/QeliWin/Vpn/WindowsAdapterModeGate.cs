using System.IO;
using QeliWin.Service;

namespace QeliWin.Vpn;

/// <summary>Machine-wide readers = complete connection runs, writer = mode change.
/// File sharing is process/thread independent and automatically released after a crash.
/// This gate must remain held through reconnect gaps and incomplete platform cleanup.</summary>
internal static class WindowsAdapterModeGate
{
    internal static IDisposable Shared()=>Open(writer:false);
    internal static IDisposable Exclusive()=>Open(writer:true);
    private static IDisposable Open(bool writer)
    {
        StorageLayout.EnsureRoot();
        string directory=Path.Combine(StorageLayout.Root,"persistent-adapters");
        StorageLayout.EnsureDirectory(directory,privateData:true);
        string path=Path.Combine(directory,"mode.lock");
        if(!StorageLayout.Exists(path)) {
            try {
                using var created=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.ReadWrite);
                ServiceState.RequireTrusted(path,privateFile:true);
            }
            catch(IOException) when(StorageLayout.Exists(path)) { /* Another creator won; check ACL below. */ }
        }
        ServiceState.CheckExistingFile(path);
        var file=OpenLeaseFile(path,writer);
        try {ServiceState.RequireTrusted(path,privateFile:true);return file;}
        catch {file.Dispose();throw;}
    }
    // Only the caller above selects/validates privileged storage. Isolated tests use
    // their own temporary file to exercise the real OS sharing semantics without PnP.
    internal static FileStream OpenLeaseFile(string path,bool writer)
    {
        FileStream file;
        try {file=new FileStream(path,FileMode.Open,writer?FileAccess.ReadWrite:FileAccess.Read,writer?FileShare.None:FileShare.Read);}
        catch(IOException error) when((error.HResult&0xffff)==32) {
            throw new InvalidOperationException(writer
                ? "Disconnect all Qeli GUI/service sessions before changing persistent adapter mode; cleanup must finish first"
                : "Persistent adapter mode is being changed; retry connecting after it completes",error);
        }
        return file;
    }
}
