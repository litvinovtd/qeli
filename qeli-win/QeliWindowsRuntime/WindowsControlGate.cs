using System.IO;

namespace QeliWin.Service;

/// <summary>Serializes complete GUI/CLI service transitions across processes.
/// Synchronous SCM transactions may nest on the same thread; they never await.</summary>
internal static class WindowsControlGate
{
    [ThreadStatic] private static Holder? current;
    private sealed class Holder(FileStream file) {internal readonly FileStream File=file;internal int Count=1;}
    internal static IDisposable Acquire()
    {
        if(current!=null) {current.Count++;return new Lease(current);}
        StorageLayout.EnsureRoot();
        var file=TrustedLease.Open(Path.Combine(StorageLayout.Root,"service-control.lock"));
        current=new Holder(file);return new Lease(current);
    }
    private sealed class Lease(Holder holder):IDisposable
    {
        private bool disposed;
        public void Dispose() {
            if(disposed)return;disposed=true;
            if(!ReferenceEquals(current,holder)) throw new InvalidOperationException("Service control lease crossed threads");
            if(--holder.Count==0) {holder.File.Dispose();current=null;}
        }
    }
}

internal static class TrustedLease
{
    internal static FileStream Open(string path)
    {
        if(!StorageLayout.Exists(path)) {
            try {using var created=new FileStream(path,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.ReadWrite);ServiceState.RequireTrusted(path,privateFile:true);}
            catch(IOException) when(StorageLayout.Exists(path)) { }
        }
        ServiceState.CheckExistingFile(path);
        var file=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None);
        try {ServiceState.RequireTrusted(path,privateFile:true);return file;}
        catch {file.Dispose();throw;}
    }
}
