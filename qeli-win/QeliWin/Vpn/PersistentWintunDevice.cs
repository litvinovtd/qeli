using System.IO;
using System.Text.Json;
using QeliWin.Service;

namespace QeliWin.Vpn;

/// <summary>Persistent device ownership is independent of a VPN session or GUI lifetime.
/// Public SwDevice APIs only; never dereference Wintun's opaque adapter handle.</summary>
internal static class PersistentWintunDevice
{
    internal sealed record Record
    {
        public int Version { get; init; } = 1;
        public Guid Key { get; init; }
        public Guid Token { get; init; }
        public string Instance { get; init; } = "";
        public string Name { get; init; } = "";
        public string DeviceId { get; init; } = "";
        public Guid InterfaceGuid { get; init; }
        public PersistentWintunNetwork.State? Network { get; init; }
    }
    internal sealed record Node(string DeviceId, string Name, Guid Token, Guid InterfaceGuid);
    internal sealed record Handle(IntPtr Value, ulong Luid, Guid InterfaceGuid, string Alias="");
    internal interface IPlatform
    {
        Node? Find(string name);
        (IntPtr device, string deviceId) Create(Record record);
        void SetLifetime(IntPtr device, bool persistent);
        void CloseDevice(IntPtr device);
        Handle OpenAdapter(string name);
        void CloseAdapter(IntPtr adapter);
    }
    internal interface IStore
    {
        IDisposable Lock(Guid key);
        Record? Read(Guid key);
        void Write(Record record);
        void Delete(Guid key);
        IEnumerable<Guid> Keys();
    }

    internal static readonly IStore Store = new FileStore();
    internal static readonly IPlatform Platform = new PersistentWintunNative();

    internal static void Validate(Record record, Guid key)
    {
        if (record.Version != 1 || key == Guid.Empty || record.Key != key || record.Token == Guid.Empty
            || !Guid.TryParseExact(record.Instance, "B", out var instance) || instance == Guid.Empty
            || string.IsNullOrWhiteSpace(record.Name) || record.Name.Length > 63 || record.Name.Any(char.IsControl)
            || record.DeviceId.Length > 200 || record.DeviceId.Any(char.IsControl))
            throw new InvalidDataException("Invalid persistent Wintun ownership record");
        if (record.DeviceId.Length != 0 && !record.DeviceId.StartsWith("SWD\\Wintun\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Persistent device is not a Wintun software device");
        if (record.InterfaceGuid != Guid.Empty && record.DeviceId.Length == 0)
            throw new InvalidDataException("Persistent interface receipt has no device identity");
    }

    private static void Match(Record record, Node node)
    {
        if (node.Name != record.Name || node.Token != record.Token || node.InterfaceGuid == Guid.Empty
            || !node.DeviceId.StartsWith("SWD\\Wintun\\", StringComparison.OrdinalIgnoreCase)
            || (record.DeviceId.Length != 0 && !node.DeviceId.Equals(record.DeviceId, StringComparison.OrdinalIgnoreCase))
            || (record.InterfaceGuid != Guid.Empty && node.InterfaceGuid != record.InterfaceGuid))
            throw new InvalidOperationException("Persistent Wintun ownership/GUID mismatch; refusing to adopt or modify this device");
    }

    internal static Lease Open(Guid key, string name, IStore? store = null, IPlatform? platform = null, bool allowCreate=true)
    {
        store ??= Store; platform ??= Platform;
        var gate = store.Lock(key);
        IntPtr device = IntPtr.Zero;
        Handle? adapter = null;
        try
        {
            var record = store.Read(key);
            var node = platform.Find(record?.Name ?? name);
            if (record == null)
            {
                if(!allowCreate) throw new InvalidOperationException("No persistent adapter receipt");
                if (node != null) throw new InvalidOperationException("Adapter name is already used without a Qeli ownership receipt");
                record = new Record {Key=key,Token=Guid.NewGuid(),Instance=Guid.NewGuid().ToString("B"),Name=name};
                Validate(record,key);
                store.Write(record); // Durable creation intent BEFORE the PnP mutation.
            }
            Validate(record,key);
            if (node == null)
            {
                if(!allowCreate) throw new InvalidOperationException("Persistent adapter is absent; recovery never creates a device");
                if (record.InterfaceGuid != Guid.Empty)
                    throw new InvalidOperationException("Previously installed persistent adapter is missing; explicit removal/reinstallation is required, not a new GUID");
                (device, var id) = platform.Create(record);
                record = record with {DeviceId=id};
                Validate(record,key);
                store.Write(record);
                node = platform.Find(record.Name) ?? throw new InvalidOperationException("Created persistent Wintun did not become ready");
            }
            Match(record,node);
            adapter = platform.OpenAdapter(record.Name);
            if (adapter.Value == IntPtr.Zero || adapter.Luid == 0 || adapter.InterfaceGuid != node.InterfaceGuid)
                throw new InvalidOperationException("Opened Wintun handle does not match the owned persistent device");
            if (device != IntPtr.Zero) platform.SetLifetime(device,persistent:true);
            record = record with {DeviceId=node.DeviceId,InterfaceGuid=node.InterfaceGuid};
            store.Write(record);
            if (device != IntPtr.Zero) {platform.CloseDevice(device);device=IntPtr.Zero;}
            var lease = new Lease(store,platform,gate,record,adapter);
            gate = null!; adapter = null;
            return lease;
        }
        finally
        {
            if (adapter != null) platform.CloseAdapter(adapter.Value);
            if (device != IntPtr.Zero) platform.CloseDevice(device);
            gate?.Dispose();
        }
    }

    internal sealed class Lease : IDisposable
    {
        private readonly IStore _store;
        private readonly IPlatform _platform;
        private IDisposable? _gate;
        internal Record Record {get;private set;}
        internal Handle Adapter {get;}
        internal string? RecoveryPath => _store is FileStore ? FileStore.PathFor(Record.Key) : null;
        internal Lease(IStore store,IPlatform platform,IDisposable gate,Record record,Handle adapter)
        { _store=store;_platform=platform;_gate=gate;Record=record;Adapter=adapter; }
        internal void Verify()
        {
            ObjectDisposedException.ThrowIf(_gate == null,this);
            Match(Record,_platform.Find(Record.Name) ?? throw new InvalidOperationException("Owned persistent device disappeared"));
        }
        internal void SaveNetwork(PersistentWintunNetwork.State? network)
        {
            Verify();
            var next=Record with {Network=network};
            _store.Write(next); Record=next;
        }
        public void Dispose()
        {
            if (_gate == null) return;
            if (Record.Network != null) throw new InvalidOperationException("Persistent Wintun network recovery is pending; retaining its lease");
            CloseRecoveryHandle();
        }
        // Recovery tools have no packet session. On failure, keep the durable journal
        // but close their temporary control handle so the next recovery can retry.
        // Active VPN wrappers must use Dispose(), which refuses incomplete cleanup.
        internal void CloseRecoveryHandle()
        {
            if(_gate==null) return;
            _platform.CloseAdapter(Adapter.Value); // OpenAdapter handle, never the device creator.
            _gate.Dispose(); _gate=null;
        }
    }

    internal static void Remove(Guid key, Action<Lease> recover, IStore? store=null, IPlatform? platform=null)
    {
        store ??=Store; platform ??=Platform;
        // A previous remove may have completed PnP removal but crashed before deleting
        // the receipt. Clearing an absent, explicitly selected device is recoverable.
        using(var gate=store.Lock(key))
        {
            var record=store.Read(key) ?? throw new InvalidOperationException("No persistent adapter receipt");
            Validate(record,key);
            if(platform.Find(record.Name)==null) {store.Delete(key);return;}
        }
        var lease=OpenExisting(key,store,platform);
        try {
        recover(lease);
        if (lease.Record.Network != null) throw new InvalidOperationException("Cannot remove adapter with pending network recovery");
        lease.Verify();
        // Reacquire the same SwDevice with identical creation info; only our receipt and
        // device marker authorize this. LifetimeHandle + close is the documented uninstall.
        var (device,id)=platform.Create(lease.Record);
        try
        {
            if (!id.Equals(lease.Record.DeviceId,StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Removal reacquired a different software device");
            lease.Verify();
            platform.SetLifetime(device,persistent:false);
        }
        finally {platform.CloseDevice(device);}
        // A busy/open external session can delay PnP removal. Keep the receipt until
        // absence is verified; callers can retry, never enumerate/remove other adapters.
        lease.Dispose();
        using var finalGate=store.Lock(key);
        if (platform.Find(lease.Record.Name) != null)
            throw new InvalidOperationException("Persistent adapter removal is pending; close other users of this adapter and retry");
        if(store.Read(key) is { } current && current.Token!=lease.Record.Token)
            throw new InvalidOperationException("Persistent receipt changed during removal");
        store.Delete(key);
        }
        finally {lease.CloseRecoveryHandle();}
    }

    internal static Lease OpenExisting(Guid key,IStore? store=null,IPlatform? platform=null)
    {
        store ??=Store;
        var record=store.Read(key) ?? throw new InvalidOperationException("No persistent Qeli adapter receipt for this key");
        return Open(key,record.Name,store,platform,allowCreate:false);
    }

    private sealed class FileStore : IStore
    {
        private static string DirectoryPath => Path.Combine(StorageLayout.Root,"persistent-adapters");
        internal static string PathFor(Guid key) => Path.Combine(DirectoryPath,key.ToString("N")+".json");
        private static void Ensure()
        { StorageLayout.EnsureRoot();StorageLayout.EnsureDirectory(DirectoryPath,privateData:true); }
        public IDisposable Lock(Guid key)
        {
            if(key==Guid.Empty) throw new ArgumentException("Persistent adapter key is empty");
            Ensure();
            string path=Path.Combine(DirectoryPath,key.ToString("N")+".lock");
            ServiceState.CheckExistingFile(path);
            var file=new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
            try {ServiceState.RequireTrusted(path,privateFile:true);return file;}
            catch {file.Dispose();throw;}
        }
        public Record? Read(Guid key)
        {
            if(!StorageLayout.Exists(DirectoryPath)) return null;
            Ensure(); var path=PathFor(key);
            if(!StorageLayout.Exists(path)) return null;
            ServiceState.CheckExistingFile(path);
            using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
            if(file.Length>4*1024*1024) throw new InvalidDataException("Persistent adapter state exceeds 4 MiB");
            var record=JsonSerializer.Deserialize<Record>(file) ?? throw new InvalidDataException("Empty persistent adapter receipt");
            Validate(record,key);return record;
        }
        public void Write(Record record)
        {
            Validate(record,record.Key);Ensure();
            byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(record);
            if(bytes.Length>4*1024*1024) throw new InvalidDataException("Persistent adapter state exceeds 4 MiB");
            ServiceState.AtomicWrite(PathFor(record.Key),bytes);
        }
        public void Delete(Guid key) {Ensure();ServiceState.CheckExistingFile(PathFor(key));File.Delete(PathFor(key));}
        public IEnumerable<Guid> Keys()
        {
            if(!StorageLayout.Exists(DirectoryPath)) return [];
            Ensure();
            return Directory.EnumerateFiles(DirectoryPath,"*.json")
                .Select(Path.GetFileNameWithoutExtension).Select(s=>Guid.TryParseExact(s,"N",out var id)?id:Guid.Empty)
                .Where(id=>id!=Guid.Empty).ToArray();
        }
    }
}
