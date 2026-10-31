using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Platform lifecycle wrapper for WireGuard's Wintun adapter. Managed code creates a unique
/// interface and keeps its creator handle for network setup/cleanup, but never starts a session
/// or touches packet bytes. The ABI 1.9 Rust core opens an independent handle by
/// <see cref="AdapterName"/> and owns the session, wait event and both rings.
/// </summary>
public sealed class WintunAdapter : IDisposable, Qeli.Shared.Vpn.IWintunTunDevice
{
    private const string Dll = "wintun.dll";

    private IntPtr _adapter;
    private bool _disposed;
    private bool _closing;
    private bool _initialized;
    private readonly object _gate = new();
    private readonly Func<string, Guid, IntPtr> _create;
    private readonly Func<IntPtr, ulong> _getLuid;
    private readonly Action<IntPtr> _close;
    private PersistentWintunDevice.Lease? _persistent;
    internal PersistentWintunDevice.Lease? PersistentLease => _persistent;

    public WintunAdapter() : this((name, guid) => WintunCreateAdapter(name, "Qeli", ref guid),
        adapter => { WintunGetAdapterLUID(adapter, out ulong luid); return luid; }, WintunCloseAdapter) { }

    internal WintunAdapter(Func<string, Guid, IntPtr> create, Func<IntPtr, ulong> getLuid, Action<IntPtr> close)
    {
        _create = create; _getLuid = getLuid; _close = close;
    }
    internal bool HasHandle { get { lock (_gate) return _adapter != IntPtr.Zero; } }
    internal void RequireReady()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed || _closing, this);
            if (!_initialized) throw new InvalidOperationException("Wintun initialization did not complete; cleanup is required");
        }
    }

    public ulong Luid { get; private set; }
    public string AdapterName { get; private set; } = "";
    internal string InterfaceAlias => _persistent?.Adapter.Alias is {Length:>0} alias ? alias : AdapterName;
    private Guid _createdGuid;
    internal void WithOwnedIdentity(Action<ulong, Guid> action)
    {
        lock (_gate)
        {
            RequireReady();
            if (_adapter == IntPtr.Zero || _createdGuid == Guid.Empty) throw new InvalidOperationException("No created Wintun adapter is owned");
            _persistent?.Verify();
            action(Luid, _createdGuid);
        }
    }

    [DllImport(Dll, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr WintunCreateAdapter(string name, string tunnelType,
        ref Guid requestedGuid);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(Dll, SetLastError = true)]
    private static extern void WintunGetAdapterLUID(IntPtr adapter, out ulong luid);

    [DllImport(Dll, SetLastError = true)]
    private static extern uint WintunGetRunningDriverVersion();

    /// <summary>Create a qeli-owned adapter. Requires administrator privileges.</summary>
    public void Open(string name, Guid guid)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed || _closing, this);
            if (_adapter != IntPtr.Zero)
                throw new InvalidOperationException("Wintun adapter is already open");

            // Never adopt an existing adapter: teardown must not remove a foreign VPN interface.
            // The stable name/GUID is attempted first; collisions use a fresh pair and the actual
            // created name is what ABI 1.9 hands to Rust for its independent OpenAdapter handle.
            string candidateName = name;
            Guid candidateGuid = guid;
            int error = 0;
            for (int attempt = 0; attempt < 4; attempt++)
            {
                _adapter = _create(candidateName, candidateGuid);
                if (_adapter != IntPtr.Zero)
                {
                    AdapterName = candidateName;
                    _createdGuid = candidateGuid;
                    break;
                }
                error = Marshal.GetLastWin32Error();
                candidateName = $"{name}-{attempt}";
                candidateGuid = Guid.NewGuid();
            }
            if (_adapter == IntPtr.Zero)
                throw new Win32Exception(error,
                    $"WintunCreateAdapter failed (err {error}; fresh name/GUID retries also failed)");

            Luid = _getLuid(_adapter);
            _initialized = true;
        }
    }

    public static uint RunningDriverVersion()
    {
        try { return WintunGetRunningDriverVersion(); } catch { return 0; }
    }

    /// <summary>Force-load the embedded wintun.dll without requiring an adapter.</summary>
    public static uint ProbeLoad() => WintunGetRunningDriverVersion();

    internal void OpenPersistent(string name, Guid key, PersistentWintunDevice.IStore? store=null, PersistentWintunDevice.IPlatform? platform=null)
    {
        lock(_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed || _closing,this);
            if(_adapter!=IntPtr.Zero) throw new InvalidOperationException("Wintun adapter is already open");
            var lease=PersistentWintunDevice.Open(key,name,store,platform);
            _persistent=lease;
            _adapter=lease.Adapter.Value;Luid=lease.Adapter.Luid;
            AdapterName=lease.Record.Name;_createdGuid=lease.Record.InterfaceGuid;
            _initialized=lease.Record.Network==null;
        }
    }

    internal void CompletePersistentRecovery()
    {
        lock(_gate)
        {
            if(_persistent==null || _adapter==IntPtr.Zero || _persistent.Record.Network!=null)
                throw new InvalidOperationException("Persistent adapter recovery did not complete");
            _initialized=true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _closing = true;
            if (_adapter != IntPtr.Zero)
            {
                if(_persistent!=null) { _persistent.Dispose(); _persistent=null; }
                else _close(_adapter); // Retain exact handle on failure so Stop can retry.
                _adapter = IntPtr.Zero;
            }
            Luid = 0;
            _createdGuid = Guid.Empty;
            AdapterName = "";
            _initialized = false;
            _disposed = true;
        }
    }
}
