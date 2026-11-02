using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>The OS callback must live in a native image, not a CLR delegate thunk.
/// Registration never creates a device or configures the network.</summary>
internal static class PersistentWintunCallbacks
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate void Created(IntPtr device,int result,IntPtr context,IntPtr instance);

    // Both DLL and delegate are process-rooted. Numeric IDs (not GCHandles or
    // allocated pointers) make callbacks after timeout/Dispose harmless.
    private static readonly Created Forward=OnCreated;
    private static readonly Lazy<IntPtr> NativeAddress=new(LoadAddress);
    private static readonly ConcurrentDictionary<IntPtr,TaskCompletionSource<(int result,string id)>> Pending=new();
    private static long _nextContext;

    [DllImport("qeli",CallingConvention=CallingConvention.Cdecl,ExactSpelling=true)]
    private static extern IntPtr qeli_windows_swdevice_callback_address(Created forward);

    internal static IntPtr Address => NativeAddress.Value;
    private static IntPtr LoadAddress()
    {
        try
        {
            var address=qeli_windows_swdevice_callback_address(Forward);
            if(address==IntPtr.Zero) throw new InvalidOperationException("Native callback registration was refused");
            return address;
        }
        catch(EntryPointNotFoundException error)
        {
            throw new InvalidOperationException("Persistent Wintun requires the matching updated qeli.dll; the Software Device callback bridge is missing",error);
        }
    }

    private static void OnCreated(IntPtr device,int result,IntPtr context,IntPtr instance)
    {
        try
        {
            if(Pending.TryGetValue(context,out var completion))
                completion.TrySetResult((result,Marshal.PtrToStringUni(instance) ?? ""));
        }
        catch(Exception error)
        {
            // Never let a managed exception cross a native callback boundary.
            if(Pending.TryGetValue(context,out var completion)) completion.TrySetException(error);
        }
    }

    internal sealed class Registration : IDisposable
    {
        internal IntPtr Context {get;}
        private readonly TaskCompletionSource<(int result,string id)> _completion=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Registration()
        {
            long next=Interlocked.Increment(ref _nextContext);
            if(next<=0) throw new InvalidOperationException("Persistent creation context exhausted");
            Context=new IntPtr(next);
            if(!Pending.TryAdd(Context,_completion)) throw new InvalidOperationException("Persistent creation context collision");
        }
        internal (int result,string id) Wait(int milliseconds)
        {
            if(!_completion.Task.Wait(milliseconds)) throw new TimeoutException("Persistent Wintun enumeration timed out");
            return _completion.Task.GetAwaiter().GetResult();
        }
        public void Dispose() => Pending.TryRemove(Context,out _);
    }
}
