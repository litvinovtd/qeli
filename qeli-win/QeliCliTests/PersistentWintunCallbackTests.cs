using System.Runtime.InteropServices;
using System.Text;
using QeliWin.Vpn;

// No PnP, adapter, route, DNS or administrator operations. Invoke only the actual
// DLL trampoline with synthetic results, as Windows would call it after creation.
internal static class PersistentWintunCallbackTests
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate IntPtr Register(IntPtr forward);
    [DllImport("kernel32.dll",ExactSpelling=true,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetModuleHandleExW(uint flags,IntPtr address,out IntPtr module);
    [DllImport("kernel32.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]
    private static extern uint GetModuleFileNameW(IntPtr module,StringBuilder path,uint length);

    internal static void Run(Action<bool,string> check)
    {
        var address=PersistentWintunCallbacks.Address;
        check(address!=IntPtr.Zero && address==PersistentWintunCallbacks.Address,"persistent callback address is stable");
        check(GetModuleHandleExW(6,address,out var module),"OS callback belongs to a loaded native image");
        var path=new StringBuilder(1024);
        check(GetModuleFileNameW(module,path,(uint)path.Capacity)>0 && Path.GetFileName(path.ToString()).Equals("qeli.dll",StringComparison.OrdinalIgnoreCase),
            "OS callback belongs to the protected Qeli core, not a CLR thunk");
        var callback=Marshal.GetDelegateForFunctionPointer<PersistentWintunCallbacks.Created>(address);
        var text=Marshal.StringToHGlobalUni("SWD\\Wintun\\тест-1");
        try
        {
            using(var pending=new PersistentWintunCallbacks.Registration())
            {
                callback(new IntPtr(11),unchecked((int)0x80070005),pending.Context,text);
                callback(new IntPtr(11),0,pending.Context,IntPtr.Zero); // Duplicate must not overwrite first result.
                var result=pending.Wait(1000);
                check(result==(unchecked((int)0x80070005),"SWD\\Wintun\\тест-1"),"native callback preserves HRESULT, context and Unicode instance");
            }
            var expired=new PersistentWintunCallbacks.Registration();
            bool timedOut=false;
            try {expired.Wait(0);} catch(TimeoutException) {timedOut=true;}
            expired.Dispose();expired.Dispose();
            callback(IntPtr.Zero,0,expired.Context,text);
            using(var next=new PersistentWintunCallbacks.Registration())
            {
                check(timedOut && next.Context!=expired.Context,"timed out contexts are never reused");
                callback(IntPtr.Zero,0,next.Context,IntPtr.Zero);
                check(next.Wait(1000)==(0,""),"late callback cannot complete another operation; null instance is safe");
            }
            Parallel.For(0,32,index=>
            {
                using var pending=new PersistentWintunCallbacks.Registration();
                callback(IntPtr.Zero,index,pending.Context,text);
                if(pending.Wait(1000)!=(index,"SWD\\Wintun\\тест-1")) throw new Exception("Callback context cross-talk");
            });
            check(true,"concurrent native callbacks stay correlated");

            PersistentWintunCallbacks.Created other=(_,_,_,_)=>throw new Exception("Replacement target must never run");
            var otherAddress=Marshal.GetFunctionPointerForDelegate(other);
            var register=Marshal.GetDelegateForFunctionPointer<Register>(NativeLibrary.GetExport(module,"qeli_windows_swdevice_callback_address"));
            check(register(IntPtr.Zero)==IntPtr.Zero && register(otherAddress)==IntPtr.Zero,"null or replacement forwarding target is refused");
            GC.KeepAlive(other);
        }
        finally {Marshal.FreeHGlobal(text);}

        _=Marshal.GetHRForException(new COMException("STALE unrelated missing module",unchecked((int)0x8007007E)));
        bool exact=false;
        try {PersistentWintunNative.CheckResult(unchecked((int)0x80070057),"SwDeviceCreate control");}
        catch(COMException error) {exact=error.HResult==unchecked((int)0x80070057) && error.Message.Contains("SwDeviceCreate control") && error.Message.Contains("0x80070057") && !error.Message.Contains("STALE");}
        check(exact,"PnP failure keeps real HRESULT and stage despite stale COM IErrorInfo");
        PersistentWintunNative.CheckResult(0,"success");
        PersistentWintunNative.CheckResult(1,"success with status");
        check(true,"successful HRESULTs are accepted");
    }
}
