using System.Runtime.InteropServices;

namespace QeliCli;

/// <summary>Windows grants only a short shutdown window. Request ordinary cleanup;
/// durable recovery remains necessary for forced process termination.</summary>
internal sealed class ConsoleLifetime:IDisposable
{
    private readonly Handler handler;
    private readonly ManualResetEventSlim finished=new(false);
    internal ConsoleLifetime(CancellationTokenSource cancellation)
    {
        handler=type=> {
            if(type is not (2 or 5 or 6)) return false;
            try {cancellation.Cancel();finished.Wait(TimeSpan.FromSeconds(4));} catch { }
            return true;
        };
        _=SetConsoleCtrlHandler(handler,true);
    }
    public void Dispose() {finished.Set();_=SetConsoleCtrlHandler(handler,false);}
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate bool Handler(uint type);
    [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleCtrlHandler(Handler handler,[MarshalAs(UnmanagedType.Bool)]bool add);
}
