using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
namespace QeliWin;

/// <summary>Keep normal and maximized dialogs inside the monitor work area,
/// including a top/left taskbar and monitors with negative/mixed-DPI origins.</summary>
internal static class WindowWorkArea
{
    [StructLayout(LayoutKind.Sequential)] internal struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct Point { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMax { public Point Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack; }
    [StructLayout(LayoutKind.Sequential)] private struct MonitorInfo { public int Size; public Rect Monitor, Work; public uint Flags; }
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern bool GetMonitorInfoW(IntPtr monitor, ref MonitorInfo info);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr window, out Rect rect);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);

    internal static Rect Fit(Rect rect, Rect work)
    {
        if(work.Right<=work.Left || work.Bottom<=work.Top) return rect;
        int width=Math.Clamp(rect.Right-rect.Left,1,Math.Max(1,work.Right-work.Left));
        int height=Math.Clamp(rect.Bottom-rect.Top,1,Math.Max(1,work.Bottom-work.Top));
        int left=Math.Clamp(rect.Left,work.Left,work.Right-width);
        int top=Math.Clamp(rect.Top,work.Top,work.Bottom-height);
        return new Rect { Left=left,Top=top,Right=left+width,Bottom=top+height };
    }
    private static bool Work(IntPtr window, out MonitorInfo info)
    {
        info=new MonitorInfo {Size=Marshal.SizeOf<MonitorInfo>()};
        return GetMonitorInfoW(MonitorFromWindow(window,2),ref info)
            && info.Work.Right>info.Work.Left && info.Work.Bottom>info.Work.Top;
    }
    internal static void Attach(Window window)
    {
        window.SourceInitialized+=(_,_)=> HwndSource.FromHwnd(new WindowInteropHelper(window).Handle)?.AddHook(Hook);
        window.ContentRendered+=(_,_)=> Clamp(window);
        window.StateChanged+=(_,_)=> { if(window.WindowState==WindowState.Normal) window.Dispatcher.BeginInvoke(new Action(()=>Clamp(window))); };
    }
    private static IntPtr Hook(IntPtr hwnd,int message,IntPtr wParam,IntPtr lParam,ref bool handled)
    {
        if(message==0x24 && lParam!=IntPtr.Zero && Work(hwnd,out var info)) {
            var limits=Marshal.PtrToStructure<MinMax>(lParam);
            limits.MaxPosition=new Point {X=info.Work.Left-info.Monitor.Left,Y=info.Work.Top-info.Monitor.Top};
            limits.MaxSize=new Point {X=info.Work.Right-info.Work.Left,Y=info.Work.Bottom-info.Work.Top};
            Marshal.StructureToPtr(limits,lParam,false); handled=true;
        }
        return IntPtr.Zero;
    }
    internal static void Clamp(Window window)
    {
        if(window.WindowState!=WindowState.Normal) return;
        var hwnd=new WindowInteropHelper(window).Handle;
        if(hwnd==IntPtr.Zero || !Work(hwnd,out var info) || !GetWindowRect(hwnd,out var before)) return;
        var after=Fit(before,info.Work);
        if(!before.Equals(after)) SetWindowPos(hwnd,IntPtr.Zero,after.Left,after.Top,after.Right-after.Left,after.Bottom-after.Top,0x14);
    }
}
