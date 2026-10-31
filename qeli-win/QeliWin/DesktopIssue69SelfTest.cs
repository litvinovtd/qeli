using Qeli.Shared.Vpn;
using System.Text.Json;
using QeliWin.Service;
namespace QeliWin;

internal static class DesktopIssue69SelfTest
{
    internal static void Run(Action<string,bool> check)
    {
        var work = new WindowWorkArea.Rect {Left=-1920,Top=48,Right=0,Bottom=1080};
        var fit = WindowWorkArea.Fit(new() {Left=-2000,Top=-10,Right=-800,Bottom=890},work);
        check("dialog: top taskbar and negative monitor origin",fit.Left==-1920 && fit.Top==48 && fit.Bottom==948);
        fit=WindowWorkArea.Fit(new() {Left=-1900,Top=10,Right=900,Bottom=2010},work);
        check("dialog: oversized window fits physical work area",fit.Equals(work));
        var normal=new WindowWorkArea.Rect {Left=-1800,Top=100,Right=-900,Bottom=700};
        check("dialog: fitting window remains unchanged",WindowWorkArea.Fit(normal,work).Equals(normal));
        check("dialog: invalid monitor data cannot move window",WindowWorkArea.Fit(normal,default).Equals(normal));
        var tooltip=TrayController.FormatTooltip(VpnStatus.Connected,"10.9.0.2","Work profile");
        check("tray: active profile precedes connection state",tooltip.StartsWith("Work profile — ") && tooltip.Contains("10.9.0.2"));
        tooltip=TrayController.FormatTooltip(VpnStatus.Error,"error",new string('a',62)+"\U0001f680\0\n");
        check("tray: tooltip limit cannot split Unicode or retain controls",tooltip.Length<=63
            && !char.IsHighSurrogate(tooltip[^1]) && !tooltip.Any(char.IsControl));
        check("tray: missing profile remains valid",!string.IsNullOrWhiteSpace(TrayController.FormatTooltip(VpnStatus.Disconnected,null,null)));
        var snapshot = new ServiceStatus {Status="Connected",Time=DateTime.UtcNow,ProfileName="Daemon profile"};
        var decoded = ServiceState.DecodeStatus(JsonSerializer.SerializeToUtf8Bytes(snapshot));
        check("tray: daemon supplies actual profile rather than GUI selection",decoded.ProfileName=="Daemon profile");
        snapshot.ProfileName=null;
        check("tray: old service status without profile remains compatible",ServiceState.DecodeStatus(JsonSerializer.SerializeToUtf8Bytes(snapshot)).ProfileName is null);
        snapshot.ProfileName=new string('a',257);
        bool rejected=false;
        try {ServiceState.DecodeStatus(JsonSerializer.SerializeToUtf8Bytes(snapshot));}
        catch(System.IO.InvalidDataException) {rejected=true;}
        check("tray: unbounded service profile name is rejected",rejected);
    }
}
