using System.IO;
using System.Text.Json;
using Qeli.Shared.Model;
using QeliWin.Model;
using QeliWin.Service;

namespace QeliWin.Vpn;

internal static class WindowsAdapterPolicySelfTest
{
    private sealed class End(Action release):IDisposable {public void Dispose()=>release();}
    private static bool Fails(Action action) {try{action();return false;}catch{return true;}}
    internal static void Run(Action<string,bool> check)
    {
        var first=new VpnConfig {Id="one",ServerAddress="192.0.2.1",WindowsPersistentAdapter=true,DevNode="custom-one"};
        var second=new VpnConfig {Id="two",ServerAddress="192.0.2.2",DevNode="custom-two"};
        check("adapter mode: app defaults off, including old profiles with an enabled flag",new AppSettings().PersistentAdapterMode=="off"
            && !WindowsAdapterPolicy.Persistent(first));
        var off=WindowsAdapterPolicy.Snapshot(first,"off");
        check("adapter mode: off disables use without changing stored flag/Id/dev_node",!WindowsAdapterPolicy.Persistent(off)
            && off.WindowsPersistentAdapter && first.WindowsPersistentAdapter && first.WindowsAdapterMode==null
            && off.Id==first.Id && off.DevNode==first.DevNode);
        var per=WindowsAdapterPolicy.Snapshot(first,"profiles");
        check("adapter mode: per profile respects both enabled and disabled flags",WindowsAdapterPolicy.Persistent(per)
            && !WindowsAdapterPolicy.Persistent(WindowsAdapterPolicy.Snapshot(second,"profiles")));
        var global=WindowsAdapterPolicy.Snapshot(first,"global");
        var other=WindowsAdapterPolicy.Snapshot(second,"global");
        check("adapter mode: one global identity across accounts/endpoints/dev_node",VpnTunnel.AdapterIdentity(global)==VpnTunnel.AdapterIdentity(other)
            && VpnTunnel.AdapterIdentity(global)==(WindowsAdapterPolicy.GlobalName,WindowsAdapterPolicy.GlobalKey));
        check("adapter mode: explicit profile names never select the global identity in profile mode",VpnTunnel.AdapterIdentity(per)!=VpnTunnel.AdapterIdentity(global));
        check("adapter mode: switching back restores stored per-profile choice",WindowsAdapterPolicy.Snapshot(first,"profiles").WindowsPersistentAdapter
            && !WindowsAdapterPolicy.Snapshot(second,"profiles").WindowsPersistentAdapter);
        check("adapter mode: service snapshot roundtrips retain both original profile flags",
            WindowsAdapterPolicy.Snapshot(WindowsAdapterPolicy.Snapshot(first,"off"),"profiles").WindowsPersistentAdapter
            && !WindowsAdapterPolicy.Snapshot(WindowsAdapterPolicy.Snapshot(second,"global"),"profiles").WindowsPersistentAdapter);
        var apps=new VpnConfig {AppsMode="exclude",Apps=["browser.exe"],WindowsPersistentAdapter=true};
        var globalApps=WindowsAdapterPolicy.Snapshot(apps,"global");
        WindowsAdapterPolicy.ValidateConnection(globalApps);
        check("adapter mode: global does not create Wintun for WinDivert",!WindowsAdapterPolicy.Persistent(globalApps)
            && globalApps.WindowsPersistentAdapter && globalApps.UsesAppFilter);
        check("adapter mode: invalid profile-owned WinDivert combination is rejected",Fails(()=>WindowsAdapterPolicy.ValidateConnection(
            WindowsAdapterPolicy.Snapshot(apps,"profiles"))));
        check("adapter mode: unknown preferences and service metadata fail closed",Fails(()=>WindowsAdapterPolicy.Snapshot(first,"gloabl"))
            && Fails(()=>WindowsAdapterPolicy.ResolvedMode(new VpnConfig {WindowsAdapterMode="gloabl"})));
        var service=ServiceProfileTransition.Snapshot(first,"debug","global");
        var loaded=JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(service))!;
        check("adapter mode: service snapshot keeps selected scope and original profile identity",loaded.WindowsAdapterMode=="global"
            && loaded.Id==first.Id && loaded.LoggingLevel=="debug" && first.LoggingLevel!="debug");
        check("adapter mode: scope is not written into shareable INI/URI",!loaded.ToIni().Contains("WindowsAdapterMode")
            && VpnConfig.FromIni(loaded.ToIni()).WindowsAdapterMode==null);

        VpnConfig stored=WindowsAdapterPolicy.Snapshot(first,"profiles");
        var events=new List<string>();
        var transition=new DesktopServiceProfileTransition(()=>true,()=>false,()=>stored,
            ()=>events.Add("stop"),bytes=>{events.Add("publish");stored=JsonSerializer.Deserialize<VpnConfig>(bytes)!;},
            ()=>events.Add("install"),()=>events.Add("start"),()=>events.Add("uninstall"),profile=>JsonSerializer.SerializeToUtf8Bytes(profile));
        transition.Apply(global,false);
        check("adapter mode: idle service notices scope-only change without autoconnect",stored.WindowsAdapterMode=="global"
            && events.SequenceEqual(new[]{"stop","publish"}));
        var modes=new[]{"off","profiles","global"};
        foreach(var before in modes)
        foreach(var after in modes)
        {
            if(before==after) continue;
            events.Clear();string published=before;
            WindowsAdapterPolicy.SaveMode(before,after,()=>{events.Add("save");published=after;},
                ()=>{events.Add("exclusive");return new End(()=>events.Add("unlock"));},
                ()=>events.Add("recover-dns-routes"),()=>{events.Add("service-snapshot");return ()=>events.Add("rollback");});
            check($"adapter mode: {before}->{after} cleans L3 before service/prefs publication",published==after
                && events.SequenceEqual(new[]{"exclusive","recover-dns-routes","service-snapshot","save","unlock"}));
        }
        events.Clear();bool saved=false;
        check("adapter mode: active GUI/service lease prevents any cleanup/publication",Fails(()=>WindowsAdapterPolicy.SaveMode("global","off",()=>saved=true,
            ()=>throw new IOException("busy"),()=>events.Add("recover"))) && !saved && events.Count==0);
        check("adapter mode: failed DNS/route rollback cannot save new mode",Fails(()=>WindowsAdapterPolicy.SaveMode("global","off",()=>saved=true,
            ()=>new End(()=>{}),()=>throw new IOException("DNS rollback failed"))) && !saved);
        events.Clear();
        check("adapter mode: failed service staging cannot publish new preference",Fails(()=>WindowsAdapterPolicy.SaveMode("global","off",()=>saved=true,
            ()=>new End(()=>{}),()=>{},()=>throw new IOException("service stop failed"))) && !saved);
        check("adapter mode: preference failure restores the idle service policy",Fails(()=>WindowsAdapterPolicy.SaveMode("profiles","global",()=>throw new IOException("save failed"),
            ()=>new End(()=>{}),()=>{},()=>()=>events.Add("rollback"))) && events.SequenceEqual(new[]{"rollback"}));
        events.Clear();
        WindowsAdapterPolicy.SaveMode("off","off",()=>events.Add("save"),()=>throw new Exception("must not lock"),()=>throw new Exception("must not recover"));
        check("adapter mode: unrelated settings save cannot touch network state",events.SequenceEqual(new[]{"save"}));
        events.Clear();bool readerHeld=false;
        WindowsAdapterPolicy.SaveMode("off","off",()=>events.Add("save"),
            ()=>{check("adapter mode: reader is released before writer upgrade",!readerHeld);events.Add("writer");return new End(()=>events.Add("unlock"));},
            ()=>events.Add("recover"),readCurrent:()=>"global",
            shared:()=>{readerHeld=true;return new End(()=>readerHeld=false);},requireIdle:()=>events.Add("idle"));
        check("adapter mode: stale GUI cannot skip cleanup when disk preference changed",events.SequenceEqual(new[]{"writer","idle","recover","save","unlock"}));
        events.Clear();
        WindowsAdapterPolicy.SaveMode("off","global",()=>events.Add(readerHeld?"save-under-reader":"unsafe"),
            ()=>throw new Exception("must not take writer"),()=>throw new Exception("must not recover"),
            readCurrent:()=>"global",shared:()=>{readerHeld=true;return new End(()=>readerHeld=false);},
            requireIdle:()=>throw new Exception("unchanged mode can save during a run"));
        check("adapter mode: unchanged persisted mode saves safely during active run",!readerHeld && events.SequenceEqual(new[]{"save-under-reader"}));
        events.Clear();int reads=0;
        WindowsAdapterPolicy.SaveMode("off","global",()=>events.Add("save"),()=>new End(()=>{}),
            ()=>throw new Exception("concurrent writer already changed mode"),readCurrent:()=>++reads==1?"off":"global",
            shared:()=>new End(()=>{}),requireIdle:()=>throw new Exception("already changed"));
        check("adapter mode: writer rechecks preference after lease upgrade",reads==2 && events.SequenceEqual(new[]{"save"}));
        saved=false;
        check("adapter mode: idle recheck failure cannot clean or save",Fails(()=>WindowsAdapterPolicy.SaveMode("off","global",()=>saved=true,
            ()=>new End(()=>{}),()=>throw new Exception("must not recover"),readCurrent:()=>"off",shared:()=>new End(()=>{}),
            requireIdle:()=>throw new IOException("still stopping"))) && !saved);
        FileGate(check);
        VpnTunnel.RunModeLeaseSelfTest(check);
    }

    private static void FileGate(Action<string,bool> check)
    {
        string path=Path.Combine(Path.GetTempPath(),"qeli-mode-gate-"+Guid.NewGuid().ToString("N"));
        using(var create=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { }
        try
        {
            using var first=WindowsAdapterModeGate.OpenLeaseFile(path,writer:false);
            var second=Task.Run(()=>WindowsAdapterModeGate.OpenLeaseFile(path,writer:false)).GetAwaiter().GetResult();
            check("adapter mode: concurrent session readers are allowed",first.CanRead && second.CanRead);
            check("adapter mode: real file sharing blocks mode writer during reconnect gap",Fails(()=>WindowsAdapterModeGate.OpenLeaseFile(path,writer:true)));
            second.Dispose();first.Dispose();
            using var writer=WindowsAdapterModeGate.OpenLeaseFile(path,writer:true);
            check("adapter mode: exclusive transition blocks a new session",Fails(()=>WindowsAdapterModeGate.OpenLeaseFile(path,writer:false)));
            writer.Dispose();
            using var next=WindowsAdapterModeGate.OpenLeaseFile(path,writer:false);
            check("adapter mode: completed transition releases the next session",next.CanRead);
        }
        finally {File.Delete(path);}
    }
}
