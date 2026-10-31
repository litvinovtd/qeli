using System.Text.Json;
using Qeli.Shared;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliMac.Vpn;

public sealed partial class VpnTunnel
{
    // All sockets, interface ownership and PF updates below are fake. This command
    // deliberately works on non-macOS build hosts and requires no elevation.
    internal static void RunUtunSelectionSelfTest(Action<string,bool> check)
    {
        static bool Fails(Action action) {try {action();return false;}catch(InvalidDataException){return true;}catch(IOException){return true;}catch(InvalidOperationException){return true;}}
        check("utun selection: missing/empty/auto default to kernel allocation",new[]{null,""," ","auto","AUTO"}.All(s=>UtunSelection.Parse(s)==null));
        check("utun selection: zero and upper client boundary are selectable",UtunSelection.Parse("utun0")==0 && UtunSelection.Parse("utun65534")==65534);
        check("utun selection: editor accepts a number or canonical name",UtunSelection.FromEditor("42")=="utun42"
            && UtunSelection.FromEditor("utun42")=="utun42" && UtunSelection.FromEditor(" ")=="auto");
        foreach(string bad in new[]{"-1","65535","utun-1","utun65535","utun01","utun+1","en0","utun42\n","42; reboot","999999999999"})
            check("utun selection: malformed name rejected: "+bad.Replace("\n","\\n"),Fails(()=>UtunSelection.Parse(bad)));
        check("utun selection: sc_unit uses zero for auto, N+1 for explicit number",UtunSelection.ControlUnit(null)==0
            && UtunSelection.ControlUnit(0)==1 && UtunSelection.ControlUnit(42)==43 && UtunSelection.ControlUnit(65534)==65535);
        check("utun selection: invalid constructor number cannot allocate resources",Fails(()=>new UtunDevice(-1)) && Fails(()=>new UtunDevice(65535)));
        string language=Loc.Lang;
        foreach(string lang in new[]{"en","ru"}) {
            Loc.SetLanguage(lang);
            check("utun selection: localized busy error identifies slot and resolution "+lang,
                UtunSelection.ConnectError(42,16).Message.Contains("utun42") && UtunSelection.ConnectError(42,48).Message.Contains("42")
                && !UtunSelection.ConnectError(42,1).Message.Contains(lang=="en"?"already in use":"уже занят"));
        }
        Loc.SetLanguage(language);
        int closed=0;
        var wrong=new UtunDevice(()=>(7,"utun43"),_=>closed++,42);
        check("utun selection: kernel name mismatch closes fd, never accepts fallback",Fails(wrong.Open) && closed==1 && Fails(()=>_=wrong.FileDescriptor));
        wrong.Dispose();

        var profile=VpnConfig.FromIni("[qeli]\nserver=vpn.example:443\nuser=test\npass=test\ndev_node=utun42\npersist_tun=true\n");
        check("utun selection: INI export/import retains slot and persist_tun",VpnConfig.FromIni(profile.ToIni()).DevNode=="utun42" && profile.PersistTun);
        VpnConfig Form(string node)=>profile.WithEditorFields(profile.Name,profile.ServerAddress,profile.Port,profile.Protocol,profile.WireMode,
            profile.ObfsKey,profile.ObfsFronting,profile.RealityShortId,profile.Sni,profile.QuicEnabled,profile.Username,profile.Password,
            profile.ServerPublicKeyHex,profile.RoutingMode,profile.AddDefaultGateway,profile.RouteLocalNetworks,profile.Mtu,profile.DnsServers,
            profile.PaddingEnabled,profile.PaddingMin,profile.PaddingMax,profile.HeartbeatEnabled,profile.HeartbeatIntervalMs,profile.HeartbeatJitterMs,devNode:node);
        check("utun selection: form override replaces native-source slot without changing profile",VpnConfig.FromIni(Form("utun43").ToIni()).DevNode=="utun43"
            && profile.DevNode=="utun42" && Form("utun43").Id==profile.Id);
        check("utun selection: form Auto clears explicit slot through native roundtrip",UtunSelection.Parse(VpnConfig.FromIni(Form("auto").ToIni()).DevNode)==null);
        var service=QeliMac.Service.ServiceProfileTransition.Snapshot(profile,"debug");
        var restored=JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(service))!;
        check("utun selection: daemon snapshot retains slot/identity independently",restored.DevNode=="utun42" && restored.Id==profile.Id && restored.LoggingLevel=="debug");

        var occupied=new HashSet<int>{42};var requests=new List<int?>();string[] allowed=[];int nextFd=100;bool failPf=false,failGuard=false;
        UtunDevice Factory(int? number) => new(()=> {
            requests.Add(number);
            if(number==null && failGuard) throw new IOException("mock guard allocation failed");
            int n=number ?? Enumerable.Range(0,100).First(i=>!occupied.Contains(i));
            if(!occupied.Add(n)) throw UtunSelection.ConnectError(n,16);
            return (++nextFd,"utun"+n);
        },_=>{if(number is {} n) occupied.Remove(n);else occupied.Remove(0);},number);
        var tunnel=new VpnTunnel(Factory,names=>{if(failPf) throw new IOException("mock PF reload failed");allowed=names.ToArray();});
        check("utun selection: busy Start preparation refuses before network configuration",Fails(()=>tunnel.AcquireRunResources(profile))
            && requests.SequenceEqual(new int?[]{42}) && occupied.SetEquals(new[]{42}) && tunnel._net==null && tunnel._prewarmedUtun==null);
        occupied.Clear();requests.Clear();
        tunnel.AcquireRunResources(profile);
        var old=tunnel._prewarmedUtun!;tunnel._prewarmedUtun=null;tunnel._tun=old;
        check("utun selection: explicit startup reserves exactly the requested slot",old.Name=="utun42" && requests.SequenceEqual(new int?[]{42}));
        var ks=typeof(VpnTunnelBase).GetField("_ksEngaged",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!;
        ks.SetValue(tunnel,1);
        try {
            failGuard=true;
            check("utun selection: failed guard allocation leaves old fd alive",Fails(tunnel.GuardFixedUtunBeforeClose) && old.FileDescriptor>0 && occupied.Contains(42));
            failGuard=false;failPf=true;
            check("utun selection: failed PF reload retains both owned slots",Fails(tunnel.GuardFixedUtunBeforeClose)
                && old.FileDescriptor>0 && tunnel._replacementGuardUtun?.FileDescriptor>0 && occupied.Count==2);
            failPf=false;
            check("utun selection: changed plan does not reserve fixed slot twice",!tunnel.TryReconfigurePersistedTun(profile,null!,System.Net.IPAddress.Loopback)
                && requests.Count(n=>n==42)==1 && allowed.SequenceEqual(new[]{"utun0"}));
            old.Dispose();tunnel._tun=null;
            check("utun selection: PF no longer permits the fixed name when released",!occupied.Contains(42) && allowed.SequenceEqual(new[]{"utun0"}));
            var next=tunnel.EnsurePrewarmedUtun();
            check("utun selection: replacement data plane still gets fixed number",next.Name=="utun42" && requests.Last()==42);
            failPf=true;
            check("utun selection: failed publication cannot release guard",Fails(()=>tunnel.PublishUtunToFirewall(next.Name)) && occupied.SetEquals(new[]{0,42}));
            failPf=false;tunnel.PublishUtunToFirewall(next.Name);
            check("utun selection: owned replacement published before guard release",allowed.SequenceEqual(new[]{"utun42"}) && occupied.SetEquals(new[]{42}));
        }
        finally {ks.SetValue(tunnel,0);tunnel._tun?.Dispose();tunnel._tun=null;tunnel.DisposeReservedUtuns();}
        check("utun selection: terminal cleanup leaves no reserved descriptors",occupied.Count==0);
        var auto=new VpnTunnel(Factory,_=>{});
        auto.AcquireRunResources(new VpnConfig());
        check("utun selection: default auto does not eagerly allocate an interface",auto._prewarmedUtun==null && auto._requestedUtunNumber==null);
        var failedAuth=new VpnTunnel(Factory,_=>{});
        failedAuth.AcquireRunResources(profile);
        failedAuth.CleanupPlatform();
        check("utun selection: failed authentication without PF releases unused reservation",occupied.Count==0 && failedAuth._prewarmedUtun==null);
    }
}
