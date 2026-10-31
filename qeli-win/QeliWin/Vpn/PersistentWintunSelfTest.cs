using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace QeliWin.Vpn;

/// <summary>No PnP, registry, adapter or route mutation. The only child process runs
/// generated recovery code behind mandatory PowerShell function mocks.</summary>
internal static class PersistentWintunSelfTest
{
    private sealed class End(Action end) : IDisposable {public void Dispose()=>end();}
    private sealed class Store : PersistentWintunDevice.IStore
    {
        internal PersistentWintunDevice.Record? Value;
        internal bool Locked,FailWrite;
        internal int Writes;
        internal int FailAtWrite;
        public IDisposable Lock(Guid key)
        {
            if(Locked) throw new IOException("Mock adapter is in use");
            Locked=true;return new End(()=>Locked=false);
        }
        public PersistentWintunDevice.Record? Read(Guid key)=>Value;
        public void Write(PersistentWintunDevice.Record record)
        {if(FailWrite || (FailAtWrite!=0 && Writes+1==FailAtWrite)) throw new IOException("Mock durable write failed");Writes++;Value=record;}
        public void Delete(Guid key)=>Value=null;
        public IEnumerable<Guid> Keys()=>Value==null?[]:[Value.Key];
    }
    private sealed class Platform : PersistentWintunDevice.IPlatform
    {
        internal PersistentWintunDevice.Node? Node;
        internal bool Persistent,WrongHandleGuid,FailLifetime,BusyRemoval,FailClose;
        internal int Creates,Closes,Removals;
        internal readonly Guid InterfaceGuid=Guid.NewGuid();
        public PersistentWintunDevice.Node? Find(string name)=>Node;
        public (IntPtr device,string deviceId) Create(PersistentWintunDevice.Record record)
        {
            Creates++;
            string id="SWD\\Wintun\\"+record.Instance;
            Node ??=new(id,record.Name,record.Token,InterfaceGuid);
            return (new IntPtr(11),Node.DeviceId);
        }
        public void SetLifetime(IntPtr device,bool persistent)
        {if(FailLifetime) throw new IOException("Mock lifetime failure");Persistent=persistent;if(!persistent) Removals++;}
        public void CloseDevice(IntPtr device) {if(!Persistent && !BusyRemoval) Node=null;}
        public PersistentWintunDevice.Handle OpenAdapter(string name)=>new(new IntPtr(12),42,WrongHandleGuid?Guid.NewGuid():InterfaceGuid);
        public void CloseAdapter(IntPtr handle) {if(FailClose) throw new IOException("Mock adapter close failure");Closes++;}
    }
    private static bool Throws(Action action) {try{action();return false;}catch{return true;}}
    internal static void Run(Action<string,bool> check)
    {
        var key=Guid.NewGuid();var store=new Store();var platform=new Platform();
        var lease=PersistentWintunDevice.Open(key,"Qeli-test",store,platform);
        check("persistent: device lifetime, identity and durable creation intent",platform.Persistent
            && store.Locked && store.Writes>=3 && lease.Record.InterfaceGuid==platform.InterfaceGuid);
        check("persistent: second process cannot use the same device",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",store,platform)));
        lease.Dispose();
        check("persistent: Disconnect/Quit closes adapter handle but not device",platform.Node!=null && !store.Locked && platform.Closes==1);
        using(var reopened=PersistentWintunDevice.Open(key,"ignored-renamed-config",store,platform))
            check("persistent: restart reopens original name and GUID without creation",platform.Creates==1 && reopened.Record.Name=="Qeli-test" && reopened.Adapter.InterfaceGuid==platform.InterfaceGuid);
        var original=platform.Node!;
        platform.Node=original with {Token=Guid.NewGuid()};
        check("persistent: foreign owner marker is refused",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",store,platform)) && !store.Locked);
        platform.Node=original with {InterfaceGuid=Guid.NewGuid()};
        check("persistent: changed device GUID is refused",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",store,platform)));
        platform.Node=original;platform.WrongHandleGuid=true;
        check("persistent: wrong OpenAdapter handle GUID is closed and refused",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",store,platform)) && !store.Locked);
        platform.WrongHandleGuid=false;
        var withoutReceipt=new Store();
        check("persistent: matching name alone never authorizes adoption",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",withoutReceipt,platform)) && withoutReceipt.Value==null);
        var blockedStore=new Store {FailWrite=true};var untouched=new Platform();
        check("persistent: failed write-ahead intent causes no PnP creation",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",blockedStore,untouched)) && untouched.Creates==0);
        var lifetimeStore=new Store();var lifetimePlatform=new Platform {FailLifetime=true};
        check("persistent: lifetime failure closes transient creation and adapter",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",lifetimeStore,lifetimePlatform))
            && lifetimePlatform.Node==null && lifetimePlatform.Closes==1 && !lifetimeStore.Locked);
        var interruptedStore=new Store {FailAtWrite=3};var interruptedPlatform=new Platform();
        check("persistent: interrupted final publication leaves recoverable device and creation intent",
            Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",interruptedStore,interruptedPlatform))
            && interruptedStore.Value?.InterfaceGuid==Guid.Empty && interruptedPlatform.Node!=null
            && interruptedPlatform.Persistent && !interruptedStore.Locked);
        interruptedStore.FailAtWrite=0;
        using(var recovered=PersistentWintunDevice.Open(key,"Qeli-test",interruptedStore,interruptedPlatform))
            check("persistent: interrupted creation recovers original identity, no second device",interruptedPlatform.Creates==1
                && recovered.Record.InterfaceGuid==interruptedPlatform.InterfaceGuid);

        lease=PersistentWintunDevice.Open(key,"Qeli-test",store,platform);
        var state=new PersistentWintunNetwork.State {InterfaceGuid=platform.InterfaceGuid,
            Addresses=[new("10.9.0.2",32)],Dns=["10.9.0.1"]};
        lease.SaveNetwork(state);
        check("persistent: pending recovery retains lease and native ownership",Throws(lease.Dispose) && store.Locked);
        check("persistent: failed rollback retains durable recovery state",Throws(()=>PersistentWintunNetwork.Recover(lease,(_,_)=>throw new IOException("rollback failed")))
            && lease.Record.Network!=null && store.Value?.Network!=null);
        store.FailWrite=true;
        check("persistent: failed rollback publication cannot clear ownership",Throws(()=>PersistentWintunNetwork.Recover(lease,(_,_)=>"verified"))
            && lease.Record.Network!=null && store.Locked);
        store.FailWrite=false;
        PersistentWintunNetwork.Recover(lease,(_,_)=>"verified");
        check("persistent: verified rollback clears recovery intent",lease.Record.Network==null && store.Value?.Network==null);
        lease.Dispose();
        lease=PersistentWintunDevice.Open(key,"Qeli-test",store,platform);platform.FailClose=true;
        check("persistent: failed adapter close retains exclusive lease",Throws(lease.Dispose) && store.Locked);
        platform.FailClose=false;lease.Dispose();
        PersistentWintunDevice.Remove(key,_=>{},store,platform);
        check("persistent: explicit removal changes lifetime, closes own device and clears receipt",platform.Node==null && store.Value==null && platform.Removals==1);

        store=new Store();platform=new Platform();lease=PersistentWintunDevice.Open(key,"Qeli-test",store,platform);lease.Dispose();
        platform.Node=null;
        check("persistent: missing installed adapter never silently gets a new GUID",Throws(()=>PersistentWintunDevice.Open(key,"Qeli-test",store,platform)) && platform.Creates==1);
        PersistentWintunDevice.Remove(key,_=>{},store,platform);
        check("persistent: explicit removal recovers an already absent device receipt",store.Value==null);
        store=new Store();platform=new Platform();lease=PersistentWintunDevice.Open(key,"Qeli-test",store,platform);lease.Dispose();
        platform.BusyRemoval=true;
        check("persistent: busy removal retains receipt for retry",Throws(()=>PersistentWintunDevice.Remove(key,_=>{},store,platform)) && store.Value!=null);
        check("persistent: Win64 public API structure layouts",Marshal.SizeOf<PersistentWintunNative.CreateInfo>()==72
            && Marshal.SizeOf<PersistentWintunNative.Key>()==20 && Marshal.SizeOf<PersistentWintunNative.CompKey>()==32
            && Marshal.SizeOf<PersistentWintunNative.Property>()==48 && Marshal.SizeOf<PersistentWintunNative.DevInfo>()==32);
        foreach(string scenario in new[]{"normal","foreign","route-readback","dns-readback","dns-edit"})
            RecoveryScript(check,scenario);
        var large=state with {Routes=Enumerable.Range(0,14000).Select(_=>new PersistentWintunNetwork.Route("2001:db8::/32","::",1)).ToArray()};
        string script=PersistentWintunNetwork.RestoreScript(large,"C:\\trusted\\owned.json");
        check("persistent: large route plans use protected data file, not command-line JSON",script.Length<9000 && !script.Contains("FromBase64String"));
        var commands=new List<string>();
        using(var network=new NetworkConfigurator(_=>{},(exe,args,optional)=>{commands.Add(args);return true;})
            {PersistentState=state,PersistentInterfaceIndex=42})
        {
            network.SetAddress("foreign\" name=Ethernet", "10.9.0.2",32);
            network.SetDns("foreign\" name=Ethernet",new[]{"10.9.0.1"});
        }
        check("persistent: IP/DNS commands use verified index, not an interpolated alias",commands.Count>=3
            && commands.All(c=>!c.Contains("Ethernet") && c.Contains("42")) && commands.Any(c=>c.Contains("add address")));
        commands.Clear();
        using(var network=new NetworkConfigurator(_=>{},(exe,args,optional)=>{commands.Add(args);return true;})
            {PersistentState=state with {Before=new() {Addresses=[new("10.9.0.2",32)]}},PersistentInterfaceIndex=42})
            network.SetAddress("Qeli","10.9.0.2",32);
        check("persistent: pre-existing address is neither overwritten nor claimed for deletion",commands.Count==0);
        check("persistent: wrong network identity is rejected before a command",Throws(()=>PersistentWintunNetwork.Validate(state,Guid.NewGuid())));
        check("persistent: malformed recovery data is rejected before a command",Throws(()=>PersistentWintunNetwork.Validate(
            state with {Addresses=[new("not-an-ip",32)]},state.InterfaceGuid)));
        var wrapperStore=new Store();var wrapperPlatform=new Platform();
        lease=PersistentWintunDevice.Open(key,"Qeli-wrapper",wrapperStore,wrapperPlatform);lease.Dispose();
        wrapperStore.Value=wrapperStore.Value! with {Network=state with {InterfaceGuid=wrapperPlatform.InterfaceGuid}};
        using(var wrapper=new WintunAdapter((_,_)=>throw new InvalidOperationException("Transient create forbidden"),_=>0,_=>throw new InvalidOperationException("Transient close forbidden")))
        {
            wrapper.OpenPersistent("Qeli-wrapper",key,wrapperStore,wrapperPlatform);
            check("persistent: stale prewarm cannot become a ready TUN",Throws(wrapper.RequireReady));
            PersistentWintunNetwork.Recover(wrapper.PersistentLease!,(_,_)=>"verified");
            wrapper.CompletePersistentRecovery();
            wrapper.RequireReady();
            check("persistent: recovered wrapper exposes the original GUID and native name",wrapper.Luid==42 && wrapper.AdapterName=="Qeli-wrapper");
        }
        check("persistent: wrapper disposal leaves the device installed",wrapperPlatform.Node!=null && !wrapperStore.Locked);
        var staleStore=new Store();var stalePlatform=new Platform();
        var crashed=PersistentWintunDevice.Open(key,"Qeli-old-profile",staleStore,stalePlatform);
        crashed.SaveNetwork(state with {InterfaceGuid=stalePlatform.InterfaceGuid});
        stalePlatform.CloseAdapter(crashed.Adapter.Value);staleStore.Locked=false; // Simulated process death; journal survives.
        string selectedMode="profiles";
        check("adapter mode: real recovery coordinator cannot bypass a failed old DNS/route rollback",
            Throws(()=>WindowsAdapterPolicy.SaveMode("profiles","global",()=>selectedMode="global",()=>new End(()=>{}),
                ()=>WindowsAdapterPolicy.RecoverIdlePlans(staleStore,stalePlatform,(_,_)=>throw new IOException("old DNS rollback failed"))))
            && selectedMode=="profiles" && staleStore.Value?.Network!=null && !staleStore.Locked);
        WindowsAdapterPolicy.SaveMode("profiles","global",()=>selectedMode="global",()=>new End(()=>{}),
            ()=>WindowsAdapterPolicy.RecoverIdlePlans(staleStore,stalePlatform,(_,_)=>"verified"));
        check("adapter mode: retry cleans the old journal before switching, without deleting its device",
            selectedMode=="global" && staleStore.Value?.Network==null && !staleStore.Locked
            && stalePlatform.Node?.Name=="Qeli-old-profile" && stalePlatform.Creates==1 && stalePlatform.Removals==0);
    }

    private static void RecoveryScript(Action<string,bool> check,string scenario)
    {
        var guid=Guid.Parse("9c2c33f3-69ee-459d-89fa-981622bc6158");
        var state=new PersistentWintunNetwork.State {InterfaceGuid=guid,
            Before=new() {Addresses=[new("192.0.2.2",32)],Dns4="9.9.9.9"},
            Addresses=[new("10.9.0.2",32)],Routes=[new("0.0.0.0/1","10.9.0.1",1)],Dns=["10.9.0.1"]};
        string script=PersistentWintunNetwork.RestoreScript(state);
        string exe=SystemPaths.Resolve("netsh").Replace("'","''");
        if(!script.Contains("$netsh='"+exe+"';")) throw new InvalidOperationException("Cannot install mandatory netsh mock");
        script=script.Replace("$netsh='"+exe+"';","$netsh='QeliMockNetsh';");
        string prelude="""
            $ErrorActionPreference='Stop'
            $script:scenario='SCENARIO';$script:raw='10.9.0.1';$script:removed=0
            if($script:scenario -eq 'dns-edit') {$script:raw='8.8.8.8'}
            $script:addresses=@(
                [pscustomobject]@{IPAddress='192.0.2.2';PrefixLength=32},
                [pscustomobject]@{IPAddress='10.9.0.2';PrefixLength=32},
                [pscustomobject]@{IPAddress='198.18.0.1';PrefixLength=32})
            $script:routes=@(
                [pscustomobject]@{DestinationPrefix='0.0.0.0/1';NextHop='10.9.0.1';RouteMetric=1;Protocol='NetMgmt'},
                [pscustomobject]@{DestinationPrefix='0.0.0.0/1';NextHop='192.0.2.1';RouteMetric=7;Protocol='NetMgmt'})
            foreach($item in @($script:addresses)+@($script:routes)) {$item | Add-Member -NotePropertyName InterfaceIndex -NotePropertyValue 42}
            $script:addresses+= [pscustomobject]@{IPAddress='10.9.0.2';PrefixLength=32;InterfaceIndex=43}
            $script:routes+= [pscustomobject]@{DestinationPrefix='0.0.0.0/1';NextHop='10.9.0.1';RouteMetric=1;Protocol='NetMgmt';InterfaceIndex=43}
            function Get-NetAdapter {
                param([switch]$IncludeHidden,$ErrorAction)
                $id=if($script:scenario -eq 'foreign') {'9c2c33f3-69ee-459d-89fa-981622bc6159'}else{'9c2c33f3-69ee-459d-89fa-981622bc6158'}
                return [pscustomobject]@{InterfaceGuid=$id;ifIndex=42}
            }
            function Get-NetIPAddress {param($InterfaceIndex,$ErrorAction,$PolicyStore) if($PolicyStore -ne 'ActiveStore'){throw 'Wrong address store'};if($InterfaceIndex -and $InterfaceIndex -ne 42){throw 'Foreign interface'};return $script:addresses}
            function Get-NetRoute {param($InterfaceIndex,$ErrorAction,$PolicyStore) if($PolicyStore -ne 'ActiveStore'){throw 'Wrong route store'};if($InterfaceIndex -and $InterfaceIndex -ne 42){throw 'Foreign interface'};return $script:routes}
            function Remove-NetRoute {
                param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm)
                process {
                    if($InputObject.NextHop -ne '10.9.0.1' -or $InputObject.InterfaceIndex -ne 42){throw 'Foreign route mutation'}
                    $script:removed++
                    if($script:scenario -ne 'route-readback') {$script:routes=@($script:routes | Where-Object {$_ -ne $InputObject})}
                }
            }
            function Remove-NetIPAddress {
                param([Parameter(ValueFromPipeline=$true)]$InputObject,$Confirm)
                process {
                    if($InputObject.IPAddress -ne '10.9.0.2' -or $InputObject.InterfaceIndex -ne 42){throw 'Pre-existing/foreign address mutation'}
                    $script:removed++;$script:addresses=@($script:addresses | Where-Object {$_ -ne $InputObject})
                }
            }
            function Test-Path {param($LiteralPath) return $true}
            function Get-ItemProperty {param($LiteralPath,$ErrorAction) if($LiteralPath -like '*Tcpip6*'){return [pscustomobject]@{NameServer=''}};return [pscustomobject]@{NameServer=$script:raw}}
            function QeliMockNetsh {
                $global:LASTEXITCODE=0
                if($script:scenario -ne 'dns-readback') {$script:raw='9.9.9.9'}
            }
            foreach($name in @('Get-NetAdapter','Get-NetIPAddress','Get-NetRoute','Remove-NetRoute','Remove-NetIPAddress','Test-Path','Get-ItemProperty','QeliMockNetsh')) {
                if((Get-Command $name).CommandType -ne 'Function') {throw 'Mandatory mock missing'}
            }
            $failed=$false
            try { & {
            """.Replace("SCENARIO",scenario);
        string after="""
            }} catch {$failed=$true;$failureMessage=$_.Exception.Message}
            $shouldFail=$script:scenario -in @('foreign','route-readback','dns-readback')
            if($failed -ne $shouldFail){throw ('Unexpected recovery result: '+$failureMessage)}
            if($script:scenario -eq 'foreign' -and $script:removed -ne 0){throw 'Foreign owner still mutated'}
            if(-not $shouldFail) {
                if($script:addresses.Count -ne 3 -or $script:routes.Count -ne 2){throw 'Wrong objects removed'}
                $expectedDns=if($script:scenario -eq 'dns-edit'){'8.8.8.8'}else{'9.9.9.9'}
                if($script:raw -ne $expectedDns){throw 'Administrator DNS was not preserved'}
            }
            """;
        var start=PersistentWintunNetwork.Start(prelude+script+after);
        using var process=Process.Start(start) ?? throw new InvalidOperationException("Cannot start mocked recovery test");
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        bool finished=process.WaitForExit(10000);
        if(!finished) {try{process.Kill(true);}catch{}}
        check("persistent mocked L3 recovery: "+scenario,finished && process.ExitCode==0);
        if(finished && process.ExitCode!=0) Console.WriteLine(error.GetAwaiter().GetResult());
    }
}
