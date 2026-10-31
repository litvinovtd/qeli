using QeliCli;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;
using QeliWin.Service;

internal static class Tests
{
    private static int checks;
    private static void Check(bool ok,string name) {checks++;if(!ok)throw new Exception(name);}
    private static void Reject(params string[] args) {
        try {CommandLine.Parse(args);throw new Exception("Accepted invalid arguments: "+string.Join(' ',args));}
        catch(CliFailure e) {Check(e.ExitCode==2,"usage classification");}
    }
    public static int Main()
    {
        try {
            Check(CommandLine.Parse([]).Command=="help","empty invocation");
            Check(CommandLine.Parse(["--version","--json"]).Json,"global version/json");
            Check(CommandLine.Parse(["run","--config","C:\\РєРёСЂРёР»Р»РёС†Р° Рё РїСЂРѕР±РµР»С‹\\profile.ini"]).Config!.Contains("РєРёСЂРёР»Р»РёС†Р°"),"Unicode literal config path");
            Check(CommandLine.Parse(["run","--config","-"]).Duration==null,"no implicit 30-second stop");
            Check(CommandLine.Parse(["run","--config","x","--duration","300"]).Duration==300,"explicit duration");
            Check(CommandLine.Parse(["connect","--config","x"]).Timeout==60,"connection deadline");
            Check(CommandLine.Parse(["logs","--follow","--json-lines"]).Follow,"stream mode");
            foreach(var args in new string[][] {
                ["run"],["run","--config"],["run","--config","x","--timeout","0"],
                ["run","--config","x","--duration","-1"],["run","--config","x","--duration","99999999999"],
                ["status","--config","x"],["status","--duration","5"],["wait"],["wait","--state","error"],
                ["logs","--follow","--json"],["status","--json-lines"],["status","--follow"],
                ["status","--json","--json"],["run","--config","x","--config","y"],
                ["connect","--config","x","--pass=canary"],["connect","x"],["config","validate","--config","x","unexpected"]
            }) Reject(args);
            Check(Program.Classify(new UnauthorizedAccessException()).ExitCode==4,"access code");
            Check(Program.Classify(new TimeoutException()).ExitCode==6,"deadline code");
            Check(Program.Classify(new OperationCanceledException()).ExitCode==12,"cancel code");
            Check(Program.Classify(new InvalidOperationException("secret")).Message.Contains("secret")==false,"exception does not leak secret");
            Check(Program.TransportFailure("SERVER KEY MISMATCH").ExitCode==8,"identity mismatch");
            Check(Program.TransportFailure("authentication failed").ExitCode==7,"auth classification");
            Check(Program.TransportFailure("localized status",TunnelFailureKind.ServerKeyMismatch).ExitCode==8,"typed identity error survives localized status");
            Check(Program.TransportFailure("generic retry status",TunnelFailureKind.Authentication).ExitCode==7,"typed auth survives generic retry status");
            Check(TunnelFailurePolicy.FromNativeError("auth failed: rejected")==TunnelFailureKind.Authentication,"native auth category");
            Check(TunnelFailurePolicy.FromNativeError("SERVER KEY MISMATCH - possible MITM")==TunnelFailureKind.ServerKeyMismatch,"native key category");
            Check(TunnelFailurePolicy.FromNativeError("socket closed")==TunnelFailureKind.Transport,"unknown native error remains transport");
            var snapshot=new ServiceStatus {Status="Connected",ControlProtocolVersion=1,ProfileId="new",SessionId="session",Time=DateTime.Now,MonotonicTimeMs=100};
            var observation=new ServiceObservation(VpnStatus.Connected,null,snapshot);
            Check(ServiceResultPolicy.Connected(observation,"new",100),"correlated connected status");
            Check(!ServiceResultPolicy.Connected(observation,"old",100),"other profile cannot confirm connect");
            Check(!ServiceResultPolicy.Connected(observation,"new",101),"old snapshot cannot confirm connect");
            Check(!ServiceResultPolicy.Connected(new(VpnStatus.Error,null,snapshot),"new",100),"error cannot confirm connect");
            Check(!ServiceResultPolicy.CleanupConfirmed(null,100),"missing cleanup confirmation");
            Check(!ServiceResultPolicy.CleanupConfirmed(snapshot,100,100),"connected cannot confirm cleanup");
            snapshot.Status="Disconnected";
            Check(ServiceResultPolicy.CleanupConfirmed(snapshot,100,100),"fresh cleanup confirmation");
            Check(!ServiceResultPolicy.CleanupConfirmed(snapshot,101,101),"stale cleanup confirmation");
            snapshot.MonotonicTimeMs=null;
            Check(!ServiceResultPolicy.CleanupConfirmed(snapshot,100,100),"legacy status not invented as confirmation");
            var ini=Path.Combine(Path.GetTempPath(),"qeli-cli-parser-"+Guid.NewGuid().ToString("N")+".ini");
            try {
                File.WriteAllText(ini,"[qeli]\nserver = 192.0.2.1:443\nproto = tcp\nuser = fixture\npass = canary-password\nmode = fake-tls\n");
                var parsed=Program.ReadConfig(ini);
                Check(parsed.ServerAddress=="192.0.2.1","actual native INI parser");
                Check(parsed.Id==Program.ReadConfig(ini).Id,"stable file profile identity across invocations");
            } finally {File.Delete(ini);}
            using(var entered=new ManualResetEventSlim())
            using(var release=new ManualResetEventSlim()) {
                var sink=new BoundedLogSink(_=>{entered.Set();release.Wait();});
                try {
                    sink.Write("first");Check(entered.Wait(2000),"log pump started");
                    for(int i=0;i<1000;i++)sink.Write("bounded");
                    Check(sink.Dropped>0,"slow log reader has bounded backlog");
                    var elapsed=System.Diagnostics.Stopwatch.StartNew();sink.Dispose();
                    Check(elapsed.Elapsed<TimeSpan.FromSeconds(2),"slow log reader cannot indefinitely block disposal");
                } finally {release.Set();}
            }
            var package=Path.Combine(Path.GetTempPath(),"qeli-cli-trust-"+Guid.NewGuid().ToString("N"));
            try {
                Directory.CreateDirectory(Path.Combine(package,"runtimes"));
                var sidecar=Path.Combine(package,"runtimes","dependency.dll");File.WriteAllText(sidecar,"fixture");
                bool refused=false;
                try {ServiceManager.ValidatePackageTree(package,p=>{if(p==sidecar)throw new UnauthorizedAccessException();});}
                catch(UnauthorizedAccessException) {refused=true;}
                Check(refused,"untrusted nested dependency refuses LocalSystem package");
            } finally {Directory.Delete(package,true);}
            Lifecycle();
            Console.WriteLine($"PASS: {checks} CLI lifecycle, parser and service-result checks");return 0;
        } catch(Exception e) {Console.Error.WriteLine(e);return 1;}
    }
    private static void Lifecycle()
    {
        var config=new VpnConfig {ServerAddress="192.0.2.1",Port=443,Username="fixture",Password="canary"};
        var options=CommandLine.Parse(["run","--config","fixture","--timeout","1"]);
        foreach(var reason in new[]{"SERVER KEY MISMATCH","authentication failed","transport failed"}) {
            var fake=new Fake {Fail=reason};
            try {Foreground.Run(config,options,CancellationToken.None,fake);throw new Exception("Expected failure");}
            catch(CliFailure e) {Check(e.ExitCode==Program.TransportFailure(reason).ExitCode,"terminal failure exit");}
            Check(fake.Stops==1,"terminal failure always cleans up");
        }
        var cleanup=new Fake {Fail="transport failed",CleanupFails=true};
        try {Foreground.Run(config,options,CancellationToken.None,cleanup);throw new Exception("Expected cleanup failure");}
        catch(CliFailure e) {Check(e.ExitCode==10,"cleanup failure overrides initial error");}
        var rejected=new Fake {Refuse=true};
        try {Foreground.Run(config,options,CancellationToken.None,rejected);throw new Exception("Expected refusal");}
        catch(CliFailure e) {Check(e.ExitCode==5 && rejected.Stops==1,"refused start and cleanup");}
        var pending=new Fake();
        try {Foreground.Run(config,options,CancellationToken.None,pending);throw new Exception("Expected startup deadline");}
        catch(CliFailure e) {Check(e.ExitCode==6 && pending.Stops==1,"startup deadline always cleans up");}
        using var cancelled=new CancellationTokenSource();cancelled.Cancel();
        var notStarted=new Fake();
        try {Foreground.Run(config,options,cancelled.Token,notStarted);throw new Exception("Expected cancellation");}
        catch(OperationCanceledException) {Check(notStarted.Starts==0,"pre-cancel does not start VPN");}
        using var stop=new CancellationTokenSource();var connected=new Fake {Connect=true};
        _=Task.Run(async()=>{await Task.Delay(100);stop.Cancel();});
        _=Foreground.Run(config,options,stop.Token,connected);
        Check(connected.Starts==1 && connected.Stops==1,"connected cancellation performs one cleanup");
    }
    private sealed class Fake:IConsoleTunnel
    {
        public event Action<string>? LogLine;
        public event Action<VpnStatus,string?>? StatusChanged;
        public event Action? RunCompleted;
        public TunnelFailureKind FailureKind {get;set;}
        public string LogLevel {private get;set;}="info";
        public long BytesUp=>10;public long BytesDown=>20;
        internal int Starts,Stops;internal bool Refuse,CleanupFails,Connect;internal string? Fail;
        public bool Start(VpnConfig config) {
            Starts++;LogLine?.Invoke("fixture canary");
            if(Fail!=null)StatusChanged?.Invoke(VpnStatus.Error,Fail);
            else if(Connect)StatusChanged?.Invoke(VpnStatus.Connected,null);
            return !Refuse;
        }
        public void Stop(){Stops++;if(CleanupFails)throw new IOException("fixture");RunCompleted?.Invoke();}
        public void OnNetworkChanged() { }
    }
}
