using System.Diagnostics;
using System.ServiceProcess;
using System.Text.Json;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;
using QeliWin.Service;

namespace QeliCli;

internal static class ServiceCommands
{
    internal static object Status()
    {
        bool installed=ServiceManager.IsInstalled();
        if(!installed) return new {backend="service",installed=false,state="unavailable"};
        ServiceManager.UseRegisteredHost();
        var observation=Observe();
        return View(observation);
    }
    private static ServiceObservation Observe() => ServiceObservation.Resolve(
        ServiceManager.GetStatus(),ServiceState.ReadExistingStatus(),DateTime.Now);
    private static object View(ServiceObservation observation) => new {
        backend="service",installed=true,state=observation.Status.ToString().ToLowerInvariant(),
        observed_at=observation.Snapshot?.Time,connected_since=observation.Snapshot?.Since,
        control_protocol=observation.Snapshot?.ControlProtocolVersion,
        profile_id=observation.Snapshot?.ProfileId,session_id=observation.Snapshot?.SessionId,
        bytes_up=observation.Snapshot?.BytesUp,bytes_down=observation.Snapshot?.BytesDown,
        addresses=observation.Snapshot?.Addresses,
        state_known=observation.Snapshot!=null || observation.Status==VpnStatus.Disconnected
    };
    internal static object Connect(VpnConfig config,TimeSpan timeout,CancellationToken cancellation)
    {
        var timer=Stopwatch.StartNew();
        using var gate=WindowsControlGate.Acquire();
        RequireInstalled();
        ServiceManager.UseRegisteredHost();
        // Stable identity on repeated import; compare all effective fields before touching VPN.
        var previous=ServiceState.LoadProfile();
        if(previous!=null) {
            string original=config.Id;config.Id=previous.Id;
            if(JsonSerializer.Serialize(previous)!=JsonSerializer.Serialize(config)) config.Id=original;
        }
        long requestedAt=ServiceMonotonicClock.NowMilliseconds;
        // Reuse the trusted profile publication and stop/publish/start transaction.
        var transition=new ServiceProfileTransition(ServiceManager.IsInstalled,ServiceState.DesiredConnected,
            ServiceState.LoadProfile,()=>ServiceManager.StopWithTimeout(Remaining(timer,timeout)),
            ServiceState.PublishProfile,()=>throw new InvalidOperationException("Install service explicitly"),
            ()=>ServiceManager.StartWithTimeout(Remaining(timer,timeout)),ServiceManager.Uninstall,
            ServiceManager.EnsureRegistration);
        cancellation.ThrowIfCancellationRequested();
        if(ServiceManager.GetStatus()==ServiceControllerStatus.Running && Observe().Status==VpnStatus.Error)
            ServiceManager.StopWithTimeout(Remaining(timer,timeout));
        transition.Apply(config,connectRequested:true);
        while(true) {
            cancellation.ThrowIfCancellationRequested();
            var current=Observe();
            if(current.Snapshot?.MonotonicTimeMs>=requestedAt && current.Snapshot.ControlProtocolVersion!=1)
                throw new CliFailure(11,"service_incompatible","Installed host predates the CLI control contract. Stop/uninstall it and install this CLI from Program Files.");
            if(current.Snapshot?.ProfileId==config.Id && current.Snapshot.MonotonicTimeMs>=requestedAt) {
                if(ServiceResultPolicy.Connected(current,config.Id,requestedAt)) return View(current);
                if(current.Status==VpnStatus.Error) throw Program.TransportFailure(current.Extra,current.Snapshot?.FailureKind ?? Qeli.Shared.Vpn.TunnelFailureKind.Transport);
            }
            if(current.Status==VpnStatus.Error && current.Snapshot?.MonotonicTimeMs>=requestedAt) throw Program.TransportFailure(current.Extra,current.Snapshot?.FailureKind ?? Qeli.Shared.Vpn.TunnelFailureKind.Transport);
            Remaining(timer,timeout);
            if(cancellation.WaitHandle.WaitOne(100)) cancellation.ThrowIfCancellationRequested();
        }
    }
    internal static object Disconnect(TimeSpan timeout,CancellationToken cancellation)
    {
        using var gate=WindowsControlGate.Acquire();
        cancellation.ThrowIfCancellationRequested();
        RequireInstalled();ServiceManager.UseRegisteredHost();
        bool wasRunning=ServiceManager.GetStatus()!=ServiceControllerStatus.Stopped;
        long requestedAt=ServiceMonotonicClock.NowMilliseconds;
        try {ServiceManager.StopWithTimeout(timeout);}
        catch(InvalidOperationException) {throw new CliFailure(10,"cleanup_incomplete","Service stop did not confirm network cleanup.");}
        var terminal=ServiceState.ReadExistingStatus();
        if(wasRunning && !ServiceResultPolicy.CleanupConfirmed(terminal,requestedAt))
            throw new CliFailure(10,"cleanup_incomplete","No fresh cleanup completion was published by the service.");
        var observation=Observe();
        if(observation.Status==VpnStatus.Error)
            throw new CliFailure(10,"cleanup_incomplete","Service stopped but network cleanup is not confirmed. Inspect recovery diagnostics.");
        return View(observation);
    }
    internal static object Wait(string state,TimeSpan timeout,CancellationToken cancellation)
    {
        RequireInstalled();ServiceManager.UseRegisteredHost();var timer=Stopwatch.StartNew();
        while(true) {
            cancellation.ThrowIfCancellationRequested();
            var current=Observe();
            if(current.Status==(state=="connected" ? VpnStatus.Connected : VpnStatus.Disconnected)) return View(current);
            if(current.Status==VpnStatus.Error && current.Snapshot!=null) throw Program.TransportFailure(current.Extra,current.Snapshot?.FailureKind ?? Qeli.Shared.Vpn.TunnelFailureKind.Transport);
            Remaining(timer,timeout);cancellation.WaitHandle.WaitOne(100);
        }
    }
    internal static object Service(string command,TimeSpan timeout,CancellationToken cancellation)
    {
        using var gate=WindowsControlGate.Acquire();cancellation.ThrowIfCancellationRequested();
        if(command=="service install") {
            if(ServiceManager.IsInstalled()) {ServiceManager.UseRegisteredHost();ServiceManager.EnsureRegistration();}
            else ServiceManager.InstallIdle();
        } else {
            RequireInstalled();ServiceManager.UseRegisteredHost();
            switch(command) {
                case "service start": ServiceManager.StartWithTimeout(timeout,connectRequested:false);break;
                case "service stop": return Disconnect(timeout,cancellation);
                case "service uninstall":
                    _=Disconnect(timeout,cancellation);
                    ServiceManager.Uninstall();break;
                default:throw CommandLine.Usage("Unknown service command");
            }
        }
        return new {installed=ServiceManager.IsInstalled(),service=ServiceManager.ServiceName};
    }
    internal static object Logs(CommandLine options,CancellationToken cancellation)
    {
        RequireInstalled();ServiceManager.UseRegisteredHost();string previous="";
        while(true) {
            string text=ServiceState.ReadExistingLog();
            // Bounded snapshot rather than an unbounded file/tail queue; rotation resets the cursor.
            string added=text.StartsWith(previous,StringComparison.Ordinal) ? text[previous.Length..] : text;
            if(!options.Follow && options.Json) return new {backend="service",log=text};
            if(options.JsonLines) {
                foreach(string line in added.Split('\n',StringSplitOptions.RemoveEmptyEntries)) Program.Emit(new {schema_version=1,@event="log",message=line.TrimEnd('\r')});
            } else Console.Write(added.Replace('\u001b','?'));
            previous=text;
            if(!options.Follow || cancellation.WaitHandle.WaitOne(250)) return new SilentResult();
        }
    }
    private static void RequireInstalled() {
        if(!ServiceManager.IsInstalled()) throw new CliFailure(11,"service_unavailable","Install the service from a protected location using service install.");
    }
    private static TimeSpan Remaining(Stopwatch timer,TimeSpan timeout) {
        var value=timeout-timer.Elapsed;
        if(value<=TimeSpan.Zero) throw new CliFailure(6,"timeout","Deadline expired. Service connection intent may remain active; use disconnect to cancel it.");
        return value;
    }
}
