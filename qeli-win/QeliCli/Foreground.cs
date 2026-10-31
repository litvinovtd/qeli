using System.Diagnostics;
using System.Net.NetworkInformation;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;
using QeliWin.Vpn;

namespace QeliCli;

internal static class Foreground
{
    internal static object Run(VpnConfig config,CommandLine options,CancellationToken cancellation,IConsoleTunnel? engine=null)
    {
        using var lifetime=CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        cancellation=lifetime.Token;
        var tunnel=engine ?? new ConsoleTunnel();
        using var logSink=new BoundedLogSink(line=>{
            if(options.JsonLines) Program.Emit(new {schema_version=1,@event="log",message=line});
            else Console.Error.WriteLine(line.Replace('\u001b','?'));
        },lifetime.Cancel);
        // The CLI reads only INI; GUI-wide preferences do not silently change its routing.
        var effective=WindowsAdapterPolicy.Snapshot(config,config.WindowsPersistentAdapter ? WindowsAdapterPolicy.Profiles : WindowsAdapterPolicy.Off);
        object gate=new();VpnStatus state=VpnStatus.Disconnected;string? detail=null;bool completed=false;
        tunnel.LogLevel=config.LoggingLevel;
        tunnel.StatusChanged+=(s,extra)=>{lock(gate) {state=s;detail=extra;}};
        tunnel.RunCompleted+=()=>{lock(gate) completed=true;};
        tunnel.LogLine+=line=>{
            string clean=string.IsNullOrEmpty(config.Password) ? line : line.Replace(config.Password,"[redacted]",StringComparison.Ordinal);
            if(!string.IsNullOrEmpty(config.ObfsKey)) clean=clean.Replace(config.ObfsKey,"[redacted]",StringComparison.Ordinal);
            logSink.Write(clean);
        };
        NetworkAddressChangedEventHandler changed=(_,_)=>{try {tunnel.OnNetworkChanged();} catch {Console.Error.WriteLine("qeli: network observation failed");}};
        NetworkChange.NetworkAddressChanged+=changed;
        var clock=Stopwatch.StartNew();bool established=false;TimeSpan? connectedAt=null;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            if(!tunnel.Start(effective)) {
                lock(gate) {
                    if(state==VpnStatus.Error && detail?.Contains("Another Qeli",StringComparison.OrdinalIgnoreCase)!=true)
                        throw Program.TransportFailure(detail,tunnel.FailureKind);
                }
                throw new CliFailure(5,"busy","Tunnel start was refused; another owner or unfinished cleanup may exist.");
            }
            while(true)
            {
                if(cancellation.IsCancellationRequested) break;
                VpnStatus current;string? reason;bool finished;
                lock(gate) {current=state;reason=detail;finished=completed;}
                if(current==VpnStatus.Connected) {established=true;connectedAt ??=clock.Elapsed;}
                if(current==VpnStatus.Error || finished) throw Program.TransportFailure(reason,tunnel.FailureKind);
                if(!established && clock.Elapsed>=TimeSpan.FromSeconds(options.Timeout)) throw new CliFailure(6,"timeout","VPN startup deadline expired.");
                if(options.Duration is int seconds && connectedAt.HasValue && clock.Elapsed-connectedAt.Value>=TimeSpan.FromSeconds(seconds)) break;
                if(cancellation.WaitHandle.WaitOne(100)) break;
            }
            if(!established) cancellation.ThrowIfCancellationRequested();
            return new {state="disconnected",connected=established,bytes_up=tunnel.BytesUp,bytes_down=tunnel.BytesDown,logs_dropped=logSink.Dropped};
        }
        finally
        {
            NetworkChange.NetworkAddressChanged-=changed;
            // Cleanup failure overrides success/cancellation: the script must know routes remain.
            try {tunnel.Stop();}
            catch {throw new CliFailure(10,"cleanup_incomplete","VPN cleanup is incomplete. Keep protection enabled and inspect recovery diagnostics.");}
        }
    }
}
