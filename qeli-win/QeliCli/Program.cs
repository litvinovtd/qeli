using System.Text;
using System.Text.Json;
using System.Security.Principal;
using System.Diagnostics;
using Qeli.Shared.Model;
using QeliWin;
using QeliWin.Service;
using QeliWin.Vpn;

namespace QeliCli;

internal sealed record SilentResult;

internal static class Program
{
    internal static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower };
    internal const string Help = """
Qeli Windows console client
  run --config FILE [--duration SECONDS] [--timeout SECONDS]
  connect --config FILE [--timeout SECONDS]
  disconnect [--timeout SECONDS]
  status
  wait --state connected|disconnected [--timeout SECONDS]
  logs [--follow] [--json-lines]
  config validate --config FILE
  probe --config FILE
  service install|start|stop|uninstall [--timeout SECONDS]
  version
  licenses [--export NEW_DIRECTORY]
Use --json for a single result, --json-lines for run/log streams.
FILE is UTF-8 INI; '-' reads redirected stdin. No inline credentials in arguments.
run requires an elevated terminal; service commands require administrator rights.
connect requires an installed service. A connect timeout leaves its intent active;
use disconnect explicitly. run startup timeout always attempts cleanup.
Exit codes: 0 success, 2 usage, 3 config, 4 access, 5 busy, 6 timeout,
7 authentication, 8 key mismatch, 9 transport, 10 cleanup, 11 service, 12 cancelled.
""";
    public static int Main(string[] args)
    {
        if(args.SequenceEqual(["--service"]))
        {
            try { ServiceHostRunner.Run(); return 0; }
            catch { try {ServiceState.AppendLog("Service host failed before worker startup");} catch { } return 11; }
        }
        try {Console.OutputEncoding=new UTF8Encoding(false);Console.InputEncoding=new UTF8Encoding(false);}
        catch(IOException) { /* A scheduler may supply no console handles. */ }
        bool json=args.Contains("--json"), lines=args.Contains("--json-lines");
        string command="unknown";
        using var cancelled=new CancellationTokenSource();
        ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancelled.Cancel();};
        Console.CancelKeyPress+=cancel;
        using var lifetime=new ConsoleLifetime(cancelled);
        try
        {
            var options=CommandLine.Parse(args);command=options.Command;json=options.Json;lines=options.JsonLines;
            object result=Execute(options,cancelled.Token);
            if(result is SilentResult) return 0;
            if(json || lines) Emit(new {schema_version=1,ok=true,command,data=result,error=(object?)null});
            else Console.WriteLine(result is string text ? text : JsonSerializer.Serialize(result,JsonOptions));
            return 0;
        }
        catch(Exception error)
        {
            var failure=Classify(error);
            var result=new {schema_version=1,ok=false,command,data=(object?)null,error=new {code=failure.Code,message=failure.Message}};
            try {
                if(json || lines) Emit(result);
                else Console.Error.WriteLine($"qeli: {failure.Code}: {failure.Message}");
            } catch(IOException) { /* Consumer closed the pipe; cleanup has already run. */ }
            return failure.ExitCode;
        }
        finally { Console.CancelKeyPress-=cancel; }
    }
    internal static void Emit(object value) => Console.Out.WriteLine(JsonSerializer.Serialize(value,JsonOptions));
    internal static void RequireAdministrator()
    {
        using var identity=WindowsIdentity.GetCurrent();
        if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new CliFailure(4,"access_denied","Run this command in an administrator CMD or PowerShell terminal. No UAC dialog is opened.");
    }
    private static object Execute(CommandLine args,CancellationToken cancellation)
    {
        if(args.Command=="help") return Help;
        if(args.Command=="version") return new {version=typeof(Program).Assembly.GetName().Version?.ToString(3),platform="win-x64"};
        if(args.Command=="licenses")
        {
            if(args.Values.TryGetValue("export",out var directory)) { EmbeddedLicenses.ExportDirectory(directory); return new {directory=Path.GetFullPath(directory)}; }
            return new {files=EmbeddedLicenses.Names};
        }
        if(args.Command is "config validate" or "probe" or "run" or "connect")
        {
            var config=ReadConfig(args.Config!);
            if(args.Command=="config validate") return new {valid=true};
            if(args.Command=="probe")
            {
                var tunnel=new VpnTunnel();
                // This is a full authenticated handshake, not proof that system routes work.
                try {return new {assigned_address=tunnel.TestHandshake(config),test="handshake"};}
                catch(Exception error) when(error is not (DllNotFoundException or BadImageFormatException or EntryPointNotFoundException or KeyNotFoundException or UnauthorizedAccessException))
                {throw TransportFailure(null,tunnel.FailureKind);}
            }
            RequireAdministrator();
            if(args.Command=="run") return Foreground.Run(config,args,cancellation);
            return ServiceCommands.Connect(WindowsAdapterPolicy.Snapshot(config,config.WindowsPersistentAdapter ? WindowsAdapterPolicy.Profiles : WindowsAdapterPolicy.Off),TimeSpan.FromSeconds(args.Timeout),cancellation);
        }
        RequireAdministrator();
        return args.Command switch {
            "status"=>ServiceCommands.Status(),
            "disconnect"=>ServiceCommands.Disconnect(TimeSpan.FromSeconds(args.Timeout),cancellation),
            "wait"=>ServiceCommands.Wait(args.Values["state"],TimeSpan.FromSeconds(args.Timeout),cancellation),
            "logs"=>ServiceCommands.Logs(args,cancellation),
            _=>ServiceCommands.Service(args.Command,TimeSpan.FromSeconds(args.Timeout),cancellation)
        };
    }
    internal static VpnConfig ReadConfig(string file)
    {
        try
        {
            if(file=="-" && !Console.IsInputRedirected) throw CommandLine.Usage("--config - requires redirected stdin");
            using Stream stream=file=="-" ? Console.OpenStandardInput() : File.OpenRead(file);
            const int maximum=256*1024;
            using var buffer=new MemoryStream();
            byte[] chunk=new byte[4096];int count;
            while((count=stream.Read(chunk,0,Math.Min(chunk.Length,maximum+1-(int)buffer.Length)))>0)
            { buffer.Write(chunk,0,count);if(buffer.Length>maximum) throw new InvalidDataException(); }
            string ini=new UTF8Encoding(false,true).GetString(buffer.ToArray()).TrimStart('\uFEFF');
            if(!ini.TrimStart().StartsWith('[') && !ini.TrimStart().StartsWith('#') && !ini.TrimStart().StartsWith(';')) throw new InvalidDataException();
            var config=VpnConfig.Parse(ini);
            if(file!="-") {
                var identity=Encoding.UTF8.GetBytes("qeli-cli-profile:v1:"+Path.GetFullPath(file).ToUpperInvariant());
                config.Id=Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(identity).AsSpan(0,16));
            }
            if(file=="-" && config.WindowsPersistentAdapter && string.IsNullOrWhiteSpace(config.DevNode)
                && (!config.CarriedKeys.TryGetValue("dev",out string? name) || string.IsNullOrWhiteSpace(name)))
                throw new CliFailure(3,"unstable_adapter_identity","Persistent stdin profiles require an explicit dev_node/dev, or use a config file for stable adapter ownership.");
            return config;
        }
        catch(CliFailure) {throw;}
        catch(UnauthorizedAccessException) {throw;}
        catch(Exception e) when(e is IOException or ArgumentException or FormatException or InvalidOperationException or System.Text.DecoderFallbackException)
        {throw new CliFailure(3,"invalid_config","Cannot read a valid UTF-8 INI configuration (maximum 256 KiB). Check the file path and configuration fields.");}
    }
    internal static CliFailure Classify(Exception error)
    {
        if(error is CliFailure failure) return failure;
        if(error is KeyNotFoundException) return new(11,"native_schema_mismatch","Managed bindings and native configuration schema differ; use a matching CLI/native build.");
        if(error is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException) return new(11,"native_unavailable","The matching Windows native core could not be loaded.");
        if(error is IOException io && (io.HResult&0xffff)==32) return new(5,"busy","Another Qeli control operation owns the resource.");
        if(error is OperationCanceledException) return new(12,"cancelled","Operation cancelled.");
        if(error is UnauthorizedAccessException || error is System.ComponentModel.Win32Exception w && w.NativeErrorCode is 5 or 740 or 1314
            || error.InnerException is System.ComponentModel.Win32Exception inner && inner.NativeErrorCode==5)
            return new(4,"access_denied","Windows denied access; use an administrator terminal and trusted storage.");
        if(error is TimeoutException or System.ServiceProcess.TimeoutException) return new(6,"timeout","The operation did not complete within its deadline.");
        // Never expose arbitrary parser/OS exception text, which can contain configuration secrets.
        return new(9,"transport_error","Operation failed; inspect the diagnostic log.");
    }
    internal static CliFailure TransportFailure(string? message,Qeli.Shared.Vpn.TunnelFailureKind kind=Qeli.Shared.Vpn.TunnelFailureKind.Transport)
    {
        if(kind==Qeli.Shared.Vpn.TunnelFailureKind.ServerKeyMismatch || message?.Contains("key mismatch",StringComparison.OrdinalIgnoreCase)==true) return new(8,"server_key_mismatch","Server identity verification failed.");
        if(kind==Qeli.Shared.Vpn.TunnelFailureKind.Authentication || message?.Contains("authentication",StringComparison.OrdinalIgnoreCase)==true || message?.Contains("auth failed",StringComparison.OrdinalIgnoreCase)==true)
            return new(7,"authentication_failed","Server authentication failed.");
        return new(9,"transport_error","VPN transport failed; inspect the diagnostic log.");
    }
}
