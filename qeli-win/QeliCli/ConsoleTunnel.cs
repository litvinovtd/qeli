using Qeli.Shared.Model;
using Qeli.Shared.Vpn;
using QeliWin.Vpn;

namespace QeliCli;

/// <summary>The executable's lifecycle seam; production always delegates to the shared Windows adapter.</summary>
internal interface IConsoleTunnel
{
    event Action<string>? LogLine;
    event Action<VpnStatus,string?>? StatusChanged;
    event Action? RunCompleted;
    TunnelFailureKind FailureKind {get;}
    string LogLevel {set;}
    long BytesUp {get;}
    long BytesDown {get;}
    bool Start(VpnConfig config);
    void Stop();
    void OnNetworkChanged();
}
internal sealed class ConsoleTunnel:IConsoleTunnel
{
    private readonly VpnTunnel tunnel=new();
    public event Action<string>? LogLine {add=>tunnel.LogLine+=value;remove=>tunnel.LogLine-=value;}
    public event Action<VpnStatus,string?>? StatusChanged {add=>tunnel.StatusChanged+=value;remove=>tunnel.StatusChanged-=value;}
    public event Action? RunCompleted {add=>tunnel.RunCompleted+=value;remove=>tunnel.RunCompleted-=value;}
    public TunnelFailureKind FailureKind=>tunnel.FailureKind;
    public string LogLevel {set=>tunnel.LogLevel=value;}
    public long BytesUp=>tunnel.BytesUp;
    public long BytesDown=>tunnel.BytesDown;
    public bool Start(VpnConfig config)=>tunnel.Start(config);
    public void Stop()=>tunnel.Stop();
    public void OnNetworkChanged()=>tunnel.OnNetworkChanged();
}
