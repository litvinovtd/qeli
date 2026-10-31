using System.Threading.Channels;

namespace QeliCli;

/// <summary>A slow script reader must not block the transport's event/packet worker.</summary>
internal sealed class BoundedLogSink:IDisposable
{
    private readonly Channel<string> queue=Channel.CreateBounded<string>(new BoundedChannelOptions(256) {
        SingleReader=true,SingleWriter=false,FullMode=BoundedChannelFullMode.Wait,AllowSynchronousContinuations=false
    });
    private readonly Task pump;
    private long dropped;
    private int closed;
    internal long Dropped=>Interlocked.Read(ref dropped);
    internal BoundedLogSink(Action<string> write,Action? brokenPipe=null)
    {
        pump=Task.Run(async()=> {
            try {
                await foreach(var line in queue.Reader.ReadAllAsync()) {
                    if(Volatile.Read(ref closed)!=0)break;
                    write(line);
                }
            } catch {Interlocked.Exchange(ref closed,1);try {brokenPipe?.Invoke();} catch { }}
        });
    }
    internal void Write(string line)
    {
        if(line.Length>4096)line=line[..4096]+" [truncated]";
        if(Volatile.Read(ref closed)!=0 || !queue.Writer.TryWrite(line))Interlocked.Increment(ref dropped);
    }
    public void Dispose()
    {
        queue.Writer.TryComplete();
        // A synchronous console/pipe write cannot always be cancelled. Network cleanup
        // has already finished; do not wait indefinitely for a paused script's log reader.
        try {pump.Wait(TimeSpan.FromSeconds(1));} catch { }
        Interlocked.Exchange(ref closed,1);
    }
}
