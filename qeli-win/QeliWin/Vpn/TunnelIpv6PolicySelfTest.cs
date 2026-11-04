using System.ComponentModel;
using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

internal static class TunnelIpv6PolicySelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        var current = new TunnelIpv6Policy.Row {
            Family = 23, Luid = 123, Advertising = 1, NeighborUnreachability = 1,
            RouterDiscovery = 1, DadTransmits = 1, Metric = 37,
        };
        int writes = 0;
        int Read(ref TunnelIpv6Policy.Row row) { row = current; return 0; }
        int Write(ref TunnelIpv6Policy.Row row) { current = row; writes++; return 0; }
        using var adapter = new WintunAdapter((_, _) => new IntPtr(1), _ => 123, _ => { });
        bool identityAccepted = false;
        try { adapter.WithOwnedIdentity((_, _) => identityAccepted = true); }
        catch (InvalidOperationException) { }
        check("IPv6 policy: requires a created owned adapter", !identityAccepted);
        adapter.Open("QeliPolicyTest", Guid.NewGuid());
        adapter.WithOwnedIdentity((luid, _) => TunnelIpv6Policy.Apply(luid, Read, Write));
        check("IPv6 policy: disables only local discovery and preserves metric",
            writes == 1 && current.Luid == 123 && current.Family == 23 && current.Metric == 37
            && current.Advertising == 0 && current.NeighborUnreachability == 0
            && current.RouterDiscovery == 0 && current.DadTransmits == 0);
        bool rejected = false;
        current.Luid = 456;
        try { TunnelIpv6Policy.Apply(123, Read, Write); }
        catch (InvalidOperationException) { rejected = true; }
        check("IPv6 policy: a mismatching interface is never written", rejected && writes == 1);
        current.Luid = 123;
        current.NeighborUnreachability = 1;
        rejected = false;
        int Ignore(ref TunnelIpv6Policy.Row row) => 0;
        try { TunnelIpv6Policy.Apply(123, Read, Ignore); }
        catch (InvalidOperationException) { rejected = true; }
        check("IPv6 policy: failed readback refuses setup", rejected);
        LayoutAndPreservation(check);
        ErrorDiagnostics(check);
        RetryAndCancellation(check);
        Ownership(check);
    }

    private static Exception? Capture(Action action)
    {
        try { action(); return null; }
        catch(Exception error) { return error; }
    }

    private static TunnelIpv6Policy.Row Initial() => new() {
        Family=23, Luid=123, InterfaceIndex=18, Advertising=1, NeighborUnreachability=1,
        RouterDiscovery=1, DadTransmits=1, Metric=37, Mtu=1400,
        SupportsNeighborDiscovery=1, SupportsRouterDiscovery=0,
    };

    private static byte[] Bytes(TunnelIpv6Policy.Row row) =>
        MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref row, 1)).ToArray();

    private static void LayoutAndPreservation(Action<string, bool> check)
    {
        // Offsets are qualified independently against netioapi.h in Windows SDK.
        var fields = new (string name, int offset)[] {
            ("Family",0),("Luid",8),("InterfaceIndex",16),("Advertising",40),
            ("NeighborUnreachability",45),("RouterDiscovery",52),("DadTransmits",56),
            ("Metric",148),("Mtu",152),("SupportsNeighborDiscovery",158),("SupportsRouterDiscovery",159),
        };
        check("IPv6 policy: native row buffer and field offsets",
            Marshal.SizeOf<TunnelIpv6Policy.Row>() == 200 &&
            fields.All(field => Marshal.OffsetOf<TunnelIpv6Policy.Row>(field.name).ToInt32() == field.offset));

        var current=Initial();
        var storage=MemoryMarshal.AsBytes(MemoryMarshal.CreateSpan(ref current,1));
        // Sentinel bytes model unrelated/opaque members returned by the OS, not
        // a row sent to Windows. No native write is used anywhere in this fixture.
        for(int i=0;i<storage.Length;i++) storage[i]=(byte)(13+i*17);
        current.Family=23; current.Luid=123;
        current.Advertising=1; current.NeighborUnreachability=1; current.RouterDiscovery=1; current.DadTransmits=1;
        var expected=current;
        expected.Advertising=0; expected.NeighborUnreachability=0; expected.RouterDiscovery=0; expected.DadTransmits=0;
        int reads=0,writes=0;
        int Read(ref TunnelIpv6Policy.Row row) { reads++; row=current; return 0; }
        int Write(ref TunnelIpv6Policy.Row row) { writes++; current=row; return 0; }
        TunnelIpv6Policy.Apply(123,Read,Write);
        check("IPv6 policy: exactly four policy fields change, every opaque byte preserved", Bytes(current).SequenceEqual(Bytes(expected)));
        TunnelIpv6Policy.Apply(123,Read,Write);
        check("IPv6 policy: reconnect skips redundant native write", writes==1 && reads==3);

        int NeverWrite(ref TunnelIpv6Policy.Row row) => throw new Exception("already configured policy must not be written");
        check("IPv6 policy: already configured interface needs no write privilege",
            Capture(() => TunnelIpv6Policy.Apply(123,Read,NeverWrite)) == null);
    }

    private static void ErrorDiagnostics(Action<string, bool> check)
    {
        foreach(string stage in new[] {"read","write","verify"})
        foreach(int code in new[] {5,87,50,2,1168,123456}) {
            var current=Initial();
            int reads=0,writes=0,waits=0;
            int Read(ref TunnelIpv6Policy.Row row) {
                reads++;
                if(stage=="read" || (stage=="verify" && writes>0)) return code;
                row=current; return 0;
            }
            int Write(ref TunnelIpv6Policy.Row row) {
                writes++;
                // A stale last-error slot must never replace the API's return code.
                Marshal.SetLastPInvokeError(999);
                if(stage=="write") return code;
                current=row; return 0;
            }
            var error=Capture(() => TunnelIpv6Policy.Apply(123,Read,Write,wait:_=>waits++));
            string message=error?.Message ?? "";
            check($"IPv6 policy: {stage} retains original Win32 {code}",
                error is Win32Exception native && native.NativeErrorCode==code &&
                message.Contains($"stage={stage}") && message.Contains($"win32={code} (0x{code:X8})") &&
                message.Contains("system=\"") && message.Contains("expected_luid=0x000000000000007B") &&
                message.Contains(stage=="write" ? "api=SetIpInterfaceEntry" : "api=GetIpInterfaceEntry") &&
                writes==(stage=="read" ? 0 : 1) &&
                waits==((stage!="write" && code is 2 or 1168) ? TunnelIpv6Policy.ReadAttempts-1 : 0));
            if(stage=="write" && code==87)
                check("IPv6 policy: rejected write includes actual and requested parameters",
                    message.Contains("before=[family=23") && message.Contains("ifindex=18") &&
                    message.Contains("dad_transmits=1") && message.Contains("dad_transmits=0") &&
                    message.Contains("mtu=1400") && message.Contains("metric=37") && message.Contains("supports_rd=0"));
        }
        var original=Initial();
        int Original(ref TunnelIpv6Policy.Row row) { row=original; return 0; }
        int CorruptFailure(ref TunnelIpv6Policy.Row row) { row.Luid=456; row.Mtu=9000; return 87; }
        var rejected=Capture(() => TunnelIpv6Policy.Apply(123,Original,CorruptFailure));
        check("IPv6 policy: failed write reports submitted snapshot, not corrupted out buffer",
            rejected is Win32Exception && rejected.Message.Contains("mtu=1400") && !rejected.Message.Contains("mtu=9000"));
        int Denied(ref TunnelIpv6Policy.Row row) => 5;
        var logging=Capture(() => TunnelIpv6Policy.Apply(123,Original,Denied,log:_=>throw new Exception("log sink failed")));
        check("IPv6 policy: logger cannot hide original Win32 failure", logging is Win32Exception nativeError && nativeError.NativeErrorCode==5);

        int diagnosticWrites=0;
        int Ignore(ref TunnelIpv6Policy.Row row) { diagnosticWrites++; return 0; }
        var mismatch=Capture(() => TunnelIpv6Policy.Apply(123,Original,Ignore));
        check("IPv6 policy: success status with wrong readback still fails closed",
            mismatch is InvalidOperationException && mismatch.Message.Contains("stage=verify") &&
            mismatch.Message.Contains("win32=0") && mismatch.Message.Contains("expected=[") &&
            mismatch.Message.Contains("actual=[") && diagnosticWrites==1);

        int WrongOutput(ref TunnelIpv6Policy.Row row) { row.Luid=456; return 0; }
        var wrong=Capture(() => TunnelIpv6Policy.Apply(123,Original,WrongOutput));
        check("IPv6 policy: setter cannot redirect the following read to another interface",
            wrong is InvalidOperationException && wrong.Message.Contains("stage=write") && wrong.Message.Contains("different tunnel interface"));
        int WrongFamily(ref TunnelIpv6Policy.Row row) { row=original; row.Family=2; return 0; }
        diagnosticWrites=0;
        var family=Capture(() => TunnelIpv6Policy.Apply(123,WrongFamily,Ignore));
        check("IPv6 policy: wrong family snapshot never authorizes a write", family is InvalidOperationException && diagnosticWrites==0);
    }

    private static void RetryAndCancellation(Action<string, bool> check)
    {
        var current=Initial();
        int reads=0,writes=0,waits=0;
        var messages=new List<string>();
        int LaggingRead(ref TunnelIpv6Policy.Row row) {
            reads++;
            if(reads<=2) return reads==1 ? 2 : 1168;
            row=current; return 0;
        }
        int Write(ref TunnelIpv6Policy.Row row) { writes++; current=row; return 0; }
        TunnelIpv6Policy.Apply(123,LaggingRead,Write,log:messages.Add,wait:_=>waits++);
        check("IPv6 policy: late IPv6 family retries reads, then writes and verifies once", reads==4 && writes==1 && waits==2);
        check("IPv6 policy: lookup retry and each stage are logged",
            messages.Any(m=>m.Contains("win32=2")) && messages.Any(m=>m.Contains("win32=1168")) &&
            messages.Any(m=>m.Contains("stage=write")) && messages.Any(m=>m.Contains("stage=verify")));

        current=Initial(); reads=0; writes=0; waits=0;
        int LaggingVerify(ref TunnelIpv6Policy.Row row) { reads++; if(reads==2) return 1168; row=current; return 0; }
        TunnelIpv6Policy.Apply(123,LaggingVerify,Write,wait:_=>waits++);
        check("IPv6 policy: delayed readback retries no mutation", reads==3 && writes==1 && waits==1);

        int calls=0;
        int Never(ref TunnelIpv6Policy.Row row) { calls++; return 0; }
        using(var stopped=new CancellationTokenSource()) {
            stopped.Cancel();
            var error=Capture(() => TunnelIpv6Policy.Apply(123,Never,Never,stopped.Token));
            check("IPv6 policy: cancelled setup starts no API calls", error is OperationCanceledException && calls==0);
        }
        using(var stopped=new CancellationTokenSource()) {
            reads=0; writes=0;
            int Missing(ref TunnelIpv6Policy.Row row) { reads++; return 1168; }
            var error=Capture(() => TunnelIpv6Policy.Apply(123,Missing,Write,stopped.Token,wait:_=>stopped.Cancel()));
            check("IPv6 policy: cancellation interrupts registration retries", error is OperationCanceledException && reads==1 && writes==0);
        }
        using(var stopped=new CancellationTokenSource()) {
            reads=0; writes=0;
            int ReadAndCancel(ref TunnelIpv6Policy.Row row) { reads++; row=Initial(); stopped.Cancel(); return 0; }
            var error=Capture(() => TunnelIpv6Policy.Apply(123,ReadAndCancel,Write,stopped.Token));
            check("IPv6 policy: cancellation after read prevents write", error is OperationCanceledException && reads==1 && writes==0);
        }
        using(var stopped=new CancellationTokenSource()) {
            reads=0; writes=0;
            int Read(ref TunnelIpv6Policy.Row row) { reads++; row=Initial(); return 0; }
            int WriteAndCancel(ref TunnelIpv6Policy.Row row) { writes++; stopped.Cancel(); return 0; }
            var error=Capture(() => TunnelIpv6Policy.Apply(123,Read,WriteAndCancel,stopped.Token));
            check("IPv6 policy: cancelled write completion is not reported as verified", error is OperationCanceledException && reads==1 && writes==1);
        }
        foreach(string stopAt in new[] {"read","write","verify","already"}) {
            using var stopped=new CancellationTokenSource();
            current=Initial(); reads=0; writes=0;
            if(stopAt=="already") {
                current.Advertising=0; current.NeighborUnreachability=0; current.RouterDiscovery=0; current.DadTransmits=0;
            }
            int Read(ref TunnelIpv6Policy.Row row) { reads++; row=current; return 0; }
            var error=Capture(() => TunnelIpv6Policy.Apply(123,Read,Write,stopped.Token,
                log:message=> { if(message.Contains($"stage={stopAt};") || (stopAt=="already" && message.Contains("already configured"))) stopped.Cancel(); }));
            check("IPv6 policy: cancellation from stage callback "+stopAt,
                error is OperationCanceledException && writes==(stopAt=="verify" ? 1 : 0));
        }
    }

    private static void Ownership(Action<string, bool> check)
    {
        using(var adapter=new WintunAdapter((_,_)=>throw new Exception("must not create adapter"),_=>123,_=>{}))
        using(var stopped=new CancellationTokenSource()) {
            stopped.Cancel();
            int calls=0;
            int Call(ref TunnelIpv6Policy.Row row) { calls++; return 0; }
            int Resolve(in ulong luid,out Guid guid) { calls++; guid=Guid.Empty; return 0; }
            var error=Capture(() => TunnelIpv6Policy.ApplyOwned(adapter,Call,Call,Resolve,stopped.Token));
            check("IPv6 policy: owned cancelled setup starts no identity or API calls", error is OperationCanceledException && calls==0);
        }
        foreach(string fault in new[] {"unopened","guid","resolve-error","after-read","before-write","after-write","during-retry"}) {
            var expected=Guid.Parse("785f2e89-0a70-4e7c-a516-0ba1430fbd38");
            var actual=expected;
            var current=Initial();
            using var adapter=new WintunAdapter((_,_)=>new IntPtr(1),_=>123,_=>{});
            if(fault!="unopened") adapter.Open("QeliIpv6PolicyFixture",expected);
            int reads=0,writes=0,resolutions=0;
            int Resolve(in ulong luid,out Guid guid) {
                resolutions++;
                guid=fault=="guid" || (fault=="before-write" && resolutions==4) ? Guid.Empty : actual;
                return fault=="resolve-error" ? 5 : 0;
            }
            int Read(ref TunnelIpv6Policy.Row row) {
                reads++; row=current;
                if(fault=="after-read") actual=Guid.Empty;
                return fault=="during-retry" ? 1168 : 0;
            }
            int Write(ref TunnelIpv6Policy.Row row) {
                writes++; current=row;
                if(fault=="after-write") actual=Guid.Empty;
                return 0;
            }
            var error=Capture(() => TunnelIpv6Policy.ApplyOwned(adapter,Read,Write,Resolve,wait:_=>actual=Guid.Empty));
            check("IPv6 policy: owned GUID guard "+fault,
                error != null && writes==(fault=="after-write" ? 1 : 0) &&
                (fault!="during-retry" || reads==1) &&
                (fault!="unopened" || (reads==0 && resolutions==0)) &&
                (fault!="resolve-error" || (error is Win32Exception native && native.NativeErrorCode==5 && native.Message.Contains("api=ConvertInterfaceLuidToGuid"))));
        }
    }
}
