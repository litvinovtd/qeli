using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Qeli.Shared.Vpn;

namespace QeliWin.Vpn;

internal static class DriverResourceSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        bool Fails(Action action)
        {
            try { action(); return false; }
            catch (Exception e) when (e is IOException or InvalidOperationException or TimeoutException
                or AggregateException or DllNotFoundException or ObjectDisposedException) { return true; }
        }
        var bytes = new byte[129_001]; Random.Shared.NextBytes(bytes);
        var hash = SHA256.HashData(bytes);
        check("native cache: exact contents accepted", NativeLoader.MatchesEmbedded(new MemoryStream(bytes), bytes.Length, hash));
        var changed = (byte[])bytes.Clone(); changed[50] ^= 1;
        check("native cache: same-length corruption refused", !NativeLoader.MatchesEmbedded(new MemoryStream(changed), bytes.Length, hash));
        check("native cache: shorter contents refused", !NativeLoader.MatchesEmbedded(new MemoryStream(bytes[..^1]), bytes.Length, hash));
        var huge = new HugeStream();
        check("native cache: oversized seekable cache refused before reading", !NativeLoader.MatchesEmbedded(huge, bytes.Length, hash) && huge.Reads == 0);
        var growing = new CountingStream(new byte[bytes.Length + 90_000]);
        check("native cache: growing/nonseekable contents consume only length plus sentinel", !NativeLoader.MatchesEmbedded(growing, bytes.Length, hash) && growing.Reads == bytes.Length + 1);
        check("native cache: zero-length resource accepted", NativeLoader.MatchesEmbedded(new MemoryStream(), 0, SHA256.HashData([])));
        var modules = new NativeModuleCache(); int loads = 0;
        var results = new IntPtr[32];
        Parallel.For(0, results.Length, i => results[i] = modules.Load(i % 2 == 0 ? "WinDivert.dll" : "windivert.dll", "private-test-path", _ => { Interlocked.Increment(ref loads); return new IntPtr(42); }));
        check("native cache: concurrent ensure owns one process-lifetime module", loads == 1 && results.All(h => h == new IntPtr(42)));
        int retries = 0;
        check("native cache: load error is not cached", Fails(() => modules.Load("failure", "test", _ => { retries++; throw new DllNotFoundException(); }))
            && modules.Load("failure", "test", _ => { retries++; return new IntPtr(43); }) == new IntPtr(43) && retries == 2);
        check("native cache: zero module is never published", Fails(() => modules.Load("zero", "test", _ => IntPtr.Zero))
            && modules.Load("zero", "test", _ => new IntPtr(44)) == new IntPtr(44));
        check("WinDivert contract: DROP is 0x0002, distinct from SNIFF", WinDivertNative.WINDIVERT_FLAG_DROP == 0x0002);
        var module = NativeLoader.EnsureWinDivertLoaded();
        check("WinDivert contract: bundled 2.2 exports shutdown without opening driver", NativeLibrary.TryGetExport(module, "WinDivertShutdown", out _));
        check("WinDivert contract: repeated ensure retains same native module", module == NativeLoader.EnsureWinDivertLoaded());

        WinDivertAdapter Adapter(WinDivertRuntime runtime, Action<string>? log = null)
        {
            var adapter = new WinDivertAdapter(IPAddress.Parse("10.8.0.2"), null,
                new[] { @"C:\Windows\System32\cmd.exe" }, true, Array.Empty<string>(), false, false,
                true, new[] { "10.8.0.0/24" }, false, null, null, null, IPAddress.Parse("203.0.113.10"),
                443, "tcp", 1400, log);
            adapter.Runtime = runtime; return adapter;
        }
        using (var scenario = new DriverScenario())
        {
            var adapter = Adapter(scenario.Runtime, _ => throw new IOException("observer"));
            adapter.Open(); check("WinDivert lifetime: observer failure cannot abort Open", scenario.Threads.Count == 2);
            check("WinDivert lifetime: duplicate Open cannot overwrite native ownership", Fails(adapter.Open) && scenario.Opens == 1);
            adapter.Dispose(); adapter.Dispose();
            check("WinDivert lifetime: shutdown joins workers before exactly one close", scenario.Shutdowns == 1 && scenario.Closes == 1 && !scenario.CloseWhileAlive);
            check("WinDivert lifetime: disposed adapter cannot reopen", Fails(adapter.Open) && scenario.Opens == 1);
            check("WinDivert lifetime: dispose completes blocked packet reader", adapter.ReceivePacket(new byte[65535], CancellationToken.None) == 0);
        }
        foreach (int failedStart in new[] { 1, 2 })
        {
            using var scenario = new DriverScenario { FailedStart = failedStart };
            var adapter = Adapter(scenario.Runtime);
            check("WinDivert lifetime: thread start failure rolls back partial open " + failedStart,
                Fails(adapter.Open) && scenario.Closes == 1 && !scenario.CloseWhileAlive);
            adapter.Dispose(); check("WinDivert lifetime: rolled-back Open remains idempotent " + failedStart, scenario.Closes == 1);
        }
        using (var scenario = new DriverScenario { HoldWorkers = true })
        {
            var adapter = Adapter(scenario.Runtime); adapter.Open();
            check("WinDivert lifetime: join timeout retains handle without false close", Fails(adapter.Dispose) && scenario.Closes == 0);
            check("WinDivert lifetime: timeout generation refuses reactivation", Fails(() => adapter.SetTunnelUp(true)));
            scenario.Release.Set(); adapter.Dispose();
            check("WinDivert lifetime: retry joins late workers and releases retained handle", scenario.Closes == 1 && scenario.Shutdowns == 1 && !scenario.CloseWhileAlive);
        }
        using (var scenario = new DriverScenario { FailShutdown = true })
        {
            var adapter = Adapter(scenario.Runtime); adapter.Open();
            check("WinDivert lifetime: failed shutdown does not close pending receive", Fails(adapter.Dispose) && scenario.Closes == 0);
            scenario.FailShutdown = false; adapter.Dispose();
            check("WinDivert lifetime: shutdown failure is retryable", scenario.Shutdowns == 2 && scenario.Closes == 1 && !scenario.CloseWhileAlive);
        }
        using (var scenario = new DriverScenario { FailClose = true })
        {
            var adapter = Adapter(scenario.Runtime); adapter.Open();
            check("WinDivert lifetime: native close failure surfaced", Fails(adapter.Dispose) && scenario.Closes == 1);
            scenario.FailClose = false; adapter.Dispose(); adapter.Dispose();
            check("WinDivert lifetime: close retry preserves exact handle", scenario.Closes == 2 && scenario.ClosedHandles.All(h => h == new IntPtr(123)));
        }
        using (var scenario = new DriverScenario { FailedStart = 2, FailShutdown = true })
        {
            var adapter = Adapter(scenario.Runtime);
            bool combined = false; try { adapter.Open(); } catch (AggregateException e) { combined = e.InnerExceptions.Count == 2; }
            check("WinDivert lifetime: Open and rollback failures both retained", combined && scenario.Closes == 0);
            scenario.FailShutdown = false; adapter.Dispose(); check("WinDivert lifetime: failed partial Open remains available for cleanup retry", scenario.Closes == 1);
        }
        using (var release = new ManualResetEventSlim())
        using (var entered = new ManualResetEventSlim())
        {
            bool Receive(IntPtr h, byte[] packet, uint capacity, out uint len, ref WinDivertNative.WinDivertAddress addr)
            { len = 0; entered.Set(); release.Wait(); throw new IOException("injected native receive"); }
            var workers = new List<Thread>(); int closes = 0;
            var runtime = new WinDivertRuntime { EnsureLoaded = () => { }, Open = _ => new IntPtr(321), Configure = _ => { },
                Shutdown = _ => release.Set(), Close = _ => closes++, Receive = Receive,
                CreateThread = (body, name) => { var thread = new Thread(body) { IsBackground = true, Name = name }; workers.Add(thread); return thread; } };
            var adapter = Adapter(runtime); adapter.Open(); bool began = entered.Wait(2000); release.Set();
            bool exited = workers.Last().Join(2000);
            check("WinDivert lifetime: actual capture loop contains receive fault", began && exited);
            check("WinDivert lifetime: receive fault closes packet channel", adapter.ReceivePacket(new byte[65535], CancellationToken.None) == 0);
            check("WinDivert lifetime: failed worker cannot mark tunnel up", Fails(() => adapter.SetTunnelUp(true)));
            adapter.Dispose(); check("WinDivert lifetime: failed workers join before release", closes == 1 && workers.All(t => !t.IsAlive));
        }

        int created = 0, wintunCloses = 0; var actualNames = new List<string>();
        var wintun = new WintunAdapter((name, _) => { actualNames.Add(name); return ++created < 3 ? IntPtr.Zero : new IntPtr(987); },
            h => h == new IntPtr(987) ? 42UL : 0, _ => wintunCloses++);
        wintun.Open("Qeli", Guid.NewGuid()); wintun.RequireReady();
        check("Wintun lifetime: collision creates fresh named handle, never adopts foreign adapter", actualNames.SequenceEqual(new[] { "Qeli", "Qeli-0", "Qeli-1" }) && wintun.AdapterName == "Qeli-1" && wintun.Luid == 42);
        check("Wintun lifetime: duplicate Open preserves owned handle", Fails(() => wintun.Open("another", Guid.NewGuid())) && created == 3);
        wintun.Dispose(); wintun.Dispose();
        check("Wintun lifetime: successful dispose closes once and clears identity", wintunCloses == 1 && wintun.Luid == 0 && wintun.AdapterName == "");
        check("Wintun lifetime: disposed object cannot reopen", Fails(() => wintun.Open("Qeli", Guid.NewGuid())));
        bool closeFailure = true; int closeCalls = 0;
        var retainedWintun = new WintunAdapter((_, _) => new IntPtr(765), _ => 84, h => { closeCalls++; if (h != new IntPtr(765) || closeFailure) throw new IOException("Wintun close"); });
        retainedWintun.Open("Qeli", Guid.NewGuid());
        check("Wintun lifetime: failed close retains handle and identity", Fails(retainedWintun.Dispose) && retainedWintun.HasHandle && retainedWintun.Luid == 84);
        check("Wintun lifetime: pending cleanup refuses Open", Fails(() => retainedWintun.Open("new", Guid.NewGuid())));
        closeFailure = false; retainedWintun.Dispose(); retainedWintun.Dispose();
        check("Wintun lifetime: cleanup retry releases exact retained handle", closeCalls == 2 && !retainedWintun.HasHandle);
        int partialCloses = 0;
        var partial = new WintunAdapter((_, _) => new IntPtr(654), _ => throw new IOException("LUID lookup"), _ => partialCloses++);
        check("Wintun lifetime: failed post-create initialization retains handle", Fails(() => partial.Open("Qeli", Guid.NewGuid())) && partial.HasHandle);
        check("Wintun lifetime: incomplete prewarm cannot be used as ready adapter", Fails(partial.RequireReady));
        partial.Dispose(); check("Wintun lifetime: incomplete prewarm can still be disposed", partialCloses == 1 && !partial.HasHandle);

        int gateAttempts = 0; bool gateFailure = true;
        var gate = new WinDivertKillSwitchGate(new IntPtr(777), h => { gateAttempts++; if (h != new IntPtr(777) || gateFailure) throw new IOException("gate close"); });
        check("drop gate: failed close preserves owned handle", Fails(gate.Dispose) && gateAttempts == 1);
        gateFailure = false; gate.Dispose(); gate.Dispose(); check("drop gate: retry closes exact handle only once", gateAttempts == 2);
        var owned = new RetainedDriverGates(); var old = new FakeGate { Fail = true }; var next = new FakeGate();
        owned.Replace(() => old);
        check("drop gate: failed retirement retains old and new generations", Fails(() => owned.Replace(() => next)) && owned.HasOwnership && old.Attempts == 1 && next.Attempts == 0);
        bool anotherOpened = false;
        check("drop gate: pending retirement refuses further native Open", Fails(() => owned.Replace(() => { anotherOpened = true; return new FakeGate(); }))
            && !anotherOpened && owned.HasOwnership);
        check("drop gate: cleanup tries every generation and reports failure", Fails(owned.Close) && next.Attempts == 1 && old.Attempts == 3 && owned.HasOwnership);
        old.Fail = false; owned.Close(); owned.Close(); check("drop gate: recovery retries only retained generation", old.Attempts == 4 && next.Attempts == 1 && !owned.HasOwnership);
        bool journal = true, owner = true;
        check("drop gate: failed close keeps journal and ownership", Fails(() => KillSwitch.CompleteRecovery(() => throw new IOException("close"), () => journal = false, () => owner = false)) && journal && owner);
        KillSwitch.CompleteRecovery(() => { }, () => journal = false, () => owner = false);
        check("drop gate: successful retry releases journal and ownership", !journal && !owner);
    }

    private sealed class DriverScenario : IDisposable
    {
        internal readonly ManualResetEventSlim Release = new();
        internal readonly List<Thread> Threads = new();
        internal readonly List<IntPtr> ClosedHandles = new();
        internal int Opens, Shutdowns, Closes, Starts, FailedStart;
        internal bool HoldWorkers, FailShutdown, FailClose, CloseWhileAlive;
        internal WinDivertRuntime Runtime => new()
        {
            EnsureLoaded = () => { }, Open = _ => { Opens++; return new IntPtr(123); }, Configure = _ => { },
            Shutdown = _ => { Shutdowns++; if (FailShutdown) throw new IOException("shutdown"); if (!HoldWorkers) Release.Set(); },
            Close = h => { Closes++; ClosedHandles.Add(h); CloseWhileAlive |= Threads.Any(t => t.IsAlive); if (FailClose) throw new IOException("close"); },
            CreateThread = (_, name) => { var thread = new Thread(() => Release.Wait()) { IsBackground = true, Name = name }; Threads.Add(thread); return thread; },
            StartThread = thread => { if (++Starts == FailedStart) throw new InvalidOperationException("thread start"); thread.Start(); }, JoinMilliseconds = 75,
        };
        public void Dispose() { Release.Set(); foreach (var thread in Threads) if ((thread.ThreadState & System.Threading.ThreadState.Unstarted) == 0) thread.Join(2000); Release.Dispose(); }
    }
    private sealed class FakeGate : IDisposable
    {
        internal bool Fail; internal int Attempts;
        public void Dispose() { Attempts++; if (Fail) throw new IOException("retired close"); }
    }
    private sealed class HugeStream : MemoryStream
    {
        internal int Reads;
        public override long Length => 2L * 1024 * 1024 * 1024;
        public override int Read(byte[] buffer, int offset, int count) { Reads++; throw new IOException("must not read oversized cache"); }
    }
    private sealed class CountingStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes);
        internal int Reads;
        public override bool CanSeek => false; public override bool CanRead => true; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => _inner.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) { int n = _inner.Read(buffer, offset, count); Reads += n; return n; }
        public override void Flush() { } public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long n) => throw new NotSupportedException(); public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
    }
}
