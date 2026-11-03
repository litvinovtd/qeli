using System.Net;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace Qeli.Conformance;

internal static class NativeLifecycleConformance
{
    internal static void Run(Action<string, bool> check)
    {
        var production = typeof(VpnConfig).Assembly;
        check("production boundary: managed crypto/codec fallbacks are conformance-only",
            production.GetType("Qeli.Shared.Crypto.PacketCipher") is null
            && production.GetType("Qeli.Shared.Protocol.PacketCodec") is null
            && production.GetType("Qeli.Shared.Model.LinkConformance") is null);
        check("production boundary: QeliShared does not load BouncyCastle",
            !production.GetReferencedAssemblies().Any(a => a.Name?.Contains("BouncyCastle") == true));

        var tunnel = new ObserverTunnel();
        int logReceived = 0;
        tunnel.LogLine += _ => throw new InvalidOperationException("fixture observer");
        tunnel.LogLine += _ => logReceived++;
        bool logSafe = true;
        try { tunnel.EmitLog(); } catch (InvalidOperationException) { logSafe = false; }
        check("lifecycle: a failing log subscriber cannot interrupt transport work", logSafe);
        check("lifecycle: later log subscribers still receive the notification", logReceived == 1);

        int statuses = 0;
        tunnel.StatusChanged += (_, _) => throw new InvalidOperationException("fixture observer");
        tunnel.StatusChanged += (status, _) => { if (status == VpnStatus.Disconnected) statuses++; };
        bool stopSafe = true;
        try { tunnel.Stop(); } catch (InvalidOperationException) { stopSafe = false; }
        check("lifecycle: a failing status subscriber cannot break Stop", stopSafe);
        check("lifecycle: later status subscribers receive the completed stop", statuses == 1);

        int dropped = 0, completed = 0;
        tunnel.ConnectionDropped += _ => throw new InvalidOperationException("fixture observer");
        tunnel.ConnectionDropped += _ => dropped++;
        tunnel.RunCompleted += () => throw new InvalidOperationException("fixture observer");
        tunnel.RunCompleted += () => completed++;
        tunnel.NotifyConnectionDropped("fixture reason");
        tunnel.NotifyRunCompleted();
        check("lifecycle: drop observers are isolated individually", dropped == 1);
        check("lifecycle: completion observers are isolated individually", completed == 1);

        CheckCleanup(check);
        CheckWorkers(check);
        NativeTransportCore.RequireCompatible();
        const string ini = "[qeli]\nserver = 127.0.0.1:1\nproto = tcp\nmode = plain\nuser = fixture\npass = fixture-only\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nroaming = off\n";
        ulong previous = 0;
        bool handlesOk = true, eventsOk = true, staleOk = true;
        for (int i = 0; i < 32; i++)
        {
            ulong handle = NativeTransportCore.New(ini, false, false);
            try
            {
                handlesOk &= handle != 0 && handle != previous;
                NativeTransportCore.SetDeviceId(handle, Enumerable.Repeat((byte)1, 16).ToArray());
                NativeTransportCore.Start(handle);
                var events = new List<NativeTransportCore.NativeEvent>();
                var payload = new byte[NativeTransportCore.MaxEventPayload];
                NativeTransportCore.NativeEvent? item;
                while ((item = NativeTransportCore.PollEvent(handle, payload)) is not null) events.Add(item);
                eventsOk &= events.Any(e => e.Kind == NativeTransportCore.EventStateChanged)
                    && events.Zip(events.Skip(1)).All(pair => pair.First.Sequence < pair.Second.Sequence);
                _ = NativeTransportCore.Stats(handle);
                // Without an authenticated pending plan, the native state machine must
                // refuse a fabricated acknowledgement. InvalidState (-3) is not the
                // StaleRequest (-11) race of a previously published, cancelled request.
                bool inactiveRejected = false;
                try { NativeTransportCore.NetworkPlanResult(handle, ulong.MaxValue, false, "fixture"); }
                catch (InvalidOperationException e) { inactiveRejected = e.Message.Contains("(-3)"); }
                staleOk &= inactiveRejected;
                NativeTransportCore.Stop(handle);
            }
            finally { NativeTransportCore.Free(handle); }
            bool invalidated = false;
            try { _ = NativeTransportCore.Stats(handle); }
            catch (InvalidOperationException e) { invalidated = e.Message.Contains("(-7)"); }
            staleOk &= invalidated;
            NativeTransportCore.Free(handle);
            previous = handle;
        }
        check("native lifecycle: 32 actual ABI handle generations do not reuse stale IDs", handlesOk);
        check("native lifecycle: actual state events retain sequence ordering", eventsOk);
        check("native lifecycle: freed handles refuse stats and tolerate repeated Free", staleOk);
        CheckActualPumps(check, ini);
    }

    private static void CheckWorkers(Action<string, bool> check)
    {
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        NativeWorkerLifetime.CheckPacketPumps(waiting.Task, null, CancellationToken.None);
        NativeWorkerLifetime.CheckPacketPumps(null, null, CancellationToken.None);
        check("packet lifetime: pending and absent pumps are ordinary running states", true);

        var failure = new IOException("fixture send error");
        var faulted = Task.FromException(failure);
        bool faultReported = false;
        try { NativeWorkerLifetime.CheckPacketPumps(null, faulted, CancellationToken.None); }
        catch (IOException error) { faultReported = ReferenceEquals(error.InnerException, failure); }
        check("packet lifetime: a downlink fault retains the original platform error", faultReported);

        bool earlyExitReported = false;
        try { NativeWorkerLifetime.CheckPacketPumps(Task.CompletedTask, null, CancellationToken.None); }
        catch (IOException) { earlyExitReported = true; }
        check("packet lifetime: unexpected normal completion cannot leave a Connected tunnel", earlyExitReported);

        using var stopped = new CancellationTokenSource();
        stopped.Cancel();
        NativeWorkerLifetime.CheckPacketPumps(faulted, Task.CompletedTask, stopped.Token);
        check("packet lifetime: explicit cancellation suppresses a spurious pump error", true);

        using var entered = new ManualResetEventSlim();
        bool joined = false;
        var owner = Task.Run(() =>
        {
            entered.Set();
            NativeWorkerLifetime.Join(faulted, waiting.Task, null);
            joined = true;
        });
        var heldTunnel = new ObserverTunnel();
        var device = new TrackedTun();
        // Inject only the private task ownership slot. Stop and resource cleanup are the
        // unchanged production paths, with a fake TUN instead of host networking.
        heldTunnel.HoldWorker(owner, device);
        bool timedOut = false;
        try
        {
            bool began = entered.Wait(TimeSpan.FromSeconds(2));
            check("packet lifetime: a fault does not release ownership while another worker is pending",
                began && !owner.Wait(100) && !joined);
            try { heldTunnel.Stop(); } catch (TimeoutException) { timedOut = true; }
            check("packet lifetime: Stop timeout retains the live task and TUN ownership",
                timedOut && heldTunnel.IsRunning && !joined && !device.Disposed);
        }
        finally { waiting.TrySetResult(); }
        check("packet lifetime: ownership releases only after all workers exit", owner.Wait(2000) && joined);
        heldTunnel.Stop();
        check("packet lifetime: Stop retry disposes the TUN after the workers have joined",
            device.Disposed && !heldTunnel.IsRunning);
    }

    private static void CheckActualPumps(Action<string, bool> check, string ini)
    {
        foreach (bool failReceive in new[] { true, false })
        {
            ulong handle = NativeTransportCore.New(ini, false, false);
            using var stop = new CancellationTokenSource();
            var tun = new FixtureTun(failReceive);
            Task? up = null, down = null;
            try
            {
                (up, down) = VpnTunnelBase.StartNativePacketPumps(handle, 1, tun, stop.Token);
                bool finished;
                try { finished = up.Wait(2000); } catch (AggregateException) { finished = up.IsCompleted; }
                bool detected = false;
                try { NativeWorkerLifetime.CheckPacketPumps(up, null, stop.Token); }
                catch (IOException error)
                {
                    detected = failReceive
                        ? error.InnerException is IOException cause && cause.Message == "fixture receive error"
                        : error.InnerException is null;
                }
                check(failReceive
                    ? "actual packet pump: a TUN read failure reaches lifecycle monitoring"
                    : "actual packet pump: a closed TUN reaches lifecycle monitoring", finished && detected);
            }
            finally
            {
                stop.Cancel();
                NativeTransportCore.Stop(handle);
                NativeWorkerLifetime.Join(up, down);
                NativeTransportCore.Free(handle);
                tun.Dispose();
            }
        }
    }

    private sealed class FixtureTun(bool failReceive) : IPacketTunDevice
    {
        public int ReceivePacket(byte[] destination, CancellationToken ct) => failReceive
            ? throw new IOException("fixture receive error") : 0;
        public void SendPacket(byte[] source, int offset, int length)
            => throw new IOException("fixture send error");
        public void Dispose() { }
    }

    private static void CheckCleanup(Action<string, bool> check)
    {
        var tunnel = new CleanupTunnel(); var tun = new FailingDisposeTun(); tunnel.Attach(tun);
        int disconnected = 0, errors = 0;
        tunnel.StatusChanged += (state, _) => { if (state == VpnStatus.Disconnected) disconnected++; if (state == VpnStatus.Error) errors++; };
        bool Failed() { try { tunnel.Stop(); return false; } catch (IOException) { return true; } }
        tunnel.FailRestore = true;
        check("TUN cleanup: failed pre-dispose restore retains adapter", Failed() && tun.Attempts == 0 && tunnel.Owns(tun) && tunnel.PlatformCalls == 0);
        tunnel.FailRestore = false; tun.Fail = true;
        check("TUN cleanup: failed Dispose retains adapter for retry", Failed() && tun.Attempts == 1 && tunnel.Owns(tun) && tunnel.PlatformCalls == 0);
        check("TUN cleanup: failed cleanup never publishes Disconnected", disconnected == 0 && errors == 2);
        tun.Fail = false; tunnel.FailPlatform = true;
        check("TUN cleanup: platform failure remains observable after adapter stop", Failed() && tun.Attempts == 2 && tunnel.Owns(tun));
        tunnel.FailPlatform = false; tunnel.Stop();
        check("TUN cleanup: retry releases retained ownership and publishes Disconnected", tun.Attempts == 3 && !tunnel.Owns(tun) && disconnected == 1);
        tunnel.Stop(); check("TUN cleanup: completed adapter is not disposed twice", tun.Attempts == 3);
    }
    private sealed class FailingDisposeTun : ITunDevice
    {
        internal bool Fail; internal int Attempts;
        public void Dispose() { Attempts++; if (Fail) throw new IOException("retained adapter"); }
    }
    private sealed class CleanupTunnel : VpnTunnelBase
    {
        internal bool FailRestore, FailPlatform; internal int PlatformCalls;
        internal void Attach(ITunDevice tun) => _tun = tun;
        internal bool Owns(ITunDevice tun) => ReferenceEquals(_tun, tun);
        protected override void BeforeTunDispose() { if (FailRestore) throw new IOException("DNS restore"); }
        protected override void CleanupPlatform() { PlatformCalls++; if (FailPlatform) throw new IOException("platform restore"); }
        protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
            IReadOnlyList<IPAddress> carrierCandidates, CancellationToken cancellationToken)
            => throw new InvalidOperationException("fixture does not change host networking");
    }

    private sealed class TrackedTun : ITunDevice
    {
        internal bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
    }

    private sealed class ObserverTunnel : VpnTunnelBase
    {
        internal void EmitLog() => Log("fixture log");
        internal void HoldWorker(Task owner, ITunDevice tun)
        {
            typeof(VpnTunnelBase).GetField("_runTask",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .SetValue(this, owner);
            _tun = tun;
        }
        protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
            IReadOnlyList<IPAddress> carrierCandidates, CancellationToken cancellationToken)
            => throw new InvalidOperationException("fixture does not mutate host networking");
    }
}
