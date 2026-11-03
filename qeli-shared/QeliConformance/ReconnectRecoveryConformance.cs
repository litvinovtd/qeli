using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace Qeli.Conformance;

internal static class ReconnectRecoveryConformance
{
    private const BindingFlags Hidden = BindingFlags.Instance | BindingFlags.NonPublic;
    private static void Set(VpnTunnelBase tunnel, string field, object value) =>
        typeof(VpnTunnelBase).GetField(field, Hidden)!.SetValue(tunnel, value);
    private static void RunLoop(VpnTunnelBase tunnel, VpnConfig config, CancellationToken token = default)
    {
        try
        {
            typeof(VpnTunnelBase).GetMethod("ConnectWithRetry", Hidden)!
                .Invoke(tunnel, new object[] { config, token });
        }
        catch (TargetInvocationException error) when (error.InnerException is not null)
        {
            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw();
        }
    }
    private static VpnConfig Config(int retries = 1, bool enabled = true, bool persist = false) => new()
    {
        ReconnectBaseDelaySecs = 0, ReconnectMaxDelaySecs = 0,
        ReconnectMaxRetries = retries, ReconnectEnabled = enabled, PersistTun = persist,
    };

    internal static void Run(Action<string, bool> check)
    {
        var transient = new Fixture { CleanupFailures = 1 };
        RunLoop(transient, Config());
        check("recovery: transient cleanup is retried before the next connection",
            transient.Trace.Take(4).SequenceEqual(new[] { "connect", "cleanup-fail", "cleanup-ok", "connect" }));
        check("recovery: a resolved cleanup error does not replace the later retry-limit status",
            transient.Dials == 2 && transient.LastError == Qeli.Shared.Loc.T("CouldNotConnect"));

        var repeated = new Fixture { CleanupFailuresPerDial = 3, StopOnDial = 3 };
        RunLoop(repeated, Config(retries: -1));
        check("recovery: one successful recovery resets the consecutive failure budget",
            repeated.Dials == 3 && repeated.CleanupCalls == 9 && repeated.LastError == Qeli.Shared.Loc.T("MitmStop"));

        var permanent = new Fixture { CleanupFailures = int.MaxValue }; permanent.Attach();
        Set(permanent, "_ksEngaged", 1);
        RunLoop(permanent, Config(retries: -1));
        check("recovery: unlimited reconnect still bounds consecutive cleanup failures",
            permanent.Dials == 1 && permanent.CleanupCalls == VpnTunnelBase.MaxConsecutiveRecoveryFailures + 1);
        check("recovery: failed terminal cleanup retains both TUN ownership and kill-switch",
            permanent.OwnsTun && permanent.Guarded && permanent.Lifts == 0 && permanent.LastError?.Contains("fail-closed") == true);

        foreach (string flag in new[] { "_ksEngaged", "_planReplacementGuardEngaged" })
        {
            var stop = new Fixture { CleanupFailures = int.MaxValue }; stop.Attach(); Set(stop, flag, 1);
            bool failed = false;
            try { stop.Stop(); } catch (IOException) { failed = true; }
            check($"recovery: Stop cleanup refusal retains {flag}", failed && stop.OwnsTun && stop.Guarded && stop.Lifts == 0);
            stop.CleanupFailures = 0; stop.Stop();
            check($"recovery: explicit Stop retry restores {flag} after successful cleanup", !stop.OwnsTun && !stop.Guarded && stop.Lifts == 1);
        }

        var disabled = new Fixture { CleanupFailures = int.MaxValue };
        RunLoop(disabled, Config(enabled: false));
        check("recovery: disabled reconnect does not retry a failed teardown",
            disabled.Dials == 1 && disabled.CleanupCalls == 2); // initial recovery + terminal cleanup
        var finite = new Fixture { CleanupFailures = int.MaxValue };
        RunLoop(finite, Config(retries: 0));
        check("recovery: a finite retry budget cannot be bypassed by teardown recovery",
            finite.Dials == 1 && finite.CleanupCalls == 2);

        using var cancelled = new CancellationTokenSource();
        var stopping = new Fixture { CleanupFailures = int.MaxValue }; stopping.Attach();
        Set(stopping, "_ksEngaged", 1);
        stopping.LogLine += line => { if (line.Contains("retrying recovery")) cancelled.Cancel(); };
        RunLoop(stopping, Config(retries: -1), cancelled.Token);
        check("recovery: cancellation interrupts recovery backoff without another connection",
            stopping.Dials == 1 && stopping.CleanupCalls == 2 && stopping.Guarded && stopping.OwnsTun);

        var guardRefusal = new Fixture { RefuseGuard = true }; guardRefusal.Attach();
        Set(guardRefusal, "_persistedClientIp", "10.9.0.2");
        Set(guardRefusal, "_persistedNetSig", "fixture-old-network");
        RunLoop(guardRefusal, Config(retries: -1, persist: true));
        check("recovery: firewall engagement refusal is terminal rather than a transient retry",
            guardRefusal.Dials == 1 && guardRefusal.Engages == 1 && guardRefusal.LastError?.Contains("fail-closed reconnect firewall") == true);

        var classifierRefusal = new Fixture { RefuseInterruption = true };
        RunLoop(classifierRefusal, Config(retries: -1));
        check("recovery: inability to lower the classifier cannot proceed to another connection",
            classifierRefusal.Dials == 1 && classifierRefusal.Interruptions == 1);

        // Even an unchanged topology must consume a requested rebuild only after cleanup
        // succeeds. Otherwise a transient failure makes the next pass keep the stale TUN.
        var forced = new Fixture { BeforeFailures = 1 }; forced.Attach();
        Set(forced, "_ksEngaged", 1);
        Set(forced, "_persistedClientIp", "10.9.0.2");
        string topology = VpnTunnelBase.ReadPhysicalNetSignature(NetworkInterface.GetAllNetworkInterfaces);
        Set(forced, "_persistedNetSig", topology);
        Set(forced, "_forcedNetworkRebuild", 1);
        RunLoop(forced, Config(persist: true));
        check("recovery: a forced rebuild survives a failed pre-dispose restore",
            forced.Trace.Take(4).SequenceEqual(new[] { "connect", "before-fail", "cleanup-ok", "connect" }) && !forced.OwnsTun);

        var fault = new Fixture(); fault.Attach();
        // Inject a loop-initialization fault before any per-attempt catch is active.
        RunLoop(fault, null!);
        check("recovery: an unexpected loop fault still cleans resources and publishes Error",
            !fault.OwnsTun && fault.LastError?.StartsWith("reconnect loop failed:") == true);

        check("recovery: failed physical-interface enumeration becomes an unknown signature",
            VpnTunnelBase.ReadPhysicalNetSignature(() => throw new NetworkInformationException()) == "");
        check("recovery: an interface disappearing during inspection invalidates the whole signature",
            VpnTunnelBase.ReadPhysicalNetSignature(() => new NetworkInterface[] { new DisappearingInterface() }) == "");
    }

    private sealed class Fixture : VpnTunnelBase
    {
        internal int CleanupFailures, BeforeFailures, CleanupCalls, Dials, Lifts, Engages, Interruptions;
        internal int CleanupFailuresPerDial, StopOnDial;
        internal bool RefuseGuard, RefuseInterruption;
        internal List<string> Trace { get; } = new();
        internal string? LastError;
        internal bool Guarded => EgressGuardEngaged;
        internal bool OwnsTun => _tun is not null;
        internal Fixture() => StatusChanged += (state, detail) => { if (state == VpnStatus.Error) LastError = detail; };
        internal void Attach() => _tun = new FakeTun();
        protected override void PrepareTransport(VpnConfig config)
        {
            Dials++; Trace.Add("connect");
            if (Dials == StopOnDial) throw new System.Security.SecurityException("fixture identity mismatch");
            if (CleanupFailuresPerDial > 0) CleanupFailures = CleanupFailuresPerDial;
            throw new IOException("fixture transport completion before sockets or native transport start");
        }
        protected override void BeforeTunDispose()
        {
            if (BeforeFailures > 0) { BeforeFailures--; Trace.Add("before-fail"); throw new IOException("fixture DNS restore"); }
        }
        protected override void CleanupPlatform()
        {
            CleanupCalls++;
            if (CleanupFailures > 0) { CleanupFailures--; Trace.Add("cleanup-fail"); throw new IOException("fixture platform restore"); }
            Trace.Add("cleanup-ok");
        }
        protected override bool SupportsPlanReplacementGuard => true;
        protected override void KillSwitchEngage(VpnConfig config)
        {
            Engages++; if (RefuseGuard) throw new InvalidOperationException("fixture firewall refusal");
        }
        protected override void KillSwitchDisengage() => Lifts++;
        protected override void OnTransportInterrupted(VpnConfig config)
        {
            Interruptions++;
            if (RefuseInterruption) throw new InvalidOperationException("fixture classifier refusal");
        }
        protected override void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
            IReadOnlyList<IPAddress> carrierCandidates, CancellationToken cancellationToken)
            => throw new InvalidOperationException("fixture cannot change host networking");
    }
    private sealed class FakeTun : ITunDevice { public void Dispose() { } }
    private sealed class DisappearingInterface : NetworkInterface
    {
        public override OperationalStatus OperationalStatus => throw new NetworkInformationException();
        public override string Id => "fixture";
        public override string Name => "fixture";
        public override string Description => "fixture";
        public override NetworkInterfaceType NetworkInterfaceType => NetworkInterfaceType.Ethernet;
        public override bool IsReceiveOnly => false;
        public override bool SupportsMulticast => true;
        public override bool Supports(NetworkInterfaceComponent component) => false;
        public override PhysicalAddress GetPhysicalAddress() => PhysicalAddress.None;
        public override IPInterfaceProperties GetIPProperties() => throw new NotSupportedException();
        public override IPv4InterfaceStatistics GetIPv4Statistics() => throw new NotSupportedException();
    }
}
