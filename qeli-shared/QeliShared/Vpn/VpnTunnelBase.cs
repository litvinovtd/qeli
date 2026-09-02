using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Qeli.Shared.Model;

namespace Qeli.Shared.Vpn;


/// <summary>
/// Shared Windows/macOS lifecycle and platform adapter for the ABI 1.11 Rust transport.
/// Rust owns carrier sockets, handshake, crypto and packet loops; this class applies the
/// authenticated NetworkPlan, creates the platform Wintun interface or transfers a Unix TUN
/// descriptor, and raises events for the UI.
/// </summary>
public abstract class VpnTunnelBase
{
    public event Action<string>? LogLine;
    public event Action<VpnStatus, string?>? StatusChanged; // status, optional ip/error
    public event Action<string>? ConnectionDropped;          // established session lost (will retry)
    /// <summary>Raised after the asynchronous run task has actually completed. A terminal
    /// Error status is published from inside that task, so observers that derive controls
    /// from <see cref="IsRunning"/> need this second edge after IsCompleted becomes true.</summary>
    public event Action? RunCompleted;
    protected void Log(string m) => LogLine?.Invoke(m);
    private void Status(VpnStatus s, string? extra = null) => StatusChanged?.Invoke(s, extra);

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    // Serializes Start()/Stop() on the single reused tunnel object so a profile switch
    // (Start->Stop->Start) can't overlap the previous attempt's teardown with the new
    // attempt's setup on the SHARED transport/TUN/route fields.
    private readonly object _lifecycleLock = new();
    private volatile bool _userRequestedDisconnect;
    // persist-tun: client IP the currently-persisted TUN adapter+routes were built for.
    // Kept separately for status/logging; reuse is gated by the complete applied-plan
    // fingerprint below, not by the address alone.
    private string? _persistedClientIp;
    // Display projection of every authenticated inner assignment. The legacy primary IP is
    // still kept separately because persist-tun fingerprints and older status consumers use it.
    private string? _persistedTunnelAddresses;
    // Canonical fingerprint of every NetworkPlan/config value that the desktop platform
    // adapter applied to the host: address/prefix, effective MTU and DNS, routes (including
    // route_file), carrier pin and platform routing policy. A new authenticated generation
    // may keep the same client IP while changing any of these values.
    private string? _persistedPlanFingerprint;
    // Physical network for which the persisted adapter's bypass routes and DNS
    // state were installed. Reusing the same client IP is not enough: a changed
    // gateway, resolver or service makes those platform settings stale.
    private string? _persistedNetSig;
    // All A/AAAA records captured before the TUN takes over routing. Reconnects reuse and rotate
    // this set instead of asking a resolver that may now live behind the retained dead TUN.
    private string[] _carrierAddresses = Array.Empty<string>();
    private int _carrierGeneration;

    // Handshake-only mode (headless --handshake test): stop after auth, skip TUN.
    private bool _handshakeOnly;
    private string? _handshakeIp;

    // True once an established tunnel is up; used to detect a server-side drop.
    private volatile bool _wasConnected;

    // 1 while the firewall kill-switch is engaged (so the teardown lifts exactly what
    // Start() raised). The kill-switch is raised ONCE before the connect loop and
    // stays up across reconnects — see KillSwitchEngage/Disengage.
    // An int (not a bool) because TWO paths may now lift it: Stop() and the reconnect
    // loop's give-up tail, which runs on the tunnel task and therefore cannot take
    // _lifecycleLock (Stop() holds it while joining that very task). Interlocked makes
    // "lift exactly once" hold without a lock. (Audit 2026-07-27, B2)
    private int _ksEngaged;
    // A changed authenticated NetworkPlan cannot be applied to the desktop system TUN
    // atomically at the OS route-table level: the old /1/include routes must be removed
    // before the replacements can be installed. When the user did not request the regular
    // kill-switch, temporarily reuse the same platform firewall transaction so that this
    // unavoidable control-plane gap is fail-closed rather than a cleartext leak. Per-app
    // adapters update their retained classifier in place and therefore never raise this.
    private int _planReplacementGuardEngaged;

    // ABI 1.7+ native whole-transport generation. Kept as a signed slot solely so
    // Interlocked can publish/clear it while Stop() interrupts qeli_client_run.
    private long _nativeHandle;
    // Optional ABI 1.12-1.14 roaming state. The handle/generation pair is published only
    // after the authenticated NetworkPlan is applied; callbacks therefore cannot submit a
    // PathUpdate into a half-configured native generation.
    private readonly object _nativeRoamingGate = new();
    private VpnConfig? _nativeRoamingConfig;
    private ulong _nativeRoamingCapabilities;
    private long _nativePlanGeneration;
    private long _nativePathUpdateId;
    protected ITunDevice? _tun;

    // Live byte counters (goodput, IP-payload bytes) for the UI speed readout.
    private long _bytesUp;
    private long _bytesDown;
    private ulong _udpKernelDrops;
    private ulong _udpInternalDrops;
    private ulong _udpBufferGrows;
    private ulong _udpRecvBufferBytes;
    private ulong _udpReportedKernelDrops;
    private ulong _udpReportedInternalDrops;
    private long _udpLastReportTick;
    private bool _udpReadyLogged;

    /// <summary>Client journal detail: <c>info</c> is compact, <c>debug</c>/<c>trace</c>
    /// retain rate-limited native telemetry. The value may be changed while connected.</summary>
    public string LogLevel { get; set; } = "info";
    public long BytesUp => Interlocked.Read(ref _bytesUp);
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    /// <summary>When the current tunnel reached Connected (for session duration).</summary>
    public DateTime? ConnectedSince { get; private set; }

    public bool IsRunning => _runTask is { IsCompleted: false };

    public bool Start(VpnConfig config)
    {

        // Serialize Start/Stop (and thus a concurrent profile switch) on one lock: Stop()
        // fully quiesces the previous attempt before we reuse the SHARED transport/TUN/route
        // fields, so the old task's teardown can't clobber the newly-established tunnel.
        lock (_lifecycleLock)
        {
            try
            {
                // This is an internal generation handoff, not a user-visible disconnect.
                // Publishing Disconnected here races the GUI's new active-profile assignment
                // and briefly makes a successful Start look stopped. Cleanup errors still
                // publish Error and abort the new generation.
                Stop(publishDisconnected: false);
            }
            catch (Exception e)
            {
                // Never start a new generation while the previous one may still own the
                // shared TUN/socket/route fields. Stop() deliberately leaves its task and
                // cancellation source published when it cannot prove quiescence, so a later
                // Stop()/Start() can retry once that task has actually returned.
                Log($"[SECURITY] previous tunnel did not stop cleanly: {e.Message}");
                Status(VpnStatus.Error, FirstSentence(e.Message));
                return false;
            }
            // Validate AFTER Stop(), inside the lock. Returning before it left the PREVIOUS
            // tunnel running while the GUI had already switched to the new profile and shown
            // an error — routes and traffic still belonged to a session the user thought was
            // gone. Refusing a profile must never mean "keep the old one silently".
            // (Audit 2026-07-31, §7.)
            try
            {
                config.Validate();
            }
            catch (Exception e)
            {
                Log($"config rejected: {e.Message}");
                Status(VpnStatus.Error, e.Message);
                return false;
            }
            _userRequestedDisconnect = false;
            Interlocked.Increment(ref _networkObservationRevision);
            Interlocked.Exchange(ref _networkObservationPending, 0);
            // TestHandshake latches this and used to never clear it, so a GUI object that had
            // run the headless handshake test once connected forever after WITHOUT a TUN —
            // "connected", no traffic. Reset it with the rest of the per-run state.
            // (Audit 2026-07-27, N5)
            _handshakeOnly = false;
            // Per-run too: left set, a previous MITM stop would suppress the ordinary
            // "could not connect" message on the NEXT attempt. (Audit 2026-07-27, Z2)
            _stoppedForSecurityReason = false;
            _wasConnected = false;
            _forcedReconnectInFlight = false;
            Interlocked.Exchange(ref _forcedNetworkRebuild, 0);
            _carrierAddresses = Array.Empty<string>();
            _carrierGeneration = 0;
            _lastNetSig = PhysicalNetSignature(); // baseline: physical net at connect (TUN excluded)
            _bytesUp = 0; _bytesDown = 0;
            _udpKernelDrops = 0; _udpInternalDrops = 0;
            _udpBufferGrows = 0; _udpRecvBufferBytes = 0;
            _udpReportedKernelDrops = 0; _udpReportedInternalDrops = 0;
            _udpLastReportTick = Environment.TickCount64; _udpReadyLogged = false;
            ConnectedSince = null;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            Status(VpnStatus.Connecting);
            Log($"Service started: {config.Protocol.ToUpperInvariant()}/{config.WireMode}" +
                (config.IsUdp && config.QuicEnabled ? "+QUIC" : ""));
            Log($"Connecting to {LogValue(config.ServerAddress)}:{config.Port} " +
                $"as user '{LogValue(config.Username)}'");

            // Raise the firewall kill-switch BEFORE the first connect, so even the first
            // attempt and every reconnect window is leak-proof. It stays up across
            // reconnects and is lifted only on Stop(). Fail closed: if the user asked for
            // it but it can't be raised, do NOT connect unprotected.
            // Asked for but inapplicable: say so. The kill-switch blocks everything that is
            // not the tunnel, which only means anything when the tunnel carries the default
            // route — in split-tunnel the untunnelled traffic is the POINT, so there is
            // nothing to fail closed to. Skipping is correct; skipping in silence is not:
            // `kill_switch = true` then sits in the config looking like protection while
            // doing nothing, and the log gives no hint either way.
            if (config.KillSwitch && (!config.IsFullTunnel || config.UsesAppFilter))
                Log(config.UsesAppFilter
                    ? "NOTE: kill_switch = true is ignored while per-app filtering is active; "
                      + "a system-wide outbound block would also block the apps deliberately routed outside the VPN."
                    : "NOTE: kill_switch = true is ignored in split-tunnel mode (gateway = false) "
                      + "— it only applies when the tunnel carries the default route. "
                      + "Set gateway = true if you want fail-closed protection.");

            if (config.KillSwitch && config.IsFullTunnel && !config.UsesAppFilter
                && config.ExcludeRoutes.Count != 0)
                Log($"WARNING: exclude + kill_switch: {config.ExcludeRoutes.Count} excluded "
                    + "subnet(s) will be BLACKHOLED, not sent direct — the kill-switch blocks "
                    + "all non-tunnel egress. Disable kill_switch if those networks must be "
                    + "reached through the physical interface.");

            if (config.KillSwitch && config.IsFullTunnel && !config.UsesAppFilter)
            {
                try { KillSwitchEngage(config); Interlocked.Exchange(ref _ksEngaged, 1); }
                catch (Exception e)
                {
                    bool egressRestored = true;
                    if (KillSwitchEngageFailureRetainsOwnership(e))
                    {
                        // Engage changed the host firewall and its own rollback failed. Record
                        // ownership before retrying cleanup so Stop/the next Start cannot forget it.
                        Interlocked.Exchange(ref _ksEngaged, 1);
                        egressRestored = KillSwitchLift();
                    }
                    Log($"[SECURITY] kill-switch could not be engaged: {e.Message} — "
                        + (egressRestored
                            ? "not connecting unprotected; egress was restored"
                            : "egress remains fail-closed and cleanup ownership was retained"));
                    // Carry the REASON into the status detail, not just "it failed". This is a
                    // refusal to connect, so the status line is the only thing many users will
                    // ever see — and a bare "kill-switch failed" says nothing about what to do,
                    // sending them to the log for text the UI could have shown. The platform
                    // messages here are written to be actionable (macOS names the missing pf
                    // anchor and the pfctl command that fixes it), so the first sentence is
                    // worth surfacing verbatim.
                    Status(VpnStatus.Error, egressRestored
                        ? $"kill-switch failed — {FirstSentence(e.Message)}"
                        : "kill-switch failed; egress remains fail-closed — retry Disconnect");
                    return false;
                }
            }

            var runTask = Task.Run(() => ConnectWithRetry(config, ct), ct);
            _runTask = runTask;
            _ = runTask.ContinueWith(
                _ =>
                {
                    try { RunCompleted?.Invoke(); }
                    catch (Exception e) { Log($"run-completion observer failed: {e.Message}"); }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return true;
        }
    }

    /// <summary>Headless test: connect + full handshake only (no TUN, no admin), return the
    /// server-assigned tunnel IP. Throws on any protocol/auth failure.</summary>
    public string TestHandshake(VpnConfig config)
    {
        _handshakeOnly = true;
        _handshakeIp = null;
        _userRequestedDisconnect = true; // no reconnect loop
        using var cts = new CancellationTokenSource();
        // Clear the handshake-only latch on EVERY exit, success or throw: it used to stay set
        // for the lifetime of the object, so a later Start() on the same tunnel skipped the TUN
        // entirely and reported a connection that carried no traffic. (Audit 2026-07-27, N5)
        try { RunVpnConnection(config, cts.Token); }
        finally { _handshakeOnly = false; CloseTransports(); }
        return _handshakeIp ?? throw new Exception("handshake produced no IP");
    }

    /// <summary>
    /// Set when the connect loop stopped because of a server-identity mismatch (possible
    /// MITM), so the generic "could not connect" message does not replace that warning.
    /// (Audit 2026-07-27, Z2.)
    /// </summary>
    private volatile bool _stoppedForSecurityReason;

    public void Stop() => Stop(publishDisconnected: true);

    private void Stop(bool publishDisconnected)
    {
        lock (_lifecycleLock)
        {
            _userRequestedDisconnect = true;
            Interlocked.Increment(ref _networkObservationRevision);
            Interlocked.Exchange(ref _networkObservationPending, 0);
            try { _cts?.Cancel(); } catch { }
            // Phase 1 — SOCKETS ONLY (keepTun), to wake every blocking read. The TUN and the
            // platform network state must NOT be torn down yet: the connect thread can be deep
            // inside SetupTun (seconds on Windows, where creating the Wintun adapter alone takes
            // ~10 s), and it assigns _tun AFTER we would have nulled it — so the adapter, its
            // routes and the DNS override survived the "stop" with nothing left referencing
            // them. Tear down only once the task is joined, below. (Audit 2026-07-27, B3)
            CloseTransports(keepTun: true);
            // FULLY join the previous attempt before returning. The switch path calls
            // Start()->Stop() on the SAME tunnel object, whose transport/TUN/route fields are
            // shared; if the old task's teardown outlived this wait it would dispose the NEW
            // _tun / close the NEW sockets / restore away the NEW routes ("previous profile
            // sticks"). CloseTransports above already woke its blocking reads, so the task
            // returns promptly; the generous bound only guards a pathological cleanup.
            var t = _runTask;
            if (t != null)
            {
                try
                {
                    if (!t.Wait(8000))
                    {
                        const string message =
                            "previous tunnel task did not stop within 8s; refusing to reuse its network state";
                        Log($"[SECURITY] {message}");
                        Status(VpnStatus.Error, message);
                        throw new TimeoutException(message);
                    }
                }
                catch (AggregateException) when (t.IsCompleted)
                {
                    // The task's own fault is irrelevant after it has relinquished all shared
                    // state; its cleanup still ran through ConnectWithRetry's finally paths.
                }
            }
            _runTask = null;
            _cts = null;
            // Phase 2 — now that nothing is running inside SetupTun / the data plane, dispose
            // the TUN and undo the platform network state. Idempotent: the joined task's own
            // error path may already have done it (both CloseTransports and CleanupPlatform
            // null-check what they release). (Audit 2026-07-27, B3)
            try
            {
                CloseTransports();
            }
            catch (Exception e)
            {
                // A platform cleanup failure is materially different from Disconnected.
                // macOS uses this to retain and retry a failed physical-service DNS restore;
                // swallowing it here made the UI green/grey while the host resolver still
                // pointed into a tunnel that no longer existed.
                Log($"[SECURITY] platform cleanup incomplete: {e.Message}");
                Status(VpnStatus.Error, FirstSentence(e.Message));
                throw;
            }
            if (!PlanReplacementGuardLift())
            {
                const string message =
                    "network-plan replacement guard could not be disengaged; egress remains fail-closed";
                Status(VpnStatus.Error, message);
                throw new InvalidOperationException(message);
            }
            // Lift the kill-switch only on a clean stop (a crash leaves it = fail-safe).
            if (!KillSwitchLift())
            {
                const string message =
                    "kill-switch could not be disengaged; egress remains fail-closed";
                Status(VpnStatus.Error, message);
                throw new InvalidOperationException(message);
            }
            if (publishDisconnected) Status(VpnStatus.Disconnected);
        }
    }

    private long _lastForceReconnectTick;
    // True while ForceReconnect() deliberately closes the live sockets for a network change,
    // so the resulting data-plane socket error is logged as a clean reconnect, not a scary ERR.
    private volatile bool _forcedReconnectInFlight;
    // Set with a forced reconnect when the platform network state itself must be rebuilt.
    // The socket close wakes the run loop first; that loop owns `config` and performs the
    // guarded teardown, so the OS callback never has to race the data-plane fields directly.
    private int _forcedNetworkRebuild;

    /// <summary>Proactively cycle the connection NOW instead of waiting out the RX-liveness
    /// watchdog — called by the platform GUIs from OS suspend/resume and network-change
    /// hooks. No-op unless an established tunnel is up; debounced (one reconnect per ~3s) so
    /// a burst of OS events collapses to a single cycle. Closes the live sockets (keeping the
    /// TUN + kill-switch up, so no leak/route gap) so the data-plane loop errors and
    /// ConnectWithRetry reconnects promptly. Mirrors the Android client's forceReconnect().</summary>
    public void ForceReconnect(string reason, bool rebuildNetwork = false)
    {
        NoteNetworkSettling();
        if (_userRequestedDisconnect || !IsRunning || !_wasConnected) return;
        if (rebuildNetwork) Interlocked.Exchange(ref _forcedNetworkRebuild, 1);
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastForceReconnectTick) < 3000)
        {
            // Ordinary duplicate lifecycle events stay debounced. A distinct physical-network
            // change must not be swallowed after a very fast reconnect, however. While the
            // previous forced cycle is still unwinding, the rebuild flag above is sufficient;
            // once it has unwound and a new session is live, immediately cycle that stale path.
            if (!rebuildNetwork || _forcedReconnectInFlight) return;
        }
        Interlocked.Exchange(ref _lastForceReconnectTick, now);
        Log($"{reason} — reconnecting");
        _forcedReconnectInFlight = true;
        // Retain the adapter until ConnectWithRetry observes the interrupted generation.
        // That path can first lower a per-app classifier or engage the system firewall;
        // destroying it here opened exactly the cleartext route gap persist_tun prevents.
        CloseTransports(keepTun: true);
    }

    /// <summary>First sentence of a message, for a one-line status detail. Falls back to a
    /// hard character cap so a message with no sentence break still cannot overrun the UI.</summary>
    private static string FirstSentence(string s)
    {
        s = (s ?? "").Replace('\n', ' ').Replace('\r', ' ').Trim();
        int dot = s.IndexOf(". ", StringComparison.Ordinal);
        if (dot > 0) s = s[..(dot + 1)];
        return s.Length <= 160 ? s : s[..157] + "…";
    }

    /// <summary>Mark the network as settling for the next <see cref="SettlingWindowMs"/>.
    ///
    /// Deliberately NOT gated on `_wasConnected`, unlike the cycle it accompanies. That guard
    /// is right for tearing a live tunnel down — there is nothing to cycle otherwise — but it
    /// is exactly wrong for recording that the network just changed. On Windows the tunnel is
    /// usually already dead by the time the Resume event arrives (the sockets went away with
    /// the suspend), so `_wasConnected` is false and every caller returned early — leaving the
    /// window unarmed in the single most common case it exists for, while the retry loop was
    /// already grinding through full-length attempts. Arm first, then decide whether a cycle
    /// is also needed.</summary>
    private void NoteNetworkSettling()
    {
        if (_userRequestedDisconnect || !IsRunning) return;
        Interlocked.Exchange(ref _settlingUntilTick, Environment.TickCount64 + SettlingWindowMs);
        // Logged only when there is no live tunnel to cycle — the path that used to be
        // entirely silent. When a cycle does follow, ForceReconnect logs its own line and a
        // second one here would just be noise. This line is what makes the window visible in
        // a field log: if recovery is still slow, its presence says the window was armed and
        // the time went somewhere else.
        if (!_wasConnected)
            Log($"Network settling — reconnect backoff constrained for the next "
                + $"{SettlingWindowMs / 1000}s");
    }

    // We know WHY we are reconnecting (resume-from-sleep, network change), and for a while
    // afterwards a failure says nothing about the server — the network is simply not carrying
    // traffic yet. See the escalation site in ConnectWithRetry for what this suppresses.
    private const int SettlingWindowMs = 30_000;
    private const int CarrierReplacementWaitMs = 5_000;
    private const int SettlingAttemptCap = 3;   // ≤ base·2² — 4 s at the default base of 1 s
    private long _settlingUntilTick;
    // Invalidates an older settle task when a newer address event, Stop or Start wins.
    private long _networkObservationRevision;
    private int _networkObservationPending;

    /// <summary>Resume-from-sleep variant of <see cref="ForceReconnect"/>. The OS raises Resume
    /// while Wi-Fi is still reassociating and DHCP is pending, so cycling right then tears the
    /// tunnel down into a network that cannot carry the handshake yet — and once it is down the
    /// well-timed NetworkAddressChanged that arrives a moment later can no longer help, because
    /// ForceReconnect no-ops without an established tunnel. The reconnect then falls back to
    /// blind attempts. So wait off-thread for a physical interface to carry an IPv4 or IPv6 address
    /// again, bounded, and only then cycle. Fires anyway at the bound so a machine that resumes
    /// with no network at all still reconnects rather than waiting forever.</summary>
    public void ForceReconnectWhenNetworkReady(
        string reason, int maxWaitMs = 15_000, string pathReason = "wake")
    {
        // Arm the settling window on the OS event itself, BEFORE the `_wasConnected` guard
        // below can return: after a suspend the tunnel is usually already gone, and that is
        // precisely when the retry loop needs to know the network is coming back rather than
        // that the server is down. See NoteNetworkSettling.
        NoteNetworkSettling();
        if (_userRequestedDisconnect || !IsRunning || !_wasConnected) return;
        // The daemon polls once per second and GUI callbacks arrive in bursts. Keep one bounded
        // settle operation so repeated empty/intermediate snapshots cannot restart its deadline.
        if (Interlocked.CompareExchange(ref _networkObservationPending, 1, 0) != 0) return;
        long observationRevision = Interlocked.Increment(ref _networkObservationRevision);
        Task.Run(async () =>
        {
            try
            {
                long deadline = Environment.TickCount64 + maxWaitMs;
                string baseline = _lastNetSig;
                string? attemptedSignature = null;
                while (true)
                {
                    if (observationRevision != Interlocked.Read(ref _networkObservationRevision)
                        || _userRequestedDisconnect || !IsRunning || !_wasConnected)
                        return;
                    string now = PhysicalNetSignature();
                    if (now.Length > 0 && now == baseline)
                    {
                        Log($"{reason} — same network, keeping the tunnel");
                        return;
                    }
                    if (now.Length > 0 && now != attemptedSignature)
                    {
                        attemptedSignature = now;
                        if (TrySubmitNativePathUpdate(pathReason))
                        {
                            _lastNetSig = now;
                            return;
                        }
                    }
                    if (Environment.TickCount64 >= deadline)
                    {
                        _lastNetSig = now;
                        ForceReconnect(reason, rebuildNetwork: true);
                        return;
                    }
                    await Task.Delay(500).ConfigureAwait(false);
                }
            }
            finally
            {
                // Stop/Start and a newer operation increment the revision; an old completion
                // must never clear the pending bit owned by that newer generation.
                if (observationRevision == Interlocked.Read(ref _networkObservationRevision))
                    Interlocked.CompareExchange(ref _networkObservationPending, 0, 1);
            }
        });
    }

    // Signature of the PHYSICAL network (non-tunnel interface addresses, gateways and DNS), captured at
    // connect. A NetworkAddressChanged whose signature still matches this is our OWN tunnel
    // adapter coming up/down (or noise), NOT a real network change — so it must not trigger a
    // reconnect (wired straight to ForceReconnect it self-triggered an endless reconnect storm
    // on Windows/macOS: TUN up → "network changed" → reconnect → TUN up → …).
    private volatile string _lastNetSig = "";

    private static string PhysicalNetSignature()
    {
        var addrs = new List<string>();
        foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
            var t = ni.NetworkInterfaceType;
            if (t == System.Net.NetworkInformation.NetworkInterfaceType.Loopback
                || t == System.Net.NetworkInformation.NetworkInterfaceType.Tunnel) continue;
            var name = (ni.Name + " " + ni.Description).ToLowerInvariant();
            if (name.Contains("qeli") || name.Contains("wintun") || name.Contains("utun")) continue; // our TUN
            try
            {
                var props = ni.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                    if (ua.Address.AddressFamily is AddressFamily.InterNetwork
                        or AddressFamily.InterNetworkV6)
                        addrs.Add($"{ni.Id}:addr:{ua.Address}/{ua.PrefixLength}");
                foreach (var gateway in props.GatewayAddresses)
                    if (gateway.Address.AddressFamily is AddressFamily.InterNetwork
                        or AddressFamily.InterNetworkV6)
                        addrs.Add($"{ni.Id}:gw:{gateway.Address}");
                foreach (var resolver in props.DnsAddresses)
                    if (resolver.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                        addrs.Add($"{ni.Id}:dns:{resolver}");
            }
            catch
            {
                // Interfaces can disappear while NetworkAddressChanged is being
                // delivered. The next event/reconnect samples the settled state.
            }
        }
        addrs.Sort(StringComparer.Ordinal);
        return string.Join(",", addrs);
    }

    /// <summary>Network-change hook for the platform GUIs. NetworkAddressChanged is a coarse
    /// signal that ALSO fires when our own TUN adapter comes up/down; wired straight to
    /// ForceReconnect it self-triggered an endless reconnect storm. Reconnect only when the
    /// PHYSICAL network actually changed (Android gets this for free via its NOT_VPN-filtered
    /// NetworkCallback).</summary>
    public void OnNetworkChanged()
    {
        if (_userRequestedDisconnect || !IsRunning || !_wasConnected) return;
        var sig = PhysicalNetSignature();
        if (sig == _lastNetSig) return;   // our own TUN up/down, or noise — ignore
        ForceReconnectWhenNetworkReady(
            "Network changed", CarrierReplacementWaitMs, "network_changed");
    }

    /// <summary>Convert one platform observation into the shared generation-scoped path
    /// transaction. Returning false means the caller must retain the existing full reconnect
    /// fallback; a successful submit leaves retry/grace/fallback policy inside Rust.</summary>
    private bool TrySubmitNativePathUpdate(string reason, ulong? requiredGeneration = null)
    {
        lock (_nativeRoamingGate)
        {
            if (_nativeRoamingCapabilities == 0 || _nativeRoamingConfig == null)
                return false;
            ulong handle = unchecked((ulong)Interlocked.Read(ref _nativeHandle));
            ulong generation = unchecked((ulong)Interlocked.Read(ref _nativePlanGeneration));
            if (handle == 0 || generation == 0
                || (requiredGeneration.HasValue && requiredGeneration.Value != generation))
                return false;
            long next = Interlocked.Increment(ref _nativePathUpdateId);
            if (next <= 0)
                return false;
            try
            {
                NativePathUpdate? update = CaptureNativeRoamingPath(
                    _nativeRoamingConfig, _carrierAddresses, generation,
                    unchecked((ulong)next), reason);
                if (update == null)
                    return false;
                ulong candidate = NativeTransportCore.PathUpdate(handle, update);
                Log($"Native roaming PathUpdate {update.UpdateId} prepared candidate {candidate}: "
                    + $"{reason}, {update.PlatformPathId}");
                return true;
            }
            catch (Exception error)
            {
                Log($"WARN: native roaming path observation failed ({error.Message})");
                return false;
            }
        }
    }

    internal static NativeTransportCore.PathCommandOutcome PathCommandOutcomeForError(
        Exception? error) => error switch
    {
        null => NativeTransportCore.PathCommandOutcome.Accepted,
        NativeRoamingPlatformStateUnknownException =>
            NativeTransportCore.PathCommandOutcome.PlatformStateUnknown,
        _ => NativeTransportCore.PathCommandOutcome.Rejected,
    };

    private void HandleNativePathCommand(ulong handle, NativeTransportCore.NativeEvent request)
    {
        NativePathCommand command = NativeRoamingPath.DecodeCommand(request);
        NativeTransportCore.PathCommandOutcome outcome =
            NativeTransportCore.PathCommandOutcome.Rejected;
        string? reason = null;
        try
        {
            lock (_nativeRoamingGate)
            {
                ulong activeGeneration = unchecked((ulong)Interlocked.Read(ref _nativePlanGeneration));
                if (_nativeRoamingCapabilities == 0 || command.Generation != activeGeneration)
                    throw new InvalidDataException("native roaming command is stale or disabled");
                ApplyNativeRoamingCommand(command);
                if (command.Action == "commit_path")
                {
                    _carrierAddresses = command.Path.ResolvedAddresses
                        .Select(item => item.Address)
                        .Distinct(StringComparer.Ordinal)
                        .ToArray();
                }
            }
            outcome = NativeTransportCore.PathCommandOutcome.Accepted;
        }
        catch (Exception error)
        {
            reason = error.Message;
            outcome = PathCommandOutcomeForError(error);
            string disposition = outcome == NativeTransportCore.PathCommandOutcome.PlatformStateUnknown
                ? "left platform state unknown" : "rejected";
            Log($"WARN: native roaming {command.Action} candidate {command.CandidateId} "
                + $"{disposition}: {reason}");
        }
        NativeTransportCore.PathCommandResult(handle, request, command, outcome, reason);
        if (outcome == NativeTransportCore.PathCommandOutcome.Accepted
            && command.Action == "commit_path")
            Log($"Native roaming committed candidate {command.CandidateId} on "
                + command.Path.PlatformPathId);
        if (outcome != NativeTransportCore.PathCommandOutcome.Accepted
            && command.Action == "abort_path")
            throw new IOException("native roaming rollback failed: " + reason);
    }

    /// <summary>Platform hook: raise the firewall kill-switch (block all egress
    /// except the tunnel, the server, DNS and DHCP). Called once before the connect
    /// loop when <see cref="VpnConfig.KillSwitch"/> is set in full-tunnel mode.
    /// Default no-op (platforms without an implementation simply don't gate).</summary>
    protected virtual void KillSwitchEngage(VpnConfig config) { }

    /// <summary>True only when a failed engage still owns a possibly active platform
    /// firewall because its internal rollback also failed. Implementations must never
    /// return true for a conflict with another process: this process must not tear down
    /// somebody else's guard.</summary>
    protected virtual bool KillSwitchEngageFailureRetainsOwnership(Exception error) => false;

    /// <summary>Platform hook invoked before a refreshed DDNS address set replaces the
    /// last-known carrier set. An engaged firewall kill-switch must allow the new server
    /// addresses before the native transport tries them; throwing keeps the previous set.</summary>
    protected virtual void CarrierAddressesChanging(
        VpnConfig config, IReadOnlyList<string> previous, IReadOnlyList<string> refreshed)
    { }

    /// <summary>Platform hook: lift the kill-switch on a clean stop.</summary>
    protected virtual void KillSwitchDisengage() { }

    /// <summary>Whether this platform can use its firewall implementation as a temporary
    /// fail-closed transaction around a system-TUN NetworkPlan replacement.</summary>
    protected virtual bool SupportsPlanReplacementGuard => false;

    /// <summary>True while either the user-requested kill switch or the temporary
    /// persisted-plan replacement transaction owns the platform firewall.</summary>
    protected bool EgressGuardEngaged =>
        Volatile.Read(ref _ksEngaged) == 1
        || Volatile.Read(ref _planReplacementGuardEngaged) == 1;

    /// <summary>Give a retained per-app adapter the first chance to prepare/confirm an in-place
    /// changed-plan update. Its classifier is already down at this point, so selected traffic
    /// remains fail-closed while the platform SetupTun path publishes the authenticated policy.
    /// Returning false delegates to the guarded system-TUN rebuild below.</summary>
    protected virtual bool TryReconfigurePersistedTun(
        VpnConfig config, Session session, IPAddress serverIp) => false;

    /// <summary>Drop platform state that can pin the encrypted carrier to the old physical
    /// network while retaining a fail-closed per-app adapter. Called only after the per-app
    /// classifier has been lowered and before the next transport attempt.</summary>
    protected virtual void PrepareRetainedTunForNetworkRebuild(VpnConfig config) { }

    private void PlanReplacementGuardEngage(VpnConfig config)
    {
        // The configured kill-switch already covers the complete reconnect window.
        if (Volatile.Read(ref _ksEngaged) == 1
            || Volatile.Read(ref _planReplacementGuardEngaged) == 1) return;
        if (!SupportsPlanReplacementGuard)
            throw new InvalidOperationException(
                "this platform cannot replace a live network plan without an egress leak guard");

        try
        {
            KillSwitchEngage(config);
            Interlocked.Exchange(ref _planReplacementGuardEngaged, 1);
            Log("persist-tun: temporary fail-closed firewall guard engaged for network-plan replacement");
        }
        catch (Exception error)
        {
            if (KillSwitchEngageFailureRetainsOwnership(error))
            {
                // A partial engage is cleanup ownership, not proof of a sound guard. Stop
                // retries so the next attempt cannot destroy the old TUN under this state.
                Interlocked.Exchange(ref _planReplacementGuardEngaged, 1);
                _stoppedForSecurityReason = true;
                _cts?.Cancel();
                bool restored = PlanReplacementGuardLift();
                Status(VpnStatus.Error, restored
                    ? "network-plan firewall guard failed; egress was restored"
                    : "network-plan firewall guard failed; egress remains fail-closed");
            }
            throw new InvalidOperationException(
                "refusing to rebuild the persisted TUN without a fail-closed firewall guard", error);
        }
    }

    private bool PlanReplacementGuardLift()
    {
        if (Interlocked.CompareExchange(ref _planReplacementGuardEngaged, 0, 1) != 1) return true;
        try
        {
            KillSwitchDisengage();
            Log("persist-tun: replacement complete; temporary firewall guard disengaged");
            return true;
        }
        catch (Exception error)
        {
            // Preserve both the platform recovery journal and our knowledge that the host is
            // still gated, so Stop()/give-up can retry instead of silently claiming egress.
            Interlocked.Exchange(ref _planReplacementGuardEngaged, 1);
            Log($"[SECURITY] network-plan replacement guard remains engaged: {error.Message}");
            return false;
        }
    }

    private static bool NeedsSystemPlanReplacementGuard(
        bool hasPersistedTun, bool usesAppFilter) => hasPersistedTun && !usesAppFilter;

    /// <summary>Lift the kill-switch exactly once, from whichever ORDERLY teardown path
    /// reaches it first — Stop(), or the reconnect loop giving up.
    ///
    /// It used to be lifted only in Stop(). An exit through `reconnect_enabled = false` or
    /// `max_retries` therefore left the host firewalled (Windows `DefaultOutboundAction
    /// Block`, macOS pf `block drop out all`) with the UI showing Error and offering only
    /// "Connect" — the user had no in-app way to get their network back. A CRASH must still
    /// leave it engaged (fail-safe, swept on the next run); only a deliberate give-up lifts
    /// it. Interlocked rather than the lifecycle lock: the give-up tail runs ON the tunnel
    /// task, which Stop() joins while holding that lock. (Audit 2026-07-27, B2)</summary>
    private bool KillSwitchLift()
    {
        if (Interlocked.CompareExchange(ref _ksEngaged, 0, 1) != 1) return true;
        try
        {
            KillSwitchDisengage();
            return true;
        }
        catch (Exception e)
        {
            // The platform restore is transactional: on failure the firewall remains
            // fail-closed and its recovery journal is preserved. Re-arm this flag so an
            // orderly retry in the same process can attempt restoration again instead of
            // permanently forgetting that the host is still gated.
            Interlocked.Exchange(ref _ksEngaged, 1);
            Log($"[SECURITY] kill-switch disengage failed; egress remains blocked: {e.Message}");
            return false;
        }
    }

    // keepTun: persist-tun reconnect — leave the TUN adapter + its routes UP so the next
    // attempt can reuse them (no adapter flicker, no route gap, fail-closed during the
    // reconnect window). Only ever true on a reconnect, NEVER on a user Stop.
    private void CloseTransports(bool keepTun = false)
    {
        long native = Interlocked.Read(ref _nativeHandle);
        if (native != 0)
        {
            try { NativeTransportCore.Stop(unchecked((ulong)native)); } catch { }
        }
        if (keepTun) return;  // persist-tun: keep _tun + routes alive for the next attempt
        try { BeforeTunDispose(); } catch (Exception e) { Log($"platform pre-dispose error: {e.Message}"); }
        try { _tun?.Dispose(); } catch { }
        CleanupPlatform();
        _tun = null;
        _persistedClientIp = null;
        _persistedTunnelAddresses = null;
        _persistedNetSig = null;
    }

    /// <summary>persist-tun: reuse a surviving TUN only when the complete effective network
    /// state is unchanged. The same address alone is insufficient: an authenticated reconnect
    /// may change the prefix, pushed routes, DNS or MTU while the physical carrier stays put.</summary>
    protected bool ReusePersistedTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        if (_tun == null) return false;                       // nothing persisted
        string currentNetSig = PhysicalNetSignature();
        string currentPlanFingerprint = NetworkPlanFingerprint(config, session, serverIp);
        if (KeepTunDuringReconnect(config)
            && _persistedClientIp == session.ClientIp
            && _persistedPlanFingerprint == currentPlanFingerprint
            && _persistedNetSig == currentNetSig)
        {
            Log("persist-tun: reusing TUN adapter + network plan (fingerprint unchanged)");
            return true;
        }
        // Per-app capture is itself the leak guard. Reconfigure it in place instead of
        // stopping the classifier and opening a fail-open window while a replacement capture
        // handle is created. The caller publishes the new fingerprint after this succeeds.
        if (TryReconfigurePersistedTun(config, session, serverIp))
        {
            Log("persist-tun: retained per-app adapter accepted the changed network plan in place");
            return true;
        }
        // No persist, or the effective plan/physical network changed: tear the stale adapter
        // down and rebuild its address, routes, DNS and MTU against the current carrier. The
        // temporary firewall transaction is raised BEFORE the first destructive step and is
        // released only after the new native generation reaches Running.
        if (_persistedClientIp != null && _persistedClientIp != session.ClientIp)
            Log($"persist-tun: client IP {_persistedClientIp} -> {session.ClientIp}; rebuilding TUN");
        else if (_persistedPlanFingerprint != null
                 && _persistedPlanFingerprint != currentPlanFingerprint)
            Log("persist-tun: effective network plan changed; rebuilding TUN address, routes, DNS and MTU");
        else if (_persistedNetSig != null && _persistedNetSig != currentNetSig)
            Log("persist-tun: physical gateway/DNS changed; rebuilding TUN routes and resolver state");
        if (NeedsSystemPlanReplacementGuard(_persistedClientIp != null, config.UsesAppFilter))
        {
            PlanReplacementGuardEngage(config);
        }
        else if (_persistedClientIp != null && config.UsesAppFilter)
        {
            throw new InvalidOperationException(
                "the retained per-app adapter cannot apply the authenticated network plan in place");
        }
        try { BeforeTunDispose(); } catch (Exception e) { Log($"platform pre-dispose error: {e.Message}"); }
        try { _tun?.Dispose(); } catch { }
        CleanupPlatform();
        _tun = null;
        _persistedClientIp = null;
        _persistedTunnelAddresses = null;
        _persistedNetSig = null;
        return false;
    }

    // ── reconnect loop ─────────────────────────────────────────────────────────
    /// <summary>Advance the backoff counter for a failed attempt — but not while the network is
    /// still settling after a resume-from-sleep / network change, or while there is no physical
    /// address at all.
    ///
    /// The exponential backoff exists to stop us hammering a server that is down. A failure into
    /// a network that cannot yet carry a handshake is not that, and counting it was the
    /// resume-from-sleep stall: with the default base of 1 s the delay doubles per attempt, so
    /// the handful of attempts burned while Wi-Fi reassociated and DHCP completed left the client
    /// parked in a 16–32 s sleep long AFTER the network became usable — the reported "about a
    /// minute" to come back, against no delay at all from clients that just keep retrying. With a
    /// finite `max_retries` those same attempts could also exhaust it, and giving up tears the
    /// TUN and routes down (see the end of the loop) — dropping the user's traffic onto the bare
    /// network, which is the leak reported alongside the delay. (Field report 2026-07-25, item 1.)
    ///
    /// Clamped rather than reset to zero: a machine that resumes with no network at all must not
    /// spin in a delay-free retry loop, and the cap keeps settling failures from ever reaching a
    /// `max_retries` above it.</summary>
    private int NextAttempt(int attempt)
    {
        bool settling = Environment.TickCount64 < Interlocked.Read(ref _settlingUntilTick)
                        || PhysicalNetSignature().Length == 0;
        return settling ? Math.Min(attempt + 1, SettlingAttemptCap) : attempt + 1;
    }

    /// <summary>Bounded 80–100% reconnect jitter. It never exceeds the configured schedule,
    /// while preventing a fleet that lost one endpoint simultaneously from retrying on the same
    /// deterministic exponential boundaries.</summary>
    internal static long JitterReconnectDelay(long scheduledMs)
    {
        if (scheduledMs <= 1) return Math.Max(0, scheduledMs);
        long minimum = scheduledMs - scheduledMs / 5;
        return Random.Shared.NextInt64(minimum, scheduledMs + 1);
    }

    /// <summary>Put the platform data plane into a safe retry state after either a native
    /// error or a clean native return that was not a user disconnect. Both outcomes occur
    /// when ForceReconnect stops a generation, so handling only the exception path loses
    /// the requested network rebuild and can leave a per-app classifier marked tunnel-up.</summary>
    private void PreparePlatformForRetry(VpnConfig config)
    {
        OnTransportInterrupted(config);
        bool physicalNetworkUnchanged = _persistedNetSig == PhysicalNetSignature();
        bool networkRebuildRequested =
            Interlocked.Exchange(ref _forcedNetworkRebuild, 0) == 1;
        bool networkPlanMustBeRebuilt =
            networkRebuildRequested || !physicalNetworkUnchanged;
        bool persistRequested = KeepTunDuringReconnect(config);
        if (networkPlanMustBeRebuilt && _persistedNetSig != null)
            Log("persist-tun: carrier topology changed during transport failure; rebuilding network state");
        bool retainedPerAppCanReconfigure =
            persistRequested && config.UsesAppFilter && _persistedClientIp != null;
        if (networkPlanMustBeRebuilt && retainedPerAppCanReconfigure)
        {
            // Force ReusePersistedTun through the in-place reconfiguration path even when a
            // noisy OS callback produced the same compact signature. Release an old carrier
            // pin before dialing on the new network, while the classifier is fail-closed.
            _persistedNetSig = null;
            PrepareRetainedTunForNetworkRebuild(config);
        }
        if (networkPlanMustBeRebuilt && _persistedClientIp != null
            && persistRequested && !retainedPerAppCanReconfigure)
            PlanReplacementGuardEngage(config);
        CloseTransports(persistRequested && !_userRequestedDisconnect
                        && _persistedClientIp != null
                        && (!networkPlanMustBeRebuilt || retainedPerAppCanReconfigure));
    }

    private void ConnectWithRetry(VpnConfig config, CancellationToken ct)
    {
        int attempt = 0;          // consecutive UNSTABLE attempts → backoff + max-retries
        bool firstAttempt = true; // very first connect: no reconnect gating / delay / status change
        long baseMs = config.ReconnectBaseDelaySecs * 1000;
        long maxMs = config.ReconnectMaxDelaySecs * 1000;
        string? reconnectStateFailure = null;
        while (!ct.IsCancellationRequested)
        {
            DateTime startedAt = DateTime.UtcNow; // reset precisely before RunVpnConnection below
            try
            {
                if (!firstAttempt)
                {
                    // The reconnect policy applies to EVERY reconnect — INCLUDING one after an
                    // established session dropped. Previously the gate/status/delay lived under
                    // `attempt > 0`, and `attempt` was reset to 0 after an established drop, so on
                    // the common flapping path ReconnectEnabled=false and max-retries were silently
                    // ignored and the UI stayed Connected while the TUN was torn down. (C-02/C-03)
                    if (!config.ReconnectEnabled) { Log("Reconnect disabled, giving up"); break; }
                    if (config.ReconnectMaxRetries >= 0 && attempt > config.ReconnectMaxRetries)
                    { Log("Max retries reached, giving up"); break; }
                    // Announce we left Connected BEFORE re-entering — no green-UI leak window
                    // while the TUN/routes are down.
                    Status(VpnStatus.Connecting);
                    if (attempt > 0)
                    {
                        long pow = (long)Math.Pow(2, Math.Min(attempt - 1, 7));
                        long scheduledMs = Math.Max(Math.Min(baseMs * Math.Min(pow, 100), maxMs), 1000);
                        long delayMs = JitterReconnectDelay(scheduledMs);
                        Log($"Reconnect attempt {attempt} in {delayMs / 1000.0:F1}s");
                        if (ct.WaitHandle.WaitOne((int)delayMs)) break; // cancelled
                    }
                    else
                    {
                        Log("Reconnecting…"); // a stable session dropped — reconnect promptly
                    }
                }
                firstAttempt = false;
                startedAt = DateTime.UtcNow;
                RunVpnConnection(config, ct);
                Log("Connection closed cleanly");
                if (_userRequestedDisconnect) break;
                bool cleanForced = _forcedReconnectInFlight;
                _forcedReconnectInFlight = false;
                bool cleanWasEstablished = _wasConnected;
                _wasConnected = false;
                if (!cleanForced && cleanWasEstablished)
                    ConnectionDropped?.Invoke("Connection closed");
                try
                {
                    PreparePlatformForRetry(config);
                }
                catch (Exception recoveryError)
                {
                    reconnectStateFailure =
                        $"could not prepare a safe reconnect: {FirstSentence(recoveryError.Message)}";
                    Log($"[SECURITY] {reconnectStateFailure}");
                    break;
                }
                // Reset the backoff only after a STABLE session (ran a while). A connect-then-
                // instant-drop keeps escalating, so it can't hot-loop AND still counts toward
                // ReconnectMaxRetries. A cycle WE asked for (resume from sleep, network change)
                // is not a failure: counting it as one made a laptop that sleeps often climb the
                // backoff until the tunnel spent longer serving a penalty than carrying traffic.
                attempt = cleanForced
                    ? 0
                    : (DateTime.UtcNow - startedAt >= TimeSpan.FromSeconds(30)) ? 0 : NextAttempt(attempt);
            }
            catch (ServerKickException e) when (!ct.IsCancellationRequested)
            {
                Log($"Server stopped reconnect: {e.Message}");
                Status(VpnStatus.Error, e.Message);
                _stoppedForSecurityReason = true;
                break;
            }
            catch (System.Security.SecurityException e) when (!ct.IsCancellationRequested)
            {
                // Server identity changed / key mismatch — a possible MITM. Do NOT
                // retry (a hijacked endpoint won't fix itself and retrying is noisy);
                // surface a clear security warning and stop. (A5 — TOFU warning.)
                Log($"[SECURITY] {e.Message}");
                Status(VpnStatus.Error, Loc.T("MitmStop"));
                // Remember WHY we stopped. The give-up tail below announces a generic
                // "could not connect" for every exit, which overwrote this security
                // warning within milliseconds — so the one message the user most needs to
                // see, on a possible MITM, never reached the UI at all.
                // (Audit 2026-07-27, Z2.)
                _stoppedForSecurityReason = true;
                break;
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                bool wasForced = _forcedReconnectInFlight;
                if (wasForced)
                {
                    // We closed the socket ourselves for a network change (ForceReconnect);
                    // the resulting socket error is expected — "…— reconnecting" was already
                    // logged, so don't surface it as an ERR.
                    _forcedReconnectInFlight = false;
                }
                else
                {
                    Log($"ERR: [{e.GetType().Name}] {e.Message}");
                    var cause = e.InnerException;
                    while (cause != null) { Log($"  <- {cause.Message}"); cause = cause.InnerException; }
                }
                // An established tunnel just dropped (server down / network lost) — notify once;
                // the loop then re-enters via the reconnect (Connecting) state above.
                bool wasEstablished = _wasConnected;
                if (_wasConnected)
                {
                    _wasConnected = false;
                    ConnectionDropped?.Invoke(e.Message);
                }
                // Reset backoff only after a STABLE established session; otherwise escalate so a
                // flapping / never-stable server hits the delay + max-retries — EXCEPT while the
                // network is still settling, where escalating is simply wrong.
                attempt = (wasForced && wasEstablished)
                    ? 0
                    : (wasEstablished && DateTime.UtcNow - startedAt >= TimeSpan.FromSeconds(30))
                        ? 0 : NextAttempt(attempt);
                // persist-tun: on a reconnect (not a user Stop) keep the TUN + routes up
                // so the next attempt reuses them (no flicker / route gap; fail-closed).
                // Only when one is actually UP, though (`_persistedClientIp` is set next to
                // `_wasConnected` once SetupTun succeeded): deciding this from the config flag
                // alone also "persisted" failures that happened BEFORE or DURING SetupTun,
                // which skipped CleanupPlatform() — the only disposer of a half-built adapter
                // and of a prewarmed Wintun adapter the failed attempt never consumed.
                try
                {
                    PreparePlatformForRetry(config);
                }
                catch (Exception recoveryError)
                {
                    // Guard engagement and stale carrier cleanup are themselves fallible. Keep
                    // the error inside the retry lifecycle so terminal cleanup and UI state are
                    // still completed instead of faulting the run task without an Error edge.
                    reconnectStateFailure =
                        $"could not prepare a safe reconnect: {FirstSentence(recoveryError.Message)}";
                    Log($"[SECURITY] {reconnectStateFailure}");
                    break;
                }
            }
            catch (Exception)
            {
                break; // cancelled
            }
        }
        // Gave up retrying: the "reconnect disabled" / "max retries" breaks above leave the
        // loop WITHOUT passing through any teardown, while persist-tun may have deliberately
        // kept the TUN + routes + DNS override up for a next attempt that will now never come
        // — leaving the host routed into a dead tunnel with a hijacked resolver, showing only
        // a generic "could not connect". On a user Stop, Stop() does the teardown itself (and
        // joins this task), so don't race it here.
        Exception? terminalCleanupFailure = null;
        if (!_userRequestedDisconnect)
        {
            try { CloseTransports(); }
            catch (Exception cleanupError)
            {
                terminalCleanupFailure = cleanupError;
                Log($"[SECURITY] terminal platform cleanup failed: {cleanupError.Message}");
            }
        }
        if (_userRequestedDisconnect) Status(VpnStatus.Disconnected);
        else
        {
            // Do not restore a firewall guard over partially cleaned routes/DNS. Stop() can
            // retry both operations; claiming ordinary egress here could hide stale resolver
            // ownership or an adapter that still owns host routes.
            if (terminalCleanupFailure != null)
            {
                Status(VpnStatus.Error,
                    EgressGuardEngaged
                        ? "platform cleanup failed; egress remains fail-closed"
                        : $"platform cleanup failed: {FirstSentence(terminalCleanupFailure.Message)}");
                return;
            }
            // …and the same is true of the kill-switch, which only Stop() used to lift: after
            // an orderly give-up the UI shows Error and offers "Connect", so a still-engaged
            // firewall left the host with no egress AND no in-app way to restore it. Lift it
            // BEFORE announcing Error, so egress is already back when the user sees the state.
            // (Audit 2026-07-27, B2)
            bool egressRestored = PlanReplacementGuardLift();
            egressRestored = KillSwitchLift() && egressRestored;
            // Keep a security stop visible: only announce the generic failure when the
            // loop ended for an ordinary reason. (Audit 2026-07-27, Z2.)
            if (!egressRestored)
            {
                Status(VpnStatus.Error,
                    "kill-switch restore failed; egress remains fail-closed");
            }
            else if (reconnectStateFailure != null)
            {
                Status(VpnStatus.Error, reconnectStateFailure);
            }
            else if (!_stoppedForSecurityReason)
            {
                Status(VpnStatus.Error, Loc.T("CouldNotConnect")); // gave up retrying
            }
        }
    }

    private void RunVpnConnection(VpnConfig config, CancellationToken ct)
    {
        // Let the platform choose its ABI data-plane ownership for this profile before
        // NativeTransportCore.RequireCompatible() observes the ownership properties.
        PrepareTransport(config);
        // Windows: kick off the (slow, ~10 s) Wintun adapter creation NOW, in parallel with
        // the handshake, so SetupTun consumes a ready adapter after Auth OK instead of
        // blocking on it — this is what made a cold connect take 11-17 s. Only on a FRESH
        // connect (no adapter up yet); a persist-tun reconnect reuses the existing one.
        if (!_handshakeOnly && _tun == null) PrewarmTun(config);
        RunNativeConnection(config, ct);
    }

    private sealed class ServerKickException : Exception
    {
        internal ServerKickException(string message) : base(message) { }
    }

    internal sealed class NativePlan
    {
        [JsonPropertyName("generation")] public ulong Generation { get; set; }
        [JsonPropertyName("family_mode")] public string FamilyMode { get; set; } = "";
        [JsonPropertyName("addresses")] public List<NativeAddress> Addresses { get; set; } = new();
        [JsonPropertyName("tunnel_address")] public string TunnelAddress { get; set; } = "";
        [JsonPropertyName("prefix_len")] public int PrefixLength { get; set; }
        [JsonPropertyName("mtu")] public int Mtu { get; set; }
        [JsonPropertyName("tunnel_gateway")] public string TunnelGateway { get; set; } = "";
        [JsonPropertyName("carrier_address")] public string? CarrierAddress { get; set; }
        [JsonPropertyName("routes")] public List<NativeRoute> Routes { get; set; } = new();
        [JsonPropertyName("pushed_routes")] public List<string> PushedRoutes { get; set; } = new();
        [JsonPropertyName("dns_servers")] public List<NativeDns> DnsServers { get; set; } = new();
        [JsonPropertyName("full_tunnel")] public bool FullTunnel { get; set; }
        [JsonPropertyName("kill_switch")] public bool KillSwitch { get; set; }
        [JsonPropertyName("allow_ipv4_leak")] public bool AllowIpv4Leak { get; set; }
        [JsonPropertyName("allow_ipv6_leak")] public bool AllowIpv6Leak { get; set; }
        [JsonPropertyName("data_plane")] public NativeDataPlane DataPlane { get; set; } = new();
        [JsonPropertyName("connection_log")] public List<string> ConnectionLog { get; set; } = new();
    }

    internal sealed class NativeAddress
    {
        [JsonPropertyName("family")] public string Family { get; set; } = "";
        [JsonPropertyName("address")] public string Address { get; set; } = "";
        [JsonPropertyName("prefix_len")] public int PrefixLength { get; set; }
        [JsonPropertyName("on_link_prefix_len")] public int OnLinkPrefixLength { get; set; }
        [JsonPropertyName("gateway")] public string? Gateway { get; set; }
    }

    internal sealed class NativeRoute
    {
        [JsonPropertyName("cidr")] public string Cidr { get; set; } = "";
        [JsonPropertyName("gateway")] public string Gateway { get; set; } = "";
        [JsonPropertyName("metric")] public uint Metric { get; set; }
    }

    internal sealed class NativeDns
    {
        [JsonPropertyName("address")] public string Address { get; set; } = "";
        [JsonPropertyName("port")] public int Port { get; set; } = 53;
    }

    internal sealed class NativeDataPlane
    {
        [JsonPropertyName("padding_enabled")] public bool PaddingEnabled { get; set; }
        [JsonPropertyName("padding_min")] public int PaddingMin { get; set; }
        [JsonPropertyName("padding_max")] public int PaddingMax { get; set; }
        [JsonPropertyName("heartbeat_enabled")] public bool HeartbeatEnabled { get; set; }
        [JsonPropertyName("heartbeat_interval_ms")] public long HeartbeatIntervalMs { get; set; }
        [JsonPropertyName("shaping_enabled")] public bool ShapingEnabled { get; set; }
    }

    internal sealed class NativeIdentity
    {
        [JsonPropertyName("server_id")] public string ServerId { get; set; } = "";
        [JsonPropertyName("public_key")] public string PublicKey { get; set; } = "";
    }

    private static bool IsUsableTunnelIpv6(IPAddress address) =>
        address.AddressFamily != AddressFamily.InterNetworkV6
        || (!address.Equals(IPAddress.IPv6Any)
            && !address.Equals(IPAddress.IPv6Loopback)
            && !address.IsIPv6Multicast
            && !address.IsIPv6LinkLocal
            && !address.IsIPv4MappedToIPv6);

    internal static void ValidateNativePlan(NativePlan plan)
    {
        if (plan.FamilyMode is not ("ipv4" or "dual" or "ipv6"))
            throw new InvalidDataException("native NetworkPlan has an invalid family_mode");
        if (plan.Addresses.Count is < 1 or > 2)
            throw new InvalidDataException("native NetworkPlan must contain one address per active family");
        var families = new HashSet<string>(StringComparer.Ordinal);
        foreach (var assigned in plan.Addresses)
        {
            if (assigned.Family is not ("ipv4" or "ipv6") || !families.Add(assigned.Family)
                || !IPAddress.TryParse(assigned.Address, out var address))
                throw new InvalidDataException("native NetworkPlan contains invalid address metadata");
            bool ipv4 = address.AddressFamily == AddressFamily.InterNetwork;
            if ((assigned.Family == "ipv4") != ipv4)
                throw new InvalidDataException("native NetworkPlan address does not match its family");
            if (!IsUsableTunnelIpv6(address))
                throw new InvalidDataException("native NetworkPlan contains an unusable IPv6 tunnel address");
            int maxPrefix = ipv4 ? 32 : 128;
            if (assigned.PrefixLength is < 1 || assigned.PrefixLength > maxPrefix
                || assigned.OnLinkPrefixLength is < 1 || assigned.OnLinkPrefixLength > maxPrefix
                || assigned.OnLinkPrefixLength > assigned.PrefixLength)
                throw new InvalidDataException("native NetworkPlan contains an invalid address prefix");
            if (assigned.Gateway != null
                && (!IPAddress.TryParse(assigned.Gateway, out var gateway)
                    || gateway.AddressFamily != address.AddressFamily
                    || !IsUsableTunnelIpv6(gateway)))
                throw new InvalidDataException("native NetworkPlan address and gateway families differ");
        }
        bool expected = plan.FamilyMode switch
        {
            "ipv4" => families.SetEquals(new[] { "ipv4" }),
            "ipv6" => families.SetEquals(new[] { "ipv6" }),
            _ => families.SetEquals(new[] { "ipv4", "ipv6" }),
        };
        if (!expected)
            throw new InvalidDataException("native NetworkPlan addresses do not match family_mode");
        if (!IPAddress.TryParse(plan.TunnelGateway, out var tunnelGateway)
            || !IsUsableTunnelIpv6(tunnelGateway))
            throw new InvalidDataException("native NetworkPlan contains an invalid tunnel gateway");
        var projection = plan.Addresses.SingleOrDefault(item => item.Address == plan.TunnelAddress);
        if (projection == null || projection.OnLinkPrefixLength != plan.PrefixLength
            || projection.Gateway != plan.TunnelGateway)
            throw new InvalidDataException("native NetworkPlan legacy projection differs from typed addresses");
        if (plan.Mtu is < VpnConfig.MtuMin or > VpnConfig.MtuMax)
            throw new InvalidDataException(
                $"native NetworkPlan MTU is outside {VpnConfig.MtuMin}..{VpnConfig.MtuMax}");
        if (plan.FamilyMode != "ipv4" && plan.Mtu < 1280)
            throw new InvalidDataException("native IPv6 NetworkPlan MTU is below 1280");
        if (plan.CarrierAddress != null && !IPAddress.TryParse(plan.CarrierAddress, out _))
            throw new InvalidDataException("native NetworkPlan contains an invalid carrier address");
        foreach (var dns in plan.DnsServers)
            if (!IPAddress.TryParse(dns.Address, out var address) || dns.Port is < 1 or > 65535
                || (address.AddressFamily == AddressFamily.InterNetwork
                    ? !families.Contains("ipv4") : !families.Contains("ipv6")))
                throw new InvalidDataException($"native NetworkPlan contains invalid DNS {dns.Address}:{dns.Port}");
        foreach (var route in plan.Routes)
        {
            var slash = route.Cidr.LastIndexOf('/');
            if (slash <= 0 || !IPAddress.TryParse(route.Cidr[..slash], out var destination)
                || !int.TryParse(route.Cidr[(slash + 1)..], out int prefix)
                || prefix < 0 || prefix > (destination.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)
                || !IPAddress.TryParse(route.Gateway, out var gateway)
                || gateway.AddressFamily != destination.AddressFamily
                || !IsUsableTunnelIpv6(gateway)
                || (destination.AddressFamily == AddressFamily.InterNetwork
                    ? !families.Contains("ipv4") : !families.Contains("ipv6")))
                throw new InvalidDataException($"native NetworkPlan contains invalid route {route.Cidr}");
        }
    }

    internal static string FingerprintNativePlan(NativePlan plan,
        IEnumerable<string>? carrierCandidates = null)
    {
        // The physical bypass is part of the applied host-network state.  A DNS refresh
        // may leave the authenticated NetworkPlan unchanged while adding/removing an
        // A/AAAA carrier address.  Include the complete, order-independent set so
        // persist_tun cannot retain stale host routes merely because the selected peer
        // happened to stay the same.
        string[] carriers = (carrierCandidates ?? Array.Empty<string>())
            .Select(value => IPAddress.Parse(value).ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var canonical = JsonSerializer.Serialize(new
        {
            family = plan.FamilyMode,
            addresses = plan.Addresses.OrderBy(item => item.Family).Select(item => new
            {
                item.Family, item.Address, item.PrefixLength, item.OnLinkPrefixLength, item.Gateway,
            }),
            plan.TunnelGateway, plan.CarrierAddress, plan.Mtu,
            // Desktop installs these as interface-scoped routes. Gateway and metric are
            // validated/logged diagnostics, but do not change the applied host state.
            routes = plan.Routes.Select(item => item.Cidr)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(cidr => cidr, StringComparer.OrdinalIgnoreCase),
            dns = plan.DnsServers.Select(item => new { item.Address, item.Port }),
            carrier_candidates = carriers,
            plan.FullTunnel, plan.KillSwitch, plan.AllowIpv4Leak, plan.AllowIpv6Leak,
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>
    /// Active Windows/macOS path since ABI 1.7. Rust owns resolution, carrier sockets,
    /// handshake, crypto, TCP/UDP/QUIC/Reality, bonding and liveness. Managed code drains
    /// lifecycle events and applies the authenticated NetworkPlan. Windows shuttles bounded
    /// Wintun batches; macOS transfers a generation-scoped duplicate of the utun descriptor,
    /// after which Rust owns packet IO as well.
    /// </summary>
    private void RunNativeConnection(VpnConfig config, CancellationToken ct)
    {
        string[] carrierAddresses = ResolveCarrierCandidates(config);
        NativeTransportCore.RequireCompatible(NativeTunFdOwnership, NativeWintunOwnership);
        ulong roamingCapabilities = NativeRoamingCapabilities(config);
        if (roamingCapabilities != 0 && !NativeTransportCore.SupportsPathTransactions())
        {
            Log("Native core has no experimental path transaction support; using reconnect fallback");
            roamingCapabilities = 0;
        }
        else if ((roamingCapabilities & NativePathRefreshCapability) != 0
                 && !NativeTransportCore.SupportsPathRefresh())
        {
            roamingCapabilities &= ~NativePathRefreshCapability;
            Log("Native core has no PATH_REFRESH support; same-network NAT failure uses reconnect fallback");
        }
        ulong handle = NativeTransportCore.New(config.ToTransportCoreIni(), NativeTunFdOwnership,
            NativeWintunOwnership, NativeIpv6Capabilities(config), roamingCapabilities);
        Interlocked.Exchange(ref _nativeHandle, unchecked((long)handle));
        lock (_nativeRoamingGate)
        {
            _nativeRoamingConfig = roamingCapabilities == 0 ? null : config;
            _nativeRoamingCapabilities = roamingCapabilities;
            Interlocked.Exchange(ref _nativePlanGeneration, 0);
            Interlocked.Exchange(ref _nativePathUpdateId, 0);
        }

        Task<int>? runner = null;
        CancellationTokenSource? packetCts = null;
        Task? uplink = null;
        Task? downlink = null;
        string? nativeError = null;
        bool handshakeComplete = false;
        long nextStats = 0;
        try
        {
            NativeTransportCore.SetDeviceId(handle, DeviceId());
            NativeTransportCore.Start(handle);
            string runtimeInput = JsonSerializer.Serialize(new
            {
                // An empty list is intentional: use explicit dns_servers or the authenticated
                // server push. Never select a public third-party resolver behind the user's back.
                fallback_dns_servers = Array.Empty<string>(),
                carrier_addresses = carrierAddresses
            });
            runner = Task.Run(() => NativeTransportCore.Run(handle, runtimeInput));
            byte[] eventPayload = new byte[NativeTransportCore.MaxEventPayload];

            while (!ct.IsCancellationRequested)
            {
                bool drained = false;
                NativeTransportCore.NativeEvent? nativeEvent;
                while ((nativeEvent = NativeTransportCore.PollEvent(handle, eventPayload)) != null)
                {
                    drained = true;
                    switch (nativeEvent.Kind)
                    {
                        case NativeTransportCore.EventServerIdentity:
                            AcceptNativeIdentity(handle, nativeEvent.Sequence, nativeEvent.Payload, config);
                            break;

                        case NativeTransportCore.EventNetworkPlan:
                        {
                            var plan = JsonSerializer.Deserialize<NativePlan>(nativeEvent.Payload)
                                ?? throw new InvalidDataException("native NetworkPlan is empty");
                            if (plan.Generation == 0 || plan.Generation != nativeEvent.PlanGeneration)
                                throw new InvalidDataException("native NetworkPlan generation mismatch");
                            ValidateNativePlan(plan);
                            if (plan.FullTunnel != config.IsFullTunnel)
                                throw new InvalidDataException(
                                    "native NetworkPlan routing mode differs from the selected profile");
                            Log($"Auth OK: user='{LogValue(config.Username)}', IP {plan.TunnelAddress}");
                            foreach (string line in plan.ConnectionLog) Log(line);
                            if (_handshakeOnly)
                            {
                                _handshakeIp = plan.TunnelAddress;
                                handshakeComplete = true;
                                NativeTransportCore.Stop(handle);
                                break;
                            }

                            try
                            {
                                IPAddress carrier = ResolveNativeCarrier(plan, config);
                                var unsupportedDns = plan.DnsServers.FirstOrDefault(item => item.Port != 53);
                                if (unsupportedDns != null)
                                    throw new InvalidDataException(
                                        $"platform DNS adapter cannot apply {unsupportedDns.Address}:{unsupportedDns.Port}");
                                var dns = plan.DnsServers.Select(item => item.Address).ToList();
                                var addresses = plan.Addresses.Select(item => new AssignedAddress(
                                    item.Family, item.Address, item.PrefixLength,
                                    item.OnLinkPrefixLength, item.Gateway)).ToList();
                                var routes = plan.Routes.Select(item => new PlannedRoute(
                                    item.Cidr, item.Gateway, item.Metric)).ToList();
                                IPAddress[] carrierCandidates = carrierAddresses
                                    .Select(IPAddress.Parse)
                                    .Append(carrier)
                                    .Distinct()
                                    .ToArray();
                                // route_file is platform-owned and absent from the Rust plan.
                                // Snapshot it once so fingerprinting and route installation see
                                // the same contents even if the file is edited concurrently.
                                IReadOnlyList<string> routeFileRoutes =
                                    config.UsesAppFilter || !config.IsFullTunnel
                                        ? LoadRouteFile(config)
                                        : Array.Empty<string>();
                                var session = new Session(plan.TunnelAddress, plan.PrefixLength, plan.Mtu,
                                    PlannedDns: dns, PlanIncludesClientRoutes: true,
                                    NetworkAddresses: addresses, PlannedRoutes: routes,
                                    AllowIpv4Leak: plan.AllowIpv4Leak,
                                    AllowIpv6Leak: plan.AllowIpv6Leak,
                                    PlanFingerprint: FingerprintNativePlan(plan,
                                        carrierCandidates.Select(address => address.ToString())),
                                    RouteFileRoutes: routeFileRoutes);
                                SetupTun(config, session, carrier, carrierCandidates);
                                EnforceDnsPolicy(config);
                                _persistedClientIp = plan.TunnelAddress;
                                _persistedTunnelAddresses = string.Join(", ",
                                    addresses.Select(address => $"{address.Address}/{address.PrefixLength}"));
                                _persistedNetSig = PhysicalNetSignature();
                                _persistedPlanFingerprint =
                                    NetworkPlanFingerprint(config, session, carrier);
                                _lastNetSig = _persistedNetSig;
                                Interlocked.Exchange(ref _forcedNetworkRebuild, 0);
                                if (NativeTunFdOwnership)
                                {
                                    if (_tun is not IFdTunDevice fdTun)
                                        throw new InvalidOperationException(
                                            "platform declared native TUN-fd ownership but exposed no descriptor");
                                    NativeTransportCore.SetTunFd(handle, plan.Generation,
                                        fdTun.FileDescriptor);
                                }
                                else if (NativeWintunOwnership)
                                {
                                    if (_tun is not IWintunTunDevice wintun)
                                        throw new InvalidOperationException(
                                            "platform declared native Wintun ownership but exposed no adapter name");
                                    NativeTransportCore.SetWintunAdapter(handle, plan.Generation,
                                        wintun.AdapterName);
                                }
                                Interlocked.Exchange(ref _nativePlanGeneration,
                                    unchecked((long)plan.Generation));
                                NativeTransportCore.NetworkPlanResult(handle, plan.Generation, true);
                                if (!NativeTunFdOwnership && !NativeWintunOwnership)
                                {
                                    packetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                                    (uplink, downlink) = StartNativePacketPumps(handle, plan.Generation,
                                        _tun as IPacketTunDevice ?? throw new InvalidOperationException(
                                            "platform declared packet TUN ownership but exposed no packet adapter"),
                                        packetCts.Token);
                                }
                                Log($"Native NetworkPlan {plan.Generation} APPLIED: " +
                                    $"mode={(plan.FullTunnel ? "full" : "split")} " +
                                    $"family={plan.FamilyMode} addresses={string.Join(", ", addresses.Select(a => $"{a.Address}/{a.PrefixLength}"))} mtu={plan.Mtu} " +
                                    $"dns={(dns.Count == 0 ? "system unchanged" : string.Join(", ", dns))} " +
                                    $"plan_routes={plan.Routes.Count} pushed_routes={plan.PushedRoutes.Count} " +
                                    $"padding={plan.DataPlane.PaddingEnabled}[{plan.DataPlane.PaddingMin}..{plan.DataPlane.PaddingMax}] " +
                                    $"heartbeat={plan.DataPlane.HeartbeatEnabled}/{plan.DataPlane.HeartbeatIntervalMs}ms " +
                                    $"shaping={plan.DataPlane.ShapingEnabled}");
                            }
                            catch (Exception error)
                            {
                                Log($"ERROR: Native NetworkPlan {plan.Generation} REJECTED: {error.Message}");
                                try
                                {
                                    NativeTransportCore.NetworkPlanResult(handle, plan.Generation, false,
                                        error.Message);
                                }
                                catch { }
                                throw;
                            }
                            break;
                        }

                        case NativeTransportCore.EventPathCommand:
                            HandleNativePathCommand(handle, nativeEvent);
                            break;

                        case NativeTransportCore.EventPathRefresh:
                            ulong refreshGeneration =
                                NativeRoamingPath.DecodeRefreshGeneration(nativeEvent);
                            if (!TrySubmitNativePathUpdate("same_network_nat_failure", refreshGeneration))
                                Log("WARN: native roaming PATH_REFRESH could not capture the active path");
                            break;

                        case NativeTransportCore.EventStateChanged
                            when nativeEvent.State == NativeTransportCore.StateRunning && !_wasConnected:
                            if (!PlanReplacementGuardLift())
                                throw new InvalidOperationException(
                                    "new tunnel is ready, but the temporary replacement firewall guard could not be restored");
                            _wasConnected = true;
                            ConnectedSince = DateTime.Now;
                            string tunnelAddresses = _persistedTunnelAddresses ?? _persistedClientIp ?? "";
                            Status(VpnStatus.Connected, DescribeConnected(tunnelAddresses));
                            uint loadedAbi = NativeTransportCore.LoadedAbiVersion();
                            Log($"TUN ready; Rust owns the complete transport data plane " +
                                $"(ABI {loadedAbi >> 16}.{loadedAbi & 0xffff}, compatibility floor " +
                                $"{NativeTransportCore.AbiVersion >> 16}.{NativeTransportCore.AbiVersion & 0xffff})");
                            break;

                        case NativeTransportCore.EventNotice:
                        {
                            var notice = NativeTransportCore.DecodeManagement(nativeEvent,
                                NativeTransportCore.EventNotice);
                            Log($"NOTICE: {notice.Message}");
                            break;
                        }

                        case NativeTransportCore.EventKick:
                        {
                            var kick = NativeTransportCore.DecodeManagement(nativeEvent,
                                NativeTransportCore.EventKick);
                            Log($"KICK: {kick.Message}");
                            NativeTransportCore.Stop(handle);
                            if (!kick.ReconnectAllowed)
                                throw new ServerKickException(kick.Message);
                            nativeError = kick.Message;
                            break;
                        }

                        case NativeTransportCore.EventError:
                            nativeError = string.IsNullOrWhiteSpace(nativeEvent.Payload)
                                ? $"native transport error {nativeEvent.ErrorCode}"
                                : nativeEvent.Payload;
                            Log($"ERROR: native transport {nativeEvent.ErrorCode}: {nativeError}");
                            break;
                    }
                }

                long now = Environment.TickCount64;
                if (now >= nextStats)
                {
                    UpdateNativeStats(handle);
                    nextStats = now + 250;
                }
                if (runner.IsCompleted && !drained) break;
                if (ct.WaitHandle.WaitOne(10)) break;
            }

            if (ct.IsCancellationRequested)
            {
                NativeTransportCore.Stop(handle);
                return;
            }
            if (handshakeComplete) return;
            int rc = runner.GetAwaiter().GetResult();
            if (rc != NativeTransportCore.Ok)
                throw new IOException(nativeError ?? $"native transport stopped ({rc})");
            if (!_userRequestedDisconnect)
                throw new IOException(nativeError ?? "native transport disconnected");
        }
        finally
        {
            lock (_nativeRoamingGate)
            {
                Interlocked.Exchange(ref _nativePlanGeneration, 0);
                _nativeRoamingCapabilities = 0;
                _nativeRoamingConfig = null;
                try { ResetNativeRoamingPath(); }
                catch (Exception error)
                {
                    Log($"WARN: native roaming cleanup deferred to platform teardown ({error.Message})");
                }
            }
            try { packetCts?.Cancel(); } catch { }
            try { NativeTransportCore.Stop(handle); } catch { }
            try { uplink?.Wait(2000); } catch { }
            try { downlink?.Wait(2000); } catch { }
            if (runner != null)
            {
                try { runner.Wait(5000); } catch { }
            }
            try { UpdateNativeStats(handle); } catch { }
            NativeTransportCore.Free(handle);
            Interlocked.CompareExchange(ref _nativeHandle, 0, unchecked((long)handle));
            packetCts?.Dispose();
        }
    }

    private string[] ResolveCarrierCandidates(VpnConfig config)
    {
        try
        {
            IPAddress? localCarrier = string.IsNullOrWhiteSpace(config.LocalAddress)
                ? null
                : IPAddress.Parse(config.LocalAddress);
            // Resolve on every native generation, not only the first one. A hostname whose
            // complete A/AAAA set changes while the tunnel is reconnecting (ordinary DDNS
            // failover) must become reachable without a manual Disconnect/Connect cycle.
            // Bound the lookup: a retained fail-closed TUN may temporarily make its resolver
            // unreachable. In that case the catch below deliberately keeps the last proven
            // addresses instead of terminating the reconnect supervisor.
            string[] refreshed = Dns.GetHostAddressesAsync(config.ServerAddress)
                .WaitAsync(TimeSpan.FromSeconds(5))
                .GetAwaiter().GetResult()
                .Select(address => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
                .Where(address => address.AddressFamily == AddressFamily.InterNetwork
                    || (address.AddressFamily == AddressFamily.InterNetworkV6
                        && !address.IsIPv6LinkLocal))
                // `local` is an explicit egress-family choice. Keeping incompatible records
                // in the platform plan would make route pinning fail before Rust can fall
                // through to a usable address of the requested family.
                .Where(address => CarrierMatchesLocalFamily(address, localCarrier))
                .Select(address => address.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (refreshed.Length == 0)
                throw new InvalidOperationException(
                    $"{config.ServerAddress} did not resolve to a usable IPv4 or IPv6 carrier address");
            if (_carrierAddresses.Length > 0 && !_carrierAddresses.SequenceEqual(refreshed))
            {
                // Update a live kill-switch allowlist BEFORE publishing the new set. If the
                // platform cannot do so it throws, the catch below retains the old addresses,
                // and reconnect remains fail-closed instead of repeatedly selecting an IP the
                // firewall itself blocks.
                CarrierAddressesChanging(config, _carrierAddresses, refreshed);
                Log($"Physical carrier DNS refreshed: {string.Join(", ", _carrierAddresses)} -> "
                    + string.Join(", ", refreshed));
            }
            _carrierAddresses = refreshed;
        }
        catch (Exception error) when (_carrierAddresses.Length > 0)
        {
            // Re-resolution is additive resilience. A temporary DNS failure must not discard
            // working cached addresses and turn a recoverable carrier outage into a terminal
            // client error.
            Log($"WARN: carrier DNS refresh failed ({error.Message}); retaining last known "
                + string.Join(", ", _carrierAddresses));
        }
        string[] rotated = RotateCarrierCandidates(_carrierAddresses, (uint)_carrierGeneration++);
        Log($"Physical carrier candidates: {string.Join(", ", rotated)}");
        return rotated;
    }

    internal static bool CarrierMatchesLocalFamily(IPAddress carrier, IPAddress? localCarrier) =>
        localCarrier == null || carrier.AddressFamily == localCarrier.AddressFamily;

    internal static string[] RotateCarrierCandidates(IReadOnlyList<string> addresses, uint generation)
    {
        if (addresses.Count == 0)
            throw new InvalidOperationException("no IPv4 or IPv6 carrier address is available");
        int offset = (int)(generation % (uint)addresses.Count);
        string[] rotated = new string[addresses.Count];
        for (int index = 0; index < rotated.Length; index++)
            rotated[index] = addresses[(index + offset) % addresses.Count];
        return rotated;
    }

    private void AcceptNativeIdentity(ulong handle, ulong sequence, string payload, VpnConfig config)
    {
        try
        {
            var identity = JsonSerializer.Deserialize<NativeIdentity>(payload)
                ?? throw new SecurityException("native server identity event is empty");
            string received = identity.PublicKey.Trim().ToLowerInvariant();
            if (received.Length != 64 || received.Any(ch => !Uri.IsHexDigit(ch)))
                throw new SecurityException("native server identity is not a 32-byte hex key");

            if (!string.IsNullOrWhiteSpace(config.ServerPublicKeyHex))
            {
                string expected = new(config.ServerPublicKeyHex.Where(Uri.IsHexDigit).ToArray());
                if (!string.Equals(expected, received, StringComparison.OrdinalIgnoreCase))
                    throw new SecurityException("SERVER KEY MISMATCH - possible MITM");
            }
            else if (!CheckKnownHost(identity.ServerId, received))
            {
                // Rust emits this event only after the peer has proved possession of the key.
                RecordKnownHost(identity.ServerId, received, config.AllowUnpinnedTofu);
            }
            NativeTransportCore.ServerIdentityResult(handle, sequence, true);
        }
        catch (Exception error)
        {
            try { NativeTransportCore.ServerIdentityResult(handle, sequence, false, error.Message); }
            catch { }
            if (error is SecurityException security) throw security;
            throw new SecurityException(error.Message, error);
        }
    }

    private IPAddress ResolveNativeCarrier(NativePlan plan, VpnConfig config)
    {
        if (!string.IsNullOrWhiteSpace(plan.CarrierAddress)
            && IPAddress.TryParse(plan.CarrierAddress, out var connected))
            return connected;
        if (_carrierAddresses.FirstOrDefault() is string cached
            && IPAddress.TryParse(cached, out var physical))
            return physical;
        throw new InvalidOperationException(
            $"native NetworkPlan omitted the connected carrier for {config.ServerAddress}");
    }

    private (Task uplink, Task downlink) StartNativePacketPumps(
        ulong handle, ulong generation, IPacketTunDevice tun, CancellationToken ct)
    {
        Task uplink = Task.Run(() =>
        {
            byte[] packet = new byte[NativeTransportCore.MaxPacketBytes];
            while (!ct.IsCancellationRequested)
            {
                int length = tun.ReceivePacket(packet, ct);
                if (length == 0) break;
                while (!NativeTransportCore.PushPacket(handle, generation, packet, length))
                {
                    if (ct.WaitHandle.WaitOne(1)) return;
                }
            }
        }, ct);

        Task downlink = Task.Run(() =>
        {
            byte[] batch = new byte[NativeTransportCore.BatchBufferBytes];
            uint[] lengths = new uint[NativeTransportCore.MaxBatchPackets];
            while (!ct.IsCancellationRequested)
            {
                int count = NativeTransportCore.PullPackets(handle, generation, batch, lengths,
                    out int used);
                if (count == 0)
                {
                    if (ct.WaitHandle.WaitOne(1)) return;
                    continue;
                }
                int offset = 0;
                for (int index = 0; index < count; index++)
                {
                    int length = checked((int)lengths[index]);
                    if (length <= 0 || offset + length > used)
                        throw new InvalidDataException("native packet batch has invalid lengths");
                    tun.SendPacket(batch, offset, length);
                    offset += length;
                }
                if (offset != used)
                    throw new InvalidDataException("native packet batch byte count mismatch");
            }
        }, ct);
        return (uplink, downlink);
    }

    private void UpdateNativeStats(ulong handle)
    {
        var stats = NativeTransportCore.Stats(handle);
        Interlocked.Exchange(ref _bytesUp, (long)Math.Min(stats.TxBytes, (ulong)long.MaxValue));
        Interlocked.Exchange(ref _bytesDown, (long)Math.Min(stats.RxBytes, (ulong)long.MaxValue));

        // Each reconnect creates a fresh native generation whose counters start at zero.
        // Do not turn that reset into a huge unsigned delta or suppress the new buffer line.
        if (stats.UdpKernelDrops < _udpKernelDrops ||
            stats.UdpInternalDrops < _udpInternalDrops ||
            stats.UdpBufferGrows < _udpBufferGrows)
        {
            _udpKernelDrops = _udpInternalDrops = _udpBufferGrows = 0;
            _udpReportedKernelDrops = _udpReportedInternalDrops = 0;
            _udpReadyLogged = false;
            _udpLastReportTick = Environment.TickCount64;
        }

        long now = Environment.TickCount64;
        bool changed = stats.UdpRecvBufferBytes != _udpRecvBufferBytes ||
                       stats.UdpKernelDrops != _udpKernelDrops ||
                       stats.UdpInternalDrops != _udpInternalDrops ||
                       stats.UdpBufferGrows != _udpBufferGrows;
        bool grew = stats.UdpBufferGrows > _udpBufferGrows;

        if (!_udpReadyLogged && stats.UdpRecvBufferBytes > 0)
        {
            Log($"UDP ready: receive buffer {stats.UdpRecvBufferBytes / 1024} KiB");
            _udpReadyLogged = true;
        }
        else if (grew)
        {
            Log($"UDP receive buffer grew to {stats.UdpRecvBufferBytes / 1024} KiB " +
                $"(growths={stats.UdpBufferGrows})");
        }

        ulong pendingKernel = stats.UdpKernelDrops - _udpReportedKernelDrops;
        ulong pendingInternal = stats.UdpInternalDrops - _udpReportedInternalDrops;
        bool detailed = IsDetailedLog;
        bool reportDetailed = detailed && changed && now - _udpLastReportTick >= 5_000;
        bool reportCompact = !detailed && (pendingKernel > 0 || pendingInternal > 0) &&
            (pendingKernel + pendingInternal >= 32 || now - _udpLastReportTick >= 30_000);
        if (reportDetailed || reportCompact)
        {
            string prefix = detailed ? "UDP telemetry" : "WARN: UDP packet loss";
            Log($"{prefix}: kernel +{pendingKernel} ({stats.UdpKernelDrops} total), " +
                $"internal +{pendingInternal} ({stats.UdpInternalDrops} total), " +
                $"buffer={stats.UdpRecvBufferBytes / 1024} KiB, grows={stats.UdpBufferGrows}");
            _udpReportedKernelDrops = stats.UdpKernelDrops;
            _udpReportedInternalDrops = stats.UdpInternalDrops;
            _udpLastReportTick = now;
        }

        _udpRecvBufferBytes = stats.UdpRecvBufferBytes;
        _udpKernelDrops = stats.UdpKernelDrops;
        _udpInternalDrops = stats.UdpInternalDrops;
        _udpBufferGrows = stats.UdpBufferGrows;
    }

    private bool IsDetailedLog =>
        string.Equals(LogLevel, "debug", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(LogLevel, "trace", StringComparison.OrdinalIgnoreCase);

    private static string LogValue(string value)
    {
        var safe = new StringBuilder(Math.Min(value.Length, 128));
        foreach (char ch in value)
        {
            if (!char.IsControl(ch)) safe.Append(ch);
            if (safe.Length == 128) break;
        }
        return safe.Length == 0 ? "?" : safe.ToString();
    }

    /// <summary>Optional platform hook: begin creating the TUN device in the background at
    /// the START of a connection attempt (before/while the handshake runs), so the (possibly
    /// slow) device open overlaps the handshake instead of adding to it after Auth OK.
    /// Default no-op; Windows overrides it (Wintun adapter creation is ~10 s). SetupTun is
    /// responsible for consuming whatever this started. Must be safe to call more than once
    /// (a failed attempt retries) — the override should no-op if it's already warming.</summary>
    protected virtual void PrewarmTun(VpnConfig config) { }

    /// <summary>Select profile-dependent platform transport ownership before the native
    /// handle is created. Default platforms have a fixed ownership mode.</summary>
    protected virtual void PrepareTransport(VpnConfig config) { }

    /// <summary>Whether the platform packet device and its routing state must survive a
    /// reconnect. Windows per-app filtering overrides this so capture remains installed
    /// in fail-closed mode while the encrypted carrier is unavailable.</summary>
    protected virtual bool KeepTunDuringReconnect(VpnConfig config)
    {
        if (!config.PersistTun) return false;
        // A retained full-tunnel carries a /32 bypass only for the address used by the
        // previous generation. If a hostname moves, the next DNS answer would follow the
        // dead TUN before the new handshake can provide a NetworkPlan and repin it. Keep
        // persist-tun for literal endpoints; rebuild routes for hostnames so DDNS can recover.
        if (!IPAddress.TryParse(config.ServerAddress, out _))
        {
            Log("persist-tun: hostname endpoint requires route rebuild on reconnect for DDNS safety");
            return false;
        }
        return true;
    }

    /// <summary>Called before reconnect teardown. A packet classifier can stop forwarding
    /// selected traffic before its capture handle is retained.</summary>
    protected virtual void OnTransportInterrupted(VpnConfig config) { }

    /// <summary>Called immediately before the platform TUN is disposed. A platform flow
    /// interceptor must stop accepting/relaying flows before the interface disappears;
    /// doing it afterwards creates a short fail-open or a relay-to-dead-interface race.</summary>
    protected virtual void BeforeTunDispose() { }

    // ── platform plan helpers ───────────────────────────────────────────────────
    /// <summary>OpenVPN route-include-from-file: read split-tunnel CIDRs (one per line;
    /// '#'/';' comments and blank lines skipped; a trailing comment/field after the CIDR
    /// is dropped) from config.RouteFile. Empty when unset or unreadable.</summary>
    protected List<string> LoadRouteFile(VpnConfig config)
    {
        var routes = new List<string>();
        if (string.IsNullOrWhiteSpace(config.RouteFile)) return routes;
        try
        {
            foreach (var raw in System.IO.File.ReadAllLines(config.RouteFile))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
                routes.Add(line.Split(' ', '\t')[0]);
            }
            Log($"Loaded {routes.Count} route(s) from {config.RouteFile}");
        }
        catch (Exception e) { Log($"WARN: cannot read route_file '{config.RouteFile}': {e.Message}"); }
        return routes;
    }

    protected sealed record AssignedAddress(string Family, string Address, int PrefixLength,
        int OnLinkPrefixLength, string? Gateway);
    protected sealed record PlannedRoute(string Cidr, string Gateway, uint Metric);

    /// <summary>Connected pool prefixes that must be routed explicitly for NetworkPlan v2.
    /// L3 TUN addresses use host prefixes (/32 and /128) to avoid ARP/NDP, so the operating
    /// system no longer synthesizes these routes from the address assignment itself.</summary>
    protected static IReadOnlyList<string> ConnectedTunnelPrefixes(Session session)
    {
        var prefixes = new List<string>();
        foreach (var assigned in session.NetworkAddresses ?? Array.Empty<AssignedAddress>())
        {
            if (assigned.OnLinkPrefixLength >= assigned.PrefixLength) continue;
            if (!IPAddress.TryParse(assigned.Address, out var address))
                throw new InvalidDataException($"invalid tunnel address {assigned.Address}");
            byte[] bytes = address.GetAddressBytes();
            int maximum = bytes.Length * 8;
            int prefix = assigned.OnLinkPrefixLength;
            if (prefix is < 0 || prefix > maximum)
                throw new InvalidDataException(
                    $"invalid on-link prefix {prefix} for tunnel address {assigned.Address}");
            int wholeBytes = prefix / 8;
            int remainingBits = prefix % 8;
            if (remainingBits != 0)
            {
                bytes[wholeBytes] &= (byte)(0xff << (8 - remainingBits));
                wholeBytes++;
            }
            Array.Clear(bytes, wholeBytes, bytes.Length - wholeBytes);
            prefixes.Add($"{new IPAddress(bytes)}/{prefix}");
        }
        return prefixes;
    }

    protected sealed record Session(string ClientIp, int Prefix, int PushedMtu,
        IReadOnlyList<string> PlannedDns, bool PlanIncludesClientRoutes,
        IReadOnlyList<AssignedAddress> NetworkAddresses,
        IReadOnlyList<PlannedRoute> PlannedRoutes,
        IReadOnlyList<string> RouteFileRoutes,
        bool AllowIpv4Leak = false, bool AllowIpv6Leak = false,
        string PlanFingerprint = "");

    /// <summary>Resolve the effective TUN MTU: an explicit client config value (>0)
    /// wins, else the server-pushed value (>0), else the auto fallback (1400).</summary>
    protected static int EffectiveMtu(int configMtu, int pushedMtu) =>
        configMtu > 0 ? configMtu : (pushedMtu > 0 ? pushedMtu : 1400);

    /// <summary>Use the authoritative DNS list already resolved by the Rust NetworkPlan.</summary>
    protected static List<string> EffectiveDns(Session session) =>
        session.PlannedDns.Where(address => !string.IsNullOrWhiteSpace(address)).ToList();

    /// <summary>The immutable route_file snapshot attached to the authenticated generation.</summary>
    protected static IReadOnlyList<string> EffectiveRouteFileRoutes(Session session) =>
        session.RouteFileRoutes;

    /// <summary>Fingerprint the projection of NetworkPlan + platform-owned profile values that
    /// actually changes host networking. Transport-only generation/data-plane facts are excluded:
    /// changing padding or stream count must not recreate a perfectly valid TUN.</summary>
    private static string NetworkPlanFingerprint(VpnConfig config, Session session, IPAddress serverIp)
    {
        var canonical = new StringBuilder(1024);

        static void Add(StringBuilder target, string name, string? value)
        {
            value ??= "";
            target.Append(name.Length).Append(':').Append(name)
                .Append('=').Append(value.Length).Append(':').Append(value).Append(';');
        }

        static string NormalizeAddress(string value)
        {
            value = value.Trim();
            return IPAddress.TryParse(value, out var parsed)
                ? parsed.ToString()
                : value.ToLowerInvariant();
        }

        static string NormalizeCidr(string value)
        {
            value = value.Trim();
            int slash = value.LastIndexOf('/');
            if (slash <= 0) return NormalizeAddress(value);
            string address = NormalizeAddress(value[..slash]);
            string prefix = int.TryParse(value[(slash + 1)..], out int parsed)
                ? parsed.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : value[(slash + 1)..].Trim();
            return $"{address}/{prefix}";
        }

        static void AddOrdered(StringBuilder target, string name, IEnumerable<string> values,
            Func<string, string>? normalize = null)
        {
            var items = values.Select(value => normalize?.Invoke(value) ?? value.Trim()).ToArray();
            Add(target, $"{name}.count", items.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
            for (int index = 0; index < items.Length; index++)
                Add(target, $"{name}[{index}]", items[index]);
        }

        static void AddSet(StringBuilder target, string name, IEnumerable<string> values,
            Func<string, string>? normalize = null)
        {
            var items = values.Select(value => normalize?.Invoke(value) ?? value.Trim())
                .Distinct(StringComparer.Ordinal)
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            AddOrdered(target, name, items);
        }

        // Next-hop and metric are diagnostic-only for desktop interface-scoped routes.
        static IEnumerable<string> CanonicalRoutes(IEnumerable<PlannedRoute> routes) =>
            routes.Select(route => NormalizeCidr(route.Cidr));

        Add(canonical, "client_ip", NormalizeAddress(session.ClientIp));
        Add(canonical, "prefix", session.Prefix.ToString(System.Globalization.CultureInfo.InvariantCulture));
        // The native fingerprint carries the complete typed dual-stack plan, including the
        // second-family address/prefix/gateway, all A/AAAA carrier candidates and leak policy.
        Add(canonical, "native_plan", session.PlanFingerprint);
        Add(canonical, "mtu", EffectiveMtu(config.Mtu, session.PushedMtu)
            .ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(canonical, "full_tunnel", config.IsFullTunnel.ToString());
        Add(canonical, "plan_includes_client_routes", session.PlanIncludesClientRoutes.ToString());
        Add(canonical, "allow_ipv4_leak", session.AllowIpv4Leak.ToString());
        Add(canonical, "allow_ipv6_leak", session.AllowIpv6Leak.ToString());
        Add(canonical, "route_local", config.RouteLocalNetworks.ToString());
        Add(canonical, "interface_metric", config.InterfaceMetric
            .ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(canonical, "forward", config.Forward.ToString());
        Add(canonical, "local_address", config.LocalAddress?.Trim());
        Add(canonical, "uses_app_filter", config.UsesAppFilter.ToString());
        Add(canonical, "apps_mode", config.AppsMode.Trim().ToLowerInvariant());
        Add(canonical, "carrier_address", serverIp.ToString());
        Add(canonical, "carrier_port", config.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Add(canonical, "carrier_protocol", config.Protocol.Trim().ToLowerInvariant());

        // Resolver order is significant (primary/secondary); route and app collections are sets.
        AddOrdered(canonical, "dns", EffectiveDns(session), NormalizeAddress);
        AddSet(canonical, "plan_routes", CanonicalRoutes(session.PlannedRoutes));
        AddSet(canonical, "profile_include_routes", config.IncludeRoutes, NormalizeCidr);
        AddSet(canonical, "profile_exclude_routes", config.ExcludeRoutes, NormalizeCidr);
        AddSet(canonical, "route_file_routes", session.RouteFileRoutes, NormalizeCidr);
        AddSet(canonical, "apps", config.Apps, value => value.Trim());

        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return Convert.ToHexString(digest);
    }



    private static readonly object _knownHostsLock = new();

    /// <summary>Trust-on-first-use with persistence (parity with the Rust client's
    /// known_hosts). Pins the server's static key on first sight (keyed by
    /// <paramref name="serverId"/> = host:port) and verifies it on every later
    /// connect — a changed key throws <see cref="SecurityException"/> as a probable
    /// MITM rather than being silently accepted. Best-effort: an unwritable store
    /// degrades to a warning, but a readable one is always enforced.</summary>
    private static string KnownHostsPath => System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "qeli", "known_hosts");

    /// <summary>
    /// Verify a received server key against an existing known_hosts pin.
    /// Returns true when a pin exists and matches, false when the host is unknown.
    /// Throws on a mismatch.
    /// </summary>
    /// <remarks>
    /// Deliberately split from <see cref="RecordKnownHost"/>: checking must happen as
    /// early as possible (fail fast on a changed key), but RECORDING must wait until
    /// the peer has proved it owns the key — see the call site.
    /// </remarks>
    private static bool CheckKnownHost(string serverId, string receivedHex)
    {
        var path = KnownHostsPath;
        lock (_knownHostsLock)
        {
            try
            {
                if (!System.IO.File.Exists(path)) return false;
                foreach (var raw in System.IO.File.ReadAllLines(path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith('#')) continue;
                    var sp = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
                    if (sp.Length == 2 && sp[0] == serverId)
                    {
                        if (string.Equals(sp[1].Trim(), receivedHex, StringComparison.OrdinalIgnoreCase))
                            return true; // matches the pin
                        throw new SecurityException(
                            $"SERVER KEY MISMATCH for {serverId} - possible MITM. Pinned {sp[1].Trim()}, " +
                            $"got {receivedHex}. If you deliberately rotated the key, remove its line " +
                            $"from {path} (or set server_public_key) and reconnect.");
                    }
                }
            }
            catch (SecurityException) { throw; }
            catch { /* unreadable store -> treat as unknown host */ }
            return false;
        }
    }

    /// <summary>Persist a first-use pin. Call ONLY after the auth proof verified.</summary>
    private void RecordKnownHost(string serverId, string receivedHex, bool allowUnpinnedTofu)
    {
        var path = KnownHostsPath;
        lock (_knownHostsLock)
        {
            try
            {
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
                System.IO.File.AppendAllText(path, $"{serverId} {receivedHex}\n");
                Log($"Pinned server key for {serverId} on first use (TOFU) -> {path}. " +
                    "A future key change will now abort as a possible MITM.");
            }
            catch (Exception e)
            {
                if (!allowUnpinnedTofu)
                    throw new SecurityException(
                        $"could not persist the proven server key for {serverId}; refusing " +
                        "unpinned TOFU (set allow_unpinned_tofu = true only to accept this risk)", e);
                Log($"WARN: could not record server key in {path} ({e.Message}); continuing " +
                    "unpinned because allow_unpinned_tofu = true. Pin key explicitly instead.");
            }
        }
    }

    /// <summary>Load (or first-time generate + persist) this device's stable 16-byte id,
    /// kept under LocalApplicationData so it survives restarts and reconnects. An
    /// unwritable host falls back to a per-run id (still works, just not stable there).</summary>
    private static readonly object _deviceIdLock = new();
    private static byte[]? _deviceId;
    private static byte[] DeviceId()
    {
        // Resolve once per process under a lock so concurrent UI/service callers cannot
        // race to generate and persist two different ids (T9).
        lock (_deviceIdLock)
        {
            if (_deviceId != null) return _deviceId;
            var dir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "qeli");
            var path = System.IO.Path.Combine(dir, "device-id");
            try
            {
                var existing = System.IO.File.ReadAllBytes(path);
                // An all-zero id (zero-filled/corrupted file) would give every such
                // device the SAME identity, so their sessions would supersede each
                // other; treat it as corrupt and regenerate over the bad file.
                if (existing.Length == 16 && Array.Exists(existing, b => b != 0))
                {
                    _deviceId = existing; return existing;
                }
            }
            catch { /* missing/unreadable -> generate below */ }
            var id = RandomNumberGenerator.GetBytes(16);
            try
            {
                System.IO.Directory.CreateDirectory(dir);
                System.IO.File.WriteAllBytes(path, id);
            }
            catch { /* unwritable host -> per-run id */ }
            _deviceId = id;
            return id;
        }
    }

    // -- TUN + network setup (platform-specific; implemented by the per-OS subclass) --
    /// <summary>Open the platform TUN device, assign addressing/routes/DNS for this session
    /// and pin the server route, then store the opened device in <c>_tun</c>.</summary>
    protected abstract void SetupTun(VpnConfig config, Session session, IPAddress serverIp,
        IReadOnlyList<IPAddress> carrierCandidates);

    /// <summary>
    /// True when the platform TUN is a transferable Unix descriptor. The base then advertises
    /// `QELI_PLATFORM_TUN_FD`, attaches it before the positive NetworkPlan ACK and does not
    /// create managed packet pumps. macOS uses this path.
    /// </summary>
    protected virtual bool NativeTunFdOwnership => false;

    /// <summary>
    /// True when the platform creates a Wintun interface but Rust must open its own adapter
    /// handle and own the session/rings. The adapter name is attached before the positive
    /// NetworkPlan ACK; managed packet pumps are not created.
    /// </summary>
    protected virtual bool NativeWintunOwnership => false;

    protected const ulong NativeIpv6SystemPlanCapabilities =
        (1UL << 8) | (1UL << 9) | (1UL << 10);
    protected const ulong NativeIpv6KillSwitchCapability = 1UL << 11;
    protected const ulong NativeRoamingPathCapabilities = (1UL << 12) | (1UL << 13);
    protected const ulong NativePathRefreshCapability = 1UL << 14;

    /// <summary>IPv6 platform operations this concrete adapter can apply completely for
    /// the selected profile.</summary>
    protected virtual ulong NativeIpv6Capabilities(VpnConfig config) => 0;

    /// <summary>Optional platform path capabilities. The default is deliberately zero;
    /// an adapter must implement every hook below before advertising the paired bits.</summary>
    protected virtual ulong NativeRoamingCapabilities(VpnConfig config) => 0;

    /// <summary>Capture one bounded physical-path snapshot. The carrier set is the last
    /// proven DNS answer captured outside the tunnel. Returning null keeps reconnect fallback.</summary>
    protected virtual NativePathUpdate? CaptureNativeRoamingPath(VpnConfig config,
        IReadOnlyList<string> carrierAddresses, ulong generation, ulong updateId,
        string reason) => null;

    /// <summary>Apply one serialized PREPARE/BIND/COMMIT/ABORT command. Throwing rejects the
    /// exact correlated command; ABORT failure is terminal and forces platform teardown.</summary>
    protected virtual void ApplyNativeRoamingCommand(NativePathCommand command) =>
        throw new NotSupportedException("native roaming path commands are not implemented");

    /// <summary>Rollback temporary candidate state when the native handle stops.</summary>
    protected virtual void ResetNativeRoamingPath() { }

    /// <summary>Tear down platform networking handles (routes/DNS) on disconnect.</summary>
    protected virtual void CleanupPlatform() { }

    /// <summary>
    /// Network setup steps the platform layer could not apply during <see cref="SetupTun"/>
    /// (failed DNS apply, dropped route, unpinned bypass). Empty = fully configured.
    /// Overridden per-OS; the base has no networking of its own. (C-17)
    /// </summary>
    protected virtual IReadOnlyList<string> NetworkWarnings => Array.Empty<string>();

    /// <summary>
    /// True when applying the tunnel's DNS servers FAILED (as opposed to a route that did
    /// not land). Overridden per-OS. (Р2)
    /// </summary>
    protected virtual bool NetworkDnsFailed => false;

    /// <summary>
    /// Refuse to run a tunnel that leaks DNS when the user asked for a kill-switch.
    ///
    /// A kill-switch is an explicit "I would rather have no connectivity than leak", so
    /// carrying traffic while every name lookup goes to the physical resolver contradicts
    /// the one instruction the user gave. Full-tunnel only, and only when the kill-switch
    /// is on: for an ordinary profile, tearing down a working tunnel because a secondary
    /// resolver did not apply would be a cure worse than the disease — there it stays a
    /// degraded status instead. (Р2)
    /// </summary>
    private void EnforceDnsPolicy(VpnConfig config)
    {
        if (!NetworkDnsFailed || !config.KillSwitch || !config.IsFullTunnel || config.UsesAppFilter) return;
        throw new InvalidOperationException(
            "Refusing to stay connected: the tunnel's DNS servers could not be applied, so " +
            "every lookup would go to the system resolver — a DNS leak — while the " +
            "kill-switch is enabled. Disconnecting instead. See the log for the failing step; " +
            "turn the kill-switch off to connect anyway (leaking DNS).");
    }

    /// <summary>The `extra` string reported alongside <c>Connected</c>: the client IP, plus
    /// a degraded marker when <see cref="NetworkWarnings"/> is non-empty so the UI cannot
    /// show an unqualified green for a half-configured tunnel. (C-17)</summary>
    private string DescribeConnected(string clientIp)
    {
        var w = NetworkWarnings;
        if (w.Count == 0) return clientIp;
        foreach (var line in w) Log($"degraded: {line}");
        return $"{clientIp} (degraded: {w.Count} network step(s) failed — see log)";
    }

}
