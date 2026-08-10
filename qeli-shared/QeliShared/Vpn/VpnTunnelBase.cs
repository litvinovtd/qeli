using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Qeli.Shared.Model;

namespace Qeli.Shared.Vpn;


/// <summary>
/// Shared Windows/macOS lifecycle and platform adapter for the ABI 1.10 Rust transport.
/// Rust owns carrier sockets, handshake, crypto and packet loops; this class applies the
/// authenticated NetworkPlan, creates the platform Wintun interface or transfers a Unix TUN
/// descriptor, and raises events for the UI.
/// </summary>
public abstract class VpnTunnelBase
{
    public event Action<string>? LogLine;
    public event Action<VpnStatus, string?>? StatusChanged; // status, optional ip/error
    public event Action<string>? ConnectionDropped;          // established session lost (will retry)
    protected void Log(string m) => LogLine?.Invoke(m);
    private void Status(VpnStatus s, string? extra = null) => StatusChanged?.Invoke(s, extra);

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    // Serializes Start()/Stop() on the single reused tunnel object so a profile switch
    // (Start->Stop->Start) can't overlap the previous attempt's teardown with the new
    // attempt's setup on the SHARED transport/TUN/route fields.
    private readonly object _lifecycleLock = new();
    private volatile bool _userRequestedDisconnect;
    // persist-tun: client IP the currently-persisted TUN adapter+routes were built for,
    // so a reconnect can reuse them when the server re-assigns the same IP. Null = no
    // persisted TUN.
    private string? _persistedClientIp;
    // All A records captured before the TUN takes over routing. Reconnects reuse and rotate
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

    // ABI 1.7+ native whole-transport generation. Kept as a signed slot solely so
    // Interlocked can publish/clear it while Stop() interrupts qeli_client_run.
    private long _nativeHandle;
    protected ITunDevice? _tun;

    // Live byte counters (goodput, IP-payload bytes) for the UI speed readout.
    private long _bytesUp;
    private long _bytesDown;
    private ulong _udpKernelDrops;
    private ulong _udpInternalDrops;
    private ulong _udpBufferGrows;
    private ulong _udpRecvBufferBytes;
    public long BytesUp => Interlocked.Read(ref _bytesUp);
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    /// <summary>When the current tunnel reached Connected (for session duration).</summary>
    public DateTime? ConnectedSince { get; private set; }

    public bool IsRunning => _runTask is { IsCompleted: false };

    public void Start(VpnConfig config)
    {

        // Serialize Start/Stop (and thus a concurrent profile switch) on one lock: Stop()
        // fully quiesces the previous attempt before we reuse the SHARED transport/TUN/route
        // fields, so the old task's teardown can't clobber the newly-established tunnel.
        lock (_lifecycleLock)
        {
            Stop();
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
                return;
            }
            _userRequestedDisconnect = false;
            // TestHandshake latches this and used to never clear it, so a GUI object that had
            // run the headless handshake test once connected forever after WITHOUT a TUN —
            // "connected", no traffic. Reset it with the rest of the per-run state.
            // (Audit 2026-07-27, N5)
            _handshakeOnly = false;
            // Per-run too: left set, a previous MITM stop would suppress the ordinary
            // "could not connect" message on the NEXT attempt. (Audit 2026-07-27, Z2)
            _stoppedForSecurityReason = false;
            _wasConnected = false;
            _carrierAddresses = Array.Empty<string>();
            _carrierGeneration = 0;
            _lastNetSig = PhysicalNetSignature(); // baseline: physical net at connect (TUN excluded)
            _bytesUp = 0; _bytesDown = 0;
            _udpKernelDrops = 0; _udpInternalDrops = 0;
            _udpBufferGrows = 0; _udpRecvBufferBytes = 0;
            ConnectedSince = null;
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            Status(VpnStatus.Connecting);
            Log($"Service started: {config.Protocol.ToUpperInvariant()}/{config.WireMode}" +
                (config.IsUdp && config.QuicEnabled ? "+QUIC" : ""));

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

            if (config.KillSwitch && config.IsFullTunnel && !config.UsesAppFilter)
            {
                try { KillSwitchEngage(config); Interlocked.Exchange(ref _ksEngaged, 1); }
                catch (Exception e)
                {
                    Log($"[SECURITY] kill-switch could not be engaged: {e.Message} — not connecting unprotected");
                    // Carry the REASON into the status detail, not just "it failed". This is a
                    // refusal to connect, so the status line is the only thing many users will
                    // ever see — and a bare "kill-switch failed" says nothing about what to do,
                    // sending them to the log for text the UI could have shown. The platform
                    // messages here are written to be actionable (macOS names the missing pf
                    // anchor and the pfctl command that fixes it), so the first sentence is
                    // worth surfacing verbatim.
                    Status(VpnStatus.Error, $"kill-switch failed — {FirstSentence(e.Message)}");
                    return;
                }
            }

            _runTask = Task.Run(() => ConnectWithRetry(config, ct), ct);
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

    public void Stop()
    {
        lock (_lifecycleLock)
        {
            _userRequestedDisconnect = true;
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
                    if (!t.Wait(8000)) Log("warn: previous tunnel task did not stop within 8s — proceeding");
                }
                catch { /* the task's own fault is irrelevant to teardown */ }
            }
            _runTask = null;
            _cts = null;
            // Phase 2 — now that nothing is running inside SetupTun / the data plane, dispose
            // the TUN and undo the platform network state. Idempotent: the joined task's own
            // error path may already have done it (both CloseTransports and CleanupPlatform
            // null-check what they release). (Audit 2026-07-27, B3)
            CloseTransports();
            // Lift the kill-switch only on a clean stop (a crash leaves it = fail-safe).
            KillSwitchLift();
            Status(VpnStatus.Disconnected);
        }
    }

    private long _lastForceReconnectTick;
    // True while ForceReconnect() deliberately closes the live sockets for a network change,
    // so the resulting data-plane socket error is logged as a clean reconnect, not a scary ERR.
    private volatile bool _forcedReconnectInFlight;

    /// <summary>Proactively cycle the connection NOW instead of waiting out the RX-liveness
    /// watchdog — called by the platform GUIs from OS suspend/resume and network-change
    /// hooks. No-op unless an established tunnel is up; debounced (one reconnect per ~3s) so
    /// a burst of OS events collapses to a single cycle. Closes the live sockets (keeping the
    /// TUN + kill-switch up, so no leak/route gap) so the data-plane loop errors and
    /// ConnectWithRetry reconnects promptly. Mirrors the Android client's forceReconnect().</summary>
    public void ForceReconnect(string reason)
    {
        NoteNetworkSettling();
        if (_userRequestedDisconnect || !IsRunning || !_wasConnected) return;
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastForceReconnectTick) < 3000) return; // debounce a burst
        Interlocked.Exchange(ref _lastForceReconnectTick, now);
        Log($"{reason} — reconnecting");
        _forcedReconnectInFlight = true;
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
    private const int SettlingAttemptCap = 3;   // ≤ base·2² — 4 s at the default base of 1 s
    private long _settlingUntilTick;

    /// <summary>Resume-from-sleep variant of <see cref="ForceReconnect"/>. The OS raises Resume
    /// while Wi-Fi is still reassociating and DHCP is pending, so cycling right then tears the
    /// tunnel down into a network that cannot carry the handshake yet — and once it is down the
    /// well-timed NetworkAddressChanged that arrives a moment later can no longer help, because
    /// ForceReconnect no-ops without an established tunnel. The reconnect then falls back to
    /// blind attempts. So wait off-thread for a physical interface to carry an IPv4 address
    /// again, bounded, and only then cycle. Fires anyway at the bound so a machine that resumes
    /// with no network at all still reconnects rather than waiting forever.</summary>
    public void ForceReconnectWhenNetworkReady(string reason, int maxWaitMs = 15_000)
    {
        // Arm the settling window on the OS event itself, BEFORE the `_wasConnected` guard
        // below can return: after a suspend the tunnel is usually already gone, and that is
        // precisely when the retry loop needs to know the network is coming back rather than
        // that the server is down. See NoteNetworkSettling.
        NoteNetworkSettling();
        if (_userRequestedDisconnect || !IsRunning || !_wasConnected) return;
        Task.Run(async () =>
        {
            long deadline = Environment.TickCount64 + maxWaitMs;
            while (PhysicalNetSignature().Length == 0 && Environment.TickCount64 < deadline)
                await Task.Delay(500).ConfigureAwait(false);
            ForceReconnect(reason);
        });
    }

    // Signature of the PHYSICAL network (non-tunnel interfaces' IPv4 addresses), captured at
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
            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    addrs.Add(ni.Id + ":" + ua.Address);
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
        _lastNetSig = sig;
        ForceReconnect("Network changed");
    }

    /// <summary>Platform hook: raise the firewall kill-switch (block all egress
    /// except the tunnel, the server, DNS and DHCP). Called once before the connect
    /// loop when <see cref="VpnConfig.KillSwitch"/> is set in full-tunnel mode.
    /// Default no-op (platforms without an implementation simply don't gate).</summary>
    protected virtual void KillSwitchEngage(VpnConfig config) { }

    /// <summary>Platform hook: lift the kill-switch on a clean stop.</summary>
    protected virtual void KillSwitchDisengage() { }

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
    private void KillSwitchLift()
    {
        if (Interlocked.Exchange(ref _ksEngaged, 0) == 0) return;
        try { KillSwitchDisengage(); } catch (Exception e) { Log($"kill-switch disengage error: {e.Message}"); }
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
    }

    /// <summary>persist-tun: if a TUN adapter + routes survived from the previous attempt
    /// (PersistTun) and the server re-assigned the SAME client IP, reuse them as-is
    /// instead of tearing down + recreating (the platform SetupTun calls this first and
    /// returns early on true). If the IP changed, rebuild cleanly (the proven path).</summary>
    protected bool ReusePersistedTun(VpnConfig config, Session session)
    {
        if (_tun == null) return false;                       // nothing persisted
        if (KeepTunDuringReconnect(config) && _persistedClientIp == session.ClientIp)
        {
            Log($"persist-tun: reusing TUN adapter + routes (client IP {session.ClientIp} unchanged)");
            return true;
        }
        // No persist, or the IP changed: tear the stale adapter down and rebuild.
        if (_persistedClientIp != null && _persistedClientIp != session.ClientIp)
            Log($"persist-tun: client IP {_persistedClientIp} -> {session.ClientIp}; rebuilding TUN");
        try { BeforeTunDispose(); } catch (Exception e) { Log($"platform pre-dispose error: {e.Message}"); }
        try { _tun?.Dispose(); } catch { }
        CleanupPlatform();
        _tun = null;
        _persistedClientIp = null;
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

    private void ConnectWithRetry(VpnConfig config, CancellationToken ct)
    {
        int attempt = 0;          // consecutive UNSTABLE attempts → backoff + max-retries
        bool firstAttempt = true; // very first connect: no reconnect gating / delay / status change
        long baseMs = config.ReconnectBaseDelaySecs * 1000;
        long maxMs = config.ReconnectMaxDelaySecs * 1000;
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
                        long delayMs = Math.Max(Math.Min(baseMs * Math.Min(pow, 100), maxMs), 1000);
                        Log($"Reconnect attempt {attempt} in {delayMs / 1000}s");
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
                _wasConnected = false;
                // Reset the backoff only after a STABLE session (ran a while). A connect-then-
                // instant-drop keeps escalating, so it can't hot-loop AND still counts toward
                // ReconnectMaxRetries.
                attempt = (DateTime.UtcNow - startedAt >= TimeSpan.FromSeconds(30)) ? 0 : NextAttempt(attempt);
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
                CloseTransports();
                break;
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                if (_forcedReconnectInFlight)
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
                attempt = (wasEstablished && DateTime.UtcNow - startedAt >= TimeSpan.FromSeconds(30))
                    ? 0 : NextAttempt(attempt);
                // persist-tun: on a reconnect (not a user Stop) keep the TUN + routes up
                // so the next attempt reuses them (no flicker / route gap; fail-closed).
                // Only when one is actually UP, though (`_persistedClientIp` is set next to
                // `_wasConnected` once SetupTun succeeded): deciding this from the config flag
                // alone also "persisted" failures that happened BEFORE or DURING SetupTun,
                // which skipped CleanupPlatform() — the only disposer of a half-built adapter
                // and of a prewarmed Wintun adapter the failed attempt never consumed.
                OnTransportInterrupted(config);
                CloseTransports(KeepTunDuringReconnect(config) && !_userRequestedDisconnect
                                && _persistedClientIp != null);
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
        if (!_userRequestedDisconnect) CloseTransports();
        if (_userRequestedDisconnect) Status(VpnStatus.Disconnected);
        else
        {
            // …and the same is true of the kill-switch, which only Stop() used to lift: after
            // an orderly give-up the UI shows Error and offers "Connect", so a still-engaged
            // firewall left the host with no egress AND no in-app way to restore it. Lift it
            // BEFORE announcing Error, so egress is already back when the user sees the state.
            // (Audit 2026-07-27, B2)
            KillSwitchLift();
            // Keep a security stop visible: only announce the generic failure when the
            // loop ended for an ordinary reason. (Audit 2026-07-27, Z2.)
            if (!_stoppedForSecurityReason)
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

    private sealed class NativePlan
    {
        [JsonPropertyName("generation")] public ulong Generation { get; set; }
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
        [JsonPropertyName("max_streams")] public int MaxStreams { get; set; } = 1;
        [JsonPropertyName("adaptive")] public bool Adaptive { get; set; }
        [JsonPropertyName("data_plane")] public NativeDataPlane DataPlane { get; set; } = new();
        [JsonPropertyName("connection_log")] public List<string> ConnectionLog { get; set; } = new();
    }

    private sealed class NativeRoute
    {
        [JsonPropertyName("cidr")] public string Cidr { get; set; } = "";
        [JsonPropertyName("gateway")] public string Gateway { get; set; } = "";
        [JsonPropertyName("metric")] public uint Metric { get; set; }
    }

    private sealed class NativeDns
    {
        [JsonPropertyName("address")] public string Address { get; set; } = "";
        [JsonPropertyName("port")] public int Port { get; set; } = 53;
    }

    private sealed class NativeDataPlane
    {
        [JsonPropertyName("padding_enabled")] public bool PaddingEnabled { get; set; }
        [JsonPropertyName("padding_min")] public int PaddingMin { get; set; }
        [JsonPropertyName("padding_max")] public int PaddingMax { get; set; }
        [JsonPropertyName("heartbeat_enabled")] public bool HeartbeatEnabled { get; set; }
        [JsonPropertyName("heartbeat_interval_ms")] public long HeartbeatIntervalMs { get; set; }
        [JsonPropertyName("shaping_enabled")] public bool ShapingEnabled { get; set; }
    }

    private sealed class NativeIdentity
    {
        [JsonPropertyName("server_id")] public string ServerId { get; set; } = "";
        [JsonPropertyName("public_key")] public string PublicKey { get; set; } = "";
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
        ulong handle = NativeTransportCore.New(config.ToTransportCoreIni(), NativeTunFdOwnership,
            NativeWintunOwnership);
        Interlocked.Exchange(ref _nativeHandle, unchecked((long)handle));

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
                            if (plan.FullTunnel != config.IsFullTunnel)
                                throw new InvalidDataException(
                                    "native NetworkPlan routing mode differs from the selected profile");
                            Log($"Auth OK, IP {plan.TunnelAddress}");
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
                                string routes = JsonSerializer.Serialize(plan.Routes);
                                var unsupportedDns = plan.DnsServers.FirstOrDefault(item => item.Port != 53);
                                if (unsupportedDns != null)
                                    throw new InvalidDataException(
                                        $"platform DNS adapter cannot apply {unsupportedDns.Address}:{unsupportedDns.Port}");
                                var dns = plan.DnsServers.Select(item => item.Address).ToList();
                                var session = new Session(plan.TunnelAddress, plan.PrefixLength,
                                    dns.FirstOrDefault() ?? "", routes, plan.Mtu,
                                    MaxStreams: plan.MaxStreams, Adaptive: plan.Adaptive,
                                    PlannedDns: dns, PlanIncludesClientRoutes: true);
                                SetupTun(config, session, carrier);
                                EnforceDnsPolicy(config);
                                _persistedClientIp = plan.TunnelAddress;
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
                                    $"address={plan.TunnelAddress}/{plan.PrefixLength} mtu={plan.Mtu} " +
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

                        case NativeTransportCore.EventStateChanged
                            when nativeEvent.State == NativeTransportCore.StateRunning && !_wasConnected:
                            _wasConnected = true;
                            ConnectedSince = DateTime.Now;
                            string clientIp = _persistedClientIp ?? "";
                            Status(VpnStatus.Connected, DescribeConnected(clientIp));
                            Log("TUN ready; Rust owns the complete transport data plane (ABI 1.10)");
                            break;

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
        if (_carrierAddresses.Length == 0)
        {
            _carrierAddresses = Dns.GetHostAddresses(config.ServerAddress)
                .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (_carrierAddresses.Length == 0)
                throw new InvalidOperationException(
                    $"{config.ServerAddress} did not resolve to an IPv4 carrier address");
        }
        int offset = (int)((uint)_carrierGeneration++ % (uint)_carrierAddresses.Length);
        string[] rotated = new string[_carrierAddresses.Length];
        for (int index = 0; index < rotated.Length; index++)
            rotated[index] = _carrierAddresses[(index + offset) % _carrierAddresses.Length];
        Log($"Physical carrier candidates: {string.Join(", ", rotated)}");
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
            $"native NetworkPlan omitted the connected IPv4 carrier for {config.ServerAddress}");
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
        if (stats.UdpRecvBufferBytes != _udpRecvBufferBytes ||
            stats.UdpKernelDrops != _udpKernelDrops ||
            stats.UdpInternalDrops != _udpInternalDrops ||
            stats.UdpBufferGrows != _udpBufferGrows)
        {
            Log($"UDP buffers: granted={stats.UdpRecvBufferBytes / 1024} KiB " +
                $"kernel_drops={stats.UdpKernelDrops} internal_drops={stats.UdpInternalDrops} " +
                $"grows={stats.UdpBufferGrows}");
            _udpRecvBufferBytes = stats.UdpRecvBufferBytes;
            _udpKernelDrops = stats.UdpKernelDrops;
            _udpInternalDrops = stats.UdpInternalDrops;
            _udpBufferGrows = stats.UdpBufferGrows;
        }
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
    protected virtual bool KeepTunDuringReconnect(VpnConfig config) => config.PersistTun;

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

    protected sealed record Session(string ClientIp, int Prefix, string DnsIp, string RoutesJson,
        int PushedMtu = 0,
        // Transport policy is executed by Rust; these values remain useful to platform
        // diagnostics without duplicating the bonding implementation.
        int MaxStreams = 1, bool Adaptive = false,
        IReadOnlyList<string>? PlannedDns = null, bool PlanIncludesClientRoutes = false);

    /// <summary>Resolve the effective TUN MTU: an explicit client config value (>0)
    /// wins, else the server-pushed value (>0), else the auto fallback (1400).</summary>
    protected static int EffectiveMtu(int configMtu, int pushedMtu) =>
        configMtu > 0 ? configMtu : (pushedMtu > 0 ? pushedMtu : 1400);

    /// <summary>Use the DNS list from the authenticated native NetworkPlan. The legacy
    /// branch is retained for platform tests and older callers that construct a Session
    /// without PlannedDns, but it never invents a third-party resolver.</summary>
    protected static List<string> EffectiveDns(VpnConfig config, Session session)
    {
        if (session.PlannedDns != null)
            return session.PlannedDns.Where(address => !string.IsNullOrWhiteSpace(address)).ToList();
        // `dns = off` / `dns = system` means LEAVE THE DEVICE RESOLVER ALONE, and it has to win
        // over everything below. Before 0.7.15 the mode collapsed into an implicit public DNS
        // fallback: the profile asked us not to touch DNS and the client did the opposite.
        if (config.DnsMode != "tunnel")
            return new List<string>();
        if (config.DnsServers.Count > 0)
            return config.DnsServers.Where(s => !string.IsNullOrEmpty(s)).ToList();
        if (!string.IsNullOrEmpty(session.DnsIp))
            return new List<string> { session.DnsIp };
        return new List<string>();
    }

    /// <summary>Pure policy checks used by both desktop headless self-test runners.</summary>
    internal static void RunNetworkPolicySelfTests(Action<string, bool> check)
    {
        static Session LegacySession(string pushedDns = "", IReadOnlyList<string>? planned = null) =>
            new("10.9.0.2", 24, pushedDns, "[]", PlannedDns: planned);

        var empty = new VpnConfig { AddDefaultGateway = true, DnsMode = "tunnel" };
        var unresolved = EffectiveDns(empty, LegacySession());
        check("dns-policy: no profile/push DNS invents no public resolver", unresolved.Count == 0);

        var explicitConfig = new VpnConfig {
            AddDefaultGateway = true,
            DnsMode = "tunnel",
            DnsServers = new List<string> { "9.9.9.9" },
        };
        check("dns-policy: explicit profile DNS wins over legacy server push",
            EffectiveDns(explicitConfig, LegacySession("10.9.0.1")).SequenceEqual(new[] { "9.9.9.9" }));
        check("dns-policy: authenticated server push is used when profile DNS is empty",
            EffectiveDns(empty, LegacySession("10.9.0.1")).SequenceEqual(new[] { "10.9.0.1" }));

        var disabled = new VpnConfig {
            AddDefaultGateway = true,
            DnsMode = "off",
            DnsServers = new List<string> { "9.9.9.9" },
        };
        check("dns-policy: dns=off suppresses legacy profile and push inputs",
            EffectiveDns(disabled, LegacySession("10.9.0.1")).Count == 0);

        check("dns-policy: authenticated native NetworkPlan is authoritative",
            EffectiveDns(empty, LegacySession("10.9.0.1", new[] { "192.0.2.53" }))
                .SequenceEqual(new[] { "192.0.2.53" }));
        check("dns-policy: an explicitly empty native NetworkPlan stays empty",
            EffectiveDns(empty, LegacySession("10.9.0.1", Array.Empty<string>())).Count == 0);
    }

    /// <summary>Rungs of the path-MTU ladder, in TUNNEL (inner) MTU units, highest first.
    /// Retained as a conformance/KAT mirror of the Rust client's <c>mtu_probe_ladder</c>.
    ///
    /// <paramref name="outerOverhead"/> is everything a probe for tunnel-MTU <c>m</c> adds on
    /// the wire: our record overhead, the obfs seal, the QUIC header and the UDP + IP headers.
    /// The floor is the largest tunnel MTU whose datagram still fits the 1280-byte IPv6 minimum
    /// path — which is the whole point: rungs are INNER MTUs, 1280 is an OUTER path MTU, and
    /// using it directly as the lowest rung meant asking a 1280-byte path for 1280 + overhead
    /// bytes. Every rung then failed on exactly the narrow paths probing exists for, the probe
    /// reported nothing, and the caller fell back to the pushed MTU with fragmentation switched
    /// back on. (Audit 2026-07-29, #12.)</summary>
    internal static int[] MtuProbeLadder(int ceiling, int outerOverhead)
    {
        const int PathFloor = 1280;  // IPv6 minimum PATH MTU — the narrowest path we must serve
        int floor = Math.Clamp(PathFloor - outerOverhead, 576, Math.Max(ceiling, 576));
        // The jumbo rungs (12000..1500) exist because the ceiling stopped being an Ethernet
        // number. While it was 1500 the next rung down was 1360 and the gap was 140 bytes; once
        // the ceiling became 16638 the same ladder went straight from 16638 to 1360, so a path
        // that carries 9000 — an ordinary jumbo LAN, which is exactly who configures a large
        // MTU — was certified at 1360 and lost ~85% of its frame. These cost nothing on a
        // normal path: they are all above a 1500 ceiling and the filter drops them.
        //
        // The set is a COMPROMISE, not an exact answer: probing fixed rungs certifies the
        // best rung that FITS, not the path's real maximum, so a 7000-byte path lands on 6000.
        // Closing that needs a binary search between the highest failing rung and the best
        // passing one — worth doing, and deliberately not smuggled in here, since it changes
        // the probe's control flow in all four ports.
        // (Audit 2026-08-01, §8.)
        return new[] { ceiling, 12000, 9000, 6000, 4000, 2500, 2000, 1500, 1360, 1320, 1280, 1200, floor }
            .Where(m => m >= floor && m <= ceiling)
            .Distinct().OrderByDescending(m => m).ToArray();
    }

    /// <summary>Stop refining once the bracket is this narrow — chasing the last few dozen
    /// bytes is not worth a round trip, and the threshold also bounds the loop for a wide
    /// gap. Same value in the Rust runtime and the retained cross-language fixtures.</summary>
    internal const int MtuRefineStepBytes = 256;

    /// <summary>Hard cap on refinement probes, so a pathological bracket cannot stretch the
    /// handshake.</summary>
    internal const int MtuRefineMaxProbes = 5;

    /// <summary>Next size to try between a rung known to WORK (<paramref name="lo"/>) and one
    /// known to FAIL (<paramref name="hi"/>), or -1 when the bracket is narrow enough to stop.
    /// Split out of the probe loop so the search is testable without a socket.</summary>
    internal static int MtuRefineStep(int lo, int hi) =>
        hi - lo <= MtuRefineStepBytes ? -1 : lo + (hi - lo) / 2;

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
    protected abstract void SetupTun(VpnConfig config, Session session, IPAddress serverIp);

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
