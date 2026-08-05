using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Qeli.Shared.Crypto;
using Qeli.Shared.Protocol;
using Qeli.Shared.Model;

namespace Qeli.Shared.Vpn;


/// <summary>
/// The qeli data plane for Windows. Direct port of the Android QeliService: shared
/// transport-agnostic handshake + tunnel loop over a small Transport abstraction
/// (TCP or UDP/QUIC), feeding a Wintun adapter. Runs on background threads and
/// raises events the WPF UI marshals to the dispatcher.
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

    // Live transports for the current attempt (closed to interrupt blocking IO).
    private Socket? _tcp;
    private Socket? _udp;
    protected ITunDevice? _tun;
    // Secondary bonded sockets (stream-bonding / multipath); closed on teardown so
    // their blocking reads unblock and the per-stream tasks exit. Primary is _tcp.
    private readonly List<Socket> _bondedSockets = new();

    // Stream-bonding wire constants, mirrored from protocol/mod.rs (JOIN_MAGIC /
    // JOIN_TOKEN_LEN). A secondary connection presents JOIN_MAGIC‖token‖index
    // instead of credentials; the server replies "JOINOK".
    private static readonly byte[] JoinMagic = Encoding.ASCII.GetBytes("QELIJOIN");
    private const int MaxBonded = 8;
    // On a UDP reconnect that reuses a fixed local port (config `local`/`lport`), the server
    // may still deliver data-plane records from the session it has not yet kicked; they'd be
    // mis-read as the ServerHello. We skip up to this many non-handshake records before giving
    // up, bounded so a peer that only sends junk still fails fast (issue #69).
    private const int MaxStalePreHandshakeRecords = 16;

    // UDP handshake retransmit tick — see RecvUdpWithClientHelloRetransmit.
    private const int HsRetransmitMs = 1000;

    // Ceiling for anything the SERVER gets to size: obfuscation padding and flow-shaping
    // cover. The Rust client caps padding on EVERY transport
    // (client/mod.rs: pad_cap = min(padding_max, 1400 - (len + 60))); the C# client only
    // capped the UDP path, via EncryptCapped(pkt, effectiveMtu). On TCP the raw pushed
    // value went straight into enc.Encrypt/EncryptPadded, so a server pushing a large
    // padding.max_bytes / traffic_shaping.max_size made PacketCodec.EncryptPadded throw
    // (payload > MaxRecordSize) on the FIRST data packet — the tunnel dropped, reconnected,
    // was handed the same values and dropped again: an unbreakable loop from one AuthOK
    // field. PadWireCeiling is the 1400 of the Rust formula; PadCapInner is its
    // per-packet budget for plaintext+padding (1400 - 60 of record/AEAD overhead), which
    // is what EncryptCapped's maxInnerPlusPad expects. (Audit 2026-07-27, N2)
    private const int PadWireCeiling = 1400;
    private const int PadCapInner = PadWireCeiling - 60;

    // Live byte counters (goodput, IP-payload bytes) for the UI speed readout.
    private long _bytesUp;
    private long _bytesDown;
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
            _lastNetSig = PhysicalNetSignature(); // baseline: physical net at connect (TUN excluded)
            _bytesUp = 0; _bytesDown = 0;
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
            if (config.KillSwitch && !config.IsFullTunnel)
                Log("NOTE: kill_switch = true is ignored in split-tunnel mode (gateway = false) "
                    + "— it only applies when the tunnel carries the default route. "
                    + "Set gateway = true if you want fail-closed protection.");
            if (config.KillSwitch && config.UsesAppFilter)
                Log("NOTE: kill_switch = true is ignored with per-app filtering (apps_mode) — "
                    + "a firewall default-block would break apps that are meant to bypass the VPN.");

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

    /// <summary>Padding length for one keepalive, mirroring the Rust client.
    ///
    /// The keepalive used to go out with an EMPTY payload here, so `obf.heartbeat
    /// .data_size_bytes` — which the server pushes and this config parses — did nothing on
    /// Windows, macOS and Android; only the Rust client honoured it. That is the setting's
    /// entire purpose: a fixed-size encrypted packet arriving at a fixed cadence is a clean
    /// DPI signature, and an EMPTY one is the most distinctive size there is. The desktop
    /// clients were therefore the easiest of the family to fingerprint while the knob meant
    /// to prevent it sat in the config looking effective.
    ///
    /// Same shape as the Rust side: a random length in [size, size+32], capped to what the
    /// path can carry so a DF-marked datagram is not dropped for being too large (which the
    /// server would then reap as an idle client).</summary>
    private static int HeartbeatPadLen(VpnConfig config, int effectiveMtu, bool isUdp, RandomNumberGenerator rng)
    {
        int want = Math.Max(0, config.HeartbeatDataSize);
        int cap = isUdp ? Math.Max(0, effectiveMtu - 60) : int.MaxValue;
        int lo = Math.Min(want, cap);
        int hi = Math.Min(want + 32, cap);
        if (hi <= lo) return lo;
        var b = new byte[4];
        rng.GetBytes(b);
        return lo + (int)(BitConverter.ToUInt32(b, 0) % (uint)(hi - lo + 1));
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
            Log($"Network settling — short attempt budget ({SettlingAttemptTimeoutMs / 1000}s) "
                + $"for the next {SettlingWindowMs / 1000}s");
    }

    // We know WHY we are reconnecting (resume-from-sleep, network change), and for a while
    // afterwards a failure says nothing about the server — the network is simply not carrying
    // traffic yet. See the escalation site in ConnectWithRetry for what this suppresses.
    private const int SettlingWindowMs = 30_000;
    private const int SettlingAttemptCap = 3;   // ≤ base·2² — 4 s at the default base of 1 s
    private long _settlingUntilTick;

    /// <summary>How long ONE connect attempt may block, in ms.
    ///
    /// Normally the configured `ConnectionTimeoutSecs` (default 30 s), which exists for
    /// genuinely slow paths. While the network is settling after a resume or a network
    /// change that budget is the wrong trade entirely: the path is not merely slow, it is
    /// not there yet, so the attempt is guaranteed to fail and every second spent waiting
    /// is a second the tunnel stays down AFTER the network comes back.
    ///
    /// This is what actually dominated the reported "about a minute" to recover from
    /// sleep — not the backoff between attempts, which the settling cap already handles.
    /// One attempt could burn an unbounded DNS lookup plus a 30 s connect, so a single
    /// badly-timed attempt outlasted the entire settling window on its own. A connect that
    /// is going to succeed on a healthy path completes in well under a second; capping the
    /// budget to a few seconds while settling costs nothing real and turns one 30 s stall
    /// into several cheap retries that land as soon as the interface is usable.</summary>
    private int AttemptTimeoutMs(VpnConfig config)
    {
        int full = (int)config.ConnectionTimeoutSecs * 1000;
        bool settling = Environment.TickCount64 < Interlocked.Read(ref _settlingUntilTick);
        return settling ? Math.Min(full, SettlingAttemptTimeoutMs) : full;
    }

    private const int SettlingAttemptTimeoutMs = 5_000;

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

    /// <summary>Close a TCP socket with a graceful FIN (Shutdown(Both) then Close) rather
    /// than the abrupt RST a bare Close() sends when there is unacked data or a live peer.
    /// Best-effort: on an already-dead socket the Shutdown throws and we fall through to
    /// Close. UDP is connectionless and needs no shutdown.</summary>
    private static void GracefulClose(Socket? s)
    {
        if (s == null) return;
        try { s.Shutdown(SocketShutdown.Both); } catch { }
        try { s.Close(); } catch { }
    }

    // keepTun: persist-tun reconnect — leave the TUN adapter + its routes UP so the next
    // attempt can reuse them (no adapter flicker, no route gap, fail-closed during the
    // reconnect window). Only ever true on a reconnect, NEVER on a user Stop.
    private void CloseTransports(bool keepTun = false)
    {
        GracefulClose(_tcp);
        // Close every secondary bonded socket so its blocking read unblocks and the
        // per-stream task exits (otherwise a reconnect leaks bonded streams).
        lock (_bondedSockets)
        {
            foreach (var s in _bondedSockets) GracefulClose(s);
            _bondedSockets.Clear();
        }
        try { _udp?.Close(); } catch { }
        _tcp = null; _udp = null;
        if (keepTun) return;  // persist-tun: keep _tun + routes alive for the next attempt
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
        if (config.PersistTun && _persistedClientIp == session.ClientIp)
        {
            Log($"persist-tun: reusing TUN adapter + routes (client IP {session.ClientIp} unchanged)");
            return true;
        }
        // No persist, or the IP changed: tear the stale adapter down and rebuild.
        if (_persistedClientIp != null && _persistedClientIp != session.ClientIp)
            Log($"persist-tun: client IP {_persistedClientIp} -> {session.ClientIp}; rebuilding TUN");
        try { _tun?.Dispose(); } catch { }
        CleanupPlatform();
        _tun = null;
        _persistedClientIp = null;
        return false;
    }

    // ── reconnect loop ─────────────────────────────────────────────────────────
    /// <summary>The clock-drift suspend detector's failure. Arms the settling window on the way
    /// out, exactly as <see cref="ForceReconnect"/> does: this is the path that fires when the OS
    /// power hook did not (a headless run, or a suspend the GUI never saw), and without it those
    /// resumes would still escalate the backoff. See <see cref="NextAttempt"/>.</summary>
    private Exception SuspendResumed(long driftMs)
    {
        Interlocked.Exchange(ref _settlingUntilTick, Environment.TickCount64 + SettlingWindowMs);
        return new Exception($"resumed after ~{driftMs / 1000}s suspend — reconnecting");
    }

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
                CloseTransports(config.PersistTun && !_userRequestedDisconnect
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
        // Windows: kick off the (slow, ~10 s) Wintun adapter creation NOW, in parallel with
        // the handshake, so SetupTun consumes a ready adapter after Auth OK instead of
        // blocking on it — this is what made a cold connect take 11-17 s. Only on a FRESH
        // connect (no adapter up yet); a persist-tun reconnect reuses the existing one.
        if (_tun == null) PrewarmTun(config);
        if (config.IsUdp) ConnectUdp(config, ct);
        else ConnectTcp(config, ct);
    }

    /// <summary>Optional platform hook: begin creating the TUN device in the background at
    /// the START of a connection attempt (before/while the handshake runs), so the (possibly
    /// slow) device open overlaps the handshake instead of adding to it after Auth OK.
    /// Default no-op; Windows overrides it (Wintun adapter creation is ~10 s). SetupTun is
    /// responsible for consuming whatever this started. Must be safe to call more than once
    /// (a failed attempt retries) — the override should no-op if it's already warming.</summary>
    protected virtual void PrewarmTun(VpnConfig config) { }

    // ── transport abstraction ───────────────────────────────────────────────────
    private interface ITransport
    {
        void Send(byte[] record, bool longHeader = false);
        byte[] RecvRecord();
        void SetReadTimeout(int ms);
        // Wall-clock ceiling (Environment.TickCount64) for a single RecvRecord's internal
        // fragment-reassembly loop; long.MaxValue = none. TCP has no fragmentation.
        void SetFillDeadline(long tickCount64);
    }

    private sealed class TcpTransport : ITransport
    {
        private readonly SocketIO _io;
        private readonly bool _raw;   // plain wire mode: bare length-prefixed records
        public TcpTransport(SocketIO io, bool raw = false) { _io = io; _raw = raw; }
        public void Send(byte[] record, bool longHeader = false) => _io.WriteFully(record);
        public byte[] RecvRecord() => _raw ? _io.ReadRawRecord() : _io.ReadTlsRecord();
        public void SetReadTimeout(int ms) { }
        public void SetFillDeadline(long tickCount64) { }
    }

    private sealed class UdpTransport : ITransport
    {
        private readonly VpnTunnelBase _t;
        private readonly Socket _sock;
        private readonly bool _quic;
        private readonly byte[] _cid;
        private readonly byte[]? _obfsKey;   // per-datagram ChaCha20 XOR (null = none)
        private int _pn;
        private byte[] _buf = Array.Empty<byte>();
        private int _pos;
        private readonly object _sendLock = new();   // serialize concurrent datagram sends

        public UdpTransport(VpnTunnelBase t, Socket sock, bool quic, byte[] cid, byte[]? obfsKey)
        { _t = t; _sock = sock; _quic = quic; _cid = cid; _obfsKey = obfsKey; }

        /// <summary>Bytes the outer layers add on the WIRE beyond the tunnel MTU itself: the
        /// obfs datagram seal, the QUIC short header, and the UDP + IP headers. Mirrors the
        /// Rust client's <c>seal_overhead() + QUIC_SHORT_HEADER_MIN + 8 + (40|20)</c>.
        ///
        /// The path-MTU ladder needs this because its rungs are INNER (tunnel) MTUs while the
        /// path limit it must respect is an OUTER size — see <c>MtuProbeLadder</c>.</summary>
        public int OuterOverhead =>
            (_obfsKey != null ? ObfsStream.DatagramSealOverhead : 0)
            + (_quic ? Quic.ShortHeaderMin : 0)
            + 8                                         // UDP header
            + (_sock.AddressFamily == AddressFamily.InterNetworkV6 ? 40 : 20);

        public void Send(byte[] record, bool longHeader = false)
        {
            // The handshake ClientHello (longHeader) is large (post-quantum) — fragment
            // it so no datagram needs IP fragmentation (mobile / CGNAT drop IP fragments
            // → UDP handshake fails on LTE). Data / auth (short header) already fit one.
            var pieces = longHeader
                ? UdpFrag.Fragment(UdpFrag.MsgClientHello, record)
                : new List<byte[]> { record };
            foreach (var piece in pieces)
            {
                byte[] outBuf = _quic
                    ? (longHeader ? Quic.WrapLong(piece, _cid, _pn++, 0x00) : Quic.WrapShort(piece, _cid, _pn++))
                    : piece;
                if (_obfsKey != null) outBuf = ObfsStream.DatagramSeal(_obfsKey, outBuf);
                lock (_sendLock) { _sock.Send(outBuf); }
            }
        }

        /// <summary>AWG junk (AmneziaWG-style Jc on UDP): emit <paramref name="jc"/> throwaway
        /// decoy datagrams of random size BEFORE the ClientHello — a polymorphic start that
        /// blurs the first datagrams' size/count fingerprint. Each rides the SAME QUIC / obfs
        /// mask as a real datagram, and the server drops it cheaply before its rate limiter.</summary>
        public void SendJunkPreamble(uint jc, ushort jmin, ushort jmax)
        {
            jc = Math.Min(jc, 128u);
            ushort jmaxC = Math.Min(jmax, (ushort)1400);
            ushort jminC = Math.Min(jmin, jmaxC);
            for (uint i = 0; i < jc; i++)
            {
                int len = System.Security.Cryptography.RandomNumberGenerator.GetInt32(jminC, jmaxC + 1);
                len = Math.Clamp(len, 1, UdpFrag.MaxChunk);   // never IP-fragment on LTE/CGNAT
                byte[] junk = UdpFrag.JunkDatagram(len);
                byte[] outBuf = _quic ? Quic.WrapLong(junk, _cid, _pn++, 0x00) : junk;
                if (_obfsKey != null) outBuf = ObfsStream.DatagramSeal(_obfsKey, outBuf);
                lock (_sendLock) { _sock.Send(outBuf); }
            }
        }

        // Wall-clock ceiling for this loop; long.MaxValue = none (data plane). During the
        // handshake RecvUdpWithRetransmit sets it to the shared deadline so a flood of
        // never-completing fragment datagrams can't spin here past connection_timeout_secs —
        // the per-read socket timeout never fires under a steady flood (each Receive returns).
        private long _fillDeadline = long.MaxValue;
        public void SetFillDeadline(long tickCount64) => _fillDeadline = tickCount64;

        private void Fill()
        {
            var rbuf = new byte[65535];
            UdpFrag.Reassembler? re = null;
            while (true)
            {
                if (Environment.TickCount64 >= _fillDeadline)
                    throw new TimeoutException(
                        "UDP: fragment reassembly did not complete before the handshake deadline");
                int n = _sock.Receive(rbuf);
                byte[]? raw = rbuf[..n];
                if (_obfsKey != null) raw = ObfsStream.DatagramOpen(_obfsKey, raw);
                if (raw == null) continue;     // malformed obfs frame — skip
                var payload = _quic ? Quic.UnwrapPayload(raw) : raw;
                if (payload == null) continue;
                // A fragmented handshake message arrives as several datagrams — reassemble
                // before handing records up. That is the ServerHello, and since 0.7.14 also a
                // large AuthOK (msg_id 6), which a big pushed-route set puts over the budget.
                // Deliberately keyed on IsFragment rather than on a specific msg_id: a real
                // record can never carry the magic in either framing (see UdpFrag.MsgAuthOk),
                // so this stays correct on the data plane too. Everything else passes through.
                if (UdpFrag.IsFragment(payload))
                {
                    re ??= new UdpFrag.Reassembler();
                    byte[]? full;
                    try { full = re.Push(payload); } catch { re = null; continue; }
                    if (full == null) continue;     // need more fragments
                    _buf = full; _pos = 0; return;
                }
                _buf = payload; _pos = 0; return;
            }
        }

        public byte[] RecvRecord()
        {
            // Keep pulling datagrams until we have at least a 5-byte record header. A datagram
            // whose (unwrapped) payload is shorter — a stray / tiny / malformed control
            // datagram — must be SKIPPED, not indexed past its end: reading _buf[_pos+4] on a
            // <5-byte buffer threw IndexOutOfRangeException and tore the tunnel loop down.
            while (true)
            {
                while (_pos + 5 > _buf.Length) Fill();
                int len = ((_buf[_pos + 3] & 0xFF) << 8) | (_buf[_pos + 4] & 0xFF);
                // A datagram must carry the WHOLE record it declares. Clamping the end to the
                // buffer (`Math.Min`) instead quietly turned a truncated record into a shorter
                // valid-looking one: the AEAD then failed and the tunnel dropped, with the real
                // cause — a peer or middlebox that cut the datagram — nowhere in the log. UDP
                // has no continuation, so no later datagram can complete it; the only correct
                // handling is to drop this datagram and read the next. The length is bounded
                // too: a record bigger than the codec will ever accept is garbage or a hostile
                // length field, and must not size an allocation. (Audit 2026-07-29, #17.)
                if (len > PacketCodec.MaxRecordSize || _pos + 5 + len > _buf.Length)
                {
                    _buf = Array.Empty<byte>();   // force Fill() to pull the next datagram
                    _pos = 0;
                    continue;
                }
                int end = _pos + 5 + len;
                var rec = _buf[_pos..end];
                _pos = end;
                return rec;
            }
        }

        public void SetReadTimeout(int ms) => _sock.ReceiveTimeout = ms;

        // ── path-MTU probe helpers (used before the TUN is up) ───────────────────
        /// <summary>Toggle Don't-Fragment on the UDP socket. On success oversized sends
        /// throw (WSAEMSGSIZE) instead of fragmenting, which is what the probe wants.</summary>
        public bool SetDontFragment(bool on)
        {
            try { _sock.DontFragment = on; return true; } catch { return false; }
        }

        /// <summary>Receive one datagram, unwrap the obfs/QUIC mask, return the payload
        /// (or null on timeout / malformed). Used to catch a probe ACK before the data loop.</summary>
        public byte[]? RecvRawPayload(int timeoutMs)
        {
            _sock.ReceiveTimeout = timeoutMs;
            var rbuf = new byte[65535];
            try
            {
                int n = _sock.Receive(rbuf);
                byte[]? raw = rbuf[..n];
                if (_obfsKey != null) raw = ObfsStream.DatagramOpen(_obfsKey, raw);
                if (raw == null) return null;
                return _quic ? Quic.UnwrapPayload(raw) : raw;
            }
            catch (SocketException) { return null; } // timeout or oversized-reply
        }
    }

    /// <summary>REALITY transport: the qeli protocol runs inside a genuine TLS 1.3
    /// session. Each inner qeli record is sealed as one TLS application_data record;
    /// inbound TLS records are decrypted and re-sliced into inner qeli records.</summary>
    private sealed class RealTlsTransport : ITransport
    {
        private readonly ITransport _inner;
        private readonly RealTls _tls;
        private byte[] _inBuf = Array.Empty<byte>();
        public RealTlsTransport(ITransport inner, RealTls tls) { _inner = inner; _tls = tls; }

        public void Send(byte[] record, bool longHeader = false) => _inner.Send(_tls.Seal(record));

        public byte[] RecvRecord()
        {
            while (!HasInnerRecord())
            {
                var plain = _tls.Open(_inner.RecvRecord()); // decrypt one outer TLS record
                if (plain.Length > 0)
                {
                    var merged = new byte[_inBuf.Length + plain.Length];
                    Buffer.BlockCopy(_inBuf, 0, merged, 0, _inBuf.Length);
                    Buffer.BlockCopy(plain, 0, merged, _inBuf.Length, plain.Length);
                    _inBuf = merged;
                }
            }
            int len = ((_inBuf[3] & 0xFF) << 8) | (_inBuf[4] & 0xFF);
            int total = 5 + len;
            var rec = _inBuf[..total];
            _inBuf = _inBuf[total..];
            return rec;
        }

        private bool HasInnerRecord()
        {
            if (_inBuf.Length < 5) return false;
            int len = ((_inBuf[3] & 0xFF) << 8) | (_inBuf[4] & 0xFF);
            return _inBuf.Length >= 5 + len;
        }

        public void SetReadTimeout(int ms) => _inner.SetReadTimeout(ms);
        // reality-tls rides TCP (no UDP fragment reassembly), so this is a no-op via _inner.
        public void SetFillDeadline(long tickCount64) => _inner.SetFillDeadline(tickCount64);
    }

    /// <summary>Drive the native REALITY TLS 1.3 handshake over the raw socket.</summary>
    private RealTls DoRealTlsHandshake(VpnConfig config, SocketIO io)
    {
        string sni = config.Sni ?? PickSni(config.ServerAddress);
        if (string.IsNullOrEmpty(config.ServerPublicKeyHex))
            throw new Exception("reality-tls requires a pinned server key (auth.server_public_key)");
        var realityPub = Convert.FromHexString(
            new string(config.ServerPublicKeyHex.Where(Uri.IsHexDigit).ToArray()));
        if (realityPub.Length != 32) throw new Exception("server key must be 32 bytes (64 hex chars)");
        var shortId = ShortIdFromHex(config.RealityShortId
            ?? throw new Exception("reality-tls requires reality_sid"));

        var tls = RealTls.Create(realityPub, shortId, sni);
        io.WriteRaw(tls.ClientHello);
        while (!tls.Established)
        {
            var outBuf = tls.Recv(io.ReadSomeRaw());
            if (outBuf.Length > 0) io.WriteRaw(outBuf);
        }
        Log($"REALITY TLS 1.3 established (SNI {sni})");
        return tls;
    }

    /// <summary>REALITY short_id: hex → exactly 8 bytes, zero-padded (matches the
    /// Rust crypto::reality::short_id_from_hex).</summary>
    private static byte[] ShortIdFromHex(string hex)
    {
        var clean = new string(hex.Where(Uri.IsHexDigit).ToArray());
        if (clean.Length > 16) clean = clean[..16];
        clean = clean.PadRight(16, '0');
        return Convert.FromHexString(clean);
    }

    // ── connection setup ──────────────────────────────────────────────────────

    /// <summary>OpenVPN `local` / `lport`: bind the carrier socket to a fixed local
    /// address and/or source port before connecting (multi-homed egress selection /
    /// stable source port for firewall rules). No-op when neither is set; a bad address
    /// or an unavailable port is logged and ignored rather than aborting the connect.</summary>
    private void BindLocal(Socket sock, VpnConfig config)
    {
        if (string.IsNullOrEmpty(config.LocalAddress) && config.LocalPort <= 0) return;
        IPAddress local = IPAddress.Any;
        if (!string.IsNullOrEmpty(config.LocalAddress) && !IPAddress.TryParse(config.LocalAddress, out local!))
        {
            Log($"WARN: invalid local address '{config.LocalAddress}' — using any");
            local = IPAddress.Any;
        }
        int port = config.LocalPort > 0 ? config.LocalPort : 0;
        try { sock.Bind(new IPEndPoint(local, port)); Log($"Bound carrier socket to {local}:{port}"); }
        catch (Exception e) { Log($"WARN: could not bind local {local}:{port}: {e.Message}"); }
    }

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

    private void ConnectTcp(VpnConfig config, CancellationToken ct)
    {
        // One budget for the whole pre-data-plane phase: resolve, connect, handshake reads.
        // Shortened while the network is settling — see AttemptTimeoutMs.
        int attemptMs = AttemptTimeoutMs(config);
        var serverIp = ResolveServer(config.ServerAddress, attemptMs);
        // Do not log the account username — this line reaches shared/world-readable logs
        // (win service.log, Android logcat). The password/keys are never logged; keep the
        // username out too. (client-audit LOW: username-logging)
        Log($"Connecting TCP {serverIp}:{config.Port}...");
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        BindLocal(sock, config);  // OpenVPN local / lport
        ProtectCarrierSocket(sock);
        // Publish the socket BEFORE the (blocking) connect so Stop()/CloseTransports
        // can close it to interrupt a connect that hangs on a dead/changed network —
        // otherwise the Disconnect button does nothing until the connect timeout.
        _tcp = sock;
        if (ct.IsCancellationRequested || _userRequestedDisconnect) { try { sock.Close(); } catch { } throw new OperationCanceledException(); }
        ConnectWithTimeout(sock, serverIp, config.Port, attemptMs);
        sock.NoDelay = true;
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        // Bound the HANDSHAKE reads by ConnectionTimeoutSecs. ConnectWithTimeout only
        // bounds the connect; without this a server that accepts TCP then goes silent at
        // the application layer would block the blocking Sock.Receive in the handshake
        // forever (KeepAlive does not help — a silent-but-alive peer keeps ACKing probes),
        // pinning the client in "Connecting" with no reconnect. RunTcpAfterHandshake resets
        // this to 0 (infinite) before the data plane, where liveness is the rxDead watchdog.
        sock.ReceiveTimeout = attemptMs;
        Log("TCP connected");
        var io = new SocketIO(sock);

        // Every TCP wire mode builds its primary transport, runs the qeli handshake,
        // then hands off to RunTcpAfterHandshake which decides single-stream vs bonded
        // multipath. Stream bonding is supported on ALL TCP modes; the per-mode
        // connector lives in OpenBondedStream.
        if (config.WireMode.Equals("plain", StringComparison.OrdinalIgnoreCase))
        {
            // No TLS mimicry: raw X25519 key exchange, then bare length-prefixed
            // records (Framing::Raw).
            Log("plain mode: raw key exchange, no TLS mimicry");
            var hs = PerformHandshakePlain(config, io);
            RunTcpAfterHandshake(config, io, new TcpTransport(io, raw: true), null, serverIp, ct, hs);
        }
        else if (config.WireMode.Equals("reality-tls", StringComparison.OrdinalIgnoreCase))
        {
            // Genuine browser TLS 1.3 (REALITY) carries the tunnel; the qeli protocol
            // runs nested inside it via RealTlsTransport.
            var tls = DoRealTlsHandshake(config, io);
            var transport = new RealTlsTransport(new TcpTransport(io), tls);
            var hs = PerformHandshake(config, transport, padToMin: 0);
            RunTcpAfterHandshake(config, io, transport, tls, serverIp, ct, hs);
        }
        else if (config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(config.ObfsKey))
                throw new InvalidOperationException("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)");
            bool fronting = config.ObfsFronting.Equals("websocket", StringComparison.OrdinalIgnoreCase);
            Log(fronting ? "obfs mode: WebSocket fronting + nonce exchange" : "obfs mode: exchanging nonces");
            // F2: AmneziaWG junk. jc=0 (default / disabled) => zero extra bytes on the wire.
            uint jc = config.AwgEnabled ? config.AwgJc : 0u;
            if (jc > 0) Log($"obfs mode: AmneziaWG junk enabled (jc={jc}, jmin={config.AwgJmin}, jmax={config.AwgJmax})");
            io.Obfs = ObfsStream.Connect(ObfsStream.DeriveKey(config.ObfsKey), fronting, io.WriteRaw, io.ReadRaw,
                jc, config.AwgJmin, config.AwgJmax);
            var transport = new TcpTransport(io);
            var hs = PerformHandshake(config, transport, padToMin: 0);
            RunTcpAfterHandshake(config, io, transport, null, serverIp, ct, hs);
        }
        else // fake-tls: TLS-record mimicry applied by the qeli handshake/codec
        {
            var transport = new TcpTransport(io);
            var hs = PerformHandshake(config, transport, padToMin: 0);
            RunTcpAfterHandshake(config, io, transport, null, serverIp, ct, hs);
        }
    }

    /// <summary>Shared TCP tail: announce, bring up the TUN, then run the bonded
    /// multipath loop (server pushed max_streams>1 + a token) or the single-stream
    /// loop.</summary>
    private void RunTcpAfterHandshake(VpnConfig config, SocketIO io, ITransport transport, RealTls? tls,
        IPAddress serverIp, CancellationToken ct, HsResult hs)
    {
        Log($"Auth OK, IP {hs.Session.ClientIp}");
        LogServerPush(hs.Config, hs.Session);
        // Handshake is done — drop the handshake read deadline. In the data plane a quiet
        // (but alive) tunnel must NOT throw on an idle read; liveness there is the rxDead
        // watchdog + heartbeats, not a socket timeout. 0 = infinite.
        io.Sock.ReceiveTimeout = 0;
        if (_handshakeOnly) { _handshakeIp = hs.Session.ClientIp; try { tls?.Dispose(); } catch { } return; }

        ConnectedSince = DateTime.Now;
        SetupTun(hs.Config, hs.Session, serverIp);
        _persistedClientIp = hs.Session.ClientIp;  // persist-tun: remember what's up now
        // Established only AFTER the TUN is up: a local SetupTun failure (e.g.
        // WintunStartSession) must count as a PRE-established failure so ConnectWithRetry
        // backs off — otherwise it reset the backoff and re-authed in a tight loop, and the
        // hosting's anti-DDoS blocked the server (issue #69).
        _wasConnected = true;
        // Report Connected (green) only now — the TUN is up. Signalling it at Auth OK, before
        // SetupTun, lit the indicator green while the Wintun adapter open (up to 10 s) or a
        // SetupTun failure was still pending, so the UI claimed "connected" with no working
        // tunnel. Status stays Connecting (yellow) until here (issue #69).
        // Qualify "Connected" with anything the platform network setup failed to apply.
        // Routes and DNS are best-effort by design, but a green indicator that hides a
        // missing DNS apply (queries leaking to the system resolver) or a dropped pushed
        // route is worse than a slower connect — the user cannot act on what they are not
        // told. The tunnel still runs; the status now says it is not fully configured. (C-17)
        // Kill-switch + full-tunnel + failed DNS => abort rather than leak. Thrown BEFORE
        // reporting Connected, so the UI never shows a green state we are about to tear
        // down; ConnectWithRetry treats it like any other post-TUN failure. (Р2)
        EnforceDnsPolicy(hs.Config);
        Status(VpnStatus.Connected, DescribeConnected(hs.Session.ClientIp));

        if (hs.Session.MaxStreams > 1 && !string.IsNullOrEmpty(hs.Session.SessionToken))
        {
            Log($"Multipath: server allows up to {hs.Session.MaxStreams} bonded stream(s) (adaptive={hs.Session.Adaptive})");
            var primary = new BondedStream(io, transport, hs.Enc, hs.Dec, tls);
            // `tls` is now owned by the bonded set; RunMultipathTunnelLoop disposes each
            // stream's Tls on teardown — do NOT dispose it here (would double-free).
            RunMultipathTunnelLoop(hs.Config, primary, hs.Session, hs.Pushed, serverIp, ct);
        }
        else
        {
            Log("TUN ready, entering tunnel loop");
            try
            {
                RunTunnelLoop(hs.Config, transport, hs.Enc, hs.Dec, isUdp: false,
                    EffectiveMtu(hs.Config.Mtu, hs.Session.PushedMtu), ct);
            }
            finally
            {
                // Single-stream owns `tls` (reality-tls) — release the native TLS session
                // so it does not leak across every reconnect. Null for other wire modes.
                try { tls?.Dispose(); } catch { }
            }
        }
    }

    private void ConnectUdp(VpnConfig config, CancellationToken ct)
    {
        int attemptMs = AttemptTimeoutMs(config);
        var serverIp = ResolveServer(config.ServerAddress, attemptMs);
        // Username deliberately omitted — see ConnectTcp. (client-audit LOW: username-logging)
        Log($"Connecting UDP {serverIp}:{config.Port}...");
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        BindLocal(sock, config);  // OpenVPN local / lport
        ProtectCarrierSocket(sock);
        // Enlarge the receive buffer over the OS default. UDP gets no autotuning (unlike TCP),
        // so the socket keeps whatever it was given; at tunnel speeds the default is only tens
        // of milliseconds of traffic and a single scheduling stall makes the kernel drop
        // datagrams. A dropped datagram is a lost TCP segment INSIDE the tunnel, which halves
        // the inner connection's window — the same defect on the server side cost half the
        // uplink until it was fixed. Best-effort: the OS may grant less, and a refusal must not
        // break the connection. 2 MB is enough to absorb a stall without queueing so much that
        // latency suffers under sustained overload.
        try { sock.ReceiveBufferSize = 2 * 1024 * 1024; } catch (Exception e) { Log($"UDP: could not enlarge the receive buffer ({e.Message}); using the default"); }
        sock.Connect(serverIp, config.Port);
        sock.ReceiveTimeout = attemptMs;
        _udp = sock;

        bool quic = config.QuicEnabled;
        var cid = quic ? Quic.GenerateConnectionId() : new byte[4];
        if (config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(config.ObfsKey))
            throw new InvalidOperationException("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)");
        byte[]? obfsKey = config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase) && config.ObfsKey.Length > 0
            ? ObfsStream.DeriveKey(config.ObfsKey)
            : null;
        if (quic) Log("UDP QUIC masking enabled");
        if (obfsKey != null) Log("UDP obfs mode enabled");
        var transport = new UdpTransport(this, sock, quic, cid, obfsKey);
        // AWG junk (AmneziaWG-style Jc) works on UDP too: emit the decoy preamble before
        // the ClientHello. OFF by default (AwgJc = 0) → byte-identical to the prior wire.
        if (config.AwgEnabled && config.AwgJc > 0)
        {
            transport.SendJunkPreamble(config.AwgJc, config.AwgJmin, config.AwgJmax);
            Log($"UDP: sent AWG junk preamble (jc={config.AwgJc}, jmin={config.AwgJmin}, jmax={config.AwgJmax}) before ClientHello");
        }
        EstablishAndRun(config, transport, padToMin: 1200, isUdp: true, serverIp, ct);
    }

    private void EstablishAndRun(VpnConfig config, ITransport transport, int padToMin, bool isUdp,
        IPAddress serverIp, CancellationToken ct)
    {
        var hs = PerformHandshake(config, transport, padToMin, isUdp);
        RunAfterHandshake(config, transport, isUdp, serverIp, ct, hs);
    }

    /// <summary>Post-handshake path for the single-stream transports (UDP); the TCP
    /// modes use RunTcpAfterHandshake which can also start the multipath loop.</summary>
    private void RunAfterHandshake(VpnConfig config, ITransport transport, bool isUdp, IPAddress serverIp,
        CancellationToken ct, HsResult hs)
    {
        Log($"Auth OK, IP {hs.Session.ClientIp}");
        LogServerPush(hs.Config, hs.Session);

        if (_handshakeOnly) { _handshakeIp = hs.Session.ClientIp; return; }

        ConnectedSince = DateTime.Now;

        // Auto MTU on UDP: when mtu=0 and probing is on, discover the path MTU (DF probes
        // from the pushed ceiling down) BEFORE the TUN is up, and fold the result into the
        // session so EffectiveMtu (in SetupTun) adopts it. Fail-safe: a miss keeps the
        // pushed MTU. TCP is untouched (the kernel does PMTUD there).
        if (isUdp && hs.Config.Mtu == 0 && hs.Config.MtuProbe && transport is UdpTransport ut)
        {
            int ceiling = EffectiveMtu(0, hs.Session.PushedMtu);
            int probed = ProbeUdpMtu(ut, ceiling);
            if (probed > 0)
            {
                Log($"UDP path-MTU probe: tunnel MTU {probed} (ceiling {ceiling})");
                hs = hs with { Session = hs.Session with { PushedMtu = probed } };
            }
            else Log($"UDP path-MTU probe: no result — using MTU {ceiling}");
        }

        // The TUN setup can take many seconds (Windows Wintun adapter creation). During it the
        // tunnel loop — which sends the client->server keepalive — is not running yet, so on a
        // UDP carrier the NAT mapping / server session could lapse and the first downlink never
        // arrives (the "no downlink for >8s" reconnect). Keep the carrier warm with periodic
        // keepalives until the TUN is up. UDP only (a TCP carrier survives at the kernel). The
        // task is the ONLY user of hs.Enc during setup and is cancelled + joined before the
        // tunnel loop, so the encoder's nonce sequence stays single-threaded and continuous.
        using (var warmCts = new CancellationTokenSource())
        {
            var keepWarm = isUdp
                ? Task.Run(() =>
                {
                    try
                    {
                        while (!warmCts.Token.WaitHandle.WaitOne(2000))
                            transport.Send(hs.Enc.Encrypt(Array.Empty<byte>()));
                    }
                    catch { /* a carrier hiccup during setup is non-fatal — the loop reconnects */ }
                })
                : Task.CompletedTask;
            try { SetupTun(hs.Config, hs.Session, serverIp); }
            finally { warmCts.Cancel(); try { keepWarm.Wait(1000); } catch { } }
        }
        _persistedClientIp = hs.Session.ClientIp;  // persist-tun: remember what's up now
        // Established only after the TUN is up (see the TCP path / issue #69) — a local
        // setup failure counts as pre-established so ConnectWithRetry backs off instead
        // of re-authing in a tight loop.
        _wasConnected = true;
        // Green only now — the TUN is up (see the TCP path / issue #69). Status stayed
        // Connecting (yellow) through the handshake, MTU probe and SetupTun.
        // Qualify "Connected" with anything the platform network setup failed to apply.
        // Routes and DNS are best-effort by design, but a green indicator that hides a
        // missing DNS apply (queries leaking to the system resolver) or a dropped pushed
        // route is worse than a slower connect — the user cannot act on what they are not
        // told. The tunnel still runs; the status now says it is not fully configured. (C-17)
        // Kill-switch + full-tunnel + failed DNS => abort rather than leak. Thrown BEFORE
        // reporting Connected, so the UI never shows a green state we are about to tear
        // down; ConnectWithRetry treats it like any other post-TUN failure. (Р2)
        EnforceDnsPolicy(hs.Config);
        Status(VpnStatus.Connected, DescribeConnected(hs.Session.ClientIp));
        Log("TUN ready, entering tunnel loop");
        RunTunnelLoop(hs.Config, transport, hs.Enc, hs.Dec, isUdp,
            EffectiveMtu(hs.Config.Mtu, hs.Session.PushedMtu), ct);
    }

    // ── handshake ───────────────────────────────────────────────────────────────
    protected sealed record Session(string ClientIp, int Prefix, string DnsIp, string RoutesJson,
        int PushedMtu = 0,
        // Stream-bonding (multipath): per-session JOIN token (lowercase hex) and how
        // many parallel connections the server permits. MaxStreams<=1 (or an older
        // server that omits these) => plain single-stream. Adaptive => ramp up.
        string SessionToken = "", int MaxStreams = 1, bool Adaptive = false);

    /// <summary>Handshake result, including server-pushed obfuscation (retained so
    /// bonded secondary streams apply the same padding distribution).</summary>
    private sealed record HsResult(Session Session, VpnConfig Config, PacketCodec Enc, PacketCodec Dec,
        PushedObf? Pushed);

    /// <summary>Resolve the effective TUN MTU: an explicit client config value (>0)
    /// wins, else the server-pushed value (>0), else the auto fallback (1400).</summary>
    protected static int EffectiveMtu(int configMtu, int pushedMtu) =>
        configMtu > 0 ? configMtu : (pushedMtu > 0 ? pushedMtu : 1400);

    /// <summary>Resolve the resolvers to program on the TUN, in priority order:
    /// 1) explicit `dns = …` from the config; 2) the server-pushed resolver
    /// (<see cref="Session.DnsIp"/> — e.g. dns.push_servers or the server's DNS proxy);
    /// 3) the public-resolver fallback (1.1.1.1 / 8.8.8.8) but ONLY on a full tunnel,
    /// where DNS must not leak outside — a split tunnel leaves the system resolver alone.
    /// Keeping the fallback here (not as a config default) means a config the user never
    /// gave DNS stays clean on round-trip and the server's push is actually honoured.</summary>
    /// <summary>Log EVERY setting the server pushed at auth, and what this client did with
    /// it. Without this you cannot tell "the server never sent it" from "the client dropped
    /// it" — from the outside both look identical (a missing route/DNS and no log at all).
    /// Each item says WHY it was not applied and which knob fixes it.</summary>
    protected void LogServerPush(VpnConfig config, Session session)
    {
        int nRoutes = 0;
        try
        {
            var raw = string.IsNullOrWhiteSpace(session.RoutesJson) ? "[]" : session.RoutesJson;
            if (JsonNode.Parse(raw) is JsonArray arr) nRoutes = arr.Count;
        }
        catch { /* malformed push — reported as 0 below */ }

        Log($"server push: ip={session.ClientIp}/{session.Prefix} " +
            $"mtu={(session.PushedMtu > 0 ? session.PushedMtu.ToString() : "-")} " +
            $"dns={(string.IsNullOrEmpty(session.DnsIp) ? "-" : session.DnsIp)} " +
            $"routes={nRoutes} streams={session.MaxStreams}");

        // MTU — the client's own explicit mtu wins over the pushed one.
        if (session.PushedMtu <= 0)
            Log($"server push: mtu not sent (older server) — using {EffectiveMtu(config.Mtu, session.PushedMtu)}");
        else if (config.Mtu > 0)
            Log($"server push: mtu {session.PushedMtu} IGNORED — this client sets mtu = {config.Mtu} (wins); " +
                $"using {EffectiveMtu(config.Mtu, session.PushedMtu)}");
        else
            Log($"server push: mtu {session.PushedMtu} APPLIED (client mtu = 0/auto)");

        // DNS — the client's own dns list (if any) overrides the pushed resolver.
        if (string.IsNullOrEmpty(session.DnsIp))
            Log("server push: no DNS sent — on the server set dns.push_servers = <ip>, or dns.enabled = true + dns.listen");
        else if (config.DnsServers.Count > 0)
            Log($"server push: DNS {session.DnsIp} IGNORED — this client's own dns = " +
                $"{string.Join(", ", config.DnsServers)} overrides it (clear it to use the pushed one)");
        else
            Log($"server push: DNS {session.DnsIp} APPLIED");

        // Routes — each applied one is logged separately by ApplyPushedRoutes.
        if (nRoutes == 0)
            Log("server push: no routes sent — the server profile has no valid `route = <cidr> …` " +
                "(or this user's personal routes override it with an empty set)");
        else
            Log($"server push: {nRoutes} route(s) received — see the 'pushed route' lines below");

        if (session.MaxStreams > 1)
            Log($"server push: multipath max_streams={session.MaxStreams} adaptive={session.Adaptive}");
    }

    protected static List<string> EffectiveDns(VpnConfig config, Session session)
    {
        // `dns = off` / `dns = system` means LEAVE THE DEVICE RESOLVER ALONE, and it has to win
        // over everything below — including the public fallback, which is what the mode used to
        // collapse into: the profile asked us not to touch DNS and every lookup went to
        // Cloudflare and Google instead. (Audit 2026-08-02, §3.)
        if (config.DnsMode != "tunnel")
            return new List<string>();
        if (config.DnsServers.Count > 0)
            return config.DnsServers.Where(s => !string.IsNullOrEmpty(s)).ToList();
        if (!string.IsNullOrEmpty(session.DnsIp))
            return new List<string> { session.DnsIp };
        return config.IsFullTunnel ? new List<string> { "1.1.1.1", "8.8.8.8" } : new List<string>();
    }

    /// <summary>Active path-MTU discovery on a UDP transport (mirrors the Rust client).
    /// Sends DF-marked probes from <paramref name="ceiling"/> down a small ladder; each
    /// probe's wire size equals a full data packet of the candidate MTU, so the largest
    /// the server echoes is a size that traverses the path unfragmented. Returns that MTU
    /// or -1 (caller keeps the pushed/effective MTU) on any miss — purely additive.</summary>
    /// <summary>Rungs of the path-MTU ladder, in TUNNEL (inner) MTU units, highest first.
    /// Port of the Rust client's <c>mtu_probe_ladder</c>.
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
    /// gap. Same value in Rust, Kotlin and Swift.</summary>
    internal const int MtuRefineStepBytes = 256;

    /// <summary>Hard cap on refinement probes, so a pathological bracket cannot stretch the
    /// handshake.</summary>
    internal const int MtuRefineMaxProbes = 5;

    /// <summary>Next size to try between a rung known to WORK (<paramref name="lo"/>) and one
    /// known to FAIL (<paramref name="hi"/>), or -1 when the bracket is narrow enough to stop.
    /// Split out of the probe loop so the search is testable without a socket.</summary>
    internal static int MtuRefineStep(int lo, int hi) =>
        hi - lo <= MtuRefineStepBytes ? -1 : lo + (hi - lo) / 2;

    private int ProbeUdpMtu(UdpTransport t, int ceiling)
    {
        const int RecOverhead = 48; // qeli UDP record + margin, so a probe certifies a real packet
        if (!t.SetDontFragment(true)) return -1;
        var ladder = MtuProbeLadder(ceiling, RecOverhead + t.OuterOverhead);
        // Randomize the probe-id sequence per connection. A fixed start ("MT") plus a
        // predictable +1 per rung let an off-path attacker forge a probe-ACK and pin the client
        // to a too-large MTU — a DoS on fake-tls-UDP-without-obfs, where the probe rides in the
        // clear. A random 16-bit start means the attacker must guess the id too. Mirrors the
        // Rust client.
        ushort id = (ushort)RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);

        // One rung: send up to twice, accept only an ACK echoing this id AND this size.
        // Matching BOTH echoed fields is what stops a stale or forged ACK for a different rung
        // from pinning the client to an MTU the path cannot carry. (Audit 2026-07-30.)
        bool TryMtu(int m)
        {
            id++;
            int outerSize = m + RecOverhead;
            var probe = UdpFrag.MtuProbeDatagram(id, outerSize);
            if (probe == null) return false;
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try { t.Send(probe, longHeader: false); }
                catch { return false; } // WSAEMSGSIZE: the local link is smaller than this probe
                var payload = t.RecvRawPayload(220);
                if (payload != null && UdpFrag.IsMtuProbeAck(payload)
                    && UdpFrag.ParseMtuProbe(payload) is (ushort ackId, ushort ackSize)
                    && ackId == id && ackSize == outerSize)
                    return true;
            }
            return false;
        }

        // Coarse pass: walk the rungs high to low, keep the first that answers, and remember
        // the lowest that did NOT — that pair brackets the path's real MTU.
        int found = -1;
        int failedAbove = -1;
        foreach (int m in ladder)
        {
            if (TryMtu(m)) { found = m; break; }
            failedAbove = m;
        }

        // Refinement: the coarse pass certifies the best rung that FITS, not the path's
        // maximum. With rungs at 9000 and 6000 an 8999-byte path was pinned to 6000 and threw
        // away a third of every frame — the ladder can only land on its own numbers, so adding
        // rungs moves the loss around instead of removing it. Binary-search the bracket; `lo`
        // has always been proven to work, so a refinement that finds nothing better still
        // returns the coarse result. (Audit 2026-08-01, §8.)
        if (found > 0 && failedAbove > found)
        {
            int lo = found, hi = failedAbove;
            for (int i = 0; i < MtuRefineMaxProbes; i++)
            {
                int mid = MtuRefineStep(lo, hi);
                if (mid < 0) break;
                if (TryMtu(mid)) lo = mid; else hi = mid;
            }
            found = lo;
        }
        // Keep DF on success (packets <= the discovered MTU never fragment); allow
        // fragmentation again on a miss so behaviour is unchanged when probes are dropped.
        t.SetDontFragment(found > 0);
        return found;
    }

    /// <summary>H-1: when <c>BindStaticToSession</c> is set (the default since 0.7.1),
    /// compute the static-ephemeral DH <c>es = X25519(clientEphPriv, pinned server static pub)</c>
    /// so the data keys can be bound to the server identity. Returns null only when explicitly
    /// disabled (bind_static=false). Requires a real (non-zero) pinned key.</summary>
    private static byte[]? StaticEs(VpnConfig config, KeyExchange ke, byte[] clientPriv)
    {
        if (!config.BindStaticToSession) return null;
        if (string.IsNullOrEmpty(config.ServerPublicKeyHex))
            throw new Exception("bind_static_to_session is on but no server key is pinned; " +
                "set the server key (qeli show-identity) or set bind_static = false");
        var clean = new string(config.ServerPublicKeyHex.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        if (clean.Length != 64) throw new Exception("invalid server_public_key hex");
        var raw = Convert.FromHexString(clean);
        if (raw.All(b => b == 0))  // all-zero TOFU sentinel — an unpinned client cannot do H-1
            throw new Exception("bind_static_to_session is on but server_public_key is the all-zero " +
                "TOFU sentinel; pin the real server key or set bind_static = false");
        return ke.ComputeSharedSecret(clientPriv, raw);
    }

    /// <summary>Receive one record on UDP, re-sending <paramref name="resend"/> on a jittered
    /// ~1s tick until a datagram arrives or <paramref name="deadline"/> passes. Used for both
    /// handshake legs (ClientHello→ServerHello, auth→AuthOK), which share one deadline.</summary>
    private byte[] RecvUdpWithRetransmit(ITransport transport, byte[] resend, bool longHeader,
        VpnConfig config, long deadline, string expected, string what)
    {
        int sends = 1;   // the caller already sent it once
        // Bound Fill()'s internal fragment-reassembly loop by the SAME wall-clock deadline —
        // otherwise a flood of never-completing fragment datagrams spins inside a single
        // RecvRecord() past connection_timeout_secs (the outer deadline is only re-checked
        // between RecvRecord calls). Reset to "none" in the finally so the data plane blocks.
        transport.SetFillDeadline(deadline);
        try
        {
            while (true)
            {
                long left = deadline - Environment.TickCount64;
                if (left <= 0)
                    throw new TimeoutException(
                        $"UDP: no {expected} after {sends} {what} send(s) in {config.ConnectionTimeoutSecs}s");
                // Jitter the cadence so a fleet reconnecting after a shared outage does not
                // phase-lock on exact 1.000s ticks, and to blur the on-wire cadence.
                long round = Math.Min(HsRetransmitMs + System.Security.Cryptography.RandomNumberGenerator.GetInt32(0, 250), left);
                transport.SetReadTimeout((int)Math.Max(round, 1));
                try { return transport.RecvRecord(); }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut) { }
                transport.Send(resend, longHeader);   // ClientHello: re-sends every fragment
                sends++;
                if (sends == 2) Log($"UDP: no {expected} yet — re-sending {what}");
            }
        }
        finally
        {
            // Restore the full per-read budget for the remaining handshake legs.
            transport.SetReadTimeout((int)config.ConnectionTimeoutSecs * 1000);
            // No fill deadline in the data plane (RecvRecord must block for real data).
            transport.SetFillDeadline(long.MaxValue);
        }
    }

    private HsResult PerformHandshake(VpnConfig config, ITransport transport, int padToMin, bool isUdp = false)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();
        using var mlkem = MlKem.Generate(); // hybrid PQ: ML-KEM-768 keypair (server requires it)

        string sni = config.Sni ?? PickSni(config.ServerAddress);
        var clientHello = TlsHandshake.BuildClientHelloPq(
            clientKeyPair.PublicKeyBytes, mlkem.EncapsulationKey, sni, padToMin);
        transport.Send(clientHello, longHeader: true);
        Log($"ClientHello sent ({clientHello.Length}B, hybrid X25519+ML-KEM)");

        // Drain stale non-handshake records before the ServerHello: a UDP reconnect on a
        // fixed local port can receive leftover data-plane records (first byte 0x17, or
        // QUIC-unwrapped junk) from the previous, not-yet-kicked server session, which would
        // otherwise be mis-parsed as the ServerHello. Skip anything that is not a TLS
        // handshake record (0x16) until one arrives, bounded by MaxStalePreHandshakeRecords
        // and the per-read socket timeout. On TCP/reality-tls the first record is already the
        // ServerHello, so this is a no-op there.
        // UDP has no retransmit of its own, so a single dropped ClientHello datagram — routine
        // right after resume-from-sleep, or on a lossy / CGNAT path — used to stall this attempt
        // for the whole connection_timeout_secs before the outer loop retried from scratch. Drive
        // the wait off ONE overall deadline (shared with the stale-record drain below, so the two
        // can't add up) and re-send the ClientHello on a jittered ~1s tick, mirroring the Rust
        // client's hs_deadline / HS_RETRANSMIT_INTERVAL loop: the server's reassembler dedups
        // duplicate ClientHello fragments and continuation fragments are not re-charged by its
        // new-session rate limiter, so re-sending is safe.
        //
        // The reverse direction is repaired by the SAME re-send: the server caches its
        // ServerHello and re-emits it on a byte-identical ClientHello, so a dropped reply costs
        // about one RTT instead of the whole timeout. That is why the re-send must be the
        // identical bytes — the server matches on them. Only if that fails too does this reach
        // the deadline and the outer loop retry from a fresh local port. (This used to say the
        // server ignores handshake re-sends once it has the session; it has re-emitted since
        // 0.7.14.) TCP needs none of this (the kernel retransmits) and is untouched.
        byte[] serverHelloRecord;
        long hsDeadline = Environment.TickCount64 + (long)config.ConnectionTimeoutSecs * 1000;
        for (int skipped = 0; ; skipped++)
        {
            serverHelloRecord = isUdp
                ? RecvUdpWithRetransmit(transport, clientHello, longHeader: true, config, hsDeadline,
                    "ServerHello", "ClientHello")
                : transport.RecvRecord();
            if (serverHelloRecord.Length > 0 && (serverHelloRecord[0] & 0xFF) == 0x16) break;
            if (skipped >= MaxStalePreHandshakeRecords)
                throw new Exception("Failed to parse ServerHello");
            Log($"Skipped a stale pre-handshake record (0x{(serverHelloRecord.Length > 0 ? serverHelloRecord[0] : 0):x2})");
        }
        var serverHelloMsg = ParseHandshakeMessage(serverHelloRecord)
            ?? throw new Exception("Failed to parse ServerHello");
        var pq = TlsHandshake.ParseServerHelloPq(serverHelloMsg)
            ?? throw new Exception("Failed to parse hybrid ServerHello");
        var serverPublicKey = pq.ServerX25519;

        var rec = transport.RecvRecord();
        if (TlsHandshake.IsChangeCipherSpec(rec)) rec = transport.RecvRecord();
        var certRecord = rec;
        var finishedRecord = transport.RecvRecord();
        // F1: the post-ServerHello flight is parsed POSITIONALLY by record length, not
        // by peeking the type byte. All of Certificate/Finished/NewSessionTicket are now
        // 0x17 application_data records. Consume the one NST record here (its bytes are
        // NOT part of the transcript), then the next record is the encrypted auth-proof.
        _ = transport.RecvRecord(); // NewSessionTicket (0x17) — always exactly one, discarded

        // Auth proof binds to the classic X25519 ephemeral shared (server uses the same);
        // the ML-KEM secret only feeds the hybrid data-plane KDF.
        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var mlkemShared = mlkem.Decapsulate(pq.Ciphertext);
        var es = StaticEs(config, ke, clientKeyPair.PrivateKey); // H-1
        var (s2c, c2s) = es != null
            ? KeyDerivation.DeriveKeysHybridBound(sharedSecret, mlkemShared, es)
            : KeyDerivation.DeriveKeysHybrid(sharedSecret, mlkemShared);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax);
        var dec = new PacketCodec(new PacketCipher(s2c));

        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientHello, serverHelloRecord, certRecord, finishedRecord });

        // F1: no type peek — after the NST record above, exactly one more record is the
        // encrypted auth-proof (server flight order is fixed: Cert, Finished, NST, proof).
        var authRec = transport.RecvRecord();
        var authProofMsg = dec.Decrypt(authRec);
        var (staticPub, staticShared) = VerifyServerAuth(
            authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash,
            config.ServerPublicKeyHex, $"{config.ServerAddress}:{config.Port}");
        Log("Server identity verified [OK]");

        var authPlain = BuildClientAuthPlaintext(config, staticShared, sharedSecret, transcriptHash);
        // Encrypt ONCE and re-send the identical inner bytes (only the QUIC wrapper's packet
        // number changes per send): a duplicate that reaches the server is replay-dropped, while
        // a re-send after loss is processed as the real auth. Re-encrypting per send would
        // instead advance this codec's counter past what the server has actually seen.
        var authPacket = enc.Encrypt(authPlain);
        transport.Send(authPacket);

        // Leg 2, same treatment as the ClientHello above and bounded by the SAME hsDeadline, so
        // the whole UDP handshake still fits one connection_timeout_secs: a dropped auth datagram
        // (client->server) recovers in ~1-2s instead of stalling the full timeout.
        //
        // A dropped AuthOK (server->client) is repaired by the SAME retransmit: the server caches
        // it and re-emits on a byte-identical AUTH, up to a small per-session cap — which is why
        // the identical inner bytes above matter, the server matches on them. Only once the cap is
        // spent does this fall through to the deadline and a fresh-port reconnect, which redoes
        // the whole handshake cleanly. (This used to say the server never re-emits; it has since
        // 0.7.14.)
        //
        // A record that decrypts is not automatically the AuthOK. Server cover and heartbeat
        // traffic carries an EMPTY payload and is encrypted with these very keys, so it
        // decrypts perfectly and used to be accepted here — then failed the `OK:` check below
        // with "Auth failed: " and nothing after it. The server no longer emits either before
        // the AuthOK, but UDP still loses and reorders: the AuthOK can be dropped while the
        // beacon that follows it arrives. "Empty is not an answer" holds whoever is on the
        // other end, and the retransmit above is already the right place to wait.
        //
        // Deliberately NOT "anything that isn't OK:": a non-empty refusal from the server must
        // still fail fast rather than spin until the deadline. (Audit 2026-08-03, P1.)
        byte[] authResponse;
        if (isUdp)
        {
            do
            {
                authResponse = dec.Decrypt(RecvUdpWithRetransmit(
                    transport, authPacket, longHeader: false, config, hsDeadline, "AuthOK", "auth"));
                if (authResponse.Length == 0)
                    Log("UDP: server cover/beacon arrived before the AuthOK — still waiting");
            } while (authResponse.Length == 0);
        }
        else
        {
            authResponse = dec.Decrypt(transport.RecvRecord());
        }
        var authStr = Encoding.UTF8.GetString(authResponse);
        if (!authStr.StartsWith("OK:", StringComparison.Ordinal))
            throw new Exception($"Auth failed: {authStr}");
        var (session, obf) = ParseOk(authStr);

        var effConfig = config;
        var pushed = DecodePushedObf(obf);
        if (pushed != null)
        {
            enc.SetPadding(pushed.PaddingEnabled, pushed.PaddingMin, pushed.PaddingMax);
            effConfig = config.WithPushedObf(pushed.HbEnabled, pushed.HbIntervalMs, pushed.HbJitterMs, pushed.HbDataSize,
                pushed.ShEnabled, pushed.ShGapMeanMs, pushed.ShGapMinMs, pushed.ShGapMaxMs,
                pushed.ShBudget, pushed.ShMinSize, pushed.ShMaxSize,
                pushed.ShStealth, pushed.ShStealthRateMbps);
            Log("Applied server-pushed obfuscation params");
        }
        return new HsResult(session, effConfig, enc, dec, pushed);
    }

    /// <summary>
    /// `plain` wire mode handshake: no TLS mimicry. Exchange ephemeral X25519 publics
    /// raw, bind the channel to H(client_pub‖server_pub), then run the same encrypted
    /// auth flow over bare length-prefixed records. Mirrors qeli/src/client/mod.rs.
    /// </summary>
    private HsResult PerformHandshakePlain(VpnConfig config, SocketIO io)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();

        // 1. Raw exchange of the 32-byte ephemeral public keys (no framing).
        io.WriteFully(clientKeyPair.PublicKeyBytes);
        var serverPublicKey = io.ReadRaw(32);
        Log("plain: exchanged ephemeral keys");

        // 2. Transcript binds to both raw publics.
        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientKeyPair.PublicKeyBytes, serverPublicKey });

        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var es = StaticEs(config, ke, clientKeyPair.PrivateKey); // H-1
        var (s2c, c2s) = es != null
            ? KeyDerivation.DeriveKeysBound(sharedSecret, es)
            : KeyDerivation.DeriveKeys(sharedSecret);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax, raw: true);
        var dec = new PacketCodec(new PacketCipher(s2c), raw: true);

        // 3. Server auth proof (raw record).
        var authProofMsg = dec.Decrypt(io.ReadRawRecord());
        var (_, staticShared) = VerifyServerAuth(
            authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash,
            config.ServerPublicKeyHex, $"{config.ServerAddress}:{config.Port}");
        Log("Server identity verified [OK] (plain)");

        // 4. Client auth.
        var authPlain = BuildClientAuthPlaintext(config, staticShared, sharedSecret, transcriptHash);
        io.WriteFully(enc.Encrypt(authPlain));

        // 5. Auth response.
        var authResponse = dec.Decrypt(io.ReadRawRecord());
        var authStr = Encoding.UTF8.GetString(authResponse);
        if (!authStr.StartsWith("OK:", StringComparison.Ordinal))
            throw new Exception($"Auth failed: {authStr}");
        var (session, obf) = ParseOk(authStr);

        var effConfig = config;
        var pushed = DecodePushedObf(obf);
        if (pushed != null)
        {
            enc.SetPadding(pushed.PaddingEnabled, pushed.PaddingMin, pushed.PaddingMax);
            effConfig = config.WithPushedObf(pushed.HbEnabled, pushed.HbIntervalMs, pushed.HbJitterMs, pushed.HbDataSize,
                pushed.ShEnabled, pushed.ShGapMeanMs, pushed.ShGapMinMs, pushed.ShGapMaxMs,
                pushed.ShBudget, pushed.ShMinSize, pushed.ShMaxSize,
                pushed.ShStealth, pushed.ShStealthRateMbps);
            Log("Applied server-pushed obfuscation params");
        }
        return new HsResult(session, effConfig, enc, dec, pushed);
    }

    private (Session, JsonObject?) ParseOk(string authStr)
    {
        var json = JsonNode.Parse(authStr.Substring("OK:".Length))!.AsObject();
        string clientIp = (json["client_ip"] as JsonValue)?.GetValue<string>() ?? "";
        if (clientIp.Length == 0) throw new Exception("server OK response missing client_ip");
        // Server-pushed strings are interpolated into netsh/route command lines, so a
        // malicious server could smuggle an argument-injection payload here. Accept the
        // client_ip only as a strict IP literal; anything else aborts the session.
        if (!IsStrictIp(clientIp)) throw new Exception("server pushed an invalid client_ip");
        // VPN subnet prefix (default /24 when an older server omits it).
        int prefix = (json["prefix"] as JsonValue)?.GetValue<int>() ?? 24;
        if (prefix is < 1 or > 32) prefix = 24;
        string dns = (json["dns"] as JsonValue)?.GetValue<string>() ?? "";
        // A non-IP dns would reach `netsh ... set dnsservers`; blank it out so the
        // caller's IsNullOrEmpty filter drops it instead of pushing it to a command line.
        if (dns.Length != 0 && !IsStrictIp(dns)) dns = "";
        string routes = json["routes"] is JsonArray arr ? arr.ToJsonString() : "[]";
        // Server-pushed MTU; out-of-range/absent => 0 (not pushed).
        int mtu = (json["mtu"] as JsonValue)?.GetValue<int>() ?? 0;
        if (mtu is < 576 or > 16638) mtu = 0;   // see VpnConfig.MtuMax
        // Stream-bonding push (handler.rs::build_auth_ok). Absent on older servers =>
        // token "", maxStreams 1, adaptive false => single stream.
        string token = (json["session_token"] as JsonValue)?.GetValue<string>() ?? "";
        int maxStreams = (json["max_streams"] as JsonValue)?.GetValue<int>() ?? 1;
        if (maxStreams is < 1 or > 64) maxStreams = 1;
        bool adaptive = (json["multipath_adaptive"] as JsonValue)?.GetValue<bool>() ?? false;
        return (new Session(clientIp, prefix, dns, routes, mtu, token, maxStreams, adaptive),
            json["obfuscation"] as JsonObject);
    }

    private sealed record PushedObf(bool PaddingEnabled, int PaddingMin, int PaddingMax,
        bool HbEnabled, long HbIntervalMs, long HbJitterMs, int HbDataSize,
        bool ShEnabled, long ShGapMeanMs, long ShGapMinMs, long ShGapMaxMs,
        int ShBudget, int ShMinSize, int ShMaxSize,
        bool ShStealth, int ShStealthRateMbps);

    private static PushedObf? DecodePushedObf(JsonObject? obf)
    {
        if (obf == null) return null;
        var pad = obf["padding"] as JsonObject ?? new JsonObject();
        var hb = obf["heartbeat"] as JsonObject ?? new JsonObject();
        var sh = obf["traffic_shaping"] as JsonObject ?? new JsonObject();
        int GetInt(JsonObject o, string k, int d) => o[k] is JsonValue v && v.TryGetValue(out int i) ? i : d;
        long GetLong(JsonObject o, string k, long d) => o[k] is JsonValue v && v.TryGetValue(out long l) ? l : d;
        bool GetBool(JsonObject o, string k, bool d) => o[k] is JsonValue v && v.TryGetValue(out bool b) ? b : d;
        // Everything the server sizes is clamped to a wire-plausible range HERE, at the one
        // place AuthOK's obfuscation object is decoded, so no send path can be handed a value
        // PacketCodec will refuse. Unclamped these reached enc.SetPadding / the shaper as-is
        // and a single oversized max_bytes / max_size turned every TCP data packet into a
        // PacketException — drop, reconnect, same values, drop. (Audit 2026-07-27, N2)
        int Bounded(JsonObject o, string k, int d) => Math.Clamp(GetInt(o, k, d), 0, PadWireCeiling);
        int padMin = Bounded(pad, "min_bytes", 0);
        int padMax = Math.Max(Bounded(pad, "max_bytes", 255), padMin);
        int shMin = Bounded(sh, "min_size", 64);
        int shMax = Math.Max(Bounded(sh, "max_size", 1024), shMin);
        return new PushedObf(
            GetBool(pad, "enabled", true), padMin, padMax,
            GetBool(hb, "enabled", true), GetLong(hb, "interval_ms", 15000), GetLong(hb, "jitter_ms", 2000),
            // The heartbeat's padded size. The keepalive is padded to this now, so dropping
            // the pushed value left the server's choice unused and the local default in its
            // place — the one knob the server has for making the beat less recognisable did
            // nothing. Clamped like every other sized field here. (Audit 2026-07-29, #9.)
            Bounded(hb, "data_size_bytes", 16),
            GetBool(sh, "enabled", false), GetLong(sh, "idle_gap_mean_ms", 700),
            GetLong(sh, "idle_gap_min_ms", 40), GetLong(sh, "idle_gap_max_ms", 6000),
            GetInt(sh, "budget_bytes_per_sec", 16384), shMin, shMax,
            GetBool(sh, "stealth", false), GetInt(sh, "stealth_rate_mbps", 2));
    }

    private (byte[] staticPub, byte[] staticShared) VerifyServerAuth(
        byte[] msg, byte[] clientPriv, byte[] ephemeralShared, byte[] transcriptHash,
        string? pinnedHex, string serverId)
    {
        var ke = new KeyExchange();
        byte[]? pinnedBytes = null;
        if (!string.IsNullOrEmpty(pinnedHex))
        {
            var clean = new string(pinnedHex.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
            if (clean.Length == 64) pinnedBytes = Convert.FromHexString(clean);
        }

        byte[] serverStaticPub, receivedProof;
        // Set to the hex key to pin once the proof below verifies; null = nothing to pin.
        string? pinOnSuccess = null;
        if (msg.Length >= 64)
        {
            serverStaticPub = msg[..32];
            receivedProof = msg[32..64];
            if (pinnedBytes != null)
            {
                if (!serverStaticPub.SequenceEqual(pinnedBytes))
                    throw new SecurityException("SERVER KEY MISMATCH - possible MITM");
            }
            else
            {
                // No explicit pin -> trust-on-first-use WITH persistence (parity with
                // the Rust client's known_hosts). CHECK an existing pin now (fail fast
                // on a changed key); RECORD a new one only after the proof verifies
                // below.
                //
                // Recording before verification let ANY injected reply poison the pin
                // permanently: the bogus key was written, the proof then failed and the
                // connect aborted — but the record stayed, so the real server was
                // rejected as a MITM on every later attempt until the user found and
                // deleted the line by hand. One forged packet, indefinite lockout.
                var receivedHex = Convert.ToHexString(serverStaticPub).ToLowerInvariant();
                pinOnSuccess = !CheckKnownHost(serverId, receivedHex) ? receivedHex : null;
            }
        }
        else if (msg.Length >= 32)
        {
            serverStaticPub = pinnedBytes
                ?? throw new SecurityException("server sent proof-only but no server_public_key pinned");
            receivedProof = msg[..32];
        }
        else throw new SecurityException($"server auth message too short: {msg.Length}");

        var staticShared = ke.ComputeSharedSecret(clientPriv, serverStaticPub);
        var expected = KeyDerivation.DeriveAuthProof(staticShared, ephemeralShared, transcriptHash);
        if (!CryptographicOperations.FixedTimeEquals(receivedProof, expected))
            throw new SecurityException("server auth proof INVALID");
        // Proof verified: the peer holds the private key for the key it presented, so
        // this is now worth remembering. Anything that failed above never reaches here
        // and therefore cannot leave a pin behind.
        if (pinOnSuccess != null) RecordKnownHost(serverId, pinOnSuccess);
        return (serverStaticPub, staticShared);
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
    private void RecordKnownHost(string serverId, string receivedHex)
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
                Log($"WARN: could not record server key in {path} ({e.Message}); MITM protection " +
                    "NOT pinned this run. Set server_public_key to pin explicitly.");
            }
        }
    }

    private static byte[] BuildClientAuthPlaintext(VpnConfig config, byte[] staticShared,
        byte[] ephemeralShared, byte[] transcriptHash)
    {
        var proof = KeyDerivation.DeriveClientKeyProof(staticShared, ephemeralShared, transcriptHash);
        var creds = Encoding.UTF8.GetBytes($"{config.Username}:{config.Password}");
        // Present this device's stable id (marker 0x00 + 16 bytes) so the server keys
        // the session/pool IP by device: several devices of one login coexist, and the
        // SAME device cleanly supersedes its own old session on an IP change.
        var deviceId = DeviceId();
        var outBuf = new byte[proof.Length + 1 + deviceId.Length + creds.Length];
        Buffer.BlockCopy(proof, 0, outBuf, 0, proof.Length);
        outBuf[proof.Length] = 0;
        Buffer.BlockCopy(deviceId, 0, outBuf, proof.Length + 1, deviceId.Length);
        Buffer.BlockCopy(creds, 0, outBuf, proof.Length + 1 + deviceId.Length, creds.Length);
        return outBuf;
    }

    /// <summary>Load (or first-time generate + persist) this device's stable 16-byte id,
    /// kept under LocalApplicationData so it survives restarts and reconnects. An
    /// unwritable host falls back to a per-run id (still works, just not stable there).</summary>
    private static readonly object _deviceIdLock = new();
    private static byte[]? _deviceId;
    private static byte[] DeviceId()
    {
        // Resolve once per process under a lock: concurrent callers (e.g. the
        // primary plus bonded streams starting together) must not race to
        // generate and persist two different ids (T9).
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

    /// <summary>Tear down platform networking handles (routes/DNS) on disconnect.</summary>
    protected virtual void CleanupPlatform() { }

    /// <summary>Mark a carrier socket so a platform packet filter does not capture it
    /// (Windows WinDivert: set TTL=<c>111</c>). Default no-op; called for every outbound
    /// tunnel socket (primary TCP/UDP and bonded secondaries).</summary>
    protected virtual void ProtectCarrierSocket(Socket socket) { }

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
        if (!NetworkDnsFailed || !config.KillSwitch || !config.IsFullTunnel) return;
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

    // Wake / dead-link detection knobs (shared by the single-path and bonded loops).
    //  • WatchdogPollMs   — how often the UDP RX path re-checks liveness (its read timeout).
    //  • SuspendGapMs     — wall clock advanced this much MORE than the monotonic clock
    //                       between two checks ⇒ the host was asleep; the server session +
    //                       NAT mapping are almost certainly gone → reconnect now instead of
    //                       waiting out the (monotonic, sleep-frozen) rxDead window.
    //  • TxActiveMs       — "we are actively relaying user uplink" window.
    //  • TxRxAsymmetryMs  — user uplink active but ZERO downlink for this long ⇒ the session
    //                       is dead (a live tunnel always returns ACKs/data). Independent of
    //                       heartbeat/shaping, so it also covers the both-off profiles.
    private const int WatchdogPollMs = 3000;
    private const int SuspendGapMs = 10_000;
    private const int TxActiveMs = 2000;
    private const int TxRxAsymmetryMs = 8000;

    // ── tunnel loop ──────────────────────────────────────────────────────────────
    /// <summary>Re-send delays for the unacknowledged MTU report on UDP, measured as successive GAPS, so the copies land ~2 s and ~8 s after the first.
    /// Spread so an isolated drop AND a short burst of loss are both survived.</summary>
    private static readonly int[] ReportRetryDelaysMs = { 2_000, 6_000 };

    /// <summary>Tell the server the MTU we settled on (#13). It sizes its downlink from the
    /// profile's tun.mtu — the path up to ITS tun — so it cannot see that our leg is narrower
    /// (a probed LTE/CGNAT path, or an explicit smaller Mtu in our config). Without this, every
    /// large packet it forwards is dropped with no signal to anyone: the connection establishes
    /// and then stalls on the first big transfer.
    ///
    /// The frame is unacknowledged by design (the server never answers a control frame), so on
    /// UDP a single lost datagram would leave the server on <c>path_mtu = 0</c> for the WHOLE
    /// session — on precisely the unreliable transport where the report matters most. The frame
    /// is idempotent (the server simply stores the latest value, and the copies all carry the same one), so re-sending costs a
    /// few bytes and removes that single point of loss. TCP retransmits for us, so it sends
    /// once. (Audit 2026-07-30, #5.)
    ///
    /// Never fatal: the tunnel works without the report, just without the downlink narrowing.</summary>
    /// <summary>Tell the server what this build is, so `list-clients` and the panel can answer
    /// "who still needs to update?". Sent once per attempt on the same authenticated in-tunnel
    /// path as the MTU report, and nothing waits for a reply — a server that predates the frame
    /// discards it and shows the session as unknown, exactly as before.
    ///
    /// No re-send on UDP, unlike the MTU report: losing this costs a label in an operator's
    /// table, not the session's downlink sizing.</summary>
    private void ReportClientInfo(ITransport transport, PacketCodec enc)
    {
        var frame = CtrlFrame.ThisBuild();
        if (frame == null) return;
        try
        {
            // No padding, for the same reason as the MTU report above.
            transport.Send(enc.EncryptPadded(frame, 0));
        }
        catch (Exception e)
        {
            // Never fatal: this is diagnostics. A real transport failure surfaces in the loop.
            Log($"could not report client version: {e.Message}");
        }
    }

    private void ReportTunnelMtu(ITransport transport, PacketCodec enc, int mtu, bool isUdp,
        CancellationToken ct)
    {
        bool SendOnce(int attempt)
        {
            try
            {
                // EncryptPadded(…, 0): NO padding, like the Rust client. Plain Encrypt applies
                // the configured padding, so with padding_min near the MTU a six-byte control
                // frame became a datagram larger than the path MTU we just discovered — and
                // under DF it failed with EMSGSIZE, every re-send identically. The server then
                // never learned the MTU at all. (Audit 2026-07-31, §6.)
                transport.Send(enc.EncryptPadded(CtrlFrame.MtuReport(mtu), 0));
                if (attempt == 0) Log($"reported tunnel MTU {mtu} to the server");
                return true;
            }
            catch (Exception e)
            {
                if (attempt == 0) Log($"could not report tunnel MTU: {e.Message}");
                return false;
            }
        }

        if (!SendOnce(0) || !isUdp) return;
        _ = Task.Run(async () =>
        {
            for (int i = 0; i < ReportRetryDelaysMs.Length; i++)
            {
                try { await Task.Delay(ReportRetryDelaysMs[i], ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                if (!SendOnce(i + 1)) return;
            }
        }, ct);
    }

    private void RunTunnelLoop(VpnConfig config, ITransport transport,
        PacketCodec enc, PacketCodec dec, bool isUdp, int effectiveMtu, CancellationToken ct)
    {
        var tun = _tun!;
        // Per-attempt cancellation, linked to the global (user-Stop) token. Cancelling
        // THIS also tears down a server-side DROP — the global ct is only tripped by the
        // user's Stop(), so without it a dropped-then-reconnecting attempt could leave the
        // upload thread parked in tun.ReceivePacket while CloseTransports disposed the TUN
        // underneath it (the reconnect-time use-after-free crash, issue #69). We cancel it
        // and JOIN the workers before returning, so the TUN is only ever disposed with no
        // thread inside it.
        using var loopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var lct = loopCts.Token;
        long lastRx = Environment.TickCount64;
        // Last time we relayed a USER uplink packet (not a keepalive) — drives the
        // uplink-active/downlink-silent dead-session check below.
        long lastTx = Environment.TickCount64;
        long rxDead = Math.Max(config.HeartbeatIntervalMs * 3, 30_000);
        // Only reconnect on server silence when the server is EXPECTED to be sending (its
        // heartbeat on, or shaping). With both off there is no server->client traffic to
        // gauge liveness, so a silence-based reconnect would storm.
        bool expectServerData = (config.HeartbeatEnabled && config.HeartbeatIntervalMs > 0) || config.ShapingEnabled;
        var firstError = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Fail(Exception e) => firstError.TrySetResult(e);

        ReportTunnelMtu(transport, enc, effectiveMtu, isUdp, ct);
        ReportClientInfo(transport, enc);

        // Poll the UDP RX path every WatchdogPollMs (not once per rxDead) so suspend/resume
        // and dead-session detection run promptly — the read simply times out when idle.
        if (isUdp) transport.SetReadTimeout(WatchdogPollMs);

        // Upload: system -> tunnel (read Wintun outbound packets, encrypt, send).
        // Stealth (TCP-only): rate-cap the uplink to stealth_rate and fill the cap
        // gaps with jittered small cover, so an upload stops looking like a high-rate
        // bulk transfer (mirrors the Rust client). The server already shapes the
        // downlink for every client; this is the matching uplink half.
        var uploadJob = Task.Run(() =>
        {
            var upShaper = new TrafficShaper(config.ShapingEnabled, config.ShapingGapMeanMs,
                config.ShapingGapMinMs, config.ShapingGapMaxMs, config.ShapingBudgetBytesPerSec,
                config.ShapingMinSize, config.ShapingMaxSize, config.ShapingStealth, config.ShapingStealthRateMbps);
            bool upStealth = upShaper.Stealth && !isUdp;
            var jit = new Random();
            try
            {
                while (!lct.IsCancellationRequested)
                {
                    var pkt = tun.ReceivePacket(lct);
                    if (pkt == null) break;                 // session ended / torn down
                    if (pkt.Length == 0) continue;
                    if ((pkt[0] >> 4) != 4) continue;        // IPv4 only
                    // Cap padding so the padded record stays inside the (probed) tunnel MTU:
                    // with DF set after the MTU probe, the server-pushed 40–400 B of padding
                    // otherwise blows a full-size data packet past the path MTU → the kernel
                    // rejects it with WSAEMSGSIZE. On UDP that must DROP the datagram (inner
                    // TCP retransmits), never tear the tunnel down — a dead link is caught by
                    // the RX-liveness timeout. TCP is an in-order stream, so a write error
                    // there IS fatal. (This EMSGSIZE-was-fatal path put udp-quic into an
                    // endless auth→drop→reconnect loop.)
                    // TCP takes the SAME per-packet cap, just against the fixed 1400-byte
                    // budget the Rust client uses instead of the probed MTU: enc.Encrypt(pkt)
                    // applied the server-pushed padding_max verbatim, so an oversized pushed
                    // value threw PacketException here and dropped the tunnel on every
                    // reconnect. (Audit 2026-07-27, N2)
                    try
                    {
                        transport.Send(enc.EncryptCapped(pkt, isUdp ? effectiveMtu : PadCapInner));
                    }
                    catch (Exception) when (isUdp) { continue; } // drop-on-egress-error (UDP loss)
                    Interlocked.Add(ref _bytesUp, pkt.Length);
                    Interlocked.Exchange(ref lastTx, Environment.TickCount64); // user uplink is flowing
                    if (upStealth)
                    {
                        long remaining = upShaper.StealthPaceMs(pkt.Length);
                        while (remaining > 6 && !lct.IsCancellationRequested)
                        {
                            int csize = upShaper.NextSize();
                            if (upShaper.TrySpend(csize))
                                transport.Send(enc.EncryptPadded(Array.Empty<byte>(), csize));
                            int step = Math.Min((int)remaining, jit.Next(4, 19));
                            if (lct.WaitHandle.WaitOne(step)) break;
                            remaining -= step;
                        }
                    }
                }
            }
            catch (Exception e) { Fail(e); }
        }, lct);

        // Download: tunnel -> system (recv record, decrypt, inject into Wintun).
        var downloadJob = Task.Run(() =>
        {
            // Suspend detector baseline: the differential between the wall clock and the
            // monotonic clock across poll ticks. Awake, both advance together (drift ≈ 0);
            // across a sleep the monotonic clock freezes while the wall clock keeps going,
            // so the differential ≈ the sleep duration.
            long lastWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long lastTick = Environment.TickCount64;
            try
            {
                while (!lct.IsCancellationRequested)
                {
                    byte[] rec;
                    try { rec = transport.RecvRecord(); }
                    catch (SocketException se) when (se.SocketErrorCode == SocketError.TimedOut)
                    {
                        long nowTick = Environment.TickCount64;
                        long nowWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        long drift = (nowWall - lastWall) - (nowTick - lastTick);
                        lastWall = nowWall; lastTick = nowTick;
                        // L1 — resumed from sleep: session + NAT almost certainly gone.
                        if (drift > SuspendGapMs)
                        { Fail(SuspendResumed(drift)); break; }
                        // L2 — user uplink active but nothing coming back ⇒ dead session
                        // (covers a network change with no suspend, and heartbeat+shaping-off).
                        if (nowTick - Interlocked.Read(ref lastTx) < TxActiveMs
                            && nowTick - Interlocked.Read(ref lastRx) > TxRxAsymmetryMs)
                        { Fail(new Exception($"uplink active but no downlink for >{TxRxAsymmetryMs / 1000}s — reconnecting")); break; }
                        // Server-silence window (only when the server is expected to send).
                        if (expectServerData && nowTick - Interlocked.Read(ref lastRx) > rxDead)
                        { Fail(new Exception($"no data from server for >{rxDead / 1000}s")); break; }
                        continue;
                    }
                    byte[] plaintext;
                    if (isUdp) { try { plaintext = dec.Decrypt(rec); } catch { continue; } }
                    else plaintext = dec.Decrypt(rec);
                    Interlocked.Exchange(ref lastRx, Environment.TickCount64);
                    if (plaintext.Length > 0)
                    {
                        tun.SendPacket(plaintext, plaintext.Length);
                        Interlocked.Add(ref _bytesDown, plaintext.Length);
                    }
                }
            }
            catch (Exception e) { Fail(e); }
        }, lct);

        // Heartbeat OR — when flow-shaping is on — Poisson idle cover. Cover
        // replaces the fixed heartbeat: the same empty encrypted record the peer
        // drops, but at exponential (non-periodic) gaps and browsing-ish sizes,
        // capped by a byte budget (DPI-AUDIT 6.1/6.2). Budget bounds cover during
        // active transfer, so no separate idle-gate is needed here.
        var heartbeatJob = Task.Run(() =>
        {
            var shaper = new TrafficShaper(config.ShapingEnabled, config.ShapingGapMeanMs,
                config.ShapingGapMinMs, config.ShapingGapMaxMs, config.ShapingBudgetBytesPerSec,
                config.ShapingMinSize, config.ShapingMaxSize);
            bool hbOn = config.HeartbeatEnabled && config.HeartbeatIntervalMs > 0;
            // Always send the client->server keepalive unless flow-shaping (cover replaces
            // it). The server reaps a session after idle_timeout_secs (default 300s) of
            // client->server SILENCE even when ITS heartbeat is off — server->client
            // heartbeats do NOT count — so a keepalive gated on hbOn gets FIN'd every ~5
            // min on a heartbeat-off/idle-timeout-on profile. Fall back to 30s when off.
            long kaIntervalMs = hbOn ? config.HeartbeatIntervalMs : 30_000;
            var rng = RandomNumberGenerator.Create();
            // TCP suspend detector (the UDP path is covered by the download-job poll above).
            long hbLastWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long hbLastTick = Environment.TickCount64;
            while (!lct.IsCancellationRequested)
            {
                long wait = shaper.Enabled
                    ? Math.Max(shaper.NextGapMs(), 1)
                    : Math.Max(kaIntervalMs + JitterMs(rng, config.HeartbeatJitterMs), 1000);
                if (lct.WaitHandle.WaitOne((int)wait)) break;
                if (!isUdp)
                {
                    long nTick = Environment.TickCount64, nWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    long drift = (nWall - hbLastWall) - (nTick - hbLastTick);
                    hbLastWall = nWall; hbLastTick = nTick;
                    if (drift > SuspendGapMs) { Fail(SuspendResumed(drift)); break; }
                }
                try
                {
                    if (shaper.Enabled)
                    {
                        // Cap cover size to the (probed) MTU on UDP so a DF-marked cover
                        // datagram isn't rejected with WSAEMSGSIZE (same reason as data).
                        int size = shaper.NextSize();
                        if (isUdp) size = Math.Min(size, Math.Max(0, effectiveMtu - 60));
                        if (shaper.TrySpend(size)) transport.Send(enc.EncryptPadded(Array.Empty<byte>(), size));
                    }
                    else transport.Send(enc.EncryptPadded(Array.Empty<byte>(),
                        HeartbeatPadLen(config, effectiveMtu, isUdp, rng)));
                }
                // A failed keepalive/cover send is not fatal on UDP (drop, like data); liveness
                // is detected by the RX timeout. On TCP a write error is fatal.
                catch (Exception) when (isUdp) { continue; }
                catch (Exception e) { Fail(e); break; }
                // RX-liveness reconnect only when the server is expected to be sending
                // (its heartbeat on, or shaping) — otherwise a silent-by-design server
                // would trigger a reconnect storm.
                if (!isUdp && (hbOn || shaper.Enabled)
                    && Environment.TickCount64 - Interlocked.Read(ref lastRx) > rxDead)
                { Fail(new Exception($"no data from server for >{rxDead / 1000}s")); break; }
            }
        }, lct);

        // Block until the first data-plane error or cancellation. Register a callback on the
        // global stop token to complete `firstError` — the old Task.Run(ct.WaitHandle.WaitOne())
        // parked a thread-pool thread on the user-Stop handle that was never joined when the
        // loop ended on a server drop, leaking one thread per reconnect on a flaky link.
        Exception error;
        using (ct.Register(() => firstError.TrySetResult(new OperationCanceledException())))
        {
            error = firstError.Task.GetAwaiter().GetResult();
        }

        GracefulClose(_tcp);
        try { _udp?.Close(); } catch { }
        // Cancel the per-attempt token so the TUN reader (parked in ReceivePacket) and the
        // heartbeat sleeper wake and exit, then JOIN them before returning — the caller
        // (ConnectWithRetry / Stop) disposes the TUN right after, and it must be idle.
        loopCts.Cancel();
        try { Task.WaitAll(new[] { uploadJob, downloadJob, heartbeatJob }, 3000); } catch { }

        if (!ct.IsCancellationRequested && error is not OperationCanceledException)
            throw error; // let ConnectWithRetry decide whether to reconnect
    }

    // ── TCP framing / raw IO (obfs-aware) ────────────────────────────────────────
    private byte[]? ParseHandshakeMessage(byte[] record)
    {
        if (record.Length < 6) return null;
        if ((record[0] & 0xFF) != 0x16) return null;
        int payloadLen = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
        if (record.Length < 5 + payloadLen) return null;
        return record[5..(5 + payloadLen)];
    }

    // ── per-socket IO (one instance per bonded stream) ───────────────────────────
    // Each connection (primary + every secondary bonded stream) owns one SocketIO:
    // its own socket, optional obfs transform, and write lock. The framed read/write
    // helpers used to be instance methods bound to the single _tcp; making them
    // per-socket is what lets several connections run in parallel for stream bonding.
    private sealed class SocketIO
    {
        public readonly Socket Sock;
        public ObfsStream? Obfs;
        private readonly object _writeLock = new();
        public SocketIO(Socket sock) { Sock = sock; }

        public void WriteFully(byte[] data)
        {
            if (Obfs == null) { WriteRaw(data); return; }
            // The ChaCha20 keystream advance (TransformWrite) and the socket send MUST be
            // one atomic step. With two concurrent writers on this stream (the upload loop
            // and the heartbeat/cover task) each ciphering then sending under SEPARATE
            // locks, a second writer could cipher after the first yet SEND before it — the
            // peer then XORs those bytes against the wrong keystream offset and the tunnel
            // desyncs/resets. Holding the socket write lock across transform+frame+send makes
            // records leave in exactly the keystream order they were ciphered. (Monitor is
            // reentrant, so the inner WriteRaw re-taking _writeLock on this thread is fine.)
            lock (_writeLock)
            {
                var cipherbytes = Obfs.TransformWrite(data);
                // F3: under WebSocket fronting the ciphered bytes travel as masked
                // client->server binary frames; otherwise they go out as the raw
                // continuous ChaCha20-XOR stream (byte-identical to the pre-F3 wire).
                WriteRaw(Obfs.WsActive ? Obfs.WsWrap(cipherbytes) : cipherbytes);
            }
        }

        public void WriteRaw(byte[] data)
        {
            lock (_writeLock)
            {
                int off = 0;
                while (off < data.Length)
                {
                    int n = Sock.Send(data, off, data.Length - off, SocketFlags.None);
                    if (n <= 0) throw new Exception("Connection closed");
                    off += n;
                }
            }
        }

        public byte[] ReadTlsRecord()
        {
            var header = ReadBytes(5);
            int payloadLen = ((header[3] & 0xFF) << 8) | (header[4] & 0xFF);
            // Cap at MaxRecordSize (not the u16 ceiling): parity with the Rust read_tls_record
            // early cap. A peer/MITM otherwise makes us buffer up to 64 KB per record before
            // PacketCodec rejects it. All qeli records (handshake + data) fit MaxRecordSize —
            // the Rust client the server also talks to enforces the same bound. (client-audit LOW)
            if (payloadLen > PacketCodec.MaxRecordSize)
                throw new Exception($"TLS record too large: {payloadLen} > {PacketCodec.MaxRecordSize}");
            var body = ReadBytes(payloadLen);
            var rec = new byte[5 + payloadLen];
            Buffer.BlockCopy(header, 0, rec, 0, 5);
            Buffer.BlockCopy(body, 0, rec, 5, payloadLen);
            return rec;
        }

        /// <summary>Read one bare length-prefixed record ([u16 len][nonce][ct]) for
        /// the `plain` wire mode. Mirrors read_record(Framing::Raw) on the Rust side.</summary>
        public byte[] ReadRawRecord()
        {
            var header = ReadBytes(2);
            int payloadLen = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF);
            // Match ReadTlsRecord / the Rust reader: cap at MaxRecordSize, not the u16 ceiling.
            if (payloadLen > PacketCodec.MaxRecordSize)
                throw new Exception($"raw record too large: {payloadLen} > {PacketCodec.MaxRecordSize}");
            var body = ReadBytes(payloadLen);
            var rec = new byte[2 + payloadLen];
            Buffer.BlockCopy(header, 0, rec, 0, 2);
            Buffer.BlockCopy(body, 0, rec, 2, payloadLen);
            return rec;
        }

        public byte[] ReadBytes(int size)
        {
            if (Obfs == null) return ReadRaw(size);
            // F3: under WebSocket fronting pull `size` cipherbytes out of the inbound
            // binary frames (server->client, unmasked) before ChaCha20-decrypting;
            // otherwise read them straight off the raw stream (pre-F3 behaviour).
            var cipherbytes = Obfs.WsActive ? Obfs.WsReadExact(size, ReadRaw) : ReadRaw(size);
            return Obfs.TransformRead(cipherbytes);
        }

        public byte[] ReadRaw(int size)
        {
            var buf = new byte[size];
            int off = 0;
            while (off < size)
            {
                int n = Sock.Receive(buf, off, size - off, SocketFlags.None);
                if (n <= 0) throw new Exception("Connection closed");
                off += n;
            }
            return buf;
        }

        /// <summary>Read whatever raw bytes are available (≥1), for the realtls
        /// handshake which buffers/parses incrementally.</summary>
        public byte[] ReadSomeRaw(int max = 16384)
        {
            var buf = new byte[max];
            int n = Sock.Receive(buf, 0, max, SocketFlags.None);
            if (n <= 0) throw new Exception("Connection closed");
            return buf[..n];
        }
    }

    // ── stream bonding (multipath) ───────────────────────────────────────────────
    // One logical tunnel carried over N parallel connections that the server
    // aggregates into one session (one TUN IP). Each BondedStream owns its own
    // socket, optional RealTls session, and enc/dec codecs (independent nonce space).
    private sealed record BondedStream(SocketIO Io, ITransport Transport, PacketCodec Enc,
        PacketCodec Dec, RealTls? Tls)
    {
        // 0 → 1 once when this stream dies, so its death is counted exactly once
        // for the live-stream tally (loss-resilience).
        public int Dead;
    }

    /// <summary>Open one secondary bonded connection (same wire mode as the primary)
    /// and JOIN it to the session. Registered for teardown. Works for every TCP mode.</summary>
    private BondedStream OpenBondedStream(VpnConfig config, IPAddress serverIp, byte[] token, int index)
    {
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        bool registered = false;
        try
        {
            ProtectCarrierSocket(sock);
            ConnectWithTimeout(sock, serverIp, config.Port, (int)config.ConnectionTimeoutSecs * 1000);
            sock.NoDelay = true;
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            lock (_bondedSockets) { _bondedSockets.Add(sock); }
            registered = true;
            var io = new SocketIO(sock);

            if (config.WireMode.Equals("plain", StringComparison.OrdinalIgnoreCase))
            {
                var transport = new TcpTransport(io, raw: true);
                var (enc, dec) = PerformJoinHandshakePlain(config, io, token, index);
                return new BondedStream(io, transport, enc, dec, null);
            }
            if (config.WireMode.Equals("reality-tls", StringComparison.OrdinalIgnoreCase))
            {
                var tls = DoRealTlsHandshake(config, io);
                try
                {
                    var transport = new RealTlsTransport(new TcpTransport(io), tls);
                    var (enc, dec) = PerformJoinHandshake(config, transport, token, index);
                    return new BondedStream(io, transport, enc, dec, tls);
                }
                catch
                {
                    // JOIN failed — the outer catch only closes the socket, so release the
                    // native TLS session here before rethrowing (else it leaks per attempt).
                    try { tls.Dispose(); } catch { }
                    throw;
                }
            }
            if (config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase))
            {
                bool fronting = config.ObfsFronting.Equals("websocket", StringComparison.OrdinalIgnoreCase);
                // F2: same AmneziaWG junk on each bonded stream; jc=0 => byte-identical.
                uint jc = config.AwgEnabled ? config.AwgJc : 0u;
                io.Obfs = ObfsStream.Connect(ObfsStream.DeriveKey(config.ObfsKey), fronting, io.WriteRaw, io.ReadRaw,
                    jc, config.AwgJmin, config.AwgJmax);
                var transport = new TcpTransport(io);
                var (enc, dec) = PerformJoinHandshake(config, transport, token, index);
                return new BondedStream(io, transport, enc, dec, null);
            }
            // fake-tls
            {
                var transport = new TcpTransport(io);
                var (enc, dec) = PerformJoinHandshake(config, transport, token, index);
                return new BondedStream(io, transport, enc, dec, null);
            }
        }
        catch
        {
            // Don't leak the socket if connect or the JOIN handshake throws (T10).
            if (registered) lock (_bondedSockets) { _bondedSockets.Remove(sock); }
            try { sock.Close(); } catch { }
            throw;
        }
    }

    /// <summary>Secondary-connection handshake (fake-tls / obfs / reality-tls). Identical
    /// to PerformHandshake up to verifying the server identity, but presents the session
    /// JOIN token instead of credentials. Mirrors tcp_join_handshake.</summary>
    private (PacketCodec enc, PacketCodec dec) PerformJoinHandshake(
        VpnConfig config, ITransport transport, byte[] token, int index)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();
        using var mlkem = MlKem.Generate(); // hybrid PQ, same as the primary handshake
        string sni = config.Sni ?? PickSni(config.ServerAddress);
        var clientHello = TlsHandshake.BuildClientHelloPq(
            clientKeyPair.PublicKeyBytes, mlkem.EncapsulationKey, sni, 0);
        transport.Send(clientHello, longHeader: true);

        var serverHelloRecord = transport.RecvRecord();
        var serverHelloMsg = ParseHandshakeMessage(serverHelloRecord) ?? throw new Exception("JOIN: parse ServerHello");
        var pq = TlsHandshake.ParseServerHelloPq(serverHelloMsg) ?? throw new Exception("JOIN: parse hybrid ServerHello");
        var serverPublicKey = pq.ServerX25519;

        var rec = transport.RecvRecord();
        if (TlsHandshake.IsChangeCipherSpec(rec)) rec = transport.RecvRecord();
        var certRecord = rec;
        var finishedRecord = transport.RecvRecord();
        // F1: positional flight parse (Cert/Finished/NST are all 0x17). Consume the one
        // NST record here (not part of the transcript), then read the auth-proof below.
        _ = transport.RecvRecord(); // NewSessionTicket (0x17) — always exactly one, discarded

        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var mlkemShared = mlkem.Decapsulate(pq.Ciphertext);
        var es = StaticEs(config, ke, clientKeyPair.PrivateKey); // H-1
        var (s2c, c2s) = es != null
            ? KeyDerivation.DeriveKeysHybridBound(sharedSecret, mlkemShared, es)
            : KeyDerivation.DeriveKeysHybrid(sharedSecret, mlkemShared);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax);
        var dec = new PacketCodec(new PacketCipher(s2c));
        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientHello, serverHelloRecord, certRecord, finishedRecord });

        // F1: no type peek — exactly one more record after the NST is the auth-proof.
        var authRec = transport.RecvRecord();
        var authProofMsg = dec.Decrypt(authRec);
        VerifyServerAuth(authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash,
            config.ServerPublicKeyHex, $"{config.ServerAddress}:{config.Port}");

        transport.Send(enc.Encrypt(BuildJoin(token, index)));
        var ack = dec.Decrypt(transport.RecvRecord());
        if (Encoding.UTF8.GetString(ack) != "JOINOK") throw new Exception("JOIN rejected by server");
        return (enc, dec);
    }

    /// <summary>`plain` secondary-connection handshake: raw X25519 exchange + identity
    /// verify, then present the JOIN token over raw-framed records.</summary>
    private (PacketCodec enc, PacketCodec dec) PerformJoinHandshakePlain(
        VpnConfig config, SocketIO io, byte[] token, int index)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();
        io.WriteFully(clientKeyPair.PublicKeyBytes);
        var serverPublicKey = io.ReadRaw(32);
        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientKeyPair.PublicKeyBytes, serverPublicKey });
        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var es = StaticEs(config, ke, clientKeyPair.PrivateKey); // H-1
        var (s2c, c2s) = es != null
            ? KeyDerivation.DeriveKeysBound(sharedSecret, es)
            : KeyDerivation.DeriveKeys(sharedSecret);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax, raw: true);
        var dec = new PacketCodec(new PacketCipher(s2c), raw: true);
        var authProofMsg = dec.Decrypt(io.ReadRawRecord());
        VerifyServerAuth(authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash,
            config.ServerPublicKeyHex, $"{config.ServerAddress}:{config.Port}");

        io.WriteFully(enc.Encrypt(BuildJoin(token, index)));
        var ack = dec.Decrypt(io.ReadRawRecord());
        if (Encoding.UTF8.GetString(ack) != "JOINOK") throw new Exception("JOIN(plain) rejected by server");
        return (enc, dec);
    }

    private static byte[] BuildJoin(byte[] token, int index)
    {
        var join = new byte[JoinMagic.Length + token.Length + 1];
        Buffer.BlockCopy(JoinMagic, 0, join, 0, JoinMagic.Length);
        Buffer.BlockCopy(token, 0, join, JoinMagic.Length, token.Length);
        join[^1] = (byte)index;
        return join;
    }

    /// <summary>Multipath data plane: one upload task round-robins outgoing Wintun
    /// packets across the live streams; each stream has its own download + heartbeat
    /// task (its dec codec is therefore single-threaded, seal/open on its RealTls are
    /// serialized by the per-instance lock). FIXED opens maxStreams immediately;
    /// ADAPTIVE ramps from 1 up under measured load.</summary>
    private void RunMultipathTunnelLoop(VpnConfig config, BondedStream primary, Session session,
        PushedObf? pushed, IPAddress serverIp, CancellationToken ct)
    {
        var tun = _tun!;
        // Per-attempt token (see RunTunnelLoop): cancelled on teardown so every bonded
        // stream's reader/heartbeat AND the shared TUN reader exit before the TUN is
        // disposed — closes the same reconnect-time use-after-free window here (issue #69).
        using var loopCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var lct = loopCts.Token;
        // Report the MTU here too, not only in the single-stream loop: this branch is taken
        // whenever the server profile allows bonding, and it used to skip the report entirely —
        // so the server stayed on path_mtu = 0 and the downlink narrowing never engaged for any
        // bonded client. Sent on the PRIMARY stream, before the others are ramped up. Bonding is
        // TCP-only, so no UDP re-sends are needed. (Audit 2026-07-30, #4.)
        ReportTunnelMtu(primary.Transport, primary.Enc,
            EffectiveMtu(config.Mtu, session.PushedMtu), isUdp: false, lct);
        ReportClientInfo(primary.Transport, primary.Enc);
        // Do NOT re-resolve config.ServerAddress here: in full-tunnel SetupTun has already
        // redirected the default route and DNS into the tunnel, so a hostname lookup fails
        // ("No such host is known") and tears the whole session down (issue #69). Bonded
        // streams reuse the IP the primary connection already resolved (passed in).
        long lastRx = Environment.TickCount64;
        long lastTx = Environment.TickCount64; // last USER uplink packet (see single-path)
        long rxDead = Math.Max(config.HeartbeatIntervalMs * 3, 30_000);
        // Only reconnect on server silence when the server is EXPECTED to be sending (its
        // heartbeat on, or shaping). With both off there is no server->client traffic to
        // gauge liveness, so a silence-based reconnect would storm.
        bool expectServerData = (config.HeartbeatEnabled && config.HeartbeatIntervalMs > 0) || config.ShapingEnabled;
        var firstError = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Fail(Exception e) => firstError.TrySetResult(e);
        var tunWriteLock = new object();

        var streams = new List<BondedStream> { primary };
        // Guarded exactly like `streams`, and for the same reason: on the ADAPTIVE path the
        // ramp task calls LaunchStreamJobs from a thread-pool thread while this thread is
        // adding its own jobs and, at teardown, snapshotting the list. A List<T> mutated from
        // two threads can lose an entry, resize mid-read or throw — and a job missing from the
        // snapshot is a worker the teardown never joins, i.e. a thread still inside the TUN
        // when the caller disposes it. (Audit 2026-07-27, N1)
        var jobs = new List<Task>();
        void AddJob(Task t) { lock (jobs) jobs.Add(t); }
        byte[] token;
        try { token = Convert.FromHexString(session.SessionToken); }
        catch (FormatException)
        {
            // A malformed server-pushed join token would throw here — AFTER Connected was
            // reported — dropping us into a teardown/reconnect loop. Degrade to a single
            // (primary) stream; bonding needs a valid token for the secondary JOINs.
            Log("Multipath: malformed session_token from server — using a single stream");
            token = Array.Empty<byte>();
        }
        int target = token.Length == 0 ? 1 : Math.Clamp(session.MaxStreams, 1, MaxBonded);
        int rr = 0;
        // Count of streams still up; a stream's death tears the tunnel down only when
        // this reaches 0 (losing one bonded stream degrades to the rest).
        int live = 0;

        // Handle one stream's death: counted once (s.Dead), drop it from the rotation,
        // and fire the fatal tunnel error ONLY if it was the last live stream.
        void OnStreamDeath(BondedStream s, Exception e)
        {
            if (Interlocked.Exchange(ref s.Dead, 1) == 0)
            {
                lock (streams) streams.Remove(s);
                try { s.Tls?.Dispose(); } catch { }
                try { s.Io.Sock.Close(); } catch { }
                if (Interlocked.Decrement(ref live) <= 0) Fail(e);
                else Log($"Bonded stream lost; {streams.Count} stream(s) remain");
            }
        }

        void LaunchStreamJobs(BondedStream s)
        {
            Interlocked.Increment(ref live);
            AddJob(Task.Run(() =>
            {
                try
                {
                    while (!lct.IsCancellationRequested)
                    {
                        var plaintext = s.Dec.Decrypt(s.Transport.RecvRecord());
                        Interlocked.Exchange(ref lastRx, Environment.TickCount64);
                        if (plaintext.Length > 0)
                        {
                            lock (tunWriteLock) { tun.SendPacket(plaintext, plaintext.Length); }
                            Interlocked.Add(ref _bytesDown, plaintext.Length);
                        }
                    }
                }
                catch (Exception e) { OnStreamDeath(s, e); }
            }, lct));
            // Per-stream heartbeat OR (flow-shaping on) Poisson idle cover. Each
            // bonded stream carries its own cover budget.
            var shaperM = new TrafficShaper(config.ShapingEnabled, config.ShapingGapMeanMs,
                config.ShapingGapMinMs, config.ShapingGapMaxMs, config.ShapingBudgetBytesPerSec,
                config.ShapingMinSize, config.ShapingMaxSize);
            bool hbOnM = config.HeartbeatEnabled && config.HeartbeatIntervalMs > 0;
            // Keepalive always runs (decoupled from the server heartbeat flag — see the
            // single-stream note) unless flow-shaping cover replaces it. 30s fallback.
            long kaIntervalMsM = hbOnM ? config.HeartbeatIntervalMs : 30_000;
            {
                AddJob(Task.Run(() =>
                {
                    var rng = RandomNumberGenerator.Create();
                    while (!lct.IsCancellationRequested)
                    {
                        long wait = shaperM.Enabled
                            ? Math.Max(shaperM.NextGapMs(), 1)
                            : Math.Max(kaIntervalMsM + JitterMs(rng, config.HeartbeatJitterMs), 1000);
                        if (lct.WaitHandle.WaitOne((int)wait)) break;
                        try
                        {
                            if (shaperM.Enabled)
                            {
                                int size = shaperM.NextSize();
                                if (shaperM.TrySpend(size)) s.Transport.Send(s.Enc.EncryptPadded(Array.Empty<byte>(), size));
                            }
                            // Bonding is TCP-only (see OpenBondedStream), so there is no
                            // DF-marked datagram to overflow and no MTU cap to apply; pass
                            // the config's own MTU and let IsUdp decide, rather than
                            // hard-coding the assumption here.
                            else s.Transport.Send(s.Enc.EncryptPadded(Array.Empty<byte>(),
                                HeartbeatPadLen(config, config.Mtu, config.IsUdp, rng)));
                        }
                        catch (Exception e) { OnStreamDeath(s, e); break; }
                    }
                }, lct));
            }
        }

        LaunchStreamJobs(primary);

        if (!session.Adaptive)
        {
            for (int idx = 1; idx < target; idx++)
            {
                try
                {
                    var s = OpenBondedStream(config, serverIp, token, idx);
                    if (pushed != null) s.Enc.SetPadding(pushed.PaddingEnabled, pushed.PaddingMin, pushed.PaddingMax);
                    lock (streams) streams.Add(s);
                    LaunchStreamJobs(s);
                    Log($"Bonded stream #{idx} joined ({streams.Count} active)");
                }
                catch (Exception e) { Log($"bonded #{idx} failed: {e.GetType().Name}: {e.Message}"); }
            }
            Log($"Multipath: {streams.Count} bonded stream(s) active (fixed)");
        }
        else
        {
            AddJob(Task.Run(() =>
            {
                long lastBytes = 0, bestRate = 0; int idx = 1;
                while (!lct.IsCancellationRequested)
                {
                    if (lct.WaitHandle.WaitOne(3000)) break;
                    int cur; lock (streams) cur = streams.Count;
                    if (cur >= target) break;
                    // Both directions, as in the Rust client: keyed on upload alone the ramp
                    // is blind to download-only load — i.e. to the case bonding exists for
                    // (a big download) — and never grows past the first stream.
                    long now = Interlocked.Read(ref _bytesUp) + Interlocked.Read(ref _bytesDown);
                    long rate = (now - lastBytes) / 3;          // bytes/s (up+down)
                    lastBytes = now;
                    if (rate <= 250_000) continue;               // >~2 Mbps — ramp under demand
                    bool improving = rate > bestRate + bestRate / 10;
                    if (rate > bestRate) bestRate = rate;
                    if (cur > 1 && !improving) { Log($"Multipath adaptive: plateau at {cur} stream(s)"); break; }
                    try
                    {
                        var s = OpenBondedStream(config, serverIp, token, idx);
                        if (pushed != null) s.Enc.SetPadding(pushed.PaddingEnabled, pushed.PaddingMin, pushed.PaddingMax);
                        lock (streams) streams.Add(s);
                        LaunchStreamJobs(s); idx++;
                        Log($"Multipath adaptive: ramped to {streams.Count} stream(s) ({rate / 1000} KB/s)");
                    }
                    catch (Exception e) { Log($"adaptive ramp failed: {e.Message}"); }
                }
            }, lct));
        }

        // Upload: round-robin Wintun outbound packets across the live streams.
        AddJob(Task.Run(() =>
        {
            try
            {
                while (!lct.IsCancellationRequested)
                {
                    var pkt = tun.ReceivePacket(lct);
                    if (pkt == null) break;
                    if (pkt.Length == 0) continue;
                    if ((pkt[0] >> 4) != 4) continue;            // IPv4 only
                    // Round-robin; a dead stream's send is non-fatal (drop it from the
                    // rotation, the tunnel runs on the rest).
                    BondedStream? s = null;
                    lock (streams) { if (streams.Count > 0) s = streams[(int)((uint)Interlocked.Increment(ref rr) % (uint)streams.Count)]; }
                    if (s == null) continue;
                    // Bonded streams are TCP, so they take the same fixed per-packet padding
                    // cap as the single-stream TCP path — Encrypt() applied the server-pushed
                    // padding_max verbatim. (Audit 2026-07-27, N2)
                    try { s.Transport.Send(s.Enc.EncryptCapped(pkt, PadCapInner)); Interlocked.Add(ref _bytesUp, pkt.Length); Interlocked.Exchange(ref lastTx, Environment.TickCount64); }
                    catch (Exception e) { OnStreamDeath(s, e); }
                }
            }
            catch (Exception e) { Fail(e); }
        }, lct));

        // Liveness watchdog: reconnect on resume-from-sleep, on active-uplink/dead-downlink,
        // or on server silence (the last only when the server is expected to be sending).
        AddJob(Task.Run(() =>
        {
            long lastWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long lastTick = Environment.TickCount64;
            while (!lct.IsCancellationRequested)
            {
                if (lct.WaitHandle.WaitOne(WatchdogPollMs)) break;
                long nowTick = Environment.TickCount64;
                long nowWall = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                long drift = (nowWall - lastWall) - (nowTick - lastTick);
                lastWall = nowWall; lastTick = nowTick;
                // L1 — resumed from sleep: every stream's session + NAT is almost certainly gone.
                if (drift > SuspendGapMs)
                { Fail(SuspendResumed(drift)); break; }
                // L2 — user uplink active but nothing coming back on any stream ⇒ dead.
                if (nowTick - Interlocked.Read(ref lastTx) < TxActiveMs
                    && nowTick - Interlocked.Read(ref lastRx) > TxRxAsymmetryMs)
                { Fail(new Exception($"uplink active but no downlink for >{TxRxAsymmetryMs / 1000}s — reconnecting")); break; }
                // Server-silence window.
                if (expectServerData && nowTick - Interlocked.Read(ref lastRx) > rxDead)
                { Fail(new Exception($"no data from server for >{rxDead / 1000}s")); break; }
            }
        }, lct));

        // Complete `firstError` on the global stop token via a registration (no parked
        // thread — see RunTunnelLoop; the old Task.Run(WaitOne) leaked one per reconnect).
        Exception error;
        using (ct.Register(() => firstError.TrySetResult(new OperationCanceledException())))
        {
            error = firstError.Task.GetAwaiter().GetResult();
        }

        GracefulClose(_tcp);
        lock (_bondedSockets) { foreach (var sk in _bondedSockets) GracefulClose(sk); }
        lock (streams) { foreach (var s in streams) { try { s.Tls?.Dispose(); } catch { } } }
        // Wake every parked worker (TUN reader + per-stream heartbeats) and join before
        // returning, so the TUN is idle when the caller disposes it.
        loopCts.Cancel();
        Task[] pending; lock (jobs) pending = jobs.ToArray();   // (Audit 2026-07-27, N1)
        try { Task.WaitAll(pending, 3000); } catch { }

        if (!ct.IsCancellationRequested && error is not OperationCanceledException)
            throw error; // let ConnectWithRetry decide whether to reconnect
    }

    // ── misc ─────────────────────────────────────────────────────────────────────
    /// <summary>True only if <paramref name="s"/> is a bare IP literal safe to splice into
    /// a netsh/route command line: no whitespace, only [0-9A-Fa-f:.] characters, and it
    /// parses as an IP address. Belt-and-suspenders against server-pushed argument injection.</summary>
    private static bool IsStrictIp(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (char c in s)
            if (!(char.IsAsciiDigit(c) || char.IsAsciiHexDigit(c) || c == ':' || c == '.'))
                return false;
        return IPAddress.TryParse(s, out _);
    }

    /// <summary>Resolve the server address, bounded by <paramref name="timeoutMs"/>.
    ///
    /// `Dns.GetHostAddresses` is a blocking `getaddrinfo` with NO timeout of its own, and
    /// right after a resume-from-sleep it is one of the slowest things on the reconnect
    /// path: the resolver is often not reachable yet, and the OS works through its retry
    /// schedule before failing. Unbounded, that stall is charged to the attempt before a
    /// single packet is sent. Bounding it lets the attempt fail fast and be retried once
    /// the network is actually up, which is the whole point of the settling window.
    /// (Field report 2026-07-25 item 1, second pass.)</summary>
    private static IPAddress ResolveServer(string address, int timeoutMs)
    {
        if (IPAddress.TryParse(address, out var ip)) return ip;
        using var cts = new CancellationTokenSource(timeoutMs);
        IPAddress[] addrs;
        try
        {
            addrs = Dns.GetHostAddressesAsync(address, cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException(
                $"DNS lookup for {address} timed out after {timeoutMs} ms");
        }
        return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
            ?? throw new Exception($"no IPv4 address for {address}");
    }

    private static void ConnectWithTimeout(Socket sock, IPAddress ip, int port, int timeoutMs)
    {
        var ar = sock.BeginConnect(ip, port, null, null);
        if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
        {
            try { sock.Close(); } catch { }
            throw new TimeoutException($"connect to {ip}:{port} timed out");
        }
        sock.EndConnect(ar);
    }

    private static long JitterMs(RandomNumberGenerator rng, long jitter)
    {
        if (jitter <= 0) return 0;
        var b = new byte[8];
        rng.GetBytes(b);
        long r = (BitConverter.ToInt64(b, 0) & long.MaxValue) % (jitter * 2);
        return r - jitter;
    }

    private static string PickSni(string address)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(address, @"^\d{1,3}(\.\d{1,3}){3}$"))
            return address;
        // ONE list, shared with the WebSocket Host pool — see TlsHandshake.DefaultSniPool.
        var pool = Protocol.TlsHandshake.DefaultSniPool;
        return pool[RandomNumberGenerator.GetInt32(pool.Length)];
    }
}
