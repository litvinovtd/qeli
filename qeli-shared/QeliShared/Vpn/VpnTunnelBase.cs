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
    private volatile bool _userRequestedDisconnect;

    // Handshake-only mode (headless --handshake test): stop after auth, skip TUN.
    private bool _handshakeOnly;
    private string? _handshakeIp;

    // True once an established tunnel is up; used to detect a server-side drop.
    private volatile bool _wasConnected;

    // True while the firewall kill-switch is engaged (so Stop() lifts exactly what
    // Start() raised). The kill-switch is raised ONCE before the connect loop and
    // stays up across reconnects — see KillSwitchEngage/Disengage.
    private bool _ksEngaged;

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
        Stop();
        _userRequestedDisconnect = false;
        _wasConnected = false;
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
        if (config.KillSwitch && config.IsFullTunnel)
        {
            try { KillSwitchEngage(config); _ksEngaged = true; }
            catch (Exception e)
            {
                Log($"[SECURITY] kill-switch could not be engaged: {e.Message} — not connecting unprotected");
                Status(VpnStatus.Error, "kill-switch failed");
                return;
            }
        }

        _runTask = Task.Run(() => ConnectWithRetry(config, ct), ct);
    }

    /// <summary>Headless test: connect + full handshake only (no TUN, no admin), return the
    /// server-assigned tunnel IP. Throws on any protocol/auth failure.</summary>
    public string TestHandshake(VpnConfig config)
    {
        _handshakeOnly = true;
        _handshakeIp = null;
        _userRequestedDisconnect = true; // no reconnect loop
        using var cts = new CancellationTokenSource();
        try { RunVpnConnection(config, cts.Token); }
        finally { CloseTransports(); }
        return _handshakeIp ?? throw new Exception("handshake produced no IP");
    }

    public void Stop()
    {
        _userRequestedDisconnect = true;
        try { _cts?.Cancel(); } catch { }
        CloseTransports();
        try { _runTask?.Wait(3000); } catch { }
        _runTask = null;
        _cts = null;
        // Lift the kill-switch only on a clean stop (a crash leaves it = fail-safe).
        if (_ksEngaged)
        {
            try { KillSwitchDisengage(); } catch (Exception e) { Log($"kill-switch disengage error: {e.Message}"); }
            _ksEngaged = false;
        }
        Status(VpnStatus.Disconnected);
    }

    /// <summary>Platform hook: raise the firewall kill-switch (block all egress
    /// except the tunnel, the server, DNS and DHCP). Called once before the connect
    /// loop when <see cref="VpnConfig.KillSwitch"/> is set in full-tunnel mode.
    /// Default no-op (platforms without an implementation simply don't gate).</summary>
    protected virtual void KillSwitchEngage(VpnConfig config) { }

    /// <summary>Platform hook: lift the kill-switch on a clean stop.</summary>
    protected virtual void KillSwitchDisengage() { }

    private void CloseTransports()
    {
        try { _tcp?.Close(); } catch { }
        // Close every secondary bonded socket so its blocking read unblocks and the
        // per-stream task exits (otherwise a reconnect leaks bonded streams).
        lock (_bondedSockets)
        {
            foreach (var s in _bondedSockets) { try { s.Close(); } catch { } }
            _bondedSockets.Clear();
        }
        try { _udp?.Close(); } catch { }
        try { _tun?.Dispose(); } catch { }
        CleanupPlatform();
        _tcp = null; _udp = null; _tun = null;
    }

    // ── reconnect loop ─────────────────────────────────────────────────────────
    private void ConnectWithRetry(VpnConfig config, CancellationToken ct)
    {
        int attempt = 0;
        long baseMs = config.ReconnectBaseDelaySecs * 1000;
        long maxMs = config.ReconnectMaxDelaySecs * 1000;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (attempt > 0)
                {
                    if (!config.ReconnectEnabled) { Log("Reconnect disabled, giving up"); break; }
                    if (config.ReconnectMaxRetries >= 0 && attempt > config.ReconnectMaxRetries)
                    { Log("Max retries reached, giving up"); break; }
                    long pow = (long)Math.Pow(2, Math.Min(attempt - 1, 7));
                    long delayMs = Math.Max(Math.Min(baseMs * Math.Min(pow, 100), maxMs), 1000);
                    Status(VpnStatus.Connecting);
                    Log($"Reconnect attempt {attempt} in {delayMs / 1000}s");
                    if (ct.WaitHandle.WaitOne((int)delayMs)) break; // cancelled
                }
                RunVpnConnection(config, ct);
                Log("Connection closed cleanly");
                if (_userRequestedDisconnect) break;
                // Established session closed cleanly — reset the backoff so only
                // *consecutive* pre-established failures escalate the delay.
                _wasConnected = false;
                attempt = 0;
            }
            catch (System.Security.SecurityException e) when (!ct.IsCancellationRequested)
            {
                // Server identity changed / key mismatch — a possible MITM. Do NOT
                // retry (a hijacked endpoint won't fix itself and retrying is noisy);
                // surface a clear security warning and stop. (A5 — TOFU warning.)
                Log($"[SECURITY] {e.Message}");
                Status(VpnStatus.Error, Loc.T("MitmStop"));
                CloseTransports();
                break;
            }
            catch (Exception e) when (!ct.IsCancellationRequested)
            {
                Log($"ERR: [{e.GetType().Name}] {e.Message}");
                var cause = e.InnerException;
                while (cause != null) { Log($"  <- {cause.Message}"); cause = cause.InnerException; }
                // An established tunnel just dropped (server down / network lost) — notify
                // once; the loop will then move to the reconnect (Connecting) state.
                if (_wasConnected)
                {
                    // Established session — reset backoff so reconnect is prompt;
                    // only consecutive pre-established failures escalate the delay.
                    _wasConnected = false;
                    ConnectionDropped?.Invoke(e.Message);
                    attempt = 0;
                }
                else
                {
                    attempt++;
                }
                CloseTransports();
            }
            catch (Exception)
            {
                break; // cancelled
            }
        }
        if (_userRequestedDisconnect) Status(VpnStatus.Disconnected);
        else Status(VpnStatus.Error, Loc.T("CouldNotConnect")); // gave up retrying
    }

    private void RunVpnConnection(VpnConfig config, CancellationToken ct)
    {
        if (config.IsUdp) ConnectUdp(config, ct);
        else ConnectTcp(config, ct);
    }

    // ── transport abstraction ───────────────────────────────────────────────────
    private interface ITransport
    {
        void Send(byte[] record, bool longHeader = false);
        byte[] RecvRecord();
        void SetReadTimeout(int ms);
    }

    private sealed class TcpTransport : ITransport
    {
        private readonly SocketIO _io;
        private readonly bool _raw;   // plain wire mode: bare length-prefixed records
        public TcpTransport(SocketIO io, bool raw = false) { _io = io; _raw = raw; }
        public void Send(byte[] record, bool longHeader = false) => _io.WriteFully(record);
        public byte[] RecvRecord() => _raw ? _io.ReadRawRecord() : _io.ReadTlsRecord();
        public void SetReadTimeout(int ms) { }
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

        public void Send(byte[] record, bool longHeader = false)
        {
            byte[] outBuf = _quic
                ? (longHeader ? Quic.WrapLong(record, _cid, _pn++, 0x02) : Quic.WrapShort(record, _cid, _pn++))
                : record;
            if (_obfsKey != null) outBuf = ObfsStream.DatagramSeal(_obfsKey, outBuf);
            lock (_sendLock) { _sock.Send(outBuf); }
        }

        private void Fill()
        {
            var rbuf = new byte[65535];
            while (true)
            {
                int n = _sock.Receive(rbuf);
                byte[]? raw = rbuf[..n];
                if (_obfsKey != null) raw = ObfsStream.DatagramOpen(_obfsKey, raw);
                if (raw == null) continue;     // malformed obfs frame — skip
                var payload = _quic ? Quic.UnwrapPayload(raw) : raw;
                if (payload != null) { _buf = payload; _pos = 0; return; }
            }
        }

        public byte[] RecvRecord()
        {
            if (_pos + 5 > _buf.Length) Fill();
            int len = ((_buf[_pos + 3] & 0xFF) << 8) | (_buf[_pos + 4] & 0xFF);
            int end = Math.Min(_pos + 5 + len, _buf.Length);
            var rec = _buf[_pos..end];
            _pos = end;
            return rec;
        }

        public void SetReadTimeout(int ms) => _sock.ReceiveTimeout = ms;
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
    private void ConnectTcp(VpnConfig config, CancellationToken ct)
    {
        var serverIp = ResolveServer(config.ServerAddress);
        Log($"Connecting TCP {serverIp}:{config.Port}...");
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        // Publish the socket BEFORE the (blocking) connect so Stop()/CloseTransports
        // can close it to interrupt a connect that hangs on a dead/changed network —
        // otherwise the Disconnect button does nothing until the connect timeout.
        _tcp = sock;
        if (ct.IsCancellationRequested || _userRequestedDisconnect) { try { sock.Close(); } catch { } throw new OperationCanceledException(); }
        ConnectWithTimeout(sock, serverIp, config.Port, (int)config.ConnectionTimeoutSecs * 1000);
        sock.NoDelay = true;
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
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
            io.Obfs = ObfsStream.Connect(ObfsStream.DeriveKey(config.ObfsKey), fronting, io.WriteRaw, io.ReadRaw);
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
        Status(VpnStatus.Connected, hs.Session.ClientIp);
        if (_handshakeOnly) { _handshakeIp = hs.Session.ClientIp; return; }

        _wasConnected = true;
        ConnectedSince = DateTime.Now;
        SetupTun(hs.Config, hs.Session, serverIp);

        if (hs.Session.MaxStreams > 1 && !string.IsNullOrEmpty(hs.Session.SessionToken))
        {
            Log($"Multipath: server allows up to {hs.Session.MaxStreams} bonded stream(s) (adaptive={hs.Session.Adaptive})");
            var primary = new BondedStream(io, transport, hs.Enc, hs.Dec, tls);
            RunMultipathTunnelLoop(hs.Config, primary, hs.Session, hs.Pushed, ct);
        }
        else
        {
            Log("TUN ready, entering tunnel loop");
            RunTunnelLoop(hs.Config, transport, hs.Enc, hs.Dec, isUdp: false, ct);
        }
    }

    private void ConnectUdp(VpnConfig config, CancellationToken ct)
    {
        var serverIp = ResolveServer(config.ServerAddress);
        Log($"Connecting UDP {serverIp}:{config.Port}...");
        var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sock.Connect(serverIp, config.Port);
        sock.ReceiveTimeout = (int)config.ConnectionTimeoutSecs * 1000;
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
        EstablishAndRun(config, new UdpTransport(this, sock, quic, cid, obfsKey), padToMin: 1200, isUdp: true, serverIp, ct);
    }

    private void EstablishAndRun(VpnConfig config, ITransport transport, int padToMin, bool isUdp,
        IPAddress serverIp, CancellationToken ct)
    {
        var hs = PerformHandshake(config, transport, padToMin);
        RunAfterHandshake(config, transport, isUdp, serverIp, ct, hs);
    }

    /// <summary>Post-handshake path for the single-stream transports (UDP); the TCP
    /// modes use RunTcpAfterHandshake which can also start the multipath loop.</summary>
    private void RunAfterHandshake(VpnConfig config, ITransport transport, bool isUdp, IPAddress serverIp,
        CancellationToken ct, HsResult hs)
    {
        Log($"Auth OK, IP {hs.Session.ClientIp}");
        Status(VpnStatus.Connected, hs.Session.ClientIp);

        if (_handshakeOnly) { _handshakeIp = hs.Session.ClientIp; return; }

        _wasConnected = true;
        ConnectedSince = DateTime.Now;
        SetupTun(hs.Config, hs.Session, serverIp);
        Log("TUN ready, entering tunnel loop");
        RunTunnelLoop(hs.Config, transport, hs.Enc, hs.Dec, isUdp, ct);
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

    private HsResult PerformHandshake(VpnConfig config, ITransport transport, int padToMin)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();
        using var mlkem = MlKem.Generate(); // hybrid PQ: ML-KEM-768 keypair (server requires it)

        string sni = config.Sni ?? PickSni(config.ServerAddress);
        var clientHello = TlsHandshake.BuildClientHelloPq(
            clientKeyPair.PublicKeyBytes, mlkem.EncapsulationKey, sni, padToMin);
        transport.Send(clientHello, longHeader: true);
        Log($"ClientHello sent ({clientHello.Length}B, hybrid X25519+ML-KEM)");

        var serverHelloRecord = transport.RecvRecord();
        var serverHelloMsg = ParseHandshakeMessage(serverHelloRecord)
            ?? throw new Exception("Failed to parse ServerHello");
        var pq = TlsHandshake.ParseServerHelloPq(serverHelloMsg)
            ?? throw new Exception("Failed to parse hybrid ServerHello");
        var serverPublicKey = pq.ServerX25519;

        var rec = transport.RecvRecord();
        if (TlsHandshake.IsChangeCipherSpec(rec)) rec = transport.RecvRecord();
        var certRecord = rec;
        var finishedRecord = transport.RecvRecord();

        // Auth proof binds to the classic X25519 ephemeral shared (server uses the same);
        // the ML-KEM secret only feeds the hybrid data-plane KDF.
        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var mlkemShared = mlkem.Decapsulate(pq.Ciphertext);
        var (s2c, c2s) = KeyDerivation.DeriveKeysHybrid(sharedSecret, mlkemShared);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax);
        var dec = new PacketCodec(new PacketCipher(s2c));

        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientHello, serverHelloRecord, certRecord, finishedRecord });

        var authRec = transport.RecvRecord();
        if (authRec.Length > 0 && (authRec[0] & 0xFF) == 0x16) authRec = transport.RecvRecord();
        var authProofMsg = dec.Decrypt(authRec);
        var (staticPub, staticShared) = VerifyServerAuth(
            authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash,
            config.ServerPublicKeyHex, $"{config.ServerAddress}:{config.Port}");
        Log("Server identity verified [OK]");

        var authPlain = BuildClientAuthPlaintext(config, staticShared, sharedSecret, transcriptHash);
        transport.Send(enc.Encrypt(authPlain));

        var authResponse = dec.Decrypt(transport.RecvRecord());
        var authStr = Encoding.UTF8.GetString(authResponse);
        if (!authStr.StartsWith("OK:", StringComparison.Ordinal))
            throw new Exception($"Auth failed: {authStr}");
        var (session, obf) = ParseOk(authStr);

        var effConfig = config;
        var pushed = DecodePushedObf(obf);
        if (pushed != null)
        {
            enc.SetPadding(pushed.PaddingEnabled, pushed.PaddingMin, pushed.PaddingMax);
            effConfig = config.WithHeartbeat(pushed.HbEnabled, pushed.HbIntervalMs, pushed.HbJitterMs);
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
        var (s2c, c2s) = KeyDerivation.DeriveKeys(sharedSecret);
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
            effConfig = config.WithHeartbeat(pushed.HbEnabled, pushed.HbIntervalMs, pushed.HbJitterMs);
            Log("Applied server-pushed obfuscation params");
        }
        return new HsResult(session, effConfig, enc, dec, pushed);
    }

    private (Session, JsonObject?) ParseOk(string authStr)
    {
        var json = JsonNode.Parse(authStr.Substring("OK:".Length))!.AsObject();
        string clientIp = (json["client_ip"] as JsonValue)?.GetValue<string>() ?? "";
        if (clientIp.Length == 0) throw new Exception("server OK response missing client_ip");
        // VPN subnet prefix (default /24 when an older server omits it).
        int prefix = (json["prefix"] as JsonValue)?.GetValue<int>() ?? 24;
        if (prefix is < 1 or > 32) prefix = 24;
        string dns = (json["dns"] as JsonValue)?.GetValue<string>() ?? "";
        string routes = json["routes"] is JsonArray arr ? arr.ToJsonString() : "[]";
        // Server-pushed MTU; out-of-range/absent => 0 (not pushed).
        int mtu = (json["mtu"] as JsonValue)?.GetValue<int>() ?? 0;
        if (mtu is < 576 or > 9000) mtu = 0;
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
        bool HbEnabled, long HbIntervalMs, long HbJitterMs);

    private static PushedObf? DecodePushedObf(JsonObject? obf)
    {
        if (obf == null) return null;
        var pad = obf["padding"] as JsonObject ?? new JsonObject();
        var hb = obf["heartbeat"] as JsonObject ?? new JsonObject();
        int GetInt(JsonObject o, string k, int d) => o[k] is JsonValue v && v.TryGetValue(out int i) ? i : d;
        long GetLong(JsonObject o, string k, long d) => o[k] is JsonValue v && v.TryGetValue(out long l) ? l : d;
        bool GetBool(JsonObject o, string k, bool d) => o[k] is JsonValue v && v.TryGetValue(out bool b) ? b : d;
        return new PushedObf(
            GetBool(pad, "enabled", true), GetInt(pad, "min_bytes", 0), GetInt(pad, "max_bytes", 255),
            GetBool(hb, "enabled", true), GetLong(hb, "interval_ms", 15000), GetLong(hb, "jitter_ms", 2000));
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
                // the Rust client's known_hosts): pin on first sight, then verify on
                // every later connect; a changed key throws instead of being accepted.
                TrustOnFirstUse(serverId, serverStaticPub);
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
        return (serverStaticPub, staticShared);
    }

    private static readonly object _knownHostsLock = new();

    /// <summary>Trust-on-first-use with persistence (parity with the Rust client's
    /// known_hosts). Pins the server's static key on first sight (keyed by
    /// <paramref name="serverId"/> = host:port) and verifies it on every later
    /// connect — a changed key throws <see cref="SecurityException"/> as a probable
    /// MITM rather than being silently accepted. Best-effort: an unwritable store
    /// degrades to a warning, but a readable one is always enforced.</summary>
    private void TrustOnFirstUse(string serverId, byte[] receivedKey)
    {
        var receivedHex = Convert.ToHexString(receivedKey).ToLowerInvariant();
        var dir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "qeli");
        var path = System.IO.Path.Combine(dir, "known_hosts");
        lock (_knownHostsLock)
        {
            try
            {
                if (System.IO.File.Exists(path))
                {
                    foreach (var raw in System.IO.File.ReadAllLines(path))
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith('#')) continue;
                        var sp = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
                        if (sp.Length == 2 && sp[0] == serverId)
                        {
                            if (string.Equals(sp[1].Trim(), receivedHex, StringComparison.OrdinalIgnoreCase))
                                return; // matches the pin
                            throw new SecurityException(
                                $"SERVER KEY MISMATCH for {serverId} - possible MITM. Pinned {sp[1].Trim()}, " +
                                $"got {receivedHex}. If you deliberately rotated the key, remove its line " +
                                $"from {path} (or set server_public_key) and reconnect.");
                        }
                    }
                }
            }
            catch (SecurityException) { throw; }
            catch { /* unreadable store -> fall through and try to record */ }

            try
            {
                System.IO.Directory.CreateDirectory(dir);
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
                if (existing.Length == 16) { _deviceId = existing; return existing; }
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

    // ── tunnel loop ──────────────────────────────────────────────────────────────
    private void RunTunnelLoop(VpnConfig config, ITransport transport,
        PacketCodec enc, PacketCodec dec, bool isUdp, CancellationToken ct)
    {
        var tun = _tun!;
        long lastRx = Environment.TickCount64;
        long rxDead = Math.Max(config.HeartbeatIntervalMs * 3, 30_000);
        var firstError = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Fail(Exception e) => firstError.TrySetResult(e);

        if (isUdp) transport.SetReadTimeout((int)rxDead);

        // Upload: system -> tunnel (read Wintun outbound packets, encrypt, send).
        var uploadJob = Task.Run(() =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var pkt = tun.ReceivePacket(ct);
                    if (pkt == null) break;                 // session ended
                    if (pkt.Length == 0) continue;
                    if ((pkt[0] >> 4) != 4) continue;        // IPv4 only
                    transport.Send(enc.Encrypt(pkt));
                    Interlocked.Add(ref _bytesUp, pkt.Length);
                }
            }
            catch (Exception e) { Fail(e); }
        }, ct);

        // Download: tunnel -> system (recv record, decrypt, inject into Wintun).
        var downloadJob = Task.Run(() =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    byte[] rec;
                    try { rec = transport.RecvRecord(); }
                    catch (SocketException se) when (se.SocketErrorCode == SocketError.TimedOut)
                    {
                        if (Environment.TickCount64 - Interlocked.Read(ref lastRx) > rxDead)
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
        }, ct);

        // Heartbeat: empty encrypted record on a jittered interval.
        var heartbeatJob = Task.Run(() =>
        {
            if (!config.HeartbeatEnabled || config.HeartbeatIntervalMs <= 0) return;
            var rng = RandomNumberGenerator.Create();
            while (!ct.IsCancellationRequested)
            {
                long jitter = JitterMs(rng, config.HeartbeatJitterMs);
                long wait = Math.Max(config.HeartbeatIntervalMs + jitter, 1000);
                if (ct.WaitHandle.WaitOne((int)wait)) break;
                try { transport.Send(enc.Encrypt(Array.Empty<byte>())); }
                catch (Exception e) { Fail(e); break; }
                if (!isUdp && Environment.TickCount64 - Interlocked.Read(ref lastRx) > rxDead)
                { Fail(new Exception($"no data from server for >{rxDead / 1000}s")); break; }
            }
        }, ct);

        // Block until the first data-plane error or cancellation.
        var cancelWait = Task.Run(() => { ct.WaitHandle.WaitOne(); return (Exception)new OperationCanceledException(); });
        var ended = Task.WhenAny(firstError.Task, cancelWait).GetAwaiter().GetResult();
        var error = ended.GetAwaiter().GetResult();

        try { _tcp?.Close(); } catch { }
        try { _udp?.Close(); } catch { }
        try { Task.WaitAll(new[] { uploadJob, downloadJob, heartbeatJob }, 2000); } catch { }

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
            var outBuf = Obfs != null ? Obfs.TransformWrite(data) : data;
            WriteRaw(outBuf);
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
            if (payloadLen > 65535) throw new Exception($"TLS record too large: {payloadLen}");
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
            if (payloadLen > 65535) throw new Exception($"raw record too large: {payloadLen}");
            var body = ReadBytes(payloadLen);
            var rec = new byte[2 + payloadLen];
            Buffer.BlockCopy(header, 0, rec, 0, 2);
            Buffer.BlockCopy(body, 0, rec, 2, payloadLen);
            return rec;
        }

        public byte[] ReadBytes(int size)
        {
            var raw = ReadRaw(size);
            return Obfs != null ? Obfs.TransformRead(raw) : raw;
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
                var transport = new RealTlsTransport(new TcpTransport(io), tls);
                var (enc, dec) = PerformJoinHandshake(config, transport, token, index);
                return new BondedStream(io, transport, enc, dec, tls);
            }
            if (config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase))
            {
                bool fronting = config.ObfsFronting.Equals("websocket", StringComparison.OrdinalIgnoreCase);
                io.Obfs = ObfsStream.Connect(ObfsStream.DeriveKey(config.ObfsKey), fronting, io.WriteRaw, io.ReadRaw);
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

        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var mlkemShared = mlkem.Decapsulate(pq.Ciphertext);
        var (s2c, c2s) = KeyDerivation.DeriveKeysHybrid(sharedSecret, mlkemShared);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax);
        var dec = new PacketCodec(new PacketCipher(s2c));
        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientHello, serverHelloRecord, certRecord, finishedRecord });

        var authRec = transport.RecvRecord();
        if (authRec.Length > 0 && (authRec[0] & 0xFF) == 0x16) authRec = transport.RecvRecord();
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
        var (s2c, c2s) = KeyDerivation.DeriveKeys(sharedSecret);
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
        PushedObf? pushed, CancellationToken ct)
    {
        var tun = _tun!;
        var serverIp = ResolveServer(config.ServerAddress);
        long lastRx = Environment.TickCount64;
        long rxDead = Math.Max(config.HeartbeatIntervalMs * 3, 30_000);
        var firstError = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Fail(Exception e) => firstError.TrySetResult(e);
        var tunWriteLock = new object();

        var streams = new List<BondedStream> { primary };
        var jobs = new List<Task>();
        var token = Convert.FromHexString(session.SessionToken);
        int target = Math.Clamp(session.MaxStreams, 1, MaxBonded);
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
            jobs.Add(Task.Run(() =>
            {
                try
                {
                    while (!ct.IsCancellationRequested)
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
            }, ct));
            if (config.HeartbeatEnabled && config.HeartbeatIntervalMs > 0)
            {
                jobs.Add(Task.Run(() =>
                {
                    var rng = RandomNumberGenerator.Create();
                    while (!ct.IsCancellationRequested)
                    {
                        long jitter = JitterMs(rng, config.HeartbeatJitterMs);
                        if (ct.WaitHandle.WaitOne((int)Math.Max(config.HeartbeatIntervalMs + jitter, 1000))) break;
                        try { s.Transport.Send(s.Enc.Encrypt(Array.Empty<byte>())); }
                        catch (Exception e) { OnStreamDeath(s, e); break; }
                    }
                }, ct));
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
            jobs.Add(Task.Run(() =>
            {
                long lastBytes = 0, bestRate = 0; int idx = 1;
                while (!ct.IsCancellationRequested)
                {
                    if (ct.WaitHandle.WaitOne(3000)) break;
                    int cur; lock (streams) cur = streams.Count;
                    if (cur >= target) break;
                    long now = Interlocked.Read(ref _bytesUp);
                    long rate = (now - lastBytes) / 3;          // bytes/s
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
            }, ct));
        }

        // Upload: round-robin Wintun outbound packets across the live streams.
        jobs.Add(Task.Run(() =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var pkt = tun.ReceivePacket(ct);
                    if (pkt == null) break;
                    if (pkt.Length == 0) continue;
                    if ((pkt[0] >> 4) != 4) continue;            // IPv4 only
                    // Round-robin; a dead stream's send is non-fatal (drop it from the
                    // rotation, the tunnel runs on the rest).
                    BondedStream? s = null;
                    lock (streams) { if (streams.Count > 0) s = streams[(int)((uint)Interlocked.Increment(ref rr) % (uint)streams.Count)]; }
                    if (s == null) continue;
                    try { s.Transport.Send(s.Enc.Encrypt(pkt)); Interlocked.Add(ref _bytesUp, pkt.Length); }
                    catch (Exception e) { OnStreamDeath(s, e); }
                }
            }
            catch (Exception e) { Fail(e); }
        }, ct));

        // Liveness: fail the tunnel if NO stream delivers data for rxDead.
        jobs.Add(Task.Run(() =>
        {
            while (!ct.IsCancellationRequested)
            {
                if (ct.WaitHandle.WaitOne(5000)) break;
                if (Environment.TickCount64 - Interlocked.Read(ref lastRx) > rxDead)
                { Fail(new Exception($"no data from server for >{rxDead / 1000}s")); break; }
            }
        }, ct));

        var cancelWait = Task.Run(() => { ct.WaitHandle.WaitOne(); return (Exception)new OperationCanceledException(); });
        var ended = Task.WhenAny(firstError.Task, cancelWait).GetAwaiter().GetResult();
        var error = ended.GetAwaiter().GetResult();

        try { _tcp?.Close(); } catch { }
        lock (_bondedSockets) { foreach (var sk in _bondedSockets) { try { sk.Close(); } catch { } } }
        lock (streams) { foreach (var s in streams) { try { s.Tls?.Dispose(); } catch { } } }
        try { Task.WaitAll(jobs.ToArray(), 2000); } catch { }

        if (!ct.IsCancellationRequested && error is not OperationCanceledException)
            throw error; // let ConnectWithRetry decide whether to reconnect
    }

    // ── misc ─────────────────────────────────────────────────────────────────────
    private static IPAddress ResolveServer(string address)
    {
        if (IPAddress.TryParse(address, out var ip)) return ip;
        var addrs = Dns.GetHostAddresses(address);
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
        var pool = new[] { "www.cloudflare.com", "www.microsoft.com", "www.apple.com", "www.google.com" };
        return pool[RandomNumberGenerator.GetInt32(pool.Length)];
    }
}
