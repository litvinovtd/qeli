using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using QeliWin.Crypto;
using QeliWin.Model;
using QeliWin.Protocol;

namespace QeliWin.Vpn;

public enum VpnStatus { Disconnected, Connecting, Connected, Error }

/// <summary>
/// The qeli data plane for Windows. Direct port of the Android QeliService: shared
/// transport-agnostic handshake + tunnel loop over a small Transport abstraction
/// (TCP or UDP/QUIC), feeding a Wintun adapter. Runs on background threads and
/// raises events the WPF UI marshals to the dispatcher.
/// </summary>
public sealed class VpnTunnel
{
    public event Action<string>? LogLine;
    public event Action<VpnStatus, string?>? StatusChanged; // status, optional ip/error
    public event Action<string>? ConnectionDropped;          // established session lost (will retry)
    private void Log(string m) => LogLine?.Invoke(m);
    private void Status(VpnStatus s, string? extra = null) => StatusChanged?.Invoke(s, extra);

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private volatile bool _userRequestedDisconnect;

    // Handshake-only mode (headless --handshake test): stop after auth, skip TUN.
    private bool _handshakeOnly;
    private string? _handshakeIp;

    // True once an established tunnel is up; used to detect a server-side drop.
    private volatile bool _wasConnected;

    // Live transports for the current attempt (closed to interrupt blocking IO).
    private Socket? _tcp;
    private Socket? _udp;
    private ObfsStream? _obfs;
    private WintunAdapter? _wintun;
    private NetworkConfigurator? _net;
    private readonly object _writeLock = new();

    // Live byte counters (goodput, IP-payload bytes) for the UI speed readout.
    private long _bytesUp;
    private long _bytesDown;
    public long BytesUp => Interlocked.Read(ref _bytesUp);
    public long BytesDown => Interlocked.Read(ref _bytesDown);

    /// <summary>When the current tunnel reached Connected (for session duration).</summary>
    public DateTime? ConnectedSince { get; private set; }

    // Stable GUID so the same Wintun adapter is reused across runs.
    private static readonly Guid AdapterGuid = new("d3a1f4e0-1c2b-4a6e-9f10-abcd00000001");

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
        Status(VpnStatus.Disconnected);
    }

    private void CloseTransports()
    {
        try { _tcp?.Close(); } catch { }
        try { _udp?.Close(); } catch { }
        try { _net?.Dispose(); } catch { }
        try { _wintun?.Dispose(); } catch { }
        _tcp = null; _udp = null; _obfs = null; _net = null; _wintun = null;
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
                Status(VpnStatus.Error, "Идентичность сервера изменилась — возможна MITM-атака. Подключение остановлено.");
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
        else Status(VpnStatus.Error, "Не удалось подключиться к серверу"); // gave up retrying
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
        private readonly VpnTunnel _t;
        private readonly bool _raw;   // plain wire mode: bare length-prefixed records
        public TcpTransport(VpnTunnel t, bool raw = false) { _t = t; _raw = raw; }
        public void Send(byte[] record, bool longHeader = false) => _t.WriteFully(record);
        public byte[] RecvRecord() => _raw ? _t.ReadRawRecord() : _t.ReadTlsRecord();
        public void SetReadTimeout(int ms) { }
    }

    private sealed class UdpTransport : ITransport
    {
        private readonly VpnTunnel _t;
        private readonly Socket _sock;
        private readonly bool _quic;
        private readonly byte[] _cid;
        private readonly byte[]? _obfsKey;   // per-datagram ChaCha20 XOR (null = none)
        private int _pn;
        private byte[] _buf = Array.Empty<byte>();
        private int _pos;

        public UdpTransport(VpnTunnel t, Socket sock, bool quic, byte[] cid, byte[]? obfsKey)
        { _t = t; _sock = sock; _quic = quic; _cid = cid; _obfsKey = obfsKey; }

        public void Send(byte[] record, bool longHeader = false)
        {
            byte[] outBuf = _quic
                ? (longHeader ? Quic.WrapLong(record, _cid, _pn++, 0x02) : Quic.WrapShort(record, _cid, _pn++))
                : record;
            if (_obfsKey != null) outBuf = ObfsStream.DatagramSeal(_obfsKey, outBuf);
            lock (_t._writeLock) { _sock.Send(outBuf); }
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
    private RealTls DoRealTlsHandshake(VpnConfig config)
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
        WriteRaw(tls.ClientHello);
        while (!tls.Established)
        {
            var outBuf = tls.Recv(ReadSomeRaw());
            if (outBuf.Length > 0) WriteRaw(outBuf);
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
        ConnectWithTimeout(sock, serverIp, config.Port, (int)config.ConnectionTimeoutSecs * 1000);
        sock.NoDelay = true;
        sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        _tcp = sock;
        Log("TCP connected");

        if (config.WireMode.Equals("plain", StringComparison.OrdinalIgnoreCase))
        {
            // No TLS mimicry at all: raw X25519 key exchange, then the encrypted
            // qeli protocol over bare length-prefixed records (Framing::Raw).
            Log("plain mode: raw key exchange, no TLS mimicry");
            var hs = PerformHandshakePlain(config);
            RunAfterHandshake(config, new TcpTransport(this, raw: true), isUdp: false, serverIp, ct, hs);
            return;
        }

        if (config.WireMode.Equals("reality-tls", StringComparison.OrdinalIgnoreCase))
        {
            // Genuine browser TLS 1.3 (REALITY) carries the tunnel; the existing
            // qeli protocol runs nested inside it via RealTlsTransport.
            var tls = DoRealTlsHandshake(config);
            EstablishAndRun(config, new RealTlsTransport(new TcpTransport(this), tls),
                padToMin: 0, isUdp: false, serverIp, ct);
            return;
        }

        if (config.WireMode.Equals("obfs", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(config.ObfsKey))
                throw new InvalidOperationException("obfs wire mode requires a non-empty obfs_key (an empty key is publicly derivable → no DPI resistance)");
            bool fronting = config.ObfsFronting.Equals("websocket", StringComparison.OrdinalIgnoreCase);
            Log(fronting ? "obfs mode: WebSocket fronting + nonce exchange" : "obfs mode: exchanging nonces");
            var key = ObfsStream.DeriveKey(config.ObfsKey);
            _obfs = ObfsStream.Connect(key, fronting, WriteRaw, ReadRaw);
        }

        EstablishAndRun(config, new TcpTransport(this), padToMin: 0, isUdp: false, serverIp, ct);
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

    /// <summary>Common post-handshake path (status, TUN setup, tunnel loop), shared by
    /// the fake-tls/obfs/reality path and the plain path.</summary>
    private void RunAfterHandshake(VpnConfig config, ITransport transport, bool isUdp, IPAddress serverIp,
        CancellationToken ct, (Session session, VpnConfig effConfig, PacketCodec enc, PacketCodec dec) hs)
    {
        var (session, effConfig, enc, dec) = hs;
        Log($"Auth OK, IP {session.ClientIp}");
        Status(VpnStatus.Connected, session.ClientIp);

        if (_handshakeOnly) { _handshakeIp = session.ClientIp; return; }

        _wasConnected = true;
        ConnectedSince = DateTime.Now;
        SetupTun(effConfig, session, serverIp);
        Log("TUN ready, entering tunnel loop");
        RunTunnelLoop(effConfig, transport, enc, dec, isUdp, ct);
    }

    // ── handshake ───────────────────────────────────────────────────────────────
    private sealed record Session(string ClientIp, int Prefix, string DnsIp, string RoutesJson, int PushedMtu = 0);

    /// <summary>Resolve the effective TUN MTU: an explicit client config value (>0)
    /// wins, else the server-pushed value (>0), else the auto fallback (1400).</summary>
    private static int EffectiveMtu(int configMtu, int pushedMtu) =>
        configMtu > 0 ? configMtu : (pushedMtu > 0 ? pushedMtu : 1400);

    private (Session, VpnConfig, PacketCodec enc, PacketCodec dec) PerformHandshake(
        VpnConfig config, ITransport transport, int padToMin)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();

        string sni = config.Sni ?? PickSni(config.ServerAddress);
        var clientHello = TlsHandshake.BuildClientHello(clientKeyPair.PublicKeyBytes, sni, padToMin);
        transport.Send(clientHello, longHeader: true);
        Log($"ClientHello sent ({clientHello.Length}B)");

        var serverHelloRecord = transport.RecvRecord();
        var serverHelloMsg = ParseHandshakeMessage(serverHelloRecord)
            ?? throw new Exception("Failed to parse ServerHello");
        var serverPublicKey = TlsHandshake.ParseServerHello(serverHelloMsg)
            ?? throw new Exception("Failed to extract server public key");

        var rec = transport.RecvRecord();
        if (TlsHandshake.IsChangeCipherSpec(rec)) rec = transport.RecvRecord();
        var certRecord = rec;
        var finishedRecord = transport.RecvRecord();

        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var (s2c, c2s) = KeyDerivation.DeriveKeys(sharedSecret);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax);
        var dec = new PacketCodec(new PacketCipher(s2c));

        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientHello, serverHelloRecord, certRecord, finishedRecord });

        var authRec = transport.RecvRecord();
        if (authRec.Length > 0 && (authRec[0] & 0xFF) == 0x16) authRec = transport.RecvRecord();
        var authProofMsg = dec.Decrypt(authRec);
        var (staticPub, staticShared) = VerifyServerAuth(
            authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash, config.ServerPublicKeyHex);
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
        return (session, effConfig, enc, dec);
    }

    /// <summary>
    /// `plain` wire mode handshake: no TLS mimicry. Exchange ephemeral X25519 publics
    /// raw, bind the channel to H(client_pub‖server_pub), then run the same encrypted
    /// auth flow over bare length-prefixed records. Mirrors qeli/src/client/mod.rs.
    /// </summary>
    private (Session, VpnConfig, PacketCodec enc, PacketCodec dec) PerformHandshakePlain(VpnConfig config)
    {
        var ke = new KeyExchange();
        var clientKeyPair = ke.GenerateKeyPair();

        // 1. Raw exchange of the 32-byte ephemeral public keys (no framing).
        WriteFully(clientKeyPair.PublicKeyBytes);
        var serverPublicKey = ReadRaw(32);
        Log("plain: exchanged ephemeral keys");

        // 2. Transcript binds to both raw publics.
        var transcriptHash = KeyDerivation.HandshakeTranscript(
            new[] { clientKeyPair.PublicKeyBytes, serverPublicKey });

        var sharedSecret = ke.ComputeSharedSecret(clientKeyPair.PrivateKey, serverPublicKey);
        var (s2c, c2s) = KeyDerivation.DeriveKeys(sharedSecret);
        var enc = new PacketCodec(new PacketCipher(c2s), config.PaddingEnabled, config.PaddingMin, config.PaddingMax, raw: true);
        var dec = new PacketCodec(new PacketCipher(s2c), raw: true);

        // 3. Server auth proof (raw record).
        var authProofMsg = dec.Decrypt(ReadRawRecord());
        var (_, staticShared) = VerifyServerAuth(
            authProofMsg, clientKeyPair.PrivateKey, sharedSecret, transcriptHash, config.ServerPublicKeyHex);
        Log("Server identity verified [OK] (plain)");

        // 4. Client auth.
        var authPlain = BuildClientAuthPlaintext(config, staticShared, sharedSecret, transcriptHash);
        WriteFully(enc.Encrypt(authPlain));

        // 5. Auth response.
        var authResponse = dec.Decrypt(ReadRawRecord());
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
        return (session, effConfig, enc, dec);
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
        return (new Session(clientIp, prefix, dns, routes, mtu), json["obfuscation"] as JsonObject);
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
        byte[] msg, byte[] clientPriv, byte[] ephemeralShared, byte[] transcriptHash, string? pinnedHex)
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
            if (pinnedBytes != null && !serverStaticPub.SequenceEqual(pinnedBytes))
                throw new SecurityException("SERVER KEY MISMATCH - possible MITM");
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

    private static byte[] BuildClientAuthPlaintext(VpnConfig config, byte[] staticShared,
        byte[] ephemeralShared, byte[] transcriptHash)
    {
        var proof = KeyDerivation.DeriveClientKeyProof(staticShared, ephemeralShared, transcriptHash);
        var creds = Encoding.UTF8.GetBytes($"{config.Username}:{config.Password}");
        var outBuf = new byte[proof.Length + creds.Length];
        Buffer.BlockCopy(proof, 0, outBuf, 0, proof.Length);
        Buffer.BlockCopy(creds, 0, outBuf, proof.Length, creds.Length);
        return outBuf;
    }

    // ── TUN + network setup ──────────────────────────────────────────────────────
    private void SetupTun(VpnConfig config, Session session, IPAddress serverIp)
    {
        _net = new NetworkConfigurator(Log);
        uint physicalIf = _net.PhysicalIfIndexFor(serverIp);
        var gateway = _net.FindGatewayFor(serverIp);

        _wintun = new WintunAdapter();
        uint drv = WintunAdapter.RunningDriverVersion();
        _wintun.Open("Qeli", AdapterGuid);
        var (tunIndex, alias) = _net.ResolveInterface(_wintun.Luid);
        Log($"Wintun adapter '{alias}' (if {tunIndex}, driver {drv >> 16}.{drv & 0xFF})");

        _net.SetAddress(alias, session.ClientIp, session.Prefix);
        int mtu = EffectiveMtu(config.Mtu, session.PushedMtu);  // explicit > pushed > 1400
        Log($"TUN MTU: {mtu}");
        _net.SetMtu(alias, mtu);

        // Pin the carrier route to the server through the physical gateway BEFORE
        // we hijack the default route, so the encrypted tunnel never loops on itself.
        if (gateway != null && physicalIf != 0)
            _net.PinServerRoute(serverIp, gateway, physicalIf);
        else
            Log("WARN: could not determine physical gateway; full-tunnel may loop");

        if (config.IsFullTunnel)
        {
            _net.SetFullTunnelRoutes(session.ClientIp, tunIndex);
            _net.CaptureIPv6(alias); // close the dual-stack IPv6 leak (E2)
        }
        else
        {
            foreach (var r in config.IncludeRoutes) _net.AddRoute(r, session.ClientIp, tunIndex);
        }

        if (config.RouteLocalNetworks)
        {
            ApplyPushedRoutes(session.RoutesJson, session.ClientIp, tunIndex);
            foreach (var r in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
                _net.AddRoute(r, session.ClientIp, tunIndex);
            Log("Routing local networks (RFC1918 + pushed) through the tunnel");
        }

        var dns = (config.DnsServers.Count > 0 ? config.DnsServers : new List<string> { session.DnsIp })
            .Where(s => !string.IsNullOrEmpty(s)).ToList();
        _net.SetDns(alias, dns);
    }

    private void ApplyPushedRoutes(string routesJson, string clientIp, uint tunIndex)
    {
        if (string.IsNullOrWhiteSpace(routesJson) || routesJson == "[]") return;
        try
        {
            if (JsonNode.Parse(routesJson) is JsonArray arr)
                foreach (var n in arr)
                {
                    string cidr = (n?["cidr"] as JsonValue)?.GetValue<string>() ?? "";
                    if (cidr.Length > 0) { _net!.AddRoute(cidr, clientIp, tunIndex); Log($"pushed route: {cidr}"); }
                }
        }
        catch (Exception e) { Log($"routes parse error: {e.Message}"); }
    }

    // ── tunnel loop ──────────────────────────────────────────────────────────────
    private void RunTunnelLoop(VpnConfig config, ITransport transport,
        PacketCodec enc, PacketCodec dec, bool isUdp, CancellationToken ct)
    {
        var wintun = _wintun!;
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
                    var pkt = wintun.ReceivePacket(ct);
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
                        wintun.SendPacket(plaintext, plaintext.Length);
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

    private byte[] ReadTlsRecord()
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

    /// <summary>Read one bare length-prefixed record ([u16 len][nonce][ct]) for the
    /// `plain` wire mode. Mirrors read_record(Framing::Raw) on the Rust side.</summary>
    private byte[] ReadRawRecord()
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

    private byte[] ReadBytes(int size)
    {
        var raw = ReadRaw(size);
        return _obfs != null ? _obfs.TransformRead(raw) : raw;
    }

    private byte[] ReadRaw(int size)
    {
        var buf = new byte[size];
        int off = 0;
        while (off < size)
        {
            int n = _tcp!.Receive(buf, off, size - off, SocketFlags.None);
            if (n <= 0) throw new Exception("Connection closed");
            off += n;
        }
        return buf;
    }

    /// <summary>Read whatever raw bytes are available (≥1), for the realtls
    /// handshake which buffers/parses incrementally.</summary>
    private byte[] ReadSomeRaw(int max = 16384)
    {
        var buf = new byte[max];
        int n = _tcp!.Receive(buf, 0, max, SocketFlags.None);
        if (n <= 0) throw new Exception("Connection closed");
        return buf[..n];
    }

    private void WriteFully(byte[] data)
    {
        var outBuf = _obfs != null ? _obfs.TransformWrite(data) : data;
        WriteRaw(outBuf);
    }

    private void WriteRaw(byte[] data)
    {
        lock (_writeLock)
        {
            int off = 0;
            while (off < data.Length)
            {
                int n = _tcp!.Send(data, off, data.Length - off, SocketFlags.None);
                if (n <= 0) throw new Exception("Connection closed");
                off += n;
            }
        }
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
