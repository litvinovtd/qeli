using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Qeli.Shared.Protocol;

/// <summary>
/// `obfs` wire mode (TCP only). Mirrors Android ObfsStream.kt / qeli/src/protocol/obfs.rs.
/// The whole connection is XORed with a ChaCha20 (RFC 8439, 12-byte nonce, counter 0)
/// keystream keyed by a PSK. Each side sends a random 12-byte nonce in the clear, then
/// derives its send keystream from its own nonce and its receive keystream from the peer's.
///
/// Two config-gated additions layer on top (OFF by default → byte-identical wire):
///   • F2 AmneziaWG junk (Jc/Jmin/Jmax): before the nonce exchange, each side emits and
///     consumes <c>jc</c> junk records of random length in [jmin,jmax].
///   • F3 WebSocket binary framing: when fronting=websocket, the entire post-101 stream
///     (junk, nonce exchange and all data) is carried in RFC-6455 binary frames.
/// </summary>
public sealed class ObfsStream
{
    private const int NonceLen = 12;

    // ── F2 AmneziaWG junk caps (bound memory) ─────────────────────────────────
    private const uint AwgJcCap = 128;
    private const ushort AwgLenCap = 1400;

    // ── F3 WebSocket binary-framing caps ──────────────────────────────────────
    /// <summary>Max payload we EMIT per WS binary frame (F3). Reads still accept the
    /// 8-byte extended-length form, but we never produce frames larger than this.</summary>
    private const int WsFrameMax = 16384;

    private readonly ChaCha7539Engine _writeCipher;
    private readonly ChaCha7539Engine _readCipher;
    private readonly object _writeLock = new();
    private readonly object _readLock = new();

    // When set, the raw byte stream after the WS "101" is carried as RFC-6455 binary
    // frames (F3). The reframer keeps partial-frame state across reads. Null =>
    // fronting!=websocket => raw continuous stream (byte-identical to the pre-F3 wire).
    private readonly WsReframer? _wsReframer;

    /// <summary>True when the post-101 stream is RFC-6455 binary-framed (F3).</summary>
    public bool WsActive => _wsReframer != null;

    private ObfsStream(ChaCha7539Engine writeCipher, ChaCha7539Engine readCipher, WsReframer? wsReframer)
    {
        _writeCipher = writeCipher;
        _readCipher = readCipher;
        _wsReframer = wsReframer;
    }

    public byte[] TransformWrite(byte[] data)
    {
        lock (_writeLock)
        {
            var outBuf = new byte[data.Length];
            _writeCipher.ProcessBytes(data, 0, data.Length, outBuf, 0);
            return outBuf;
        }
    }

    public byte[] TransformRead(byte[] data)
    {
        lock (_readLock)
        {
            var outBuf = new byte[data.Length];
            _readCipher.ProcessBytes(data, 0, data.Length, outBuf, 0);
            return outBuf;
        }
    }

    /// <summary>key = SHA256("qeli-obfs-key-v1" || psk)</summary>
    public static byte[] DeriveKey(string psk)
    {
        using var sha = SHA256.Create();
        var prefix = Encoding.UTF8.GetBytes("qeli-obfs-key-v1");
        var pskBytes = Encoding.UTF8.GetBytes(psk);
        var input = new byte[prefix.Length + pskBytes.Length];
        Buffer.BlockCopy(prefix, 0, input, 0, prefix.Length);
        Buffer.BlockCopy(pskBytes, 0, input, prefix.Length, pskBytes.Length);
        return sha.ComputeHash(input);
    }

    private static ChaCha7539Engine MakeCipher(byte[] key, byte[] nonce)
    {
        var engine = new ChaCha7539Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        return engine;
    }

    // ── F2 AmneziaWG junk (Jc/Jmin/Jmax) ─────────────────────────────────────
    // Config-gated, OFF by default. Both ends MUST agree on `jc` (the count of junk
    // records exchanged); `jmin`/`jmax` bound each record's random length and are
    // sender-only. jc=0/disabled => zero extra bytes => byte-identical wire.

    /// <summary>AmneziaWG-style pre-handshake junk parameters (F2).</summary>
    public readonly struct AwgParams
    {
        public bool Enabled { get; init; }
        public uint Jc { get; init; }
        public ushort Jmin { get; init; }
        public ushort Jmax { get; init; }

        /// <summary>Defaults mirror the Rust AwgParams::default: disabled, jc=0,
        /// jmin=40, jmax=300.</summary>
        public static AwgParams Default => new() { Enabled = false, Jc = 0, Jmin = 40, Jmax = 300 };

        /// <summary>Effective junk-record count after the config gate + cap. Zero when
        /// disabled or jc==0 (→ byte-identical to the pre-F2 wire).</summary>
        public uint EffectiveJc() => Enabled ? Math.Min(Jc, AwgJcCap) : 0;

        /// <summary>Clamp the per-record length window into [jmin, min(jmax, CAP)].</summary>
        public (ushort jmin, ushort jmax) ClampWindow()
        {
            ushort jmax = Math.Min(Jmax, AwgLenCap);
            ushort jmin = Math.Min(Jmin, jmax);
            return (jmin, jmax);
        }
    }

    /// <summary>Emit <c>jc</c> junk records via <paramref name="sendRaw"/>. Non-ws
    /// fronting: each record is [u16 BE len][len random bytes]. Websocket fronting:
    /// each record is ONE WS binary frame whose payload is len random bytes. No-op
    /// when jc==0.</summary>
    private static void SendJunk(AwgParams awg, bool ws, Action<byte[]> sendRaw)
    {
        uint jc = awg.EffectiveJc();
        if (jc == 0) return;
        var (jmin, jmax) = awg.ClampWindow();
        for (uint i = 0; i < jc; i++)
        {
            // Inclusive [jmin, jmax] random length (GetInt32 upper bound is exclusive).
            int len = jmin + RandomNumberGenerator.GetInt32(jmax - jmin + 1);
            var body = RandomNumberGenerator.GetBytes(len);
            if (ws)
            {
                sendRaw(WsEncodeFrame(body, RandomNumberGenerator.GetBytes(4)));
            }
            else
            {
                var rec = new byte[2 + len];
                rec[0] = (byte)((len >> 8) & 0xFF);
                rec[1] = (byte)(len & 0xFF);
                Buffer.BlockCopy(body, 0, rec, 2, len);
                sendRaw(rec);
            }
        }
    }

    /// <summary>Read and DISCARD exactly <c>jc</c> junk records. Non-ws fronting:
    /// [u16 BE len] then len bytes. Websocket fronting: exactly one WS binary frame's
    /// payload per record (via <paramref name="reframer"/>). No-op when jc==0.</summary>
    private static void ConsumeJunk(AwgParams awg, WsReframer? reframer,
        Func<int, byte[]> recvRaw)
    {
        uint jc = awg.EffectiveJc();
        if (jc == 0) return;
        for (uint i = 0; i < jc; i++)
        {
            if (reframer != null)
            {
                reframer.NextFramePayload(recvRaw); // one frame == one junk record
            }
            else
            {
                var hdr = recvRaw(2);
                int len = ((hdr[0] & 0xFF) << 8) | (hdr[1] & 0xFF);
                if (len > 0) recvRaw(len);
            }
        }
    }

    // ── F3 WebSocket binary framing (RFC 6455, opcode 0x2) ────────────────────
    // After the "101 Switching Protocols" the ENTIRE post-101 stream (junk, nonce
    // exchange and all data) is carried as binary frames. client->server frames are
    // masked (MASK=1, 4 random mask bytes, payload[i]=cipher[i]^mask[i%4]); the
    // reader is a stateful reframer since TCP can split a header or coalesce frames.
    //
    // Transform order (client->server): ChaCha20 FIRST over the plaintext, THEN the WS
    // mask XOR on top. Receiver (server->client): plain ChaCha20-decrypt, no mask.

    /// <summary>Encode one RFC-6455 binary frame (FIN=1, opcode=0x2). When
    /// <paramref name="mask"/> is non-null (client->server) the payload is masked with
    /// it (4 bytes); when null (server->client) the payload is emitted unmasked. Caps
    /// the emitted payload's length form: &lt;=125 inline, &lt;=65535 the u16 form; the
    /// u64 form is never produced (payloads are chunked to WsFrameMax) but accepted on
    /// read.</summary>
    public static byte[] WsEncodeFrame(byte[] payload, byte[]? mask)
    {
        bool masked = mask != null;
        int len = payload.Length;
        int headerLen = 2 + (len <= 125 ? 0 : len <= 65535 ? 2 : 8) + (masked ? 4 : 0);
        var frame = new byte[headerLen + len];
        int p = 0;
        frame[p++] = 0x82; // FIN=1, opcode=0x2 (binary)
        byte maskBit = (byte)(masked ? 0x80 : 0x00);
        if (len <= 125)
        {
            frame[p++] = (byte)(maskBit | (byte)len);
        }
        else if (len <= 65535)
        {
            frame[p++] = (byte)(maskBit | 126);
            frame[p++] = (byte)((len >> 8) & 0xFF);
            frame[p++] = (byte)(len & 0xFF);
        }
        else
        {
            frame[p++] = (byte)(maskBit | 127);
            for (int s = 56; s >= 0; s -= 8) frame[p++] = (byte)((long)((ulong)len >> s) & 0xFF);
        }
        if (masked)
        {
            Buffer.BlockCopy(mask!, 0, frame, p, 4);
            p += 4;
            for (int i = 0; i < len; i++) frame[p + i] = (byte)(payload[i] ^ mask![i % 4]);
        }
        else
        {
            Buffer.BlockCopy(payload, 0, frame, p, len);
        }
        return frame;
    }

    /// <summary>Chunk <paramref name="cipherbytes"/> into masked client->server binary
    /// frames (each &lt;=WsFrameMax payload) and concatenate them. This is the on-wire
    /// image the WRITER produces after ChaCha20 has already been applied.</summary>
    public static byte[] WsEncodeOutbound(byte[] cipherbytes)
    {
        using var ms = new MemoryStream();
        int off = 0;
        // Preserve empty writes as a single empty frame (matches the raw-stream no-op
        // shape where a zero-length write emits nothing meaningful downstream).
        do
        {
            int n = Math.Min(WsFrameMax, cipherbytes.Length - off);
            var chunk = new byte[n];
            Buffer.BlockCopy(cipherbytes, off, chunk, 0, n);
            var frame = WsEncodeFrame(chunk, RandomNumberGenerator.GetBytes(4));
            ms.Write(frame, 0, frame.Length);
            off += n;
        } while (off < cipherbytes.Length);
        return ms.ToArray();
    }

    /// <summary>Stateful RFC-6455 binary-frame reader. Buffers a partial frame header
    /// or payload tail across socket reads and unmasks server-authored frames (which
    /// per RFC are unmasked; masked server frames are also tolerated). Yields the
    /// unmasked payload = the ChaCha20-cipherbytes to be decrypted.</summary>
    private sealed class WsReframer
    {
        // Decoded-but-not-yet-consumed cipherbytes (frame payloads already unmasked).
        private byte[] _pending = Array.Empty<byte>();
        private int _pendingOff;

        /// <summary>Return exactly the next frame's payload (used to skip one junk
        /// frame during F2 consume).</summary>
        public byte[] NextFramePayload(Func<int, byte[]> recvRaw) => ReadOneFrame(recvRaw);

        /// <summary>Return exactly <paramref name="size"/> cipherbytes, pulling and
        /// deframing as many binary frames as needed and buffering any surplus.</summary>
        public byte[] ReadExact(int size, Func<int, byte[]> recvRaw)
        {
            var outBuf = new byte[size];
            int got = 0;
            // Drain any surplus left from a previous over-read first.
            int avail = _pending.Length - _pendingOff;
            if (avail > 0)
            {
                int take = Math.Min(avail, size);
                Buffer.BlockCopy(_pending, _pendingOff, outBuf, 0, take);
                _pendingOff += take;
                got += take;
            }
            while (got < size)
            {
                var frame = ReadOneFrame(recvRaw);
                if (frame.Length == 0) continue; // empty frame carries no cipherbytes
                int take = Math.Min(frame.Length, size - got);
                Buffer.BlockCopy(frame, 0, outBuf, got, take);
                got += take;
                if (take < frame.Length)
                {
                    _pending = frame;
                    _pendingOff = take;
                }
            }
            return outBuf;
        }

        /// <summary>Read one whole binary frame and return its unmasked payload.
        /// Reads are exact-length (recvRaw blocks for the requested count), so a header
        /// split across TCP reads is handled by requesting the missing bytes; there is
        /// no need to buffer partial *headers* here because recvRaw is exact.</summary>
        private static byte[] ReadOneFrame(Func<int, byte[]> recvRaw)
        {
            byte b0 = recvRaw(1)[0];
            byte opcode = (byte)(b0 & 0x0F);
            byte b1 = recvRaw(1)[0];
            bool masked = (b1 & 0x80) != 0;
            long len = b1 & 0x7F;
            if (len == 126)
            {
                var e = recvRaw(2);
                len = ((long)(e[0] & 0xFF) << 8) | (long)(e[1] & 0xFF);
            }
            else if (len == 127)
            {
                var e = recvRaw(8);
                len = 0;
                for (int i = 0; i < 8; i++) len = (len << 8) | (long)(e[i] & 0xFF);
            }
            byte[] mask = masked ? recvRaw(4) : Array.Empty<byte>();
            var payload = len > 0 ? recvRaw((int)len) : Array.Empty<byte>();
            if (masked)
                for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(payload[i] ^ mask[i % 4]);
            // opcode 0x2 = binary (data); tolerate others by returning their payload
            // (control frames won't appear on this transport). Silence unused warning.
            _ = opcode;
            return payload;
        }
    }

    // ── per-datagram obfs (UDP) ──────────────────────────────────────────────
    // Each datagram is self-contained: a fresh random 12-byte nonce + ChaCha20
    // XOR of the payload. Stateless (tolerates UDP loss/reordering). Mirrors
    // Android ObfsStream.datagramSeal/open and Rust obfs_datagram_seal/open.

    /// <summary>Seal one datagram: [flag(1)][nonce(12)][ChaCha20(key,nonce) XOR payload].
    /// The flag byte has the QUIC fixed bit (0x40) set so the datagram reads as a QUIC
    /// short-header packet, not a high-entropy random blob (DPI-AUDIT tell 4.2). Ignored
    /// on open, so the two sides need not agree on it.</summary>
    public static byte[] DatagramSeal(byte[] key, byte[] payload)
    {
        var nonce = new byte[NonceLen];
        RandomNumberGenerator.Fill(nonce);
        byte flag = (byte)(0x40 | RandomNumberGenerator.GetInt32(0x40));
        var body = new byte[payload.Length];
        MakeCipher(key, nonce).ProcessBytes(payload, 0, payload.Length, body, 0);
        var outBuf = new byte[1 + NonceLen + body.Length];
        outBuf[0] = flag;
        Buffer.BlockCopy(nonce, 0, outBuf, 1, NonceLen);
        Buffer.BlockCopy(body, 0, outBuf, 1 + NonceLen, body.Length);
        return outBuf;
    }

    /// <summary>Open a sealed datagram, or null if too short / malformed.</summary>
    public static byte[]? DatagramOpen(byte[] key, byte[] datagram)
    {
        if (datagram.Length < 1 + NonceLen) return null;
        var nonce = datagram[1..(1 + NonceLen)]; // [0] = QUIC-shaped flag byte
        var body = new byte[datagram.Length - 1 - NonceLen];
        MakeCipher(key, nonce).ProcessBytes(datagram, 1 + NonceLen, body.Length, body, 0);
        return body;
    }

    /// <summary>
    /// Client handshake: write our nonce, read the server's, derive keystreams.
    /// When <paramref name="fronting"/> is set, a WebSocket Upgrade handshake is
    /// performed first (mirrors qeli/src/protocol/obfs.rs::ws and Android
    /// ObfsStream.kt) so the connection's first bytes are printable HTTP text and
    /// survive the GFW/TSPU "fully encrypted traffic" heuristic.
    ///
    /// When <paramref name="fronting"/> is set the post-101 stream is RFC-6455
    /// binary-framed (F3): the nonce exchange (and, on the returned stream, all data)
    /// travels in binary frames. F2 junk (<paramref name="awg"/>, OFF by default) is
    /// emitted/consumed before the nonce exchange.
    /// </summary>
    public static ObfsStream Connect(byte[] key, bool fronting, Action<byte[]> sendRaw, Func<int, byte[]> recvRaw)
        => ConnectInternal(key, fronting, AwgParams.Default, sendRaw, recvRaw);

    /// <summary>Overload carrying the F2 AmneziaWG junk parameters as flat scalars (the
    /// shape the VpnTunnelBase caller passes from config): <paramref name="jc"/>&gt;0
    /// enables junk. The 4-arg overload is retained (junk-off) so the jc=0 /
    /// fronting=none path is byte-identical to the pre-F2/F3 wire.</summary>
    public static ObfsStream Connect(byte[] key, bool fronting,
        Action<byte[]> sendRaw, Func<int, byte[]> recvRaw, uint jc, ushort jmin, ushort jmax)
        => ConnectInternal(key, fronting,
            new AwgParams { Enabled = jc > 0, Jc = jc, Jmin = jmin, Jmax = jmax }, sendRaw, recvRaw);

    private static ObfsStream ConnectInternal(byte[] key, bool fronting, AwgParams awg,
        Action<byte[]> sendRaw, Func<int, byte[]> recvRaw)
    {
        if (fronting)
        {
            sendRaw(BuildWsRequest());
            string head = ReadHttpHead(recvRaw);
            if (!head.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
                throw new IOException("obfs ws: server did not switch protocols");
        }

        // F3: after the 101, the whole stream is binary-framed. The reframer is stateful
        // and reused for junk consume + nonce read + all later reads.
        WsReframer? reframer = fronting ? new WsReframer() : null;

        // F2: before the nonce exchange, emit `jc` junk records and read/discard `jc`.
        SendJunk(awg, fronting, sendRaw);
        ConsumeJunk(awg, reframer, recvRaw);

        var local = new byte[NonceLen];
        RandomNumberGenerator.Fill(local);
        // Nonce is pre-cipher: its "cipherbyte" is the raw nonce. Under WS it still
        // travels in a masked client->server binary frame.
        if (fronting) sendRaw(WsEncodeFrame(local, RandomNumberGenerator.GetBytes(4)));
        else sendRaw(local);

        var peer = reframer != null ? reframer.ReadExact(NonceLen, recvRaw) : recvRaw(NonceLen);
        return new ObfsStream(MakeCipher(key, local), MakeCipher(key, peer), reframer);
    }

    /// <summary>WS-frame already-ciphered outbound bytes for the socket (client->server,
    /// masked). Called by the transport's raw-write path when <see cref="WsActive"/>.</summary>
    public byte[] WsWrap(byte[] cipherbytes) => WsEncodeOutbound(cipherbytes);

    /// <summary>Return exactly <paramref name="size"/> inbound cipherbytes, deframing WS
    /// binary frames (server->client, unmasked) as needed. Called by the transport's
    /// raw-read path when <see cref="WsActive"/>.</summary>
    public byte[] WsReadExact(int size, Func<int, byte[]> recvRaw)
    {
        if (_wsReframer == null) throw new InvalidOperationException("WsReadExact called on a non-WS stream");
        return _wsReframer.ReadExact(size, recvRaw);
    }

    // ── WebSocket-Upgrade fronting (client side) ─────────────────────────────

    private const int MaxHttpHead = 4096;

    private static readonly string[] WsHosts =
    {
        "www.cloudflare.com", "www.google.com", "www.microsoft.com",
        "www.apple.com", "www.amazon.com",
    };

    private static readonly string[] WsUserAgents =
    {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    };

    private const string PathAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>Build a randomised WebSocket Upgrade request (the client's first bytes).</summary>
    private static byte[] BuildWsRequest()
    {
        string host = WsHosts[RandomNumberGenerator.GetInt32(WsHosts.Length)];
        string ua = WsUserAgents[RandomNumberGenerator.GetInt32(WsUserAgents.Length)];
        int pathLen = 12 + RandomNumberGenerator.GetInt32(17); // 12..28
        var path = new StringBuilder(pathLen + 1).Append('/');
        for (int i = 0; i < pathLen; i++)
            path.Append(PathAlphabet[RandomNumberGenerator.GetInt32(PathAlphabet.Length)]);
        string wsKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        string req =
            $"GET {path} HTTP/1.1\r\n" +
            $"Host: {host}\r\n" +
            $"User-Agent: {ua}\r\n" +
            "Accept: */*\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Key: {wsKey}\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "\r\n";
        return Encoding.ASCII.GetBytes(req);
    }

    /// <summary>Read an HTTP head up to and including CRLFCRLF, bounded (anti-OOM).</summary>
    private static string ReadHttpHead(Func<int, byte[]> recvRaw)
    {
        var buf = new List<byte>(256);
        int window = 0; // rolling big-endian last-4-bytes tracker for "\r\n\r\n"
        while (true)
        {
            var b = recvRaw(1);
            if (b == null || b.Length == 0)
                throw new IOException("obfs ws: connection closed during handshake");
            buf.Add(b[0]);
            window = (window << 8) | b[0];
            if (buf.Count >= 4 && window == 0x0D0A0D0A)
                return Encoding.ASCII.GetString(buf.ToArray());
            if (buf.Count > MaxHttpHead)
                throw new IOException("obfs ws: handshake head too large");
        }
    }

    // ── self-tests (invoked from CliRunner.SelfTest) ─────────────────────────
    /// <summary>Assert the mandated F3 masking vector plus a junk + WS round-trip so the
    /// three language implementations provably agree. Returns true on success. See the
    /// coordinated wire spec F3: post-cipher [0x01,0x02,0x03] with mask
    /// [0xAA,0xBB,0xCC,0xDD] MUST emit [0x82,0x83,0xAA,0xBB,0xCC,0xDD,0xAB,0xB9,0xCF].</summary>
    public static bool SelfTestWsFraming()
    {
        // F3 MANDATORY VECTOR: exact client->server frame for a known cipher+mask.
        var frame = WsEncodeFrame(new byte[] { 0x01, 0x02, 0x03 },
            new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
        var expected = new byte[] { 0x82, 0x83, 0xAA, 0xBB, 0xCC, 0xDD, 0xAB, 0xB9, 0xCF };
        if (!frame.SequenceEqual(expected)) return false;

        // Server->client is unmasked: byte1 has no MASK bit, payload verbatim.
        var srvFrame = WsEncodeFrame(new byte[] { 0x01, 0x02, 0x03 }, null);
        if (!srvFrame.SequenceEqual(new byte[] { 0x82, 0x03, 0x01, 0x02, 0x03 })) return false;

        // WS reframer round-trip: encode outbound (chunked+masked), then read it back
        // exactly across an arbitrary read split. Reader unmasks → recovers cipherbytes.
        var cipherbytes = RandomNumberGenerator.GetBytes(40000); // spans >2 WsFrameMax frames
        var onWire = WsEncodeOutbound(cipherbytes);
        int pos = 0;
        Func<int, byte[]> recv = n =>
        {
            var chunk = new byte[n];
            Buffer.BlockCopy(onWire, pos, chunk, 0, n);
            pos += n;
            return chunk;
        };
        var reframer = new WsReframer();
        var got = new List<byte>();
        // Read in odd-sized bites to exercise partial-frame buffering.
        int[] bites = { 1, 7, 13000, 100, 26892 };
        foreach (var sz in bites) got.AddRange(reframer.ReadExact(sz, recv));
        if (!got.ToArray().SequenceEqual(cipherbytes)) return false;

        // F2 junk round-trip (websocket path): SendJunk → ConsumeJunk consumes exactly
        // jc frames, leaving the following nonce frame intact for the reframer.
        var awg = new AwgParams { Enabled = true, Jc = 3, Jmin = 40, Jmax = 300 };
        using var jb = new MemoryStream();
        SendJunk(awg, ws: true, b => jb.Write(b, 0, b.Length));
        var nonce = RandomNumberGenerator.GetBytes(NonceLen);
        var nonceFrame = WsEncodeFrame(nonce, RandomNumberGenerator.GetBytes(4));
        jb.Write(nonceFrame, 0, nonceFrame.Length);
        var junkWire = jb.ToArray();
        int jpos = 0;
        Func<int, byte[]> jrecv = n =>
        {
            var chunk = new byte[n];
            Buffer.BlockCopy(junkWire, jpos, chunk, 0, n);
            jpos += n;
            return chunk;
        };
        var jre = new WsReframer();
        ConsumeJunk(awg, jre, jrecv);
        var recoveredNonce = jre.ReadExact(NonceLen, jrecv);
        if (!recoveredNonce.SequenceEqual(nonce)) return false;

        // F2 junk round-trip (non-ws path): [u16 len][bytes] framing, jc records consumed.
        using var jb2 = new MemoryStream();
        SendJunk(awg, ws: false, b => jb2.Write(b, 0, b.Length));
        // Append a sentinel so ConsumeJunk stopping at exactly jc records is observable.
        var sentinel = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        jb2.Write(sentinel, 0, sentinel.Length);
        var junkWire2 = jb2.ToArray();
        int jpos2 = 0;
        Func<int, byte[]> jrecv2 = n =>
        {
            var chunk = new byte[n];
            Buffer.BlockCopy(junkWire2, jpos2, chunk, 0, n);
            jpos2 += n;
            return chunk;
        };
        ConsumeJunk(awg, null, jrecv2);
        var tail = jrecv2(4);
        if (!tail.SequenceEqual(sentinel)) return false;

        // jc=0 / disabled emits ZERO bytes (regression guard: byte-identical wire).
        using var jz = new MemoryStream();
        SendJunk(AwgParams.Default, ws: false, b => jz.Write(b, 0, b.Length));
        SendJunk(AwgParams.Default, ws: true, b => jz.Write(b, 0, b.Length));
        SendJunk(new AwgParams { Enabled = true, Jc = 0, Jmin = 40, Jmax = 300 },
            ws: true, b => jz.Write(b, 0, b.Length));
        if (jz.Length != 0) return false;

        return true;
    }
}
