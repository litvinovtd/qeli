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
/// </summary>
public sealed class ObfsStream
{
    private const int NonceLen = 12;

    private readonly ChaCha7539Engine _writeCipher;
    private readonly ChaCha7539Engine _readCipher;
    private readonly object _writeLock = new();
    private readonly object _readLock = new();

    private ObfsStream(ChaCha7539Engine writeCipher, ChaCha7539Engine readCipher)
    {
        _writeCipher = writeCipher;
        _readCipher = readCipher;
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
    /// </summary>
    public static ObfsStream Connect(byte[] key, bool fronting, Action<byte[]> sendRaw, Func<int, byte[]> recvRaw)
    {
        if (fronting)
        {
            sendRaw(BuildWsRequest());
            string head = ReadHttpHead(recvRaw);
            if (!head.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
                throw new IOException("obfs ws: server did not switch protocols");
        }
        var local = new byte[NonceLen];
        RandomNumberGenerator.Fill(local);
        sendRaw(local);
        var peer = recvRaw(NonceLen);
        return new ObfsStream(MakeCipher(key, local), MakeCipher(key, peer));
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
}
