using System.Security.Cryptography;
using Qeli.Shared.Crypto;

namespace Qeli.Shared.Protocol;

public sealed class PacketException : Exception
{
    public PacketException(string message) : base(message) { }
}

/// <summary>
/// Frames/deframes data-plane records. Direct port of Android PacketCodec.kt.
/// Wire layout: TLS record header [0x17 0x03 0x03 len_hi len_lo] || nonce(12) ||
/// ChaCha20-Poly1305( counter(8) || plaintext || padding || pad_len(2) ).
/// Includes the same 64-entry anti-replay sliding window as the server.
/// </summary>
public sealed class PacketCodec
{
    public const int HeaderSize = 5;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int CounterSize = 8;
    public const int ReplayWindow = 64;
    public const byte ApplicationData = 0x17;
    public const int MaxRecordSize = 16384 + NonceSize + TagSize + CounterSize + 256;

    private readonly PacketCipher _cipher;
    private bool _paddingEnabled;
    private int _paddingMin;
    private int _paddingMax;

    // Wire framing. TLS (5-byte 0x17 0x03 0x03 + u16 len) for fake-tls/obfs/reality;
    // Raw (bare u16 len, RAW_RECORD_HEADER) for the `plain` wire mode. Mirrors the
    // Rust PacketCodec Framing::Tls / Framing::Raw.
    private readonly bool _raw;
    private readonly int _headerSize;

    private long _counter;            // outbound, monotonically increasing
    private long _replayHighest = -1; // inbound replay window
    private ulong _replayBitmap;

    public PacketCodec(PacketCipher cipher, bool paddingEnabled = true, int paddingMin = 0, int paddingMax = 255,
        bool raw = false)
    {
        _cipher = cipher;
        _paddingEnabled = paddingEnabled;
        _paddingMin = paddingMin;
        _paddingMax = paddingMax;
        _raw = raw;
        _headerSize = raw ? 2 : HeaderSize;
    }

    /// <summary>Apply server-pushed padding params without resetting the packet counter.</summary>
    public void SetPadding(bool enabled, int min, int max)
    {
        _paddingEnabled = enabled;
        _paddingMin = min;
        _paddingMax = max;
    }

    private bool AcceptCounter(long seq)
    {
        if (_replayHighest < 0) { _replayHighest = seq; _replayBitmap = 1UL; return true; }
        if (seq > _replayHighest)
        {
            long shift = seq - _replayHighest;
            _replayBitmap = shift >= ReplayWindow ? 1UL : (_replayBitmap << (int)shift) | 1UL;
            _replayHighest = seq;
            return true;
        }
        long diff = _replayHighest - seq;
        if (diff >= ReplayWindow) return false;
        ulong mask = 1UL << (int)diff;
        if ((_replayBitmap & mask) != 0) return false;
        _replayBitmap |= mask;
        return true;
    }

    private static byte[] BuildTlsRecordHeader(byte contentType, int length) => new[]
    {
        contentType, (byte)0x03, (byte)0x03,
        (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF),
    };

    public byte[] Encrypt(byte[] plaintext)
    {
        long currentCounter = Interlocked.Increment(ref _counter) - 1;
        if (currentCounter >= long.MaxValue - 1000)
            throw new PacketException("Counter exhausted - session must be renegotiated");

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        int paddingLen = 0;
        if (_paddingEnabled)
        {
            int lo = Math.Clamp(_paddingMin, 0, 65535);
            int hi = Math.Clamp(_paddingMax, lo, 65535);
            paddingLen = hi > lo ? lo + RandomNumberGenerator.GetInt32(hi - lo + 1) : lo;
        }
        var padding = new byte[paddingLen];
        if (paddingLen > 0) RandomNumberGenerator.Fill(padding);

        var inner = new byte[CounterSize + plaintext.Length + paddingLen + 2];
        inner[0] = (byte)((currentCounter >> 56) & 0xFF);
        inner[1] = (byte)((currentCounter >> 48) & 0xFF);
        inner[2] = (byte)((currentCounter >> 40) & 0xFF);
        inner[3] = (byte)((currentCounter >> 32) & 0xFF);
        inner[4] = (byte)((currentCounter >> 24) & 0xFF);
        inner[5] = (byte)((currentCounter >> 16) & 0xFF);
        inner[6] = (byte)((currentCounter >> 8) & 0xFF);
        inner[7] = (byte)(currentCounter & 0xFF);
        Buffer.BlockCopy(plaintext, 0, inner, CounterSize, plaintext.Length);
        Buffer.BlockCopy(padding, 0, inner, CounterSize + plaintext.Length, paddingLen);
        inner[^2] = (byte)((paddingLen >> 8) & 0xFF);
        inner[^1] = (byte)(paddingLen & 0xFF);

        var ciphertext = _cipher.Encrypt(inner, nonce);

        int payloadLen = NonceSize + ciphertext.Length;

        var packet = new byte[_headerSize + payloadLen];
        if (_raw)
        {
            // Bare 2-byte big-endian length prefix (no TLS type/version).
            packet[0] = (byte)((payloadLen >> 8) & 0xFF);
            packet[1] = (byte)(payloadLen & 0xFF);
        }
        else
        {
            var header = BuildTlsRecordHeader(ApplicationData, payloadLen);
            Buffer.BlockCopy(header, 0, packet, 0, HeaderSize);
        }
        Buffer.BlockCopy(nonce, 0, packet, _headerSize, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, packet, _headerSize + NonceSize, ciphertext.Length);
        return packet;
    }

    public byte[] Decrypt(byte[] packet)
    {
        if (packet.Length < _headerSize + NonceSize + TagSize + CounterSize + 2)
            throw new PacketException($"Packet too short: {packet.Length}");

        int payloadLen;
        if (_raw)
        {
            payloadLen = ((packet[0] & 0xFF) << 8) | (packet[1] & 0xFF);
        }
        else
        {
            if (packet[0] != ApplicationData)
                throw new PacketException($"Wrong content type: {packet[0]}");
            payloadLen = ((packet[3] & 0xFF) << 8) | (packet[4] & 0xFF);
        }
        if (payloadLen > MaxRecordSize)
            throw new PacketException($"Packet too large: {payloadLen}");
        // Defensive bounds (parity with the Rust decoder): the declared length must
        // be large enough to hold nonce+tag+counter+pad_len AND no larger than the
        // bytes actually present, otherwise the slices below would throw a raw
        // ArgumentOutOfRangeException on a malformed/truncated record. (L3)
        if (payloadLen < NonceSize + TagSize + CounterSize + 2
            || _headerSize + payloadLen > packet.Length)
            throw new PacketException(
                $"Packet truncated: payloadLen={payloadLen}, have={packet.Length - _headerSize}");

        var nonce = packet[_headerSize..(_headerSize + NonceSize)];
        var ciphertext = packet[(_headerSize + NonceSize)..(_headerSize + payloadLen)];

        var plaintext = _cipher.Decrypt(ciphertext, nonce);
        if (plaintext.Length < CounterSize + 2)
            throw new PacketException($"Decrypted payload too short: {plaintext.Length}");

        long packetCounter =
            ((long)(plaintext[0] & 0xFF) << 56) | ((long)(plaintext[1] & 0xFF) << 48) |
            ((long)(plaintext[2] & 0xFF) << 40) | ((long)(plaintext[3] & 0xFF) << 32) |
            ((long)(plaintext[4] & 0xFF) << 24) | ((long)(plaintext[5] & 0xFF) << 16) |
            ((long)(plaintext[6] & 0xFF) << 8) | (long)(plaintext[7] & 0xFF);

        if (!AcceptCounter(packetCounter))
            throw new PacketException($"Replay detected: counter {packetCounter} (window highest {_replayHighest})");

        int paddingLen = ((plaintext[^2] & 0xFF) << 8) | (plaintext[^1] & 0xFF);
        if (CounterSize + paddingLen + 2 > plaintext.Length)
            throw new PacketException($"Invalid padding: {paddingLen}");

        int dataLen = plaintext.Length - CounterSize - 2 - paddingLen;
        return plaintext[CounterSize..(CounterSize + dataLen)];
    }
}
