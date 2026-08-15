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
    public const int ReplayWindow = 2048; // WireGuard-sized anti-replay window (M-13)
    public const int ReplayWords = ReplayWindow / 64;
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
    // "Not initialised yet" used to be encoded as `_replayHighest < 0`, which collides with
    // every counter whose top bit is set. One record with a counter >= 2^63 — the sequence
    // comes straight out of the decrypted plaintext, so a hostile or compromised server picks
    // it — left _replayHighest negative, and from then on the `< 0` branch fired on EVERY
    // packet and returned true unconditionally: the window was off for the rest of the
    // session and any captured record could be replayed at will. Rust keeps a separate
    // `initialized` flag and a u64 counter; Swift uses `UInt64?`. Only C# and Kotlin encoded
    // the sentinel in-band. (Audit 2026-08-04, H-06.)
    private bool _replayInitialized;
    private long _replayHighest;      // inbound replay window (unsigned value in a long)
    private readonly ulong[] _replayBits = new ulong[ReplayWords]; // 2048-bit window (M-13)

    // M6: per-instance nonce seed + PRP key. The nonce goes on the wire and the peer never
    // inverts the PRP (it reads the nonce off the wire), so these are local randomness and
    // need NOT match the peer's — they only have to make (seed‖counter) unique per key, which
    // a monotonic counter + fresh per-session key guarantee. Fresh seed per instance also
    // keeps nonces unique across a reconnect that reused the key.
    private readonly byte[] _nonceSeed = RandomNumberGenerator.GetBytes(4);
    private readonly byte[] _noncePrpKey = RandomNumberGenerator.GetBytes(32);

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

    /// <summary>Anti-replay verdict for <paramref name="seq"/>, recording it as seen.
    /// `internal` so the shared replay-window fixture (<c>conformance/replay-window.json</c>)
    /// can drive it directly — the window is pure state, and going through Decrypt would
    /// need a valid record per sequence number.</summary>
    internal bool AcceptCounter(long seq)
    {
        // The counter is an UNSIGNED 64-bit wire value; `long` only holds its bit pattern,
        // so every comparison below goes through `ulong`. See _replayInitialized.
        ulong s = (ulong)seq, highest = (ulong)_replayHighest;
        if (!_replayInitialized)
        {
            _replayInitialized = true;
            _replayHighest = seq;
            _replayBits[0] = 1UL;
            return true;
        }
        if (s > highest)
        {
            ulong advance = s - highest;
            if (advance >= ReplayWindow) Array.Clear(_replayBits, 0, ReplayWords);
            else ShiftWindow((int)advance);
            _replayHighest = seq;
            _replayBits[0] |= 1UL; // distance 0 = current highest seq
            return true;
        }
        ulong diff = highest - s;
        if (diff >= ReplayWindow) return false;
        ulong mask = 1UL << (int)(diff % 64);
        int wi = (int)(diff / 64);
        if ((_replayBits[wi] & mask) != 0) return false;
        _replayBits[wi] |= mask;
        return true;
    }

    /// <summary>Multi-word left shift of the replay window by <paramref name="n"/> bits
    /// (toward higher distance), discarding bits that fall off the top.</summary>
    private void ShiftWindow(int n)
    {
        int words = n / 64, off = n % 64;
        if (off == 0)
            for (int i = ReplayWords - 1; i >= 0; i--)
                _replayBits[i] = i >= words ? _replayBits[i - words] : 0UL;
        else
            for (int i = ReplayWords - 1; i >= 0; i--)
            {
                ulong lo = i >= words ? _replayBits[i - words] << off : 0UL;
                ulong hi = i > words ? _replayBits[i - words - 1] >> (64 - off) : 0UL;
                _replayBits[i] = lo | hi;
            }
    }

    private static byte[] BuildTlsRecordHeader(byte contentType, int length) => new[]
    {
        contentType, (byte)0x03, (byte)0x03,
        (byte)((length >> 8) & 0xFF), (byte)(length & 0xFF),
    };

    public byte[] Encrypt(byte[] plaintext)
    {
        int paddingLen = 0;
        if (_paddingEnabled)
        {
            int lo = Math.Clamp(_paddingMin, 0, 65535);
            int hi = Math.Clamp(_paddingMax, lo, 65535);
            paddingLen = hi > lo ? lo + RandomNumberGenerator.GetInt32(hi - lo + 1) : lo;
        }
        return EncryptPadded(plaintext, paddingLen);
    }

    /// <summary>Encrypt with the configured padding range, but capped so that
    /// plaintext+padding never exceeds <paramref name="maxInnerPlusPad"/>. Keeps the
    /// padded record inside the (probed) tunnel MTU so a DF-marked UDP datagram is not
    /// dropped with EMSGSIZE after path-MTU probing — the server pushes 40–400 B of
    /// padding, which otherwise pushes every full-size data packet past the path MTU.
    /// Mirrors the Rust client's per-packet pad_cap (client/mod.rs).</summary>
    public byte[] EncryptCapped(byte[] plaintext, int maxInnerPlusPad)
    {
        if (!_paddingEnabled) return EncryptPadded(plaintext, 0);
        int room = Math.Max(0, maxInnerPlusPad - plaintext.Length);
        int lo = Math.Clamp(_paddingMin, 0, room);
        int hi = Math.Clamp(_paddingMax, lo, room);
        int pad = hi > lo ? lo + RandomNumberGenerator.GetInt32(hi - lo + 1) : lo;
        return EncryptPadded(plaintext, pad);
    }

    /// <summary>Encrypt with an EXPLICIT padding length, ignoring the codec's
    /// configured padding range. Used by flow-shaping cover traffic to emit
    /// browsing-sized cover packets (empty plaintext + sized padding); the wire
    /// format is byte-identical to <see cref="Encrypt(byte[])"/>.</summary>
    public byte[] EncryptPadded(byte[] plaintext, int paddingLen)
    {
        long currentCounter = Interlocked.Increment(ref _counter) - 1;
        if (currentCounter >= long.MaxValue - 1000)
            throw new PacketException("Counter exhausted - session must be renegotiated");

        // Counter-derived, collision-free, DPI-opaque nonce (was a random 96-bit value,
        // which carries a birthday-bound collision risk the Rust core eliminates). See
        // NonceForCounter / PrpNonce. (client-audit M6)
        var nonce = NonceForCounter(currentCounter);

        paddingLen = Math.Clamp(paddingLen, 0, 65535);
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
        // Guard the record size BEFORE writing the 16-bit length field (parity with Rust
        // encrypt_packet's MAX_RECORD_SIZE check). Without it, an oversized padding_max or
        // shaping cover size can build a record the peer rejects as too large (16677-65535),
        // and past 65535 the length write wraps and desyncs the whole TCP stream. Fail here
        // instead of emitting a record we (or the peer) can't parse.
        if (payloadLen > MaxRecordSize)
            throw new PacketException(
                $"record payload {payloadLen} exceeds MaxRecordSize {MaxRecordSize} — " +
                "reduce padding_max or the shaping cover size");

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

    // ── M6: counter-derived data-plane nonce (mirrors Rust packet.rs) ────────────
    /// <summary>Build the 96-bit wire nonce for <paramref name="counter"/> as
    /// PRP(seed(4) ‖ counter_be(8)). A balanced Feistel network is bijective for any round
    /// function, so distinct (seed,counter) inputs — counter is monotonic — always map to
    /// distinct nonces (no AEAD nonce reuse), while the on-wire value no longer increments by
    /// 1 (no visible-counter DPI tell). Replaces the previous random 96-bit nonce.</summary>
    private byte[] NonceForCounter(long counter) => PrpNonce(_noncePrpKey, RawNonce(_nonceSeed, counter));

    /// <summary>The pre-permutation nonce input: seed(4) ‖ counter big-endian(8). Split out of
    /// <see cref="NonceForCounter"/> so the whole derivation is checkable against the shared
    /// fixture (<c>conformance/prp-nonce.json</c>) without constructing a codec.</summary>
    internal static byte[] RawNonce(byte[] seed, long counter)
    {
        var raw = new byte[NonceSize];
        Buffer.BlockCopy(seed, 0, raw, 0, 4);
        raw[4] = (byte)((counter >> 56) & 0xFF);
        raw[5] = (byte)((counter >> 48) & 0xFF);
        raw[6] = (byte)((counter >> 40) & 0xFF);
        raw[7] = (byte)((counter >> 32) & 0xFF);
        raw[8] = (byte)((counter >> 24) & 0xFF);
        raw[9] = (byte)((counter >> 16) & 0xFF);
        raw[10] = (byte)((counter >> 8) & 0xFF);
        raw[11] = (byte)(counter & 0xFF);
        return raw;
    }

    /// <summary>96-bit balanced Feistel permutation, 4 rounds; round fn = SHA256(key‖round‖half)[..6].
    /// Byte-for-byte identical to Rust <c>packet.rs prp_nonce</c> (not required for interop — the peer
    /// reads the nonce straight off the wire — but kept identical for auditability).</summary>
    internal static byte[] PrpNonce(byte[] key, byte[] raw)
    {
        var l = new byte[6];
        var r = new byte[6];
        Buffer.BlockCopy(raw, 0, l, 0, 6);
        Buffer.BlockCopy(raw, 6, r, 0, 6);
        for (byte round = 0; round < 4; round++)
        {
            var f = PrpRound(key, round, r);
            var nr = new byte[6];
            for (int i = 0; i < 6; i++) nr[i] = (byte)(l[i] ^ f[i]);
            l = r;
            r = nr;
        }
        var outp = new byte[NonceSize];
        Buffer.BlockCopy(l, 0, outp, 0, 6);
        Buffer.BlockCopy(r, 0, outp, 6, 6);
        return outp;
    }

    private static byte[] PrpRound(byte[] key, byte round, byte[] half)
    {
        var input = new byte[key.Length + 1 + half.Length];
        Buffer.BlockCopy(key, 0, input, 0, key.Length);
        input[key.Length] = round;
        Buffer.BlockCopy(half, 0, input, key.Length + 1, half.Length);
        var d = SHA256.HashData(input);
        var outp = new byte[6];
        Buffer.BlockCopy(d, 0, outp, 0, 6);
        return outp;
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
            // The legacy_record_version too, not just the content type. Every record we EMIT
            // carries 0x03 0x03, and a real TLS 1.3 peer emits nothing else on an established
            // connection — so accepting other bytes made the masking framing looser than the
            // thing it imitates, for no gain. (Audit 2026-08-03, P3.)
            if (packet[1] != 0x03 || packet[2] != 0x03)
                throw new PacketException($"Wrong record version: {packet[1]:x2} {packet[2]:x2}");
            payloadLen = ((packet[3] & 0xFF) << 8) | (packet[4] & 0xFF);
        }
        if (payloadLen > MaxRecordSize)
            throw new PacketException($"Packet too large: {payloadLen}");
        // Defensive bounds (parity with the Rust decoder): the declared length must
        // be large enough to hold nonce+tag+counter+pad_len and must consume the complete
        // supplied record. Otherwise truncation would throw a raw range exception, while
        // trailing bytes would remain outside authentication. (L3)
        if (payloadLen < NonceSize + TagSize + CounterSize + 2
            || _headerSize + payloadLen != packet.Length)
            throw new PacketException(
                $"Packet length mismatch: payloadLen={payloadLen}, have={packet.Length - _headerSize}");

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

        // Validate the padding BEFORE recording the counter, like the Rust and iOS clients.
        // A record that decrypts (so it is genuinely from the peer) but carries malformed
        // padding is a peer bug, not an attack — recording it first needlessly burned that
        // counter's slot in the replay window. (Audit 2026-07-30.)
        int paddingLen = ((plaintext[^2] & 0xFF) << 8) | (plaintext[^1] & 0xFF);
        if (CounterSize + paddingLen + 2 > plaintext.Length)
            throw new PacketException($"Invalid padding: {paddingLen}");

        if (!AcceptCounter(packetCounter))
            throw new PacketException($"Replay detected: counter {packetCounter} (window highest {_replayHighest})");

        int dataLen = plaintext.Length - CounterSize - 2 - paddingLen;
        return plaintext[CounterSize..(CounterSize + dataLen)];
    }
}
