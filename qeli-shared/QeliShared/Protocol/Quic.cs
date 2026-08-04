using System.Security.Cryptography;

namespace Qeli.Shared.Protocol;

/// <summary>
/// QUIC-masking for the UDP transport. Port of Android Quic.kt / qeli/src/protocol/quic.rs.
/// The data plane is wrapped in QUIC-looking long/short headers so a passive observer
/// sees QUIC packets instead of a raw obfuscated stream.
/// </summary>
public static class Quic
{
    private const int VersionV1 = 0x00000001;
    private const int LongHeaderFlag = 0xC0;
    private const int ShortHeaderFlag = 0x40;

    /// <summary>Bytes <see cref="WrapShort"/> emits ahead of the payload: flags(1) +
    /// connection id(4) + packet number(4). This is the DATA-plane header; the handshake uses
    /// the longer <c>WrapLong</c> one. Public because the path-MTU probe budgets for it.</summary>
    public const int ShortHeaderMin = 1 + 4 + 4;

    public static byte[] GenerateConnectionId()
    {
        var id = new byte[4];
        RandomNumberGenerator.Fill(id);
        return id;
    }

    /// <summary>Append a QUIC variable-length integer in its SHORTEST form (RFC 9000
    /// §16), mirroring <c>quic.rs::push_varint</c>.
    ///
    /// This port used to emit the Length field as a fixed 2-byte varint with a silent
    /// <c>&amp; 0x3FFF</c> truncation, guarded only by a <c>Debug.Assert</c> that release
    /// builds strip. Two problems. The truncation is the same "unreachable now, corrupt
    /// later" class Rust fixed in audit 2026-07-27 (F5). More immediately, every real QUIC
    /// stack encodes minimally, so a datagram whose Length is padded to two bytes when one
    /// would do is a static per-packet deviation from genuine QUIC — and the whole point of
    /// the mask is to read as genuine QUIC. Rust emits minimal form; the ports did not.
    /// (Audit 2026-08-04.)</summary>
    private static void PushVarint(List<byte> outBuf, ulong v)
    {
        if (v < 0x40)
        {
            outBuf.Add((byte)v);
        }
        else if (v < 0x4000)
        {
            outBuf.Add((byte)(0x40 | (v >> 8)));
            outBuf.Add((byte)(v & 0xFF));
        }
        else if (v < 0x4000_0000)
        {
            outBuf.Add((byte)(0x80 | (v >> 24)));
            outBuf.Add((byte)((v >> 16) & 0xFF));
            outBuf.Add((byte)((v >> 8) & 0xFF));
            outBuf.Add((byte)(v & 0xFF));
        }
        else
        {
            // Rust returns false here and the caller fails the wrap; silently truncating
            // is what this code used to do and is exactly what must not happen.
            throw new ArgumentOutOfRangeException(
                nameof(v), v, "QUIC varint above the 4-byte form is not emitted");
        }
    }

    /// <summary>RFC 9001 §17.2.2 Initial long header (mirrors quic.rs::wrap_quic_long):
    /// flags | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | token_len=0 |
    /// length_varint(2) | pn(4) | data. Long packet type in bits 4-5; the low 2 bits
    /// are the packet-number length minus one (always a 4-byte pn → 0b11).</summary>
    public static byte[] WrapLong(byte[] data, byte[] connectionId, int packetNumber, int packetType)
    {
        var outBuf = new List<byte>();
        outBuf.Add((byte)(LongHeaderFlag | ((packetType & 0x03) << 4) | 0x03));
        WriteIntBE(outBuf, VersionV1);
        outBuf.Add(4);                              // DCID length
        outBuf.AddRange(connectionId[..4]);
        outBuf.Add(0);                              // SCID length = 0
        PushVarint(outBuf, 0);                      // Token Length varint = 0
        PushVarint(outBuf, (ulong)(4 + data.Length)); // pn(4) + payload
        WriteIntBE(outBuf, packetNumber);           // 4-byte packet number
        outBuf.AddRange(data);
        return outBuf.ToArray();
    }

    /// <summary>flags | dcid(4) | pn(4) | data</summary>
    public static byte[] WrapShort(byte[] data, byte[] connectionId, int packetNumber)
    {
        var outBuf = new List<byte>();
        outBuf.Add((byte)(ShortHeaderFlag | 0x03));
        outBuf.AddRange(connectionId[..4]);
        WriteIntBE(outBuf, packetNumber);
        outBuf.AddRange(data);
        return outBuf.ToArray();
    }

    /// <summary>Parse a QUIC packet and return the inner payload, or null if malformed.</summary>
    public static byte[]? UnwrapPayload(byte[] packet)
    {
        if (packet.Length == 0) return null;
        bool isLong = (packet[0] & 0x80) != 0;
        return isLong ? UnwrapLong(packet) : UnwrapShort(packet);
    }

    private static byte[]? UnwrapLong(byte[] packet)
    {
        if (packet.Length < 12) return null;
        int flags = packet[0] & 0xFF;
        int pnLen = (flags & 0x03) + 1;
        int offset = 5; // flags + version
        int dcidLen = packet[offset] & 0xFF; offset += 1;
        if (offset + dcidLen > packet.Length) return null;
        offset += dcidLen;
        if (offset >= packet.Length) return null;
        int scidLen = packet[offset] & 0xFF; offset += 1;
        if (offset + scidLen > packet.Length) return null;
        offset += scidLen;
        // RFC 9001 §17.2.2: Token Length varint, token, then a Length varint. Skip both.
        if (ReadVarint(packet, ref offset) is not long tokenLen) return null;
        // tokenLen is a QUIC varint (0 .. 2^62-1). Guard against a crafted large/oversize
        // value in LONG arithmetic: without this the old int cast overflowed negative, and
        // `offset += tokenLen` then drove offset below zero → IndexOutOfRange on the next
        // read (a pre-auth reconnect-DoS on the no-obfs udp-quic wire). tokenLen>=0 always
        // now; reject anything that doesn't fit the packet before the (safe) int cast.
        if (tokenLen < 0 || offset + tokenLen > packet.Length) return null;
        offset += (int)tokenLen;
        if (ReadVarint(packet, ref offset) is null) return null;
        if (offset + pnLen > packet.Length) return null;
        offset += pnLen; // packet number (pn_len bytes)
        return packet[offset..];
    }

    /// <summary>QUIC variable-length integer (RFC 9000 §16): the first byte's top 2 bits
    /// give the length (1/2/4/8), the value is the remaining bits. Advances offset.</summary>
    private static long? ReadVarint(byte[] buf, ref int offset)
    {
        if (offset >= buf.Length) return null;
        int first = buf[offset] & 0xFF;
        int len = 1 << (first >> 6);
        if (offset + len > buf.Length) return null;
        // Accumulate into a LONG: an 8-byte varint holds up to 2^62-1, which overflowed the
        // old 32-bit `int` accumulator negative and poisoned the caller's offset math.
        long v = first & 0x3F;
        for (int i = 1; i < len; i++) v = (v << 8) | (long)(buf[offset + i] & 0xFF);
        offset += len;
        return v;
    }

    private static byte[]? UnwrapShort(byte[] packet)
    {
        if (packet.Length < 1 + 4 + 4) return null;
        int flags = packet[0] & 0xFF;
        int pnLen = (flags & 0x03) + 1;
        int offset = 1 + 4;
        int pnEnd = offset + Math.Min(pnLen, 4);
        if (pnEnd > packet.Length) return null;
        offset = pnEnd;
        return packet[offset..];
    }

    private static void WriteIntBE(List<byte> buf, int value)
    {
        buf.Add((byte)((value >> 24) & 0xFF));
        buf.Add((byte)((value >> 16) & 0xFF));
        buf.Add((byte)((value >> 8) & 0xFF));
        buf.Add((byte)(value & 0xFF));
    }
}
