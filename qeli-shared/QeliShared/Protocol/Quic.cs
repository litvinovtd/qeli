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

    public static byte[] GenerateConnectionId()
    {
        var id = new byte[4];
        RandomNumberGenerator.Fill(id);
        return id;
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
        outBuf.Add(0);                              // Token Length varint = 0
        int length = (4 + data.Length) & 0x3FFF;    // pn(4) + payload, 2-byte QUIC varint
        outBuf.Add((byte)(0x40 | (length >> 8)));   // Length varint, high byte
        outBuf.Add((byte)(length & 0xFF));          // Length varint, low byte
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
        if (ReadVarint(packet, ref offset) is not int tokenLen) return null;
        if (offset + tokenLen > packet.Length) return null;
        offset += tokenLen;
        if (ReadVarint(packet, ref offset) is null) return null;
        if (offset + pnLen > packet.Length) return null;
        offset += pnLen; // packet number (pn_len bytes)
        return packet[offset..];
    }

    /// <summary>QUIC variable-length integer (RFC 9000 §16): the first byte's top 2 bits
    /// give the length (1/2/4/8), the value is the remaining bits. Advances offset.</summary>
    private static int? ReadVarint(byte[] buf, ref int offset)
    {
        if (offset >= buf.Length) return null;
        int first = buf[offset] & 0xFF;
        int len = 1 << (first >> 6);
        if (offset + len > buf.Length) return null;
        int v = first & 0x3F;
        for (int i = 1; i < len; i++) v = (v << 8) | (buf[offset + i] & 0xFF);
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
