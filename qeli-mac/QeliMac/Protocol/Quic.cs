using System.Security.Cryptography;

namespace QeliMac.Protocol;

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

    /// <summary>flags | version(4) | dcid_len=4 | dcid(4) | scid_len=0 | pn(4) | data</summary>
    public static byte[] WrapLong(byte[] data, byte[] connectionId, int packetNumber, int packetType)
    {
        var outBuf = new List<byte>();
        outBuf.Add((byte)(LongHeaderFlag | (packetType & 0x0F)));
        WriteIntBE(outBuf, VersionV1);
        outBuf.Add(4);
        outBuf.AddRange(connectionId[..4]);
        outBuf.Add(0);
        WriteIntBE(outBuf, packetNumber);
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
        if (packet.Length < 11) return null;
        int offset = 5; // skip flags + version
        int dcidLen = packet[offset] & 0xFF; offset += 1;
        if (offset + dcidLen > packet.Length) return null;
        offset += dcidLen;
        if (offset >= packet.Length) return null;
        int scidLen = packet[offset] & 0xFF; offset += 1;
        if (offset + scidLen > packet.Length) return null;
        offset += scidLen;
        if (offset + 4 > packet.Length) return null;
        offset += 4; // packet number
        return packet[offset..];
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
