namespace Qeli.Shared.Protocol;

/// <summary>
/// App-layer fragmentation for the large UDP handshake messages. Port of
/// qeli/src/protocol/udp_frag.rs.
///
/// The post-quantum UDP handshake is big (ML-KEM-768: ek 1184 B in the ClientHello,
/// ct 1088 B + cert in the ServerHello → CH ≈1440 B, SH ≈1959 B). A single ~2 KB
/// datagram is IP-fragmented, and mobile / CGNAT networks routinely DROP IP fragments,
/// so the UDP handshake silently hangs (works on Wi-Fi, fails on LTE). We split the
/// ClientHello (and reassemble the ServerHello) ourselves into &lt;= <see cref="MaxChunk"/>-byte
/// fragments that never need IP fragmentation.
///
/// Wire: <c>[MAGIC(3)][msgId(1)][idx(1)][count(1)][chunk...]</c>. Sits below the
/// QUIC-mask / obfs-XOR transforms (each fragment is wrapped independently). The magic
/// cannot open a TLS record (0x16 0x03), so a fragment is distinguishable from a legacy
/// single-datagram message.
/// </summary>
public static class UdpFrag
{
    public static readonly byte[] Magic = { 0xF0, 0x9B, 0x71 };
    public const int HdrLen = 6;            // magic(3) + msgId(1) + idx(1) + count(1)
    public const int MaxChunk = 1200;       // payload bytes per fragment (safe < IPv6 min 1280 / LTE)
    public const int MaxFrags = 24;         // anti-DoS cap on the reassembly buffer
    public const byte MsgClientHello = 1;
    public const byte MsgServerHello = 2;
    // A throwaway pre-handshake junk decoy (AmneziaWG-style Jc on UDP): carries no real
    // data; the server drops it cheaply before its rate limiter. The client may emit
    // `jc` of these before its ClientHello to blur the first datagrams' size/count.
    public const byte MsgJunk = 3;
    // Path-MTU probe (client->server): a single-fragment datagram padded so the whole
    // outer datagram is exactly the size being tested (sent with DF, so an oversized one
    // is dropped, not IP-fragmented -> no ACK). Body: [id(2 LE)][outerSize(2 LE)] + pad.
    // The server echoes a tiny MsgMtuProbeAck. Recognized before the reassembler.
    public const byte MsgMtuProbe = 4;
    public const byte MsgMtuProbeAck = 5;
    public const int ProbeBodyLen = 4; // id(2) + outerSize(2)

    public static bool IsFragment(byte[] d) =>
        d.Length >= HdrLen && d[0] == Magic[0] && d[1] == Magic[1] && d[2] == Magic[2];

    /// <summary>True if <paramref name="d"/> (after obfs/QUIC unwrap) is an AWG junk decoy.</summary>
    public static bool IsJunk(byte[] d) => IsFragment(d) && d[3] == MsgJunk;

    /// <summary>True if <paramref name="d"/> (after unwrap) is a path-MTU probe.</summary>
    public static bool IsMtuProbe(byte[] d) =>
        IsFragment(d) && d[3] == MsgMtuProbe && d.Length >= HdrLen + ProbeBodyLen;

    /// <summary>True if <paramref name="d"/> (after unwrap) is a path-MTU probe ACK.</summary>
    public static bool IsMtuProbeAck(byte[] d) =>
        IsFragment(d) && d[3] == MsgMtuProbeAck && d.Length >= HdrLen + ProbeBodyLen;

    /// <summary>Read <c>(id, outerSize)</c> from a probe or probe-ACK datagram (after unwrap).</summary>
    public static (ushort id, ushort size)? ParseMtuProbe(byte[] d)
    {
        if (d.Length < HdrLen + ProbeBodyLen) return null;
        ushort id = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(HdrLen));
        ushort size = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(HdrLen + 2));
        return (id, size);
    }

    /// <summary>Build a probe datagram padded so the total outer datagram is
    /// <paramref name="outerSize"/> bytes. Null if it can't hold header+body.</summary>
    public static byte[]? MtuProbeDatagram(ushort id, int outerSize)
    {
        int min = HdrLen + ProbeBodyLen;
        if (outerSize < min || outerSize > ushort.MaxValue) return null;
        var d = new byte[outerSize];
        d[0] = Magic[0]; d[1] = Magic[1]; d[2] = Magic[2];
        d[3] = MsgMtuProbe; d[4] = 0; d[5] = 1;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(HdrLen), id);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(HdrLen + 2), (ushort)outerSize);
        System.Security.Cryptography.RandomNumberGenerator.Fill(d.AsSpan(min));
        return d;
    }

    /// <summary>Build the tiny ACK for a received probe (echoes its id + outerSize).</summary>
    public static byte[] MtuProbeAckDatagram(ushort id, ushort outerSize)
    {
        var d = new byte[HdrLen + ProbeBodyLen];
        d[0] = Magic[0]; d[1] = Magic[1]; d[2] = Magic[2];
        d[3] = MsgMtuProbeAck; d[4] = 0; d[5] = 1;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(HdrLen), id);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(d.AsSpan(HdrLen + 2), outerSize);
        return d;
    }

    /// <summary>Build ONE junk decoy datagram: a single-fragment <see cref="MsgJunk"/>
    /// message with <paramref name="len"/> random body bytes. Same on-wire envelope as a
    /// real fragment so it rides the identical obfs-XOR / QUIC mask and the peer's
    /// <see cref="IsJunk"/> recognizes it after unwrap.</summary>
    public static byte[] JunkDatagram(int len)
    {
        var d = new byte[HdrLen + len];
        d[0] = Magic[0]; d[1] = Magic[1]; d[2] = Magic[2];
        d[3] = MsgJunk; d[4] = 0; d[5] = 1;
        System.Security.Cryptography.RandomNumberGenerator.Fill(d.AsSpan(HdrLen));
        return d;
    }

    /// <summary>Split a handshake message into fragment datagrams (always &gt;= 1).</summary>
    public static List<byte[]> Fragment(byte msgId, byte[] msg)
    {
        int count = Math.Max(1, (msg.Length + MaxChunk - 1) / MaxChunk);
        var frags = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            int start = i * MaxChunk;
            int len = Math.Min(MaxChunk, msg.Length - start);
            var f = new byte[HdrLen + len];
            f[0] = Magic[0]; f[1] = Magic[1]; f[2] = Magic[2];
            f[3] = msgId; f[4] = (byte)i; f[5] = (byte)count;
            Array.Copy(msg, start, f, HdrLen, len);
            frags.Add(f);
        }
        return frags;
    }

    /// <summary>Reassembles the fragments of ONE message. Tolerates out-of-order
    /// arrival and duplicates; throws on a malformed/inconsistent fragment.</summary>
    public sealed class Reassembler
    {
        private byte _msgId, _count, _have;
        private byte[]?[] _parts = System.Array.Empty<byte[]?>();

        /// <summary>Feed one fragment datagram. Returns the full message once every
        /// fragment has arrived, else null.</summary>
        public byte[]? Push(byte[] d)
        {
            if (!IsFragment(d)) throw new System.Exception("not a fragment");
            byte msgId = d[3], idx = d[4], count = d[5];
            if (count == 0 || count > MaxFrags) throw new System.Exception("bad fragment count");
            if (idx >= count) throw new System.Exception("fragment index out of range");
            if (_count == 0) { _msgId = msgId; _count = count; _parts = new byte[count][]; _have = 0; }
            else if (msgId != _msgId || count != _count) throw new System.Exception("inconsistent fragment");
            if (_parts[idx] == null) { _parts[idx] = d[HdrLen..]; _have++; }
            if (_have != _count) return null;
            int total = 0;
            foreach (var p in _parts) total += p!.Length;
            var msg = new byte[total];
            int o = 0;
            foreach (var p in _parts) { System.Array.Copy(p!, 0, msg, o, p!.Length); o += p!.Length; }
            return msg;
        }
    }
}
