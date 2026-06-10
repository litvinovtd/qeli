using System.Security.Cryptography;
using System.Text;

namespace Qeli.Shared.Protocol;

/// <summary>
/// Fake-TLS 1.3 ClientHello/ServerHello. Direct port of Android TlsHandshake.kt,
/// mirroring qeli/src/protocol/tls.rs. GREASE (RFC 8701) for JA3 polymorphism and
/// an RFC 7685 padding extension to reach a minimum record size (UDP initials).
/// </summary>
public static class TlsHandshake
{
    private const byte ClientHelloType = 0x01;
    private const byte ServerHelloType = 0x02;

    /// <summary>A growable byte buffer with TLS-style big-endian writers.</summary>
    private sealed class Buf
    {
        private readonly List<byte> _b = new();
        public int Size => _b.Count;
        public void W(int v) => _b.Add((byte)(v & 0xFF));
        public void W(byte[] data) => _b.AddRange(data);
        public void WShort(int v) { W((v >> 8) & 0xFF); W(v & 0xFF); }
        public void WInt24(int v) { W((v >> 16) & 0xFF); W((v >> 8) & 0xFF); W(v & 0xFF); }
        public byte[] ToArray() => _b.ToArray();
    }

    public static byte[] BuildClientHello(byte[] keyShare, string sni = "www.cloudflare.com", int padToMin = 0)
    {
        var sessionId = new byte[32]; RandomNumberGenerator.Fill(sessionId);
        var randomBytes = new byte[32]; RandomNumberGenerator.Fill(randomBytes);
        int greaseFirst = GreaseValue();
        int greaseLast = GreaseValue();

        var ext = new Buf();
        BuildGreaseExtension(ext, greaseFirst);
        BuildSniExtension(ext, sni);
        BuildEmptyExtension(ext, 0x0017); // extended_master_secret
        BuildSupportedGroupsExtension(ext);
        BuildClientKeyShareExtension(ext, keyShare);
        BuildPskKeyExchangeModesExtension(ext);
        BuildSupportedVersionsExtension(ext);
        BuildSignatureAlgorithmsExtension(ext);
        BuildCompressCertificateExtension(ext);
        BuildGreaseExtension(ext, greaseLast);

        // RFC 7685 padding: record size = 9 (record+handshake headers) + 79 (fixed body) + extLen.
        int projected = 88 + ext.Size;
        if (padToMin > projected + 4)
        {
            int padData = padToMin - projected - 4; // 4 = padding ext header
            ext.W(0x00); ext.W(0x15); // padding extension type
            ext.WShort(padData);
            ext.W(new byte[padData]);
        }

        var body = new Buf();
        body.WShort(0x0303);
        body.W(randomBytes);
        body.W(sessionId.Length);
        body.W(sessionId);
        body.WShort(6);
        body.WShort(0x1301); // TLS_AES_128_GCM_SHA256
        body.WShort(0x1302); // TLS_AES_256_GCM_SHA384
        body.WShort(0x1303); // TLS_CHACHA20_POLY1305_SHA256
        body.W(1);
        body.W(0x00);
        body.WShort(ext.Size);
        body.W(ext.ToArray());
        var bodyBytes = body.ToArray();

        var handshake = new Buf();
        handshake.W(ClientHelloType);
        handshake.WInt24(bodyBytes.Length);
        handshake.W(bodyBytes);
        var hsBytes = handshake.ToArray();

        var record = new Buf();
        record.W(0x16);
        record.W(0x03); record.W(0x03);
        record.WShort(hsBytes.Length);
        record.W(hsBytes);
        return record.ToArray();
    }

    private static int GreaseValue()
    {
        int b = (RandomNumberGenerator.GetInt32(16) << 4) | 0x0A;
        return (b << 8) | b;
    }

    private static void BuildGreaseExtension(Buf buf, int value)
    {
        buf.WShort(value);
        buf.W(0x00); buf.W(0x00);
    }

    public static byte[]? ParseServerHello(byte[] data)
    {
        if (data.Length < 5 || data[0] != ServerHelloType) return null;
        int bodyLen = ReadInt24(data, 1);
        if (bodyLen < 43 || data.Length < 4 + bodyLen) return null;
        int pos = 4;

        pos += 2;  // version
        pos += 32; // random
        int sessionIdLen = data[pos] & 0xFF; pos += 1 + sessionIdLen;
        pos += 2; // cipher suite
        pos += 1; // compression
        if (pos + 2 > data.Length) return null;
        int extLen = ReadShort(data, pos); pos += 2;
        if (pos + extLen > data.Length) return null;
        int extEnd = pos + extLen;

        while (pos + 4 <= extEnd)
        {
            int extType = ReadShort(data, pos);
            int extDataLen = ReadShort(data, pos + 2); pos += 4;
            if (pos + extDataLen > extEnd) break;
            if (extType == 0x0033)
            {
                if (extDataLen < 6) return null;
                int group = ReadShort(data, pos + 2);
                int keyLen = ReadShort(data, pos + 4);
                if (group == 0x001d && keyLen >= 32)
                    return data[(pos + 6)..(pos + 6 + 32)];
            }
            pos += extDataLen;
        }
        return null;
    }

    private static void BuildSniExtension(Buf buf, string sni)
    {
        var sniBytes = Encoding.ASCII.GetBytes(sni);
        var name = new Buf();
        name.W(0x00); // hostname type
        name.WShort(sniBytes.Length);
        name.W(sniBytes);
        var nameBytes = name.ToArray();
        buf.W(0x00); buf.W(0x00); // SNI extension type
        buf.WShort(nameBytes.Length);
        buf.W(nameBytes);
    }

    private static void BuildClientKeyShareExtension(Buf buf, byte[] keyShare)
    {
        var entry = new Buf();
        entry.WShort(0x001d);
        entry.WShort(keyShare.Length);
        entry.W(keyShare);
        var entryBytes = entry.ToArray();
        var list = new Buf();
        list.WShort(entryBytes.Length);
        list.W(entryBytes);
        var listBytes = list.ToArray();
        buf.W(0x00); buf.W(0x33); // key_share
        buf.WShort(listBytes.Length);
        buf.W(listBytes);
    }

    private static void BuildSupportedVersionsExtension(Buf buf)
    {
        buf.W(0x00); buf.W(0x2B);
        buf.W(0x00); buf.W(0x03);
        buf.W(0x02);
        buf.W(0x03); buf.W(0x04); // TLS 1.3
    }

    private static void BuildPskKeyExchangeModesExtension(Buf buf)
    {
        buf.W(0x00); buf.W(0x2D);
        buf.W(0x00); buf.W(0x02);
        buf.W(0x01);
        buf.W(0x01); // PSK with (EC)DHE
    }

    private static void BuildSignatureAlgorithmsExtension(Buf buf)
    {
        byte[] algorithms =
        {
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04,
            0x04, 0x01, 0x05, 0x01, 0x02, 0x01,
        };
        buf.W(0x00); buf.W(0x0D);
        buf.WShort(algorithms.Length + 2);
        buf.WShort(algorithms.Length);
        buf.W(algorithms);
    }

    private static void BuildSupportedGroupsExtension(Buf buf)
    {
        byte[] groups = { 0x00, 0x1D, 0x00, 0x17 }; // x25519, secp256r1
        buf.W(0x00); buf.W(0x0A);
        buf.WShort(groups.Length + 2);
        buf.WShort(groups.Length);
        buf.W(groups);
    }

    private static void BuildCompressCertificateExtension(Buf buf)
    {
        buf.W(0x00); buf.W(0x1B);
        buf.W(0x00); buf.W(0x03);
        buf.W(0x02);
        buf.W(0x00); buf.W(0x02); // brotli
    }

    private static void BuildEmptyExtension(Buf buf, int extType)
    {
        buf.W((extType >> 8) & 0xFF);
        buf.W(extType & 0xFF);
        buf.W(0x00); buf.W(0x00);
    }

    public static bool IsChangeCipherSpec(byte[] record) =>
        record.Length == 6 && record[0] == 0x14 && record[1] == 0x03 &&
        record[2] == 0x03 && record[3] == 0x00 && record[4] == 0x01 && record[5] == 0x01;

    private static int ReadShort(byte[] data, int offset) =>
        ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);

    private static int ReadInt24(byte[] data, int offset) =>
        ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
}
