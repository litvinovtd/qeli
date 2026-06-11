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

    /// <summary>ML-KEM-768 ciphertext length (FIPS 203) — the server's hybrid key_share
    /// PQ component.</summary>
    private const int MlKemCtLen = 1088;

    /// <summary>Fingerprint-only ClientHello: a classic x25519 key_share (no real PQ
    /// exchange). Kept for the <c>plain</c>-adjacent callers and tests; the live
    /// fake-tls / obfs / UDP paths use <see cref="BuildClientHelloPq"/> because the
    /// server now requires the X25519MLKEM768 share for the hybrid tunnel.</summary>
    public static byte[] BuildClientHello(byte[] keyShare, string sni = "www.cloudflare.com", int padToMin = 0)
        => BuildClientHelloInner(keyShare, null, sni, padToMin);

    /// <summary>Hybrid post-quantum ClientHello: carries the real ML-KEM-768
    /// encapsulation key in an X25519MLKEM768 (0x11ec) key_share alongside the classic
    /// x25519 share, so the server can encapsulate against it. Mirrors Rust
    /// <c>build_client_hello_pq</c>. The caller keeps the matching <c>MlKem</c> handle
    /// to decapsulate the server's ciphertext.</summary>
    public static byte[] BuildClientHelloPq(byte[] x25519Pub, byte[] mlKemEk,
        string sni = "www.cloudflare.com", int padToMin = 0)
        => BuildClientHelloInner(x25519Pub, mlKemEk, sni, padToMin);

    private static byte[] BuildClientHelloInner(byte[] x25519Pub, byte[]? mlKemEk, string sni, int padToMin)
    {
        bool pq = mlKemEk != null;
        var sessionId = new byte[32]; RandomNumberGenerator.Fill(sessionId);
        var randomBytes = new byte[32]; RandomNumberGenerator.Fill(randomBytes);
        int greaseFirst = GreaseValue();
        int greaseLast = GreaseValue();

        var ext = new Buf();
        BuildGreaseExtension(ext, greaseFirst);
        BuildSniExtension(ext, sni);
        BuildEmptyExtension(ext, 0x0017); // extended_master_secret
        BuildSupportedGroupsExtension(ext, pq);
        if (pq) BuildClientKeyShareExtensionPq(ext, x25519Pub, mlKemEk!);
        else BuildClientKeyShareExtension(ext, x25519Pub);
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

    /// <summary>Parse a hybrid ServerHello (handshake-message bytes, starting 0x02),
    /// returning the ML-KEM-768 ciphertext (1088) and the server's x25519 public (32)
    /// from its X25519MLKEM768 (0x11ec) key_share. Mirrors Rust
    /// <c>parse_server_hello_pq</c>; null if the hybrid share is absent/malformed.</summary>
    public static (byte[] Ciphertext, byte[] ServerX25519)? ParseServerHelloPq(byte[] data)
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
                // server_share length(2) is skipped via the +2; value = ct(1088) ‖ x25519(32).
                if (group == 0x11EC && keyLen == MlKemCtLen + 32 && pos + 6 + keyLen <= extEnd)
                {
                    var ct = data[(pos + 6)..(pos + 6 + MlKemCtLen)];
                    var sx = data[(pos + 6 + MlKemCtLen)..(pos + 6 + MlKemCtLen + 32)];
                    return (ct, sx);
                }
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

    /// <summary>Hybrid key_share: two entries, PQ first like Chrome — X25519MLKEM768
    /// (value = ML-KEM ek(1184) ‖ x25519(32)) then classic x25519. Mirrors Rust
    /// <c>build_key_share_extension</c>.</summary>
    private static void BuildClientKeyShareExtensionPq(Buf buf, byte[] x25519Pub, byte[] mlKemEk)
    {
        var pqValue = new byte[mlKemEk.Length + x25519Pub.Length];
        Buffer.BlockCopy(mlKemEk, 0, pqValue, 0, mlKemEk.Length);
        Buffer.BlockCopy(x25519Pub, 0, pqValue, mlKemEk.Length, x25519Pub.Length);

        var shares = new Buf();
        shares.WShort(0x11EC);          // X25519MLKEM768
        shares.WShort(pqValue.Length);  // 1216
        shares.W(pqValue);
        shares.WShort(0x001D);          // x25519
        shares.WShort(x25519Pub.Length);
        shares.W(x25519Pub);
        var sharesBytes = shares.ToArray();

        var list = new Buf();
        list.WShort(sharesBytes.Length); // client_shares_length
        list.W(sharesBytes);
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

    private static void BuildSupportedGroupsExtension(Buf buf, bool pq)
    {
        // PQ first like current Chrome when the hybrid share is offered.
        byte[] groups = pq
            ? new byte[] { 0x11, 0xEC, 0x00, 0x1D, 0x00, 0x17 } // X25519MLKEM768, x25519, secp256r1
            : new byte[] { 0x00, 0x1D, 0x00, 0x17 };            // x25519, secp256r1
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
