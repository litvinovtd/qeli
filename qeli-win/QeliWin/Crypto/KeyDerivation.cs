using System.Security.Cryptography;
using System.Text;

namespace QeliWin.Crypto;

/// <summary>
/// HKDF-SHA256 key schedule. Direct port of the Android KeyDerivation.kt, which in
/// turn mirrors the Rust crypto/derive.rs + crypto/auth.rs. Hand-rolled HMAC
/// extract/expand to stay byte-identical with the server.
/// </summary>
public static class KeyDerivation
{
    /// <summary>SHA-256 over the in-order concatenation of the handshake records.</summary>
    public static byte[] HandshakeTranscript(IEnumerable<byte[]> records)
    {
        using var sha = SHA256.Create();
        foreach (var r in records)
            sha.TransformBlock(r, 0, r.Length, null, 0);
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    /// <summary>Server-auth proof v2 (channel-bound). info = "vpn-server-auth-proof-v2" || transcript.</summary>
    public static byte[] DeriveAuthProof(byte[] staticShared, byte[] ephemeralShared, byte[] transcriptHash)
    {
        var prk = Hmac(staticShared, ephemeralShared);
        var info = Concat(Encoding.UTF8.GetBytes("vpn-server-auth-proof-v2"), transcriptHash);
        return Expand(prk, info, 32);
    }

    /// <summary>Client→server key proof. info = "vpn-client-key-proof-v1" || transcript.</summary>
    public static byte[] DeriveClientKeyProof(byte[] staticShared, byte[] ephemeralShared, byte[] transcriptHash)
    {
        var prk = Hmac(staticShared, ephemeralShared);
        var info = Concat(Encoding.UTF8.GetBytes("vpn-client-key-proof-v1"), transcriptHash);
        return Expand(prk, info, 32);
    }

    /// <summary>Returns (serverToClient, clientToServer) 32-byte ChaCha20-Poly1305 keys.</summary>
    public static (byte[] serverToClient, byte[] clientToServer) DeriveKeys(byte[] sharedSecret)
    {
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v1");
        var prk = Hmac(salt, sharedSecret);
        var s2c = Expand(prk, Encoding.UTF8.GetBytes("server-to-client-enc-key"), 32);
        var c2s = Expand(prk, Encoding.UTF8.GetBytes("client-to-server-enc-key"), 32);
        return (s2c, c2s);
    }

    private static byte[] Hmac(byte[] key, byte[] data)
    {
        using var mac = new HMACSHA256(key);
        return mac.ComputeHash(data);
    }

    /// <summary>RFC 5869 HKDF-Expand (single info, 1-byte counter as in the Android port).</summary>
    private static byte[] Expand(byte[] prk, byte[] info, int length)
    {
        using var mac = new HMACSHA256(prk);
        var result = new byte[length];
        var t = Array.Empty<byte>();
        int offset = 0;
        byte blockIndex = 1;
        while (offset < length)
        {
            mac.Initialize();
            var input = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
            input[^1] = blockIndex;
            t = mac.ComputeHash(input);

            int copyLen = Math.Min(t.Length, length - offset);
            Buffer.BlockCopy(t, 0, result, offset, copyLen);
            offset += copyLen;
            blockIndex++;
        }
        return result;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
}
