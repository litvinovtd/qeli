using System.Security.Cryptography;
using System.Text;

namespace Qeli.Shared.Crypto;

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

    /// <summary>Hybrid post-quantum key schedule: the directional keys depend on BOTH
    /// the classic X25519 shared secret AND the ML-KEM-768 shared secret, concatenated
    /// as the HKDF IKM (<c>x25519 ‖ mlkem</c>, 64 bytes) under a distinct v2 salt.
    /// Mirrors Rust <c>crypto::derive::derive_keys_hybrid</c> byte-for-byte — the order
    /// and salt are wire-format, so a hybrid peer cannot interop with a classic one
    /// (no silent PQ downgrade). Used by the fake-tls / obfs / UDP modes; <c>plain</c>
    /// stays on <see cref="DeriveKeys"/>.</summary>
    public static (byte[] serverToClient, byte[] clientToServer) DeriveKeysHybrid(
        byte[] x25519Shared, byte[] mlkemShared)
    {
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v2-hybrid");
        var ikm = Concat(x25519Shared, mlkemShared); // x25519 first, then ML-KEM
        var prk = Hmac(salt, ikm);
        var s2c = Expand(prk, Encoding.UTF8.GetBytes("server-to-client-enc-key"), 32);
        var c2s = Expand(prk, Encoding.UTF8.GetBytes("client-to-server-enc-key"), 32);
        return (s2c, c2s);
    }

    /// <summary>Classic derivation (<see cref="DeriveKeys"/>) with the static-ephemeral
    /// DH <c>es</c> folded into the IKM (<c>ee ‖ es</c>) under a distinct salt, binding
    /// the data keys to the server identity (H-1). Mirrors Rust <c>derive_keys_bound</c>.
    /// Enabled by <c>bind_static_to_session</c>; requires the server key pinned.</summary>
    public static (byte[] serverToClient, byte[] clientToServer) DeriveKeysBound(
        byte[] ee, byte[] es)
    {
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v1-static-bound");
        var prk = Hmac(salt, Concat(ee, es));
        var s2c = Expand(prk, Encoding.UTF8.GetBytes("server-to-client-enc-key"), 32);
        var c2s = Expand(prk, Encoding.UTF8.GetBytes("client-to-server-enc-key"), 32);
        return (s2c, c2s);
    }

    /// <summary>Hybrid derivation (<see cref="DeriveKeysHybrid"/>) with the
    /// static-ephemeral DH <c>es</c> folded in (IKM = <c>x25519 ‖ mlkem ‖ es</c>) under a
    /// distinct salt. Mirrors Rust <c>derive_keys_hybrid_bound</c>. See <see cref="DeriveKeysBound"/>.</summary>
    public static (byte[] serverToClient, byte[] clientToServer) DeriveKeysHybridBound(
        byte[] x25519Shared, byte[] mlkemShared, byte[] es)
    {
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v2-hybrid-static-bound");
        var ikm = Concat(Concat(x25519Shared, mlkemShared), es); // x25519 ‖ mlkem ‖ es
        var prk = Hmac(salt, ikm);
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
