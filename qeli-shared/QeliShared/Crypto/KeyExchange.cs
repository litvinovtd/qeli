using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Qeli.Shared.Crypto;

/// <summary>
/// X25519 ephemeral key exchange. Mirrors the Android KeyExchange.kt and the Rust
/// client (x25519-dalek). Private key = 32 random bytes (clamping is applied inside
/// BouncyCastle's X25519); public = ScalarMultBase(priv); shared = ScalarMult(priv, peer).
/// </summary>
public sealed class KeyExchange
{
    public sealed class KeyPair
    {
        public required byte[] PrivateKey { get; init; }   // 32 raw scalar bytes
        public required byte[] PublicKeyBytes { get; init; } // 32 raw u-coordinate bytes
    }

    public KeyPair GenerateKeyPair()
    {
        var priv = new byte[X25519.ScalarSize];
        RandomNumberGenerator.Fill(priv);
        var pub = new byte[X25519.PointSize];
        X25519.ScalarMultBase(priv, 0, pub, 0);

        if (IsWeakKey(pub))
            throw new InvalidOperationException("Generated weak X25519 key");

        return new KeyPair { PrivateKey = priv, PublicKeyBytes = pub };
    }

    public byte[] ComputeSharedSecret(byte[] privateKey, byte[] peerPublicKeyRaw)
    {
        if (IsWeakKey(peerPublicKeyRaw))
            throw new ArgumentException("Peer public key is weak (all zeros or order-8 point)");

        var shared = new byte[X25519.PointSize];
        if (!X25519.CalculateAgreement(privateKey, 0, peerPublicKeyRaw, 0, shared, 0))
            throw new CryptographicException("X25519 agreement produced an all-zero shared secret");
        return shared;
    }

    /// <summary>Reject all-zero, all-FF and the known small-order (order-8) points.</summary>
    private static bool IsWeakKey(byte[] rawKey)
    {
        if (rawKey.Length != 32) return true;
        if (rawKey.All(b => b == 0x00)) return true;
        if (rawKey.All(b => b == 0xFF)) return true;
        var hex = Convert.ToHexString(rawKey).ToLowerInvariant();
        return Order8Points.Contains(hex);
    }

    private static readonly HashSet<string> Order8Points = new(StringComparer.Ordinal)
    {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224edda094e000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "1d00000000000000000000000000000000000000000000000000000000000000",
        "5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a0002",
        "6f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224edda094e000",
        "0000000000000000000000000000000000000000000000000000000000000080",
    };
}
