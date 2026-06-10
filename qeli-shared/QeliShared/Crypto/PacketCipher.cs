using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Qeli.Shared.Crypto;

/// <summary>
/// ChaCha20-Poly1305 AEAD (no AAD), matching the Android PacketCipher.kt / Rust
/// server. Output layout is ciphertext || 16-byte tag. 12-byte nonce.
/// A fresh BouncyCastle instance per call keeps it usable from multiple threads.
/// </summary>
public sealed class PacketCipher
{
    public const int NonceSize = 12;
    public const int TagSize = 16;

    private readonly byte[] _key;

    public PacketCipher(byte[] key)
    {
        if (key.Length != 32) throw new ArgumentException("ChaCha20-Poly1305 key must be 32 bytes");
        _key = key;
    }

    public byte[] Encrypt(byte[] plaintext, byte[] nonce)
    {
        if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes");
        var cipher = new ChaCha20Poly1305();
        cipher.Init(true, new AeadParameters(new KeyParameter(_key), TagSize * 8, nonce));
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        cipher.DoFinal(output, len);
        return output;
    }

    public byte[] Decrypt(byte[] ciphertextWithTag, byte[] nonce)
    {
        if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes");
        if (ciphertextWithTag.Length < TagSize) throw new ArgumentException("Ciphertext too short for tag");
        var cipher = new ChaCha20Poly1305();
        cipher.Init(false, new AeadParameters(new KeyParameter(_key), TagSize * 8, nonce));
        var output = new byte[cipher.GetOutputSize(ciphertextWithTag.Length)];
        int len = cipher.ProcessBytes(ciphertextWithTag, 0, ciphertextWithTag.Length, output, 0);
        len += cipher.DoFinal(output, len);
        // GetOutputSize is an upper bound; trim to the actual plaintext length.
        if (len == output.Length) return output;
        var trimmed = new byte[len];
        Buffer.BlockCopy(output, 0, trimmed, 0, len);
        return trimmed;
    }
}
