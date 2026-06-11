using System.Runtime.InteropServices;

namespace Qeli.Shared.Crypto;

/// <summary>
/// ML-KEM-768 (FIPS 203) key encapsulation, backed by the Rust <c>ml-kem</c> crate
/// via P/Invoke over <c>qeli.dll</c> (the C ABI in <c>src/protocol/realtls/ffi.rs</c>).
///
/// Neither BouncyCastle (2.6.2) nor .NET's OS-gated <c>MLKem</c> give us a portable,
/// server-byte-identical ML-KEM, so the managed clients drive the post-quantum half
/// of the qeli handshake through the same native primitive the server uses. The
/// client generates a keypair, embeds <see cref="EncapsulationKey"/> in its
/// X25519MLKEM768 ClientHello key_share, then <see cref="Decapsulate"/>s the server's
/// ciphertext; the resulting shared secret is folded into the tunnel keys by
/// <c>KeyDerivation.DeriveKeysHybrid</c>.
/// </summary>
public sealed class MlKem : IDisposable
{
    private const string Dll = "qeli"; // qeli.dll / libqeli.dylib, next to the executable

    /// <summary>ML-KEM-768 encapsulation key (1184 bytes) for the ClientHello key_share.</summary>
    public byte[] EncapsulationKey { get; }

    private IntPtr _handle; // opaque *mut DecapsulationKey owned by the native side

    private MlKem(IntPtr handle, byte[] ek)
    {
        _handle = handle;
        EncapsulationKey = ek;
    }

    /// <summary>Generate a fresh ML-KEM-768 keypair; the decapsulation key is retained
    /// natively behind the handle, the encapsulation key is copied to managed memory.</summary>
    public static MlKem Generate()
    {
        IntPtr h = qeli_mlkem_keygen(out IntPtr ekPtr, out UIntPtr ekLen);
        if (h == IntPtr.Zero) throw new Exception("ML-KEM keygen failed");
        return new MlKem(h, Consume(ekPtr, ekLen));
    }

    /// <summary>Decapsulate the server's ciphertext (1088 bytes) into the 32-byte
    /// ML-KEM shared secret. Throws on a malformed ciphertext.</summary>
    public byte[] Decapsulate(byte[] ciphertext)
    {
        if (_handle == IntPtr.Zero) throw new ObjectDisposedException(nameof(MlKem));
        int st = qeli_mlkem_decapsulate(_handle, ciphertext, (UIntPtr)ciphertext.Length,
            out IntPtr p, out UIntPtr l);
        if (st != 0) throw new Exception("ML-KEM decapsulation failed");
        return Consume(p, l);
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            qeli_mlkem_free(_handle);
            _handle = IntPtr.Zero;
        }
    }

    /// <summary>Copy a native buffer to managed memory and free the native side
    /// (same allocator as the realtls FFI: <c>qeli_realtls_buf_free</c>).</summary>
    private static byte[] Consume(IntPtr ptr, UIntPtr len)
    {
        if (ptr == IntPtr.Zero || len == UIntPtr.Zero) return Array.Empty<byte>();
        int n = (int)len;
        var managed = new byte[n];
        Marshal.Copy(ptr, managed, 0, n);
        qeli_realtls_buf_free(ptr, len);
        return managed;
    }

    // ── C ABI (src/protocol/realtls/ffi.rs) ──────────────────────────────────────
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr qeli_mlkem_keygen(out IntPtr outEk, out UIntPtr outEkLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_mlkem_decapsulate(IntPtr handle, byte[] ct, UIntPtr ctLen,
        out IntPtr outSs, out UIntPtr outSsLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void qeli_mlkem_free(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void qeli_realtls_buf_free(IntPtr ptr, UIntPtr len);
}
