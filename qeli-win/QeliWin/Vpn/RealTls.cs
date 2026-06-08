using System.Runtime.InteropServices;

namespace QeliWin.Vpn;

/// <summary>
/// Native REALITY TLS 1.3 handshake + record framing, backed by the Rust
/// <c>realtls</c> core via P/Invoke over <c>qeli.dll</c> (the C ABI in
/// <c>src/protocol/realtls/ffi.rs</c>). The same genuine browser-grade TLS stack
/// the Rust and Android clients use, so the Windows client's on-wire fingerprint
/// matches Chrome. The qeli tunnel runs <i>inside</i> this TLS session (nested).
/// </summary>
public sealed class RealTls : IDisposable
{
    private const string Dll = "qeli"; // qeli.dll, copied next to the executable

    private IntPtr _handle;

    // The native SansIoClient is taken as `&mut self` by BOTH seal and open (and
    // shares an internal buffer), so concurrent native calls alias one &mut (Rust
    // UB → TLS state corruption / stalls / disconnects under load). VpnTunnel pumps
    // upload (Seal) and download (Open) on separate Tasks plus a heartbeat (Seal),
    // so every native call on this handle MUST be serialized. The blocking socket
    // read in RealTlsTransport happens OUTSIDE this lock, so duplex is preserved.
    private readonly object _lock = new();

    /// <summary>The ClientHello to send first (captured at creation).</summary>
    public byte[] ClientHello { get; private set; } = Array.Empty<byte>();

    /// <summary>True once the handshake has completed (recv returned "done").</summary>
    public bool Established { get; private set; }

    private RealTls(IntPtr handle) => _handle = handle;

    /// <param name="realityPub">server profile's pinned X25519 identity (32 bytes)</param>
    /// <param name="shortId">REALITY short_id (8 bytes)</param>
    /// <param name="sni">borrowed SNI, e.g. "www.microsoft.com"</param>
    public static RealTls Create(byte[] realityPub, byte[] shortId, string sni)
    {
        IntPtr h = qeli_realtls_new(realityPub, shortId, sni, out IntPtr helloPtr, out UIntPtr helloLen);
        if (h == IntPtr.Zero) throw new Exception("RealTls native init failed");
        return new RealTls(h) { ClientHello = Consume(helloPtr, helloLen) };
    }

    /// <summary>Feed inbound server bytes. Returns the bytes to send when the
    /// handshake completes, or an empty array while more input is needed.</summary>
    public byte[] Recv(byte[] data)
    {
        lock (_lock)
        {
            int st = qeli_realtls_recv(_handle, data, (UIntPtr)data.Length, out IntPtr p, out UIntPtr l);
            if (st < 0) throw new Exception("realtls handshake error");
            var outBuf = Consume(p, l);
            if (st == 1) Established = true;
            return outBuf;
        }
    }

    /// <summary>Frame application data as one TLS record (after the handshake).</summary>
    public byte[] Seal(byte[] plaintext)
    {
        lock (_lock)
        {
            int st = qeli_realtls_seal(_handle, plaintext, (UIntPtr)plaintext.Length, out IntPtr p, out UIntPtr l);
            if (st < 0) throw new Exception("realtls seal error");
            return Consume(p, l);
        }
    }

    /// <summary>Decrypt inbound application bytes → concatenated plaintext.</summary>
    public byte[] Open(byte[] data)
    {
        lock (_lock)
        {
            int st = qeli_realtls_open(_handle, data, (UIntPtr)data.Length, out IntPtr p, out UIntPtr l);
            if (st < 0) throw new Exception("realtls open error");
            return Consume(p, l);
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_handle != IntPtr.Zero)
            {
                qeli_realtls_free(_handle);
                _handle = IntPtr.Zero;
            }
        }
    }

    /// <summary>Copy a native buffer to managed memory and free the native side.</summary>
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
    private static extern IntPtr qeli_realtls_new(
        byte[] realityPub, byte[] shortId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sni,
        out IntPtr outHello, out UIntPtr outHelloLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_realtls_recv(IntPtr handle, byte[] data, UIntPtr len,
        out IntPtr outBuf, out UIntPtr outLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_realtls_seal(IntPtr handle, byte[] data, UIntPtr len,
        out IntPtr outBuf, out UIntPtr outLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_realtls_open(IntPtr handle, byte[] data, UIntPtr len,
        out IntPtr outBuf, out UIntPtr outLen);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void qeli_realtls_free(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void qeli_realtls_buf_free(IntPtr ptr, UIntPtr len);
}
