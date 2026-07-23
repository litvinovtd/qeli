using System.Runtime.InteropServices;
using System.Text;

namespace QeliMac.Vpn;

/// <summary>
/// Thin managed wrapper over a macOS <c>utun</c> kernel-control TUN interface — the
/// macOS analogue of qeli-win's Wintun adapter (and of Android's TUN
/// ParcelFileDescriptor). Opens <c>com.apple.net.utun_control</c> via a PF_SYSTEM
/// control socket and exposes a blocking <see cref="ReceivePacket"/> (with
/// cancellation) and <see cref="SendPacket"/> over L3 IPv4 packets.
///
/// utun frames carry a 4-byte address-family prefix (AF_INET = 2, big-endian) which
/// this wrapper strips on read and prepends on write, so callers deal in raw IP
/// packets exactly as the Wintun wrapper did. Requires root.
/// </summary>
public sealed class UtunDevice : IDisposable, Qeli.Shared.Vpn.ITunDevice
{
    // ── libc ────────────────────────────────────────────────────────────────
    [DllImport("libc", SetLastError = true)] private static extern int socket(int domain, int type, int protocol);
    // `ioctl` is variadic — ioctl(int, unsigned long, ...). The variadic ABI differs by
    // architecture, so we declare BOTH shapes and pick at runtime (C-07):
    //  • Apple ARM64: the variadic argument is passed on the STACK, not a register — a
    //    plain 3-arg P/Invoke would put the pointer in x2 and the kernel would dereference
    //    a garbage pointer (CTLIOCGINFO → ENOENT, "utun control isn't found"). Six dummy
    //    fillers (d2..d7 occupy x2..x7) push the real `arg` to the stack at sp+0, exactly
    //    where the variadic ioctl reads its first argument.
    //  • x86_64 (Intel) System V: the first variadic argument is passed in a REGISTER
    //    (rdx = the 3rd integer arg). The ARM64 stack-filler signature would place `info`
    //    in the wrong slot, so CTLIOCGINFO fails and utun is NEVER created on Intel Macs —
    //    which the shipped x64/universal build runs on. A plain 3-arg ioctl is correct there.
    // (`__arglist` is rejected by the runtime: "Vararg calling convention not supported".)
    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int ioctl_arm64(int fd, ulong request,
        long d2, long d3, long d4, long d5, long d6, long d7, byte[] arg);
    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int ioctl_x64(int fd, ulong request, byte[] arg);
    [DllImport("libc", SetLastError = true)] private static extern int connect(int fd, byte[] addr, int addrLen);
    [DllImport("libc", SetLastError = true)] private static extern int getsockopt(int fd, int level, int optname, byte[] optval, ref int optlen);
    [DllImport("libc", SetLastError = true)] private static extern nint read(int fd, byte[] buf, nint count);
    [DllImport("libc", SetLastError = true)] private static extern nint write(int fd, byte[] buf, nint count);
    [DllImport("libc", SetLastError = true)] private static extern int close(int fd);
    [DllImport("libc", SetLastError = true)] private static extern int poll([In, Out] PollFd[] fds, uint nfds, int timeoutMs);

    [StructLayout(LayoutKind.Sequential)]
    private struct PollFd { public int fd; public short events; public short revents; }

    private const int PF_SYSTEM = 32;
    private const int SOCK_DGRAM = 2;
    private const int SYSPROTO_CONTROL = 2;
    private const int AF_SYSTEM = 32;
    private const int AF_SYS_CONTROL = 2;
    private const int UTUN_OPT_IFNAME = 2;
    private const short POLLIN = 0x0001;

    // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)  (sizeof ctl_info = 100) → 0xC0644E03
    private const ulong CTLIOCGINFO = 0xC0644E03;
    private const string UtunControlName = "com.apple.net.utun_control";

    private int _fd = -1;

    // Set before close() in Dispose so an in-flight ReceivePacket loop stops issuing
    // read()/poll() on a torn-down (possibly recycled) fd during a reconnect. macOS
    // read/poll are blocking, so we can't hold a lock across them like the Windows
    // Wintun wrapper does; the blocked syscall instead returns on close() and the
    // shared tunnel loop now cancels + joins the reader BEFORE Dispose (see
    // VpnTunnelBase). This flag is the belt-and-suspenders half.
    private volatile bool _disposed;

    /// <summary>The kernel-assigned interface name, e.g. "utun4" (set by <see cref="Open"/>).</summary>
    public string Name { get; private set; } = "";

    /// <summary>Create a fresh utun interface and connect to it. Requires root.</summary>
    public void Open()
    {
        // One Open per instance: a second call would overwrite `_fd` and leak the first
        // utun fd. Callers create a fresh UtunDevice per connection (VpnTunnel.SetupTun),
        // so make that invariant explicit and fail loud instead of leaking silently.
        if (_disposed) throw new ObjectDisposedException(nameof(UtunDevice));
        if (_fd >= 0) throw new InvalidOperationException("utun: device is already open");
        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) throw new IOException($"utun: socket(PF_SYSTEM) failed (errno {Marshal.GetLastWin32Error()}) — are you root?");

        try
        {
            // Resolve the utun control id by name.
            var info = new byte[100]; // u_int32 ctl_id + char[96] ctl_name
            var nameBytes = Encoding.ASCII.GetBytes(UtunControlName);
            Buffer.BlockCopy(nameBytes, 0, info, 4, nameBytes.Length);
            // Pick the ioctl shape for this arch (see the declarations): ARM64 needs the
            // stack-filler variant, x86_64 the plain 3-arg one — otherwise `info` lands in
            // the wrong slot and utun creation fails on that arch.
            int rc = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture
                        == System.Runtime.InteropServices.Architecture.Arm64
                ? ioctl_arm64(fd, CTLIOCGINFO, 0, 0, 0, 0, 0, 0, info)
                : ioctl_x64(fd, CTLIOCGINFO, info);
            if (rc < 0)
                throw new IOException($"utun: CTLIOCGINFO failed (errno {Marshal.GetLastWin32Error()})");
            uint ctlId = BitConverter.ToUInt32(info, 0);

            // connect() to sc_unit=0 → kernel auto-assigns the next free utunN.
            var sc = new byte[32];
            sc[0] = 32;                 // sc_len
            sc[1] = AF_SYSTEM;          // sc_family
            sc[2] = AF_SYS_CONTROL & 0xFF; sc[3] = (AF_SYS_CONTROL >> 8) & 0xFF; // ss_sysaddr (host order)
            BitConverter.GetBytes(ctlId).CopyTo(sc, 4);  // sc_id
            BitConverter.GetBytes(0u).CopyTo(sc, 8);     // sc_unit = 0 (auto)
            if (connect(fd, sc, sc.Length) < 0)
                throw new IOException($"utun: connect failed (errno {Marshal.GetLastWin32Error()})");

            // Read back the interface name the kernel chose.
            var ifname = new byte[32];
            int len = ifname.Length;
            if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, ref len) < 0)
                throw new IOException($"utun: getsockopt(IFNAME) failed (errno {Marshal.GetLastWin32Error()})");
            Name = Encoding.ASCII.GetString(ifname, 0, Math.Max(0, len - 1)).TrimEnd('\0');

            _fd = fd;
        }
        catch
        {
            close(fd);
            throw;
        }
    }

    /// <summary>
    /// Block until an outbound packet (system → tunnel) is available, copy it out and
    /// return the raw IP packet (4-byte AF header stripped). Returns null on EOF/close.
    /// Honors the cancellation token via a short poll timeout so a disconnect tears
    /// the read loop down promptly.
    /// </summary>
    public byte[]? ReceivePacket(CancellationToken ct)
    {
        var fds = new PollFd[1];
        var buf = new byte[65536];
        while (!ct.IsCancellationRequested)
        {
            if (_disposed || _fd < 0) return null; // torn down
            fds[0] = new PollFd { fd = _fd, events = POLLIN, revents = 0 };
            int pr = poll(fds, 1, 250); // wake to re-check cancellation
            if (pr == 0) continue;      // timeout
            if (pr < 0)
            {
                if (Marshal.GetLastWin32Error() == 4 /* EINTR */) continue;
                return null;
            }
            if ((fds[0].revents & POLLIN) == 0) return null; // POLLHUP/ERR/NVAL → closed

            nint n = read(_fd, buf, buf.Length);
            if (n <= 4) { if (n < 0 && Marshal.GetLastWin32Error() == 4) continue; return n <= 0 ? null : Array.Empty<byte>(); }
            int len = (int)n - 4;        // drop the 4-byte AF_INET prefix
            var pkt = new byte[len];
            Buffer.BlockCopy(buf, 4, pkt, 0, len);
            return pkt;
        }
        return null;
    }

    /// <summary>Inject one inbound packet (server → system): prepend the AF_INET header and write.</summary>
    public void SendPacket(byte[] packet, int length)
    {
        if (_disposed || _fd < 0 || length <= 0) return;
        var framed = new byte[4 + length];
        framed[0] = 0; framed[1] = 0; framed[2] = 0; framed[3] = 2; // AF_INET, big-endian
        Buffer.BlockCopy(packet, 0, framed, 4, length);
        _ = write(_fd, framed, framed.Length); // best-effort; drop on transient error (like UDP loss)
    }

    public void Dispose()
    {
        _disposed = true; // stop the reader loop from issuing new syscalls on this fd
        if (_fd >= 0) { close(_fd); _fd = -1; }
    }
}
