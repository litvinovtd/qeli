using System.Runtime.InteropServices;
using System.Text;

namespace QeliMac.Vpn;

/// <summary>
/// Thin managed wrapper over a macOS <c>utun</c> kernel-control TUN interface — the
/// macOS analogue of qeli-win's Wintun adapter (and of Android's TUN
/// ParcelFileDescriptor). Opens <c>com.apple.net.utun_control</c> via a PF_SYSTEM
/// control socket and exposes only its descriptor/lifecycle. Rust duplicates the fd and
/// owns every packet read/write, including the four-byte utun address-family prefix.
/// Requires root.
/// </summary>
public sealed class UtunDevice : IDisposable, Qeli.Shared.Vpn.IFdTunDevice
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
    [DllImport("libc", SetLastError = true)] private static extern int close(int fd);

    private const int PF_SYSTEM = 32;
    private const int SOCK_DGRAM = 2;
    private const int SYSPROTO_CONTROL = 2;
    private const int AF_SYSTEM = 32;
    private const int AF_SYS_CONTROL = 2;
    private const int UTUN_OPT_IFNAME = 2;

    // CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)  (sizeof ctl_info = 100) → 0xC0644E03
    private const ulong CTLIOCGINFO = 0xC0644E03;
    private const string UtunControlName = "com.apple.net.utun_control";

    private readonly object _gate = new();
    private readonly Func<(int fd, string name)> _create;
    private readonly Action<int> _close;
    public UtunDevice() : this(CreateNative, fd => { _ = close(fd); }) { }
    internal UtunDevice(Func<(int fd, string name)> create, Action<int> closeDescriptor)
    { _create = create; _close = closeDescriptor; }
    private int _fd = -1;

    // Set before close() so descriptor access fails closed during reconnect teardown.
    // Rust owns independent generation-scoped duplicates and joins its fd workers first.
    private volatile bool _disposed;

    /// <summary>The kernel-assigned interface name, e.g. "utun4" (set by <see cref="Open"/>).</summary>
    public string Name { get; private set; } = "";

    /// <summary>Borrowed for one generation-scoped duplication by the Rust core.</summary>
    public int FileDescriptor
    {
        get { lock (_gate) return !_disposed && _fd >= 0 ? _fd : throw new ObjectDisposedException(nameof(UtunDevice)); }
    }

    public void Open()
    {
        lock (_gate)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(UtunDevice));
            if (_fd >= 0) throw new InvalidOperationException("utun: device is already open");
            var created = _create();
            try
            {
                if (created.fd < 0 || !ValidName(created.name)) throw new IOException("utun: invalid kernel descriptor/interface name");
                Name = created.name; _fd = created.fd;
            }
            catch { if (created.fd >= 0) _close(created.fd); throw; }
        }
    }
    internal static bool ValidName(string name) => name.StartsWith("utun", StringComparison.Ordinal)
        && name.Length > 4 && name.AsSpan(4).ToArray().All(char.IsAsciiDigit)
        && int.TryParse(name.AsSpan(4), out int index) && index >= 0;

    // fcntl is variadic too; Darwin ARM64 requires the third value on the stack.
    [DllImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int fcntl_arm64(int fd, int command, long d2, long d3, long d4, long d5, long d6, long d7, int flags);
    [DllImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int fcntl_x64(int fd, int command, int flags);

    private static (int fd, string name) CreateNative()
    {
        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) throw new IOException($"utun: socket(PF_SYSTEM) failed (errno {Marshal.GetLastWin32Error()}) — are you root?");

        try
        {
            const int F_SETFD = 2, FD_CLOEXEC = 1;
            int flagResult = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? fcntl_arm64(fd, F_SETFD, 0, 0, 0, 0, 0, 0, FD_CLOEXEC) : fcntl_x64(fd, F_SETFD, FD_CLOEXEC);
            if (flagResult != 0) throw new IOException($"utun: close-on-exec failed (errno {Marshal.GetLastPInvokeError()})");
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
            if (len <= 1 || len > ifname.Length || ifname[len - 1] != 0)
                throw new IOException("utun: invalid IFNAME response length/terminator");
            string name = Encoding.ASCII.GetString(ifname, 0, len - 1);
            if (!ValidName(name)) throw new IOException("utun: invalid IFNAME response");
            return (fd, name);
        }
        catch
        {
            close(fd);
            throw;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            int fd = _fd; _fd = -1;
            if (fd >= 0) _close(fd);
        }
    }
}
