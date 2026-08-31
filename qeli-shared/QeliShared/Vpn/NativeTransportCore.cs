using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Qeli.Shared.Vpn;

/// <summary>Versioned C ABI adapter for the shared Rust transport core.</summary>
internal static unsafe class NativeTransportCore
{
    private const string Library = "qeli";

    internal const uint AbiVersion = 0x0001_000b;
    internal const int Ok = 0;
    internal const int NoEvent = 1;
    internal const int BufferTooSmall = -6;
    internal const int StaleRequest = -11;

    internal enum PathCommandOutcome
    {
        Accepted = 0,
        Rejected = 1,
        PlatformStateUnknown = 2,
    }
    internal const uint PayloadNone = 0;
    internal const uint PayloadJson = 1;
    internal const uint PayloadUtf8 = 2;

    internal const uint StateConnecting = 1;
    internal const uint StateRunning = 3;
    internal const uint StateStopped = 5;
    internal const uint StateFailed = 6;

    internal const uint EventStateChanged = 1;
    internal const uint EventNetworkPlan = 2;
    internal const uint EventError = 3;
    internal const uint EventServerIdentity = 5;
    internal const uint EventPathCommand = 6;
    internal const uint EventPathRefresh = 7;
    internal const uint EventNotice = 8;
    internal const uint EventKick = 9;

    internal const ulong PlatformRoutes = 1UL << 0;
    internal const ulong PlatformDns = 1UL << 1;
    internal const ulong PlatformKillSwitch = 1UL << 2;
    internal const ulong PlatformTunFd = 1UL << 3;
    internal const ulong PlatformTunPacketBatch = 1UL << 4;
    internal const ulong PlatformServerIdentity = 1UL << 6;
    internal const ulong PlatformTunWintun = 1UL << 7;
    internal const ulong PlatformIpv6Tun = 1UL << 8;
    internal const ulong PlatformIpv6Routes = 1UL << 9;
    internal const ulong PlatformIpv6Dns = 1UL << 10;
    internal const ulong PlatformIpv6KillSwitch = 1UL << 11;
    internal const ulong PlatformPathTransactions = 1UL << 12;
    internal const ulong PlatformPathSocketBinding = 1UL << 13;
    internal const ulong PlatformPathRefresh = 1UL << 14;
    internal const ulong PlatformManagementEvents = 1UL << 15;
    internal const ulong PlatformRoamingPath = PlatformPathTransactions | PlatformPathSocketBinding;
    internal const ulong PlatformIpv6SystemPlan =
        PlatformIpv6Tun | PlatformIpv6Routes | PlatformIpv6Dns;
    internal const ulong DesktopBaseCapabilities = PlatformRoutes | PlatformDns |
        PlatformKillSwitch | PlatformServerIdentity | PlatformManagementEvents;

    internal const ulong CoreNativeDataPlane = 1UL << 8;
    internal const ulong CoreTunFdOwnership = 1UL << 3;
    internal const ulong CoreTunPacketIo = 1UL << 9;
    internal const ulong CoreUdpDiagnostic = 1UL << 10;
    internal const ulong CoreWintunIo = 1UL << 11;
    internal const ulong CorePathTransactions = 1UL << 13;
    internal const ulong CorePathRefreshEvents = 1UL << 14;
    internal const ulong CoreManagementEvents = 1UL << 15;

    internal const int MaxPacketBytes = 65_535;
    internal const int MaxBatchPackets = 64;
    internal const int BatchBufferBytes = 256 * 1024;
    internal const int MaxEventPayload = 256 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct EventHeader
    {
        internal uint StructSize;
        internal uint AbiVersion;
        internal uint Kind;
        internal uint State;
        internal uint PayloadFormat;
        internal uint Reserved;
        internal ulong Sequence;
        internal ulong PlanGeneration;
        internal int ErrorCode;
        internal uint PayloadLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StatsHeader
    {
        internal uint StructSize;
        internal uint AbiVersion;
        internal uint State;
        internal uint Reserved;
        internal ulong TxPackets;
        internal ulong TxBytes;
        internal ulong RxPackets;
        internal ulong RxBytes;
        internal ulong Reconnects;
        internal ulong UptimeMs;
        internal ulong UdpKernelDrops;
        internal ulong UdpInternalDrops;
        internal ulong UdpBufferGrows;
        internal ulong UdpRecvBufferBytes;
    }

    internal sealed record NativeEvent(uint Kind, uint State, uint PayloadFormat,
        ulong Sequence, ulong PlanGeneration, int ErrorCode, string Payload);
    internal sealed record NativeStats(uint State, ulong TxPackets, ulong TxBytes,
        ulong RxPackets, ulong RxBytes, ulong Reconnects, ulong UptimeMs,
        ulong UdpKernelDrops, ulong UdpInternalDrops, ulong UdpBufferGrows,
        ulong UdpRecvBufferBytes);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint qeli_client_abi_version();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern ulong qeli_client_core_capabilities();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_udp_probe(byte* config, nuint configLen,
        uint timeoutMs, out ulong latencyMs);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_new(byte* config, nuint configLen,
        ulong platformCapabilities, uint eventCapacity, out ulong handle);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_set_device_id(ulong handle, byte* deviceId, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_start(ulong handle);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_run(ulong handle, byte* input, nuint inputLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_stop(ulong handle);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_free(ulong handle);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_poll_event(ulong handle, EventHeader* output,
        byte* payload, nuint payloadCapacity, out nuint payloadLength);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_network_plan_result(ulong handle, ulong generation,
        int resultCode, byte* reason, nuint reasonLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_set_tun_fd(ulong handle, ulong generation, int fd);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_set_wintun_adapter(ulong handle, ulong generation,
        byte* adapterName, nuint adapterNameLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_server_identity_result(ulong handle, ulong sequence,
        int resultCode, byte* reason, nuint reasonLen);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_stats(ulong handle, StatsHeader* output);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_tun_push(ulong handle, ulong generation,
        byte* packets, nuint packetsLen, uint* lengths, nuint packetCount, out nuint accepted);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_tun_pull(ulong handle, ulong generation,
        byte* packets, nuint packetsCapacity, uint* lengths, nuint lengthCapacity,
        out nuint packetCount, out nuint bytes);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_path_update(ulong handle, byte* input, nuint inputLen,
        out ulong candidateId);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    private static extern int qeli_client_path_command_result(ulong handle, ulong generation,
        ulong candidateId, ulong requestSequence, int resultCode, byte* reason,
        nuint reasonLen);

    internal static void RequireCompatible(bool tunFdOwnership = false, bool wintunOwnership = false)
    {
        if (tunFdOwnership && wintunOwnership)
            throw new InvalidOperationException("a platform cannot advertise two native TUN owners");
        uint actual = qeli_client_abi_version();
        if ((actual >> 16) != (AbiVersion >> 16) || (actual & 0xffff) < (AbiVersion & 0xffff))
            throw new InvalidOperationException(
                $"native transport ABI 0x{actual:x8} is incompatible with required 0x{AbiVersion:x8}");
        ulong capabilities = qeli_client_core_capabilities();
        ulong tunCapability = tunFdOwnership ? CoreTunFdOwnership
            : wintunOwnership ? CoreWintunIo
            : CoreTunPacketIo;
        ulong required = CoreNativeDataPlane | CoreUdpDiagnostic | tunCapability;
        if ((capabilities & required) != required)
            throw new InvalidOperationException(
                $"native core capabilities 0x{capabilities:x} do not include 0x{required:x}");
    }

    internal static bool SupportsPathTransactions()
    {
        uint actual = qeli_client_abi_version();
        return (actual >> 16) == 1 && (actual & 0xffff) >= 14
            && (qeli_client_core_capabilities() & CorePathTransactions) != 0;
    }

    internal static bool SupportsPathRefresh() => SupportsPathTransactions()
        && (qeli_client_abi_version() & 0xffff) >= 13
        && (qeli_client_core_capabilities() & CorePathRefreshEvents) != 0;

    internal static ulong New(string config, bool tunFdOwnership, bool wintunOwnership,
        ulong ipv6Capabilities = 0, ulong roamingCapabilities = 0)
    {
        if (tunFdOwnership && wintunOwnership)
            throw new InvalidOperationException("a platform cannot advertise two native TUN owners");
        ulong allowedRoaming = PlatformRoamingPath | PlatformPathRefresh;
        if ((roamingCapabilities & ~allowedRoaming) != 0)
            throw new ArgumentOutOfRangeException(nameof(roamingCapabilities));
        ulong roamingPath = roamingCapabilities & PlatformRoamingPath;
        if (roamingPath != 0 && roamingPath != PlatformRoamingPath)
            throw new ArgumentException(
                "path transactions and exact socket binding must be advertised together",
                nameof(roamingCapabilities));
        if ((roamingCapabilities & PlatformPathRefresh) != 0
            && roamingPath != PlatformRoamingPath)
            throw new ArgumentException(
                "path refresh requires the complete roaming path contract",
                nameof(roamingCapabilities));
        if (roamingPath != 0 && !SupportsPathTransactions())
            throw new InvalidOperationException(
                "native core does not expose the path-transaction ABI required by the platform");
        if ((roamingCapabilities & PlatformPathRefresh) != 0 && !SupportsPathRefresh())
            throw new InvalidOperationException(
                "native core does not expose the path-refresh ABI required by the platform");
        byte[] bytes = Encoding.UTF8.GetBytes(config);
        try
        {
            fixed (byte* pointer = bytes)
            {
                ulong tunCapability = tunFdOwnership ? PlatformTunFd
                    : wintunOwnership ? PlatformTunWintun
                    : PlatformTunPacketBatch;
                ulong capabilities = DesktopBaseCapabilities | tunCapability | ipv6Capabilities
                    | roamingCapabilities;
                int rc = qeli_client_new(pointer, (nuint)bytes.Length, capabilities, 128, out ulong handle);
                Check(rc, "qeli_client_new");
                if (handle == 0) throw new InvalidOperationException("native core returned a zero handle");
                return handle;
            }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static bool TryUdpProbe(string config, uint timeoutMs, out ulong latencyMs)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(config);
        try
        {
            fixed (byte* pointer = bytes)
                return qeli_client_udp_probe(pointer, (nuint)bytes.Length, timeoutMs,
                    out latencyMs) == Ok;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static void SetDeviceId(ulong handle, byte[] deviceId)
    {
        fixed (byte* pointer = deviceId)
            Check(qeli_client_set_device_id(handle, pointer, (nuint)deviceId.Length),
                "qeli_client_set_device_id");
    }

    internal static void Start(ulong handle) => Check(qeli_client_start(handle), "qeli_client_start");

    internal static void SetTunFd(ulong handle, ulong generation, int fd) =>
        Check(qeli_client_set_tun_fd(handle, generation, fd), "qeli_client_set_tun_fd");

    internal static void SetWintunAdapter(ulong handle, ulong generation, string adapterName)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(adapterName);
        fixed (byte* pointer = bytes)
            Check(qeli_client_set_wintun_adapter(handle, generation, pointer,
                (nuint)bytes.Length), "qeli_client_set_wintun_adapter");
    }

    internal static ulong PathUpdate(ulong handle, NativePathUpdate update)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(NativeRoamingPath.EncodeUpdate(update));
        fixed (byte* pointer = bytes)
        {
            Check(qeli_client_path_update(handle, pointer, (nuint)bytes.Length,
                out ulong candidateId), "qeli_client_path_update");
            if (candidateId == 0)
                throw new InvalidOperationException("native core returned a zero path candidate id");
            return candidateId;
        }
    }

    internal static void PathCommandResult(ulong handle, NativeEvent request,
        NativePathCommand command, PathCommandOutcome outcome, string? reason = null)
    {
        if (request.Kind != EventPathCommand || request.PayloadFormat != PayloadJson
            || request.Sequence == 0 || request.PlanGeneration == 0
            || command.Generation != request.PlanGeneration || command.CandidateId == 0)
            throw new InvalidDataException("invalid native path-command acknowledgement");
        if (!Enum.IsDefined(outcome))
            throw new ArgumentOutOfRangeException(nameof(outcome));
        ResultWithReason((pointer, length) =>
            qeli_client_path_command_result(handle, request.PlanGeneration, command.CandidateId,
                request.Sequence, (int)outcome, pointer, length), reason,
            "qeli_client_path_command_result");
    }

    internal static int Run(ulong handle, string input)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(input);
        try
        {
            fixed (byte* pointer = bytes)
                return qeli_client_run(handle, pointer, (nuint)bytes.Length);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static void Stop(ulong handle)
    {
        int rc = qeli_client_stop(handle);
        if (rc != Ok && rc != -7) Check(rc, "qeli_client_stop");
    }

    internal static void Free(ulong handle)
    {
        int rc = qeli_client_free(handle);
        if (rc != Ok && rc != -7) Check(rc, "qeli_client_free");
    }

    internal static NativeEvent? PollEvent(ulong handle, byte[] payload)
    {
        EventHeader header = new() { StructSize = (uint)sizeof(EventHeader), AbiVersion = AbiVersion };
        fixed (byte* payloadPointer = payload)
        {
            int rc = qeli_client_poll_event(handle, &header, payloadPointer,
                (nuint)payload.Length, out nuint payloadLength);
            if (rc == NoEvent) return null;
            Check(rc, "qeli_client_poll_event");
            string text = payloadLength == 0
                ? ""
                : Encoding.UTF8.GetString(payload, 0, checked((int)payloadLength));
            return new NativeEvent(header.Kind, header.State, header.PayloadFormat,
                header.Sequence, header.PlanGeneration, header.ErrorCode, text);
        }
    }

    internal static void NetworkPlanResult(ulong handle, ulong generation, bool accepted, string? reason = null) =>
        ResultWithReason((pointer, length) => qeli_client_network_plan_result(handle, generation,
            accepted ? 0 : -1, pointer, length), reason, "qeli_client_network_plan_result");

    internal static void ServerIdentityResult(ulong handle, ulong sequence, bool accepted, string? reason = null) =>
        ResultWithReason((pointer, length) => qeli_client_server_identity_result(handle, sequence,
            accepted ? 0 : -1, pointer, length), reason, "qeli_client_server_identity_result");

    private unsafe delegate int ReasonCall(byte* reason, nuint length);

    private static void ResultWithReason(ReasonCall call, string? reason, string operation)
    {
        byte[] bytes = string.IsNullOrEmpty(reason) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(reason);
        fixed (byte* pointer = bytes)
        {
            int result = call(pointer, (nuint)bytes.Length);
            // A reconnect can cancel this generation while the platform applies trust or
            // network state. Android and Swift already treat that race as a normal outcome;
            // escalating it made a network change look like a key mismatch on Windows/macOS.
            if (result == StaleRequest)
                return;
            Check(result, operation);
        }
    }

    internal static NativeStats Stats(ulong handle)
    {
        StatsHeader stats = new() { StructSize = (uint)sizeof(StatsHeader), AbiVersion = AbiVersion };
        Check(qeli_client_stats(handle, &stats), "qeli_client_stats");
        return new NativeStats(stats.State, stats.TxPackets, stats.TxBytes, stats.RxPackets,
            stats.RxBytes, stats.Reconnects, stats.UptimeMs, stats.UdpKernelDrops,
            stats.UdpInternalDrops, stats.UdpBufferGrows, stats.UdpRecvBufferBytes);
    }

    internal static bool PushPacket(ulong handle, ulong generation, byte[] packet, int length)
    {
        if (length <= 0 || length > packet.Length)
            throw new ArgumentOutOfRangeException(nameof(length));
        uint wireLength = checked((uint)length);
        fixed (byte* packetPointer = packet)
        {
            uint* lengthPointer = &wireLength;
            int rc = qeli_client_tun_push(handle, generation, packetPointer,
                (nuint)length, lengthPointer, 1, out nuint accepted);
            if (rc == NoEvent) return accepted == 1;
            Check(rc, "qeli_client_tun_push");
            return accepted == 1;
        }
    }

    internal static int PullPackets(ulong handle, ulong generation, byte[] packets, uint[] lengths,
        out int bytes)
    {
        fixed (byte* packetPointer = packets)
        fixed (uint* lengthPointer = lengths)
        {
            int rc = qeli_client_tun_pull(handle, generation, packetPointer, (nuint)packets.Length,
                lengthPointer, (nuint)lengths.Length, out nuint count, out nuint used);
            bytes = checked((int)used);
            if (rc == NoEvent) return 0;
            Check(rc, "qeli_client_tun_pull");
            return checked((int)count);
        }
    }

    private static void Check(int rc, string operation)
    {
        if (rc != Ok) throw new InvalidOperationException($"{operation} failed ({rc})");
    }
}

/// <summary>Handle-free native diagnostics shared by the desktop UIs.</summary>
public static class NativeTransportDiagnostics
{
    public static bool TryUdpProbe(string config, int timeoutMs, out int latencyMs)
    {
        latencyMs = 0;
        if (timeoutMs is < 100 or > 5_000) return false;
        try
        {
            NativeTransportCore.RequireCompatible();
            if (!NativeTransportCore.TryUdpProbe(config, checked((uint)timeoutMs), out ulong value))
                return false;
            latencyMs = checked((int)Math.Min(value, int.MaxValue));
            return true;
        }
        catch (DllNotFoundException) { return false; }
        catch (EntryPointNotFoundException) { return false; }
        catch (BadImageFormatException) { return false; }
        catch (InvalidOperationException) { return false; }
    }
}
