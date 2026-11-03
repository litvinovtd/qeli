using System.ComponentModel;
using System.IO;
using System.Security.AccessControl;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace QeliWin.Service;

internal static class ServiceObservationSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        bool Fails(Action action)
        {
            try { action(); return false; }
            catch (Exception e) when (e is InvalidDataException or InvalidOperationException
                or DecoderFallbackException or JsonException or UnauthorizedAccessException) { return true; }
        }
        byte[] Security(string sddl)
        {
            var sd = new RawSecurityDescriptor(sddl); var bytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(bytes, 0); return bytes;
        }
        var trusted = Security("O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002008d;;;AU)");
        const string exe = @"C:\Program Files\QeliWin\QeliWin.exe";
        var registration = new ServiceRegistration($"\"{exe}\" --service", "LocalSystem", 0x10, trusted);
        int inspected = 0;
        ServiceRegistration.Validate(registration, exe, path => { if (path == exe) inspected++; });
        check("service registration: protected matching worker accepted and file ACL rechecked", inspected == 1);
        foreach (var command in new[] { $"{exe} --service", $"\"{exe}\" --service selftest", "\"C:\\Users\\user\\qeli.exe\" --service", "\"C:\\Program Files\\Other\\qeli.exe\" --service" })
            check("service registration: rejects ambiguous/foreign command " + command,
                Fails(() => ServiceRegistration.Validate(registration with { Command = command }, exe, _ => inspected++)) && inspected == 1);
        check("service registration: refuses wrong account", Fails(() => ServiceRegistration.Validate(registration with { Account = "LocalService" }, exe, _ => { })));
        check("service registration: refuses shared/interactive process", Fails(() => ServiceRegistration.Validate(registration with { Type = 0x110 }, exe, _ => { })));
        check("service registration: unsafe filesystem exception propagates", Fails(() => ServiceRegistration.Validate(registration, exe, _ => throw new UnauthorizedAccessException("unsafe directory"))));
        foreach (string rights in new[] { "0x00000002", "WD", "WO", "SD", "GW", "GA" })
            check("service registration: refuses unprivileged mutation " + rights,
                ServiceRegistration.UntrustedAccess(Security($"O:SYG:SYD:(A;;GA;;;SY)(A;;{rights};;;AU)")) != null);
        check("service registration: refuses untrusted owner", ServiceRegistration.UntrustedAccess(Security("O:AUG:SYD:(A;;GA;;;SY)")) != null);
        check("service registration: refuses null DACL", ServiceRegistration.UntrustedAccess(Security("O:SYG:SY")) != null);
        check("service registration: deny ACE does not hide unsafe allow", ServiceRegistration.UntrustedAccess(Security("O:SYG:SYD:(D;;GA;;;AU)(A;;GA;;;AU)(A;;GA;;;SY)")) != null);
        try { ServiceRegistration.Read("QeliAuditMissing-" + Guid.NewGuid().ToString("N")); check("SCM read-only missing GUID query returns absence", false); }
        catch (Win32Exception e) { check("SCM read-only missing GUID query returns absence", e.NativeErrorCode == 1060); }
        var eventLog = ServiceRegistration.Read("EventLog");
        check("SCM read-only real configuration/security marshalling", eventLog.Command.Length > 0
            && eventLog.Account.Length > 0 && eventLog.Type != 0 && new RawSecurityDescriptor(eventLog.Security, 0).Owner != null);
        int mutations = 0;
        var controller = new ServiceProfileTransition(() => true, () => true, () => new VpnConfig(),
            () => mutations++, _ => mutations++, () => mutations++, () => mutations++, () => mutations++,
            () => throw new InvalidOperationException("bad registration"));
        check("service registration: refused apply leaves worker/intent/profile untouched",
            Fails(() => controller.Apply(new VpnConfig(), false)) && mutations == 0);

        var now = DateTime.Now;
        ServiceStatus Snapshot(string status = "Connected", int seconds = 0, string? extra = null) =>
            new() { Status = status, Time = now.AddSeconds(seconds), Extra = extra, BytesUp = 12, BytesDown = 34 };
        var connected = Snapshot();
        var live = ServiceObservation.Resolve(ServiceControllerStatus.Running, connected, now);
        check("service observation: fresh connected snapshot retains traffic", live.Status == VpnStatus.Connected && ReferenceEquals(live.Snapshot, connected));
        check("service observation: stale connected is unknown error without traffic",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, Snapshot(seconds: -11), now) is { Status: VpnStatus.Error, Snapshot: null });
        check("service observation: future status refused", ServiceObservation.Resolve(ServiceControllerStatus.Running, Snapshot(seconds: 6), now).Status == VpnStatus.Error);
        check("service observation: missing running snapshot is error", ServiceObservation.Resolve(ServiceControllerStatus.Running, null, now).Status == VpnStatus.Error);
        check("service observation: stopped stale connected is disconnected", ServiceObservation.Resolve(ServiceControllerStatus.Stopped, connected, now).Status == VpnStatus.Disconnected);
        check("service observation: stopped cleanup error retained",
            ServiceObservation.Resolve(ServiceControllerStatus.Stopped, Snapshot("Error", -60, QeliWorker.CleanupIncomplete), now) is { Status: VpnStatus.Error, Extra: QeliWorker.CleanupIncomplete, Snapshot: null });
        check("service observation: start pending is connecting", ServiceObservation.Resolve(ServiceControllerStatus.StartPending, connected, now).Status == VpnStatus.Connecting);
        check("service observation: stop pending/paused does not reuse connected",
            ServiceObservation.Resolve(ServiceControllerStatus.StopPending, connected, now).Status == VpnStatus.Error
            && ServiceObservation.Resolve(ServiceControllerStatus.Paused, connected, now).Status == VpnStatus.Error);
        check("service observation: same enum carries changed error detail",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, Snapshot("Error", extra: "second"), now).Extra == "second");

        var monotonic = Snapshot();
        monotonic.MonotonicTimeMs = 20_000;
        monotonic.Time = now.AddHours(-12);
        check("service observation: clock jump forward does not hide a live monotonic snapshot",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, monotonic, now, 20_500)
                is { Status: VpnStatus.Connected, Snapshot: not null });
        monotonic.Time = now.AddHours(12);
        check("service observation: clock jump backward does not hide a live monotonic snapshot",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, monotonic, now, 20_500)
                is { Status: VpnStatus.Connected, Snapshot: not null });
        monotonic.Time = now;
        check("service observation: fresh wall clock cannot rescue a stale monotonic snapshot",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, monotonic, now, 30_001)
                is { Status: VpnStatus.Error, Snapshot: null });
        check("service observation: future uptime cannot fall back to the wall clock",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, monotonic, now, 19_999)
                is { Status: VpnStatus.Error, Snapshot: null });
        monotonic.MonotonicTimeMs = 0;
        check("service observation: zero uptime is present rather than legacy or unspecified now",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, monotonic, now, 0)
                is { Status: VpnStatus.Connected, Snapshot: not null });
        check("service observation: legacy status ignores the optional current uptime",
            ServiceObservation.Resolve(ServiceControllerStatus.Running, connected, now, 0)
                is { Status: VpnStatus.Connected, Snapshot: not null });
        byte[] Encode(ServiceStatus value) => JsonSerializer.SerializeToUtf8Bytes(value);
        check("service status: valid strict decode", ServiceState.DecodeStatus(Encode(connected)).BytesUp == 12);
        check("service status: Windows codec retains the optional uptime",
            ServiceState.DecodeStatus(Encode(monotonic)).MonotonicTimeMs == 0);
        foreach (string value in new[] { "999", "2", "connected", "Unknown", "" })
            check("service status: rejects invalid enum " + value, Fails(() => ServiceState.DecodeStatus(Encode(Snapshot(value)))));
        check("service status: rejects null snapshot", Fails(() => ServiceState.DecodeStatus(Encoding.UTF8.GetBytes("null"))));
        check("service status: rejects negative counters", Fails(() => ServiceState.DecodeStatus(Encode(new ServiceStatus { Time = now, BytesUp = -1 }))));
        check("service status: rejects absent timestamp", Fails(() => ServiceState.DecodeStatus(Encode(new ServiceStatus()))));
        check("service status: rejects oversized detail", Fails(() => ServiceState.DecodeStatus(Encode(Snapshot(extra: new string('x', 2049))))));
        check("service status: rejects invalid UTF8", Fails(() => ServiceState.DecodeStatus([0xff])));
        foreach (var addresses in new[] { new DesktopTunnelAddresses("::1", null), new DesktopTunnelAddresses(null, "1.2.3.4"), new DesktopTunnelAddresses(null, "fe80::1%2"), new DesktopTunnelAddresses(new string('1', 46), null) })
            check("service status: rejects invalid typed address", Fails(() => ServiceState.DecodeStatus(Encode(new ServiceStatus { Time = now, Addresses = addresses }))));
        check("service status: preserves full IPv6", ServiceState.DecodeStatus(Encode(new ServiceStatus { Time = now, Addresses = new("10.8.0.2", "2001:db8:1234:5678:abcd:ffff:ffff:ffff") })).Addresses.Ipv6 == "2001:db8:1234:5678:abcd:ffff:ffff:ffff");

        var dir = Path.Combine(Path.GetTempPath(), "qeli-observation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "log");
            var oversized = ServiceState.EncodeLogLine(new string('漢', 100_000) + "😀", DateTime.UtcNow);
            check("service log: giant unicode line truncated before writing", oversized.Length < 17_000 && Encoding.UTF8.GetString(oversized).Contains("[truncated]"));
            var surrogate = ServiceState.EncodeLogLine(new string('x', 4095) + "😀more", DateTime.UtcNow);
            check("service log: truncation does not split surrogate pair", !new UTF8Encoding(false, true).GetString(surrogate).Contains('\ufffd'));
            File.WriteAllBytes(path, new byte[ServiceState.MaxLogBytes - oversized.Length + 1]);
            ServiceState.AppendLogFile(path, oversized);
            check("service log: rotates before crossing byte budget", File.ReadAllBytes(path).SequenceEqual(oversized));
            ServiceState.AppendLogFile(path, oversized);
            check("service log: append remains bounded", new FileInfo(path).Length == 2 * oversized.Length);
            File.WriteAllBytes(path, new byte[ServiceState.MaxLogBytes + 10]);
            ServiceState.AppendLogFile(path, oversized);
            check("service log: oversized legacy file replaced by bounded generation", File.ReadAllBytes(path).SequenceEqual(oversized));
            check("service log: rogue oversized read refused", Fails(() => ServiceState.ReadLogSnapshot(new MemoryStream(new byte[ServiceState.MaxLogBytes + 1]))));
            var bytes = Encoding.UTF8.GetBytes("first\nsecond😀\n");
            var stream = new GrowingStream(bytes);
            string first = ServiceState.ReadLogSnapshot(stream);
            stream.Grow(); stream.Position = 0;
            string next = ServiceState.ReadLogSnapshot(stream);
            check("service log: append after observed EOF is present next poll", first == "first\n" && next == "first\nsecond😀\n");
            check("service log: partial UTF8 is retried without advancing cursor", Fails(() => ServiceState.ReadLogSnapshot(new MemoryStream([0xf0, 0x9f])))
                && ServiceState.ReadLogSnapshot(new MemoryStream(Encoding.UTF8.GetBytes("😀"))) == "😀");
            using var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            ServiceState.AppendLogFile(path, new byte[ServiceState.MaxLogBytes]);
            check("service log: atomic rotation preserves existing reader generation", ServiceState.ReadLogSnapshot(handle) == Encoding.UTF8.GetString(oversized)
                && new FileInfo(path).Length == ServiceState.MaxLogBytes);
        }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class GrowingStream(byte[] bytes) : MemoryStream(bytes)
    {
        private bool grown;
        internal void Grow() => grown = true;
        public override int Read(byte[] buffer, int offset, int count)
        {
            int visible = grown ? (int)Length : 6;
            return Position >= visible ? 0 : base.Read(buffer, offset, (int)Math.Min(count, visible - Position));
        }
    }
}
