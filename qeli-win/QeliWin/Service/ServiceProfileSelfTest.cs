using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace QeliWin.Service;

internal static class ServiceProfileSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        // Production codec + bounded stream, real machine-scope DPAPI; no SCM/ProgramData access.
        byte[] Seal(byte[] bytes) => ProtectedData.Protect(bytes, null, DataProtectionScope.LocalMachine);
        bool Refused(Action action)
        {
            try { action(); return false; }
            catch (Exception e) when (e is InvalidDataException or JsonException or DecoderFallbackException)
            { return true; }
        }
        var cfg = new VpnConfig { Id = "service-test", Password = "test-only-password" };
        var encrypted = ServiceState.EncodeProfile(cfg);
        var decoded = ServiceState.DecodeProfile(encrypted, allowLegacy: false, out bool legacy);
        check("service DPAPI: valid machine-scope roundtrip without legacy",
            !legacy && decoded.Id == cfg.Id && decoded.Password == cfg.Password);
        byte[] plain = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(cfg));
        check("service DPAPI: LocalSystem policy refuses legacy plaintext",
            Refused(() => ServiceState.DecodeProfile(plain, allowLegacy: false, out _)));
        var migrated = ServiceState.DecodeProfile(plain, allowLegacy: true, out legacy);
        check("service DPAPI: trusted GUI legacy migration remains available",
            legacy && migrated.Id == cfg.Id && ServiceState.EncodeProfile(migrated).Length != 0);

        var prefix = Encoding.UTF8.GetBytes("{\"Id\":\"utf\",\"Password\":\"");
        byte[] invalidUtf8 = prefix.Concat(new byte[] { 0xff }).Concat(Encoding.UTF8.GetBytes("\"}")).ToArray();
        foreach (bool allowLegacy in new[] { false, true })
            check($"service DPAPI: malformed encrypted UTF-8 refused (legacy={allowLegacy})",
                Refused(() => ServiceState.DecodeProfile(Seal(invalidUtf8), allowLegacy, out _)));
        check("service DPAPI: malformed legacy UTF-8 refused",
            Refused(() => ServiceState.DecodeProfile(invalidUtf8, allowLegacy: true, out _)));
        foreach (var invalid in new[] { "null", "[]", "{\"Id\":\"\"}", "{\"Password\":null}",
            "{\"IncludeRoutes\":null}", "{\"Apps\":[null]}", "{\"CarriedKeys\":{\"x\":null}}" })
            check($"service DPAPI: invalid profile {invalid} refused before use",
                Refused(() => ServiceState.DecodeProfile(Seal(Encoding.UTF8.GetBytes(invalid)), false, out _)));
        check("service DPAPI: writer rejects null required fields",
            Refused(() => ServiceState.EncodeProfile(new VpnConfig { Password = null! })));
        check("service DPAPI: writer rejects unreadable oversized profile",
            Refused(() => ServiceState.EncodeProfile(new VpnConfig { Password = new string('x', ServiceState.MaximumProfileBytes) })));
        // Envelope overhead must count too: tune a valid JSON body just below the cap.
        int overhead = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(new VpnConfig { Password = "" }));
        check("service DPAPI: writer includes DPAPI overhead in stored limit",
            Refused(() => ServiceState.EncodeProfile(new VpnConfig {
                Password = new string('x', ServiceState.MaximumProfileBytes - overhead - 1) })));

        using var exact = new MemoryStream(new byte[ServiceState.MaximumProfileBytes]);
        check("service storage: exact 4 MiB boundary accepted",
            ServiceState.ReadBounded(exact, ServiceState.MaximumProfileBytes).Length == ServiceState.MaximumProfileBytes);
        using var growing = new GrowingStream(ServiceState.MaximumProfileBytes + 65536);
        check("service storage: growth after initial Length cannot bypass 4 MiB",
            Refused(() => ServiceState.ReadBounded(growing, ServiceState.MaximumProfileBytes))
            && growing.Consumed == ServiceState.MaximumProfileBytes + 1);
        using var status = new GrowingStream(ServiceState.MaximumStatusBytes + 65536);
        check("service storage: status snapshot stops at 64 KiB plus sentinel",
            Refused(() => ServiceState.ReadBounded(status, ServiceState.MaximumStatusBytes))
            && status.Consumed == ServiceState.MaximumStatusBytes + 1);
        using var flag = new GrowingStream(65536);
        check("service storage: connection intent stops at 16 bytes plus sentinel",
            Refused(() => ServiceState.ReadBounded(flag, 16)) && flag.Consumed == 17);
    }

    // Length reports the initial snapshot; bytes keep arriving in short chunks after it.
    private sealed class GrowingStream(int totalBytes) : Stream
    {
        internal int Consumed { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 1;
        public override long Position { get => Consumed; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = Math.Min(Math.Min(count, 137), totalBytes - Consumed);
            Array.Fill(buffer, (byte)'x', offset, n);
            Consumed += n;
            return n;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
