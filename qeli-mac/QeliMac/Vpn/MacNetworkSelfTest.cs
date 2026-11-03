using System.Net;
using System.Text;
using System.Text.Json;
using Qeli.Shared.Vpn;
namespace QeliMac.Vpn;

internal static class MacNetworkSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        void Check(string name, bool ok) => check("mac network: " + name, ok);
        static bool Fails(Action action) { try { action(); return false; } catch (Exception e) when (e is IOException or InvalidDataException or InvalidOperationException or ObjectDisposedException or JsonException or DecoderFallbackException) { return true; } }
        var self = new DnsJournal.Owner(100, 1000); var other = new DnsJournal.Owner(200, 2000);
        var events = new List<string>(); byte[]? state = null; string? failure = null; bool alive = true;
        PfRecovery Recovery() => new(() => state,
            () => { events.Add("flush"); if (failure == "flush") throw new IOException("pf failure"); },
            () => { events.Add("rules"); if (failure == "rules") throw new IOException("delete failure"); },
            () => { events.Add("state"); state = null; }, _ => alive, self);
        Check("missing journal never authorizes anchor flush", !Recovery().Release(false) && events.Count == 0);
        state = PfRecovery.Encode(other, false);
        Check("foreign live owner cannot be disconnected", Fails(() => Recovery().Release(false)) && events.Count == 0 && state is not null);
        Check("startup sweep preserves live owner", !Recovery().Release(true) && events.Count == 0);
        Check("allowlist refresh refuses foreign owner", Fails(Recovery().RequireCurrentOwner));
        state = PfRecovery.Encode(self, true); Recovery().RequireCurrentOwner();
        Check("current owner may refresh its own rules", true);
        Check("pf owner stamp roundtrips diagnostic enabled flag", PfRecovery.Decode(state).Owner == self && PfRecovery.Decode(state).WasEnabled);
        foreach (var bytes in new[] { Array.Empty<byte>(), new byte[4097], new byte[] { 255 },
            Encoding.UTF8.GetBytes("enabled=0\n"), Encoding.UTF8.GetBytes("pid=1\nstart=1\nenabled=0\npid=2\n"),
            Encoding.UTF8.GetBytes("pid=0\nstart=1\nenabled=0\n"), Encoding.UTF8.GetBytes("pid=1\nstart=1\nenabled=2\n") })
            Check("malformed pf journal rejected before flush", Fails(() => PfRecovery.Decode(bytes)));
        state = new byte[] { 255 }; events.Clear();
        Check("corrupt persisted pf owner cannot authorize cleanup", Fails(() => Recovery().Release(false)) && events.Count == 0 && state is not null);
        state = PfRecovery.Encode(other, false); alive = false; failure = "flush"; events.Clear();
        Check("failed pf flush retains recovery journal", Fails(() => Recovery().Release(true)) && state is not null && events.SequenceEqual(new[] { "flush" }));
        failure = "rules"; events.Clear();
        Check("failed rules cleanup keeps last journal", Fails(() => Recovery().Release(true)) && state is not null && events.SequenceEqual(new[] { "flush", "rules" }));
        failure = null; events.Clear();
        Check("stale cleanup retries before deleting ownership", Recovery().Release(true) && state is null && events.SequenceEqual(new[] { "flush", "rules", "state" }));
        Check("repeat cleanup is a no-op", !Recovery().Release(false));
        Check("explicit Qeli anchor selected", PfRecovery.Anchor("anchor \"qeli\" all\n") == "qeli");
        Check("stock wildcard anchor selected", PfRecovery.Anchor("anchor \"com.apple/*\" all\n") == "com.apple/qeli");
        foreach (string rules in new[] { "", "# anchor \"qeli\" all", "anchor \"qeli\" on en0 all", "anchor \"qeli-extra\" all", "pass out quick all" })
            Check("unreferenced/conditional anchor refuses global reload", Fails(() => PfRecovery.Anchor(rules)));
        foreach (var (literal, expected) in new[] {
            ("1.1.1.1",true), ("10.0.0.1",true), ("2001:db8::53",true), ("::ffff:1.1.1.1",true),
            ("0.0.0.0",false), ("0.1.2.3",false), ("127.0.0.1",false), ("169.254.1.1",false),
            ("224.0.0.53",false), ("255.255.255.255",false), ("::",false), ("::1",false), ("fe80::1",false),
            ("fec0::1",false), ("ff02::1",false), ("::ffff:127.0.0.1",false), ("::ffff:224.0.0.53",false) })
            Check("physical DNS policy " + literal, PhysicalDnsPolicy.IsUsableResolver(IPAddress.Parse(literal)) == expected);

        Check("DNS snapshot literal list preserved", NetworkConfigurator.ParseSystemDns("Wi-Fi", "1.1.1.1\n2001:db8::53\n").Servers.SequenceEqual(new[] { "1.1.1.1", "2001:db8::53" }));
        Check("exact automatic DNS diagnostic parsed", NetworkConfigurator.ParseSystemDns("Wi-Fi", "There aren't any DNS Servers set on Wi-Fi.").Ok);
        foreach (string text in new[] { "", "Error: permission denied", "There aren't any DNS Servers set on Ethernet.", "1.1.1.1\ntruncated output" })
            Check("unknown DNS output is not invented automatic state", !NetworkConfigurator.ParseSystemDns("Wi-Fi", text).Ok);

        var ipv6Primary = new NetworkConfigurator(_ => { }, (exe, args) => exe.Contains("networksetup")
            ? ("(1) Ethernet\n(Hardware Port: Ethernet, Device: en1)\n", "", 0)
            : args.Contains("-inet6") ? ("interface: en1\n", "", 0) : ("", "no IPv4 default", 1), _ => true);
        Check("IPv6-only default selects its actual DNS service", ipv6Primary.PrimaryNetworkService() == "Ethernet");
        var noPrimary = new NetworkConfigurator(_ => { }, (_, _) => ("", "query failed", 1), _ => true);
        Check("failed primary lookup cannot guess another service", noPrimary.PrimaryNetworkService() is null);

        foreach (var address in new[] { IPAddress.Parse("10.8.0.2"), IPAddress.Parse("fd71:e1::2") })
        {
            bool fail = true; int deletes = 0;
            var net = new NetworkConfigurator(_ => { }, (_, args) =>
            {
                if (args.Contains("-alias")) { deletes++; return ("", "refused", fail ? 1 : 0); }
                if (args == "utun7") return ($"utun7: flags=8051<UP> mtu 1400\n  {(address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "inet6" : "inet")} {address}\n", "", 0);
                return ("", "", 0);
            }, _ => true);
            net.SetAddress("utun7", address.ToString());
            Check("failed address removal stays owned " + address, Fails(net.Dispose) && deletes == 1);
            fail = false; net.Dispose(); net.Dispose();
            Check("address removal retries once then forgets success " + address, deletes == 2);
        }
        int aliasAttempts = 0;
        var missing = new NetworkConfigurator(_ => { }, (_, args) => {
            if (args.Contains("-alias")) { aliasAttempts++; return ("", "not present", 1); }
            if (args == "utun7") return ("utun7: flags=8051<UP> mtu 1400\n", "", 0);
            return ("", "", 0);
        }, _ => true);
        missing.SetAddress("utun7", "10.8.0.2"); missing.Dispose(); missing.Dispose();
        Check("verified absent address releases cleanup ownership", aliasAttempts == 1);
        Check("empty ifconfig output is not absence proof", !NetworkConfigurator.AddressAbsent("", "utun7", IPAddress.Parse("10.8.0.2")));
        Check("foreign interface header is not absence proof", !NetworkConfigurator.AddressAbsent("utun8: flags=1\n", "utun7", IPAddress.Parse("10.8.0.2")));
        Check("malformed address output is not absence proof", !NetworkConfigurator.AddressAbsent("utun7: flags=1\ninet invalid\n", "utun7", IPAddress.Parse("10.8.0.2")));
        int cleanup = 0;
        var partial = new NetworkConfigurator(_ => { }, (_, args) => {
            if (args.Contains("-alias")) { cleanup++; return ("", "", 0); } return ("", "partial add failure", 1);
        }, _ => true);
        Check("failed partial address apply is observable", Fails(() => partial.SetAddress("utun7", "10.8.0.2")));
        partial.Dispose(); Check("failed partial apply retains cleanup action", cleanup == 1);
        Check("invalid IPv4 prefix refuses before apply", Fails(() => partial.SetAddress("utun7", "10.8.0.2", 33)));

        int mutations = 0;
        var unknownRoute = new NetworkConfigurator(_ => { }, (_, args) =>
        {
            if (args.Contains("get")) return ("", "query denied", 1);
            mutations++; return ("", "", 0);
        }, _ => true);
        Check("unknown existing carrier route refuses before mutation", Fails(() =>
            unknownRoute.PinServerRoute(IPAddress.Parse("203.0.113.7"), IPAddress.Parse("192.0.2.1"), "en0")) && mutations == 0);

        string? exactGateway = null; int routeDeletes = 0;
        var external = new NetworkConfigurator(_ => { }, (_, args) =>
        {
            if (args.Contains("get")) return (exactGateway is null
                ? "destination: default\nmask: default\ngateway: 192.0.2.1\ninterface: en0\nflags: <UP,GATEWAY>\n"
                : $"destination: 203.0.113.7\ngateway: {exactGateway}\ninterface: en0\nflags: <UP,GATEWAY,HOST,STATIC>\n", "", 0);
            if (args.Contains("delete")) { routeDeletes++; exactGateway = null; }
            else if (args.Contains("add")) exactGateway = "192.0.2.1";
            return ("", "", 0);
        }, _ => true);
        external.PinServerRoute(IPAddress.Parse("203.0.113.7"), IPAddress.Parse("192.0.2.1"), "en0");
        exactGateway = "198.51.100.1";
        external.Dispose();
        Check("cleanup preserves externally replaced carrier route", routeDeletes == 0 && exactGateway == "198.51.100.1");

        int created = 0, closed = 0;
        var device = new UtunDevice(() => { Interlocked.Increment(ref created); return (7, "utun7"); }, _ => Interlocked.Increment(ref closed));
        Parallel.For(0, 2, _ => { try { device.Open(); } catch (InvalidOperationException) { } });
        Check("concurrent Open creates one owned descriptor", created == 1 && device.FileDescriptor == 7);
        Parallel.For(0, 64, _ => device.Dispose());
        Check("concurrent Dispose closes descriptor once", closed == 1 && Fails(() => _ = device.FileDescriptor));
        Check("disposed utun never reopens", Fails(device.Open) && created == 1);
        var bad = new UtunDevice(() => (8, "utun +1"), _ => closed++);
        Check("invalid kernel name closes newly opened descriptor", Fails(bad.Open) && closed == 2);
        foreach (string name in new[] { "utun", "utun+1", "utun-1", "utun 1", "en0", "utun1\npass all" })
            Check("noncanonical utun name rejected", !UtunDevice.ValidName(name));

        RunOwnerIdentity(Check);
        RunDns(Check);
    }

    private static void RunOwnerIdentity(Action<string, bool> check)
    {
        var current = DnsJournal.CurrentOwner();
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        check("current DNS/PF identity is explicitly UTC", !current.LegacyLocalTime
            && current.StartTicks == process.StartTime.ToUniversalTime().Ticks);
        check("current UTC generation is alive", DnsJournal.IsOwnerAlive(current));
        var shifted = new DnsJournal.Owner(current.Pid, current.StartTicks - TimeSpan.TicksPerHour * 3);
        check("UTC generation mismatch detects PID reuse", !DnsJournal.IsOwnerAlive(shifted));
        byte[] Legacy(long ticks) => Encoding.UTF8.GetBytes($"pid={current.Pid}\nstart={ticks}\nenabled=0\n");
        var legacy = PfRecovery.Decode(Legacy(shifted.StartTicks));
        check("legacy local stamp keeps clock ambiguity", legacy.Owner.LegacyLocalTime);
        check("timezone-shifted legacy PID remains protected", DnsJournal.IsOwnerAlive(legacy.Owner));
        check("same numeric ticks do not claim legacy ownership", PfRecovery.Decode(Legacy(current.StartTicks)).Owner != current);
        int mutations = 0; byte[]? state = Legacy(shifted.StartTicks);
        var recovery = new PfRecovery(() => state, () => mutations++, () => mutations++, () => state = null,
            DnsJournal.IsOwnerAlive, current);
        check("legacy live pf owner survives startup sweep", !recovery.Release(true) && mutations == 0);
        check("legacy live pf owner refuses explicit release", Reject(recovery, false) && mutations == 0);
        check("legacy live pf owner refuses refresh", RejectRefresh(recovery) && mutations == 0);
        foreach (string suffix in new[] { "clock=local\n", "clock=utc\nclock=utc\n", "extra=1\n" })
            check("invalid pf clock marker rejected", RejectDecode(Legacy(1).Concat(Encoding.UTF8.GetBytes(suffix)).ToArray()));
        check("out-of-range pf start rejected", RejectDecode(Legacy(DateTime.MaxValue.Ticks + 1)));
        state = PfRecovery.Encode(shifted, false);
        check("tagged stale pf generation can be recovered", recovery.Release(true) && mutations == 2 && state is null);
        check("legacy missing PID can be recovered", !DnsJournal.IsOwnerAlive(new(int.MaxValue, 1, true)));
        static bool Reject(PfRecovery r, bool stale) { try { r.Release(stale); return false; } catch (InvalidOperationException) { return true; } }
        static bool RejectRefresh(PfRecovery r) { try { r.RequireCurrentOwner(); return false; } catch (InvalidOperationException) { return true; } }
        static bool RejectDecode(byte[] bytes) { try { PfRecovery.Decode(bytes); return false; } catch (InvalidDataException) { return true; } }
    }

    private static void RunDns(Action<string, bool> check)
    {
        string dir = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "qeli-network-audit-" + Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(dir);
        try
        {
            int writes = 0; var owner = new DnsJournal.Owner(1, 1);
            DnsJournal New(string path, Func<byte[]?>? bytes = null) => new(path, _ => new(true, new[] { "192.0.2.53" }, ""),
                (_, _) => { writes++; return new(true, ""); }, _ => false, owner, _ => { }, readState: bytes);
            foreach (var data in new[] { new byte[65537], new byte[] { 255 }, Encoding.UTF8.GetBytes("{\"PreviousServers\":null}"), Array.Empty<byte>() })
            {
                string path = Path.Combine(dir, Guid.NewGuid().ToString("N")); File.WriteAllBytes(path, data);
                check("invalid/oversized/UTF8 DNS journal retained without writes", New(path).RecoverStale() == DnsJournal.RecoveryResult.Failed && File.ReadAllBytes(path).SequenceEqual(data) && writes == 0);
            }
            check("read failure never looks like missing DNS journal", New(Path.Combine(dir, "unreadable"), () => throw new IOException("denied")).RecoverStale() == DnsJournal.RecoveryResult.Failed && writes == 0);

            string clockPath = Path.Combine(dir, "clock.json");
            var currentOwner = DnsJournal.CurrentOwner();
            byte[]? clockState = null;
            var clockDns = new List<string> { "192.0.2.53" }; int clockWrites = 0;
            DnsJournal ClockJournal(DnsJournal.Owner claimant) => new(clockPath,
                _ => new(true, clockDns.ToArray(), ""), (_, servers) => { clockWrites++; clockDns = servers.ToList(); return new(true, ""); },
                DnsJournal.IsOwnerAlive, claimant, _ => { }, readState: () => clockState,
                publishState: bytes => { clockState = bytes; return true; }, deleteState: () => clockState = null);
            var clock = ClockJournal(currentOwner);
            check("UTC DNS claim succeeds", clock.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out var clockRelease, out _));
            var json = System.Text.Json.Nodes.JsonNode.Parse(clockState!)!;
            check("new DNS snapshot persists schema 2 UTC", json["Version"]!.GetValue<int>() == 2
                && json["OwnerStartTicks"]!.GetValue<long>() == currentOwner.StartTicks);
            json["Version"] = 1; json["OwnerStartTicks"] = currentOwner.StartTicks - TimeSpan.TicksPerHour * 3;
            clockState = Encoding.UTF8.GetBytes(json.ToJsonString());
            check("legacy live DNS PID survives simulated timezone change", clock.RecoverStale() == DnsJournal.RecoveryResult.LiveOwner
                && clockWrites == 1 && clockState is not null && clockDns.SequenceEqual(new[] { "10.9.0.1" }));
            json["OwnerStartTicks"] = currentOwner.StartTicks; clockState = Encoding.UTF8.GetBytes(json.ToJsonString());
            bool refused = false; try { clockRelease!(); } catch (InvalidOperationException) { refused = true; }
            check("release cannot equate UTC lease with legacy numeric ticks", refused && clockWrites == 1 && clockState is not null);
            json["OwnerPid"] = int.MaxValue; clockState = Encoding.UTF8.GetBytes(json.ToJsonString());
            check("legacy dead DNS PID restores exact prior servers", clock.RecoverStale() == DnsJournal.RecoveryResult.Restored
                && clockWrites == 2 && clockState is null && clockDns.SequenceEqual(new[] { "192.0.2.53" }));
            json["Version"] = 2; json["OwnerPid"] = currentOwner.Pid; json["OwnerStartTicks"] = currentOwner.StartTicks - 1;
            clockDns = new() { "10.9.0.1" }; clockState = Encoding.UTF8.GetBytes(json.ToJsonString());
            check("UTC DNS reused PID generation restores", clock.RecoverStale() == DnsJournal.RecoveryResult.Restored
                && clockWrites == 3 && clockState is null);
            foreach (int version in new[] { 0, 3 })
            {
                json["Version"] = version; clockState = Encoding.UTF8.GetBytes(json.ToJsonString());
                check("unknown DNS clock schema refuses mutation", clock.RecoverStale() == DnsJournal.RecoveryResult.Failed && clockWrites == 3 && clockState is not null);
            }

            string throwingPath = Path.Combine(dir, "throwing.json");
            var throwingCurrent = new List<string> { "192.0.2.53" };
            var throwing = new DnsJournal(throwingPath, _ => new(true, throwingCurrent, ""),
                (_, servers) => { throwingCurrent = servers.ToList(); if (servers.Contains("10.9.0.1")) throw new IOException("partial apply"); return new(true, ""); },
                _ => false, owner, _ => { });
            check("throwing DNS apply rolls back partial mutation", !throwing.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out _, out _)
                && throwingCurrent.SequenceEqual(new[] { "192.0.2.53" }) && !File.Exists(throwingPath));

            string race = Path.Combine(dir, "race.json");
            var old = new DnsJournal.Owner(10, 10); var next = new DnsJournal.Owner(20, 20);
            var current = new List<string> { "192.0.2.53" };
            DnsJournal.ReadResult Read(string _) => new(true, current.ToArray(), "");
            DnsJournal.WriteResult Write(string _, IReadOnlyList<string> servers) { current = servers.ToList(); return new(true, ""); }
            var first = new DnsJournal(race, Read, Write, _ => false, old, _ => { });
            check("DNS fixture creates original recovery state", first.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out _, out _));
            using var entered = new ManualResetEventSlim(false); using var resume = new ManualResetEventSlim(false);
            DnsJournal.ReadResult HeldRead(string service) { var snapshot = Read(service); entered.Set(); if (!resume.Wait(5000)) throw new IOException("test synchronization timeout"); return snapshot; }
            var recovering = new DnsJournal(race, HeldRead, Write, _ => false, new(30, 30), _ => { });
            var recoveringTask = Task.Run(recovering.RecoverStale);
            if (!entered.Wait(5000)) throw new IOException("recovery did not enter");
            var contender = new DnsJournal(race, Read, Write, o => o == next, next, _ => { });
            var contenderTask = Task.Run(() => contender.TryTakeOver("Wi-Fi", new[] { "10.9.0.2" }, out _, out _));
            bool waited = !contenderTask.Wait(150); resume.Set(); Task.WaitAll(recoveringTask, contenderTask);
            check("new DNS owner waits for stale restoration transaction", waited && recoveringTask.Result == DnsJournal.RecoveryResult.Restored && contenderTask.Result);
            check("stale restoration cannot erase new DNS journal/override", File.Exists(race) && current.SequenceEqual(new[] { "10.9.0.2" }));
        }
        finally
        {
            if (!dir.StartsWith(Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(dir).StartsWith("qeli-network-audit-", StringComparison.Ordinal)) throw new IOException("Unsafe test cleanup path");
            Directory.Delete(dir, recursive: true);
        }
    }
}
