using System.Security;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class ServerIdentityConformance
{
    internal static void Run(Action<string, bool> check)
    {
        string a = new('a', 64), b = new('b', 64);
        string rows = $"vpn:443 {b}\ntcp://vpn:443 {a}\nudp://vpn:443 {b}\n";
        bool Reject(Action action) { try { action(); return false; } catch (SecurityException) { return true; } }
        check("identity: TCP and UDP use different pins on one port",
            ServerIdentityPolicy.CheckKnownHosts(rows, "tcp://vpn:443", a)
            && ServerIdentityPolicy.CheckKnownHosts(rows, "udp://vpn:443", b));
        check("identity: existing qualified mismatch never falls back to legacy",
            Reject(() => ServerIdentityPolicy.CheckKnownHosts(rows, "tcp://vpn:443", b)));
        check("identity: matching legacy is copied, not forgotten",
            !ServerIdentityPolicy.CheckKnownHosts($"vpn:443 {a}\n", "tcp://vpn:443", a));
        check("identity: mismatching and malformed legacy fail closed",
            Reject(() => ServerIdentityPolicy.CheckKnownHosts($"vpn:443 {b}\n", "tcp://vpn:443", a))
            && Reject(() => ServerIdentityPolicy.CheckKnownHosts("vpn:443", "tcp://vpn:443", a)));
        check("identity: another protocol is a separate first-use decision",
            !ServerIdentityPolicy.CheckKnownHosts($"udp://vpn:443 {b}\n", "tcp://vpn:443", a));
        check("identity: conflicting duplicate pins are all checked",
            Reject(() => ServerIdentityPolicy.CheckKnownHosts(rows + $"tcp://vpn:443 {b}\n", "tcp://vpn:443", a)));
        check("identity: IPv6 is bracketed and legacy names are retained",
            ServerIdentityPolicy.EndpointId("udp", "2001:db8::1", 443) == "udp://[2001:db8::1]:443"
            && ServerIdentityPolicy.LegacyId("udp://[2001:db8::1]:443") == "2001:db8::1:443");
        check("identity: old native events are scoped from the active profile",
            ServerIdentityPolicy.StorageId("vpn:443", "tcp", "vpn", 443) == "tcp://vpn:443");
        check("identity: foreign endpoint/transport events are rejected",
            Reject(() => ServerIdentityPolicy.StorageId("udp://vpn:443", "tcp", "vpn", 443))
            && Reject(() => ServerIdentityPolicy.StorageId("tcp://other:443", "tcp", "vpn", 443)));
        check("identity: native key mismatches remain security failures, not reconnect errors",
            ServerIdentityPolicy.IsKeyMismatch("REALITY authentication failed: SERVER KEY MISMATCH")
            && !ServerIdentityPolicy.IsKeyMismatch("transport disconnected"));
    }
}
