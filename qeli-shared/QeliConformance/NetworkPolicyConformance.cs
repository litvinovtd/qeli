using System.Net;
using Qeli.Shared.Model;
using Qeli.Shared.Vpn;

namespace Qeli.Shared.Protocol;

/// <summary>
/// Conformance-only probes for the desktop adapter's pure network-policy helpers. The
/// production assembly exposes only the internal helpers used at runtime; fixture setup
/// and assertions stay in this standalone runner.
/// </summary>
internal abstract class NetworkPolicyConformance : VpnTunnelBase
{
    internal static void Run(Action<string, bool> check)
    {
        static Session TestSession(IReadOnlyList<string>? planned = null) =>
            new("10.9.0.2", 24, 1400,
                PlannedDns: planned ?? Array.Empty<string>(),
                PlanIncludesClientRoutes: true,
                NetworkAddresses: new[] {
                    new AssignedAddress("ipv4", "10.9.0.2", 32, 24, "10.9.0.1"),
                },
                PlannedRoutes: Array.Empty<PlannedRoute>(),
                RouteFileRoutes: Array.Empty<string>());

        var unresolved = EffectiveDns(TestSession());
        check("dns-policy: no profile/push DNS invents no public resolver", unresolved.Count == 0);

        check("dns-policy: authenticated server push is used when profile DNS is empty",
            EffectiveDns(TestSession(new[] { "10.9.0.1" }))
                .SequenceEqual(new[] { "10.9.0.1" }));

        check("dns-policy: authenticated native NetworkPlan is authoritative",
            EffectiveDns(TestSession(new[] { "192.0.2.53" }))
                .SequenceEqual(new[] { "192.0.2.53" }));
        check("dns-policy: an explicitly empty native NetworkPlan stays empty",
            EffectiveDns(TestSession(Array.Empty<string>())).Count == 0);

        var carriers = new[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" };
        check("carrier-dns: a reconnect generation rotates every refreshed A record",
            RotateCarrierCandidates(carriers, 1)
                .SequenceEqual(new[] { "192.0.2.11", "192.0.2.12", "192.0.2.10" }));
        check("carrier-dns: generation wrap retains the complete A set",
            RotateCarrierCandidates(carriers, 4)
                .SequenceEqual(new[] { "192.0.2.11", "192.0.2.12", "192.0.2.10" }));
        check("carrier-local: an IPv4 local bind rejects only incompatible AAAA candidates",
            CarrierMatchesLocalFamily(IPAddress.Parse("192.0.2.10"), IPAddress.Parse("192.0.2.50"))
            && !CarrierMatchesLocalFamily(IPAddress.Parse("2001:db8::10"),
                IPAddress.Parse("192.0.2.50")));
        check("carrier-local: no local bind keeps both outer address families",
            CarrierMatchesLocalFamily(IPAddress.Parse("192.0.2.10"), null)
            && CarrierMatchesLocalFamily(IPAddress.Parse("2001:db8::10"), null));

        var dualStack = new Session("10.9.0.27", 24, 1400,
            PlannedDns: Array.Empty<string>(),
            PlanIncludesClientRoutes: true,
            NetworkAddresses: new[] {
                new AssignedAddress("ipv4", "10.9.0.27", 32, 24, "10.9.0.1"),
                new AssignedAddress("ipv6", "fd71:e1:20::beef", 128, 64, "fd71:e1:20::1"),
            },
            PlannedRoutes: Array.Empty<PlannedRoute>(),
            RouteFileRoutes: Array.Empty<string>());
        check("network-plan: host TUN addresses retain canonical connected pool routes",
            ConnectedTunnelPrefixes(dualStack)
                .SequenceEqual(new[] { "10.9.0.0/24", "fd71:e1:20::/64" }));

        var perAppForward = new VpnConfig
        {
            ServerAddress = "vpn.example",
            AppsMode = "include",
            Apps = new List<string> { "example-app" },
            Forward = true,
        };
        bool perAppForwardRejected;
        try { perAppForward.Validate(); perAppForwardRejected = false; }
        catch (ArgumentException) { perAppForwardRejected = true; }
        check("routing-policy: desktop per-app mode rejects inapplicable LAN forwarding",
            perAppForwardRejected);

        static NativePlan ValidNativePlan() => new()
        {
            Generation = 1,
            FamilyMode = "ipv4",
            Addresses = new List<NativeAddress> {
                new() {
                    Family = "ipv4", Address = "10.9.0.27", PrefixLength = 32,
                    OnLinkPrefixLength = 24, Gateway = "10.9.0.1",
                },
            },
            TunnelAddress = "10.9.0.27",
            PrefixLength = 24,
            Mtu = 1400,
            TunnelGateway = "10.9.0.1",
            CarrierAddress = "192.0.2.10",
            Routes = new List<NativeRoute> {
                new() { Cidr = "10.20.0.0/16", Gateway = "10.9.0.1", Metric = 100 },
            },
            DnsServers = new List<NativeDns> {
                new() { Address = "10.9.0.1", Port = 53 },
            },
        };
        static bool NativePlanRejected(NativePlan plan)
        {
            try { ValidateNativePlan(plan); return false; }
            catch (InvalidDataException) { return true; }
        }

        var validNativePlan = ValidNativePlan();
        check("network-plan: managed adapter accepts a canonical IPv4 plan",
            !NativePlanRejected(validNativePlan));

        var invalidPrefixPlan = ValidNativePlan();
        invalidPrefixPlan.Addresses[0].OnLinkPrefixLength = 32;
        invalidPrefixPlan.Addresses[0].PrefixLength = 24;
        invalidPrefixPlan.PrefixLength = 32;
        check("network-plan: managed adapter rejects on-link prefixes narrower than the TUN address",
            NativePlanRejected(invalidPrefixPlan));

        var inactiveDnsPlan = ValidNativePlan();
        inactiveDnsPlan.DnsServers[0].Address = "2001:db8::53";
        check("network-plan: managed adapter rejects DNS from an inactive address family",
            NativePlanRejected(inactiveDnsPlan));

        var inactiveRoutePlan = ValidNativePlan();
        inactiveRoutePlan.Routes[0].Cidr = "2001:db8:20::/48";
        inactiveRoutePlan.Routes[0].Gateway = "2001:db8::1";
        check("network-plan: managed adapter rejects routes from an inactive address family",
            NativePlanRejected(inactiveRoutePlan));

        var movedCarrierPlan = ValidNativePlan();
        movedCarrierPlan.CarrierAddress = "192.0.2.11";
        check("persist-tun: selected carrier address participates in the complete plan fingerprint",
            FingerprintNativePlan(validNativePlan) != FingerprintNativePlan(movedCarrierPlan));

        var diagnosticRoutePlan = ValidNativePlan();
        diagnosticRoutePlan.Routes[0].Gateway = "10.9.0.254";
        diagnosticRoutePlan.Routes[0].Metric = 999;
        check("persist-tun: diagnostic route gateway/metric do not rebuild interface-scoped routes",
            FingerprintNativePlan(validNativePlan) == FingerprintNativePlan(diagnosticRoutePlan));

        var duplicateRoutePlan = ValidNativePlan();
        duplicateRoutePlan.Routes.Add(new NativeRoute {
            Cidr = "10.20.0.0/16", Gateway = "10.9.0.254", Metric = 999,
        });
        check("persist-tun: duplicate interface-scoped routes do not rebuild the native plan",
            FingerprintNativePlan(validNativePlan) == FingerprintNativePlan(duplicateRoutePlan));

        string carrierSetFingerprint = FingerprintNativePlan(validNativePlan,
            new[] { "192.0.2.10", "2001:db8::10" });
        check("persist-tun: carrier DNS ordering does not rebuild an otherwise identical plan",
            carrierSetFingerprint == FingerprintNativePlan(validNativePlan,
                new[] { "2001:db8::10", "192.0.2.10" }));
        check("persist-tun: a changed carrier DNS set rebuilds the native network plan",
            carrierSetFingerprint != FingerprintNativePlan(validNativePlan,
                new[] { "192.0.2.10", "2001:db8::11" }));
    }
}
