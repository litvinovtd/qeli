import Darwin
import Foundation

private var failures = 0

private func expect(_ condition: @autoclosure () -> Bool, _ name: String) {
    if condition() { print("  [PASS] \(name)") }
    else { failures += 1; print("  [FAIL] \(name)") }
}

private func isTunnel(_ decision: DestinationDecision) -> Bool {
    if case .tunnel = decision { return true }
    return false
}

private func isBypass(_ decision: DestinationDecision) -> Bool {
    if case .bypass = decision { return true }
    return false
}

private func isDrop(_ decision: DestinationDecision) -> Bool {
    if case .drop = decision { return true }
    return false
}

func makeState(mode: String = "include", apps: [String] = ["com.apple.Safari"],
               routeLocal: Bool = false, tunnelIPv4: Bool = true, tunnelIPv6: Bool = true,
               allowIPv4: Bool = false, allowIPv6: Bool = false,
               fullTunnel: Bool = true,
               include: [String] = [], exclude: [String] = [], pushed: [String] = [],
               tunnelSubnets: [String] = ["10.8.0.2/24", "fd71:e1:42::2/64"])
    -> RoutingState {
    RoutingState(version: qeliRoutingStateVersion, tunnelUp: true,
                 leaseExpiresAtUnixMs: Int64(Date().timeIntervalSince1970 * 1000) + 10_000,
                 interfaceName: "utun7", mode: mode,
                 apps: apps, dnsServers: ["10.8.0.1"], carrierAddress: "203.0.113.7",
                 carrierPort: 443, carrierProtocol: "tcp",
                 tunnelIpv4: tunnelIPv4, tunnelIpv6: tunnelIPv6,
                 allowIpv4Leak: allowIPv4, allowIpv6Leak: allowIPv6,
                 fullTunnel: fullTunnel,
                 routeLocalNetworks: routeLocal, includeRoutes: include,
                 excludeRoutes: exclude, pushedRoutes: pushed,
                 tunnelSubnets: tunnelSubnets,
                 alwaysBypassApps: ["ru.qeli.app", "ru.qeli.app.perapp"])
}

print("qeli macOS per-app policy self-test")
let include = makeState()
expect((try? RoutingStateStore.validate(include)) != nil, "current state schema is accepted")
var futureSchema = include
futureSchema.version = qeliRoutingStateVersion + 1
expect((try? RoutingStateStore.validate(futureSchema)) == nil,
       "unknown future state schema is rejected")
expect(include.selects("com.apple.Safari"), "include selects listed signing identifier")
expect(!include.selects("org.mozilla.firefox"), "include bypasses unlisted signing identifier")
expect(!include.selects(nil), "include fails closed for missing identity")
expect(!include.selects("ru.qeli.app.perapp"), "provider always bypasses itself")
expect(include.leaseIsValid(), "fresh owner lease is valid")
var expired = include
expired.leaseExpiresAtUnixMs = 0
expect(!expired.leaseIsValid(), "expired owner lease fails open")
expect(include.policyEquivalent(to: expired), "lease heartbeat does not change routing policy")
for mutation in [
    { (state: inout RoutingState) in state.tunnelIpv4.toggle() },
    { (state: inout RoutingState) in state.tunnelIpv6.toggle() },
    { (state: inout RoutingState) in state.allowIpv4Leak.toggle() },
    { (state: inout RoutingState) in state.allowIpv6Leak.toggle() },
    { (state: inout RoutingState) in state.fullTunnel.toggle() }
] {
    var changed = include
    mutation(&changed)
    expect(!include.policyEquivalent(to: changed), "traffic-policy mutation retires live relays")
}

let exclude = makeState(mode: "exclude")
expect(!exclude.selects("com.apple.Safari"), "exclude bypasses listed signing identifier")
expect(exclude.selects("org.mozilla.firefox"), "exclude tunnels unlisted signing identifier")
expect(exclude.selects(nil), "exclude tunnels unknown identity")

expect(isTunnel(include.destinationDecision("1.1.1.1")), "public IPv4 tunnels")
expect(isBypass(include.destinationDecision("192.168.1.1")), "RFC1918 bypasses by default")
expect(isTunnel(makeState(routeLocal: true).destinationDecision("192.168.1.1")),
       "route_local tunnels RFC1918")
expect(isTunnel(makeState(include: ["10.20.0.0/16"]).destinationDecision("10.20.1.2")),
       "explicit include tunnels matching private CIDR")
expect(isTunnel(makeState(pushed: ["172.20.0.0/16"]).destinationDecision("172.20.2.3")),
       "server-pushed private CIDR tunnels")
expect(isBypass(makeState(routeLocal: true, exclude: ["10.1.0.0/16"])
    .destinationDecision("10.1.2.3")), "exclude wins over route_local")
expect(isBypass(include.destinationDecision("127.0.0.1")), "IPv4 loopback bypasses")
expect(isBypass(include.destinationDecision("fe80::1")), "IPv6 link-local bypasses")
expect(isTunnel(include.destinationDecision("2001:4860:4860::8888")), "public IPv6 tunnels")
expect(isDrop(makeState(tunnelIPv6: false).destinationDecision("2001:4860:4860::8888")),
       "inactive IPv6 fails closed by default")
expect(isBypass(makeState(tunnelIPv6: false, allowIPv6: true)
    .destinationDecision("2001:4860:4860::8888")),
       "allow_ipv6_leak bypasses public IPv6")
expect(isDrop(makeState(tunnelIPv4: false).destinationDecision("1.1.1.1")),
       "inactive IPv4 fails closed by default")
expect(isBypass(makeState(tunnelIPv4: false, allowIPv4: true).destinationDecision("1.1.1.1")),
       "allow_ipv4_leak bypasses public IPv4")
expect(isBypass(makeState().destinationDecision("fd00::1")), "ULA bypasses by default")
expect(isTunnel(makeState(include: ["fd00::/8"]).destinationDecision("fd00::1")),
       "explicit IPv6 include tunnels ULA")
expect(isBypass(makeState(exclude: ["2001:db8:1::/48"])
    .destinationDecision("2001:db8:1::42")), "explicit IPv6 exclude bypasses")
let split = makeState(fullTunnel: false, include: ["198.51.100.0/24", "2001:db8:20::/48"])
expect(isBypass(split.destinationDecision("1.1.1.1")), "split public IPv4 bypasses")
expect(isTunnel(split.destinationDecision("198.51.100.7")), "split public include tunnels")
expect(isTunnel(split.destinationDecision("10.8.0.1")),
       "split connected IPv4 tunnel subnet remains tunnelled")
expect(isTunnel(split.destinationDecision("fd71:e1:42::1")),
       "split connected IPv6 tunnel subnet remains tunnelled")
expect(isBypass(split.destinationDecision("2001:4860:4860::8888")), "split native IPv6 bypasses")
expect(isTunnel(split.destinationDecision("2001:db8:20::7")),
       "split IPv6 include tunnels when IPv6 is active")
expect(isDrop(makeState(tunnelIPv4: false, allowIPv4: true, fullTunnel: false,
                        include: ["198.51.100.0/24"]).destinationDecision("198.51.100.7")),
       "split IPv4 include fails closed when IPv4 is inactive")
expect(isDrop(makeState(tunnelIPv6: false, allowIPv6: true, fullTunnel: false,
                        include: ["2001:db8:20::/48"]).destinationDecision("2001:db8:20::7")),
       "split IPv6 include fails closed when IPv6 is inactive")
expect(isDrop(makeState(routeLocal: true, tunnelIPv6: false, allowIPv6: true,
                        fullTunnel: false).destinationDecision("fd00::1")),
       "route_local IPv6 fails closed when IPv6 is inactive")

if failures > 0 { exit(1) }
print("ALL PASS")
