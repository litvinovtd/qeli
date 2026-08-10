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
               routeLocal: Bool = false, allowIPv6: Bool = false,
               include: [String] = [], exclude: [String] = [], pushed: [String] = [])
    -> RoutingState {
    RoutingState(version: 1, tunnelUp: true, interfaceName: "utun7", mode: mode,
                 apps: apps, dnsServers: ["10.8.0.1"], carrierAddress: "203.0.113.7",
                 carrierPort: 443, carrierProtocol: "tcp", allowIpv6Leak: allowIPv6,
                 routeLocalNetworks: routeLocal, includeRoutes: include,
                 excludeRoutes: exclude, pushedRoutes: pushed,
                 alwaysBypassApps: ["ru.qeli.app", "ru.qeli.app.perapp"])
}

print("qeli macOS per-app policy self-test")
let include = makeState()
expect(include.selects("com.apple.Safari"), "include selects listed signing identifier")
expect(!include.selects("org.mozilla.firefox"), "include bypasses unlisted signing identifier")
expect(!include.selects(nil), "include fails closed for missing identity")
expect(!include.selects("ru.qeli.app.perapp"), "provider always bypasses itself")

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
expect(isDrop(include.destinationDecision("2001:4860:4860::8888")), "IPv6 fails closed by default")
expect(isBypass(makeState(allowIPv6: true).destinationDecision("2001:4860:4860::8888")),
       "allow_ipv6_leak bypasses public IPv6")
expect(isBypass(makeState(exclude: ["2001:db8:1::/48"])
    .destinationDecision("2001:db8:1::42")), "explicit IPv6 exclude bypasses")

if failures > 0 { exit(1) }
print("ALL PASS")
