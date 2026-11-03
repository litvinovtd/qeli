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
               tunnelSubnets: [String] = ["10.8.0.2/24", "fd71:e1:42::2/64"],
               physicalLocal: [String] = ["192.168.1.0/24"])
    -> RoutingState {
    RoutingState(ownerToken: String(repeating: "a", count: 32), ownerPid: getpid(), ownerReleased: false,
                 version: qeliRoutingStateVersion, tunnelUp: true,
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
                 physicalLocalRoutes: physicalLocal,
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
    { (state: inout RoutingState) in state.fullTunnel.toggle() },
    { (state: inout RoutingState) in state.physicalLocalRoutes.append("10.44.0.0/16") }
] {
    var changed = include
    mutation(&changed)
    expect(!include.policyEquivalent(to: changed), "traffic-policy mutation retires live relays")
}

// Source cases: require macOS/Xcode; Windows managed fixtures do not execute Swift.
expect(RoutingStateStore.sameOwner(include, token: String(repeating: "a", count: 32), pid: getpid()),
       "exact owner generation matches")
expect(!RoutingStateStore.sameOwner(include, token: String(repeating: "b", count: 32), pid: getpid()),
       "different token at same PID is a different owner")
expect(!RoutingStateStore.sameOwner(include, token: String(repeating: "a", count: 32), pid: getpid() + 1),
       "same token at another PID is a different owner")
var retiredOwner = include
retiredOwner.ownerReleased = true
retiredOwner.tunnelUp = false
retiredOwner.leaseExpiresAtUnixMs = 0
expect(!retiredOwner.leaseIsValid(), "completed owner never renews traffic allowance")
expect(!include.policyEquivalent(to: retiredOwner), "owner retirement retires existing relays")
var newOwner = include
newOwner.ownerToken = String(repeating: "b", count: 32)
expect(!include.policyEquivalent(to: newOwner), "new owner retires otherwise identical relays")
var badOwner = include
badOwner.ownerToken = nil
expect((try? RoutingStateStore.validate(badOwner)) == nil, "missing token is rejected")
badOwner.ownerToken = String(repeating: "A", count: 32)
expect((try? RoutingStateStore.validate(badOwner)) == nil, "noncanonical token is rejected")
badOwner = include
badOwner.ownerPid = 1
expect((try? RoutingStateStore.validate(badOwner)) == nil, "invalid parent PID is rejected")
badOwner = include
badOwner.ownerReleased = nil
expect((try? RoutingStateStore.validate(badOwner)) == nil, "unknown release progress is rejected")

let exclude = makeState(mode: "exclude")
expect(!exclude.selects("com.apple.Safari"), "exclude bypasses listed signing identifier")
expect(exclude.selects("org.mozilla.firefox"), "exclude tunnels unlisted signing identifier")
expect(exclude.selects(nil), "exclude tunnels unknown identity")

expect(isTunnel(include.destinationDecision("1.1.1.1")), "public IPv4 tunnels")
expect(isBypass(include.destinationDecision("192.168.1.1")),
       "physically connected RFC1918 bypasses when route_local is off")
expect(isTunnel(include.destinationDecision("192.168.50.1")),
       "remote RFC1918 follows full-tunnel policy")
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
expect(isTunnel(makeState().destinationDecision("fd00::1")), "ULA follows full-tunnel policy")
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
expect(isBypass(makeState(routeLocal: true, tunnelIPv6: false, allowIPv6: true,
                          fullTunnel: false).destinationDecision("fd00::1")),
       "route_local does not change split-tunnel IPv6 policy")

for malformed in ["", "/", "/24", "10.1.2.3/", "10.1.2.3//24"] {
    expect(isTunnel(makeState(exclude: [malformed]).destinationDecision("10.1.2.3")),
           "malformed CIDR never crashes or invents bypass: \(malformed)")
}

final class FixtureRelay: RelayClosable {
    var stops = 0
    func stop(_ error: Error?) { stops += 1 }
}
let registry = RelayRegistry()
let retiredEpoch = registry.generation
let firstRelay = FixtureRelay()
expect(registry.add(firstRelay, id: UUID(), generation: retiredEpoch),
       "current policy accepts relay registration")
registry.closeAll()
expect(firstRelay.stops == 1, "policy retirement closes registered relay")
let lateRelay = FixtureRelay()
expect(!registry.add(lateRelay, id: UUID(), generation: retiredEpoch),
       "delayed old-policy relay cannot register after retirement")
let nextRelay = FixtureRelay()
expect(registry.add(nextRelay, id: UUID(), generation: registry.generation),
       "new policy accepts its own relay")
registry.closeAll(); registry.closeAll()
expect(firstRelay.stops == 1 && nextRelay.stops == 1,
       "repeat retirement never closes a released relay twice")

// Production latch/deadline cases. Require Swift/Xcode; not Windows runtime PASS.
let lifetime = RelayLifetime()
var publications = 0
expect((try? lifetime.publish { publications += 1; return true }) == true,
       "live relay can publish one owned descriptor")
expect(lifetime.stop(), "first stop retires the relay")
expect(!lifetime.stop(), "repeat stop is idempotent")
expect((try? lifetime.publish { publications += 1 }) == nil && publications == 1,
       "retired relay cannot publish another descriptor")
expect((try? lifetime.check()) == nil, "retired relay refuses queued I/O")
let deadline = RelayDeadline(milliseconds: 500, now: 1_000_000)
expect(deadline.waitSlice(now: 1_000_000) == 100, "poll slice caps cancellation latency")
expect(deadline.waitSlice(now: 500_500_000) == 1, "last partial millisecond remains pollable")
expect(deadline.waitSlice(now: 501_000_000) == 0, "expired deadline cannot extend a retry")
expect((try? deadline.check(now: 501_000_000)) == nil, "deadline expiry refuses work")
expect(deadline.capped(milliseconds: 2000, now: 1_000_000).expiry == deadline.expiry,
       "DNS sub-budget cannot extend the connect budget")
expect(deadline.capped(milliseconds: 100, now: 1_000_000).expiry == 101_000_000,
       "shorter DNS budget is honored")

let writes = RelayLifetime()
let writeTicket = writes.beginWrite(now: 0)!
expect(writes.expiredWrite(now: 9_999_999_999) == nil, "watchdog does not expire a progressing write early")
expect(writes.expiredWrite(now: 10_000_000_000) == writeTicket, "one watchdog sees the current expired write")
expect(!writes.stop(writeTicket: writeTicket + 1), "unrelated write timer cannot retire the relay")
expect(writes.completeWrite(writeTicket), "matching write completion clears its timeout")
expect(!writes.stop(writeTicket: writeTicket), "completed write timer cannot close an active relay")
let nextWrite = writes.beginWrite()!
expect(nextWrite != writeTicket, "next framework write has a distinct timeout ticket")
expect(writes.stop(writeTicket: nextWrite), "pending framework write timeout retires the relay")
expect(!writes.completeWrite(nextWrite), "late completion cannot resume a retired source")
expect(writes.beginWrite() == nil, "retired relay cannot admit another framework write")

// Production directional EOF state; native execution remains a Mac requirement.
var appFirst = RelayDuplex()
expect(!appFirst.finished, "new TCP flow has two active directions")
expect(appFirst.end(.outbound) && !appFirst.finished && !appFirst.inboundEnded,
       "app FIN preserves server response direction")
expect(!appFirst.end(.outbound) && !appFirst.finished, "duplicate app FIN is idempotent")
expect(appFirst.end(.inbound) && appFirst.finished, "server FIN after response completes TCP flow")
var serverFirst = RelayDuplex()
expect(serverFirst.end(.inbound) && !serverFirst.finished && !serverFirst.outboundEnded,
       "server FIN preserves app outbound direction")
expect(!serverFirst.end(.inbound) && !serverFirst.finished, "duplicate server FIN is idempotent")
expect(serverFirst.end(.outbound) && serverFirst.finished, "app FIN completes server-first flow")
expect(!serverFirst.end(.outbound) && serverFirst.finished, "terminal EOF state remains stable")

if failures > 0 { exit(1) }
print("ALL PASS")
