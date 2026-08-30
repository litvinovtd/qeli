import Darwin
import Foundation
import Network
import NetworkExtension

let qeliAppGroup = "group.ru.qeli.app"
let qeliStateFile = "per-app-state.json"
let qeliRoutingStateVersion = 4

struct RoutingState: Codable, Equatable {
    var version: Int
    var tunnelUp: Bool
    /// Renewed by the host-side guardian. Network Extension preferences outlive the app,
    /// so providers must fail open when their owner disappeared instead of indefinitely
    /// binding DNS/flows to a dead utun. Optional keeps stale pre-lease state decodable;
    /// absence is deliberately treated as expired.
    var leaseExpiresAtUnixMs: Int64?
    var interfaceName: String
    var mode: String
    var apps: [String]
    var dnsServers: [String]
    var carrierAddress: String
    var carrierPort: Int
    var carrierProtocol: String
    var tunnelIpv4: Bool
    var tunnelIpv6: Bool
    var allowIpv4Leak: Bool
    var allowIpv6Leak: Bool
    var fullTunnel: Bool
    var routeLocalNetworks: Bool
    var includeRoutes: [String]
    var excludeRoutes: [String]
    var pushedRoutes: [String]
    var tunnelSubnets: [String]
    var physicalLocalRoutes: [String]
    var alwaysBypassApps: [String]

    func leaseIsValid(nowUnixMs: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        guard let expiry = leaseExpiresAtUnixMs else { return false }
        return expiry > nowUnixMs
    }

    /// Heartbeats only change the lease. They must not retire every live relay twice a
    /// second; actual routing-policy or tunnel-generation changes still do.
    func policyEquivalent(to other: RoutingState) -> Bool {
        version == other.version
            && tunnelUp == other.tunnelUp
            && interfaceName == other.interfaceName
            && mode == other.mode
            && apps == other.apps
            && dnsServers == other.dnsServers
            && carrierAddress == other.carrierAddress
            && carrierPort == other.carrierPort
            && carrierProtocol == other.carrierProtocol
            && tunnelIpv4 == other.tunnelIpv4
            && tunnelIpv6 == other.tunnelIpv6
            && allowIpv4Leak == other.allowIpv4Leak
            && allowIpv6Leak == other.allowIpv6Leak
            && fullTunnel == other.fullTunnel
            && routeLocalNetworks == other.routeLocalNetworks
            && includeRoutes == other.includeRoutes
            && excludeRoutes == other.excludeRoutes
            && pushedRoutes == other.pushedRoutes
            && tunnelSubnets == other.tunnelSubnets
            && physicalLocalRoutes == other.physicalLocalRoutes
            && alwaysBypassApps == other.alwaysBypassApps
    }

    func selects(_ signingIdentifier: String?) -> Bool {
        let identifier = signingIdentifier ?? ""
        if alwaysBypassApps.contains(identifier) { return false }
        let listed = apps.contains(identifier)
        return mode == "include" ? listed : !listed
    }

    /// Mirrors WinDivertDestinationPolicy. Explicit exclusions win. route_local applies
    /// only to IPv4 RFC1918; otherwise full/split policy is identical to system-TUN.
    func destinationDecision(_ host: String) -> DestinationDecision {
        guard let address = IPAddress(host) else { return .tunnel }
        if excludeRoutes.compactMap(CIDR.init).contains(where: { $0.contains(address) }) {
            return .bypass
        }
        let explicitlyTunneled = (tunnelSubnets + includeRoutes + pushedRoutes).compactMap(CIDR.init)
            .contains(where: { $0.contains(address) })
        let physicallyConnected = physicalLocalRoutes.compactMap(CIDR.init)
            .contains(where: { $0.contains(address) })
        if address.isIPv6 {
            if address.isIPv6LoopbackOrLinkLocal { return .bypass }
            if explicitlyTunneled { return tunnelIpv6 ? .tunnel : .drop }
            if !fullTunnel { return .bypass }
            if tunnelIpv6 { return .tunnel }
            return allowIpv6Leak ? .bypass : .drop
        }
        if address.isIPv4LoopbackOrLinkLocal { return .bypass }
        if explicitlyTunneled { return tunnelIpv4 ? .tunnel : .drop }
        if address.isRFC1918 && routeLocalNetworks {
            return tunnelIpv4 ? .tunnel : .drop
        }
        if physicallyConnected { return .bypass }
        if !fullTunnel { return .bypass }
        if tunnelIpv4 { return .tunnel }
        return allowIpv4Leak ? .bypass : .drop
    }
}

enum DestinationDecision { case tunnel, bypass, drop }

enum RoutingStateStore {
    static func url() throws -> URL {
        guard let base = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: qeliAppGroup) else {
            throw StateError.appGroupUnavailable
        }
        return base.appendingPathComponent(qeliStateFile)
    }

    static func validate(_ state: RoutingState) throws {
        guard state.version == qeliRoutingStateVersion else {
            throw StateError.unsupportedVersion(state.version)
        }
    }

    static func load() throws -> RoutingState {
        let state = try JSONDecoder().decode(
            RoutingState.self, from: Data(contentsOf: try url()))
        try validate(state)
        return state
    }

    /// Replace the complete policy under the same cross-process lock used by lease
    /// heartbeats and tunnel-down transitions. Atomic file replacement protects readers
    /// from partial JSON, but by itself it does not protect a read/modify/write operation:
    /// a guardian could load the old policy, an update could install a new one, and the
    /// guardian could then atomically replace it with its stale copy. `flock` serializes
    /// every writer while providers continue to read the atomically replaced snapshot.
    static func replace(_ state: RoutingState) throws {
        try withExclusiveLock { try saveUnlocked(state) }
    }

    static func mutate(_ body: (inout RoutingState) -> Void) throws {
        try withExclusiveLock {
            var state = try load()
            body(&state)
            try saveUnlocked(state)
        }
    }

    private static func saveUnlocked(_ state: RoutingState) throws {
        try validate(state)
        let data = try JSONEncoder().encode(state)
        try data.write(to: url(), options: .atomic)
    }

    private static func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
        let lockURL = try url().deletingLastPathComponent()
            .appendingPathComponent("\(qeliStateFile).lock")
        let descriptor = Darwin.open(
            lockURL.path,
            O_CREAT | O_RDWR,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
        )
        guard descriptor >= 0 else { throw posixError() }
        defer { Darwin.close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw posixError() }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try body()
    }

    private static func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    enum StateError: LocalizedError {
        case appGroupUnavailable
        case unsupportedVersion(Int)

        var errorDescription: String? {
            switch self {
            case .appGroupUnavailable:
                return "Qeli application group is unavailable"
            case .unsupportedVersion(let version):
                return "Unsupported Qeli per-app state version \(version)"
            }
        }
    }
}

private struct IPAddress {
    let bytes: [UInt8]
    let isIPv6: Bool

    init?(_ text: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
            isIPv6 = false
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
            isIPv6 = true
            return
        }
        return nil
    }

    var isRFC1918: Bool {
        guard !isIPv6 else { return false }
        return bytes[0] == 10
            || (bytes[0] == 172 && (16...31).contains(bytes[1]))
            || (bytes[0] == 192 && bytes[1] == 168)
    }
    var isIPv4LoopbackOrLinkLocal: Bool {
        !isIPv6 && (bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254))
    }
    var isIPv6LoopbackOrLinkLocal: Bool {
        guard isIPv6 else { return false }
        return (bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1)
            || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
    }
}

private struct CIDR {
    let address: IPAddress
    let prefix: Int

    init?(_ text: String) {
        let fields = text.split(separator: "/", maxSplits: 1).map(String.init)
        guard let ip = IPAddress(fields[0]) else { return nil }
        let maximum = ip.isIPv6 ? 128 : 32
        let parsed = fields.count == 2 ? Int(fields[1]) : maximum
        guard let prefix = parsed, (0...maximum).contains(prefix) else { return nil }
        self.address = ip
        self.prefix = prefix
    }

    func contains(_ candidate: IPAddress) -> Bool {
        guard address.isIPv6 == candidate.isIPv6 else { return false }
        let whole = prefix / 8
        let remainder = prefix % 8
        if whole > 0 && !address.bytes[..<whole].elementsEqual(candidate.bytes[..<whole]) { return false }
        guard remainder > 0 else { return true }
        let mask = UInt8(truncatingIfNeeded: 0xff << (8 - remainder))
        return address.bytes[whole] & mask == candidate.bytes[whole] & mask
    }
}
