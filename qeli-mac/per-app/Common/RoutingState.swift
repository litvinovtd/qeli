import Darwin
import Foundation
import Network
import NetworkExtension

let qeliAppGroup = "group.ru.qeli.app"
let qeliStateFile = "per-app-state.json"

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
    var allowIpv6Leak: Bool
    var routeLocalNetworks: Bool
    var includeRoutes: [String]
    var excludeRoutes: [String]
    var pushedRoutes: [String]
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
            && allowIpv6Leak == other.allowIpv6Leak
            && routeLocalNetworks == other.routeLocalNetworks
            && includeRoutes == other.includeRoutes
            && excludeRoutes == other.excludeRoutes
            && pushedRoutes == other.pushedRoutes
            && alwaysBypassApps == other.alwaysBypassApps
    }

    func selects(_ signingIdentifier: String?) -> Bool {
        let identifier = signingIdentifier ?? ""
        if alwaysBypassApps.contains(identifier) { return false }
        let listed = apps.contains(identifier)
        return mode == "include" ? listed : !listed
    }

    /// Mirrors WinDivertDestinationPolicy. Local/link-local destinations bypass; RFC1918
    /// bypasses unless explicitly requested; exclusions win over includes/pushes.
    func destinationDecision(_ host: String) -> DestinationDecision {
        guard let address = IPAddress(host) else { return .tunnel }
        if excludeRoutes.compactMap(CIDR.init).contains(where: { $0.contains(address) }) {
            return .bypass
        }
        if address.isIPv6 {
            if address.isIPv6LoopbackOrLinkLocal { return .bypass }
            return allowIpv6Leak ? .bypass : .drop
        }
        if address.isIPv4LoopbackOrLinkLocal { return .bypass }
        if address.isRFC1918 {
            let explicit = routeLocalNetworks
                || (includeRoutes + pushedRoutes).compactMap(CIDR.init)
                    .contains(where: { $0.contains(address) })
            return explicit ? .tunnel : .bypass
        }
        return .tunnel
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

    static func load() throws -> RoutingState {
        try JSONDecoder().decode(RoutingState.self, from: Data(contentsOf: try url()))
    }

    static func save(_ state: RoutingState) throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: url(), options: .atomic)
    }

    enum StateError: LocalizedError {
        case appGroupUnavailable
        var errorDescription: String? { "Qeli application group is unavailable" }
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
