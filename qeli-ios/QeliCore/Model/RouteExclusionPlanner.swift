import Darwin
import Foundation

/// Pure, family-neutral CIDR subtraction used by NetworkExtension route planning.
///
/// Installing a narrow included route beside a broad exclusion does not carve the include out:
/// normal longest-prefix routing makes the narrow route win. Representing `include - exclude`
/// as exact CIDR fragments is therefore required for both IPv4 and IPv6.
enum RouteExclusionPlanner {
    static let maximumRoutes = 256
    static let lanBypassExcludes = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "224.0.0.0/24", "239.255.255.250/32",
        "fc00::/7", "fe80::/10", "ff00::/8"
    ]

    /// `allow_lan` is a carve-out from a full tunnel. In split mode there is no default
    /// capture to carve, and treating this convenience switch as a general exclusion would
    /// silently subtract authenticated server-pushed private routes.
    static func effectiveExcludes(
        configured: [String],
        fullTunnel: Bool,
        allowLAN: Bool
    ) -> [String] {
        configured + (fullTunnel && allowLAN ? lanBypassExcludes : [])
    }

    private struct Prefix: Equatable {
        var bytes: [UInt8]
        let length: Int

        var bitCount: Int { bytes.count * 8 }

        func overlaps(_ other: Prefix) -> Bool {
            guard bytes.count == other.bytes.count else { return false }
            return Self.prefixMatches(bytes, other.bytes, bits: min(length, other.length))
        }

        func children() -> (Prefix, Prefix)? {
            guard length < bitCount else { return nil }
            let nextLength = length + 1
            var second = bytes
            let byteIndex = length / 8
            let bitIndex = 7 - (length % 8)
            second[byteIndex] |= UInt8(1 << bitIndex)
            return (
                Prefix(bytes: bytes, length: nextLength),
                Prefix(bytes: second, length: nextLength)
            )
        }

        func rendered() -> String? {
            let family = bytes.count == 4 ? AF_INET : AF_INET6
            var output = [CChar](
                repeating: 0,
                count: family == AF_INET ? Int(INET_ADDRSTRLEN) : Int(INET6_ADDRSTRLEN)
            )
            let result = bytes.withUnsafeBytes { storage in
                inet_ntop(family, storage.baseAddress, &output, socklen_t(output.count))
            }
            guard result != nil else { return nil }
            return "\(String(cString: output))/\(length)"
        }

        private static func prefixMatches(
            _ lhs: [UInt8],
            _ rhs: [UInt8],
            bits: Int
        ) -> Bool {
            let wholeBytes = bits / 8
            if wholeBytes > 0 && lhs[..<wholeBytes] != rhs[..<wholeBytes] { return false }
            let remaining = bits % 8
            guard remaining > 0 else { return true }
            let mask = UInt8((0xff << (8 - remaining)) & 0xff)
            return lhs[wholeBytes] & mask == rhs[wholeBytes] & mask
        }
    }

    /// Exact part of `cidr` not covered by same-family exclusions. `nil` means malformed input
    /// or an expansion beyond the bounded NetworkPlan route contract; results are never cut off.
    static func subtract(_ cidr: String, excludes: [String]) -> [String]? {
        guard let base = parse(cidr) else { return nil }
        var fragments = [base]
        for excludedText in excludes {
            guard let excluded = parse(excludedText) else { return nil }
            guard excluded.bytes.count == base.bytes.count else { continue }
            var next: [Prefix] = []
            for fragment in fragments {
                guard subtract(fragment, excluded: excluded, output: &next) else { return nil }
            }
            fragments = next
            if fragments.isEmpty { break }
        }
        if fragments == [base] { return [cidr] }
        var rendered: [String] = []
        rendered.reserveCapacity(fragments.count)
        for fragment in fragments {
            guard let route = fragment.rendered() else { return nil }
            rendered.append(route)
        }
        return rendered
    }

    /// Whether an exclusion can beat or tie the route that keeps the negotiated gateway
    /// on-link. Opposite families are harmless; `nil` means malformed input.
    static func overridesOnLinkGateway(
        _ cidr: String,
        gateway: String,
        onLinkPrefixLength: Int
    ) -> Bool? {
        guard let excluded = parse(cidr) else { return nil }
        let hostLength = gateway.contains(":") ? 128 : 32
        guard let host = parse("\(gateway)/\(hostLength)"),
              (0...hostLength).contains(onLinkPrefixLength) else { return nil }
        guard excluded.bytes.count == host.bytes.count else { return false }
        guard excluded.length >= onLinkPrefixLength else { return false }
        return excluded.overlaps(host)
    }

    private static func subtract(
        _ base: Prefix,
        excluded: Prefix,
        output: inout [Prefix]
    ) -> Bool {
        if !base.overlaps(excluded) {
            output.append(base)
        } else if excluded.length <= base.length {
            // For overlapping CIDRs the broader/equal prefix covers this complete fragment.
        } else if let (first, second) = base.children() {
            guard subtract(first, excluded: excluded, output: &output),
                  subtract(second, excluded: excluded, output: &output) else { return false }
        }
        return output.count <= maximumRoutes
    }

    private static func parse(_ cidr: String) -> Prefix? {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]) else { return nil }
        let address = String(parts[0])
        let family = address.contains(":") ? AF_INET6 : AF_INET
        let byteCount = family == AF_INET ? 4 : 16
        guard (0...(byteCount * 8)).contains(length) else { return nil }
        var bytes = [UInt8](repeating: 0, count: byteCount)
        let parsed = address.withCString { source in
            bytes.withUnsafeMutableBytes { storage in
                inet_pton(family, source, storage.baseAddress)
            }
        }
        guard parsed == 1 else { return nil }
        let wholeBytes = length / 8
        let remaining = length % 8
        if remaining > 0 {
            bytes[wholeBytes] &= UInt8((0xff << (8 - remaining)) & 0xff)
        }
        let zeroFrom = wholeBytes + (remaining == 0 ? 0 : 1)
        if zeroFrom < bytes.count {
            for index in zeroFrom..<bytes.count { bytes[index] = 0 }
        }
        return Prefix(bytes: bytes, length: length)
    }
}
