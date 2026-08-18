import Foundation

/// Device-local trusted-network policy. SSIDs are deliberately not part of a profile or a
/// qeli:// link: importing somebody else's tunnel must never make their Wi-Fi name trusted.
enum TrustedWiFiPolicy {
    static func normalized<S: Sequence>(_ values: S) -> [String] where S.Element == String {
        var seen = Set<String>()
        return values.compactMap { raw in
            let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, seen.insert(value).inserted else { return nil }
            return value
        }
    }

    static func parse(_ raw: String) -> [String] {
        normalized(raw.components(separatedBy: .newlines))
    }
}
