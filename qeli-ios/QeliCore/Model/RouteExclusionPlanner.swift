import Foundation

/// Thin adapter to the same bounded CIDR operations used by Rust NetworkPlan.
enum RouteExclusionPlanner {
    static let maximumRoutes = 256
    static var lanBypassExcludes: [String] {
        // This operation contains no user input; failure means a missing/incompatible core.
        get throws { try ConfigCore.policy("effective_excludes",["excludes":[],"full":true,"lan":true])["value"] as! [String] }
    }
    static func effectiveExcludes(configured: [String], fullTunnel: Bool, allowLAN: Bool) throws -> [String] {
        try ConfigCore.policy("effective_excludes",["excludes":configured,"full":fullTunnel,"lan":allowLAN])["value"] as! [String]
    }
    static func subtract(_ cidr: String, excludes: [String]) -> [String]? {
        try? ConfigCore.policy("subtract",["cidr":cidr,"excludes":excludes])["value"] as? [String]
    }
    static func countInstalledOriginals(_ originals: [String], installedFragments: Set<String>, excludes: [String], protectedCidrs: Set<String>) -> Int {
        (try? ConfigCore.policy("installed",["originals":originals,"installed":Array(installedFragments),"excludes":excludes,"protected":Array(protectedCidrs)])["value"] as? Int) ?? 0
    }
    static func overridesOnLinkGateway(_ cidr: String, gateway: String, onLinkPrefixLength: Int) -> Bool? {
        try? ConfigCore.policy("on_link",["cidr":cidr,"gateway":gateway,"prefix":onLinkPrefixLength])["value"] as? Bool
    }
}
