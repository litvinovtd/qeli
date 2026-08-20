import Foundation

enum TunnelPhase: String, Codable, Sendable {
    case disconnected
    case preparing
    case connecting
    case connected
    case reconnecting
    case waiting
    case disconnecting
    case error

    var isActive: Bool {
        switch self {
        case .preparing, .connecting, .connected, .reconnecting, .waiting, .disconnecting: return true
        case .disconnected, .error: return false
        }
    }
}

/// Persistable, non-secret projection of the immutable config owned by the running tunnel.
/// It lives in this file because the widget compiles `TunnelSnapshot` without `VPNConfig` or
/// `ProtectionSummary`. The app/extension mapping is defined beside those richer models.
enum LiveProtectionScope: String, Codable, Equatable, Sendable {
    case all
    case onlySelected
    case allExcept
    case splitRoutes
}

enum LiveProtectionWarning: String, Codable, Equatable, Sendable {
    case lanOutside
    case ipv4Outside
    case ipv6Outside
    case excludedRoutes
    case noPinnedKey
    case perAppNotApplied
}

struct LiveConnectionProperties: Codable, Equatable, Sendable {
    var serverAddress: String
    var port: Int
    var wireMode: String
    var protocolName: String
    var quicEnabled: Bool
    var configuredMTU: Int
    var reconnectEnabled: Bool
    var scope: LiveProtectionScope
    var appCount: Int
    var excludedRouteCount: Int
    var postQuantum: Bool
    var dnsThroughTunnel: Bool
    var keyPinned: Bool
    var warnings: [LiveProtectionWarning]

    var displayEndpoint: String {
        serverAddress.contains(":") ? "[\(serverAddress)]:\(port)" : "\(serverAddress):\(port)"
    }
}

struct TunnelSnapshot: Codable, Equatable, Sendable {
    var phase: TunnelPhase = .disconnected
    var message = ""
    var error: String?
    var clientAddress: String?
    /// Exact authenticated in-tunnel server endpoint. Optional keeps snapshots written by
    /// older app/extension builds decodable during an upgrade.
    var tunnelGateway: String?
    var connectedAt: Date?
    var bytesUploaded: UInt64 = 0
    var bytesDownloaded: UInt64 = 0
    var uploadBytesPerSecond: UInt64 = 0
    var downloadBytesPerSecond: UInt64 = 0
    var profileID: UUID?
    var updatedAt = Date()

    /// Privacy property of the immutable config actually loaded by PacketTunnel. Optional
    /// keeps snapshots written by older extension builds decodable during an app upgrade.
    var privateUpdatePath: Bool?

    /// Display-safe properties of the config actually loaded by PacketTunnel. Optional so
    /// snapshots written by an older app/extension build remain decodable during upgrades.
    var liveConnectionProperties: LiveConnectionProperties?

    // ── negotiated facts the UI cannot derive from the profile ──
    // The protection card states what is actually in force, and these are only known after
    // the handshake: the server pushes DNS/MTU/routes/streams. Carried here rather than
    // scraped out of the log — log lines are the documented error-catalog surface
    // (docs/*/TROUBLESHOOTING.md), not a data channel. Mirrors the Android `live*` snapshot
    // fields on VpnServiceImpl.

    /// Resolver the server pushed; nil when it pushed none.
    var pushedDNS: String?

    /// MTU actually applied to the tunnel (explicit profile value or the pushed one).
    var appliedMTU: Int?

    /// Bonded streams the server allowed; 1 means single-stream.
    var maxStreams: Int = 1

    /// Routes the server pushed and this client applied.
    var pushedRoutes: Int = 0

    /// The rest of the push (capped route sample, multipath mode, the obfuscation knobs the
    /// server owns). OPTIONAL on purpose: Swift's synthesized decoder throws on a missing key
    /// rather than using a default, so a non-optional field would make every snapshot written
    /// by an older build fail to decode. Optional decodes to nil instead.
    var pushed: PushedFacts?

    var uptime: TimeInterval {
        connectedAt.map { max(0, Date().timeIntervalSince($0)) } ?? 0
    }
}

struct TunnelLogLine: Codable, Equatable, Identifiable, Sendable {
    var id = UUID()
    var date = Date()
    var message: String
}
