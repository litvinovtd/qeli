import Foundation

enum TunnelPhase: String, Codable, Sendable {
    case disconnected
    case preparing
    case connecting
    case connected
    case reconnecting
    case disconnecting
    case error

    var isActive: Bool {
        switch self {
        case .preparing, .connecting, .connected, .reconnecting, .disconnecting: return true
        case .disconnected, .error: return false
        }
    }
}

struct TunnelSnapshot: Codable, Equatable, Sendable {
    var phase: TunnelPhase = .disconnected
    var message = ""
    var error: String?
    var clientAddress: String?
    var connectedAt: Date?
    var bytesUploaded: UInt64 = 0
    var bytesDownloaded: UInt64 = 0
    var uploadBytesPerSecond: UInt64 = 0
    var downloadBytesPerSecond: UInt64 = 0
    var profileID: UUID?
    var updatedAt = Date()

    var uptime: TimeInterval {
        connectedAt.map { max(0, Date().timeIntervalSince($0)) } ?? 0
    }
}

struct TunnelLogLine: Codable, Equatable, Identifiable, Sendable {
    var id = UUID()
    var date = Date()
    var message: String
}

