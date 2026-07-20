import Foundation

enum LogTimeFormat: String, Codable, CaseIterable, Identifiable, Sendable {
    case time
    case datetime
    case rfc3339
    case epoch
    case none

    var id: String { rawValue }

    var title: String {
        switch self {
        case .time: return "Time only"
        case .datetime: return "Date and time"
        case .rfc3339: return "RFC 3339 (UTC)"
        case .epoch: return "Unix time"
        case .none: return "No timestamp"
        }
    }
}

enum AppAppearance: String, Codable, CaseIterable, Identifiable, Sendable {
    case system
    case light
    case dark

    var id: String { rawValue }
    var title: String { rawValue.capitalized }
}

struct AppSettings: Codable, Equatable, Sendable {
    var autoConnectOnLaunch = false
    var onDemandEnabled = false
    var allowLAN = false
    var checkForUpdates = false
    var logTimeFormat: LogTimeFormat = .time
    var appearance: AppAppearance = .system
}

