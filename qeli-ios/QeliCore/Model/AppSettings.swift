import Foundation

/// UI language. Deliberately explicit rather than "follow the device": the Android client
/// forces English until the user picks otherwise, and a mirror has to behave the same way
/// (a Russian phone must not silently open in Russian). `.en` is the default.
enum AppLanguage: String, Codable, CaseIterable, Identifiable, Sendable {
    case en
    case ru

    var id: String { rawValue }

    /// Endonym — a language is always listed in its own language, never translated.
    var displayName: String {
        switch self {
        case .en: return "English"
        case .ru: return "Русский"
        }
    }

    var locale: Locale { Locale(identifier: rawValue) }
}

enum LogTimeFormat: String, Codable, CaseIterable, Identifiable, Sendable {
    case time
    case datetime
    case rfc3339
    case epoch
    case none

    var id: String { rawValue }

    /// Localization KEY, not display text — QeliCore stays SwiftUI-free, so the view wraps
    /// this in `LocalizedStringKey`. Passing it to `Text` as a plain String would render it
    /// verbatim in English (the bug this replaced).
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

enum ClientLogLevel: String, Codable, CaseIterable, Identifiable, Sendable {
    case info
    case debug

    var id: String { rawValue }
    var title: String {
        switch self {
        case .info: return "Compact"
        case .debug: return "Detailed diagnostics"
        }
    }
}

enum AppAppearance: String, Codable, CaseIterable, Identifiable, Sendable {
    case system
    case light
    case dark

    var id: String { rawValue }

    /// Localization key (see `LogTimeFormat.title`). Spelled out rather than
    /// `rawValue.capitalized` so the key is greppable and locale-independent.
    var title: String {
        switch self {
        case .system: return "System"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

struct AppSettings: Codable, Equatable, Sendable {
    var autoConnectOnLaunch = false
    var onDemandEnabled = false
    var allowLAN = false
    var checkForUpdates = false
    var logTimeFormat: LogTimeFormat = .time
    var logLevel: ClientLogLevel = .info
    var appearance: AppAppearance = .system
    var language: AppLanguage = .en

    init() {}

    /// Decode field by field, falling back to the default for anything absent.
    ///
    /// Swift's synthesized decoder does NOT apply property defaults for missing keys — it
    /// throws `keyNotFound`. `SettingsStore.load()` answers a decode failure by returning a
    /// fresh `AppSettings()`, so adding one property (as `language` did) would have wiped
    /// every stored preference on upgrade. Writing this out keeps old payloads loadable and
    /// makes the next added field harmless too.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let fallback = AppSettings()
        autoConnectOnLaunch = try container.decodeIfPresent(Bool.self, forKey: .autoConnectOnLaunch)
            ?? fallback.autoConnectOnLaunch
        onDemandEnabled = try container.decodeIfPresent(Bool.self, forKey: .onDemandEnabled)
            ?? fallback.onDemandEnabled
        allowLAN = try container.decodeIfPresent(Bool.self, forKey: .allowLAN) ?? fallback.allowLAN
        checkForUpdates = try container.decodeIfPresent(Bool.self, forKey: .checkForUpdates)
            ?? fallback.checkForUpdates
        logTimeFormat = try container.decodeIfPresent(LogTimeFormat.self, forKey: .logTimeFormat)
            ?? fallback.logTimeFormat
        logLevel = try container.decodeIfPresent(ClientLogLevel.self, forKey: .logLevel)
            ?? fallback.logLevel
        appearance = try container.decodeIfPresent(AppAppearance.self, forKey: .appearance)
            ?? fallback.appearance
        language = try container.decodeIfPresent(AppLanguage.self, forKey: .language) ?? fallback.language
    }
}
