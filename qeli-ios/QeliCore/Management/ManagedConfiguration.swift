import Foundation

/// Typed, side-effect-free view of legacy MDM managed app configuration.
/// Applying these values remains an explicit policy decision in the app.
struct QeliManagedConfiguration: Equatable, Sendable {
    var isManaged = false
    var configurationVersion: Int?
    var activeProfileID: UUID?
    /// Distinguishes an omitted optional policy from a malformed UUID. When the
    /// key is present the app must not silently fall back to a local profile.
    var hasActiveProfilePolicy = false
    var onDemandEnabled: Bool?
    var widgetControlsEnabled: Bool?
}

struct ManagedConfigurationReader {
    static let managedDefaultsKey = "com.apple.configuration.managed"

    enum Key {
        static let configurationVersion = "configurationVersion"
        static let activeProfileID = "activeProfileID"
        static let onDemandEnabled = "onDemandEnabled"
        static let widgetControlsEnabled = "widgetControlsEnabled"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func load() -> QeliManagedConfiguration {
        Self.parse(defaults.dictionary(forKey: Self.managedDefaultsKey))
    }

    static func parse(_ dictionary: [String: Any]?) -> QeliManagedConfiguration {
        guard let dictionary else { return QeliManagedConfiguration() }
        let profileID = (dictionary[Key.activeProfileID] as? String)
            .flatMap(UUID.init(uuidString:))
        return QeliManagedConfiguration(
            isManaged: true,
            configurationVersion: integer(dictionary[Key.configurationVersion]),
            activeProfileID: profileID,
            hasActiveProfilePolicy: dictionary.keys.contains(Key.activeProfileID),
            onDemandEnabled: boolean(dictionary[Key.onDemandEnabled]),
            widgetControlsEnabled: boolean(dictionary[Key.widgetControlsEnabled])
        )
    }

    private static func boolean(_ value: Any?) -> Bool? {
        if let value = value as? Bool { return value }
        guard let number = value as? NSNumber else { return nil }
        return number.intValue == 0 ? false : number.intValue == 1 ? true : nil
    }

    private static func integer(_ value: Any?) -> Int? {
        if let value = value as? Int { return value }
        return (value as? NSNumber)?.intValue
    }
}
