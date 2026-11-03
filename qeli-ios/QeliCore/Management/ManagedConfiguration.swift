import CoreFoundation
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
        guard let number = value as? NSNumber else { return nil }
        if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue }
        // Retain legacy numeric 0/1 compatibility without truncating fractions.
        guard let value = integer(number), value == 0 || value == 1 else { return nil }
        return value == 1
    }

    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite else { return nil }
        // Reject nonfinite input before Decimal conversion instead of relying on
        // platform-specific parsing of NSNumber's string representation.
        let decimal = NSDecimalNumber(
            string: number.stringValue,
            locale: Locale(identifier: "en_US_POSIX")
        )
        guard decimal != .notANumber,
              decimal.compare(NSDecimalNumber(value: Int.min)) != .orderedAscending,
              decimal.compare(NSDecimalNumber(value: Int.max)) != .orderedDescending else { return nil }
        let integer = decimal.intValue
        return decimal == NSDecimalNumber(value: integer) ? integer : nil
    }
}
