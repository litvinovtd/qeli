import Foundation

final class SettingsStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let key = "app.settings.v1"

    init(suiteName: String? = AppConstants.appGroupIdentifier) {
        defaults = suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }

    func load() -> AppSettings {
        guard let data = defaults.data(forKey: key),
              let value = try? JSONDecoder().decode(AppSettings.self, from: data) else {
            return AppSettings()
        }
        return value
    }

    func save(_ value: AppSettings) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        defaults.set(data, forKey: key)
    }
}

