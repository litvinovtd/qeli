import Foundation

enum AppConstants {
    /// The running app's version, read from the bundle — NOT a literal.
    ///
    /// These were hard-coded and had already drifted: `0.7.12` / `715` while
    /// `project.yml` said `0.7.13` / `716`. `sync_version.py` stamps `MARKETING_VERSION`
    /// and `CURRENT_PROJECT_VERSION` in `project.yml`, and nothing propagated them here,
    /// so every release silently left this file behind. The update check compares the
    /// newest GitHub release against `AppConstants.version`, so a freshly-installed
    /// current build reported an update as available, permanently. Xcode writes the same
    /// two values into Info.plist from those variables, so the bundle is the one source
    /// that cannot drift. (Audit 2026-07-27, M10.)
    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? fallbackVersion
    }

    static var build: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String
            ?? fallbackBuild
    }

    /// Used only when the bundle has no version (unit tests, a stripped host). Keep in
    /// step with `qeli-ios/project.yml` if you touch it, but prefer fixing the bundle.
    private static let fallbackVersion = "0.8.0"
    private static let fallbackBuild = "720"

    static let defaultAppGroup = "group.ru.qeli.app"
    static let defaultTunnelBundleIdentifier = "ru.qeli.app.PacketTunnel"
    static let statusWidgetKind = "ru.qeli.app.status-widget"
    static let connectionControlKind = "ru.qeli.app.connection-control"

    static var appGroupIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "QeliAppGroup") as? String
            ?? defaultAppGroup
    }

    static var keychainAccessGroup: String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "QeliKeychainAccessGroup") as? String,
              !value.isEmpty,
              !value.contains("$(") else { return nil }
        return value
    }

    static var tunnelBundleIdentifier: String {
        Bundle.main.object(forInfoDictionaryKey: "QeliPacketTunnelBundleIdentifier") as? String
            ?? defaultTunnelBundleIdentifier
    }
}
