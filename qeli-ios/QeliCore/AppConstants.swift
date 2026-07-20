import Foundation

enum AppConstants {
    static let version = "0.7.12"
    static let build = "715"
    static let defaultAppGroup = "group.ru.autocash.qeli"
    static let defaultTunnelBundleIdentifier = "ru.autocash.qeli.PacketTunnel"
    static let statusWidgetKind = "ru.autocash.qeli.status-widget"
    static let connectionControlKind = "ru.autocash.qeli.connection-control"

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
