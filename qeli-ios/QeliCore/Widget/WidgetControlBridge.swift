import Foundation

enum QeliConnectionCommand: String, Codable, Sendable {
    case toggle
    case connect
    case disconnect
}

struct QeliWidgetControlRequest: Codable, Equatable, Sendable {
    // Unknown keys from the old id/delivery schema are intentionally ignored by Codable,
    // so a short-lived request queued by the previous app version remains readable.
    let command: QeliConnectionCommand
    let createdAt: Date
}

enum WidgetControlBridge {
    static let urlScheme = "qeli-control"
    static let statusURL = URL(string: "qeli-control://status")!

    private static let requestsKey = "widget.control.requests.v1"
    private static let controlsEnabledKey = "widget.control.enabled.v1"
    private static let maximumRequestAge: TimeInterval = 5 * 60
    private static let maximumStoredRequests = 16
    private static let lock = NSLock()

    /// Creates a request that only the app and its signed extensions can place in
    /// the shared App Group.
    static func issue(
        _ command: QeliConnectionCommand,
        now: Date = Date()
    ) -> QeliWidgetControlRequest? {
        guard widgetControlsEnabled else { return nil }
        guard let defaults = appGroupDefaults() else { return nil }
        return lock.withLock {
            var requests = load(from: defaults).filter { isFresh($0, now: now) }
            let request = QeliWidgetControlRequest(command: command, createdAt: now)
            requests.append(request)
            if requests.count > maximumStoredRequests {
                requests.removeFirst(requests.count - maximumStoredRequests)
            }
            save(requests, to: defaults)
            return request
        }
    }

    /// Consumes the newest request and drops older requests so repeated quick taps
    /// settle on the latest desired state.
    static func consumePendingIntent(now: Date = Date()) -> QeliWidgetControlRequest? {
        guard widgetControlsEnabled else { return nil }
        guard let defaults = appGroupDefaults() else { return nil }
        return lock.withLock {
            var requests = load(from: defaults).filter { isFresh($0, now: now) }
            let request = requests.last
            requests.removeAll()
            save(requests, to: defaults)
            return request
        }
    }

    static func isControlURL(_ url: URL) -> Bool {
        url.scheme?.lowercased() == urlScheme && url.host?.lowercased() == "status"
    }

    static var widgetControlsEnabled: Bool {
        // Consult the MDM policy DIRECTLY first — do not rely on the app having mirrored
        // it into the App Group.
        //
        // This used to read only the mirrored copy and default to ENABLED whenever the key
        // was absent, and the mirror is written exclusively by the main app. So on a
        // freshly-enrolled or freshly-rebooted device, a user who tapped the Control
        // Centre toggle without ever opening Qeli was allowed straight through: the
        // organisation's `widgetControlsEnabled: false` had never been copied anywhere the
        // extension looked. A policy check that defaults to "permitted" when it cannot
        // find the policy is not a policy check. The extension can read the managed
        // dictionary itself, so read it, and treat an explicit `false` as final.
        // (Audit 2026-07-27, M9.)
        if let managed = ManagedConfigurationReader().load().widgetControlsEnabled {
            return managed
        }
        guard let defaults = appGroupDefaults(),
              defaults.object(forKey: controlsEnabledKey) != nil else { return true }
        return defaults.bool(forKey: controlsEnabledKey)
    }

    static func setWidgetControlsEnabled(_ enabled: Bool) {
        guard let defaults = appGroupDefaults() else { return }
        defaults.set(enabled, forKey: controlsEnabledKey)
        if !enabled { defaults.removeObject(forKey: requestsKey) }
    }

    private static func appGroupDefaults() -> UserDefaults? {
        UserDefaults(suiteName: AppConstants.appGroupIdentifier)
    }

    private static func isFresh(_ request: QeliWidgetControlRequest, now: Date) -> Bool {
        let age = now.timeIntervalSince(request.createdAt)
        return age >= -30 && age <= maximumRequestAge
    }

    private static func load(from defaults: UserDefaults) -> [QeliWidgetControlRequest] {
        guard let data = defaults.data(forKey: requestsKey) else { return [] }
        return (try? JSONDecoder().decode([QeliWidgetControlRequest].self, from: data)) ?? []
    }

    private static func save(_ requests: [QeliWidgetControlRequest], to defaults: UserDefaults) {
        if requests.isEmpty {
            defaults.removeObject(forKey: requestsKey)
        } else if let data = try? JSONEncoder().encode(requests) {
            defaults.set(data, forKey: requestsKey)
        }
    }
}

extension Notification.Name {
    static let qeliWidgetControlRequestAvailable = Notification.Name(
        "ru.qeli.app.widget-control-request"
    )
}
