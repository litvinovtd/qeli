import Foundation

enum QeliConnectionCommand: String, Codable, Sendable {
    case connect
    case disconnect
}

struct QeliWidgetControlRequest: Codable, Equatable, Sendable {
    let id: UUID
    let command: QeliConnectionCommand
    let createdAt: Date
    let delivery: Delivery

    enum Delivery: String, Codable, Sendable {
        case foregroundIntent
        case url
    }
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
    /// the shared App Group. A custom URL by itself never authorizes a VPN action.
    static func issue(
        _ command: QeliConnectionCommand,
        delivery: QeliWidgetControlRequest.Delivery = .foregroundIntent,
        now: Date = Date()
    ) -> QeliWidgetControlRequest? {
        guard widgetControlsEnabled else { return nil }
        guard let defaults = appGroupDefaults() else { return nil }
        return lock.withLock {
            var requests = load(from: defaults).filter { isFresh($0, now: now) }
            let request = QeliWidgetControlRequest(
                id: UUID(),
                command: command,
                createdAt: now,
                delivery: delivery
            )
            requests.append(request)
            if requests.count > maximumStoredRequests {
                requests.removeFirst(requests.count - maximumStoredRequests)
            }
            save(requests, to: defaults)
            return request
        }
    }

    /// Consumes the newest foreground intent request and drops older requests so
    /// repeated quick taps settle on the latest desired state.
    static func consumePendingIntent(now: Date = Date()) -> QeliWidgetControlRequest? {
        guard widgetControlsEnabled else { return nil }
        guard let defaults = appGroupDefaults() else { return nil }
        return lock.withLock {
            var requests = load(from: defaults).filter { isFresh($0, now: now) }
            let request = requests.last(where: { $0.delivery == .foregroundIntent })
            if request != nil {
                requests.removeAll(where: { $0.delivery == .foregroundIntent })
            }
            save(requests, to: defaults)
            return request
        }
    }

    static func requestURL(for request: QeliWidgetControlRequest) -> URL? {
        guard request.delivery == .url else { return nil }
        return URL(string: "\(urlScheme)://request/\(request.id.uuidString)")
    }

    /// Returns `.url` requests only when the opaque token exists in the App Group,
    /// is fresh, and has not previously been consumed.
    static func consume(url: URL, now: Date = Date()) -> QeliWidgetControlRequest? {
        guard widgetControlsEnabled else { return nil }
        guard url.scheme?.lowercased() == urlScheme,
              url.host?.lowercased() == "request",
              let token = url.pathComponents.dropFirst().first,
              let id = UUID(uuidString: token),
              let defaults = appGroupDefaults() else { return nil }

        return lock.withLock {
            var requests = load(from: defaults).filter { isFresh($0, now: now) }
            guard let index = requests.firstIndex(where: {
                $0.id == id && $0.delivery == .url
            }) else {
                save(requests, to: defaults)
                return nil
            }
            let request = requests.remove(at: index)
            save(requests, to: defaults)
            return request
        }
    }

    static func isStatusURL(_ url: URL) -> Bool {
        url.scheme?.lowercased() == urlScheme && url.host?.lowercased() == "status"
    }

    static func isControlURL(_ url: URL) -> Bool {
        url.scheme?.lowercased() == urlScheme
    }

    static var widgetControlsEnabled: Bool {
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
