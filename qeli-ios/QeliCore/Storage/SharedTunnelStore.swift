import Foundation

final class SharedTunnelStore: @unchecked Sendable {
    private let defaults: UserDefaults
    private let lock = NSLock()
    private let snapshotKey = "tunnel.snapshot.v1"
    private let logKey = "tunnel.log.v1"
    private let maximumLogLines = 500

    init(suiteName: String? = AppConstants.appGroupIdentifier) {
        defaults = suiteName.flatMap(UserDefaults.init(suiteName:)) ?? .standard
    }

    func snapshot() -> TunnelSnapshot {
        lock.withLock {
            guard let data = defaults.data(forKey: snapshotKey),
                  let value = try? JSONDecoder.shared.decode(TunnelSnapshot.self, from: data) else {
                return TunnelSnapshot()
            }
            return value
        }
    }

    func save(_ snapshot: TunnelSnapshot) {
        lock.withLock {
            guard let data = try? JSONEncoder.shared.encode(snapshot) else { return }
            defaults.set(data, forKey: snapshotKey)
        }
    }

    func logLines() -> [TunnelLogLine] {
        lock.withLock {
            guard let data = defaults.data(forKey: logKey),
                  let lines = try? JSONDecoder.shared.decode([TunnelLogLine].self, from: data) else {
                return []
            }
            return lines
        }
    }

    func appendLog(_ message: String, date: Date = Date()) {
        lock.withLock {
            var lines: [TunnelLogLine] = []
            if let data = defaults.data(forKey: logKey),
               let stored = try? JSONDecoder.shared.decode([TunnelLogLine].self, from: data) {
                lines = stored
            }
            lines.append(TunnelLogLine(date: date, message: message))
            if lines.count > maximumLogLines { lines.removeFirst(lines.count - maximumLogLines) }
            if let data = try? JSONEncoder.shared.encode(lines) { defaults.set(data, forKey: logKey) }
        }
    }

    func clearLog() { lock.withLock { defaults.removeObject(forKey: logKey) } }
}

private extension JSONEncoder {
    static var shared: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return encoder
    }
}

private extension JSONDecoder {
    static var shared: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}

